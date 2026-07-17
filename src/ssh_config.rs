use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::TelepromptError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshImportCandidate {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub identity_file: Option<PathBuf>,
    pub known_host_lines: Vec<String>,
}

#[derive(Debug, Default)]
pub struct DiscoveryReport {
    pub candidates: Vec<SshImportCandidate>,
    pub skipped_wildcards: usize,
    pub skipped_hashed_hosts: usize,
    pub skipped_standalone_hosts: usize,
    pub malformed_known_hosts: usize,
}

#[derive(Debug, Default)]
struct HostBlock {
    aliases: Vec<String>,
    host_name: Option<String>,
    username: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
}

pub fn discover_ssh_hosts(home: &Path) -> Result<DiscoveryReport, TelepromptError> {
    let ssh_dir = home.join(".ssh");
    let config_path = ssh_dir.join("config");
    let known_hosts_path = ssh_dir.join("known_hosts");

    let config = match fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(TelepromptError::Io(error)),
    };

    let mut report = parse_ssh_config(&config, home);

    let known_hosts = match fs::read_to_string(&known_hosts_path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(TelepromptError::Io(error)),
    };
    enrich_from_known_hosts(&mut report, &known_hosts);

    Ok(report)
}

pub fn first_default_identity(home: &Path) -> Option<PathBuf> {
    ["id_ed25519", "id_ecdsa", "id_rsa"]
        .iter()
        .map(|name| home.join(".ssh").join(name))
        .find(|path| path.is_file())
}

fn parse_ssh_config(content: &str, home: &Path) -> DiscoveryReport {
    let mut report = DiscoveryReport::default();
    let mut current: Option<HostBlock> = None;

    for raw_line in content.lines() {
        let line = strip_comment(raw_line);
        let Some((keyword, value)) = split_directive(&line) else {
            continue;
        };

        match keyword.to_ascii_lowercase().as_str() {
            "host" => {
                if let Some(block) = current.take() {
                    append_block(block, home, &mut report.candidates);
                }

                let mut aliases = Vec::new();
                for alias in parse_words(value) {
                    if alias.contains(['*', '?', '!']) {
                        report.skipped_wildcards += 1;
                    } else if !alias.is_empty() {
                        aliases.push(alias);
                    }
                }
                current = Some(HostBlock {
                    aliases,
                    ..HostBlock::default()
                });
            }
            "match" => {
                if let Some(block) = current.take() {
                    append_block(block, home, &mut report.candidates);
                }
            }
            "hostname" => set_first(&mut current, |block| &mut block.host_name, value),
            "user" => set_first(&mut current, |block| &mut block.username, value),
            "port" => {
                if let Some(block) = current.as_mut() {
                    if block.port.is_none() {
                        block.port = first_word(value).and_then(|port| port.parse::<u16>().ok());
                    }
                }
            }
            "identityfile" => set_first(&mut current, |block| &mut block.identity_file, value),
            _ => {}
        }
    }

    if let Some(block) = current {
        append_block(block, home, &mut report.candidates);
    }

    report
}

fn set_first<F>(current: &mut Option<HostBlock>, field: F, value: &str)
where
    F: FnOnce(&mut HostBlock) -> &mut Option<String>,
{
    if let Some(block) = current.as_mut() {
        let target = field(block);
        if target.is_none() {
            *target = first_word(value);
        }
    }
}

fn append_block(block: HostBlock, home: &Path, candidates: &mut Vec<SshImportCandidate>) {
    let identity_file = block
        .identity_file
        .as_deref()
        .map(|path| expand_home(path, home));

    for alias in block.aliases {
        candidates.push(SshImportCandidate {
            name: alias.clone(),
            host: block.host_name.clone().unwrap_or(alias),
            port: block.port.unwrap_or(22),
            username: block.username.clone(),
            identity_file: identity_file.clone(),
            known_host_lines: Vec::new(),
        });
    }
}

fn enrich_from_known_hosts(report: &mut DiscoveryReport, content: &str) {
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        let host_index = usize::from(fields.first().is_some_and(|field| field.starts_with('@')));
        if fields.len() < host_index + 3 {
            report.malformed_known_hosts += 1;
            continue;
        }

        let hosts_field = fields[host_index];
        if hosts_field.split(',').any(|host| host.starts_with("|1|")) {
            report.skipped_hashed_hosts += 1;
            continue;
        }

        let mut matched = false;
        for host_token in hosts_field.split(',') {
            let Some((host, port)) = parse_known_host(host_token) else {
                report.malformed_known_hosts += 1;
                continue;
            };

            for candidate in &mut report.candidates {
                let host_matches = candidate.name.eq_ignore_ascii_case(&host)
                    || candidate.host.eq_ignore_ascii_case(&host);
                if host_matches && candidate.port == port {
                    if !candidate
                        .known_host_lines
                        .iter()
                        .any(|existing| existing == line)
                    {
                        candidate.known_host_lines.push(line.to_string());
                    }
                    matched = true;
                }
            }
        }

        if !matched {
            report.skipped_standalone_hosts += 1;
        }
    }

    for candidate in &mut report.candidates {
        let mut seen = HashSet::new();
        candidate
            .known_host_lines
            .retain(|line| seen.insert(line.clone()));
    }
}

fn parse_known_host(value: &str) -> Option<(String, u16)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.rsplit_once("]:")?;
        return Some((host.to_string(), port.parse().ok()?));
    }

    if value.is_empty() {
        None
    } else {
        Some((value.to_string(), 22))
    }
}

fn expand_home(value: &str, home: &Path) -> PathBuf {
    let expanded = if value == "~" {
        home.to_path_buf()
    } else if let Some(relative) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        home.join(relative)
    } else {
        PathBuf::from(value)
    };

    if expanded.is_relative() {
        home.join(".ssh").join(expanded)
    } else {
        expanded
    }
}

fn strip_comment(line: &str) -> String {
    let mut result = String::new();
    let mut quote = None;
    let mut escaped = false;

    for character in line.chars() {
        if escaped {
            result.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            result.push(character);
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            result.push(character);
            continue;
        }
        if character == '#' && quote.is_none() {
            break;
        }
        result.push(character);
    }

    result.trim().to_string()
}

fn split_directive(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let split_at = line.char_indices().find_map(|(index, character)| {
        (character.is_whitespace() || character == '=').then_some(index)
    });

    match split_at {
        Some(index) => {
            let keyword = &line[..index];
            let value = line[index..]
                .trim_start_matches(|character: char| character.is_whitespace() || character == '=')
                .trim();
            (!keyword.is_empty() && !value.is_empty()).then_some((keyword, value))
        }
        None => None,
    }
}

fn first_word(value: &str) -> Option<String> {
    parse_words(value).into_iter().next()
}

fn parse_words(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;

    for character in value.chars() {
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                current.push(character);
            }
            continue;
        }
        if character.is_whitespace() && quote.is_none() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            // Keep backslashes intact so Windows drive and UNC paths survive parsing.
            current.push(character);
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_home() -> PathBuf {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("teleprompt-ssh-config-{}-{id}", std::process::id()));
        fs::create_dir_all(path.join(".ssh")).unwrap();
        path
    }

    #[test]
    fn parses_supported_fields_and_skips_wildcards() {
        let home = temp_home();
        let config = r#"
            Host production prod
                HostName = server.example.com
                User "deploy"
                Port 2222
                IdentityFile ~/.ssh/prod_key # trailing comment

            Host *.internal !blocked
                User ignored
        "#;

        let report = parse_ssh_config(config, &home);
        assert_eq!(report.candidates.len(), 2);
        assert_eq!(report.skipped_wildcards, 2);
        assert_eq!(report.candidates[0].name, "production");
        assert_eq!(report.candidates[0].host, "server.example.com");
        assert_eq!(report.candidates[0].port, 2222);
        assert_eq!(report.candidates[0].username.as_deref(), Some("deploy"));
        assert_eq!(
            report.candidates[0].identity_file.as_deref(),
            Some(home.join(".ssh/prod_key").as_path())
        );

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn known_hosts_only_enriches_matching_config_candidates() {
        let home = temp_home();
        let config = "Host prod\n HostName prod.example.com\n Port 2222\n";
        let mut report = parse_ssh_config(config, &home);
        enrich_from_known_hosts(
            &mut report,
            "[prod.example.com]:2222 ssh-ed25519 AAAA\nstandalone ssh-rsa BBBB\n|1|salt|hash ssh-ed25519 CCCC\nbroken\n",
        );

        assert_eq!(report.candidates[0].known_host_lines.len(), 1);
        assert_eq!(report.skipped_standalone_hosts, 1);
        assert_eq!(report.skipped_hashed_hosts, 1);
        assert_eq!(report.malformed_known_hosts, 1);

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn default_identity_uses_expected_precedence() {
        let home = temp_home();
        let ssh_dir = home.join(".ssh");
        fs::write(ssh_dir.join("id_rsa"), "rsa").unwrap();
        fs::write(ssh_dir.join("id_ed25519"), "ed25519").unwrap();

        assert_eq!(
            first_default_identity(&home),
            Some(ssh_dir.join("id_ed25519"))
        );

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn preserves_windows_identity_file_backslashes() {
        assert_eq!(
            parse_words(r#"C:\Users\alice\.ssh\id_ed25519"#),
            vec![r#"C:\Users\alice\.ssh\id_ed25519"#]
        );
        assert_eq!(
            parse_words(r#""C:\Users\Alice Smith\.ssh\id_ed25519""#),
            vec![r#"C:\Users\Alice Smith\.ssh\id_ed25519"#]
        );
        assert_eq!(
            parse_words(r#"\\server\share\id_ed25519"#),
            vec![r#"\\server\share\id_ed25519"#]
        );
    }

    #[test]
    fn discovery_tolerates_missing_files() {
        let home = temp_home();
        let report = discover_ssh_hosts(&home).unwrap();
        assert!(report.candidates.is_empty());
        let _ = fs::remove_dir_all(home);
    }
}
