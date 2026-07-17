use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::commands::{get_known_hosts_path, get_master_password, test_and_prepare_device};
use crate::credentials::{self, ConnectionType, Device, HostKeyPolicy, OsType};
use crate::error::TelepromptError;
use crate::ssh_config::{self, SshImportCandidate};

const RESERVED_DEVICE_NAMES: &[&str] = &[
    "init",
    "add",
    "remove",
    "edit",
    "list",
    "test",
    "import",
    "generate-key",
    "install-skill",
];

#[derive(Debug, Default)]
struct ImportSummary {
    detected: usize,
    imported: usize,
    declined: usize,
    conflicts: usize,
    incomplete: usize,
    test_failed: usize,
}

pub fn run(
    db_path: Option<&Path>,
    import_all: bool,
    assume_yes: bool,
    timeout_secs: u64,
    verbose: bool,
) -> Result<(), TelepromptError> {
    if assume_yes && !import_all {
        return Err(TelepromptError::Cli(
            "--yes can only be used together with --all".to_string(),
        ));
    }

    let resolved_path = match db_path {
        Some(path) => path.to_path_buf(),
        None => credentials::get_default_db_path()?,
    };
    if !resolved_path.exists() {
        return Err(TelepromptError::NotInitialized);
    }

    let home = dirs::home_dir()
        .ok_or_else(|| TelepromptError::Other("Could not find home directory".to_string()))?;
    let report = ssh_config::discover_ssh_hosts(&home)?;
    let mut summary = ImportSummary {
        detected: report.candidates.len(),
        ..ImportSummary::default()
    };

    println!("--- Import SSH Devices ---");
    println!(
        "Detected {} candidate(s) in ~/.ssh/config.",
        summary.detected
    );
    if report.skipped_wildcards > 0
        || report.skipped_hashed_hosts > 0
        || report.skipped_standalone_hosts > 0
        || report.malformed_known_hosts > 0
    {
        println!(
            "Discovery notes: {} wildcard(s), {} hashed host(s), {} standalone host(s), {} malformed known_hosts line(s) skipped.",
            report.skipped_wildcards,
            report.skipped_hashed_hosts,
            report.skipped_standalone_hosts,
            report.malformed_known_hosts
        );
    }

    if report.candidates.is_empty() {
        print_summary(&summary);
        return Ok(());
    }

    let master_password = get_master_password()?;
    let mut store = credentials::load_store(&resolved_path, &master_password)?;
    let mut accepted_names: HashSet<String> = store.devices.keys().cloned().collect();
    let mut accepted_endpoints: HashSet<(String, u16)> = store
        .devices
        .values()
        .map(|device| (device.host.to_ascii_lowercase(), device.port))
        .collect();

    for candidate in report.candidates {
        if is_reserved_name(&candidate.name)
            || accepted_names.contains(&candidate.name)
            || accepted_endpoints.contains(&(candidate.host.to_ascii_lowercase(), candidate.port))
        {
            println!(
                "Skipping '{}': device name or endpoint already exists/reserved.",
                candidate.name
            );
            summary.conflicts += 1;
            continue;
        }

        println!(
            "\nCandidate: {} -> {}:{}{}",
            candidate.name,
            candidate.host,
            candidate.port,
            candidate
                .username
                .as_deref()
                .map(|user| format!(" as {user}"))
                .unwrap_or_default()
        );

        if !import_all && !prompt_yes_no("Import this device? (y/N): ")? {
            summary.declined += 1;
            continue;
        }

        if assume_yes && !can_import_unattended(&candidate) {
            println!(
                "Skipping '{}': unattended import requires a matching unhashed known_hosts entry.",
                candidate.name
            );
            summary.incomplete += 1;
            continue;
        }

        let Some(mut device) = build_device(&candidate, &home, assume_yes)? else {
            println!(
                "Skipping '{}': authentication details are incomplete.",
                candidate.name
            );
            summary.incomplete += 1;
            continue;
        };

        seed_known_hosts(&candidate.known_host_lines)?;
        println!("Testing connection to {}...", device.name);
        match test_and_prepare_device(&mut device, timeout_secs, verbose) {
            Ok(()) => {
                println!("Connection successful.");
                if device.os_type == OsType::Linux {
                    println!(
                        "Sudo capable: {} (password required: {}).",
                        device.sudo_capable, device.sudo_password_required
                    );
                }
            }
            Err(error) => {
                println!("Connection failed: {error}");
                summary.test_failed += 1;
                if assume_yes || !prompt_yes_no("Save this device anyway? (y/N): ")? {
                    println!("Skipping '{}'.", candidate.name);
                    continue;
                }
            }
        }

        accepted_names.insert(device.name.clone());
        accepted_endpoints.insert((device.host.to_ascii_lowercase(), device.port));
        store.devices.insert(device.name.clone(), device);
        summary.imported += 1;
    }

    if summary.imported > 0 {
        credentials::save_store(&store, &resolved_path, &master_password)?;
    }
    print_summary(&summary);
    Ok(())
}

fn build_device(
    candidate: &SshImportCandidate,
    home: &Path,
    assume_yes: bool,
) -> Result<Option<Device>, TelepromptError> {
    let username = match candidate.username.clone() {
        Some(username) if !username.trim().is_empty() => username,
        _ if assume_yes => return Ok(None),
        _ => prompt_required("Username: ")?,
    };

    let mut key_path = candidate.identity_file.clone();
    if key_path.is_none() {
        key_path = ssh_config::first_default_identity(home);
    }

    let mut password = None;
    let mut key_passphrase = None;
    if let Some(path) = key_path.as_ref() {
        println!("Using SSH key: {}", path.display());
        if !assume_yes {
            key_passphrase =
                prompt_secret_optional("SSH key passphrase (optional, press Enter to skip): ")?;
            password =
                prompt_secret_optional("Sudo/password fallback (optional, press Enter to skip): ")?;
        }
    } else if assume_yes {
        return Ok(None);
    } else {
        let entered_path = prompt_input("SSH private key path (leave empty to use password): ")?;
        if entered_path.is_empty() {
            password = prompt_secret_optional("Password: ")?;
            if password.is_none() {
                return Ok(None);
            }
        } else {
            key_path = Some(expand_user_path(&entered_path, home));
            key_passphrase =
                prompt_secret_optional("SSH key passphrase (optional, press Enter to skip): ")?;
            password =
                prompt_secret_optional("Sudo/password fallback (optional, press Enter to skip): ")?;
        }
    }

    let os_type = if assume_yes {
        OsType::Generic
    } else {
        prompt_os_type()?
    };

    Ok(Some(Device {
        name: candidate.name.clone(),
        host: candidate.host.clone(),
        port: candidate.port,
        username,
        password,
        key_path: key_path.map(|path| path.to_string_lossy().into_owned()),
        key_passphrase,
        connection_type: ConnectionType::Ssh,
        sudo_capable: false,
        sudo_password_required: false,
        os_type,
        host_key_policy: if assume_yes {
            HostKeyPolicy::Strict
        } else {
            HostKeyPolicy::AcceptNew
        },
    }))
}

fn prompt_os_type() -> Result<OsType, TelepromptError> {
    loop {
        let value =
            prompt_input("OS type (linux/windows/routeros/cisco/junos/generic) [generic]: ")?;
        match value.to_ascii_lowercase().as_str() {
            "" | "generic" => return Ok(OsType::Generic),
            "linux" => return Ok(OsType::Linux),
            "windows" => return Ok(OsType::Windows),
            "routeros" => return Ok(OsType::RouterOs),
            "cisco" | "ciscoios" => return Ok(OsType::CiscoIos),
            "junos" => return Ok(OsType::JunOs),
            _ => println!("Unknown OS type. Please try again."),
        }
    }
}

fn prompt_required(label: &str) -> Result<String, TelepromptError> {
    loop {
        let value = prompt_input(label)?;
        if !value.is_empty() {
            return Ok(value);
        }
        println!("This value cannot be empty.");
    }
}

fn prompt_input(label: &str) -> Result<String, TelepromptError> {
    print!("{label}");
    std::io::stdout().flush().map_err(TelepromptError::Io)?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(TelepromptError::Io)?;
    Ok(input.trim().to_string())
}

fn prompt_secret_optional(label: &str) -> Result<Option<String>, TelepromptError> {
    print!("{label}");
    std::io::stdout().flush().map_err(TelepromptError::Io)?;
    let value = rpassword::read_password().map_err(TelepromptError::Io)?;
    Ok((!value.is_empty()).then_some(value))
}

fn prompt_yes_no(label: &str) -> Result<bool, TelepromptError> {
    Ok(prompt_input(label)?.eq_ignore_ascii_case("y"))
}

fn expand_user_path(value: &str, home: &Path) -> PathBuf {
    if value == "~" {
        home.to_path_buf()
    } else if let Some(relative) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        home.join(relative)
    } else {
        PathBuf::from(value)
    }
}

fn seed_known_hosts(lines: &[String]) -> Result<(), TelepromptError> {
    if lines.is_empty() {
        return Ok(());
    }

    let path = get_known_hosts_path()?;
    merge_known_host_lines(&path, lines)
}

fn merge_known_host_lines(path: &Path, lines: &[String]) -> Result<(), TelepromptError> {
    let existing = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(TelepromptError::Io(error)),
    };
    let mut known: HashSet<String> = existing.lines().map(str::to_string).collect();
    let new_lines: Vec<&String> = lines
        .iter()
        .filter(|line| known.insert((*line).clone()))
        .collect();
    if new_lines.is_empty() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let needs_leading_newline = !existing.is_empty() && !existing.ends_with('\n');
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    if needs_leading_newline {
        file.write_all(b"\n")?;
    }
    for line in new_lines {
        writeln!(file, "{line}")?;
    }
    file.sync_all()?;
    Ok(())
}

fn can_import_unattended(candidate: &SshImportCandidate) -> bool {
    !candidate.known_host_lines.is_empty()
}

fn is_reserved_name(name: &str) -> bool {
    RESERVED_DEVICE_NAMES
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

fn print_summary(summary: &ImportSummary) {
    println!("\nImport summary:");
    println!("  Detected:    {}", summary.detected);
    println!("  Imported:    {}", summary.imported);
    println!("  Declined:    {}", summary.declined);
    println!("  Conflicts:   {}", summary.conflicts);
    println!("  Incomplete:  {}", summary.incomplete);
    println!("  Test failed: {}", summary.test_failed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> PathBuf {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "teleprompt-import-known-hosts-{}-{id}",
            std::process::id()
        ))
    }

    #[test]
    fn reserved_names_are_case_insensitive() {
        assert!(is_reserved_name("import"));
        assert!(is_reserved_name("Generate-Key"));
        assert!(!is_reserved_name("production"));
    }

    #[test]
    fn unattended_import_requires_existing_host_trust() {
        let mut candidate = SshImportCandidate {
            name: "prod".to_string(),
            host: "prod.example.com".to_string(),
            port: 22,
            username: Some("deploy".to_string()),
            identity_file: Some(PathBuf::from("/tmp/key")),
            known_host_lines: Vec::new(),
        };
        assert!(!can_import_unattended(&candidate));

        candidate
            .known_host_lines
            .push("prod.example.com ssh-ed25519 AAAA".to_string());
        assert!(can_import_unattended(&candidate));
    }

    #[test]
    fn merges_known_hosts_without_duplicates() {
        let path = temp_path().join("known_hosts");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "existing ssh-ed25519 AAAA\n").unwrap();

        merge_known_host_lines(
            &path,
            &[
                "existing ssh-ed25519 AAAA".to_string(),
                "new ssh-ed25519 BBBB".to_string(),
            ],
        )
        .unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.matches("existing ssh-ed25519 AAAA").count(), 1);
        assert_eq!(content.matches("new ssh-ed25519 BBBB").count(), 1);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
