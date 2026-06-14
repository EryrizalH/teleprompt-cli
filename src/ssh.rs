use ssh2::{Session, KeyboardInteractivePrompt, Prompt, CheckResult, KnownHostFileKind};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use crate::credentials::{Device, ConnectionType, HostKeyPolicy};
use crate::commands::get_known_hosts_path;
use crate::error::TelepromptError;
pub fn execute_command(
    device: &Device,
    command: &str,
    timeout_secs: u64,
    verbose: bool,
    on_stdout: &mut dyn FnMut(&[u8]),
    on_stderr: &mut dyn FnMut(&[u8]),
) -> Result<i32, TelepromptError> {
    if device.connection_type != ConnectionType::Ssh {
        return Err(TelepromptError::Other("Device is not configured for SSH".to_string()));
    }

    // Connect to host
    let addr = format!("{}:{}", device.host, device.port);
    if verbose {
        eprintln!("[verbose] Connecting to {}...", addr);
    }
    let socket_addrs = addr.to_socket_addrs()
        .map_err(|e| TelepromptError::ConnectionFailed(addr.clone(), e.to_string()))?;
    let socket_addr = socket_addrs.into_iter().next()
        .ok_or_else(|| TelepromptError::ConnectionFailed(addr.clone(), "No addresses resolved".to_string()))?;
    let stream = TcpStream::connect_timeout(
        &socket_addr,
        Duration::from_secs(timeout_secs),
    ).map_err(|e| TelepromptError::ConnectionFailed(addr.clone(), e.to_string()))?;
    if verbose {
        eprintln!("[verbose] TCP connected, performing SSH handshake...");
    }

    let mut sess = Session::new()
        .map_err(|e| TelepromptError::ConnectionFailed(addr.clone(), e.to_string()))?;
    sess.set_tcp_stream(stream);
    sess.set_timeout(timeout_secs as u32 * 1000);
    sess.handshake()
        .map_err(|e| TelepromptError::ConnectionFailed(addr.clone(), e.to_string()))?;


    if verbose {
        eprintln!("[verbose] SSH handshake complete, verifying host key...");
    }
    verify_host_key(&sess, device, &addr)?;

    // Authenticate
    if verbose {
        eprintln!("[verbose] Authenticating as {}...", device.username);
    }
    authenticate_session(&mut sess, device, &addr)?;

    let mut channel = sess.channel_session()
        .map_err(|e| TelepromptError::Other(format!("Failed to open channel: {}", e)))?;

    let is_sudo = command.trim().starts_with("sudo ") || command.trim() == "sudo";
    
    if is_sudo {
        // Sudo requires a PTY to receive the password
        channel.request_pty("vanilla", None, None)
            .map_err(|e| TelepromptError::Other(format!("Failed to request PTY for sudo: {}", e)))?;
    }

    channel.exec(command)
        .map_err(|e| TelepromptError::Other(format!("Failed to execute command: {}", e)))?;

    sess.set_blocking(false);

    let mut stdout_closed = false;
    let mut stderr_closed = false;

    #[derive(PartialEq)]
    enum SudoState {
        CheckingPrompt,
        PasswordSent,
        Disabled,
    }

    let mut sudo_state = if is_sudo && device.sudo_password_required {
        SudoState::CheckingPrompt
    } else {
        SudoState::Disabled
    };

    let mut initial_prompts = 0;
    let mut stdout_buf = Vec::new();

    while !stdout_closed || !stderr_closed {
        // Read stdout
        if !stdout_closed {
            let mut buf = [0u8; 1024];
            match channel.read(&mut buf) {
                Ok(0) => stdout_closed = true,
                Ok(n) => {
                    match sudo_state {
                        SudoState::Disabled => {
                            on_stdout(&buf[..n]);
                        }
                        SudoState::CheckingPrompt => {
                            stdout_buf.extend_from_slice(&buf[..n]);
                            let stdout_str = String::from_utf8_lossy(&stdout_buf);
                            if contains_sudo_prompt(&stdout_str) {
                                if let Some(ref pwd) = device.password {
                                    initial_prompts = count_sudo_prompts(&stdout_str);
                                    // Write password to stdin
                                    sess.set_blocking(true);
                                    if let Err(e) = channel.write_all(format!("{}\n", pwd).as_bytes()) {
                                        return Err(TelepromptError::SudoFailed(e.to_string()));
                                    }
                                    let _ = channel.flush();
                                    sess.set_blocking(false);
                                    sudo_state = SudoState::PasswordSent;
                                } else {
                                    return Err(TelepromptError::SudoFailed("Sudo requires a password, but none is saved".to_string()));
                                }
                            } else if (stdout_str.contains('\n') && !contains_sudo_prompt(&stdout_str)) || stdout_buf.len() > 512 {
                                // Sudo didn't prompt, probably not asking for password
                                on_stdout(&stdout_buf);
                                stdout_buf.clear();
                                sudo_state = SudoState::Disabled;
                            }
                        }
                        SudoState::PasswordSent => {
                            stdout_buf.extend_from_slice(&buf[..n]);
                            let stdout_str = String::from_utf8_lossy(&stdout_buf);
                            if count_sudo_prompts(&stdout_str) > initial_prompts {
                                return Err(TelepromptError::SudoFailed("Incorrect password".to_string()));
                            }
                            let pwd = device.password.as_deref().unwrap_or("");
                            let cleaned = clean_sudo_output(stdout_buf.clone(), pwd);
                            if !cleaned.is_empty() {
                                on_stdout(&cleaned);
                                stdout_buf.clear();
                                sudo_state = SudoState::Disabled;
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(TelepromptError::Io(e)),
            }
        }

        // Read stderr
        if !stderr_closed {
            let mut buf = [0u8; 1024];
            match channel.stderr().read(&mut buf) {
                Ok(0) => stderr_closed = true,
                Ok(n) => on_stderr(&buf[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(TelepromptError::Io(e)),
            }
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    // Flush any remaining buffered stdout from sudo prompting phase
    if sudo_state != SudoState::Disabled && !stdout_buf.is_empty() {
        let pwd = device.password.as_deref().unwrap_or("");
        let cleaned = clean_sudo_output(stdout_buf, pwd);
        if !cleaned.is_empty() {
            on_stdout(&cleaned);
        }
    }

    sess.set_blocking(true);
    let _ = channel.wait_eof();
    let _ = channel.close();
    let _ = channel.wait_close();

    let exit_status = channel.exit_status()
        .map_err(|e| TelepromptError::Other(format!("Failed to retrieve exit status: {}", e)))?;

    Ok(exit_status)
}

pub fn test_connection(device: &Device, timeout_secs: u64, verbose: bool) -> Result<(), TelepromptError> {
    // We execute a simple echo command to test connectivity
    let status = execute_command(
        device,
        "echo 'teleprompt_ok'",
        timeout_secs,
        verbose,
        &mut |_| {},
        &mut |_| {},
    )?;
    if status == 0 {
        Ok(())
    } else {
        Err(TelepromptError::Other(format!("Test command exited with code {}", status)))
    }
}

pub fn detect_sudo_capability(device: &mut Device, timeout_secs: u64) -> Result<(), TelepromptError> {
    // 1. Check if sudo is installed and if we can run without password
    // We run `sudo -n true`
    let status_no_pwd = execute_command(
        device,
        "sudo -n true",
        timeout_secs,
        false,
        &mut |_| {},
        &mut |_| {},
    )?;
    if status_no_pwd == 0 {
        device.sudo_capable = true;
        device.sudo_password_required = false;
        return Ok(());
    }

    // 2. Check if we can run with password
    device.sudo_capable = true;
    device.sudo_password_required = true;
    let status_pwd = execute_command(
        device,
        "sudo -S true",
        timeout_secs,
        false,
        &mut |_| {},
        &mut |_| {},
    )?;
    if status_pwd == 0 {
        // Sudo works with password!
        Ok(())
    } else {
        // Sudo failed
        device.sudo_capable = false;
        device.sudo_password_required = false;
        Ok(())
    }
}

/// Verifies the remote host key against the known_hosts file.
fn verify_host_key(
    sess: &Session,
    device: &Device,
    addr: &str,
) -> Result<(), TelepromptError> {
    if device.host_key_policy == HostKeyPolicy::Off {
        return Ok(());
    }

    let (key, key_type) = sess.host_key()
        .ok_or_else(|| TelepromptError::HostKeyRejected(
            addr.to_string(),
            "Could not retrieve host key from server".to_string(),
        ))?;

    let mut known_hosts = sess.known_hosts()
        .map_err(|e| TelepromptError::HostKeyRejected(
            addr.to_string(),
            format!("Failed to initialize known_hosts: {}", e),
        ))?;

    // Try to load known_hosts file (OK if missing)
    if let Ok(kh_path) = get_known_hosts_path() {
        if kh_path.exists() {
            known_hosts.read_file(&kh_path, KnownHostFileKind::OpenSSH)
                .map_err(|e| TelepromptError::HostKeyRejected(
                    addr.to_string(),
                    format!("Failed to read known_hosts: {}", e),
                ))?;
        }
    }

    let host_for_check = if device.port != 22 {
        format!("[{}]:{}", device.host, device.port)
    } else {
        device.host.clone()
    };

    let check_result = known_hosts.check(&host_for_check, key);

    match check_result {
        CheckResult::Match => Ok(()),
        CheckResult::NotFound => {
            if device.host_key_policy == HostKeyPolicy::AcceptNew {
                // Add to known_hosts and save
                let comment = &device.host;
                known_hosts.add(&host_for_check, key, comment, key_type.into())
                    .map_err(|e| TelepromptError::HostKeyRejected(
                        addr.to_string(),
                        format!("Failed to add host to known_hosts: {}", e),
                    ))?;
                // Append to file
                if let Ok(kh_path) = get_known_hosts_path() {
                    if let Some(parent) = kh_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    known_hosts.write_file(&kh_path, KnownHostFileKind::OpenSSH)
                        .map_err(|e| TelepromptError::HostKeyRejected(
                            addr.to_string(),
                            format!("Failed to write known_hosts: {}", e),
                        ))?;
                }
                Ok(())
            } else {
                Err(TelepromptError::HostKeyRejected(
                    addr.to_string(),
                    "Host not in known_hosts (policy: Strict)".to_string(),
                ))
            }
        }
        CheckResult::Mismatch => Err(TelepromptError::HostKeyRejected(
            addr.to_string(),
            "Host key mismatch — possible MITM attack!".to_string(),
        )),
        CheckResult::Failure => Err(TelepromptError::HostKeyRejected(
            addr.to_string(),
            "Host key check failed".to_string(),
        )),
    }
}

fn authenticate_session(
    sess: &mut Session,
    device: &Device,
    addr: &str,
) -> Result<(), TelepromptError> {
    // 1. Try public key if key_path is specified
    if let Some(ref key_path) = device.key_path {
        let path = Path::new(key_path);
        if path.exists() {
            if let Err(_e) = sess.userauth_pubkey_file(
                &device.username,
                None,  // public key file (None = read from private key)
                path,
                device.key_passphrase.as_deref(),
            ) {
                // If pubkey failed and no password is saved, return auth error
                if device.password.is_none() {
                    return Err(TelepromptError::AuthFailed(device.username.clone(), addr.to_string()));
                }
            } else {
                return Ok(()); // Key auth succeeded
            }
        } else if device.password.is_none() {
            return Err(TelepromptError::Other(format!("SSH key file not found at: {}", key_path)));
        }
    }

    // 2. Try password auth
    if let Some(ref password) = device.password {
        if sess.userauth_password(&device.username, password).is_ok() {
            return Ok(());
        }

        // Fallback to keyboard-interactive authentication
        struct SimplePromptHandler {
            password: String,
        }

        impl KeyboardInteractivePrompt for SimplePromptHandler {
            fn prompt<'a>(
                &mut self,
                _username: &str,
                _instructions: &str,
                prompts: &[Prompt<'a>],
            ) -> Vec<String> {
                prompts.iter().map(|_| self.password.clone()).collect()
            }
        }

        let mut prompter = SimplePromptHandler {
            password: password.clone(),
        };

        if sess.userauth_keyboard_interactive(&device.username, &mut prompter).is_ok() {
            return Ok(());
        }

        Err(TelepromptError::AuthFailed(device.username.clone(), addr.to_string()))
    } else {
        Err(TelepromptError::Other("No credentials (password or valid key) provided for SSH auth".to_string()))
    }
}

fn contains_sudo_prompt(stdout: &str) -> bool {
    let lower = stdout.to_lowercase();
    lower.contains("password for") || lower.contains("[sudo]") || lower.contains("password:")
}

fn count_sudo_prompts(stdout: &str) -> usize {
    let lower = stdout.to_lowercase();
    let mut count = 0;
    for pattern in &["password for", "[sudo]", "password:"] {
        count += lower.matches(pattern).count();
    }
    count
}

fn clean_sudo_output(stdout: Vec<u8>, password: &str) -> Vec<u8> {
    let stdout_str = String::from_utf8_lossy(&stdout);
    let lines = stdout_str.lines().collect::<Vec<&str>>();
    
    // Sudo with PTY will echo the prompt and the password typed (or stars, or just newline)
    // E.g.:
    // [sudo] password for user:
    // (password typed)
    // <actual command output>
    
    // We filter out lines that contain sudo prompt or match the password
    let mut filtered_lines = Vec::new();
    let mut prompt_passed = false;
    
    for line in lines {
        let lower = line.to_lowercase();
        let is_prompt = lower.contains("[sudo]") || lower.contains("password for") || lower.contains("password:");
        let is_password = !password.is_empty() && (line.trim() == password.trim() || line.trim() == "");
        
        if is_prompt {
            continue;
        }
        if !prompt_passed && is_password {
            // Skip the first empty line/password echo right after prompt
            continue;
        }
        
        // Once we hit non-prompt/non-password-echo, everything else is output
        prompt_passed = true;
        filtered_lines.push(line);
    }
    
    filtered_lines.join("\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_sudo_prompt() {
        assert!(contains_sudo_prompt("[sudo] password for user:"));
        assert!(contains_sudo_prompt("password:"));
        assert!(contains_sudo_prompt("Password for root:"));
        assert!(!contains_sudo_prompt("access granted"));
        assert!(!contains_sudo_prompt(""));
    }

    #[test]
    fn test_count_sudo_prompts() {
        assert_eq!(count_sudo_prompts("[sudo] password for user:"), 2); // Matches [sudo] and password for
        assert_eq!(count_sudo_prompts("password:"), 1);
        assert_eq!(count_sudo_prompts("[sudo]\npassword:"), 2);
        assert_eq!(count_sudo_prompts("normal command output"), 0);
    }

    #[test]
    fn test_clean_sudo_output() {
        let password = "my_password";
        
        // Output from command with sudo prompting
        let raw_output = b"[sudo] password for admin:\n\nmy_password\nHello World\nSuccess".to_vec();
        let cleaned = clean_sudo_output(raw_output, password);
        assert_eq!(String::from_utf8_lossy(&cleaned), "Hello World\nSuccess");

        // Without password prompting (no [sudo] in prompt or password matches)
        let raw_output_normal = b"Hello World\nSuccess".to_vec();
        let cleaned_normal = clean_sudo_output(raw_output_normal, password);
        assert_eq!(String::from_utf8_lossy(&cleaned_normal), "Hello World\nSuccess");

        // Only sudo prompt and password echo, empty actual output
        let raw_output_empty = b"[sudo] password for admin:\nmy_password\n".to_vec();
        let cleaned_empty = clean_sudo_output(raw_output_empty, password);
        assert_eq!(String::from_utf8_lossy(&cleaned_empty), "");
    }
}

