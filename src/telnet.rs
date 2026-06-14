use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::credentials::{Device, ConnectionType};
use crate::error::TelepromptError;

// Telnet Command Codes (RFC 854)
const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

pub fn execute_command(
    device: &Device,
    command: &str,
    timeout_secs: u64,
    verbose: bool,
    on_stdout: &mut dyn FnMut(&[u8]),
) -> Result<i32, TelepromptError> {
    if device.connection_type != ConnectionType::Telnet {
        return Err(TelepromptError::Other("Device is not configured for Telnet".to_string()));
    }
    let addr = format!("{}:{}", device.host, device.port);
    if verbose {
        eprintln!("[verbose] Connecting to {}...", addr);
    }
    let socket_addrs = addr.to_socket_addrs()
        .map_err(|e| TelepromptError::ConnectionFailed(addr.clone(), e.to_string()))?;
    let socket_addr = socket_addrs.into_iter().next()
        .ok_or_else(|| TelepromptError::ConnectionFailed(addr.clone(), "No addresses resolved".to_string()))?;
    let mut stream = TcpStream::connect_timeout(
        &socket_addr,
        Duration::from_secs(timeout_secs),
    ).map_err(|e| TelepromptError::ConnectionFailed(addr.clone(), e.to_string()))?;
    if verbose {
        eprintln!("[verbose] TCP connected, awaiting login prompt...");
    }

    stream.set_read_timeout(Some(Duration::from_secs(timeout_secs)))
        .map_err(|e| TelepromptError::Io(e))?;
    stream.set_write_timeout(Some(Duration::from_secs(timeout_secs)))
        .map_err(|e| TelepromptError::Io(e))?;


    let start_time = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    // 1. Read login prompt
    let mut buffer = Vec::new();
    let username = &device.username;
    let password = device.password.as_deref().unwrap_or("");

    wait_for_prompts(&mut stream, &mut buffer, &["login:", "username:", "user:"], start_time, timeout)?;
    
    // Send username
    stream.write_all(format!("{}\r\n", username).as_bytes())
        .map_err(|e| TelepromptError::Io(e))?;
    stream.flush().map_err(|e| TelepromptError::Io(e))?;

    // 2. Read password prompt
    wait_for_prompts(&mut stream, &mut buffer, &["password:"], start_time, timeout)?;

    // Send password
    stream.write_all(format!("{}\r\n", password).as_bytes())
        .map_err(|e| TelepromptError::Io(e))?;
    stream.flush().map_err(|e| TelepromptError::Io(e))?;

    // 3. Wait for shell prompt to confirm login
    // Common prompt suffixes: "$", "#", ">"
    let prompt_suffixes = &["$", "#", ">"];
    let (matched_prompt, prompt_index) = wait_for_prompts(&mut stream, &mut buffer, prompt_suffixes, start_time, timeout)?;

    // Clear buffer up to the prompt so we only return command output
    buffer.drain(0..prompt_index + matched_prompt.len());

    // 4. Send command
    let is_sudo = command.trim().starts_with("sudo ") || command.trim() == "sudo";
    stream.write_all(format!("{}\r\n", command).as_bytes())
        .map_err(|e| TelepromptError::Io(e))?;
    stream.flush().map_err(|e| TelepromptError::Io(e))?;

    // 5. Read output
    let mut stdout_buf = Vec::new();
    let mut sudo_prompt_handled = false;

    loop {
        let mut temp_buf = [0u8; 1024];
        let bytes_read = match stream.read(&mut temp_buf) {
            Ok(0) => break, // Connection closed
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => return Err(TelepromptError::Io(e)),
        };

        // Negotiate telnet options and extract raw text
        let raw_bytes = handle_telnet_options(&mut stream, &temp_buf[..bytes_read])?;
        stdout_buf.extend_from_slice(&raw_bytes);

        let output_str = String::from_utf8_lossy(&stdout_buf);

        // Sudo password prompt detection
        if is_sudo && !sudo_prompt_handled && device.sudo_password_required {
            if contains_sudo_prompt(&output_str) {
                stream.write_all(format!("{}\r\n", password).as_bytes())
                    .map_err(|e| TelepromptError::Io(e))?;
                stream.flush().map_err(|e| TelepromptError::Io(e))?;
                sudo_prompt_handled = true;
                // Clear the output buffer to remove the prompt and password echo
                stdout_buf.clear();
                continue;
            }
        }

        // Wait for prompt to return (indicating command completed)
        if ends_with_any_prompt(&output_str, prompt_suffixes) {
            // Remove the trailing shell prompt from output
            let mut prompt_len = 0;
            for suffix in prompt_suffixes {
                if output_str.trim_end().ends_with(suffix) {
                    let trimmed = output_str.trim_end();
                    prompt_len = suffix.len() + (output_str.len() - trimmed.len());
                    break;
                }
            }
            if stdout_buf.len() >= prompt_len {
                stdout_buf.truncate(stdout_buf.len() - prompt_len);
            }
            let cleaned = clean_newlines(stdout_buf);
            if !cleaned.is_empty() {
                on_stdout(&cleaned);
            }
            break;
        }

        // Stream everything up to the last \n or \r
        if let Some(last_pos) = stdout_buf.iter().rposition(|&x| x == b'\n' || x == b'\r') {
            let streamable = stdout_buf.drain(0..=last_pos).collect::<Vec<u8>>();
            let cleaned = clean_newlines(streamable);
            if !cleaned.is_empty() {
                on_stdout(&cleaned);
            }
        }

        // If the buffer is getting large, stream the head of it (keeping the last 32 bytes just in case)
        if stdout_buf.len() > 256 {
            let stream_len = stdout_buf.len() - 32;
            let streamable = stdout_buf.drain(0..stream_len).collect::<Vec<u8>>();
            let cleaned = clean_newlines(streamable);
            if !cleaned.is_empty() {
                on_stdout(&cleaned);
            }
        }
    }

    // Telnet doesn't return exit codes natively, so we default to 0 on success
    Ok(0)
}

pub fn test_connection(device: &Device, timeout_secs: u64, verbose: bool) -> Result<(), TelepromptError> {
    // A connection test for telnet logs in and waits for the prompt
    let code = execute_command(
        device,
        "echo 'teleprompt_ok'",
        timeout_secs,
        verbose,
        &mut |_| {},
    )?;
    if code == 0 {
        Ok(())
    } else {
        Err(TelepromptError::Other("Failed to execute test command over Telnet".to_string()))
    }
}

fn wait_for_prompts(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    prompts: &[&str],
    start_time: Instant,
    timeout: Duration,
) -> Result<(String, usize), TelepromptError> {
    loop {
        if start_time.elapsed() > timeout {
            return Err(TelepromptError::Timeout(timeout.as_secs()));
        }

        // Check if we already have one of the prompts in the buffer
        let buffer_str = String::from_utf8_lossy(buffer);
        for prompt in prompts {
            if let Some(idx) = buffer_str.to_lowercase().rfind(&prompt.to_lowercase()) {
                return Ok((prompt.to_string(), idx));
            }
        }

        let mut temp_buf = [0u8; 1024];
        match stream.read(&mut temp_buf) {
            Ok(0) => return Err(TelepromptError::ConnectionFailed("".to_string(), "Connection closed by remote host".to_string())),
            Ok(n) => {
                let raw_bytes = handle_telnet_options(stream, &temp_buf[..n])?;
                buffer.extend_from_slice(&raw_bytes);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(TelepromptError::Io(e)),
        }
    }
}

fn ends_with_any_prompt(s: &str, prompts: &[&str]) -> bool {
    let trimmed = s.trim_end();
    for prompt in prompts {
        if trimmed.ends_with(prompt) {
            return true;
        }
    }
    false
}

fn contains_sudo_prompt(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.contains("password for") || lower.contains("[sudo]") || lower.contains("password:")
}

fn clean_newlines(bytes: Vec<u8>) -> Vec<u8> {
    let mut cleaned = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                cleaned.push(b'\n');
                i += 2;
                continue;
            }
        }
        cleaned.push(bytes[i]);
        i += 1;
    }
    cleaned
}

/// Parses Telnet protocol negotiations (IAC commands) and returns clean text bytes.
/// Responds to the stream for any options we decline (WONT/DONT).
fn handle_telnet_options(stream: &mut TcpStream, data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut clean_data = Vec::with_capacity(data.len());
    let mut i = 0;

    while i < data.len() {
        if data[i] == IAC {
            if i + 1 >= data.len() {
                break; // Incomplete command
            }
            let command = data[i + 1];
            match command {
                WILL | WONT | DO | DONT => {
                    if i + 2 >= data.len() {
                        break; // Incomplete option negotiation
                    }
                    let option = data[i + 2];
                    
                    // Reply to negotiation
                    let response = match command {
                        WILL => vec![IAC, DONT, option], // We don't want them doing it
                        DO => vec![IAC, WONT, option],   // We won't do it
                        _ => vec![],                     // No reply needed for WONT/DONT
                    };
                    
                    if !response.is_empty() {
                        stream.write_all(&response)?;
                        stream.flush()?;
                    }
                    i += 3;
                }
                SB => {
                    // Subnegotiation: skip until IAC SE
                    i += 2;
                    while i < data.len() {
                        if data[i] == IAC {
                            if i + 1 < data.len() && data[i + 1] == SE {
                                i += 2;
                                break;
                            }
                        }
                        i += 1;
                    }
                }
                _ => {
                    // Other 2-byte commands
                    i += 2;
                }
            }
        } else {
            clean_data.push(data[i]);
            i += 1;
        }
    }

    Ok(clean_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ends_with_any_prompt() {
        let prompts = &["$", "#", ">"];
        assert!(ends_with_any_prompt("user@host:~$", prompts));
        assert!(ends_with_any_prompt("root@host:~# ", prompts)); // trailing whitespace trimmed
        assert!(ends_with_any_prompt("router>", prompts));
        assert!(!ends_with_any_prompt("normal text", prompts));
        assert!(!ends_with_any_prompt("", prompts));
    }

    #[test]
    fn test_contains_sudo_prompt() {
        assert!(contains_sudo_prompt("[sudo] password for admin:"));
        assert!(contains_sudo_prompt("password:"));
        assert!(contains_sudo_prompt("Password:"));
        assert!(!contains_sudo_prompt("normal prompt $"));
    }

    #[test]
    fn test_clean_newlines() {
        let input = b"line1\r\nline2\r\nline3\r".to_vec();
        let expected = b"line1\nline2\nline3\r".to_vec();
        assert_eq!(clean_newlines(input), expected);

        let input_no_cr = b"line1\nline2\n".to_vec();
        assert_eq!(clean_newlines(input_no_cr.clone()), input_no_cr);
    }
}

