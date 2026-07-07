use std::io::Write;
use std::path::Path;

use crate::commands::get_master_password;
use crate::credentials::{self, should_detect_sudo, ConnectionType, OsType, HostKeyPolicy};
use crate::error::TelepromptError;
use crate::{ssh, telnet};

pub fn run(db_path: Option<&Path>, name: &str, timeout_secs: u64, verbose: bool) -> Result<(), TelepromptError> {
    let resolved_path = match db_path {
        Some(p) => p.to_path_buf(),
        None => credentials::get_default_db_path()?,
    };

    if !resolved_path.exists() {
        return Err(TelepromptError::NotInitialized);
    }

    let master_pwd = get_master_password()?;
    let mut store = credentials::load_store(&resolved_path, &master_pwd)?;

    let mut device = store.devices.get(name)
        .ok_or_else(|| TelepromptError::DeviceNotFound(name.to_string()))?
        .clone();

    println!("--- Edit Device '{}' (Press Enter to keep current value) ---", name);

    // 1. Host
    let host = prompt_input("Host/IP Address", Some(&device.host))?;
    let host_changed = host != device.host;
    device.host = host;

    // 2. Connection Type
    let current_type_str = match device.connection_type {
        ConnectionType::Ssh => "ssh",
        ConnectionType::Telnet => "telnet",
    };
    let conn_type_str = prompt_input("Connection Type (ssh/telnet)", Some(current_type_str))?;
    let new_conn_type = match conn_type_str.trim().to_lowercase().as_str() {
        "telnet" => ConnectionType::Telnet,
        _ => ConnectionType::Ssh,
    };
    let type_changed = new_conn_type != device.connection_type;
    device.connection_type = new_conn_type;

    // 3. Port
    let current_port_str = device.port.to_string();
    let port_str = prompt_input("Port", Some(&current_port_str))?;
    let new_port: u16 = port_str.trim().parse().unwrap_or(device.port);
    let port_changed = new_port != device.port;
    device.port = new_port;

    // 4. Username
    let username = prompt_input("Username", Some(&device.username))?;
    let username_changed = username != device.username;
    device.username = username;

    // 5. Auth / Password / Key
    let mut auth_changed = false;
    match device.connection_type {
        ConnectionType::Ssh => {
            let current_auth_method = if device.key_path.is_some() { "key" } else { "password" };
            let auth_method = prompt_input("Auth Method (password/key)", Some(current_auth_method))?;
            
            if auth_method.trim().to_lowercase() == "key" {
                let default_key = device.key_path.as_deref().unwrap_or("");
                let kp = prompt_input("SSH Private Key Path", Some(default_key))?;
                if device.key_path.as_deref() != Some(&kp) {
                    device.key_path = Some(kp);
                    auth_changed = true;
                }

                // Prompt for key passphrase update
                let current_pp = device.key_passphrase.as_deref().unwrap_or("");
                let current_pp_label = if current_pp.is_empty() { "(not set)" } else { "(set, hidden)" };
                print!("Update SSH Key Passphrase {} (press Enter to keep): ", current_pp_label);
                std::io::stdout().flush().map_err(TelepromptError::Io)?;
                let pp = rpassword::read_password().map_err(TelepromptError::Io)?;
                if !pp.is_empty() {
                    device.key_passphrase = Some(pp);
                    auth_changed = true;
                }

                
                print!("Update Sudo/Password (optional, press Enter to skip): ");
                std::io::stdout().flush().map_err(TelepromptError::Io)?;
                let pwd = rpassword::read_password().map_err(TelepromptError::Io)?;
                if !pwd.is_empty() {
                    device.password = Some(pwd);
                    auth_changed = true;
                }
            } else {
                device.key_path = None;
                device.key_passphrase = None;
                print!("Update Password (press Enter to keep current): ");
                std::io::stdout().flush().map_err(TelepromptError::Io)?;
                let pwd = rpassword::read_password().map_err(TelepromptError::Io)?;
                if !pwd.is_empty() {
                    device.password = Some(pwd);
                    auth_changed = true;
                }
            }
        }
        ConnectionType::Telnet => {
            device.key_path = None;
            device.key_passphrase = None;
            print!("Update Password (press Enter to keep current): ");
            std::io::stdout().flush().map_err(TelepromptError::Io)?;
            let pwd = rpassword::read_password().map_err(TelepromptError::Io)?;
            if !pwd.is_empty() {
                device.password = Some(pwd);
                auth_changed = true;
            }
        }
    }

    // 6. OS Type
    println!();
    let os_type = OsType::prompt_selection(Some(device.os_type))?;
    let os_type_changed = os_type != device.os_type;
    device.os_type = os_type;

    // 7. Host key policy (SSH only)
    let hk_changed;
    if device.connection_type == ConnectionType::Ssh {
        println!();
        let policy = prompt_host_key_policy(Some(&device.host_key_policy))?;
        hk_changed = policy != device.host_key_policy;
        device.host_key_policy = policy;
    } else {
        hk_changed = false;
    }

    let credentials_changed = host_changed || type_changed || port_changed || username_changed || auth_changed || os_type_changed || hk_changed;

    if credentials_changed {
        println!("\nTesting updated connection details...");
        let test_res = match device.connection_type {
            ConnectionType::Ssh => ssh::test_connection(&device, timeout_secs, verbose),
            ConnectionType::Telnet => telnet::test_connection(&device, timeout_secs, verbose),
        };

        match test_res {
            Ok(_) => {
                println!("✔ Connection successful!");
                if should_detect_sudo(&device.connection_type, device.os_type) {
                    println!("Checking sudo capability...");
                    let mut mock_device = device.clone();
                    if let Ok(_) = ssh::detect_sudo_capability(&mut mock_device, timeout_secs) {
                        device.sudo_capable = mock_device.sudo_capable;
                        device.sudo_password_required = mock_device.sudo_password_required;
                        if device.sudo_capable {
                            println!("✔ Sudo capable (Password required: {})", device.sudo_password_required);
                        } else {
                            println!("ℹ Sudo not available or access denied.");
                        }
                    }
                }
            }
            Err(e) => {
                println!("✖ Connection test failed: {}", e);
                print!("Do you still want to save these changes? (y/N): ");
                std::io::stdout().flush().map_err(TelepromptError::Io)?;
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer).map_err(TelepromptError::Io)?;
                if !answer.trim().eq_ignore_ascii_case("y") {
                    println!("Changes not saved.");
                    return Ok(());
                }
            }
        }
    }

    // Save
    store.devices.insert(name.to_string(), device);
    credentials::save_store(&store, &resolved_path, &master_pwd)?;

    println!("✔ Device '{}' updated successfully!", name);
    Ok(())
}

fn prompt_input(label: &str, current: Option<&str>) -> Result<String, TelepromptError> {
    if let Some(curr) = current {
        if curr.is_empty() {
            print!("{}: ", label);
        } else {
            print!("{} [{}]: ", label, curr);
        }
    } else {
        print!("{}: ", label);
    }
    
    std::io::stdout().flush().map_err(TelepromptError::Io)?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).map_err(TelepromptError::Io)?;
    let input = input.trim();
    if input.is_empty() {
        if let Some(curr) = current {
            return Ok(curr.to_string());
        }
    }
    Ok(input.to_string())
}

fn prompt_host_key_policy(current: Option<&HostKeyPolicy>) -> Result<HostKeyPolicy, TelepromptError> {
    println!("Host Key Verification Policy:");
    println!("1) AcceptNew — accept new hosts, verify existing (recommended)");
    println!("2) Strict — reject unknown hosts");
    println!("3) Off — skip verification (insecure)");

    let default_val = match current {
        None | Some(HostKeyPolicy::AcceptNew) => "1",
        Some(HostKeyPolicy::Strict) => "2",
        Some(HostKeyPolicy::Off) => "3",
    };

    loop {
        print!("Enter choice (1-3) [{}]: ", default_val);
        std::io::stdout().flush().map_err(TelepromptError::Io)?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).map_err(TelepromptError::Io)?;
        let input = input.trim();
        let selected = if input.is_empty() { default_val } else { input };

        match selected {
            "1" => return Ok(HostKeyPolicy::AcceptNew),
            "2" => return Ok(HostKeyPolicy::Strict),
            "3" => return Ok(HostKeyPolicy::Off),
            _ => println!("Invalid choice. Please select 1, 2, or 3."),
        }
    }
}
