use std::io::Write;
use std::path::Path;

use crate::commands::{get_master_password, test_and_prepare_device};
use crate::credentials::{self, ConnectionType, Device, HostKeyPolicy, OsType};
use crate::error::TelepromptError;

pub fn run(
    db_path: Option<&Path>,
    timeout_secs: u64,
    verbose: bool,
) -> Result<(), TelepromptError> {
    let resolved_path = match db_path {
        Some(p) => p.to_path_buf(),
        None => credentials::get_default_db_path()?,
    };

    if !resolved_path.exists() {
        return Err(TelepromptError::NotInitialized);
    }

    let master_pwd = get_master_password()?;
    let mut store = credentials::load_store(&resolved_path, &master_pwd)?;

    println!("--- Add New Device ---");

    // 1. Device name
    let name = loop {
        let n = prompt_input("Device Name", None)?;
        if n.trim().is_empty() {
            println!("Device name cannot be empty.");
            continue;
        }
        if store.devices.contains_key(&n) {
            println!("Device '{}' already exists.", n);
            continue;
        }
        break n;
    };

    // 2. Host
    let host = loop {
        let h = prompt_input("Host/IP Address", None)?;
        if h.trim().is_empty() {
            println!("Host cannot be empty.");
            continue;
        }
        break h;
    };

    // 3. Connection type
    let conn_type_str = prompt_input("Connection Type (ssh/telnet) [ssh]", Some("ssh"))?;
    let connection_type = match conn_type_str.trim().to_lowercase().as_str() {
        "telnet" => ConnectionType::Telnet,
        _ => ConnectionType::Ssh,
    };

    // 4. Port
    let default_port = match connection_type {
        ConnectionType::Ssh => "22",
        ConnectionType::Telnet => "23",
    };
    let port_str = prompt_input(&format!("Port [{}]", default_port), Some(default_port))?;
    let port: u16 = port_str.trim().parse().unwrap_or(match connection_type {
        ConnectionType::Ssh => 22,
        ConnectionType::Telnet => 23,
    });

    // 5. Username
    let username = loop {
        let u = prompt_input("Username", None)?;
        if u.trim().is_empty() {
            println!("Username cannot be empty.");
            continue;
        }
        break u;
    };

    // 6. Authentication details
    let mut password = None;
    let mut key_path = None;
    let mut key_passphrase = None;

    match connection_type {
        ConnectionType::Ssh => {
            let auth_method =
                prompt_input("Auth Method (password/key) [password]", Some("password"))?;
            if auth_method.trim().to_lowercase() == "key" {
                let kp = prompt_input("SSH Private Key Path", None)?;
                key_path = Some(kp);
                // Prompt for key passphrase
                print!("SSH Key Passphrase (optional, press Enter to skip): ");
                std::io::stdout().flush().map_err(TelepromptError::Io)?;
                let pp = rpassword::read_password().map_err(TelepromptError::Io)?;
                key_passphrase = if pp.is_empty() { None } else { Some(pp) };
                // Prompt for password anyway in case key is encrypted or we need password for sudo
                print!("Sudo/Password (optional, press Enter to skip): ");
                std::io::stdout().flush().map_err(TelepromptError::Io)?;
                let pwd = rpassword::read_password().map_err(TelepromptError::Io)?;
                if !pwd.is_empty() {
                    password = Some(pwd);
                }
            } else {
                print!("Password: ");
                std::io::stdout().flush().map_err(TelepromptError::Io)?;
                let pwd = rpassword::read_password().map_err(TelepromptError::Io)?;
                password = Some(pwd);
            }
        }
        ConnectionType::Telnet => {
            print!("Password: ");
            std::io::stdout().flush().map_err(TelepromptError::Io)?;
            let pwd = rpassword::read_password().map_err(TelepromptError::Io)?;
            password = Some(pwd);
        }
    }

    // 6. OS Type Selection
    // Host key policy (SSH only)
    let host_key_policy = match connection_type {
        ConnectionType::Ssh => prompt_host_key_policy(None)?,
        ConnectionType::Telnet => HostKeyPolicy::default(),
    };

    let os_type = OsType::prompt_selection(None)?;

    let mut device = Device {
        name: name.clone(),
        host,
        port,
        username,
        password,
        key_path,
        key_passphrase,
        connection_type: connection_type.clone(),
        sudo_capable: false,
        sudo_password_required: false,
        os_type,
        host_key_policy,
    };

    // 7. Test connection and detect sudo
    println!("\nTesting connection to {}...", device.name);
    match test_and_prepare_device(&mut device, timeout_secs, verbose) {
        Ok(()) => {
            println!("✔ Connection successful!");
            if device.os_type == OsType::Linux && connection_type == ConnectionType::Ssh {
                if device.sudo_capable {
                    println!(
                        "✔ Sudo capable (Password required: {})",
                        device.sudo_password_required
                    );
                } else {
                    println!("ℹ Sudo not available or access denied.");
                }
            }
        }
        Err(e) => {
            println!("✖ Connection failed: {}", e);
            print!("Do you still want to save this device? (y/N): ");
            std::io::stdout().flush().map_err(TelepromptError::Io)?;
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .map_err(TelepromptError::Io)?;
            if !answer.trim().eq_ignore_ascii_case("y") {
                println!("Device not saved.");
                return Ok(());
            }
        }
    }

    // 8. Save
    store.devices.insert(name.clone(), device);
    credentials::save_store(&store, &resolved_path, &master_pwd)?;

    println!("✔ Device '{}' successfully saved!", name);
    Ok(())
}

fn prompt_input(label: &str, default: Option<&str>) -> Result<String, TelepromptError> {
    print!("{}: ", label);
    std::io::stdout().flush().map_err(TelepromptError::Io)?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(TelepromptError::Io)?;
    let input = input.trim();
    if input.is_empty() {
        if let Some(def) = default {
            return Ok(def.to_string());
        }
    }
    Ok(input.to_string())
}

fn prompt_host_key_policy(
    current: Option<&HostKeyPolicy>,
) -> Result<HostKeyPolicy, TelepromptError> {
    println!("\nHost Key Verification Policy:");
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
        std::io::stdin()
            .read_line(&mut input)
            .map_err(TelepromptError::Io)?;
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
