pub mod add;
pub mod edit;
pub mod exec;
pub mod generate_key;
pub mod import_ssh;
pub mod init;
pub mod install_skill;
pub mod list;
pub mod remove;
pub mod test;

use std::io::Write;

use crate::credentials::{should_detect_sudo, ConnectionType, Device};
use crate::error::TelepromptError;
use crate::{ssh, telnet};

pub fn get_master_key_path() -> Result<std::path::PathBuf, crate::error::TelepromptError> {
    let home_dir = dirs::home_dir().ok_or_else(|| {
        crate::error::TelepromptError::Other("Could not find home directory".to_string())
    })?;
    Ok(home_dir.join(".teleprompt").join("master.key"))
}

/// Returns the path to the known_hosts file
pub fn get_known_hosts_path() -> Result<std::path::PathBuf, crate::error::TelepromptError> {
    let home_dir = dirs::home_dir().ok_or_else(|| {
        crate::error::TelepromptError::Other("Could not find home directory".to_string())
    })?;
    Ok(home_dir.join(".teleprompt").join("known_hosts"))
}

// Helper to get master password from env var, key file, or prompt the user
pub fn get_master_password() -> Result<String, crate::error::TelepromptError> {
    if let Ok(pwd) = std::env::var("TELEPROMPT_KEY") {
        if !pwd.is_empty() {
            return Ok(pwd);
        }
    }

    // Try reading from master.key file
    if let Ok(key_path) = get_master_key_path() {
        if key_path.exists() {
            if let Ok(pwd) = std::fs::read_to_string(&key_path) {
                let pwd = pwd.trim();
                if !pwd.is_empty() {
                    return Ok(pwd.to_string());
                }
            }
        }
    }

    // Prompt user
    print!("Enter Master Password: ");
    std::io::stdout()
        .flush()
        .map_err(crate::error::TelepromptError::Io)?;

    let pwd = rpassword::read_password().map_err(crate::error::TelepromptError::Io)?;

    if pwd.is_empty() {
        return Err(crate::error::TelepromptError::InvalidPassword);
    }

    Ok(pwd)
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

pub fn save_master_password(password: &str) -> Result<(), crate::error::TelepromptError> {
    let key_path = get_master_key_path()?;
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).map_err(crate::error::TelepromptError::Io)?;
    }

    // Write password
    std::fs::write(&key_path, password).map_err(crate::error::TelepromptError::Io)?;

    // Set secure permissions
    let _ = set_owner_only_permissions(&key_path);

    Ok(())
}

/// Tests connectivity and enriches Linux SSH devices with sudo capability details.
pub fn test_and_prepare_device(
    device: &mut Device,
    timeout_secs: u64,
    verbose: bool,
) -> Result<(), TelepromptError> {
    match device.connection_type {
        ConnectionType::Ssh => ssh::test_connection(device, timeout_secs, verbose)?,
        ConnectionType::Telnet => telnet::test_connection(device, timeout_secs, verbose)?,
    }

    if should_detect_sudo(&device.connection_type, device.os_type) {
        // Commit probe results only after the complete sudo check succeeds.
        let mut checked_device = device.clone();
        if ssh::detect_sudo_capability(&mut checked_device, timeout_secs).is_ok() {
            device.sudo_capable = checked_device.sudo_capable;
            device.sudo_password_required = checked_device.sudo_password_required;
        }
    }

    Ok(())
}
