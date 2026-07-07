use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Reject connection if host not in known_hosts or key mismatches
    Strict,
    /// Accept new hosts automatically, verify existing ones
    AcceptNew,
    /// Skip host key verification entirely (insecure)
    Off,
}

impl Default for HostKeyPolicy {
    fn default() -> Self {
        HostKeyPolicy::AcceptNew
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ConnectionType {
    Ssh,
    Telnet,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsType {
    Linux,
    Windows,
    RouterOs,
    CiscoIos,
    JunOs,
    Generic,
}

impl Default for OsType {
    fn default() -> Self {
        OsType::Generic
    }
}

impl std::fmt::Display for OsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            OsType::Linux => "Linux",
            OsType::Windows => "Windows",
            OsType::RouterOs => "RouterOS (MikroTik)",
            OsType::CiscoIos => "Cisco IOS",
            OsType::JunOs => "JunOS",
            OsType::Generic => "Generic/Other",
        };
        write!(f, "{}", s)
    }
}

impl OsType {
    pub fn prompt_selection(current: Option<OsType>) -> Result<Self, TelepromptError> {
        println!("Select Operating System:");
        println!("1) Linux");
        println!("2) Windows");
        println!("3) RouterOS (MikroTik)");
        println!("4) Cisco IOS");
        println!("5) JunOS");
        println!("6) Generic/Other");

        let default_val = match current {
            Some(OsType::Linux) => "1",
            Some(OsType::Windows) => "2",
            Some(OsType::RouterOs) => "3",
            Some(OsType::CiscoIos) => "4",
            Some(OsType::JunOs) => "5",
            None | Some(OsType::Generic) => "6",
        };

        loop {
            print!("Enter choice (1-6) [{}]: ", default_val);
            std::io::stdout().flush().map_err(TelepromptError::Io)?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).map_err(TelepromptError::Io)?;
            let input = input.trim();
            let selected = if input.is_empty() {
                default_val
            } else {
                input
            };

            match selected {
                "1" => return Ok(OsType::Linux),
                "2" => return Ok(OsType::Windows),
                "3" => return Ok(OsType::RouterOs),
                "4" => return Ok(OsType::CiscoIos),
                "5" => return Ok(OsType::JunOs),
                "6" => return Ok(OsType::Generic),
                _ => println!("Invalid choice. Please select a number from 1 to 6."),
            }
        }
    }
}

pub fn should_detect_sudo(connection_type: &ConnectionType, os_type: OsType) -> bool {
    *connection_type == ConnectionType::Ssh && os_type == OsType::Linux
}

#[derive(Serialize, Deserialize, Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Device {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub key_path: Option<String>,
    #[serde(default)]
    pub key_passphrase: Option<String>,
    #[zeroize(skip)]
    pub connection_type: ConnectionType,
    #[zeroize(skip)]
    pub sudo_capable: bool,
    #[zeroize(skip)]
    pub sudo_password_required: bool,
    #[zeroize(skip)]
    #[serde(default)]
    pub os_type: OsType,
    #[zeroize(skip)]
    #[serde(default)]
    pub host_key_policy: HostKeyPolicy,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CredentialStore {
    pub devices: HashMap<String, Device>,
}

use crate::error::TelepromptError;

/// Returns the default path to the credentials file (~/.teleprompt/credentials.enc)
pub fn get_default_db_path() -> Result<PathBuf, TelepromptError> {
    let home_dir = dirs::home_dir()
        .ok_or_else(|| TelepromptError::Other("Could not find home directory".to_string()))?;
    Ok(home_dir.join(".teleprompt").join("credentials.enc"))
}

/// Loads and decrypts the credential store from the specified path.
/// If the file does not exist, returns an empty CredentialStore.
pub fn load_store<P: AsRef<Path>>(path: P, password: &str) -> Result<CredentialStore, TelepromptError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(CredentialStore::default());
    }

    let encrypted_data = fs::read(path)?;
    let decrypted_json = crypto::decrypt(&encrypted_data, password)
        .map_err(|_e| TelepromptError::InvalidPassword)?;
    
    let store: CredentialStore = serde_json::from_slice(&decrypted_json)
        .map_err(|e| TelepromptError::CryptoOrSerial(e.to_string()))?;
    Ok(store)
}

/// Encrypts and saves the credential store to the specified path.
pub fn save_store<P: AsRef<Path>>(
    store: &CredentialStore,
    path: P,
    password: &str,
) -> Result<(), TelepromptError> {
    let path = path.as_ref();
    
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json_bytes = serde_json::to_vec(store)
        .map_err(|e| TelepromptError::CryptoOrSerial(e.to_string()))?;
    let encrypted_data = crypto::encrypt(&json_bytes, password)
        .map_err(|e| TelepromptError::CryptoOrSerial(e.to_string()))?;
    
    // Write atomically
    let temp_path = path.with_extension("tmp");
    let mut file = File::create(&temp_path)?;
    file.write_all(&encrypted_data)?;
    file.sync_all()?;
    
    fs::rename(temp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_device(name: &str, conn: ConnectionType) -> Device {
        Device {
            name: name.to_string(),
            host: "127.0.0.1".to_string(),
            port: if conn == ConnectionType::Telnet { 23 } else { 22 },
            username: "admin".to_string(),
            password: Some("test123".to_string()),
            key_path: None,
            key_passphrase: None,
            connection_type: conn,
            sudo_capable: false,
            sudo_password_required: false,
            os_type: OsType::Linux,
            host_key_policy: HostKeyPolicy::AcceptNew,
        }
    }

    #[test]
    fn test_store_crud_operations() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("teleprompt_test_db.enc");
        if db_path.exists() {
            let _ = std::fs::remove_file(&db_path);
        }

        let password = "master_pwd_123";

        // 1. Load non-existent store (should be empty)
        let mut store = load_store(&db_path, password).expect("Failed to load empty store");
        assert!(store.devices.is_empty());

        // 2. Add device
        let dev1 = make_device("test_srv", ConnectionType::Ssh);

        store.devices.insert(dev1.name.clone(), dev1);
        save_store(&store, &db_path, password).expect("Failed to save store");

        // 3. Load again and verify
        let loaded_store = load_store(&db_path, password).expect("Failed to load saved store");
        assert_eq!(loaded_store.devices.len(), 1);
        let loaded_dev = loaded_store.devices.get("test_srv").unwrap();
        assert_eq!(loaded_dev.host, "127.0.0.1");
        assert_eq!(loaded_dev.password.as_deref(), Some("test123"));
        assert_eq!(loaded_dev.os_type, OsType::Linux);
        assert_eq!(loaded_dev.key_passphrase, None);
        assert_eq!(loaded_dev.host_key_policy, HostKeyPolicy::AcceptNew);

        // 4. Delete file
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_load_store_invalid_password() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("teleprompt_test_invalid_pwd_db.enc");
        if db_path.exists() {
            let _ = std::fs::remove_file(&db_path);
        }

        let password = "correct_password";
        let wrong_password = "wrong_password";

        let mut store = CredentialStore::default();
        let dev = make_device("test_srv", ConnectionType::Ssh);
        store.devices.insert(dev.name.clone(), dev);

        save_store(&store, &db_path, password).expect("Failed to save store");

        // Loading with wrong password should fail with InvalidPassword
        let load_res = load_store(&db_path, wrong_password);
        assert!(load_res.is_err());
        match load_res.unwrap_err() {
            TelepromptError::InvalidPassword => {}
            other => panic!("Expected TelepromptError::InvalidPassword, got: {:?}", other),
        }

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_load_store_corrupted_data() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("teleprompt_test_corrupt_db.enc");
        if db_path.exists() {
            let _ = std::fs::remove_file(&db_path);
        }

        // Write corrupt/invalid non-crypto data (too short)
        std::fs::write(&db_path, b"too_short").expect("Failed to write corrupt data");
        let load_res = load_store(&db_path, "password");
        assert!(load_res.is_err());
        match load_res.unwrap_err() {
            TelepromptError::InvalidPassword => {}
            other => panic!("Expected TelepromptError::InvalidPassword, got: {:?}", other),
        }

        // Write corrupt but long enough non-crypto data
        std::fs::write(&db_path, vec![0u8; 100]).expect("Failed to write corrupt data");
        let load_res = load_store(&db_path, "password");
        assert!(load_res.is_err());
        match load_res.unwrap_err() {
            TelepromptError::InvalidPassword => {}
            other => panic!("Expected TelepromptError::InvalidPassword, got: {:?}", other),
        }

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_store_multiple_devices_and_types() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("teleprompt_test_multi_db.enc");
        if db_path.exists() {
            let _ = std::fs::remove_file(&db_path);
        }

        let password = "pwd";
        let mut store = CredentialStore::default();

        let mut ssh_dev = make_device("ssh_device", ConnectionType::Ssh);
        ssh_dev.key_path = Some("/path/to/key".to_string());
        ssh_dev.key_passphrase = Some("key_pass".to_string());
        ssh_dev.sudo_capable = true;
        ssh_dev.sudo_password_required = true;

        let telnet_dev = make_device("telnet_device", ConnectionType::Telnet);

        store.devices.insert(ssh_dev.name.clone(), ssh_dev);
        store.devices.insert(telnet_dev.name.clone(), telnet_dev.clone());

        save_store(&store, &db_path, password).expect("Failed to save store");

        let loaded = load_store(&db_path, password).expect("Failed to load store");
        assert_eq!(loaded.devices.len(), 2);

        let loaded_ssh = loaded.devices.get("ssh_device").expect("Missing ssh device");
        assert_eq!(loaded_ssh.connection_type, ConnectionType::Ssh);
        assert_eq!(loaded_ssh.key_path.as_deref(), Some("/path/to/key"));
        assert_eq!(loaded_ssh.key_passphrase.as_deref(), Some("key_pass"));
        assert!(loaded_ssh.sudo_capable);
        assert_eq!(loaded_ssh.os_type, OsType::Linux);

        let loaded_telnet = loaded.devices.get("telnet_device").expect("Missing telnet device");
        assert_eq!(loaded_telnet.connection_type, ConnectionType::Telnet);
        assert_eq!(loaded_telnet.key_path, None);
        assert_eq!(loaded_telnet.key_passphrase, None);
        assert!(!loaded_telnet.sudo_capable);
        assert_eq!(loaded_telnet.host_key_policy, HostKeyPolicy::AcceptNew);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_should_detect_sudo_only_for_ssh_linux() {
        assert!(should_detect_sudo(&ConnectionType::Ssh, OsType::Linux));
        assert!(!should_detect_sudo(&ConnectionType::Telnet, OsType::Linux));

        for os_type in [
            OsType::Windows,
            OsType::RouterOs,
            OsType::CiscoIos,
            OsType::JunOs,
            OsType::Generic,
        ] {
            assert!(!should_detect_sudo(&ConnectionType::Ssh, os_type));
        }
    }
}
