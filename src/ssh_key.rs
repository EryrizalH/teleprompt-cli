use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

use crate::error::TelepromptError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateKeyOutcome {
    Generated {
        private_key: PathBuf,
        public_key: PathBuf,
    },
    AlreadyExists {
        private_key: PathBuf,
        public_key: PathBuf,
    },
}

pub fn generate_default_keypair(home: &Path) -> Result<GenerateKeyOutcome, TelepromptError> {
    generate_keypair(&home.join(".ssh").join("teleprompt_ed25519"))
}

fn generate_keypair(private_path: &Path) -> Result<GenerateKeyOutcome, TelepromptError> {
    let mut public_name = private_path.as_os_str().to_os_string();
    public_name.push(".pub");
    let public_path = PathBuf::from(public_name);
    if private_path.exists() || public_path.exists() {
        return Ok(GenerateKeyOutcome::AlreadyExists {
            private_key: private_path.to_path_buf(),
            public_key: public_path,
        });
    }

    let parent = private_path.parent().ok_or_else(|| {
        TelepromptError::Other("SSH key path has no parent directory".to_string())
    })?;
    let parent_existed = parent.exists();
    fs::create_dir_all(parent)?;
    if !parent_existed {
        set_directory_permissions(parent)?;
    }

    let private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|error| {
        TelepromptError::Other(format!("Failed to generate Ed25519 key: {error}"))
    })?;
    let private_openssh = private_key.to_openssh(LineEnding::LF).map_err(|error| {
        TelepromptError::Other(format!("Failed to encode private key: {error}"))
    })?;
    let public_openssh = private_key
        .public_key()
        .to_openssh()
        .map_err(|error| TelepromptError::Other(format!("Failed to encode public key: {error}")))?;

    let mut private_file = open_private_key(private_path)?;
    if let Err(error) = private_file
        .write_all(private_openssh.as_bytes())
        .and_then(|_| private_file.sync_all())
    {
        let _ = fs::remove_file(private_path);
        return Err(TelepromptError::Io(error));
    }

    let mut public_file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&public_path)
    {
        Ok(file) => file,
        Err(error) => {
            let _ = fs::remove_file(private_path);
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                return Ok(GenerateKeyOutcome::AlreadyExists {
                    private_key: private_path.to_path_buf(),
                    public_key: public_path,
                });
            }
            return Err(TelepromptError::Io(error));
        }
    };

    if let Err(error) = public_file
        .write_all(public_openssh.as_bytes())
        .and_then(|_| public_file.write_all(b" teleprompt\n"))
        .and_then(|_| public_file.sync_all())
    {
        let _ = fs::remove_file(private_path);
        // This invocation created the public file, so it is safe to clean it up.
        let _ = fs::remove_file(&public_path);
        return Err(TelepromptError::Io(error));
    }

    Ok(GenerateKeyOutcome::Generated {
        private_key: private_path.to_path_buf(),
        public_key: public_path,
    })
}

#[cfg(unix)]
fn open_private_key(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private_key(path: &Path) -> std::io::Result<std::fs::File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<(), TelepromptError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<(), TelepromptError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::PublicKey;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_home() -> PathBuf {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("teleprompt-ssh-key-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn generates_matching_openssh_keypair() {
        let home = temp_home();
        let outcome = generate_default_keypair(&home).unwrap();
        let GenerateKeyOutcome::Generated {
            private_key,
            public_key,
        } = outcome
        else {
            panic!("expected generated keypair");
        };

        let private_text = fs::read_to_string(private_key).unwrap();
        let public_text = fs::read_to_string(public_key).unwrap();
        let private = PrivateKey::from_openssh(&private_text).unwrap();
        let public = PublicKey::from_openssh(public_text.trim()).unwrap();
        assert_eq!(private.algorithm(), Algorithm::Ed25519);
        assert_eq!(private.public_key().key_data(), public.key_data());

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn never_overwrites_an_existing_key_file() {
        let home = temp_home();
        let private_path = home.join(".ssh").join("teleprompt_ed25519");
        fs::create_dir_all(private_path.parent().unwrap()).unwrap();
        fs::write(&private_path, "existing secret").unwrap();

        let outcome = generate_default_keypair(&home).unwrap();
        assert!(matches!(outcome, GenerateKeyOutcome::AlreadyExists { .. }));
        assert_eq!(fs::read_to_string(private_path).unwrap(), "existing secret");

        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn never_removes_an_existing_public_key_file() {
        let home = temp_home();
        let public_path = home.join(".ssh").join("teleprompt_ed25519.pub");
        fs::create_dir_all(public_path.parent().unwrap()).unwrap();
        fs::write(&public_path, "existing public key").unwrap();

        let outcome = generate_default_keypair(&home).unwrap();
        assert!(matches!(outcome, GenerateKeyOutcome::AlreadyExists { .. }));
        assert_eq!(
            fs::read_to_string(&public_path).unwrap(),
            "existing public key"
        );
        assert!(!home.join(".ssh").join("teleprompt_ed25519").exists());

        let _ = fs::remove_dir_all(home);
    }

    #[cfg(unix)]
    #[test]
    fn private_key_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let home = temp_home();
        let outcome = generate_default_keypair(&home).unwrap();
        let GenerateKeyOutcome::Generated { private_key, .. } = outcome else {
            panic!("expected generated keypair");
        };
        let mode = fs::metadata(private_key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = fs::remove_dir_all(home);
    }
}
