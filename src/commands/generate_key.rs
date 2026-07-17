use crate::error::TelepromptError;
use crate::ssh_key::{self, GenerateKeyOutcome};

pub fn run() -> Result<(), TelepromptError> {
    let home = dirs::home_dir()
        .ok_or_else(|| TelepromptError::Other("Could not find home directory".to_string()))?;

    match ssh_key::generate_default_keypair(&home)? {
        GenerateKeyOutcome::Generated {
            private_key,
            public_key,
        } => {
            println!("Generated Ed25519 SSH key pair:");
            println!("  Private key: {}", private_key.display());
            println!("  Public key:  {}", public_key.display());
            println!("Install the public key on a remote host before using it for authentication.");
        }
        GenerateKeyOutcome::AlreadyExists {
            private_key,
            public_key,
        } => {
            println!("SSH key was not changed because a destination file already exists:");
            println!("  Private key: {}", private_key.display());
            println!("  Public key:  {}", public_key.display());
        }
    }

    Ok(())
}
