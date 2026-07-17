use std::io::Write;
use std::path::Path;

use crate::credentials::{self, CredentialStore};
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

    if resolved_path.exists() {
        print!(
            "Credential store already exists at {}. Overwrite? (y/N): ",
            resolved_path.display()
        );
        std::io::stdout().flush().map_err(TelepromptError::Io)?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(TelepromptError::Io)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            println!("Abort initialization.");
            return Ok(());
        }
    }

    // Prompt for password
    print!("Set Master Password (used to encrypt credentials): ");
    std::io::stdout().flush().map_err(TelepromptError::Io)?;
    let password = rpassword::read_password().map_err(TelepromptError::Io)?;

    if password.trim().is_empty() {
        return Err(TelepromptError::Cli(
            "Master password cannot be empty".to_string(),
        ));
    }

    print!("Confirm Master Password: ");
    std::io::stdout().flush().map_err(TelepromptError::Io)?;
    let confirm = rpassword::read_password().map_err(TelepromptError::Io)?;

    if password != confirm {
        return Err(TelepromptError::Cli("Passwords do not match".to_string()));
    }

    let store = CredentialStore::default();
    credentials::save_store(&store, &resolved_path, &password)?;

    // Cache the master password securely in ~/.teleprompt/master.key
    super::save_master_password(&password)?;

    println!(
        "\nSuccessfully initialized empty credential store at: {}",
        resolved_path.display()
    );
    println!(
        "✔ Master password cached locally in ~/.teleprompt/master.key (owner-only permissions)."
    );
    println!("✔ Future teleprompt commands will run automatically without asking for a password.");

    if prompt_yes_no("Generate a Teleprompt Ed25519 SSH key? (y/N): ")? {
        if let Err(error) = super::generate_key::run() {
            eprintln!("Warning: SSH key generation failed: {error}");
        }
    }

    if prompt_yes_no("Detect and import devices from your SSH config? (y/N): ")? {
        if let Err(error) =
            super::import_ssh::run(Some(&resolved_path), false, false, timeout_secs, verbose)
        {
            eprintln!("Warning: SSH device import failed: {error}");
        }
    }

    Ok(())
}

fn prompt_yes_no(label: &str) -> Result<bool, TelepromptError> {
    print!("{label}");
    std::io::stdout().flush().map_err(TelepromptError::Io)?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(TelepromptError::Io)?;
    Ok(answer_is_yes(&answer))
}

fn answer_is_yes(answer: &str) -> bool {
    answer.trim().eq_ignore_ascii_case("y")
}

#[cfg(test)]
mod tests {
    use super::answer_is_yes;

    #[test]
    fn onboarding_prompts_are_opt_in() {
        assert!(answer_is_yes("y"));
        assert!(answer_is_yes("Y\n"));
        assert!(!answer_is_yes(""));
        assert!(!answer_is_yes("yes"));
        assert!(!answer_is_yes("n"));
    }
}
