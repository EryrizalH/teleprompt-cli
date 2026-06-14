use std::io::Write;
use std::path::Path;

use crate::commands::get_master_password;
use crate::credentials::{self, ConnectionType};
use crate::error::TelepromptError;
use crate::{ssh, telnet};

pub fn run(
    db_path: Option<&Path>,
    name: &str,
    command_args: &[String],
    timeout_secs: u64,
    verbose: bool,
) -> Result<i32, TelepromptError> {
    let resolved_path = match db_path {
        Some(p) => p.to_path_buf(),
        None => credentials::get_default_db_path()?,
    };

    if !resolved_path.exists() {
        return Err(TelepromptError::NotInitialized);
    }

    let master_pwd = get_master_password()?;
    let store = credentials::load_store(&resolved_path, &master_pwd)?;

    let device = store.devices.get(name)
        .ok_or_else(|| TelepromptError::DeviceNotFound(name.to_string()))?;

    // Combine args into single command
    // If command_args is empty, we default to doing nothing or throwing error
    if command_args.is_empty() {
        return Err(TelepromptError::Cli("No remote command provided".to_string()));
    }
    let command = command_args.join(" ");

    // Execute based on connection type
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    let exit_code = match device.connection_type {
        ConnectionType::Ssh => ssh::execute_command(
            device,
            &command,
            timeout_secs,
            verbose,
            &mut |data| {
                let _ = out.write_all(data);
                let _ = out.flush();
            },
            &mut |data| {
                let _ = err.write_all(data);
                let _ = err.flush();
            },
        )?,
        ConnectionType::Telnet => telnet::execute_command(
            device,
            &command,
            timeout_secs,
            verbose,
            &mut |data| {
                let _ = out.write_all(data);
                let _ = out.flush();
            },
        )?,
    };

    Ok(exit_code)
}
