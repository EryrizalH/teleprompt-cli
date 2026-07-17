use clap::Parser;
use std::path::Path;
use std::process;

use teleprompt_cli::cli::{Cli, Commands};
use teleprompt_cli::commands;
use teleprompt_cli::error::TelepromptError;

fn main() {
    let args = Cli::parse();

    match run_app(args) {
        Ok(exit_code) => {
            process::exit(exit_code);
        }
        Err(err) => {
            eprintln!("Error: {}", err);
            process::exit(err.exit_code());
        }
    }
}

fn run_app(args: Cli) -> Result<i32, TelepromptError> {
    let db_path = args.db_path.as_ref().map(Path::new);
    let timeout = args.timeout;
    let verbose = args.verbose;

    match args.command {
        Some(Commands::Init) => {
            commands::init::run(db_path, timeout, verbose)?;
            Ok(0)
        }
        Some(Commands::Add) => {
            commands::add::run(db_path, timeout, verbose)?;
            Ok(0)
        }
        Some(Commands::Import { all, yes }) => {
            commands::import_ssh::run(db_path, all, yes, timeout, verbose)?;
            Ok(0)
        }
        Some(Commands::GenerateKey) => {
            commands::generate_key::run()?;
            Ok(0)
        }
        Some(Commands::Remove { name }) => {
            commands::remove::run(db_path, &name)?;
            Ok(0)
        }
        Some(Commands::Edit { name }) => {
            commands::edit::run(db_path, &name, timeout, verbose)?;
            Ok(0)
        }
        Some(Commands::List) => {
            commands::list::run(db_path)?;
            Ok(0)
        }
        Some(Commands::Test { name }) => {
            commands::test::run(db_path, &name, timeout, verbose)?;
            Ok(0)
        }
        Some(Commands::InstallSkill) => {
            commands::install_skill::run()?;
            Ok(0)
        }
        Some(Commands::External(ext_args)) => {
            if ext_args.is_empty() {
                // Should not happen with Clap subcommands, but handle safely
                eprintln!("No device or command specified. Run 'teleprompt --help' for help.");
                return Ok(1);
            }

            let string_args: Vec<String> = ext_args
                .into_iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();

            let device_name = &string_args[0];
            let cmd_args = &string_args[1..];

            if cmd_args.is_empty() {
                return Err(TelepromptError::Cli(format!(
                    "No remote command provided for device '{}'. Usage: teleprompt {} <command>...",
                    device_name, device_name
                )));
            }

            let exit_code = commands::exec::run(db_path, device_name, cmd_args, timeout, verbose)?;
            Ok(exit_code)
        }
        None => {
            // No subcommand or external arguments passed
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            cmd.print_help()
                .map_err(|e| TelepromptError::Other(e.to_string()))?;
            println!(); // Print newline
            Ok(0)
        }
    }
}
