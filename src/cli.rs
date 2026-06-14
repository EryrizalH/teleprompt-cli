use clap::{Parser, Subcommand};
use std::ffi::OsString;

#[derive(Parser, Debug)]
#[command(
    name = "teleprompt",
    about = "Secure remote device management CLI for AI agents",
    version = env!("CARGO_PKG_VERSION"),
    allow_external_subcommands = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Override the connection timeout (in seconds). Does not affect command execution duration.
    #[arg(long, global = true, default_value = "30")]
    pub timeout: u64,

    /// Verbose output for debugging connection issues
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// Custom path to the encrypted credential store
    #[arg(long, global = true)]
    pub db_path: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize the encrypted credential store and set master password
    Init,

    /// Add a new remote device (SSH/Telnet)
    Add,

    /// Remove a registered remote device
    Remove {
        /// Name of the device to remove
        name: String,
    },

    /// Edit credentials/details of an existing device
    Edit {
        /// Name of the device to edit
        name: String,
    },

    /// List all registered remote devices (passwords masked)
    List,

    /// Test the connection to a registered device
    Test {
        /// Name of the device to test
        name: String,
    },

    /// Install AI Agent instructions (SKILL.md) to the current directory
    #[command(name = "install-skill")]
    InstallSkill,

    // Catch-all for executing commands on a device
    // E.g. `teleprompt deviceA ls -la`
    #[command(external_subcommand)]
    External(Vec<OsString>),
}
