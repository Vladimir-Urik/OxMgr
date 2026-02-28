//! Entry point for the `oxmgr` binary.
//!
//! The binary is intentionally thin: it configures tracing, parses CLI input,
//! loads the local application configuration, and then hands control to either
//! the daemon loop or the command dispatcher.

mod bundle;
mod cgroup;
mod cli;
mod commands;
mod config;
mod daemon;
mod ecosystem;
mod errors;
mod ipc;
mod logging;
mod oxfile;
mod process;
mod process_manager;
mod storage;
mod ui;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Commands, DaemonCommand};
use crate::config::AppConfig;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let config = AppConfig::load()?;

    match cli.command {
        Commands::Daemon {
            command: DaemonCommand::Run,
        } => daemon::run_foreground(config).await,
        command => commands::run(command, &config).await,
    }
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}
