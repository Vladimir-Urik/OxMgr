//! Command dispatcher for the non-daemon `oxmgr` CLI entry points.

mod apply;
mod common;
mod convert;
mod daemon_stop;
mod delete;
mod deploy;
mod doctor;
mod events;
mod export;
mod import;
mod list;
mod logs;
mod pull;
mod reload;
mod restart;
mod runtime;
mod service;
mod start;
mod startup;
mod status;
mod stop;
mod ui;
mod validate;

use anyhow::Result;

use crate::cli::{Commands, DaemonCommand};
use crate::config::AppConfig;

/// Dispatches one parsed CLI command to its concrete implementation.
pub async fn run(command: Commands, config: &AppConfig) -> Result<()> {
    if let Commands::Start(start) = &command {
        start::validate_flags(start)?;
    }

    let needs_daemon = !matches!(
        command,
        Commands::Startup { .. }
            | Commands::Service { .. }
            | Commands::Convert { .. }
            | Commands::Validate { .. }
            | Commands::Deploy { .. }
            | Commands::Doctor
            | Commands::Runtime { .. }
            | Commands::Daemon {
                command: DaemonCommand::Stop,
            }
            | Commands::Events { .. }
    );

    if needs_daemon {
        crate::daemon::ensure_daemon_running(config).await?;
    }

    match command {
        Commands::Start(start) => start::run(config, *start).await,
        Commands::Stop { target } => stop::run(config, target).await,
        Commands::Restart { target } => restart::run(config, target).await,
        Commands::Reload { target } => reload::run(config, target).await,
        Commands::Pull { target } => pull::run(config, target).await,
        Commands::Delete { target } => delete::run(config, target).await,
        Commands::List => list::run(config).await,
        Commands::Ui { interval_ms } => ui::run(config, interval_ms).await,
        Commands::Status { target } => status::run(config, target).await,
        Commands::Logs {
            target,
            follow,
            lines,
        } => logs::run(config, target, follow, lines).await,
        Commands::Import {
            source,
            env,
            only,
            sha256,
        } => import::run(config, source, env, only, sha256).await,
        Commands::Export { target, out } => export::run(config, target, out).await,
        Commands::Apply {
            paths,
            env,
            only,
            prune,
        } => apply::run(config, paths, env, only, prune).await,
        Commands::Convert { input, out, env } => convert::run(input, out, env),
        Commands::Validate { paths, env, only } => validate::run(&paths, env.as_deref(), &only),
        Commands::Deploy {
            config,
            force,
            args,
        } => deploy::run(config, force, args).await,
        Commands::Doctor => doctor::run(config).await,
        Commands::Events {
            process,
            filter,
            json,
        } => events::run(config, process, filter, json).await,
        Commands::Runtime { path, env, only } => runtime::run(config, path, env, only).await,
        Commands::Startup { system } => startup::run(system, config),
        Commands::Service { command, system } => service::run(command, system, config),
        Commands::Daemon {
            command: DaemonCommand::Run,
        } => unreachable!("daemon mode is handled before CLI dispatch"),
        Commands::Daemon {
            command: DaemonCommand::Stop,
        } => daemon_stop::run(config).await,
    }
}
