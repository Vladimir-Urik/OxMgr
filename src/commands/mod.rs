mod apply;
mod common;
mod convert;
mod daemon_stop;
mod delete;
mod deploy;
mod doctor;
mod export;
mod import;
mod list;
mod logs;
mod pull;
mod reload;
mod restart;
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

pub async fn run(command: Commands, config: &AppConfig) -> Result<()> {
    if let Commands::Start {
        cluster,
        cluster_instances,
        ..
    } = &command
    {
        start::validate_flags(*cluster, *cluster_instances)?;
    }

    let needs_daemon = !matches!(
        command,
        Commands::Startup { .. }
            | Commands::Service { .. }
            | Commands::Convert { .. }
            | Commands::Validate { .. }
            | Commands::Deploy { .. }
            | Commands::Doctor
            | Commands::Daemon {
                command: DaemonCommand::Stop,
            }
    );

    if needs_daemon {
        crate::daemon::ensure_daemon_running(config).await?;
    }

    match command {
        Commands::Start {
            command,
            name,
            restart,
            max_restarts,
            crash_restart_limit,
            cwd,
            env,
            health_cmd,
            health_interval,
            health_timeout,
            health_max_failures,
            kill_signal,
            stop_timeout,
            restart_delay,
            start_delay,
            watch,
            cluster,
            cluster_instances,
            namespace,
            max_memory_mb,
            max_cpu_percent,
            cgroup_enforce,
            deny_gpu,
        } => {
            start::run(
                config,
                start::StartArgs {
                    command,
                    name,
                    restart,
                    max_restarts,
                    crash_restart_limit,
                    cwd,
                    env,
                    health_cmd,
                    health_interval,
                    health_timeout,
                    health_max_failures,
                    kill_signal,
                    stop_timeout,
                    restart_delay,
                    start_delay,
                    watch,
                    cluster,
                    cluster_instances,
                    namespace,
                    max_memory_mb,
                    max_cpu_percent,
                    cgroup_enforce,
                    deny_gpu,
                },
            )
            .await
        }
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
            path,
            env,
            only,
            prune,
        } => apply::run(config, path, env, only, prune).await,
        Commands::Convert { input, out, env } => convert::run(input, out, env),
        Commands::Validate { path, env, only } => validate::run(&path, env.as_deref(), &only),
        Commands::Deploy {
            config,
            force,
            args,
        } => deploy::run(config, force, args).await,
        Commands::Doctor => doctor::run(config).await,
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
