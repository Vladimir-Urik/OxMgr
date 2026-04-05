use anyhow::{Context, Result};

use crate::cli::{build_health_check, build_resource_limits, env_pairs_to_map, StartCommand};
use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::process::StartProcessSpec;

use super::common::expect_ok;

pub(crate) fn validate_flags(args: &StartCommand) -> Result<()> {
    if args.cluster_instances.is_some() && !args.cluster {
        anyhow::bail!("--cluster-instances requires --cluster");
    }
    if (!args.watch_path.is_empty() || !args.ignore_watch.is_empty() || args.watch_delay > 0)
        && !args.watch
    {
        anyhow::bail!("watch-specific flags require --watch");
    }
    if args.wait_ready && args.ready_timeout == 0 {
        anyhow::bail!("--ready-timeout must be at least 1 second");
    }

    Ok(())
}

pub(crate) async fn run(config: &AppConfig, args: StartCommand) -> Result<()> {
    validate_flags(&args)?;
    let spec = build_start_spec(args)?;

    let response = send_request(
        &config.daemon_addr,
        &IpcRequest::Start {
            spec: Box::new(spec),
        },
    )
    .await?;

    let response = expect_ok(response)?;
    println!("{}", response.message);

    Ok(())
}

fn build_start_spec(args: StartCommand) -> Result<StartProcessSpec> {
    let cwd = Some(match args.cwd {
        Some(cwd) => cwd,
        None => std::env::current_dir().context("failed to resolve current working directory")?,
    });

    let health_check = build_health_check(
        args.health_cmd,
        args.health_interval,
        args.health_timeout,
        args.health_max_failures,
    );
    if args.wait_ready && health_check.is_none() {
        anyhow::bail!("--wait-ready requires --health-cmd");
    }
    let resource_limits = build_resource_limits(
        args.max_memory_mb,
        args.max_cpu_percent,
        args.cgroup_enforce,
        args.deny_gpu,
    );

    Ok(StartProcessSpec {
        command: args.command,
        name: args.name,
        pre_reload_cmd: args.pre_reload_cmd,
        restart_policy: args.restart.into(),
        max_restarts: args.max_restarts,
        crash_restart_limit: args.crash_restart_limit,
        cwd,
        env: env_pairs_to_map(args.env),
        health_check,
        stop_signal: args.kill_signal,
        stop_timeout_secs: args.stop_timeout.max(1),
        restart_delay_secs: args.restart_delay,
        start_delay_secs: args.start_delay,
        watch: args.watch,
        watch_paths: args.watch_path,
        ignore_watch: args.ignore_watch,
        watch_delay_secs: args.watch_delay,
        cluster_mode: args.cluster,
        cluster_instances: args.cluster_instances.map(|value| value.max(1)),
        namespace: args.namespace,
        resource_limits,
        git_repo: None,
        git_ref: None,
        pull_secret_hash: None,
        reuse_port: args.reuse_port,
        wait_ready: args.wait_ready,
        ready_timeout_secs: args.ready_timeout.max(1),
        log_date_format: args.log_date_format,
        unified_logs: false,
        cron_restart: args.cron_restart,
    })
}
