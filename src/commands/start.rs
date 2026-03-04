use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::cli::{build_health_check, build_resource_limits, env_pairs_to_map, RestartArg};
use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::process::StartProcessSpec;

use super::common::expect_ok;

pub(crate) struct StartArgs {
    pub(crate) command: String,
    pub(crate) name: Option<String>,
    pub(crate) restart: RestartArg,
    pub(crate) max_restarts: u32,
    pub(crate) crash_restart_limit: u32,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) health_cmd: Option<String>,
    pub(crate) health_interval: u64,
    pub(crate) health_timeout: u64,
    pub(crate) health_max_failures: u32,
    pub(crate) kill_signal: Option<String>,
    pub(crate) stop_timeout: u64,
    pub(crate) restart_delay: u64,
    pub(crate) start_delay: u64,
    pub(crate) watch: bool,
    pub(crate) watch_path: Vec<PathBuf>,
    pub(crate) ignore_watch: Vec<String>,
    pub(crate) watch_delay: u64,
    pub(crate) cluster: bool,
    pub(crate) cluster_instances: Option<u32>,
    pub(crate) namespace: Option<String>,
    pub(crate) max_memory_mb: Option<u64>,
    pub(crate) max_cpu_percent: Option<f32>,
    pub(crate) cgroup_enforce: bool,
    pub(crate) deny_gpu: bool,
    pub(crate) wait_ready: bool,
    pub(crate) ready_timeout: u64,
}

pub(crate) fn validate_flags(
    cluster: bool,
    cluster_instances: Option<u32>,
    watch: bool,
    watch_path: &[PathBuf],
    ignore_watch: &[String],
    watch_delay: u64,
    wait_ready: bool,
    ready_timeout: u64,
) -> Result<()> {
    if cluster_instances.is_some() && !cluster {
        anyhow::bail!("--cluster-instances requires --cluster");
    }
    if (!watch_path.is_empty() || !ignore_watch.is_empty() || watch_delay > 0) && !watch {
        anyhow::bail!("watch-specific flags require --watch");
    }
    if wait_ready && ready_timeout == 0 {
        anyhow::bail!("--ready-timeout must be at least 1 second");
    }

    Ok(())
}

pub(crate) async fn run(config: &AppConfig, args: StartArgs) -> Result<()> {
    validate_flags(
        args.cluster,
        args.cluster_instances,
        args.watch,
        &args.watch_path,
        &args.ignore_watch,
        args.watch_delay,
        args.wait_ready,
        args.ready_timeout,
    )?;

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

    let response = send_request(
        &config.daemon_addr,
        &IpcRequest::Start {
            spec: Box::new(StartProcessSpec {
                command: args.command,
                name: args.name,
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
                wait_ready: args.wait_ready,
                ready_timeout_secs: args.ready_timeout.max(1),
            }),
        },
    )
    .await?;

    let response = expect_ok(response)?;
    println!("{}", response.message);

    Ok(())
}
