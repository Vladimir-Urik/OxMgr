use std::path::PathBuf;

use anyhow::Result;

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
    pub(crate) cluster: bool,
    pub(crate) cluster_instances: Option<u32>,
    pub(crate) namespace: Option<String>,
    pub(crate) max_memory_mb: Option<u64>,
    pub(crate) max_cpu_percent: Option<f32>,
    pub(crate) cgroup_enforce: bool,
    pub(crate) deny_gpu: bool,
}

pub(crate) async fn run(config: &AppConfig, args: StartArgs) -> Result<()> {
    if args.cluster_instances.is_some() && !args.cluster {
        anyhow::bail!("--cluster-instances requires --cluster");
    }

    let cwd = if args.watch {
        args.cwd.clone().or_else(|| std::env::current_dir().ok())
    } else {
        args.cwd.clone()
    };

    let health_check = build_health_check(
        args.health_cmd,
        args.health_interval,
        args.health_timeout,
        args.health_max_failures,
    );
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
                cwd,
                env: env_pairs_to_map(args.env),
                health_check,
                stop_signal: args.kill_signal,
                stop_timeout_secs: args.stop_timeout.max(1),
                restart_delay_secs: args.restart_delay,
                start_delay_secs: args.start_delay,
                watch: args.watch,
                cluster_mode: args.cluster,
                cluster_instances: args.cluster_instances.map(|value| value.max(1)),
                namespace: args.namespace,
                resource_limits,
            }),
        },
    )
    .await?;

    let response = expect_ok(response)?;
    println!("{}", response.message);

    Ok(())
}
