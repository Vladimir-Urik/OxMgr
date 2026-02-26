use std::collections::HashMap;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::process::{HealthCheck, ResourceLimits, RestartPolicy};

#[derive(Debug, Parser)]
#[command(name = "oxmgr", version, about = "Oxmgr process manager")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Start {
        command: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_enum, default_value_t = RestartArg::OnFailure)]
        restart: RestartArg,
        #[arg(long, default_value_t = 10)]
        max_restarts: u32,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long = "env", value_parser = parse_env_var)]
        env: Vec<(String, String)>,
        #[arg(long = "health-cmd")]
        health_cmd: Option<String>,
        #[arg(long = "health-interval", default_value_t = 30)]
        health_interval: u64,
        #[arg(long = "health-timeout", default_value_t = 5)]
        health_timeout: u64,
        #[arg(long = "health-max-failures", default_value_t = 3)]
        health_max_failures: u32,
        #[arg(long = "kill-signal")]
        kill_signal: Option<String>,
        #[arg(long = "stop-timeout", default_value_t = 5)]
        stop_timeout: u64,
        #[arg(long = "restart-delay", default_value_t = 0)]
        restart_delay: u64,
        #[arg(long = "start-delay", default_value_t = 0)]
        start_delay: u64,
        #[arg(long)]
        namespace: Option<String>,
        #[arg(long = "max-memory-mb")]
        max_memory_mb: Option<u64>,
        #[arg(long = "max-cpu-percent")]
        max_cpu_percent: Option<f32>,
    },
    Stop {
        target: String,
    },
    Restart {
        target: String,
    },
    Reload {
        target: String,
    },
    Delete {
        target: String,
    },
    List,
    Logs {
        target: String,
        #[arg(short = 'f', long)]
        follow: bool,
        #[arg(long, default_value_t = 100)]
        lines: usize,
    },
    Status {
        target: String,
    },
    Import {
        path: PathBuf,
        #[arg(long)]
        env: Option<String>,
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
    },
    Apply {
        path: PathBuf,
        #[arg(long)]
        env: Option<String>,
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        #[arg(long)]
        prune: bool,
    },
    Convert {
        input: PathBuf,
        #[arg(long, short = 'o', default_value = "oxfile.toml")]
        out: PathBuf,
        #[arg(long)]
        env: Option<String>,
    },
    Validate {
        path: PathBuf,
        #[arg(long)]
        env: Option<String>,
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
    },
    Startup {
        #[arg(long, value_enum, default_value_t = InitSystem::Auto)]
        system: InitSystem,
    },
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    Run,
}

#[derive(Debug, Copy, Clone, ValueEnum)]
pub enum RestartArg {
    Always,
    OnFailure,
    Never,
}

#[derive(Debug, Copy, Clone, ValueEnum)]
pub enum InitSystem {
    Auto,
    Systemd,
    Launchd,
    TaskScheduler,
}

impl From<RestartArg> for RestartPolicy {
    fn from(value: RestartArg) -> Self {
        match value {
            RestartArg::Always => RestartPolicy::Always,
            RestartArg::OnFailure => RestartPolicy::OnFailure,
            RestartArg::Never => RestartPolicy::Never,
        }
    }
}

pub fn env_pairs_to_map(items: Vec<(String, String)>) -> HashMap<String, String> {
    items.into_iter().collect()
}

pub fn build_health_check(
    health_cmd: Option<String>,
    health_interval: u64,
    health_timeout: u64,
    health_max_failures: u32,
) -> Option<HealthCheck> {
    health_cmd.map(|command| HealthCheck {
        command,
        interval_secs: health_interval.max(1),
        timeout_secs: health_timeout.max(1),
        max_failures: health_max_failures.max(1),
    })
}

pub fn build_resource_limits(
    max_memory_mb: Option<u64>,
    max_cpu_percent: Option<f32>,
) -> Option<ResourceLimits> {
    if max_memory_mb.is_none() && max_cpu_percent.is_none() {
        None
    } else {
        Some(ResourceLimits {
            max_memory_mb,
            max_cpu_percent,
        })
    }
}

fn parse_env_var(value: &str) -> Result<(String, String), String> {
    let Some((key, val)) = value.split_once('=') else {
        return Err("environment variable must look like KEY=VALUE".to_string());
    };

    if key.is_empty() {
        return Err("environment variable key cannot be empty".to_string());
    }

    Ok((key.to_string(), val.to_string()))
}
