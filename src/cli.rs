use std::collections::HashMap;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::process::{HealthCheck, ResourceLimits, RestartPolicy};

const BUILD_VERSION: &str = env!("OXMGR_BUILD_VERSION");
const HELP_TEMPLATE: &str = "\
{before-help}{name} {version}
{about-with-newline}
USAGE:
  {usage}

COMMANDS:
{subcommands}

OPTIONS:
{options}
{after-help}
";
const HELP_AFTER: &str = "\
Quick Command Map
  Runtime:
    list/ls/ps, status, ui, logs/log
  Lifecycle:
    start, stop, restart/rs, reload, pull, delete/rm
  Config:
    import, export, apply, validate, convert
  Platform:
    service, startup, daemon, doctor
  Deploy:
    deploy

Compatibility Aliases
  list    -> ls, ps
  delete  -> rm
  restart -> rs
  logs    -> log

Examples
  oxmgr ps
  oxmgr rs api
  oxmgr log api -f
  oxmgr rm api
";

#[derive(Debug, Parser)]
#[command(
    name = "oxmgr",
    version = BUILD_VERSION,
    about = "Oxmgr process manager",
    help_template = HELP_TEMPLATE,
    after_help = HELP_AFTER
)]
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
        #[arg(long, default_value_t = 3)]
        crash_restart_limit: u32,
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
        #[arg(long, default_value_t = false)]
        watch: bool,
        #[arg(long, default_value_t = false)]
        cluster: bool,
        #[arg(long = "cluster-instances")]
        cluster_instances: Option<u32>,
        #[arg(long)]
        namespace: Option<String>,
        #[arg(long = "max-memory-mb")]
        max_memory_mb: Option<u64>,
        #[arg(long = "max-cpu-percent")]
        max_cpu_percent: Option<f32>,
        #[arg(long = "cgroup-enforce", default_value_t = false)]
        cgroup_enforce: bool,
        #[arg(long = "deny-gpu", default_value_t = false)]
        deny_gpu: bool,
    },
    Stop {
        target: String,
    },
    #[command(visible_alias = "rs")]
    Restart {
        target: String,
    },
    Reload {
        target: String,
    },
    Pull {
        target: Option<String>,
    },
    #[command(visible_alias = "rm")]
    Delete {
        target: String,
    },
    #[command(visible_aliases = ["ls", "ps"])]
    List,
    Ui {
        #[arg(long, default_value_t = 800)]
        interval_ms: u64,
    },
    #[command(visible_alias = "log")]
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
        source: String,
        #[arg(long)]
        env: Option<String>,
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        #[arg(long)]
        sha256: Option<String>,
    },
    Export {
        target: String,
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
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
    Deploy {
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        force: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    Doctor,
    Startup {
        #[arg(long, value_enum, default_value_t = InitSystem::Auto)]
        system: InitSystem,
    },
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
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
    Stop,
}

#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    Install,
    Uninstall,
    Status,
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
    cgroup_enforce: bool,
    deny_gpu: bool,
) -> Option<ResourceLimits> {
    if max_memory_mb.is_none() && max_cpu_percent.is_none() && !cgroup_enforce && !deny_gpu {
        None
    } else {
        Some(ResourceLimits {
            max_memory_mb,
            max_cpu_percent,
            cgroup_enforce,
            deny_gpu,
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{
        build_health_check, build_resource_limits, env_pairs_to_map, parse_env_var, Cli, Commands,
        RestartArg,
    };
    use crate::process::RestartPolicy;

    #[test]
    fn parse_env_var_accepts_values_with_equals_sign() {
        let parsed = parse_env_var("DATABASE_URL=postgres://a:b@localhost/db?sslmode=disable")
            .expect("expected valid KEY=VALUE format");
        assert_eq!(parsed.0, "DATABASE_URL");
        assert_eq!(
            parsed.1,
            "postgres://a:b@localhost/db?sslmode=disable".to_string()
        );
    }

    #[test]
    fn parse_env_var_rejects_missing_separator() {
        let err = parse_env_var("NO_EQUALS").expect_err("expected parser failure");
        assert!(
            err.contains("KEY=VALUE"),
            "unexpected parse error message: {err}"
        );
    }

    #[test]
    fn parse_env_var_rejects_empty_key() {
        let err = parse_env_var("=value").expect_err("expected parser failure");
        assert!(
            err.contains("key cannot be empty"),
            "unexpected parse error message: {err}"
        );
    }

    #[test]
    fn env_pairs_to_map_keeps_last_value_for_duplicate_key() {
        let env = env_pairs_to_map(vec![
            ("PORT".to_string(), "3000".to_string()),
            ("PORT".to_string(), "8080".to_string()),
            ("HOST".to_string(), "127.0.0.1".to_string()),
        ]);

        assert_eq!(env.len(), 2);
        assert_eq!(env.get("PORT").map(String::as_str), Some("8080"));
        assert_eq!(env.get("HOST").map(String::as_str), Some("127.0.0.1"));
    }

    #[test]
    fn build_health_check_normalizes_minimum_thresholds() {
        let check =
            build_health_check(Some("curl -f http://localhost/health".to_string()), 0, 0, 0)
                .expect("expected health check to be present");

        assert_eq!(check.interval_secs, 1);
        assert_eq!(check.timeout_secs, 1);
        assert_eq!(check.max_failures, 1);
    }

    #[test]
    fn build_health_check_returns_none_when_command_is_missing() {
        assert!(build_health_check(None, 30, 5, 3).is_none());
    }

    #[test]
    fn build_resource_limits_returns_none_without_any_limits() {
        assert!(build_resource_limits(None, None, false, false).is_none());
    }

    #[test]
    fn build_resource_limits_includes_flags_without_numeric_limits() {
        let limits = build_resource_limits(None, None, true, true)
            .expect("expected resource limits to be present");
        assert_eq!(limits.max_memory_mb, None);
        assert_eq!(limits.max_cpu_percent, None);
        assert!(limits.cgroup_enforce);
        assert!(limits.deny_gpu);
    }

    #[test]
    fn restart_arg_maps_to_restart_policy() {
        assert_eq!(
            RestartPolicy::from(RestartArg::Always),
            RestartPolicy::Always
        );
        assert_eq!(
            RestartPolicy::from(RestartArg::OnFailure),
            RestartPolicy::OnFailure
        );
        assert_eq!(RestartPolicy::from(RestartArg::Never), RestartPolicy::Never);
    }

    #[test]
    fn clap_start_command_parses_env_flags() {
        let cli = Cli::try_parse_from([
            "oxmgr",
            "start",
            "node server.js",
            "--name",
            "api",
            "--env",
            "A=1",
            "--env",
            "B=two",
            "--restart",
            "never",
        ])
        .expect("expected CLI parsing success");

        match cli.command {
            Commands::Start {
                name, env, restart, ..
            } => {
                assert_eq!(name.as_deref(), Some("api"));
                assert_eq!(
                    env,
                    vec![
                        ("A".to_string(), "1".to_string()),
                        ("B".to_string(), "two".to_string())
                    ]
                );
                assert!(matches!(restart, RestartArg::Never));
            }
            _ => panic!("expected start subcommand"),
        }
    }

    #[test]
    fn clap_parses_doctor_command() {
        let cli = Cli::try_parse_from(["oxmgr", "doctor"]).expect("expected CLI parsing success");
        assert!(matches!(cli.command, Commands::Doctor));
    }

    #[test]
    fn clap_parses_list_aliases_ls_and_ps() {
        let ls = Cli::try_parse_from(["oxmgr", "ls"]).expect("expected ls alias parsing success");
        assert!(matches!(ls.command, Commands::List));

        let ps = Cli::try_parse_from(["oxmgr", "ps"]).expect("expected ps alias parsing success");
        assert!(matches!(ps.command, Commands::List));
    }

    #[test]
    fn clap_parses_restart_alias_rs() {
        let cli = Cli::try_parse_from(["oxmgr", "rs", "api"]).expect("expected rs alias parsing");
        match cli.command {
            Commands::Restart { target } => assert_eq!(target, "api"),
            _ => panic!("expected restart subcommand"),
        }
    }

    #[test]
    fn clap_parses_delete_alias_rm() {
        let cli = Cli::try_parse_from(["oxmgr", "rm", "api"]).expect("expected rm alias parsing");
        match cli.command {
            Commands::Delete { target } => assert_eq!(target, "api"),
            _ => panic!("expected delete subcommand"),
        }
    }

    #[test]
    fn clap_parses_logs_alias_log_with_follow_flag() {
        let cli =
            Cli::try_parse_from(["oxmgr", "log", "api", "-f"]).expect("expected log alias parsing");
        match cli.command {
            Commands::Logs {
                target,
                follow,
                lines,
            } => {
                assert_eq!(target, "api");
                assert!(follow);
                assert_eq!(lines, 100);
            }
            _ => panic!("expected logs subcommand"),
        }
    }

    #[test]
    fn clap_parses_pull_with_and_without_target() {
        let all =
            Cli::try_parse_from(["oxmgr", "pull"]).expect("expected pull parsing without target");
        match all.command {
            Commands::Pull { target } => assert!(target.is_none()),
            _ => panic!("expected pull subcommand"),
        }

        let one = Cli::try_parse_from(["oxmgr", "pull", "api"])
            .expect("expected pull parsing with target");
        match one.command {
            Commands::Pull { target } => assert_eq!(target.as_deref(), Some("api")),
            _ => panic!("expected pull subcommand"),
        }
    }

    #[test]
    fn clap_parses_deploy_with_positional_tokens() {
        let cli = Cli::try_parse_from([
            "oxmgr",
            "deploy",
            "ecosystem.config.js",
            "production",
            "setup",
        ])
        .expect("expected deploy parsing success");

        match cli.command {
            Commands::Deploy {
                config,
                force,
                args,
            } => {
                assert!(config.is_none());
                assert!(!force);
                assert_eq!(
                    args,
                    vec![
                        "ecosystem.config.js".to_string(),
                        "production".to_string(),
                        "setup".to_string()
                    ]
                );
            }
            _ => panic!("expected deploy subcommand"),
        }
    }

    #[test]
    fn clap_parses_deploy_with_config_flag_and_force() {
        let cli = Cli::try_parse_from([
            "oxmgr",
            "deploy",
            "--config",
            "ecosystem.config.js",
            "--force",
            "production",
            "update",
        ])
        .expect("expected deploy parsing success");

        match cli.command {
            Commands::Deploy {
                config,
                force,
                args,
            } => {
                assert_eq!(
                    config,
                    Some(std::path::PathBuf::from("ecosystem.config.js"))
                );
                assert!(force);
                assert_eq!(args, vec!["production".to_string(), "update".to_string()]);
            }
            _ => panic!("expected deploy subcommand"),
        }
    }

    #[test]
    fn clap_parses_import_with_sha256_pin() {
        let cli = Cli::try_parse_from([
            "oxmgr",
            "import",
            "https://example.com/api.oxpkg",
            "--sha256",
            "0de9dbf5a7b951f684d5d2be08150795ee93fe01d0c246960534721dd30595f7",
            "--only",
            "api,worker",
        ])
        .expect("expected import parsing success");

        match cli.command {
            Commands::Import {
                source,
                env,
                only,
                sha256,
            } => {
                assert_eq!(source, "https://example.com/api.oxpkg");
                assert!(env.is_none());
                assert_eq!(only, vec!["api".to_string(), "worker".to_string()]);
                assert_eq!(
                    sha256.as_deref(),
                    Some("0de9dbf5a7b951f684d5d2be08150795ee93fe01d0c246960534721dd30595f7")
                );
            }
            _ => panic!("expected import subcommand"),
        }
    }

    #[test]
    fn clap_parses_export_with_output_path() {
        let cli = Cli::try_parse_from(["oxmgr", "export", "api", "--out", "./bundle.oxpkg"])
            .expect("expected export parsing success");

        match cli.command {
            Commands::Export { target, out } => {
                assert_eq!(target, "api");
                assert_eq!(out, Some(std::path::PathBuf::from("./bundle.oxpkg")));
            }
            _ => panic!("expected export subcommand"),
        }
    }
}
