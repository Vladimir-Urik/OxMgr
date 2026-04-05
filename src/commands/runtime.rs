use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout, Instant};

use crate::config::AppConfig;
use crate::ecosystem::EcosystemProcessSpec;
use crate::process::StartProcessSpec;

use super::import::{load_import_specs, order_specs_for_start};

const CRASH_RESTART_WINDOW_SECS: u64 = 5 * 60;

pub(crate) async fn run(
    config: &AppConfig,
    path: PathBuf,
    env: Option<String>,
    only: Vec<String>,
) -> Result<()> {
    let mut specs = load_import_specs(&path, env.as_deref())?;
    if !only.is_empty() {
        specs.retain(|spec| {
            spec.name
                .as_ref()
                .map(|name| only.iter().any(|selected| selected == name))
                .unwrap_or(false)
        });
    }
    specs = order_specs_for_start(specs);
    let desired = expand_specs_for_runtime(specs)?;
    if desired.is_empty() {
        println!("No apps found in {}", path.display());
        return Ok(());
    }

    let mut entries = Vec::with_capacity(desired.len());
    for spec in desired {
        let name = spec
            .name
            .clone()
            .context("runtime requires app names; set `name` in oxfile")?;
        entries.push(RuntimeEntry {
            name,
            spec,
            child: None,
            restart_count: 0,
            auto_restart_history: Vec::new(),
            next_restart_at: None,
        });
    }

    for entry in &mut entries {
        spawn_entry(config, entry).await?;
    }

    println!(
        "Runtime started {} process(es) from {} (foreground mode)",
        entries.len(),
        path.display()
    );
    println!("Waiting for SIGTERM/SIGINT (or Ctrl-C)...");

    let mut shutdown_signal = Box::pin(wait_for_shutdown_signal());
    let mut shutting_down = false;
    let mut fatal_exit: Option<String> = None;

    loop {
        tokio::select! {
            _ = &mut shutdown_signal, if !shutting_down => {
                println!("Shutdown signal received, stopping child processes...");
                shutdown_all_entries(&mut entries).await;
                break;
            }
            _ = sleep(Duration::from_millis(250)) => {}
        }

        let now = Instant::now();
        for entry in &mut entries {
            if let Some(restart_at) = entry.next_restart_at {
                if now >= restart_at && !shutting_down {
                    entry.next_restart_at = None;
                    if let Err(err) = spawn_entry(config, entry).await {
                        fatal_exit = Some(format!("failed to restart {}: {}", entry.name, err));
                        shutting_down = true;
                        break;
                    }
                }
            }

            let Some(child) = entry.child.as_mut() else {
                continue;
            };

            match child.try_wait() {
                Ok(Some(status)) => {
                    let code = status.code().unwrap_or(-1);
                    let success = status.success();
                    entry.child = None;
                    if shutting_down {
                        continue;
                    }

                    if should_restart(entry, success) {
                        entry.restart_count = entry.restart_count.saturating_add(1);
                        record_auto_restart(entry, now_epoch_secs());
                        let delay = entry.spec.restart_delay_secs;
                        entry.next_restart_at = Some(now + Duration::from_secs(delay));
                        eprintln!(
                            "[runtime] {} exited (code={}), restarting in {}s ({}/{})",
                            entry.name, code, delay, entry.restart_count, entry.spec.max_restarts
                        );
                    } else {
                        fatal_exit = Some(format!(
                            "process {} exited (code={}) and is not restartable",
                            entry.name, code
                        ));
                        shutting_down = true;
                        break;
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    fatal_exit = Some(format!("failed waiting for {}: {}", entry.name, err));
                    shutting_down = true;
                    break;
                }
            }
        }

        if shutting_down {
            shutdown_all_entries(&mut entries).await;
            break;
        }
    }

    if let Some(message) = fatal_exit {
        anyhow::bail!(message);
    }
    Ok(())
}

struct RuntimeEntry {
    name: String,
    spec: StartProcessSpec,
    child: Option<Child>,
    restart_count: u32,
    auto_restart_history: Vec<u64>,
    next_restart_at: Option<Instant>,
}

async fn spawn_entry(config: &AppConfig, entry: &mut RuntimeEntry) -> Result<()> {
    let spawn = resolve_runtime_spawn(config, &entry.spec)?;
    let mut command = Command::new(&spawn.program);
    #[cfg(unix)]
    {
        // Keep each managed process in its own process group for signal fan-out.
        unsafe {
            command.pre_exec(|| {
                if nix::libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }
    command
        .args(&spawn.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(cwd) = &entry.spec.cwd {
        command.current_dir(cwd);
    }
    if !entry.spec.env.is_empty() {
        command.envs(&entry.spec.env);
    }
    if !spawn.extra_env.is_empty() {
        command.envs(&spawn.extra_env);
    }
    if entry.spec.reuse_port {
        #[cfg(unix)]
        {
            command.env("OXMGR_REUSEPORT", "1");
            command.env("SO_REUSEPORT", "1");
        }
    }
    if entry
        .spec
        .resource_limits
        .as_ref()
        .map(|limits| limits.deny_gpu)
        .unwrap_or(false)
    {
        command.env("CUDA_VISIBLE_DEVICES", "");
        command.env("NVIDIA_VISIBLE_DEVICES", "none");
        command.env("HIP_VISIBLE_DEVICES", "");
        command.env("ROCR_VISIBLE_DEVICES", "");
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn {}", entry.spec.command))?;

    if let Some(stdout) = child.stdout.take() {
        forward_logs(stdout, entry.name.clone(), "stdout".to_string(), false);
    }
    if let Some(stderr) = child.stderr.take() {
        forward_logs(stderr, entry.name.clone(), "stderr".to_string(), true);
    }

    let pid = child.id().unwrap_or(0);
    println!("[runtime] started {} (pid {})", entry.name, pid);
    entry.child = Some(child);
    Ok(())
}

fn forward_logs(
    pipe: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    name: String,
    source: String,
    is_stderr: bool,
) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(pipe).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if is_stderr {
                eprintln!("[{}:{}] {}", name, source, line);
            } else {
                println!("[{}:{}] {}", name, source, line);
            }
        }
    });
}

async fn shutdown_all_entries(entries: &mut [RuntimeEntry]) {
    for entry in entries {
        if let Some(child) = entry.child.as_mut() {
            terminate_child(
                child,
                entry.spec.stop_signal.as_deref(),
                Duration::from_secs(entry.spec.stop_timeout_secs.max(1)),
            )
            .await;
        }
        entry.child = None;
        entry.next_restart_at = None;
    }
}

#[cfg(unix)]
async fn terminate_child(child: &mut Child, signal_name: Option<&str>, timeout_window: Duration) {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let Some(pid) = child.id() else {
        return;
    };
    let signal = unix_signal_from_name(signal_name).unwrap_or(Signal::SIGTERM);
    let pgid = Pid::from_raw(-(pid as i32));
    let os_pid = Pid::from_raw(pid as i32);

    let _ = kill(pgid, signal);
    let _ = kill(os_pid, signal);

    if timeout(timeout_window, child.wait()).await.is_ok() {
        return;
    }

    let _ = kill(pgid, Signal::SIGKILL);
    let _ = kill(os_pid, Signal::SIGKILL);
    let _ = timeout(Duration::from_secs(2), child.wait()).await;
}

#[cfg(windows)]
async fn terminate_child(child: &mut Child, _signal_name: Option<&str>, timeout_window: Duration) {
    if timeout(timeout_window, child.wait()).await.is_ok() {
        return;
    }
    let _ = child.start_kill();
    let _ = timeout(Duration::from_secs(2), child.wait()).await;
}

#[cfg(not(any(unix, windows)))]
async fn terminate_child(child: &mut Child, _signal_name: Option<&str>, _timeout_window: Duration) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

fn should_restart(entry: &mut RuntimeEntry, exited_successfully: bool) -> bool {
    if !entry
        .spec
        .restart_policy
        .should_restart(exited_successfully)
    {
        return false;
    }
    if entry.restart_count >= entry.spec.max_restarts {
        return false;
    }
    !crash_loop_limit_reached(entry, now_epoch_secs())
}

fn crash_loop_limit_reached(entry: &mut RuntimeEntry, now: u64) -> bool {
    entry
        .auto_restart_history
        .retain(|timestamp| now.saturating_sub(*timestamp) < CRASH_RESTART_WINDOW_SECS);
    entry.spec.crash_restart_limit > 0
        && entry.auto_restart_history.len() >= entry.spec.crash_restart_limit as usize
}

fn record_auto_restart(entry: &mut RuntimeEntry, now: u64) {
    if entry.spec.crash_restart_limit == 0 {
        return;
    }
    entry
        .auto_restart_history
        .retain(|timestamp| now.saturating_sub(*timestamp) < CRASH_RESTART_WINDOW_SECS);
    entry.auto_restart_history.push(now);
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn unix_signal_from_name(value: Option<&str>) -> Option<nix::sys::signal::Signal> {
    use nix::sys::signal::Signal;

    let normalized = value?.trim().to_ascii_uppercase();
    let raw = normalized.strip_prefix("SIG").unwrap_or(&normalized);
    match raw {
        "TERM" => Some(Signal::SIGTERM),
        "INT" => Some(Signal::SIGINT),
        "QUIT" => Some(Signal::SIGQUIT),
        "HUP" => Some(Signal::SIGHUP),
        "KILL" => Some(Signal::SIGKILL),
        "USR1" => Some(Signal::SIGUSR1),
        "USR2" => Some(Signal::SIGUSR2),
        _ => None,
    }
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn expand_specs_for_runtime(specs: Vec<EcosystemProcessSpec>) -> Result<Vec<StartProcessSpec>> {
    let mut desired = Vec::new();
    for spec in specs {
        let instances = spec.instances.max(1);
        let base_name = spec.name.clone().with_context(|| {
            format!(
                "app command '{}' is missing 'name'; runtime requires deterministic names",
                spec.command
            )
        })?;

        for idx in 0..instances {
            let mut env = spec.env.clone();
            let name = if instances > 1 {
                let key = spec
                    .instance_var
                    .clone()
                    .unwrap_or_else(|| "NODE_APP_INSTANCE".to_string());
                env.insert(key, idx.to_string());
                format!("{base_name}-{idx}")
            } else {
                base_name.clone()
            };

            desired.push(StartProcessSpec {
                command: spec.command.clone(),
                name: Some(name),
                pre_reload_cmd: spec.pre_reload_cmd.clone(),
                restart_policy: spec.restart_policy.clone(),
                max_restarts: spec.max_restarts,
                crash_restart_limit: spec.crash_restart_limit,
                cwd: spec.cwd.clone(),
                env,
                health_check: spec.health_check.clone(),
                stop_signal: spec.stop_signal.clone(),
                stop_timeout_secs: spec.stop_timeout_secs.max(1),
                restart_delay_secs: spec.restart_delay_secs,
                start_delay_secs: spec.start_delay_secs,
                watch: spec.watch,
                watch_paths: spec.watch_paths.clone(),
                ignore_watch: spec.ignore_watch.clone(),
                watch_delay_secs: spec.watch_delay_secs,
                cluster_mode: spec.cluster_mode,
                cluster_instances: spec.cluster_instances,
                namespace: spec.namespace.clone(),
                resource_limits: spec.resource_limits.clone(),
                git_repo: spec.git_repo.clone(),
                git_ref: spec.git_ref.clone(),
                pull_secret_hash: spec.pull_secret_hash.clone(),
                reuse_port: spec.reuse_port,
                wait_ready: spec.wait_ready,
                ready_timeout_secs: spec.ready_timeout_secs,
                log_date_format: spec.log_date_format.clone(),
                unified_logs: spec.unified_logs,
                cron_restart: spec.cron_restart.clone(),
            });
        }
    }
    Ok(desired)
}

struct RuntimeSpawnPlan {
    program: String,
    args: Vec<String>,
    extra_env: HashMap<String, String>,
}

fn resolve_runtime_spawn(config: &AppConfig, spec: &StartProcessSpec) -> Result<RuntimeSpawnPlan> {
    let (command, args) = parse_command_line(&spec.command)?;
    if !spec.cluster_mode {
        return Ok(RuntimeSpawnPlan {
            program: command,
            args,
            extra_env: HashMap::new(),
        });
    }

    if !is_node_binary(&command) {
        anyhow::bail!("cluster mode requires a Node.js command (expected `node <script> ...`)");
    }
    let Some(script) = args.first() else {
        anyhow::bail!("cluster mode requires a script argument (expected `node <script> ...`)");
    };
    if script.starts_with('-') {
        anyhow::bail!(
            "cluster mode currently does not support Node runtime flags before script path"
        );
    }

    let bootstrap = ensure_node_cluster_bootstrap(&config.base_dir)?;
    let mut resolved_args = Vec::with_capacity(args.len() + 2);
    resolved_args.push(bootstrap.display().to_string());
    resolved_args.push("--".to_string());
    resolved_args.extend(args);

    let mut extra_env = HashMap::new();
    extra_env.insert(
        "OXMGR_CLUSTER_INSTANCES".to_string(),
        spec.cluster_instances
            .map(|value| value.to_string())
            .unwrap_or_else(|| "auto".to_string()),
    );

    Ok(RuntimeSpawnPlan {
        program: command,
        args: resolved_args,
        extra_env,
    })
}

fn parse_command_line(command_line: &str) -> Result<(String, Vec<String>)> {
    let tokens = shell_words::split(command_line)
        .with_context(|| format!("invalid command syntax: {}", command_line))?;
    if tokens.is_empty() {
        anyhow::bail!("command cannot be empty");
    }
    Ok((tokens[0].clone(), tokens[1..].to_vec()))
}

fn ensure_node_cluster_bootstrap(base_dir: &Path) -> Result<PathBuf> {
    let runtime_dir = base_dir.join("runtime");
    std::fs::create_dir_all(&runtime_dir).with_context(|| {
        format!(
            "failed to create runtime directory {}",
            runtime_dir.display()
        )
    })?;
    let bootstrap_path = runtime_dir.join("node_cluster_bootstrap.cjs");
    std::fs::write(&bootstrap_path, NODE_CLUSTER_BOOTSTRAP).with_context(|| {
        format!(
            "failed to write node cluster bootstrap at {}",
            bootstrap_path.display()
        )
    })?;
    Ok(bootstrap_path)
}

fn is_node_binary(command: &str) -> bool {
    let executable = Path::new(command)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(command)
        .to_ascii_lowercase();
    matches!(
        executable.as_str(),
        "node" | "node.exe" | "nodejs" | "nodejs.exe"
    )
}

const NODE_CLUSTER_BOOTSTRAP: &str = r#""use strict";
const cluster = require("node:cluster");
const os = require("node:os");
const path = require("node:path");
const process = require("node:process");

function parseDesiredInstances(raw) {
  if (!raw || raw === "auto") return 0;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return 0;
  return parsed;
}

function cpuCount() {
  if (typeof os.availableParallelism === "function") {
    const value = os.availableParallelism();
    if (Number.isFinite(value) && value > 0) return value;
  }
  const cpus = os.cpus();
  return Array.isArray(cpus) && cpus.length > 0 ? cpus.length : 1;
}

const argv = process.argv.slice(2);
if (argv[0] === "--") argv.shift();
const script = argv.shift();

if (!script) {
  console.error("[oxmgr] cluster mode needs a script argument (expected: node <script> ...)");
  process.exit(2);
}

const desired = parseDesiredInstances(process.env.OXMGR_CLUSTER_INSTANCES || "");
const workerCount = desired > 0 ? desired : cpuCount();

cluster.setupPrimary({
  exec: path.resolve(script),
  args: argv
});

let shuttingDown = false;
let nextInstance = 0;

function forkWorker() {
  const env = { NODE_APP_INSTANCE: String(nextInstance) };
  nextInstance += 1;
  return cluster.fork(env);
}

for (let idx = 0; idx < workerCount; idx += 1) {
  forkWorker();
}

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  const workers = Object.values(cluster.workers).filter(Boolean);
  for (const worker of workers) {
    worker.process.kill(signal);
  }
  setTimeout(() => process.exit(0), 3000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

cluster.on("exit", (worker) => {
  if (shuttingDown) return;
  if (worker.exitedAfterDisconnect) return;
  forkWorker();
});
"#;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::ecosystem::EcosystemProcessSpec;
    use crate::logging::LogRotationPolicy;
    use crate::process::RestartPolicy;

    use super::{expand_specs_for_runtime, resolve_runtime_spawn, should_restart, RuntimeEntry};

    #[test]
    fn expand_specs_for_runtime_expands_instances_and_sets_instance_env() {
        let spec = fixture_spec("api", 3, Some("INSTANCE".to_string()));
        let expanded =
            expand_specs_for_runtime(vec![spec]).expect("expected runtime expansion to succeed");
        assert_eq!(expanded.len(), 3);
        assert_eq!(expanded[0].name.as_deref(), Some("api-0"));
        assert_eq!(
            expanded[0].env.get("INSTANCE").map(String::as_str),
            Some("0")
        );
        assert_eq!(expanded[2].name.as_deref(), Some("api-2"));
        assert_eq!(
            expanded[2].env.get("INSTANCE").map(String::as_str),
            Some("2")
        );
    }

    #[test]
    fn expand_specs_for_runtime_rejects_unnamed_specs() {
        let mut spec = fixture_spec("api", 1, None);
        spec.name = None;
        let err = expand_specs_for_runtime(vec![spec]).expect_err("expected missing-name error");
        assert!(
            err.to_string()
                .contains("runtime requires deterministic names"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn should_restart_obeys_policy_and_limits() {
        let mut entry = runtime_entry("api");
        assert!(should_restart(&mut entry, false));

        entry.restart_count = entry.spec.max_restarts;
        assert!(!should_restart(&mut entry, false));

        let mut never_entry = runtime_entry("never");
        never_entry.spec.restart_policy = RestartPolicy::Never;
        assert!(!should_restart(&mut never_entry, false));
    }

    #[test]
    fn resolve_runtime_spawn_supports_cluster_bootstrap() {
        let mut spec = runtime_entry("clustered").spec;
        spec.command = "node server.js --port 3000".to_string();
        spec.cluster_mode = true;
        spec.cluster_instances = Some(2);

        let config = test_config("runtime-cluster");
        let plan = resolve_runtime_spawn(&config, &spec).expect("expected cluster spawn plan");
        assert_eq!(plan.program, "node");
        assert!(plan.args.len() >= 3, "expected bootstrap args");
        assert_eq!(plan.args[1], "--");
        assert_eq!(
            plan.extra_env
                .get("OXMGR_CLUSTER_INSTANCES")
                .map(String::as_str),
            Some("2")
        );
    }

    #[test]
    fn runtime_supports_pm2_merge_logs_mapping_via_import_specs() {
        let path = temp_file_path("runtime-pm2-merge-logs", "js");
        std::fs::write(
            &path,
            r#"
module.exports = {
  apps: [
    {
      name: "api",
      cmd: "node server.js",
      merge_logs: true
    }
  ]
};
"#,
        )
        .expect("failed to write PM2 fixture");

        let imported = crate::commands::import::load_import_specs(&path, None)
            .expect("expected ecosystem parse success");
        assert_eq!(imported.len(), 1);
        assert!(
            imported[0].unified_logs,
            "merge_logs should map to unified_logs"
        );

        let expanded =
            expand_specs_for_runtime(imported).expect("expected runtime expansion from PM2 spec");
        assert_eq!(expanded.len(), 1);
        assert!(expanded[0].unified_logs);

        let _ = std::fs::remove_file(path);
    }

    fn fixture_spec(
        name: &str,
        instances: u32,
        instance_var: Option<String>,
    ) -> EcosystemProcessSpec {
        EcosystemProcessSpec {
            command: "node server.js".to_string(),
            name: Some(name.to_string()),
            pre_reload_cmd: None,
            restart_policy: RestartPolicy::OnFailure,
            max_restarts: 10,
            crash_restart_limit: 3,
            cwd: None,
            env: HashMap::new(),
            health_check: None,
            stop_signal: None,
            stop_timeout_secs: 5,
            restart_delay_secs: 0,
            start_delay_secs: 0,
            watch: false,
            watch_paths: Vec::new(),
            ignore_watch: Vec::new(),
            watch_delay_secs: 0,
            cluster_mode: false,
            cluster_instances: None,
            namespace: None,
            resource_limits: None,
            git_repo: None,
            git_ref: None,
            pull_secret_hash: None,
            reuse_port: false,
            start_order: 0,
            depends_on: Vec::new(),
            instances,
            instance_var,
            wait_ready: false,
            ready_timeout_secs: 30,
            log_date_format: None,
            unified_logs: false,
            cron_restart: None,
        }
    }

    fn runtime_entry(name: &str) -> RuntimeEntry {
        RuntimeEntry {
            name: name.to_string(),
            spec: expand_specs_for_runtime(vec![fixture_spec(name, 1, None)])
                .expect("expected expansion")
                .remove(0),
            child: None,
            restart_count: 0,
            auto_restart_history: Vec::new(),
            next_restart_at: None,
        }
    }

    fn test_config(prefix: &str) -> crate::config::AppConfig {
        let base = temp_dir(prefix);
        crate::config::AppConfig {
            base_dir: base.clone(),
            daemon_addr: "127.0.0.1:0".to_string(),
            api_addr: "127.0.0.1:0".to_string(),
            state_path: base.join("state.json"),
            log_dir: base.join("logs"),
            log_rotation: LogRotationPolicy {
                max_size_bytes: 1024 * 1024,
                max_files: 3,
                max_age_days: 1,
            },
        }
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("oxmgr-runtime-test-{prefix}-{nonce}"));
        std::fs::create_dir_all(&dir).expect("failed to create temp dir");
        dir
    }

    fn temp_file_path(prefix: &str, extension: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.{extension}"))
    }
}
