use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc::unbounded_channel;
use tokio::time::Instant as TokioInstant;

#[cfg(unix)]
use super::graceful_wait_before_force_kill;
use super::{
    args_match_expected, compute_restart_delay_secs, constant_time_eq, crash_loop_limit_reached,
    maybe_reset_backoff_attempt, now_epoch_secs, process_exists, program_matches_expected,
    resolve_spawn_program, sha256_hex, short_commit, watch_fingerprint_for_dir,
    watch_fingerprint_for_roots, ProcessManager, CRASH_RESTART_WINDOW_SECS,
};
use crate::config::AppConfig;
use crate::process::{
    DesiredState, HealthCheck, HealthStatus, ManagedProcess, ProcessExitEvent, ProcessStatus,
    RestartPolicy, StartProcessSpec,
};

mod cron;
mod git;
mod lifecycle;
mod restart;
mod spawn;
mod stop_delete_all;
mod watch;

fn fixture_process() -> ManagedProcess {
    ManagedProcess {
        id: 1,
        name: "api".to_string(),
        command: "node".to_string(),
        args: vec!["server.js".to_string()],
        pre_reload_cmd: None,
        cwd: None,
        env: HashMap::new(),
        restart_policy: RestartPolicy::OnFailure,
        max_restarts: 10,
        restart_count: 0,
        crash_restart_limit: 3,
        auto_restart_history: Vec::new(),
        namespace: None,
        git_repo: None,
        git_ref: None,
        pull_secret_hash: None,
        reuse_port: false,
        stop_signal: Some("SIGTERM".to_string()),
        stop_timeout_secs: 5,
        restart_delay_secs: 1,
        restart_backoff_cap_secs: 300,
        restart_backoff_reset_secs: 60,
        restart_backoff_attempt: 0,
        start_delay_secs: 0,
        watch: false,
        watch_paths: Vec::new(),
        ignore_watch: Vec::new(),
        watch_delay_secs: 0,
        cluster_mode: false,
        cluster_instances: None,
        resource_limits: None,
        cgroup_path: None,
        pid: Some(1234),
        status: ProcessStatus::Running,
        desired_state: DesiredState::Running,
        last_exit_code: None,
        stdout_log: PathBuf::from("/tmp/out.log"),
        stderr_log: PathBuf::from("/tmp/err.log"),
        health_check: None,
        health_status: HealthStatus::Unknown,
        health_failures: 0,
        last_health_check: None,
        next_health_check: None,
        last_health_error: None,
        wait_ready: false,
        ready_timeout_secs: crate::process::default_ready_timeout_secs(),
        cpu_percent: 0.0,
        memory_bytes: 0,
        last_metrics_at: None,
        last_started_at: Some(now_epoch_secs()),
        last_stopped_at: None,
        config_fingerprint: String::new(),
        log_date_format: Some("%Y-%m-%d %H:%M:%S".to_string()),
        unified_logs: false,
        cron_restart: None,
        next_cron_restart: None,
    }
}

fn spawnable_fixture_process() -> ManagedProcess {
    let mut process = fixture_process();
    process.command = std::env::current_exe()
        .expect("failed to resolve current test executable")
        .display()
        .to_string();
    process.args = vec!["--help".to_string()];
    process
}

fn long_running_fixture_process() -> ManagedProcess {
    let mut process = fixture_process();
    #[cfg(windows)]
    {
        // Keep the fixture alive long enough for parallel CI runs on slower
        // Windows runners to complete reload/crash assertions reliably.
        process.command = "powershell".to_string();
        process.args = vec![
            "-NoProfile".to_string(),
            "-Command".to_string(),
            "Start-Sleep -Seconds 30".to_string(),
        ];
    }
    #[cfg(not(windows))]
    {
        // Keep the fixture alive long enough for parallel CI runs to
        // finish the assertion phase before the process exits naturally.
        process.command = "sh".to_string();
        process.args = vec!["-c".to_string(), "sleep 30".to_string()];
    }
    process
}

fn empty_manager(prefix: &str) -> ProcessManager {
    let config = test_config(prefix);
    let (exit_tx, _exit_rx) = unbounded_channel();
    ProcessManager::new(config, exit_tx).expect("failed to create test process manager")
}

fn test_config(prefix: &str) -> AppConfig {
    let base = temp_watch_dir(prefix);
    let log_dir = base.join("logs");
    fs::create_dir_all(&log_dir).expect("failed to create test log directory");
    AppConfig {
        base_dir: base.clone(),
        daemon_addr: "127.0.0.1:50100".to_string(),
        api_addr: "127.0.0.1:51100".to_string(),
        state_path: base.join("state.json"),
        log_dir,
        log_rotation: crate::logging::LogRotationPolicy {
            max_size_bytes: 1024 * 1024,
            max_files: 2,
            max_age_days: 1,
        },
        event_socket_path: base.join("events.sock"),
    }
}

struct GitFixture {
    root: PathBuf,
    remote_dir: PathBuf,
    source_dir: PathBuf,
    clone_dir: PathBuf,
}

fn setup_git_fixture(prefix: &str) -> GitFixture {
    let root = temp_watch_dir(prefix);
    let remote_dir = root.join("remote.git");
    let source_dir = root.join("source");
    let clone_dir = root.join("clone");

    fs::create_dir_all(&root).expect("failed to create git fixture root");
    fs::create_dir_all(&source_dir).expect("failed to create git source dir");
    run_git_sync(
        &root,
        &["init", "--bare", remote_dir.to_str().unwrap_or_default()],
    );
    run_git_sync(&source_dir, &["init"]);
    run_git_sync(&source_dir, &["config", "user.email", "tests@oxmgr.local"]);
    run_git_sync(&source_dir, &["config", "user.name", "Oxmgr Tests"]);
    fs::write(source_dir.join("app.js"), "console.log('v1');\n")
        .expect("failed to write initial source file");
    run_git_sync(&source_dir, &["add", "."]);
    run_git_sync(&source_dir, &["commit", "-m", "initial"]);
    run_git_sync(&source_dir, &["branch", "-M", "main"]);
    run_git_sync(
        &source_dir,
        &[
            "remote",
            "add",
            "origin",
            remote_dir.to_str().unwrap_or_default(),
        ],
    );
    run_git_sync(&source_dir, &["push", "-u", "origin", "main"]);
    run_git_sync(
        &root,
        &[
            "clone",
            remote_dir.to_str().unwrap_or_default(),
            clone_dir.to_str().unwrap_or_default(),
        ],
    );
    run_git_sync(&clone_dir, &["checkout", "main"]);

    GitFixture {
        root,
        remote_dir,
        source_dir,
        clone_dir,
    }
}

fn write_commit_and_push(source_dir: &Path, file_name: &str, content: &str, message: &str) {
    fs::write(source_dir.join(file_name), content).expect("failed writing updated source file");
    run_git_sync(source_dir, &["add", "."]);
    run_git_sync(source_dir, &["commit", "-m", message]);
    run_git_sync(source_dir, &["push", "origin", "main"]);
}

fn git_head(repo_dir: &Path) -> String {
    let output = StdCommand::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .current_dir(repo_dir)
        .output()
        .expect("failed running git rev-parse");
    assert!(
        output.status.success(),
        "git rev-parse failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn run_git_sync(cwd: &Path, args: &[&str]) {
    let output = StdCommand::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("failed to launch git in test");
    assert!(
        output.status.success(),
        "git {:?} failed in {}: {}",
        args,
        cwd.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn cleanup_git_fixture(fixture: GitFixture) {
    let _ = fs::remove_dir_all(fixture.root);
}

fn temp_watch_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock failure")
        .as_nanos();
    std::env::temp_dir().join(format!("oxmgr-{prefix}-{nonce}"))
}

fn command_line(program: &str, args: &[String]) -> String {
    let mut parts = vec![shell_words::quote(program).to_string()];
    for arg in args {
        parts.push(shell_words::quote(arg).to_string());
    }
    parts.join(" ")
}

#[cfg(windows)]
fn failing_readiness_check_command() -> String {
    "powershell -NoProfile -Command \"exit 1\"".to_string()
}

#[cfg(not(windows))]
fn failing_readiness_check_command() -> String {
    "sh -c 'exit 1'".to_string()
}

#[cfg(windows)]
fn successful_readiness_check_command() -> String {
    "powershell -NoProfile -Command \"exit 0\"".to_string()
}

#[cfg(not(windows))]
fn successful_readiness_check_command() -> String {
    "sh -c 'exit 0'".to_string()
}

fn wait_for_process_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if !process_exists(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    !process_exists(pid)
}
