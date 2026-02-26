use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

struct TestEnv {
    home: PathBuf,
    daemon_addr: String,
}

impl TestEnv {
    fn new(prefix: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        let home = std::env::temp_dir().join(format!("oxmgr-e2e-{prefix}-{nonce}"));
        fs::create_dir_all(&home).expect("failed to create temporary home");

        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind random port");
        let port = listener
            .local_addr()
            .expect("failed to resolve local addr")
            .port();
        drop(listener);

        Self {
            home,
            daemon_addr: format!("127.0.0.1:{port}"),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        let bin = env!("CARGO_BIN_EXE_oxmgr");
        Command::new(bin)
            .args(args)
            .env("OXMGR_HOME", &self.home)
            .env("OXMGR_DAEMON_ADDR", &self.daemon_addr)
            .env("OXMGR_LOG_MAX_SIZE_MB", "1")
            .env("OXMGR_LOG_MAX_FILES", "3")
            .env("OXMGR_LOG_MAX_DAYS", "1")
            .output()
            .expect("failed to execute oxmgr command")
    }

    fn run_vec(&self, args: Vec<String>) -> Output {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run(&refs)
    }

    fn write_file(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.home.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("failed to create parent directory");
        }
        fs::write(&path, contents).expect("failed to write fixture file");
        path
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = self.run(&["daemon", "stop"]);
        let _ = fs::remove_dir_all(&self.home);
    }
}

fn should_run_e2e(test_name: &str) -> bool {
    if std::env::var("OXMGR_RUN_E2E").ok().as_deref() == Some("1") {
        true
    } else {
        eprintln!("skipping {test_name} (set OXMGR_RUN_E2E=1 to run)");
        false
    }
}

fn wait_until<F>(timeout: Duration, mut predicate: F) -> bool
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        sleep(Duration::from_millis(150));
    }
    predicate()
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn escape_toml_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(windows)]
fn sleep_command(seconds: u64) -> String {
    format!("powershell -NoProfile -Command \"Start-Sleep -Seconds {seconds}\"")
}

#[cfg(not(windows))]
fn sleep_command(seconds: u64) -> String {
    format!("sh -c 'sleep {seconds}'")
}

#[cfg(windows)]
fn echo_and_sleep_command(marker: &str, seconds: u64) -> String {
    format!(
        "powershell -NoProfile -Command \"Write-Output {marker}; Start-Sleep -Seconds {seconds}\""
    )
}

#[cfg(not(windows))]
fn echo_and_sleep_command(marker: &str, seconds: u64) -> String {
    format!("sh -c 'echo {marker}; sleep {seconds}'")
}

fn parse_pid_from_status(output: &str) -> Option<u32> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "PID" {
            return None;
        }
        let value = value.trim();
        if value == "-" {
            None
        } else {
            value.parse::<u32>().ok()
        }
    })
}

fn wait_for_pid(env: &TestEnv, target: &str, timeout: Duration) -> Option<u32> {
    let mut pid = None;
    let found = wait_until(timeout, || {
        let output = env.run(&["status", target]);
        if !output.status.success() {
            return false;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        pid = parse_pid_from_status(&stdout);
        pid.is_some()
    });

    if found {
        pid
    } else {
        None
    }
}

#[test]
fn e2e_process_lifecycle() {
    if !should_run_e2e("e2e_process_lifecycle") {
        return;
    }

    let env = TestEnv::new("lifecycle");
    let command = sleep_command(15);

    let start = env.run_vec(vec![
        "start".to_string(),
        command,
        "--name".to_string(),
        "e2e".to_string(),
        "--restart".to_string(),
        "never".to_string(),
        "--stop-timeout".to_string(),
        "1".to_string(),
    ]);
    assert!(
        start.status.success(),
        "start failed: {}",
        String::from_utf8_lossy(&start.stderr)
    );

    let list = env.run(&["list"]);
    assert!(
        list.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(
        list_stdout.contains("e2e"),
        "unexpected list output: {list_stdout}"
    );

    let restart = env.run(&["restart", "e2e"]);
    assert!(
        restart.status.success(),
        "restart failed: {}",
        String::from_utf8_lossy(&restart.stderr)
    );

    let stop = env.run(&["stop", "e2e"]);
    assert!(
        stop.status.success(),
        "stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );

    let delete = env.run(&["delete", "e2e"]);
    assert!(
        delete.status.success(),
        "delete failed: {}",
        String::from_utf8_lossy(&delete.stderr)
    );
}

#[test]
fn e2e_validate_oxfile() {
    if !should_run_e2e("e2e_validate_oxfile") {
        return;
    }

    let env = TestEnv::new("validate");
    let oxfile = format!(
        "{}/docs/examples/oxfile.web-stack.toml",
        env!("CARGO_MANIFEST_DIR")
    );

    let output = env.run(&["validate", &oxfile]);
    assert!(
        output.status.success(),
        "validate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Oxfile validation: OK"),
        "unexpected validate output: {stdout}"
    );
}

#[test]
fn e2e_validate_rejects_non_toml_input() {
    if !should_run_e2e("e2e_validate_rejects_non_toml_input") {
        return;
    }

    let env = TestEnv::new("validate-non-toml");
    let ecosystem_path = env.write_file("ecosystem.config.json", r#"{"apps":[]}"#);
    let output = env.run_vec(vec!["validate".to_string(), path_string(&ecosystem_path)]);

    assert!(
        !output.status.success(),
        "validate unexpectedly succeeded for non-toml input"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stderr.contains("validate expects oxfile.toml input")
            || stdout.contains("validate expects oxfile.toml input"),
        "unexpected validate failure output\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn e2e_convert_ecosystem_to_oxfile_and_validate() {
    if !should_run_e2e("e2e_convert_ecosystem_to_oxfile_and_validate") {
        return;
    }

    let env = TestEnv::new("convert");
    let ecosystem_payload = json!({
        "apps": [
            {
                "name": "converted-app",
                "cmd": sleep_command(20),
                "autorestart": false,
                "max_restarts": 0,
                "stop_timeout": 1
            }
        ]
    });
    let ecosystem_path = env.write_file(
        "fixtures/ecosystem.config.json",
        &serde_json::to_string_pretty(&ecosystem_payload)
            .expect("failed to serialize ecosystem fixture"),
    );
    let oxfile_path = env.home.join("fixtures/oxfile.converted.toml");

    let convert = env.run_vec(vec![
        "convert".to_string(),
        path_string(&ecosystem_path),
        "--out".to_string(),
        path_string(&oxfile_path),
    ]);
    assert!(
        convert.status.success(),
        "convert failed: {}",
        String::from_utf8_lossy(&convert.stderr)
    );

    let generated =
        fs::read_to_string(&oxfile_path).expect("converted oxfile should exist and be readable");
    assert!(
        generated.contains("version = 1") && generated.contains("name = \"converted-app\""),
        "unexpected converted oxfile:\n{generated}"
    );

    let validate = env.run_vec(vec!["validate".to_string(), path_string(&oxfile_path)]);
    assert!(
        validate.status.success(),
        "validate failed: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
}

#[test]
fn e2e_apply_is_idempotent() {
    if !should_run_e2e("e2e_apply_is_idempotent") {
        return;
    }

    let env = TestEnv::new("apply-idempotent");
    let command = escape_toml_string(&sleep_command(25));
    let oxfile = format!(
        r#"version = 1

[[apps]]
name = "idempotent-app"
command = "{command}"
restart_policy = "never"
max_restarts = 0
stop_timeout_secs = 1
"#
    );
    let oxfile_path = env.write_file("fixtures/oxfile.idempotent.toml", &oxfile);

    let first_apply = env.run_vec(vec!["apply".to_string(), path_string(&oxfile_path)]);
    assert!(
        first_apply.status.success(),
        "first apply failed: {}",
        String::from_utf8_lossy(&first_apply.stderr)
    );
    let first_stdout = String::from_utf8_lossy(&first_apply.stdout);
    assert!(
        first_stdout.contains("Apply complete:") && first_stdout.contains("1 created"),
        "unexpected first apply output: {first_stdout}"
    );

    let second_apply = env.run_vec(vec!["apply".to_string(), path_string(&oxfile_path)]);
    assert!(
        second_apply.status.success(),
        "second apply failed: {}",
        String::from_utf8_lossy(&second_apply.stderr)
    );
    let second_stdout = String::from_utf8_lossy(&second_apply.stdout);
    assert!(
        second_stdout.contains("Apply complete:") && second_stdout.contains("1 unchanged"),
        "apply was not idempotent, output: {second_stdout}"
    );

    let _ = env.run(&["delete", "idempotent-app"]);
}

#[test]
fn e2e_reload_replaces_pid() {
    if !should_run_e2e("e2e_reload_replaces_pid") {
        return;
    }

    let env = TestEnv::new("reload");
    let command = sleep_command(30);
    let start = env.run_vec(vec![
        "start".to_string(),
        command,
        "--name".to_string(),
        "reload-app".to_string(),
        "--restart".to_string(),
        "never".to_string(),
        "--stop-timeout".to_string(),
        "1".to_string(),
    ]);
    assert!(
        start.status.success(),
        "start failed: {}",
        String::from_utf8_lossy(&start.stderr)
    );

    let old_pid = wait_for_pid(&env, "reload-app", Duration::from_secs(8))
        .expect("expected pid after starting process");

    let reload = env.run(&["reload", "reload-app"]);
    assert!(
        reload.status.success(),
        "reload failed: {}",
        String::from_utf8_lossy(&reload.stderr)
    );

    let mut new_pid = None;
    let replaced = wait_until(Duration::from_secs(8), || {
        let output = env.run(&["status", "reload-app"]);
        if !output.status.success() {
            return false;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        new_pid = parse_pid_from_status(&stdout);
        new_pid.is_some() && new_pid != Some(old_pid) && stdout.contains("Status:      running")
    });
    assert!(
        replaced,
        "expected reload to replace pid (old={old_pid}, new={new_pid:?})"
    );

    let _ = env.run(&["delete", "reload-app"]);
}

#[test]
fn e2e_logs_show_stdout_content() {
    if !should_run_e2e("e2e_logs_show_stdout_content") {
        return;
    }

    let env = TestEnv::new("logs");
    let marker = "OXMGR_E2E_LOG_MARKER";
    let command = echo_and_sleep_command(marker, 15);
    let start = env.run_vec(vec![
        "start".to_string(),
        command,
        "--name".to_string(),
        "logs-app".to_string(),
        "--restart".to_string(),
        "never".to_string(),
        "--stop-timeout".to_string(),
        "1".to_string(),
    ]);
    assert!(
        start.status.success(),
        "start failed: {}",
        String::from_utf8_lossy(&start.stderr)
    );

    let found = wait_until(Duration::from_secs(8), || {
        let logs = env.run(&["logs", "logs-app", "--lines", "50"]);
        if !logs.status.success() {
            return false;
        }
        let stdout = String::from_utf8_lossy(&logs.stdout);
        stdout.contains(marker)
    });
    assert!(found, "expected marker to be present in logs output");

    let _ = env.run(&["delete", "logs-app"]);
}
