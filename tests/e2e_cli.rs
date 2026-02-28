use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;
use serial_test::serial;

struct TestEnv {
    home: PathBuf,
    daemon_addr: String,
}

static COMMAND_SEQ: AtomicU64 = AtomicU64::new(0);

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
        self.run_with(args, None)
    }

    fn run_in_dir(&self, args: &[&str], cwd: &Path) -> Output {
        self.run_with(args, Some(cwd))
    }

    fn run_with(&self, args: &[&str], cwd: Option<&Path>) -> Output {
        let bin = env!("CARGO_BIN_EXE_oxmgr");
        let command_id = COMMAND_SEQ.fetch_add(1, Ordering::Relaxed);
        let stdout_path = self.home.join(format!("cmd-{command_id}.stdout.log"));
        let stderr_path = self.home.join(format!("cmd-{command_id}.stderr.log"));
        let stdout_file = fs::File::create(&stdout_path).expect("failed to create stdout capture");
        let stderr_file = fs::File::create(&stderr_path).expect("failed to create stderr capture");

        let mut command = Command::new(bin);
        command
            .args(args)
            .env("OXMGR_HOME", &self.home)
            .env("OXMGR_DAEMON_ADDR", &self.daemon_addr)
            .env("OXMGR_LOG_MAX_SIZE_MB", "1")
            .env("OXMGR_LOG_MAX_FILES", "3")
            .env("OXMGR_LOG_MAX_DAYS", "1")
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }

        let mut child = command.spawn().expect("failed to spawn oxmgr command");

        let timeout = Duration::from_secs(60);
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    let status = child.wait().expect("failed to wait for oxmgr command");
                    return read_command_output(status, &stdout_path, &stderr_path);
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let status = child
                            .wait()
                            .expect("failed to wait for timed out oxmgr command");
                        let output = read_command_output(status, &stdout_path, &stderr_path);
                        panic!(
                            "oxmgr command timed out after {:?}: {:?}\nstdout:\n{}\nstderr:\n{}",
                            timeout,
                            args,
                            String::from_utf8_lossy(&output.stdout),
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                    sleep(Duration::from_millis(100));
                }
                Err(err) => {
                    panic!("failed while waiting for oxmgr command {:?}: {err}", args);
                }
            }
        }
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

fn read_command_output(status: ExitStatus, stdout_path: &Path, stderr_path: &Path) -> Output {
    let stdout = fs::read(stdout_path).expect("failed to read captured stdout");
    let stderr = fs::read(stderr_path).expect("failed to read captured stderr");
    let _ = fs::remove_file(stdout_path);
    let _ = fs::remove_file(stderr_path);

    Output {
        status,
        stdout,
        stderr,
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

fn normalize_path_for_compare(path: &Path) -> String {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    normalize_path_text_for_compare(&canonical.to_string_lossy())
}

fn normalize_path_text_for_compare(value: &str) -> String {
    let trimmed = value.trim().trim_matches('"');
    let canonical = fs::canonicalize(trimmed).unwrap_or_else(|_| PathBuf::from(trimmed));
    let rendered = canonical.to_string_lossy();

    #[cfg(windows)]
    {
        rendered
            .trim_start_matches(r"\\?\")
            .replace('/', "\\")
            .to_ascii_lowercase()
    }

    #[cfg(not(windows))]
    {
        rendered.into_owned()
    }
}

fn logs_contain_cwd_env_marker(log_output: &str, expected_cwd: &str, env_value: &str) -> bool {
    log_output.lines().any(|line| {
        let Some((cwd, logged_env_value)) = line.rsplit_once('|') else {
            return false;
        };

        logged_env_value.trim() == env_value && normalize_path_text_for_compare(cwd) == expected_cwd
    })
}

fn escape_toml_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn output_contains(output: &Output, needle: &str) -> bool {
    String::from_utf8_lossy(&output.stdout).contains(needle)
        || String::from_utf8_lossy(&output.stderr).contains(needle)
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

#[cfg(windows)]
fn echo_two_lines_and_sleep_command(first: &str, second: &str, seconds: u64) -> String {
    format!(
        "powershell -NoProfile -Command \"Write-Output {first}; Write-Output {second}; Start-Sleep -Seconds {seconds}\""
    )
}

#[cfg(not(windows))]
fn echo_two_lines_and_sleep_command(first: &str, second: &str, seconds: u64) -> String {
    format!("sh -c 'printf \"%s\\n%s\\n\" \"{first}\" \"{second}\"; sleep {seconds}'")
}

#[cfg(windows)]
fn print_pwd_and_env_then_sleep_command(env_key: &str, seconds: u64) -> String {
    format!(
        "powershell -NoProfile -Command \"$cwd = (Get-Location).Path; $value = [Environment]::GetEnvironmentVariable('{env_key}'); Write-Output \\\"$cwd|$value\\\"; Start-Sleep -Seconds {seconds}\""
    )
}

#[cfg(not(windows))]
fn print_pwd_and_env_then_sleep_command(env_key: &str, seconds: u64) -> String {
    format!("sh -c 'printf \"%s|%s\\n\" \"$PWD\" \"${{{env_key}}}\"; sleep {seconds}'")
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
#[serial]
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
#[serial]
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
#[serial]
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
#[serial]
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
#[serial]
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
#[serial]
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
#[serial]
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

#[test]
#[serial]
fn e2e_apply_prune_removes_unmanaged_process() {
    if !should_run_e2e("e2e_apply_prune_removes_unmanaged_process") {
        return;
    }

    let env = TestEnv::new("apply-prune");

    let start_orphan = env.run_vec(vec![
        "start".to_string(),
        sleep_command(25),
        "--name".to_string(),
        "orphan-app".to_string(),
        "--restart".to_string(),
        "never".to_string(),
        "--stop-timeout".to_string(),
        "1".to_string(),
    ]);
    assert!(
        start_orphan.status.success(),
        "failed to start orphan app: {}",
        String::from_utf8_lossy(&start_orphan.stderr)
    );
    wait_for_pid(&env, "orphan-app", Duration::from_secs(8))
        .expect("expected orphan app pid after startup");

    let oxfile = format!(
        r#"version = 1

[[apps]]
name = "managed-app"
command = "{command}"
restart_policy = "never"
max_restarts = 0
stop_timeout_secs = 1
"#,
        command = escape_toml_string(&sleep_command(25))
    );
    let oxfile_path = env.write_file("fixtures/oxfile.prune.toml", &oxfile);

    let apply = env.run_vec(vec![
        "apply".to_string(),
        path_string(&oxfile_path),
        "--prune".to_string(),
    ]);
    assert!(
        apply.status.success(),
        "apply --prune failed: {}",
        String::from_utf8_lossy(&apply.stderr)
    );
    let apply_stdout = String::from_utf8_lossy(&apply.stdout);
    assert!(
        apply_stdout.contains("Apply complete:")
            && apply_stdout.contains("1 created")
            && apply_stdout.contains("1 pruned"),
        "unexpected apply --prune output: {apply_stdout}"
    );

    wait_for_pid(&env, "managed-app", Duration::from_secs(8))
        .expect("expected managed app pid after apply");

    let orphan_removed = wait_until(Duration::from_secs(8), || {
        let status = env.run(&["status", "orphan-app"]);
        !status.status.success()
    });
    assert!(orphan_removed, "expected orphan-app to be pruned");

    let list = env.run(&["list"]);
    assert!(
        list.status.success(),
        "list failed after apply --prune: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(
        list_stdout.contains("managed-app") && !list_stdout.contains("orphan-app"),
        "unexpected list output after prune: {list_stdout}"
    );

    let _ = env.run(&["delete", "managed-app"]);
}

#[test]
#[serial]
fn e2e_export_import_bundle_roundtrip() {
    if !should_run_e2e("e2e_export_import_bundle_roundtrip") {
        return;
    }

    let env = TestEnv::new("bundle-roundtrip");

    let start = env.run_vec(vec![
        "start".to_string(),
        sleep_command(25),
        "--name".to_string(),
        "bundle-app".to_string(),
        "--restart".to_string(),
        "never".to_string(),
        "--stop-timeout".to_string(),
        "1".to_string(),
        "--namespace".to_string(),
        "bundle-ns".to_string(),
        "--max-memory-mb".to_string(),
        "64".to_string(),
        "--max-cpu-percent".to_string(),
        "25".to_string(),
    ]);
    assert!(
        start.status.success(),
        "start failed: {}",
        String::from_utf8_lossy(&start.stderr)
    );
    wait_for_pid(&env, "bundle-app", Duration::from_secs(8))
        .expect("expected bundle-app pid after startup");

    let bundle_path = env.home.join("exports/bundle-app.oxpkg");
    let export = env.run_vec(vec![
        "export".to_string(),
        "bundle-app".to_string(),
        "--out".to_string(),
        path_string(&bundle_path),
    ]);
    assert!(
        export.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let export_stdout = String::from_utf8_lossy(&export.stdout);
    assert!(
        export_stdout.contains("Exported service bundle:")
            && export_stdout.contains(&path_string(&bundle_path)),
        "unexpected export output: {export_stdout}"
    );
    let bundle_bytes = fs::read(&bundle_path).expect("expected exported bundle to exist");
    assert!(
        !bundle_bytes.is_empty(),
        "expected exported bundle to contain data"
    );

    let delete_original = env.run(&["delete", "bundle-app"]);
    assert!(
        delete_original.status.success(),
        "failed to delete original bundle-app: {}",
        String::from_utf8_lossy(&delete_original.stderr)
    );

    let import = env.run_vec(vec!["import".to_string(), path_string(&bundle_path)]);
    assert!(
        import.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&import.stderr)
    );
    let import_stdout = String::from_utf8_lossy(&import.stdout);
    assert!(
        import_stdout.contains("Imported: 1 started, 0 failed"),
        "unexpected import output: {import_stdout}"
    );
    wait_for_pid(&env, "bundle-app", Duration::from_secs(8))
        .expect("expected bundle-app pid after import");

    let status = env.run(&["status", "bundle-app"]);
    assert!(
        status.status.success(),
        "status failed after import: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        status_stdout.contains("bundle-ns")
            && status_stdout.contains("memory=64 MB")
            && status_stdout.contains("cpu=25.0%")
            && status_stdout.contains("Policy:      never"),
        "unexpected imported status output:\n{status_stdout}"
    );

    let _ = env.run(&["delete", "bundle-app"]);
}

#[test]
#[serial]
fn e2e_start_applies_cwd_env_namespace_and_limits() {
    if !should_run_e2e("e2e_start_applies_cwd_env_namespace_and_limits") {
        return;
    }

    let env = TestEnv::new("start-options");
    let working_dir = env.home.join("workspace/service-a");
    fs::create_dir_all(&working_dir).expect("failed to create working directory fixture");

    let env_key = "OXMGR_E2E_MARKER";
    let env_value = "cwd-env-check";
    let start = env.run_vec(vec![
        "start".to_string(),
        print_pwd_and_env_then_sleep_command(env_key, 20),
        "--name".to_string(),
        "options-app".to_string(),
        "--restart".to_string(),
        "never".to_string(),
        "--stop-timeout".to_string(),
        "1".to_string(),
        "--cwd".to_string(),
        path_string(&working_dir),
        "--env".to_string(),
        format!("{env_key}={env_value}"),
        "--namespace".to_string(),
        "ops".to_string(),
        "--max-memory-mb".to_string(),
        "96".to_string(),
        "--max-cpu-percent".to_string(),
        "12.5".to_string(),
    ]);
    assert!(
        start.status.success(),
        "start with options failed: {}",
        String::from_utf8_lossy(&start.stderr)
    );
    wait_for_pid(&env, "options-app", Duration::from_secs(8))
        .expect("expected options-app pid after startup");

    let status = env.run(&["status", "options-app"]);
    assert!(
        status.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        status_stdout.contains("Namespace:") && status_stdout.contains("ops"),
        "namespace missing from status output:\n{status_stdout}"
    );
    assert!(
        status_stdout.contains("Working Dir:")
            && status_stdout.contains(&path_string(&working_dir)),
        "working dir missing from status output:\n{status_stdout}"
    );
    assert!(
        status_stdout.contains("Limits:")
            && status_stdout.contains("memory=96 MB")
            && status_stdout.contains("cpu=12.5%"),
        "limits missing from status output:\n{status_stdout}"
    );

    let expected_cwd = normalize_path_for_compare(&working_dir);
    let mut last_logs = String::new();
    let found_log_line = wait_until(Duration::from_secs(8), || {
        let logs = env.run(&["logs", "options-app", "--lines", "50"]);
        if !logs.status.success() {
            last_logs = format!(
                "stdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&logs.stdout),
                String::from_utf8_lossy(&logs.stderr)
            );
            return false;
        }
        let stdout = String::from_utf8_lossy(&logs.stdout).into_owned();
        last_logs = format!(
            "stdout:\n{}\nstderr:\n{}",
            stdout,
            String::from_utf8_lossy(&logs.stderr)
        );
        logs_contain_cwd_env_marker(&stdout, &expected_cwd, env_value)
    });
    assert!(
        found_log_line,
        "expected cwd/env marker in logs for {expected_cwd}|{env_value}\n{last_logs}"
    );

    let _ = env.run(&["delete", "options-app"]);
}

#[test]
#[serial]
fn e2e_start_defaults_cwd_to_invocation_directory() {
    if !should_run_e2e("e2e_start_defaults_cwd_to_invocation_directory") {
        return;
    }

    let env = TestEnv::new("start-default-cwd");
    let working_dir = env.home.join("workspace/service-b");
    fs::create_dir_all(&working_dir).expect("failed to create working directory fixture");

    let env_key = "OXMGR_E2E_DEFAULT_CWD";
    let env_value = "cwd-default-check";
    let start = env.run_in_dir(
        &[
            "start",
            &print_pwd_and_env_then_sleep_command(env_key, 20),
            "--name",
            "default-cwd-app",
            "--restart",
            "never",
            "--stop-timeout",
            "1",
            "--env",
            &format!("{env_key}={env_value}"),
        ],
        &working_dir,
    );
    assert!(
        start.status.success(),
        "start with implicit cwd failed: {}",
        String::from_utf8_lossy(&start.stderr)
    );
    wait_for_pid(&env, "default-cwd-app", Duration::from_secs(8))
        .expect("expected default-cwd-app pid after startup");

    let status = env.run(&["status", "default-cwd-app"]);
    assert!(
        status.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        status_stdout.contains("Working Dir:")
            && status_stdout.contains(&path_string(&working_dir)),
        "working dir missing from status output:\n{status_stdout}"
    );

    let expected_cwd = normalize_path_for_compare(&working_dir);
    let mut last_logs = String::new();
    let found_log_line = wait_until(Duration::from_secs(8), || {
        let logs = env.run(&["logs", "default-cwd-app", "--lines", "50"]);
        if !logs.status.success() {
            last_logs = format!(
                "stdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&logs.stdout),
                String::from_utf8_lossy(&logs.stderr)
            );
            return false;
        }
        let stdout = String::from_utf8_lossy(&logs.stdout).into_owned();
        last_logs = format!(
            "stdout:\n{}\nstderr:\n{}",
            stdout,
            String::from_utf8_lossy(&logs.stderr)
        );
        logs_contain_cwd_env_marker(&stdout, &expected_cwd, env_value)
    });
    assert!(
        found_log_line,
        "expected cwd/env marker in logs for {expected_cwd}|{env_value}\n{last_logs}"
    );

    let _ = env.run(&["delete", "default-cwd-app"]);
}

#[test]
#[serial]
fn e2e_validate_profile_and_only_reports_expanded_processes() {
    if !should_run_e2e("e2e_validate_profile_and_only_reports_expanded_processes") {
        return;
    }

    let env = TestEnv::new("validate-profile-only");
    let oxfile = format!(
        "{}/docs/examples/oxfile.profiles.toml",
        env!("CARGO_MANIFEST_DIR")
    );

    let output = env.run(&["validate", &oxfile, "--env", "prod", "--only", "api"]);
    assert!(
        output.status.success(),
        "validate with profile/only failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Oxfile validation: OK")
            && stdout.contains("Profile: prod")
            && stdout.contains("Apps: 1")
            && stdout.contains("Expanded Processes: 4"),
        "unexpected validate profile/only output:\n{stdout}"
    );
}

#[test]
#[serial]
fn e2e_validate_rejects_only_filter_without_matches() {
    if !should_run_e2e("e2e_validate_rejects_only_filter_without_matches") {
        return;
    }

    let env = TestEnv::new("validate-only-miss");
    let oxfile = format!(
        "{}/docs/examples/oxfile.profiles.toml",
        env!("CARGO_MANIFEST_DIR")
    );

    let output = env.run(&["validate", &oxfile, "--only", "missing-app"]);
    assert!(
        !output.status.success(),
        "validate unexpectedly succeeded for missing --only match"
    );
    assert!(
        output_contains(&output, "no apps matched --only filter (missing-app)"),
        "unexpected validate --only failure\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[serial]
fn e2e_validate_rejects_invalid_cluster_command() {
    if !should_run_e2e("e2e_validate_rejects_invalid_cluster_command") {
        return;
    }

    let env = TestEnv::new("validate-bad-cluster");
    let oxfile = env.write_file(
        "fixtures/oxfile.bad-cluster.toml",
        r#"version = 1

[[apps]]
name = "bad-cluster"
command = "python worker.py"
cluster_mode = true
cluster_instances = 2
"#,
    );

    let output = env.run_vec(vec!["validate".to_string(), path_string(&oxfile)]);
    assert!(
        !output.status.success(),
        "validate unexpectedly succeeded for invalid cluster command"
    );
    assert!(
        output_contains(&output, "cluster_mode but command is not Node.js"),
        "unexpected invalid cluster validation output\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[serial]
fn e2e_import_oxfile_profile_and_only_expands_instances() {
    if !should_run_e2e("e2e_import_oxfile_profile_and_only_expands_instances") {
        return;
    }

    let env = TestEnv::new("import-profile-only");
    let sleep = escape_toml_string(&sleep_command(25));
    let oxfile = format!(
        r#"version = 1

[[apps]]
name = "api"
command = "{sleep}"
restart_policy = "never"
max_restarts = 0
stop_timeout_secs = 1

[apps.profiles.prod]
instances = 2
namespace = "blue"

[apps.profiles.prod.env]
MODE = "prod"

[[apps]]
name = "worker"
command = "{sleep}"
restart_policy = "never"
max_restarts = 0
stop_timeout_secs = 1

[apps.profiles.prod]
disabled = true
"#
    );
    let oxfile_path = env.write_file("fixtures/oxfile.import-profile.toml", &oxfile);

    let import = env.run_vec(vec![
        "import".to_string(),
        path_string(&oxfile_path),
        "--env".to_string(),
        "prod".to_string(),
        "--only".to_string(),
        "api-0,api-1".to_string(),
    ]);
    assert!(
        import.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&import.stderr)
    );
    let import_stdout = String::from_utf8_lossy(&import.stdout);
    assert!(
        import_stdout.contains("Imported: 2 started, 0 failed"),
        "unexpected import output:\n{import_stdout}"
    );

    for target in ["api-0", "api-1"] {
        wait_for_pid(&env, target, Duration::from_secs(8))
            .unwrap_or_else(|| panic!("expected {target} pid after import"));
    }

    let list = env.run(&["list"]);
    assert!(
        list.status.success(),
        "list failed after import: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(
        list_stdout.contains("api-0")
            && list_stdout.contains("api-1")
            && !list_stdout.contains("worker"),
        "unexpected import list output:\n{list_stdout}"
    );

    let status = env.run(&["status", "api-0"]);
    assert!(
        status.status.success(),
        "status failed for imported api-0: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        status_stdout.contains("Namespace:") && status_stdout.contains("blue"),
        "expected namespace from profile in imported process status:\n{status_stdout}"
    );

    for target in ["api-0", "api-1"] {
        let _ = env.run(&["delete", target]);
    }
}

#[test]
#[serial]
fn e2e_export_rejects_existing_output_file() {
    if !should_run_e2e("e2e_export_rejects_existing_output_file") {
        return;
    }

    let env = TestEnv::new("export-existing-file");
    let start = env.run_vec(vec![
        "start".to_string(),
        sleep_command(25),
        "--name".to_string(),
        "export-app".to_string(),
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
    wait_for_pid(&env, "export-app", Duration::from_secs(8))
        .expect("expected export-app pid after startup");

    let bundle_path = env.write_file("exports/existing.oxpkg", "already here");
    let export = env.run_vec(vec![
        "export".to_string(),
        "export-app".to_string(),
        "--out".to_string(),
        path_string(&bundle_path),
    ]);
    assert!(
        !export.status.success(),
        "export unexpectedly succeeded despite existing output file"
    );
    assert!(
        output_contains(&export, "failed to create bundle file"),
        "unexpected export failure output\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&export.stdout),
        String::from_utf8_lossy(&export.stderr)
    );

    let _ = env.run(&["delete", "export-app"]);
}

#[test]
#[serial]
fn e2e_doctor_reports_running_daemon_and_processes() {
    if !should_run_e2e("e2e_doctor_reports_running_daemon_and_processes") {
        return;
    }

    let env = TestEnv::new("doctor");
    let start = env.run_vec(vec![
        "start".to_string(),
        sleep_command(20),
        "--name".to_string(),
        "doctor-app".to_string(),
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
    wait_for_pid(&env, "doctor-app", Duration::from_secs(8))
        .expect("expected doctor-app pid after startup");

    let doctor = env.run(&["doctor"]);
    assert!(
        doctor.status.success(),
        "doctor failed: {}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        stdout.contains("Oxmgr doctor")
            && stdout.contains("[OK] daemon_ping")
            && stdout.contains("[OK] daemon_list")
            && stdout.contains("1 managed process(es)"),
        "unexpected doctor output:\n{stdout}"
    );

    let _ = env.run(&["delete", "doctor-app"]);
}

#[test]
#[serial]
fn e2e_start_rejects_cluster_instances_without_cluster() {
    if !should_run_e2e("e2e_start_rejects_cluster_instances_without_cluster") {
        return;
    }

    let env = TestEnv::new("start-bad-cluster");
    let output = env.run_vec(vec![
        "start".to_string(),
        sleep_command(10),
        "--name".to_string(),
        "bad-cluster".to_string(),
        "--cluster-instances".to_string(),
        "2".to_string(),
    ]);

    assert!(
        !output.status.success(),
        "start unexpectedly succeeded without --cluster"
    );
    assert!(
        output_contains(&output, "--cluster-instances requires --cluster"),
        "unexpected cluster validation output\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[serial]
fn e2e_list_empty_prints_no_managed_processes() {
    if !should_run_e2e("e2e_list_empty_prints_no_managed_processes") {
        return;
    }

    let env = TestEnv::new("list-empty");
    let list = env.run(&["list"]);
    assert!(
        list.status.success(),
        "list failed on empty env: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(
        stdout.contains("No managed processes."),
        "unexpected empty list output:\n{stdout}"
    );
}

#[test]
#[serial]
fn e2e_stop_clears_pid_and_marks_process_stopped() {
    if !should_run_e2e("e2e_stop_clears_pid_and_marks_process_stopped") {
        return;
    }

    let env = TestEnv::new("stop-status");
    let start = env.run_vec(vec![
        "start".to_string(),
        sleep_command(25),
        "--name".to_string(),
        "stop-app".to_string(),
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
    wait_for_pid(&env, "stop-app", Duration::from_secs(8))
        .expect("expected stop-app pid after startup");

    let stop = env.run(&["stop", "stop-app"]);
    assert!(
        stop.status.success(),
        "stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    assert!(
        output_contains(&stop, "stopped stop-app"),
        "unexpected stop output\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stop.stdout),
        String::from_utf8_lossy(&stop.stderr)
    );

    let status = env.run(&["status", "stop-app"]);
    assert!(
        status.status.success(),
        "status failed after stop: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        stdout.contains("Status:      stopped") && stdout.contains("PID:         -"),
        "unexpected stopped status output:\n{stdout}"
    );

    let list = env.run(&["list"]);
    assert!(
        list.status.success(),
        "list failed after stop: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    assert!(
        list_stdout.contains("stop-app") && list_stdout.contains("stopped"),
        "unexpected list output after stop:\n{list_stdout}"
    );

    let _ = env.run(&["delete", "stop-app"]);
}

#[test]
#[serial]
fn e2e_doctor_warns_when_daemon_not_running() {
    if !should_run_e2e("e2e_doctor_warns_when_daemon_not_running") {
        return;
    }

    let env = TestEnv::new("doctor-no-daemon");
    let doctor = env.run(&["doctor"]);
    assert!(
        doctor.status.success(),
        "doctor failed unexpectedly: {}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        stdout.contains("Oxmgr doctor")
            && stdout.contains("[WARN] daemon_ping")
            && stdout.contains("daemon not reachable")
            && stdout.contains("Summary:")
            && stdout.contains("warning(s), 0 failure(s)"),
        "unexpected doctor no-daemon output:\n{stdout}"
    );
}

#[test]
#[serial]
fn e2e_daemon_stop_reports_not_running_when_idle() {
    if !should_run_e2e("e2e_daemon_stop_reports_not_running_when_idle") {
        return;
    }

    let env = TestEnv::new("daemon-stop-idle");
    let output = env.run(&["daemon", "stop"]);
    assert!(
        output.status.success(),
        "daemon stop should succeed when idle: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Daemon is not running."),
        "unexpected daemon stop output:\n{stdout}"
    );
}

#[test]
#[serial]
fn e2e_apply_profile_with_all_apps_disabled_reports_no_apps() {
    if !should_run_e2e("e2e_apply_profile_with_all_apps_disabled_reports_no_apps") {
        return;
    }

    let env = TestEnv::new("apply-no-apps");
    let oxfile = env.write_file(
        "fixtures/oxfile.no-apps.toml",
        &format!(
            r#"version = 1

[[apps]]
name = "disabled-app"
command = "{command}"
restart_policy = "never"
max_restarts = 0
stop_timeout_secs = 1

[apps.profiles.prod]
disabled = true
"#,
            command = escape_toml_string(&sleep_command(10))
        ),
    );

    let apply = env.run_vec(vec![
        "apply".to_string(),
        path_string(&oxfile),
        "--env".to_string(),
        "prod".to_string(),
    ]);
    assert!(
        apply.status.success(),
        "apply should succeed when profile disables all apps: {}",
        String::from_utf8_lossy(&apply.stderr)
    );
    let stdout = String::from_utf8_lossy(&apply.stdout);
    assert!(
        stdout.contains("No apps found in"),
        "unexpected apply no-apps output:\n{stdout}"
    );
}

#[test]
#[serial]
fn e2e_logs_lines_returns_only_tail() {
    if !should_run_e2e("e2e_logs_lines_returns_only_tail") {
        return;
    }

    let env = TestEnv::new("logs-tail");
    let first = "OXMGR_E2E_FIRST";
    let second = "OXMGR_E2E_SECOND";
    let start = env.run_vec(vec![
        "start".to_string(),
        echo_two_lines_and_sleep_command(first, second, 15),
        "--name".to_string(),
        "tail-app".to_string(),
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
        let logs = env.run(&["logs", "tail-app", "--lines", "1"]);
        if !logs.status.success() {
            return false;
        }
        let stdout = String::from_utf8_lossy(&logs.stdout);
        stdout.contains(second) && !stdout.contains(first)
    });
    assert!(found, "expected logs --lines 1 to show only the tail line");

    let _ = env.run(&["delete", "tail-app"]);
}

#[test]
#[serial]
fn e2e_missing_target_commands_report_process_not_found() {
    if !should_run_e2e("e2e_missing_target_commands_report_process_not_found") {
        return;
    }

    let env = TestEnv::new("missing-targets");
    let commands = [
        vec!["status".to_string(), "missing-app".to_string()],
        vec!["logs".to_string(), "missing-app".to_string()],
        vec!["stop".to_string(), "missing-app".to_string()],
        vec!["restart".to_string(), "missing-app".to_string()],
        vec!["reload".to_string(), "missing-app".to_string()],
        vec!["delete".to_string(), "missing-app".to_string()],
        vec!["export".to_string(), "missing-app".to_string()],
    ];

    for args in commands {
        let output = env.run_vec(args.clone());
        assert!(
            !output.status.success(),
            "command unexpectedly succeeded for missing target: {:?}",
            args
        );
        assert!(
            output_contains(&output, "process not found: missing-app"),
            "unexpected missing-target output for {:?}\nstdout:\n{}\nstderr:\n{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
