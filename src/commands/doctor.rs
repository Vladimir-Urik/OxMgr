use std::fs;
use std::io::{ErrorKind, Write};
use std::net::{TcpListener, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::cli::InitSystem;
use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::process::ManagedProcess;
use crate::storage::PersistedState;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum DoctorStatus {
    Ok,
    Warn,
    Fail,
}

impl DoctorStatus {
    fn label(self) -> &'static str {
        match self {
            DoctorStatus::Ok => "OK",
            DoctorStatus::Warn => "WARN",
            DoctorStatus::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum BindStatus {
    Free,
    Occupied,
    Unavailable,
}

pub(crate) async fn run(config: &AppConfig) -> Result<()> {
    println!("Oxmgr doctor");
    println!("Home: {}", config.base_dir.display());
    println!("Daemon: {}", config.daemon_addr);
    println!("API: {}", config.api_addr);
    println!();

    let mut passed = 0_usize;
    let mut warned = 0_usize;
    let mut failed = 0_usize;

    let mut record = |status: DoctorStatus, name: &str, detail: String| {
        print_doctor_check(status, name, detail);
        match status {
            DoctorStatus::Ok => passed = passed.saturating_add(1),
            DoctorStatus::Warn => warned = warned.saturating_add(1),
            DoctorStatus::Fail => failed = failed.saturating_add(1),
        }
    };

    if config.base_dir.exists() {
        record(
            DoctorStatus::Ok,
            "base_dir",
            format!("{}", config.base_dir.display()),
        );
    } else {
        record(
            DoctorStatus::Fail,
            "base_dir",
            format!("missing path {}", config.base_dir.display()),
        );
    }

    if config.log_dir.exists() {
        record(
            DoctorStatus::Ok,
            "log_dir",
            format!("{}", config.log_dir.display()),
        );
    } else {
        record(
            DoctorStatus::Fail,
            "log_dir",
            format!("missing path {}", config.log_dir.display()),
        );
    }

    match check_directory_writable(&config.base_dir) {
        Ok(()) => record(
            DoctorStatus::Ok,
            "base_write",
            "directory is writable".to_string(),
        ),
        Err(err) => record(DoctorStatus::Fail, "base_write", err.to_string()),
    }

    match check_directory_writable(&config.log_dir) {
        Ok(()) => record(
            DoctorStatus::Ok,
            "log_write",
            "directory is writable".to_string(),
        ),
        Err(err) => record(DoctorStatus::Fail, "log_write", err.to_string()),
    }

    let daemon_addr_resolved = match resolve_socket_addr(&config.daemon_addr) {
        Ok(resolved) => {
            record(DoctorStatus::Ok, "daemon_addr", resolved);
            true
        }
        Err(err) => {
            record(DoctorStatus::Fail, "daemon_addr", err.to_string());
            false
        }
    };

    let api_addr_resolved = match resolve_socket_addr(&config.api_addr) {
        Ok(resolved) => {
            record(DoctorStatus::Ok, "api_addr", resolved);
            true
        }
        Err(err) => {
            record(DoctorStatus::Fail, "api_addr", err.to_string());
            false
        }
    };

    let persisted_state = match inspect_state_file(&config.state_path) {
        Ok((status, detail, state)) => {
            record(status, "state_file", detail);
            state
        }
        Err(err) => {
            record(DoctorStatus::Fail, "state_file", err.to_string());
            PersistedState::default()
        }
    };

    if daemon_addr_resolved {
        match send_request(&config.daemon_addr, &IpcRequest::Ping).await {
            Ok(response) if response.ok => {
                record(
                    DoctorStatus::Ok,
                    "daemon_ping",
                    "daemon responded".to_string(),
                );

                match send_request(&config.daemon_addr, &IpcRequest::List).await {
                    Ok(response) if response.ok => record(
                        DoctorStatus::Ok,
                        "daemon_list",
                        format!("{} managed process(es)", response.processes.len()),
                    ),
                    Ok(response) => record(DoctorStatus::Fail, "daemon_list", response.message),
                    Err(err) => record(DoctorStatus::Fail, "daemon_list", err.to_string()),
                }
            }
            Ok(response) => record(DoctorStatus::Fail, "daemon_ping", response.message),
            Err(err) => match probe_bind_status(&config.daemon_addr) {
                Ok(BindStatus::Free) => record(
                    DoctorStatus::Warn,
                    "daemon_ping",
                    format!("daemon not reachable ({err})"),
                ),
                Ok(BindStatus::Occupied) => record(
                    DoctorStatus::Fail,
                    "daemon_ping",
                    format!("daemon address is occupied but not responding ({err})"),
                ),
                Ok(BindStatus::Unavailable) => record(
                    DoctorStatus::Fail,
                    "daemon_ping",
                    format!("daemon address is not bindable ({err})"),
                ),
                Err(bind_err) => record(
                    DoctorStatus::Fail,
                    "daemon_ping",
                    format!("{err}; bind probe failed: {bind_err}"),
                ),
            },
        }
    }

    if api_addr_resolved {
        match probe_metrics_endpoint(&config.api_addr).await {
            Ok(detail) => record(DoctorStatus::Ok, "api_metrics", detail),
            Err(err) => match probe_bind_status(&config.api_addr) {
                Ok(BindStatus::Free) => record(
                    DoctorStatus::Warn,
                    "api_metrics",
                    format!("webhook API not reachable ({err})"),
                ),
                Ok(BindStatus::Occupied) => record(
                    DoctorStatus::Fail,
                    "api_metrics",
                    format!("API address is occupied but /metrics probe failed ({err})"),
                ),
                Ok(BindStatus::Unavailable) => record(
                    DoctorStatus::Fail,
                    "api_metrics",
                    format!("API address is not bindable ({err})"),
                ),
                Err(bind_err) => record(
                    DoctorStatus::Fail,
                    "api_metrics",
                    format!("{err}; bind probe failed: {bind_err}"),
                ),
            },
        }
    }

    let service_system = resolve_init_system();
    let (service_unit_status, service_unit_detail) = inspect_service_definition(service_system);
    record(service_unit_status, "service_unit", service_unit_detail);
    let (service_runtime_status, service_runtime_detail) = inspect_service_runtime(service_system);
    record(
        service_runtime_status,
        "service_runtime",
        service_runtime_detail,
    );

    let (cgroup_status, cgroup_detail) = inspect_cgroup_support(&persisted_state.processes);
    record(cgroup_status, "cgroup", cgroup_detail);

    let (git_pull_status, git_pull_detail) = inspect_git_pull_setup(&persisted_state.processes);
    record(git_pull_status, "git_pull", git_pull_detail);

    record(
        DoctorStatus::Ok,
        "log_policy",
        format!(
            "{} MB, {} file(s), {} day(s)",
            config.log_rotation.max_size_bytes / (1024 * 1024),
            config.log_rotation.max_files,
            config.log_rotation.max_age_days
        ),
    );

    println!();
    println!(
        "Summary: {} ok, {} warning(s), {} failure(s)",
        passed, warned, failed
    );

    if failed > 0 {
        anyhow::bail!("doctor reported failures");
    }

    Ok(())
}

fn print_doctor_check(status: DoctorStatus, name: &str, detail: impl AsRef<str>) {
    println!("[{}] {:<16} {}", status.label(), name, detail.as_ref());
}

fn inspect_state_file(path: &Path) -> Result<(DoctorStatus, String, PersistedState)> {
    if !path.exists() {
        return Ok((
            DoctorStatus::Ok,
            format!("{} (not created yet)", path.display()),
            PersistedState::default(),
        ));
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read state file {}", path.display()))?;
    if content.trim().is_empty() {
        return Ok((
            DoctorStatus::Warn,
            format!("{} is empty", path.display()),
            PersistedState::default(),
        ));
    }

    let state = serde_json::from_str::<PersistedState>(&content)
        .with_context(|| format!("{} is not valid state JSON", path.display()))?;
    Ok((
        DoctorStatus::Ok,
        format!("{} ({} processes)", path.display(), state.processes.len()),
        state,
    ))
}

fn resolve_socket_addr(addr: &str) -> Result<String> {
    let mut addrs = addr
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {addr}"))?;
    Ok(addrs
        .next()
        .map(|resolved| resolved.to_string())
        .unwrap_or_else(|| "no resolved address".to_string()))
}

fn check_directory_writable(path: &Path) -> Result<()> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let probe = path.join(format!(".oxmgr-doctor-{nonce}.tmp"));

    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&probe)
        .with_context(|| format!("failed to create probe file {}", probe.display()))?;
    file.write_all(b"ok")
        .with_context(|| format!("failed to write probe file {}", probe.display()))?;
    fs::remove_file(&probe)
        .with_context(|| format!("failed to remove probe file {}", probe.display()))?;

    Ok(())
}

fn probe_bind_status(addr: &str) -> Result<BindStatus> {
    match TcpListener::bind(addr) {
        Ok(listener) => {
            drop(listener);
            Ok(BindStatus::Free)
        }
        Err(err) if err.kind() == ErrorKind::AddrInUse => Ok(BindStatus::Occupied),
        Err(err)
            if err.kind() == ErrorKind::AddrNotAvailable
                || err.kind() == ErrorKind::PermissionDenied =>
        {
            let _ = err;
            Ok(BindStatus::Unavailable)
        }
        Err(err) => Err(err).with_context(|| format!("failed to probe bindability of {addr}")),
    }
}

async fn probe_metrics_endpoint(addr: &str) -> Result<String> {
    let mut stream = timeout(NETWORK_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("timed out connecting to webhook API")?
        .with_context(|| format!("failed to connect to webhook API at {addr}"))?;
    let request = format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");

    timeout(NETWORK_TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .context("timed out sending /metrics request")?
        .context("failed to send /metrics request")?;

    let _ = timeout(NETWORK_TIMEOUT, stream.shutdown()).await;

    let mut response = Vec::new();
    timeout(NETWORK_TIMEOUT, stream.read_to_end(&mut response))
        .await
        .context("timed out reading /metrics response")?
        .context("failed to read /metrics response")?;

    let (status, body) = parse_http_response(&response)?;
    if status != 200 {
        anyhow::bail!("/metrics returned HTTP {status}");
    }
    if !body.contains("oxmgr_managed_processes") {
        anyhow::bail!("/metrics response did not contain oxmgr metrics");
    }

    let line_count = body.lines().filter(|line| !line.trim().is_empty()).count();
    Ok(format!(
        "GET /metrics responded 200 ({line_count} metric lines)"
    ))
}

fn parse_http_response(bytes: &[u8]) -> Result<(u16, String)> {
    let response =
        String::from_utf8(bytes.to_vec()).context("HTTP response was not valid UTF-8")?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .or_else(|| response.split_once("\n\n"))
        .context("HTTP response did not contain a header/body separator")?;
    let status_line = head.lines().next().context("HTTP response was empty")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .context("HTTP response was missing status code")?
        .parse::<u16>()
        .context("HTTP response status code was not numeric")?;
    Ok((status, body.to_string()))
}

fn resolve_init_system() -> InitSystem {
    if cfg!(target_os = "macos") {
        InitSystem::Launchd
    } else if cfg!(target_os = "windows") {
        InitSystem::TaskScheduler
    } else {
        InitSystem::Systemd
    }
}

fn inspect_service_definition(system: InitSystem) -> (DoctorStatus, String) {
    match system {
        InitSystem::Systemd | InitSystem::Launchd => {
            let Some(path) = service_definition_path(system) else {
                return (
                    DoctorStatus::Warn,
                    "could not determine service definition path".to_string(),
                );
            };
            if path.exists() {
                (
                    DoctorStatus::Ok,
                    format!(
                        "{} service definition installed at {}",
                        init_system_label(system),
                        path.display()
                    ),
                )
            } else {
                (
                    DoctorStatus::Warn,
                    format!(
                        "{} service definition not installed (expected {}). Use `oxmgr service install` if you want auto-start.",
                        init_system_label(system),
                        path.display()
                    ),
                )
            }
        }
        InitSystem::TaskScheduler => {
            match run_command_capture("schtasks", &["/Query", "/TN", "OxmgrDaemon"]) {
                CommandCapture::Success(_) => (
                    DoctorStatus::Ok,
                    "scheduled task OxmgrDaemon is installed".to_string(),
                ),
                CommandCapture::Failure(detail) => (
                    DoctorStatus::Warn,
                    format!(
                        "scheduled task OxmgrDaemon is not installed or not queryable ({detail})"
                    ),
                ),
                CommandCapture::Missing => (
                    DoctorStatus::Warn,
                    "schtasks is not available in PATH".to_string(),
                ),
            }
        }
        InitSystem::Auto => unreachable!("auto should have been resolved"),
    }
}

fn inspect_service_runtime(system: InitSystem) -> (DoctorStatus, String) {
    match system {
        InitSystem::Systemd => {
            match run_command_capture("systemctl", &["--user", "is-active", "oxmgr.service"]) {
                CommandCapture::Success(detail) => (
                    DoctorStatus::Ok,
                    format!("systemd user service active ({detail})"),
                ),
                CommandCapture::Failure(detail) => (
                    DoctorStatus::Warn,
                    format!("systemd user service not active ({detail})"),
                ),
                CommandCapture::Missing => (
                    DoctorStatus::Warn,
                    "systemctl is not available in PATH".to_string(),
                ),
            }
        }
        InitSystem::Launchd => {
            let uid = current_uid_string();
            let service_id = format!("gui/{uid}/io.oxmgr.daemon");
            match run_command_capture("launchctl", &["print", &service_id]) {
                CommandCapture::Success(_) => (
                    DoctorStatus::Ok,
                    format!("launchd service active ({service_id})"),
                ),
                CommandCapture::Failure(detail) => (
                    DoctorStatus::Warn,
                    format!("launchd service not active ({detail})"),
                ),
                CommandCapture::Missing => (
                    DoctorStatus::Warn,
                    "launchctl is not available in PATH".to_string(),
                ),
            }
        }
        InitSystem::TaskScheduler => {
            match run_command_capture(
                "schtasks",
                &["/Query", "/TN", "OxmgrDaemon", "/FO", "LIST", "/V"],
            ) {
                CommandCapture::Success(_) => (
                    DoctorStatus::Ok,
                    "scheduled task OxmgrDaemon is queryable".to_string(),
                ),
                CommandCapture::Failure(detail) => (
                    DoctorStatus::Warn,
                    format!("scheduled task OxmgrDaemon is not active ({detail})"),
                ),
                CommandCapture::Missing => (
                    DoctorStatus::Warn,
                    "schtasks is not available in PATH".to_string(),
                ),
            }
        }
        InitSystem::Auto => unreachable!("auto should have been resolved"),
    }
}

fn service_definition_path(system: InitSystem) -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    match system {
        InitSystem::Systemd => Some(home.join(".config/systemd/user/oxmgr.service")),
        InitSystem::Launchd => Some(home.join("Library/LaunchAgents/io.oxmgr.daemon.plist")),
        InitSystem::TaskScheduler | InitSystem::Auto => None,
    }
}

fn init_system_label(system: InitSystem) -> &'static str {
    match system {
        InitSystem::Systemd => "systemd",
        InitSystem::Launchd => "launchd",
        InitSystem::TaskScheduler => "task scheduler",
        InitSystem::Auto => "auto",
    }
}

fn inspect_cgroup_support(processes: &[ManagedProcess]) -> (DoctorStatus, String) {
    let requiring: Vec<&ManagedProcess> = processes
        .iter()
        .filter(|process| {
            process
                .resource_limits
                .as_ref()
                .map(|limits| limits.cgroup_enforce)
                .unwrap_or(false)
        })
        .collect();
    if requiring.is_empty() {
        return (
            DoctorStatus::Ok,
            "no services require cgroup enforcement".to_string(),
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        (
            DoctorStatus::Fail,
            format!(
                "{} service(s) require cgroup enforcement, but this platform is not Linux",
                requiring.len()
            ),
        )
    }

    #[cfg(target_os = "linux")]
    {
        let controllers_path = Path::new("/sys/fs/cgroup/cgroup.controllers");
        if !controllers_path.exists() {
            return (
                DoctorStatus::Fail,
                format!(
                    "{} service(s) require cgroup enforcement, but cgroup v2 is not mounted",
                    requiring.len()
                ),
            );
        }

        let controllers = match fs::read_to_string(controllers_path) {
            Ok(content) => content,
            Err(err) => {
                return (
                    DoctorStatus::Fail,
                    format!(
                        "failed to read {} while checking cgroup support: {err}",
                        controllers_path.display()
                    ),
                )
            }
        };

        let needs_cpu = requiring.iter().any(|process| {
            process
                .resource_limits
                .as_ref()
                .and_then(|limits| limits.max_cpu_percent)
                .is_some()
        });
        let needs_memory = requiring.iter().any(|process| {
            process
                .resource_limits
                .as_ref()
                .and_then(|limits| limits.max_memory_mb)
                .is_some()
        });

        let mut missing = Vec::new();
        if needs_cpu && !controllers.split_whitespace().any(|value| value == "cpu") {
            missing.push("cpu");
        }
        if needs_memory
            && !controllers
                .split_whitespace()
                .any(|value| value == "memory")
        {
            missing.push("memory");
        }

        if missing.is_empty() {
            (
                DoctorStatus::Ok,
                format!("cgroup v2 available for {} service(s)", requiring.len()),
            )
        } else {
            (
                DoctorStatus::Fail,
                format!(
                    "cgroup v2 is mounted, but controller(s) missing for {} service(s): {}",
                    requiring.len(),
                    missing.join(", ")
                ),
            )
        }
    }
}

fn inspect_git_pull_setup(processes: &[ManagedProcess]) -> (DoctorStatus, String) {
    let git_enabled = processes
        .iter()
        .filter(|process| process.git_repo.is_some())
        .count();
    let pull_hooks = processes
        .iter()
        .filter(|process| process.pull_secret_hash.is_some())
        .count();
    let invalid_hooks = processes
        .iter()
        .filter(|process| process.pull_secret_hash.is_some() && process.git_repo.is_none())
        .count();

    if invalid_hooks > 0 {
        return (
            DoctorStatus::Warn,
            format!(
                "{invalid_hooks} service(s) define a pull secret without git_repo; webhook pulls will fail"
            ),
        );
    }

    (
        DoctorStatus::Ok,
        format!("{git_enabled} git-enabled service(s), {pull_hooks} webhook-enabled service(s)"),
    )
}

enum CommandCapture {
    Success(String),
    Failure(String),
    Missing,
}

fn run_command_capture(program: &str, args: &[&str]) -> CommandCapture {
    match StdCommand::new(program).args(args).output() {
        Ok(output) if output.status.success() => {
            CommandCapture::Success(compact_command_output(&output.stdout, &output.stderr))
        }
        Ok(output) => {
            CommandCapture::Failure(compact_command_output(&output.stdout, &output.stderr))
        }
        Err(err) if err.kind() == ErrorKind::NotFound => CommandCapture::Missing,
        Err(err) => CommandCapture::Failure(err.to_string()),
    }
}

fn compact_command_output(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    let text = if stdout.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    if text.is_empty() {
        "no output".to_string()
    } else {
        text.lines().next().unwrap_or(text).trim().to_string()
    }
}

#[cfg(unix)]
fn current_uid_string() -> String {
    nix::unistd::Uid::effective().as_raw().to_string()
}

#[cfg(not(unix))]
fn current_uid_string() -> String {
    "0".to_string()
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::path::PathBuf;

    use crate::cli::InitSystem;
    use crate::process::{ManagedProcess, ProcessStatus, RestartPolicy};

    use super::{
        inspect_git_pull_setup, parse_http_response, probe_bind_status, service_definition_path,
        BindStatus, DoctorStatus,
    };

    #[test]
    fn parse_http_response_extracts_status_and_body() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello";
        let (status, body) =
            parse_http_response(response).expect("expected valid HTTP response parsing");
        assert_eq!(status, 200);
        assert_eq!(body, "hello");
    }

    #[test]
    fn probe_bind_status_detects_occupied_and_free_ports() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind ephemeral port");
        let occupied_addr = listener
            .local_addr()
            .expect("failed to read listener address")
            .to_string();
        assert_eq!(
            probe_bind_status(&occupied_addr).expect("expected bind probe success"),
            BindStatus::Occupied
        );

        let free_listener =
            TcpListener::bind("127.0.0.1:0").expect("failed to bind free probe port");
        let free_addr = free_listener
            .local_addr()
            .expect("failed to read free listener address")
            .to_string();
        drop(free_listener);
        assert_eq!(
            probe_bind_status(&free_addr).expect("expected free bind probe success"),
            BindStatus::Free
        );
    }

    #[test]
    fn inspect_git_pull_setup_warns_when_pull_secret_has_no_repo() {
        let mut process = sample_process();
        process.pull_secret_hash = Some("hashed".to_string());
        process.git_repo = None;

        let (status, detail) = inspect_git_pull_setup(&[process]);
        assert_eq!(status, DoctorStatus::Warn);
        assert!(detail.contains("pull secret without git_repo"));
    }

    #[test]
    fn service_definition_path_matches_expected_suffix() {
        #[cfg(target_os = "windows")]
        {
            assert!(service_definition_path(InitSystem::TaskScheduler).is_none());
        }

        #[cfg(not(target_os = "windows"))]
        {
            let systemd = service_definition_path(InitSystem::Systemd)
                .expect("expected systemd service definition path");
            assert!(systemd.ends_with(".config/systemd/user/oxmgr.service"));

            let launchd = service_definition_path(InitSystem::Launchd)
                .expect("expected launchd service definition path");
            assert!(launchd.ends_with("Library/LaunchAgents/io.oxmgr.daemon.plist"));
        }
    }

    fn sample_process() -> ManagedProcess {
        ManagedProcess {
            id: 1,
            name: "api".to_string(),
            command: "node".to_string(),
            args: vec!["server.js".to_string()],
            pre_reload_cmd: None,
            cwd: None,
            env: std::collections::HashMap::new(),
            restart_policy: RestartPolicy::OnFailure,
            max_restarts: 5,
            restart_count: 0,
            crash_restart_limit: 3,
            auto_restart_history: Vec::new(),
            namespace: None,
            git_repo: Some("https://example.com/repo.git".to_string()),
            git_ref: None,
            pull_secret_hash: None,
            reuse_port: false,
            stop_signal: None,
            stop_timeout_secs: 5,
            restart_delay_secs: 0,
            restart_backoff_cap_secs: 0,
            restart_backoff_reset_secs: 0,
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
            pid: None,
            status: ProcessStatus::Stopped,
            desired_state: crate::process::DesiredState::Stopped,
            last_exit_code: None,
            stdout_log: PathBuf::from("/tmp/stdout.log"),
            stderr_log: PathBuf::from("/tmp/stderr.log"),
            health_check: None,
            health_status: crate::process::HealthStatus::Unknown,
            health_failures: 0,
            last_health_check: None,
            next_health_check: None,
            last_health_error: None,
            wait_ready: false,
            ready_timeout_secs: 30,
            last_started_at: None,
            last_stopped_at: None,
            last_metrics_at: None,
            memory_bytes: 0,
            cpu_percent: 0.0,
            config_fingerprint: String::new(),
            log_date_format: Some("%Y-%m-%d %H:%M:%S".to_string()),
            cron_restart: None,
            next_cron_restart: None,
        }
    }
}
