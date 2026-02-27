use std::env;
use std::process::Stdio;
use std::str;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time::{sleep, timeout, Duration, MissedTickBehavior};
use tracing::{error, info, warn};

use crate::config::AppConfig;
use crate::errors::OxmgrError;
use crate::ipc::{read_json_line, write_json_line, IpcRequest, IpcResponse};
use crate::logging::ProcessLogs;
use crate::process::ManagedProcess;
use crate::process_manager::ProcessManager;

#[derive(Clone, Default)]
struct DaemonSnapshot {
    processes: Arc<RwLock<Vec<ManagedProcess>>>,
}

enum ManagerCommand {
    Ipc {
        request: IpcRequest,
        response_tx: oneshot::Sender<IpcResponse>,
    },
    Api {
        request: HttpRequest,
        response_tx: oneshot::Sender<HttpResponse>,
    },
}

pub async fn run_foreground(config: AppConfig) -> Result<()> {
    config.ensure_layout()?;
    let listener = bind_listener(&config.daemon_addr).await?;
    let api_listener = bind_api_listener(&config.api_addr).await?;

    let (exit_tx, mut exit_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel::<()>();
    let (command_tx, mut command_rx) = mpsc::unbounded_channel::<ManagerCommand>();
    let mut manager = ProcessManager::new(config.clone(), exit_tx)?;
    manager.recover_processes().await?;
    let snapshot = DaemonSnapshot::default();
    snapshot.publish(&manager).await;

    let mut restart_tick = tokio::time::interval(Duration::from_millis(250));
    restart_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut maintenance = tokio::time::interval(Duration::from_secs(2));
    maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);

    info!("oxmgr daemon started at {}", config.daemon_addr);
    info!("oxmgr webhook API started at {}", config.api_addr);

    loop {
        tokio::select! {
            incoming = listener.accept() => {
                match incoming {
                    Ok((stream, _)) => {
                        let command_tx = command_tx.clone();
                        let snapshot = snapshot.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_client(stream, snapshot, command_tx).await {
                                error!("failed to handle IPC client: {err}");
                            }
                        });
                    }
                    Err(err) => {
                        error!("IPC accept failed: {err}");
                    }
                }
            }
            incoming = api_listener.accept() => {
                match incoming {
                    Ok((stream, _)) => {
                        let command_tx = command_tx.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_api_client(stream, command_tx).await {
                                error!("failed to handle webhook API client: {err}");
                            }
                        });
                    }
                    Err(err) => {
                        error!("webhook API accept failed: {err}");
                    }
                }
            }
            Some(command) = command_rx.recv() => {
                match command {
                    ManagerCommand::Ipc { request, response_tx } => {
                        let response = execute_request(request, &mut manager, &shutdown_tx).await;
                        let _ = response_tx.send(response);
                    }
                    ManagerCommand::Api { request, response_tx } => {
                        let response = execute_api_request(request, &mut manager).await;
                        let _ = response_tx.send(response);
                    }
                }
                snapshot.publish(&manager).await;
            }
            Some(event) = exit_rx.recv() => {
                if let Err(err) = manager.handle_exit_event(event).await {
                    error!("failed to process exit event: {err}");
                }
                snapshot.publish(&manager).await;
            }
            _ = restart_tick.tick() => {
                if let Err(err) = manager.run_scheduled_restarts().await {
                    error!("scheduled restart task failed: {err}");
                }
                snapshot.publish(&manager).await;
            }
            _ = maintenance.tick() => {
                if let Err(err) = manager.run_periodic_tasks().await {
                    error!("periodic manager task failed: {err}");
                }
                snapshot.publish(&manager).await;
            }
            Some(_) = shutdown_rx.recv() => {
                info!("shutdown requested via IPC; stopping managed processes");
                manager.shutdown_all().await?;
                snapshot.publish(&manager).await;
                break;
            }
            ctrl = tokio::signal::ctrl_c() => {
                if let Err(err) = ctrl {
                    warn!("failed to wait for CTRL-C signal: {err}");
                }
                info!("received shutdown signal; stopping managed processes");
                manager.shutdown_all().await?;
                snapshot.publish(&manager).await;
                break;
            }
        }
    }

    Ok(())
}

pub async fn ensure_daemon_running(config: &AppConfig) -> Result<()> {
    if daemon_socket_available(&config.daemon_addr).await {
        return Ok(());
    }

    let executable = env::current_exe().context("failed to locate current executable")?;
    Command::new(executable)
        .arg("daemon")
        .arg("run")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn daemon")?;

    for _ in 0..50 {
        if daemon_socket_available(&config.daemon_addr).await {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }

    anyhow::bail!("daemon did not become ready in time")
}

async fn daemon_socket_available(daemon_addr: &str) -> bool {
    match timeout(Duration::from_millis(250), TcpStream::connect(daemon_addr)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            true
        }
        _ => false,
    }
}

async fn bind_listener(daemon_addr: &str) -> Result<TcpListener> {
    if daemon_socket_available(daemon_addr).await {
        return Err(OxmgrError::DaemonAlreadyRunning.into());
    }

    TcpListener::bind(daemon_addr)
        .await
        .with_context(|| format!("failed to bind daemon endpoint at {daemon_addr}"))
}

async fn bind_api_listener(api_addr: &str) -> Result<TcpListener> {
    TcpListener::bind(api_addr)
        .await
        .with_context(|| format!("failed to bind webhook API endpoint at {api_addr}"))
}

async fn handle_client(
    mut stream: TcpStream,
    snapshot: DaemonSnapshot,
    command_tx: mpsc::UnboundedSender<ManagerCommand>,
) -> Result<()> {
    let request = read_json_line::<IpcRequest, _>(&mut stream).await?;
    let response = if let Some(response) = execute_snapshot_request(&request, &snapshot).await {
        response
    } else {
        send_ipc_command(&command_tx, request).await?
    };
    write_json_line(&mut stream, &response).await
}

async fn execute_request(
    request: IpcRequest,
    manager: &mut ProcessManager,
    shutdown_tx: &mpsc::UnboundedSender<()>,
) -> IpcResponse {
    match request {
        IpcRequest::Ping => IpcResponse::ok("pong"),
        IpcRequest::Shutdown => {
            let _ = shutdown_tx.send(());
            IpcResponse::ok("daemon shutdown scheduled")
        }
        IpcRequest::Start { spec } => match manager.start_process(*spec).await {
            Ok(process) => {
                let mut response = IpcResponse::ok(format!("started {}", process.target_label()));
                response.process = Some(process.redacted_for_transport());
                response
            }
            Err(err) => IpcResponse::error(err.to_string()),
        },
        IpcRequest::Stop { target } => match manager.stop_process(&target).await {
            Ok(process) => {
                let mut response = IpcResponse::ok(format!("stopped {}", process.target_label()));
                response.process = Some(process.redacted_for_transport());
                response
            }
            Err(err) => IpcResponse::error(err.to_string()),
        },
        IpcRequest::Restart { target } => match manager.restart_process(&target).await {
            Ok(process) => {
                let mut response = IpcResponse::ok(format!("restarted {}", process.target_label()));
                response.process = Some(process.redacted_for_transport());
                response
            }
            Err(err) => IpcResponse::error(err.to_string()),
        },
        IpcRequest::Reload { target } => match manager.reload_process(&target).await {
            Ok(process) => {
                let mut response = IpcResponse::ok(format!("reloaded {}", process.target_label()));
                response.process = Some(process.redacted_for_transport());
                response
            }
            Err(err) => IpcResponse::error(err.to_string()),
        },
        IpcRequest::Pull { target } => match manager.pull_processes(target.as_deref()).await {
            Ok(message) => IpcResponse::ok(message),
            Err(err) => IpcResponse::error(err.to_string()),
        },
        IpcRequest::Delete { target } => match manager.delete_process(&target).await {
            Ok(process) => {
                let mut response = IpcResponse::ok(format!("deleted {}", process.target_label()));
                response.process = Some(process.redacted_for_transport());
                response
            }
            Err(err) => IpcResponse::error(err.to_string()),
        },
        IpcRequest::List => {
            let mut response = IpcResponse::ok("ok");
            response.processes = redact_processes(manager.list_processes());
            response
        }
        IpcRequest::Status { target } => match manager.get_process(&target) {
            Ok(process) => {
                let mut response = IpcResponse::ok("ok");
                response.process = Some(process.redacted_for_transport());
                response
            }
            Err(err) => IpcResponse::error(err.to_string()),
        },
        IpcRequest::Logs { target } => match manager.logs_for(&target) {
            Ok(logs) => {
                let mut response = IpcResponse::ok("ok");
                response.logs = Some(logs);
                response
            }
            Err(err) => IpcResponse::error(err.to_string()),
        },
    }
}

async fn execute_snapshot_request(
    request: &IpcRequest,
    snapshot: &DaemonSnapshot,
) -> Option<IpcResponse> {
    match request {
        IpcRequest::Ping => Some(IpcResponse::ok("pong")),
        IpcRequest::List => {
            let mut response = IpcResponse::ok("ok");
            response.processes = redact_processes(snapshot.list_processes().await);
            Some(response)
        }
        IpcRequest::Status { target } => {
            let process = snapshot.get_process(target).await?;
            let mut response = IpcResponse::ok("ok");
            response.process = Some(process.redacted_for_transport());
            Some(response)
        }
        IpcRequest::Logs { target } => {
            let logs = snapshot.logs_for(target).await?;
            let mut response = IpcResponse::ok("ok");
            response.logs = Some(logs);
            Some(response)
        }
        _ => None,
    }
}

fn redact_processes(processes: Vec<ManagedProcess>) -> Vec<ManagedProcess> {
    processes
        .into_iter()
        .map(|process| process.redacted_for_transport())
        .collect()
}

async fn send_ipc_command(
    command_tx: &mpsc::UnboundedSender<ManagerCommand>,
    request: IpcRequest,
) -> Result<IpcResponse> {
    let (response_tx, response_rx) = oneshot::channel();
    command_tx
        .send(ManagerCommand::Ipc {
            request,
            response_tx,
        })
        .map_err(|_| anyhow::anyhow!("daemon manager loop is unavailable"))?;
    response_rx
        .await
        .map_err(|_| anyhow::anyhow!("daemon manager loop dropped IPC response"))
}

async fn send_api_command(
    command_tx: &mpsc::UnboundedSender<ManagerCommand>,
    request: HttpRequest,
) -> Result<HttpResponse> {
    let (response_tx, response_rx) = oneshot::channel();
    command_tx
        .send(ManagerCommand::Api {
            request,
            response_tx,
        })
        .map_err(|_| anyhow::anyhow!("daemon manager loop is unavailable"))?;
    response_rx
        .await
        .map_err(|_| anyhow::anyhow!("daemon manager loop dropped API response"))
}

async fn handle_api_client(
    mut stream: TcpStream,
    command_tx: mpsc::UnboundedSender<ManagerCommand>,
) -> Result<()> {
    let request = read_http_request(&mut stream).await?;
    let response = send_api_command(&command_tx, request).await?;
    write_http_response(&mut stream, response.status_code, &response.body).await
}

async fn execute_api_request(request: HttpRequest, manager: &mut ProcessManager) -> HttpResponse {
    if request.method != "POST" {
        return HttpResponse::error(405, "method not allowed");
    }

    let Some(target) = request.path.strip_prefix("/pull/") else {
        return HttpResponse::error(404, "not found");
    };
    if target.is_empty() {
        return HttpResponse::error(404, "not found");
    }

    if manager.get_process(target).is_err() {
        return HttpResponse::error(404, "service not found");
    }

    let Some(secret) = extract_api_secret(&request) else {
        return HttpResponse::error(401, "missing webhook secret");
    };

    if manager.verify_pull_webhook_secret(target, &secret).is_err() {
        return HttpResponse::error(401, "invalid webhook secret");
    }

    match manager.pull_processes(Some(target)).await {
        Ok(message) => HttpResponse::ok(message),
        Err(err) => HttpResponse::error(500, err.to_string()),
    }
}

async fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];

    loop {
        let read = timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .context("timed out while reading webhook request")?
            .context("failed to read webhook request")?;

        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);

        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > MAX_HEADER_BYTES {
            anyhow::bail!("webhook request headers exceed maximum size");
        }
    }

    let raw = str::from_utf8(&buffer).context("webhook request is not valid UTF-8")?;
    let header_end = raw
        .find("\r\n\r\n")
        .context("malformed webhook request headers")?;
    let head = &raw[..header_end];

    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .context("missing webhook request line")?
        .trim()
        .to_string();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .context("missing webhook request method")?
        .to_string();
    let path = request_parts
        .next()
        .context("missing webhook request path")?
        .to_string();

    let mut headers = std::collections::HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
    })
}

async fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    body: &serde_json::Value,
) -> Result<()> {
    let reason = match status_code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let body_text = serde_json::to_string(body).context("failed to encode webhook response")?;
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code,
        reason,
        body_text.len(),
        body_text
    );

    stream
        .write_all(response.as_bytes())
        .await
        .context("failed to write webhook response")?;
    stream
        .flush()
        .await
        .context("failed to flush webhook response")
}

fn extract_api_secret(request: &HttpRequest) -> Option<String> {
    if let Some(value) = request.headers.get("x-oxmgr-secret") {
        return Some(value.trim().to_string());
    }
    request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.trim().to_string())
}

struct HttpRequest {
    method: String,
    path: String,
    headers: std::collections::HashMap<String, String>,
}

struct HttpResponse {
    status_code: u16,
    body: serde_json::Value,
}

impl HttpResponse {
    fn ok(message: impl Into<String>) -> Self {
        Self {
            status_code: 200,
            body: json!({
                "ok": true,
                "message": message.into()
            }),
        }
    }

    fn error(status_code: u16, message: impl Into<String>) -> Self {
        Self {
            status_code,
            body: json!({
                "ok": false,
                "message": message.into()
            }),
        }
    }
}

impl DaemonSnapshot {
    async fn publish(&self, manager: &ProcessManager) {
        let mut processes = self.processes.write().await;
        *processes = manager.list_processes();
    }

    async fn list_processes(&self) -> Vec<ManagedProcess> {
        self.processes.read().await.clone()
    }

    async fn get_process(&self, target: &str) -> Option<ManagedProcess> {
        let processes = self.processes.read().await;
        if let Some(process) = processes.iter().find(|process| process.name == target) {
            return Some(process.clone());
        }

        let id = target.parse::<u64>().ok()?;
        processes.iter().find(|process| process.id == id).cloned()
    }

    async fn logs_for(&self, target: &str) -> Option<ProcessLogs> {
        let process = self.get_process(target).await?;
        Some(ProcessLogs {
            stdout: process.stdout_log,
            stderr: process.stderr_log,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command as StdCommand;
    use std::time::{SystemTime, UNIX_EPOCH};

    use sha2::{Digest, Sha256};
    use tokio::sync::mpsc::unbounded_channel;

    use super::{
        execute_api_request, execute_snapshot_request, extract_api_secret, DaemonSnapshot,
        HttpRequest,
    };
    use crate::config::AppConfig;
    use crate::process::{RestartPolicy, StartProcessSpec};
    use crate::process_manager::ProcessManager;

    #[tokio::test]
    async fn execute_api_request_rejects_non_post_method() {
        let mut manager = empty_manager("daemon-api-method");
        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/pull/api".to_string(),
            headers: HashMap::new(),
        };

        let response = execute_api_request(request, &mut manager).await;
        assert_eq!(response.status_code, 405);
        assert_eq!(response.body["ok"], false);
    }

    #[tokio::test]
    async fn execute_api_request_rejects_missing_secret() {
        let mut manager = empty_manager("daemon-api-missing-secret");
        start_minimal_service(&mut manager, "api", None, None, None).await;

        let request = HttpRequest {
            method: "POST".to_string(),
            path: "/pull/api".to_string(),
            headers: HashMap::new(),
        };

        let response = execute_api_request(request, &mut manager).await;
        assert_eq!(response.status_code, 401);
        assert_eq!(response.body["message"], "missing webhook secret");
        let _ = manager.shutdown_all().await;
    }

    #[tokio::test]
    async fn execute_api_request_rejects_invalid_secret() {
        let mut manager = empty_manager("daemon-api-invalid-secret");
        start_minimal_service(
            &mut manager,
            "api",
            None,
            None,
            Some(hash_secret("expected")),
        )
        .await;

        let mut headers = HashMap::new();
        headers.insert("x-oxmgr-secret".to_string(), "wrong".to_string());
        let request = HttpRequest {
            method: "POST".to_string(),
            path: "/pull/api".to_string(),
            headers,
        };

        let response = execute_api_request(request, &mut manager).await;
        assert_eq!(response.status_code, 401);
        assert_eq!(response.body["message"], "invalid webhook secret");
        let _ = manager.shutdown_all().await;
    }

    #[tokio::test]
    async fn execute_api_request_runs_pull_when_secret_is_valid() {
        let git = setup_git_fixture("daemon-api-pull");
        let mut manager = empty_manager("daemon-api-pull-manager");
        start_minimal_service(
            &mut manager,
            "api",
            Some(git.clone_dir.clone()),
            Some(git.remote_dir.display().to_string()),
            Some(hash_secret("hook-secret")),
        )
        .await;

        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_string(),
            "Bearer hook-secret".to_string(),
        );
        let request = HttpRequest {
            method: "POST".to_string(),
            path: "/pull/api".to_string(),
            headers,
        };

        let response = execute_api_request(request, &mut manager).await;
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body["ok"], true);
        assert!(
            response.body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("Pull complete"),
            "unexpected response body: {}",
            response.body
        );

        let _ = manager.shutdown_all().await;
        let _ = fs::remove_dir_all(git.root);
    }

    #[test]
    fn extract_api_secret_prefers_explicit_header_then_bearer() {
        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_string(),
            "Bearer bearer-secret".to_string(),
        );
        headers.insert("x-oxmgr-secret".to_string(), "header-secret".to_string());
        let request = HttpRequest {
            method: "POST".to_string(),
            path: "/pull/api".to_string(),
            headers,
        };

        assert_eq!(
            extract_api_secret(&request).as_deref(),
            Some("header-secret")
        );
    }

    #[test]
    fn extract_api_secret_accepts_bearer_when_custom_header_missing() {
        let request = HttpRequest {
            method: "POST".to_string(),
            path: "/pull/api".to_string(),
            headers: HashMap::from([("authorization".to_string(), "Bearer token123".to_string())]),
        };
        assert_eq!(extract_api_secret(&request).as_deref(), Some("token123"));
    }

    #[tokio::test]
    async fn snapshot_request_serves_list_status_and_logs_without_manager() {
        let mut manager = empty_manager("daemon-snapshot-read");
        start_minimal_service(&mut manager, "api", None, None, None).await;

        let snapshot = DaemonSnapshot::default();
        snapshot.publish(&manager).await;

        let list = execute_snapshot_request(&crate::ipc::IpcRequest::List, &snapshot)
            .await
            .expect("list should be served from snapshot");
        assert_eq!(list.processes.len(), 1);

        let status = execute_snapshot_request(
            &crate::ipc::IpcRequest::Status {
                target: "api".to_string(),
            },
            &snapshot,
        )
        .await
        .expect("status should be served from snapshot");
        assert_eq!(
            status.process.as_ref().map(|process| process.name.as_str()),
            Some("api")
        );

        let logs = execute_snapshot_request(
            &crate::ipc::IpcRequest::Logs {
                target: "api".to_string(),
            },
            &snapshot,
        )
        .await
        .expect("logs should be served from snapshot");
        assert!(logs.logs.is_some());

        let _ = manager.shutdown_all().await;
    }

    #[tokio::test]
    async fn snapshot_request_redacts_env_and_pull_secret_hash() {
        let mut manager = empty_manager("daemon-snapshot-redaction");
        let exe = std::env::current_exe().expect("failed to read current executable path");
        let command = format!("\"{}\" --help", exe.display());
        let spec = StartProcessSpec {
            command,
            name: Some("api".to_string()),
            restart_policy: RestartPolicy::Never,
            max_restarts: 1,
            crash_restart_limit: 3,
            cwd: None,
            env: HashMap::from([("SECRET_TOKEN".to_string(), "value".to_string())]),
            health_check: None,
            stop_signal: None,
            stop_timeout_secs: 1,
            restart_delay_secs: 0,
            start_delay_secs: 0,
            watch: false,
            cluster_mode: false,
            cluster_instances: None,
            namespace: None,
            resource_limits: None,
            git_repo: None,
            git_ref: None,
            pull_secret_hash: Some(hash_secret("hook-secret")),
        };

        manager
            .start_process(spec)
            .await
            .expect("failed to start redaction test service");

        let snapshot = DaemonSnapshot::default();
        snapshot.publish(&manager).await;

        let status = execute_snapshot_request(
            &crate::ipc::IpcRequest::Status {
                target: "api".to_string(),
            },
            &snapshot,
        )
        .await
        .expect("status should be served from snapshot");
        let process = status.process.expect("expected process in status response");
        assert!(process.env.is_empty(), "env should be redacted from IPC");
        assert_eq!(
            process.pull_secret_hash.as_deref(),
            Some("<redacted>"),
            "pull secret hash should be redacted from IPC"
        );

        let _ = manager.shutdown_all().await;
    }

    async fn start_minimal_service(
        manager: &mut ProcessManager,
        name: &str,
        cwd: Option<PathBuf>,
        git_repo: Option<String>,
        pull_secret_hash: Option<String>,
    ) {
        let exe = std::env::current_exe().expect("failed to read current executable path");
        let command = format!("\"{}\" --help", exe.display());

        let spec = StartProcessSpec {
            command,
            name: Some(name.to_string()),
            restart_policy: RestartPolicy::Never,
            max_restarts: 1,
            crash_restart_limit: 3,
            cwd,
            env: HashMap::new(),
            health_check: None,
            stop_signal: None,
            stop_timeout_secs: 1,
            restart_delay_secs: 0,
            start_delay_secs: 0,
            watch: false,
            cluster_mode: false,
            cluster_instances: None,
            namespace: None,
            resource_limits: None,
            git_repo,
            git_ref: Some("main".to_string()),
            pull_secret_hash,
        };

        manager
            .start_process(spec)
            .await
            .expect("failed to start service for daemon API test");
    }

    fn empty_manager(prefix: &str) -> ProcessManager {
        let config = test_config(prefix);
        let (exit_tx, _exit_rx) = unbounded_channel();
        ProcessManager::new(config, exit_tx).expect("failed to initialize test process manager")
    }

    fn hash_secret(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }

    struct GitFixture {
        root: PathBuf,
        remote_dir: PathBuf,
        clone_dir: PathBuf,
    }

    fn setup_git_fixture(prefix: &str) -> GitFixture {
        let root = temp_dir(prefix);
        let remote_dir = root.join("remote.git");
        let source_dir = root.join("source");
        let clone_dir = root.join("clone");

        fs::create_dir_all(&root).expect("failed to create git fixture root");
        fs::create_dir_all(&source_dir).expect("failed to create git source directory");
        run_git_sync(
            &root,
            &["init", "--bare", remote_dir.to_str().unwrap_or_default()],
        );
        run_git_sync(&source_dir, &["init"]);
        run_git_sync(&source_dir, &["config", "user.email", "tests@oxmgr.local"]);
        run_git_sync(&source_dir, &["config", "user.name", "Oxmgr Tests"]);
        fs::write(source_dir.join("app.js"), "console.log('v1');\n")
            .expect("failed writing fixture file");
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
            clone_dir,
        }
    }

    fn run_git_sync(cwd: &Path, args: &[&str]) {
        let output = StdCommand::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("failed to run git in daemon test");
        assert!(
            output.status.success(),
            "git {:?} failed in {}: {}",
            args,
            cwd.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn test_config(prefix: &str) -> AppConfig {
        let base = temp_dir(prefix);
        let log_dir = base.join("logs");
        fs::create_dir_all(&log_dir).expect("failed to create log directory");
        AppConfig {
            base_dir: base.clone(),
            daemon_addr: "127.0.0.1:50200".to_string(),
            api_addr: "127.0.0.1:51200".to_string(),
            state_path: base.join("state.json"),
            log_dir,
            log_rotation: crate::logging::LogRotationPolicy {
                max_size_bytes: 1024 * 1024,
                max_files: 2,
                max_age_days: 1,
            },
        }
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("oxmgr-daemon-{prefix}-{nonce}"))
    }
}
