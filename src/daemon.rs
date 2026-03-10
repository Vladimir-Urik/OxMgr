//! Foreground daemon loop, local IPC handling, and HTTP API handling.

use std::env;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time::{
    sleep, sleep_until, timeout, Duration, Instant as TokioInstant, MissedTickBehavior, Sleep,
};
use tracing::{error, info, warn};

use crate::config::AppConfig;
use crate::errors::OxmgrError;
use crate::ipc::{read_json_line, send_request, write_json_line, IpcRequest, IpcResponse};
use crate::logging::ProcessLogs;
use crate::process::ManagedProcess;
use crate::process_manager::ProcessManager;

mod http;

#[cfg(test)]
use self::http::{
    escape_prometheus_label_value, execute_snapshot_api_request, extract_api_secret,
    render_prometheus_metrics, HttpBody,
};
use self::http::{execute_api_request, handle_api_client, HttpRequest, HttpResponse};

#[derive(Clone, Default)]
struct DaemonSnapshot {
    processes: Arc<RwLock<Vec<ManagedProcess>>>,
}

const DISABLED_RESTART_SLEEP_SECS: u64 = 24 * 60 * 60;
const JSON_CONTENT_TYPE: &str = "application/json";
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

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

/// Runs the Oxmgr daemon in the foreground.
///
/// The daemon owns process lifecycle management, serves the local IPC socket
/// used by the CLI, and exposes the lightweight HTTP API used for authenticated
/// pull triggers and Prometheus scraping.
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

    let mut restart_sleep = Box::pin(sleep_until(restart_sleep_deadline(
        manager.next_scheduled_restart_at(),
        TokioInstant::now(),
    )));
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
                        let snapshot = snapshot.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_api_client(stream, snapshot, command_tx).await {
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
                reset_restart_sleep(restart_sleep.as_mut(), &manager);
            }
            Some(event) = exit_rx.recv() => {
                if let Err(err) = manager.handle_exit_event(event).await {
                    error!("failed to process exit event: {err}");
                }
                snapshot.publish(&manager).await;
                reset_restart_sleep(restart_sleep.as_mut(), &manager);
            }
            _ = restart_sleep.as_mut() => {
                if let Err(err) = manager.run_scheduled_restarts().await {
                    error!("scheduled restart task failed: {err}");
                }
                snapshot.publish(&manager).await;
                reset_restart_sleep(restart_sleep.as_mut(), &manager);
            }
            _ = maintenance.tick() => {
                if let Err(err) = manager.run_periodic_tasks().await {
                    error!("periodic manager task failed: {err}");
                }
                snapshot.publish(&manager).await;
                reset_restart_sleep(restart_sleep.as_mut(), &manager);
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

fn reset_restart_sleep(restart_sleep: Pin<&mut Sleep>, manager: &ProcessManager) {
    let deadline = restart_sleep_deadline(manager.next_scheduled_restart_at(), TokioInstant::now());
    restart_sleep.reset(deadline);
}

fn restart_sleep_deadline(next_due_at: Option<TokioInstant>, now: TokioInstant) -> TokioInstant {
    next_due_at.unwrap_or_else(|| now + Duration::from_secs(DISABLED_RESTART_SLEEP_SECS))
}

/// Ensures that the local daemon is running, spawning a detached foreground
/// instance when necessary and waiting briefly for it to become reachable.
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

    for _ in 0..300 {
        if daemon_socket_available(&config.daemon_addr).await {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }

    anyhow::bail!("daemon did not become ready in time")
}

async fn daemon_socket_available(daemon_addr: &str) -> bool {
    matches!(
        timeout(
            Duration::from_millis(250),
            send_request(daemon_addr, &IpcRequest::Ping),
        )
        .await,
        Ok(Ok(response)) if response.ok
    )
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
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc::unbounded_channel;
    use tokio::sync::RwLock;
    use tokio::time::Instant as TokioInstant;

    use super::{
        daemon_socket_available, escape_prometheus_label_value, execute_api_request,
        execute_snapshot_api_request, execute_snapshot_request, extract_api_secret,
        handle_api_client, render_prometheus_metrics, restart_sleep_deadline, DaemonSnapshot,
        HttpBody, HttpRequest, DISABLED_RESTART_SLEEP_SECS, PROMETHEUS_CONTENT_TYPE,
    };
    use crate::config::AppConfig;
    use crate::ipc::{read_json_line, write_json_line, IpcRequest, IpcResponse};
    use crate::process::{
        DesiredState, HealthStatus, ManagedProcess, RestartPolicy, StartProcessSpec,
        DEFAULT_CRASH_RESTART_LIMIT,
    };
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
        assert_eq!(json_body(&response)["ok"], false);
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
        assert_eq!(json_body(&response)["message"], "missing webhook secret");
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
        assert_eq!(json_body(&response)["message"], "invalid webhook secret");
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
        assert_eq!(json_body(&response)["ok"], true);
        assert!(
            json_body(&response)["message"]
                .as_str()
                .unwrap_or_default()
                .contains("Pull complete"),
            "unexpected response body: {}",
            json_body(&response)
        );

        let _ = manager.shutdown_all().await;
        let _ = fs::remove_dir_all(git.root);
    }

    #[tokio::test]
    async fn execute_snapshot_api_request_serves_prometheus_metrics() {
        let snapshot = snapshot_with_processes(vec![fixture_metrics_process()]);
        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/metrics".to_string(),
            headers: HashMap::new(),
        };

        let response = execute_snapshot_api_request(&request, &snapshot)
            .await
            .expect("metrics should be served from snapshot");
        assert_eq!(response.status_code, 200);
        assert_eq!(response.content_type, PROMETHEUS_CONTENT_TYPE);

        let body = text_body(&response);
        assert!(body.contains("# TYPE oxmgr_managed_processes gauge"));
        assert!(body.contains("oxmgr_managed_processes 1"));
        assert!(body.contains("oxmgr_process_up{id=\"42\",name=\"api\",namespace=\"prod\"} 1"));
        assert!(body.contains(
            "oxmgr_process_info{id=\"42\",name=\"api\",namespace=\"prod\",desired_state=\"running\",restart_policy=\"always\",status=\"running\"} 1"
        ));
        assert!(body.contains(
            "oxmgr_process_health_status{id=\"42\",name=\"api\",namespace=\"prod\",health_status=\"healthy\"} 1"
        ));
    }

    #[tokio::test]
    async fn handle_api_client_serves_metrics_over_http() {
        let snapshot = snapshot_with_processes(vec![fixture_metrics_process()]);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test metrics listener");
        let addr = listener
            .local_addr()
            .expect("failed to resolve test metrics addr");
        let (command_tx, _command_rx) = unbounded_channel();

        let server_snapshot = snapshot.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept failed");
            handle_api_client(stream, server_snapshot, command_tx)
                .await
                .expect("failed to handle api client");
        });

        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("failed to connect to metrics listener");
        client
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("failed to write metrics request");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("failed to read metrics response");

        let response = String::from_utf8(response).expect("metrics response should be utf-8");
        let (headers, body) = response
            .split_once("\r\n\r\n")
            .expect("expected HTTP response separator");
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(headers.contains(&format!("Content-Type: {PROMETHEUS_CONTENT_TYPE}\r\n")));
        assert!(body.contains(
            "oxmgr_process_memory_bytes{id=\"42\",name=\"api\",namespace=\"prod\"} 4096"
        ));

        server.await.expect("server task failed");
    }

    #[test]
    fn render_prometheus_metrics_escapes_labels_and_sanitizes_nan() {
        let mut process = fixture_metrics_process();
        process.name = "api\"svc".to_string();
        process.namespace = Some("prod\\blue\nline".to_string());
        process.cpu_percent = f32::NAN;

        let rendered = render_prometheus_metrics(&[process]);
        assert!(rendered.contains("name=\"api\\\"svc\""));
        assert!(rendered.contains("namespace=\"prod\\\\blue\\nline\""));
        assert!(rendered.contains("oxmgr_process_cpu_percent{id=\"42\",name=\"api\\\"svc\",namespace=\"prod\\\\blue\\nline\"} 0"));
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

    #[test]
    fn escape_prometheus_label_value_handles_special_characters() {
        assert_eq!(
            escape_prometheus_label_value("prod\\blue\"green\nline"),
            "prod\\\\blue\\\"green\\nline"
        );
    }

    #[test]
    fn restart_sleep_deadline_uses_due_instant_when_available() {
        let now = TokioInstant::now();
        let due = now + Duration::from_secs(7);
        assert_eq!(restart_sleep_deadline(Some(due), now), due);
    }

    #[test]
    fn restart_sleep_deadline_uses_far_future_when_no_restart_is_scheduled() {
        let now = TokioInstant::now();
        let deadline = restart_sleep_deadline(None, now);
        assert_eq!(
            deadline,
            now + Duration::from_secs(DISABLED_RESTART_SLEEP_SECS)
        );
    }

    #[tokio::test]
    async fn daemon_socket_available_sends_ping_request() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind local listener");
        let addr = listener
            .local_addr()
            .expect("failed to resolve listener addr");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept failed");
            let request: IpcRequest = read_json_line(&mut stream).await.expect("read failed");
            assert!(matches!(request, IpcRequest::Ping));
            write_json_line(&mut stream, &IpcResponse::ok("pong"))
                .await
                .expect("write failed");
        });

        assert!(daemon_socket_available(&addr.to_string()).await);
        server.await.expect("server task failed");
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
            pre_reload_cmd: None,
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
            watch_paths: Vec::new(),
            ignore_watch: Vec::new(),
            watch_delay_secs: 0,
            cluster_mode: false,
            cluster_instances: None,
            namespace: None,
            resource_limits: None,
            git_repo: None,
            git_ref: None,
            pull_secret_hash: Some(hash_secret("hook-secret")),
            reuse_port: false,
            wait_ready: false,
            ready_timeout_secs: crate::process::default_ready_timeout_secs(),
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
            pre_reload_cmd: None,
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
            watch_paths: Vec::new(),
            ignore_watch: Vec::new(),
            watch_delay_secs: 0,
            cluster_mode: false,
            cluster_instances: None,
            namespace: None,
            resource_limits: None,
            git_repo,
            git_ref: Some("main".to_string()),
            pull_secret_hash,
            reuse_port: false,
            wait_ready: false,
            ready_timeout_secs: crate::process::default_ready_timeout_secs(),
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

    fn json_body(response: &super::HttpResponse) -> &serde_json::Value {
        match &response.body {
            HttpBody::Json(body) => body,
            HttpBody::Text(_) => panic!("expected JSON response body"),
        }
    }

    fn text_body(response: &super::HttpResponse) -> &str {
        match &response.body {
            HttpBody::Text(body) => body,
            HttpBody::Json(_) => panic!("expected text response body"),
        }
    }

    fn snapshot_with_processes(processes: Vec<ManagedProcess>) -> DaemonSnapshot {
        DaemonSnapshot {
            processes: Arc::new(RwLock::new(processes)),
        }
    }

    fn fixture_metrics_process() -> ManagedProcess {
        ManagedProcess {
            id: 42,
            name: "api".to_string(),
            command: "sleep".to_string(),
            args: vec!["30".to_string()],
            pre_reload_cmd: None,
            cwd: None,
            env: HashMap::new(),
            restart_policy: RestartPolicy::Always,
            max_restarts: 5,
            restart_count: 2,
            crash_restart_limit: DEFAULT_CRASH_RESTART_LIMIT,
            auto_restart_history: Vec::new(),
            namespace: Some("prod".to_string()),
            git_repo: None,
            git_ref: None,
            pull_secret_hash: None,
            reuse_port: false,
            stop_signal: Some("SIGTERM".to_string()),
            stop_timeout_secs: 5,
            restart_delay_secs: 1,
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
            pid: Some(4242),
            status: crate::process::ProcessStatus::Running,
            desired_state: DesiredState::Running,
            last_exit_code: None,
            stdout_log: PathBuf::from("/tmp/api.stdout.log"),
            stderr_log: PathBuf::from("/tmp/api.stderr.log"),
            health_check: None,
            health_status: HealthStatus::Healthy,
            health_failures: 0,
            last_health_check: Some(1_700_000_100),
            next_health_check: Some(1_700_000_120),
            last_health_error: None,
            wait_ready: false,
            ready_timeout_secs: crate::process::default_ready_timeout_secs(),
            cpu_percent: 12.5,
            memory_bytes: 4096,
            last_metrics_at: Some(1_700_000_050),
            last_started_at: Some(1_700_000_000),
            last_stopped_at: None,
            config_fingerprint: "fixture-fingerprint".to_string(),
        }
    }
}
