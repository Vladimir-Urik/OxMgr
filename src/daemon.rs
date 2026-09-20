//! Foreground daemon loop and local IPC handling.

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
use crate::events::BusEvent;
#[cfg(unix)]
use crate::events::EventFilter;
use crate::ipc::{read_json_line, send_request, write_json_line, IpcRequest, IpcResponse};
use crate::logging::ProcessLogs;
use crate::process::ManagedProcess;
use crate::process_manager::ProcessManager;

#[derive(Clone, Default)]
struct DaemonSnapshot {
    processes: Arc<RwLock<Vec<ManagedProcess>>>,
}

const DISABLED_RESTART_SLEEP_SECS: u64 = 24 * 60 * 60;
enum ManagerCommand {
    Ipc {
        request: IpcRequest,
        response_tx: oneshot::Sender<IpcResponse>,
    },
}

/// Runs the Oxmgr daemon in the foreground.
///
/// The daemon owns process lifecycle management and serves the local IPC socket
/// used by the CLI.
pub async fn run_foreground(config: AppConfig) -> Result<()> {
    config.ensure_layout()?;
    let listener = bind_listener(&config.daemon_addr).await?;

    let (exit_tx, mut exit_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel::<()>();
    let (command_tx, mut command_rx) = mpsc::unbounded_channel::<ManagerCommand>();
    let mut manager = ProcessManager::new(config.clone(), exit_tx)?;
    manager.recover_processes().await?;
    let snapshot = DaemonSnapshot::default();
    snapshot.publish(&manager).await;

    let event_tx = manager.event_tx();
    #[cfg(unix)]
    {
        let socket_path = config.event_socket_path.clone();
        let tx = event_tx.clone();
        tokio::spawn(async move {
            run_event_socket(socket_path, tx).await;
        });
    }

    let mut restart_sleep = Box::pin(sleep_until(restart_sleep_deadline(
        manager.next_scheduled_restart_at(),
        TokioInstant::now(),
    )));
    let mut maintenance = tokio::time::interval(Duration::from_secs(2));
    maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);

    info!("oxmgr daemon started at {}", config.daemon_addr);

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
            Some(command) = command_rx.recv() => {
                match command {
                    ManagerCommand::Ipc { request, response_tx } => {
                        let response = execute_request(request, &mut manager, &shutdown_tx).await;
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
                let _ = event_tx.send(std::sync::Arc::new(BusEvent::daemon_shutdown()));
                manager.shutdown_all().await?;
                snapshot.publish(&manager).await;
                break;
            }
            ctrl = tokio::signal::ctrl_c() => {
                if let Err(err) = ctrl {
                    warn!("failed to wait for CTRL-C signal: {err}");
                }
                info!("received shutdown signal; stopping managed processes");
                let _ = event_tx.send(std::sync::Arc::new(BusEvent::daemon_shutdown()));
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
        IpcRequest::Stop { target } if target == "all" => {
            match manager.stop_all_processes().await {
                Ok(processes) => {
                    let mut response =
                        IpcResponse::ok(format!("stopped {} process(es)", processes.len()));
                    response.processes = redact_processes(processes);
                    response
                }
                Err(err) => IpcResponse::error(err.to_string()),
            }
        }
        IpcRequest::Stop { target } => match manager.stop_process(&target).await {
            Ok(process) => {
                let mut response = IpcResponse::ok(format!("stopped {}", process.target_label()));
                response.process = Some(process.redacted_for_transport());
                response
            }
            Err(err) => IpcResponse::error(err.to_string()),
        },
        IpcRequest::Restart { target } if target == "all" => {
            match manager.restart_all_processes().await {
                Ok(processes) => {
                    let mut response =
                        IpcResponse::ok(format!("restarted {} process(es)", processes.len()));
                    response.processes = redact_processes(processes);
                    response
                }
                Err(err) => IpcResponse::error(err.to_string()),
            }
        }
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
        IpcRequest::Delete { target } if target == "all" => {
            match manager.delete_all_processes().await {
                Ok(processes) => {
                    let mut response =
                        IpcResponse::ok(format!("deleted {} process(es)", processes.len()));
                    response.processes = redact_processes(processes);
                    response
                }
                Err(err) => IpcResponse::error(err.to_string()),
            }
        }
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

// ---------------------------------------------------------------------------
// Event socket (Unix only)
// ---------------------------------------------------------------------------

#[cfg(unix)]
async fn run_event_socket(
    socket_path: std::path::PathBuf,
    event_tx: tokio::sync::broadcast::Sender<std::sync::Arc<BusEvent>>,
) {
    use tokio::net::UnixListener;

    let _ = std::fs::remove_file(&socket_path);
    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(err) => {
            error!(
                "failed to bind event socket at {}: {err}",
                socket_path.display()
            );
            return;
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));
    }

    info!("oxmgr event socket listening at {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let rx = event_tx.subscribe();
                tokio::spawn(async move {
                    if let Err(err) = handle_event_client(stream, rx).await {
                        if !is_client_disconnect(&err) {
                            error!("event socket client error: {err}");
                        }
                    }
                });
            }
            Err(err) => {
                error!("event socket accept failed: {err}");
            }
        }
    }
}

#[cfg(unix)]
async fn handle_event_client(
    stream: tokio::net::UnixStream,
    mut rx: tokio::sync::broadcast::Receiver<std::sync::Arc<BusEvent>>,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::time::Duration;

    let (read_half, mut write_half) = stream.into_split();

    // Give the client up to 500 ms to send a filter line.
    let filter = {
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        match tokio::time::timeout(Duration::from_millis(500), reader.read_line(&mut line)).await {
            Ok(Ok(n)) if n > 0 => {
                serde_json::from_str::<EventFilter>(line.trim()).unwrap_or_default()
            }
            _ => EventFilter::default(),
        }
    };

    loop {
        match rx.recv().await {
            Ok(event) => {
                if filter.matches(&event) {
                    let mut payload = serde_json::to_vec(&*event)?;
                    payload.push(b'\n');
                    write_half.write_all(&payload).await?;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                warn!("event socket client lagged, dropped {n} events");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }

    Ok(())
}

#[cfg(unix)]
fn is_client_disconnect(err: &anyhow::Error) -> bool {
    err.downcast_ref::<std::io::Error>()
        .map(|e| {
            matches!(
                e.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::net::TcpListener;
    use tokio::sync::mpsc::unbounded_channel;

    use super::{daemon_socket_available, execute_snapshot_request, DaemonSnapshot};
    use crate::config::AppConfig;
    use crate::ipc::{read_json_line, write_json_line, IpcRequest, IpcResponse};
    use crate::process::{RestartPolicy, StartProcessSpec};
    use crate::process_manager::ProcessManager;

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
        start_minimal_service(&mut manager, "api").await;

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
    async fn snapshot_request_redacts_env() {
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
            reuse_port: false,
            wait_ready: false,
            ready_timeout_secs: crate::process::default_ready_timeout_secs(),
            log_date_format: None,
            unified_logs: false,
            cron_restart: None,
            stdout_log_override: None,
            stderr_log_override: None,
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

        let _ = manager.shutdown_all().await;
    }

    async fn start_minimal_service(manager: &mut ProcessManager, name: &str) {
        let exe = std::env::current_exe().expect("failed to read current executable path");
        let spec = StartProcessSpec {
            command: format!("\"{}\" --help", exe.display()),
            name: Some(name.to_string()),
            pre_reload_cmd: None,
            restart_policy: RestartPolicy::Never,
            max_restarts: 1,
            crash_restart_limit: 0,
            cwd: None,
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
            reuse_port: false,
            wait_ready: false,
            ready_timeout_secs: crate::process::default_ready_timeout_secs(),
            log_date_format: None,
            unified_logs: false,
            cron_restart: None,
            stdout_log_override: None,
            stderr_log_override: None,
        };
        manager
            .start_process(spec)
            .await
            .expect("failed to start service for daemon test");
    }

    fn empty_manager(prefix: &str) -> ProcessManager {
        let config = test_config(prefix);
        let (exit_tx, _exit_rx) = unbounded_channel();
        ProcessManager::new(config, exit_tx).expect("failed to initialize test process manager")
    }

    fn test_config(prefix: &str) -> AppConfig {
        let base = temp_dir(prefix);
        let log_dir = base.join("logs");
        fs::create_dir_all(&log_dir).expect("failed to create log directory");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .subsec_nanos();
        // Unix socket paths must be < 104 chars on macOS; use /tmp directly
        let event_socket_path = PathBuf::from(format!("/tmp/oxmgr-ev-{nonce}.sock"));
        AppConfig {
            base_dir: base.clone(),
            daemon_addr: "127.0.0.1:50200".to_string(),
            state_path: base.join("state.json"),
            log_dir,
            log_rotation: crate::logging::LogRotationPolicy {
                max_size_bytes: 1024 * 1024,
                max_files: 2,
                max_age_days: 1,
            },
            event_socket_path,
        }
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("oxmgr-daemon-{prefix}-{nonce}"))
    }

    /// Returns a short socket path under /tmp to stay within SUN_LEN (~104 chars on macOS).
    #[cfg(unix)]
    fn short_socket_path(tag: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .subsec_nanos();
        PathBuf::from(format!("/tmp/ox-{tag}-{nonce}.sock"))
    }

    // --- event socket tests (Unix only) ---

    #[cfg(unix)]
    #[tokio::test]
    async fn event_socket_delivers_events_to_connected_client() {
        use std::sync::Arc;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;
        use tokio::time::{timeout, Duration};

        use crate::events::{BusEvent, EventFilter, EventProcessInfo};

        let dir = temp_dir("event-socket-basic");
        let socket_path = short_socket_path("basic");

        let (event_tx, _) = tokio::sync::broadcast::channel::<Arc<BusEvent>>(64);
        let tx_clone = event_tx.clone();
        let path_clone = socket_path.clone();
        tokio::spawn(async move {
            super::run_event_socket(path_clone, tx_clone).await;
        });

        // Give the socket a moment to bind.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = UnixStream::connect(&socket_path)
            .await
            .expect("failed to connect to event socket");

        // Send an empty filter (subscribe to everything).
        let filter = EventFilter::default();
        let mut payload = serde_json::to_vec(&filter).expect("serialize filter");
        payload.push(b'\n');
        client.write_all(&payload).await.expect("write filter");

        // Give the socket task time to read the filter before emitting.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let process_info = EventProcessInfo {
            id: 1,
            name: "api".into(),
            namespace: None,
            pid: Some(1234),
            command: "node server.js".into(),
            cwd: None,
        };
        event_tx
            .send(Arc::new(BusEvent::process_crashed(
                process_info,
                Some(1),
                None,
                0,
                3,
                vec![],
            )))
            .expect("broadcast send failed");

        let (read_half, _) = client.into_split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .expect("timed out waiting for event")
            .expect("read failed");

        let json: serde_json::Value =
            serde_json::from_str(line.trim()).expect("invalid JSON from socket");
        assert_eq!(json["event"], "process:crashed");
        assert_eq!(json["process"]["name"], "api");
        assert_eq!(json["data"]["exit_code"], 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn event_socket_respects_process_filter() {
        use std::sync::Arc;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;
        use tokio::time::{timeout, Duration};

        use crate::events::{BusEvent, EventFilter, EventProcessInfo};

        let dir = temp_dir("event-socket-filter");
        let socket_path = short_socket_path("filter");

        let (event_tx, _) = tokio::sync::broadcast::channel::<Arc<BusEvent>>(64);
        let tx_clone = event_tx.clone();
        let path_clone = socket_path.clone();
        tokio::spawn(async move {
            super::run_event_socket(path_clone, tx_clone).await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = UnixStream::connect(&socket_path)
            .await
            .expect("connect failed");

        // Only subscribe to events for "api" process.
        let filter = EventFilter {
            subscribe: vec![],
            process: Some("api".into()),
        };
        let mut payload = serde_json::to_vec(&filter).expect("serialize filter");
        payload.push(b'\n');
        client.write_all(&payload).await.expect("write filter");

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Emit for "worker" — should be filtered out.
        event_tx
            .send(Arc::new(BusEvent::process_online(EventProcessInfo {
                id: 2,
                name: "worker".into(),
                namespace: None,
                pid: Some(9999),
                command: String::new(),
                cwd: None,
            })))
            .expect("send worker event");

        // Emit for "api" — should be delivered.
        event_tx
            .send(Arc::new(BusEvent::process_online(EventProcessInfo {
                id: 1,
                name: "api".into(),
                namespace: None,
                pid: Some(1234),
                command: String::new(),
                cwd: None,
            })))
            .expect("send api event");

        let (read_half, _) = client.into_split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .expect("timed out waiting for event")
            .expect("read failed");

        let json: serde_json::Value = serde_json::from_str(line.trim()).expect("invalid JSON");
        // The first line received must be the "api" event, not "worker".
        assert_eq!(json["event"], "process:online");
        assert_eq!(json["process"]["name"], "api");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn event_socket_delivers_daemon_shutdown_through_process_filter() {
        use std::sync::Arc;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;
        use tokio::time::{timeout, Duration};

        use crate::events::{BusEvent, EventFilter};

        let dir = temp_dir("event-socket-shutdown");
        let socket_path = short_socket_path("shutdown");

        let (event_tx, _) = tokio::sync::broadcast::channel::<Arc<BusEvent>>(64);
        let tx_clone = event_tx.clone();
        let path_clone = socket_path.clone();
        tokio::spawn(async move {
            super::run_event_socket(path_clone, tx_clone).await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = UnixStream::connect(&socket_path)
            .await
            .expect("connect failed");

        // Subscribe only to "api" process — daemon:shutdown must still arrive.
        let filter = EventFilter {
            subscribe: vec![],
            process: Some("api".into()),
        };
        let mut payload = serde_json::to_vec(&filter).expect("serialize filter");
        payload.push(b'\n');
        client.write_all(&payload).await.expect("write filter");

        tokio::time::sleep(Duration::from_millis(100)).await;

        event_tx
            .send(Arc::new(BusEvent::daemon_shutdown()))
            .expect("send shutdown event");

        let (read_half, _) = client.into_split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .expect("timed out waiting for event")
            .expect("read failed");

        let json: serde_json::Value = serde_json::from_str(line.trim()).expect("invalid JSON");
        assert_eq!(json["event"], "daemon:shutdown");

        let _ = std::fs::remove_dir_all(dir);
    }
}
