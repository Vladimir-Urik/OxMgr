use std::env;
use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration, MissedTickBehavior};
use tracing::{error, info, warn};

use crate::config::AppConfig;
use crate::errors::OxmgrError;
use crate::ipc::{read_json_line, send_request, write_json_line, IpcRequest, IpcResponse};
use crate::process_manager::ProcessManager;

pub async fn run_foreground(config: AppConfig) -> Result<()> {
    config.ensure_layout()?;
    let listener = bind_listener(&config.daemon_addr).await?;

    let (exit_tx, mut exit_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel::<()>();
    let mut manager = ProcessManager::new(config.clone(), exit_tx)?;
    manager.recover_processes().await?;

    let mut maintenance = tokio::time::interval(Duration::from_secs(2));
    maintenance.set_missed_tick_behavior(MissedTickBehavior::Skip);

    info!("oxmgr daemon started at {}", config.daemon_addr);

    loop {
        tokio::select! {
            incoming = listener.accept() => {
                match incoming {
                    Ok((mut stream, _)) => {
                        if let Err(err) = handle_client(&mut stream, &mut manager, &shutdown_tx).await {
                            error!("failed to handle IPC client: {err}");
                        }
                    }
                    Err(err) => {
                        error!("IPC accept failed: {err}");
                    }
                }
            }
            Some(event) = exit_rx.recv() => {
                if let Err(err) = manager.handle_exit_event(event).await {
                    error!("failed to process exit event: {err}");
                }
            }
            _ = maintenance.tick() => {
                if let Err(err) = manager.run_periodic_tasks().await {
                    error!("periodic manager task failed: {err}");
                }
            }
            Some(_) = shutdown_rx.recv() => {
                info!("shutdown requested via IPC; stopping managed processes");
                manager.shutdown_all().await?;
                break;
            }
            ctrl = tokio::signal::ctrl_c() => {
                if let Err(err) = ctrl {
                    warn!("failed to wait for CTRL-C signal: {err}");
                }
                info!("received shutdown signal; stopping managed processes");
                manager.shutdown_all().await?;
                break;
            }
        }
    }

    Ok(())
}

pub async fn ensure_daemon_running(config: &AppConfig) -> Result<()> {
    if ping(config).await {
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
        if ping(config).await {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }

    anyhow::bail!("daemon did not become ready in time")
}

async fn ping(config: &AppConfig) -> bool {
    match send_request(&config.daemon_addr, &IpcRequest::Ping).await {
        Ok(response) => response.ok,
        Err(_) => false,
    }
}

async fn bind_listener(daemon_addr: &str) -> Result<TcpListener> {
    if TcpStream::connect(daemon_addr).await.is_ok() {
        return Err(OxmgrError::DaemonAlreadyRunning.into());
    }

    TcpListener::bind(daemon_addr)
        .await
        .with_context(|| format!("failed to bind daemon endpoint at {daemon_addr}"))
}

async fn handle_client(
    stream: &mut TcpStream,
    manager: &mut ProcessManager,
    shutdown_tx: &mpsc::UnboundedSender<()>,
) -> Result<()> {
    let request = read_json_line::<IpcRequest, _>(stream).await?;
    let response = execute_request(request, manager, shutdown_tx).await;
    write_json_line(stream, &response).await
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
        IpcRequest::Start {
            command,
            name,
            restart_policy,
            max_restarts,
            cwd,
            env,
            health_check,
            stop_signal,
            stop_timeout_secs,
            restart_delay_secs,
            start_delay_secs,
            namespace,
            resource_limits,
        } => match manager
            .start_process(
                command,
                name,
                restart_policy,
                max_restarts,
                cwd,
                env,
                health_check,
                stop_signal,
                stop_timeout_secs,
                restart_delay_secs,
                start_delay_secs,
                namespace,
                resource_limits,
            )
            .await
        {
            Ok(process) => {
                let mut response = IpcResponse::ok(format!("started {}", process.target_label()));
                response.process = Some(process);
                response
            }
            Err(err) => IpcResponse::error(err.to_string()),
        },
        IpcRequest::Stop { target } => match manager.stop_process(&target).await {
            Ok(process) => {
                let mut response = IpcResponse::ok(format!("stopped {}", process.target_label()));
                response.process = Some(process);
                response
            }
            Err(err) => IpcResponse::error(err.to_string()),
        },
        IpcRequest::Restart { target } => match manager.restart_process(&target).await {
            Ok(process) => {
                let mut response = IpcResponse::ok(format!("restarted {}", process.target_label()));
                response.process = Some(process);
                response
            }
            Err(err) => IpcResponse::error(err.to_string()),
        },
        IpcRequest::Reload { target } => match manager.reload_process(&target).await {
            Ok(process) => {
                let mut response = IpcResponse::ok(format!("reloaded {}", process.target_label()));
                response.process = Some(process);
                response
            }
            Err(err) => IpcResponse::error(err.to_string()),
        },
        IpcRequest::Delete { target } => match manager.delete_process(&target).await {
            Ok(process) => {
                let mut response = IpcResponse::ok(format!("deleted {}", process.target_label()));
                response.process = Some(process);
                response
            }
            Err(err) => IpcResponse::error(err.to_string()),
        },
        IpcRequest::List => {
            let mut response = IpcResponse::ok("ok");
            response.processes = manager.list_processes();
            response
        }
        IpcRequest::Status { target } => match manager.get_process(&target) {
            Ok(process) => {
                let mut response = IpcResponse::ok("ok");
                response.process = Some(process);
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
