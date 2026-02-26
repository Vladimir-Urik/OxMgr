use std::fs;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::storage::PersistedState;

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

pub(crate) async fn run(config: &AppConfig) -> Result<()> {
    println!("Oxmgr doctor");
    println!("Home: {}", config.base_dir.display());
    println!("Daemon: {}", config.daemon_addr);
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

    match config.daemon_addr.to_socket_addrs() {
        Ok(mut addrs) => {
            let resolved = addrs
                .next()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "no resolved address".to_string());
            record(DoctorStatus::Ok, "daemon_addr", resolved);
        }
        Err(err) => record(DoctorStatus::Fail, "daemon_addr", err.to_string()),
    }

    if config.state_path.exists() {
        match fs::read_to_string(&config.state_path) {
            Ok(content) if content.trim().is_empty() => record(
                DoctorStatus::Warn,
                "state_file",
                format!("{} is empty", config.state_path.display()),
            ),
            Ok(content) => match serde_json::from_str::<PersistedState>(&content) {
                Ok(state) => record(
                    DoctorStatus::Ok,
                    "state_file",
                    format!(
                        "{} ({} processes)",
                        config.state_path.display(),
                        state.processes.len()
                    ),
                ),
                Err(err) => record(
                    DoctorStatus::Fail,
                    "state_file",
                    format!("{} ({err})", config.state_path.display()),
                ),
            },
            Err(err) => record(DoctorStatus::Fail, "state_file", err.to_string()),
        }
    } else {
        record(
            DoctorStatus::Ok,
            "state_file",
            format!("{} (not created yet)", config.state_path.display()),
        );
    }

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
        Err(err) => record(
            DoctorStatus::Warn,
            "daemon_ping",
            format!("daemon not reachable ({err})"),
        ),
    }

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
    println!("[{}] {:<14} {}", status.label(), name, detail.as_ref());
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
