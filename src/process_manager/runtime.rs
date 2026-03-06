use std::ffi::OsString;
use std::path::Path;
#[cfg(windows)]
use std::process::Stdio;
use std::time::{Duration, Instant as StdInstant};

use anyhow::Result;
use sysinfo::{Pid as SysPid, ProcessesToUpdate, System};
#[cfg(windows)]
use tokio::process::Command;
use tokio::time::sleep;
#[cfg(windows)]
use tokio::time::timeout as tokio_timeout;
use tracing::warn;

use crate::cgroup;
use crate::process::ManagedProcess;

#[cfg(unix)]
pub(super) fn process_exists(pid: u32) -> bool {
    use nix::errno::Errno;
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    match kill(Pid::from_raw(pid as i32), None::<Signal>) {
        Ok(()) => true,
        Err(Errno::EPERM) => true,
        Err(Errno::ESRCH) => false,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
pub(super) fn process_exists(pid: u32) -> bool {
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::Some(&[SysPid::from_u32(pid)]), true);
    system.process(SysPid::from_u32(pid)).is_some()
}

#[cfg(unix)]
pub(super) async fn terminate_pid(
    pid: u32,
    signal_name: Option<&str>,
    timeout: Duration,
) -> Result<()> {
    use nix::errno::Errno;
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    let os_pid = Pid::from_raw(pid as i32);
    let pgid = Pid::from_raw(-(pid as i32));
    let signal = unix_signal_from_name(signal_name).unwrap_or(Signal::SIGTERM);

    let mut delivered = false;
    match kill(pgid, signal) {
        Ok(()) => delivered = true,
        Err(Errno::ESRCH) => {}
        Err(err) => {
            warn!(
                "failed to send {:?} to process group {} for pid {}: {}",
                signal, pgid, pid, err
            );
        }
    }

    if !delivered {
        match kill(os_pid, signal) {
            Ok(()) => {}
            Err(Errno::ESRCH) => return Ok(()),
            Err(err) => {
                return Err(anyhow::anyhow!("failed to send {signal:?} to {pid}: {err}"));
            }
        }
    }

    let graceful_wait = graceful_wait_before_force_kill(signal, timeout);
    let start = StdInstant::now();
    while start.elapsed() < graceful_wait {
        if !process_exists(pid) {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }

    if process_exists(pid) {
        let _ = kill(pgid, Signal::SIGKILL);
        let _ = kill(os_pid, Signal::SIGKILL);
    }

    Ok(())
}

#[cfg(unix)]
pub(super) fn graceful_wait_before_force_kill(
    signal: nix::sys::signal::Signal,
    timeout: Duration,
) -> Duration {
    if signal == nix::sys::signal::Signal::SIGTERM {
        timeout.min(Duration::from_secs(15))
    } else {
        timeout
    }
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

#[cfg(windows)]
pub(super) async fn terminate_pid(
    pid: u32,
    _signal_name: Option<&str>,
    timeout: Duration,
) -> Result<()> {
    use anyhow::Context;

    if !process_exists(pid) {
        return Ok(());
    }

    let taskkill_timeout = timeout.max(Duration::from_secs(2));
    let pid_string = pid.to_string();
    let graceful_status = tokio_timeout(
        taskkill_timeout,
        Command::new("taskkill")
            .args(["/PID", &pid_string, "/T"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    )
    .await
    .context("taskkill timed out during graceful stop")?
    .context("failed to run taskkill for graceful stop")?;

    if !graceful_status.success() && !process_exists(pid) {
        return Ok(());
    }

    let start = StdInstant::now();
    while start.elapsed() < timeout {
        if !process_exists(pid) {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }

    if process_exists(pid) {
        let force_status = tokio_timeout(
            taskkill_timeout,
            Command::new("taskkill")
                .args(["/PID", &pid_string, "/T", "/F"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
        )
        .await
        .context("taskkill timed out during forced stop")?
        .context("failed to run taskkill for forced stop")?;
        if !force_status.success() && process_exists(pid) {
            anyhow::bail!("failed to force-kill process {pid} with taskkill");
        }
    }

    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(super) async fn terminate_pid(
    _pid: u32,
    _signal_name: Option<&str>,
    _timeout: Duration,
) -> Result<()> {
    Ok(())
}

pub(super) fn cleanup_process_cgroup(process: &mut ManagedProcess) {
    let Some(path) = process.cgroup_path.take() else {
        return;
    };
    if let Err(err) = cgroup::cleanup(&path) {
        warn!(
            "failed to cleanup cgroup for process {}: {}",
            process.name, err
        );
    }
}

pub(super) fn pid_matches_expected_process(
    pid: u32,
    expected_program: &str,
    expected_args: &[String],
    expected_cwd: Option<&Path>,
) -> bool {
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::Some(&[SysPid::from_u32(pid)]), true);

    let Some(info) = system.process(SysPid::from_u32(pid)) else {
        return false;
    };

    if let Some(expected_cwd) = expected_cwd {
        match info.cwd() {
            Some(actual_cwd) if actual_cwd == expected_cwd => {}
            _ => return false,
        }
    }

    if !program_matches_expected(info.exe(), expected_program) {
        return false;
    }

    args_match_expected(info.cmd(), expected_program, expected_args)
}

pub(super) fn program_matches_expected(actual_exe: Option<&Path>, expected_program: &str) -> bool {
    let Some(actual_exe) = actual_exe else {
        return false;
    };
    let expected_path = Path::new(expected_program);

    if expected_path.is_absolute() {
        return actual_exe == expected_path;
    }

    actual_exe
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case(expected_program))
        .unwrap_or(false)
}

pub(super) fn args_match_expected(
    actual_args: &[OsString],
    expected_program: &str,
    expected_args: &[String],
) -> bool {
    if actual_args.len() == expected_args.len()
        && actual_args
            .iter()
            .zip(expected_args)
            .all(|(actual, expected)| {
                actual
                    .to_str()
                    .map(|value| value == expected)
                    .unwrap_or(false)
            })
    {
        return true;
    }

    actual_args.len() == expected_args.len().saturating_add(1)
        && actual_args
            .first()
            .and_then(|value| value.to_str())
            .map(|value| {
                let actual = Path::new(value)
                    .file_name()
                    .and_then(|item| item.to_str())
                    .unwrap_or(value);
                let expected = Path::new(expected_program)
                    .file_name()
                    .and_then(|item| item.to_str())
                    .unwrap_or(expected_program);
                actual.eq_ignore_ascii_case(expected)
            })
            .unwrap_or(false)
        && actual_args[1..]
            .iter()
            .zip(expected_args)
            .all(|(actual, expected)| {
                actual
                    .to_str()
                    .map(|value| value == expected)
                    .unwrap_or(false)
            })
}
