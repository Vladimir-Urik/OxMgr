use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;

use super::spawn::parse_command_line;
use crate::process::{HealthCheck, ManagedProcess};

pub(super) async fn execute_health_check(
    process: &ManagedProcess,
    check: &HealthCheck,
) -> Result<()> {
    let (command, args) = parse_command_line(&check.command)?;

    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(process.cwd.as_ref().unwrap_or(&std::env::current_dir()?))
        .envs(&process.env)
        .spawn()
        .context("failed to spawn health-check command")?;

    match tokio::time::timeout(Duration::from_secs(check.timeout_secs.max(1)), child.wait()).await {
        Ok(wait_result) => {
            let status = wait_result.context("health-check wait failed")?;
            if status.success() {
                Ok(())
            } else {
                anyhow::bail!("health command exited with {:?}", status.code())
            }
        }
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!("health command timed out after {}s", check.timeout_secs)
        }
    }
}
