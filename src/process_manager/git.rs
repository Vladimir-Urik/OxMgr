use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::process::Command;

#[derive(Debug)]
pub(super) struct PullOutcome {
    pub(super) changed: bool,
    pub(super) restarted_or_reloaded: bool,
    pub(super) message: String,
}

pub(super) async fn ensure_repo_checkout(
    cwd: &Path,
    repo: &str,
    git_ref: Option<&str>,
) -> Result<()> {
    if !cwd.exists() {
        let parent = cwd.parent().context("cwd has no parent directory")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        let cwd_text = cwd.to_string_lossy().to_string();
        if let Some(git_ref) = git_ref {
            run_git(
                parent,
                &["clone", "--branch", git_ref, repo, &cwd_text],
                "clone repository",
            )
            .await?;
        } else {
            run_git(parent, &["clone", repo, &cwd_text], "clone repository").await?;
        }
        return Ok(());
    }

    let dot_git = cwd.join(".git");
    if dot_git.exists() {
        return Ok(());
    }

    let mut entries =
        fs::read_dir(cwd).with_context(|| format!("failed to read directory {}", cwd.display()))?;
    if entries.next().is_some() {
        anyhow::bail!(
            "cwd {} exists but is not a git checkout and is not empty",
            cwd.display()
        );
    }

    if let Some(git_ref) = git_ref {
        run_git(
            cwd,
            &["clone", "--branch", git_ref, repo, "."],
            "clone repository into cwd",
        )
        .await
    } else {
        run_git(cwd, &["clone", repo, "."], "clone repository into cwd").await
    }?;
    Ok(())
}

pub(super) async fn ensure_origin_remote(cwd: &Path, repo: &str) -> Result<()> {
    match run_git(cwd, &["remote", "get-url", "origin"], "read git origin").await {
        Ok(current) => {
            if current.trim() != repo {
                run_git(
                    cwd,
                    &["remote", "set-url", "origin", repo],
                    "set git origin",
                )
                .await?;
            }
        }
        Err(_) => {
            run_git(cwd, &["remote", "add", "origin", repo], "add git origin").await?;
        }
    }
    Ok(())
}

pub(super) async fn git_rev_parse_head(cwd: &Path) -> Result<String> {
    run_git(cwd, &["rev-parse", "HEAD"], "read current commit")
        .await
        .map(|value| value.trim().to_string())
}

pub(super) async fn run_git(cwd: &Path, args: &[&str], action: &str) -> Result<String> {
    let mut command = Command::new("git");
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = tokio::time::timeout(Duration::from_secs(120), command.output())
        .await
        .with_context(|| format!("timed out while attempting to {action}"))?
        .with_context(|| format!("failed to start git command to {action}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let details = if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else {
            stderr.trim().to_string()
        };
        anyhow::bail!(
            "git command failed while trying to {} in {}: {}",
            action,
            cwd.display(),
            details
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(super) fn short_commit(commit: &str) -> String {
    commit.chars().take(8).collect::<String>()
}

pub(super) fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{:x}", digest)
}

pub(super) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }

    diff == 0
}
