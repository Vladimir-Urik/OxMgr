#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{bail, Result};

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::ErrorKind;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

use crate::process::ResourceLimits;

#[cfg(target_os = "linux")]
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
#[cfg(target_os = "linux")]
const OXMGR_SLICE: &str = "oxmgr";

#[cfg(target_os = "linux")]
pub fn apply_limits(
    process_name: &str,
    process_id: u64,
    pid: u32,
    limits: &ResourceLimits,
) -> Result<Option<String>> {
    if !limits.cgroup_enforce {
        return Ok(None);
    }

    let root = Path::new(CGROUP_ROOT);
    if !root.join("cgroup.controllers").exists() {
        bail!("cgroup enforcement requires cgroup v2 mounted at {CGROUP_ROOT}");
    }

    let managed_root = root.join(OXMGR_SLICE);
    ensure_dir(&managed_root, "creating oxmgr cgroup root")?;

    if limits.max_cpu_percent.is_some() {
        ensure_controller_enabled(&managed_root, "cpu")?;
    }
    if limits.max_memory_mb.is_some() {
        ensure_controller_enabled(&managed_root, "memory")?;
    }

    let group_name = format!("{}-{}", sanitize_cgroup_name(process_name), process_id);
    let group_path = managed_root.join(group_name);
    ensure_dir(&group_path, "creating process cgroup")?;

    if let Some(max_cpu_percent) = limits.max_cpu_percent {
        if max_cpu_percent > 0.0 {
            let period_us: u64 = 100_000;
            let quota_us = ((max_cpu_percent as f64 / 100.0) * period_us as f64).round() as u64;
            let quota_us = quota_us.max(1);
            fs::write(
                group_path.join("cpu.max"),
                format!("{quota_us} {period_us}\n"),
            )
            .with_context(|| {
                format!(
                    "failed to write cpu.max for cgroup {}",
                    group_path.display()
                )
            })?;
        }
    }

    if let Some(max_memory_mb) = limits.max_memory_mb {
        if max_memory_mb > 0 {
            let max_bytes = max_memory_mb.saturating_mul(1024 * 1024);
            fs::write(group_path.join("memory.max"), format!("{max_bytes}\n")).with_context(
                || {
                    format!(
                        "failed to write memory.max for cgroup {}",
                        group_path.display()
                    )
                },
            )?;
        }
    }

    fs::write(group_path.join("cgroup.procs"), format!("{pid}\n")).with_context(|| {
        format!(
            "failed to attach pid {pid} into cgroup {}",
            group_path.display()
        )
    })?;

    Ok(Some(group_path.display().to_string()))
}

#[cfg(not(target_os = "linux"))]
pub fn apply_limits(_: &str, _: u64, _: u32, limits: &ResourceLimits) -> Result<Option<String>> {
    if limits.cgroup_enforce {
        bail!("cgroup enforcement is only supported on Linux");
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
pub fn cleanup(path: &str) -> Result<()> {
    let group = PathBuf::from(path);
    let root = Path::new(CGROUP_ROOT)
        .canonicalize()
        .with_context(|| format!("failed to resolve cgroup root {CGROUP_ROOT}"))?;

    let canonical_group = match group.canonicalize() {
        Ok(path) => path,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to resolve cgroup path {path}"))
        }
    };

    if !canonical_group.starts_with(&root) {
        bail!(
            "refusing to cleanup non-cgroup path: {}",
            canonical_group.display()
        );
    }

    match fs::remove_dir(&canonical_group) {
        Ok(()) => Ok(()),
        Err(err)
            if err.kind() == ErrorKind::NotFound || err.kind() == ErrorKind::DirectoryNotEmpty =>
        {
            Ok(())
        }
        Err(err) => Err(err).with_context(|| {
            format!(
                "failed to remove cgroup directory {}",
                canonical_group.display()
            )
        }),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn cleanup(_: &str) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_dir(path: &Path, operation: &str) -> Result<()> {
    fs::create_dir_all(path).map_err(|err| {
        if err.kind() == ErrorKind::PermissionDenied {
            anyhow::anyhow!(
                "{operation} failed: permission denied on {}. Run oxmgr daemon with privileges that can manage cgroups, or delegate cgroup control to this user.",
                path.display()
            )
        } else {
            anyhow::anyhow!("{operation} at {}: {err}", path.display())
        }
    })
}

#[cfg(target_os = "linux")]
fn ensure_controller_enabled(root: &Path, controller: &str) -> Result<()> {
    let controllers_path = root.join("cgroup.controllers");
    let controllers = fs::read_to_string(&controllers_path)
        .with_context(|| format!("failed to read {}", controllers_path.display()))?;

    if !controllers
        .split_whitespace()
        .any(|value| value == controller)
    {
        bail!(
            "cgroup controller '{controller}' is not available under {}",
            root.display()
        );
    }

    let subtree_path = root.join("cgroup.subtree_control");
    let subtree = fs::read_to_string(&subtree_path)
        .with_context(|| format!("failed to read {}", subtree_path.display()))?;
    if subtree.split_whitespace().any(|value| value == controller) {
        return Ok(());
    }

    fs::write(&subtree_path, format!("+{controller}\n")).map_err(|err| {
        if err.kind() == ErrorKind::PermissionDenied {
            anyhow::anyhow!(
                "enabling cgroup controller '{controller}' failed: permission denied on {}. Delegate cgroup subtree control or run daemon with elevated privileges.",
                subtree_path.display()
            )
        } else {
            anyhow::anyhow!(
                "failed to enable cgroup controller '{controller}' in {}: {err}",
                subtree_path.display()
            )
        }
    })
}

#[cfg(target_os = "linux")]
fn sanitize_cgroup_name(name: &str) -> String {
    let mut sanitized = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }
    if sanitized.is_empty() {
        "process".to_string()
    } else {
        sanitized
    }
}
