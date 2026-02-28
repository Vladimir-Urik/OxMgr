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

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "linux"))]
    use super::{apply_limits, cleanup};
    #[cfg(target_os = "linux")]
    use super::{ensure_controller_enabled, sanitize_cgroup_name};
    #[cfg(not(target_os = "linux"))]
    use crate::process::ResourceLimits;

    #[cfg(target_os = "linux")]
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::path::{Path, PathBuf};
    #[cfg(target_os = "linux")]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(target_os = "linux")]
    struct TempDir {
        path: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl TempDir {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "oxmgr-cgroup-{label}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("failed to create temporary test directory");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sanitize_cgroup_name_replaces_invalid_characters_and_defaults_empty() {
        assert_eq!(sanitize_cgroup_name("api/service #1"), "api_service__1");
        assert_eq!(sanitize_cgroup_name(""), "process");
        assert_eq!(sanitize_cgroup_name("worker-1.prod"), "worker-1.prod");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ensure_controller_enabled_writes_subtree_when_controller_is_available() {
        let temp = TempDir::new("enable-controller");
        fs::write(temp.path().join("cgroup.controllers"), "cpu memory\n")
            .expect("failed to write controllers file");
        fs::write(temp.path().join("cgroup.subtree_control"), "memory\n")
            .expect("failed to write subtree control file");

        ensure_controller_enabled(temp.path(), "cpu")
            .expect("expected cpu controller to be enabled");

        assert_eq!(
            fs::read_to_string(temp.path().join("cgroup.subtree_control"))
                .expect("failed to read subtree control"),
            "+cpu\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ensure_controller_enabled_is_noop_when_controller_already_enabled() {
        let temp = TempDir::new("controller-noop");
        fs::write(temp.path().join("cgroup.controllers"), "cpu memory\n")
            .expect("failed to write controllers file");
        fs::write(temp.path().join("cgroup.subtree_control"), "cpu memory\n")
            .expect("failed to write subtree control file");

        ensure_controller_enabled(temp.path(), "cpu")
            .expect("expected already-enabled controller to succeed");

        assert_eq!(
            fs::read_to_string(temp.path().join("cgroup.subtree_control"))
                .expect("failed to read subtree control"),
            "cpu memory\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ensure_controller_enabled_rejects_unavailable_controller() {
        let temp = TempDir::new("missing-controller");
        fs::write(temp.path().join("cgroup.controllers"), "memory io\n")
            .expect("failed to write controllers file");
        fs::write(temp.path().join("cgroup.subtree_control"), "")
            .expect("failed to write subtree control file");

        let err = ensure_controller_enabled(temp.path(), "cpu")
            .expect_err("expected unavailable controller to fail");

        assert!(
            err.to_string()
                .contains("cgroup controller 'cpu' is not available"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn apply_limits_returns_none_without_enforcement() {
        let result = apply_limits(
            "api",
            7,
            1234,
            &ResourceLimits {
                max_memory_mb: Some(256),
                max_cpu_percent: Some(50.0),
                cgroup_enforce: false,
                deny_gpu: false,
            },
        )
        .expect("expected limits to be ignored off Linux");

        assert!(result.is_none());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn apply_limits_rejects_enforcement_on_non_linux() {
        let err = apply_limits(
            "api",
            7,
            1234,
            &ResourceLimits {
                max_memory_mb: None,
                max_cpu_percent: None,
                cgroup_enforce: true,
                deny_gpu: false,
            },
        )
        .expect_err("expected cgroup enforcement to be unsupported");

        assert_eq!(
            err.to_string(),
            "cgroup enforcement is only supported on Linux"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn cleanup_is_a_noop_on_non_linux() {
        cleanup("/tmp/not-a-real-cgroup").expect("cleanup should be a no-op off Linux");
    }
}
