use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};
use regex::RegexSet;

use crate::process::ManagedProcess;

#[cfg(test)]
pub(super) fn watch_fingerprint_for_dir(root: &Path) -> Result<u64> {
    watch_fingerprint_for_roots(&[root.to_path_buf()], root, &[])
}

pub(super) fn watch_fingerprint_for_process(process: &ManagedProcess) -> Result<u64> {
    let cwd = process
        .cwd
        .as_ref()
        .with_context(|| format!("watch requires cwd to be set for process {}", process.name))?;

    let roots = if process.watch_paths.is_empty() {
        vec![cwd.clone()]
    } else {
        process
            .watch_paths
            .iter()
            .map(|path| {
                if path.is_absolute() {
                    path.clone()
                } else {
                    cwd.join(path)
                }
            })
            .collect()
    };

    watch_fingerprint_for_roots(&roots, cwd, &process.ignore_watch)
}

pub(super) fn watch_fingerprint_for_roots(
    roots: &[PathBuf],
    cwd: &Path,
    ignore_watch: &[String],
) -> Result<u64> {
    let matcher = compile_watch_ignore_matcher(ignore_watch)?;
    let mut hash = 1469598103934665603_u64;
    let mut roots = roots.to_vec();
    roots.sort();

    for root in roots {
        let logical_root = watch_logical_path(cwd, &root);
        fingerprint_watch_path(&root, &logical_root, &matcher, &mut hash)?;
    }

    Ok(hash)
}

fn compile_watch_ignore_matcher(ignore_watch: &[String]) -> Result<Option<RegexSet>> {
    if ignore_watch.is_empty() {
        return Ok(None);
    }

    Ok(Some(
        RegexSet::new(ignore_watch).context("invalid ignore_watch pattern")?,
    ))
}

fn fingerprint_watch_path(
    path: &Path,
    logical_path: &str,
    matcher: &Option<RegexSet>,
    hash: &mut u64,
) -> Result<()> {
    if !logical_path.is_empty() && should_ignore_watch_path(logical_path, matcher) {
        return Ok(());
    }
    if !path.exists() {
        anyhow::bail!("watch path does not exist: {}", path.display());
    }

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;
    if !logical_path.is_empty() {
        hash_bytes(hash, logical_path.as_bytes());
    }

    let file_type_tag = if metadata.file_type().is_dir() {
        1_u64
    } else if metadata.file_type().is_symlink() {
        2_u64
    } else {
        3_u64
    };
    hash_u64(hash, file_type_tag);
    hash_u64(hash, metadata.len());
    hash_u64(
        hash,
        metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|value| value.as_secs())
            .unwrap_or(0),
    );
    hash_u64(
        hash,
        metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|value| value.subsec_nanos() as u64)
            .unwrap_or(0),
    );

    if !metadata.file_type().is_dir() {
        return Ok(());
    }

    let mut children: Vec<PathBuf> = fs::read_dir(path)
        .with_context(|| format!("failed to read watch directory {}", path.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    children.sort();

    for child in children {
        let child_name = child
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        let child_logical = if logical_path.is_empty() {
            child_name.to_string()
        } else {
            format!("{logical_path}/{child_name}")
        };
        fingerprint_watch_path(&child, &child_logical, matcher, hash)?;
    }

    Ok(())
}

fn should_ignore_watch_path(path: &str, matcher: &Option<RegexSet>) -> bool {
    matcher
        .as_ref()
        .map(|matcher| matcher.is_match(path))
        .unwrap_or(false)
}

fn watch_logical_path(cwd: &Path, path: &Path) -> String {
    normalize_watch_path(
        path.strip_prefix(cwd)
            .unwrap_or(path)
            .to_string_lossy()
            .as_ref(),
    )
}

fn normalize_watch_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= *byte as u64;
        *hash = hash.wrapping_mul(1099511628211);
    }
}

fn hash_u64(hash: &mut u64, value: u64) {
    hash_bytes(hash, &value.to_le_bytes());
}
