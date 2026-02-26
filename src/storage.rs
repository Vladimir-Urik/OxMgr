use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::process::ManagedProcess;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    pub next_id: u64,
    pub processes: Vec<ManagedProcess>,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            next_id: 1,
            processes: Vec::new(),
        }
    }
}

pub fn load_state(path: &Path) -> Result<PersistedState> {
    if !path.exists() {
        return Ok(PersistedState::default());
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read state file {}", path.display()))?;

    if content.trim().is_empty() {
        return Ok(PersistedState::default());
    }

    match serde_json::from_str::<PersistedState>(&content) {
        Ok(state) => Ok(state),
        Err(error) => {
            let backup = corrupted_backup_path(path);
            if let Err(rename_err) = fs::rename(path, &backup) {
                warn!(
                    "failed to move corrupted state file {} -> {}: {rename_err}",
                    path.display(),
                    backup.display()
                );
            } else {
                warn!(
                    "state file {} is corrupted ({error}), moved to {}",
                    path.display(),
                    backup.display()
                );
            }
            Ok(PersistedState::default())
        }
    }
}

pub fn save_state(path: &Path, state: &PersistedState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let payload = serde_json::to_vec_pretty(state)?;
    let tmp_path = tmp_state_path(path);

    fs::write(&tmp_path, payload)
        .with_context(|| format!("failed to write temporary state {}", tmp_path.display()))?;
    replace_state_file(&tmp_path, path)?;

    Ok(())
}

fn corrupted_backup_path(path: &Path) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    path.with_extension(format!("corrupt-{suffix}.json"))
}

fn tmp_state_path(path: &Path) -> PathBuf {
    path.with_extension("tmp")
}

fn replace_state_file(tmp_path: &Path, path: &Path) -> Result<()> {
    match fs::rename(tmp_path, path) {
        Ok(()) => Ok(()),
        Err(rename_err) => {
            #[cfg(windows)]
            {
                if path.exists() {
                    fs::remove_file(path).with_context(|| {
                        format!("failed to remove state file {}", path.display())
                    })?;
                    fs::rename(tmp_path, path).with_context(|| {
                        format!("failed to replace state file {}", path.display())
                    })?;
                    return Ok(());
                }
            }

            Err(rename_err)
                .with_context(|| format!("failed to replace state file {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{load_state, save_state, PersistedState};

    #[test]
    fn save_and_load_roundtrip() {
        let path = temp_state_file("roundtrip");
        let state = PersistedState {
            next_id: 42,
            processes: Vec::new(),
        };

        save_state(&path, &state).expect("failed to save test state");
        let loaded = load_state(&path).expect("failed to load test state");

        assert_eq!(loaded.next_id, 42);
        assert!(loaded.processes.is_empty());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn save_state_overwrites_existing_file() {
        let path = temp_state_file("overwrite");
        let first = PersistedState {
            next_id: 7,
            processes: Vec::new(),
        };
        let second = PersistedState {
            next_id: 9,
            processes: Vec::new(),
        };

        save_state(&path, &first).expect("failed to save first state");
        save_state(&path, &second).expect("failed to overwrite existing state");
        let loaded = load_state(&path).expect("failed to load overwritten state");

        assert_eq!(loaded.next_id, 9);
        assert!(loaded.processes.is_empty());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_state_recovers_from_corruption() {
        let path = temp_state_file("corrupt");
        fs::write(&path, "{ not valid json ]").expect("failed to write corrupted state file");

        let loaded = load_state(&path).expect("load_state should recover from corruption");
        assert_eq!(loaded.next_id, 1);
        assert!(loaded.processes.is_empty());
        assert!(!path.exists(), "corrupted file should have been renamed");

        let original_stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_string();

        let backup_found = path
            .parent()
            .expect("temp file has no parent")
            .read_dir()
            .expect("failed to read temp parent")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .any(|candidate| {
                candidate
                    .file_name()
                    .and_then(|value| value.to_str())
                    .map(|name| name.starts_with(&original_stem) && name.contains(".corrupt-"))
                    .unwrap_or(false)
            });

        assert!(backup_found, "expected renamed corrupt backup state file");

        // Best-effort cleanup.
        if let Some(parent) = path.parent() {
            if let Ok(entries) = parent.read_dir() {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.contains("corrupt-") {
                            let _ = fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }

    fn temp_state_file(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.state.json"))
    }
}
