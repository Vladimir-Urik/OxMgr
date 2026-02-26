use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLogs {
    pub stdout: PathBuf,
    pub stderr: PathBuf,
}

pub fn process_logs(log_dir: &Path, name: &str) -> ProcessLogs {
    ProcessLogs {
        stdout: log_dir.join(format!("{name}.out.log")),
        stderr: log_dir.join(format!("{name}.err.log")),
    }
}

pub fn open_log_writers(logs: &ProcessLogs) -> Result<(File, File)> {
    if let Some(parent) = logs.stdout.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&logs.stdout)
        .with_context(|| format!("failed opening {}", logs.stdout.display()))?;

    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&logs.stderr)
        .with_context(|| format!("failed opening {}", logs.stderr.display()))?;

    Ok((stdout, stderr))
}

pub fn read_last_lines(path: &Path, max_lines: usize) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(path).with_context(|| format!("failed opening {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut ring = VecDeque::with_capacity(max_lines.saturating_add(1));
    for line in reader.lines() {
        let line = line.with_context(|| format!("failed reading {}", path.display()))?;
        ring.push_back(line);
        if ring.len() > max_lines {
            ring.pop_front();
        }
    }

    Ok(ring.into_iter().collect())
}
