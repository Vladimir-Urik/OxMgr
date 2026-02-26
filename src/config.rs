use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub base_dir: PathBuf,
    pub daemon_addr: String,
    pub state_path: PathBuf,
    pub log_dir: PathBuf,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let base_dir = dirs::data_local_dir()
            .unwrap_or_else(env::temp_dir)
            .join("oxmgr");
        let daemon_addr = format!("127.0.0.1:{}", daemon_port());
        let state_path = base_dir.join("state.json");
        let log_dir = base_dir.join("logs");

        let config = Self {
            base_dir,
            daemon_addr,
            state_path,
            log_dir,
        };
        config.ensure_layout()?;
        Ok(config)
    }

    pub fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(&self.base_dir)
            .with_context(|| format!("failed to create {}", self.base_dir.display()))?;
        fs::create_dir_all(&self.log_dir)
            .with_context(|| format!("failed to create {}", self.log_dir.display()))?;
        Ok(())
    }
}

fn daemon_port() -> u16 {
    let identity = current_identity();
    let mut hash = 2166136261_u32;
    for byte in identity.as_bytes() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(16777619);
    }

    // Keep daemon ports in a high, non-privileged range.
    let range = 20000_u16;
    40000 + (hash % range as u32) as u16
}

fn current_identity() -> String {
    #[cfg(unix)]
    {
        format!("uid-{}", nix::unistd::Uid::effective().as_raw())
    }

    #[cfg(windows)]
    {
        let username = env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string());
        format!("win-{username}")
    }

    #[cfg(not(any(unix, windows)))]
    {
        "oxmgr-generic".to_string()
    }
}
