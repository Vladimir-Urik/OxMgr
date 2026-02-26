use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::logging::LogRotationPolicy;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub base_dir: PathBuf,
    pub daemon_addr: String,
    pub state_path: PathBuf,
    pub log_dir: PathBuf,
    pub log_rotation: LogRotationPolicy,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let base_dir = env::var("OXMGR_HOME")
            .map(PathBuf::from)
            .ok()
            .unwrap_or_else(|| {
                dirs::data_local_dir()
                    .unwrap_or_else(env::temp_dir)
                    .join("oxmgr")
            });
        let daemon_addr = env::var("OXMGR_DAEMON_ADDR")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("127.0.0.1:{}", daemon_port()));
        let state_path = base_dir.join("state.json");
        let log_dir = base_dir.join("logs");
        let log_rotation = LogRotationPolicy {
            max_size_bytes: env_u64("OXMGR_LOG_MAX_SIZE_MB", 20)
                .max(1)
                .saturating_mul(1024 * 1024),
            max_files: env_u64("OXMGR_LOG_MAX_FILES", 5).max(1) as u32,
            max_age_days: env_u64("OXMGR_LOG_MAX_DAYS", 14).max(1),
        };

        let config = Self {
            base_dir,
            daemon_addr,
            state_path,
            log_dir,
            log_rotation,
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

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{daemon_port, env_u64, AppConfig};

    #[test]
    fn daemon_port_is_stable_and_in_expected_range() {
        let first = daemon_port();
        let second = daemon_port();
        assert_eq!(first, second, "daemon port should be deterministic");
        assert!(
            (40000..60000).contains(&first),
            "daemon port should stay in non-privileged range, got {first}"
        );
    }

    #[test]
    fn env_u64_uses_default_for_invalid_values() {
        let _guard = env_lock().lock().expect("failed to acquire env lock");
        let old = std::env::var("OXMGR_TEST_ENV_U64").ok();
        std::env::set_var("OXMGR_TEST_ENV_U64", "not-a-number");

        let parsed = env_u64("OXMGR_TEST_ENV_U64", 42);
        assert_eq!(parsed, 42);

        restore_env("OXMGR_TEST_ENV_U64", old);
    }

    #[test]
    fn app_config_load_uses_env_and_creates_layout() {
        let _guard = env_lock().lock().expect("failed to acquire env lock");
        let base = temp_dir("config-load");

        let old_home = std::env::var("OXMGR_HOME").ok();
        let old_addr = std::env::var("OXMGR_DAEMON_ADDR").ok();
        let old_size = std::env::var("OXMGR_LOG_MAX_SIZE_MB").ok();
        let old_files = std::env::var("OXMGR_LOG_MAX_FILES").ok();
        let old_days = std::env::var("OXMGR_LOG_MAX_DAYS").ok();

        std::env::set_var("OXMGR_HOME", &base);
        std::env::set_var("OXMGR_DAEMON_ADDR", " ");
        std::env::set_var("OXMGR_LOG_MAX_SIZE_MB", "0");
        std::env::set_var("OXMGR_LOG_MAX_FILES", "0");
        std::env::set_var("OXMGR_LOG_MAX_DAYS", "0");

        let config = AppConfig::load().expect("expected config load to succeed");
        assert_eq!(config.base_dir, base);
        assert_eq!(config.state_path, base.join("state.json"));
        assert_eq!(config.log_dir, base.join("logs"));
        assert_eq!(config.log_rotation.max_size_bytes, 1024 * 1024);
        assert_eq!(config.log_rotation.max_files, 1);
        assert_eq!(config.log_rotation.max_age_days, 1);
        assert!(
            config.daemon_addr.starts_with("127.0.0.1:"),
            "expected default daemon address, got {}",
            config.daemon_addr
        );
        assert!(config.base_dir.exists(), "base directory should be created");
        assert!(config.log_dir.exists(), "log directory should be created");

        let _ = fs::remove_dir_all(&base);
        restore_env("OXMGR_HOME", old_home);
        restore_env("OXMGR_DAEMON_ADDR", old_addr);
        restore_env("OXMGR_LOG_MAX_SIZE_MB", old_size);
        restore_env("OXMGR_LOG_MAX_FILES", old_files);
        restore_env("OXMGR_LOG_MAX_DAYS", old_days);
    }

    #[test]
    fn ensure_layout_creates_missing_directories() {
        let base = temp_dir("config-layout");
        let log_dir = base.join("custom-logs");
        let cfg = AppConfig {
            base_dir: base.clone(),
            daemon_addr: "127.0.0.1:50000".to_string(),
            state_path: base.join("state.json"),
            log_dir: log_dir.clone(),
            log_rotation: crate::logging::LogRotationPolicy {
                max_size_bytes: 1024,
                max_files: 3,
                max_age_days: 7,
            },
        };

        cfg.ensure_layout()
            .expect("expected ensure_layout to create directories");
        assert!(base.exists(), "base directory should exist");
        assert!(log_dir.exists(), "log directory should exist");

        let _ = fs::remove_dir_all(base);
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn restore_env(key: &str, previous: Option<String>) {
        if let Some(value) = previous {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        std::env::temp_dir().join(format!("oxmgr-{prefix}-{nonce}"))
    }
}
