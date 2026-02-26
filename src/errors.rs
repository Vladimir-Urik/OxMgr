use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OxmgrError {
    #[error("process not found: {0}")]
    ProcessNotFound(String),
    #[error("duplicate process name: {0}")]
    DuplicateProcessName(String),
    #[error("invalid process name: {0}")]
    InvalidProcessName(String),
    #[error("invalid command: {0}")]
    InvalidCommand(String),
    #[error("daemon is already running")]
    DaemonAlreadyRunning,
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
