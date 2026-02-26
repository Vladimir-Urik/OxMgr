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

#[cfg(test)]
mod tests {
    use std::io;

    use super::OxmgrError;

    #[test]
    fn domain_error_messages_are_human_readable() {
        let not_found = OxmgrError::ProcessNotFound("api".to_string());
        assert_eq!(not_found.to_string(), "process not found: api");

        let duplicate = OxmgrError::DuplicateProcessName("worker".to_string());
        assert_eq!(duplicate.to_string(), "duplicate process name: worker");

        let daemon_running = OxmgrError::DaemonAlreadyRunning;
        assert_eq!(daemon_running.to_string(), "daemon is already running");
    }

    #[test]
    fn io_error_is_wrapped_with_context() {
        let source = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let err: OxmgrError = source.into();
        assert!(
            err.to_string().contains("io error: denied"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn serde_error_is_wrapped_with_context() {
        let source = serde_json::from_str::<serde_json::Value>("{")
            .expect_err("expected invalid JSON parser error");
        let err: OxmgrError = source.into();
        assert!(
            err.to_string().contains("serialization error:"),
            "unexpected error message: {err}"
        );
    }
}
