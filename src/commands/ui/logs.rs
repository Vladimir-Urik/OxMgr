use std::path::Path;

use crate::logging::log_modified_at;

use super::LogSource;

pub(super) fn default_log_source(stdout_lines: &[String], _stderr_lines: &[String]) -> LogSource {
    if !stdout_lines.is_empty() {
        LogSource::Stdout
    } else {
        LogSource::Stderr
    }
}

pub(super) fn preferred_log_source(
    stdout_path: &Path,
    stderr_path: &Path,
    stdout_lines: &[String],
    stderr_lines: &[String],
) -> LogSource {
    match (stdout_lines.is_empty(), stderr_lines.is_empty()) {
        (false, true) => LogSource::Stdout,
        (true, false) => LogSource::Stderr,
        (true, true) => LogSource::Stderr,
        (false, false) => {
            if log_modified_at(stdout_path) > log_modified_at(stderr_path) {
                LogSource::Stdout
            } else {
                LogSource::Stderr
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::thread::sleep;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{default_log_source, preferred_log_source};
    use crate::commands::ui::LogSource;
    use crate::logging::log_modified_at;

    #[test]
    fn preferred_log_source_uses_newer_nonempty_stream() {
        let tmp = temp_dir("preferred-log-source");
        let stdout = tmp.join("stdout.log");
        let stderr = tmp.join("stderr.log");

        std::fs::write(&stderr, "older\n").expect("failed to seed stderr");
        let older_mtime = log_modified_at(&stderr);
        write_until_newer(&stdout, "newer\n", older_mtime);

        let source = preferred_log_source(
            &stdout,
            &stderr,
            &["newer".to_string()],
            &["older".to_string()],
        );

        assert_eq!(source, LogSource::Stdout);

        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn default_log_source_prefers_stdout_when_available() {
        let source = default_log_source(&["out".to_string()], &["err".to_string()]);
        assert_eq!(source, LogSource::Stdout);

        let source = default_log_source(&[], &["err".to_string()]);
        assert_eq!(source, LogSource::Stderr);
    }

    fn temp_dir(prefix: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock failure")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("oxmgr-ui-test-{prefix}-{nonce}"));
        fs::create_dir_all(&dir).expect("failed to create temp dir");
        dir
    }

    fn write_until_newer(path: &Path, contents: &str, older_than: SystemTime) {
        for _ in 0..10 {
            fs::write(path, contents).expect("failed to write ui test log");
            if log_modified_at(path) > older_than {
                return;
            }
            sleep(Duration::from_millis(20));
        }
        panic!("failed to produce a newer mtime for {}", path.display());
    }
}
