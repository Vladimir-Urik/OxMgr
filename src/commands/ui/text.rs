use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn visible_len(value: &str) -> usize {
    let mut len = 0usize;
    let mut iter = value.chars().peekable();
    while let Some(ch) = iter.next() {
        if ch == '\x1b' {
            if iter.peek() == Some(&'[') {
                let _ = iter.next();
                for next in iter.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        len += 1;
    }
    len
}

pub(super) fn truncate_visible_ansi(value: &str, max_visible: usize) -> String {
    if max_visible == 0 {
        return String::new();
    }

    let mut out = String::new();
    let mut visible = 0usize;
    let mut saw_ansi = false;
    let mut iter = value.chars().peekable();

    while let Some(ch) = iter.next() {
        if ch == '\x1b' {
            saw_ansi = true;
            out.push(ch);
            if iter.peek() == Some(&'[') {
                out.push(iter.next().unwrap_or('['));
                for next in iter.by_ref() {
                    out.push(next);
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }

        if visible >= max_visible {
            break;
        }

        out.push(ch);
        visible += 1;
        if visible >= max_visible {
            break;
        }
    }

    if saw_ansi {
        out.push_str("\x1b[0m");
    }

    out
}

pub(super) fn truncate(value: &str, max_len: usize) -> String {
    let value_len = value.chars().count();
    if value_len <= max_len {
        return value.to_string();
    }
    if max_len <= 1 {
        return "…".to_string();
    }
    let mut output = String::new();
    for ch in value.chars().take(max_len - 1) {
        output.push(ch);
    }
    output.push('…');
    output
}

pub(super) fn pad(value: &str, width: usize) -> String {
    let current = value.chars().count();
    if current >= width {
        value.to_string()
    } else {
        format!("{value}{}", " ".repeat(width - current))
    }
}

pub(super) fn style_status(padded: &str, raw: &str) -> String {
    match raw {
        "running" => paint("1;32", padded),
        "restarting" => paint("1;33", padded),
        "stopped" => paint("2;37", padded),
        "crashed" | "errored" => paint("1;31", padded),
        _ => padded.to_string(),
    }
}

pub(super) fn style_health(padded: &str, raw: &str) -> String {
    match raw {
        "healthy" => paint("1;32", padded),
        "unknown" => paint("1;33", padded),
        "unhealthy" => paint("1;31", padded),
        _ => padded.to_string(),
    }
}

pub(super) fn paint(code: &str, value: &str) -> String {
    format!("\x1b[{code}m{value}\x1b[0m")
}

pub(super) fn wall_clock_hms() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

#[cfg(test)]
mod tests {
    use super::{truncate, truncate_visible_ansi, visible_len};

    #[test]
    fn truncate_adds_ellipsis_when_needed() {
        let value = truncate("abcdefgh", 5);
        assert_eq!(value, "abcd…");
    }

    #[test]
    fn visible_len_ignores_ansi_sequences() {
        let value = "\x1b[1;32mhello\x1b[0m";
        assert_eq!(visible_len(value), 5);
    }

    #[test]
    fn truncate_visible_ansi_keeps_reset_code() {
        let input = "\x1b[1;31mabcdef\x1b[0m";
        let output = truncate_visible_ansi(input, 3);
        assert_eq!(visible_len(&output), 3);
        assert!(output.ends_with("\x1b[0m"));
    }
}
