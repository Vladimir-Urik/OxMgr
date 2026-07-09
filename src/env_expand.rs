//! Shell-style expansion of `~` and `$VAR`/`${VAR}` references used when
//! loading user-provided config (oxfile.toml, PM2 ecosystem files).
//!
//! - `~` or `~/...` at the start of a value is replaced with the user's home
//!   directory (from `$HOME` via the `dirs` crate). `~user` form is not
//!   supported.
//! - `$VAR` and `${VAR}` are replaced with the daemon's environment values.
//!   Missing variables cause an error so users notice typos instead of getting
//!   silent empty strings.
//! - `$$` is an escape that produces a literal `$`.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};

/// Expand `~` and `$VAR`/`${VAR}` references in `value`. Returns an error if a
/// referenced variable is not present in the daemon's environment.
pub fn expand(value: &str) -> Result<String> {
    let tilde_expanded = expand_tilde(value)?;
    expand_vars(&tilde_expanded, |name| std::env::var(name).ok())
}

/// Same as [`expand`] but returns a `PathBuf`.
pub fn expand_path(value: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(expand(value)?))
}

fn expand_tilde(value: &str) -> Result<String> {
    if value == "~" || value.starts_with("~/") {
        let home = dirs::home_dir().context("cannot expand `~`: home directory is unknown")?;
        let home_str = home
            .to_str()
            .ok_or_else(|| anyhow!("home directory path is not valid UTF-8"))?;
        if value == "~" {
            return Ok(home_str.to_string());
        }
        let mut out = String::with_capacity(home_str.len() + value.len() - 1);
        out.push_str(home_str);
        out.push_str(&value[1..]);
        return Ok(out);
    }
    Ok(value.to_string())
}

fn expand_vars<F>(value: &str, lookup: F) -> Result<String>
where
    F: Fn(&str) -> Option<String>,
{
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c != b'$' {
            out.push(c as char);
            i += 1;
            continue;
        }
        // c == '$'
        let next = bytes.get(i + 1).copied();
        match next {
            Some(b'$') => {
                out.push('$');
                i += 2;
            }
            Some(b'{') => {
                let end = value[i + 2..]
                    .find('}')
                    .ok_or_else(|| anyhow!("unterminated `${{` in value `{value}`"))?;
                let name = &value[i + 2..i + 2 + end];
                if name.is_empty() {
                    bail!("empty variable name in value `{value}`");
                }
                let resolved = lookup(name).ok_or_else(|| {
                    anyhow!("environment variable `{name}` is not set (referenced in `{value}`)")
                })?;
                out.push_str(&resolved);
                i += 2 + end + 1;
            }
            Some(b) if is_var_start(b) => {
                let mut j = i + 1;
                while j < bytes.len() && is_var_continue(bytes[j]) {
                    j += 1;
                }
                let name = &value[i + 1..j];
                let resolved = lookup(name).ok_or_else(|| {
                    anyhow!("environment variable `{name}` is not set (referenced in `{value}`)")
                })?;
                out.push_str(&resolved);
                i = j;
            }
            _ => {
                // Lone `$` followed by something that can't start an identifier
                // (digit, punctuation, end of string) — keep literal so values
                // like prices or shell quirks aren't mangled.
                out.push('$');
                i += 1;
            }
        }
    }
    Ok(out)
}

fn is_var_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_var_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup_fixed<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn expand_vars_replaces_braced_and_bare_names() {
        let lookup = lookup_fixed(&[("HOME", "/home/u"), ("X", "42")]);
        assert_eq!(
            expand_vars("${HOME}/bin:$X", &lookup).unwrap(),
            "/home/u/bin:42"
        );
    }

    #[test]
    fn expand_vars_double_dollar_escapes_to_literal() {
        let lookup = lookup_fixed(&[]);
        assert_eq!(expand_vars("price=$$10", &lookup).unwrap(), "price=$10");
    }

    #[test]
    fn expand_vars_errors_on_missing_variable() {
        let lookup = lookup_fixed(&[]);
        let err = expand_vars("$NOPE/x", &lookup).unwrap_err().to_string();
        assert!(
            err.contains("NOPE"),
            "error should name the variable: {err}"
        );
    }

    #[test]
    fn expand_vars_errors_on_unterminated_brace() {
        let lookup = lookup_fixed(&[("HOME", "/h")]);
        assert!(expand_vars("${HOME/x", &lookup).is_err());
    }

    #[test]
    fn expand_vars_leaves_lone_dollar_literal() {
        let lookup = lookup_fixed(&[]);
        assert_eq!(expand_vars("cost: $", &lookup).unwrap(), "cost: $");
        assert_eq!(expand_vars("amount $5", &lookup).unwrap(), "amount $5");
    }

    fn expected_home() -> String {
        dirs::home_dir()
            .expect("home directory")
            .to_str()
            .expect("utf-8 home directory")
            .to_string()
    }

    #[test]
    fn expand_tilde_replaces_leading_tilde_only() {
        let home = expected_home();
        assert_eq!(expand_tilde("~").unwrap(), home);
        assert_eq!(expand_tilde("~/folder").unwrap(), format!("{home}/folder"));
        // Tilde in the middle stays literal.
        assert_eq!(expand_tilde("/foo/~bar").unwrap(), "/foo/~bar");
        // `~user` form is not expanded.
        assert_eq!(expand_tilde("~user/x").unwrap(), "~user/x");
    }

    #[test]
    fn expand_combines_tilde_and_vars() {
        // SAFETY: set_var is unsafe in newer Rust because it mutates global env
        // state. Tests in this module are single-threaded with respect to
        // these specific keys.
        unsafe {
            std::env::set_var("SUB", "data");
        }
        let home = expected_home();
        assert_eq!(
            expand("~/${SUB}/cache").unwrap(),
            format!("{home}/data/cache")
        );
    }
}
