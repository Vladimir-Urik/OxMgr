//! `oxmgr ui web`: points the browser at the dashboard served by the daemon.

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::config::AppConfig;
use crate::daemon::ensure_daemon_running;

/// Checks that the daemon serves the dashboard, then prints its URL and opens
/// it in the default browser unless `no_open` is set.
pub(crate) async fn run(config: &AppConfig, no_open: bool) -> Result<()> {
    ensure_daemon_running(config).await?;

    let addr = browsable_addr(&config.api_addr);
    let url = format!("http://{addr}/");
    match probe_dashboard(&addr).await {
        Ok(200 | 401) => {}
        Ok(403) => anyhow::bail!(
            "the dashboard at {url} refused the request; when OXMGR_API_ADDR is not a loopback \
             address it needs OXMGR_DASHBOARD_USER and OXMGR_DASHBOARD_PASS"
        ),
        Ok(404) => anyhow::bail!(
            "the web dashboard is disabled; restart the daemon with OXMGR_DASHBOARD=1 \
             (and OXMGR_DASHBOARD_USER / OXMGR_DASHBOARD_PASS if it is reachable from other hosts)"
        ),
        Ok(status) => anyhow::bail!("dashboard at {url} answered with HTTP {status}"),
        Err(err) => {
            return Err(err.context(format!("dashboard at {url} is not reachable")));
        }
    }

    println!("Dashboard: {url}");
    if !no_open {
        open_browser(&url)?;
    }
    Ok(())
}

/// A wildcard bind (`0.0.0.0`, `[::]`) is reachable through loopback, and the
/// dashboard only accepts loopback `Host` names when it has no credentials.
fn browsable_addr(api_addr: &str) -> String {
    match api_addr.parse::<std::net::SocketAddr>() {
        Ok(addr) if addr.ip().is_unspecified() => format!("127.0.0.1:{}", addr.port()),
        _ => api_addr.to_string(),
    }
}

/// Requests `/` and returns the HTTP status code.
async fn probe_dashboard(api_addr: &str) -> Result<u16> {
    let exchange = async {
        let mut stream = TcpStream::connect(api_addr).await?;
        let request = format!("GET / HTTP/1.1\r\nHost: {api_addr}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        let mut head = [0_u8; 32];
        let read = stream.read(&mut head).await?;
        Ok::<_, std::io::Error>(String::from_utf8_lossy(&head[..read]).into_owned())
    };
    let head = timeout(Duration::from_secs(3), exchange)
        .await
        .context("timed out")??;
    head.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .context("malformed HTTP response")
}

/// Opens the given URL in the system's default browser.
fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = std::process::Command::new("explorer");
        command.arg(url);
        command
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut command = std::process::Command::new("xdg-open");

    #[cfg(not(target_os = "windows"))]
    command.arg(url);
    command.spawn().context("failed to open browser")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::browsable_addr;

    #[test]
    fn wildcard_binds_are_opened_through_loopback() {
        assert_eq!(browsable_addr("0.0.0.0:46001"), "127.0.0.1:46001");
        assert_eq!(browsable_addr("[::]:46001"), "127.0.0.1:46001");
        assert_eq!(browsable_addr("10.0.0.5:46001"), "10.0.0.5:46001");
        assert_eq!(browsable_addr("localhost:46001"), "localhost:46001");
    }
}
