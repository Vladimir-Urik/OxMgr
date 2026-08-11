//! Web dashboard UI served via a local HTTP server.
//!
//! This module provides `oxmgr ui web` functionality - a browser-based dashboard
//! that connects to the daemon's API for real-time process monitoring.

use anyhow::{Context, Result};

use crate::config::AppConfig;

/// Runs the web dashboard by opening the daemon's built-in web UI in the browser.
///
/// The daemon already serves the dashboard at its API address. This command
/// simply opens the browser to that address, optionally on a custom port.
pub(crate) async fn run(config: &AppConfig, _bind: &str, _port: u16, no_open: bool) -> Result<()> {
    let url = format!("http://{}", config.api_addr);

    println!("Dashboard available at: {url}");
    println!("Press Ctrl+C to stop.");

    if !no_open {
        open_browser(&url)?;
    }

    // Keep running until interrupted
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;

    println!("\nShutting down...");
    Ok(())
}

/// Opens the given URL in the system's default browser.
fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .context("failed to open browser")?;
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .context("failed to open browser")?;
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/c", "start", url])
            .spawn()
            .context("failed to open browser")?;
    }

    Ok(())
}
