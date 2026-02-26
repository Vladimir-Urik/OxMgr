use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::cli::InitSystem;
use crate::config::AppConfig;

pub(crate) fn run(system: InitSystem, config: &AppConfig) -> Result<()> {
    let executable = std::env::current_exe().context("failed to resolve current executable")?;
    let user = std::env::var("USER").unwrap_or_else(|_| "<user>".to_string());

    let resolved = match system {
        InitSystem::Auto => {
            if cfg!(target_os = "macos") {
                InitSystem::Launchd
            } else if cfg!(target_os = "windows") {
                InitSystem::TaskScheduler
            } else {
                InitSystem::Systemd
            }
        }
        other => other,
    };

    match resolved {
        InitSystem::Systemd => {
            println!("Create ~/.config/systemd/user/oxmgr.service with:");
            println!();
            println!("[Unit]");
            println!("Description=Oxmgr daemon");
            println!("After=network.target");
            println!();
            println!("[Service]");
            println!("Type=simple");
            println!(
                "ExecStart={} daemon run",
                escape_systemd_exec_arg(&executable)
            );
            println!("Restart=always");
            println!("RestartSec=2");
            println!();
            println!("[Install]");
            println!("WantedBy=default.target");
            println!();
            println!("Then run:");
            println!("systemctl --user daemon-reload");
            println!("systemctl --user enable --now oxmgr.service");
            println!("loginctl enable-linger {}", user);
        }
        InitSystem::Launchd => {
            let plist = dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("~"))
                .join("Library/LaunchAgents/io.oxmgr.daemon.plist");
            println!("Create {} with:", plist.display());
            println!();
            println!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            println!("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">");
            println!("<plist version=\"1.0\">");
            println!("<dict>");
            println!("  <key>Label</key><string>io.oxmgr.daemon</string>");
            println!("  <key>ProgramArguments</key>");
            println!("  <array>");
            println!("    <string>{}</string>", to_launchd_path(&executable));
            println!("    <string>daemon</string>");
            println!("    <string>run</string>");
            println!("  </array>");
            println!("  <key>RunAtLoad</key><true/>");
            println!("  <key>KeepAlive</key><true/>");
            println!(
                "  <key>StandardOutPath</key><string>{}</string>",
                to_launchd_path(&config.base_dir.join("daemon.out.log"))
            );
            println!(
                "  <key>StandardErrorPath</key><string>{}</string>",
                to_launchd_path(&config.base_dir.join("daemon.err.log"))
            );
            println!("</dict>");
            println!("</plist>");
            println!();
            println!("Then run:");
            println!("launchctl bootstrap gui/$(id -u) {}", plist.display());
            println!("launchctl enable gui/$(id -u)/io.oxmgr.daemon");
            println!("launchctl kickstart -k gui/$(id -u)/io.oxmgr.daemon");
        }
        InitSystem::TaskScheduler => {
            let task_name = "OxmgrDaemon";
            println!("Create a scheduled task (at user logon) with:");
            println!();
            println!(
                "schtasks /Create /F /SC ONLOGON /TN {} /TR \"\\\"{}\\\" daemon run\"",
                task_name,
                executable.display()
            );
            println!();
            println!("Start it immediately:");
            println!("schtasks /Run /TN {}", task_name);
            println!();
            println!("Delete it later if needed:");
            println!("schtasks /Delete /F /TN {}", task_name);
        }
        InitSystem::Auto => unreachable!("auto should have been resolved"),
    }

    Ok(())
}

fn escape_systemd_exec_arg(path: &Path) -> String {
    let mut escaped = String::new();
    for ch in path.display().to_string().chars() {
        if matches!(ch, '\\' | ' ' | '\t' | '\n' | '"' | '\'') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn to_launchd_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
