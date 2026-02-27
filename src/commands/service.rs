use std::env;
use std::fs;
use std::path::Path;
use std::process::Command as StdCommand;

use anyhow::{Context, Result};

use crate::cli::{InitSystem, ServiceCommand};
use crate::config::AppConfig;

pub(crate) fn run(command: ServiceCommand, system: InitSystem, config: &AppConfig) -> Result<()> {
    let executable = std::env::current_exe().context("failed to resolve current executable")?;
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

    match (resolved, command) {
        (InitSystem::Systemd, ServiceCommand::Install) => install_systemd_service(&executable),
        (InitSystem::Systemd, ServiceCommand::Uninstall) => uninstall_systemd_service(),
        (InitSystem::Systemd, ServiceCommand::Status) => status_systemd_service(),

        (InitSystem::Launchd, ServiceCommand::Install) => {
            install_launchd_service(&executable, config)
        }
        (InitSystem::Launchd, ServiceCommand::Uninstall) => uninstall_launchd_service(),
        (InitSystem::Launchd, ServiceCommand::Status) => status_launchd_service(),

        (InitSystem::TaskScheduler, ServiceCommand::Install) => {
            install_windows_task_service(&executable)
        }
        (InitSystem::TaskScheduler, ServiceCommand::Uninstall) => uninstall_windows_task_service(),
        (InitSystem::TaskScheduler, ServiceCommand::Status) => status_windows_task_service(),
        (InitSystem::Auto, _) => unreachable!("auto should have been resolved"),
    }
}

fn install_systemd_service(executable: &Path) -> Result<()> {
    let home = dirs::home_dir().context("failed to determine home directory")?;
    let service_path = home.join(".config/systemd/user/oxmgr.service");
    let service_content = render_systemd_service(executable);

    if let Some(parent) = service_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&service_path, service_content)
        .with_context(|| format!("failed to write {}", service_path.display()))?;

    run_os_command("systemctl", &["--user", "daemon-reload"])?;
    run_os_command("systemctl", &["--user", "enable", "--now", "oxmgr.service"])?;

    if let Ok(user) = env::var("USER") {
        let _ = run_os_command_allow_failure("loginctl", &["enable-linger", &user]);
    }

    println!(
        "Installed systemd user service at {}",
        service_path.display()
    );
    Ok(())
}

fn uninstall_systemd_service() -> Result<()> {
    let home = dirs::home_dir().context("failed to determine home directory")?;
    let service_path = home.join(".config/systemd/user/oxmgr.service");

    let _ = run_os_command_allow_failure(
        "systemctl",
        &["--user", "disable", "--now", "oxmgr.service"],
    );
    if service_path.exists() {
        fs::remove_file(&service_path)
            .with_context(|| format!("failed to remove {}", service_path.display()))?;
    }
    let _ = run_os_command_allow_failure("systemctl", &["--user", "daemon-reload"]);

    println!("Uninstalled systemd user service.");
    Ok(())
}

fn status_systemd_service() -> Result<()> {
    let output = StdCommand::new("systemctl")
        .args(["--user", "status", "oxmgr.service", "--no-pager"])
        .output()
        .context("failed to run systemctl")?;

    if output.status.success() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("systemd service not active: {}", stderr.trim());
    }
}

fn install_launchd_service(executable: &Path, config: &AppConfig) -> Result<()> {
    let home = dirs::home_dir().context("failed to determine home directory")?;
    let plist_path = home.join("Library/LaunchAgents/io.oxmgr.daemon.plist");
    let uid = current_uid_string();
    let domain = format!("gui/{uid}");
    let service_id = format!("{domain}/io.oxmgr.daemon");

    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let plist = render_launchd_plist(executable, config);
    fs::write(&plist_path, plist)
        .with_context(|| format!("failed to write {}", plist_path.display()))?;

    let _ = run_os_command_allow_failure("launchctl", &["bootout", &service_id]);
    run_os_command(
        "launchctl",
        &["bootstrap", &domain, plist_path.to_string_lossy().as_ref()],
    )?;
    let _ = run_os_command_allow_failure("launchctl", &["enable", &service_id]);
    run_os_command("launchctl", &["kickstart", "-k", &service_id])?;

    println!("Installed launchd service at {}", plist_path.display());
    Ok(())
}

fn uninstall_launchd_service() -> Result<()> {
    let home = dirs::home_dir().context("failed to determine home directory")?;
    let plist_path = home.join("Library/LaunchAgents/io.oxmgr.daemon.plist");
    let uid = current_uid_string();
    let domain = format!("gui/{uid}");
    let service_id = format!("{domain}/io.oxmgr.daemon");

    let _ = run_os_command_allow_failure("launchctl", &["bootout", &service_id]);
    let _ = run_os_command_allow_failure("launchctl", &["disable", &service_id]);
    if plist_path.exists() {
        fs::remove_file(&plist_path)
            .with_context(|| format!("failed to remove {}", plist_path.display()))?;
    }

    println!("Uninstalled launchd service.");
    Ok(())
}

fn status_launchd_service() -> Result<()> {
    let uid = current_uid_string();
    let service_id = format!("gui/{uid}/io.oxmgr.daemon");

    let output = StdCommand::new("launchctl")
        .args(["print", &service_id])
        .output()
        .context("failed to run launchctl")?;
    if output.status.success() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("launchd service not active: {}", stderr.trim());
    }
}

fn install_windows_task_service(executable: &Path) -> Result<()> {
    let task = "OxmgrDaemon";
    let command = format!("\\\"{}\\\" daemon run", executable.display());
    let output = StdCommand::new("schtasks")
        .args([
            "/Create", "/F", "/SC", "ONLOGON", "/TN", task, "/TR", &command,
        ])
        .output()
        .context("failed to run schtasks create")?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to install task: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let _ = run_os_command_allow_failure("schtasks", &["/Run", "/TN", task]);
    println!("Installed Windows Task Scheduler service '{}'.", task);
    Ok(())
}

fn uninstall_windows_task_service() -> Result<()> {
    let task = "OxmgrDaemon";
    let output = StdCommand::new("schtasks")
        .args(["/Delete", "/F", "/TN", task])
        .output()
        .context("failed to run schtasks delete")?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to uninstall task: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    println!("Uninstalled Windows Task Scheduler service '{}'.", task);
    Ok(())
}

fn status_windows_task_service() -> Result<()> {
    let task = "OxmgrDaemon";
    let output = StdCommand::new("schtasks")
        .args(["/Query", "/TN", task, "/FO", "LIST", "/V"])
        .output()
        .context("failed to run schtasks query")?;
    if output.status.success() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
        Ok(())
    } else {
        anyhow::bail!(
            "task '{}' not found or inactive: {}",
            task,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
}

fn render_systemd_service(executable: &Path) -> String {
    let escaped_exec = escape_systemd_exec_arg(executable);
    format!(
        "[Unit]\nDescription=Oxmgr daemon\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={} daemon run\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n",
        escaped_exec
    )
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

fn render_launchd_plist(executable: &Path, config: &AppConfig) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>io.oxmgr.daemon</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>{}</string>\n    <string>daemon</string>\n    <string>run</string>\n  </array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n  <key>StandardOutPath</key><string>{}</string>\n  <key>StandardErrorPath</key><string>{}</string>\n</dict>\n</plist>\n",
        to_launchd_path(executable),
        to_launchd_path(&config.base_dir.join("daemon.out.log")),
        to_launchd_path(&config.base_dir.join("daemon.err.log"))
    )
}

fn run_os_command(program: &str, args: &[&str]) -> Result<()> {
    let output = StdCommand::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run '{}'", program))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{} failed: {}", program, stderr.trim());
    }
}

fn run_os_command_allow_failure(program: &str, args: &[&str]) -> Result<()> {
    let output = StdCommand::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run '{}'", program))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("warning: command '{}' failed: {}", program, stderr.trim());
    }
    Ok(())
}

#[cfg(unix)]
fn current_uid_string() -> String {
    nix::unistd::Uid::effective().as_raw().to_string()
}

#[cfg(not(unix))]
fn current_uid_string() -> String {
    "0".to_string()
}

#[cfg(test)]
mod tests {
    use super::{render_launchd_plist, render_systemd_service};
    use crate::config::AppConfig;
    use crate::logging::LogRotationPolicy;
    use std::path::Path;

    #[test]
    fn render_systemd_service_contains_execstart() {
        let service = render_systemd_service(Path::new("/usr/local/bin/oxmgr"));
        assert!(service.contains("ExecStart=/usr/local/bin/oxmgr daemon run"));
        assert!(service.contains("[Service]"));
    }

    #[test]
    fn render_systemd_service_escapes_spaces_in_execstart() {
        let service = render_systemd_service(Path::new("/opt/ox mgr/bin/oxmgr"));
        assert!(service.contains("ExecStart=/opt/ox\\ mgr/bin/oxmgr daemon run"));
    }

    #[test]
    fn render_launchd_plist_contains_expected_paths() {
        let cfg = AppConfig {
            base_dir: Path::new("/tmp/oxmgr").to_path_buf(),
            daemon_addr: "127.0.0.1:50000".to_string(),
            api_addr: "127.0.0.1:51000".to_string(),
            state_path: Path::new("/tmp/oxmgr/state.json").to_path_buf(),
            log_dir: Path::new("/tmp/oxmgr/logs").to_path_buf(),
            log_rotation: LogRotationPolicy {
                max_size_bytes: 1024,
                max_files: 3,
                max_age_days: 7,
            },
        };

        let plist = render_launchd_plist(Path::new("/usr/local/bin/oxmgr"), &cfg);
        assert!(plist.contains("io.oxmgr.daemon"));
        assert!(plist.contains("/tmp/oxmgr/daemon.out.log"));
        assert!(plist.contains("/tmp/oxmgr/daemon.err.log"));
    }

    #[test]
    fn render_launchd_plist_normalizes_backslashes() {
        let cfg = AppConfig {
            base_dir: Path::new(r"C:\tmp\oxmgr").to_path_buf(),
            daemon_addr: "127.0.0.1:50000".to_string(),
            api_addr: "127.0.0.1:51000".to_string(),
            state_path: Path::new(r"C:\tmp\oxmgr\state.json").to_path_buf(),
            log_dir: Path::new(r"C:\tmp\oxmgr\logs").to_path_buf(),
            log_rotation: LogRotationPolicy {
                max_size_bytes: 1024,
                max_files: 3,
                max_age_days: 7,
            },
        };

        let plist = render_launchd_plist(Path::new(r"C:\usr\local\bin\oxmgr"), &cfg);
        assert!(plist.contains("C:/usr/local/bin/oxmgr"));
        assert!(plist.contains("C:/tmp/oxmgr/daemon.out.log"));
        assert!(plist.contains("C:/tmp/oxmgr/daemon.err.log"));
    }
}
