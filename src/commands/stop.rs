use anyhow::Result;

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};

use super::common::{config_target_display, expect_ok, maybe_load_named_targets_from_config};

pub(crate) async fn run(config: &AppConfig, target: String) -> Result<()> {
    if target != "all" {
        if let Some(targets) = maybe_load_named_targets_from_config(&target)? {
            let mut stopped = 0_usize;
            let mut failures = Vec::new();

            for name in targets {
                let response = send_request(
                    &config.daemon_addr,
                    &IpcRequest::Stop {
                        target: name.clone(),
                    },
                )
                .await?;
                if response.ok {
                    stopped = stopped.saturating_add(1);
                } else {
                    failures.push(format!("stop {}: {}", name, response.message));
                }
            }

            println!(
                "Stopped {} process(es) from {}",
                stopped,
                config_target_display(&target)
            );
            if !failures.is_empty() {
                for failure in failures {
                    eprintln!("- {}", failure);
                }
                anyhow::bail!("stop finished with failures");
            }
            return Ok(());
        }
    }

    let response = send_request(&config.daemon_addr, &IpcRequest::Stop { target }).await?;
    let response = expect_ok(response)?;
    println!("{}", response.message);

    Ok(())
}
