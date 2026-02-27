use anyhow::Result;

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::process::ManagedProcess;
use crate::ui;

use super::common::expect_ok;

pub(crate) async fn run(config: &AppConfig) -> Result<()> {
    let response = send_request(&config.daemon_addr, &IpcRequest::List).await?;
    let response = expect_ok(response)?;
    print_process_table(response.processes);

    Ok(())
}

fn print_process_table(mut processes: Vec<ManagedProcess>) {
    processes.sort_by_key(|process| process.id);

    if processes.is_empty() {
        println!("No managed processes.");
        return;
    }

    let headers = [
        "ID", "NAME", "STATUS", "MODE", "PID", "UPTIME", "RESTARTS", "CPU%", "RAM(MB)", "HEALTH",
    ];

    let rows: Vec<[String; 10]> = processes
        .into_iter()
        .map(|process| {
            [
                process.id.to_string(),
                process.name,
                process.status.to_string(),
                if process.cluster_mode {
                    process
                        .cluster_instances
                        .map(|instances| format!("cluster:{instances}"))
                        .unwrap_or_else(|| "cluster:auto".to_string())
                } else {
                    "single".to_string()
                },
                process
                    .pid
                    .map_or_else(|| "-".to_string(), |value| value.to_string()),
                ui::format_process_uptime(&process.status, process.last_started_at),
                process.restart_count.to_string(),
                format!("{:.1}", process.cpu_percent),
                (process.memory_bytes / (1024 * 1024)).to_string(),
                process.health_status.to_string(),
            ]
        })
        .collect();

    let mut widths = headers.map(str::len);
    for row in &rows {
        for (idx, cell) in row.iter().enumerate() {
            widths[idx] = widths[idx].max(cell.len());
        }
    }

    print_border(&widths);
    print_header_row(&headers, &widths);
    print_border(&widths);
    for row in rows {
        print_data_row(&row, &widths);
    }
    print_border(&widths);
}

fn print_border(widths: &[usize; 10]) {
    let mut line = String::from("+");
    for width in widths {
        line.push_str(&format!("-{}-+", "-".repeat(*width)));
    }
    println!("{}", ui::table_border(&line));
}

fn print_header_row(cells: &[&str; 10], widths: &[usize; 10]) {
    let mut line = String::from("|");
    for (idx, cell) in cells.iter().enumerate() {
        let padded = format!("{:<width$}", cell, width = widths[idx]);
        line.push_str(&format!(" {} |", ui::table_header(&padded)));
    }
    println!("{line}");
}

fn print_data_row(cells: &[String; 10], widths: &[usize; 10]) {
    let mut line = String::from("|");
    for (idx, cell) in cells.iter().enumerate() {
        let padded = format!("{:<width$}", cell, width = widths[idx]);
        let styled = match idx {
            2 => ui::style_status_cell(&padded, cell),
            9 => ui::style_health_cell(&padded, cell),
            _ => padded,
        };
        line.push_str(&format!(" {styled} |"));
    }
    println!("{line}");
}
