use anyhow::Result;

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::process::ManagedProcess;

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
        "ID", "NAME", "STATUS", "PID", "RESTARTS", "CPU%", "RAM(MB)", "HEALTH",
    ];

    let rows: Vec<[String; 8]> = processes
        .into_iter()
        .map(|process| {
            [
                process.id.to_string(),
                process.name,
                process.status.to_string(),
                process
                    .pid
                    .map_or_else(|| "-".to_string(), |value| value.to_string()),
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
    print_row(&headers, &widths);
    print_border(&widths);
    for row in rows {
        let cells: [&str; 8] = [
            &row[0], &row[1], &row[2], &row[3], &row[4], &row[5], &row[6], &row[7],
        ];
        print_row(&cells, &widths);
    }
    print_border(&widths);
}

fn print_border(widths: &[usize; 8]) {
    print!("+");
    for width in widths {
        print!("-{}-+", "-".repeat(*width));
    }
    println!();
}

fn print_row(cells: &[&str; 8], widths: &[usize; 8]) {
    print!("|");
    for (idx, cell) in cells.iter().enumerate() {
        print!(" {:<width$} |", cell, width = widths[idx]);
    }
    println!();
}
