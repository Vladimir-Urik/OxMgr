use std::cmp::min;
use std::io::{stdout, Write};
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::cursor;
use crossterm::execute;
use crossterm::terminal::{self, Clear, ClearType};

use super::layout::{
    compute_table_view, delete_confirm_layout, esc_menu_layout, process_sidebar_layout,
    table_inner_width,
};
use super::text::{
    pad, paint, style_health, style_status, truncate, truncate_visible_ansi, visible_len,
    wall_clock_hms,
};
use super::{
    CreateProcessForm, DashboardState, DeleteConfirmChoice, DeleteConfirmLayout,
    DeleteConfirmState, EscMenuChoice, EscMenuLayout, FlashLevel, FrameInfo, LogViewerState,
    ProcessSidebarLayout, TableArea, TableView,
};
use crate::process::ManagedProcess;
use crate::ui::format_process_uptime;

pub(super) fn draw_frame(
    processes: &[ManagedProcess],
    visible_processes: &[&ManagedProcess],
    state: &DashboardState,
    refresh: Duration,
    clear_all: bool,
) -> Result<FrameInfo> {
    let (width, height) = terminal::size().context("failed reading terminal size")?;
    // Keep one column unused to avoid terminal auto-wrap artifacts on the last column.
    let width = (width as usize).saturating_sub(1).max(1);
    let height = height as usize;
    let table_view = compute_table_view(height, state.selected);
    let log_viewer_open = state.log_viewer.is_some();
    let sidebar_layout = if !log_viewer_open
        && !state.esc_menu_open
        && !state.help_open
        && state.create_form.is_none()
    {
        visible_processes
            .get(state.selected)
            .and_then(|_| process_sidebar_layout(width, height))
    } else {
        None
    };
    let table_inner_width = table_inner_width(width, sidebar_layout);
    let table_area = TableArea {
        left_col: 1,
        right_col: table_inner_width as u16,
        first_row: 9,
        last_row: 9_u16 + table_view.visible_rows.saturating_sub(1) as u16,
    };
    let menu_layout = if state.esc_menu_open {
        esc_menu_layout(width, height)
    } else {
        None
    };
    let delete_confirm_layout = if state.delete_confirm.is_some() {
        delete_confirm_layout(width, height)
    } else {
        None
    };

    let mut frame = Vec::<u8>::new();

    if width < 80 || height < 20 {
        write_line(
            &mut frame,
            &paint(
                "1;31",
                "Terminal too small for oxmgr ui. Resize to at least 80x20.",
            ),
        )?;
        let mut out = stdout();
        execute!(out, cursor::MoveTo(0, 0)).context("failed moving cursor")?;
        if clear_all {
            execute!(out, Clear(ClearType::All)).context("failed clearing terminal frame")?;
        }
        out.write_all(&frame)
            .context("failed writing terminal warning frame")?;
        out.flush().context("failed flushing terminal frame")?;
        return Ok(FrameInfo {
            table_view,
            table_area,
            menu_layout,
            delete_confirm_layout,
        });
    }

    if let Some(viewer) = state.log_viewer.as_ref() {
        draw_log_viewer_frame(&mut frame, viewer, width, height)?;

        let mut out = stdout();
        execute!(out, cursor::MoveTo(0, 0)).context("failed moving cursor")?;
        if clear_all {
            execute!(out, Clear(ClearType::All)).context("failed clearing terminal frame")?;
        }
        out.write_all(&frame)
            .context("failed writing terminal log viewer frame")?;

        if state.help_open {
            draw_help_overlay(&mut out, width, height)?;
        }

        out.flush().context("failed flushing terminal log viewer")?;

        return Ok(FrameInfo {
            table_view,
            table_area,
            menu_layout: None,
            delete_confirm_layout: None,
        });
    }

    let frame_line_content = |content: &str| {
        if sidebar_layout.is_some() {
            frame_content_line_left(content, table_inner_width, width)
        } else {
            frame_content_line(content, width)
        }
    };

    let now = wall_clock_hms();
    let selected = visible_processes.get(state.selected).copied();
    let selected_summary = selected
        .map(|process| {
            let mode = if process.cluster_mode {
                process
                    .cluster_instances
                    .map(|instances| format!("cluster:{instances}"))
                    .unwrap_or_else(|| "cluster:auto".to_string())
            } else {
                "single".to_string()
            };
            format!(
                "selected {}  status {}  mode {}",
                process.name, process.status, mode
            )
        })
        .unwrap_or_else(|| "selected -".to_string());
    let search_summary = if state.search_query.is_empty() {
        "search -".to_string()
    } else {
        format!("search {}", state.search_query)
    };
    let title = format!(
        " OXMGR UI  │  {}  │ refresh {}ms  │ view {}/{}  │ filter {}  │ sort {}  │ {}  │ {} ",
        now,
        refresh.as_millis(),
        visible_processes.len(),
        processes.len(),
        state.filter.label(),
        state.sort.label(),
        search_summary,
        selected_summary
    );
    write_line(
        &mut frame,
        &paint("1;36", &frame_line("╔", "╗", width, '═')),
    )?;
    write_line(&mut frame, &paint("1;36", &frame_line_content(&title)))?;
    write_line(
        &mut frame,
        &paint("1;36", &frame_line("╠", "╣", width, '═')),
    )?;

    let running = processes
        .iter()
        .filter(|process| process.status.to_string() == "running")
        .count();
    let restarting = processes
        .iter()
        .filter(|process| process.status.to_string() == "restarting")
        .count();
    let stopped = processes
        .iter()
        .filter(|process| process.status.to_string() == "stopped")
        .count();
    let unhealthy = processes
        .iter()
        .filter(|process| process.health_status.to_string() == "unhealthy")
        .count();
    let summary = format!(
        " Visible {}  •  Total {}  •  {}  •  {}  •  {}  •  {} ",
        paint(
            "1;36",
            &format!("{}/{}", visible_processes.len(), processes.len())
        ),
        paint("1;37", &processes.len().to_string()),
        paint("1;32", &format!("running {running}")),
        paint("1;33", &format!("restarting {restarting}")),
        paint("2;37", &format!("stopped {stopped}")),
        paint("1;31", &format!("unhealthy {unhealthy}"))
    );
    write_line(&mut frame, &frame_line_content(&summary))?;

    if state.search_input_open {
        let search_text = if state.search_query.is_empty() {
            " Search:  (type to filter, Enter/Esc close, Delete/Ctrl+U clear) ".to_string()
        } else {
            format!(
                " Search: {}_  (Enter/Esc close, Delete/Ctrl+U clear) ",
                state.search_query
            )
        };
        write_line(
            &mut frame,
            &frame_line_content(&paint("1;33", &search_text)),
        )?;
    } else if let Some(message) = state.flash.as_ref() {
        let code = match message.level {
            FlashLevel::Info => "1;34",
            FlashLevel::Error => "1;31",
        };
        let text = format!(" {}", message.text);
        write_line(&mut frame, &frame_line_content(&paint(code, &text)))?;
    } else {
        write_line(
            &mut frame,
            &frame_line_content(
                " Keys: j/k move  / search  f filter  o sort  n new  s stop  d delete  r reload  R restart  l logs  p pull  t tail  g/space refresh  ? help  Esc menu ",
            ),
        )?;
    }

    write_line(
        &mut frame,
        &paint(
            "1;36",
            &frame_content_line_left(
                &frame_line_with_label("╠", "╣", table_inner_width, '═', "SERVICES"),
                table_inner_width,
                width,
            ),
        ),
    )?;

    draw_table(
        &mut frame,
        visible_processes,
        processes.len(),
        &table_view,
        state.selected,
        width,
        table_inner_width,
    )?;

    write_line(
        &mut frame,
        &paint("1;36", &frame_line("╚", "╝", width, '═')),
    )?;

    let mut out = stdout();
    execute!(out, cursor::MoveTo(0, 0)).context("failed moving cursor")?;
    if clear_all {
        execute!(out, Clear(ClearType::All)).context("failed clearing terminal frame")?;
    }
    out.write_all(&frame)
        .context("failed writing terminal dashboard frame")?;

    if let Some(layout) = menu_layout {
        draw_esc_menu(&mut out, layout, state.esc_menu_selected)?;
    }
    if let (Some(process), Some(layout)) = (selected, sidebar_layout) {
        draw_process_sidebar(
            &mut out,
            layout,
            process,
            state.selected,
            visible_processes.len(),
            processes.len(),
        )?;
    }
    if state.help_open {
        draw_help_overlay(&mut out, width, height)?;
    }
    if let Some(form) = state.create_form.as_ref() {
        draw_create_overlay(&mut out, width, height, form)?;
    }
    if let (Some(confirm), Some(layout)) = (state.delete_confirm.as_ref(), delete_confirm_layout) {
        draw_delete_confirm_overlay(&mut out, layout, confirm)?;
    }

    out.flush().context("failed flushing terminal frame")?;

    Ok(FrameInfo {
        table_view,
        table_area,
        menu_layout,
        delete_confirm_layout,
    })
}

fn draw_log_viewer_frame(
    frame: &mut Vec<u8>,
    viewer: &LogViewerState,
    width: usize,
    height: usize,
) -> Result<()> {
    let visible_rows = log_viewer_content_rows(height);
    let lines = viewer.current_lines();
    let scroll = viewer.scroll.min(lines.len().saturating_sub(visible_rows));
    let start = scroll;
    let end = min(lines.len(), start + visible_rows);
    let inner = width.saturating_sub(2);
    let source = viewer.source_label();
    let status = viewer.status.as_deref().unwrap_or("no log metadata");
    let title = format!(
        " LOG VIEWER  │  {}  │  {}  │  {} lines ",
        viewer.process_name,
        source,
        lines.len()
    );
    let path_line = format!(" Path: {} ", viewer.current_path().display());
    let meta_line = format!(
        " Scroll {}/{}  │  {} ",
        start.saturating_add(1).min(lines.len()),
        lines.len().max(1),
        status
    );
    let controls =
        " Keys: j/k or ↑/↓ scroll  PgUp/PgDn jump  Home/End  Tab switch stdout/stderr  g/space reload  l/Esc close ";

    write_line(frame, &paint("1;35", &frame_line("╔", "╗", width, '═')))?;
    write_line(frame, &paint("1;35", &frame_content_line(&title, width)))?;
    write_line(
        frame,
        &frame_content_line(&paint("2;37", &path_line), width),
    )?;
    write_line(
        frame,
        &frame_content_line(&paint("1;36", &meta_line), width),
    )?;
    write_line(frame, &frame_content_line(&paint("1;34", controls), width))?;
    write_line(
        frame,
        &paint("1;35", &frame_line_with_label("╠", "╣", width, '═', "LOGS")),
    )?;

    let line_no_width = lines.len().max(1).to_string().chars().count().max(3);
    let line_inner = inner.saturating_sub(line_no_width + 3);
    if lines.is_empty() {
        write_line(
            frame,
            &frame_content_line(
                &paint(
                    "2;37",
                    " no logs yet - use Tab to switch source or g to reload ",
                ),
                width,
            ),
        )?;
        for _ in 1..visible_rows {
            write_line(frame, &frame_content_line(" ", width))?;
        }
    } else {
        for (row_idx, line) in lines.iter().enumerate().take(end).skip(start) {
            let prefix = paint(
                "2;36",
                &format!("{:>width$} │ ", row_idx + 1, width = line_no_width),
            );
            let text = line.trim_end_matches(['\r', '\n']);
            let text = truncate_visible_ansi(text, line_inner);
            write_line(
                frame,
                &frame_content_line(&format!("{prefix}{text}"), width),
            )?;
        }
        for _ in end.saturating_sub(start)..visible_rows {
            write_line(frame, &frame_content_line(" ", width))?;
        }
    }

    write_line(frame, &paint("1;35", &frame_line("╚", "╝", width, '═')))?;
    Ok(())
}

fn draw_table(
    out: &mut impl Write,
    processes: &[&ManagedProcess],
    total_count: usize,
    table_view: &TableView,
    selected: usize,
    width: usize,
    table_inner_width: usize,
) -> Result<()> {
    let mut cols: [(&str, usize); 9] = [
        ("S", 1),
        ("ID", 4),
        ("NAME", 18),
        ("STATUS", 10),
        ("PID", 8),
        ("UPTIME", 9),
        ("CPU%", 6),
        ("RAM", 9),
        ("HEALTH", 9),
    ];

    let separators_width = (cols.len() - 1) * 3;
    let min_table_width = cols.iter().map(|(_, col)| *col).sum::<usize>() + separators_width;
    if min_table_width > table_inner_width {
        write_line(
            out,
            &frame_content_line_left(
                " table too wide for current terminal ",
                table_inner_width,
                width,
            ),
        )?;
        return Ok(());
    }
    let extra = table_inner_width - min_table_width;
    // Stretch table to fill the left pane by allocating slack to NAME column.
    cols[2].1 = cols[2].1.saturating_add(extra);

    let mut header_parts = Vec::with_capacity(cols.len());
    for (name, col_width) in cols {
        header_parts.push(pad(name, col_width));
    }
    write_line(
        out,
        &frame_content_line_left(
            &paint("1;36", &header_parts.join(" │ ")),
            table_inner_width,
            width,
        ),
    )?;
    write_line(
        out,
        &frame_content_line_left(
            &paint("2;34", &"─".repeat(table_inner_width)),
            table_inner_width,
            width,
        ),
    )?;

    let visible_rows = table_view.visible_rows;
    let start = table_view.start_index;
    let end = min(processes.len(), start + visible_rows);

    if processes.is_empty() {
        let message = if total_count == 0 {
            " no managed processes (use `oxmgr start ...`) "
        } else {
            " no services match current search/filter "
        };
        write_line(
            out,
            &frame_content_line_left(message, table_inner_width, width),
        )?;
    } else {
        for (idx, process) in processes.iter().enumerate().take(end).skip(start) {
            let mark = if idx == selected { "▸" } else { " " };
            let status_raw = process.status.to_string();
            let health_raw = process.health_status.to_string();
            let ram_text = format_memory_cell(process.memory_bytes);
            let row_cells = vec![
                pad(mark, 1),
                pad(&process.id.to_string(), 4),
                pad(&truncate(&process.name, cols[2].1), cols[2].1),
                style_status(&pad(&status_raw, 10), &status_raw),
                pad(
                    &process
                        .pid
                        .map_or_else(|| "-".to_string(), |pid| pid.to_string()),
                    8,
                ),
                pad(
                    &format_process_uptime(&process.status, process.last_started_at),
                    9,
                ),
                pad(&format!("{:.1}", process.cpu_percent), 6),
                pad(&ram_text, 9),
                style_health(&pad(&health_raw, 9), &health_raw),
            ];
            let base = row_cells.join(" │ ");
            let line = if idx == selected {
                paint("48;5;236", &base)
            } else {
                base
            };
            write_line(
                out,
                &frame_content_line_left(&line, table_inner_width, width),
            )?;
        }
    }

    for _ in end.saturating_sub(start)..visible_rows {
        write_line(out, &frame_content_line_left(" ", table_inner_width, width))?;
    }

    Ok(())
}

fn draw_esc_menu(
    out: &mut impl Write,
    layout: EscMenuLayout,
    selected: EscMenuChoice,
) -> Result<()> {
    let x = layout.box_x;
    let y = layout.box_y;
    let inner = layout.box_width.saturating_sub(2) as usize;

    let top = format!("╔{}╗", "═".repeat(inner));
    let mid = format!("║{}║", " ".repeat(inner));
    let title = centered(" ESC MENU ", inner);
    let hint = centered("Arrows/Tab + Enter, or click", inner);
    let bottom = format!("╚{}╝", "═".repeat(inner));

    execute!(out, cursor::MoveTo(x, y))?;
    write!(out, "{}", paint("1;34", &top))?;
    execute!(out, cursor::MoveTo(x, y + 1))?;
    write!(out, "{}", paint("1;34", &format!("║{}║", title)))?;
    execute!(out, cursor::MoveTo(x, y + 2))?;
    write!(out, "{}", paint("1;34", &mid))?;
    execute!(out, cursor::MoveTo(x, y + 3))?;
    write!(out, "{}", paint("2;37", &format!("║{}║", hint)))?;

    execute!(out, cursor::MoveTo(x, layout.buttons_y))?;
    write!(out, "{}", paint("1;34", &mid))?;
    let resume = if selected == EscMenuChoice::Resume {
        paint("1;30;42", " Resume ")
    } else {
        paint("1;32", "[Resume]")
    };
    let quit = if selected == EscMenuChoice::Quit {
        paint("1;37;41", " Quit ")
    } else {
        paint("1;31", "[Quit]")
    };
    execute!(out, cursor::MoveTo(layout.resume_x, layout.buttons_y))?;
    write!(out, "{resume}")?;
    execute!(out, cursor::MoveTo(layout.quit_x, layout.buttons_y))?;
    write!(out, "{quit}")?;
    execute!(
        out,
        cursor::MoveTo(x, y + layout.box_height.saturating_sub(1))
    )?;
    write!(out, "{}", paint("1;34", &bottom))?;
    Ok(())
}

fn draw_help_overlay(out: &mut impl Write, width: usize, height: usize) -> Result<()> {
    if width < 40 || height < 14 {
        return Ok(());
    }

    let box_width = 72_u16.min(width as u16 - 4);
    let box_height = 13_u16.min(height as u16 - 4);
    let box_x = ((width as u16).saturating_sub(box_width)) / 2;
    let box_y = ((height as u16).saturating_sub(box_height)) / 2;
    let inner = box_width.saturating_sub(2) as usize;

    let top = format!("╔{}╗", "═".repeat(inner));
    let bottom = format!("╚{}╝", "═".repeat(inner));

    let lines = [
        centered(" OXMGR UI HELP ", inner),
        " Navigation: j/k or ↑/↓, mouse wheel, left click row".to_string(),
        " View: / search, f cycles filters, o cycles sort order".to_string(),
        " Actions: s stop, d delete (confirm), r reload, Shift+R restart".to_string(),
        " Git: p pull selected service and auto reload/restart on commit change".to_string(),
        " Logs: l opens fullscreen viewer, t shows latest line snapshot".to_string(),
        " Log viewer: Tab switches stdout/stderr, PgUp/PgDn/Home/End scroll".to_string(),
        " Refresh: g or Space".to_string(),
        " Menu: Esc opens quick menu with Resume/Quit".to_string(),
        " Exit: q".to_string(),
        centered(" Press Esc or ? to close help ", inner),
    ];

    execute!(out, cursor::MoveTo(box_x, box_y))?;
    write!(out, "{}", paint("1;34", &top))?;
    for (idx, line) in lines.iter().enumerate() {
        let y = box_y + 1 + idx as u16;
        let clipped = truncate_visible_ansi(line, inner);
        execute!(out, cursor::MoveTo(box_x, y))?;
        write!(out, "{}", paint("1;34", "║"))?;
        write!(out, "{clipped}")?;
        let fill = inner.saturating_sub(visible_len(&clipped));
        if fill > 0 {
            write!(out, "{}", " ".repeat(fill))?;
        }
        write!(out, "{}", paint("1;34", "║"))?;
    }
    execute!(
        out,
        cursor::MoveTo(box_x, box_y + box_height.saturating_sub(1))
    )?;
    write!(out, "{}", paint("1;34", &bottom))?;
    Ok(())
}

fn draw_delete_confirm_overlay(
    out: &mut impl Write,
    layout: DeleteConfirmLayout,
    confirm: &DeleteConfirmState,
) -> Result<()> {
    let x = layout.box_x;
    let y = layout.box_y;
    let inner = layout.box_width.saturating_sub(2) as usize;

    let top = format!("╔{}╗", "═".repeat(inner));
    let mid = format!("║{}║", " ".repeat(inner));
    let bottom = format!("╚{}╝", "═".repeat(inner));

    let title = centered(" DELETE PROCESS ", inner);
    let target_line =
        truncate_visible_ansi(&format!(" Remove {} from oxmgr? ", confirm.label), inner);
    let hint_line =
        truncate_visible_ansi(" Enter/y confirm  Esc/n cancel  Arrows/Tab switch ", inner);

    execute!(out, cursor::MoveTo(x, y))?;
    write!(out, "{}", paint("1;31", &top))?;
    execute!(out, cursor::MoveTo(x, y + 1))?;
    write!(out, "{}", paint("1;31", "║"))?;
    write!(out, "{}", paint("1;37", &title))?;
    write!(out, "{}", paint("1;31", "║"))?;

    execute!(out, cursor::MoveTo(x, y + 2))?;
    write!(out, "{}", paint("1;31", "║"))?;
    write!(out, "{target_line}")?;
    let target_fill = inner.saturating_sub(visible_len(&target_line));
    if target_fill > 0 {
        write!(out, "{}", " ".repeat(target_fill))?;
    }
    write!(out, "{}", paint("1;31", "║"))?;

    execute!(out, cursor::MoveTo(x, y + 3))?;
    write!(out, "{}", paint("1;31", "║"))?;
    write!(out, "{}", paint("2;37", &hint_line))?;
    let hint_fill = inner.saturating_sub(visible_len(&hint_line));
    if hint_fill > 0 {
        write!(out, "{}", " ".repeat(hint_fill))?;
    }
    write!(out, "{}", paint("1;31", "║"))?;

    execute!(out, cursor::MoveTo(x, y + 4))?;
    write!(out, "{}", paint("1;31", &mid))?;
    execute!(out, cursor::MoveTo(x, layout.buttons_y))?;
    write!(out, "{}", paint("1;31", &mid))?;

    let cancel = if confirm.selected == DeleteConfirmChoice::Cancel {
        paint("1;30;42", " Cancel ")
    } else {
        paint("1;32", "[Cancel]")
    };
    let delete = if confirm.selected == DeleteConfirmChoice::Delete {
        paint("1;37;41", " Delete ")
    } else {
        paint("1;31", "[Delete]")
    };
    execute!(out, cursor::MoveTo(layout.cancel_x, layout.buttons_y))?;
    write!(out, "{cancel}")?;
    execute!(out, cursor::MoveTo(layout.delete_x, layout.buttons_y))?;
    write!(out, "{delete}")?;

    execute!(
        out,
        cursor::MoveTo(x, y + layout.box_height.saturating_sub(1))
    )?;
    write!(out, "{}", paint("1;31", &bottom))?;
    Ok(())
}

fn draw_create_overlay(
    out: &mut impl Write,
    width: usize,
    height: usize,
    form: &CreateProcessForm,
) -> Result<()> {
    if width < 50 || height < 14 {
        return Ok(());
    }

    let box_width = 86_u16.min(width as u16 - 4);
    let box_height = 10_u16.min(height as u16 - 4);
    let box_x = ((width as u16).saturating_sub(box_width)) / 2;
    let box_y = ((height as u16).saturating_sub(box_height)) / 2;
    let inner = box_width.saturating_sub(2) as usize;

    let top = format!("╔{}╗", "═".repeat(inner));
    let bottom = format!("╚{}╝", "═".repeat(inner));
    execute!(out, cursor::MoveTo(box_x, box_y))?;
    write!(out, "{}", paint("1;34", &top))?;

    let title = centered(" CREATE PROCESS ", inner);
    execute!(out, cursor::MoveTo(box_x, box_y + 1))?;
    write!(out, "{}", paint("1;34", "║"))?;
    write!(out, "{}", paint("1;37", &title))?;
    write!(out, "{}", paint("1;34", "║"))?;

    let hint = "Enter=create  Tab=switch field  Esc=cancel";
    execute!(out, cursor::MoveTo(box_x, box_y + 2))?;
    write!(out, "{}", paint("1;34", "║"))?;
    let hint = truncate_visible_ansi(hint, inner);
    write!(out, "{hint}")?;
    let hint_fill = inner.saturating_sub(visible_len(&hint));
    if hint_fill > 0 {
        write!(out, "{}", " ".repeat(hint_fill))?;
    }
    write!(out, "{}", paint("1;34", "║"))?;

    let command_label = if form.active == super::CreateField::Command {
        paint("1;30;46", " command ")
    } else {
        paint("1;36", " command ")
    };
    let name_label = if form.active == super::CreateField::Name {
        paint("1;30;46", " name ")
    } else {
        paint("1;36", " name ")
    };

    let command_line = format!("{command_label}: {}", form.command);
    execute!(out, cursor::MoveTo(box_x, box_y + 4))?;
    write!(out, "{}", paint("1;34", "║"))?;
    let command_line = truncate_visible_ansi(&command_line, inner);
    write!(out, "{command_line}")?;
    let cmd_fill = inner.saturating_sub(visible_len(&command_line));
    if cmd_fill > 0 {
        write!(out, "{}", " ".repeat(cmd_fill))?;
    }
    write!(out, "{}", paint("1;34", "║"))?;

    let name_line = format!("{name_label}: {}", form.name);
    execute!(out, cursor::MoveTo(box_x, box_y + 5))?;
    write!(out, "{}", paint("1;34", "║"))?;
    let name_line = truncate_visible_ansi(&name_line, inner);
    write!(out, "{name_line}")?;
    let name_fill = inner.saturating_sub(visible_len(&name_line));
    if name_fill > 0 {
        write!(out, "{}", " ".repeat(name_fill))?;
    }
    write!(out, "{}", paint("1;34", "║"))?;

    let error_text = form
        .error
        .as_ref()
        .map(|value| paint("1;31", &format!(" error: {}", value)))
        .unwrap_or_else(|| paint("1;32", " ready"));
    execute!(out, cursor::MoveTo(box_x, box_y + 7))?;
    write!(out, "{}", paint("1;34", "║"))?;
    let error_text = truncate_visible_ansi(&error_text, inner);
    write!(out, "{error_text}")?;
    let error_fill = inner.saturating_sub(visible_len(&error_text));
    if error_fill > 0 {
        write!(out, "{}", " ".repeat(error_fill))?;
    }
    write!(out, "{}", paint("1;34", "║"))?;

    for row in [box_y + 3, box_y + 6, box_y + 8] {
        execute!(out, cursor::MoveTo(box_x, row))?;
        write!(out, "{}", paint("1;34", "║"))?;
        write!(out, "{}", " ".repeat(inner))?;
        write!(out, "{}", paint("1;34", "║"))?;
    }

    execute!(
        out,
        cursor::MoveTo(box_x, box_y + box_height.saturating_sub(1))
    )?;
    write!(out, "{}", paint("1;34", &bottom))?;
    Ok(())
}

fn draw_process_sidebar(
    out: &mut impl Write,
    layout: ProcessSidebarLayout,
    process: &ManagedProcess,
    selected_index: usize,
    visible_count: usize,
    total_count: usize,
) -> Result<()> {
    let box_x = layout.box_x;
    let box_y = layout.box_y;
    let box_width = layout.box_width;
    let box_height = layout.box_height;
    let inner = box_width.saturating_sub(2) as usize;

    let top = format!("╔{}╗", "═".repeat(inner));
    let bottom = format!("╚{}╝", "═".repeat(inner));
    execute!(out, cursor::MoveTo(box_x, box_y))?;
    write!(out, "{}", paint("1;34", &top))?;

    let mode = if process.cluster_mode {
        process
            .cluster_instances
            .map(|instances| format!("cluster:{instances}"))
            .unwrap_or_else(|| "cluster:auto".to_string())
    } else {
        "single".to_string()
    };
    let ram_pct = ((process.memory_bytes as f64) / (1024.0 * 1024.0 * 1024.0) * 100.0)
        .clamp(0.0, 100.0) as f32;
    let command = if process.args.is_empty() {
        process.command.clone()
    } else {
        format!("{} {}", process.command, process.args.join(" "))
    };

    let lines = vec![
        paint("1;37", &centered(" PROCESS SIDEBAR ", inner)),
        format!(
            " row {} / {} shown  │ total {} ",
            selected_index.saturating_add(1),
            visible_count.max(1),
            total_count
        ),
        format!(" name: {}", process.name),
        format!(
            " status: {}",
            style_status(&process.status.to_string(), &process.status.to_string())
        ),
        format!(
            " health: {}",
            style_health(
                &process.health_status.to_string(),
                &process.health_status.to_string()
            )
        ),
        format!(
            " pid: {}",
            process
                .pid
                .map_or_else(|| "-".to_string(), |value| value.to_string())
        ),
        format!(
            " uptime: {}",
            format_process_uptime(&process.status, process.last_started_at)
        ),
        format!(
            " restarts: {}/{}",
            process.restart_count, process.max_restarts
        ),
        format!(" mode: {}", mode),
        format!(" cpu: {:>5.1}%", process.cpu_percent),
        format!(
            " cpubar: {}",
            paint("1;32", &progress_bar(process.cpu_percent, 16))
        ),
        format!(" ram: {}", format_memory_cell(process.memory_bytes)),
        format!(" rambar: {}", paint("1;35", &progress_bar(ram_pct, 16))),
        format!(
            " pull hook: {}",
            if process.pull_secret_hash.is_some() {
                "enabled"
            } else {
                "disabled"
            }
        ),
        format!(" watch: {}", if process.watch { "on" } else { "off" }),
        format!(" ns: {}", process.namespace.as_deref().unwrap_or("-")),
        format!(" cmd: {}", truncate(&command, inner.saturating_sub(6))),
        format!(
            " cwd: {}",
            process
                .cwd
                .as_ref()
                .map(|cwd| cwd.display().to_string())
                .unwrap_or_else(|| "-".to_string())
        ),
        format!(
            " git: {}{}",
            process.git_repo.as_deref().unwrap_or("-"),
            process
                .git_ref
                .as_ref()
                .map(|value| format!(" @ {value}"))
                .unwrap_or_default()
        ),
    ];

    let max_lines = box_height.saturating_sub(2) as usize;
    for idx in 0..max_lines {
        let y = box_y + 1 + idx as u16;
        execute!(out, cursor::MoveTo(box_x, y))?;
        write!(out, "{}", paint("1;34", "║"))?;
        let value = lines.get(idx).cloned().unwrap_or_default();
        let value = truncate_visible_ansi(&value, inner);
        write!(out, "{value}")?;
        let fill = inner.saturating_sub(visible_len(&value));
        if fill > 0 {
            write!(out, "{}", " ".repeat(fill))?;
        }
        write!(out, "{}", paint("1;34", "║"))?;
    }

    execute!(
        out,
        cursor::MoveTo(box_x, box_y + box_height.saturating_sub(1))
    )?;
    write!(out, "{}", paint("1;34", &bottom))?;
    Ok(())
}

pub(super) fn log_viewer_content_rows(height: usize) -> usize {
    height.saturating_sub(6).max(1)
}

fn centered(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        return text.chars().take(width).collect();
    }
    let left = (width - len) / 2;
    let right = width - len - left;
    format!("{}{}{}", " ".repeat(left), text, " ".repeat(right))
}

pub(super) fn progress_bar(percent: f32, width: usize) -> String {
    let clamped = percent.clamp(0.0, 100.0);
    let filled = ((clamped / 100.0) * width as f32).round() as usize;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

pub(super) fn format_memory_cell(memory_bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;

    let bytes = memory_bytes as f64;
    if bytes >= GB {
        format!("{:.1} GB", bytes / GB)
    } else if bytes >= MB {
        format!("{} MB", (bytes / MB).round() as u64)
    } else if bytes >= KB {
        format!("{} KB", (bytes / KB).round() as u64)
    } else {
        format!("{memory_bytes} B")
    }
}

fn frame_line(left: &str, right: &str, width: usize, fill: char) -> String {
    format!(
        "{left}{}{right}",
        fill.to_string().repeat(width.saturating_sub(2))
    )
}

pub(super) fn frame_line_with_label(
    left: &str,
    right: &str,
    width: usize,
    fill: char,
    label: &str,
) -> String {
    let inner = width.saturating_sub(2);
    let label = format!(" {label} ");
    let label_len = label.chars().count();
    if label_len >= inner {
        return frame_line(left, right, width, fill);
    }

    let remaining = inner - label_len;
    let left_len = remaining / 2;
    let right_len = remaining - left_len;
    format!(
        "{left}{}{}{}{right}",
        fill.to_string().repeat(left_len),
        label,
        fill.to_string().repeat(right_len)
    )
}

fn write_line(out: &mut impl Write, line: &str) -> Result<()> {
    out.write_all(line.as_bytes())?;
    out.write_all(b"\r\n")?;
    Ok(())
}

fn frame_content_line(content: &str, width: usize) -> String {
    let inner = width.saturating_sub(2);
    let visible = visible_len(content);
    let clipped = if visible > inner {
        truncate_visible_ansi(content, inner)
    } else {
        content.to_string()
    };
    let clipped_visible = visible_len(&clipped);
    let mut line = String::new();
    line.push('║');
    line.push_str(&clipped);
    if clipped_visible < inner {
        line.push_str(&" ".repeat(inner - clipped_visible));
    }
    line.push('║');
    line
}

pub(super) fn frame_content_line_left(
    content: &str,
    left_inner_width: usize,
    total_width: usize,
) -> String {
    let inner_total = total_width.saturating_sub(2);
    let left_clipped = if visible_len(content) > left_inner_width {
        truncate_visible_ansi(content, left_inner_width)
    } else {
        content.to_string()
    };
    let left_visible = visible_len(&left_clipped);

    let mut line = String::new();
    line.push('║');
    line.push_str(&left_clipped);
    if left_visible < inner_total {
        line.push_str(&" ".repeat(inner_total - left_visible));
    }
    line.push('║');
    line
}
