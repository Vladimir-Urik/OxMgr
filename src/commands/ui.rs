use std::cmp::min;
use std::io::{stdout, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use crossterm::cursor;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseButton,
    MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    self, disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen,
    LeaveAlternateScreen,
};

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::process::ManagedProcess;
use crate::ui::format_process_uptime;

use super::common::expect_ok;

pub(crate) async fn run(config: &AppConfig, interval_ms: u64) -> Result<()> {
    let refresh_interval = Duration::from_millis(interval_ms.clamp(200, 5000));
    let _guard = TerminalGuard::enter()?;

    let mut state = DashboardState::default();
    let mut processes = Vec::<ManagedProcess>::new();
    let mut next_refresh_at = Instant::now();
    let mut needs_full_clear = true;
    let mut should_exit = false;

    while !should_exit {
        if Instant::now() >= next_refresh_at {
            match fetch_processes(config).await {
                Ok(items) => {
                    processes = items;
                    state.clamp_selection(processes.len());
                    state.clear_error();
                }
                Err(err) => {
                    state.set_error(format!("refresh failed: {err}"));
                }
            }
            next_refresh_at = Instant::now() + refresh_interval;
        }

        let frame_info = draw_frame(&processes, &state, refresh_interval, needs_full_clear)?;
        needs_full_clear = false;

        if event::poll(Duration::from_millis(90)).context("failed polling terminal input")? {
            match event::read().context("failed reading terminal input")? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if state.esc_menu_open {
                        match key.code {
                            KeyCode::Esc => {
                                state.close_menu();
                                needs_full_clear = true;
                            }
                            KeyCode::Left
                            | KeyCode::Up
                            | KeyCode::Char('h')
                            | KeyCode::Char('k') => {
                                state.esc_menu_selected = EscMenuChoice::Resume;
                            }
                            KeyCode::Right
                            | KeyCode::Down
                            | KeyCode::Tab
                            | KeyCode::Char('l')
                            | KeyCode::Char('j') => {
                                state.esc_menu_selected = EscMenuChoice::Quit;
                            }
                            KeyCode::Enter => match state.esc_menu_selected {
                                EscMenuChoice::Resume => {
                                    state.close_menu();
                                    needs_full_clear = true;
                                }
                                EscMenuChoice::Quit => {
                                    should_exit = true;
                                }
                            },
                            KeyCode::Char('q') => should_exit = true,
                            _ => {}
                        }
                        continue;
                    }

                    match key.code {
                        KeyCode::Char('q') => should_exit = true,
                        KeyCode::Esc => {
                            state.toggle_menu();
                            needs_full_clear = true;
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if state.selected > 0 {
                                state.selected -= 1;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if state.selected + 1 < processes.len() {
                                state.selected += 1;
                            }
                        }
                        KeyCode::Char('g') => {
                            next_refresh_at = Instant::now();
                        }
                        KeyCode::Char('s') => {
                            stop_selected(config, &processes, &mut state).await;
                            next_refresh_at = Instant::now();
                        }
                        KeyCode::Char('r') => {
                            restart_selected(config, &processes, &mut state).await;
                            next_refresh_at = Instant::now();
                        }
                        _ => {}
                    }
                }
                Event::Mouse(mouse) => {
                    if state.esc_menu_open {
                        if let Some(layout) = frame_info.menu_layout {
                            if let Some(action) = handle_menu_mouse(mouse, layout) {
                                match action {
                                    EscMenuChoice::Resume => {
                                        state.close_menu();
                                        needs_full_clear = true;
                                    }
                                    EscMenuChoice::Quit => should_exit = true,
                                }
                            }
                        }
                        continue;
                    }

                    handle_table_mouse_selection(
                        mouse,
                        &frame_info.table_view,
                        &mut state,
                        processes.len(),
                    );
                }
                Event::Resize(_, _) => {
                    needs_full_clear = true;
                }
                _ => {}
            }
        }

        state.prune_flash();
    }

    Ok(())
}

#[derive(Debug, Default)]
struct DashboardState {
    selected: usize,
    flash: Option<FlashMessage>,
    esc_menu_open: bool,
    esc_menu_selected: EscMenuChoice,
}

#[derive(Debug)]
struct FlashMessage {
    text: String,
    level: FlashLevel,
    at: Instant,
}

#[derive(Debug, Copy, Clone)]
enum FlashLevel {
    Info,
    Error,
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
enum EscMenuChoice {
    #[default]
    Resume,
    Quit,
}

#[derive(Debug, Copy, Clone)]
struct EscMenuLayout {
    box_x: u16,
    box_y: u16,
    box_width: u16,
    box_height: u16,
    resume_x: u16,
    quit_x: u16,
    buttons_y: u16,
}

#[derive(Debug, Copy, Clone)]
struct TableView {
    start_index: usize,
    visible_rows: usize,
}

#[derive(Debug, Copy, Clone)]
struct FrameInfo {
    table_view: TableView,
    menu_layout: Option<EscMenuLayout>,
}

impl DashboardState {
    fn clamp_selection(&mut self, len: usize) {
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    fn set_info(&mut self, text: impl Into<String>) {
        self.flash = Some(FlashMessage {
            text: text.into(),
            level: FlashLevel::Info,
            at: Instant::now(),
        });
    }

    fn set_error(&mut self, text: impl Into<String>) {
        self.flash = Some(FlashMessage {
            text: text.into(),
            level: FlashLevel::Error,
            at: Instant::now(),
        });
    }

    fn clear_error(&mut self) {
        if matches!(
            self.flash.as_ref().map(|message| message.level),
            Some(FlashLevel::Error)
        ) {
            self.flash = None;
        }
    }

    fn prune_flash(&mut self) {
        let should_drop = self
            .flash
            .as_ref()
            .map(|message| message.at.elapsed() > Duration::from_secs(4))
            .unwrap_or(false);
        if should_drop {
            self.flash = None;
        }
    }

    fn open_menu(&mut self) {
        self.esc_menu_open = true;
        self.esc_menu_selected = EscMenuChoice::Resume;
    }

    fn close_menu(&mut self) {
        self.esc_menu_open = false;
    }

    fn toggle_menu(&mut self) {
        if self.esc_menu_open {
            self.close_menu();
        } else {
            self.open_menu();
        }
    }
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("failed enabling raw mode")?;
        let mut out = stdout();
        execute!(out, EnterAlternateScreen, cursor::Hide, EnableMouseCapture)
            .context("failed entering alternate screen")?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut out = stdout();
        let _ = execute!(out, DisableMouseCapture, cursor::Show, LeaveAlternateScreen);
    }
}

async fn fetch_processes(config: &AppConfig) -> Result<Vec<ManagedProcess>> {
    let response = send_request(&config.daemon_addr, &IpcRequest::List).await?;
    let response = expect_ok(response)?;

    let mut processes = response.processes;
    processes.sort_by_key(|process| process.id);
    Ok(processes)
}

fn selected_name(processes: &[ManagedProcess], selected: usize) -> Option<&str> {
    processes.get(selected).map(|process| process.name.as_str())
}

async fn stop_selected(
    config: &AppConfig,
    processes: &[ManagedProcess],
    state: &mut DashboardState,
) {
    if let Some(target) = selected_name(processes, state.selected) {
        match send_request(
            &config.daemon_addr,
            &IpcRequest::Stop {
                target: target.to_string(),
            },
        )
        .await
        {
            Ok(response) => match expect_ok(response) {
                Ok(ok) => state.set_info(ok.message),
                Err(err) => state.set_error(err.to_string()),
            },
            Err(err) => state.set_error(err.to_string()),
        }
    }
}

async fn restart_selected(
    config: &AppConfig,
    processes: &[ManagedProcess],
    state: &mut DashboardState,
) {
    if let Some(target) = selected_name(processes, state.selected) {
        match send_request(
            &config.daemon_addr,
            &IpcRequest::Restart {
                target: target.to_string(),
            },
        )
        .await
        {
            Ok(response) => match expect_ok(response) {
                Ok(ok) => state.set_info(ok.message),
                Err(err) => state.set_error(err.to_string()),
            },
            Err(err) => state.set_error(err.to_string()),
        }
    }
}

fn compute_table_view(height: usize, selected: usize) -> TableView {
    let visible_rows = height.saturating_sub(14).max(3);
    let start_index = if selected >= visible_rows {
        selected + 1 - visible_rows
    } else {
        0
    };

    TableView {
        start_index,
        visible_rows,
    }
}

fn esc_menu_layout(width: usize, height: usize) -> Option<EscMenuLayout> {
    if width < 30 || height < 10 {
        return None;
    }

    let box_width = 34_u16.min(width as u16 - 2);
    let box_height = 7_u16.min(height as u16 - 2);
    let box_x = ((width as u16).saturating_sub(box_width)) / 2;
    let box_y = ((height as u16).saturating_sub(box_height)) / 2;

    Some(EscMenuLayout {
        box_x,
        box_y,
        box_width,
        box_height,
        resume_x: box_x + 3,
        quit_x: box_x + box_width.saturating_sub(12),
        buttons_y: box_y + 4,
    })
}

fn handle_menu_mouse(mouse: MouseEvent, layout: EscMenuLayout) -> Option<EscMenuChoice> {
    if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
        return None;
    }

    let x = mouse.column;
    let y = mouse.row;
    if y != layout.buttons_y {
        return None;
    }

    if x >= layout.resume_x && x < layout.resume_x + 8 {
        return Some(EscMenuChoice::Resume);
    }
    if x >= layout.quit_x && x < layout.quit_x + 6 {
        return Some(EscMenuChoice::Quit);
    }
    None
}

fn handle_table_mouse_selection(
    mouse: MouseEvent,
    view: &TableView,
    state: &mut DashboardState,
    process_count: usize,
) {
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            let table_first_row = 8_u16;
            let table_last_row = table_first_row + view.visible_rows.saturating_sub(1) as u16;
            if mouse.row < table_first_row || mouse.row > table_last_row {
                return;
            }
            let relative = (mouse.row - table_first_row) as usize;
            let idx = view.start_index.saturating_add(relative);
            if idx < process_count {
                state.selected = idx;
            }
        }
        MouseEventKind::ScrollUp => {
            if state.selected > 0 {
                state.selected -= 1;
            }
        }
        MouseEventKind::ScrollDown => {
            if state.selected + 1 < process_count {
                state.selected += 1;
            }
        }
        _ => {}
    }
}

fn draw_frame(
    processes: &[ManagedProcess],
    state: &DashboardState,
    refresh: Duration,
    clear_all: bool,
) -> Result<FrameInfo> {
    let (width, height) = terminal::size().context("failed reading terminal size")?;
    let width = width as usize;
    let height = height as usize;
    let table_view = compute_table_view(height, state.selected);
    let menu_layout = if state.esc_menu_open {
        esc_menu_layout(width, height)
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
            menu_layout,
        });
    }

    let now = wall_clock_hms();
    let title = format!(
        " OXMGR UI  │  {}  │ refresh {}ms  │ Esc menu · q quit · j/k move · mouse select ",
        now,
        refresh.as_millis()
    );
    write_line(
        &mut frame,
        &paint("1;36", &frame_line("╔", "╗", width, '═')),
    )?;
    write_line(
        &mut frame,
        &paint("1;36", &frame_content_line(&title, width)),
    )?;
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
        " Total {}  •  {}  •  {}  •  {}  •  {} ",
        paint("1;37", &processes.len().to_string()),
        paint("1;32", &format!("running {running}")),
        paint("1;33", &format!("restarting {restarting}")),
        paint("2;37", &format!("stopped {stopped}")),
        paint("1;31", &format!("unhealthy {unhealthy}"))
    );
    write_line(&mut frame, &frame_content_line(&summary, width))?;

    if let Some(message) = state.flash.as_ref() {
        let code = match message.level {
            FlashLevel::Info => "1;34",
            FlashLevel::Error => "1;31",
        };
        let text = format!(" {}", message.text);
        write_line(&mut frame, &frame_content_line(&paint(code, &text), width))?;
    } else {
        write_line(&mut frame, &frame_content_line(" ", width))?;
    }

    write_line(
        &mut frame,
        &paint("1;36", &frame_line("╠", "╣", width, '═')),
    )?;

    draw_table(&mut frame, processes, &table_view, state.selected, width)?;

    write_line(
        &mut frame,
        &paint("1;36", &frame_line("╠", "╣", width, '═')),
    )?;
    draw_details(&mut frame, processes, state.selected, width)?;
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
    execute!(out, Clear(ClearType::FromCursorDown)).context("failed clearing trailing area")?;

    if let Some(layout) = menu_layout {
        draw_esc_menu(&mut out, layout, state.esc_menu_selected)?;
    }

    out.flush().context("failed flushing terminal frame")?;

    Ok(FrameInfo {
        table_view,
        menu_layout,
    })
}

fn draw_table(
    out: &mut impl Write,
    processes: &[ManagedProcess],
    table_view: &TableView,
    selected: usize,
    width: usize,
) -> Result<()> {
    let cols: [(&str, usize); 9] = [
        ("S", 1),
        ("ID", 4),
        ("NAME", 18),
        ("STATUS", 10),
        ("PID", 8),
        ("UPTIME", 9),
        ("CPU%", 6),
        ("RAM", 7),
        ("HEALTH", 9),
    ];

    let min_table_width = cols.iter().map(|(_, col)| *col).sum::<usize>() + (cols.len() - 1) * 3;
    if min_table_width + 4 > width {
        write_line(
            out,
            &frame_content_line(" table too wide for current terminal ", width),
        )?;
        return Ok(());
    }

    let mut header_parts = Vec::with_capacity(cols.len());
    for (name, col_width) in cols {
        header_parts.push(pad(name, col_width));
    }
    write_line(
        out,
        &frame_content_line(&paint("1;36", &header_parts.join(" │ ")), width),
    )?;
    write_line(
        out,
        &frame_content_line(&paint("2;34", &"─".repeat(min_table_width)), width),
    )?;

    let visible_rows = table_view.visible_rows.max(3);
    let start = table_view.start_index;
    let end = min(processes.len(), start + visible_rows);

    if processes.is_empty() {
        write_line(
            out,
            &frame_content_line(" no managed processes (use `oxmgr start ...`) ", width),
        )?;
    } else {
        for (idx, process) in processes.iter().enumerate().take(end).skip(start) {
            let mark = if idx == selected { "▸" } else { " " };
            let status_raw = process.status.to_string();
            let health_raw = process.health_status.to_string();
            let row_cells = vec![
                pad(mark, 1),
                pad(&process.id.to_string(), 4),
                pad(&truncate(&process.name, 18), 18),
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
                pad(&(process.memory_bytes / (1024 * 1024)).to_string(), 7),
                style_health(&pad(&health_raw, 9), &health_raw),
            ];
            let base = row_cells.join(" │ ");
            let line = if idx == selected {
                paint("48;5;236", &base)
            } else {
                base
            };
            write_line(out, &frame_content_line(&line, width))?;
        }
    }

    for _ in end.saturating_sub(start)..visible_rows {
        write_line(out, &frame_content_line(" ", width))?;
    }

    Ok(())
}

fn draw_details(
    out: &mut impl Write,
    processes: &[ManagedProcess],
    selected: usize,
    width: usize,
) -> Result<()> {
    if let Some(process) = processes.get(selected) {
        let max_ram_bytes = processes
            .iter()
            .map(|item| item.memory_bytes)
            .max()
            .unwrap_or(process.memory_bytes.max(1));
        let ram_ratio = if max_ram_bytes == 0 {
            0.0
        } else {
            (process.memory_bytes as f64 / max_ram_bytes as f64) as f32 * 100.0
        };

        let detail_title = format!(" Selected: {} (id {}) ", process.name, process.id);
        let mode = if process.cluster_mode {
            process
                .cluster_instances
                .map(|instances| format!("cluster:{instances}"))
                .unwrap_or_else(|| "cluster:auto".to_string())
        } else {
            "single".to_string()
        };
        write_line(
            out,
            &frame_content_line(&paint("1;37", &detail_title), width),
        )?;
        write_line(
            out,
            &frame_content_line(
                &format!(
                    " PID {}  •  Uptime {}  •  Restarts {}/{}  •  Mode {} ",
                    process
                        .pid
                        .map_or_else(|| "-".to_string(), |pid| pid.to_string()),
                    format_process_uptime(&process.status, process.last_started_at),
                    process.restart_count,
                    process.max_restarts,
                    mode
                ),
                width,
            ),
        )?;
        write_line(
            out,
            &frame_content_line(
                &format!(
                    " CPU {} {:>5.1}% ",
                    paint("1;32", &progress_bar(process.cpu_percent, 24)),
                    process.cpu_percent
                ),
                width,
            ),
        )?;
        write_line(
            out,
            &frame_content_line(
                &format!(
                    " RAM {} {:>5} MB ",
                    paint("1;35", &progress_bar(ram_ratio, 24)),
                    process.memory_bytes / (1024 * 1024)
                ),
                width,
            ),
        )?;
        let command = if process.args.is_empty() {
            process.command.clone()
        } else {
            format!("{} {}", process.command, process.args.join(" "))
        };
        write_line(
            out,
            &frame_content_line(
                &format!(" Cmd: {}", truncate(&command, width.saturating_sub(8))),
                width,
            ),
        )?;
        write_line(
            out,
            &frame_content_line(
                &format!(
                    " Cwd: {}",
                    process
                        .cwd
                        .as_ref()
                        .map(|cwd| cwd.display().to_string())
                        .unwrap_or_else(|| "-".to_string())
                ),
                width,
            ),
        )?;
    } else {
        write_line(out, &frame_content_line(" No process selected ", width))?;
        write_line(out, &frame_content_line(" ", width))?;
        write_line(out, &frame_content_line(" ", width))?;
        write_line(out, &frame_content_line(" ", width))?;
        write_line(out, &frame_content_line(" ", width))?;
        write_line(out, &frame_content_line(" ", width))?;
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

fn centered(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        return text.chars().take(width).collect();
    }
    let left = (width - len) / 2;
    let right = width - len - left;
    format!("{}{}{}", " ".repeat(left), text, " ".repeat(right))
}

fn progress_bar(percent: f32, width: usize) -> String {
    let clamped = percent.clamp(0.0, 100.0);
    let filled = ((clamped / 100.0) * width as f32).round() as usize;
    let filled = filled.min(width);
    format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
}

fn frame_line(left: &str, right: &str, width: usize, fill: char) -> String {
    format!(
        "{left}{}{right}",
        fill.to_string().repeat(width.saturating_sub(2))
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

fn visible_len(value: &str) -> usize {
    let mut len = 0usize;
    let mut iter = value.chars().peekable();
    while let Some(ch) = iter.next() {
        if ch == '\x1b' {
            if iter.peek() == Some(&'[') {
                let _ = iter.next();
                while let Some(next) = iter.next() {
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

fn truncate_visible_ansi(value: &str, max_visible: usize) -> String {
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
                while let Some(next) = iter.next() {
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

fn truncate(value: &str, max_len: usize) -> String {
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

fn pad(value: &str, width: usize) -> String {
    let current = value.chars().count();
    if current >= width {
        value.to_string()
    } else {
        format!("{value}{}", " ".repeat(width - current))
    }
}

fn style_status(padded: &str, raw: &str) -> String {
    match raw {
        "running" => paint("1;32", padded),
        "restarting" => paint("1;33", padded),
        "stopped" => paint("2;37", padded),
        "crashed" | "errored" => paint("1;31", padded),
        _ => padded.to_string(),
    }
}

fn style_health(padded: &str, raw: &str) -> String {
    match raw {
        "healthy" => paint("1;32", padded),
        "unknown" => paint("1;33", padded),
        "unhealthy" => paint("1;31", padded),
        _ => padded.to_string(),
    }
}

fn paint(code: &str, value: &str) -> String {
    format!("\x1b[{code}m{value}\x1b[0m")
}

fn wall_clock_hms() -> String {
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
    use super::{progress_bar, truncate, visible_len};

    #[test]
    fn progress_bar_uses_requested_width() {
        let bar = progress_bar(50.0, 10);
        assert_eq!(bar.chars().count(), 10);
    }

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
}
