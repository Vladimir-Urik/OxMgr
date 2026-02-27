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
use crate::logging::read_last_lines;
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
    let mut needs_redraw = true;
    let mut should_exit = false;
    let mut frame_info = FrameInfo {
        table_view: TableView {
            start_index: 0,
            visible_rows: 3,
        },
        menu_layout: None,
    };

    while !should_exit {
        let now = Instant::now();
        if now >= next_refresh_at {
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
            needs_redraw = true;
        }

        if needs_redraw {
            frame_info = draw_frame(&processes, &state, refresh_interval, needs_full_clear)?;
            needs_full_clear = false;
            needs_redraw = false;
        }

        if event::poll(Duration::from_millis(90)).context("failed polling terminal input")? {
            match event::read().context("failed reading terminal input")? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if state.create_form.is_some() {
                        match key.code {
                            KeyCode::Esc => {
                                state.close_create_form();
                                needs_full_clear = true;
                                needs_redraw = true;
                            }
                            KeyCode::Tab | KeyCode::BackTab => {
                                if let Some(form) = state.create_form.as_mut() {
                                    form.toggle_field();
                                    form.error = None;
                                }
                                needs_redraw = true;
                            }
                            KeyCode::Backspace => {
                                if let Some(form) = state.create_form.as_mut() {
                                    let _ = form.active_mut().pop();
                                    form.error = None;
                                }
                                needs_redraw = true;
                            }
                            KeyCode::Enter => {
                                submit_create_form(config, &mut state).await;
                                next_refresh_at = Instant::now();
                                needs_redraw = true;
                            }
                            KeyCode::Char(ch) => {
                                if !ch.is_control() {
                                    if let Some(form) = state.create_form.as_mut() {
                                        if form.active_mut().chars().count() < 256 {
                                            form.active_mut().push(ch);
                                        }
                                        form.error = None;
                                    }
                                }
                                needs_redraw = true;
                            }
                            _ => {}
                        }
                        continue;
                    }

                    if state.help_open {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('?') => {
                                state.toggle_help();
                                needs_full_clear = true;
                                needs_redraw = true;
                            }
                            KeyCode::Char('q') => should_exit = true,
                            _ => {}
                        }
                        continue;
                    }

                    if state.esc_menu_open {
                        match key.code {
                            KeyCode::Esc => {
                                state.close_menu();
                                needs_full_clear = true;
                                needs_redraw = true;
                            }
                            KeyCode::Left
                            | KeyCode::Up
                            | KeyCode::Char('h')
                            | KeyCode::Char('k') => {
                                state.esc_menu_selected = EscMenuChoice::Resume;
                                needs_redraw = true;
                            }
                            KeyCode::Right
                            | KeyCode::Down
                            | KeyCode::Tab
                            | KeyCode::Char('l')
                            | KeyCode::Char('j') => {
                                state.esc_menu_selected = EscMenuChoice::Quit;
                                needs_redraw = true;
                            }
                            KeyCode::Enter => match state.esc_menu_selected {
                                EscMenuChoice::Resume => {
                                    state.close_menu();
                                    needs_full_clear = true;
                                    needs_redraw = true;
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
                            needs_redraw = true;
                        }
                        KeyCode::Char('?') => {
                            state.toggle_help();
                            needs_full_clear = true;
                            needs_redraw = true;
                        }
                        KeyCode::Char('n') => {
                            state.open_create_form();
                            needs_redraw = true;
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if state.selected > 0 {
                                state.selected -= 1;
                                needs_redraw = true;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if state.selected + 1 < processes.len() {
                                state.selected += 1;
                                needs_redraw = true;
                            }
                        }
                        KeyCode::Char('g') => {
                            next_refresh_at = Instant::now();
                            state.set_info("refresh scheduled");
                            needs_redraw = true;
                        }
                        KeyCode::Char(' ') => {
                            next_refresh_at = Instant::now();
                            needs_redraw = true;
                        }
                        KeyCode::Char('s') => {
                            stop_selected(config, &processes, &mut state).await;
                            next_refresh_at = Instant::now();
                            needs_redraw = true;
                        }
                        KeyCode::Char('r') => {
                            restart_selected(config, &processes, &mut state).await;
                            next_refresh_at = Instant::now();
                            needs_redraw = true;
                        }
                        KeyCode::Char('l') => {
                            reload_selected(config, &processes, &mut state).await;
                            next_refresh_at = Instant::now();
                            needs_redraw = true;
                        }
                        KeyCode::Char('p') => {
                            pull_selected(config, &processes, &mut state).await;
                            next_refresh_at = Instant::now();
                            needs_redraw = true;
                        }
                        KeyCode::Char('t') => {
                            tail_selected(config, &processes, &mut state).await;
                            needs_redraw = true;
                        }
                        _ => {}
                    }
                }
                Event::Mouse(mouse) => {
                    if state.create_form.is_some() {
                        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
                            needs_redraw = true;
                        }
                        continue;
                    }

                    if state.help_open {
                        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
                            state.toggle_help();
                            needs_full_clear = true;
                            needs_redraw = true;
                        }
                        continue;
                    }

                    if state.esc_menu_open {
                        if let Some(layout) = frame_info.menu_layout {
                            if let Some(action) = handle_menu_mouse(mouse, layout) {
                                match action {
                                    EscMenuChoice::Resume => {
                                        state.close_menu();
                                        needs_full_clear = true;
                                        needs_redraw = true;
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
                    needs_redraw = true;
                }
                Event::Resize(_, _) => {
                    needs_full_clear = true;
                    needs_redraw = true;
                }
                _ => {}
            }
        }

        if state.prune_flash() {
            needs_redraw = true;
        }
    }

    Ok(())
}

#[derive(Debug, Default)]
struct DashboardState {
    selected: usize,
    flash: Option<FlashMessage>,
    esc_menu_open: bool,
    esc_menu_selected: EscMenuChoice,
    help_open: bool,
    create_form: Option<CreateProcessForm>,
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

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
enum CreateField {
    #[default]
    Command,
    Name,
}

#[derive(Debug, Default)]
struct CreateProcessForm {
    command: String,
    name: String,
    active: CreateField,
    error: Option<String>,
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

    fn prune_flash(&mut self) -> bool {
        let should_drop = self
            .flash
            .as_ref()
            .map(|message| message.at.elapsed() > Duration::from_secs(4))
            .unwrap_or(false);
        if should_drop {
            self.flash = None;
            return true;
        }
        false
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

    fn toggle_help(&mut self) {
        self.help_open = !self.help_open;
    }

    fn open_create_form(&mut self) {
        self.create_form = Some(CreateProcessForm::default());
    }

    fn close_create_form(&mut self) {
        self.create_form = None;
    }
}

impl CreateProcessForm {
    fn toggle_field(&mut self) {
        self.active = match self.active {
            CreateField::Command => CreateField::Name,
            CreateField::Name => CreateField::Command,
        };
    }

    fn active_mut(&mut self) -> &mut String {
        match self.active {
            CreateField::Command => &mut self.command,
            CreateField::Name => &mut self.name,
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

async fn reload_selected(
    config: &AppConfig,
    processes: &[ManagedProcess],
    state: &mut DashboardState,
) {
    if let Some(target) = selected_name(processes, state.selected) {
        match send_request(
            &config.daemon_addr,
            &IpcRequest::Reload {
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

async fn pull_selected(
    config: &AppConfig,
    processes: &[ManagedProcess],
    state: &mut DashboardState,
) {
    if let Some(target) = selected_name(processes, state.selected) {
        match send_request(
            &config.daemon_addr,
            &IpcRequest::Pull {
                target: Some(target.to_string()),
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

async fn tail_selected(
    config: &AppConfig,
    processes: &[ManagedProcess],
    state: &mut DashboardState,
) {
    if let Some(target) = selected_name(processes, state.selected) {
        match send_request(
            &config.daemon_addr,
            &IpcRequest::Logs {
                target: target.to_string(),
            },
        )
        .await
        {
            Ok(response) => match expect_ok(response) {
                Ok(ok) => {
                    if let Some(logs) = ok.logs {
                        let mut lines = read_last_lines(&logs.stderr, 1)
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|line| !line.trim().is_empty())
                            .collect::<Vec<_>>();
                        if lines.is_empty() {
                            lines = read_last_lines(&logs.stdout, 1)
                                .unwrap_or_default()
                                .into_iter()
                                .filter(|line| !line.trim().is_empty())
                                .collect::<Vec<_>>();
                        }
                        if let Some(line) = lines.last() {
                            state.set_info(format!("log: {}", truncate(line.trim(), 90)));
                        } else {
                            state.set_info("log: no lines yet");
                        }
                    } else {
                        state.set_error("log paths unavailable");
                    }
                }
                Err(err) => state.set_error(err.to_string()),
            },
            Err(err) => state.set_error(err.to_string()),
        }
    }
}

async fn submit_create_form(config: &AppConfig, state: &mut DashboardState) {
    let Some(form) = state.create_form.as_ref() else {
        return;
    };

    let command = form.command.trim().to_string();
    let name_text = form.name.trim().to_string();
    if command.is_empty() {
        if let Some(form) = state.create_form.as_mut() {
            form.error = Some("command is required".to_string());
        }
        return;
    }

    let spec = crate::process::StartProcessSpec {
        command,
        name: if name_text.is_empty() {
            None
        } else {
            Some(name_text)
        },
        restart_policy: crate::process::RestartPolicy::OnFailure,
        max_restarts: 10,
        cwd: None,
        env: std::collections::HashMap::new(),
        health_check: None,
        stop_signal: None,
        stop_timeout_secs: 5,
        restart_delay_secs: 0,
        start_delay_secs: 0,
        watch: false,
        cluster_mode: false,
        cluster_instances: None,
        namespace: None,
        resource_limits: None,
        git_repo: None,
        git_ref: None,
        pull_secret_hash: None,
    };

    match send_request(
        &config.daemon_addr,
        &IpcRequest::Start {
            spec: Box::new(spec),
        },
    )
    .await
    {
        Ok(response) => match expect_ok(response) {
            Ok(ok) => {
                state.set_info(ok.message);
                state.close_create_form();
            }
            Err(err) => {
                if let Some(form) = state.create_form.as_mut() {
                    form.error = Some(err.to_string());
                }
            }
        },
        Err(err) => {
            if let Some(form) = state.create_form.as_mut() {
                form.error = Some(err.to_string());
            }
        }
    }
}

fn compute_table_view(height: usize, selected: usize) -> TableView {
    // Static frame rows outside table:
    // 6 rows above table + 2 table header rows + 1 bottom border = 9.
    let visible_rows = height.saturating_sub(9).max(1);
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
            let table_first_row = 9_u16;
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
    // Keep one column unused to avoid terminal auto-wrap artifacts on the last column.
    let width = (width as usize).saturating_sub(1).max(1);
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
    let selected = processes.get(state.selected);
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
    let title = format!(
        " OXMGR UI  │  {}  │ refresh {}ms  │ {} ",
        now,
        refresh.as_millis(),
        selected_summary
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
        write_line(
            &mut frame,
            &frame_content_line(
                " Keys: j/k move  n new  s stop  r restart  l reload  p pull  t tail  g/space refresh  ? help  Esc menu ",
                width,
            ),
        )?;
    }

    write_line(
        &mut frame,
        &paint(
            "1;36",
            &frame_line_with_label("╠", "╣", width, '═', "SERVICES"),
        ),
    )?;

    draw_table(&mut frame, processes, &table_view, state.selected, width)?;

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
    if let Some(process) = processes.get(state.selected) {
        if !state.esc_menu_open && !state.help_open && state.create_form.is_none() {
            draw_process_sidebar(&mut out, width, height, process, processes.len())?;
        }
    }
    if state.help_open {
        draw_help_overlay(&mut out, width, height)?;
    }
    if let Some(form) = state.create_form.as_ref() {
        draw_create_overlay(&mut out, width, height, form)?;
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
    let inner_width = width.saturating_sub(2);
    if min_table_width > inner_width {
        write_line(
            out,
            &frame_content_line(" table too wide for current terminal ", width),
        )?;
        return Ok(());
    }
    let extra = inner_width - min_table_width;
    // Stretch table to full frame width by allocating slack to NAME column.
    cols[2].1 = cols[2].1.saturating_add(extra);

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
        &frame_content_line(&paint("2;34", &"─".repeat(inner_width)), width),
    )?;

    let visible_rows = table_view.visible_rows;
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
            write_line(out, &frame_content_line(&line, width))?;
        }
    }

    for _ in end.saturating_sub(start)..visible_rows {
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

fn draw_help_overlay(out: &mut impl Write, width: usize, height: usize) -> Result<()> {
    if width < 40 || height < 14 {
        return Ok(());
    }

    let box_width = 72_u16.min(width as u16 - 4);
    let box_height = 12_u16.min(height as u16 - 4);
    let box_x = ((width as u16).saturating_sub(box_width)) / 2;
    let box_y = ((height as u16).saturating_sub(box_height)) / 2;
    let inner = box_width.saturating_sub(2) as usize;

    let top = format!("╔{}╗", "═".repeat(inner));
    let bottom = format!("╚{}╝", "═".repeat(inner));

    let lines = [
        centered(" OXMGR UI HELP ", inner),
        " Navigation: j/k or ↑/↓, mouse wheel, left click row".to_string(),
        " Actions: s stop, r restart, l reload (best effort no-downtime)".to_string(),
        " Git: p pull selected service and auto reload/restart on commit change".to_string(),
        " Logs: t show latest line snapshot (stderr preferred, then stdout)".to_string(),
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

    let command_label = if form.active == CreateField::Command {
        paint("1;30;46", " command ")
    } else {
        paint("1;36", " command ")
    };
    let name_label = if form.active == CreateField::Name {
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
    width: usize,
    height: usize,
    process: &ManagedProcess,
    process_count: usize,
) -> Result<()> {
    if width < 100 || height < 14 {
        return Ok(());
    }

    let box_width = 44_u16.min(width as u16 - 4);
    let box_x = (width as u16).saturating_sub(box_width + 1);
    let box_y = 7_u16;
    let max_height = (height as u16).saturating_sub(box_y + 1);
    let box_height = max_height.min(24).max(12);
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
        format!(" selected {} / {} ", process.id, process_count),
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

fn format_memory_cell(memory_bytes: u64) -> String {
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

fn frame_line_with_label(left: &str, right: &str, width: usize, fill: char, label: &str) -> String {
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
    use std::time::{Duration, Instant};

    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    use super::{
        compute_table_view, esc_menu_layout, format_memory_cell, frame_line_with_label,
        handle_menu_mouse, progress_bar, truncate, truncate_visible_ansi, visible_len, CreateField,
        CreateProcessForm, DashboardState, EscMenuChoice, EscMenuLayout, FlashLevel, FlashMessage,
    };

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

    #[test]
    fn compute_table_view_scrolls_selected_row_into_view() {
        let view = compute_table_view(24, 12);
        assert_eq!(view.start_index, 0);
        assert_eq!(view.visible_rows, 15);
    }

    #[test]
    fn esc_menu_layout_requires_reasonable_terminal_size() {
        assert!(esc_menu_layout(20, 8).is_none());
        assert!(esc_menu_layout(80, 24).is_some());
    }

    #[test]
    fn handle_menu_mouse_detects_resume_and_quit_buttons() {
        let layout = EscMenuLayout {
            box_x: 10,
            box_y: 4,
            box_width: 34,
            box_height: 7,
            resume_x: 13,
            quit_x: 32,
            buttons_y: 8,
        };

        let resume_click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: layout.resume_x + 1,
            row: layout.buttons_y,
            modifiers: KeyModifiers::empty(),
        };
        let quit_click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: layout.quit_x + 1,
            row: layout.buttons_y,
            modifiers: KeyModifiers::empty(),
        };

        assert_eq!(
            handle_menu_mouse(resume_click, layout),
            Some(EscMenuChoice::Resume)
        );
        assert_eq!(
            handle_menu_mouse(quit_click, layout),
            Some(EscMenuChoice::Quit)
        );
    }

    #[test]
    fn truncate_visible_ansi_keeps_reset_code() {
        let input = "\x1b[1;31mabcdef\x1b[0m";
        let output = truncate_visible_ansi(input, 3);
        assert_eq!(visible_len(&output), 3);
        assert!(output.ends_with("\x1b[0m"));
    }

    #[test]
    fn prune_flash_returns_true_when_expired_message_removed() {
        let mut state = DashboardState::default();
        state.flash = Some(FlashMessage {
            text: "expired".to_string(),
            level: FlashLevel::Info,
            at: Instant::now() - Duration::from_secs(5),
        });

        assert!(state.prune_flash());
        assert!(state.flash.is_none());
    }

    #[test]
    fn format_memory_cell_includes_units() {
        assert_eq!(format_memory_cell(39 * 1024 * 1024), "39 MB");
        assert_eq!(format_memory_cell(512), "512 B");
        assert!(
            format_memory_cell(3 * 1024 * 1024 * 1024).ends_with("GB"),
            "expected GB unit for large values"
        );
    }

    #[test]
    fn frame_line_with_label_preserves_total_width() {
        let line = frame_line_with_label("╠", "╣", 40, '═', "SERVICES");
        assert_eq!(line.chars().count(), 40);
        assert!(line.contains(" SERVICES "));
    }

    #[test]
    fn create_form_toggles_and_edits_active_field() {
        let mut form = CreateProcessForm::default();
        assert_eq!(form.active, CreateField::Command);
        form.active_mut().push_str("node app.js");
        form.toggle_field();
        assert_eq!(form.active, CreateField::Name);
        form.active_mut().push_str("api");

        assert_eq!(form.command, "node app.js");
        assert_eq!(form.name, "api");
    }
}
