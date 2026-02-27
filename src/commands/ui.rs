use std::cmp::min;
use std::io::{stdout, Write};
use std::path::PathBuf;
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
        table_area: TableArea {
            left_col: 1,
            right_col: 78,
            first_row: 9,
            last_row: 11,
        },
        menu_layout: None,
        delete_confirm_layout: None,
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

                    if let Some(confirm) = state.delete_confirm.as_mut() {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('n') => {
                                state.close_delete_confirm();
                                needs_full_clear = true;
                                needs_redraw = true;
                            }
                            KeyCode::Left
                            | KeyCode::Up
                            | KeyCode::Char('h')
                            | KeyCode::Char('k') => {
                                confirm.selected = DeleteConfirmChoice::Cancel;
                                needs_redraw = true;
                            }
                            KeyCode::Right
                            | KeyCode::Down
                            | KeyCode::Tab
                            | KeyCode::Char('l')
                            | KeyCode::Char('j') => {
                                confirm.selected = DeleteConfirmChoice::Delete;
                                needs_redraw = true;
                            }
                            KeyCode::Char('y') => {
                                let target = confirm.target.clone();
                                state.close_delete_confirm();
                                delete_target(config, &target, &mut state).await;
                                next_refresh_at = Instant::now();
                                needs_full_clear = true;
                                needs_redraw = true;
                            }
                            KeyCode::Enter => {
                                let action = confirm.selected;
                                let target = confirm.target.clone();
                                state.close_delete_confirm();
                                match action {
                                    DeleteConfirmChoice::Cancel => {}
                                    DeleteConfirmChoice::Delete => {
                                        delete_target(config, &target, &mut state).await;
                                        next_refresh_at = Instant::now();
                                    }
                                }
                                needs_full_clear = true;
                                needs_redraw = true;
                            }
                            _ => {}
                        }
                        continue;
                    }

                    if let Some(viewer) = state.log_viewer.as_mut() {
                        let visible_rows = log_viewer_content_rows(
                            terminal::size().ok().map(|(_, h)| h as usize).unwrap_or(20),
                        );
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('l') => {
                                state.close_log_viewer();
                                needs_full_clear = true;
                                needs_redraw = true;
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                viewer.scroll_up(1);
                                needs_redraw = true;
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                viewer.scroll_down(visible_rows, 1);
                                needs_redraw = true;
                            }
                            KeyCode::PageUp => {
                                viewer.scroll_up(visible_rows.saturating_sub(1).max(1));
                                needs_redraw = true;
                            }
                            KeyCode::PageDown => {
                                viewer.scroll_down(
                                    visible_rows,
                                    visible_rows.saturating_sub(1).max(1),
                                );
                                needs_redraw = true;
                            }
                            KeyCode::Home => {
                                viewer.scroll_to_top();
                                needs_redraw = true;
                            }
                            KeyCode::End => {
                                viewer.scroll_to_bottom(visible_rows);
                                needs_redraw = true;
                            }
                            KeyCode::Tab => {
                                viewer.toggle_source();
                                needs_redraw = true;
                            }
                            KeyCode::Char('g') | KeyCode::Char(' ') => {
                                viewer.reload();
                                viewer.clamp_scroll(visible_rows);
                                needs_redraw = true;
                            }
                            KeyCode::Char('q') => should_exit = true,
                            KeyCode::Char('?') => {
                                state.toggle_help();
                                needs_full_clear = true;
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
                        KeyCode::Char('d') => {
                            if let Some(process) = processes.get(state.selected) {
                                state.open_delete_confirm(process);
                            }
                            needs_redraw = true;
                        }
                        KeyCode::Char('r') => {
                            reload_selected(config, &processes, &mut state).await;
                            next_refresh_at = Instant::now();
                            needs_redraw = true;
                        }
                        KeyCode::Char('R') => {
                            restart_selected(config, &processes, &mut state).await;
                            next_refresh_at = Instant::now();
                            needs_redraw = true;
                        }
                        KeyCode::Char('l') => {
                            open_logs_selected(config, &processes, &mut state).await;
                            needs_full_clear = true;
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

                    if state.delete_confirm.is_some() {
                        if let Some(layout) = frame_info.delete_confirm_layout {
                            if let Some(action) = handle_delete_confirm_mouse(mouse, layout) {
                                let target = state
                                    .delete_confirm
                                    .as_ref()
                                    .map(|confirm| confirm.target.clone());
                                match action {
                                    DeleteConfirmChoice::Cancel => {
                                        state.close_delete_confirm();
                                    }
                                    DeleteConfirmChoice::Delete => {
                                        state.close_delete_confirm();
                                        if let Some(target) = target {
                                            delete_target(config, &target, &mut state).await;
                                            next_refresh_at = Instant::now();
                                        }
                                    }
                                }
                                needs_full_clear = true;
                                needs_redraw = true;
                            }
                        }
                        continue;
                    }

                    if let Some(viewer) = state.log_viewer.as_mut() {
                        let visible_rows = log_viewer_content_rows(
                            terminal::size().ok().map(|(_, h)| h as usize).unwrap_or(20),
                        );
                        match mouse.kind {
                            MouseEventKind::ScrollUp => {
                                viewer.scroll_up(3);
                                needs_redraw = true;
                            }
                            MouseEventKind::ScrollDown => {
                                viewer.scroll_down(visible_rows, 3);
                                needs_redraw = true;
                            }
                            _ => {}
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

                    let selection_changed = handle_table_mouse_selection(
                        mouse,
                        &frame_info.table_view,
                        frame_info.table_area,
                        &mut state,
                        processes.len(),
                    );
                    if selection_changed {
                        needs_redraw = true;
                    }
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
    delete_confirm: Option<DeleteConfirmState>,
    log_viewer: Option<LogViewerState>,
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

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
enum DeleteConfirmChoice {
    #[default]
    Cancel,
    Delete,
}

#[derive(Debug)]
struct DeleteConfirmState {
    target: String,
    label: String,
    selected: DeleteConfirmChoice,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum LogSource {
    Stdout,
    Stderr,
}

#[derive(Debug)]
struct LogViewerState {
    process_name: String,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    stdout_lines: Vec<String>,
    stderr_lines: Vec<String>,
    active_source: LogSource,
    scroll: usize,
    status: Option<String>,
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
struct DeleteConfirmLayout {
    box_x: u16,
    box_y: u16,
    box_width: u16,
    box_height: u16,
    cancel_x: u16,
    delete_x: u16,
    buttons_y: u16,
}

#[derive(Debug, Copy, Clone)]
struct TableView {
    start_index: usize,
    visible_rows: usize,
}

#[derive(Debug, Copy, Clone)]
struct TableArea {
    left_col: u16,
    right_col: u16,
    first_row: u16,
    last_row: u16,
}

#[derive(Debug, Copy, Clone)]
struct ProcessSidebarLayout {
    box_x: u16,
    box_y: u16,
    box_width: u16,
    box_height: u16,
}

#[derive(Debug, Copy, Clone)]
struct FrameInfo {
    table_view: TableView,
    table_area: TableArea,
    menu_layout: Option<EscMenuLayout>,
    delete_confirm_layout: Option<DeleteConfirmLayout>,
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

    fn open_delete_confirm(&mut self, process: &ManagedProcess) {
        self.delete_confirm = Some(DeleteConfirmState {
            target: process.name.clone(),
            label: format!("{} (id {})", process.name, process.id),
            selected: DeleteConfirmChoice::Cancel,
        });
    }

    fn close_delete_confirm(&mut self) {
        self.delete_confirm = None;
    }

    fn open_log_viewer(&mut self, viewer: LogViewerState) {
        self.log_viewer = Some(viewer);
    }

    fn close_log_viewer(&mut self) {
        self.log_viewer = None;
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

impl LogViewerState {
    fn from_logs(process_name: String, stdout_path: PathBuf, stderr_path: PathBuf) -> Self {
        let mut viewer = Self {
            process_name,
            stdout_path,
            stderr_path,
            stdout_lines: Vec::new(),
            stderr_lines: Vec::new(),
            active_source: LogSource::Stderr,
            scroll: 0,
            status: None,
        };
        viewer.reload();
        viewer
    }

    fn reload(&mut self) {
        self.stderr_lines = read_last_lines(&self.stderr_path, 4000).unwrap_or_default();
        self.stdout_lines = read_last_lines(&self.stdout_path, 4000).unwrap_or_default();

        if self.current_lines().is_empty() {
            if !self.stdout_lines.is_empty() {
                self.active_source = LogSource::Stdout;
            }
        } else if self.active_source == LogSource::Stdout
            && self.stdout_lines.is_empty()
            && !self.stderr_lines.is_empty()
        {
            self.active_source = LogSource::Stderr;
        }

        self.status = Some(format!(
            "{} stderr lines, {} stdout lines",
            self.stderr_lines.len(),
            self.stdout_lines.len()
        ));
    }

    fn current_lines(&self) -> &[String] {
        match self.active_source {
            LogSource::Stdout => &self.stdout_lines,
            LogSource::Stderr => &self.stderr_lines,
        }
    }

    fn current_path(&self) -> &PathBuf {
        match self.active_source {
            LogSource::Stdout => &self.stdout_path,
            LogSource::Stderr => &self.stderr_path,
        }
    }

    fn source_label(&self) -> &'static str {
        match self.active_source {
            LogSource::Stdout => "stdout",
            LogSource::Stderr => "stderr",
        }
    }

    fn toggle_source(&mut self) {
        self.active_source = match self.active_source {
            LogSource::Stdout => LogSource::Stderr,
            LogSource::Stderr => LogSource::Stdout,
        };
        self.scroll = 0;
    }

    fn clamp_scroll(&mut self, visible_rows: usize) {
        let max_scroll = self.current_lines().len().saturating_sub(visible_rows);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }
    }

    fn scroll_up(&mut self, amount: usize) {
        self.scroll = self.scroll.saturating_sub(amount);
    }

    fn scroll_down(&mut self, visible_rows: usize, amount: usize) {
        let max_scroll = self.current_lines().len().saturating_sub(visible_rows);
        self.scroll = self.scroll.saturating_add(amount).min(max_scroll);
    }

    fn scroll_to_top(&mut self) {
        self.scroll = 0;
    }

    fn scroll_to_bottom(&mut self, visible_rows: usize) {
        self.scroll = self.current_lines().len().saturating_sub(visible_rows);
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

async fn delete_target(config: &AppConfig, target: &str, state: &mut DashboardState) {
    match send_request(
        &config.daemon_addr,
        &IpcRequest::Delete {
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

async fn open_logs_selected(
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
                        state.open_log_viewer(LogViewerState::from_logs(
                            target.to_string(),
                            logs.stdout,
                            logs.stderr,
                        ));
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
        crash_restart_limit: 3,
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

fn delete_confirm_layout(width: usize, height: usize) -> Option<DeleteConfirmLayout> {
    if width < 44 || height < 12 {
        return None;
    }

    let box_width = 54_u16.min(width as u16 - 4);
    let box_height = 8_u16.min(height as u16 - 4);
    let box_x = ((width as u16).saturating_sub(box_width)) / 2;
    let box_y = ((height as u16).saturating_sub(box_height)) / 2;

    Some(DeleteConfirmLayout {
        box_x,
        box_y,
        box_width,
        box_height,
        cancel_x: box_x + 4,
        delete_x: box_x + box_width.saturating_sub(13),
        buttons_y: box_y + 5,
    })
}

fn handle_delete_confirm_mouse(
    mouse: MouseEvent,
    layout: DeleteConfirmLayout,
) -> Option<DeleteConfirmChoice> {
    if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
        return None;
    }

    if mouse.row != layout.buttons_y {
        return None;
    }

    if mouse.column >= layout.cancel_x && mouse.column < layout.cancel_x + 8 {
        return Some(DeleteConfirmChoice::Cancel);
    }
    if mouse.column >= layout.delete_x && mouse.column < layout.delete_x + 8 {
        return Some(DeleteConfirmChoice::Delete);
    }

    None
}

fn handle_table_mouse_selection(
    mouse: MouseEvent,
    view: &TableView,
    area: TableArea,
    state: &mut DashboardState,
    process_count: usize,
) -> bool {
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            if mouse.row < area.first_row
                || mouse.row > area.last_row
                || mouse.column < area.left_col
                || mouse.column > area.right_col
            {
                return false;
            }
            let relative = (mouse.row - area.first_row) as usize;
            let idx = view.start_index.saturating_add(relative);
            if idx < process_count {
                if state.selected == idx {
                    return false;
                }
                state.selected = idx;
                return true;
            }
            false
        }
        MouseEventKind::ScrollUp => {
            if mouse.column < area.left_col || mouse.column > area.right_col {
                return false;
            }
            if state.selected > 0 {
                state.selected -= 1;
                return true;
            }
            false
        }
        MouseEventKind::ScrollDown => {
            if mouse.column < area.left_col || mouse.column > area.right_col {
                return false;
            }
            if state.selected + 1 < process_count {
                state.selected += 1;
                return true;
            }
            false
        }
        _ => false,
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
    let log_viewer_open = state.log_viewer.is_some();
    let sidebar_layout = if !log_viewer_open
        && !state.esc_menu_open
        && !state.help_open
        && state.create_form.is_none()
    {
        processes
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
        " Total {}  •  {}  •  {}  •  {}  •  {} ",
        paint("1;37", &processes.len().to_string()),
        paint("1;32", &format!("running {running}")),
        paint("1;33", &format!("restarting {restarting}")),
        paint("2;37", &format!("stopped {stopped}")),
        paint("1;31", &format!("unhealthy {unhealthy}"))
    );
    write_line(&mut frame, &frame_line_content(&summary))?;

    if let Some(message) = state.flash.as_ref() {
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
                " Keys: j/k move  n new  s stop  d delete  r reload  R restart  l logs  p pull  t tail  g/space refresh  ? help  Esc menu ",
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
        processes,
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
    if let (Some(process), Some(layout)) = (processes.get(state.selected), sidebar_layout) {
        draw_process_sidebar(&mut out, layout, process, processes.len())?;
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
    processes: &[ManagedProcess],
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
        write_line(
            out,
            &frame_content_line_left(
                " no managed processes (use `oxmgr start ...`) ",
                table_inner_width,
                width,
            ),
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
    let box_height = 12_u16.min(height as u16 - 4);
    let box_x = ((width as u16).saturating_sub(box_width)) / 2;
    let box_y = ((height as u16).saturating_sub(box_height)) / 2;
    let inner = box_width.saturating_sub(2) as usize;

    let top = format!("╔{}╗", "═".repeat(inner));
    let bottom = format!("╚{}╝", "═".repeat(inner));

    let lines = [
        centered(" OXMGR UI HELP ", inner),
        " Navigation: j/k or ↑/↓, mouse wheel, left click row".to_string(),
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

fn process_sidebar_layout(width: usize, height: usize) -> Option<ProcessSidebarLayout> {
    if width < 110 || height < 14 {
        return None;
    }

    let inner = width.saturating_sub(2);
    let gap = 1_usize;
    let min_left = 66_usize;
    let max_sidebar = 44_usize;
    let min_sidebar = 36_usize;
    if inner < min_left + gap + min_sidebar {
        return None;
    }

    let box_width = inner
        .saturating_sub(min_left + gap)
        .min(max_sidebar)
        .max(min_sidebar) as u16;
    let box_x = (width as u16).saturating_sub(box_width + 1);
    let box_y = 1_u16;
    let box_height = (height as u16).saturating_sub(box_y).max(9);

    Some(ProcessSidebarLayout {
        box_x,
        box_y,
        box_width,
        box_height,
    })
}

fn table_inner_width(width: usize, sidebar_layout: Option<ProcessSidebarLayout>) -> usize {
    if let Some(layout) = sidebar_layout {
        (layout.box_x as usize).saturating_sub(2)
    } else {
        width.saturating_sub(2)
    }
}

fn draw_process_sidebar(
    out: &mut impl Write,
    layout: ProcessSidebarLayout,
    process: &ManagedProcess,
    process_count: usize,
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

fn log_viewer_content_rows(height: usize) -> usize {
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

fn frame_content_line_left(content: &str, left_inner_width: usize, total_width: usize) -> String {
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
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    use crate::process::{
        DesiredState, HealthStatus, ManagedProcess, ProcessStatus, RestartPolicy,
    };

    use super::{
        compute_table_view, delete_confirm_layout, esc_menu_layout, format_memory_cell,
        frame_content_line_left, frame_line_with_label, handle_delete_confirm_mouse,
        handle_menu_mouse, handle_table_mouse_selection, log_viewer_content_rows,
        process_sidebar_layout, progress_bar, table_inner_width, truncate, truncate_visible_ansi,
        visible_len, CreateField, CreateProcessForm, DashboardState, DeleteConfirmChoice,
        DeleteConfirmLayout, EscMenuChoice, EscMenuLayout, FlashLevel, FlashMessage, LogSource,
        LogViewerState, ProcessSidebarLayout, TableArea, TableView,
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
    fn process_sidebar_layout_uses_full_body_height() {
        let layout = process_sidebar_layout(140, 30).expect("sidebar layout should exist");
        assert_eq!(layout.box_y, 1);
        assert_eq!(layout.box_height, 29);
    }

    #[test]
    fn table_inner_width_stops_before_sidebar() {
        let layout = ProcessSidebarLayout {
            box_x: 90,
            box_y: 5,
            box_width: 44,
            box_height: 20,
        };
        assert_eq!(table_inner_width(140, Some(layout)), 88);
        assert_eq!(table_inner_width(140, None), 138);
    }

    #[test]
    fn frame_content_line_left_preserves_full_terminal_width() {
        let line = frame_content_line_left("hello", 10, 20);
        assert_eq!(visible_len(&line), 20);
        assert!(line.starts_with('║'));
        assert!(line.ends_with('║'));
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

    #[test]
    fn mouse_move_does_not_change_selection_or_trigger_redraw() {
        let view = TableView {
            start_index: 0,
            visible_rows: 10,
        };
        let area = TableArea {
            left_col: 1,
            right_col: 60,
            first_row: 9,
            last_row: 18,
        };
        let mut state = DashboardState::default();
        state.selected = 2;

        let moved = MouseEvent {
            kind: MouseEventKind::Moved,
            column: 10,
            row: 12,
            modifiers: KeyModifiers::empty(),
        };

        let changed = handle_table_mouse_selection(moved, &view, area, &mut state, 5);
        assert!(!changed);
        assert_eq!(state.selected, 2);
    }

    #[test]
    fn sidebar_click_does_not_change_table_selection() {
        let view = TableView {
            start_index: 0,
            visible_rows: 10,
        };
        let area = TableArea {
            left_col: 1,
            right_col: 60,
            first_row: 9,
            last_row: 18,
        };
        let mut state = DashboardState::default();
        state.selected = 1;

        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 90,
            row: 10,
            modifiers: KeyModifiers::empty(),
        };

        let changed = handle_table_mouse_selection(click, &view, area, &mut state, 5);
        assert!(!changed);
        assert_eq!(state.selected, 1);
    }

    #[test]
    fn delete_confirm_layout_is_centered_and_usable() {
        let layout = delete_confirm_layout(120, 30).expect("layout should exist");
        assert_eq!(layout.box_width, 54);
        assert_eq!(layout.box_height, 8);
        assert_eq!(layout.buttons_y, layout.box_y + 5);
    }

    #[test]
    fn handle_delete_confirm_mouse_detects_buttons() {
        let layout = DeleteConfirmLayout {
            box_x: 20,
            box_y: 6,
            box_width: 54,
            box_height: 8,
            cancel_x: 24,
            delete_x: 61,
            buttons_y: 11,
        };

        let cancel_click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: layout.cancel_x + 1,
            row: layout.buttons_y,
            modifiers: KeyModifiers::empty(),
        };
        let delete_click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: layout.delete_x + 1,
            row: layout.buttons_y,
            modifiers: KeyModifiers::empty(),
        };

        assert_eq!(
            handle_delete_confirm_mouse(cancel_click, layout),
            Some(DeleteConfirmChoice::Cancel)
        );
        assert_eq!(
            handle_delete_confirm_mouse(delete_click, layout),
            Some(DeleteConfirmChoice::Delete)
        );
    }

    #[test]
    fn open_delete_confirm_captures_process_identity() {
        let mut state = DashboardState::default();
        let process = ManagedProcess {
            id: 7,
            name: "api".to_string(),
            command: "node".to_string(),
            args: vec!["server.js".to_string()],
            cwd: None,
            env: HashMap::new(),
            restart_policy: RestartPolicy::OnFailure,
            max_restarts: 10,
            restart_count: 0,
            crash_restart_limit: 3,
            auto_restart_history: Vec::new(),
            namespace: None,
            git_repo: None,
            git_ref: None,
            pull_secret_hash: None,
            stop_signal: None,
            stop_timeout_secs: 5,
            restart_delay_secs: 0,
            restart_backoff_cap_secs: 0,
            restart_backoff_reset_secs: 0,
            restart_backoff_attempt: 0,
            start_delay_secs: 0,
            watch: false,
            cluster_mode: false,
            cluster_instances: None,
            resource_limits: None,
            cgroup_path: None,
            pid: Some(4242),
            status: ProcessStatus::Running,
            desired_state: DesiredState::Running,
            last_exit_code: None,
            stdout_log: PathBuf::from("stdout.log"),
            stderr_log: PathBuf::from("stderr.log"),
            health_check: None,
            health_status: HealthStatus::Unknown,
            health_failures: 0,
            last_health_check: None,
            next_health_check: None,
            last_health_error: None,
            cpu_percent: 0.0,
            memory_bytes: 0,
            last_metrics_at: None,
            last_started_at: None,
            last_stopped_at: None,
            config_fingerprint: String::new(),
        };

        state.open_delete_confirm(&process);

        let confirm = state.delete_confirm.as_ref().expect("confirm should open");
        assert_eq!(confirm.target, "api");
        assert_eq!(confirm.label, "api (id 7)");
        assert_eq!(confirm.selected, DeleteConfirmChoice::Cancel);
    }

    #[test]
    fn log_viewer_content_rows_reserves_header_space() {
        assert_eq!(log_viewer_content_rows(20), 14);
        assert_eq!(log_viewer_content_rows(6), 1);
    }

    #[test]
    fn log_viewer_toggle_source_resets_scroll() {
        let mut viewer = LogViewerState {
            process_name: "api".to_string(),
            stdout_path: "stdout.log".into(),
            stderr_path: "stderr.log".into(),
            stdout_lines: vec!["out".to_string()],
            stderr_lines: vec!["err".to_string()],
            active_source: LogSource::Stderr,
            scroll: 8,
            status: None,
        };

        viewer.toggle_source();

        assert_eq!(viewer.active_source, LogSource::Stdout);
        assert_eq!(viewer.scroll, 0);
    }

    #[test]
    fn log_viewer_scroll_down_clamps_to_bottom() {
        let mut viewer = LogViewerState {
            process_name: "api".to_string(),
            stdout_path: "stdout.log".into(),
            stderr_path: "stderr.log".into(),
            stdout_lines: (0..10).map(|idx| format!("line-{idx}")).collect(),
            stderr_lines: Vec::new(),
            active_source: LogSource::Stdout,
            scroll: 0,
            status: None,
        };

        viewer.scroll_down(4, 99);

        assert_eq!(viewer.scroll, 6);
    }
}
