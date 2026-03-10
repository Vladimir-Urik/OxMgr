use std::io::stdout;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::cursor;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    self, disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};

use crate::config::AppConfig;
use crate::ipc::{send_request, IpcRequest};
use crate::logging::read_last_lines;
use crate::process::ManagedProcess;

#[cfg(test)]
use self::layout::{
    compute_table_view, delete_confirm_layout, esc_menu_layout, process_sidebar_layout,
    table_inner_width,
};
use self::layout::{handle_delete_confirm_mouse, handle_menu_mouse, handle_table_mouse_selection};
use self::logs::{default_log_source, preferred_log_source};
use self::render::{draw_frame, log_viewer_content_rows};
#[cfg(test)]
use self::render::{
    format_memory_cell, frame_content_line_left, frame_line_with_label, progress_bar,
};
use self::text::truncate;
#[cfg(test)]
use self::text::visible_len;
use super::common::expect_ok;

mod layout;
mod logs;
mod render;
mod text;

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
                    state.clamp_selection(visible_processes(&processes, &state).len());
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
            let visible = visible_processes(&processes, &state);
            state.clamp_selection(visible.len());
            frame_info = draw_frame(
                &processes,
                &visible,
                &state,
                refresh_interval,
                needs_full_clear,
            )?;
            needs_full_clear = false;
            needs_redraw = false;
        }

        if event::poll(Duration::from_millis(90)).context("failed polling terminal input")? {
            match event::read().context("failed reading terminal input")? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    let visible = visible_processes(&processes, &state);
                    if state.search_input_open {
                        match key.code {
                            KeyCode::Esc | KeyCode::Enter => {
                                state.close_search();
                                needs_redraw = true;
                            }
                            KeyCode::Backspace => {
                                state.pop_search_char();
                                state.clamp_selection(visible_processes(&processes, &state).len());
                                needs_redraw = true;
                            }
                            KeyCode::Delete => {
                                state.clear_search_query();
                                state.clamp_selection(visible_processes(&processes, &state).len());
                                needs_redraw = true;
                            }
                            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                state.clear_search_query();
                                state.clamp_selection(visible_processes(&processes, &state).len());
                                needs_redraw = true;
                            }
                            KeyCode::Char(ch) => {
                                if !ch.is_control() {
                                    state.push_search_char(ch);
                                    state.clamp_selection(
                                        visible_processes(&processes, &state).len(),
                                    );
                                    needs_redraw = true;
                                }
                            }
                            _ => {}
                        }
                        continue;
                    }

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
                                viewer.toggle_source(visible_rows);
                                viewer.clamp_scroll(visible_rows);
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
                        KeyCode::Char('/') => {
                            state.open_search();
                            needs_redraw = true;
                        }
                        KeyCode::Char('f') => {
                            state.cycle_filter();
                            state.clamp_selection(visible_processes(&processes, &state).len());
                            state.set_info(format!("filter: {}", state.filter.label()));
                            needs_redraw = true;
                        }
                        KeyCode::Char('o') => {
                            state.cycle_sort();
                            state.clamp_selection(visible_processes(&processes, &state).len());
                            state.set_info(format!("sort: {}", state.sort.label()));
                            needs_redraw = true;
                        }
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
                            if state.selected + 1 < visible.len() {
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
                            stop_selected(
                                config,
                                selected_target(&visible, state.selected),
                                &mut state,
                            )
                            .await;
                            next_refresh_at = Instant::now();
                            needs_redraw = true;
                        }
                        KeyCode::Char('d') => {
                            if let Some(process) = visible.get(state.selected).copied() {
                                state.open_delete_confirm(process);
                            }
                            needs_redraw = true;
                        }
                        KeyCode::Char('r') => {
                            reload_selected(
                                config,
                                selected_target(&visible, state.selected),
                                &mut state,
                            )
                            .await;
                            next_refresh_at = Instant::now();
                            needs_redraw = true;
                        }
                        KeyCode::Char('R') => {
                            restart_selected(
                                config,
                                selected_target(&visible, state.selected),
                                &mut state,
                            )
                            .await;
                            next_refresh_at = Instant::now();
                            needs_redraw = true;
                        }
                        KeyCode::Char('l') => {
                            open_logs_selected(
                                config,
                                selected_target(&visible, state.selected),
                                &mut state,
                            )
                            .await;
                            needs_full_clear = true;
                            needs_redraw = true;
                        }
                        KeyCode::Char('p') => {
                            pull_selected(
                                config,
                                selected_target(&visible, state.selected),
                                &mut state,
                            )
                            .await;
                            next_refresh_at = Instant::now();
                            needs_redraw = true;
                        }
                        KeyCode::Char('t') => {
                            tail_selected(
                                config,
                                selected_target(&visible, state.selected),
                                &mut state,
                            )
                            .await;
                            needs_redraw = true;
                        }
                        _ => {}
                    }
                }
                Event::Mouse(mouse) => {
                    let visible = visible_processes(&processes, &state);
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
                        visible.len(),
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
    search_query: String,
    search_input_open: bool,
    filter: ProcessFilter,
    sort: ProcessSort,
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
enum ProcessFilter {
    #[default]
    All,
    Running,
    Stopped,
    Unhealthy,
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
enum ProcessSort {
    #[default]
    Id,
    Name,
    Cpu,
    Ram,
    Restarts,
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

    fn open_search(&mut self) {
        self.search_input_open = true;
    }

    fn close_search(&mut self) {
        self.search_input_open = false;
    }

    fn push_search_char(&mut self, ch: char) {
        if self.search_query.chars().count() < 64 {
            self.search_query.push(ch);
        }
    }

    fn pop_search_char(&mut self) {
        let _ = self.search_query.pop();
    }

    fn clear_search_query(&mut self) {
        self.search_query.clear();
    }

    fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
    }

    fn cycle_sort(&mut self) {
        self.sort = self.sort.next();
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
        viewer.active_source = default_log_source(&viewer.stdout_lines, &viewer.stderr_lines);
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

    fn toggle_source(&mut self, visible_rows: usize) {
        self.active_source = match self.active_source {
            LogSource::Stdout => LogSource::Stderr,
            LogSource::Stderr => LogSource::Stdout,
        };
        self.scroll_to_bottom(visible_rows);
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

fn visible_processes<'a>(
    processes: &'a [ManagedProcess],
    state: &DashboardState,
) -> Vec<&'a ManagedProcess> {
    let query = state.search_query.trim().to_ascii_lowercase();
    let mut visible = processes
        .iter()
        .filter(|process| state.filter.matches(process))
        .filter(|process| process_matches_query(process, &query))
        .collect::<Vec<_>>();

    visible.sort_by(|left, right| state.sort.compare(left, right));
    visible
}

fn process_matches_query(process: &ManagedProcess, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }

    let command = if process.args.is_empty() {
        process.command.clone()
    } else {
        format!("{} {}", process.command, process.args.join(" "))
    };
    let namespace = process.namespace.as_deref().unwrap_or_default();

    process.name.to_ascii_lowercase().contains(query)
        || namespace.to_ascii_lowercase().contains(query)
        || command.to_ascii_lowercase().contains(query)
        || process.id.to_string().contains(query)
        || process.status.to_string().contains(query)
        || process.health_status.to_string().contains(query)
}

fn selected_target(processes: &[&ManagedProcess], selected: usize) -> Option<String> {
    processes.get(selected).map(|process| process.name.clone())
}

async fn stop_selected(config: &AppConfig, target: Option<String>, state: &mut DashboardState) {
    if let Some(target) = target {
        match send_request(&config.daemon_addr, &IpcRequest::Stop { target }).await {
            Ok(response) => match expect_ok(response) {
                Ok(ok) => state.set_info(ok.message),
                Err(err) => state.set_error(err.to_string()),
            },
            Err(err) => state.set_error(err.to_string()),
        }
    }
}

async fn restart_selected(config: &AppConfig, target: Option<String>, state: &mut DashboardState) {
    if let Some(target) = target {
        match send_request(&config.daemon_addr, &IpcRequest::Restart { target }).await {
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

async fn reload_selected(config: &AppConfig, target: Option<String>, state: &mut DashboardState) {
    if let Some(target) = target {
        match send_request(&config.daemon_addr, &IpcRequest::Reload { target }).await {
            Ok(response) => match expect_ok(response) {
                Ok(ok) => state.set_info(ok.message),
                Err(err) => state.set_error(err.to_string()),
            },
            Err(err) => state.set_error(err.to_string()),
        }
    }
}

async fn pull_selected(config: &AppConfig, target: Option<String>, state: &mut DashboardState) {
    if let Some(target) = target {
        match send_request(
            &config.daemon_addr,
            &IpcRequest::Pull {
                target: Some(target),
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

async fn tail_selected(config: &AppConfig, target: Option<String>, state: &mut DashboardState) {
    if let Some(target) = target {
        match send_request(&config.daemon_addr, &IpcRequest::Logs { target }).await {
            Ok(response) => match expect_ok(response) {
                Ok(ok) => {
                    if let Some(logs) = ok.logs {
                        let stdout_lines = read_last_lines(&logs.stdout, 1)
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|line| !line.trim().is_empty())
                            .collect::<Vec<_>>();
                        let stderr_lines = read_last_lines(&logs.stderr, 1)
                            .unwrap_or_default()
                            .into_iter()
                            .filter(|line| !line.trim().is_empty())
                            .collect::<Vec<_>>();
                        let lines = match preferred_log_source(
                            &logs.stdout,
                            &logs.stderr,
                            &stdout_lines,
                            &stderr_lines,
                        ) {
                            LogSource::Stdout if !stdout_lines.is_empty() => stdout_lines,
                            LogSource::Stderr if !stderr_lines.is_empty() => stderr_lines,
                            LogSource::Stdout => stderr_lines,
                            LogSource::Stderr => stdout_lines,
                        };
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
    target: Option<String>,
    state: &mut DashboardState,
) {
    if let Some(target) = target {
        match send_request(
            &config.daemon_addr,
            &IpcRequest::Logs {
                target: target.clone(),
            },
        )
        .await
        {
            Ok(response) => match expect_ok(response) {
                Ok(ok) => {
                    if let Some(logs) = ok.logs {
                        let mut viewer =
                            LogViewerState::from_logs(target.to_string(), logs.stdout, logs.stderr);
                        let visible_rows = log_viewer_content_rows(
                            terminal::size().ok().map(|(_, h)| h as usize).unwrap_or(20),
                        );
                        viewer.scroll_to_bottom(visible_rows);
                        viewer.clamp_scroll(visible_rows);
                        state.open_log_viewer(viewer);
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

impl ProcessFilter {
    fn next(self) -> Self {
        match self {
            Self::All => Self::Running,
            Self::Running => Self::Stopped,
            Self::Stopped => Self::Unhealthy,
            Self::Unhealthy => Self::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Unhealthy => "unhealthy",
        }
    }

    fn matches(self, process: &ManagedProcess) -> bool {
        match self {
            Self::All => true,
            Self::Running => process.status == crate::process::ProcessStatus::Running,
            Self::Stopped => process.status == crate::process::ProcessStatus::Stopped,
            Self::Unhealthy => process.health_status == crate::process::HealthStatus::Unhealthy,
        }
    }
}

impl ProcessSort {
    fn next(self) -> Self {
        match self {
            Self::Id => Self::Name,
            Self::Name => Self::Cpu,
            Self::Cpu => Self::Ram,
            Self::Ram => Self::Restarts,
            Self::Restarts => Self::Id,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Id => "id asc",
            Self::Name => "name asc",
            Self::Cpu => "cpu desc",
            Self::Ram => "ram desc",
            Self::Restarts => "restarts desc",
        }
    }

    fn compare(self, left: &ManagedProcess, right: &ManagedProcess) -> std::cmp::Ordering {
        match self {
            Self::Id => left.id.cmp(&right.id),
            Self::Name => left
                .name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
                .then_with(|| left.id.cmp(&right.id)),
            Self::Cpu => right
                .cpu_percent
                .total_cmp(&left.cpu_percent)
                .then_with(|| left.id.cmp(&right.id)),
            Self::Ram => right
                .memory_bytes
                .cmp(&left.memory_bytes)
                .then_with(|| left.id.cmp(&right.id)),
            Self::Restarts => right
                .restart_count
                .cmp(&left.restart_count)
                .then_with(|| left.id.cmp(&right.id)),
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
        pre_reload_cmd: None,
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
        watch_paths: Vec::new(),
        ignore_watch: Vec::new(),
        watch_delay_secs: 0,
        cluster_mode: false,
        cluster_instances: None,
        namespace: None,
        resource_limits: None,
        git_repo: None,
        git_ref: None,
        pull_secret_hash: None,
        reuse_port: false,
        wait_ready: false,
        ready_timeout_secs: crate::process::default_ready_timeout_secs(),
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

#[cfg(test)]
mod tests;
