//! Input handling for the interactive TUI dashboard.
//!
//! Keyboard and mouse events are routed to one handler per active overlay so
//! every decision path stays small, readable, and independently testable.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use crossterm::terminal;

use crate::config::AppConfig;
use crate::process::ManagedProcess;

use super::layout::{handle_delete_confirm_mouse, handle_menu_mouse, handle_table_mouse_selection};
use super::render::log_viewer_content_rows;
use super::{
    delete_target, open_logs_selected, pull_selected, reload_selected, restart_selected,
    selected_target, stop_selected, submit_create_form, tail_selected, visible_processes,
    DashboardState, DeleteConfirmChoice, EscMenuChoice, FrameInfo,
};

/// Redraw and lifecycle flags produced while handling one input event.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct LoopControl {
    pub(super) needs_full_clear: bool,
    pub(super) needs_redraw: bool,
    pub(super) should_exit: bool,
    pub(super) refresh_now: bool,
}

impl LoopControl {
    /// Requests a partial repaint of the current frame.
    fn redraw(&mut self) {
        self.needs_redraw = true;
    }

    /// Requests a full clear before the next repaint, used when an overlay
    /// opens or closes and leaves stale cells behind.
    fn full_redraw(&mut self) {
        self.needs_full_clear = true;
        self.needs_redraw = true;
    }

    /// Schedules an immediate daemon refresh followed by a repaint.
    fn refresh(&mut self) {
        self.refresh_now = true;
        self.needs_redraw = true;
    }
}

/// Clamps the selected row against the currently visible process list.
fn clamp_to_visible(processes: &[ManagedProcess], state: &mut DashboardState) {
    let len = visible_processes(processes, state).len();
    state.clamp_selection(len);
}

/// Returns the number of log lines that fit in the log viewer viewport.
fn log_viewer_rows() -> usize {
    log_viewer_content_rows(terminal::size().ok().map(|(_, h)| h as usize).unwrap_or(20))
}

/// Dispatches a key press to the handler owning the active overlay.
pub(super) async fn handle_key(
    config: &AppConfig,
    key: KeyEvent,
    processes: &[ManagedProcess],
    state: &mut DashboardState,
    ctl: &mut LoopControl,
) {
    if state.search_input_open {
        handle_search_key(key, processes, state, ctl);
    } else if state.create_form.is_some() {
        handle_create_form_key(config, key, state, ctl).await;
    } else if state.delete_confirm.is_some() {
        handle_delete_confirm_key(config, key, state, ctl).await;
    } else if state.log_viewer.is_some() {
        handle_log_viewer_key(key, state, ctl);
    } else if state.help_open {
        handle_help_key(key, state, ctl);
    } else if state.esc_menu_open {
        handle_menu_key(key, state, ctl);
    } else {
        handle_dashboard_key(config, key, processes, state, ctl).await;
    }
}

/// Handles typing in the search prompt.
fn handle_search_key(
    key: KeyEvent,
    processes: &[ManagedProcess],
    state: &mut DashboardState,
    ctl: &mut LoopControl,
) {
    match key.code {
        KeyCode::Esc | KeyCode::Enter => {
            state.close_search();
            ctl.redraw();
        }
        KeyCode::Backspace => {
            state.pop_search_char();
            clamp_to_visible(processes, state);
            ctl.redraw();
        }
        KeyCode::Delete => {
            state.clear_search_query();
            clamp_to_visible(processes, state);
            ctl.redraw();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.clear_search_query();
            clamp_to_visible(processes, state);
            ctl.redraw();
        }
        KeyCode::Char(ch) if !ch.is_control() => {
            state.push_search_char(ch);
            clamp_to_visible(processes, state);
            ctl.redraw();
        }
        _ => {}
    }
}

/// Handles editing and submission of the create-process form.
async fn handle_create_form_key(
    config: &AppConfig,
    key: KeyEvent,
    state: &mut DashboardState,
    ctl: &mut LoopControl,
) {
    match key.code {
        KeyCode::Esc => {
            state.close_create_form();
            ctl.full_redraw();
        }
        KeyCode::Tab | KeyCode::BackTab => {
            if let Some(form) = state.create_form.as_mut() {
                form.toggle_field();
                form.error = None;
            }
            ctl.redraw();
        }
        KeyCode::Backspace => {
            if let Some(form) = state.create_form.as_mut() {
                let _ = form.active_mut().pop();
                form.error = None;
            }
            ctl.redraw();
        }
        KeyCode::Enter => {
            submit_create_form(config, state).await;
            ctl.refresh();
        }
        KeyCode::Char(ch) if !ch.is_control() => {
            if let Some(form) = state.create_form.as_mut() {
                if form.active_mut().chars().count() < 256 {
                    form.active_mut().push(ch);
                }
                form.error = None;
            }
            ctl.redraw();
        }
        KeyCode::Char(_) => ctl.redraw(),
        _ => {}
    }
}

/// Handles the delete confirmation dialog.
async fn handle_delete_confirm_key(
    config: &AppConfig,
    key: KeyEvent,
    state: &mut DashboardState,
    ctl: &mut LoopControl,
) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('n') => {
            state.close_delete_confirm();
            ctl.full_redraw();
        }
        KeyCode::Left | KeyCode::Up | KeyCode::Char('h') | KeyCode::Char('k') => {
            if let Some(confirm) = state.delete_confirm.as_mut() {
                confirm.selected = DeleteConfirmChoice::Cancel;
            }
            ctl.redraw();
        }
        KeyCode::Right
        | KeyCode::Down
        | KeyCode::Tab
        | KeyCode::Char('l')
        | KeyCode::Char('j') => {
            if let Some(confirm) = state.delete_confirm.as_mut() {
                confirm.selected = DeleteConfirmChoice::Delete;
            }
            ctl.redraw();
        }
        KeyCode::Char('y') => {
            confirm_delete(config, state, ctl).await;
        }
        KeyCode::Enter => {
            let action = state
                .delete_confirm
                .as_ref()
                .map(|confirm| confirm.selected)
                .unwrap_or_default();
            match action {
                DeleteConfirmChoice::Cancel => {
                    state.close_delete_confirm();
                    ctl.full_redraw();
                }
                DeleteConfirmChoice::Delete => confirm_delete(config, state, ctl).await,
            }
        }
        _ => {}
    }
}

/// Deletes the process targeted by the confirmation dialog and closes it.
async fn confirm_delete(config: &AppConfig, state: &mut DashboardState, ctl: &mut LoopControl) {
    let target = state
        .delete_confirm
        .as_ref()
        .map(|confirm| confirm.target.clone());
    state.close_delete_confirm();
    if let Some(target) = target {
        delete_target(config, &target, state).await;
        ctl.refresh();
    }
    ctl.full_redraw();
}

/// Handles scrolling and source switching inside the log viewer.
fn handle_log_viewer_key(key: KeyEvent, state: &mut DashboardState, ctl: &mut LoopControl) {
    let visible_rows = log_viewer_rows();
    let Some(viewer) = state.log_viewer.as_mut() else {
        return;
    };

    match key.code {
        KeyCode::Esc | KeyCode::Char('l') => {
            state.close_log_viewer();
            ctl.full_redraw();
        }
        KeyCode::Up | KeyCode::Char('k') => {
            viewer.scroll_up(1);
            ctl.redraw();
        }
        KeyCode::Down | KeyCode::Char('j') => {
            viewer.scroll_down(visible_rows, 1);
            ctl.redraw();
        }
        KeyCode::PageUp => {
            viewer.scroll_up(visible_rows.saturating_sub(1).max(1));
            ctl.redraw();
        }
        KeyCode::PageDown => {
            viewer.scroll_down(visible_rows, visible_rows.saturating_sub(1).max(1));
            ctl.redraw();
        }
        KeyCode::Home => {
            viewer.scroll_to_top();
            ctl.redraw();
        }
        KeyCode::End => {
            viewer.scroll_to_bottom(visible_rows);
            ctl.redraw();
        }
        KeyCode::Tab => {
            viewer.toggle_source(visible_rows);
            viewer.clamp_scroll(visible_rows);
            ctl.redraw();
        }
        KeyCode::Char('g') | KeyCode::Char(' ') => {
            viewer.reload();
            viewer.clamp_scroll(visible_rows);
            ctl.redraw();
        }
        KeyCode::Char('q') => ctl.should_exit = true,
        KeyCode::Char('?') => {
            state.toggle_help();
            ctl.full_redraw();
        }
        _ => {}
    }
}

/// Handles the help overlay.
fn handle_help_key(key: KeyEvent, state: &mut DashboardState, ctl: &mut LoopControl) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('?') => {
            state.toggle_help();
            ctl.full_redraw();
        }
        KeyCode::Char('q') => ctl.should_exit = true,
        _ => {}
    }
}

/// Handles the escape menu overlay.
fn handle_menu_key(key: KeyEvent, state: &mut DashboardState, ctl: &mut LoopControl) {
    match key.code {
        KeyCode::Esc => {
            state.close_menu();
            ctl.full_redraw();
        }
        KeyCode::Left | KeyCode::Up | KeyCode::Char('h') | KeyCode::Char('k') => {
            state.esc_menu_selected = EscMenuChoice::Resume;
            ctl.redraw();
        }
        KeyCode::Right
        | KeyCode::Down
        | KeyCode::Tab
        | KeyCode::Char('l')
        | KeyCode::Char('j') => {
            state.esc_menu_selected = EscMenuChoice::Quit;
            ctl.redraw();
        }
        KeyCode::Enter => match state.esc_menu_selected {
            EscMenuChoice::Resume => {
                state.close_menu();
                ctl.full_redraw();
            }
            EscMenuChoice::Quit => ctl.should_exit = true,
        },
        KeyCode::Char('q') => ctl.should_exit = true,
        _ => {}
    }
}

/// Handles keys on the main dashboard, trying view keys before process actions.
async fn handle_dashboard_key(
    config: &AppConfig,
    key: KeyEvent,
    processes: &[ManagedProcess],
    state: &mut DashboardState,
    ctl: &mut LoopControl,
) {
    if handle_dashboard_view_key(key, processes, state, ctl) {
        return;
    }
    handle_dashboard_action_key(config, key, processes, state, ctl).await;
}

/// Handles navigation, filtering, and overlay-opening keys. Returns `true` when
/// the key was consumed.
fn handle_dashboard_view_key(
    key: KeyEvent,
    processes: &[ManagedProcess],
    state: &mut DashboardState,
    ctl: &mut LoopControl,
) -> bool {
    let visible_len = visible_processes(processes, state).len();

    match key.code {
        KeyCode::Char('q') => ctl.should_exit = true,
        KeyCode::Char('/') => {
            state.open_search();
            ctl.redraw();
        }
        KeyCode::Char('f') => {
            state.cycle_filter();
            clamp_to_visible(processes, state);
            state.set_info(format!("filter: {}", state.filter.label()));
            ctl.redraw();
        }
        KeyCode::Char('o') => {
            state.cycle_sort();
            clamp_to_visible(processes, state);
            state.set_info(format!("sort: {}", state.sort.label()));
            ctl.redraw();
        }
        KeyCode::Esc => {
            state.toggle_menu();
            ctl.full_redraw();
        }
        KeyCode::Char('?') => {
            state.toggle_help();
            ctl.full_redraw();
        }
        KeyCode::Char('n') => {
            state.open_create_form();
            ctl.redraw();
        }
        KeyCode::Up | KeyCode::Char('k') if state.selected > 0 => {
            state.selected -= 1;
            ctl.redraw();
        }
        KeyCode::Down | KeyCode::Char('j') if state.selected + 1 < visible_len => {
            state.selected += 1;
            ctl.redraw();
        }
        KeyCode::Char('g') => {
            state.set_info("refresh scheduled");
            ctl.refresh();
        }
        KeyCode::Char(' ') => ctl.refresh(),
        _ => return false,
    }

    true
}

/// Handles keys that act on the selected process.
async fn handle_dashboard_action_key(
    config: &AppConfig,
    key: KeyEvent,
    processes: &[ManagedProcess],
    state: &mut DashboardState,
    ctl: &mut LoopControl,
) {
    let visible = visible_processes(processes, state);
    let target = selected_target(&visible, state.selected);

    match key.code {
        KeyCode::Char('s') => {
            stop_selected(config, target, state).await;
            ctl.refresh();
        }
        KeyCode::Char('d') => {
            if let Some(process) = visible.get(state.selected).copied() {
                state.open_delete_confirm(process);
            }
            ctl.redraw();
        }
        KeyCode::Char('r') => {
            reload_selected(config, target, state).await;
            ctl.refresh();
        }
        KeyCode::Char('R') => {
            restart_selected(config, target, state).await;
            ctl.refresh();
        }
        KeyCode::Char('l') => {
            open_logs_selected(config, target, state).await;
            ctl.full_redraw();
        }
        KeyCode::Char('p') => {
            pull_selected(config, target, state).await;
            ctl.refresh();
        }
        KeyCode::Char('t') => {
            tail_selected(config, target, state).await;
            ctl.redraw();
        }
        _ => {}
    }
}

/// Dispatches a mouse event to the handler owning the active overlay.
pub(super) async fn handle_mouse(
    config: &AppConfig,
    mouse: MouseEvent,
    processes: &[ManagedProcess],
    state: &mut DashboardState,
    frame_info: &FrameInfo,
    ctl: &mut LoopControl,
) {
    let left_click = matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left));

    if state.create_form.is_some() {
        if left_click {
            ctl.redraw();
        }
    } else if state.delete_confirm.is_some() {
        handle_delete_confirm_mouse_event(config, mouse, state, frame_info, ctl).await;
    } else if state.log_viewer.is_some() {
        handle_log_viewer_mouse(mouse, state, ctl);
    } else if state.help_open {
        if left_click {
            state.toggle_help();
            ctl.full_redraw();
        }
    } else if state.esc_menu_open {
        handle_menu_mouse_event(mouse, state, frame_info, ctl);
    } else {
        handle_table_mouse(mouse, processes, state, frame_info, ctl);
    }
}

/// Routes clicks on the delete confirmation buttons.
async fn handle_delete_confirm_mouse_event(
    config: &AppConfig,
    mouse: MouseEvent,
    state: &mut DashboardState,
    frame_info: &FrameInfo,
    ctl: &mut LoopControl,
) {
    let Some(layout) = frame_info.delete_confirm_layout else {
        return;
    };
    let Some(action) = handle_delete_confirm_mouse(mouse, layout) else {
        return;
    };

    match action {
        DeleteConfirmChoice::Cancel => {
            state.close_delete_confirm();
            ctl.full_redraw();
        }
        DeleteConfirmChoice::Delete => confirm_delete(config, state, ctl).await,
    }
}

/// Routes scroll wheel events to the log viewer.
fn handle_log_viewer_mouse(mouse: MouseEvent, state: &mut DashboardState, ctl: &mut LoopControl) {
    let visible_rows = log_viewer_rows();
    let Some(viewer) = state.log_viewer.as_mut() else {
        return;
    };

    match mouse.kind {
        MouseEventKind::ScrollUp => {
            viewer.scroll_up(3);
            ctl.redraw();
        }
        MouseEventKind::ScrollDown => {
            viewer.scroll_down(visible_rows, 3);
            ctl.redraw();
        }
        _ => {}
    }
}

/// Routes clicks on the escape menu buttons.
fn handle_menu_mouse_event(
    mouse: MouseEvent,
    state: &mut DashboardState,
    frame_info: &FrameInfo,
    ctl: &mut LoopControl,
) {
    let Some(layout) = frame_info.menu_layout else {
        return;
    };
    let Some(action) = handle_menu_mouse(mouse, layout) else {
        return;
    };

    match action {
        EscMenuChoice::Resume => {
            state.close_menu();
            ctl.full_redraw();
        }
        EscMenuChoice::Quit => ctl.should_exit = true,
    }
}

/// Routes clicks and scrolls over the process table to row selection.
fn handle_table_mouse(
    mouse: MouseEvent,
    processes: &[ManagedProcess],
    state: &mut DashboardState,
    frame_info: &FrameInfo,
    ctl: &mut LoopControl,
) {
    let visible_len = visible_processes(processes, state).len();
    if handle_table_mouse_selection(
        mouse,
        &frame_info.table_view,
        frame_info.table_area,
        state,
        visible_len,
    ) {
        ctl.redraw();
    }
}
