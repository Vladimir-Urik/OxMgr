use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

use super::{
    DashboardState, DeleteConfirmChoice, DeleteConfirmLayout, EscMenuChoice, EscMenuLayout,
    ProcessSidebarLayout, TableArea, TableView,
};

pub(super) fn compute_table_view(height: usize, selected: usize) -> TableView {
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

pub(super) fn esc_menu_layout(width: usize, height: usize) -> Option<EscMenuLayout> {
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

pub(super) fn handle_menu_mouse(mouse: MouseEvent, layout: EscMenuLayout) -> Option<EscMenuChoice> {
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

pub(super) fn delete_confirm_layout(width: usize, height: usize) -> Option<DeleteConfirmLayout> {
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

pub(super) fn handle_delete_confirm_mouse(
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

pub(super) fn handle_table_mouse_selection(
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

pub(super) fn process_sidebar_layout(width: usize, height: usize) -> Option<ProcessSidebarLayout> {
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

pub(super) fn table_inner_width(
    width: usize,
    sidebar_layout: Option<ProcessSidebarLayout>,
) -> usize {
    if let Some(layout) = sidebar_layout {
        (layout.box_x as usize).saturating_sub(2)
    } else {
        width.saturating_sub(2)
    }
}
