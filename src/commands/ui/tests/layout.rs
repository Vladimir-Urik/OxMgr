use super::*;

#[test]
fn progress_bar_uses_requested_width() {
    let bar = progress_bar(50.0, 10);
    assert_eq!(bar.chars().count(), 10);
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
fn log_viewer_content_rows_reserves_header_space() {
    assert_eq!(log_viewer_content_rows(20), 14);
    assert_eq!(log_viewer_content_rows(6), 1);
}
