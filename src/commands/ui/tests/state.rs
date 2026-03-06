use super::*;

#[test]
fn prune_flash_returns_true_when_expired_message_removed() {
    let mut state = DashboardState {
        flash: Some(FlashMessage {
            text: "expired".to_string(),
            level: FlashLevel::Info,
            at: Instant::now() - Duration::from_secs(5),
        }),
        ..DashboardState::default()
    };

    assert!(state.prune_flash());
    assert!(state.flash.is_none());
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
    let mut state = DashboardState {
        selected: 2,
        ..DashboardState::default()
    };

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
    let mut state = DashboardState {
        selected: 1,
        ..DashboardState::default()
    };

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
fn open_delete_confirm_captures_process_identity() {
    let mut state = DashboardState::default();
    let process = sample_process();

    state.open_delete_confirm(&process);

    let confirm = state.delete_confirm.as_ref().expect("confirm should open");
    assert_eq!(confirm.target, "api");
    assert_eq!(confirm.label, "api (id 7)");
    assert_eq!(confirm.selected, DeleteConfirmChoice::Cancel);
}

#[test]
fn log_viewer_toggle_source_jumps_to_latest_tail() {
    let mut viewer = LogViewerState {
        process_name: "api".to_string(),
        stdout_path: "stdout.log".into(),
        stderr_path: "stderr.log".into(),
        stdout_lines: (0..10).map(|idx| format!("out-{idx}")).collect(),
        stderr_lines: (0..10).map(|idx| format!("err-{idx}")).collect(),
        active_source: LogSource::Stderr,
        scroll: 8,
        status: None,
    };

    viewer.toggle_source(4);

    assert_eq!(viewer.active_source, LogSource::Stdout);
    assert_eq!(viewer.scroll, 6);
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

#[test]
fn search_state_edits_and_clears_query() {
    let mut state = DashboardState::default();

    state.open_search();
    state.push_search_char('a');
    state.push_search_char('p');
    state.push_search_char('i');
    assert!(state.search_input_open);
    assert_eq!(state.search_query, "api");

    state.pop_search_char();
    assert_eq!(state.search_query, "ap");

    state.clear_search_query();
    state.close_search();
    assert_eq!(state.search_query, "");
    assert!(!state.search_input_open);
}

#[test]
fn visible_processes_applies_search_filter_and_sort() {
    let mut api = sample_process();
    api.id = 2;
    api.name = "api".to_string();
    api.namespace = Some("prod".to_string());
    api.cpu_percent = 10.0;
    api.memory_bytes = 128 * 1024 * 1024;
    api.restart_count = 1;
    api.status = ProcessStatus::Running;

    let mut worker = sample_process();
    worker.id = 1;
    worker.name = "worker".to_string();
    worker.command = "python".to_string();
    worker.args = vec!["worker.py".to_string()];
    worker.cpu_percent = 75.0;
    worker.memory_bytes = 512 * 1024 * 1024;
    worker.restart_count = 4;
    worker.status = ProcessStatus::Stopped;
    worker.health_status = HealthStatus::Unhealthy;

    let processes = vec![api, worker];
    let mut state = DashboardState {
        search_query: "work".to_string(),
        filter: ProcessFilter::All,
        sort: ProcessSort::Id,
        ..DashboardState::default()
    };

    let visible = visible_processes(&processes, &state);
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].name, "worker");

    state.search_query.clear();
    state.filter = ProcessFilter::Unhealthy;
    let visible = visible_processes(&processes, &state);
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].name, "worker");

    state.filter = ProcessFilter::All;
    state.sort = ProcessSort::Cpu;
    let visible = visible_processes(&processes, &state);
    assert_eq!(visible[0].name, "worker");

    state.sort = ProcessSort::Name;
    let visible = visible_processes(&processes, &state);
    assert_eq!(visible[0].name, "api");
}

#[test]
fn process_filter_and_sort_cycle_through_expected_values() {
    let mut state = DashboardState::default();

    state.cycle_filter();
    assert_eq!(state.filter, ProcessFilter::Running);
    state.cycle_filter();
    assert_eq!(state.filter, ProcessFilter::Stopped);
    state.cycle_filter();
    assert_eq!(state.filter, ProcessFilter::Unhealthy);
    state.cycle_filter();
    assert_eq!(state.filter, ProcessFilter::All);

    state.cycle_sort();
    assert_eq!(state.sort, ProcessSort::Name);
    state.cycle_sort();
    assert_eq!(state.sort, ProcessSort::Cpu);
    state.cycle_sort();
    assert_eq!(state.sort, ProcessSort::Ram);
    state.cycle_sort();
    assert_eq!(state.sort, ProcessSort::Restarts);
    state.cycle_sort();
    assert_eq!(state.sort, ProcessSort::Id);
}
