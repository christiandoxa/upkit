//! Interactive terminal interface.
use std::{
    collections::VecDeque,
    io::{self, stdout},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame,
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style, Stylize},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

struct TerminalSession {
    raw: bool,
    alternate: bool,
}

impl TerminalSession {
    fn start() -> io::Result<Self> {
        Self::start_with(|| execute!(stdout(), EnterAlternateScreen))
    }

    fn start_with(enter: impl FnOnce() -> io::Result<()>) -> io::Result<Self> {
        let mut session = Self {
            raw: false,
            alternate: false,
        };
        enable_raw_mode()?;
        session.raw = true;
        // An output error may occur after the escape sequence was partly written.
        session.alternate = true;
        enter()?;
        Ok(session)
    }

    fn restore(&mut self) -> io::Result<()> {
        let raw = if self.raw { disable_raw_mode() } else { Ok(()) };
        if raw.is_ok() {
            self.raw = false;
        }
        let alternate = if self.alternate {
            execute!(stdout(), LeaveAlternateScreen)
        } else {
            Ok(())
        };
        if alternate.is_ok() {
            self.alternate = false;
        }
        raw.and(alternate)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

use crate::{
    Ctx, ToolKind, ToolReport, application::diagnose_with_config, check_tools_parallel,
    ensure_dirs, update_tool,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Start {
    Dashboard,
    Toolchains,
    Doctor,
    Artifacts,
    Maintenance,
    Cache,
    Trash,
    Containers,
    Automation,
    Reports,
    Settings,
}

#[derive(Clone)]
enum DirectoryPlan {
    Artifact(crate::artifact_cleanup::ArtifactPlan),
    ArtifactBatch(crate::artifact_cleanup::ArtifactBatchPlan),
    Cache(crate::shared_cache_cleanup::CacheRemovalPlan),
}

#[derive(Clone)]
struct ManagedCleanupTarget {
    tool: ToolKind,
    plan: crate::managed_cleanup::CleanupPlan,
}

struct ManagedBatchItem {
    tool: ToolKind,
    status: &'static str,
    detail: Option<String>,
    history_warning: Option<String>,
}

struct ManagedBatchResult {
    items: Vec<ManagedBatchItem>,
    cancelled: bool,
}

#[derive(Debug)]
struct ManagedBatchPreviewFailure {
    tool: Option<ToolKind>,
    error: String,
    tools: Vec<ToolKind>,
    cancelled: bool,
}

impl DirectoryPlan {
    fn entries(&self) -> &[crate::artifact_cleanup::ArtifactEntry] {
        match self {
            Self::Artifact(plan) => &plan.entries,
            Self::ArtifactBatch(_) => &[],
            Self::Cache(plan) => &plan.entries,
        }
    }

    fn entry_count(&self) -> usize {
        match self {
            Self::Artifact(plan) => plan.entries.len(),
            Self::ArtifactBatch(plan) => plan.items.iter().map(|item| item.entries.len()).sum(),
            Self::Cache(plan) => plan.entries.len(),
        }
    }
}

#[derive(Clone, Copy, Default)]
enum ArtifactSort {
    #[default]
    Path,
    Size,
    Age,
}

impl ArtifactSort {
    fn next(self) -> Self {
        match self {
            Self::Path => Self::Size,
            Self::Size => Self::Age,
            Self::Age => Self::Path,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Size => "size (largest first; incomplete last)",
            Self::Age => "age (oldest first; unknown last)",
        }
    }

    fn compare(
        self,
        a: &crate::sweep::Candidate,
        b: &crate::sweep::Candidate,
    ) -> std::cmp::Ordering {
        match self {
            Self::Path => std::cmp::Ordering::Equal,
            Self::Size => b
                .size_complete
                .cmp(&a.size_complete)
                .then_with(|| b.logical_bytes.cmp(&a.logical_bytes)),
            Self::Age => match (a.modified_unix, b.modified_unix) {
                (Some(a), Some(b)) => a.cmp(&b),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            },
        }
        .then_with(|| a.target.cmp(&b.target))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum CacheSort {
    #[default]
    Name,
    Size,
    Risk,
}

impl CacheSort {
    fn next(self) -> Self {
        match self {
            Self::Name => Self::Size,
            Self::Size => Self::Risk,
            Self::Risk => Self::Name,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Size => "logical size (complete first; largest first; unknown last)",
            Self::Risk => "risk (observed activity and uncertainty first)",
        }
    }

    fn compare(
        self,
        a: &crate::cache::CacheEntry,
        b: &crate::cache::CacheEntry,
    ) -> std::cmp::Ordering {
        use std::cmp::Ordering;

        match self {
            Self::Name => Ordering::Equal,
            Self::Size => match (a.logical_bytes, b.logical_bytes) {
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (Some(a_size), Some(b_size)) => b
                    .size_complete
                    .cmp(&a.size_complete)
                    .then_with(|| b_size.cmp(&a_size)),
                (None, None) => Ordering::Equal,
            },
            Self::Risk => cache_risk_rank(a).cmp(&cache_risk_rank(b)),
        }
        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        .then_with(|| a.path.cmp(&b.path))
    }
}

fn cache_risk_rank(entry: &crate::cache::CacheEntry) -> u8 {
    if matches!(
        entry.activity_status,
        "open_handles_or_cwd_observed" | "executable_observed"
    ) {
        0
    } else if entry.status != "inventory only"
        || !entry.size_complete
        || entry.logical_bytes.is_none()
        || entry.activity_status != "no_open_handles_or_cwd_observed"
        || entry.directory_owner_status != "current_user"
        || !entry.warnings.is_empty()
        || entry
            .go_test_cache
            .as_ref()
            .is_some_and(|cache| cache.status == "unavailable")
    {
        1
    } else {
        2
    }
}

#[cfg(target_os = "linux")]
fn temp_cleanup_candidate_line(
    app: &App,
    index: usize,
    candidate: &crate::temp_cleanup::Candidate,
) -> String {
    format!(
        "{}[{}] {}  age={}d  {}",
        if index == app.temp_selected {
            "›"
        } else {
            " "
        },
        if app.temp_marks.contains(&candidate.path) {
            "x"
        } else {
            " "
        },
        candidate.status,
        candidate
            .age_days
            .map_or("unknown".into(), |days| days.to_string()),
        crate::sweep::display_path(&candidate.path)
    )
}

#[cfg(target_os = "linux")]
fn temp_cleanup_candidate_lines(app: &App, plan: &crate::temp_cleanup::Plan) -> Vec<String> {
    plan.candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| temp_cleanup_candidate_line(app, index, candidate))
        .collect()
}

fn temp_cleanup_screen_scroll(app: &App, area: Rect) -> u16 {
    #[cfg(target_os = "linux")]
    if app.temp_mode && app.temp_result.is_some() && app.temp_plan.is_none() {
        let width = area.width.saturating_sub(2);
        let visible = area.height.saturating_sub(2) as usize;
        let total = Paragraph::new(temp_cleanup_content(app))
            .wrap(Wrap { trim: false })
            .line_count(width);
        return app
            .temp_result_scroll
            .min(total.saturating_sub(visible).min(u16::MAX as usize) as u16);
    }
    if app.temp_mode && app.temp_plan.is_some() {
        let width = area.width.saturating_sub(2);
        let visible = area.height.saturating_sub(2) as usize;
        if width == 0 || visible == 0 {
            return 0;
        }
        #[cfg(target_os = "linux")]
        let selected_scroll = if let Some(Ok(plan)) = &app.temp_plan
            && plan.supported
            && let Some(candidate) = plan.candidates.get(app.temp_selected)
        {
            let candidates = temp_cleanup_candidate_lines(app, plan);
            let prefix = std::iter::once(
                "Review abandoned Upkit symlink staging directories (30-day minimum age)."
                    .to_owned(),
            )
            .chain(std::iter::once(
                "Only eligible, inactive staging directories can be selected; the linked target is never removed."
                    .to_owned(),
            ))
            .chain(candidates.iter().take(app.temp_selected).cloned())
            .collect::<Vec<_>>()
            .join("\n");
            let before = Paragraph::new(prefix)
                .wrap(Wrap { trim: false })
                .line_count(width);
            let selected = Paragraph::new(temp_cleanup_candidate_line(
                app,
                app.temp_selected,
                candidate,
            ))
            .wrap(Wrap { trim: false })
            .line_count(width);
            before.saturating_add(selected).saturating_sub(visible)
        } else {
            0
        };
        #[cfg(not(target_os = "linux"))]
        let selected_scroll = 0;
        let total = Paragraph::new(temp_cleanup_content(app))
            .wrap(Wrap { trim: false })
            .line_count(width);
        let max_scroll = total.saturating_sub(visible).min(u16::MAX as usize);
        return (selected_scroll.min(max_scroll) as i32)
            .saturating_add(app.temp_inventory_scroll_offset)
            .clamp(0, max_scroll as i32) as u16;
    }
    let _ = (app, area);
    0
}

fn temp_cleanup_content(app: &App) -> String {
    if app.temp_preparing {
        return "Inspecting Upkit link staging directories…\nEsc: cancel".into();
    }
    if app.temp_running {
        return "Removing reviewed staging directories in the background…\nEsc: request cancellation; the current item may finish.".into();
    }
    let mut lines = vec![
        "Review abandoned Upkit symlink staging directories (30-day minimum age).".into(),
        "Only eligible, inactive staging directories can be selected; the linked target is never removed.".into(),
    ];
    match &app.temp_plan {
        None => lines.push("Press r to inspect managed Upkit roots and its bindir.".into()),
        Some(Err(error)) => lines.push(format!(
            "Inventory failed: {}",
            schedule_escape_controls(error)
        )),
        Some(Ok(plan)) if !plan.supported => {
            #[cfg(not(target_os = "linux"))]
            lines.push(plan.warning.into());
            #[cfg(target_os = "linux")]
            lines.push("Stale link staging cleanup is unavailable on this platform.".into());
        }
        #[cfg(target_os = "linux")]
        Some(Ok(plan)) => {
            if plan.candidates.is_empty() {
                lines.push("No staging candidates found.".into());
            } else {
                lines.extend(temp_cleanup_candidate_lines(app, plan));
            }
            lines.push(format!(
                "Selected: {}  Complete inventory: {}",
                app.temp_marks.len(),
                plan.complete
            ));
            lines.extend(
                plan.warnings
                    .iter()
                    .map(|warning| format!("Warning: {}", schedule_escape_controls(warning))),
            );
        }
        #[cfg(not(target_os = "linux"))]
        Some(Ok(_)) => {}
    }
    if let Some(result) = &app.temp_result {
        lines.push(String::new());
        lines.push(result.clone());
    }
    lines.join("\n")
}

fn temp_cleanup_review_content(
    plan: &crate::temp_cleanup::Plan,
    confirm: bool,
    dry_run: bool,
) -> String {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (confirm, dry_run);
        format!("{}\nEsc: cancel", plan.warning)
    }
    #[cfg(target_os = "linux")]
    {
        let mut lines = if confirm {
            vec![
                "Confirm permanent removal of the explicitly selected staging directories:".into(),
                "The operation revalidates each candidate; link targets are preserved.".into(),
            ]
        } else {
            vec![
                format!(
                    "Review the complete staging inventory: {} candidate(s), {} selected.",
                    plan.candidates.len(),
                    plan.selected_count
                ),
                format!(
                    "Inventory complete: {}. Minimum age: {} days.",
                    plan.complete, plan.retention_days
                ),
                "Review every candidate and warning before continuing.".into(),
            ]
        };
        if confirm {
            lines.extend(
                plan.candidates
                    .iter()
                    .filter(|candidate| candidate.selected)
                    .map(|candidate| {
                        format!(
                            "Selected: {}  ({} days old)",
                            crate::sweep::display_path(&candidate.path),
                            candidate
                                .age_days
                                .map_or("unknown".into(), |days| days.to_string())
                        )
                    }),
            );
        } else {
            lines.extend(plan.candidates.iter().map(|candidate| {
                format!(
                    "{} {}  age={}d  {}",
                    if candidate.selected {
                        "[selected]"
                    } else {
                        "[not selected]"
                    },
                    candidate.status,
                    candidate
                        .age_days
                        .map_or("unknown".into(), |days| days.to_string()),
                    crate::sweep::display_path(&candidate.path)
                )
            }));
        }
        lines.extend(
            plan.warnings
                .iter()
                .map(|warning| format!("Warning: {}", schedule_escape_controls(warning))),
        );
        lines.push("Removal is limited to inactive Upkit-created link staging directories.".into());
        if confirm && dry_run {
            lines.push(
                "Dry run is enabled: confirming will not remove files or write history.".into(),
            );
        }
        lines.push(if confirm {
            "↑/↓: scroll  y: confirm at end  Esc: cancel".into()
        } else {
            "↑/↓: scroll  Enter: continue at end  Esc: cancel".into()
        });
        lines.join("\n")
    }
}

fn temp_cleanup_review_metrics(
    plan: &crate::temp_cleanup::Plan,
    confirm: bool,
    dry_run: bool,
    area: Rect,
) -> (usize, usize) {
    let modal = centered(
        area,
        area.width.saturating_sub(4),
        area.height.saturating_sub(6),
    );
    let width = modal.width.saturating_sub(2);
    let text = temp_cleanup_review_content(plan, confirm, dry_run);
    let lines = Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .line_count(width);
    (lines, modal.height.saturating_sub(2) as usize)
}

fn temp_cleanup_review_complete(
    plan: &crate::temp_cleanup::Plan,
    confirm: bool,
    dry_run: bool,
    scroll: u16,
    area: Rect,
) -> bool {
    let (lines, rows) = temp_cleanup_review_metrics(plan, confirm, dry_run, area);
    rows > 0 && scroll as usize + rows >= lines
}

#[cfg(target_os = "linux")]
enum TrashRetentionReviewPlan {
    Install(crate::schedule::trash_retention::TrashRetentionSchedulePreview),
    Enable(crate::schedule::trash_retention::TrashRetentionActionPreview),
    Disable(crate::schedule::trash_retention::TrashRetentionActionPreview),
    Remove(crate::schedule::trash_retention::TrashRetentionActionPreview),
}

#[cfg(target_os = "linux")]
const TRASH_RETENTION_DEFAULT_AGE_SECONDS: u64 = 30 * 24 * 60 * 60;

#[cfg(target_os = "linux")]
fn trash_retention_action_available(app: &App, key: KeyEvent) -> bool {
    app.page == Start::Automation
        && SchedulePlatform::current() == SchedulePlatform::Systemd
        && !app.schedule_running
        && !app.schedule_read_only
        && app.schedule_edit_plan.is_none()
        && app.schedule_remove_plan.is_none()
        && app.schedule_install_plan.is_none()
        && app.schedule_enable_plan.is_none()
        && app.schedule_disable_plan.is_none()
        && !app.schedule_edit_preparing
        && !app.schedule_edit_running
        && !app.schedule_remove_preparing
        && !app.schedule_remove_running
        && !app.schedule_install_preparing
        && !app.schedule_install_running
        && !app.schedule_enable_preparing
        && !app.schedule_enable_running
        && !app.schedule_disable_preparing
        && !app.schedule_disable_running
        && !app.trash_retention_preparing
        && !app.trash_retention_running
        && !app.updating
        && !app.trim_running
        && !app.container_removing
        && !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

fn toolchain_confirmation_key(key: KeyEvent) -> bool {
    matches!(key.code, KeyCode::Enter | KeyCode::Char('y'))
        && !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

struct App {
    reports: Option<Vec<ToolReport>>,
    startup_checks: StartupChecks,
    toolchain_check_failed: bool,
    maintenance_check_failed: bool,
    page: Start,
    help: bool,
    help_scroll: u16,
    selected: usize,
    confirmation: bool,
    updating: bool,
    self_update_preparing: bool,
    self_update_command: bool,
    self_update_plan: Option<crate::application::SelfUpdatePlan>,
    message: String,
    issues: Option<Vec<String>>,
    doctor_available_bytes: Option<u64>,
    doctor_capabilities: Option<crate::doctor::Capabilities>,
    doctor_scroll: u16,
    doctor_filter: String,
    doctor_search: Option<String>,
    dashboard_scroll: u16,
    marked: Vec<ToolKind>,
    toolchain_filter: String,
    toolchain_search: Option<String>,
    force: bool,
    managed_mode: bool,
    managed_scope: Option<Vec<ToolKind>>,
    managed_preparing: bool,
    managed_running: bool,
    managed_plan: Option<crate::managed_cleanup::CleanupPlan>,
    managed_batch_plans: Vec<ManagedCleanupTarget>,
    managed_batch_review_scroll: usize,
    managed_batch_review_rows: usize,
    managed_batch_review_lines: usize,
    managed_batch_review_area: Rect,
    managed_batch_review_content: Option<Vec<String>>,
    managed_current: Option<ToolKind>,
    managed_detail: bool,
    managed_detail_scroll: u16,
    managed_result: Option<String>,
    managed_result_scroll: u16,
    scan: Option<Result<crate::sweep::ScanReport, String>>,
    scan_running: bool,
    scan_visited: usize,
    scan_scroll: u16,
    artifact_filter: String,
    artifact_sort: ArtifactSort,
    artifact_marks: Vec<PathBuf>,
    artifact_search: Option<String>,
    preview_mode: bool,
    cli_preview_read_only: bool,
    plan: Option<Result<crate::sweep::CleanupPlan, String>>,
    plan_detail: bool,
    detail_scroll: u16,
    artifact_preparing: bool,
    artifact_running: bool,
    artifact_plan: Option<DirectoryPlan>,
    artifact_review_scroll: usize,
    artifact_review_rows: usize,
    artifact_review_lines: usize,
    artifact_review_width: u16,
    artifact_review_content: Option<Vec<String>>,
    artifact_confirm: bool,
    bytecode_preparing: bool,
    bytecode_running: bool,
    bytecode_plan: Option<crate::bytecode::BytecodePlan>,
    bytecode_batch_plan: Option<crate::bytecode::BytecodeBatchPlan>,
    bytecode_listing_running: bool,
    bytecode_listing: Option<BytecodeListing>,
    bytecode_selected: usize,
    bytecode_marks: Vec<PathBuf>,
    maintenance: Option<crate::maintenance::TrimStatus>,
    trim_selected: usize,
    trim_preparing: bool,
    trim_running: bool,
    trim_plan: Option<crate::maintenance::TrimPlan>,
    trim_read_only: bool,
    dry_run: bool,
    temp_mode: bool,
    temp_plan: Option<Result<crate::temp_cleanup::Plan, String>>,
    temp_marks: Vec<PathBuf>,
    temp_selected: usize,
    temp_preparing: bool,
    temp_running: bool,
    temp_review_plan: Option<crate::temp_cleanup::Plan>,
    temp_review_confirm: bool,
    temp_review_scroll: u16,
    temp_review_rows: usize,
    temp_review_lines: usize,
    temp_review_area: Rect,
    temp_result: Option<String>,
    temp_result_scroll: u16,
    temp_inventory_scroll_offset: i32,
    cache: Option<crate::cache::CacheReport>,
    cache_running: bool,
    cache_scroll: u16,
    cache_filter: String,
    cache_sort: CacheSort,
    cache_details: bool,
    cache_search: Option<String>,
    cache_choosing: bool,
    cache_selected: Option<PathBuf>,
    go_test_preparing: bool,
    go_test_running: bool,
    go_test_plan: Option<crate::cache::GoTestExpirationPlan>,
    go_test_read_only: bool,
    trash: Option<crate::trash::TrashReport>,
    trash_preview: Option<Result<crate::trash::RetentionPreview, String>>,
    trash_age: Option<Duration>,
    trash_running: bool,
    trash_scroll: u16,
    trash_selected: usize,
    trash_review: bool,
    trash_review_scroll: u16,
    trash_removal_preparing: bool,
    trash_marking: bool,
    trash_removing: bool,
    trash_removal_plan: Option<crate::trash::TrashBatchPlan>,
    trash_last_result: Option<crate::trash::TrashBatchResult>,
    containers: Option<Vec<crate::containers::EngineStatus>>,
    containers_running: bool,
    containers_scroll: u16,
    container_selected: usize,
    container_filter: String,
    container_search: Option<String>,
    container_preparing: bool,
    container_removing: bool,
    container_plan: Option<crate::containers::RemovalPlan>,
    network_preparing: bool,
    network_removing: bool,
    network_plan: Option<crate::containers::NetworkRemovalPlan>,
    build_cache_preparing: bool,
    build_cache_removing: bool,
    build_cache_plan: Option<crate::containers::BuildCacheRemovalPlan>,
    build_cache_read_only: bool,
    schedule: Option<crate::maintenance::TimerStatus>,
    schedule_running: bool,
    schedule_scroll: u16,
    schedule_read_only: bool,
    schedule_preview_scroll: u16,
    schedule_confirmation_scroll: usize,
    schedule_confirmation_area: Rect,
    schedule_confirmation_identity: Option<String>,
    schedule_confirmation_content: Option<Vec<String>>,
    schedule_edit_preparing: bool,
    schedule_edit_running: bool,
    schedule_edit_plan: Option<(
        crate::schedule::EditSchedulePreview,
        crate::schedule::Frequency,
    )>,
    schedule_remove_preparing: bool,
    schedule_remove_running: bool,
    schedule_remove_plan: Option<crate::schedule::RemoveSchedulePreview>,
    schedule_disable_preparing: bool,
    schedule_disable_running: bool,
    schedule_disable_plan: Option<crate::schedule::DisableSchedulePreview>,
    schedule_install_preparing: bool,
    schedule_install_running: bool,
    schedule_install_plan: Option<(
        crate::schedule::ScanSchedulePreview,
        crate::schedule::Frequency,
    )>,
    schedule_enable_preparing: bool,
    schedule_enable_running: bool,
    schedule_enable_plan: Option<(
        crate::schedule::EnableSchedulePreview,
        crate::schedule::Frequency,
    )>,
    #[cfg(target_os = "linux")]
    trash_retention_status:
        Option<Result<crate::schedule::trash_retention::TrashRetentionStatus, String>>,
    #[cfg(target_os = "linux")]
    trash_retention_status_loading: bool,
    #[cfg(target_os = "linux")]
    trash_retention_preparing: bool,
    #[cfg(target_os = "linux")]
    trash_retention_running: bool,
    #[cfg(target_os = "linux")]
    trash_retention_plan: Option<TrashRetentionReviewPlan>,
    history: Option<Result<crate::reports::History, String>>,
    history_running: bool,
    history_scroll: u16,
    history_oldest_first: bool,
    history_filter: String,
    history_search: Option<String>,
    history_purge_preparing: bool,
    history_purging: bool,
    history_purge_read_only: bool,
    history_purge_plan: Option<crate::reports::HistoryPurgePlan>,
    history_purge_result: Option<crate::reports::HistoryPurgeResult>,
    history_purge_warning: Option<String>,
    history_purge_scroll: u16,
    history_purge_area: Rect,
    history_purge_content: Option<Vec<String>>,
    settings: Option<Result<crate::config::ConfigDocument, String>>,
    settings_loading: bool,
    theme: crate::config::Theme,
    settings_saving: bool,
    settings_editor: Option<ConfigEditor>,
    settings_form: Option<SettingsForm>,
    settings_pending_save: Option<SettingsPendingSave>,
    settings_prompt: Option<SettingsPrompt>,
    settings_scroll: u16,
    settings_confirmation_scroll: u16,
    settings_confirmation_area: Rect,
}

#[derive(Clone, Copy, Default)]
struct StartupChecks {
    toolchains: bool,
    doctor: bool,
    maintenance: bool,
}

enum Action {
    None,
    Quit,
    Update(Vec<ToolKind>),
    PreviewSelfUpdate,
    SelfUpdate(crate::application::SelfUpdatePlan),
    PreviewManaged(ToolKind),
    PreviewManagedBatch(Vec<ToolKind>),
    RemoveManaged(crate::managed_cleanup::CleanupPlan),
    RemoveManagedBatch(Vec<ManagedCleanupTarget>),
    CancelManaged,
    CancelScan,
    CancelDoctor,
    CancelTemp,
    PreviewTempCleanup(Vec<PathBuf>, bool),
    #[cfg(target_os = "linux")]
    RemoveTempCleanup(crate::temp_cleanup::Plan),
    StartArtifactScan {
        configured: bool,
    },
    PreviewArtifact(PathBuf),
    PreviewArtifactBatch(Vec<PathBuf>),
    RemoveArtifact(crate::artifact_cleanup::ArtifactPlan),
    RemoveArtifactBatch(crate::artifact_cleanup::ArtifactBatchPlan),
    PreviewSharedCache(PathBuf),
    RemoveSharedCache(crate::shared_cache_cleanup::CacheRemovalPlan),
    ListBytecode(PathBuf),
    PreviewBytecode(PathBuf),
    RemoveBytecode(crate::bytecode::BytecodePlan),
    PreviewBytecodeBatch(Vec<PathBuf>),
    RemoveBytecodeBatch(crate::bytecode::BytecodeBatchPlan),
    CancelCache,
    StartCache,
    PreviewGoTest(PathBuf),
    ExpireGoTest(crate::cache::GoTestExpirationPlan),
    StartTrash(Option<Duration>),
    CancelTrash,
    PreviewTrashRemoval(crate::trash::RetentionPreview),
    SelectOldTrash(crate::trash::RetentionPreview, PathBuf),
    RemoveTrash(crate::trash::TrashBatchPlan),
    StartContainers,
    PreviewContainer(String, String),
    RemoveContainer(crate::containers::RemovalPlan),
    PreviewNetwork(String, String),
    RemoveNetwork(crate::containers::NetworkRemovalPlan),
    PreviewBuildCache(String, String),
    RemoveBuildCache(crate::containers::BuildCacheRemovalPlan),
    RefreshToolchains,
    RefreshHistory,
    RefreshSchedule,
    PreviewScheduleEdit(crate::schedule::Frequency),
    EditSchedule(
        crate::schedule::EditSchedulePreview,
        crate::schedule::Frequency,
    ),
    PreviewScheduleRemove,
    RemoveSchedule(crate::schedule::RemoveSchedulePreview),
    PreviewScheduleDisable,
    DisableSchedule(crate::schedule::DisableSchedulePreview),
    PreviewScheduleInstall(crate::schedule::Frequency, bool),
    InstallSchedule(
        crate::schedule::ScanSchedulePreview,
        crate::schedule::Frequency,
    ),
    PreviewScheduleEnable(crate::schedule::Frequency),
    EnableSchedule(
        crate::schedule::EnableSchedulePreview,
        crate::schedule::Frequency,
    ),
    #[cfg(target_os = "linux")]
    PreviewTrashRetentionInstall(PathBuf, Duration),
    #[cfg(target_os = "linux")]
    PreviewTrashRetentionEnable,
    #[cfg(target_os = "linux")]
    PreviewTrashRetentionDisable,
    #[cfg(target_os = "linux")]
    PreviewTrashRetentionRemove,
    #[cfg(target_os = "linux")]
    InstallTrashRetention(crate::schedule::trash_retention::TrashRetentionSchedulePreview),
    #[cfg(target_os = "linux")]
    EnableTrashRetention(crate::schedule::trash_retention::TrashRetentionActionPreview),
    #[cfg(target_os = "linux")]
    DisableTrashRetention(crate::schedule::trash_retention::TrashRetentionActionPreview),
    #[cfg(target_os = "linux")]
    RemoveTrashRetention(crate::schedule::trash_retention::TrashRetentionActionPreview),
    PreviewHistoryPurge(Duration),
    PurgeHistory(crate::reports::HistoryPurgePlan),
    CancelHistoryPurge,
    RefreshDoctor,
    LoadSettings,
    SaveSettings(crate::config::ConfigDocument, String),
    PreviewTrim(PathBuf),
    RunTrim(crate::maintenance::TrimPlan),
}

struct BytecodeListing {
    cache: PathBuf,
    files: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SettingsPrompt {
    Save,
    Discard,
}

struct SettingsPendingSave {
    snapshot: crate::config::ConfigDocument,
    text: String,
    cleanup_impacts: Vec<String>,
    changes: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsField {
    WorkspaceRoots,
    Exclusions,
    ArtifactRetention,
    EnabledEcosystems,
    ScheduledBytecodeCleanup,
    ScheduledArtifactCleanup,
    ScheduledTrashRetention,
    ScheduleFrequency,
    Theme,
}

#[derive(Clone, PartialEq, Eq)]
struct SettingsTarget {
    profile: Option<String>,
    field: SettingsField,
}

#[derive(Clone, Copy)]
enum SettingsRow {
    Profile,
    Root(usize),
    AddRoot,
    Exclusion(usize),
    AddExclusion,
    Retention,
    Ecosystem(crate::sweep::Ecosystem),
    AllEcosystems,
    ScheduledCleanup,
    ScheduledArtifactCleanup,
    ScheduledTrashRetention,
    ScheduleFrequency,
    Theme,
}

#[derive(Clone)]
struct SettingsInput {
    target: SettingsTarget,
    new_profile: bool,
    index: Option<usize>,
    value: Vec<char>,
    cursor: usize,
}

struct SettingsForm {
    snapshot: crate::config::ConfigDocument,
    settings: crate::config::Settings,
    profile: Option<String>,
    selected: usize,
    dirty: Vec<SettingsTarget>,
    input: Option<SettingsInput>,
}

const SETTINGS_ECOSYSTEMS: [crate::sweep::Ecosystem; 14] = [
    crate::sweep::Ecosystem::Cargo,
    crate::sweep::Ecosystem::Go,
    crate::sweep::Ecosystem::Zig,
    crate::sweep::Ecosystem::Cmake,
    crate::sweep::Ecosystem::Meson,
    crate::sweep::Ecosystem::Ninja,
    crate::sweep::Ecosystem::Gradle,
    crate::sweep::Ecosystem::Maven,
    crate::sweep::Ecosystem::Sbt,
    crate::sweep::Ecosystem::Dotnet,
    crate::sweep::Ecosystem::Flutter,
    crate::sweep::Ecosystem::Dart,
    crate::sweep::Ecosystem::Python,
    crate::sweep::Ecosystem::Javascript,
];

struct ConfigEditor {
    snapshot: crate::config::ConfigDocument,
    lines: Vec<Vec<char>>,
    row: usize,
    column: usize,
    bytes: usize,
}

fn is_bidi_control(character: char) -> bool {
    matches!(character as u32, 0x061c | 0x200e..=0x200f | 0x202a..=0x202e | 0x2066..=0x2069)
}

fn config_display_character(character: char) -> char {
    if character.is_control() || is_bidi_control(character) {
        '�'
    } else {
        character
    }
}

fn settings_error(error: &str) -> String {
    error
        .chars()
        .take(512)
        .map(config_display_character)
        .collect()
}

fn document_theme(document: &crate::config::ConfigDocument) -> Option<crate::config::Theme> {
    let settings: crate::config::Settings = toml::from_str(&document.text).ok()?;
    settings.validate().ok()?;
    Some(settings.theme)
}

impl ConfigEditor {
    fn new(snapshot: crate::config::ConfigDocument) -> Self {
        let bytes = snapshot.text.len();
        let lines = snapshot
            .text
            .split('\n')
            .map(|line| line.chars().collect())
            .collect();
        Self {
            snapshot,
            lines,
            row: 0,
            column: 0,
            bytes,
        }
    }

    fn text(&self) -> String {
        self.lines
            .iter()
            .map(|line| line.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn insert(&mut self, character: char) -> bool {
        let len = character.len_utf8();
        if self.bytes + len > crate::config::MAX_EDIT_BYTES as usize {
            return false;
        }
        self.lines[self.row].insert(self.column, character);
        self.column += 1;
        self.bytes += len;
        true
    }

    fn key(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Left if self.column > 0 => self.column -= 1,
            KeyCode::Left if self.row > 0 => {
                self.row -= 1;
                self.column = self.lines[self.row].len();
            }
            KeyCode::Right if self.column < self.lines[self.row].len() => self.column += 1,
            KeyCode::Right if self.row + 1 < self.lines.len() => {
                self.row += 1;
                self.column = 0;
            }
            KeyCode::Up if self.row > 0 => {
                self.row -= 1;
                self.column = self.column.min(self.lines[self.row].len());
            }
            KeyCode::Down if self.row + 1 < self.lines.len() => {
                self.row += 1;
                self.column = self.column.min(self.lines[self.row].len());
            }
            KeyCode::Home => self.column = 0,
            KeyCode::End => self.column = self.lines[self.row].len(),
            KeyCode::Char(character) if !character.is_control() => return self.insert(character),
            KeyCode::Tab => {
                if self.bytes + 4 > crate::config::MAX_EDIT_BYTES as usize {
                    return false;
                }
                for _ in 0..4 {
                    self.insert(' ');
                }
            }
            KeyCode::Enter => {
                if self.bytes >= crate::config::MAX_EDIT_BYTES as usize {
                    return false;
                }
                let next = self.lines[self.row].split_off(self.column);
                self.row += 1;
                self.column = 0;
                self.bytes += 1;
                self.lines.insert(self.row, next);
            }
            KeyCode::Backspace if self.column > 0 => {
                self.column -= 1;
                self.bytes -= self.lines[self.row].remove(self.column).len_utf8();
            }
            KeyCode::Backspace if self.row > 0 => {
                let current = self.lines.remove(self.row);
                self.row -= 1;
                self.column = self.lines[self.row].len();
                self.lines[self.row].extend(current);
                self.bytes -= 1;
            }
            KeyCode::Delete if self.column < self.lines[self.row].len() => {
                self.bytes -= self.lines[self.row].remove(self.column).len_utf8();
            }
            KeyCode::Delete if self.row + 1 < self.lines.len() => {
                let next = self.lines.remove(self.row + 1);
                self.lines[self.row].extend(next);
                self.bytes -= 1;
            }
            _ => {}
        }
        true
    }
}

impl SettingsForm {
    fn new(snapshot: crate::config::ConfigDocument) -> Result<Self> {
        let settings: crate::config::Settings = toml::from_str(&snapshot.text)?;
        settings.validate()?;
        Ok(Self {
            snapshot,
            settings,
            profile: None,
            selected: 0,
            dirty: Vec::new(),
            input: None,
        })
    }

    fn target(&self, field: SettingsField) -> SettingsTarget {
        SettingsTarget {
            profile: self.profile.clone(),
            field,
        }
    }

    fn mark_dirty(&mut self, target: SettingsTarget) {
        if !self.dirty.contains(&target) {
            self.dirty.push(target);
        }
    }

    fn has_changes(&self) -> Result<bool> {
        let original: crate::config::Settings = toml::from_str(&self.snapshot.text)?;
        Ok(self.settings.profiles.keys().ne(original.profiles.keys())
            || self
                .dirty
                .iter()
                .any(|target| !settings_field_equal(&self.settings, &original, target)))
    }

    fn save_text(&self) -> Result<String> {
        self.settings.validate()?;
        let original: crate::config::Settings = toml::from_str(&self.snapshot.text)?;
        let mut text = self.snapshot.text.clone();
        for name in self
            .settings
            .profiles
            .keys()
            .filter(|name| !original.profiles.contains_key(*name))
        {
            let ending = if text.contains("\r\n") { "\r\n" } else { "\n" };
            if !text.is_empty() && !text.ends_with('\n') {
                text.push_str(ending);
            }
            text.push_str(&format!("{ending}[profiles.{name}]{ending}"));
        }
        for target in &self.dirty {
            if settings_field_equal(&self.settings, &original, target) {
                continue;
            }
            let value = settings_field_toml_value(&self.settings, target)?;
            text = patch_config_assignment(
                &text,
                target.profile.as_deref(),
                settings_field_key(target.field),
                value.as_deref(),
            )?;
        }
        crate::config::validate_document(&text)?;
        Ok(text)
    }

    fn cleanup_impacts(&self) -> Result<Vec<String>> {
        let original: crate::config::Settings = toml::from_str(&self.snapshot.text)?;
        let mut impacts = Vec::new();
        if self.dirty.iter().any(|target| {
            target.field == SettingsField::ScheduleFrequency
                && !settings_field_equal(&self.settings, &original, target)
        }) {
            impacts.push("Frequency defaults affect future schedule previews; saving does not change an existing timer.".into());
        }
        for target in &self.dirty {
            if target.field == SettingsField::ScheduledTrashRetention
                && !settings_field_equal(&self.settings, &original, target)
            {
                impacts.push(scheduled_trash_retention_impact(
                    self.settings.scheduled_trash_retention,
                ));
                continue;
            }
            if target.field == SettingsField::ScheduledArtifactCleanup
                && !settings_field_equal(&self.settings, &original, target)
            {
                impacts.push(scheduled_artifact_cleanup_impact(
                    target.profile.as_deref().unwrap_or("global defaults"),
                    settings_artifact_cleanup_value(&self.settings, target.profile.as_deref()),
                ));
                continue;
            }
            if target.field != SettingsField::ScheduledBytecodeCleanup
                || settings_field_equal(&self.settings, &original, target)
            {
                continue;
            }
            let enabled = settings_cleanup_value(&self.settings, target.profile.as_deref());
            impacts.push(scheduled_cleanup_impact(
                target.profile.as_deref().unwrap_or("global defaults"),
                enabled,
            ));
        }
        Ok(impacts)
    }

    fn move_profile(&mut self, forward: bool) {
        let mut scopes = vec![None];
        scopes.extend(self.settings.profiles.keys().cloned().map(Some));
        let current = scopes
            .iter()
            .position(|profile| *profile == self.profile)
            .unwrap_or(0);
        let next = if forward {
            (current + 1) % scopes.len()
        } else {
            (current + scopes.len() - 1) % scopes.len()
        };
        self.profile = scopes[next].clone();
        self.selected = 0;
    }
}

fn scheduled_cleanup_impact(scope: &str, enabled: bool) -> String {
    if enabled {
        format!(
            "Scheduled bytecode cleanup will be enabled for {scope}. A later configured timer install or re-enable can permanently remove eligible Python bytecode (up to 32 files per run; retention must be at least 7 days). Saving does not install or change a timer."
        )
    } else {
        format!(
            "Scheduled bytecode cleanup will be disabled for {scope}. Saving does not edit an installed timer; policy changes can make its next run stop for review."
        )
    }
}

fn scheduled_artifact_cleanup_impact(scope: &str, enabled: bool) -> String {
    if enabled {
        format!(
            "Scheduled artifact cleanup policy will be enabled for {scope}. Cargo is excluded from scheduled cleanup; scheduled removal is limited to Maven targets, Zig cache, Dart generated state, and Python pytest/mypy caches. Installation still requires a separate preview and confirmation. Each removal reserves a local history attempt; a failed write can leave an incomplete record. Saving does not install or change a timer."
        )
    } else {
        format!(
            "Scheduled artifact cleanup policy will be disabled for {scope}. An existing timer can still trigger, but its policy is rechecked before cleanup. Saving does not disable or remove the timer."
        )
    }
}

fn scheduled_trash_retention_impact(enabled: bool) -> String {
    if enabled {
        "Scheduled Trash retention opt-in will be enabled. An installed timer may permanently delete matching Trash items at its bound location; saving does not install or change the timer. Review the location and age threshold in Automation.".into()
    } else {
        "Scheduled Trash retention opt-in will be disabled. An installed timer will fail closed on its next run; saving does not disable or remove the timer.".into()
    }
}

fn settings_cleanup_impacts_between(
    snapshot: &crate::config::ConfigDocument,
    text: &str,
) -> Result<Vec<String>> {
    let current: crate::config::Settings = toml::from_str(text)?;
    let original = toml::from_str::<crate::config::Settings>(&snapshot.text).ok();
    let mut impacts = Vec::new();
    let old_global = original
        .as_ref()
        .map(|settings| settings.scheduled_bytecode_cleanup);
    if original.as_ref().is_none_or(|previous| {
        previous.schedule_frequency != current.schedule_frequency
            || previous
                .profiles
                .keys()
                .chain(current.profiles.keys())
                .any(|name| {
                    previous
                        .profiles
                        .get(name)
                        .and_then(|profile| profile.schedule_frequency)
                        != current
                            .profiles
                            .get(name)
                            .and_then(|profile| profile.schedule_frequency)
                })
    }) {
        impacts.push("Frequency defaults affect future schedule previews; saving does not change an existing timer.".into());
    }
    if old_global != Some(current.scheduled_bytecode_cleanup) {
        impacts.push(scheduled_cleanup_impact(
            "global defaults",
            current.scheduled_bytecode_cleanup,
        ));
    }
    if original.as_ref().is_none_or(|previous| {
        previous.scheduled_artifact_cleanup != current.scheduled_artifact_cleanup
    }) {
        impacts.push(scheduled_artifact_cleanup_impact(
            "global defaults",
            current.scheduled_artifact_cleanup,
        ));
    }
    if original.as_ref().is_none_or(|previous| {
        previous.scheduled_trash_retention != current.scheduled_trash_retention
    }) {
        impacts.push(scheduled_trash_retention_impact(
            current.scheduled_trash_retention,
        ));
    }
    let profiles = original
        .iter()
        .flat_map(|settings| settings.profiles.keys().cloned())
        .chain(current.profiles.keys().cloned())
        .collect::<std::collections::BTreeSet<_>>();
    for name in profiles {
        let previous_artifacts = original
            .as_ref()
            .and_then(|settings| settings.profiles.get(&name))
            .is_some_and(|profile| profile.scheduled_artifact_cleanup);
        let artifacts_enabled = current
            .profiles
            .get(&name)
            .is_some_and(|profile| profile.scheduled_artifact_cleanup);
        if original.is_none() || previous_artifacts != artifacts_enabled {
            impacts.push(scheduled_artifact_cleanup_impact(
                &format!("profile {name}"),
                artifacts_enabled,
            ));
        }
        let previous = original
            .as_ref()
            .and_then(|settings| settings.profiles.get(&name))
            .is_some_and(|profile| profile.scheduled_bytecode_cleanup);
        let enabled = current
            .profiles
            .get(&name)
            .is_some_and(|profile| profile.scheduled_bytecode_cleanup);
        if original.is_none() || previous != enabled {
            impacts.push(scheduled_cleanup_impact(
                &format!("profile {name}"),
                enabled,
            ));
        }
    }
    if original.is_none() {
        impacts.push(
            "The previous TOML could not be parsed, so the earlier scheduled-cleanup settings are unknown; review this full configuration before saving.".into(),
        );
    }
    Ok(impacts)
}

fn settings_rows(form: &SettingsForm) -> Vec<SettingsRow> {
    let roots = settings_roots(&form.settings, form.profile.as_deref());
    let exclusions = settings_exclusions(&form.settings, form.profile.as_deref());
    let mut rows = vec![SettingsRow::Profile];
    rows.extend((0..roots.len()).map(SettingsRow::Root));
    rows.push(SettingsRow::AddRoot);
    rows.extend((0..exclusions.len()).map(SettingsRow::Exclusion));
    rows.push(SettingsRow::AddExclusion);
    rows.push(SettingsRow::Retention);
    rows.extend(SETTINGS_ECOSYSTEMS.into_iter().map(SettingsRow::Ecosystem));
    rows.push(SettingsRow::AllEcosystems);
    rows.push(SettingsRow::ScheduledCleanup);
    rows.push(SettingsRow::ScheduledArtifactCleanup);
    rows.push(SettingsRow::ScheduleFrequency);
    if form.profile.is_none() {
        rows.push(SettingsRow::ScheduledTrashRetention);
        rows.push(SettingsRow::Theme);
    }
    rows
}

fn settings_roots<'a>(
    settings: &'a crate::config::Settings,
    profile: Option<&str>,
) -> &'a [PathBuf] {
    profile
        .and_then(|name| settings.profiles.get(name))
        .map_or(&settings.workspace_roots, |profile| {
            &profile.workspace_roots
        })
}

fn settings_exclusions<'a>(
    settings: &'a crate::config::Settings,
    profile: Option<&str>,
) -> &'a [PathBuf] {
    profile
        .and_then(|name| settings.profiles.get(name))
        .map_or(&settings.exclusions, |profile| &profile.exclusions)
}

fn settings_retention<'a>(
    settings: &'a crate::config::Settings,
    profile: Option<&str>,
) -> Option<&'a str> {
    profile
        .and_then(|name| settings.profiles.get(name))
        .and_then(|profile| profile.artifact_retention.as_deref())
        .or_else(|| {
            if profile.is_none() {
                settings.artifact_retention.as_deref()
            } else {
                None
            }
        })
}

fn settings_ecosystems<'a>(
    settings: &'a crate::config::Settings,
    profile: Option<&str>,
) -> Option<&'a [crate::sweep::Ecosystem]> {
    profile
        .and_then(|name| settings.profiles.get(name))
        .and_then(|profile| profile.enabled_ecosystems.as_deref())
        .or_else(|| {
            if profile.is_none() {
                settings.enabled_ecosystems.as_deref()
            } else {
                None
            }
        })
}

fn settings_ecosystem_enabled(
    settings: &crate::config::Settings,
    profile: Option<&str>,
    ecosystem: crate::sweep::Ecosystem,
) -> bool {
    let globally_enabled = settings
        .enabled_ecosystems
        .as_ref()
        .is_none_or(|items| items.contains(&ecosystem));
    let selected = profile
        .and_then(|name| settings.profiles.get(name))
        .and_then(|profile| profile.enabled_ecosystems.as_ref())
        .or(settings.enabled_ecosystems.as_ref())
        .is_none_or(|items| items.contains(&ecosystem));
    globally_enabled && selected
}

fn settings_cleanup_value(settings: &crate::config::Settings, profile: Option<&str>) -> bool {
    profile
        .and_then(|name| settings.profiles.get(name))
        .map_or(settings.scheduled_bytecode_cleanup, |profile| {
            profile.scheduled_bytecode_cleanup
        })
}

fn settings_artifact_cleanup_value(
    settings: &crate::config::Settings,
    profile: Option<&str>,
) -> bool {
    profile
        .and_then(|name| settings.profiles.get(name))
        .map_or(settings.scheduled_artifact_cleanup, |profile| {
            profile.scheduled_artifact_cleanup
        })
}

fn settings_frequency_value(
    settings: &crate::config::Settings,
    profile: Option<&str>,
) -> Option<crate::config::ScheduleFrequency> {
    match profile {
        Some(name) => settings
            .profiles
            .get(name)
            .and_then(|profile| profile.schedule_frequency),
        None => settings.schedule_frequency,
    }
}

fn settings_field_equal(
    current: &crate::config::Settings,
    original: &crate::config::Settings,
    target: &SettingsTarget,
) -> bool {
    if target.profile.as_ref().is_some_and(|name| {
        current.profiles.contains_key(name) != original.profiles.contains_key(name)
    }) {
        return false;
    }
    match target.field {
        SettingsField::WorkspaceRoots => {
            settings_roots(current, target.profile.as_deref())
                == settings_roots(original, target.profile.as_deref())
        }
        SettingsField::Exclusions => {
            settings_exclusions(current, target.profile.as_deref())
                == settings_exclusions(original, target.profile.as_deref())
        }
        SettingsField::ArtifactRetention => {
            settings_retention(current, target.profile.as_deref())
                == settings_retention(original, target.profile.as_deref())
        }
        SettingsField::EnabledEcosystems => {
            settings_ecosystems(current, target.profile.as_deref())
                == settings_ecosystems(original, target.profile.as_deref())
        }
        SettingsField::ScheduledBytecodeCleanup => {
            settings_cleanup_value(current, target.profile.as_deref())
                == settings_cleanup_value(original, target.profile.as_deref())
        }
        SettingsField::ScheduledArtifactCleanup => {
            settings_artifact_cleanup_value(current, target.profile.as_deref())
                == settings_artifact_cleanup_value(original, target.profile.as_deref())
        }
        SettingsField::ScheduledTrashRetention => {
            current.scheduled_trash_retention == original.scheduled_trash_retention
        }
        SettingsField::ScheduleFrequency => {
            settings_frequency_value(current, target.profile.as_deref())
                == settings_frequency_value(original, target.profile.as_deref())
        }
        SettingsField::Theme => current.theme == original.theme,
    }
}

fn settings_field_key(field: SettingsField) -> &'static str {
    match field {
        SettingsField::WorkspaceRoots => "workspace_roots",
        SettingsField::Exclusions => "exclusions",
        SettingsField::ArtifactRetention => "artifact_retention",
        SettingsField::EnabledEcosystems => "enabled_ecosystems",
        SettingsField::ScheduledBytecodeCleanup => "scheduled_bytecode_cleanup",
        SettingsField::ScheduledArtifactCleanup => "scheduled_artifact_cleanup",
        SettingsField::ScheduledTrashRetention => "scheduled_trash_retention",
        SettingsField::ScheduleFrequency => "schedule_frequency",
        SettingsField::Theme => "theme",
    }
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}

fn settings_field_toml_value(
    settings: &crate::config::Settings,
    target: &SettingsTarget,
) -> Result<Option<String>> {
    let profile = target
        .profile
        .as_deref()
        .and_then(|name| settings.profiles.get(name));
    let value = match target.field {
        SettingsField::WorkspaceRoots => {
            let paths = profile.map_or(&settings.workspace_roots, |p| &p.workspace_roots);
            Some(format!(
                "[{}]",
                paths
                    .iter()
                    .map(|path| toml_string(&path.to_string_lossy()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
        SettingsField::Exclusions => {
            let paths = profile.map_or(&settings.exclusions, |p| &p.exclusions);
            Some(format!(
                "[{}]",
                paths
                    .iter()
                    .map(|path| toml_string(&path.to_string_lossy()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
        SettingsField::ArtifactRetention => profile
            .and_then(|p| p.artifact_retention.as_deref())
            .or_else(|| {
                if target.profile.is_none() {
                    settings.artifact_retention.as_deref()
                } else {
                    None
                }
            })
            .map(toml_string),
        SettingsField::EnabledEcosystems => {
            let ecosystems = profile
                .and_then(|p| p.enabled_ecosystems.as_deref())
                .or_else(|| {
                    if target.profile.is_none() {
                        settings.enabled_ecosystems.as_deref()
                    } else {
                        None
                    }
                });
            ecosystems.map(|ecosystems| {
                format!(
                    "[{}]",
                    ecosystems
                        .iter()
                        .map(|ecosystem| toml_string(ecosystem.as_str()))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
        }
        SettingsField::ScheduledBytecodeCleanup => {
            Some(settings_cleanup_value(settings, target.profile.as_deref()).to_string())
        }
        SettingsField::ScheduledArtifactCleanup => {
            Some(settings_artifact_cleanup_value(settings, target.profile.as_deref()).to_string())
        }
        SettingsField::ScheduledTrashRetention => {
            Some(settings.scheduled_trash_retention.to_string())
        }
        SettingsField::ScheduleFrequency => {
            settings_frequency_value(settings, target.profile.as_deref()).map(|frequency| {
                toml_string(match frequency {
                    crate::config::ScheduleFrequency::Daily => "daily",
                    crate::config::ScheduleFrequency::Weekly => "weekly",
                })
            })
        }
        SettingsField::Theme => Some(toml_string(match settings.theme {
            crate::config::Theme::Dark => "dark",
            crate::config::Theme::Light => "light",
        })),
    };
    Ok(value)
}

fn settings_field_display_value(
    settings: &crate::config::Settings,
    target: &SettingsTarget,
) -> String {
    if target
        .profile
        .as_ref()
        .is_some_and(|name| !settings.profiles.contains_key(name))
    {
        return "profile absent".into();
    }
    match settings_field_toml_value(settings, target).ok().flatten() {
        Some(value) => value,
        None => match (target.field, target.profile.is_some()) {
            (SettingsField::ArtifactRetention, true) => "inherit global".into(),
            (SettingsField::EnabledEcosystems, true) => "inherit global".into(),
            (SettingsField::ScheduleFrequency, true) => "inherit global".into(),
            (SettingsField::ScheduleFrequency, false) => "weekly (default)".into(),
            (SettingsField::ArtifactRetention, false) => "unset".into(),
            (SettingsField::EnabledEcosystems, false) => "all supported".into(),
            _ => "unset".into(),
        },
    }
}

fn settings_change_lines(snapshot: &crate::config::ConfigDocument, text: &str) -> Vec<String> {
    let Ok(current) = toml::from_str::<crate::config::Settings>(text) else {
        return vec![
            "Proposed field values are unavailable; configuration validation failed.".into(),
        ];
    };
    let previous = toml::from_str::<crate::config::Settings>(&snapshot.text).ok();
    let mut lines = Vec::new();
    let fields = [
        SettingsField::WorkspaceRoots,
        SettingsField::Exclusions,
        SettingsField::ArtifactRetention,
        SettingsField::EnabledEcosystems,
        SettingsField::ScheduledBytecodeCleanup,
        SettingsField::ScheduledArtifactCleanup,
        SettingsField::ScheduledTrashRetention,
        SettingsField::ScheduleFrequency,
        SettingsField::Theme,
    ];
    let mut scopes = vec![None];
    let profiles = previous
        .iter()
        .flat_map(|settings| settings.profiles.keys())
        .chain(current.profiles.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    scopes.extend(profiles.into_iter().map(Some));
    for profile in scopes {
        let scope = profile.as_deref().map_or_else(
            || "global defaults".into(),
            |name| format!("profile {name}"),
        );
        for field in fields {
            if field == SettingsField::Theme && profile.is_some() {
                continue;
            }
            if field == SettingsField::ScheduledTrashRetention && profile.is_some() {
                continue;
            }
            let target = SettingsTarget {
                profile: profile.clone(),
                field,
            };
            let after = settings_field_display_value(&current, &target);
            let before = previous
                .as_ref()
                .map(|settings| settings_field_display_value(settings, &target));
            if previous.is_none() || before.as_deref() != Some(after.as_str()) {
                let before = before.unwrap_or_else(|| "unknown".into());
                lines.push(schedule_escape_controls(&format!(
                    "{scope}.{}: {before} → {after}",
                    settings_field_key(field)
                )));
            }
        }
    }
    if previous.is_none() {
        lines.insert(
            0,
            "Earlier settings could not be parsed; proposed values are listed with unknown before values.".into(),
        );
    }
    if lines.is_empty() {
        lines.push("No semantic setting fields changed; this save only changes TOML formatting or comments.".into());
    }
    lines
}

fn settings_form_content(form: &SettingsForm) -> String {
    let mut lines = vec![
        format!(
            "Configuration: {}",
            crate::sweep::display_path(&form.snapshot.path)
        ),
        format!(
            "Editing: {}  ({} profile(s); ←/→ to switch, n to add)",
            form.profile.as_deref().unwrap_or("global defaults"),
            form.settings.profiles.len()
        ),
        "Roots in a profile replace global roots; profile exclusions add to global exclusions."
            .into(),
        "Profile ecosystem settings can narrow the global list but cannot re-enable globally disabled items.".into(),
        String::new(),
    ];
    for (index, row) in settings_rows(form).into_iter().enumerate() {
        let value = match row {
            SettingsRow::Profile => "Profile scope".to_owned(),
            SettingsRow::Root(path_index) => format!(
                "Workspace root {}: {}",
                path_index + 1,
                crate::sweep::display_path(
                    &settings_roots(&form.settings, form.profile.as_deref())[path_index]
                )
            ),
            SettingsRow::AddRoot => "Add workspace root".into(),
            SettingsRow::Exclusion(path_index) => format!(
                "Exclusion {}: {}",
                path_index + 1,
                crate::sweep::display_path(
                    &settings_exclusions(&form.settings, form.profile.as_deref())[path_index]
                )
            ),
            SettingsRow::AddExclusion => "Add exclusion".into(),
            SettingsRow::Retention => format!(
                "Artifact retention: {}",
                settings_retention(&form.settings, form.profile.as_deref()).map_or_else(
                    || {
                        if form.profile.is_some() {
                            settings_retention(&form.settings, None).map_or_else(
                                || "inherited (unlimited)".to_owned(),
                                |value| format!("inherited ({value})"),
                            )
                        } else {
                            "unlimited".to_owned()
                        }
                    },
                    str::to_owned,
                )
            ),
            SettingsRow::Ecosystem(ecosystem) => {
                let enabled =
                    settings_ecosystem_enabled(&form.settings, form.profile.as_deref(), ecosystem);
                let globally_disabled = form.profile.is_some()
                    && form
                        .settings
                        .enabled_ecosystems
                        .as_ref()
                        .is_some_and(|items| !items.contains(&ecosystem));
                format!(
                    "[{}] {}{}",
                    if enabled { 'x' } else { ' ' },
                    ecosystem.as_str(),
                    if globally_disabled {
                        " (disabled globally)"
                    } else {
                        ""
                    }
                )
            }
            SettingsRow::AllEcosystems => {
                if form.profile.is_some() {
                    "Inherit global ecosystem policy".into()
                } else {
                    "Allow all ecosystems (default)".into()
                }
            }
            SettingsRow::ScheduledCleanup => format!(
                "Scheduled bytecode cleanup: {} (future configured timers may permanently remove eligible Python bytecode)",
                if settings_cleanup_value(&form.settings, form.profile.as_deref()) {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
            SettingsRow::ScheduledArtifactCleanup => format!(
                "Scheduled artifact cleanup: {} (Linux only; up to 8 Maven, Zig, Dart, or Python directories after 30+ days; Cargo is excluded from scheduled cleanup)",
                if settings_artifact_cleanup_value(&form.settings, form.profile.as_deref()) {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
            #[cfg(target_os = "linux")]
            SettingsRow::ScheduledTrashRetention => format!(
                "Scheduled Trash retention opt-in: {} (an installed timer can permanently delete matching items at its bound location)",
                if form.settings.scheduled_trash_retention {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
            #[cfg(not(target_os = "linux"))]
            SettingsRow::ScheduledTrashRetention => {
                "Scheduled Trash retention: available on Linux only".into()
            }
            SettingsRow::ScheduleFrequency => {
                let configured = settings_frequency_value(&form.settings, form.profile.as_deref());
                let effective =
                    crate::config::schedule_frequency(&form.settings, form.profile.as_deref())
                        .unwrap_or_default();
                let label = match effective {
                    crate::config::ScheduleFrequency::Daily => "daily",
                    crate::config::ScheduleFrequency::Weekly => "weekly",
                };
                format!(
                    "Schedule frequency: {label}{} (existing timers are unchanged)",
                    if configured.is_none() {
                        " (inherited/default)"
                    } else {
                        ""
                    }
                )
            }
            SettingsRow::Theme => format!(
                "Theme: {}",
                match form.settings.theme {
                    crate::config::Theme::Dark => "dark",
                    crate::config::Theme::Light => "light",
                }
            ),
        };
        lines.push(format!(
            "{}{}",
            if index == form.selected { "› " } else { "  " },
            value
        ));
    }
    lines.join("\n")
}

fn settings_form_scroll(form: &SettingsForm, area: Rect) -> u16 {
    let lines = settings_form_content(form)
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let selected = 5usize
        .saturating_add(form.selected)
        .min(lines.len().saturating_sub(1));
    let width = area.width.saturating_sub(2);
    let visible = area.height.saturating_sub(2) as usize;
    let prefix = lines[..selected]
        .iter()
        .map(|line| ratatui::text::Line::from(line.as_str()))
        .collect::<Vec<_>>();
    let before = Paragraph::new(prefix)
        .wrap(Wrap { trim: false })
        .line_count(width);
    let selected_lines = Paragraph::new(lines[selected].as_str())
        .wrap(Wrap { trim: false })
        .line_count(width);
    let scroll = if selected_lines > visible {
        before
    } else {
        before
            .saturating_add(selected_lines)
            .saturating_sub(visible)
    };
    u16::try_from(scroll).unwrap_or(u16::MAX)
}

fn settings_target_for_row(form: &SettingsForm, row: SettingsRow) -> Option<SettingsTarget> {
    let field = match row {
        SettingsRow::Root(_) | SettingsRow::AddRoot => SettingsField::WorkspaceRoots,
        SettingsRow::Exclusion(_) | SettingsRow::AddExclusion => SettingsField::Exclusions,
        SettingsRow::Retention => SettingsField::ArtifactRetention,
        SettingsRow::Ecosystem(_) | SettingsRow::AllEcosystems => SettingsField::EnabledEcosystems,
        SettingsRow::ScheduledCleanup => SettingsField::ScheduledBytecodeCleanup,
        SettingsRow::ScheduledArtifactCleanup => SettingsField::ScheduledArtifactCleanup,
        #[cfg(target_os = "linux")]
        SettingsRow::ScheduledTrashRetention => SettingsField::ScheduledTrashRetention,
        #[cfg(not(target_os = "linux"))]
        SettingsRow::ScheduledTrashRetention => return None,
        SettingsRow::ScheduleFrequency => SettingsField::ScheduleFrequency,
        SettingsRow::Theme => SettingsField::Theme,
        SettingsRow::Profile => return None,
    };
    Some(form.target(field))
}

fn settings_text_input_label(input: &SettingsInput) -> &'static str {
    if input.new_profile {
        return "New profile name (letters, digits, - or _)";
    }
    match input.target.field {
        SettingsField::WorkspaceRoots => "Workspace root path",
        SettingsField::Exclusions => "Exclusion path or glob: pattern",
        SettingsField::ArtifactRetention => "Artifact retention (blank clears it)",
        _ => "Configuration value",
    }
}

fn toml_line_ending(line: &str) -> (&str, &str) {
    if let Some(body) = line.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = line.strip_suffix('\n') {
        (body, "\n")
    } else {
        (line, "")
    }
}

fn toml_header(line: &str) -> Option<&str> {
    let header = toml_line_ending(line).0.trim();
    (header.starts_with('[') && header.ends_with(']')).then(|| &header[1..header.len() - 1])
}

fn profile_header_matches(header: &str, profile: &str) -> bool {
    [
        format!("profiles.{profile}"),
        format!("profiles.\"{profile}\""),
        format!("profiles.'{profile}'"),
        format!("\"profiles\".{profile}"),
    ]
    .iter()
    .any(|candidate| header == candidate)
}

fn toml_comment_start(value: &str) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if character == '\\' => escaped = true,
            Some(quote_character) if character == quote_character => quote = None,
            Some(_) => {}
            None if character == '"' || character == '\'' => quote = Some(character),
            None if character == '#' => return Some(index),
            None => {}
        }
    }
    None
}

fn patch_config_assignment(
    text: &str,
    profile: Option<&str>,
    key: &str,
    value: Option<&str>,
) -> Result<String> {
    // shortcut: only single-line assignments are rewritten; use the TOML editor for multiline values.
    let mut lines = text
        .split_inclusive('\n')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !text.is_empty() && !text.ends_with('\n') && lines.is_empty() {
        lines.push(text.to_owned());
    }
    let matches_section =
        |header: &str| profile.is_some_and(|profile| profile_header_matches(header, profile));
    let mut section_start = if profile.is_none() { Some(0) } else { None };
    let mut section_end = None;
    let mut current_profile_section = false;
    let mut found_assignment = None;
    let mut found_section = profile.is_none();
    for (index, line) in lines.iter().enumerate() {
        if let Some(header) = toml_header(line) {
            if profile.is_none() {
                section_end = Some(index);
                break;
            }
            if matches_section(header) {
                if found_section {
                    anyhow::bail!("configuration repeats a profile table; use the TOML editor");
                }
                found_section = true;
                current_profile_section = true;
                section_start = Some(index + 1);
                continue;
            }
            if current_profile_section {
                section_end = Some(index);
                break;
            }
            current_profile_section = false;
            continue;
        }
        let in_section = if profile.is_none() {
            true
        } else {
            current_profile_section
        };
        if !in_section {
            continue;
        }
        let body = toml_line_ending(line).0;
        let Some(equals) = body.find('=') else {
            continue;
        };
        if body[..equals].trim() == key && found_assignment.replace(index).is_some() {
            anyhow::bail!("configuration repeats {key}; use the TOML editor");
        }
    }
    if profile.is_some() && !found_section {
        anyhow::bail!("profile table is not in a form the settings editor can safely update");
    }
    let start = section_start.unwrap_or(0);
    let end = section_end.unwrap_or(lines.len());
    if let Some(index) = found_assignment {
        let (body, ending) = toml_line_ending(&lines[index]);
        let equals = body.find('=').expect("matched assignment has equals");
        let rhs_start = equals + 1;
        let rhs = &body[rhs_start..];
        if rhs.contains("\"\"\"") || rhs.contains("'''") {
            anyhow::bail!("multi-line setting values must be edited in the TOML editor");
        }
        let comment = toml_comment_start(rhs).map(|offset| rhs_start + offset);
        let expression_end = comment.unwrap_or(body.len());
        let expression = body[rhs_start..expression_end].trim();
        if toml::from_str::<toml::Value>(&format!("value = {expression}")).is_err() {
            anyhow::bail!("setting value is multi-line or unsupported; use the TOML editor");
        }
        if let Some(value) = value {
            let before = &body[..rhs_start];
            let old_value = &body[rhs_start..expression_end];
            let leading = old_value.len() - old_value.trim_start().len();
            let trailing = old_value.len() - old_value.trim_end().len();
            let value_start = rhs_start + leading;
            let value_end = expression_end.saturating_sub(trailing);
            let mut updated = String::with_capacity(lines[index].len() + value.len());
            updated.push_str(before);
            updated.push_str(&old_value[..leading]);
            updated.push_str(value);
            updated.push_str(&old_value[old_value.len() - trailing..]);
            updated.push_str(&body[expression_end..]);
            updated.push_str(ending);
            let _ = (value_start, value_end);
            lines[index] = updated;
        } else if let Some(comment) = comment {
            let indent = &body[..body.len() - body.trim_start().len()];
            lines[index] = format!("{indent}{}{}", &body[comment..], ending);
        } else {
            lines.remove(index);
        }
    } else if let Some(value) = value {
        let mut insertion = end;
        while insertion > start {
            let body = toml_line_ending(&lines[insertion - 1]).0.trim();
            if body.is_empty() || body.starts_with('#') {
                insertion -= 1;
            } else {
                break;
            }
        }
        let ending = if text.contains("\r\n") { "\r\n" } else { "\n" };
        let line = format!("{key} = {value}");
        if insertion < lines.len() {
            lines.insert(insertion, format!("{line}{ending}"));
        } else if lines.is_empty() {
            lines.push(if text.ends_with('\n') {
                format!("{line}{ending}")
            } else {
                line
            });
        } else {
            if !lines[insertion - 1].ends_with('\n') {
                lines[insertion - 1].push_str(ending);
            }
            lines.push(if text.ends_with('\n') {
                format!("{line}{ending}")
            } else {
                line
            });
        }
    }
    Ok(lines.concat())
}

fn settings_input_apply(form: &mut SettingsForm, input: &SettingsInput) -> Result<()> {
    let value = input.value.iter().collect::<String>();
    if input.new_profile {
        if form.settings.profiles.contains_key(&value) {
            anyhow::bail!("profile already exists");
        }
        let mut settings = form.settings.clone();
        settings.profiles.insert(value.clone(), Default::default());
        settings.validate()?;
        form.settings = settings;
        form.profile = Some(value);
        form.selected = 0;
        return Ok(());
    }
    let profile = input
        .target
        .profile
        .as_deref()
        .and_then(|name| form.settings.profiles.get_mut(name));
    match input.target.field {
        SettingsField::WorkspaceRoots => {
            if value.is_empty() {
                anyhow::bail!("workspace roots cannot be empty; use d to remove a row");
            }
            let roots = profile.map_or(&mut form.settings.workspace_roots, |p| {
                &mut p.workspace_roots
            });
            let path = PathBuf::from(value);
            if let Some(index) = input.index {
                roots[index] = path;
            } else {
                roots.push(path);
            }
        }
        SettingsField::Exclusions => {
            if value.is_empty() {
                anyhow::bail!("exclusions cannot be empty; use d to remove a row");
            }
            let exclusions = profile.map_or(&mut form.settings.exclusions, |p| &mut p.exclusions);
            let path = PathBuf::from(value);
            if let Some(index) = input.index {
                exclusions[index] = path;
            } else {
                exclusions.push(path);
            }
        }
        SettingsField::ArtifactRetention => {
            let retention = if value.is_empty() { None } else { Some(value) };
            if let Some(profile) = profile {
                profile.artifact_retention = retention;
            } else {
                form.settings.artifact_retention = retention;
            }
        }
        _ => anyhow::bail!("this setting does not accept text"),
    }
    form.mark_dirty(input.target.clone());
    form.selected = settings_rows(form)
        .len()
        .saturating_sub(1)
        .min(form.selected);
    Ok(())
}

fn remove_settings_path(form: &mut SettingsForm, target: SettingsTarget, index: usize) {
    let profile = target
        .profile
        .as_deref()
        .and_then(|name| form.settings.profiles.get_mut(name));
    let paths = match target.field {
        SettingsField::WorkspaceRoots => profile.map_or(&mut form.settings.workspace_roots, |p| {
            &mut p.workspace_roots
        }),
        SettingsField::Exclusions => {
            profile.map_or(&mut form.settings.exclusions, |p| &mut p.exclusions)
        }
        _ => return,
    };
    if index < paths.len() {
        paths.remove(index);
        form.mark_dirty(target);
        form.selected = form
            .selected
            .saturating_sub(1)
            .min(settings_rows(form).len() - 1);
    }
}

fn settings_input_for_row(form: &SettingsForm, row: SettingsRow) -> Option<SettingsInput> {
    let (target, index, value) = match row {
        SettingsRow::Root(index) => (
            form.target(SettingsField::WorkspaceRoots),
            Some(index),
            settings_roots(&form.settings, form.profile.as_deref())[index]
                .to_string_lossy()
                .into_owned(),
        ),
        SettingsRow::AddRoot => (
            form.target(SettingsField::WorkspaceRoots),
            None,
            String::new(),
        ),
        SettingsRow::Exclusion(index) => (
            form.target(SettingsField::Exclusions),
            Some(index),
            settings_exclusions(&form.settings, form.profile.as_deref())[index]
                .to_string_lossy()
                .into_owned(),
        ),
        SettingsRow::AddExclusion => (form.target(SettingsField::Exclusions), None, String::new()),
        SettingsRow::Retention => (
            form.target(SettingsField::ArtifactRetention),
            None,
            settings_retention(&form.settings, form.profile.as_deref())
                .unwrap_or_default()
                .to_owned(),
        ),
        _ => return None,
    };
    let cursor = value.chars().count();
    Some(SettingsInput {
        target,
        new_profile: false,
        index,
        value: value.chars().collect(),
        cursor,
    })
}

fn settings_form_toggle(form: &mut SettingsForm, row: SettingsRow) {
    let Some(target) = settings_target_for_row(form, row) else {
        return;
    };
    match row {
        SettingsRow::Ecosystem(ecosystem) => {
            if form
                .settings
                .enabled_ecosystems
                .as_ref()
                .is_some_and(|items| !items.contains(&ecosystem))
            {
                return;
            }
            let current = form
                .profile
                .as_deref()
                .and_then(|name| form.settings.profiles.get(name))
                .and_then(|profile| profile.enabled_ecosystems.as_ref())
                .or(form.settings.enabled_ecosystems.as_ref());
            let mut enabled =
                current.map_or_else(|| SETTINGS_ECOSYSTEMS.to_vec(), |items| items.to_vec());
            if let Some(index) = enabled.iter().position(|item| *item == ecosystem) {
                enabled.remove(index);
            } else {
                enabled.push(ecosystem);
                enabled.sort_by_key(|item| {
                    SETTINGS_ECOSYSTEMS
                        .iter()
                        .position(|known| known == item)
                        .unwrap_or(usize::MAX)
                });
            }
            let profile = target
                .profile
                .as_deref()
                .and_then(|name| form.settings.profiles.get_mut(name));
            if let Some(profile) = profile {
                profile.enabled_ecosystems = Some(enabled);
            } else {
                form.settings.enabled_ecosystems = Some(enabled);
            }
            form.mark_dirty(target);
        }
        SettingsRow::AllEcosystems => {
            let profile = target
                .profile
                .as_deref()
                .and_then(|name| form.settings.profiles.get_mut(name));
            if let Some(profile) = profile {
                if profile.enabled_ecosystems.take().is_some() {
                    form.mark_dirty(target);
                }
            } else if form.settings.enabled_ecosystems.take().is_some() {
                form.mark_dirty(target);
            }
        }
        SettingsRow::ScheduledCleanup => {
            let profile = target
                .profile
                .as_deref()
                .and_then(|name| form.settings.profiles.get_mut(name));
            if let Some(profile) = profile {
                profile.scheduled_bytecode_cleanup = !profile.scheduled_bytecode_cleanup;
            } else {
                form.settings.scheduled_bytecode_cleanup =
                    !form.settings.scheduled_bytecode_cleanup;
            }
            form.mark_dirty(target);
        }
        SettingsRow::ScheduledArtifactCleanup => {
            let profile = target
                .profile
                .as_deref()
                .and_then(|name| form.settings.profiles.get_mut(name));
            if let Some(profile) = profile {
                profile.scheduled_artifact_cleanup = !profile.scheduled_artifact_cleanup;
            } else {
                form.settings.scheduled_artifact_cleanup =
                    !form.settings.scheduled_artifact_cleanup;
            }
            form.mark_dirty(target);
        }
        SettingsRow::ScheduledTrashRetention => {
            form.settings.scheduled_trash_retention = !form.settings.scheduled_trash_retention;
            form.mark_dirty(target);
        }
        SettingsRow::ScheduleFrequency => {
            let profile = target
                .profile
                .as_deref()
                .and_then(|name| form.settings.profiles.get_mut(name));
            let value = profile.map_or(&mut form.settings.schedule_frequency, |profile| {
                &mut profile.schedule_frequency
            });
            *value = match *value {
                None => Some(crate::config::ScheduleFrequency::Daily),
                Some(crate::config::ScheduleFrequency::Daily) => {
                    Some(crate::config::ScheduleFrequency::Weekly)
                }
                Some(crate::config::ScheduleFrequency::Weekly) => None,
            };
            form.mark_dirty(target);
        }
        SettingsRow::Theme => {
            form.settings.theme = match form.settings.theme {
                crate::config::Theme::Dark => crate::config::Theme::Light,
                crate::config::Theme::Light => crate::config::Theme::Dark,
            };
            form.mark_dirty(target);
        }
        _ => {}
    }
}

fn settings_text_input_key(input: &mut SettingsInput, key: KeyCode) -> bool {
    match key {
        KeyCode::Left if input.cursor > 0 => input.cursor -= 1,
        KeyCode::Right if input.cursor < input.value.len() => input.cursor += 1,
        KeyCode::Home => input.cursor = 0,
        KeyCode::End => input.cursor = input.value.len(),
        KeyCode::Char(character) if !character.is_control() => {
            if input
                .value
                .iter()
                .map(|character| character.len_utf8())
                .sum::<usize>()
                + character.len_utf8()
                > crate::config::MAX_EDIT_BYTES as usize
            {
                return false;
            }
            input.value.insert(input.cursor, character);
            input.cursor += 1;
        }
        KeyCode::Backspace if input.cursor > 0 => {
            input.cursor -= 1;
            input.value.remove(input.cursor);
        }
        KeyCode::Delete if input.cursor < input.value.len() => {
            input.value.remove(input.cursor);
        }
        _ => {}
    }
    true
}

fn stopped_containers(
    report: &[crate::containers::EngineStatus],
) -> Vec<(&str, &str, &serde_json::Value)> {
    report
        .iter()
        .filter(|engine| engine.state == "available")
        .flat_map(|engine| {
            engine
                .resources
                .iter()
                .filter(|list| list.kind == "containers" && list.error.is_none())
                .flat_map(move |list| {
                    list.items.iter().filter_map(move |item| {
                        let id = item
                            .get("ID")
                            .or_else(|| item.get("Id"))
                            .or_else(|| item.get("id"))?
                            .as_str()?;
                        let state = item.get("State").or_else(|| item.get("state"))?.as_str()?;
                        (state == "exited"
                            && id.len() == 64
                            && id
                                .bytes()
                                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
                        .then_some((engine.engine, id, item))
                    })
                })
        })
        .collect()
}

fn dangling_images(
    report: &[crate::containers::EngineStatus],
) -> Vec<(&str, &str, &serde_json::Value)> {
    report
        .iter()
        .filter(|engine| engine.state == "available")
        .flat_map(|engine| {
            engine
                .resources
                .iter()
                .filter(|list| list.kind == "dangling images" && list.error.is_none())
                .flat_map(move |list| {
                    list.items.iter().filter_map(move |item| {
                        crate::containers::image_id(item).map(|id| (engine.engine, id, item))
                    })
                })
        })
        .collect()
}

fn unused_networks(
    report: &[crate::containers::EngineStatus],
) -> Vec<(&str, &str, &serde_json::Value)> {
    report
        .iter()
        .filter(|engine| engine.state == "available")
        .flat_map(|engine| {
            engine
                .resources
                .iter()
                .filter(move |list| {
                    list.error.is_none()
                        && ((engine.engine == "docker"
                            && list.kind == "unattached custom networks (snapshot)")
                            || (engine.engine == "podman" && list.kind == "unattached networks"))
                })
                .flat_map(move |list| {
                    list.items.iter().filter_map(move |item| {
                        crate::containers::image_id(item).map(|id| (engine.engine, id, item))
                    })
                })
        })
        .collect()
}

fn build_caches(
    report: &[crate::containers::EngineStatus],
) -> Vec<(&str, &str, &serde_json::Value)> {
    report
        .iter()
        .filter(|engine| engine.engine == "docker" && engine.state == "available")
        .flat_map(|engine| {
            engine
                .resources
                .iter()
                .filter(|list| list.kind == crate::containers::BUILD_CACHE && list.error.is_none())
        })
        .flat_map(|list| {
            list.items.iter().filter_map(|item| {
                let builder = item.get("Builder")?.as_str()?;
                let id = item.get("ID")?.as_str()?;
                (id.len() == 25
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                    && item.get("Reclaimable")?.as_bool()?
                    && !item.get("Mutable")?.as_bool()?
                    && !item.get("Shared")?.as_bool()?)
                .then_some((builder, id, item))
            })
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ContainerCategory {
    Stopped,
    UnusedNetwork,
    BuildCache,
}

#[derive(Clone, Copy)]
enum ContainerSelection<'a> {
    Stopped {
        engine: &'a str,
        id: &'a str,
        item: &'a serde_json::Value,
    },
    UnusedNetwork {
        engine: &'a str,
        id: &'a str,
        item: &'a serde_json::Value,
    },
    BuildCache {
        builder: &'a str,
        id: &'a str,
        item: &'a serde_json::Value,
    },
}

impl ContainerSelection<'_> {
    fn category(self) -> ContainerCategory {
        match self {
            Self::Stopped { .. } => ContainerCategory::Stopped,
            Self::UnusedNetwork { .. } => ContainerCategory::UnusedNetwork,
            Self::BuildCache { .. } => ContainerCategory::BuildCache,
        }
    }

    fn matches(self, filter: &str) -> bool {
        let filter = filter.to_lowercase();
        if filter.is_empty() {
            return true;
        }
        let (scope, id, item) = match self {
            Self::Stopped { engine, id, item } | Self::UnusedNetwork { engine, id, item } => {
                (engine, id, item)
            }
            Self::BuildCache { builder, id, item } => (builder, id, item),
        };
        scope.to_lowercase().contains(&filter)
            || id.to_lowercase().contains(&filter)
            || item.to_string().to_lowercase().contains(&filter)
    }
}

fn container_resources(report: &[crate::containers::EngineStatus]) -> Vec<ContainerSelection<'_>> {
    let mut resources = Vec::new();
    resources.extend(
        stopped_containers(report)
            .into_iter()
            .map(|(engine, id, item)| ContainerSelection::Stopped { engine, id, item }),
    );
    resources.extend(
        unused_networks(report)
            .into_iter()
            .map(|(engine, id, item)| ContainerSelection::UnusedNetwork { engine, id, item }),
    );
    resources.extend(
        build_caches(report)
            .into_iter()
            .map(|(builder, id, item)| ContainerSelection::BuildCache { builder, id, item }),
    );
    resources
}

fn visible_container_indices(
    report: &[crate::containers::EngineStatus],
    filter: &str,
) -> Vec<usize> {
    container_resources(report)
        .iter()
        .enumerate()
        .filter_map(|(index, resource)| resource.matches(filter).then_some(index))
        .collect()
}

fn selected_container_resource<'a>(
    report: &'a [crate::containers::EngineStatus],
    filter: &str,
    selected: usize,
) -> Option<ContainerSelection<'a>> {
    container_resources(report)
        .get(selected)
        .copied()
        .filter(|resource| resource.matches(filter))
}

fn container_selection_line(
    report: &[crate::containers::EngineStatus],
    filter: &str,
    selected: usize,
) -> usize {
    let resources = container_resources(report);
    let Some(resource) = resources
        .get(selected)
        .copied()
        .filter(|item| item.matches(filter))
    else {
        return 0;
    };
    let visible = visible_container_indices(report, filter);
    let mut line = usize::from(!filter.is_empty());
    for category in [
        ContainerCategory::Stopped,
        ContainerCategory::UnusedNetwork,
        ContainerCategory::BuildCache,
    ] {
        line += 1;
        let category_indices = visible
            .iter()
            .filter(|index| resources[**index].category() == category)
            .collect::<Vec<_>>();
        if resource.category() == category {
            return line
                + category_indices
                    .iter()
                    .position(|index| **index == selected)
                    .unwrap_or(0);
        }
        line += category_indices.len().max(1);
    }
    0
}

fn container_resource_line(resource: ContainerSelection<'_>, selected: bool) -> String {
    let marker = if selected { "›" } else { " " };
    let field = |item: &serde_json::Value, keys: &[&str]| {
        keys.iter()
            .find_map(|key| item.get(key))
            .map_or("?".into(), |value| value.to_string())
    };
    match resource {
        ContainerSelection::Stopped { engine, id, item } => format!(
            "{marker} {engine} {} {} image={} state={}",
            &id[..12],
            field(item, &["Names", "Name", "names", "name"]),
            field(item, &["Image", "image"]),
            field(item, &["State", "state"])
        ),
        ContainerSelection::UnusedNetwork { engine, id, item } => format!(
            "{marker} {engine} {} {} driver={}",
            &id[..12],
            field(item, &["Name", "name"]),
            field(item, &["Driver", "driver"])
        ),
        ContainerSelection::BuildCache { builder, id, item } => format!(
            "{marker} {builder} {id} type={} size={}",
            field(item, &["Type", "type"]),
            field(item, &["Size", "size"])
        ),
    }
}

fn container_screen_content(app: &App, report: &[crate::containers::EngineStatus]) -> String {
    let resources = container_resources(report);
    let visible = visible_container_indices(report, &app.container_filter);
    let mut lines = Vec::new();
    if !app.container_filter.is_empty() {
        lines.push(format!(
            "Filter: {} ({}/{} eligible resources). Full engine details below are not filtered or selectable.",
            app.container_filter,
            visible.len(),
            resources.len()
        ));
    }
    for (category, title, empty) in [
        (
            ContainerCategory::Stopped,
            "Exited containers (select and press d to preview removal):",
            "No exited containers with complete IDs found.",
        ),
        (
            ContainerCategory::UnusedNetwork,
            "Unused networks (select and press d to preview removal):",
            "No unused networks with complete IDs found.",
        ),
        (
            ContainerCategory::BuildCache,
            "Private, immutable build cache (select and press d to preview):",
            "No eligible Buildx cache IDs found.",
        ),
    ] {
        lines.push(title.into());
        let category_indices = visible
            .iter()
            .filter(|index| resources[**index].category() == category)
            .copied()
            .collect::<Vec<_>>();
        if category_indices.is_empty() {
            lines.push(if app.container_filter.is_empty() {
                format!("  {empty}")
            } else {
                "  No matching eligible resources.".into()
            });
        } else {
            lines.extend(category_indices.into_iter().map(|index| {
                container_resource_line(resources[index], index == app.container_selected)
            }));
        }
    }
    lines.push("Dangling images (read-only; removal unsupported):".into());
    let images = dangling_images(report);
    if images.is_empty() {
        lines.push("  No dangling images with complete IDs found.".into());
    } else {
        let field = |item: &serde_json::Value, keys: &[&str]| {
            keys.iter()
                .find_map(|key| item.get(key))
                .map_or("?".into(), |value| value.to_string())
        };
        lines.extend(images.into_iter().map(|(engine, id, item)| {
            format!(
                "  {engine} {} size={}",
                &id[..12],
                field(item, &["Size", "size"])
            )
        }));
    }
    lines.push(
        "Full engine inventory (reference only; only eligible rows above are selectable):".into(),
    );
    for engine in report {
        lines.push(format!("{}: {}", engine.engine, engine.state));
        lines.extend(engine.usage.iter().map(|row| {
            let field = |key| {
                row.get(key).map_or("?".into(), |value| {
                    value.as_str().map_or_else(
                        || value.to_string(),
                        |text| text.chars().flat_map(char::escape_default).collect(),
                    )
                })
            };
            format!(
                "  {}: total={} active={} size={} reclaimable={}",
                field("Type"),
                field("Total"),
                field("Active"),
                field("Size"),
                field("Reclaimable")
            )
        }));
        if let Some(detail) = &engine.detail {
            lines.push(format!("  {detail}"));
        }
        for list in &engine.resources {
            lines.push(format!("  {}:", list.kind));
            if let Some(error) = list.error {
                lines.push(format!("    {error}"));
            }
            lines.extend(list.items.iter().map(|item| format!("    {item}")));
        }
    }
    lines.push("Storage figures are estimates; removal requires a separate preview.".into());
    lines
        .iter()
        .map(|line| schedule_escape_controls(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn artifact_matches(candidate: &crate::sweep::Candidate, filter: &str) -> bool {
    let filter = filter.to_lowercase();
    filter.is_empty()
        || candidate.ecosystem.to_lowercase().contains(&filter)
        || crate::sweep::display_path(&candidate.project_root)
            .to_lowercase()
            .contains(&filter)
        || crate::sweep::display_path(&candidate.target)
            .to_lowercase()
            .contains(&filter)
}

fn cache_matches(entry: &crate::cache::CacheEntry, filter: &str) -> bool {
    let filter = filter.to_lowercase();
    filter.is_empty()
        || entry.name.to_lowercase().contains(&filter)
        || crate::shared_cache_cleanup::display_path(&entry.path)
            .to_lowercase()
            .contains(&filter)
}

fn visible_cache_entries<'a>(
    report: &'a crate::cache::CacheReport,
    filter: &str,
    sort: CacheSort,
) -> Vec<&'a crate::cache::CacheEntry> {
    let mut visible = report
        .entries
        .iter()
        .filter(|entry| cache_matches(entry, filter))
        .collect::<Vec<_>>();
    visible.sort_by(|a, b| sort.compare(a, b));
    let mut unique_paths = std::collections::HashSet::new();
    visible.retain(|entry| unique_paths.insert(entry.path.clone()));
    visible
}

fn trash_location_path(path: &std::path::Path) -> String {
    if path.as_os_str().is_empty() {
        "(virtual; no filesystem path)".into()
    } else {
        crate::sweep::display_path(path)
    }
}

fn toolchain_matches(report: &ToolReport, filter: &str) -> bool {
    let filter = filter.to_lowercase();
    filter.is_empty()
        || report.tool.as_str().to_lowercase().contains(&filter)
        || report
            .installed
            .as_ref()
            .is_some_and(|version| version.to_string().to_lowercase().contains(&filter))
        || report
            .latest
            .as_ref()
            .is_some_and(|version| version.to_string().to_lowercase().contains(&filter))
        || format!("{:?}", report.status)
            .to_lowercase()
            .contains(&filter)
        || report
            .notes
            .iter()
            .any(|note| note.to_lowercase().contains(&filter))
}

fn visible_toolchain_indices(reports: &[ToolReport], filter: &str) -> Vec<usize> {
    reports
        .iter()
        .enumerate()
        .filter_map(|(index, report)| toolchain_matches(report, filter).then_some(index))
        .collect()
}

fn compact_toolchain_footer(app: &App, content_width: u16) -> &'static str {
    if app.managed_mode {
        let batch = app
            .managed_scope
            .as_ref()
            .is_some_and(|scope| scope.len() > 1);
        if batch {
            if content_width < 31 {
                "Space D review q"
            } else if content_width < 40 {
                "Space: mark D: review q: quit"
            } else if content_width < 59 {
                "r refresh Space mark D review q quit"
            } else {
                "r: refresh  ↑/↓: select  Space: mark  D: review  q: quit"
            }
        } else if content_width < 24 {
            "Enter/d clean q"
        } else if content_width < 40 {
            "Enter/d: clean q: quit"
        } else if content_width < 57 {
            "r: refresh  Enter/d: clean  q: quit"
        } else {
            "r: refresh  ↑/↓: select  Enter/d: clean  q: quit"
        }
    } else if content_width < 24 {
        "Enter update q"
    } else if content_width < 40 {
        "Enter: update q: quit"
    } else if content_width < 59 {
        "r: refresh  Enter: update  q: quit"
    } else {
        "/: filter  r: refresh  ↑/↓: select  Enter: update  q: quit"
    }
}

fn visible_plan_index(
    plan: &crate::sweep::CleanupPlan,
    filter: &str,
    index: usize,
) -> Option<usize> {
    plan.items
        .iter()
        .enumerate()
        .filter(|(_, item)| artifact_matches(&item.candidate, filter))
        .nth(index)
        .map(|(index, _)| index)
}

impl App {
    fn show_schedule_install_preview(
        &mut self,
        plan: crate::schedule::ScanSchedulePreview,
        frequency: crate::schedule::Frequency,
    ) {
        self.schedule_read_only |=
            !cfg!(target_os = "linux") && crate::schedule::schedules_artifact_cleanup(&plan);
        self.schedule_install_plan = Some((plan, frequency));
        self.message.clear();
    }

    fn normalize_toolchain_selection(&mut self) {
        if let Some(reports) = &self.reports {
            let visible = visible_toolchain_indices(reports, &self.toolchain_filter);
            if !visible.contains(&self.selected)
                && let Some(index) = visible.first()
            {
                self.selected = *index;
            }
        }
    }

    fn move_toolchain_selection(&mut self, forward: bool) {
        let Some(reports) = &self.reports else {
            return;
        };
        let visible = visible_toolchain_indices(reports, &self.toolchain_filter);
        if visible.is_empty() {
            return;
        }
        let position = visible.iter().position(|index| *index == self.selected);
        let next = match position {
            Some(position) if forward => (position + 1).min(visible.len() - 1),
            Some(position) => position.saturating_sub(1),
            None => 0,
        };
        self.selected = visible[next];
    }

    fn selected_toolchain(&self) -> Option<ToolKind> {
        self.reports
            .as_ref()?
            .get(self.selected)
            .filter(|report| toolchain_matches(report, &self.toolchain_filter))
            .map(|report| report.tool)
    }

    fn normalize_container_selection(&mut self) {
        if let Some(report) = &self.containers {
            let visible = visible_container_indices(report, &self.container_filter);
            if !visible.contains(&self.container_selected)
                && let Some(index) = visible.first()
            {
                self.container_selected = *index;
            }
        }
    }

    fn move_container_selection(&mut self, forward: bool) {
        let Some(report) = &self.containers else {
            return;
        };
        let visible = visible_container_indices(report, &self.container_filter);
        if visible.is_empty() {
            return;
        }
        let position = visible
            .iter()
            .position(|index| *index == self.container_selected);
        let next = match position {
            Some(position) if forward => (position + 1).min(visible.len() - 1),
            Some(position) => position.saturating_sub(1),
            None => 0,
        };
        self.container_selected = visible[next];
    }

    fn normalize_cache_selection(&mut self) {
        let Some(report) = &self.cache else {
            return;
        };
        let selection_still_exists = self
            .cache_selected
            .as_ref()
            .is_some_and(|selected| report.entries.iter().any(|entry| &entry.path == selected));
        if !selection_still_exists {
            self.cache_selected =
                visible_cache_entries(report, &self.cache_filter, self.cache_sort)
                    .first()
                    .map(|entry| entry.path.clone());
        }
    }

    fn move_cache_selection(&mut self, forward: bool) {
        let visible_paths = self
            .cache
            .as_ref()
            .map(|report| {
                visible_cache_entries(report, &self.cache_filter, self.cache_sort)
                    .into_iter()
                    .map(|entry| entry.path.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if visible_paths.is_empty() {
            self.cache_selected = None;
            return;
        }
        let position = visible_paths
            .iter()
            .position(|path| Some(path) == self.cache_selected.as_ref());
        let next = match position {
            Some(position) if forward => (position + 1).min(visible_paths.len() - 1),
            Some(position) => position.saturating_sub(1),
            None => 0,
        };
        self.cache_selected = Some(visible_paths[next].clone());
    }

    fn sort_artifacts(&mut self) {
        let selected = if let Some(Ok(plan)) = &self.plan {
            visible_plan_index(plan, &self.artifact_filter, self.scan_scroll as usize)
                .map(|index| plan.items[index].candidate.target.clone())
        } else {
            self.scan
                .as_ref()
                .and_then(|report| report.as_ref().ok())
                .and_then(|report| {
                    report
                        .candidates
                        .iter()
                        .filter(|candidate| artifact_matches(candidate, &self.artifact_filter))
                        .nth(self.scan_scroll as usize)
                        .map(|candidate| candidate.target.clone())
                })
        };
        if let Some(Ok(report)) = &mut self.scan {
            report
                .candidates
                .sort_by(|a, b| self.artifact_sort.compare(a, b));
        }
        if let Some(Ok(plan)) = &mut self.plan {
            plan.items
                .sort_by(|a, b| self.artifact_sort.compare(&a.candidate, &b.candidate));
        }
        let position = if let Some(Ok(plan)) = &self.plan {
            plan.items
                .iter()
                .map(|item| &item.candidate)
                .filter(|candidate| artifact_matches(candidate, &self.artifact_filter))
                .position(|candidate| Some(&candidate.target) == selected.as_ref())
        } else if let Some(Ok(report)) = &self.scan {
            report
                .candidates
                .iter()
                .filter(|candidate| artifact_matches(candidate, &self.artifact_filter))
                .position(|candidate| Some(&candidate.target) == selected.as_ref())
        } else {
            None
        };
        self.scan_scroll = position
            .and_then(|index| u16::try_from(index).ok())
            .unwrap_or(0);
    }

    fn update_artifact_review(&mut self, area: Rect) {
        if let Some(plan) = &self.artifact_plan
            && (!self.artifact_confirm || matches!(plan, DirectoryPlan::ArtifactBatch(_)))
        {
            let content = if self.artifact_confirm {
                artifact_batch_confirmation_content(plan, area)
            } else {
                artifact_review_lines(plan, area)
            };
            if self.artifact_review_width != area.width || self.artifact_review_content != content {
                self.artifact_review_scroll = 0;
                self.artifact_review_width = area.width;
                self.artifact_review_content = content;
            }
            self.artifact_review_rows = if self.artifact_review_content.is_some() {
                if self.artifact_confirm {
                    artifact_batch_confirmation_rows(area)
                } else {
                    artifact_review_rows(plan, area)
                }
            } else {
                0
            };
            self.artifact_review_lines = self.artifact_review_content.as_ref().map_or(0, Vec::len);
        }
    }

    fn update_managed_batch_review(&mut self, area: Rect) {
        if self.managed_batch_plans.is_empty() {
            self.managed_batch_review_scroll = 0;
            self.managed_batch_review_rows = 0;
            self.managed_batch_review_lines = 0;
            self.managed_batch_review_area = Rect::default();
            self.managed_batch_review_content = None;
            return;
        }
        let content = managed_batch_review_content(&self.managed_batch_plans, area);
        if self.managed_batch_review_area != area || self.managed_batch_review_content != content {
            self.managed_batch_review_scroll = 0;
        }
        self.managed_batch_review_area = area;
        self.managed_batch_review_content = content;
        self.managed_batch_review_rows = if self.managed_batch_review_content.is_some() {
            managed_batch_review_rows(area)
        } else {
            0
        };
        self.managed_batch_review_lines = self
            .managed_batch_review_content
            .as_ref()
            .map_or(0, Vec::len);
        self.managed_batch_review_scroll = self.managed_batch_review_scroll.min(
            self.managed_batch_review_lines
                .saturating_sub(self.managed_batch_review_rows),
        );
    }

    fn update_temp_review(&mut self, area: Rect) {
        if let Some(plan) = &self.temp_review_plan {
            let (lines, rows) =
                temp_cleanup_review_metrics(plan, self.temp_review_confirm, self.dry_run, area);
            if self.temp_review_area != area {
                self.temp_review_scroll = 0;
                self.temp_review_area = area;
            }
            self.temp_review_lines = lines;
            self.temp_review_rows = rows;
            self.temp_review_scroll = self
                .temp_review_scroll
                .min(lines.saturating_sub(rows).min(u16::MAX as usize) as u16);
        } else {
            self.temp_review_scroll = 0;
            self.temp_review_rows = 0;
            self.temp_review_lines = 0;
            self.temp_review_area = Rect::default();
        }
    }

    fn update_schedule_confirmation(&mut self, area: Rect) {
        let Some((identity, lines, preview_token)) = schedule_confirmation_review(self) else {
            self.schedule_confirmation_scroll = 0;
            self.schedule_preview_scroll = 0;
            self.schedule_confirmation_area = area;
            self.schedule_confirmation_identity = None;
            self.schedule_confirmation_content = None;
            return;
        };
        let identity = if self.schedule_read_only {
            format!("preview:{identity}")
        } else {
            format!("confirm:{identity}")
        };
        let content = if self.schedule_read_only {
            schedule_preview_display_lines(lines, &preview_token, area)
        } else {
            schedule_confirmation_display_lines(&lines, area)
        };
        if self.schedule_confirmation_area != area
            || self.schedule_confirmation_identity.as_deref() != Some(identity.as_str())
            || self.schedule_confirmation_content.as_ref() != Some(&content)
        {
            if self.schedule_read_only {
                self.schedule_preview_scroll = 0;
            } else {
                self.schedule_confirmation_scroll = 0;
            }
        }
        self.schedule_confirmation_area = area;
        self.schedule_confirmation_identity = Some(identity);
        self.schedule_confirmation_content = Some(content);
        let visible_rows = schedule_confirmation_visible_rows(area);
        let max_scroll = self
            .schedule_confirmation_content
            .as_ref()
            .map_or(0, |lines| lines.len().saturating_sub(visible_rows));
        if self.schedule_read_only {
            self.schedule_preview_scroll = self
                .schedule_preview_scroll
                .min(u16::try_from(max_scroll.min(u16::MAX as usize)).unwrap_or(u16::MAX));
            self.schedule_confirmation_scroll = 0;
        } else {
            self.schedule_confirmation_scroll = self
                .schedule_confirmation_scroll
                .min(max_scroll.min(u16::MAX as usize));
            self.schedule_preview_scroll = 0;
        }
    }

    fn update_history_purge_review(&mut self, area: Rect) {
        let Some(plan) = &self.history_purge_plan else {
            self.history_purge_scroll = 0;
            self.history_purge_area = area;
            self.history_purge_content = None;
            return;
        };
        let content = schedule_confirmation_display_lines(
            &history_purge_confirmation_lines(plan, self.history_purge_read_only),
            area,
        );
        if self.history_purge_area != area || self.history_purge_content.as_ref() != Some(&content)
        {
            self.history_purge_scroll = 0;
        }
        self.history_purge_area = area;
        self.history_purge_content = Some(content);
        let max_scroll = self.history_purge_content.as_ref().map_or(0, |lines| {
            lines
                .len()
                .saturating_sub(history_purge_visible_rows(area))
                .min(u16::MAX as usize)
        });
        self.history_purge_scroll = self.history_purge_scroll.min(max_scroll as u16);
    }

    fn update_settings_confirmation_area(&mut self, area: Rect) {
        if self.settings_confirmation_area != area {
            self.settings_confirmation_scroll = 0;
            self.settings_confirmation_area = area;
        }
    }

    fn key(&mut self, key: KeyEvent) -> Action {
        if key.kind == KeyEventKind::Release
            || (key.kind == KeyEventKind::Repeat
                && !matches!(
                    key.code,
                    KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown
                )
                && !(key.modifiers == KeyModifiers::NONE
                    && matches!(key.code, KeyCode::Char('j' | 'k'))))
        {
            return Action::None;
        }
        if schedule_activation_is_preview_only(self) {
            self.schedule_read_only = true;
        }
        if self.settings_saving {
            return Action::None;
        }
        #[cfg(target_os = "linux")]
        if self.trash_retention_preparing || self.trash_retention_running {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('q'))
                || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
            {
                self.message = "Wait for the Trash retention operation to finish.".into();
            }
            return Action::None;
        }
        if self.temp_preparing || self.temp_running {
            return match key.code {
                KeyCode::Esc => {
                    self.message = if self.temp_running {
                        "Cancellation requested; the current staging directory may finish.".into()
                    } else {
                        "Cancelling staging inventory…".into()
                    };
                    Action::CancelTemp
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.message = if self.temp_running {
                        "Cancellation requested; the current staging directory may finish.".into()
                    } else {
                        "Cancelling staging inventory…".into()
                    };
                    Action::CancelTemp
                }
                KeyCode::Char('q') => {
                    self.message =
                        "An operation is running; wait or press Esc to request cancellation."
                            .into();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.temp_review_plan.is_some() {
            let max_scroll = self.temp_review_lines.saturating_sub(self.temp_review_rows);
            return match key.code {
                KeyCode::Esc | KeyCode::Char('n') => {
                    self.temp_review_plan = None;
                    self.temp_review_confirm = false;
                    self.temp_review_scroll = 0;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.temp_review_scroll = self.temp_review_scroll.saturating_sub(1);
                    Action::None
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.temp_review_scroll =
                        (self.temp_review_scroll + 1).min(max_scroll.min(u16::MAX as usize) as u16);
                    Action::None
                }
                KeyCode::PageUp => {
                    self.temp_review_scroll = self
                        .temp_review_scroll
                        .saturating_sub(self.temp_review_rows.min(u16::MAX as usize) as u16);
                    Action::None
                }
                KeyCode::PageDown => {
                    self.temp_review_scroll = (self.temp_review_scroll
                        + self.temp_review_rows.min(u16::MAX as usize) as u16)
                        .min(max_scroll.min(u16::MAX as usize) as u16);
                    Action::None
                }
                KeyCode::Enter if !self.temp_review_confirm => {
                    if self.temp_review_rows == 0 {
                        self.message =
                            "Enlarge the terminal to review the complete staging inventory.".into();
                    } else if self.temp_review_scroll as usize + self.temp_review_rows
                        < self.temp_review_lines
                    {
                        self.message =
                            "Scroll through every staging candidate and warning before continuing."
                                .into();
                    } else {
                        self.temp_review_confirm = true;
                        self.temp_review_scroll = 0;
                        self.message.clear();
                    }
                    Action::None
                }
                #[cfg(target_os = "linux")]
                KeyCode::Char('y')
                    if self.temp_review_confirm
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if self.temp_review_rows == 0 {
                        self.message =
                            "Enlarge the terminal to review the complete confirmation.".into();
                        return Action::None;
                    }
                    if self.temp_review_scroll as usize + self.temp_review_rows
                        < self.temp_review_lines
                    {
                        self.message =
                            "Scroll through every selected path and warning before confirming."
                                .into();
                        return Action::None;
                    }
                    if self.dry_run {
                        self.temp_review_plan = None;
                        self.temp_review_confirm = false;
                        self.temp_result = Some("Dry run: no staging directories were removed and no history was written.".into());
                        self.message.clear();
                        return Action::None;
                    }
                    let plan = self.temp_review_plan.take().expect("review plan exists");
                    self.temp_review_confirm = false;
                    self.temp_running = true;
                    self.message =
                        "Removing reviewed staging directories; Esc requests cancellation.".into();
                    Action::RemoveTempCleanup(plan)
                }
                _ => Action::None,
            };
        }
        if self.temp_mode
            && self.page == Start::Maintenance
            && !matches!(
                key.code,
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right
            )
        {
            return match key.code {
                KeyCode::Esc | KeyCode::Char('b') => {
                    self.temp_mode = false;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('r') => {
                    self.temp_preparing = true;
                    self.temp_plan = None;
                    self.temp_marks.clear();
                    self.temp_selected = 0;
                    self.temp_result = None;
                    self.temp_result_scroll = 0;
                    self.temp_inventory_scroll_offset = 0;
                    self.message = "Inspecting Upkit link staging directories…".into();
                    Action::PreviewTempCleanup(Vec::new(), false)
                }
                KeyCode::Up | KeyCode::Char('k') if self.temp_result.is_some() => {
                    self.temp_result_scroll = self.temp_result_scroll.saturating_sub(1);
                    Action::None
                }
                KeyCode::Down | KeyCode::Char('j') if self.temp_result.is_some() => {
                    self.temp_result_scroll = self.temp_result_scroll.saturating_add(1);
                    Action::None
                }
                KeyCode::PageUp if self.temp_result.is_some() => {
                    self.temp_result_scroll = self.temp_result_scroll.saturating_sub(8);
                    Action::None
                }
                KeyCode::PageDown if self.temp_result.is_some() => {
                    self.temp_result_scroll = self.temp_result_scroll.saturating_add(8);
                    Action::None
                }
                KeyCode::PageUp => {
                    self.temp_inventory_scroll_offset =
                        self.temp_inventory_scroll_offset.saturating_sub(8);
                    Action::None
                }
                KeyCode::PageDown => {
                    self.temp_inventory_scroll_offset =
                        self.temp_inventory_scroll_offset.saturating_add(8);
                    Action::None
                }
                KeyCode::Home => {
                    self.temp_inventory_scroll_offset = i32::MIN;
                    Action::None
                }
                KeyCode::End => {
                    self.temp_inventory_scroll_offset = i32::MAX;
                    Action::None
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.temp_selected = self.temp_selected.saturating_sub(1);
                    self.temp_inventory_scroll_offset = 0;
                    Action::None
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    #[cfg(target_os = "linux")]
                    if let Some(Ok(plan)) = &self.temp_plan {
                        self.temp_selected = self
                            .temp_selected
                            .saturating_add(1)
                            .min(plan.candidates.len().saturating_sub(1));
                    }
                    self.temp_inventory_scroll_offset = 0;
                    Action::None
                }
                KeyCode::Char(' ') => {
                    #[cfg(target_os = "linux")]
                    if self.temp_inventory_scroll_offset != 0 {
                        self.temp_inventory_scroll_offset = 0;
                        self.message =
                            "Returned to the selected candidate; press Space again to mark it."
                                .into();
                        return Action::None;
                    }
                    #[cfg(target_os = "linux")]
                    if let Some(Ok(plan)) = &self.temp_plan
                        && let Some(candidate) = plan.candidates.get(self.temp_selected)
                    {
                        if !plan.complete || candidate.status != "eligible" {
                            self.message = "Only eligible candidates from a complete inventory can be selected.".into();
                        } else if let Some(index) = self
                            .temp_marks
                            .iter()
                            .position(|path| path == &candidate.path)
                        {
                            self.temp_marks.remove(index);
                            self.message.clear();
                        } else {
                            self.temp_marks.push(candidate.path.clone());
                            self.temp_marks.sort();
                            self.message.clear();
                        }
                    }
                    Action::None
                }
                KeyCode::Char('d' | 'v') | KeyCode::Enter => {
                    if self.temp_marks.is_empty() {
                        self.message =
                            "Mark at least one eligible staging directory with Space.".into();
                        Action::None
                    } else {
                        self.temp_preparing = true;
                        self.message =
                            "Building a fresh preview for the selected staging directories…".into();
                        Action::PreviewTempCleanup(self.temp_marks.clone(), true)
                    }
                }
                _ => Action::None,
            };
        }
        if self.history_purge_preparing || self.history_purging {
            return match key.code {
                KeyCode::Esc => {
                    self.message = if self.history_purging {
                        "Cancellation requested; removal may already be in progress.".into()
                    } else {
                        "Cancelling history purge preview…".into()
                    };
                    Action::CancelHistoryPurge
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.message = if self.history_purging {
                        "Cancellation requested; removal may already be in progress.".into()
                    } else {
                        "Cancelling history purge preview…".into()
                    };
                    Action::CancelHistoryPurge
                }
                _ => Action::None,
            };
        }
        if self.history_purge_plan.is_some() {
            let visible = history_purge_visible_rows(self.history_purge_area);
            let max_scroll = self.history_purge_content.as_ref().map_or(0, |lines| {
                lines.len().saturating_sub(visible).min(u16::MAX as usize)
            }) as u16;
            return match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.history_purge_scroll =
                        self.history_purge_scroll.saturating_add(1).min(max_scroll);
                    Action::None
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.history_purge_scroll = self.history_purge_scroll.saturating_sub(1);
                    Action::None
                }
                KeyCode::PageDown => {
                    let step = visible.saturating_sub(1).max(1).min(u16::MAX as usize) as u16;
                    self.history_purge_scroll = self
                        .history_purge_scroll
                        .saturating_add(step)
                        .min(max_scroll);
                    Action::None
                }
                KeyCode::PageUp => {
                    let step = visible.saturating_sub(1).max(1).min(u16::MAX as usize) as u16;
                    self.history_purge_scroll = self.history_purge_scroll.saturating_sub(step);
                    Action::None
                }
                KeyCode::Char('y')
                    if !self.history_purge_read_only
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if !history_purge_ready(self, self.history_purge_area) {
                        self.message =
                            "Scroll through every history record and warning before confirming."
                                .into();
                        return Action::None;
                    }
                    self.history_purge_content = None;
                    self.history_purge_scroll = 0;
                    self.history_purging = true;
                    self.message =
                        "Removing reviewed history records; Esc requests cancellation.".into();
                    Action::PurgeHistory(self.history_purge_plan.take().expect("preview exists"))
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.history_purge_plan = None;
                    self.history_purge_read_only = false;
                    self.history_purge_content = None;
                    self.history_purge_scroll = 0;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.history_purge_plan = None;
                    self.history_purge_read_only = false;
                    self.history_purge_content = None;
                    self.history_purge_scroll = 0;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if let Some(prompt) = self.settings_prompt {
            return match key.code {
                KeyCode::Char('y')
                    if prompt == SettingsPrompt::Save
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    self.settings_prompt = None;
                    if let Some(pending) = self.settings_pending_save.take() {
                        self.settings_saving = true;
                        self.message = "Saving configuration…".into();
                        Action::SaveSettings(pending.snapshot, pending.text)
                    } else {
                        self.message = "No configuration save is pending.".into();
                        Action::None
                    }
                }
                KeyCode::Char('y')
                    if prompt == SettingsPrompt::Discard
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    self.settings_prompt = None;
                    self.settings_editor = None;
                    self.settings_form = None;
                    self.settings_pending_save = None;
                    self.message = "Edits discarded.".into();
                    Action::None
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.settings_prompt = None;
                    self.settings_pending_save = None;
                    self.settings_confirmation_scroll = 0;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.settings_prompt = None;
                    self.settings_pending_save = None;
                    self.settings_confirmation_scroll = 0;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Up => {
                    self.settings_confirmation_scroll =
                        self.settings_confirmation_scroll.saturating_sub(1);
                    Action::None
                }
                KeyCode::Down => {
                    self.settings_confirmation_scroll =
                        self.settings_confirmation_scroll.saturating_add(1);
                    Action::None
                }
                _ => Action::None,
            };
        }
        if let Some(editor) = &mut self.settings_editor {
            if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL) {
                let text = editor.text();
                if text == editor.snapshot.text && editor.snapshot.exists() {
                    self.message = "No changes to save.".into();
                } else if editor.snapshot.exists() && !cfg!(target_os = "linux") {
                    self.message =
                        "Replacing an existing configuration is unavailable on this platform."
                            .into();
                } else if let Err(error) = crate::config::validate_document(&text) {
                    self.message = format!(
                        "Invalid configuration: {}",
                        settings_error(&format!("{error:#}"))
                    );
                } else {
                    match settings_cleanup_impacts_between(&editor.snapshot, &text) {
                        Ok(cleanup_impacts) => {
                            self.settings_pending_save = Some(SettingsPendingSave {
                                snapshot: editor.snapshot.clone(),
                                changes: settings_change_lines(&editor.snapshot, &text),
                                text,
                                cleanup_impacts,
                            });
                            self.settings_confirmation_scroll = 0;
                            self.settings_prompt = Some(SettingsPrompt::Save);
                            self.message.clear();
                        }
                        Err(error) => {
                            self.message = format!(
                                "Invalid configuration: {}",
                                settings_error(&format!("{error:#}"))
                            );
                        }
                    }
                }
            } else if key.code == KeyCode::Esc
                || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
            {
                if editor.text() == editor.snapshot.text {
                    self.settings_editor = None;
                    self.message.clear();
                } else {
                    self.settings_confirmation_scroll = 0;
                    self.settings_prompt = Some(SettingsPrompt::Discard);
                }
            } else if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            {
                if !editor.key(key.code) {
                    self.message = "Configuration cannot exceed 128 KiB.".into();
                } else {
                    self.message.clear();
                }
            }
            return Action::None;
        }
        if self.settings_form.is_some() {
            if let Some(mut input) = self
                .settings_form
                .as_mut()
                .and_then(|form| form.input.take())
            {
                match key.code {
                    KeyCode::Enter => {
                        let result = settings_input_apply(
                            self.settings_form.as_mut().expect("settings form exists"),
                            &input,
                        );
                        if let Err(error) = result {
                            self.message = settings_error(&format!("{error:#}"));
                            input.cursor = input.cursor.min(input.value.len());
                            self.settings_form.as_mut().unwrap().input = Some(input);
                        } else {
                            self.message.clear();
                        }
                    }
                    KeyCode::Esc => self.message.clear(),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.message.clear();
                    }
                    _ if key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                    {
                        self.settings_form.as_mut().unwrap().input = Some(input);
                    }
                    code => {
                        if !settings_text_input_key(&mut input, code) {
                            self.message = "Setting value cannot exceed 128 KiB.".into();
                        } else {
                            self.message.clear();
                        }
                        self.settings_form.as_mut().unwrap().input = Some(input);
                    }
                }
                return Action::None;
            }

            let mut switch_to_toml = None;
            let mut close_form = false;
            if let Some(form) = &mut self.settings_form {
                let rows = settings_rows(form);
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        form.selected = form.selected.saturating_sub(1);
                        self.message.clear();
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        form.selected = form.selected.saturating_add(1).min(rows.len() - 1);
                        self.message.clear();
                    }
                    KeyCode::Left | KeyCode::Right
                        if matches!(rows[form.selected], SettingsRow::Profile) =>
                    {
                        form.move_profile(key.code == KeyCode::Right);
                        self.message.clear();
                    }
                    KeyCode::Char('n')
                        if !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                    {
                        form.input = Some(SettingsInput {
                            target: form.target(SettingsField::WorkspaceRoots),
                            new_profile: true,
                            index: None,
                            value: Vec::new(),
                            cursor: 0,
                        });
                        self.message.clear();
                    }
                    KeyCode::Enter => match rows[form.selected] {
                        SettingsRow::Profile => {
                            form.move_profile(true);
                            self.message.clear();
                        }
                        row @ (SettingsRow::Root(_)
                        | SettingsRow::AddRoot
                        | SettingsRow::Exclusion(_)
                        | SettingsRow::AddExclusion
                        | SettingsRow::Retention) => {
                            form.input = settings_input_for_row(form, row);
                            self.message.clear();
                        }
                        row @ (SettingsRow::Ecosystem(_)
                        | SettingsRow::AllEcosystems
                        | SettingsRow::ScheduledCleanup
                        | SettingsRow::ScheduledArtifactCleanup
                        | SettingsRow::ScheduledTrashRetention
                        | SettingsRow::ScheduleFrequency
                        | SettingsRow::Theme) => {
                            if let SettingsRow::Ecosystem(ecosystem) = row
                                && form.profile.is_some()
                                && form
                                    .settings
                                    .enabled_ecosystems
                                    .as_ref()
                                    .is_some_and(|items| !items.contains(&ecosystem))
                            {
                                self.message = "This ecosystem is disabled globally; profiles cannot re-enable it.".into();
                            } else {
                                settings_form_toggle(form, row);
                                self.message.clear();
                            }
                        }
                    },
                    KeyCode::Char(' ') => {
                        if matches!(
                            rows[form.selected],
                            SettingsRow::Ecosystem(_)
                                | SettingsRow::ScheduledCleanup
                                | SettingsRow::ScheduledArtifactCleanup
                                | SettingsRow::ScheduledTrashRetention
                                | SettingsRow::ScheduleFrequency
                                | SettingsRow::Theme
                        ) {
                            if let SettingsRow::Ecosystem(ecosystem) = rows[form.selected]
                                && form.profile.is_some()
                                && form
                                    .settings
                                    .enabled_ecosystems
                                    .as_ref()
                                    .is_some_and(|items| !items.contains(&ecosystem))
                            {
                                self.message = "This ecosystem is disabled globally; profiles cannot re-enable it.".into();
                            } else {
                                settings_form_toggle(form, rows[form.selected]);
                                self.message.clear();
                            }
                        }
                    }
                    KeyCode::Char('d') | KeyCode::Delete
                        if !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                    {
                        match rows[form.selected] {
                            SettingsRow::Root(index) => remove_settings_path(
                                form,
                                form.target(SettingsField::WorkspaceRoots),
                                index,
                            ),
                            SettingsRow::Exclusion(index) => remove_settings_path(
                                form,
                                form.target(SettingsField::Exclusions),
                                index,
                            ),
                            _ => {}
                        }
                        self.message.clear();
                    }
                    KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        match form.has_changes() {
                            Ok(false) => self.message = "No changes to save.".into(),
                            Err(error) => {
                                self.message = format!(
                                    "Invalid configuration: {}",
                                    settings_error(&format!("{error:#}"))
                                )
                            }
                            Ok(true) if form.snapshot.exists() && !cfg!(target_os = "linux") => {
                                self.message = "Replacing an existing configuration is unavailable on this platform.".into();
                            }
                            Ok(true) => match form
                                .save_text()
                                .and_then(|text| Ok((text, form.cleanup_impacts()?)))
                            {
                                Ok((text, cleanup_impacts)) => {
                                    self.settings_pending_save = Some(SettingsPendingSave {
                                        snapshot: form.snapshot.clone(),
                                        changes: settings_change_lines(&form.snapshot, &text),
                                        text,
                                        cleanup_impacts,
                                    });
                                    self.settings_confirmation_scroll = 0;
                                    self.settings_prompt = Some(SettingsPrompt::Save);
                                    self.message.clear();
                                }
                                Err(error) => {
                                    self.message = format!(
                                        "Invalid configuration: {}",
                                        settings_error(&format!("{error:#}"))
                                    );
                                }
                            },
                        }
                    }
                    KeyCode::Esc => match form.has_changes() {
                        Ok(true) | Err(_) => {
                            self.settings_confirmation_scroll = 0;
                            self.settings_prompt = Some(SettingsPrompt::Discard);
                        }
                        Ok(false) => close_form = true,
                    },
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        match form.has_changes() {
                            Ok(true) | Err(_) => {
                                self.settings_confirmation_scroll = 0;
                                self.settings_prompt = Some(SettingsPrompt::Discard)
                            }
                            Ok(false) => close_form = true,
                        }
                    }
                    KeyCode::Char('t') => match form.has_changes() {
                        Ok(true) | Err(_) => {
                            self.message =
                                "Save or discard form edits before opening the TOML editor.".into();
                        }
                        Ok(false) => switch_to_toml = Some(form.snapshot.clone()),
                    },
                    _ => {}
                }
            }
            if close_form {
                self.settings_form = None;
                self.message.clear();
            }
            if let Some(snapshot) = switch_to_toml {
                self.settings_form = None;
                self.settings_editor = Some(ConfigEditor::new(snapshot));
                self.message = "Edit TOML; Ctrl+S reviews save, Esc exits.".into();
            }
            return Action::None;
        }
        if self.managed_result.is_some() {
            return match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.managed_result_scroll = self.managed_result_scroll.saturating_sub(1);
                    Action::None
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.managed_result_scroll = self.managed_result_scroll.saturating_add(1);
                    Action::None
                }
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.managed_result = None;
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.managed_result = None;
                    Action::None
                }
                _ => Action::None,
            };
        }
        if !self.managed_batch_plans.is_empty() {
            return match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.managed_batch_review_scroll =
                        self.managed_batch_review_scroll.saturating_sub(1);
                    Action::None
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.managed_batch_review_scroll = (self.managed_batch_review_scroll + 1).min(
                        self.managed_batch_review_lines
                            .saturating_sub(self.managed_batch_review_rows),
                    );
                    Action::None
                }
                KeyCode::Char('y')
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if self.managed_batch_review_rows == 0 {
                        self.message = "Enlarge the terminal to review every selected tool.".into();
                        Action::None
                    } else if !managed_batch_review_scroll_supported(
                        self.managed_batch_review_lines,
                        self.managed_batch_review_rows,
                        self.managed_batch_review_scroll,
                    ) {
                        self.message =
                            "The review exceeds the terminal scroll range; select fewer targets."
                                .into();
                        Action::None
                    } else if self.managed_batch_review_scroll + self.managed_batch_review_rows
                        < self.managed_batch_review_lines
                    {
                        self.message =
                            "Scroll through every selected tool before confirming.".into();
                        Action::None
                    } else if let Some(tool) = managed_batch_active_tool(&self.managed_batch_plans)
                    {
                        self.message = format!(
                            "Stop the process using {} and preview the cleanup again.",
                            tool.as_str()
                        );
                        Action::None
                    } else {
                        let plans = std::mem::take(&mut self.managed_batch_plans);
                        self.managed_batch_review_content = None;
                        self.managed_running = true;
                        self.message =
                            "Preflighting all selected tools before cleanup; Esc requests cancellation."
                                .into();
                        Action::RemoveManagedBatch(plans)
                    }
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.managed_batch_plans.clear();
                    self.managed_batch_review_content = None;
                    self.managed_batch_review_scroll = 0;
                    self.managed_batch_review_rows = 0;
                    self.managed_batch_review_lines = 0;
                    self.managed_batch_review_area = Rect::default();
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.managed_batch_plans.clear();
                    self.managed_batch_review_content = None;
                    self.managed_batch_review_scroll = 0;
                    self.managed_batch_review_rows = 0;
                    self.managed_batch_review_lines = 0;
                    self.managed_batch_review_area = Rect::default();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if let Some(plan) = &self.managed_plan {
            if self.managed_detail {
                return match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.managed_detail_scroll = self.managed_detail_scroll.saturating_sub(1);
                        Action::None
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.managed_detail_scroll = self.managed_detail_scroll.saturating_add(1);
                        Action::None
                    }
                    KeyCode::Esc | KeyCode::Char('q' | 'i') => {
                        self.managed_detail = false;
                        Action::None
                    }
                    _ => Action::None,
                };
            }
            return match key.code {
                KeyCode::Char('i') => {
                    self.managed_detail = true;
                    self.managed_detail_scroll = 0;
                    Action::None
                }
                KeyCode::Char('y')
                    if matches!(
                        plan.activity_status,
                        "open_handles_or_cwd_observed" | "executable_observed"
                    ) =>
                {
                    self.message = "Stop the process using this tool and preview again.".into();
                    Action::None
                }
                KeyCode::Char('y')
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if plan.selected_entries.is_empty() && plan.links.is_empty() {
                        self.message = "No verified installation or recorded link is eligible; root data was preserved.".into();
                        return Action::None;
                    }
                    let plan = self.managed_plan.take().expect("preview exists");
                    self.managed_running = true;
                    self.message = "Cleaning managed tool; wait for verification.".into();
                    Action::RemoveManaged(plan)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.managed_plan = None;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.managed_plan = None;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.managed_preparing {
            return match key.code {
                KeyCode::Esc => {
                    self.message = "Cancelling managed cleanup preview…".into();
                    Action::CancelManaged
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.message = "Cancelling managed cleanup preview…".into();
                    Action::CancelManaged
                }
                _ => Action::None,
            };
        }
        if self.managed_running {
            return match key.code {
                KeyCode::Esc => {
                    self.message =
                        "Cancellation requested; removal may already be in progress.".into();
                    Action::CancelManaged
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.message =
                        "Cancellation requested; removal may already be in progress.".into();
                    Action::CancelManaged
                }
                _ => Action::None,
            };
        }
        if self.artifact_plan.is_some() {
            let artifact_batch = self
                .artifact_plan
                .as_ref()
                .is_some_and(|plan| matches!(plan, DirectoryPlan::ArtifactBatch(_)));
            return match key.code {
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.artifact_plan = None;
                    self.artifact_review_content = None;
                    self.artifact_confirm = false;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.artifact_plan = None;
                    self.artifact_review_content = None;
                    self.artifact_confirm = false;
                    Action::None
                }
                KeyCode::Down | KeyCode::Char('j') if !self.artifact_confirm || artifact_batch => {
                    self.artifact_review_scroll = (self.artifact_review_scroll + 1).min(
                        self.artifact_review_lines
                            .saturating_sub(self.artifact_review_rows),
                    );
                    Action::None
                }
                KeyCode::Up | KeyCode::Char('k') if !self.artifact_confirm || artifact_batch => {
                    self.artifact_review_scroll = self.artifact_review_scroll.saturating_sub(1);
                    Action::None
                }
                KeyCode::Enter
                    if !self.artifact_confirm
                        && self.artifact_review_rows > 0
                        && self.artifact_review_scroll + self.artifact_review_rows
                            >= self.artifact_review_lines =>
                {
                    self.artifact_confirm = true;
                    if artifact_batch {
                        self.artifact_review_scroll = 0;
                        self.artifact_review_content = None;
                        self.artifact_review_width = 0;
                        self.artifact_review_rows = 0;
                        self.artifact_review_lines = 0;
                    }
                    Action::None
                }
                KeyCode::Char('y')
                    if self.artifact_confirm
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if artifact_batch
                        && (self.artifact_review_rows == 0
                            || self.artifact_review_scroll + self.artifact_review_rows
                                < self.artifact_review_lines)
                    {
                        self.message = if self.artifact_review_rows == 0 {
                            "Enlarge the terminal to review every selected target.".into()
                        } else {
                            "Review every selected target before confirming.".into()
                        };
                        return Action::None;
                    }
                    let plan = self.artifact_plan.take().expect("preview exists");
                    self.artifact_review_content = None;
                    self.artifact_confirm = false;
                    self.artifact_running = true;
                    self.message = if artifact_batch {
                        "Removing reviewed directories; Esc requests cancellation.".into()
                    } else {
                        "Removing selected directory; Esc requests cancellation.".into()
                    };
                    match plan {
                        DirectoryPlan::Artifact(plan) => Action::RemoveArtifact(plan),
                        DirectoryPlan::ArtifactBatch(plan) => Action::RemoveArtifactBatch(plan),
                        DirectoryPlan::Cache(plan) => Action::RemoveSharedCache(plan),
                    }
                }
                _ => Action::None,
            };
        }
        if self.artifact_preparing || self.artifact_running {
            return match key.code {
                KeyCode::Esc => Action::CancelScan,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    Action::CancelScan
                }
                _ => Action::None,
            };
        }
        if self.cache_choosing {
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => self.move_cache_selection(true),
                KeyCode::Up | KeyCode::Char('k') => self.move_cache_selection(false),
                KeyCode::Char('s') => {
                    self.cache_sort = self.cache_sort.next();
                    self.normalize_cache_selection();
                }
                KeyCode::Enter => {
                    if let Some(path) = self
                        .cache
                        .as_ref()
                        .and_then(|report| {
                            visible_cache_entries(report, &self.cache_filter, self.cache_sort)
                                .into_iter()
                                .find(|entry| Some(&entry.path) == self.cache_selected.as_ref())
                        })
                        .map(|entry| entry.path.clone())
                    {
                        self.cache_choosing = false;
                        self.artifact_preparing = true;
                        self.message = "Preparing full shared-cache removal preview…".into();
                        return Action::PreviewSharedCache(path);
                    } else {
                        self.message = "Choose a visible cache before reviewing removal.".into();
                    }
                }
                KeyCode::Esc | KeyCode::Char('q') => self.cache_choosing = false,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.cache_choosing = false
                }
                _ => {}
            }
            return Action::None;
        }
        if self.bytecode_batch_plan.is_some() {
            return match key.code {
                KeyCode::Char('y')
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    let plan = self.bytecode_batch_plan.take().expect("preview exists");
                    self.bytecode_running = true;
                    self.message = "Removing selected bytecode; Esc requests cancellation.".into();
                    Action::RemoveBytecodeBatch(plan)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.bytecode_batch_plan = None;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.bytecode_batch_plan = None;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.bytecode_plan.is_some() {
            return match key.code {
                KeyCode::Char('y') => {
                    let plan = self.bytecode_plan.take().expect("preview exists");
                    self.bytecode_running = true;
                    self.message = "Removing bytecode; wait for verification.".into();
                    Action::RemoveBytecode(plan)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.bytecode_plan = None;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.bytecode_plan = None;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.bytecode_preparing || self.bytecode_running || self.bytecode_listing_running {
            return match key.code {
                KeyCode::Esc => {
                    self.message = "Cancelling bytecode operation…".into();
                    Action::CancelScan
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.message = "Cancelling bytecode operation…".into();
                    Action::CancelScan
                }
                _ => Action::None,
            };
        }
        if let Some(listing) = &self.bytecode_listing {
            return match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.bytecode_selected = self
                        .bytecode_selected
                        .saturating_add(1)
                        .min(listing.files.len().saturating_sub(1));
                    Action::None
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.bytecode_selected = self.bytecode_selected.saturating_sub(1);
                    Action::None
                }
                KeyCode::Char(' ') => {
                    if let Some(file) = listing.files.get(self.bytecode_selected) {
                        self.message.clear();
                        if let Some(index) =
                            self.bytecode_marks.iter().position(|marked| marked == file)
                        {
                            self.bytecode_marks.remove(index);
                        } else if self.bytecode_marks.len() < crate::bytecode::MAX_BATCH_FILES {
                            self.bytecode_marks.push(file.clone());
                        } else {
                            self.message = format!(
                                "Select at most {} files.",
                                crate::bytecode::MAX_BATCH_FILES
                            );
                        }
                    }
                    Action::None
                }
                KeyCode::Enter => {
                    if !self.bytecode_marks.is_empty() {
                        self.bytecode_preparing = true;
                        self.message = "Preparing bytecode batch preview…".into();
                        Action::PreviewBytecodeBatch(self.bytecode_marks.clone())
                    } else if let Some(file) = listing.files.get(self.bytecode_selected) {
                        self.bytecode_preparing = true;
                        self.message = "Preparing bytecode preview…".into();
                        Action::PreviewBytecode(file.clone())
                    } else {
                        Action::None
                    }
                }
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.bytecode_listing = None;
                    self.bytecode_marks.clear();
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.bytecode_listing = None;
                    self.bytecode_marks.clear();
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.schedule_read_only
            && (self.schedule_edit_plan.is_some()
                || self.schedule_remove_plan.is_some()
                || self.schedule_install_plan.is_some()
                || self.schedule_enable_plan.is_some()
                || self.schedule_disable_plan.is_some()
                || {
                    #[cfg(target_os = "linux")]
                    {
                        self.trash_retention_plan.is_some()
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        false
                    }
                })
        {
            if matches!(
                key.code,
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('n' | 'q')
            ) || (key.code == KeyCode::Char('c')
                && key.modifiers.contains(KeyModifiers::CONTROL))
            {
                self.schedule_edit_plan = None;
                self.schedule_remove_plan = None;
                self.schedule_install_plan = None;
                self.schedule_enable_plan = None;
                self.schedule_disable_plan = None;
                #[cfg(target_os = "linux")]
                {
                    self.trash_retention_plan = None;
                }
                self.schedule_read_only = false;
                self.schedule_preview_scroll = 0;
            } else {
                match key.code {
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.schedule_preview_scroll =
                            self.schedule_preview_scroll.saturating_add(1)
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.schedule_preview_scroll =
                            self.schedule_preview_scroll.saturating_sub(1)
                    }
                    KeyCode::PageDown => {
                        self.schedule_preview_scroll =
                            self.schedule_preview_scroll.saturating_add(10)
                    }
                    KeyCode::PageUp => {
                        self.schedule_preview_scroll =
                            self.schedule_preview_scroll.saturating_sub(10)
                    }
                    _ => {}
                }
            }
            return Action::None;
        }
        if self.schedule_confirmation_identity.is_some() {
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.schedule_confirmation_scroll =
                        self.schedule_confirmation_scroll.saturating_add(1).min(
                            self.schedule_confirmation_content
                                .as_ref()
                                .map_or(0, |lines| {
                                    lines
                                        .len()
                                        .saturating_sub(schedule_confirmation_visible_rows(
                                            self.schedule_confirmation_area,
                                        ))
                                        .min(u16::MAX as usize)
                                }),
                        );
                    return Action::None;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.schedule_confirmation_scroll =
                        self.schedule_confirmation_scroll.saturating_sub(1);
                    return Action::None;
                }
                KeyCode::PageDown => {
                    let step = schedule_confirmation_visible_rows(self.schedule_confirmation_area)
                        .saturating_sub(1)
                        .max(1);
                    let max_scroll =
                        self.schedule_confirmation_content
                            .as_ref()
                            .map_or(0, |lines| {
                                lines
                                    .len()
                                    .saturating_sub(schedule_confirmation_visible_rows(
                                        self.schedule_confirmation_area,
                                    ))
                                    .min(u16::MAX as usize)
                            });
                    self.schedule_confirmation_scroll = self
                        .schedule_confirmation_scroll
                        .saturating_add(step)
                        .min(max_scroll);
                    return Action::None;
                }
                KeyCode::PageUp => {
                    let step = schedule_confirmation_visible_rows(self.schedule_confirmation_area)
                        .saturating_sub(1)
                        .max(1);
                    self.schedule_confirmation_scroll =
                        self.schedule_confirmation_scroll.saturating_sub(step);
                    return Action::None;
                }
                _ => {}
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(plan) = self.trash_retention_plan.take() {
            return match key.code {
                KeyCode::Char('y') => {
                    self.trash_retention_running = true;
                    let action = match &plan {
                        TrashRetentionReviewPlan::Install(_) => "installing",
                        TrashRetentionReviewPlan::Enable(_) => "enabling",
                        TrashRetentionReviewPlan::Disable(_) => "disabling",
                        TrashRetentionReviewPlan::Remove(_) => "removing",
                    };
                    self.message =
                        format!("{action} scheduled Trash retention; wait for verification.");
                    match plan {
                        TrashRetentionReviewPlan::Install(plan) => {
                            Action::InstallTrashRetention(plan)
                        }
                        TrashRetentionReviewPlan::Enable(plan) => {
                            Action::EnableTrashRetention(plan)
                        }
                        TrashRetentionReviewPlan::Disable(plan) => {
                            Action::DisableTrashRetention(plan)
                        }
                        TrashRetentionReviewPlan::Remove(plan) => {
                            Action::RemoveTrashRetention(plan)
                        }
                    }
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.message.clear();
                    Action::None
                }
                _ => {
                    self.trash_retention_plan = Some(plan);
                    Action::None
                }
            };
        }
        if self.schedule_edit_plan.is_some() {
            return match key.code {
                KeyCode::Char('y') => {
                    let (plan, frequency) = self.schedule_edit_plan.take().expect("preview exists");
                    self.schedule_edit_running = true;
                    self.message = format!(
                        "Replacing {}; wait for verification.",
                        SchedulePlatform::current().subject()
                    );
                    Action::EditSchedule(plan, frequency)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.schedule_edit_plan = None;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.schedule_edit_plan = None;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.schedule_edit_preparing || self.schedule_edit_running {
            return Action::None;
        }
        if self.schedule_remove_plan.is_some() {
            return match key.code {
                KeyCode::Char('y') => {
                    let plan = self.schedule_remove_plan.take().expect("preview exists");
                    self.schedule_remove_running = true;
                    self.message = format!(
                        "Removing {}; wait for verification.",
                        SchedulePlatform::current().removal_subject()
                    );
                    Action::RemoveSchedule(plan)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.schedule_remove_plan = None;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.schedule_remove_plan = None;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.schedule_remove_preparing || self.schedule_remove_running {
            return Action::None;
        }
        if self.schedule_install_plan.is_some() {
            return match key.code {
                KeyCode::Char('y') => {
                    let (plan, frequency) =
                        self.schedule_install_plan.take().expect("preview exists");
                    self.schedule_install_running = true;
                    self.message = format!(
                        "Installing {}; wait for verification.",
                        SchedulePlatform::current().subject()
                    );
                    Action::InstallSchedule(plan, frequency)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.schedule_install_plan = None;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.schedule_install_plan = None;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.schedule_install_preparing || self.schedule_install_running {
            return Action::None;
        }
        if self.schedule_enable_plan.is_some() {
            return match key.code {
                KeyCode::Char('y') => {
                    let (plan, frequency) =
                        self.schedule_enable_plan.take().expect("preview exists");
                    self.schedule_enable_running = true;
                    self.message = format!(
                        "Enabling {}; wait for verification.",
                        SchedulePlatform::current().subject()
                    );
                    Action::EnableSchedule(plan, frequency)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.schedule_enable_plan = None;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.schedule_enable_plan = None;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.schedule_enable_preparing || self.schedule_enable_running {
            return Action::None;
        }
        if self.schedule_disable_plan.is_some() {
            return match key.code {
                KeyCode::Char('y') => {
                    let plan = self.schedule_disable_plan.take().expect("preview exists");
                    self.schedule_disable_running = true;
                    self.message = format!(
                        "Disabling {}; wait for verification.",
                        SchedulePlatform::current().subject()
                    );
                    Action::DisableSchedule(plan)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.schedule_disable_plan = None;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.schedule_disable_plan = None;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.schedule_disable_preparing || self.schedule_disable_running {
            return Action::None;
        }
        if self.go_test_plan.is_some() {
            return match key.code {
                KeyCode::Char('y') if !self.go_test_read_only => {
                    let plan = self.go_test_plan.take().expect("preview exists");
                    self.go_test_running = true;
                    self.message = "Expiring Go test results; wait for verification.".into();
                    Action::ExpireGoTest(plan)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.go_test_plan = None;
                    self.go_test_read_only = false;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.go_test_plan = None;
                    self.go_test_read_only = false;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.go_test_running || self.go_test_preparing {
            return Action::None;
        }
        if self.build_cache_plan.is_some() {
            return match key.code {
                KeyCode::Char('y') if !self.build_cache_read_only => {
                    let plan = self.build_cache_plan.take().expect("preview exists");
                    self.build_cache_removing = true;
                    self.message = "Removing build cache; wait for verification.".into();
                    Action::RemoveBuildCache(plan)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.build_cache_plan = None;
                    self.build_cache_read_only = false;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.build_cache_plan = None;
                    self.build_cache_read_only = false;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.build_cache_preparing || self.build_cache_removing {
            return Action::None;
        }
        if self.network_plan.is_some() {
            return match key.code {
                KeyCode::Char('y') => {
                    let plan = self.network_plan.take().expect("preview exists");
                    self.network_removing = true;
                    self.message = "Removing network; wait for verification.".into();
                    Action::RemoveNetwork(plan)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.network_plan = None;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.network_plan = None;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.network_preparing || self.network_removing {
            return Action::None;
        }
        if self.container_plan.is_some() {
            return match key.code {
                KeyCode::Char('y') => {
                    let plan = self.container_plan.take().expect("preview exists");
                    self.container_removing = true;
                    self.message = "Removing container; wait for verification.".into();
                    Action::RemoveContainer(plan)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.container_plan = None;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.container_plan = None;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.container_preparing {
            return match key.code {
                KeyCode::Esc | KeyCode::Char('q') => Action::Quit,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Action::Quit,
                _ => Action::None,
            };
        }
        if self.trash_removal_plan.is_some() {
            return match key.code {
                KeyCode::Char('y') => {
                    let plan = self.trash_removal_plan.take().expect("preview exists");
                    self.trash_removing = true;
                    self.message = "Removing Trash item; wait for verification.".into();
                    Action::RemoveTrash(plan)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.trash_removal_plan = None;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.trash_removal_plan = None;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.trash_marking {
            return match key.code {
                KeyCode::Esc => {
                    self.message = "Cancelling Trash selection…".into();
                    Action::CancelTrash
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.message = "Cancelling Trash selection…".into();
                    Action::CancelTrash
                }
                _ => Action::None,
            };
        }
        if self.trash_removing {
            return match key.code {
                KeyCode::Esc => {
                    self.message =
                        "Cancelling remaining Trash items after the current item…".into();
                    Action::CancelTrash
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.message =
                        "Cancelling remaining Trash items after the current item…".into();
                    Action::CancelTrash
                }
                _ => Action::None,
            };
        }
        if self.trash_removal_preparing {
            return Action::None;
        }
        if self.trash_review {
            match key.code {
                KeyCode::Char('d') => {
                    if let Some(Ok(preview)) = &self.trash_preview {
                        self.trash_review = false;
                        self.trash_removal_preparing = true;
                        self.message = "Preparing permanent deletion preview…".into();
                        return Action::PreviewTrashRemoval(preview.clone());
                    }
                }
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => self.trash_review = false,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.trash_review = false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.trash_review_scroll = self.trash_review_scroll.saturating_add(1)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.trash_review_scroll = self.trash_review_scroll.saturating_sub(1)
                }
                _ => {}
            }
            return Action::None;
        }
        if self.trim_plan.is_some() {
            return match key.code {
                KeyCode::Char('y') if !self.trim_read_only => {
                    let plan = self.trim_plan.take().expect("preview exists");
                    self.trim_running = true;
                    self.message = "Running TRIM; wait for completion.".into();
                    Action::RunTrim(plan)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.trim_plan = None;
                    self.trim_read_only = false;
                    self.message.clear();
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.trim_plan = None;
                    self.trim_read_only = false;
                    self.message.clear();
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.trim_preparing {
            return match key.code {
                KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Action::Quit,
                _ => Action::None,
            };
        }
        if self.plan_detail {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => self.plan_detail = false,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.plan_detail = false
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.detail_scroll = self.detail_scroll.saturating_add(1)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.detail_scroll = self.detail_scroll.saturating_sub(1)
                }
                _ => {}
            }
            return Action::None;
        }
        if self.self_update_preparing {
            return match key.code {
                KeyCode::Esc | KeyCode::Char('q') => Action::Quit,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Action::Quit,
                _ => Action::None,
            };
        }
        if self.self_update_plan.is_some() {
            return match key.code {
                KeyCode::Enter | KeyCode::Char('y')
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    let plan = self.self_update_plan.take().expect("plan checked above");
                    self.updating = true;
                    self.message = "Updating Upkit…".into();
                    Action::SelfUpdate(plan)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.self_update_plan = None;
                    if self.self_update_command {
                        Action::Quit
                    } else {
                        Action::None
                    }
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.self_update_plan = None;
                    if self.self_update_command {
                        Action::Quit
                    } else {
                        Action::None
                    }
                }
                _ => Action::None,
            };
        }
        if self.confirmation {
            return match key.code {
                KeyCode::Enter | KeyCode::Char('y') if toolchain_confirmation_key(key) => {
                    self.confirmation = false;
                    let targets = if self.marked.is_empty() {
                        self.selected_toolchain().into_iter().collect()
                    } else {
                        self.marked.clone()
                    };
                    if !targets.is_empty() {
                        self.updating = true;
                        self.message = format!("Updating {} tool(s)…", targets.len());
                        Action::Update(targets)
                    } else {
                        Action::None
                    }
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.confirmation = false;
                    Action::None
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.confirmation = false;
                    Action::None
                }
                _ => Action::None,
            };
        }
        if self.help {
            match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?' | 'q') => self.help = false,
                KeyCode::Down | KeyCode::Char('j') => {
                    self.help_scroll = self.help_scroll.saturating_add(1)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.help_scroll = self.help_scroll.saturating_sub(1)
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.help = false
                }
                _ => {}
            }
            return Action::None;
        }
        if let Some(search) = &mut self.toolchain_search {
            match key.code {
                KeyCode::Enter => {
                    self.toolchain_filter = self.toolchain_search.take().unwrap_or_default();
                    self.normalize_toolchain_selection();
                }
                KeyCode::Esc => self.toolchain_search = None,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.toolchain_search = None
                }
                KeyCode::Backspace => {
                    search.pop();
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && !character.is_control()
                        && search.chars().count() < 128 =>
                {
                    search.push(character)
                }
                _ => {}
            }
            return Action::None;
        }
        if self.page == Start::Toolchains && key.code == KeyCode::Char('/') {
            self.toolchain_search = Some(self.toolchain_filter.clone());
            return Action::None;
        }
        if let Some(search) = &mut self.container_search {
            match key.code {
                KeyCode::Enter => {
                    self.container_filter = self.container_search.take().unwrap_or_default();
                    self.containers_scroll = 0;
                    self.normalize_container_selection();
                }
                KeyCode::Esc => self.container_search = None,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.container_search = None
                }
                KeyCode::Backspace => {
                    search.pop();
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && !character.is_control()
                        && search.chars().count() < 128 =>
                {
                    search.push(character)
                }
                _ => {}
            }
            return Action::None;
        }
        if self.page == Start::Containers && key.code == KeyCode::Char('/') {
            self.container_search = Some(self.container_filter.clone());
            return Action::None;
        }
        if let Some(search) = &mut self.artifact_search {
            match key.code {
                KeyCode::Enter => {
                    self.artifact_filter = self.artifact_search.take().unwrap_or_default();
                    self.scan_scroll = 0;
                }
                KeyCode::Esc => self.artifact_search = None,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.artifact_search = None
                }
                KeyCode::Backspace => {
                    search.pop();
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && !character.is_control()
                        && search.chars().count() < 128 =>
                {
                    search.push(character)
                }
                _ => {}
            }
            return Action::None;
        }
        if self.page == Start::Artifacts && key.code == KeyCode::Char('/') {
            self.artifact_search = Some(self.artifact_filter.clone());
            return Action::None;
        }
        if let Some(search) = &mut self.cache_search {
            match key.code {
                KeyCode::Enter => {
                    self.cache_filter = self.cache_search.take().unwrap_or_default();
                    self.cache_scroll = 0;
                    self.normalize_cache_selection();
                }
                KeyCode::Esc => self.cache_search = None,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.cache_search = None
                }
                KeyCode::Backspace => {
                    search.pop();
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && !character.is_control()
                        && search.chars().count() < 128 =>
                {
                    search.push(character)
                }
                _ => {}
            }
            return Action::None;
        }
        if self.page == Start::Cache && key.code == KeyCode::Char('/') {
            self.cache_search = Some(self.cache_filter.clone());
            return Action::None;
        }
        if let Some(search) = &mut self.history_search {
            match key.code {
                KeyCode::Enter => {
                    self.history_filter = self.history_search.take().unwrap_or_default();
                    self.history_scroll = 0;
                }
                KeyCode::Esc => self.history_search = None,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.history_search = None
                }
                KeyCode::Backspace => {
                    search.pop();
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && !character.is_control()
                        && search.chars().count() < 128 =>
                {
                    search.push(character)
                }
                _ => {}
            }
            return Action::None;
        }
        if self.page == Start::Reports && key.code == KeyCode::Char('/') {
            self.history_search = Some(self.history_filter.clone());
            return Action::None;
        }
        if let Some(search) = &mut self.doctor_search {
            match key.code {
                KeyCode::Enter => {
                    self.doctor_filter = self.doctor_search.take().unwrap_or_default();
                    self.doctor_scroll = 0;
                }
                KeyCode::Esc => self.doctor_search = None,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.doctor_search = None
                }
                KeyCode::Backspace => {
                    search.pop();
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && !character.is_control()
                        && search.chars().count() < 128 =>
                {
                    search.push(character)
                }
                _ => {}
            }
            return Action::None;
        }
        if self.page == Start::Doctor && key.code == KeyCode::Char('/') {
            self.doctor_search = Some(self.doctor_filter.clone());
            return Action::None;
        }
        if key.code == KeyCode::Char('?') {
            self.help = true;
            self.help_scroll = 0;
            return Action::None;
        }
        if key.code == KeyCode::Esc && self.page == Start::Artifacts && self.scan_running {
            self.message = "Cancelling scan…".into();
            return Action::CancelScan;
        }
        if key.code == KeyCode::Esc && self.page == Start::Doctor && self.issues.is_none() {
            self.message =
                "Requesting cancellation; an active filesystem call may finish first.".into();
            return Action::CancelDoctor;
        }
        if key.code == KeyCode::Esc && self.page == Start::Cache && self.cache_running {
            self.message = "Cancelling cache inventory…".into();
            return Action::CancelCache;
        }
        if key.code == KeyCode::Esc && self.page == Start::Trash && self.trash_running {
            self.message = "Cancelling Trash inventory…".into();
            return Action::CancelTrash;
        }
        if self.cli_preview_read_only {
            match key.code {
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                    self.message = "This CLI preview is read-only; press q to close it.".into();
                    return Action::None;
                }
                KeyCode::Char('d' | 'b' | 'r') if self.page == Start::Artifacts => {
                    self.message = "Read-only CLI preview; use the dashboard for cleanup.".into();
                    return Action::None;
                }
                _ => {}
            }
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('c')
                if key.code != KeyCode::Char('c')
                    || key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                if self.updating || self.trim_running || self.container_removing {
                    self.message =
                        "An operation is running; wait for it to finish before exiting.".into();
                    Action::None
                } else {
                    Action::Quit
                }
            }
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                self.temp_mode = false;
                self.page = match (self.page, key.code) {
                    (Start::Dashboard, KeyCode::BackTab | KeyCode::Left) => Start::Settings,
                    (Start::Dashboard, _) => Start::Toolchains,
                    (Start::Toolchains, KeyCode::BackTab | KeyCode::Left) => Start::Dashboard,
                    (Start::Toolchains, _) => Start::Doctor,
                    (Start::Doctor, KeyCode::BackTab | KeyCode::Left) => Start::Toolchains,
                    (Start::Doctor, _) => Start::Artifacts,
                    (Start::Artifacts, KeyCode::BackTab | KeyCode::Left) => Start::Doctor,
                    (Start::Artifacts, _) => Start::Maintenance,
                    (Start::Maintenance, KeyCode::BackTab | KeyCode::Left) => Start::Artifacts,
                    (Start::Maintenance, _) => Start::Cache,
                    (Start::Cache, KeyCode::BackTab | KeyCode::Left) => Start::Maintenance,
                    (Start::Cache, _) => Start::Trash,
                    (Start::Trash, KeyCode::BackTab | KeyCode::Left) => Start::Cache,
                    (Start::Trash, _) => Start::Containers,
                    (Start::Containers, KeyCode::BackTab | KeyCode::Left) => Start::Trash,
                    (Start::Containers, _) => Start::Automation,
                    (Start::Automation, KeyCode::BackTab | KeyCode::Left) => Start::Containers,
                    (Start::Automation, _) => Start::Reports,
                    (Start::Reports, KeyCode::BackTab | KeyCode::Left) => Start::Automation,
                    (Start::Reports, _) => Start::Settings,
                    (Start::Settings, KeyCode::BackTab | KeyCode::Left) => Start::Reports,
                    (Start::Settings, _) => Start::Dashboard,
                };
                if self.page == Start::Settings && self.settings.is_none() && !self.settings_loading
                {
                    self.settings_loading = true;
                    return Action::LoadSettings;
                }
                if self.page == Start::Automation
                    && self.schedule.is_none()
                    && !self.schedule_running
                {
                    self.schedule_running = true;
                    return Action::RefreshSchedule;
                }
                if matches!(self.page, Start::Dashboard | Start::Reports)
                    && self.history.is_none()
                    && !self.history_running
                {
                    self.history_running = true;
                    Action::RefreshHistory
                } else {
                    Action::None
                }
            }
            #[cfg(target_os = "linux")]
            KeyCode::Char('T') if trash_retention_action_available(self, key) => {
                let Some(data_dir) = dirs::data_local_dir() else {
                    self.message = "Cannot determine the home XDG data directory.".into();
                    return Action::None;
                };
                self.schedule_read_only = false;
                self.schedule_preview_scroll = 0;
                self.schedule_confirmation_scroll = 0;
                self.trash_retention_plan = None;
                self.trash_retention_preparing = true;
                self.message = "Preparing home Trash retention installation preview…".into();
                Action::PreviewTrashRetentionInstall(
                    data_dir.join("Trash"),
                    Duration::from_secs(TRASH_RETENTION_DEFAULT_AGE_SECONDS),
                )
            }
            #[cfg(target_os = "linux")]
            KeyCode::Char('G') if trash_retention_action_available(self, key) => {
                self.schedule_read_only = false;
                self.schedule_preview_scroll = 0;
                self.schedule_confirmation_scroll = 0;
                self.trash_retention_plan = None;
                self.trash_retention_preparing = true;
                self.message = "Preparing Trash retention enable preview…".into();
                Action::PreviewTrashRetentionEnable
            }
            #[cfg(target_os = "linux")]
            KeyCode::Char('D') if trash_retention_action_available(self, key) => {
                self.schedule_read_only = false;
                self.schedule_preview_scroll = 0;
                self.schedule_confirmation_scroll = 0;
                self.trash_retention_plan = None;
                self.trash_retention_preparing = true;
                self.message = "Preparing Trash retention disable preview…".into();
                Action::PreviewTrashRetentionDisable
            }
            #[cfg(target_os = "linux")]
            KeyCode::Char('X') if trash_retention_action_available(self, key) => {
                self.schedule_read_only = false;
                self.schedule_preview_scroll = 0;
                self.schedule_confirmation_scroll = 0;
                self.trash_retention_plan = None;
                self.trash_retention_preparing = true;
                self.message = "Preparing Trash retention removal preview…".into();
                Action::PreviewTrashRetentionRemove
            }
            KeyCode::Char('e' | 'E')
                if self.page == Start::Automation
                    && !self.schedule_running
                    && !self.updating
                    && !self.trim_running
                    && !self.container_removing =>
            {
                let frequency = if key.code == KeyCode::Char('e') {
                    crate::schedule::Frequency::Daily
                } else {
                    crate::schedule::Frequency::Weekly
                };
                self.schedule_edit_preparing = true;
                self.message = format!(
                    "Preparing configured {} replacement preview…",
                    SchedulePlatform::current().subject()
                );
                Action::PreviewScheduleEdit(frequency)
            }
            KeyCode::Char('x')
                if self.page == Start::Automation
                    && !self.schedule_running
                    && !self.updating
                    && !self.trim_running
                    && !self.container_removing =>
            {
                self.schedule_remove_preparing = true;
                self.message = format!(
                    "Preparing {} removal preview…",
                    SchedulePlatform::current().removal_subject()
                );
                Action::PreviewScheduleRemove
            }
            KeyCode::Char('a' | 'w')
                if self.page == Start::Automation
                    && !self.schedule_running
                    && !self.updating
                    && !self.trim_running
                    && !self.container_removing =>
            {
                let frequency = if key.code == KeyCode::Char('a') {
                    crate::schedule::Frequency::Daily
                } else {
                    crate::schedule::Frequency::Weekly
                };
                self.schedule_read_only = false;
                self.schedule_install_preparing = true;
                self.message = format!(
                    "Preparing configured {} installation preview…",
                    SchedulePlatform::current().subject()
                );
                Action::PreviewScheduleInstall(frequency, false)
            }
            KeyCode::Char('p' | 'P')
                if self.page == Start::Automation
                    && !self.schedule_running
                    && !self.schedule_install_preparing
                    && !self.updating
                    && !self.trim_running
                    && !self.container_removing
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                let frequency = if key.code == KeyCode::Char('p') {
                    crate::schedule::Frequency::Daily
                } else {
                    crate::schedule::Frequency::Weekly
                };
                self.schedule_read_only = true;
                self.schedule_install_preparing = true;
                self.schedule_install_plan = None;
                self.schedule_preview_scroll = 0;
                self.schedule_confirmation_scroll = 0;
                self.message = format!(
                    "Preparing read-only configured {} schedule preview…",
                    match frequency {
                        crate::schedule::Frequency::Daily => "daily",
                        crate::schedule::Frequency::Weekly => "weekly",
                    }
                );
                Action::PreviewScheduleInstall(frequency, true)
            }
            KeyCode::Char('1' | '7')
                if self.page == Start::Automation
                    && !self.schedule_running
                    && !self.updating
                    && !self.trim_running
                    && !self.container_removing =>
            {
                let frequency = if key.code == KeyCode::Char('1') {
                    crate::schedule::Frequency::Daily
                } else {
                    crate::schedule::Frequency::Weekly
                };
                self.schedule_enable_preparing = true;
                self.message = format!(
                    "Preparing configured {} enable preview…",
                    SchedulePlatform::current().subject()
                );
                Action::PreviewScheduleEnable(frequency)
            }
            KeyCode::Char('d')
                if self.page == Start::Automation
                    && !self.schedule_running
                    && !self.updating
                    && !self.trim_running
                    && !self.container_removing =>
            {
                self.schedule_disable_preparing = true;
                self.message = format!(
                    "Preparing {} disable preview…",
                    SchedulePlatform::current().subject()
                );
                Action::PreviewScheduleDisable
            }
            KeyCode::Down | KeyCode::Char('j') if self.page == Start::Automation => {
                self.schedule_scroll = self.schedule_scroll.saturating_add(1);
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') if self.page == Start::Automation => {
                self.schedule_scroll = self.schedule_scroll.saturating_sub(1);
                Action::None
            }
            KeyCode::Enter | KeyCode::Char('r')
                if self.page == Start::Automation && !self.schedule_running =>
            {
                self.schedule_running = true;
                self.schedule = None;
                self.schedule_scroll = 0;
                Action::RefreshSchedule
            }
            KeyCode::Down | KeyCode::Char('j') if self.page == Start::Dashboard => {
                self.dashboard_scroll = self.dashboard_scroll.saturating_add(1);
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') if self.page == Start::Dashboard => {
                self.dashboard_scroll = self.dashboard_scroll.saturating_sub(1);
                Action::None
            }
            KeyCode::Char('r') if self.page == Start::Dashboard && !self.history_running => {
                self.history_running = true;
                self.history = None;
                Action::RefreshHistory
            }
            KeyCode::Char('c') if self.page == Start::Dashboard && !self.cache_running => {
                self.page = Start::Cache;
                self.cache_running = true;
                self.cache = None;
                self.cache_scroll = 0;
                Action::StartCache
            }
            KeyCode::Char('r') if self.page == Start::Settings && !self.settings_loading => {
                self.settings_loading = true;
                self.settings = None;
                self.settings_scroll = 0;
                Action::LoadSettings
            }
            KeyCode::Char('e') if self.page == Start::Settings && !self.settings_loading => {
                if let Some(Ok(document)) = &self.settings {
                    match SettingsForm::new(document.clone()) {
                        Ok(form) => {
                            self.settings_form = Some(form);
                            self.message.clear();
                        }
                        Err(error) => {
                            self.message = format!(
                                "Structured editing is unavailable: {} Use t for TOML editing.",
                                settings_error(&format!("{error:#}"))
                            );
                        }
                    }
                } else {
                    self.message = "Load a configuration before editing.".into();
                }
                Action::None
            }
            KeyCode::Char('t') if self.page == Start::Settings && !self.settings_loading => {
                if let Some(Ok(document)) = &self.settings {
                    self.settings_editor = Some(ConfigEditor::new(document.clone()));
                    self.message = "Edit TOML; Ctrl+S reviews save, Esc exits.".into();
                } else {
                    self.message = "Load a configuration before editing.".into();
                }
                Action::None
            }
            KeyCode::Down | KeyCode::Char('j') if self.page == Start::Settings => {
                self.settings_scroll = self.settings_scroll.saturating_add(1);
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') if self.page == Start::Settings => {
                self.settings_scroll = self.settings_scroll.saturating_sub(1);
                Action::None
            }
            KeyCode::Char('s') if self.page == Start::Dashboard => {
                self.page = Start::Artifacts;
                if self.scan_running {
                    Action::None
                } else {
                    self.scan_running = true;
                    self.scan = None;
                    self.plan = None;
                    self.preview_mode = false;
                    self.artifact_marks.clear();
                    self.scan_scroll = 0;
                    self.scan_visited = 0;
                    self.message.clear();
                    Action::StartArtifactScan { configured: true }
                }
            }
            KeyCode::Down | KeyCode::Char('j')
                if self.page == Start::Maintenance && !self.trim_running =>
            {
                if let Some(report) = &self.maintenance {
                    self.trim_selected = self
                        .trim_selected
                        .saturating_add(1)
                        .min(report.mounts.len().saturating_sub(1));
                }
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k')
                if self.page == Start::Maintenance && !self.trim_running =>
            {
                self.trim_selected = self.trim_selected.saturating_sub(1);
                Action::None
            }
            KeyCode::Char('l') if self.page == Start::Maintenance && !self.trim_running => {
                self.temp_mode = true;
                self.temp_preparing = true;
                self.temp_plan = None;
                self.temp_marks.clear();
                self.temp_selected = 0;
                self.temp_result = None;
                self.temp_result_scroll = 0;
                self.temp_inventory_scroll_offset = 0;
                self.message = "Inspecting Upkit link staging directories…".into();
                Action::PreviewTempCleanup(Vec::new(), false)
            }
            KeyCode::Char('U')
                if self.page == Start::Toolchains
                    && !self.managed_mode
                    && !self.updating
                    && !self.trim_running
                    && !self.container_removing =>
            {
                self.self_update_preparing = true;
                self.message = "Preparing Upkit self-update preview…".into();
                Action::PreviewSelfUpdate
            }
            KeyCode::Enter
                if self.page == Start::Maintenance
                    && !self.trim_running
                    && !self.updating
                    && !self.container_removing =>
            {
                if let Some(report) = &self.maintenance
                    && report.fstrim_available
                    && let Some(mount) = report.mounts.get(self.trim_selected)
                {
                    self.trim_read_only = false;
                    self.trim_preparing = true;
                    self.message = "Preparing TRIM preview…".into();
                    Action::PreviewTrim(mount.mount_path.clone())
                } else {
                    self.message = if self
                        .maintenance
                        .as_ref()
                        .is_some_and(|report| !report.fstrim_available)
                    {
                        "TRIM preview is unavailable on this system.".into()
                    } else {
                        "Select an available mount with fstrim installed.".into()
                    };
                    Action::None
                }
            }
            KeyCode::Char('7' | '3' | '9')
                if self.page == Start::Reports
                    && !self.history_purge_preparing
                    && !self.history_purging
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                let days = match key.code {
                    KeyCode::Char('7') => 7,
                    KeyCode::Char('3') => 30,
                    _ => 90,
                };
                let age = Duration::from_secs(days * 86_400);
                self.history_purge_preparing = true;
                self.history_purge_read_only = false;
                self.history_purge_plan = None;
                self.history_purge_content = None;
                self.history_purge_scroll = 0;
                self.history_purge_result = None;
                self.history_purge_warning = None;
                self.message = format!("Previewing history records older than {days} days…");
                Action::PreviewHistoryPurge(age)
            }
            KeyCode::Down | KeyCode::Char('j') if self.page == Start::Reports => {
                self.history_scroll = self.history_scroll.saturating_add(1);
                Action::None
            }
            KeyCode::Char('s') if self.page == Start::Reports => {
                self.history_oldest_first = !self.history_oldest_first;
                self.history_scroll = 0;
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') if self.page == Start::Reports => {
                self.history_scroll = self.history_scroll.saturating_sub(1);
                Action::None
            }
            KeyCode::Enter | KeyCode::Char('r')
                if self.page == Start::Reports && !self.history_running =>
            {
                self.history_running = true;
                self.history = None;
                self.history_scroll = 0;
                Action::RefreshHistory
            }
            KeyCode::Down | KeyCode::Char('j') if self.page == Start::Containers => {
                self.move_container_selection(true);
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') if self.page == Start::Containers => {
                self.move_container_selection(false);
                Action::None
            }
            KeyCode::PageDown if self.page == Start::Containers => {
                self.containers_scroll = self.containers_scroll.saturating_add(5);
                Action::None
            }
            KeyCode::PageUp if self.page == Start::Containers => {
                self.containers_scroll = self.containers_scroll.saturating_sub(5);
                Action::None
            }
            KeyCode::Char('d')
                if self.page == Start::Containers
                    && !self.containers_running
                    && !self.container_removing
                    && !self.updating
                    && !self.trim_running =>
            {
                let selection = self.containers.as_ref().and_then(|report| {
                    selected_container_resource(
                        report,
                        &self.container_filter,
                        self.container_selected,
                    )
                });
                match selection {
                    Some(ContainerSelection::Stopped { engine, id, .. }) => {
                        self.container_preparing = true;
                        self.message = "Preparing container removal preview…".into();
                        Action::PreviewContainer(engine.to_owned(), id.to_owned())
                    }
                    Some(ContainerSelection::UnusedNetwork { engine, id, .. }) => {
                        self.network_preparing = true;
                        self.message = "Preparing network removal preview…".into();
                        Action::PreviewNetwork(engine.to_owned(), id.to_owned())
                    }
                    Some(ContainerSelection::BuildCache { builder, id, .. }) => {
                        self.build_cache_preparing = true;
                        self.build_cache_read_only = false;
                        self.message = "Preparing build-cache removal preview…".into();
                        Action::PreviewBuildCache(builder.to_owned(), id.to_owned())
                    }
                    None => {
                        self.message = "Select a visible resource with a complete ID.".into();
                        Action::None
                    }
                }
            }
            KeyCode::Enter
                if self.page == Start::Trash
                    && !self.trash_running
                    && self.trash_preview.is_some() =>
            {
                if self
                    .trash_preview
                    .as_ref()
                    .and_then(|report| report.as_ref().ok())
                    .is_some_and(|preview| preview.items.iter().any(|item| item.selected))
                {
                    self.trash_review = true;
                    self.trash_review_scroll = 0;
                    self.message.clear();
                } else {
                    self.message = "Mark at least one eligible item before reviewing.".into();
                }
                Action::None
            }
            KeyCode::Enter | KeyCode::Char('r')
                if self.page == Start::Containers
                    && !self.containers_running
                    && !self.container_removing =>
            {
                self.containers_running = true;
                self.containers = None;
                self.containers_scroll = 0;
                self.container_selected = 0;
                Action::StartContainers
            }
            KeyCode::Down | KeyCode::Char('j') if self.page == Start::Doctor => {
                if self.issues.is_some() {
                    self.doctor_scroll = self.doctor_scroll.saturating_add(1);
                }
                Action::None
            }
            KeyCode::Char('r') if self.page == Start::Doctor && self.issues.is_some() => {
                self.issues = None;
                self.doctor_capabilities = None;
                self.doctor_scroll = 0;
                Action::RefreshDoctor
            }
            KeyCode::Up | KeyCode::Char('k') if self.page == Start::Doctor => {
                self.doctor_scroll = self.doctor_scroll.saturating_sub(1);
                Action::None
            }
            KeyCode::Char('d')
                if self.page == Start::Cache
                    && !self.cache_running
                    && !self.updating
                    && !self.trim_running
                    && !self.container_removing =>
            {
                if self.cache.as_ref().is_some_and(|report| {
                    !visible_cache_entries(report, &self.cache_filter, self.cache_sort).is_empty()
                }) {
                    self.normalize_cache_selection();
                    self.cache_choosing = true;
                } else {
                    self.message =
                        "No visible cache to select; inventory or clear the filter.".into();
                }
                Action::None
            }
            KeyCode::Char('w') if self.page == Start::Cache && self.cache.is_some() => {
                self.cache_details = !self.cache_details;
                self.cache_scroll = 0;
                Action::None
            }
            KeyCode::Char('s') if self.page == Start::Cache && !self.cache_running => {
                self.cache_sort = self.cache_sort.next();
                self.normalize_cache_selection();
                Action::None
            }
            KeyCode::Char('e')
                if self.page == Start::Cache
                    && !self.cache_running
                    && !self.updating
                    && !self.trim_running
                    && !self.container_removing =>
            {
                if let Some(entry) = self.cache.as_ref().and_then(|report| {
                    report.entries.iter().find(|entry| {
                        entry.name == "Go build" && cache_matches(entry, &self.cache_filter)
                    })
                }) {
                    self.go_test_read_only = false;
                    self.go_test_preparing = true;
                    self.message = "Preparing Go test-cache preview…".into();
                    Action::PreviewGoTest(entry.path.clone())
                } else {
                    self.message =
                        "No visible Go build cache; inventory or clear the filter.".into();
                    Action::None
                }
            }
            KeyCode::Down | KeyCode::Char('j') if self.page == Start::Cache => {
                self.cache_scroll = self.cache_scroll.saturating_add(1);
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') if self.page == Start::Cache => {
                self.cache_scroll = self.cache_scroll.saturating_sub(1);
                Action::None
            }
            KeyCode::Down | KeyCode::Char('j') if self.page == Start::Trash => {
                if let Some(Ok(preview)) = &self.trash_preview {
                    self.trash_selected = self
                        .trash_selected
                        .saturating_add(1)
                        .min(preview.items.len().saturating_sub(1));
                }
                if let Some(report) = &self.trash {
                    self.trash_scroll = self.trash_scroll.saturating_add(1).min(
                        u16::try_from(
                            report.locations.len() * 2
                                + report.warnings.len()
                                + report
                                    .locations
                                    .iter()
                                    .map(|location| location.items.len())
                                    .sum::<usize>()
                                + report
                                    .locations
                                    .iter()
                                    .map(|location| location.warnings.len())
                                    .sum::<usize>(),
                        )
                        .unwrap_or(u16::MAX),
                    );
                } else if self.trash_last_result.is_some() {
                    self.trash_scroll = self.trash_scroll.saturating_add(1);
                }
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') if self.page == Start::Trash => {
                if self.trash_preview.is_some() {
                    self.trash_selected = self.trash_selected.saturating_sub(1);
                } else {
                    self.trash_scroll = self.trash_scroll.saturating_sub(1);
                }
                Action::None
            }
            KeyCode::Char(' ') if self.page == Start::Trash && !self.trash_running => {
                if let Some(Ok(preview)) = &mut self.trash_preview {
                    self.message = match preview.toggle(self.trash_selected) {
                        Ok(()) => {
                            "Selection requires review and separate confirmation for deletion."
                                .into()
                        }
                        Err(error) => error.to_string(),
                    };
                }
                Action::None
            }
            KeyCode::Char('A') if self.page == Start::Trash && !self.trash_running => {
                if let Some(Ok(preview)) = &self.trash_preview
                    && let Some(item) = preview.items.get(self.trash_selected)
                {
                    self.trash_marking = true;
                    self.message = format!(
                        "Selecting eligible old files in {}…",
                        crate::sweep::display_path(&item.location)
                    );
                    return Action::SelectOldTrash(preview.clone(), item.location.clone());
                }
                self.message = "Select an item to choose its Trash location.".into();
                Action::None
            }
            KeyCode::Enter | KeyCode::Char('r')
                if self.page == Start::Trash && !self.trash_running =>
            {
                self.trash_running = true;
                self.trash = None;
                self.trash_last_result = None;
                self.trash_preview = None;
                self.trash_scroll = 0;
                self.trash_selected = 0;
                Action::StartTrash(self.trash_age)
            }
            KeyCode::Char('7' | '1' | '3') if self.page == Start::Trash && !self.trash_running => {
                let days = match key.code {
                    KeyCode::Char('7') => 7,
                    KeyCode::Char('1') => 14,
                    _ => 30,
                };
                self.trash_age = Some(Duration::from_secs(days * 86400));
                self.trash_running = true;
                self.trash = None;
                self.trash_last_result = None;
                self.trash_preview = None;
                self.trash_scroll = 0;
                self.trash_selected = 0;
                Action::StartTrash(self.trash_age)
            }
            KeyCode::Char('0') if self.page == Start::Trash && !self.trash_running => {
                self.trash_age = None;
                self.trash_running = true;
                self.trash = None;
                self.trash_last_result = None;
                self.trash_preview = None;
                self.trash_scroll = 0;
                self.trash_selected = 0;
                Action::StartTrash(None)
            }
            KeyCode::Enter | KeyCode::Char('r')
                if self.page == Start::Cache && !self.cache_running =>
            {
                self.cache_running = true;
                self.cache = None;
                self.cache_scroll = 0;
                Action::StartCache
            }
            KeyCode::Down | KeyCode::Char('j') if self.page == Start::Artifacts => {
                if let Some(Ok(plan)) = &self.plan {
                    self.scan_scroll = self.scan_scroll.saturating_add(1).min(
                        u16::try_from(
                            plan.items
                                .iter()
                                .filter(|item| {
                                    artifact_matches(&item.candidate, &self.artifact_filter)
                                })
                                .count()
                                .max(1)
                                + plan.warnings.len(),
                        )
                        .unwrap_or(u16::MAX),
                    );
                } else if let Some(Ok(report)) = &self.scan {
                    self.scan_scroll = self.scan_scroll.saturating_add(1).min(
                        u16::try_from(
                            report
                                .candidates
                                .iter()
                                .filter(|candidate| {
                                    artifact_matches(candidate, &self.artifact_filter)
                                })
                                .count()
                                .max(1)
                                + report.warnings.len(),
                        )
                        .unwrap_or(u16::MAX),
                    );
                }
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') if self.page == Start::Artifacts => {
                self.scan_scroll = self.scan_scroll.saturating_sub(1);
                Action::None
            }
            KeyCode::Char('s') if self.page == Start::Artifacts && !self.scan_running => {
                self.artifact_sort = self.artifact_sort.next();
                self.sort_artifacts();
                Action::None
            }
            KeyCode::Char('r') if self.page == Start::Artifacts && !self.scan_running => {
                self.scan_running = true;
                self.scan = None;
                self.plan = None;
                self.preview_mode = false;
                self.artifact_marks.clear();
                self.scan_scroll = 0;
                self.scan_visited = 0;
                self.message.clear();
                Action::StartArtifactScan { configured: false }
            }
            KeyCode::Char('d') if self.page == Start::Artifacts && !self.scan_running => {
                let marked = if let Some(Ok(plan)) = &self.plan {
                    plan.items
                        .iter()
                        .filter(|item| item.selected)
                        .map(|item| item.candidate.target.clone())
                        .collect::<Vec<_>>()
                } else {
                    self.artifact_marks.clone()
                };
                if !marked.is_empty() {
                    if marked.len() > crate::artifact_cleanup::MAX_BATCH_ARTIFACTS {
                        self.message = format!(
                            "Select at most {} artifact directories per batch.",
                            crate::artifact_cleanup::MAX_BATCH_ARTIFACTS
                        );
                        return Action::None;
                    }
                    self.artifact_preparing = true;
                    self.message = format!(
                        "Preparing a complete removal preview for {} marked directories…",
                        marked.len()
                    );
                    return Action::PreviewArtifactBatch(marked);
                }
                let candidate = if let Some(Ok(plan)) = &self.plan {
                    visible_plan_index(plan, &self.artifact_filter, self.scan_scroll as usize)
                        .and_then(|index| plan.items.get(index).map(|item| &item.candidate))
                } else {
                    self.scan
                        .as_ref()
                        .and_then(|report| report.as_ref().ok())
                        .and_then(|report| {
                            report
                                .candidates
                                .iter()
                                .filter(|candidate| {
                                    artifact_matches(candidate, &self.artifact_filter)
                                })
                                .nth(self.scan_scroll as usize)
                        })
                };
                if let Some(candidate) = candidate {
                    self.artifact_preparing = true;
                    self.message = "Preparing full artifact removal preview…".into();
                    Action::PreviewArtifact(candidate.target.clone())
                } else {
                    self.message = "Select an artifact first.".into();
                    Action::None
                }
            }
            KeyCode::Char('b') if self.page == Start::Artifacts && !self.scan_running => {
                let candidate = if let Some(Ok(plan)) = &self.plan {
                    visible_plan_index(plan, &self.artifact_filter, self.scan_scroll as usize)
                        .and_then(|index| plan.items.get(index).map(|item| &item.candidate))
                } else {
                    self.scan
                        .as_ref()
                        .and_then(|report| report.as_ref().ok())
                        .and_then(|report| {
                            report
                                .candidates
                                .iter()
                                .filter(|candidate| {
                                    artifact_matches(candidate, &self.artifact_filter)
                                })
                                .nth(self.scan_scroll as usize)
                        })
                };
                if let Some(candidate) = candidate.filter(|candidate| {
                    candidate.ecosystem == "python"
                        && candidate.target.file_name().and_then(|name| name.to_str())
                            == Some("__pycache__")
                }) {
                    self.bytecode_listing_running = true;
                    self.message = "Listing bytecode files…".into();
                    Action::ListBytecode(candidate.target.clone())
                } else {
                    self.message = "Select a Python __pycache__ candidate first.".into();
                    Action::None
                }
            }
            KeyCode::Char(' ') if self.page == Start::Artifacts => {
                if let Some(Ok(plan)) = &mut self.plan
                    && let Some(index) =
                        visible_plan_index(plan, &self.artifact_filter, self.scan_scroll as usize)
                    && let Some(item) = plan.items.get_mut(index)
                {
                    item.selected = !item.selected;
                } else if let Some(candidate) = self
                    .scan
                    .as_ref()
                    .and_then(|report| report.as_ref().ok())
                    .and_then(|report| {
                        report
                            .candidates
                            .iter()
                            .filter(|candidate| artifact_matches(candidate, &self.artifact_filter))
                            .nth(self.scan_scroll as usize)
                    })
                {
                    if let Some(index) = self
                        .artifact_marks
                        .iter()
                        .position(|target| target == &candidate.target)
                    {
                        self.artifact_marks.remove(index);
                    } else if self.artifact_marks.len()
                        < crate::artifact_cleanup::MAX_BATCH_ARTIFACTS
                    {
                        self.artifact_marks.push(candidate.target.clone());
                    } else {
                        self.message = format!(
                            "A batch can contain at most {} artifact directories.",
                            crate::artifact_cleanup::MAX_BATCH_ARTIFACTS
                        );
                    }
                }
                Action::None
            }
            KeyCode::Enter if self.page == Start::Artifacts => {
                if let Some(Ok(plan)) = &self.plan
                    && visible_plan_index(plan, &self.artifact_filter, self.scan_scroll as usize)
                        .is_some()
                {
                    self.plan_detail = true;
                    self.detail_scroll = 0;
                }
                Action::None
            }
            KeyCode::Char('r')
                if self.page == Start::Toolchains
                    && !self.startup_checks.toolchains
                    && !self.updating =>
            {
                self.startup_checks.toolchains = true;
                self.toolchain_check_failed = false;
                self.reports = None;
                self.message = "Refreshing toolchain inventory…".into();
                Action::RefreshToolchains
            }
            KeyCode::Char('r')
                if self.page == Start::Toolchains && self.startup_checks.toolchains =>
            {
                self.message = "Toolchain inventory is already loading.".into();
                Action::None
            }
            KeyCode::Down | KeyCode::Char('j') if self.page == Start::Toolchains => {
                self.move_toolchain_selection(true);
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') if self.page == Start::Toolchains => {
                self.move_toolchain_selection(false);
                Action::None
            }
            KeyCode::Char(' ')
                if self.page == Start::Toolchains
                    && !self.updating
                    && (!self.managed_mode
                        || self
                            .managed_scope
                            .as_ref()
                            .is_some_and(|scope| scope.len() > 1)) =>
            {
                if let Some(tool) = self.selected_toolchain() {
                    if self.marked.contains(&tool) {
                        self.marked.retain(|item| *item != tool);
                    } else {
                        self.marked.push(tool);
                    }
                }
                Action::None
            }
            KeyCode::Char('D')
                if self.page == Start::Toolchains
                    && !self.updating
                    && !self.managed_preparing
                    && !self.managed_running
                    && !self.trim_running
                    && !self.container_removing
                    && (!self.managed_mode
                        || self
                            .managed_scope
                            .as_ref()
                            .is_some_and(|scope| scope.len() > 1)) =>
            {
                let targets = if self.marked.is_empty() {
                    self.selected_toolchain().into_iter().collect::<Vec<_>>()
                } else {
                    self.marked.clone()
                };
                if targets.is_empty() {
                    self.message = "Select or mark at least one tool to clean.".into();
                    return Action::None;
                }
                if let Some(tool) = targets.iter().find(|tool| {
                    self.managed_scope
                        .as_ref()
                        .is_some_and(|scope| !scope.contains(tool))
                }) {
                    self.message = format!(
                        "Choose only tools included in this command; {} is outside its scope.",
                        tool.as_str()
                    );
                    return Action::None;
                }
                self.managed_preparing = true;
                if targets.len() > 1 {
                    self.managed_current = None;
                    self.message = format!(
                        "Preparing one combined cleanup preview for {} marked tools…",
                        targets.len()
                    );
                    Action::PreviewManagedBatch(targets)
                } else {
                    let tool = targets[0];
                    self.managed_current = Some(tool);
                    self.message = format!("Inspecting managed {} files…", tool.as_str());
                    Action::PreviewManaged(tool)
                }
            }
            KeyCode::Char('d') | KeyCode::Enter
                if self.page == Start::Toolchains
                    && !self.updating
                    && (key.code == KeyCode::Char('d') || self.managed_mode) =>
            {
                if let Some(tool) = self.selected_toolchain() {
                    if self
                        .managed_scope
                        .as_ref()
                        .is_some_and(|scope| !scope.contains(&tool))
                    {
                        self.message = "Choose a tool included in this command.".into();
                    } else {
                        self.managed_preparing = true;
                        self.message = format!("Inspecting managed {} files…", tool.as_str());
                        return Action::PreviewManaged(tool);
                    }
                }
                Action::None
            }
            KeyCode::Enter
                if self.page == Start::Toolchains
                    && !self.updating
                    && !self.trim_running
                    && !self.container_removing =>
            {
                if !self.marked.is_empty() || self.selected_toolchain().is_some() {
                    self.confirmation = true;
                } else {
                    self.message = "No visible toolchain matches the filter.".into();
                }
                Action::None
            }
            _ => Action::None,
        }
    }
}

fn important_dashboard_warning(issues: &[String]) -> Option<String> {
    const PRIORITY_PREFIXES: &[&str] = &[
        "Upkit home filesystem has ",
        "invalid or unreadable Upkit configuration:",
        "workspace root ",
        "home directory ",
        "home path ",
        "home dir ",
        "bindir ",
        "tool link ",
        "cannot resolve tool link ",
        "Scheduled scan records ",
    ];
    let issue = PRIORITY_PREFIXES
        .iter()
        .find_map(|prefix| issues.iter().find(|issue| issue.starts_with(prefix)))?;
    let sanitized = schedule_escape_controls(issue);
    let mut characters = sanitized.chars();
    let mut warning = characters.by_ref().take(160).collect::<String>();
    if characters.next().is_some() {
        warning.push('…');
    }
    Some(warning)
}

fn dashboard_cards(app: &App) -> [(&'static str, String); 4] {
    let toolchains = match &app.reports {
        None if app.toolchain_check_failed => {
            "Toolchain check failed; results are unavailable.".into()
        }
        None if app.self_update_command => {
            "Toolchain inventory was not loaded for self-update.".into()
        }
        None => "Checking toolchains…".into(),
        Some(reports) => format!(
            "Toolchains: {}/{} installed\nUpdates: {}\nUnknown: {}",
            reports
                .iter()
                .filter(|report| report.installed.is_some())
                .count(),
            reports.len(),
            reports
                .iter()
                .filter(|report| report.status == crate::Status::Outdated)
                .count(),
            reports
                .iter()
                .filter(|report| report.status == crate::Status::Unknown)
                .count(),
        ),
    };
    let storage = match &app.maintenance {
        None if app.maintenance_check_failed => "Maintenance status is unavailable.".into(),
        None if app.self_update_command => {
            "Maintenance status was not loaded for self-update.".into()
        }
        None => "Checking maintenance status…".into(),
        Some(status) => {
            let mut lines = vec![format!(
                "TRIM: {}; system timer: {}",
                status.capability, status.timer.state
            )];
            let root = status
                .mounts
                .iter()
                .find(|mount| mount.mount_path == std::path::Path::new("/"));
            lines.push(root.map_or_else(
                || "Root filesystem available space: unavailable".into(),
                |mount| {
                    format!(
                        "Root free bytes: {} (snapshot)",
                        mount
                            .available_bytes
                            .map_or("unknown".into(), |bytes| bytes.to_string())
                    )
                },
            ));
            if status.mounts_warning.is_some() {
                lines.push("Storage inventory has warnings; see Maintenance.".into());
            }
            lines.join("\n")
        }
    };
    let cleanup = if let Some(Ok(plan)) = &app.plan {
        format!("Artifact preview: {} candidates.", plan.items.len())
    } else {
        match &app.scan {
            Some(Ok(report)) => format!(
                "Artifacts: {} candidates{}",
                report.candidates.len(),
                if report.is_complete() {
                    ""
                } else {
                    " (partial)"
                }
            ),
            Some(Err(_)) => "Artifact scan failed; see Artifacts.".into(),
            None if app.scan_running => "Artifact scan in progress.".into(),
            None => "Artifacts: no scan yet; choose workspace roots.".into(),
        }
    };
    let mut cleanup = vec![cleanup];
    cleanup.push(match &app.cache {
        Some(report) => format!(
            "Caches: {} entries{}",
            report.entries.len(),
            if report.cancelled { " (partial)" } else { "" }
        ),
        None if app.cache_running => "Cache inventory in progress.".into(),
        None => "Caches: inventory not yet loaded.".into(),
    });
    cleanup.push("Sizes are snapshots; cleanup needs a reviewed action.".into());

    let mut activity = match &app.issues {
        None => vec!["Doctor: checking…".into()],
        Some(issues) => vec![format!("Doctor: {} diagnostic(s).", issues.len())],
    };
    if let Some(warning) = app.issues.as_deref().and_then(important_dashboard_warning) {
        activity.push(format!("Important warning: {warning}"));
    }
    match &app.history {
        None if app.history_running => activity.push("Recent operations: loading…".into()),
        None => activity.push("Recent operations: not loaded; press r.".into()),
        Some(Err(_)) => {
            activity.push("Recent operations: history unavailable; see Reports.".into())
        }
        Some(Ok(history)) => {
            if history.records.is_empty() {
                activity.push("Recent operations: no records.".into());
            } else {
                activity.extend(
                    history
                        .records
                        .iter()
                        .take(3)
                        .map(|record| format!("{} — {}", record.operation, record.outcome)),
                );
            }
            if !history.warnings.is_empty() {
                activity.push("Operation history is incomplete; see Reports.".into());
            }
        }
    }

    [
        ("Toolchains", toolchains),
        ("Storage & maintenance", storage),
        ("Artifacts & caches", cleanup.join("\n")),
        ("Recent activity", activity.join("\n")),
    ]
}

fn draw_dashboard(frame: &mut Frame<'_>, area: Rect, app: &App, fallback: &str) {
    if area.width < 72 || area.height < 18 {
        let block = Block::default().borders(Borders::ALL).title(" Dashboard ");
        let inner = block.inner(area);
        let content = Paragraph::new(fallback).wrap(Wrap { trim: false });
        let max_scroll = content
            .line_count(inner.width)
            .saturating_sub(inner.height as usize)
            .min(u16::MAX as usize) as u16;
        frame.render_widget(
            content
                .scroll((app.dashboard_scroll.min(max_scroll), 0))
                .block(block),
            area,
        );
        return;
    }

    let dashboard = Block::default().borders(Borders::ALL).title(" Dashboard ");
    let inner = dashboard.inner(area);
    frame.render_widget(dashboard, area);
    let rows =
        Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).split(inner);
    let top =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[0]);
    let bottom =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[1]);
    let areas = [top[0], top[1], bottom[0], bottom[1]];

    for ((title, text), area) in dashboard_cards(app).into_iter().zip(areas) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(Color::DarkGray));
        let inner = area.inner(ratatui::layout::Margin::new(1, 1));
        let content = Paragraph::new(text.as_str()).wrap(Wrap { trim: false });
        let max_scroll = content
            .line_count(inner.width)
            .saturating_sub(inner.height as usize)
            .min(u16::MAX as usize) as u16;
        frame.render_widget(
            content
                .scroll((app.dashboard_scroll.min(max_scroll), 0))
                .block(block),
            area,
        );
    }
}

fn dashboard_content(app: &App) -> String {
    let mut content = String::from("Developer environment overview");
    for (title, details) in dashboard_cards(app) {
        content.push_str(&format!("\n\n{title}\n{details}"));
    }
    content
}

fn doctor_content(app: &App) -> String {
    let content = match &app.issues {
        None => "Running diagnostics in the background…".to_owned(),
        Some(issues) => {
            let diagnostics = if issues.is_empty() {
                "No issues found by the available checks.".into()
            } else {
                issues
                    .iter()
                    .map(|issue| format!("• {issue}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            format!(
                "Home filesystem available bytes: {} (snapshot)\n\n{}\n\n{}\n\nWrite-permission probes were skipped in the dashboard.",
                app.doctor_available_bytes
                    .map_or("unavailable".into(), |bytes| bytes.to_string()),
                diagnostics,
                app.doctor_capabilities
                    .as_ref()
                    .map_or("Capability checks unavailable.".into(), |capabilities| {
                        capabilities.lines().join("\n")
                    }),
            )
        }
    };
    if app.doctor_filter.is_empty() {
        return content;
    }
    if app.issues.is_none() {
        return format!(
            "Filter: {}\nDiagnostics are still loading.\n\nWrite-permission probes were skipped in the dashboard.",
            app.doctor_filter
        );
    }

    let safety_note = "Write-permission probes were skipped in the dashboard.";
    let filter = app.doctor_filter.to_lowercase();
    let matches = content
        .lines()
        .filter(|line| {
            !line.is_empty() && *line != safety_note && line.to_lowercase().contains(&filter)
        })
        .collect::<Vec<_>>();
    let mut lines = vec![format!(
        "Filter: {} ({} matching lines)",
        app.doctor_filter,
        matches.len()
    )];
    if matches.is_empty() {
        lines.push("No Doctor lines match this filter.".into());
    } else {
        lines.extend(matches.into_iter().map(str::to_owned));
    }
    lines.push(String::new());
    lines.push(safety_note.into());
    lines.join("\n")
}

fn settings_content(app: &App) -> String {
    match &app.settings {
        None if app.settings_loading => "Loading configuration…".into(),
        None => "Press r to load configuration.".into(),
        Some(Err(error)) => format!("Cannot read configuration: {error}"),
        Some(Ok(document)) => format!(
            "Configuration: {}\n{}\n\n{}",
            crate::sweep::display_path(&document.path),
            if document.exists() {
                "Press e for structured fields, t for TOML; r reloads from disk."
            } else {
                "Configuration does not exist yet; press e to set fields or t to edit TOML."
            },
            document
                .text
                .chars()
                .map(|character| {
                    if character == '\n' {
                        '\n'
                    } else {
                        config_display_character(character)
                    }
                })
                .collect::<String>()
        ),
    }
}

fn reports_content(app: &App) -> String {
    let history_content = match &app.history {
        None if app.history_running => "Loading local operation history…".into(),
        None => "Press Enter to load local operation history.".into(),
        Some(Err(error)) => format!("Cannot read history: {error}"),
        Some(Ok(history)) => {
            let filter = app.history_filter.to_lowercase();
            let mut records = history
                .records
                .iter()
                .filter(|record| {
                    filter.is_empty()
                        || [&record.operation, &record.target, &record.outcome]
                            .into_iter()
                            .any(|value| value.to_lowercase().contains(&filter))
                        || record
                            .detail
                            .as_ref()
                            .is_some_and(|value| value.to_lowercase().contains(&filter))
                })
                .collect::<Vec<_>>();
            records.sort_by(|a, b| {
                let order = a.started_unix.cmp(&b.started_unix).then(a.id.cmp(&b.id));
                if app.history_oldest_first {
                    order
                } else {
                    order.reverse()
                }
            });
            let mut lines = vec![format!(
                "Order: {} first",
                if app.history_oldest_first {
                    "oldest"
                } else {
                    "newest"
                }
            )];
            if records.is_empty() {
                lines.push(
                    if filter.is_empty() {
                        "No maintenance operation records."
                    } else {
                        "No records match the filter."
                    }
                    .into(),
                );
            } else {
                lines.extend(records.into_iter().map(|record| {
                    format!(
                        "started={}  finished={}  {}  {}  {}\n  target={}\n  duration={}ms  {}\n  estimated={}  verified reclaimed={}",
                        crate::reports::format_timestamp(record.started_unix),
                        record
                            .finished_unix
                            .map(crate::reports::format_timestamp)
                            .unwrap_or_else(|| "unfinished".into()),
                        record.id,
                        record.operation,
                        record.outcome,
                        record.target,
                        record.duration_ms,
                        record.detail.as_deref().unwrap_or(""),
                        record.estimated_bytes.map_or("unknown".into(), |v| v.to_string()),
                        record.verified_reclaimed_bytes.map_or("unknown".into(), |v| v.to_string())
                    )
                }));
            }
            if !app.history_filter.is_empty() {
                lines.insert(0, format!("Filter: {}", app.history_filter));
            }
            lines.extend(
                history
                    .warnings
                    .iter()
                    .map(|warning| format!("Warning: {warning}")),
            );
            lines.push(format!("Verified reclaimed-byte subtotal: {}; records without measurement: {}. All readable records, including filtered-out records.", history.known_reclaimed_bytes.map_or("unknown".into(), |v| v.to_string()), history.records_without_verified_reclaimed_bytes));
            lines.push(format!("{} of {} slots contain valid records; byte estimates are not guaranteed reclaimed space.", history.records.len(), history.capacity));
            lines.join("\n")
        }
    };
    if let Some(result) = &app.history_purge_result {
        let mut lines = vec![format!(
            "History purge: {}{}",
            result.outcome,
            if result.cancelled { " (cancelled)" } else { "" }
        )];
        if result.items.is_empty() {
            lines.push("No candidate records were removed.".into());
        } else {
            lines.extend(result.items.iter().map(|item| {
                format!(
                    "Record {}: {}{}",
                    item.id,
                    item.status,
                    item.error.as_ref().map_or_else(String::new, |error| {
                        format!(" — {}", schedule_escape_controls(error))
                    })
                )
            }));
        }
        if let Some(warning) = &app.history_purge_warning {
            lines.push(format!(
                "History warning: {}",
                schedule_escape_controls(warning)
            ));
        }
        lines.push(String::new());
        lines.push(history_content);
        lines.join("\n")
    } else if let Some(warning) = &app.history_purge_warning {
        format!(
            "History warning: {}\n\n{}",
            schedule_escape_controls(warning),
            history_content
        )
    } else {
        history_content
    }
}

fn cache_content(app: &App) -> String {
    match &app.cache {
        None if app.cache_running => "Inventorying shared caches… Esc: cancel".into(),
        None => "Press Enter to inventory shared caches.".into(),
        Some(report) => {
            let visible = visible_cache_entries(report, &app.cache_filter, app.cache_sort);
            let total = visible_cache_entries(report, "", app.cache_sort).len();
            let selection_visible = visible
                .iter()
                .any(|entry| Some(&entry.path) == app.cache_selected.as_ref());
            let mut lines = vec![format!(
                "Filter: {}  ({} of {} caches)  Sort: {}",
                if app.cache_filter.is_empty() {
                    "(none)"
                } else {
                    &app.cache_filter
                },
                visible.len(),
                total,
                app.cache_sort.label()
            )];
            if app.cache_selected.is_some() && !selection_visible {
                lines.push(
                    "Current selection is hidden by this filter; clearing it restores the target."
                        .into(),
                );
            }
            if visible.is_empty() {
                lines.push(
                    if app.cache_filter.is_empty() {
                        "No caches found."
                    } else {
                        "No caches match the filter."
                    }
                    .into(),
                );
            }
            if !app.cache_details {
                lines.extend(visible.iter().map(|entry| {
                    let selected = if Some(&entry.path) == app.cache_selected.as_ref() {
                        "›"
                    } else {
                        " "
                    };
                    let size = entry.logical_bytes.map_or_else(
                        || "size unknown".to_owned(),
                        |bytes| {
                            if bytes >= 1_048_576 {
                                format!("{:.1} MiB snapshot", bytes as f64 / 1_048_576.0)
                            } else if bytes >= 1024 {
                                format!("{:.1} KiB snapshot", bytes as f64 / 1024.0)
                            } else {
                                format!("{bytes} B snapshot")
                            }
                        },
                    );
                    format!(
                        "{selected} {}: {size}  |  {}\n    {}",
                        entry.name,
                        entry.status,
                        crate::shared_cache_cleanup::display_path(&entry.path),
                    )
                }));
                let warning_count = report.warnings.len()
                    + visible
                        .iter()
                        .map(|entry| entry.warnings.len())
                        .sum::<usize>();
                if warning_count > 0 {
                    lines.push(format!(
                        "⚠ {warning_count} diagnostic warning(s). Press w to read details."
                    ));
                    lines.push(
                        "Unverified and unsafe cache paths are never eligible for deletion.".into(),
                    );
                }
                if report.cancelled {
                    lines.push("Inventory cancelled; results are partial.".into());
                    lines.extend(
                        report
                            .warnings
                            .iter()
                            .take(2)
                            .map(|warning| format!("Warning: {warning}")),
                    );
                }
                lines.push("s: sort  /: filter  d: review removal  w: diagnostics".into());
                return lines.join("\n");
            }
            lines.extend(visible.iter().map(|entry| {
                let selected = if Some(&entry.path) == app.cache_selected.as_ref() {
                    "›"
                } else {
                    " "
                };
                let logical = entry
                    .logical_bytes
                    .map_or_else(|| "unknown".to_owned(), |bytes| bytes.to_string());
                let allocated = entry
                    .allocated_bytes
                    .map_or_else(|| "unknown".to_owned(), |bytes| bytes.to_string());
                let mut text = format!(
                    "{} {}: logical snapshot {} bytes{}; allocated snapshot {} bytes  {}\n  {}",
                    selected,
                    entry.name,
                    logical,
                    if entry.size_complete {
                        ""
                    } else {
                        " (incomplete)"
                    },
                    allocated,
                    crate::shared_cache_cleanup::display_path(&entry.path),
                    entry.consequence
                );
                text.push_str(&format!(
                    "\n  Directory owner (snapshot): {}",
                    entry.directory_owner_status
                ));
                text.push_str(&format!(
                    "\n  Status snapshot: {}; process activity: {}",
                    entry.status, entry.activity_status
                ));
                if let Some(test_cache) = &entry.go_test_cache {
                    text.push_str(&format!(
                        "\n  Go test cache: {}; expiration (Unix ns): {}",
                        test_cache.status,
                        test_cache
                            .expired_before_unix_nanos
                            .map_or("unknown".into(), |value| value.to_string())
                    ));
                }
                text
            }));
            lines.extend(visible.iter().flat_map(|entry| {
                entry
                    .warnings
                    .iter()
                    .map(move |warning| format!("Warning ({}): {warning}", entry.name))
            }));
            lines.extend(
                report
                    .warnings
                    .iter()
                    .map(|warning| format!("Warning: {warning}")),
            );
            if report.cancelled {
                lines.push("Inventory cancelled; results are partial.".into());
            }
            lines.push(
                "Select a cache to review removal; inventory sizes are estimates, not reclaimed bytes."
                    .into(),
            );
            lines.join("\n")
        }
    }
}

fn wrapped_content_scroll_limit(content: &str, body: Rect) -> u16 {
    let line_count = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .line_count(body.width.saturating_sub(2));
    let max_scroll = line_count.saturating_sub(body.height.saturating_sub(2) as usize);
    u16::try_from(max_scroll).unwrap_or(u16::MAX)
}

fn content_area(area: Rect) -> Rect {
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(3),
    ])
    .split(area);
    let body = if area.width >= 60 {
        Layout::horizontal([Constraint::Length(20), Constraint::Min(1)]).split(rows[1])
    } else {
        Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).split(rows[1])
    };
    body[1]
}

fn clamp_doctor_scroll(app: &mut App, area: Rect) {
    if app.page == Start::Doctor {
        let content = doctor_content(app);
        app.doctor_scroll = app
            .doctor_scroll
            .min(wrapped_content_scroll_limit(&content, content_area(area)));
    }
}

fn clamp_history_settings_scroll(app: &mut App, area: Rect) {
    let body = content_area(area);
    if app.page == Start::Reports {
        let content = reports_content(app);
        app.history_scroll = app
            .history_scroll
            .min(wrapped_content_scroll_limit(&content, body));
    } else if app.page == Start::Settings && app.settings_form.is_none() {
        let content = settings_content(app);
        app.settings_scroll = app
            .settings_scroll
            .min(wrapped_content_scroll_limit(&content, body));
    }
}

fn clamp_schedule_scroll(app: &mut App, area: Rect, platform: SchedulePlatform) {
    if app.page == Start::Automation {
        let content = automation_content(app, platform);
        app.schedule_scroll = app
            .schedule_scroll
            .min(wrapped_content_scroll_limit(&content, content_area(area)));
    }
}

fn clamp_cache_scroll(app: &mut App, area: Rect) {
    if app.page == Start::Cache {
        let content = cache_content(app);
        app.cache_scroll = app
            .cache_scroll
            .min(wrapped_content_scroll_limit(&content, content_area(area)));
    }
}

fn draw(frame: &mut Frame<'_>, app: &App) {
    draw_for_platform(frame, app, SchedulePlatform::current());
}

fn application_status(app: &App) -> &'static str {
    let initial_checks_running = app.startup_checks.toolchains
        || app.startup_checks.doctor
        || app.startup_checks.maintenance;
    let working = initial_checks_running
        || [
            app.updating,
            app.self_update_preparing,
            app.managed_preparing,
            app.managed_running,
            app.scan_running,
            app.artifact_preparing,
            app.artifact_running,
            app.bytecode_preparing,
            app.bytecode_running,
            app.bytecode_listing_running,
            app.trim_preparing,
            app.trim_running,
            app.temp_preparing,
            app.temp_running,
            app.cache_running,
            app.go_test_preparing,
            app.go_test_running,
            app.trash_running,
            app.trash_removal_preparing,
            app.trash_marking,
            app.trash_removing,
            app.containers_running,
            app.container_preparing,
            app.container_removing,
            app.network_preparing,
            app.network_removing,
            app.build_cache_preparing,
            app.build_cache_removing,
            app.schedule_running,
            app.schedule_edit_preparing,
            app.schedule_edit_running,
            app.schedule_remove_preparing,
            app.schedule_remove_running,
            app.schedule_disable_preparing,
            app.schedule_disable_running,
            app.schedule_install_preparing,
            app.schedule_install_running,
            app.schedule_enable_preparing,
            app.schedule_enable_running,
            app.history_running,
            app.history_purge_preparing,
            app.history_purging,
            app.settings_loading,
            app.settings_saving,
        ]
        .into_iter()
        .any(|active| active)
        || {
            #[cfg(target_os = "linux")]
            {
                app.trash_retention_status_loading
                    || app.trash_retention_preparing
                    || app.trash_retention_running
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        };
    if working {
        "Working"
    } else if confirmation_surfaces(app).contains(&true) {
        "Review"
    } else if app.reports.is_none() || app.issues.is_none() || app.maintenance.is_none() {
        "Idle"
    } else {
        "Ready"
    }
}

fn expire_toolchain_refresh_notice(
    message: &mut String,
    first_seen: &mut Option<std::time::Instant>,
    now: std::time::Instant,
) {
    if message == "Toolchain inventory refreshed." {
        let start = first_seen.get_or_insert(now);
        if now.duration_since(*start) >= Duration::from_secs(4) {
            message.clear();
            *first_seen = None;
        }
    } else {
        *first_seen = None;
    }
}

fn draw_for_platform(frame: &mut Frame<'_>, app: &App, platform: SchedulePlatform) {
    let areas = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(3),
    ])
    .split(frame.area());
    let status = application_status(app);
    let header = if frame.area().width < 24 {
        status.to_owned()
    } else if frame.area().width < 34 {
        format!(" Upkit  •  {status}")
    } else if frame.area().width < 40 {
        format!(" Upkit {}  •  {status}", env!("CARGO_PKG_VERSION"))
    } else if frame.area().width < 50 {
        format!(
            " Upkit {}  •  {}  •  {status}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
        )
    } else if frame.area().width < 72 {
        format!(
            " Upkit {}  •  {}/{}  •  {status}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
        )
    } else {
        format!(
            " Upkit {}  •  {} / {}  •  Status: {status}  •  ?: help",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    };
    frame.render_widget(
        Paragraph::new(header)
            .block(Block::default().borders(Borders::ALL))
            .cyan(),
        areas[0],
    );
    let body = if frame.area().width >= 60 {
        Layout::horizontal([Constraint::Length(20), Constraint::Min(1)]).split(areas[1])
    } else {
        Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).split(areas[1])
    };
    let pages = [
        (Start::Dashboard, "Dashboard"),
        (Start::Toolchains, "Toolchains"),
        (Start::Doctor, "Doctor"),
        (Start::Artifacts, "Artifacts"),
        (Start::Maintenance, "Maintenance"),
        (Start::Cache, "Caches"),
        (Start::Trash, "Trash"),
        (Start::Containers, "Containers"),
        (Start::Automation, "Automation"),
        (Start::Reports, "Reports"),
        (Start::Settings, "Settings"),
    ];
    let nav: Vec<ratatui::text::Line<'_>> = if frame.area().width < 60 {
        let name = pages
            .iter()
            .find(|(page, _)| *page == app.page)
            .map_or("", |(_, name)| *name);
        vec![ratatui::text::Line::from(if app.cli_preview_read_only {
            format!("› {name}  (read-only)")
        } else {
            format!("←/→ {name}  Tab: next")
        })]
    } else {
        pages
            .iter()
            .map(|(page, name)| {
                if *page == app.page {
                    ratatui::text::Line::from(ratatui::text::Span::styled(
                        format!("› {name}"),
                        Style::default().fg(Color::Black).bg(Color::Cyan),
                    ))
                } else {
                    ratatui::text::Line::raw(format!("  {name}"))
                }
            })
            .collect()
    };
    frame.render_widget(
        Paragraph::new(nav)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Pages ←/→ Tab "),
            )
            .style(Style::default().fg(Color::Cyan)),
        body[0],
    );
    let content = if app.temp_mode {
        temp_cleanup_content(app)
    } else if app.page == Start::Automation {
        automation_content(app, platform)
    } else if let Some(form) = &app.settings_form {
        settings_form_content(form)
    } else if app.page == Start::Settings {
        settings_content(app)
    } else if app.page == Start::Dashboard {
        dashboard_content(app)
    } else if app.page == Start::Reports {
        reports_content(app)
    } else if app.page == Start::Containers {
        match &app.containers {
            None if app.containers_running => "Inspecting container storage…".into(),
            None => "Press Enter to inspect container storage.".into(),
            Some(report) => container_screen_content(app, report),
        }
    } else if app.page == Start::Trash {
        if let Some(preview) = &app.trash_preview {
            match preview {
                Err(err) => format!("Trash preview failed: {err}"),
                Ok(preview) => {
                    let mut lines = vec![format!(
                        "Retention preview: older than {} seconds; {} (time zone may have changed)",
                        preview.older_than_seconds,
                        if preview.complete {
                            "inventory complete"
                        } else {
                            "some locations incomplete; selection requires a complete location"
                        }
                    )];
                    lines.extend(preview.items.iter().enumerate().map(|(index, item)| {
                        format!(
                            "{}[{}] {}  {}  deleted={}  {}",
                            if index == app.trash_selected {
                                "›"
                            } else {
                                " "
                            },
                            if item.selected { "x" } else { " " },
                            item.age_status,
                            item.name,
                            item.deletion_date.as_deref().unwrap_or("unknown"),
                            crate::sweep::display_path(&item.location)
                        )
                    }));
                    if preview.items.is_empty() {
                        lines.push("No Trash items found.".into());
                    }
                    lines.extend(
                        preview
                            .warnings
                            .iter()
                            .map(|warning| format!("Warning: {warning}")),
                    );
                    if preview.cancelled {
                        lines.push("Inventory cancelled; results are partial.".into());
                    }
                    lines.push(
                        "Select files or directories, review, and request a deletion preview."
                            .into(),
                    );
                    lines.join("\n")
                }
            }
        } else if let Some(result) = &app.trash_last_result {
            let mut lines = vec![format!("Trash deletion: {}", result.outcome)];
            for item in &result.items {
                lines.push(format!(
                    "{} / {}: {}",
                    crate::sweep::display_path(&item.location),
                    item.name,
                    item.status
                ));
                if let Some(error) = &item.error {
                    lines.push(format!("  {error}"));
                }
            }
            lines.push("Reclaimed space is unknown; press r to refresh.".into());
            lines.join("\n")
        } else {
            match &app.trash {
                None if app.trash_running => "Inspecting Trash… Esc: cancel".into(),
                None => "Press Enter to inspect Trash locations.".into(),
                Some(report) => {
                    let mut lines = report
                        .locations
                        .iter()
                        .map(|location| {
                            let mut line = format!(
                                "{}: {}\n  items={} logical={} bytes{}",
                                location.kind,
                                trash_location_path(&location.path),
                                location
                                    .item_count
                                    .map_or("unknown".into(), |v| v.to_string()),
                                location
                                    .logical_bytes
                                    .map_or("unknown".into(), |v| v.to_string()),
                                if location.size_complete {
                                    ""
                                } else {
                                    " (incomplete)"
                                }
                            );
                            for item in &location.items {
                                line.push_str(&format!(
                                    "\n  {}  deleted={}",
                                    item.name,
                                    item.deletion_date.as_deref().unwrap_or("unknown")
                                ));
                            }
                            line
                        })
                        .collect::<Vec<_>>();
                    lines.extend(report.locations.iter().flat_map(|location| {
                        location.warnings.iter().map(move |warning| {
                            format!(
                                "Warning ({}): {warning}",
                                trash_location_path(&location.path)
                            )
                        })
                    }));
                    lines.extend(
                        report
                            .warnings
                            .iter()
                            .map(|warning| format!("Warning: {warning}")),
                    );
                    if report.cancelled {
                        lines.push("Inventory cancelled; results are partial.".into());
                    }
                    lines.push(
                        match report.platform {
                            "linux" => {
                                "Counts include orphaned entries; review old items to preview deletion."
                            }
                            "macos" => {
                                "Names are a read-only snapshot; deletion dates and item actions are unavailable."
                            }
                            "windows" => {
                                "Recycle Bin sizes are estimates; item-level actions are unsupported."
                            }
                            _ => "Item-level Trash actions are unsupported on this platform.",
                        }
                        .into(),
                    );
                    lines.join("\n")
                }
            }
        }
    } else if app.page == Start::Cache {
        cache_content(app)
    } else if app.page == Start::Maintenance {
        match &app.maintenance {
            None if app.maintenance_check_failed => "Maintenance status is unavailable.".into(),
            None if app.self_update_command => {
                "Maintenance status was not loaded for self-update.".into()
            }
            None => "Checking TRIM timer status…".into(),
            Some(report) => {
                let mut lines = vec![
                    format!("TRIM: {}", report.capability),
                    format!("fstrim available: {}", report.fstrim_available),
                    format!("System timer: {}", report.timer.state),
                    format!(
                        "Last trigger: {}",
                        report.timer.last_trigger.as_deref().unwrap_or("unknown")
                    ),
                    format!(
                        "Next trigger: {}",
                        report.timer.next_trigger.as_deref().unwrap_or("unknown")
                    ),
                    if report.fstrim_available {
                        "Select a mount and press Enter for a TRIM preview:"
                    } else {
                        "Volume inventory is read-only; TRIM preview is unavailable."
                    }
                    .into(),
                ];
                lines.extend(report.mounts.iter().enumerate().map(|(index, mount)| {
                    format!(
                        "{} {}: filesystem {}  device discard {}  available bytes {}\n  FITRIM: {}\n  online discard option: {}  fstab TRIM exclusion: {}",
                        if index == app.trim_selected {
                            "›"
                        } else {
                            " "
                        },
                        crate::maintenance::display_mount_path(&mount.mount_path),
                        schedule_escape_controls(&mount.filesystem),
                        mount.device_discard,
                        mount
                            .available_bytes
                            .map_or("unknown".into(), |value| value.to_string()),
                        mount.filesystem_trim,
                        mount.online_discard_option,
                        mount.fstab_trim_exclusion
                    )
                }));
                if report.mounts.is_empty() {
                    lines.push("No supported mount inventory available.".into());
                }
                if let Some(detail) = &report.timer.detail {
                    lines.push(detail.clone());
                }
                if let Some(warning) = &report.mounts_warning {
                    lines.push(warning.clone());
                }
                lines.push(report.guidance.into());
                lines.join("\n")
            }
        }
    } else if app.page == Start::Artifacts && app.preview_mode {
        match &app.plan {
            None if app.scan_running => format!(
                "Preparing preview… {} directories inspected.\nEsc: cancel",
                app.scan_visited
            ),
            None => "No preview available.".into(),
            Some(Err(err)) => format!("Preview failed: {err}"),
            Some(Ok(plan)) => {
                let mut lines = plan
                    .items
                    .iter()
                    .filter(|item| artifact_matches(&item.candidate, &app.artifact_filter))
                    .enumerate()
                    .map(|(index, item)| {
                        format!(
                            "{}[{}] {}  {} bytes{}  modified={}  {}  {}",
                            if index == app.scan_scroll as usize {
                                "›"
                            } else {
                                " "
                            },
                            if item.selected { "x" } else { " " },
                            item.candidate.ecosystem,
                            item.candidate.logical_bytes,
                            if item.candidate.size_complete {
                                ""
                            } else {
                                " (incomplete)"
                            },
                            item.candidate
                                .modified_unix
                                .map_or("?".into(), |n| n.to_string()),
                            item.risk,
                            crate::sweep::display_path(&item.candidate.target)
                        )
                    })
                    .collect::<Vec<_>>();
                if lines.is_empty() {
                    lines.push(
                        if app.artifact_filter.is_empty() {
                            "No artifacts found."
                        } else {
                            "No artifacts match the filter."
                        }
                        .into(),
                    );
                }
                lines.extend(
                    plan.warnings
                        .iter()
                        .map(|warning| format!("Warning: {warning}")),
                );
                lines.push(format!(
                    "Filter: {}  Sort: {}  Selected (including hidden): {}",
                    if app.artifact_filter.is_empty() {
                        "(none)"
                    } else {
                        &app.artifact_filter
                    },
                    app.artifact_sort.label(),
                    plan.items.iter().filter(|item| item.selected).count()
                ));
                lines.push(if app.cli_preview_read_only {
                    "Read-only CLI preview; Space changes selection locally. Open the interactive dashboard for cleanup actions.".into()
                } else {
                    "Space marks targets; d reviews marked targets, or the current target if none are marked.".into()
                });
                lines.join("\n")
            }
        }
    } else if app.page == Start::Artifacts {
        match &app.scan {
            None if app.scan_running => format!(
                "Scanning workspace… {} directories inspected.\nEsc: cancel",
                app.scan_visited
            ),
            None => "Press r to scan configured roots, or choose roots with: upkit sweep scan <path>\nConfigure roots with: upkit config init <path>\nNo paths are scanned by default."
                .into(),
            Some(Err(err)) => format!("Scan failed: {err}"),
            Some(Ok(report)) => {
                let mut lines = report
                    .candidates
                    .iter()
                    .filter(|candidate| artifact_matches(candidate, &app.artifact_filter))
                    .enumerate()
                    .map(|(index, c)| {
                        format!(
                            "{}[{}] {}  logical={}  allocated={}  modified={}{}{}  {}",
                            if index == app.scan_scroll as usize { "›" } else { " " },
                            if app.artifact_marks.contains(&c.target) { "x" } else { " " },
                            c.ecosystem,
                            c.logical_bytes,
                            c.allocated_bytes.map_or("?".into(), |n| n.to_string()),
                            c.modified_unix.map_or("?".into(), |n| n.to_string()),
                            if c.size_complete { "" } else { " (incomplete)" },
                            if c.nested_project_marker.is_some() || c.nested_vcs_marker.is_some() || c.hard_link_marker.is_some() || c.symlink_marker.is_some() { " (review marker)" } else { "" },
                            crate::sweep::display_path(&c.target)
                        )
                    })
                    .collect::<Vec<_>>();
                if lines.is_empty() {
                    lines.push(if app.artifact_filter.is_empty() { "No artifacts found." } else { "No artifacts match the filter." }.into());
                }
                lines.extend(
                    report
                        .warnings
                        .iter()
                        .map(|warning| format!("Warning: {warning}")),
                );
                lines.push(format!("Filter: {}  Sort: {}", if app.artifact_filter.is_empty() { "(none)" } else { &app.artifact_filter }, app.artifact_sort.label()));
                lines.push(format!(
                    "Marked for batch removal: {} / {}",
                    app.artifact_marks.len(),
                    crate::artifact_cleanup::MAX_BATCH_ARTIFACTS
                ));
                lines.push(
                    if report.cancelled {
                        "Scan cancelled; results are partial."
                    } else {
                        "Read-only scan; sizes are estimates."
                    }
                    .into(),
                );
                lines.join("\n")
            }
        }
    } else if app.page == Start::Doctor {
        doctor_content(app)
    } else {
        match &app.reports {
            None if app.toolchain_check_failed => {
                "Toolchain check failed; results are unavailable.".to_owned()
            }
            None if app.self_update_command => {
                "Toolchain inventory was not loaded for self-update.".to_owned()
            }
            None => "Checking toolchains in the background…".to_owned(),
            Some(reports) => {
                let visible = visible_toolchain_indices(reports, &app.toolchain_filter);
                let mut lines = Vec::new();
                if !app.toolchain_filter.is_empty() {
                    lines.push(format!(
                        "Filter: {} ({}/{} toolchains)",
                        app.toolchain_filter,
                        visible.len(),
                        reports.len()
                    ));
                }
                lines.extend(visible.iter().map(|&index| {
                    let r = &reports[index];
                    let marker = if app.page == Start::Toolchains && index == app.selected {
                        "›"
                    } else {
                        " "
                    };
                    format!(
                        "{marker}[{}] {:<8} installed: {:<13} latest: {:<13} {}",
                        if app.marked.contains(&r.tool) {
                            "x"
                        } else {
                            " "
                        },
                        r.tool.as_str(),
                        r.installed
                            .as_ref()
                            .map_or("-".to_owned(), |v| v.to_string()),
                        r.latest.as_ref().map_or("-".to_owned(), |v| v.to_string()),
                        match r.status {
                            crate::Status::UpToDate => "Up to date",
                            crate::Status::Outdated => "Update available",
                            crate::Status::NotInstalled => "Not installed",
                            crate::Status::Unknown => "Unknown",
                        }
                    )
                }));
                if visible.is_empty() {
                    lines.push(if app.toolchain_filter.is_empty() {
                        "No toolchains available.".into()
                    } else {
                        "No toolchains match the filter.".into()
                    });
                }
                if !app.marked.is_empty() {
                    let hidden = reports
                        .iter()
                        .filter(|report| {
                            app.marked.contains(&report.tool)
                                && !toolchain_matches(report, &app.toolchain_filter)
                        })
                        .count();
                    lines.push(format!(
                        "{} tool(s) marked for {} ({} hidden by filter).",
                        app.marked.len(),
                        if app.managed_mode {
                            "managed cleanup"
                        } else {
                            "update or cleanup"
                        },
                        hidden
                    ));
                }
                lines.join("\n")
            }
        }
    };
    let title = match app.page {
        Start::Dashboard => " Dashboard ",
        Start::Toolchains => " Toolchains ",
        Start::Doctor => " Doctor ",
        Start::Artifacts if app.preview_mode => " Cleanup preview ",
        Start::Artifacts => " Developer artifacts ",
        Start::Maintenance => " System maintenance ",
        Start::Cache => " Shared caches ",
        Start::Trash => " Trash ",
        Start::Containers => " Container storage ",
        Start::Automation => " Automation ",
        Start::Reports => " Operation history ",
        Start::Settings => " Settings ",
    };
    let artifact_title = if app.page == Start::Artifacts && app.preview_mode {
        app.plan
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|plan| {
                let selected = plan.items.iter().filter(|item| item.selected).count();
                let hidden = plan
                    .items
                    .iter()
                    .filter(|item| {
                        item.selected && !artifact_matches(&item.candidate, &app.artifact_filter)
                    })
                    .count();
                format!(" Cleanup preview: {selected} selected, {hidden} hidden ")
            })
    } else {
        None
    };
    let title = artifact_title.as_deref().unwrap_or(title);
    let scroll = if app.page == Start::Toolchains {
        app.reports
            .as_ref()
            .map(|reports| {
                visible_toolchain_indices(reports, &app.toolchain_filter)
                    .iter()
                    .position(|index| *index == app.selected)
                    .unwrap_or(0)
                    .saturating_add(usize::from(!app.toolchain_filter.is_empty()))
            })
            .unwrap_or(0)
            .saturating_sub(body[1].height.saturating_sub(3) as usize) as u16
    } else if app.page == Start::Doctor {
        app.doctor_scroll
            .min(wrapped_content_scroll_limit(&content, body[1]))
    } else if app.page == Start::Dashboard {
        app.dashboard_scroll
    } else if app.page == Start::Artifacts {
        app.scan_scroll
    } else if app.page == Start::Cache {
        app.cache_scroll
            .min(wrapped_content_scroll_limit(&content, body[1]))
    } else if app.page == Start::Trash {
        if app.trash_preview.is_some() {
            u16::try_from(
                1usize
                    .saturating_add(app.trash_selected)
                    .saturating_sub(body[1].height.saturating_sub(3) as usize),
            )
            .unwrap_or(u16::MAX)
        } else {
            app.trash_scroll
        }
    } else if app.page == Start::Containers {
        app.containers_scroll.max(
            u16::try_from(
                app.containers
                    .as_ref()
                    .map_or(0, |report| {
                        container_selection_line(
                            report,
                            &app.container_filter,
                            app.container_selected,
                        )
                    })
                    .saturating_sub(body[1].height.saturating_sub(3) as usize),
            )
            .unwrap_or(u16::MAX),
        )
    } else if app.page == Start::Automation {
        app.schedule_scroll
            .min(wrapped_content_scroll_limit(&content, body[1]))
    } else if app.page == Start::Reports {
        app.history_scroll
            .min(wrapped_content_scroll_limit(&content, body[1]))
    } else if app.page == Start::Settings {
        if let Some(form) = &app.settings_form {
            settings_form_scroll(form, body[1])
        } else {
            app.settings_scroll
                .min(wrapped_content_scroll_limit(&content, body[1]))
        }
    } else if app.page == Start::Maintenance && app.temp_mode {
        temp_cleanup_screen_scroll(app, body[1])
    } else if app.page == Start::Maintenance
        && app
            .maintenance
            .as_ref()
            .is_some_and(|report| !report.mounts.is_empty())
    {
        u16::try_from(
            6usize
                .saturating_add(app.trim_selected)
                .saturating_sub(body[1].height.saturating_sub(3) as usize),
        )
        .unwrap_or(u16::MAX)
    } else {
        0
    };
    if app.page == Start::Dashboard {
        draw_dashboard(frame, body[1], app, &content);
    } else {
        let paragraph = Paragraph::new(content)
            .scroll((scroll, 0))
            .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(
            if matches!(
                app.page,
                Start::Reports | Start::Doctor | Start::Automation | Start::Cache | Start::Settings
            ) || app.temp_mode
            {
                paragraph.wrap(Wrap { trim: false })
            } else {
                paragraph
            },
            body[1],
        );
    }
    if let Some(editor) = &app.settings_editor {
        let area = body[1];
        let inner = area.inner(ratatui::layout::Margin::new(1, 1));
        let height = inner.height as usize;
        let width = inner.width as usize;
        let top = editor.row.saturating_sub(height.saturating_sub(1));
        let mut left = editor.column.saturating_sub(width.saturating_sub(1));
        let prefix = |start: usize| {
            editor.lines[editor.row][start..editor.column]
                .iter()
                .copied()
                .map(config_display_character)
                .collect::<String>()
        };
        while left < editor.column && ratatui::text::Line::from(prefix(left)).width() >= width {
            left += 1;
        }
        let visible = editor
            .lines
            .iter()
            .skip(top)
            .take(height)
            .map(|line| {
                line.iter()
                    .skip(left)
                    .take(width.saturating_add(1))
                    .copied()
                    .map(config_display_character)
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(visible).block(Block::default().borders(Borders::ALL).title(format!(
                " Edit TOML — line {}, column {}{} ",
                editor.row + 1,
                editor.column + 1,
                if editor
                    .lines
                    .iter()
                    .flatten()
                    .any(|character| character.is_control() || is_bidi_control(*character))
                {
                    " — � may denote a control"
                } else {
                    ""
                }
            ))),
            area,
        );
        if width > 0 && height > 0 && app.settings_prompt.is_none() && !app.settings_saving {
            let cursor_x = ratatui::text::Line::from(prefix(left))
                .width()
                .min(width - 1);
            let cursor_y = editor.row.saturating_sub(top).min(height - 1);
            frame.set_cursor_position((inner.x + cursor_x as u16, inner.y + cursor_y as u16));
        }
    }
    let search_footer = app
        .toolchain_search
        .as_ref()
        .or(app.container_search.as_ref())
        .or(app.artifact_search.as_ref())
        .or(app.cache_search.as_ref())
        .or(app.doctor_search.as_ref())
        .or(app.history_search.as_ref())
        .map(|search| format!("Filter: {search}  (Enter: apply  Esc: cancel)"));
    let footer = if let Some(search) = &search_footer {
        search.as_str()
    } else if app.settings_form.is_some() {
        "↑/↓: select  Enter: edit/toggle  d: remove path  ←/→: profile  n: add profile  Ctrl+S: save  t: TOML  Esc: back"
    } else if app.settings_editor.is_some() {
        "Ctrl+S: review save  Esc: exit  Tab: indent"
    } else {
        match app.page {
            Start::Toolchains if app.managed_mode => {
                if app
                    .managed_scope
                    .as_ref()
                    .is_some_and(|scope| scope.len() > 1)
                {
                    "/: filter  r: refresh  ↑/↓: select  Space: mark  D: review marked cleanup  Enter/d: selected cleanup  q: quit"
                } else {
                    "/: filter  r: refresh  ↑/↓: select tool  Enter/d: preview cleanup  Tab: page  q: quit"
                }
            }
            Start::Toolchains => {
                "/: filter  r: refresh  ↑/↓: select  Space: mark  Enter: update  U: self-update  d/D: cleanup  q: quit"
            }
            Start::Artifacts if app.cli_preview_read_only && app.scan_running => {
                "Esc: cancel read-only preview scan  q: quit"
            }
            Start::Artifacts if app.scan_running => "Tab: page  Esc: cancel scan  q: quit",
            Start::Artifacts if app.cli_preview_read_only => {
                "/: filter  s: sort  ↑/↓: browse  Space: local selection  Enter: details  q: close read-only preview"
            }
            Start::Artifacts if app.preview_mode => {
                "/: filter  s: sort  ↑/↓: browse  Space: mark  d: review marked/current  b: bytecode  Enter: details  q: quit"
            }
            Start::Artifacts => {
                "/: filter  s: sort  ↑/↓: select  Space: mark  d: review marked/current  b: bytecode  r: scan  q: quit"
            }
            Start::Doctor if app.issues.is_none() => "Esc: cancel Doctor checks  q: quit",
            Start::Doctor => "/: filter  r: refresh  ↑/↓: scroll  Tab: page  q: quit",
            Start::Dashboard => {
                if frame.area().width < 42 {
                    "s scan c cache q quit"
                } else if frame.area().width < 65 {
                    "s scan c cache r history Tab page q quit"
                } else if frame.area().width < 81 {
                    "s: scan  c: caches  r: history  ↑/↓: scroll  Tab: page  q: quit"
                } else {
                    "s: scan roots  c: inventory caches  r: history  ↑/↓: scroll  Tab: page  q: quit"
                }
            }
            Start::Maintenance if app.temp_preparing => "Esc: cancel inventory  q: quit",
            Start::Maintenance if app.temp_running => {
                "Esc: request cancellation  q: wait for operation"
            }
            Start::Maintenance if app.temp_mode && app.temp_result.is_some() => {
                "↑/↓: scroll result  r: rescan  Esc: back  q: quit"
            }
            Start::Maintenance if app.temp_mode => {
                "↑/↓: select  Space: mark eligible  PgUp/PgDn: scroll inventory  Home/End: top/bottom  d: preview selection  r: rescan  Esc: back  q: quit"
            }
            Start::Maintenance if app.trim_preparing => "Esc: cancel preview  q: quit",
            Start::Maintenance if app.trim_read_only => {
                "Esc/n: close read-only TRIM preview  q: quit"
            }
            Start::Maintenance => {
                "↑/↓: select mount  Enter: preview TRIM  l: inspect Upkit temp links  Tab: page  q: quit"
            }
            Start::Cache if app.cache_running => "Tab: page  Esc: cancel inventory  q: quit",
            Start::Cache => {
                "/: filter  s: sort  Enter/r: refresh  d: preview removal  w: warnings  ↑/↓: scroll  q: quit"
            }
            Start::Trash if app.trash_running => "Tab: page  Esc: cancel inventory  q: quit",
            Start::Trash => {
                "7/1/3: age  Space: mark  A: mark eligible in location  Enter: review  q: quit"
            }
            Start::Containers => {
                "/: filter eligible resources  ↑/↓: select visible resource  d: preview removal  PgUp/PgDn: scroll  r: refresh  q: quit"
            }
            Start::Automation if platform == SchedulePlatform::Systemd => {
                "p/P: read-only daily/weekly preview  a/w: install  1/7: enable  d: disable  e/E: edit  x: remove  T: Trash install preview  G: Trash re-enable  D: Trash disable  X: Trash removal  q: quit"
            }
            Start::Automation => {
                "p/P: read-only daily/weekly preview  a/w: install  1/7: enable  d: disable  e/E: edit  x: remove  q: quit"
            }
            Start::Reports if app.history_purge_read_only && app.history_purge_plan.is_some() => {
                "Preview only; Esc/n closes  q: quit"
            }
            Start::Reports => {
                "/: filter  s: order  7/3/9: purge records older than 7/30/90 days  Enter/r: refresh  ↑/↓: scroll  q: quit"
            }
            Start::Settings => {
                "e: structured edit  t: edit TOML  r: reload  ↑/↓: scroll  Tab: page  q: quit"
            }
        }
    };
    let footer = if app.page == Start::Toolchains
        && search_footer.is_none()
        && ratatui::text::Line::from(footer).width() > frame.area().width.saturating_sub(2) as usize
    {
        compact_toolchain_footer(app, frame.area().width.saturating_sub(2))
    } else {
        footer
    };
    // Keep the original three-row footer so terminal height and safety
    // disclosures do not shrink. Navigation is always visible in the top
    // border, page actions stay on the content row, and status is independent
    // in the bottom border—even after an asynchronous refresh completes.
    let mut footer_block = Block::default()
        .borders(Borders::ALL)
        .title(" ←/→: sections  Tab: next  ?: help ");
    if !app.message.is_empty() {
        footer_block = footer_block.title_bottom(ratatui::text::Line::from(format!(
            " Status: {} ",
            schedule_escape_controls(&app.message).replace('\n', " ")
        )));
    }
    frame.render_widget(Paragraph::new(footer).block(footer_block), areas[2]);
    if let Some(message) = &app.managed_result {
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(4),
            frame.area().height.saturating_sub(4),
        );
        let safe = message
            .chars()
            .map(|character| {
                if character == '\n' {
                    '\n'
                } else {
                    config_display_character(character)
                }
            })
            .collect::<String>();
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(format!("{safe}\n\n↑/↓: scroll  Esc: close"))
                .wrap(Wrap { trim: false })
                .scroll((app.managed_result_scroll, 0))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Cleanup result "),
                ),
            area,
        );
    }
    if !app.managed_batch_plans.is_empty() {
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            frame.area().height.saturating_sub(2),
        );
        let title = format!(
            " Review all {} managed cleanup targets ",
            app.managed_batch_plans.len()
        );
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        frame.render_widget(Clear, area);
        frame.render_widget(block, area);
        let [content_area, footer_area] =
            Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).areas(inner);
        let content = app
            .managed_batch_review_content
            .as_ref()
            .map(|lines| lines.join("\n"))
            .unwrap_or_else(|| "Enlarge the terminal to review every selected tool.".into());
        frame.render_widget(
            Paragraph::new(content).scroll((
                u16::try_from(app.managed_batch_review_scroll).unwrap_or(u16::MAX),
                0,
            )),
            content_area,
        );
        let footer = if app.message.is_empty() {
            "↑/↓: scroll  y: confirm at the end  Esc/n: cancel\n".to_owned()
        } else {
            format!(
                "↑/↓: scroll  y: confirm at the end  Esc/n: cancel\n{}",
                app.message
            )
        };
        frame.render_widget(Paragraph::new(footer), footer_area);
    }
    if let Some(plan) = &app.managed_plan {
        let lines = managed_confirmation_lines(plan);
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Confirm managed cleanup "),
                )
                .yellow(),
            area,
        );
        if app.managed_detail {
            let area = centered(
                frame.area(),
                frame.area().width.saturating_sub(4),
                frame.area().height.saturating_sub(4),
            );
            let lines = plan
                .entries
                .iter()
                .map(|path| {
                    let kind = if plan.selected_entries.contains(path) {
                        "REMOVE sealed installation"
                    } else {
                        "PRESERVE unverified/root data"
                    };
                    format!("{kind}: {}", crate::sweep::display_path(path))
                })
                .collect::<Vec<_>>()
                .join("\n");
            frame.render_widget(Clear, area);
            frame.render_widget(
                Paragraph::new(if lines.is_empty() {
                    "No top-level entries.".into()
                } else {
                    lines
                })
                .scroll((app.managed_detail_scroll, 0))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Top-level contents — Esc: back "),
                ),
                area,
            );
        }
    }
    if let Some(input) = app
        .settings_form
        .as_ref()
        .and_then(|form| form.input.as_ref())
    {
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(4).min(80),
            5,
        );
        let inner = area.inner(ratatui::layout::Margin::new(1, 1));
        let width = inner.width as usize;
        let left = input.cursor.saturating_sub(width.saturating_sub(1));
        let visible = input
            .value
            .iter()
            .skip(left)
            .take(width.saturating_add(1))
            .copied()
            .collect::<String>();
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(format!("{}\n{}", settings_text_input_label(input), visible)).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Edit setting "),
            ),
            area,
        );
        if width > 0 {
            let prefix = input
                .value
                .iter()
                .take(input.cursor)
                .copied()
                .collect::<String>();
            let before = input.value.iter().take(left).copied().collect::<String>();
            let cursor_x = ratatui::text::Line::from(prefix.as_str())
                .width()
                .saturating_sub(ratatui::text::Line::from(before.as_str()).width())
                .min(width.saturating_sub(1));
            frame.set_cursor_position((inner.x + cursor_x as u16, inner.y + 1));
        }
    }
    let settings_snapshot = app
        .settings_pending_save
        .as_ref()
        .map(|pending| &pending.snapshot)
        .or_else(|| app.settings_editor.as_ref().map(|editor| &editor.snapshot))
        .or_else(|| app.settings_form.as_ref().map(|form| &form.snapshot));
    let cleanup_impacts = app
        .settings_pending_save
        .as_ref()
        .map_or(&[][..], |pending| pending.cleanup_impacts.as_slice());
    let settings_changes = app
        .settings_pending_save
        .as_ref()
        .map_or(&[][..], |pending| pending.changes.as_slice());
    if let (Some(snapshot), Some(prompt)) = (settings_snapshot, app.settings_prompt) {
        let lines =
            settings_confirmation_lines(snapshot, prompt, cleanup_impacts, settings_changes);
        let area = settings_confirmation_area(frame.area());
        let scroll = app
            .settings_confirmation_scroll
            .min(settings_confirmation_scroll_limit(
                snapshot,
                prompt,
                cleanup_impacts,
                settings_changes,
                frame.area(),
            ));
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .wrap(Wrap { trim: false })
                .scroll((scroll, 0))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Confirm settings "),
                )
                .yellow(),
            area,
        );
    }
    if let Some(listing) = &app.bytecode_listing {
        let mut lines = vec![
            format!("Cache: {}", crate::sweep::display_path(&listing.cache)),
            format!(
                "Space: mark ({} / {})   Enter: preview   Esc: back",
                app.bytecode_marks.len(),
                crate::bytecode::MAX_BATCH_FILES
            ),
        ];
        if !app.message.is_empty() {
            lines.push(app.message.chars().map(config_display_character).collect());
        }
        let header_lines = lines.len();
        lines.extend(listing.files.iter().enumerate().map(|(index, file)| {
            format!(
                "{}[{}] {}",
                if index == app.bytecode_selected {
                    "›"
                } else {
                    " "
                },
                if app.bytecode_marks.contains(file) {
                    "x"
                } else {
                    " "
                },
                crate::sweep::display_path(std::path::Path::new(
                    file.file_name().unwrap_or_default()
                ))
            )
        }));
        if listing.files.is_empty() {
            lines.push("No supported bytecode filenames found.".into());
        }
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            frame.area().height.saturating_sub(2),
        );
        let scroll = u16::try_from(
            app.bytecode_selected
                .saturating_add(header_lines + 1)
                .saturating_sub(area.height.saturating_sub(2) as usize),
        )
        .unwrap_or(u16::MAX);
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n")).scroll((scroll, 0)).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Choose bytecode file "),
            ),
            area,
        );
    }
    if app.cache_choosing
        && let Some(report) = &app.cache
    {
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            frame.area().height.saturating_sub(2),
        );
        frame.render_widget(Clear, area);
        let visible = visible_cache_entries(report, &app.cache_filter, app.cache_sort);
        let selection_index = visible
            .iter()
            .position(|entry| Some(&entry.path) == app.cache_selected.as_ref());
        let mut lines = vec![
            "↑/↓: select  s: sort  Enter: review  Esc: cancel".to_owned(),
            format!("Sort: {}", app.cache_sort.label()),
        ];
        if app.cache_selected.is_some() && selection_index.is_none() {
            lines.push("Selected target is hidden; choose a visible cache.".into());
        }
        lines.extend(visible.iter().map(|entry| {
            format!(
                "{} {}  {}",
                if Some(&entry.path) == app.cache_selected.as_ref() {
                    "›"
                } else {
                    " "
                },
                entry.name,
                crate::shared_cache_cleanup::display_path(&entry.path)
            )
        }));
        let scroll = selection_index
            .unwrap_or(0)
            .saturating_sub(area.height.saturating_sub(6) as usize);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .scroll((u16::try_from(scroll).unwrap_or(u16::MAX), 0))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Select shared cache "),
                ),
            area,
        );
    }
    if let Some(plan) = &app.artifact_plan {
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            frame.area().height.saturating_sub(2),
        );
        frame.render_widget(Clear, area);
        let is_batch = matches!(plan, DirectoryPlan::ArtifactBatch(_));
        let lines = if app.artifact_confirm && is_batch {
            let rows = artifact_batch_confirmation_rows(frame.area());
            let DirectoryPlan::ArtifactBatch(batch) = plan else {
                unreachable!("batch confirmation requires a batch plan")
            };
            let mut lines = vec![
                format!(
                    "Confirm removal of all {} reviewed directories:",
                    batch.items.len()
                ),
                "↑/↓: scroll  y: confirm at end  Esc: cancel".into(),
            ];
            if let Some(content) = &app.artifact_review_content {
                lines.extend(
                    content
                        .iter()
                        .skip(app.artifact_review_scroll)
                        .take(rows)
                        .cloned(),
                );
            }
            if rows == 0 {
                lines.push("Enlarge terminal to review every target.".into());
            }
            lines
        } else if app.artifact_confirm {
            directory_confirmation_lines(plan)
        } else {
            let rows = if app.artifact_review_content.is_some() {
                artifact_review_rows(plan, frame.area())
            } else {
                0
            };
            let mut lines = vec![
                match plan {
                    DirectoryPlan::ArtifactBatch(batch) => format!(
                        "Review all {} entries across {} selected targets.",
                        plan.entry_count(),
                        batch.items.len()
                    ),
                    _ => format!(
                        "Review all {} entries; paths are relative to the selected directory.",
                        plan.entry_count()
                    ),
                },
                "↑/↓: scroll  +: continued  Enter: continue at end  Esc: cancel".into(),
            ];
            if let Some(entries) = &app.artifact_review_content {
                lines.extend(
                    entries
                        .iter()
                        .skip(app.artifact_review_scroll)
                        .take(rows)
                        .cloned(),
                );
            }
            if rows == 0 {
                lines.push("Enlarge terminal to review the entries.".into());
            }
            lines
        };
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .block(Block::default().borders(Borders::ALL).title(
                    match (plan, app.artifact_confirm) {
                        (DirectoryPlan::Artifact(_), true) => {
                            " Confirm permanent artifact removal "
                        }
                        (DirectoryPlan::Artifact(_), false) => " Review artifact entries ",
                        (DirectoryPlan::ArtifactBatch(_), true) => {
                            " Confirm permanent artifact batch removal "
                        }
                        (DirectoryPlan::ArtifactBatch(_), false) => {
                            " Review artifact batch entries "
                        }
                        (DirectoryPlan::Cache(_), true) => {
                            " Confirm permanent shared-cache removal "
                        }
                        (DirectoryPlan::Cache(_), false) => " Review shared-cache entries ",
                    },
                ))
                .yellow(),
            area,
        );
    }
    if let Some(plan) = &app.bytecode_plan {
        let lines = bytecode_confirmation_lines(plan);
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Confirm bytecode removal "),
                )
                .yellow(),
            area,
        );
    }
    if let Some(plan) = &app.bytecode_batch_plan {
        let lines = bytecode_batch_confirmation_lines(plan);
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Confirm bytecode batch removal "),
                )
                .yellow(),
            area,
        );
    }
    if let Some(plan) = &app.go_test_plan {
        let lines = go_test_confirmation_lines(plan, app.go_test_read_only);
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(if app.go_test_read_only {
                            " Go test cache preview "
                        } else {
                            " Confirm Go test expiration "
                        }),
                )
                .yellow(),
            area,
        );
    }
    #[cfg(target_os = "linux")]
    if let Some(plan) = &app.trash_retention_plan {
        let (token, title) = match plan {
            TrashRetentionReviewPlan::Install(plan) => (
                plan.preview_token.as_str(),
                if app.schedule_read_only {
                    " Trash retention installation preview "
                } else {
                    " Confirm Trash retention installation "
                },
            ),
            TrashRetentionReviewPlan::Enable(plan) => (
                plan.preview_token.as_str(),
                if app.schedule_read_only {
                    " Trash retention enable preview "
                } else {
                    " Confirm Trash retention enable "
                },
            ),
            TrashRetentionReviewPlan::Disable(plan) => (
                plan.preview_token.as_str(),
                if app.schedule_read_only {
                    " Trash retention disable preview "
                } else {
                    " Confirm Trash retention disable "
                },
            ),
            TrashRetentionReviewPlan::Remove(plan) => (
                plan.preview_token.as_str(),
                if app.schedule_read_only {
                    " Trash retention removal preview "
                } else {
                    " Confirm Trash retention removal "
                },
            ),
        };
        let lines = if app.schedule_read_only {
            schedule_preview_display_lines(trash_retention_review_lines(plan), token, frame.area())
        } else {
            schedule_confirmation_display_lines(&trash_retention_review_lines(plan), frame.area())
        };
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .scroll((
                    if app.schedule_read_only {
                        app.schedule_preview_scroll
                    } else {
                        u16::try_from(app.schedule_confirmation_scroll).unwrap_or(u16::MAX)
                    },
                    0,
                ))
                .block(Block::default().borders(Borders::ALL).title(title))
                .yellow(),
            area,
        );
    }
    if let Some((plan, _)) = &app.schedule_edit_plan {
        let lines = if app.schedule_read_only {
            schedule_preview_display_lines(
                schedule_edit_confirmation_lines_for(plan, platform),
                &plan.preview_token,
                frame.area(),
            )
        } else {
            schedule_confirmation_display_lines(
                &schedule_edit_confirmation_lines_for(plan, platform),
                frame.area(),
            )
        };
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .scroll((
                    if app.schedule_read_only {
                        app.schedule_preview_scroll
                    } else {
                        u16::try_from(app.schedule_confirmation_scroll).unwrap_or(u16::MAX)
                    },
                    0,
                ))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(schedule_dialog_title(
                            platform,
                            "replacement",
                            app.schedule_read_only,
                        )),
                )
                .yellow(),
            area,
        );
    }
    if let Some(plan) = &app.schedule_remove_plan {
        let lines = if app.schedule_read_only {
            schedule_preview_display_lines(
                schedule_remove_confirmation_lines_for(plan, platform),
                &plan.preview_token,
                frame.area(),
            )
        } else {
            schedule_confirmation_display_lines(
                &schedule_remove_confirmation_lines_for(plan, platform),
                frame.area(),
            )
        };
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .scroll((
                    if app.schedule_read_only {
                        app.schedule_preview_scroll
                    } else {
                        u16::try_from(app.schedule_confirmation_scroll).unwrap_or(u16::MAX)
                    },
                    0,
                ))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(schedule_dialog_title(
                            platform,
                            "removal",
                            app.schedule_read_only,
                        )),
                )
                .yellow(),
            area,
        );
    }
    if let Some((plan, _)) = &app.schedule_install_plan {
        let lines = if app.schedule_read_only {
            schedule_preview_display_lines(
                schedule_install_confirmation_lines_for(plan, platform),
                &plan.preview_token,
                frame.area(),
            )
        } else {
            schedule_confirmation_display_lines(
                &schedule_install_confirmation_lines_for(plan, platform),
                frame.area(),
            )
        };
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .scroll((
                    if app.schedule_read_only {
                        app.schedule_preview_scroll
                    } else {
                        u16::try_from(app.schedule_confirmation_scroll).unwrap_or(u16::MAX)
                    },
                    0,
                ))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(schedule_dialog_title(
                            platform,
                            "installation",
                            app.schedule_read_only,
                        )),
                )
                .yellow(),
            area,
        );
    }
    if let Some((plan, _)) = &app.schedule_enable_plan {
        let lines = if app.schedule_read_only {
            schedule_preview_display_lines(
                schedule_enable_confirmation_lines_for(plan, platform),
                &plan.preview_token,
                frame.area(),
            )
        } else {
            schedule_confirmation_display_lines(
                &schedule_enable_confirmation_lines_for(plan, platform),
                frame.area(),
            )
        };
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .scroll((
                    if app.schedule_read_only {
                        app.schedule_preview_scroll
                    } else {
                        u16::try_from(app.schedule_confirmation_scroll).unwrap_or(u16::MAX)
                    },
                    0,
                ))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(schedule_dialog_title(
                            platform,
                            "enable",
                            app.schedule_read_only,
                        )),
                )
                .yellow(),
            area,
        );
    }
    if let Some(plan) = &app.schedule_disable_plan {
        let lines = if app.schedule_read_only {
            schedule_preview_display_lines(
                schedule_disable_confirmation_lines_for(plan, platform),
                &plan.preview_token,
                frame.area(),
            )
        } else {
            schedule_confirmation_display_lines(
                &schedule_disable_confirmation_lines_for(plan, platform),
                frame.area(),
            )
        };
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .scroll((
                    if app.schedule_read_only {
                        app.schedule_preview_scroll
                    } else {
                        u16::try_from(app.schedule_confirmation_scroll).unwrap_or(u16::MAX)
                    },
                    0,
                ))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(schedule_dialog_title(
                            platform,
                            "disable",
                            app.schedule_read_only,
                        )),
                )
                .yellow(),
            area,
        );
    }
    if let Some(plan) = &app.history_purge_plan {
        let lines = app.history_purge_content.clone().unwrap_or_else(|| {
            schedule_confirmation_display_lines(
                &history_purge_confirmation_lines(plan, app.history_purge_read_only),
                frame.area(),
            )
        });
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .scroll((app.history_purge_scroll, 0))
                .block(Block::default().borders(Borders::ALL).title(
                    if app.history_purge_read_only {
                        " History purge preview "
                    } else {
                        " Confirm history purge "
                    },
                ))
                .yellow(),
            area,
        );
    }
    if let Some(plan) = &app.container_plan {
        let lines = container_confirmation_lines(plan);
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Confirm container removal "),
                )
                .yellow(),
            area,
        );
    }
    if let Some(plan) = &app.build_cache_plan {
        let lines = build_cache_confirmation_lines(plan, app.build_cache_read_only);
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(if app.build_cache_read_only {
                            " Build cache preview "
                        } else {
                            " Confirm build cache removal "
                        }),
                )
                .yellow(),
            area,
        );
    }
    if let Some(plan) = &app.network_plan {
        let lines = network_confirmation_lines(plan);
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Confirm network removal "),
                )
                .yellow(),
            area,
        );
    }
    if app.trash_review
        && let Some(Ok(preview)) = &app.trash_preview
    {
        let area = centered(frame.area(), 90, frame.area().height.saturating_sub(2));
        frame.render_widget(Clear, area);
        let mut lines = vec!["Marked items:".to_owned()];
        lines.extend(
            preview
                .items
                .iter()
                .filter(|item| item.selected)
                .map(|item| {
                    format!(
                        "{} / {}  deleted={}",
                        crate::sweep::display_path(&item.location),
                        item.name,
                        item.deletion_date.as_deref().unwrap_or("unknown")
                    )
                }),
        );
        lines.push(
            "Items may have changed since marking. Permanent deletion is irreversible.".into(),
        );
        lines.push("d: preview deletion of selected items   Esc/Enter: close   ↑/↓: scroll".into());
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .wrap(Wrap { trim: false })
                .scroll((app.trash_review_scroll, 0))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Review marked Trash "),
                ),
            area,
        );
    }
    if let Some(plan) = &app.trash_removal_plan {
        let lines = trash_removal_confirmation_lines(plan);
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Confirm permanent Trash deletion "),
                )
                .yellow(),
            area,
        );
    }
    if let Some(plan) = &app.trim_plan {
        let lines = trim_confirmation_lines(plan, app.trim_read_only);
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(if app.trim_read_only {
                            " TRIM preview "
                        } else {
                            " Confirm TRIM "
                        }),
                )
                .yellow(),
            area,
        );
    }
    if app.confirmation
        && let Some(lines) = toolchain_confirmation_lines(app)
    {
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Confirm toolchain update "),
                )
                .yellow(),
            area,
        );
    }
    if let Some(plan) = &app.self_update_plan {
        let lines = self_update_confirmation_lines(plan);
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(2),
            u16::try_from(lines.len() + 2).unwrap_or(u16::MAX),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .block(Block::default().borders(Borders::ALL).title(
                    if self_update_confirmation_fits(plan, frame.area()) {
                        " Confirm Upkit self-update "
                    } else {
                        " Enlarge terminal to review self-update "
                    },
                ))
                .yellow(),
            area,
        );
    }
    if app.plan_detail
        && let Some(Ok(plan)) = &app.plan
        && let Some(index) =
            visible_plan_index(plan, &app.artifact_filter, app.scan_scroll as usize)
        && let Some(item) = plan.items.get(index)
    {
        let area = centered(frame.area(), 76, frame.area().height.saturating_sub(2));
        frame.render_widget(Clear, area);
        let details = format!(
            "Inspection only. Esc: close; ↑/↓: scroll. Use d on the list for removal review.\nProject: {}\nTarget: {}\nEcosystem: {}\nCargo workspace: {}\nRisk: {}\nIdentity metadata: {}\nGit index: {}\nGit HEAD or index: {} (nested repositories not checked)\nGit history: {} (checked only for initial selection)\nProcess activity: {} (absence does not prove inactivity)\nProject marker at scan: {}\nVCS marker at scan: {}\nHard-linked file at scan: {}\nSymbolic link at scan: {}\nLogical bytes: {}{}\nAllocated bytes: {}\nNewest modification (Unix): {}\nProposed operation: {}\n\nRequired before execution:\n{}{}",
            crate::sweep::display_path(&item.candidate.project_root),
            crate::sweep::display_path(&item.candidate.target),
            item.candidate.ecosystem,
            item.candidate
                .cargo_workspace
                .as_ref()
                .map_or("not applicable".into(), |workspace| {
                    format!(
                        "{}{}",
                        workspace.status,
                        workspace
                            .workspace_root
                            .as_deref()
                            .map_or(String::new(), |root| format!(
                                " ({})",
                                crate::sweep::display_path(root)
                            ))
                    )
                }),
            item.risk,
            item.identity_status,
            item.git_index_status,
            item.git_head_status,
            item.git_history_status,
            item.activity_status,
            item.candidate
                .nested_project_marker
                .as_deref()
                .map_or("none observed".into(), crate::sweep::display_path),
            item.candidate
                .nested_vcs_marker
                .as_deref()
                .map_or("none observed".into(), crate::sweep::display_path),
            item.candidate.hard_link_marker.as_deref().map_or(
                "none observed (Unix only)".into(),
                crate::sweep::display_path
            ),
            item.candidate
                .symlink_marker
                .as_deref()
                .map_or("none observed".into(), crate::sweep::display_path),
            item.candidate.logical_bytes,
            if item.candidate.size_complete {
                ""
            } else {
                " (incomplete)"
            },
            item.candidate
                .allocated_bytes
                .map_or("unknown".into(), |v| v.to_string()),
            item.candidate
                .modified_unix
                .map_or("unknown".into(), |v| v.to_string()),
            item.proposed_operation,
            item.safeguards_required
                .iter()
                .map(|value| format!("- {value}"))
                .collect::<Vec<_>>()
                .join("\n"),
            if item.candidate.cargo_workspace.is_some() {
                "\n\nCargo workspace evidence inspects every ancestor manifest; package.workspace overrides and custom Cargo output settings remain ineligible for removal."
            } else {
                ""
            }
        );
        frame.render_widget(
            Paragraph::new(details)
                .wrap(Wrap { trim: false })
                .scroll((app.detail_scroll, 0))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Preview details "),
                ),
            area,
        );
    }
    if let Some(plan) = &app.temp_review_plan {
        let area = centered(
            frame.area(),
            frame.area().width.saturating_sub(4),
            frame.area().height.saturating_sub(6),
        );
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(temp_cleanup_review_content(
                plan,
                app.temp_review_confirm,
                app.dry_run,
            ))
            .wrap(Wrap { trim: false })
            .scroll((app.temp_review_scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(if app.temp_review_confirm {
                        " Confirm temporary staging cleanup "
                    } else {
                        " Review temporary staging inventory "
                    }),
            ),
            area,
        );
    }
    if app.help {
        let area = centered(frame.area(), 72, frame.area().height.saturating_sub(2));
        frame.render_widget(Clear, area);
        let context = match app.page {
            Start::Dashboard => {
                "Dashboard: s scans configured roots; c opens Caches and starts its read-only inventory; ↑/↓ scrolls details; r refreshes history; Tab opens the next page."
            }
            Start::Toolchains if app.managed_mode => {
                "Toolchains: / filters tool names, versions, status, or notes; Space marks allowed cleanup targets. Enter or d previews the selected tool; D reviews marked targets together."
            }
            Start::Toolchains => {
                "Toolchains: / filters tool names, versions, status, or notes; r refreshes the inventory; ↑/↓ selects visible tools; Space marks tools for update or cleanup. Marks persist while filtering. Enter previews update; U previews Upkit self-update; d previews selected cleanup; D reviews marked cleanup together."
            }
            Start::Doctor => "Doctor: / filters diagnostic lines; r refreshes; ↑/↓ or j/k scrolls.",
            Start::Artifacts if app.cli_preview_read_only => {
                "Read-only CLI preview: / filters; s sorts; ↑/↓ selects; Space changes local selection; Enter opens details. Cleanup keys and page navigation are disabled."
            }
            Start::Artifacts if app.preview_mode => {
                "Artifacts preview: / filters; s sorts; ↑/↓ selects; Space marks up to 32 targets; d previews marked targets (or current target if none are marked); b lists Python bytecode; Enter opens details."
            }
            Start::Artifacts => {
                "Artifacts: r scans; / filters; s sorts; ↑/↓ selects; Space marks up to 32 targets; d previews marked targets (or current target if none are marked); b lists Python bytecode. Esc cancels an active scan."
            }
            Start::Maintenance if app.temp_mode => {
                "Temporary links: r inventories stale Upkit staging directories; Space marks eligible candidates; PgUp/PgDn scrolls the full inventory and Home/End jumps to its top or bottom; d previews selected paths. Review every candidate and warning, then continue to a separate confirmation. Esc cancels or returns to Maintenance; cancellation may finish the current item."
            }
            Start::Maintenance => {
                "Maintenance: ↑/↓ selects a mount; Enter previews TRIM; l reviews stale Upkit link staging directories."
            }
            Start::Cache => {
                "Caches: start with a concise summary. w toggles full diagnostic warnings and ownership details; / filters names and escaped paths; s sorts; Enter or r refreshes; d opens a separate removal review (never removes immediately); ↑/↓ scrolls."
            }
            Start::Trash => {
                "Trash: 7, 1, or 3 previews 7, 14, or 30 days; Space marks; A selects eligible items in the highlighted location; Enter reviews; 0 shows status."
            }
            Start::Containers => {
                "Containers: / filters exited containers, unused networks, and private build caches by engine, ID, and reported fields. Dangling images remain read-only because the engines cannot preserve tags added during deletion. ↑/↓ selects eligible results; d opens a target-specific preview. The full engine inventory remains reference-only. Previews bind to an exact target and recheck it before removal. Page Up/Down scrolls; r refreshes."
            }
            Start::Automation => automation_help(platform),
            Start::Reports => {
                "Reports: / filters operation, target, outcome, or detail; s switches newest/oldest order; Enter or r refreshes; 7/3/9 previews a purge of records older than 7/30/90 days. Review every candidate and warning, then press y; Esc cancels preview or requests cancellation while running."
            }
            Start::Settings => {
                "Settings: e opens structured global/profile fields; edit roots, exclusions and retention with Enter, toggle ecosystems, cleanup, schedule frequency and theme with Space, remove paths with d, switch profile with ←/→, add a profile with n, and save with Ctrl+S. Frequency changes apply to future previews and do not change existing timers. t opens the advanced TOML editor. Changes require complete review before save; r reloads."
            }
        };
        let page_navigation = if app.cli_preview_read_only {
            "Page navigation is disabled for this CLI preview."
        } else {
            "Tab/Shift+Tab or Left/Right: change page."
        };
        let text = format!(
            "{context}\n\n{page_navigation}\nq or Esc: quit when no operation is running.\nCtrl+C: quit or close a dialog.\n\nConfirmations show their own controls and require review.\n\n↑/↓: scroll help   Esc, Enter, or ?: close"
        );
        frame.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: false })
                .scroll((app.help_scroll, 0))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Keyboard help "),
                ),
            area,
        );
    }
    apply_theme(frame, app.theme);
}

fn apply_theme(frame: &mut Frame<'_>, theme: crate::config::Theme) {
    let (foreground, background, accent, warning) = match theme {
        crate::config::Theme::Dark => (
            Color::Rgb(225, 229, 235),
            Color::Rgb(20, 24, 30),
            Color::Rgb(100, 210, 220),
            Color::Rgb(255, 210, 100),
        ),
        crate::config::Theme::Light => (
            Color::Rgb(28, 33, 40),
            Color::Rgb(248, 249, 251),
            Color::Rgb(0, 90, 110),
            Color::Rgb(110, 65, 0),
        ),
    };
    for cell in &mut frame.buffer_mut().content {
        cell.bg = if cell.bg == Color::Reset {
            background
        } else {
            cell.bg
        };
        cell.fg = match cell.fg {
            Color::Reset => foreground,
            Color::Cyan => accent,
            Color::Yellow => warning,
            color => color,
        };
    }
}

fn self_update_confirmation_lines(plan: &crate::application::SelfUpdatePlan) -> Vec<String> {
    let mut lines = vec![
        format!("Method: {}", plan.via),
        format!(
            "Program: {}",
            crate::sweep::display_path(&plan.program_path)
        ),
    ];
    lines.extend(
        plan.args
            .iter()
            .map(|arg| format!("Argument: {}", schedule_escape_controls(arg))),
    );
    if plan.via == "github" {
        let source = plan.release_source.as_ref().map_or_else(
            || format!("{}/releases/latest/download", env!("CARGO_PKG_REPOSITORY")),
            |source| self_update_source_display(source),
        );
        lines.push(format!("Release source: {source}"));
        lines.push(format!(
            "Install directory: {}",
            crate::sweep::display_path(&plan.destination)
        ));
    } else {
        lines.push(format!(
            "Install location is chosen by {}; it may differ from the current executable.",
            plan.via
        ));
    }
    lines.push("The update downloads and runs the selected installer.".into());
    lines.push("The executable can change at the same path after preview.".into());
    lines.push("Enter/y: confirm    Esc/n: cancel".into());
    lines
}

fn self_update_source_display(source: &std::ffi::OsStr) -> String {
    if let Some(mut url) = source
        .to_str()
        .and_then(|value| reqwest::Url::parse(value).ok())
        .filter(|url| url.host_str().is_some())
    {
        let hidden = !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some();
        let _ = url.set_password(None);
        let _ = url.set_username("");
        url.set_query(None);
        url.set_fragment(None);
        return format!(
            "{url}{}",
            if hidden {
                " (credentials/query hidden)"
            } else {
                ""
            }
        );
    }
    crate::sweep::display_path(std::path::Path::new(source))
}

fn self_update_confirmation_fits(plan: &crate::application::SelfUpdatePlan, area: Rect) -> bool {
    let lines = self_update_confirmation_lines(plan);
    area.height as usize >= lines.len() + 2
        && lines.iter().all(|line| {
            ratatui::text::Line::from(line.as_str()).width()
                <= area.width.saturating_sub(4) as usize
        })
}

fn toolchain_confirmation_lines(app: &App) -> Option<Vec<String>> {
    let reports = app.reports.as_ref()?;
    let targets = if app.marked.is_empty() {
        vec![app.selected_toolchain()?]
    } else {
        app.marked.clone()
    };
    let mut lines = vec![format!(
        "Update or install{}:",
        if app.force { " (forced)" } else { "" }
    )];
    let hidden_marked = targets
        .iter()
        .filter(|tool| {
            reports
                .iter()
                .find(|report| report.tool == **tool)
                .is_some_and(|report| !toolchain_matches(report, &app.toolchain_filter))
        })
        .count();
    if hidden_marked > 0 {
        lines.push(format!(
            "{hidden_marked} marked target(s) are hidden by the filter; all targets are listed below."
        ));
    }
    for tool in targets {
        let report = reports.iter().find(|report| report.tool == tool)?;
        lines.push(format!(
            "{}: {} → {}",
            tool.as_str(),
            report
                .installed
                .as_ref()
                .map_or("-".into(), |v| v.to_string()),
            report
                .latest
                .as_ref()
                .map_or("unknown".into(), |v| v.to_string())
        ));
        lines.extend(
            report
                .notes
                .iter()
                .filter(|note| {
                    matches!(
                        note.as_str(),
                        "Windows installation requires permission to create symbolic links."
                            | "Windows: put flutter/active/bin first on PATH."
                            | "Windows Flutter requires Git and PowerShell on PATH."
                            | "Windows: put node/active first on PATH."
                            | "Existing GOROOT settings can override the managed Go installation."
                    )
                })
                .cloned(),
        );
    }
    lines.push("Enter/y: confirm    Esc/n: cancel".into());
    Some(lines)
}

fn toolchain_confirmation_fits(app: &App, area: Rect) -> bool {
    toolchain_confirmation_lines(app).is_some_and(|lines| {
        area.height as usize >= lines.len() + 2
            && lines.iter().all(|line| {
                ratatui::text::Line::from(line.as_str()).width()
                    <= area.width.saturating_sub(4) as usize
            })
    })
}

fn managed_confirmation_lines(plan: &crate::managed_cleanup::CleanupPlan) -> Vec<String> {
    let mut lines = vec![
        format!("Tool: {}", plan.tool),
        format!(
            "Root: {} ({})",
            crate::sweep::display_path(&plan.root),
            if plan.root_present {
                "present"
            } else {
                "absent"
            }
        ),
        format!(
            "Remove {} verified installs and {} recorded links.",
            plan.selected_entries.len(),
            plan.links.len()
        ),
        format!(
            "Preserve {} root entries and {} unrecorded links (i: inspect).",
            plan.preserved_entries.len(),
            plan.preserved_links.len()
        ),
        format!(
            "Logical bytes: {} (reclaimed space unknown).",
            plan.logical_bytes
        ),
        format!("Installation identity: {}", plan.installation_status),
        format!("Process activity: {}", plan.activity_status),
        format!(
            "Group/other-writable managed paths: {}",
            if plan.writable_by_others { "yes" } else { "no" }
        ),
    ];
    lines.push(match plan.activity_status {
        "open_handles_or_cwd_observed" | "executable_observed" => {
            "A process is using this root; stop it and preview again.".into()
        }
        "inspection_incomplete" | "unavailable" => {
            "Some processes could not be inspected; active use may be missed.".into()
        }
        "not_applicable" => "No tool root is present for a process check.".into(),
        _ => "No activity was observed; this does not prove the tool is idle.".into(),
    });
    if plan.selected_entries.is_empty() && plan.links.is_empty() {
        lines.push("No sealed Upkit installation or recorded link is eligible.".into());
    } else {
        lines.extend(
            plan.links
                .iter()
                .map(|path| format!("Remove link: {}", crate::sweep::display_path(path))),
        );
    }
    lines.extend([
        "Only listed content with a verified Upkit seal and link receipt is removed.".into(),
        "Other root data stays; links outside Upkit's recorded names cannot be enumerated.".into(),
        "Process and mount checks can race; shell PATH entries remain unchanged.".into(),
        "Failure or interruption may leave files in a private quarantine.".into(),
        "Press y to remove; Esc/n cancels. i shows top-level contents.".into(),
    ]);
    lines
}

fn managed_confirmation_fits(plan: &crate::managed_cleanup::CleanupPlan, area: Rect) -> bool {
    let lines = managed_confirmation_lines(plan);
    area.height as usize >= lines.len() + 2
        && lines.iter().all(|line| {
            ratatui::text::Line::from(line.as_str()).width()
                <= area.width.saturating_sub(4) as usize
        })
}

fn managed_batch_review_content(
    targets: &[ManagedCleanupTarget],
    area: Rect,
) -> Option<Vec<String>> {
    let width = area.width.checked_sub(8)? as usize;
    if width == 0 {
        return None;
    }
    let mut source = Vec::new();
    for (index, target) in targets.iter().enumerate() {
        source.push(format!(
            "Selected tool {}/{}: {}",
            index + 1,
            targets.len(),
            target.tool.as_str()
        ));
        let mut details = managed_confirmation_lines(&target.plan);
        details.pop();
        if let Some(line) = details.get_mut(2) {
            *line = line.replace(" (i: inspect)", "");
        }
        source.extend(details);
        source.push("Top-level entries:".into());
        if target.plan.entries.is_empty() {
            source.push("No top-level entries.".into());
        } else {
            source.extend(target.plan.entries.iter().map(|path| {
                let kind = if target.plan.selected_entries.contains(path) {
                    "REMOVE sealed installation"
                } else {
                    "PRESERVE unverified/root data"
                };
                format!("{kind}: {}", crate::sweep::display_path(path))
            }));
        }
        source.push(format!("Warning: {}", target.plan.warning));
        source.push(String::new());
    }
    source.extend([
        "All targets are rechecked before the first removal.".into(),
        "Failure or cancellation stops later targets; completed removals are not rolled back."
            .into(),
    ]);
    artifact_wrap_lines(&source, width)
}

fn managed_batch_review_rows(area: Rect) -> usize {
    let width = area.width.saturating_sub(8) as usize;
    if area.height < 9
        || ratatui::text::Line::from("↑/↓: scroll  y: confirm after the end  Esc/n: cancel").width()
            > width
    {
        0
    } else {
        area.height.saturating_sub(6) as usize
    }
}

fn managed_batch_review_complete(app: &App, area: Rect) -> bool {
    app.managed_batch_review_area == area
        && app.managed_batch_review_rows > 0
        && managed_batch_review_scroll_supported(
            app.managed_batch_review_lines,
            app.managed_batch_review_rows,
            app.managed_batch_review_scroll,
        )
        && app.managed_batch_review_scroll + app.managed_batch_review_rows
            >= app.managed_batch_review_lines
}

fn managed_batch_review_scroll_supported(lines: usize, rows: usize, scroll: usize) -> bool {
    lines.saturating_sub(rows) <= u16::MAX as usize && scroll <= u16::MAX as usize
}

fn managed_batch_active_tool(targets: &[ManagedCleanupTarget]) -> Option<ToolKind> {
    targets
        .iter()
        .find(|target| {
            matches!(
                target.plan.activity_status,
                "open_handles_or_cwd_observed" | "executable_observed"
            )
        })
        .map(|target| target.tool)
}

fn managed_batch_preview_failure_lines(failure: &ManagedBatchPreviewFailure) -> Vec<String> {
    let mut lines = if failure.cancelled {
        vec!["Combined managed cleanup preview cancelled; no removals were attempted.".into()]
    } else {
        vec!["Combined managed cleanup preview failed; no removals were attempted.".into()]
    };
    if let Some(tool) = failure.tool {
        lines.push(format!(
            "{}: preview failed — {}",
            tool.as_str(),
            failure.error
        ));
    }
    for tool in &failure.tools {
        if Some(*tool) != failure.tool {
            lines.push(format!(
                "{}: skipped; the combined preview did not complete.",
                tool.as_str()
            ));
        }
    }
    lines
}

fn managed_batch_result_lines(result: &ManagedBatchResult) -> Vec<String> {
    let removed = result
        .items
        .iter()
        .filter(|item| item.status == "verified selected absent")
        .count();
    let preserved = result
        .items
        .iter()
        .filter(|item| item.status == "preserved")
        .count();
    let failed = result
        .items
        .iter()
        .filter(|item| item.status == "failed/uncertain")
        .count();
    let skipped = result
        .items
        .iter()
        .filter(|item| item.status == "skipped")
        .count();
    let mut lines = vec![format!(
        "Managed cleanup batch result: {removed} selected paths removed; {preserved} tools preserved; {failed} failed/uncertain; {skipped} skipped."
    )];
    if result.cancelled {
        lines.push("Cancellation stopped the remaining targets.".into());
    }
    for item in &result.items {
        lines.push(format!("{}: {}.", item.tool.as_str(), item.status));
        if let Some(detail) = &item.detail {
            lines.push(format!("  {detail}"));
        }
        if let Some(warning) = &item.history_warning {
            lines.push(format!("  History warning: {warning}"));
        }
    }
    lines.push("Completed removals are not rolled back if a later target fails.".into());
    lines
}

fn settings_confirmation_lines(
    snapshot: &crate::config::ConfigDocument,
    prompt: SettingsPrompt,
    cleanup_impacts: &[String],
    changes: &[String],
) -> Vec<String> {
    match prompt {
        SettingsPrompt::Save => {
            let mut lines = vec![
                format!("Save: {}", crate::sweep::display_path(&snapshot.path)),
                if snapshot.exists() {
                    "The previous file will be saved as a private backup.".into()
                } else {
                    "A new configuration file will be created.".into()
                },
                "The policy applies to future operations; saving runs no cleanup.".into(),
                "Changed scope fields (before → after):".into(),
            ];
            lines.extend(changes.iter().cloned());
            lines.extend(
                cleanup_impacts
                    .iter()
                    .map(|line| schedule_escape_controls(line)),
            );
            lines.push(
                "↑/↓ reviews every changed field and impact. Press y after the end to save; Esc/n cancels.".into(),
            );
            lines
        }
        SettingsPrompt::Discard => vec![
            "Discard unsaved configuration edits?".into(),
            "Press y to discard; Esc/n returns to editing.".into(),
        ],
    }
}

fn settings_confirmation_area(area: Rect) -> Rect {
    centered(
        area,
        area.width.saturating_sub(4),
        area.height.saturating_sub(4),
    )
}

fn settings_confirmation_scroll_limit(
    snapshot: &crate::config::ConfigDocument,
    prompt: SettingsPrompt,
    cleanup_impacts: &[String],
    changes: &[String],
    terminal_area: Rect,
) -> u16 {
    let dialog = settings_confirmation_area(terminal_area);
    let content =
        settings_confirmation_lines(snapshot, prompt, cleanup_impacts, changes).join("\n");
    let inner = dialog.inner(ratatui::layout::Margin::new(1, 1));
    let rows = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .line_count(inner.width);
    u16::try_from(rows.saturating_sub(inner.height as usize)).unwrap_or(u16::MAX)
}

fn settings_confirmation_fits(area: Rect) -> bool {
    area.width >= 16 && area.height >= 8
}

fn settings_confirmation_ready(
    snapshot: &crate::config::ConfigDocument,
    prompt: SettingsPrompt,
    cleanup_impacts: &[String],
    changes: &[String],
    scroll: u16,
    terminal_area: Rect,
) -> bool {
    if !settings_confirmation_fits(terminal_area) {
        return false;
    }
    let dialog = settings_confirmation_area(terminal_area);
    let inner = dialog.inner(ratatui::layout::Margin::new(1, 1));
    let content =
        settings_confirmation_lines(snapshot, prompt, cleanup_impacts, changes).join("\n");
    let rows = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .line_count(inner.width);
    (scroll as usize).saturating_add(inner.height as usize) >= rows
}

fn artifact_entry_line(entry: &crate::artifact_cleanup::ArtifactEntry) -> String {
    format!(
        "{}  {}  {}",
        entry.kind,
        entry.logical_bytes.map_or("-".into(), |n| n.to_string()),
        entry.path
    )
}

fn artifact_review_rows(plan: &DirectoryPlan, area: Rect) -> usize {
    let width = area.width.saturating_sub(4) as usize;
    let header = match plan {
        DirectoryPlan::ArtifactBatch(batch) => format!(
            "Review all {} entries across {} selected targets.",
            plan.entry_count(),
            batch.items.len()
        ),
        _ => format!(
            "Review all {} entries; paths are relative to the selected directory.",
            plan.entry_count()
        ),
    };
    if area.height < 7
        || ratatui::text::Line::from(header).width() > width
        || ratatui::text::Line::from(
            "↑/↓: scroll  +: continued  Enter: continue at end  Esc: cancel",
        )
        .width()
            > width
    {
        0
    } else {
        area.height.saturating_sub(6) as usize
    }
}

fn artifact_review_lines(plan: &DirectoryPlan, area: Rect) -> Option<Vec<String>> {
    let width = area.width.checked_sub(6)? as usize;
    if width == 0 {
        return None;
    }
    if let DirectoryPlan::ArtifactBatch(batch) = plan {
        let mut source = Vec::new();
        for (index, item) in batch.items.iter().enumerate() {
            source.extend([
                format!("Artifact {}/{}:", index + 1, batch.items.len()),
                format!("Project: {}", crate::sweep::display_path(&item.project)),
                format!("Manifest: {}", crate::sweep::display_path(&item.manifest)),
                format!("Target: {}", crate::sweep::display_path(&item.target)),
                format!(
                    "Ecosystem: {}  Classification: {}",
                    item.ecosystem, item.classification
                ),
                format!("Logical size: {} bytes", item.logical_bytes),
                "Directory contents:".into(),
            ]);
            if let Some(warning) = item.reproduction_warning {
                source.push(format!("Reproduction warning: {warning}"));
            }
            source.extend(item.entries.iter().map(artifact_entry_line));
            source.push(String::new());
        }
        source.push(format!("Batch warning: {}", batch.warning));
        return artifact_wrap_lines(&source, width);
    }
    let mut lines = Vec::new();
    for entry in plan.entries() {
        let line = artifact_entry_line(entry);
        if !line.is_ascii() {
            return None;
        }
        for (index, chunk) in line.as_bytes().chunks(width).enumerate() {
            lines.push(format!(
                "{}{}",
                if index == 0 { "  " } else { "+ " },
                std::str::from_utf8(chunk).ok()?
            ));
        }
    }
    Some(lines)
}

fn artifact_wrap_lines(source: &[String], width: usize) -> Option<Vec<String>> {
    if width == 0 {
        return None;
    }
    let mut lines = Vec::new();
    for line in source {
        if !line.is_ascii() {
            return None;
        }
        if line.is_empty() {
            lines.push(String::new());
            continue;
        }
        for (index, chunk) in line.as_bytes().chunks(width).enumerate() {
            lines.push(format!(
                "{}{}",
                if index == 0 { "  " } else { "+ " },
                std::str::from_utf8(chunk).ok()?
            ));
        }
    }
    Some(lines)
}

fn artifact_batch_confirmation_content(plan: &DirectoryPlan, area: Rect) -> Option<Vec<String>> {
    let DirectoryPlan::ArtifactBatch(_) = plan else {
        return None;
    };
    let width = area.width.checked_sub(6)? as usize;
    artifact_wrap_lines(&directory_confirmation_lines(plan), width)
}

fn artifact_batch_confirmation_rows(area: Rect) -> usize {
    let width = area.width.saturating_sub(4) as usize;
    if area.height < 7
        || ratatui::text::Line::from("Exact selected targets and consequences:").width() > width
        || ratatui::text::Line::from("↑/↓: scroll  y: confirm at end  Esc: cancel").width() > width
    {
        0
    } else {
        area.height.saturating_sub(6) as usize
    }
}

fn artifact_confirmation_lines(plan: &crate::artifact_cleanup::ArtifactPlan) -> Vec<String> {
    let mut lines = vec![
        format!("Project: {}", crate::sweep::display_path(&plan.project)),
        format!("Manifest: {}", crate::sweep::display_path(&plan.manifest)),
        format!("Target: {}", crate::sweep::display_path(&plan.target)),
        format!(
            "Ecosystem: {}  Classification: {}",
            plan.ecosystem, plan.classification
        ),
        format!(
            "Logical size: {} bytes; reclaimed space is unknown.",
            plan.logical_bytes
        ),
    ];
    if let Some(warning) = plan.reproduction_warning {
        lines.push(warning.into());
    }
    lines.extend([
        "Permanently deletes every listed entry and directory, including user data.".into(),
        "Git and process checks are snapshots; concurrent changes can race.".into(),
        "Failure may leave a partially removed directory in quarantine.".into(),
        "Press y to delete; Esc/n cancels.".into(),
    ]);
    lines
}

fn artifact_confirmation_fits(plan: &crate::artifact_cleanup::ArtifactPlan, area: Rect) -> bool {
    let lines = artifact_confirmation_lines(plan);
    area.height as usize >= lines.len() + 4
        && lines.iter().all(|line| {
            ratatui::text::Line::from(line.as_str()).width()
                <= area.width.saturating_sub(4) as usize
        })
}

fn directory_confirmation_lines(plan: &DirectoryPlan) -> Vec<String> {
    match plan {
        DirectoryPlan::Artifact(plan) => artifact_confirmation_lines(plan),
        DirectoryPlan::ArtifactBatch(plan) => {
            let mut lines = vec![
                format!(
                    "Permanently deletes all {} selected artifact directories, including user data.",
                    plan.items.len()
                ),
                "Exact reviewed targets:".into(),
            ];
            lines.extend(
                plan.items
                    .iter()
                    .map(|item| crate::sweep::display_path(&item.target)),
            );
            lines.extend([
                "Git, process, and filesystem checks are snapshots; concurrent changes can race."
                    .into(),
                "Failure may leave some directories removed and others unchanged or in quarantine."
                    .into(),
                format!("Consequence: {}", plan.warning),
                "Press y only after reviewing every target; Esc/n cancels.".into(),
            ]);
            lines
        }
        DirectoryPlan::Cache(plan) => vec![
            format!(
                "Shared cache: {}  Classification: {}",
                plan.name, plan.classification
            ),
            format!(
                "Target: {}",
                crate::shared_cache_cleanup::display_path(&plan.target)
            ),
            format!(
                "Logical size: {} bytes; reclaimed space is unknown.",
                plan.logical_bytes
            ),
            format!("Consequence: {}.", plan.consequence),
            "Permanently deletes every listed entry, including user data or source files.".into(),
            "Cache location is inferred; check the selected path carefully.".into(),
            "Other caches inside this directory will also be deleted.".into(),
            "Workspace scan profiles and exclusions do not apply.".into(),
            "External cache programs are not run; their contents may remain.".into(),
            "Process and filesystem checks are snapshots; concurrent changes can race.".into(),
            "Failure may leave a partially removed cache in quarantine.".into(),
            "Press y to delete; Esc/n cancels.".into(),
        ],
    }
}

fn directory_confirmation_fits(plan: &DirectoryPlan, area: Rect) -> bool {
    match plan {
        DirectoryPlan::Artifact(plan) => return artifact_confirmation_fits(plan, area),
        DirectoryPlan::ArtifactBatch(_) => return artifact_batch_confirmation_rows(area) > 0,
        DirectoryPlan::Cache(_) => {}
    }
    let lines = directory_confirmation_lines(plan);
    area.height as usize >= lines.len() + 4
        && lines.iter().all(|line| {
            ratatui::text::Line::from(line.as_str()).width()
                <= area.width.saturating_sub(4) as usize
        })
}

fn bytecode_confirmation_lines(plan: &crate::bytecode::BytecodePlan) -> Vec<String> {
    let mut lines = vec![
        format!("Project: {}", crate::sweep::display_path(&plan.project)),
        format!("Manifest: {}", crate::sweep::display_path(&plan.manifest)),
        format!("Source: {}", crate::sweep::display_path(&plan.source)),
        format!("Delete: {}", crate::sweep::display_path(&plan.file)),
        format!(
            "CPython {}; {}; logical size {} bytes (reclaimed space unknown).",
            plan.python, plan.invalidation, plan.logical_bytes
        ),
        "Permanent deletion; Python may rebuild this file.".into(),
        "Header validation does not prove bytecode matches source.".into(),
        "Git and process checks are snapshots; concurrent changes can race.".into(),
        "Interruption can leave a file in a private quarantine directory.".into(),
    ];
    if plan.invalidation == "hash-unchecked" {
        lines.push("Unchecked hash bytecode may run code different from the source.".into());
    }
    lines.push("Press y to remove this file; Esc/n cancels.".into());
    lines
}

fn bytecode_confirmation_fits(plan: &crate::bytecode::BytecodePlan, area: Rect) -> bool {
    let lines = bytecode_confirmation_lines(plan);
    area.height as usize >= lines.len() + 2
        && lines.iter().all(|line| {
            ratatui::text::Line::from(line.as_str()).width()
                <= area.width.saturating_sub(4) as usize
        })
}

fn bytecode_batch_confirmation_lines(plan: &crate::bytecode::BytecodeBatchPlan) -> Vec<String> {
    let mut lines = vec![format!(
        "Permanently remove {} selected bytecode files:",
        plan.files.len()
    )];
    for file in &plan.files {
        lines.push(format!(
            "Delete: {}",
            crate::sweep::display_path(&file.file)
        ));
        lines.push(format!(
            "Source: {}",
            crate::sweep::display_path(&file.source)
        ));
        lines.push(format!(
            "Manifest: {}  CPython {}  {}  {} bytes",
            crate::sweep::display_path(&file.manifest),
            file.python,
            file.invalidation,
            file.logical_bytes
        ));
    }
    lines.extend([
        "Python may rebuild these files; reclaimed space is unknown.".into(),
        "Header validation does not prove bytecode matches source.".into(),
        "Git and process checks are snapshots; changes may race.".into(),
        "Failure stops the batch; interruption can leave quarantine files.".into(),
    ]);
    if plan
        .files
        .iter()
        .any(|file| file.invalidation == "hash-unchecked")
    {
        lines.push("Unchecked hash bytecode may run code different from the source.".into());
    }
    lines.push("Press y to remove these files; Esc/n cancels.".into());
    lines
}

fn bytecode_batch_confirmation_fits(plan: &crate::bytecode::BytecodeBatchPlan, area: Rect) -> bool {
    let lines = bytecode_batch_confirmation_lines(plan);
    area.height as usize >= lines.len() + 2
        && lines.iter().all(|line| {
            ratatui::text::Line::from(line.as_str()).width()
                <= area.width.saturating_sub(4) as usize
        })
}

fn go_test_confirmation_lines(
    plan: &crate::cache::GoTestExpirationPlan,
    read_only: bool,
) -> Vec<String> {
    vec![
        format!("Cache: {}", crate::sweep::display_path(&plan.cache_path)),
        format!("Marker: {}", crate::sweep::display_path(&plan.marker_path)),
        format!(
            "Previous expiration (Unix ns): {}",
            plan.current_expiration_unix_nanos
                .map_or("none".into(), |n| n.to_string())
        ),
        "This shared cache may be used by other projects or users.".into(),
        "Go may use a different cache path; tests will need to run again.".into(),
        "This expires test results; it does not free disk space.".into(),
        if read_only {
            "Preview only; Esc/n closes.".into()
        } else {
            "Press y to expire these results; Esc/n cancels.".into()
        },
    ]
}

fn go_test_confirmation_fits(
    plan: &crate::cache::GoTestExpirationPlan,
    read_only: bool,
    area: Rect,
) -> bool {
    let lines = go_test_confirmation_lines(plan, read_only);
    area.height as usize >= lines.len() + 2
        && lines.iter().all(|line| {
            ratatui::text::Line::from(line.as_str()).width()
                <= area.width.saturating_sub(4) as usize
        })
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SchedulePlatform {
    Systemd,
    LaunchAgent,
    TaskScheduler,
    Unsupported,
}

impl SchedulePlatform {
    fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::Systemd
        }
        #[cfg(target_os = "macos")]
        {
            Self::LaunchAgent
        }
        #[cfg(target_os = "windows")]
        {
            Self::TaskScheduler
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Self::Unsupported
        }
    }

    fn manager(self) -> &'static str {
        match self {
            Self::Systemd => "systemd user timer",
            Self::LaunchAgent => "LaunchAgent",
            Self::TaskScheduler => "Task Scheduler",
            Self::Unsupported => "user schedule",
        }
    }

    fn subject(self) -> &'static str {
        match self {
            Self::Systemd => "timer",
            Self::LaunchAgent => "LaunchAgent",
            Self::TaskScheduler => "Task Scheduler task",
            Self::Unsupported => "schedule",
        }
    }

    fn removal_subject(self) -> &'static str {
        match self {
            Self::Systemd => "timer units",
            Self::LaunchAgent => "LaunchAgent",
            Self::TaskScheduler => "Task Scheduler task",
            Self::Unsupported => "schedule",
        }
    }
}

fn automation_content(app: &App, platform: SchedulePlatform) -> String {
    let content =
        automation_schedule_content(app.schedule.as_ref(), app.schedule_running, platform);
    #[cfg(target_os = "linux")]
    let content = {
        let mut content = content;
        content.push_str("\n\n");
        content.push_str(&trash_retention_status_content(
            app.trash_retention_status.as_ref(),
            app.trash_retention_status_loading,
        ));
        content
    };
    content
}

fn automation_schedule_content(
    status: Option<&crate::maintenance::TimerStatus>,
    loading: bool,
    platform: SchedulePlatform,
) -> String {
    let manager = platform.manager();
    let Some(status) = status else {
        return if loading {
            format!("Checking {manager} status…")
        } else {
            format!("Press r to inspect {manager} status.")
        };
    };

    let (target, state_detail, last_label, next_label) = match platform {
        SchedulePlatform::Systemd => (
            "Timer: upkit-scan.timer".to_owned(),
            format!(
                "Unit file state: {}",
                status.unit_file_state.as_deref().unwrap_or("unknown")
            ),
            "Last trigger",
            "Next trigger",
        ),
        SchedulePlatform::LaunchAgent => (
            "LaunchAgent label: upkit-scan.timer".to_owned(),
            format!(
                "Launch state: {}",
                status.load_state.as_deref().unwrap_or("unknown")
            ),
            "Last run",
            "Next run",
        ),
        SchedulePlatform::TaskScheduler => (
            "Task Scheduler path: \\Upkit-Workspace-Scan".to_owned(),
            format!(
                "Enabled: {}",
                status.unit_file_state.as_deref().unwrap_or("unknown")
            ),
            "Last run",
            "Next run",
        ),
        SchedulePlatform::Unsupported => (
            "Schedule target: unsupported".to_owned(),
            "Enabled: unsupported".to_owned(),
            "Last run",
            "Next run",
        ),
    };
    let state = if platform == SchedulePlatform::TaskScheduler {
        status.state.replace('_', " ")
    } else {
        status.state.clone()
    };
    let verification = match platform {
        SchedulePlatform::TaskScheduler
            if status.load_state.as_deref() == Some("registered")
                && matches!(
                    status.state.as_str(),
                    "ready" | "queued" | "running" | "disabled"
                ) =>
        {
            "Task identity: verified."
        }
        SchedulePlatform::TaskScheduler if status.state == "not_found" => {
            "Task identity: no task is registered at this path."
        }
        SchedulePlatform::TaskScheduler if status.state == "unavailable" => {
            "Task identity: unavailable; task state was not verified."
        }
        SchedulePlatform::TaskScheduler => "Task identity: not verified.",
        SchedulePlatform::Unsupported => "Automation is unsupported on this platform.",
        _ => "Name only: ownership and action are not verified.",
    };
    let mut lines = vec![
        target,
        format!("State: {state}"),
        state_detail,
        format!(
            "{last_label}: {}",
            status.last_trigger.as_deref().unwrap_or("unknown")
        ),
        format!(
            "{next_label}: {}",
            status.next_trigger.as_deref().unwrap_or("unknown")
        ),
    ];
    if let Some(detail) = &status.detail {
        lines.push(format!("Status detail: {detail}"));
    }
    lines.push(verification.into());
    lines.push(String::new());
    if platform == SchedulePlatform::Unsupported {
        lines.push("Press r to refresh status.".into());
    } else {
        lines.push("Press p/P to preview the configured daily/weekly schedule read-only; a/w to install, 1/7 to enable, d to disable, e/E to edit daily/weekly, or x to remove. Schedule plans use the configured profile.".into());
    }
    #[cfg(target_os = "linux")]
    if platform == SchedulePlatform::Systemd {
        lines.push("Trash timer: enable the opt-in in Settings first; T previews installation for the home Trash at 30 days; G re-enables; D disables; X removes. Use `schedule trash-retention` for another location or age.".into());
    }
    lines.join("\n")
}

#[cfg(target_os = "linux")]
fn trash_retention_change_message(
    action: &str,
    result: std::result::Result<&'static str, String>,
) -> String {
    match (action, result) {
        ("install", Ok("active_and_enabled")) => {
            "Trash retention timer installed and enabled; verify its status before relying on cleanup.".into()
        }
        ("enable", Ok("active_and_enabled")) => {
            "Trash retention timer enabled; it may start promptly.".into()
        }
        ("disable", Ok("inactive_and_disabled")) => {
            "Trash retention timer disabled; a service already running may continue.".into()
        }
        ("remove", Ok("units_absent")) => "Trash retention timer units removed; absence verified.".into(),
        (_, Ok(status)) => format!(
            "Trash retention {action} returned {status}; inspect the current-user manager before retrying."
        ),
        (_, Err(_)) => format!(
            "Trash retention {action} failed; inspect the Automation status and local operation history."
        ),
    }
}

#[cfg(target_os = "linux")]
fn trash_retention_status_content(
    status: Option<&Result<crate::schedule::trash_retention::TrashRetentionStatus, String>>,
    loading: bool,
) -> String {
    match status {
        None if loading => "Trash retention timer: checking current-user systemd manager…".into(),
        None => "Trash retention timer: press r to inspect status.".into(),
        Some(Err(error)) => format!(
            "Trash retention timer: unavailable ({error}); no scheduled Trash removal should proceed."
        ),
        Some(Ok(status)) => format!(
            "Trash retention timer: {}  enabled={}  next={}{}",
            status.state.replace('_', " "),
            status.unit_file_state.as_deref().unwrap_or("unknown"),
            status.next_trigger.as_deref().unwrap_or("unknown"),
            status
                .detail
                .as_ref()
                .map_or(String::new(), |detail| format!("  ({detail})"))
        ),
    }
}

fn automation_help(platform: SchedulePlatform) -> &'static str {
    match platform {
        SchedulePlatform::Systemd => {
            "Automation: p/P previews configured scan units; a/w installs; 1/7 re-enables; d disables; e/E replaces; x removes. Enable the scheduled Trash retention opt-in in Settings first. T previews the home Trash daily timer at 30 days; G re-enables it; D disables it; X removes it. Review every Trash policy field, current eligible item, unit line, and warning before confirming."
        }
        SchedulePlatform::LaunchAgent => {
            "Automation: p/P previews the configured daily/weekly LaunchAgent read-only; a/w previews installation; 1/7 re-enable; d disable; e/E daily/weekly replacement; x removal; r refreshes status. Review the plist and warnings before confirming."
        }
        SchedulePlatform::TaskScheduler => {
            "Automation: p/P previews the configured daily/weekly Task Scheduler definition read-only; a/w previews installation; 1/7 re-enable; d disable; e/E daily/weekly replacement; x removal; r refreshes status. Review the XML definition and warnings before confirming."
        }
        SchedulePlatform::Unsupported => {
            "Automation: user schedules are unsupported on this platform; r refreshes status."
        }
    }
}

fn scheduled_scan_output_note(platform: SchedulePlatform) -> &'static str {
    match platform {
        SchedulePlatform::Systemd => "Scan JSON is written to the systemd user journal.",
        SchedulePlatform::LaunchAgent => {
            "Scan JSON is emitted on standard output; the LaunchAgent plist does not configure a log destination."
        }
        SchedulePlatform::TaskScheduler => {
            "Scan JSON is emitted on standard output; the task definition does not configure a log destination."
        }
        SchedulePlatform::Unsupported => {
            "The scan output destination is unavailable on this platform."
        }
    }
}

fn scheduled_scan_history_note() -> &'static str {
    "Upkit attempts to record scheduled scan results in local operation history; a history write can fail."
}

fn scheduled_scan_timing_note(platform: SchedulePlatform) -> &'static str {
    match platform {
        SchedulePlatform::Systemd => "The timer may start a scan promptly.",
        SchedulePlatform::LaunchAgent => {
            "The LaunchAgent runs at its next configured 03:00 local calendar interval; RunAtLoad is false."
        }
        SchedulePlatform::TaskScheduler => {
            "The task runs at its next configured 03:00 local calendar trigger; StartWhenAvailable is false."
        }
        SchedulePlatform::Unsupported => "User schedules are unsupported on this platform.",
    }
}

fn schedule_edit_transition_note(
    platform: SchedulePlatform,
    bytecode_cleanup: bool,
) -> &'static str {
    match (platform, bytecode_cleanup) {
        (SchedulePlatform::Systemd, true) => {
            "Old units are deleted; the replacement timer may start automatic cleanup promptly."
        }
        (SchedulePlatform::Systemd, false) => {
            "Old units are deleted; the replacement timer may start a scan promptly."
        }
        (SchedulePlatform::LaunchAgent, _) => {
            "The old LaunchAgent plist is removed; the replacement scan runs at its next configured 03:00 local calendar interval; RunAtLoad is false."
        }
        (SchedulePlatform::TaskScheduler, _) => {
            "The old Task Scheduler task is removed; the replacement scan runs at its next configured 03:00 local calendar trigger; StartWhenAvailable is false."
        }
        (SchedulePlatform::Unsupported, _) => {
            "The previous schedule is removed before replacement."
        }
    }
}

fn schedule_edit_failure_note(platform: SchedulePlatform) -> &'static str {
    match platform {
        SchedulePlatform::Systemd => {
            "Failure may leave missing, quarantined, partial, or active units; no rollback."
        }
        SchedulePlatform::LaunchAgent => {
            "Failure may leave the old LaunchAgent removed and the replacement absent or partly installed; no rollback is performed."
        }
        SchedulePlatform::TaskScheduler => {
            "Failure may leave the old Task Scheduler task removed and the replacement absent or partly registered; no rollback is performed."
        }
        SchedulePlatform::Unsupported => "Replacement may be partial; no rollback is performed.",
    }
}

fn schedule_operation_result_message(
    platform: SchedulePlatform,
    action: &'static str,
    result: std::result::Result<&'static str, String>,
) -> String {
    let (operation, past_tense) = match action {
        "replacement" => ("replacement", "replaced"),
        "installation" => ("installation", "installed"),
        "enable" => ("enable", "enabled"),
        _ => (action, action),
    };
    let inspect = match platform {
        SchedulePlatform::Systemd => "the user manager and unit files",
        SchedulePlatform::LaunchAgent => "launchd and the plist",
        SchedulePlatform::TaskScheduler => "Task Scheduler and the task path",
        SchedulePlatform::Unsupported => "the scheduler and target",
    };
    match result {
        Ok("active_and_enabled") if platform == SchedulePlatform::Systemd => match action {
            "replacement" => "Timer replaced; the scheduled operation may start promptly.".into(),
            "installation" => "Timer installed; the scheduled operation may start promptly.".into(),
            _ => "Timer enabled; the scheduled operation may start promptly.".into(),
        },
        Ok("active_and_enabled") => format!(
            "{} {past_tense}; the read-only scan runs at its next configured 03:00 local calendar {}.",
            platform.subject(),
            if platform == SchedulePlatform::LaunchAgent {
                "interval"
            } else {
                "trigger"
            }
        ),
        Ok(status) => format!(
            "{} {operation}: {status}; inspect {inspect} before retrying.",
            platform.subject()
        ),
        Err(error) => format!("{} {operation} result: {error}", platform.subject()),
    }
}

fn schedule_preview_lines(lines: &mut Vec<String>, token: &str) {
    if let Some(last) = lines.last_mut() {
        if let Some(index) = last.find("Press y") {
            last.truncate(index);
        }
        last.push_str("Preview only; ↑/↓ scroll, Esc closes.");
    }
    lines.insert(
        lines.len().saturating_sub(1),
        format!("Preview token: {token}"),
    );
}

fn schedule_preview_display_lines(mut lines: Vec<String>, token: &str, area: Rect) -> Vec<String> {
    schedule_preview_lines(&mut lines, token);
    schedule_wrap_lines(&lines, area.width.saturating_sub(4) as usize)
}

fn append_schedule_unit_lines(lines: &mut Vec<String>, unit: &str) {
    if !unit.is_empty() {
        lines.extend(unit.split_terminator('\n').map(str::to_owned));
    }
}

fn schedule_scan_confirmation_lines_for(
    plan: &crate::schedule::ScanSchedulePreview,
    platform: SchedulePlatform,
) -> Vec<String> {
    let target_label = match platform {
        SchedulePlatform::Systemd => "Unit directory",
        SchedulePlatform::LaunchAgent => "LaunchAgents directory",
        SchedulePlatform::TaskScheduler => "Task Scheduler path",
        SchedulePlatform::Unsupported => "Schedule target",
    };
    let mut lines = vec![
        format!(
            "{target_label}: {}",
            crate::sweep::display_path(&plan.unit_directory)
        ),
        format!("Frequency: {}", plan.frequency),
        "Workspace roots:".into(),
    ];
    lines.extend(
        plan.roots
            .iter()
            .map(|path| format!("  {}", crate::sweep::display_path(path))),
    );
    lines.push("Exclusions:".into());
    if plan.exclusions.is_empty() {
        lines.push("  (none)".into());
    } else {
        lines.extend(
            plan.exclusions
                .iter()
                .map(|path| format!("  {}", crate::sweep::display_path(path))),
        );
    }
    match platform {
        SchedulePlatform::LaunchAgent => {
            lines.push("LaunchAgent property list:".into());
            append_schedule_unit_lines(&mut lines, &plan.service_unit);
        }
        SchedulePlatform::TaskScheduler => {
            lines.push("Task Scheduler XML definition:".into());
            append_schedule_unit_lines(&mut lines, &plan.service_unit);
        }
        SchedulePlatform::Systemd => {
            lines.push("Service unit:".into());
            append_schedule_unit_lines(&mut lines, &plan.service_unit);
            lines.push("Timer unit:".into());
            append_schedule_unit_lines(&mut lines, &plan.timer_unit);
        }
        SchedulePlatform::Unsupported => {
            lines.push("Schedule definition:".into());
            append_schedule_unit_lines(&mut lines, &plan.service_unit);
            append_schedule_unit_lines(&mut lines, &plan.timer_unit);
        }
    }
    lines
}

fn schedule_install_confirmation_lines(plan: &crate::schedule::ScanSchedulePreview) -> Vec<String> {
    schedule_install_confirmation_lines_for(plan, SchedulePlatform::current())
}

fn schedule_install_confirmation_lines_for(
    plan: &crate::schedule::ScanSchedulePreview,
    platform: SchedulePlatform,
) -> Vec<String> {
    let mut lines = schedule_scan_confirmation_lines_for(plan, platform);
    let artifact_cleanup = crate::schedule::schedules_artifact_cleanup(plan);
    let bytecode_cleanup = crate::schedule::schedules_bytecode_cleanup(plan);
    let cleanup = artifact_cleanup || bytecode_cleanup;
    if artifact_cleanup && platform != SchedulePlatform::Systemd {
        append_schedule_cleanup_details(&mut lines, true, bytecode_cleanup);
        lines
            .push("Scheduled artifact cleanup can only be installed on Linux with systemd.".into());
        lines.push(format!("Schedule warning: {}", plan.warning));
        return lines;
    }
    if cleanup && platform != SchedulePlatform::Systemd {
        append_schedule_cleanup_details(&mut lines, artifact_cleanup, bytecode_cleanup);
        lines.push(
            "Automatic scheduled cleanup can be installed only as a configured Linux systemd timer.".into(),
        );
        lines.push(format!("Schedule warning: {}", plan.warning));
        lines.push("Press y to install; Esc/n cancels.".into());
        return lines;
    }
    if platform == SchedulePlatform::LaunchAgent {
        lines.extend([
            "Creates the verified LaunchAgent plist in the current user's LaunchAgents directory."
                .into(),
            "Launchd is enabled and bootstrapped only after explicit confirmation.".into(),
            "RunAtLoad is false; the scheduled scan runs at its next calendar interval.".into(),
            scheduled_scan_output_note(platform).into(),
            "The scheduled operation is a read-only workspace scan; it does not clean files."
                .into(),
            scheduled_scan_history_note().into(),
            plan.warning.into(),
            "Press y to install; Esc/n cancels.".into(),
        ]);
        return lines;
    }
    if platform == SchedulePlatform::TaskScheduler {
        lines.extend([
            "Registers one Task Scheduler job for the current Windows user after explicit confirmation.".into(),
            "The shown task uses the least-privilege interactive principal and read-only scan action.".into(),
            scheduled_scan_timing_note(platform).into(),
            scheduled_scan_output_note(platform).into(),
            "Windows bytecode cleanup is not scheduled; workspace files are not cleaned.".into(),
            scheduled_scan_history_note().into(),
            format!("Task Scheduler warning: {}", plan.warning),
            "Press y to install; Esc/n cancels.".into(),
        ]);
        return lines;
    }
    if platform == SchedulePlatform::Unsupported {
        lines.extend([
            "User schedules are unsupported on this platform.".into(),
            format!("Schedule warning: {}", plan.warning),
            "Press y to install; Esc/n cancels.".into(),
        ]);
        return lines;
    }
    lines.extend([
        "Unit directory must exist, be user-owned, and not group/other writable.".into(),
        "Creates unit files and enables a user timer; failures may be partial.".into(),
    ]);
    if cleanup {
        append_schedule_cleanup_details(&mut lines, artifact_cleanup, bytecode_cleanup);
    } else {
        lines.push("Scan may start promptly and writes JSON to the user journal; no workspace files are cleaned.".into());
    }
    lines.push(scheduled_scan_history_note().into());
    lines.push(format!(
        "{} warning: {}",
        if cleanup { "Scheduled cleanup" } else { "Scan" },
        plan.warning
    ));
    lines.push("Press y to install; Esc/n cancels.".into());
    lines
}

fn schedule_enable_confirmation_lines(
    plan: &crate::schedule::EnableSchedulePreview,
) -> Vec<String> {
    schedule_enable_confirmation_lines_for(plan, SchedulePlatform::current())
}

fn schedule_enable_confirmation_lines_for(
    plan: &crate::schedule::EnableSchedulePreview,
    platform: SchedulePlatform,
) -> Vec<String> {
    let mut lines = schedule_scan_confirmation_lines_for(&plan.intended, platform);
    let artifact_cleanup = crate::schedule::schedules_artifact_cleanup(&plan.intended);
    let bytecode_cleanup = crate::schedule::schedules_bytecode_cleanup(&plan.intended);
    let cleanup = artifact_cleanup || bytecode_cleanup;
    if artifact_cleanup && platform != SchedulePlatform::Systemd {
        append_schedule_cleanup_details(&mut lines, true, bytecode_cleanup);
        lines.push("Scheduled artifact cleanup can only be enabled on Linux with systemd.".into());
        lines.push(format!("Enable warning: {}", plan.warning));
        return lines;
    }
    if cleanup && platform != SchedulePlatform::Systemd {
        append_schedule_cleanup_details(&mut lines, artifact_cleanup, bytecode_cleanup);
        lines.push(
            "Automatic scheduled cleanup can be enabled only for a configured Linux systemd timer."
                .into(),
        );
        lines.push(format!("Enable warning: {}", plan.warning));
        lines.push("Press y to enable; Esc/n cancels.".into());
        return lines;
    }
    if platform == SchedulePlatform::TaskScheduler {
        lines.extend([
            "Re-enables only the verified Task Scheduler task for the current Windows user.".into(),
            scheduled_scan_timing_note(platform).into(),
            scheduled_scan_output_note(platform).into(),
            "Workspace files are not cleaned.".into(),
            scheduled_scan_history_note().into(),
            format!("Task Scheduler warning: {}", plan.warning),
        ]);
    } else if platform == SchedulePlatform::LaunchAgent {
        lines.extend([
            scheduled_scan_timing_note(platform).into(),
            scheduled_scan_output_note(platform).into(),
            "No workspace files are cleaned.".into(),
            "The LaunchAgent plist and loaded path are identity-checked.".into(),
            scheduled_scan_history_note().into(),
        ]);
    } else if platform == SchedulePlatform::Unsupported {
        lines.extend([
            "User schedules are unsupported on this platform.".into(),
            scheduled_scan_output_note(platform).into(),
            scheduled_scan_history_note().into(),
        ]);
    } else if cleanup {
        append_schedule_cleanup_details(&mut lines, artifact_cleanup, bytecode_cleanup);
        lines.push("Existing unit ownership is not independently proven.".into());
    } else {
        lines.extend([
            "Scan may start promptly; its JSON is written to the user journal.".into(),
            "No workspace files are cleaned.".into(),
            "Existing unit ownership is not independently proven.".into(),
        ]);
    }
    if platform == SchedulePlatform::Systemd {
        lines.push(scheduled_scan_history_note().into());
    }
    lines.push(format!(
        "Intended {} warning: {}",
        if cleanup { "cleanup" } else { "scan" },
        plan.intended.warning
    ));
    if platform != SchedulePlatform::TaskScheduler {
        lines.push(format!("Enable warning: {}", plan.warning));
    }
    lines.push("Press y to enable; Esc/n cancels.".into());
    lines
}

fn append_schedule_cleanup_details(lines: &mut Vec<String>, artifacts: bool, bytecode: bool) {
    if artifacts {
        lines.extend([
            "This policy permanently removes explicitly scoped rebuildable project artifacts.".into(),
            "Artifact retention is at least 30 days; at most 8 directories are attempted per run.".into(),
            "Eligible targets are Maven target, Zig .zig-cache, Dart .dart_tool, and Python pytest/mypy caches; Cargo is excluded from scheduled cleanup until its target-directory configuration can be verified safely.".into(),
            "Active or unknown process activity and failed project, Git, history, or identity checks stop cleanup.".into(),
            "Each attempted removal reserves local history first; interruptions may leave an incomplete record.".into(),
            "The scheduler output and local history omit workspace paths and raw error details.".into(),
        ]);
    }
    if bytecode {
        lines.extend([
            "This policy automatically and permanently removes eligible Python bytecode.".into(),
            "Scheduled bytecode cleanup requires explicit opt-in in the bound configuration.".into(),
            "Bytecode retention is at least 7 days; at most 32 files are removed per run.".into(),
            "Each file is revalidated against project, Git, process, path, source and configuration policy.".into(),
            "Unchecked-hash bytecode is excluded; concurrent changes can still race.".into(),
        ]);
    }
}

fn schedule_escape_controls(line: &str) -> String {
    use std::fmt::Write;

    let mut visible = String::with_capacity(line.len());
    for character in line.chars() {
        if character == '\\' {
            visible.push_str("\\\\");
        } else if character.is_control() || is_bidi_control(character) {
            let code = character as u32;
            if code <= 0xff {
                let _ = write!(visible, "\\x{code:02X}");
            } else {
                let _ = write!(visible, "\\u{{{code:X}}}");
            }
        } else {
            visible.push(character);
        }
    }
    visible
}

fn schedule_wrap_line(line: &str, width: usize) -> Vec<String> {
    let visible = schedule_escape_controls(line);
    let line = visible.as_str();
    if width == 0 || line.is_empty() {
        return vec![line.to_owned()];
    }

    let mut wrapped = Vec::new();
    let mut current = String::new();
    let mut current_width = 0_usize;
    for grapheme in ratatui::text::Line::from(line).styled_graphemes(Style::default()) {
        let grapheme_width = ratatui::text::Line::from(grapheme.symbol).width();
        if !current.is_empty() && current_width.saturating_add(grapheme_width) > width {
            wrapped.push(std::mem::take(&mut current));
            current_width = 0;
        }
        current.push_str(grapheme.symbol);
        current_width = current_width.saturating_add(grapheme_width);
    }
    if !current.is_empty() {
        wrapped.push(current);
    }
    wrapped
}

fn schedule_wrap_lines(lines: &[String], width: usize) -> Vec<String> {
    lines
        .iter()
        .flat_map(|line| schedule_wrap_line(line, width))
        .collect()
}

fn schedule_confirmation_display_lines(content: &[String], area: Rect) -> Vec<String> {
    let mut lines =
        vec!["Review all lines (backslashes/controls escaped); ↑/↓ or PgUp/PgDn.".into()];
    lines.extend_from_slice(content);
    let mut wrapped = schedule_wrap_lines(&lines, area.width.saturating_sub(4) as usize);
    if wrapped
        .len()
        .saturating_sub(schedule_confirmation_visible_rows(area))
        > u16::MAX as usize
    {
        lines.insert(
            0,
            "Widen terminal; this view cannot scroll through the entire plan.".into(),
        );
        wrapped = schedule_wrap_lines(&lines, area.width.saturating_sub(4) as usize);
    }
    wrapped
}

fn schedule_confirmation_visible_rows(area: Rect) -> usize {
    area.height.saturating_sub(2) as usize
}

fn history_purge_visible_rows(area: Rect) -> usize {
    schedule_confirmation_visible_rows(area)
}

fn history_purge_confirmation_lines(
    plan: &crate::reports::HistoryPurgePlan,
    read_only: bool,
) -> Vec<String> {
    let days = plan.older_than_seconds / 86_400;
    let mut lines = vec![
        if read_only {
            format!("Read-only preview of records older than {days} days.")
        } else {
            format!("Permanently remove records older than {days} days.")
        },
        format!(
            "Cutoff Unix: {}; {} readable records; {} candidates; {} unfinished records skipped.",
            plan.cutoff_unix,
            plan.record_count,
            plan.candidates.len(),
            plan.skipped_unfinished_records
        ),
        "Candidates (ID, start, finish, operation, outcome, target):".into(),
    ];
    if plan.candidates.is_empty() {
        lines.push("No records match this retention period.".into());
    } else {
        for candidate in &plan.candidates {
            lines.push(format!(
                "ID {} | started={} | finished={} | {} | {}",
                candidate.id,
                crate::reports::format_timestamp(candidate.started_unix),
                candidate
                    .finished_unix
                    .map(crate::reports::format_timestamp)
                    .unwrap_or_else(|| "unfinished".into()),
                candidate.operation,
                candidate.outcome
            ));
            lines.push(format!("  target: {}", candidate.target));
        }
    }
    lines.push(format!("Warning: {}", plan.warning));
    lines.push(if read_only {
        "Preview only; records will not be removed. Esc/n closes.".into()
    } else {
        "Press y after reviewing every record to remove them; Esc/n cancels.".into()
    });
    lines
}

fn history_purge_ready(app: &App, area: Rect) -> bool {
    if app.history_purge_read_only || app.history_purge_area != area {
        return false;
    }
    let Some(plan) = &app.history_purge_plan else {
        return false;
    };
    let displayed = schedule_confirmation_display_lines(
        &history_purge_confirmation_lines(plan, app.history_purge_read_only),
        area,
    );
    app.history_purge_content.as_ref() == Some(&displayed)
        && schedule_confirmation_reviewed(&displayed, area, app.history_purge_scroll as usize)
}

fn history_purge_can_confirm(app: &App, drawn: Rect, actual: Rect) -> bool {
    drawn == actual && history_purge_ready(app, drawn) && history_purge_ready(app, actual)
}

fn schedule_confirmation_reviewed(lines: &[String], area: Rect, scroll: usize) -> bool {
    let width = area.width.saturating_sub(4) as usize;
    let visible_rows = schedule_confirmation_visible_rows(area).min(lines.len());
    width > 0
        && visible_rows > 0
        && scroll <= u16::MAX as usize
        && lines
            .iter()
            .all(|line| ratatui::text::Line::from(line.as_str()).width() <= width)
        && scroll.saturating_add(visible_rows) >= lines.len()
}

fn schedule_confirmation_review(app: &App) -> Option<(String, Vec<String>, String)> {
    #[cfg(target_os = "linux")]
    if let Some(plan) = &app.trash_retention_plan {
        let (identity, token) = match plan {
            TrashRetentionReviewPlan::Install(plan) => (
                format!("trash-install:{}", plan.preview_token),
                plan.preview_token.clone(),
            ),
            TrashRetentionReviewPlan::Enable(plan) => (
                format!("trash-enable:{}", plan.preview_token),
                plan.preview_token.clone(),
            ),
            TrashRetentionReviewPlan::Disable(plan) => (
                format!("trash-disable:{}", plan.preview_token),
                plan.preview_token.clone(),
            ),
            TrashRetentionReviewPlan::Remove(plan) => (
                format!("trash-remove:{}", plan.preview_token),
                plan.preview_token.clone(),
            ),
        };
        return Some((identity, trash_retention_review_lines(plan), token));
    }
    if let Some((plan, _)) = &app.schedule_edit_plan {
        return Some((
            format!("edit:{}", plan.preview_token),
            schedule_edit_confirmation_lines(plan),
            plan.preview_token.clone(),
        ));
    }
    if let Some(plan) = &app.schedule_remove_plan {
        return Some((
            format!("remove:{}", plan.preview_token),
            schedule_remove_confirmation_lines(plan),
            plan.preview_token.clone(),
        ));
    }
    if let Some((plan, _)) = &app.schedule_install_plan {
        return Some((
            format!("install:{}", plan.preview_token),
            schedule_install_confirmation_lines(plan),
            plan.preview_token.clone(),
        ));
    }
    if let Some((plan, _)) = &app.schedule_enable_plan {
        return Some((
            format!("enable:{}", plan.preview_token),
            schedule_enable_confirmation_lines(plan),
            plan.preview_token.clone(),
        ));
    }
    if let Some(plan) = &app.schedule_disable_plan {
        return Some((
            format!("disable:{}", plan.preview_token),
            schedule_disable_confirmation_lines(plan),
            plan.preview_token.clone(),
        ));
    }
    None
}

#[cfg(target_os = "linux")]
fn trash_retention_review_lines(plan: &TrashRetentionReviewPlan) -> Vec<String> {
    let (action, location, age_seconds, unit_directory, service_unit, timer_unit, warning) =
        match plan {
            TrashRetentionReviewPlan::Install(plan) => (
                "install and enable",
                &plan.location,
                plan.age_seconds,
                &plan.unit_directory,
                &plan.service_unit,
                &plan.timer_unit,
                plan.warning,
            ),
            TrashRetentionReviewPlan::Enable(plan) => (
                "re-enable",
                &plan.location,
                plan.age_seconds,
                &plan.unit_directory,
                &plan.service_unit,
                &plan.timer_unit,
                plan.warning,
            ),
            TrashRetentionReviewPlan::Disable(plan) => (
                "disable",
                &plan.location,
                plan.age_seconds,
                &plan.unit_directory,
                &plan.service_unit,
                &plan.timer_unit,
                plan.warning,
            ),
            TrashRetentionReviewPlan::Remove(plan) => (
                "remove",
                &plan.location,
                plan.age_seconds,
                &plan.unit_directory,
                &plan.service_unit,
                &plan.timer_unit,
                plan.warning,
            ),
        };
    let current_preview = match plan {
        TrashRetentionReviewPlan::Install(plan) => Some(&plan.current_preview),
        TrashRetentionReviewPlan::Enable(plan) => plan.current_preview.as_ref(),
        TrashRetentionReviewPlan::Disable(_) | TrashRetentionReviewPlan::Remove(_) => None,
    };
    let unit_state = match plan {
        TrashRetentionReviewPlan::Install(_) => None,
        TrashRetentionReviewPlan::Enable(plan)
        | TrashRetentionReviewPlan::Disable(plan)
        | TrashRetentionReviewPlan::Remove(plan) => Some((
            plan.active_state.as_str(),
            plan.unit_file_state.as_deref().unwrap_or("unknown"),
        )),
    };
    let age = if age_seconds.is_multiple_of(24 * 60 * 60) {
        format!("{} days", age_seconds / (24 * 60 * 60))
    } else {
        format!("{age_seconds} seconds")
    };
    let enabling = matches!(
        plan,
        TrashRetentionReviewPlan::Install(_) | TrashRetentionReviewPlan::Enable(_)
    );
    let mut lines = vec![
        format!("Action: {action} the daily scheduled Trash retention timer"),
        format!("Trash location: {}", crate::sweep::display_path(location)),
        format!("Age threshold: {age} (minimum 30 days)"),
        format!("Unit directory: {}", crate::sweep::display_path(unit_directory)),
        format!(
            "Timer state before action: {}",
            unit_state.map_or("not installed or not inspected".into(), |(active, enabled)| {
                format!("active={active}, enabled={enabled}")
            })
        ),
        "Opt-in: scheduled_trash_retention = true must remain enabled in the bound private config.".into(),
        "Limit: at most 32 eligible items per run; excess eligible items remain deferred and make that run partial.".into(),
    ];
    if let Some(current) = current_preview {
        lines.push(
            "Policy: while enabled, this exact location and age threshold cover current eligible items and future matching Trash items.".into(),
        );
        lines.push(
            "Deletion: current eligible items listed below and future matching Trash items are permanently deleted; no recovery is provided.".into(),
        );
        lines.push(format!(
            "Current inventory: {} eligible; {} deferred; {} skipped.",
            current.eligible, current.deferred, current.skipped
        ));
        if current.next_run_items.is_empty() {
            lines.push("No currently eligible items are in the next run.".into());
        } else {
            lines.push(format!(
                "Currently eligible items in the next run (up to {}):",
                crate::trash::MAX_SCHEDULED_TRASH_REMOVALS
            ));
            lines.extend(current.next_run_items.iter().map(|item| {
                format!(
                    "  {} | deleted={} | {} | descendants={} | logical_bytes={}",
                    item.name,
                    item.deletion_date.as_deref().unwrap_or("unknown"),
                    item.kind,
                    item.descendant_count,
                    item.logical_bytes
                )
            }));
        }
        lines.push(
            "This inventory is a current sample; future matching items at the same location remain within the policy.".into(),
        );
    } else {
        lines.push(
            "No Trash items are removed by this timer-management action; a service that already started may finish.".into(),
        );
    }
    if enabling {
        lines.push(
            "Timing: the persistent daily timer can catch up a missed run and may start the service promptly after installation or re-enabling.".into(),
        );
    }
    lines.push("Service unit:".into());
    append_schedule_unit_lines(&mut lines, service_unit);
    lines.push("Timer unit:".into());
    append_schedule_unit_lines(&mut lines, timer_unit);
    if let TrashRetentionReviewPlan::Remove(plan) = plan {
        lines.push("Quarantine paths:".into());
        lines.extend(
            plan.quarantine_paths
                .iter()
                .map(|path| format!("  {}", crate::sweep::display_path(path))),
        );
    }
    lines.extend([
        format!("Manager warning: {warning}"),
        "Filesystem warning: identity and age are rechecked before removal, but concurrent filesystem changes can still race a check.".into(),
        "History stores the operation and counts; Trash names and paths are redacted.".into(),
        "Press y only after reviewing every line; Esc/n cancels.".into(),
    ]);
    lines
}

fn schedule_confirmation_ready(app: &App, lines: &[String], area: Rect) -> bool {
    if app.schedule_confirmation_area != area {
        return false;
    }
    let displayed = schedule_confirmation_display_lines(lines, area);
    app.schedule_confirmation_content.as_ref() == Some(&displayed)
        && schedule_confirmation_reviewed(&displayed, area, app.schedule_confirmation_scroll)
}

fn schedule_confirmation_can_confirm(app: &App, drawn: Rect, actual: Rect) -> bool {
    if app.schedule_read_only || schedule_activation_is_preview_only(app) || drawn != actual {
        return false;
    }
    let Some((_, lines, _)) = schedule_confirmation_review(app) else {
        return false;
    };
    schedule_confirmation_ready(app, &lines, drawn)
        && schedule_confirmation_ready(app, &lines, actual)
}

fn schedule_activation_is_preview_only(app: &App) -> bool {
    !cfg!(target_os = "linux")
        && (app
            .schedule_install_plan
            .as_ref()
            .is_some_and(|(plan, _)| crate::schedule::schedules_artifact_cleanup(plan))
            || app.schedule_enable_plan.as_ref().is_some_and(|(plan, _)| {
                crate::schedule::schedules_artifact_cleanup(&plan.intended)
            })
            || app.schedule_edit_plan.as_ref().is_some_and(|(plan, _)| {
                crate::schedule::schedules_artifact_cleanup(&plan.replacement)
            }))
}

fn schedule_dialog_title(
    platform: SchedulePlatform,
    action: &'static str,
    preview: bool,
) -> String {
    let label = match (platform, action) {
        (SchedulePlatform::Systemd, "removal") => "timer unit removal",
        (SchedulePlatform::Systemd, action) => {
            return format!(
                " {} timer {action} ",
                if preview { "Preview" } else { "Confirm" }
            );
        }
        (SchedulePlatform::LaunchAgent, "removal") => "LaunchAgent removal",
        (SchedulePlatform::LaunchAgent, action) => {
            return format!(
                " {} LaunchAgent {action} ",
                if preview { "Preview" } else { "Confirm" }
            );
        }
        (SchedulePlatform::TaskScheduler, "removal") => "Task Scheduler task removal",
        (SchedulePlatform::TaskScheduler, action) => {
            return format!(
                " {} Task Scheduler task {action} ",
                if preview { "Preview" } else { "Confirm" }
            );
        }
        (SchedulePlatform::Unsupported, action) => {
            return format!(
                " {} schedule {action} ",
                if preview { "Preview" } else { "Confirm" }
            );
        }
    };
    format!(" {} {label} ", if preview { "Preview" } else { "Confirm" })
}

fn schedule_edit_confirmation_lines(plan: &crate::schedule::EditSchedulePreview) -> Vec<String> {
    schedule_edit_confirmation_lines_for(plan, SchedulePlatform::current())
}

fn schedule_edit_confirmation_lines_for(
    plan: &crate::schedule::EditSchedulePreview,
    platform: SchedulePlatform,
) -> Vec<String> {
    let target_label = match platform {
        SchedulePlatform::Systemd => "unit directory",
        SchedulePlatform::LaunchAgent => "LaunchAgents directory",
        SchedulePlatform::TaskScheduler => "Task Scheduler path",
        SchedulePlatform::Unsupported => "schedule target",
    };
    let launchd = platform == SchedulePlatform::LaunchAgent;
    let task_scheduler = platform == SchedulePlatform::TaskScheduler;
    let mut lines = vec![
        format!(
            "Old {target_label}: {}",
            crate::sweep::display_path(&plan.previous.existing.unit_directory)
        ),
        format!(
            "Old {}: {} / {}",
            if task_scheduler {
                "task state"
            } else {
                "schedule"
            },
            plan.previous.existing.active_state,
            plan.previous
                .existing
                .unit_file_state
                .as_deref()
                .unwrap_or("unknown")
        ),
        if launchd {
            "Old LaunchAgent plist:".into()
        } else if task_scheduler {
            "Old Task Scheduler XML definition:".into()
        } else {
            "Old service unit:".into()
        },
    ];
    append_schedule_unit_lines(&mut lines, &plan.previous.existing.service_unit);
    if platform == SchedulePlatform::Systemd {
        lines.push("Old timer unit:".into());
        append_schedule_unit_lines(&mut lines, &plan.previous.existing.timer_unit);
    }
    lines.push("Quarantine paths:".into());
    lines.extend(
        plan.previous
            .quarantine_paths
            .iter()
            .map(|path| format!("  {}", crate::sweep::display_path(path))),
    );
    lines.push("Replacement:".into());
    lines.extend(schedule_scan_confirmation_lines_for(
        &plan.replacement,
        platform,
    ));
    let artifact_cleanup = crate::schedule::schedules_artifact_cleanup(&plan.replacement);
    let bytecode_cleanup = crate::schedule::schedules_bytecode_cleanup(&plan.replacement);
    let cleanup = artifact_cleanup || bytecode_cleanup;
    if artifact_cleanup && platform != SchedulePlatform::Systemd {
        append_schedule_cleanup_details(&mut lines, true, bytecode_cleanup);
        lines.push("Scheduled artifact cleanup can only be edited on Linux with systemd.".into());
        lines.push(format!(
            "Replacement cleanup warning: {}",
            plan.replacement.warning
        ));
        lines.push(format!("Edit warning: {}", plan.warning));
        return lines;
    }
    if cleanup && platform != SchedulePlatform::Systemd {
        append_schedule_cleanup_details(&mut lines, artifact_cleanup, bytecode_cleanup);
        lines.push(
            "Automatic scheduled cleanup can be installed only as a configured Linux systemd timer.".into(),
        );
        lines.push(format!(
            "Replacement cleanup warning: {}",
            plan.replacement.warning
        ));
        lines.push(format!("Edit warning: {}", plan.warning));
        lines.push("Press y to replace; Esc/n cancels.".into());
        return lines;
    }
    lines.extend([
        schedule_edit_transition_note(platform, cleanup).into(),
        schedule_edit_failure_note(platform).into(),
    ]);
    if cleanup {
        append_schedule_cleanup_details(&mut lines, artifact_cleanup, bytecode_cleanup);
    } else {
        lines.push(scheduled_scan_output_note(platform).into());
        lines.push("No workspace files are cleaned.".into());
        lines.push(scheduled_scan_history_note().into());
    }
    if task_scheduler {
        lines.push(format!(
            "Task Scheduler warning: {}",
            plan.replacement.warning
        ));
    }
    lines.push(format!(
        "Replacement {} warning: {}",
        if cleanup { "cleanup" } else { "scan" },
        plan.replacement.warning
    ));
    lines.push(format!("Edit warning: {}", plan.warning));
    lines.push("Press y to replace; Esc/n cancels.".into());
    lines
}

fn schedule_remove_confirmation_lines(
    plan: &crate::schedule::RemoveSchedulePreview,
) -> Vec<String> {
    schedule_remove_confirmation_lines_for(plan, SchedulePlatform::current())
}

fn schedule_remove_confirmation_lines_for(
    plan: &crate::schedule::RemoveSchedulePreview,
    platform: SchedulePlatform,
) -> Vec<String> {
    let target_label = match platform {
        SchedulePlatform::Systemd => "Unit directory",
        SchedulePlatform::LaunchAgent => "LaunchAgents directory",
        SchedulePlatform::TaskScheduler => "Task Scheduler path",
        SchedulePlatform::Unsupported => "Schedule target",
    };
    let launchd = platform == SchedulePlatform::LaunchAgent;
    let task_scheduler = platform == SchedulePlatform::TaskScheduler;
    let mut lines = vec![
        format!(
            "{target_label}: {}",
            crate::sweep::display_path(&plan.existing.unit_directory)
        ),
        format!(
            "{}: {} / {}",
            if task_scheduler {
                "Task state"
            } else {
                "Schedule"
            },
            plan.existing.active_state,
            plan.existing
                .unit_file_state
                .as_deref()
                .unwrap_or("unknown")
        ),
        if launchd {
            "LaunchAgent plist:".into()
        } else if task_scheduler {
            "Task Scheduler XML definition:".into()
        } else {
            "Service unit:".into()
        },
    ];
    append_schedule_unit_lines(&mut lines, &plan.existing.service_unit);
    if platform == SchedulePlatform::Systemd {
        lines.push("Timer unit:".into());
        append_schedule_unit_lines(&mut lines, &plan.existing.timer_unit);
    }
    lines.push("Quarantine paths:".into());
    lines.extend(
        plan.quarantine_paths
            .iter()
            .map(|path| format!("  {}", crate::sweep::display_path(path))),
    );
    lines.push(if task_scheduler {
        "The Task Scheduler task is removed; workspace files are not removed.".into()
    } else {
        "Workspace files are not removed.".into()
    });
    lines.push(if task_scheduler {
        format!("Task Scheduler warning: {}", plan.warning)
    } else {
        plan.warning.into()
    });
    lines.push("Press y to remove; Esc/n cancels.".into());
    lines
}

fn schedule_disable_confirmation_lines(
    plan: &crate::schedule::DisableSchedulePreview,
) -> Vec<String> {
    schedule_disable_confirmation_lines_for(plan, SchedulePlatform::current())
}

fn schedule_disable_confirmation_lines_for(
    plan: &crate::schedule::DisableSchedulePreview,
    platform: SchedulePlatform,
) -> Vec<String> {
    let target_label = match platform {
        SchedulePlatform::Systemd => "Unit directory",
        SchedulePlatform::LaunchAgent => "LaunchAgents directory",
        SchedulePlatform::TaskScheduler => "Task Scheduler path",
        SchedulePlatform::Unsupported => "Schedule target",
    };
    let launchd = platform == SchedulePlatform::LaunchAgent;
    let task_scheduler = platform == SchedulePlatform::TaskScheduler;
    let mut lines = vec![
        format!(
            "{target_label}: {}",
            crate::sweep::display_path(&plan.unit_directory)
        ),
        format!(
            "{}: {} / {}",
            if task_scheduler {
                "Task state"
            } else {
                "Schedule state"
            },
            plan.active_state,
            plan.unit_file_state.as_deref().unwrap_or("unknown")
        ),
        if launchd {
            "LaunchAgent plist:".into()
        } else if task_scheduler {
            "Task Scheduler XML definition:".into()
        } else {
            "Service unit:".into()
        },
    ];
    append_schedule_unit_lines(&mut lines, &plan.service_unit);
    if platform == SchedulePlatform::Systemd {
        lines.push("Timer unit:".into());
        append_schedule_unit_lines(&mut lines, &plan.timer_unit);
    }
    lines.extend([
        if task_scheduler {
            format!("Task Scheduler warning: {}", plan.warning)
        } else {
            plan.warning.into()
        },
        "Press y to disable; Esc/n cancels.".into(),
    ]);
    lines
}

fn container_confirmation_lines(plan: &crate::containers::RemovalPlan) -> Vec<String> {
    vec![
        format!("Engine: {}  {}", plan.engine, plan.engine_identity),
        format!("ID: {}", plan.container_id),
        format!("Name: {}", plan.name),
        format!(
            "Writable layer bytes: {}",
            plan.writable_bytes
                .map_or("unknown".into(), |size| size.to_string())
        ),
        "Removing this stopped container permanently deletes its writable layer,".into(),
        "configuration and logs. No force or volume-removal flag is used.".into(),
        "Reclaimed space is not guaranteed; state will be checked again.".into(),
        "Press y to remove this container; Esc/n cancels.".into(),
    ]
}

fn build_cache_confirmation_lines(
    plan: &crate::containers::BuildCacheRemovalPlan,
    read_only: bool,
) -> Vec<String> {
    vec![
        format!("Engine: {}", plan.engine_identity),
        format!("Builder: {}", plan.builder),
        format!("Cache ID: {}", plan.cache_id),
        format!("Type: {}  Reported size: {}", plan.cache_type, plan.size),
        "Permanently removes build cache that may contain build data.".into(),
        "BuildKit may also remove linked metadata or run garbage collection.".into(),
        "Builds may redownload or rebuild. Reclaimed space is unknown.".into(),
        "Builder and cache can change after inspection; failures may be partial.".into(),
        if read_only {
            "Preview only; Esc/n closes.".into()
        } else {
            "Press y to remove this cache; Esc/n cancels.".into()
        },
    ]
}

fn build_cache_confirmation_fits(
    plan: &crate::containers::BuildCacheRemovalPlan,
    read_only: bool,
    area: Rect,
) -> bool {
    let lines = build_cache_confirmation_lines(plan, read_only);
    area.height as usize >= lines.len() + 2
        && lines.iter().all(|line| {
            ratatui::text::Line::from(line.as_str()).width()
                <= area.width.saturating_sub(4) as usize
        })
}

fn trash_removal_confirmation_lines(plan: &crate::trash::TrashBatchPlan) -> Vec<String> {
    let mut lines = vec![format!("{} selected items:", plan.items.len())];
    if let Some(note) = &plan.selection_note {
        lines.push(note.clone());
    }
    for item in &plan.items {
        lines.push(format!(
            "Trash: {}",
            crate::sweep::display_path(&item.location)
        ));
        lines.push(format!(
            "Item: {}  {}  descendants={}  deleted={}  bytes={}",
            item.name,
            item.kind,
            item.descendant_count,
            item.deletion_date.as_deref().unwrap_or("unknown"),
            item.logical_bytes
        ));
    }
    lines.extend([
        "These items, directory contents and Trash metadata will be permanently deleted.".into(),
        "Reclaimed space is unknown; interruptions may leave quarantine files.".into(),
        "Press y to delete permanently; Esc/n cancels.".into(),
    ]);
    lines
}

fn trash_removal_confirmation_fits(plan: &crate::trash::TrashBatchPlan, area: Rect) -> bool {
    let lines = trash_removal_confirmation_lines(plan);
    area.height as usize >= lines.len() + 2
        && lines.iter().all(|line| {
            ratatui::text::Line::from(line.as_str()).width()
                <= area.width.saturating_sub(4) as usize
        })
}

fn network_confirmation_lines(plan: &crate::containers::NetworkRemovalPlan) -> Vec<String> {
    vec![
        format!("Engine: {}  {}", plan.engine, plan.engine_identity),
        format!("Network ID: {}", plan.network_id),
        format!("Name: {}", plan.name),
        "Permanently removes this unused bridge network without force.".into(),
        "Services may need it later; attachments and engine state can change.".into(),
        "Podman custom default networks are not independently identified.".into(),
        "Press y to remove this network; Esc/n cancels.".into(),
    ]
}

fn network_confirmation_fits(plan: &crate::containers::NetworkRemovalPlan, area: Rect) -> bool {
    let lines = network_confirmation_lines(plan);
    area.height as usize >= lines.len() + 2
        && lines.iter().all(|line| {
            ratatui::text::Line::from(line.as_str()).width()
                <= area.width.saturating_sub(4) as usize
        })
}

fn container_confirmation_fits(plan: &crate::containers::RemovalPlan, area: Rect) -> bool {
    let lines = container_confirmation_lines(plan);
    area.height as usize >= lines.len() + 2
        && lines.iter().all(|line| {
            ratatui::text::Line::from(line.as_str()).width()
                <= area.width.saturating_sub(4) as usize
        })
}

fn trim_confirmation_lines(plan: &crate::maintenance::TrimPlan, read_only: bool) -> Vec<String> {
    vec![
        format!("Mount: {}", crate::sweep::display_path(&plan.mount)),
        format!("Filesystem: {}  Device: {}", plan.filesystem, plan.device),
        "TRIM affects unused blocks across this entire filesystem.".into(),
        "Support and permissions are unknown; free space will not increase.".into(),
        "No privilege elevation or timer changes will be performed.".into(),
        if read_only {
            "Read-only preview; Esc/n closes.".into()
        } else {
            "Press y to run TRIM; Esc/n cancels.".into()
        },
    ]
}

fn trim_confirmation_fits(
    plan: &crate::maintenance::TrimPlan,
    read_only: bool,
    area: Rect,
) -> bool {
    let lines = trim_confirmation_lines(plan, read_only);
    area.height as usize >= lines.len() + 2
        && lines.iter().all(|line| {
            ratatui::text::Line::from(line.as_str()).width()
                <= area.width.saturating_sub(4) as usize
        })
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

enum WorkerEvent {
    Checked(Result<Vec<ToolReport>, String>),
    Diagnosed(
        Vec<String>,
        Option<u64>,
        Option<crate::doctor::Capabilities>,
    ),
    Updating(ToolKind, usize, usize),
    Updated(Vec<(ToolKind, Result<(), String>)>),
    SelfUpdatePreview(Result<crate::application::SelfUpdatePlan, String>),
    SelfUpdated(Result<(), String>),
    ManagedPreview(Result<crate::managed_cleanup::CleanupPlan, String>),
    ManagedBatchPreview(Result<Vec<ManagedCleanupTarget>, ManagedBatchPreviewFailure>),
    ManagedCleaned(crate::reports::Performed<&'static str>),
    ManagedBatchRemoved(ManagedBatchResult),
    TempPreview(Result<crate::temp_cleanup::Plan, String>, bool),
    #[cfg(target_os = "linux")]
    TempCleaned(crate::reports::Performed<crate::temp_cleanup::CleanupResult>),
    Scanned(Result<crate::sweep::ScanReport, String>),
    Previewed(Result<crate::sweep::CleanupPlan, String>),
    ArtifactPreview(Result<crate::artifact_cleanup::ArtifactPlan, String>),
    ArtifactBatchPreview(Result<crate::artifact_cleanup::ArtifactBatchPlan, String>),
    ArtifactRemoved(crate::reports::Performed<&'static str>),
    ArtifactBatchRemoved(crate::reports::ArtifactBatchReport),
    SharedCachePreview(Result<crate::shared_cache_cleanup::CacheRemovalPlan, String>),
    SharedCacheRemoved(crate::reports::Performed<&'static str>),
    BytecodeListed(Result<BytecodeListing, String>),
    BytecodePreview(Result<crate::bytecode::BytecodePlan, String>),
    BytecodeRemoved(crate::reports::Performed<&'static str>),
    BytecodeBatchPreview(Result<crate::bytecode::BytecodeBatchPlan, String>),
    BytecodeBatchProgress(usize, usize),
    BytecodeBatchRemoved(Result<crate::reports::BytecodeBatchResult, String>),
    SettingsLoaded(Result<crate::config::ConfigDocument, String>),
    SettingsSaved(Result<(crate::config::ConfigDocument, Option<PathBuf>), String>),
    Maintenance(Result<crate::maintenance::TrimStatus, String>),
    TrimPreview(Result<crate::maintenance::TrimPlan, String>),
    TrimFinished(crate::reports::Performed<()>),
    Cache(crate::cache::CacheReport),
    GoTestPreview(Result<crate::cache::GoTestExpirationPlan, String>),
    GoTestFinished(crate::reports::Performed<crate::cache::GoTestExpirationResult>),
    Trash(crate::trash::TrashReport),
    TrashPreview(Result<crate::trash::RetentionPreview, String>),
    TrashRemovalPreview(Result<crate::trash::TrashBatchPlan, String>),
    TrashSelection(
        Result<
            (
                crate::trash::RetentionPreview,
                crate::trash::RetentionSelection,
            ),
            String,
        >,
    ),
    TrashRemovalProgress(usize, usize),
    TrashRemoved(crate::reports::Performed<crate::trash::TrashBatchResult>),
    Containers(Vec<crate::containers::EngineStatus>),
    ContainerPreview(Result<crate::containers::RemovalPlan, String>),
    ContainerRemoved(crate::reports::Performed<&'static str>),
    NetworkPreview(Result<crate::containers::NetworkRemovalPlan, String>),
    NetworkRemoved(crate::reports::Performed<&'static str>),
    BuildCachePreview(Result<crate::containers::BuildCacheRemovalPlan, String>),
    BuildCacheRemoved(crate::reports::Performed<&'static str>),
    History(Result<crate::reports::History, String>),
    HistoryPurgePreview(Result<crate::reports::HistoryPurgePlan, String>),
    HistoryPurgeProgress(usize, usize),
    HistoryPurged(crate::reports::Performed<crate::reports::HistoryPurgeResult>),
    Schedule(crate::maintenance::TimerStatus),
    ScheduleEditPreview(
        Result<crate::schedule::EditSchedulePreview, String>,
        crate::schedule::Frequency,
    ),
    ScheduleEdited(crate::reports::Performed<&'static str>),
    ScheduleRemovePreview(Result<crate::schedule::RemoveSchedulePreview, String>),
    ScheduleRemoved(crate::reports::Performed<&'static str>),
    ScheduleDisablePreview(Result<crate::schedule::DisableSchedulePreview, String>),
    ScheduleDisabled(crate::reports::Performed<&'static str>),
    ScheduleInstallPreview(
        Result<crate::schedule::ScanSchedulePreview, String>,
        crate::schedule::Frequency,
    ),
    ScheduleInstalled(crate::reports::Performed<&'static str>),
    ScheduleEnablePreview(
        Result<crate::schedule::EnableSchedulePreview, String>,
        crate::schedule::Frequency,
    ),
    ScheduleEnabled(crate::reports::Performed<&'static str>),
    #[cfg(target_os = "linux")]
    TrashRetentionStatus(Result<crate::schedule::trash_retention::TrashRetentionStatus, String>),
    #[cfg(target_os = "linux")]
    TrashRetentionPreview(Result<TrashRetentionReviewPlan, String>, bool),
    #[cfg(target_os = "linux")]
    TrashRetentionChanged(&'static str, crate::reports::Performed<&'static str>),
}

const MAX_WORKER_EVENTS_PER_FRAME: usize = 64;

fn worker_events_for_frame(rx: &mpsc::Receiver<WorkerEvent>) -> Vec<WorkerEvent> {
    rx.try_iter().take(MAX_WORKER_EVENTS_PER_FRAME).collect()
}

fn report_scan_progress(progress: &AtomicUsize, visited: &mut usize) {
    *visited = visited.saturating_add(1);
    if *visited == 1 || visited.is_multiple_of(128) {
        progress.store(*visited, Ordering::Relaxed);
    }
}

fn check(ctx: Ctx, kinds: Vec<ToolKind>, tx: mpsc::Sender<WorkerEvent>) {
    thread::spawn(move || {
        let result = operation_worker(|| Ok(check_tools_parallel(&ctx, &kinds)));
        let _ = tx.send(WorkerEvent::Checked(result));
    });
}

fn inspect_self_update(ctx: Ctx, tx: mpsc::Sender<WorkerEvent>) {
    thread::spawn(move || {
        let result = operation_worker(|| crate::application::self_update_plan(&ctx));
        let _ = tx.send(WorkerEvent::SelfUpdatePreview(result));
    });
}

fn is_confirmation_navigation_or_cancellation(event: &Event) -> bool {
    matches!(
        event,
        Event::Key(KeyEvent {
            code: KeyCode::Esc,
            ..
        }) | Event::Key(KeyEvent {
            code: KeyCode::Char('n' | 'q' | 'j' | 'k'),
            modifiers: KeyModifiers::NONE,
            ..
        }) | Event::Key(KeyEvent {
            code: KeyCode::Up
                | KeyCode::Down
                | KeyCode::PageUp
                | KeyCode::PageDown
                | KeyCode::Home
                | KeyCode::End,
            modifiers: KeyModifiers::NONE,
            ..
        }) | Event::Key(KeyEvent {
            code: KeyCode::Char('c'),
            modifiers: KeyModifiers::CONTROL,
            ..
        })
    )
}

fn discard_pending_terminal_input(
    retain_navigation_and_cancellation: bool,
) -> io::Result<VecDeque<Event>> {
    let mut retained = VecDeque::new();
    for _ in 0..1024 {
        if !event::poll(Duration::ZERO)? {
            return Ok(retained);
        }
        let input = event::read()?;
        if retain_navigation_and_cancellation && is_confirmation_navigation_or_cancellation(&input)
        {
            retained.push_back(input);
        }
    }
    Err(io::Error::other(
        "too much pending input; review the plan again",
    ))
}

fn draw_confirmation_frame(
    newly_visible: bool,
    mut discard: impl FnMut(bool) -> io::Result<VecDeque<Event>>,
    draw: impl FnOnce() -> io::Result<()>,
) -> io::Result<VecDeque<Event>> {
    if newly_visible {
        discard(false)?;
    }
    draw()?;
    if newly_visible {
        discard(true)
    } else {
        Ok(VecDeque::new())
    }
}

fn confirmation_surfaces(app: &App) -> [bool; 25] {
    [
        app.confirmation,
        app.self_update_plan.is_some(),
        app.managed_plan.is_some(),
        !app.managed_batch_plans.is_empty(),
        app.artifact_plan.is_some(),
        app.artifact_confirm,
        app.bytecode_plan.is_some(),
        app.bytecode_batch_plan.is_some(),
        app.temp_review_plan.is_some(),
        app.temp_review_confirm,
        app.trim_plan.is_some(),
        app.go_test_plan.is_some(),
        app.container_plan.is_some(),
        app.network_plan.is_some(),
        app.build_cache_plan.is_some(),
        app.trash_removal_plan.is_some(),
        app.history_purge_plan.is_some(),
        app.schedule_edit_plan.is_some(),
        app.schedule_remove_plan.is_some(),
        app.schedule_install_plan.is_some(),
        app.schedule_enable_plan.is_some(),
        app.schedule_disable_plan.is_some(),
        app.settings_prompt == Some(SettingsPrompt::Save),
        app.settings_prompt == Some(SettingsPrompt::Discard),
        {
            #[cfg(target_os = "linux")]
            {
                app.trash_retention_plan.is_some()
            }
            #[cfg(not(target_os = "linux"))]
            {
                false
            }
        },
    ]
}

fn newly_visible_confirmation(previous: &[bool], current: &[bool]) -> bool {
    previous.iter().zip(current).any(|(old, new)| !old && *new)
}

fn start_managed_preview(
    ctx: Ctx,
    tool: ToolKind,
    cancel: Arc<AtomicBool>,
    tx: mpsc::Sender<WorkerEvent>,
) {
    thread::spawn(move || {
        let result = operation_worker(|| crate::managed_cleanup::preview(&ctx, tool, &cancel));
        let _ = tx.send(WorkerEvent::ManagedPreview(result));
    });
}

fn start_managed_batch_preview(
    ctx: Ctx,
    tools: Vec<ToolKind>,
    cancel: Arc<AtomicBool>,
    tx: mpsc::Sender<WorkerEvent>,
) {
    thread::spawn(move || {
        let result = preview_managed_batch(&ctx, &tools, &cancel);
        let _ = tx.send(WorkerEvent::ManagedBatchPreview(result));
    });
}

fn preview_managed_batch(
    ctx: &Ctx,
    tools: &[ToolKind],
    cancel: &AtomicBool,
) -> std::result::Result<Vec<ManagedCleanupTarget>, ManagedBatchPreviewFailure> {
    let mut plans = Vec::with_capacity(tools.len());
    for tool in tools {
        if cancel.load(Ordering::Relaxed) {
            return Err(ManagedBatchPreviewFailure {
                tool: None,
                error: "managed cleanup preview cancelled".into(),
                tools: tools.to_vec(),
                cancelled: true,
            });
        }
        match operation_worker(|| {
            crate::managed_cleanup::preview_including_absent(ctx, *tool, cancel)
        }) {
            Ok(plan) => plans.push(ManagedCleanupTarget { tool: *tool, plan }),
            Err(error) => {
                let cancelled = cancel.load(Ordering::Relaxed);
                return Err(ManagedBatchPreviewFailure {
                    tool: (!cancelled).then_some(*tool),
                    error,
                    tools: tools.to_vec(),
                    cancelled,
                });
            }
        }
    }
    Ok(plans)
}

fn preflight_managed_batch(
    ctx: &Ctx,
    targets: &[ManagedCleanupTarget],
    cancel: &AtomicBool,
) -> std::result::Result<(), ManagedBatchPreviewFailure> {
    let tools = targets.iter().map(|target| target.tool).collect::<Vec<_>>();
    for target in targets {
        if cancel.load(Ordering::Relaxed) {
            return Err(ManagedBatchPreviewFailure {
                tool: None,
                error: "managed cleanup cancelled during batch preflight".into(),
                tools,
                cancelled: true,
            });
        }
        let fresh = match operation_worker(|| {
            crate::managed_cleanup::preview_including_absent(ctx, target.tool, cancel)
        }) {
            Ok(fresh) => fresh,
            Err(error) => {
                let cancelled = cancel.load(Ordering::Relaxed);
                return Err(ManagedBatchPreviewFailure {
                    tool: (!cancelled).then_some(target.tool),
                    error,
                    tools,
                    cancelled,
                });
            }
        };
        if let Err(error) = crate::managed_cleanup::validate_removal_plan(&fresh) {
            return Err(ManagedBatchPreviewFailure {
                tool: Some(target.tool),
                error: format!("{error:#}"),
                tools,
                cancelled: false,
            });
        }
        if fresh.preview_token != target.plan.preview_token {
            return Err(ManagedBatchPreviewFailure {
                tool: Some(target.tool),
                error: "managed paths changed after review; no cleanup was started".into(),
                tools,
                cancelled: false,
            });
        }
    }
    Ok(())
}

fn run_managed_batch(
    ctx: &Ctx,
    targets: &[ManagedCleanupTarget],
    cancel: &AtomicBool,
) -> ManagedBatchResult {
    let mut items = targets
        .iter()
        .map(|target| ManagedBatchItem {
            tool: target.tool,
            status: "skipped",
            detail: None,
            history_warning: None,
        })
        .collect::<Vec<_>>();
    if let Err(failure) = preflight_managed_batch(ctx, targets, cancel) {
        if let Some(tool) = failure.tool
            && let Some(item) = items.iter_mut().find(|item| item.tool == tool)
        {
            item.status = "failed/uncertain";
            item.detail = Some(failure.error);
        }
        return ManagedBatchResult {
            items,
            cancelled: failure.cancelled,
        };
    }

    let mut cancelled = false;
    for (index, target) in targets.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }
        if target.plan.selected_entries.is_empty() && target.plan.links.is_empty() {
            match operation_worker(|| {
                crate::managed_cleanup::preview_including_absent(ctx, target.tool, cancel)
            }) {
                Ok(fresh)
                    if fresh.preview_token == target.plan.preview_token
                        && fresh.selected_entries.is_empty()
                        && fresh.links.is_empty() =>
                {
                    items[index].status = "preserved";
                    let paths = target
                        .plan
                        .preserved_entries
                        .iter()
                        .chain(&target.plan.preserved_links)
                        .map(|path| crate::sweep::display_path(path))
                        .collect::<Vec<_>>();
                    items[index].detail = Some(format!(
                        "No sealed installation or recorded link was eligible; preserved paths: {}",
                        if paths.is_empty() {
                            "none listed".into()
                        } else {
                            paths.join(", ")
                        }
                    ));
                }
                Ok(_) => {
                    items[index].status = "failed/uncertain";
                    items[index].detail =
                        Some("managed paths changed before absence could be verified".into());
                    break;
                }
                Err(error) => {
                    cancelled = cancel.load(Ordering::Relaxed);
                    if cancelled {
                        items[index].status = "skipped";
                        items[index].detail = Some("absence verification was cancelled".into());
                    } else {
                        items[index].status = "failed/uncertain";
                        items[index].detail = Some(error);
                    }
                    break;
                }
            }
            continue;
        }

        let performed = crate::reports::perform_managed_cleanup(ctx, &target.plan, cancel);
        let history_warning = performed.history_warning;
        match performed.result {
            Ok("verified_selected_absent") => {
                items[index].status = "verified selected absent";
                let paths = target
                    .plan
                    .preserved_entries
                    .iter()
                    .chain(&target.plan.preserved_links)
                    .map(|path| crate::sweep::display_path(path))
                    .collect::<Vec<_>>();
                items[index].detail = Some(format!(
                    "Selected sealed paths and recorded links are absent; managed root retained. Preserved paths: {}",
                    if paths.is_empty() {
                        "none listed".into()
                    } else {
                        paths.join(", ")
                    }
                ));
                items[index].history_warning = history_warning;
                if items[index].history_warning.is_some() {
                    break;
                }
            }
            Ok(status) => {
                items[index].status = "failed/uncertain";
                items[index].detail = Some(format!("cleanup returned {status}"));
                items[index].history_warning = history_warning;
                break;
            }
            Err(error) => {
                items[index].status = "failed/uncertain";
                items[index].detail = Some(error);
                items[index].history_warning = history_warning;
                cancelled = cancel.load(Ordering::Relaxed);
                break;
            }
        }
    }
    ManagedBatchResult { items, cancelled }
}

fn operation_worker<T>(operation: impl FnOnce() -> anyhow::Result<T>) -> Result<T, String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(result) => result.map_err(|error| format!("{error:#}")),
        Err(_) => Err("worker panicked; operation outcome may be unknown".into()),
    }
}

fn inspect_settings(config: Option<PathBuf>, tx: mpsc::Sender<WorkerEvent>) {
    thread::spawn(move || {
        let result = operation_worker(|| {
            let path = crate::config::config_path(config.as_deref())?;
            crate::config::read_document(&path)
        });
        let _ = tx.send(WorkerEvent::SettingsLoaded(result));
    });
}

fn inspect_trash(cancel: Arc<AtomicBool>, age: Option<Duration>, tx: mpsc::Sender<WorkerEvent>) {
    thread::spawn(move || {
        let report = crate::trash::status(&cancel);
        let event = match age {
            Some(age) => WorkerEvent::TrashPreview(
                crate::trash::retention_preview(report, age).map_err(|err| format!("{err:#}")),
            ),
            None => WorkerEvent::Trash(report),
        };
        let _ = tx.send(event);
    });
}

fn inspect_doctor(
    ctx: Ctx,
    config: Option<PathBuf>,
    profile: Option<String>,
    cancel: Arc<AtomicBool>,
    tx: mpsc::Sender<WorkerEvent>,
) {
    thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut capabilities = crate::doctor::capabilities(&ctx.home, ctx.offline, &cancel);
            if cancel.load(Ordering::Relaxed) {
                capabilities.cancelled = true;
                let issues = capabilities
                    .installation_diagnostic()
                    .into_iter()
                    .chain(std::iter::once(
                        "Doctor checks were cancelled; remaining checks were not started. An active filesystem call may finish first."
                            .into(),
                    ))
                    .collect();
                return (issues, None, capabilities);
            }
            let diagnostics = diagnose_with_config(&ctx, config.as_deref(), profile.as_deref());
            let mut issues = diagnostics.issues;
            capabilities
                .actionable_diagnostics
                .extend(diagnostics.warnings);
            if cancel.load(Ordering::Relaxed) {
                capabilities.cancelled = true;
                issues.push(
                    "Doctor checks were cancelled after the current diagnostic checks finished; remaining checks were not started. An active filesystem call may finish first.".into(),
                );
                return (issues, None, capabilities);
            }
            if let Some(diagnostic) = capabilities.installation_diagnostic() {
                issues.push(diagnostic);
            }
            let available = crate::maintenance::available_space(&ctx.home);
            if cancel.load(Ordering::Relaxed) {
                capabilities.cancelled = true;
                issues.push(
                    "Doctor checks were cancelled after the current filesystem query finished; remaining checks were not started.".into(),
                );
                return (issues, None, capabilities);
            }
            (issues, available, capabilities)
        }));
        let (issues, available, capabilities) = match result {
            Ok((issues, available, capabilities)) => (issues, available, Some(capabilities)),
            Err(_) => (
                vec!["Doctor worker failed; diagnostics are incomplete".into()],
                None,
                None,
            ),
        };
        let _ = tx.send(WorkerEvent::Diagnosed(issues, available, capabilities));
    });
}

pub type ScanRequest = (
    Vec<PathBuf>,
    Vec<PathBuf>,
    Option<Duration>,
    Option<Vec<crate::sweep::Ecosystem>>,
    Option<Vec<PathBuf>>,
);

#[derive(Clone)]
pub(crate) struct BytecodeRequest {
    pub file: PathBuf,
    pub roots: Vec<PathBuf>,
    pub exclusions: Vec<PathBuf>,
    pub age: Option<Duration>,
}

impl BytecodeRequest {
    fn scope(
        &self,
        config: Option<&std::path::Path>,
        profile: Option<&str>,
    ) -> anyhow::Result<crate::bytecode::Scope> {
        let (roots, exclusions, age, enabled) = crate::application::resolve_scan_config(
            config,
            profile,
            &self.roots,
            &self.exclusions,
            self.age,
        )?;
        Ok(crate::bytecode::Scope {
            roots,
            exclusions,
            older_than_seconds: age.map(|age| age.as_secs()),
            enabled,
        })
    }
}

fn unattempted_artifact_batch(
    plan: &crate::artifact_cleanup::ArtifactBatchPlan,
    error: String,
    cancelled: bool,
) -> crate::reports::ArtifactBatchReport {
    crate::reports::ArtifactBatchReport {
        items: plan
            .items
            .iter()
            .map(|item| crate::reports::ArtifactBatchItemReport {
                target: item.target.clone(),
                status: "not_attempted",
                attempted: false,
                error: Some(error.clone()),
                history_warning: None,
            })
            .collect(),
        complete: false,
        cancelled,
        error: Some(error),
    }
}

fn start_schedule_request(
    command: crate::application::ScheduleCommand,
    config: Option<PathBuf>,
    profile: Option<String>,
    tx: mpsc::Sender<WorkerEvent>,
) {
    use crate::application::ScheduleCommand as Schedule;
    thread::spawn(move || match command {
        Schedule::Preview {
            frequency,
            paths,
            exclude,
        }
        | Schedule::Add {
            frequency,
            paths,
            exclude,
            ..
        } => {
            let frequency = match crate::application::resolve_schedule_frequency_for(
                config.as_deref(),
                profile.as_deref(),
                frequency,
            ) {
                Ok(frequency) => frequency,
                Err(error) => {
                    let _ = tx.send(WorkerEvent::ScheduleInstallPreview(
                        Err(format!("{error:#}")),
                        crate::schedule::Frequency::Weekly,
                    ));
                    return;
                }
            };
            let result = operation_worker(|| {
                let configured = crate::application::schedule_uses_config(&paths, &exclude)?;
                let executable = std::env::current_exe()?.canonicalize()?;
                if configured {
                    crate::schedule::preview_configured_install(
                        &executable,
                        config.as_deref(),
                        profile.as_deref(),
                        frequency,
                    )
                } else {
                    crate::schedule::preview_scan(&executable, &paths, &exclude, frequency)
                }
            });
            let _ = tx.send(WorkerEvent::ScheduleInstallPreview(result, frequency));
        }
        Schedule::PreviewEdit {
            frequency,
            paths,
            exclude,
        }
        | Schedule::Edit {
            frequency,
            paths,
            exclude,
            ..
        } => {
            let frequency = match crate::application::resolve_schedule_frequency_for(
                config.as_deref(),
                profile.as_deref(),
                frequency,
            ) {
                Ok(frequency) => frequency,
                Err(error) => {
                    let _ = tx.send(WorkerEvent::ScheduleEditPreview(
                        Err(format!("{error:#}")),
                        crate::schedule::Frequency::Weekly,
                    ));
                    return;
                }
            };
            let result = operation_worker(|| {
                let configured = crate::application::schedule_uses_config(&paths, &exclude)?;
                let executable = std::env::current_exe()?.canonicalize()?;
                if configured {
                    crate::schedule::preview_configured_edit(
                        &executable,
                        config.as_deref(),
                        profile.as_deref(),
                        frequency,
                    )
                } else {
                    crate::schedule::preview_edit(&executable, &paths, &exclude, frequency)
                }
            });
            let _ = tx.send(WorkerEvent::ScheduleEditPreview(result, frequency));
        }
        Schedule::PreviewEnable {
            frequency,
            paths,
            exclude,
        }
        | Schedule::Enable {
            frequency,
            paths,
            exclude,
            ..
        } => {
            let frequency = match crate::application::resolve_schedule_frequency_for(
                config.as_deref(),
                profile.as_deref(),
                frequency,
            ) {
                Ok(frequency) => frequency,
                Err(error) => {
                    let _ = tx.send(WorkerEvent::ScheduleEnablePreview(
                        Err(format!("{error:#}")),
                        crate::schedule::Frequency::Weekly,
                    ));
                    return;
                }
            };
            let result = operation_worker(|| {
                let configured = crate::application::schedule_uses_config(&paths, &exclude)?;
                let executable = std::env::current_exe()?.canonicalize()?;
                if configured {
                    crate::schedule::preview_configured_enable(
                        &executable,
                        config.as_deref(),
                        profile.as_deref(),
                        frequency,
                    )
                } else {
                    crate::schedule::preview_enable(&executable, &paths, &exclude, frequency)
                }
            });
            let _ = tx.send(WorkerEvent::ScheduleEnablePreview(result, frequency));
        }
        Schedule::PreviewRemove | Schedule::Remove { .. } => {
            let _ = tx.send(WorkerEvent::ScheduleRemovePreview(operation_worker(
                crate::schedule::preview_remove,
            )));
        }
        Schedule::PreviewDisable | Schedule::Disable { .. } => {
            let _ = tx.send(WorkerEvent::ScheduleDisablePreview(operation_worker(
                crate::schedule::preview_disable,
            )));
        }
        #[cfg(target_os = "linux")]
        Schedule::TrashRetention { command } => {
            use crate::application::TrashRetentionScheduleCommand as TrashRetention;
            let preview_install = |location: PathBuf, older_than: Duration, read_only| {
                let result = operation_worker(|| {
                    let executable = std::env::current_exe()?.canonicalize()?;
                    let config_path = crate::config::config_path(config.as_deref())?;
                    crate::schedule::trash_retention::preview_trash_retention(
                        &executable,
                        &config_path,
                        &location,
                        older_than,
                    )
                    .map(TrashRetentionReviewPlan::Install)
                });
                let _ = tx.send(WorkerEvent::TrashRetentionPreview(result, read_only));
            };
            let preview_action = |action, read_only| {
                let result = operation_worker(|| match action {
                    "enable" => crate::schedule::trash_retention::preview_trash_retention_enable()
                        .map(TrashRetentionReviewPlan::Enable),
                    "disable" => {
                        crate::schedule::trash_retention::preview_trash_retention_disable()
                            .map(TrashRetentionReviewPlan::Disable)
                    }
                    _ => crate::schedule::trash_retention::preview_trash_retention_remove()
                        .map(TrashRetentionReviewPlan::Remove),
                });
                let _ = tx.send(WorkerEvent::TrashRetentionPreview(result, read_only));
            };
            match command {
                TrashRetention::Preview {
                    location,
                    older_than,
                } => preview_install(location, older_than, true),
                TrashRetention::Install {
                    location,
                    older_than,
                    ..
                } => preview_install(location, older_than, false),
                TrashRetention::PreviewEnable => preview_action("enable", true),
                TrashRetention::Enable { .. } => preview_action("enable", false),
                TrashRetention::PreviewDisable => preview_action("disable", true),
                TrashRetention::Disable { .. } => preview_action("disable", false),
                TrashRetention::PreviewRemove => preview_action("remove", true),
                TrashRetention::Remove { .. } => preview_action("remove", false),
                TrashRetention::Status => {
                    let result = operation_worker(|| {
                        crate::schedule::trash_retention::trash_retention_status()
                    });
                    let _ = tx.send(WorkerEvent::TrashRetentionStatus(result));
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        Schedule::TrashRetention { .. } => {}
        Schedule::List => {}
    });
}

#[derive(Default)]
pub(crate) struct LaunchOptions {
    pub config: Option<PathBuf>,
    pub profile: Option<String>,
    pub temp_cleanup_requested: bool,
    pub trim_preview_target: Option<PathBuf>,
    pub trash_age: Option<Duration>,
    pub trash_target: Option<(PathBuf, Vec<String>, Duration)>,
    pub trash_retention_target: Option<(PathBuf, Duration)>,
    pub trash_empty_target: Option<PathBuf>,
    pub container_target: Option<(String, String)>,
    pub network_target: Option<(String, String)>,
    pub build_cache_target: Option<(String, String, bool)>,
    pub bytecode_target: Option<BytecodeRequest>,
    pub artifact_scope: Option<(Vec<PathBuf>, Vec<PathBuf>, Option<Duration>)>,
    pub artifact_target: Option<BytecodeRequest>,
    pub shared_cache_target: Option<PathBuf>,
    pub go_test_target: Option<PathBuf>,
    pub history_purge_preview: Option<Duration>,
    pub managed_scope: Option<Vec<ToolKind>>,
    pub schedule_request: Option<crate::application::ScheduleCommand>,
    pub self_update_requested: bool,
}

pub fn run(
    ctx: &Ctx,
    start: Start,
    only: Option<ToolKind>,
    selected: Option<Vec<ToolKind>>,
    scan_request: Option<ScanRequest>,
) -> Result<()> {
    run_with_config(
        ctx,
        start,
        only,
        selected,
        scan_request,
        LaunchOptions::default(),
    )
}

pub(crate) fn run_with_config(
    ctx: &Ctx,
    start: Start,
    only: Option<ToolKind>,
    selected: Option<Vec<ToolKind>>,
    scan_request: Option<ScanRequest>,
    options: LaunchOptions,
) -> Result<()> {
    let LaunchOptions {
        config,
        profile,
        temp_cleanup_requested,
        trim_preview_target,
        trash_age,
        trash_target,
        trash_retention_target,
        trash_empty_target,
        container_target,
        network_target,
        build_cache_target,
        mut bytecode_target,
        mut artifact_scope,
        mut artifact_target,
        shared_cache_target,
        go_test_target,
        history_purge_preview,
        managed_scope,
        schedule_request,
        self_update_requested,
    } = options;
    let mut worker_ctx = ctx.clone();
    worker_ctx.quiet = true;
    worker_ctx.no_progress = true;
    let kinds = selected
        .clone()
        .unwrap_or_else(|| only.map_or_else(ToolKind::all, |kind| vec![kind]));
    let (tx, rx) = mpsc::channel();
    if self_update_requested {
        inspect_self_update(worker_ctx.clone(), tx.clone());
    }
    use crate::application::ScheduleCommand as Schedule;
    let mut schedule_explicit = match schedule_request.as_ref() {
        Some(
            Schedule::Preview { paths, exclude, .. }
            | Schedule::Add { paths, exclude, .. }
            | Schedule::PreviewEdit { paths, exclude, .. }
            | Schedule::Edit { paths, exclude, .. }
            | Schedule::PreviewEnable { paths, exclude, .. }
            | Schedule::Enable { paths, exclude, .. },
        ) => !crate::application::schedule_uses_config(paths, exclude)?,
        _ => false,
    };
    let schedule_read_only = matches!(
        schedule_request,
        Some(
            Schedule::Preview { .. }
                | Schedule::PreviewEdit { .. }
                | Schedule::PreviewEnable { .. }
                | Schedule::PreviewRemove
                | Schedule::PreviewDisable
        )
    ) || {
        #[cfg(target_os = "linux")]
        {
            use crate::application::TrashRetentionScheduleCommand as TrashRetention;
            matches!(
                schedule_request.as_ref(),
                Some(Schedule::TrashRetention {
                    command: TrashRetention::Preview { .. }
                        | TrashRetention::PreviewEnable
                        | TrashRetention::PreviewDisable
                        | TrashRetention::PreviewRemove,
                })
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    };
    #[cfg(target_os = "linux")]
    let trash_retention_preparing = {
        use crate::application::TrashRetentionScheduleCommand as TrashRetention;
        matches!(
            schedule_request.as_ref(),
            Some(Schedule::TrashRetention {
                command: TrashRetention::Preview { .. }
                    | TrashRetention::Install { .. }
                    | TrashRetention::PreviewEnable
                    | TrashRetention::Enable { .. }
                    | TrashRetention::PreviewDisable
                    | TrashRetention::Disable { .. }
                    | TrashRetention::PreviewRemove
                    | TrashRetention::Remove { .. },
            })
        )
    };
    #[cfg(target_os = "linux")]
    let trash_retention_status_loading = start == Start::Automation
        || matches!(
            schedule_request.as_ref(),
            Some(Schedule::TrashRetention {
                command: crate::application::TrashRetentionScheduleCommand::Status,
            })
        );
    let schedule_install_preparing = matches!(
        schedule_request,
        Some(Schedule::Preview { .. } | Schedule::Add { .. })
    );
    let schedule_edit_preparing = matches!(
        schedule_request,
        Some(Schedule::PreviewEdit { .. } | Schedule::Edit { .. })
    );
    let schedule_enable_preparing = matches!(
        schedule_request,
        Some(Schedule::PreviewEnable { .. } | Schedule::Enable { .. })
    );
    let schedule_remove_preparing = matches!(
        schedule_request,
        Some(Schedule::PreviewRemove | Schedule::Remove { .. })
    );
    let schedule_disable_preparing = matches!(
        schedule_request,
        Some(Schedule::PreviewDisable | Schedule::Disable { .. })
    );
    if let Some(request) = schedule_request {
        start_schedule_request(request, config.clone(), profile.clone(), tx.clone());
    }
    let mut session = TerminalSession::start()?;
    let mut terminal = ratatui::Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut doctor_ctx = worker_ctx.clone();
    doctor_ctx.dry_run = true;
    let doctor_cancel = Arc::new(AtomicBool::new(false));
    if !self_update_requested {
        check(worker_ctx.clone(), kinds.clone(), tx.clone());
        inspect_doctor(
            doctor_ctx.clone(),
            config.clone(),
            profile.clone(),
            doctor_cancel.clone(),
            tx.clone(),
        );
        let maintenance_tx = tx.clone();
        thread::spawn(move || {
            let result = operation_worker(|| Ok(crate::maintenance::trim_status()));
            let _ = maintenance_tx.send(WorkerEvent::Maintenance(result));
        });
    }
    let trim_preparing = trim_preview_target.is_some();
    let trim_read_only = trim_preparing;
    if let Some(mount) = trim_preview_target {
        let tx = tx.clone();
        thread::spawn(move || {
            let result = operation_worker(|| crate::maintenance::trim_plan(&mount));
            let _ = tx.send(WorkerEvent::TrimPreview(result));
        });
    }
    let scan_cancel = Arc::new(AtomicBool::new(false));
    let managed_cancel = Arc::new(AtomicBool::new(false));
    let managed_preparing = managed_scope.as_ref().is_some_and(|scope| scope.len() == 1);
    if let Some(tool) = managed_scope
        .as_ref()
        .filter(|scope| scope.len() == 1)
        .map(|scope| scope[0])
    {
        let tx = tx.clone();
        let cancel = managed_cancel.clone();
        let worker_ctx = worker_ctx.clone();
        thread::spawn(move || {
            let result =
                operation_worker(|| crate::managed_cleanup::preview(&worker_ctx, tool, &cancel));
            let _ = tx.send(WorkerEvent::ManagedPreview(result));
        });
    }
    let bytecode_preparing = bytecode_target.is_some();
    if let Some(request) = bytecode_target.clone() {
        let tx = tx.clone();
        let cancel = scan_cancel.clone();
        let config = config.clone();
        let profile = profile.clone();
        thread::spawn(move || {
            let result = operation_worker(|| {
                let scope = request.scope(config.as_deref(), profile.as_deref())?;
                crate::bytecode::preview(&scope, &request.file, &cancel)
            });
            let _ = tx.send(WorkerEvent::BytecodePreview(result));
        });
    }
    let artifact_preparing = artifact_target.is_some() || shared_cache_target.is_some();
    if let Some(request) = artifact_target.clone() {
        let tx = tx.clone();
        let cancel = scan_cancel.clone();
        let config = config.clone();
        let profile = profile.clone();
        thread::spawn(move || {
            let result = operation_worker(|| {
                let scope = request.scope(config.as_deref(), profile.as_deref())?;
                crate::artifact_cleanup::preview(&scope, &request.file, &cancel)
            });
            let _ = tx.send(WorkerEvent::ArtifactPreview(result));
        });
    }
    if let Some(target) = shared_cache_target.clone() {
        let tx = tx.clone();
        let cancel = scan_cancel.clone();
        thread::spawn(move || {
            let result =
                operation_worker(|| crate::shared_cache_cleanup::preview(&target, &cancel));
            let _ = tx.send(WorkerEvent::SharedCachePreview(result));
        });
    }
    let cache_cancel = Arc::new(AtomicBool::new(false));
    let trash_cancel = Arc::new(AtomicBool::new(false));
    let temp_cancel = Arc::new(AtomicBool::new(false));
    if temp_cleanup_requested {
        let tx = tx.clone();
        let home = ctx.home.clone();
        let bindir = ctx.bindir.clone();
        let cancel = temp_cancel.clone();
        thread::spawn(move || {
            let result =
                operation_worker(|| crate::temp_cleanup::preview(&home, &bindir, &[], &cancel));
            let _ = tx.send(WorkerEvent::TempPreview(result, false));
        });
    }
    let history_purge_cancel = Arc::new(AtomicBool::new(false));
    let history_purge_preparing = history_purge_preview.is_some();
    let history_purge_read_only = history_purge_preparing;
    if let Some(age) = history_purge_preview {
        let tx = tx.clone();
        let home = ctx.home.clone();
        let cancel = history_purge_cancel.clone();
        thread::spawn(move || {
            let result =
                operation_worker(|| crate::reports::preview_history_purge(&home, age, &cancel));
            let _ = tx.send(WorkerEvent::HistoryPurgePreview(result));
        });
    }
    let containers_running = start == Start::Containers;
    let schedule_running = start == Start::Automation;
    if schedule_running {
        let schedule_tx = tx.clone();
        thread::spawn(move || {
            let _ = schedule_tx.send(WorkerEvent::Schedule(crate::schedule::status()));
        });
        #[cfg(target_os = "linux")]
        {
            let tx = tx.clone();
            thread::spawn(move || {
                let result =
                    operation_worker(crate::schedule::trash_retention::trash_retention_status);
                let _ = tx.send(WorkerEvent::TrashRetentionStatus(result));
            });
        }
    }
    let history_running = matches!(start, Start::Dashboard | Start::Reports);
    if history_running {
        let tx = tx.clone();
        let home = ctx.home.clone();
        thread::spawn(move || {
            let _ = tx.send(WorkerEvent::History(
                crate::reports::read(&home).map_err(|err| format!("{err:#}")),
            ));
        });
    }
    let settings_loading = true;
    inspect_settings(config.clone(), tx.clone());
    if containers_running {
        let tx = tx.clone();
        let offline = ctx.offline;
        let dry_run = ctx.dry_run;
        thread::spawn(move || {
            let _ = tx.send(WorkerEvent::Containers(
                crate::containers::status_with_dry_run(offline, dry_run),
            ));
        });
    }
    let container_preparing = container_target.is_some();
    if let Some((engine, id)) = container_target {
        let tx = tx.clone();
        let offline = ctx.offline;
        thread::spawn(move || {
            let result =
                operation_worker(|| crate::containers::removal_preview(&engine, &id, offline));
            let _ = tx.send(WorkerEvent::ContainerPreview(result));
        });
    }
    let network_preparing = network_target.is_some();
    if let Some((engine, id)) = network_target {
        let tx = tx.clone();
        let offline = ctx.offline;
        thread::spawn(move || {
            let result = operation_worker(|| {
                crate::containers::network_removal_preview(&engine, &id, offline)
            });
            let _ = tx.send(WorkerEvent::NetworkPreview(result));
        });
    }
    let build_cache_preparing = build_cache_target.is_some();
    let build_cache_read_only = build_cache_target
        .as_ref()
        .is_some_and(|(_, _, read_only)| *read_only);
    if let Some((builder, id, _)) = build_cache_target {
        let tx = tx.clone();
        let offline = ctx.offline;
        thread::spawn(move || {
            let result =
                operation_worker(|| crate::containers::build_cache_preview(&builder, &id, offline));
            let _ = tx.send(WorkerEvent::BuildCachePreview(result));
        });
    }
    let trash_running = start == Start::Trash;
    if trash_running {
        inspect_trash(trash_cancel.clone(), trash_age, tx.clone());
    }
    let trash_removal_preparing =
        trash_target.is_some() || trash_retention_target.is_some() || trash_empty_target.is_some();
    if let Some((location, names, age)) = trash_target {
        let tx = tx.clone();
        let cancel = trash_cancel.clone();
        thread::spawn(move || {
            let result = operation_worker(|| {
                crate::trash::named_batch_preview(&location, &names, age, &cancel)
            });
            let _ = tx.send(WorkerEvent::TrashRemovalPreview(result));
        });
    }
    if let Some((location, age)) = trash_retention_target {
        let tx = tx.clone();
        let cancel = trash_cancel.clone();
        thread::spawn(move || {
            let result = operation_worker(|| {
                let preview = crate::trash::retention_batch_preview(&location, age, &cancel)?;
                preview.plan.ok_or_else(|| {
                    anyhow::anyhow!(
                        "No eligible items; {} newer/unknown, {} unsupported.",
                        preview.selection.newer_or_unknown,
                        preview.selection.unsupported
                    )
                })
            });
            let _ = tx.send(WorkerEvent::TrashRemovalPreview(result));
        });
    }
    if let Some(location) = trash_empty_target {
        let tx = tx.clone();
        let cancel = trash_cancel.clone();
        thread::spawn(move || {
            let result = operation_worker(|| {
                crate::trash::empty_preview(&location, &cancel)?.ok_or_else(|| {
                    anyhow::anyhow!("No files in the selected Trash location; metadata may remain.")
                })
            });
            let _ = tx.send(WorkerEvent::TrashRemovalPreview(result));
        });
    }
    let cache_running = start == Start::Cache && shared_cache_target.is_none();
    if cache_running {
        let cancel = cache_cancel.clone();
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send(WorkerEvent::Cache(crate::cache::inventory(&cancel)));
        });
    }
    let go_test_preparing = go_test_target.is_some();
    if let Some(path) = go_test_target {
        let tx = tx.clone();
        thread::spawn(move || {
            let result = operation_worker(|| crate::cache::go_test_expiration_preview(&path));
            let _ = tx.send(WorkerEvent::GoTestPreview(result));
        });
    }
    let scan_running = scan_request.is_some();
    let scan_progress = Arc::new(AtomicUsize::new(0));
    let cli_preview_read_only = scan_request
        .as_ref()
        .is_some_and(|(_, _, _, _, selected)| selected.is_some());
    let preview_mode = cli_preview_read_only;
    if let Some((paths, exclude, older_than, enabled, preview_selection)) = scan_request {
        let tx = tx.clone();
        let cancel = scan_cancel.clone();
        let progress = scan_progress.clone();
        thread::spawn(move || {
            let mut visited = 0usize;
            let report = operation_worker(|| {
                crate::sweep::scan_with_policy(
                    &paths,
                    &exclude,
                    older_than,
                    enabled.as_deref(),
                    &cancel,
                    |_| report_scan_progress(&progress, &mut visited),
                )
            });
            if let Some(selected) = preview_selection {
                let plan = report.and_then(|report| {
                    operation_worker(|| {
                        crate::sweep::preview_with_cancel(report, &selected, &cancel)
                    })
                });
                let _ = tx.send(WorkerEvent::Previewed(plan));
            } else {
                let _ = tx.send(WorkerEvent::Scanned(report));
            }
        });
    }
    let result = (|| -> Result<()> {
        let mut self_update_failed = false;
        let mut app = App {
            reports: None,
            startup_checks: StartupChecks {
                toolchains: !self_update_requested,
                doctor: !self_update_requested,
                maintenance: !self_update_requested,
            },
            toolchain_check_failed: false,
            maintenance_check_failed: false,
            page: start,
            help: false,
            help_scroll: 0,
            selected: 0,
            confirmation: false,
            updating: false,
            self_update_preparing: self_update_requested,
            self_update_command: self_update_requested,
            self_update_plan: None,
            message: if self_update_requested {
                "Preparing Upkit self-update preview…".into()
            } else if go_test_preparing {
                "Preparing Go test-cache preview…".into()
            } else if history_purge_preparing {
                "Preparing read-only history purge preview…".into()
            } else if temp_cleanup_requested {
                "Inspecting Upkit link staging directories…".into()
            } else if trim_preparing {
                "Preparing read-only TRIM preview…".into()
            } else if managed_preparing {
                "Inspecting managed tool files…".into()
            } else {
                String::new()
            },
            issues: None,
            doctor_available_bytes: None,
            doctor_capabilities: None,
            doctor_scroll: 0,
            doctor_filter: String::new(),
            doctor_search: None,
            dashboard_scroll: 0,
            marked: if managed_scope.is_some() {
                Vec::new()
            } else {
                selected.unwrap_or_default()
            },
            toolchain_filter: String::new(),
            toolchain_search: None,
            force: ctx.force,
            managed_mode: managed_scope.is_some(),
            managed_scope: managed_scope.clone(),
            managed_preparing,
            managed_running: false,
            managed_plan: None,
            managed_batch_plans: Vec::new(),
            managed_batch_review_scroll: 0,
            managed_batch_review_rows: 0,
            managed_batch_review_lines: 0,
            managed_batch_review_area: Rect::default(),
            managed_batch_review_content: None,
            managed_current: managed_scope
                .as_ref()
                .and_then(|scope| (scope.len() == 1).then_some(scope[0])),
            managed_detail: false,
            managed_detail_scroll: 0,
            managed_result: None,
            managed_result_scroll: 0,
            scan: None,
            scan_running,
            scan_visited: 0,
            scan_scroll: 0,
            artifact_filter: String::new(),
            artifact_sort: ArtifactSort::default(),
            artifact_marks: Vec::new(),
            artifact_search: None,
            preview_mode,
            cli_preview_read_only,
            plan: None,
            plan_detail: false,
            detail_scroll: 0,
            artifact_preparing,
            artifact_running: false,
            artifact_plan: None,
            artifact_review_scroll: 0,
            artifact_review_rows: 0,
            artifact_review_lines: 0,
            artifact_review_width: 0,
            artifact_review_content: None,
            artifact_confirm: false,
            bytecode_preparing,
            bytecode_running: false,
            bytecode_plan: None,
            bytecode_batch_plan: None,
            bytecode_listing_running: false,
            bytecode_listing: None,
            bytecode_selected: 0,
            bytecode_marks: Vec::new(),
            maintenance: None,
            trim_selected: 0,
            trim_preparing,
            trim_running: false,
            trim_plan: None,
            trim_read_only,
            dry_run: ctx.dry_run,
            temp_mode: temp_cleanup_requested,
            temp_plan: None,
            temp_marks: Vec::new(),
            temp_selected: 0,
            temp_preparing: temp_cleanup_requested,
            temp_running: false,
            temp_review_plan: None,
            temp_review_confirm: false,
            temp_review_scroll: 0,
            temp_review_rows: 0,
            temp_review_lines: 0,
            temp_review_area: Rect::default(),
            temp_result: None,
            temp_result_scroll: 0,
            temp_inventory_scroll_offset: 0,
            cache: None,
            cache_running,
            cache_scroll: 0,
            cache_filter: String::new(),
            cache_sort: CacheSort::default(),
            cache_details: false,
            cache_search: None,
            cache_choosing: false,
            cache_selected: None,
            go_test_preparing,
            go_test_running: false,
            go_test_plan: None,
            go_test_read_only: go_test_preparing,
            trash: None,
            trash_preview: None,
            trash_age,
            trash_running,
            trash_scroll: 0,
            trash_selected: 0,
            trash_review: false,
            trash_review_scroll: 0,
            trash_removal_preparing,
            trash_marking: false,
            trash_removing: false,
            trash_removal_plan: None,
            trash_last_result: None,
            containers: None,
            containers_running,
            containers_scroll: 0,
            container_selected: 0,
            container_filter: String::new(),
            container_search: None,
            container_preparing,
            container_removing: false,
            container_plan: None,
            network_preparing,
            network_removing: false,
            network_plan: None,
            build_cache_preparing,
            build_cache_removing: false,
            build_cache_plan: None,
            build_cache_read_only,
            schedule: None,
            schedule_running,
            schedule_scroll: 0,
            schedule_read_only,
            schedule_preview_scroll: 0,
            schedule_confirmation_scroll: 0,
            schedule_confirmation_area: Rect::default(),
            schedule_confirmation_identity: None,
            schedule_confirmation_content: None,
            schedule_edit_preparing,
            schedule_edit_running: false,
            schedule_edit_plan: None,
            schedule_remove_preparing,
            schedule_remove_running: false,
            schedule_remove_plan: None,
            schedule_disable_preparing,
            schedule_disable_running: false,
            schedule_disable_plan: None,
            schedule_install_preparing,
            schedule_install_running: false,
            schedule_install_plan: None,
            schedule_enable_preparing,
            schedule_enable_running: false,
            schedule_enable_plan: None,
            #[cfg(target_os = "linux")]
            trash_retention_status: None,
            #[cfg(target_os = "linux")]
            trash_retention_status_loading,
            #[cfg(target_os = "linux")]
            trash_retention_preparing,
            #[cfg(target_os = "linux")]
            trash_retention_running: false,
            #[cfg(target_os = "linux")]
            trash_retention_plan: None,
            history: None,
            history_running,
            history_scroll: 0,
            history_oldest_first: false,
            history_filter: String::new(),
            history_search: None,
            history_purge_preparing,
            history_purging: false,
            history_purge_read_only,
            history_purge_plan: None,
            history_purge_result: None,
            history_purge_warning: None,
            history_purge_scroll: 0,
            history_purge_area: Rect::default(),
            history_purge_content: None,
            settings: None,
            settings_loading,
            theme: crate::config::Theme::Dark,
            settings_saving: false,
            settings_editor: None,
            settings_form: None,
            settings_pending_save: None,
            settings_prompt: None,
            settings_scroll: 0,
            settings_confirmation_scroll: 0,
            settings_confirmation_area: Rect::default(),
        };
        let mut visible_confirmations = confirmation_surfaces(&app);
        let mut pending_safe_input = VecDeque::new();
        let mut toolchain_refresh_notice_started = None;
        loop {
            if app.scan_running {
                app.scan_visited = scan_progress.load(Ordering::Relaxed);
            }
            for event in worker_events_for_frame(&rx) {
                match event {
                    WorkerEvent::Checked(result) => {
                        app.startup_checks.toolchains = false;
                        match result {
                            Ok(reports) => {
                                app.reports = Some(reports);
                                app.toolchain_check_failed = false;
                                app.normalize_toolchain_selection();
                                match app.message.as_str() {
                                    "Refreshing toolchain inventory…" => {
                                        app.message = "Toolchain inventory refreshed.".into();
                                    }
                                    "Toolchain inventory is already loading." => {
                                        app.message.clear();
                                    }
                                    _ => {}
                                }
                            }
                            Err(_) => {
                                app.toolchain_check_failed = true;
                                app.message =
                                    "Toolchain check failed; results are unavailable.".into();
                            }
                        }
                    }
                    WorkerEvent::ManagedPreview(result) => {
                        app.managed_preparing = false;
                        let cancelled = managed_cancel.load(Ordering::Relaxed);
                        match result {
                            Ok(_) if cancelled => {
                                app.message = "Managed cleanup preview cancelled.".into();
                                app.managed_current = None;
                            }
                            Ok(plan) => {
                                app.managed_plan = Some(plan);
                                app.message.clear();
                            }
                            Err(_) if cancelled => {
                                app.message = "Managed cleanup preview cancelled.".into();
                                app.managed_current = None;
                            }
                            Err(error) => {
                                app.message = format!("Managed cleanup preview failed: {error}");
                                app.managed_current = None;
                            }
                        }
                    }
                    WorkerEvent::ManagedBatchPreview(result) => {
                        app.managed_preparing = false;
                        app.managed_current = None;
                        let result = match result {
                            Ok(plans) if managed_cancel.load(Ordering::Relaxed) => {
                                Err(ManagedBatchPreviewFailure {
                                    tool: None,
                                    error: "managed cleanup preview cancelled".into(),
                                    tools: plans.iter().map(|target| target.tool).collect(),
                                    cancelled: true,
                                })
                            }
                            other => other,
                        };
                        match result {
                            Ok(plans) => {
                                app.managed_batch_plans = plans;
                                app.managed_batch_review_scroll = 0;
                                app.managed_batch_review_rows = 0;
                                app.managed_batch_review_lines = 0;
                                app.managed_batch_review_area = Rect::default();
                                app.managed_batch_review_content = None;
                                app.message.clear();
                            }
                            Err(failure) => {
                                app.message = if failure.cancelled {
                                    "Combined managed cleanup preview cancelled.".into()
                                } else {
                                    "Combined managed cleanup preview failed; no removals were attempted.".into()
                                };
                                app.managed_result =
                                    Some(managed_batch_preview_failure_lines(&failure).join("\n"));
                                app.managed_result_scroll = 0;
                            }
                        }
                    }
                    WorkerEvent::ManagedCleaned(performed) => {
                        app.managed_running = false;
                        let verified_selected_absent =
                            matches!(performed.result.as_deref(), Ok("verified_selected_absent"));
                        let history_warning = performed.history_warning;
                        app.message = match performed.result {
                            Ok("verified_selected_absent") => "Selected sealed installations and recorded links are absent; unverified root data may remain.".into(),
                            Ok(status) => format!("Cleanup result: {status}; inspect paths before retrying."),
                            Err(error) => format!("Managed cleanup result: {error}"),
                        };
                        if let Some(warning) = &history_warning {
                            app.message = format!("{} ({warning})", app.message);
                        }
                        if !verified_selected_absent {
                            app.managed_result = Some(app.message.clone());
                            app.managed_result_scroll = 0;
                        }
                        app.managed_current = None;
                        app.history = None;
                        check(worker_ctx.clone(), kinds.clone(), tx.clone());
                    }
                    WorkerEvent::ManagedBatchRemoved(result) => {
                        app.managed_running = false;
                        let complete = result.items.iter().all(|item| {
                            matches!(item.status, "verified selected absent" | "preserved")
                        });
                        let failed = result
                            .items
                            .iter()
                            .any(|item| item.status == "failed/uncertain");
                        let history_warning = result
                            .items
                            .iter()
                            .any(|item| item.history_warning.is_some());
                        app.message = if result.cancelled {
                            "Managed cleanup batch cancelled; inspect each target result.".into()
                        } else if complete {
                            "Managed cleanup batch finished; selected paths were removed or preserved as ineligible."
                                .into()
                        } else if failed {
                            "Managed cleanup batch stopped; inspect failed and skipped targets."
                                .into()
                        } else if history_warning {
                            "Managed cleanup batch stopped after a history warning; inspect skipped targets."
                                .into()
                        } else {
                            "Managed cleanup batch stopped; inspect skipped targets.".into()
                        };
                        app.managed_result = Some(managed_batch_result_lines(&result).join("\n"));
                        app.managed_result_scroll = 0;
                        if complete {
                            app.marked.clear();
                        }
                        app.managed_batch_review_scroll = 0;
                        app.managed_batch_review_rows = 0;
                        app.managed_batch_review_lines = 0;
                        app.managed_batch_review_area = Rect::default();
                        app.managed_batch_review_content = None;
                        app.history = None;
                        check(worker_ctx.clone(), kinds.clone(), tx.clone());
                    }
                    WorkerEvent::SettingsLoaded(result) => {
                        app.settings_loading = false;
                        if let Ok(document) = &result
                            && let Some(theme) = document_theme(document)
                        {
                            app.theme = theme;
                        }
                        app.settings = Some(result.map_err(|error| settings_error(&error)));
                    }
                    WorkerEvent::SettingsSaved(result) => {
                        app.settings_saving = false;
                        match result {
                            Ok((document, backup)) => {
                                if let Some(theme) = document_theme(&document) {
                                    app.theme = theme;
                                }
                                if let Some(editor) = &mut app.settings_editor {
                                    editor.snapshot = document.clone();
                                }
                                if let Some(form) = &mut app.settings_form {
                                    form.snapshot = document.clone();
                                    form.dirty.clear();
                                    form.input = None;
                                }
                                app.settings_prompt = None;
                                app.settings_pending_save = None;
                                app.settings = Some(Ok(document));
                                app.message =
                                    backup.map_or("Configuration saved.".into(), |path| {
                                        format!(
                                            "Configuration saved. Backup: {}",
                                            crate::sweep::display_path(&path)
                                        )
                                    });
                            }
                            Err(error) => {
                                app.message = format!("Save failed: {}", settings_error(&error))
                            }
                        }
                    }
                    WorkerEvent::ArtifactPreview(result) => {
                        app.artifact_preparing = false;
                        match result {
                            Ok(_) if scan_cancel.load(Ordering::Relaxed) => {
                                app.message = "Artifact preview cancelled.".into()
                            }
                            Ok(plan) => {
                                app.artifact_plan = Some(DirectoryPlan::Artifact(plan));
                                app.artifact_review_scroll = 0;
                                app.artifact_review_width = 0;
                                app.artifact_confirm = false;
                                app.message.clear();
                            }
                            Err(error) => app.message = format!("Artifact preview failed: {error}"),
                        }
                    }
                    WorkerEvent::ArtifactBatchPreview(result) => {
                        app.artifact_preparing = false;
                        match result {
                            Ok(_) if scan_cancel.load(Ordering::Relaxed) => {
                                app.message = "Artifact batch preview cancelled.".into()
                            }
                            Ok(plan) => {
                                app.artifact_plan = Some(DirectoryPlan::ArtifactBatch(plan));
                                app.artifact_review_scroll = 0;
                                app.artifact_review_width = 0;
                                app.artifact_review_content = None;
                                app.artifact_confirm = false;
                                app.message.clear();
                            }
                            Err(error) => {
                                app.message = format!("Artifact batch preview failed: {error}")
                            }
                        }
                    }
                    WorkerEvent::ArtifactRemoved(performed) => {
                        app.artifact_running = false;
                        let mut detail = match performed.result {
                            Ok("verified_absent") => {
                                "Artifact removed; absence verified. Reclaimed space is unknown."
                                    .into()
                            }
                            Ok(status) => format!(
                                "Removal result: {status}; inspect the path before retrying."
                            ),
                            Err(error) => format!("Artifact removal result: {error}"),
                        };
                        if let Some(warning) = performed.history_warning {
                            detail.push_str(&format!("\n{warning}"));
                        }
                        app.message = "Artifact removal finished; inspect the result.".into();
                        app.managed_result = Some(detail);
                        app.managed_result_scroll = 0;
                        app.history = None;
                        app.plan = None;
                        app.scan = None;
                    }
                    WorkerEvent::ArtifactBatchRemoved(performed) => {
                        app.artifact_running = false;
                        let mut detail = format!(
                            "Complete: {}; cancelled: {}",
                            performed.complete, performed.cancelled
                        );
                        if let Some(error) = performed.error {
                            detail.push_str(&format!("\nBatch error: {error}"));
                        }
                        for item in performed.items {
                            detail.push_str(&format!(
                                "\n{}: {}",
                                item.status,
                                crate::sweep::display_path(&item.target)
                            ));
                            if let Some(error) = item.error {
                                detail.push_str(&format!(" — {error}"));
                            }
                            if let Some(warning) = item.history_warning {
                                detail.push_str(&format!("\n  {warning}"));
                            }
                        }
                        app.message = if performed.cancelled {
                            "Artifact batch cancelled; inspect every item result.".into()
                        } else {
                            "Artifact batch finished; inspect every item result.".into()
                        };
                        app.managed_result = Some(detail);
                        app.managed_result_scroll = 0;
                        app.history = None;
                        app.plan = None;
                        app.scan = None;
                        app.artifact_marks.clear();
                    }
                    WorkerEvent::SharedCachePreview(result) => {
                        app.artifact_preparing = false;
                        match result {
                            Ok(_) if scan_cancel.load(Ordering::Relaxed) => {
                                app.message = "Shared-cache preview cancelled.".into()
                            }
                            Ok(plan) => {
                                app.artifact_plan = Some(DirectoryPlan::Cache(plan));
                                app.artifact_review_scroll = 0;
                                app.artifact_review_width = 0;
                                app.artifact_confirm = false;
                                app.message.clear();
                            }
                            Err(error) => {
                                app.message = format!("Shared-cache preview failed: {error}")
                            }
                        }
                    }
                    WorkerEvent::SharedCacheRemoved(performed) => {
                        app.artifact_running = false;
                        let mut detail = match performed.result {
                            Ok("verified_absent") => "Shared cache removed; absence verified. Reclaimed space is unknown.".into(),
                            Ok(status) => format!("Removal result: {status}; inspect the path before retrying."),
                            Err(error) => format!("Shared-cache removal result: {error}"),
                        };
                        if let Some(warning) = performed.history_warning {
                            detail.push_str(&format!("\n{warning}"));
                        }
                        app.message = "Shared-cache removal finished; inspect the result.".into();
                        app.managed_result = Some(detail);
                        app.managed_result_scroll = 0;
                        app.history = None;
                        app.cache = None;
                    }
                    WorkerEvent::BytecodeListed(result) => {
                        app.bytecode_listing_running = false;
                        match result {
                            Ok(_) if scan_cancel.load(Ordering::Relaxed) => {
                                app.message = "Bytecode listing cancelled.".into()
                            }
                            Ok(listing) => {
                                app.bytecode_listing = Some(listing);
                                app.bytecode_selected = 0;
                                app.bytecode_marks.clear();
                                app.message.clear();
                            }
                            Err(error) => app.message = format!("Bytecode listing failed: {error}"),
                        }
                    }
                    WorkerEvent::BytecodePreview(result) => {
                        app.bytecode_preparing = false;
                        match result {
                            Ok(_) if scan_cancel.load(Ordering::Relaxed) => {
                                app.message = "Bytecode preview cancelled.".into();
                            }
                            Ok(plan) => {
                                app.bytecode_listing = None;
                                app.bytecode_plan = Some(plan);
                                app.message.clear();
                            }
                            Err(error) => app.message = format!("Bytecode preview failed: {error}"),
                        }
                    }
                    WorkerEvent::BytecodeBatchPreview(result) => {
                        app.bytecode_preparing = false;
                        match result {
                            Ok(_) if scan_cancel.load(Ordering::Relaxed) => {
                                app.message = "Bytecode preview cancelled.".into()
                            }
                            Ok(plan) => {
                                app.bytecode_listing = None;
                                app.bytecode_marks.clear();
                                app.bytecode_batch_plan = Some(plan);
                                app.message.clear();
                            }
                            Err(error) => {
                                app.message = format!("Bytecode batch preview failed: {error}")
                            }
                        }
                    }
                    WorkerEvent::BytecodeBatchProgress(done, total) => {
                        if !scan_cancel.load(Ordering::Relaxed) {
                            app.message = format!(
                                "Processed {done} of {total} bytecode files; Esc requests cancellation."
                            );
                        }
                    }
                    WorkerEvent::BytecodeBatchRemoved(result) => {
                        app.bytecode_running = false;
                        let detail = match result {
                            Ok(result) => {
                                app.message = if result.complete {
                                    "Bytecode batch completed.".into()
                                } else {
                                    "Bytecode batch stopped; inspect individual results.".into()
                                };
                                let mut lines = vec![app.message.clone()];
                                for item in result.items {
                                    lines.push(format!(
                                        "{}: {}",
                                        item.status,
                                        crate::sweep::display_path(&item.file)
                                    ));
                                    if let Some(error) = item.error {
                                        lines.push(format!("  {error}"));
                                    }
                                    if let Some(warning) = item.history_warning {
                                        lines.push(format!("  {warning}"));
                                    }
                                }
                                lines.join("\n")
                            }
                            Err(error) => {
                                app.message =
                                    "Bytecode batch did not complete; inspect the result.".into();
                                error
                            }
                        };
                        app.managed_result = Some(detail);
                        app.managed_result_scroll = 0;
                        app.history = None;
                        app.plan = None;
                        app.scan = None;
                    }
                    WorkerEvent::BytecodeRemoved(performed) => {
                        app.bytecode_running = false;
                        app.message = match performed.result {
                            Ok("verified_absent") => {
                                "Bytecode removed; absence verified. Reclaimed space is unknown."
                                    .into()
                            }
                            Ok(status) => format!(
                                "Removal result: {status}; inspect the path before retrying."
                            ),
                            Err(error) => format!("Bytecode removal result: {error}"),
                        };
                        if let Some(warning) = performed.history_warning {
                            app.message = format!("{} ({warning})", app.message);
                        }
                        app.history = None;
                        app.plan = None;
                        app.scan = None;
                    }
                    WorkerEvent::Diagnosed(issues, available, capabilities) => {
                        app.startup_checks.doctor = false;
                        app.issues = Some(issues);
                        app.doctor_available_bytes = available;
                        app.doctor_capabilities = capabilities;
                    }
                    WorkerEvent::Maintenance(report) => {
                        app.startup_checks.maintenance = false;
                        match report {
                            Ok(report) => {
                                app.maintenance = Some(report);
                                app.maintenance_check_failed = false;
                            }
                            Err(_) => {
                                app.maintenance_check_failed = true;
                                app.message =
                                    "Maintenance status unavailable; the check failed.".into();
                            }
                        }
                    }
                    WorkerEvent::TempPreview(result, review) => {
                        app.temp_preparing = false;
                        if temp_cancel.load(Ordering::Relaxed) {
                            app.message = "Temporary staging preview cancelled.".into();
                        } else if review {
                            match result {
                                Ok(plan) if !plan.supported => {
                                    app.message = "Temporary staging cleanup is unavailable on this platform.".into();
                                }
                                #[cfg(target_os = "linux")]
                                Ok(plan) if plan.selected_count > 0 => {
                                    app.temp_review_plan = Some(plan);
                                    app.temp_review_confirm = false;
                                    app.temp_review_scroll = 0;
                                    app.temp_review_area = Rect::default();
                                    app.message.clear();
                                }
                                Ok(_) => {
                                    app.message = "The selected staging paths are no longer eligible; rescan and review again.".into();
                                }
                                Err(error) => {
                                    app.message = format!(
                                        "Temporary staging preview failed: {}",
                                        schedule_escape_controls(&error)
                                    );
                                }
                            }
                        } else {
                            app.temp_plan =
                                Some(result.map_err(|error| schedule_escape_controls(&error)));
                            app.temp_selected = 0;
                            app.temp_inventory_scroll_offset = 0;
                            app.temp_marks.clear();
                            app.message.clear();
                        }
                    }
                    #[cfg(target_os = "linux")]
                    WorkerEvent::TempCleaned(performed) => {
                        app.temp_running = false;
                        let history_warning = performed.history_warning;
                        let mut lines = match performed.result {
                            Ok(result) => {
                                let mut lines = vec![format!(
                                    "Temporary staging cleanup: {} ({} removed).",
                                    result.outcome, result.removed_count
                                )];
                                lines.extend(result.items.into_iter().map(|item| {
                                    format!(
                                        "{}: {}{}",
                                        crate::sweep::display_path(&item.path),
                                        item.status,
                                        item.error.map_or_else(String::new, |error| {
                                            format!(" — {}", schedule_escape_controls(&error))
                                        })
                                    )
                                }));
                                lines
                            }
                            Err(error) => vec![format!(
                                "Temporary staging cleanup failed: {}",
                                schedule_escape_controls(&error)
                            )],
                        };
                        if let Some(warning) = history_warning {
                            lines.push(format!(
                                "History warning: {}",
                                schedule_escape_controls(&warning)
                            ));
                        }
                        app.temp_result = Some(lines.join("\n"));
                        app.temp_result_scroll = 0;
                        app.temp_plan = None;
                        app.temp_marks.clear();
                        app.temp_selected = 0;
                        app.history = None;
                        app.message.clear();
                    }
                    WorkerEvent::TrimPreview(result) => {
                        app.trim_preparing = false;
                        match result {
                            Ok(plan) => {
                                app.trim_plan = Some(plan);
                                app.message.clear();
                            }
                            Err(error) => app.message = format!("TRIM preview failed: {error}"),
                        }
                    }
                    WorkerEvent::TrimFinished(performed) => {
                        app.trim_running = false;
                        app.message = match performed.result {
                            Ok(()) => {
                                "TRIM completed; filesystem free space is unchanged by TRIM.".into()
                            }
                            Err(error) => format!("TRIM result: {error}"),
                        };
                        if let Some(warning) = performed.history_warning {
                            app.message = format!("History failed; {}  ({warning})", app.message);
                        }
                        app.history = None;
                    }
                    WorkerEvent::GoTestPreview(result) => {
                        app.go_test_preparing = false;
                        match result {
                            Ok(plan) => {
                                app.go_test_plan = Some(plan);
                                app.message.clear();
                            }
                            Err(error) => {
                                app.go_test_read_only = false;
                                app.message = format!("Go test-cache preview failed: {error}")
                            }
                        }
                    }
                    WorkerEvent::GoTestFinished(performed) => {
                        app.go_test_running = false;
                        app.message = match performed.result {
                            Ok(result) => format!(
                                "Go test expiration: {}; changed={}; no space reclaimed.",
                                result.verification, result.changed
                            ),
                            Err(error) => format!("Go test expiration result: {error}"),
                        };
                        if let Some(warning) = performed.history_warning {
                            app.message = format!("History failed; {} ({warning})", app.message);
                        }
                        app.history = None;
                        app.cache = None;
                    }
                    WorkerEvent::Cache(report) => {
                        app.cache_running = false;
                        app.cache = Some(report);
                        app.normalize_cache_selection();
                        app.message.clear();
                    }
                    WorkerEvent::Containers(report) => {
                        app.containers_running = false;
                        app.containers = Some(report);
                        app.normalize_container_selection();
                    }
                    WorkerEvent::ContainerPreview(result) => {
                        app.container_preparing = false;
                        match result {
                            Ok(plan) => {
                                app.container_plan = Some(plan);
                                app.message.clear();
                            }
                            Err(error) => {
                                app.message = format!("Container preview failed: {error}")
                            }
                        }
                    }
                    WorkerEvent::ContainerRemoved(performed) => {
                        app.container_removing = false;
                        app.message = match performed.result {
                            Ok("verified_absent") => {
                                "Container removed; absence verified by the engine.".into()
                            }
                            Ok(status) => format!(
                                "Removal command completed; {status}. Inspect engine state before retrying."
                            ),
                            Err(error) => format!("Removal result: {error}"),
                        };
                        if let Some(warning) = performed.history_warning {
                            app.message = format!("History failed; {}  ({warning})", app.message);
                        }
                        app.history = None;
                        app.containers = None;
                        app.containers_running = true;
                        app.container_selected = 0;
                        app.containers_scroll = 0;
                        let tx = tx.clone();
                        let offline = ctx.offline;
                        let dry_run = ctx.dry_run;
                        thread::spawn(move || {
                            let _ = tx.send(WorkerEvent::Containers(
                                crate::containers::status_with_dry_run(offline, dry_run),
                            ));
                        });
                    }
                    WorkerEvent::BuildCachePreview(result) => {
                        app.build_cache_preparing = false;
                        match result {
                            Ok(plan) => {
                                app.build_cache_plan = Some(plan);
                                app.message.clear();
                            }
                            Err(error) => {
                                app.build_cache_read_only = false;
                                app.message = format!("Build cache preview failed: {error}");
                            }
                        }
                    }
                    WorkerEvent::BuildCacheRemoved(performed) => {
                        app.build_cache_removing = false;
                        app.message = match performed.result {
                            Ok("verified_absent") => {
                                "Build cache removed; absence verified by the builder.".into()
                            }
                            Ok(status) => format!(
                                "Removal command completed; {status}. Inspect builder before retrying."
                            ),
                            Err(error) => format!("Build cache removal result: {error}"),
                        };
                        if let Some(warning) = performed.history_warning {
                            app.message = format!("History failed; {} ({warning})", app.message);
                        }
                        app.history = None;
                        app.containers = None;
                        app.containers_running = true;
                        app.container_selected = 0;
                        app.containers_scroll = 0;
                        let tx = tx.clone();
                        let offline = ctx.offline;
                        let dry_run = ctx.dry_run;
                        thread::spawn(move || {
                            let _ = tx.send(WorkerEvent::Containers(
                                crate::containers::status_with_dry_run(offline, dry_run),
                            ));
                        });
                    }
                    WorkerEvent::NetworkPreview(result) => {
                        app.network_preparing = false;
                        match result {
                            Ok(plan) => {
                                app.network_plan = Some(plan);
                                app.message.clear();
                            }
                            Err(error) => app.message = format!("Network preview failed: {error}"),
                        }
                    }
                    WorkerEvent::NetworkRemoved(performed) => {
                        app.network_removing = false;
                        app.message = match performed.result {
                            Ok("verified_absent") => {
                                "Network removed; absence verified by the engine.".into()
                            }
                            Ok(status) => format!(
                                "Removal command completed; {status}. Inspect engine state before retrying."
                            ),
                            Err(error) => format!("Network removal result: {error}"),
                        };
                        if let Some(warning) = performed.history_warning {
                            app.message = format!("History failed; {} ({warning})", app.message);
                        }
                        app.history = None;
                        app.containers = None;
                        app.containers_running = true;
                        app.container_selected = 0;
                        app.containers_scroll = 0;
                        let tx = tx.clone();
                        let offline = ctx.offline;
                        let dry_run = ctx.dry_run;
                        thread::spawn(move || {
                            let _ = tx.send(WorkerEvent::Containers(
                                crate::containers::status_with_dry_run(offline, dry_run),
                            ));
                        });
                    }
                    WorkerEvent::ScheduleEditPreview(result, frequency) => {
                        app.schedule_edit_preparing = false;
                        match result {
                            Ok(plan) => {
                                app.schedule_read_only |= !cfg!(target_os = "linux")
                                    && crate::schedule::schedules_artifact_cleanup(
                                        &plan.replacement,
                                    );
                                app.schedule_edit_plan = Some((plan, frequency));
                                app.message.clear();
                            }
                            Err(error) => {
                                app.message = format!(
                                    "{} replacement preview failed: {error}",
                                    SchedulePlatform::current().subject()
                                )
                            }
                        }
                    }
                    WorkerEvent::ScheduleEdited(performed) => {
                        app.schedule_edit_running = false;
                        app.message = schedule_operation_result_message(
                            SchedulePlatform::current(),
                            "replacement",
                            performed.result,
                        );
                        if let Some(warning) = performed.history_warning {
                            app.message = format!("History failed; {} ({warning})", app.message);
                        }
                        app.history = None;
                        app.schedule = None;
                        app.schedule_running = true;
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let _ = tx.send(WorkerEvent::Schedule(crate::schedule::status()));
                        });
                    }
                    WorkerEvent::ScheduleRemovePreview(result) => {
                        app.schedule_remove_preparing = false;
                        match result {
                            Ok(plan) => {
                                app.schedule_remove_plan = Some(plan);
                                app.message.clear();
                            }
                            Err(error) => {
                                app.message = format!("Timer unit removal preview failed: {error}")
                            }
                        }
                    }
                    WorkerEvent::ScheduleRemoved(performed) => {
                        app.schedule_remove_running = false;
                        app.message = match performed.result {
                            Ok("units_absent") => "Timer units removed; absence verified.".into(),
                            Ok(status) => format!(
                                "Timer unit removal: {status}; inspect manager and directory before retrying."
                            ),
                            Err(error) => format!("Timer unit removal result: {error}"),
                        };
                        if let Some(warning) = performed.history_warning {
                            app.message = format!("History failed; {} ({warning})", app.message);
                        }
                        app.history = None;
                        app.schedule = None;
                        app.schedule_running = true;
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let _ = tx.send(WorkerEvent::Schedule(crate::schedule::status()));
                        });
                    }
                    WorkerEvent::ScheduleInstallPreview(result, frequency) => {
                        app.schedule_install_preparing = false;
                        match result {
                            Ok(plan) => {
                                app.show_schedule_install_preview(plan, frequency);
                            }
                            Err(error) => {
                                app.schedule_read_only = false;
                                app.message = format!(
                                    "{} installation preview failed: {error}",
                                    SchedulePlatform::current().subject()
                                )
                            }
                        }
                    }
                    WorkerEvent::ScheduleInstalled(performed) => {
                        app.schedule_install_running = false;
                        app.message = schedule_operation_result_message(
                            SchedulePlatform::current(),
                            "installation",
                            performed.result,
                        );
                        if let Some(warning) = performed.history_warning {
                            app.message = format!("History failed; {} ({warning})", app.message);
                        }
                        app.history = None;
                        app.schedule = None;
                        app.schedule_running = true;
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let _ = tx.send(WorkerEvent::Schedule(crate::schedule::status()));
                        });
                    }
                    WorkerEvent::ScheduleEnablePreview(result, frequency) => {
                        app.schedule_enable_preparing = false;
                        match result {
                            Ok(plan) => {
                                app.schedule_read_only |= !cfg!(target_os = "linux")
                                    && crate::schedule::schedules_artifact_cleanup(&plan.intended);
                                app.schedule_enable_plan = Some((plan, frequency));
                                app.message.clear();
                            }
                            Err(error) => {
                                app.message = format!(
                                    "{} enable preview failed: {error}",
                                    SchedulePlatform::current().subject()
                                )
                            }
                        }
                    }
                    WorkerEvent::ScheduleEnabled(performed) => {
                        app.schedule_enable_running = false;
                        app.message = schedule_operation_result_message(
                            SchedulePlatform::current(),
                            "enable",
                            performed.result,
                        );
                        if let Some(warning) = performed.history_warning {
                            app.message = format!("History failed; {} ({warning})", app.message);
                        }
                        app.history = None;
                        app.schedule = None;
                        app.schedule_running = true;
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let _ = tx.send(WorkerEvent::Schedule(crate::schedule::status()));
                        });
                    }
                    WorkerEvent::ScheduleDisablePreview(result) => {
                        app.schedule_disable_preparing = false;
                        match result {
                            Ok(plan) => {
                                app.schedule_disable_plan = Some(plan);
                                app.message.clear();
                            }
                            Err(error) => {
                                app.message = format!("Timer disable preview failed: {error}")
                            }
                        }
                    }
                    WorkerEvent::ScheduleDisabled(performed) => {
                        app.schedule_disable_running = false;
                        app.message = match performed.result {
                            Ok("inactive_and_disabled") => {
                                "Timer disabled; an already running service, including cleanup, may continue.".into()
                            }
                            Ok(status) => {
                                format!("Timer disable: {status}; inspect manager before retrying.")
                            }
                            Err(error) => format!("Timer disable result: {error}"),
                        };
                        if let Some(warning) = performed.history_warning {
                            app.message = format!("History failed; {} ({warning})", app.message);
                        }
                        app.history = None;
                        app.schedule = None;
                        app.schedule_running = true;
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let _ = tx.send(WorkerEvent::Schedule(crate::schedule::status()));
                        });
                    }
                    WorkerEvent::Schedule(status) => {
                        app.schedule_running = false;
                        app.schedule = Some(status);
                    }
                    #[cfg(target_os = "linux")]
                    WorkerEvent::TrashRetentionStatus(status) => {
                        app.trash_retention_status_loading = false;
                        app.trash_retention_status = Some(status);
                    }
                    #[cfg(target_os = "linux")]
                    WorkerEvent::TrashRetentionPreview(result, read_only) => {
                        app.trash_retention_preparing = false;
                        app.schedule_read_only = read_only;
                        match result {
                            Ok(plan) => {
                                app.trash_retention_plan = Some(plan);
                                app.message.clear();
                            }
                            Err(error) => {
                                app.trash_retention_plan = None;
                                app.schedule_read_only = false;
                                app.message = format!("Trash retention preview failed: {error}");
                            }
                        }
                    }
                    #[cfg(target_os = "linux")]
                    WorkerEvent::TrashRetentionChanged(action, performed) => {
                        app.trash_retention_running = false;
                        app.trash_retention_plan = None;
                        app.message = trash_retention_change_message(action, performed.result);
                        if performed.history_warning.is_some() {
                            app.message
                                .push_str(" Local operation history was not recorded.");
                        }
                        app.history = None;
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let status = operation_worker(|| {
                                crate::schedule::trash_retention::trash_retention_status()
                            });
                            let _ = tx.send(WorkerEvent::TrashRetentionStatus(status));
                        });
                    }
                    WorkerEvent::History(history) => {
                        app.history_running = false;
                        app.history = Some(history);
                    }
                    WorkerEvent::HistoryPurgePreview(result) => {
                        app.history_purge_preparing = false;
                        app.history_purge_content = None;
                        app.history_purge_scroll = 0;
                        if history_purge_cancel.load(Ordering::Relaxed) {
                            app.history_purge_plan = None;
                            app.message = "History purge preview cancelled.".into();
                        } else {
                            match result {
                                Ok(plan) => {
                                    app.history_purge_plan = Some(plan);
                                    app.message.clear();
                                }
                                Err(error) => {
                                    app.history_purge_plan = None;
                                    app.message = format!("History purge preview failed: {error}");
                                }
                            }
                        }
                    }
                    WorkerEvent::HistoryPurgeProgress(done, total) => {
                        if !history_purge_cancel.load(Ordering::Relaxed) {
                            app.message = format!(
                                "Removing history record {done}/{total}; Esc cancels remaining records."
                            );
                        }
                    }
                    WorkerEvent::HistoryPurged(performed) => {
                        app.history_purging = false;
                        app.history_scroll = 0;
                        app.history_purge_warning = performed.history_warning;
                        app.message = match performed.result {
                            Ok(result) => {
                                let message = format!(
                                    "History purge: {}; per-record results are shown in Reports.",
                                    result.outcome
                                );
                                app.history_purge_result = Some(result);
                                message
                            }
                            Err(error) => {
                                app.history_purge_result = None;
                                format!("History purge result: {error}")
                            }
                        };
                        app.history = None;
                        app.history_running = true;
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        thread::spawn(move || {
                            let _ = tx.send(WorkerEvent::History(
                                crate::reports::read(&home).map_err(|error| format!("{error:#}")),
                            ));
                        });
                    }
                    WorkerEvent::Trash(report) => {
                        app.trash_running = false;
                        app.trash = Some(report);
                        app.message.clear();
                    }
                    WorkerEvent::TrashPreview(report) => {
                        app.trash_running = false;
                        app.trash_preview = Some(report);
                        app.message.clear();
                    }
                    WorkerEvent::TrashRemovalPreview(result) => {
                        app.trash_removal_preparing = false;
                        match result {
                            Ok(plan) => {
                                app.trash_removal_plan = Some(plan);
                                app.message.clear();
                            }
                            Err(error) => {
                                app.message = format!("Trash deletion preview failed: {error}")
                            }
                        }
                    }
                    WorkerEvent::TrashSelection(result) => {
                        app.trash_marking = false;
                        match result {
                            Ok((preview, selection)) => {
                                app.message = format!(
                                    "{}: {} eligible; {} newer/unknown; {} unsupported. Review before deletion.",
                                    crate::sweep::display_path(&selection.location),
                                    selection.eligible,
                                    selection.newer_or_unknown,
                                    selection.unsupported
                                );
                                app.trash_preview = Some(Ok(preview));
                            }
                            Err(error) => app.message = format!("Trash selection: {error}"),
                        }
                    }
                    WorkerEvent::TrashRemovalProgress(index, total) => {
                        if !trash_cancel.load(Ordering::Relaxed) {
                            app.message = format!(
                                "Removing Trash item {} of {}; Esc cancels remaining items.",
                                index + 1,
                                total
                            );
                        }
                    }
                    WorkerEvent::TrashRemoved(performed) => {
                        app.trash_removing = false;
                        app.message = match performed.result {
                            Ok(result) => {
                                let message = format!(
                                    "Trash deletion: {}; review item results.",
                                    result.outcome
                                );
                                app.trash_last_result = Some(result);
                                message
                            }
                            Err(error) => format!("Trash deletion result: {error}"),
                        };
                        if let Some(warning) = performed.history_warning {
                            app.message = format!("History failed; {} ({warning})", app.message);
                        }
                        app.history = None;
                        app.trash = None;
                        app.trash_preview = None;
                        app.trash_selected = 0;
                        app.trash_scroll = 0;
                    }
                    WorkerEvent::Scanned(report) => {
                        app.scan_running = false;
                        app.scan = Some(report);
                        app.sort_artifacts();
                        app.message.clear();
                    }
                    WorkerEvent::Previewed(plan) => {
                        app.scan_running = false;
                        app.plan = Some(plan);
                        app.sort_artifacts();
                        app.message.clear();
                    }
                    WorkerEvent::Updating(tool, index, total) => {
                        app.message = format!("Updating {} ({index}/{total})…", tool.as_str());
                    }
                    WorkerEvent::Updated(results) => {
                        app.updating = false;
                        app.message = results
                            .iter()
                            .map(|(tool, result)| match result {
                                Ok(()) => format!("{}: done", tool.as_str()),
                                Err(err) => format!("{}: {err}", tool.as_str()),
                            })
                            .collect::<Vec<_>>()
                            .join("; ");
                        app.marked.clear();
                        check(worker_ctx.clone(), kinds.clone(), tx.clone());
                    }
                    WorkerEvent::SelfUpdatePreview(result) => {
                        app.self_update_preparing = false;
                        match result {
                            Ok(plan) => {
                                self_update_failed = false;
                                app.self_update_plan = Some(plan);
                                app.message.clear();
                            }
                            Err(error) => {
                                if self_update_requested {
                                    self_update_failed = true;
                                }
                                app.message = format!(
                                    "Self-update preview failed: {}",
                                    schedule_escape_controls(&error)
                                        .chars()
                                        .take(300)
                                        .collect::<String>()
                                );
                            }
                        }
                    }
                    WorkerEvent::SelfUpdated(result) => {
                        app.updating = false;
                        if self_update_requested {
                            self_update_failed = result.is_err();
                        }
                        app.message = match result {
                            Ok(()) => "Upkit updated; restart it to use the new version.".into(),
                            Err(error) => format!(
                                "Self-update failed or its outcome is unknown: {}",
                                schedule_escape_controls(&error)
                                    .chars()
                                    .take(300)
                                    .collect::<String>()
                            ),
                        };
                    }
                }
            }
            expire_toolchain_refresh_notice(
                &mut app.message,
                &mut toolchain_refresh_notice_started,
                std::time::Instant::now(),
            );
            let size = terminal.size()?;
            let area = Rect::new(0, 0, size.width, size.height);
            app.update_artifact_review(area);
            app.update_managed_batch_review(area);
            app.update_temp_review(area);
            app.update_schedule_confirmation(area);
            app.update_history_purge_review(area);
            app.update_settings_confirmation_area(area);
            clamp_doctor_scroll(&mut app, area);
            clamp_history_settings_scroll(&mut app, area);
            clamp_schedule_scroll(&mut app, area, SchedulePlatform::current());
            clamp_cache_scroll(&mut app, area);
            let confirmations = confirmation_surfaces(&app);
            pending_safe_input.extend(draw_confirmation_frame(
                newly_visible_confirmation(&visible_confirmations, &confirmations),
                discard_pending_terminal_input,
                || terminal.draw(|frame| draw(frame, &app)).map(|_| ()),
            )?);
            visible_confirmations = confirmations;
            let input = if let Some(input) = pending_safe_input.pop_front() {
                Some(input)
            } else if event::poll(Duration::from_millis(100))? {
                Some(event::read()?)
            } else {
                None
            };
            if let Some(Event::Key(key)) = input {
                if let Some(plan) = &app.artifact_plan {
                    let size = terminal.size()?;
                    let actual = Rect::new(0, 0, size.width, size.height);
                    let drawn = terminal.get_frame().area();
                    let batch_confirmation =
                        app.artifact_confirm && matches!(plan, DirectoryPlan::ArtifactBatch(_));
                    if batch_confirmation {
                        if drawn.width != actual.width || drawn.width != app.artifact_review_width {
                            app.artifact_review_rows = 0;
                            app.artifact_review_scroll = 0;
                        } else {
                            app.artifact_review_rows = artifact_batch_confirmation_rows(drawn)
                                .min(artifact_batch_confirmation_rows(actual));
                        }
                    }
                    if app.artifact_confirm && key.code == KeyCode::Char('y') {
                        if !directory_confirmation_fits(plan, drawn)
                            || !directory_confirmation_fits(plan, actual)
                        {
                            app.message =
                                "Enlarge the terminal to review the complete confirmation.".into();
                            continue;
                        }
                        if batch_confirmation
                            && app.artifact_review_scroll + app.artifact_review_rows
                                < app.artifact_review_lines
                        {
                            app.message =
                                "Scroll through every selected target before confirming.".into();
                            continue;
                        }
                    }
                    if !app.artifact_confirm {
                        if drawn.width != actual.width || drawn.width != app.artifact_review_width {
                            app.artifact_review_rows = 0;
                            app.artifact_review_scroll = 0;
                        } else if app.artifact_review_content.is_some() {
                            app.artifact_review_rows = artifact_review_rows(plan, drawn)
                                .min(artifact_review_rows(plan, actual));
                        } else {
                            app.artifact_review_rows = 0;
                        }
                        if app.artifact_review_rows == 0
                            && matches!(
                                key.code,
                                KeyCode::Down | KeyCode::Char('j') | KeyCode::Enter
                            )
                        {
                            app.message = "Enlarge the terminal to review every entry.".into();
                            continue;
                        }
                    }
                }
                if let Some(plan) = &app.temp_review_plan
                    && matches!(key.code, KeyCode::Enter | KeyCode::Char('y'))
                {
                    let size = terminal.size()?;
                    let actual = Rect::new(0, 0, size.width, size.height);
                    let drawn = terminal.get_frame().area();
                    let confirming = app.temp_review_confirm;
                    if (key.code == KeyCode::Enter && !confirming)
                        || (key.code == KeyCode::Char('y') && confirming)
                    {
                        if drawn != actual {
                            app.temp_review_scroll = 0;
                            app.temp_review_area = Rect::default();
                            app.message =
                                "Terminal resized; review the current plan again before continuing.".into();
                            continue;
                        }
                        if !temp_cleanup_review_complete(
                            plan,
                            confirming,
                            app.dry_run,
                            app.temp_review_scroll,
                            drawn,
                        ) || !temp_cleanup_review_complete(
                            plan,
                            confirming,
                            app.dry_run,
                            app.temp_review_scroll,
                            actual,
                        ) {
                            app.message = if confirming {
                                "Review every selected path and warning at the current terminal size before confirming.".into()
                            } else {
                                "Review every staging candidate and warning at the current terminal size before continuing.".into()
                            };
                            continue;
                        }
                    }
                }
                if let Some(plan) = &app.self_update_plan
                    && matches!(key.code, KeyCode::Enter | KeyCode::Char('y'))
                {
                    let size = terminal.size()?;
                    let drawn = terminal.get_frame().area();
                    let actual = Rect::new(0, 0, size.width, size.height);
                    if drawn != actual
                        || !self_update_confirmation_fits(plan, drawn)
                        || !self_update_confirmation_fits(plan, actual)
                    {
                        app.message =
                            "Enlarge the terminal to see the entire plan before confirming.".into();
                        continue;
                    }
                }
                if app.confirmation && toolchain_confirmation_key(key) {
                    let size = terminal.size()?;
                    if !toolchain_confirmation_fits(&app, terminal.get_frame().area())
                        || !toolchain_confirmation_fits(
                            &app,
                            Rect::new(0, 0, size.width, size.height),
                        )
                    {
                        app.message =
                            "Enlarge the terminal to see the entire plan before confirming.".into();
                        continue;
                    }
                }
                if !app.managed_batch_plans.is_empty()
                    && key.code == KeyCode::Char('y')
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                {
                    let size = terminal.size()?;
                    let actual = Rect::new(0, 0, size.width, size.height);
                    let drawn = terminal.get_frame().area();
                    if drawn != actual || app.managed_batch_review_area != drawn {
                        app.managed_batch_review_scroll = 0;
                        app.managed_batch_review_rows = 0;
                        app.managed_batch_review_area = Rect::default();
                        app.message =
                            "Terminal resized; review the complete batch again before confirming."
                                .into();
                        continue;
                    }
                    if !managed_batch_review_complete(&app, drawn) {
                        app.message = if app.managed_batch_review_rows == 0 {
                            "Enlarge the terminal to review every selected tool.".into()
                        } else if !managed_batch_review_scroll_supported(
                            app.managed_batch_review_lines,
                            app.managed_batch_review_rows,
                            app.managed_batch_review_scroll,
                        ) {
                            "The review exceeds the terminal scroll range; select fewer targets."
                                .into()
                        } else {
                            "Scroll through every selected tool before confirming.".into()
                        };
                        continue;
                    }
                }
                if let Some(plan) = &app.managed_plan
                    && !app.managed_detail
                    && key.code == KeyCode::Char('y')
                {
                    let size = terminal.size()?;
                    if !managed_confirmation_fits(plan, terminal.get_frame().area())
                        || !managed_confirmation_fits(
                            plan,
                            Rect::new(0, 0, size.width, size.height),
                        )
                    {
                        app.message =
                            "Enlarge the terminal to review the complete managed cleanup plan."
                                .into();
                        continue;
                    }
                }
                if let (Some(pending), Some(SettingsPrompt::Save)) =
                    (&app.settings_pending_save, app.settings_prompt)
                    && key.code == KeyCode::Char('y')
                {
                    let size = terminal.size()?;
                    let drawn = terminal.get_frame().area();
                    let actual = Rect::new(0, 0, size.width, size.height);
                    if drawn != actual
                        || app.settings_confirmation_area != drawn
                        || !settings_confirmation_ready(
                            &pending.snapshot,
                            SettingsPrompt::Save,
                            &pending.cleanup_impacts,
                            &pending.changes,
                            app.settings_confirmation_scroll,
                            drawn,
                        )
                        || !settings_confirmation_ready(
                            &pending.snapshot,
                            SettingsPrompt::Save,
                            &pending.cleanup_impacts,
                            &pending.changes,
                            app.settings_confirmation_scroll,
                            actual,
                        )
                    {
                        app.message = "Review every settings impact and keep the full confirmation visible before saving.".into();
                        continue;
                    }
                }
                if let Some(plan) = &app.trim_plan
                    && key.code == KeyCode::Char('y')
                    && !app.trim_read_only
                {
                    let size = terminal.size()?;
                    if !trim_confirmation_fits(
                        plan,
                        app.trim_read_only,
                        terminal.get_frame().area(),
                    ) || !trim_confirmation_fits(
                        plan,
                        app.trim_read_only,
                        Rect::new(0, 0, size.width, size.height),
                    ) {
                        app.message =
                            "Enlarge the terminal to see the entire TRIM plan before confirming."
                                .into();
                        continue;
                    }
                }
                if let Some(plan) = &app.bytecode_plan
                    && key.code == KeyCode::Char('y')
                {
                    let size = terminal.size()?;
                    if !bytecode_confirmation_fits(plan, terminal.get_frame().area())
                        || !bytecode_confirmation_fits(
                            plan,
                            Rect::new(0, 0, size.width, size.height),
                        )
                    {
                        app.message = "Enlarge the terminal to see the entire bytecode plan before confirming.".into();
                        continue;
                    }
                }
                if let Some(plan) = &app.bytecode_batch_plan
                    && key.code == KeyCode::Char('y')
                {
                    let size = terminal.size()?;
                    if !bytecode_batch_confirmation_fits(plan, terminal.get_frame().area())
                        || !bytecode_batch_confirmation_fits(
                            plan,
                            Rect::new(0, 0, size.width, size.height),
                        )
                    {
                        app.message =
                            "Enlarge the terminal to see every bytecode target before confirming."
                                .into();
                        continue;
                    }
                }
                if let Some(plan) = &app.go_test_plan
                    && !app.go_test_read_only
                    && key.code == KeyCode::Char('y')
                {
                    let size = terminal.size()?;
                    if !go_test_confirmation_fits(
                        plan,
                        app.go_test_read_only,
                        terminal.get_frame().area(),
                    ) || !go_test_confirmation_fits(
                        plan,
                        app.go_test_read_only,
                        Rect::new(0, 0, size.width, size.height),
                    ) {
                        app.message = "Enlarge the terminal to see the entire Go test-cache plan before confirming.".into();
                        continue;
                    }
                }
                if key.code == KeyCode::Char('y')
                    && !app.schedule_read_only
                    && schedule_confirmation_review(&app).is_some()
                {
                    let size = terminal.size()?;
                    let drawn = terminal.get_frame().area();
                    let actual = Rect::new(0, 0, size.width, size.height);
                    if !schedule_confirmation_can_confirm(&app, drawn, actual) {
                        app.message = "Scroll through every complete unit line and warning before confirming.".into();
                        continue;
                    }
                }
                if key.code == KeyCode::Char('y') && app.history_purge_plan.is_some() {
                    let size = terminal.size()?;
                    let drawn = terminal.get_frame().area();
                    let actual = Rect::new(0, 0, size.width, size.height);
                    if !history_purge_can_confirm(&app, drawn, actual) {
                        app.message =
                            "Scroll through every history record and warning before confirming."
                                .into();
                        continue;
                    }
                }
                if let Some(plan) = &app.container_plan
                    && key.code == KeyCode::Char('y')
                {
                    let size = terminal.size()?;
                    if !container_confirmation_fits(plan, terminal.get_frame().area())
                        || !container_confirmation_fits(
                            plan,
                            Rect::new(0, 0, size.width, size.height),
                        )
                    {
                        app.message = "Enlarge the terminal to see the entire container plan before confirming.".into();
                        continue;
                    }
                }
                if let Some(plan) = &app.network_plan
                    && key.code == KeyCode::Char('y')
                {
                    let size = terminal.size()?;
                    if !network_confirmation_fits(plan, terminal.get_frame().area())
                        || !network_confirmation_fits(
                            plan,
                            Rect::new(0, 0, size.width, size.height),
                        )
                    {
                        app.message = "Enlarge the terminal to see the entire network plan before confirming.".into();
                        continue;
                    }
                }
                if let Some(plan) = &app.build_cache_plan
                    && !app.build_cache_read_only
                    && key.code == KeyCode::Char('y')
                {
                    let size = terminal.size()?;
                    if !build_cache_confirmation_fits(plan, false, terminal.get_frame().area())
                        || !build_cache_confirmation_fits(
                            plan,
                            false,
                            Rect::new(0, 0, size.width, size.height),
                        )
                    {
                        app.message = "Enlarge the terminal to see the entire build cache plan before confirming.".into();
                        continue;
                    }
                }
                if let Some(plan) = &app.trash_removal_plan
                    && key.code == KeyCode::Char('y')
                {
                    let size = terminal.size()?;
                    if !trash_removal_confirmation_fits(plan, terminal.get_frame().area())
                        || !trash_removal_confirmation_fits(
                            plan,
                            Rect::new(0, 0, size.width, size.height),
                        )
                    {
                        app.message = "Enlarge the terminal to see the entire irreversible deletion plan before confirming.".into();
                        continue;
                    }
                }
                match app.key(key) {
                    Action::Quit => {
                        scan_cancel.store(true, Ordering::Relaxed);
                        managed_cancel.store(true, Ordering::Relaxed);
                        cache_cancel.store(true, Ordering::Relaxed);
                        trash_cancel.store(true, Ordering::Relaxed);
                        temp_cancel.store(true, Ordering::Relaxed);
                        history_purge_cancel.store(true, Ordering::Relaxed);
                        break;
                    }
                    Action::CancelManaged => managed_cancel.store(true, Ordering::Relaxed),
                    Action::PreviewManaged(tool) => {
                        managed_cancel.store(false, Ordering::Relaxed);
                        app.managed_current = Some(tool);
                        start_managed_preview(
                            worker_ctx.clone(),
                            tool,
                            managed_cancel.clone(),
                            tx.clone(),
                        );
                    }
                    Action::PreviewManagedBatch(tools) => {
                        managed_cancel.store(false, Ordering::Relaxed);
                        start_managed_batch_preview(
                            worker_ctx.clone(),
                            tools,
                            managed_cancel.clone(),
                            tx.clone(),
                        );
                    }
                    Action::RemoveManaged(plan) => {
                        let tx = tx.clone();
                        let cancel = managed_cancel.clone();
                        let worker_ctx = worker_ctx.clone();
                        thread::spawn(move || {
                            let result = crate::reports::perform_managed_cleanup(
                                &worker_ctx,
                                &plan,
                                &cancel,
                            );
                            let _ = tx.send(WorkerEvent::ManagedCleaned(result));
                        });
                    }
                    Action::RemoveManagedBatch(targets) => {
                        managed_cancel.store(false, Ordering::Relaxed);
                        let tx = tx.clone();
                        let cancel = managed_cancel.clone();
                        let worker_ctx = worker_ctx.clone();
                        thread::spawn(move || {
                            let result = run_managed_batch(&worker_ctx, &targets, &cancel);
                            let _ = tx.send(WorkerEvent::ManagedBatchRemoved(result));
                        });
                    }
                    Action::CancelScan => scan_cancel.store(true, Ordering::Relaxed),
                    Action::CancelDoctor => doctor_cancel.store(true, Ordering::Relaxed),
                    Action::CancelTemp => temp_cancel.store(true, Ordering::Relaxed),
                    Action::PreviewTempCleanup(paths, review) => {
                        temp_cancel.store(false, Ordering::Relaxed);
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        let bindir = ctx.bindir.clone();
                        let cancel = temp_cancel.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                crate::temp_cleanup::preview(&home, &bindir, &paths, &cancel)
                            });
                            let _ = tx.send(WorkerEvent::TempPreview(result, review));
                        });
                    }
                    #[cfg(target_os = "linux")]
                    Action::RemoveTempCleanup(plan) => {
                        if ctx.dry_run {
                            app.temp_running = false;
                            app.temp_result = Some(
                                "Dry run: no staging directories were removed and no history was written.".into(),
                            );
                        } else {
                            let tx = tx.clone();
                            let home = ctx.home.clone();
                            let cancel = temp_cancel.clone();
                            thread::spawn(move || {
                                let performed = crate::reports::perform_temp_cleanup(
                                    &home,
                                    &plan,
                                    &plan.preview_token,
                                    &cancel,
                                );
                                let _ = tx.send(WorkerEvent::TempCleaned(performed));
                            });
                        }
                    }
                    Action::StartArtifactScan { configured } => {
                        let request = if configured {
                            (Vec::new(), Vec::new(), None)
                        } else {
                            artifact_scope.clone().unwrap_or_default()
                        };
                        artifact_scope = Some(request.clone());
                        scan_cancel.store(false, Ordering::Relaxed);
                        scan_progress.store(0, Ordering::Relaxed);
                        let tx = tx.clone();
                        let cancel = scan_cancel.clone();
                        let progress = scan_progress.clone();
                        let config = config.clone();
                        let profile = profile.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                let (paths, exclusions, age, enabled) =
                                    crate::application::resolve_scan_config(
                                        config.as_deref(),
                                        profile.as_deref(),
                                        &request.0,
                                        &request.1,
                                        request.2,
                                    )?;
                                let mut visited = 0usize;
                                crate::sweep::scan_with_policy(
                                    &paths,
                                    &exclusions,
                                    age,
                                    enabled.as_deref(),
                                    &cancel,
                                    |_| report_scan_progress(&progress, &mut visited),
                                )
                            });
                            let _ = tx.send(WorkerEvent::Scanned(result));
                        });
                    }
                    Action::PreviewArtifact(file) => {
                        if let Some((roots, exclusions, age)) = &artifact_scope {
                            let request = BytecodeRequest {
                                file,
                                roots: roots.clone(),
                                exclusions: exclusions.clone(),
                                age: *age,
                            };
                            artifact_target = Some(request.clone());
                            scan_cancel.store(false, Ordering::Relaxed);
                            let tx = tx.clone();
                            let cancel = scan_cancel.clone();
                            let config = config.clone();
                            let profile = profile.clone();
                            thread::spawn(move || {
                                let result = operation_worker(|| {
                                    let scope =
                                        request.scope(config.as_deref(), profile.as_deref())?;
                                    crate::artifact_cleanup::preview(&scope, &request.file, &cancel)
                                });
                                let _ = tx.send(WorkerEvent::ArtifactPreview(result));
                            });
                        } else {
                            app.artifact_preparing = false;
                            app.message =
                                "Original scan scope is unavailable; start a new scan.".into();
                        }
                    }
                    Action::PreviewArtifactBatch(targets) => {
                        if let Some((roots, exclusions, age)) = &artifact_scope
                            && let Some(first) = targets.first()
                        {
                            let request = BytecodeRequest {
                                file: first.clone(),
                                roots: roots.clone(),
                                exclusions: exclusions.clone(),
                                age: *age,
                            };
                            scan_cancel.store(false, Ordering::Relaxed);
                            let tx = tx.clone();
                            let cancel = scan_cancel.clone();
                            let config = config.clone();
                            let profile = profile.clone();
                            thread::spawn(move || {
                                let result = operation_worker(|| {
                                    let scope =
                                        request.scope(config.as_deref(), profile.as_deref())?;
                                    crate::artifact_cleanup::preview_batch(
                                        &scope, &targets, &cancel,
                                    )
                                });
                                let _ = tx.send(WorkerEvent::ArtifactBatchPreview(result));
                            });
                        } else {
                            app.artifact_preparing = false;
                            app.message =
                                "Original scan scope is unavailable; start a new scan.".into();
                        }
                    }
                    Action::RemoveArtifact(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        let request = artifact_target.clone();
                        let config = config.clone();
                        let profile = profile.clone();
                        let cancel = scan_cancel.clone();
                        thread::spawn(move || {
                            let scope = request
                                .as_ref()
                                .ok_or_else(|| anyhow::anyhow!("artifact request is unavailable"))
                                .and_then(|request| {
                                    request.scope(config.as_deref(), profile.as_deref())
                                });
                            let performed = match scope {
                                Ok(scope) if scope == plan.scope => {
                                    crate::reports::perform_artifact_removal(
                                        &home,
                                        &plan,
                                        &plan.preview_token,
                                        &cancel,
                                    )
                                }
                                Ok(_) => crate::reports::Performed {
                                    result: Err(
                                        "scan configuration changed; review the preview again"
                                            .into(),
                                    ),
                                    history_warning: None,
                                },
                                Err(error) => crate::reports::Performed {
                                    result: Err(format!(
                                        "scan configuration unavailable: {error:#}"
                                    )),
                                    history_warning: None,
                                },
                            };
                            let _ = tx.send(WorkerEvent::ArtifactRemoved(performed));
                        });
                    }
                    Action::RemoveArtifactBatch(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        let scope_inputs = artifact_scope.clone();
                        let config = config.clone();
                        let profile = profile.clone();
                        let cancel = scan_cancel.clone();
                        thread::spawn(move || {
                            let request = scope_inputs.and_then(|(roots, exclusions, age)| {
                                plan.items.first().map(|item| BytecodeRequest {
                                    file: item.target.clone(),
                                    roots,
                                    exclusions,
                                    age,
                                })
                            });
                            let scope = request
                                .as_ref()
                                .ok_or_else(|| {
                                    anyhow::anyhow!("artifact scan scope is unavailable")
                                })
                                .and_then(|request| {
                                    request.scope(config.as_deref(), profile.as_deref())
                                });
                            let performed = match scope {
                                Ok(scope) if scope == plan.scope => {
                                    crate::reports::perform_artifact_batch(
                                        &home,
                                        &plan,
                                        &plan.preview_token,
                                        &cancel,
                                    )
                                }
                                Ok(_) => unattempted_artifact_batch(
                                    &plan,
                                    "scan configuration changed; review the preview again".into(),
                                    false,
                                ),
                                Err(error) => unattempted_artifact_batch(
                                    &plan,
                                    format!("scan configuration unavailable: {error:#}"),
                                    cancel.load(Ordering::Relaxed),
                                ),
                            };
                            let _ = tx.send(WorkerEvent::ArtifactBatchRemoved(performed));
                        });
                    }
                    Action::PreviewSharedCache(target) => {
                        scan_cancel.store(false, Ordering::Relaxed);
                        let tx = tx.clone();
                        let cancel = scan_cancel.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                crate::shared_cache_cleanup::preview(&target, &cancel)
                            });
                            let _ = tx.send(WorkerEvent::SharedCachePreview(result));
                        });
                    }
                    Action::RemoveSharedCache(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        let cancel = scan_cancel.clone();
                        thread::spawn(move || {
                            let performed = crate::reports::perform_shared_cache_removal(
                                &home,
                                &plan,
                                &plan.preview_token,
                                &cancel,
                            );
                            let _ = tx.send(WorkerEvent::SharedCacheRemoved(performed));
                        });
                    }
                    Action::ListBytecode(cache) => {
                        scan_cancel.store(false, Ordering::Relaxed);
                        let tx = tx.clone();
                        let cancel = scan_cancel.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                Ok(BytecodeListing {
                                    files: crate::bytecode::list(&cache, &cancel)?,
                                    cache,
                                })
                            });
                            let _ = tx.send(WorkerEvent::BytecodeListed(result));
                        });
                    }
                    Action::PreviewBytecode(file) => {
                        if let Some((roots, exclusions, age)) = &artifact_scope {
                            let request = BytecodeRequest {
                                file,
                                roots: roots.clone(),
                                exclusions: exclusions.clone(),
                                age: *age,
                            };
                            bytecode_target = Some(request.clone());
                            scan_cancel.store(false, Ordering::Relaxed);
                            let tx = tx.clone();
                            let cancel = scan_cancel.clone();
                            let config = config.clone();
                            let profile = profile.clone();
                            thread::spawn(move || {
                                let result = operation_worker(|| {
                                    let scope =
                                        request.scope(config.as_deref(), profile.as_deref())?;
                                    crate::bytecode::preview(&scope, &request.file, &cancel)
                                });
                                let _ = tx.send(WorkerEvent::BytecodePreview(result));
                            });
                        } else {
                            app.bytecode_preparing = false;
                            app.message =
                                "Original scan scope is unavailable; start a new scan.".into();
                        }
                    }
                    Action::PreviewBytecodeBatch(files) => {
                        if let (Some((roots, exclusions, age)), Some(first)) =
                            (&artifact_scope, files.first())
                        {
                            let request = BytecodeRequest {
                                file: first.clone(),
                                roots: roots.clone(),
                                exclusions: exclusions.clone(),
                                age: *age,
                            };
                            bytecode_target = Some(request.clone());
                            scan_cancel.store(false, Ordering::Relaxed);
                            let tx = tx.clone();
                            let cancel = scan_cancel.clone();
                            let config = config.clone();
                            let profile = profile.clone();
                            thread::spawn(move || {
                                let result = operation_worker(|| {
                                    let scope =
                                        request.scope(config.as_deref(), profile.as_deref())?;
                                    crate::bytecode::preview_batch(&scope, &files, &cancel)
                                });
                                let _ = tx.send(WorkerEvent::BytecodeBatchPreview(result));
                            });
                        } else {
                            app.bytecode_preparing = false;
                            app.message = "Original scan scope or selected files are unavailable; start a new scan.".into();
                        }
                    }
                    Action::RemoveBytecode(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        let request = bytecode_target.clone();
                        let config = config.clone();
                        let profile = profile.clone();
                        let cancel = scan_cancel.clone();
                        thread::spawn(move || {
                            let scope = request
                                .as_ref()
                                .ok_or_else(|| anyhow::anyhow!("bytecode request is unavailable"))
                                .and_then(|request| {
                                    request.scope(config.as_deref(), profile.as_deref())
                                });
                            let performed = match scope {
                                Ok(scope) if scope == plan.scope => {
                                    crate::reports::perform_bytecode_removal(
                                        &home,
                                        &plan,
                                        &plan.preview_token,
                                        &cancel,
                                    )
                                }
                                Ok(_) => crate::reports::Performed {
                                    result: Err(
                                        "scan configuration changed; review the preview again"
                                            .into(),
                                    ),
                                    history_warning: None,
                                },
                                Err(error) => crate::reports::Performed {
                                    result: Err(format!(
                                        "scan configuration unavailable: {error:#}"
                                    )),
                                    history_warning: None,
                                },
                            };
                            let _ = tx.send(WorkerEvent::BytecodeRemoved(performed));
                        });
                    }
                    Action::RemoveBytecodeBatch(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        let request = bytecode_target.clone();
                        let config = config.clone();
                        let profile = profile.clone();
                        let cancel = scan_cancel.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                let request = request.as_ref().ok_or_else(|| {
                                    anyhow::anyhow!("bytecode request is unavailable")
                                })?;
                                let scope = request.scope(config.as_deref(), profile.as_deref())?;
                                if scope != plan.scope {
                                    anyhow::bail!(
                                        "scan configuration changed; review the preview again"
                                    );
                                }
                                crate::reports::perform_bytecode_batch_with_progress(
                                    &home,
                                    &plan,
                                    &plan.preview_token,
                                    &cancel,
                                    |done, total| {
                                        let _ = tx
                                            .send(WorkerEvent::BytecodeBatchProgress(done, total));
                                    },
                                )
                            });
                            let _ = tx.send(WorkerEvent::BytecodeBatchRemoved(result));
                        });
                    }
                    Action::CancelCache => cache_cancel.store(true, Ordering::Relaxed),
                    Action::CancelTrash => trash_cancel.store(true, Ordering::Relaxed),
                    Action::PreviewTrashRemoval(preview) => {
                        let tx = tx.clone();
                        trash_cancel.store(false, Ordering::Relaxed);
                        let cancel = trash_cancel.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                preview.batch_removal_plan_with_cancel(&cancel)
                            });
                            let _ = tx.send(WorkerEvent::TrashRemovalPreview(result));
                        });
                    }
                    Action::SelectOldTrash(mut preview, location) => {
                        let tx = tx.clone();
                        trash_cancel.store(false, Ordering::Relaxed);
                        let cancel = trash_cancel.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                let selection = preview.select_old_files(&location, &cancel)?;
                                Ok((preview, selection))
                            });
                            let _ = tx.send(WorkerEvent::TrashSelection(result));
                        });
                    }
                    Action::RemoveTrash(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        trash_cancel.store(false, Ordering::Relaxed);
                        let cancel = trash_cancel.clone();
                        thread::spawn(move || {
                            let progress_tx = tx.clone();
                            let performed = crate::reports::perform_trash_batch_with_progress(
                                &home,
                                &plan,
                                &plan.preview_token,
                                &cancel,
                                move |index, total| {
                                    let _ = progress_tx
                                        .send(WorkerEvent::TrashRemovalProgress(index, total));
                                },
                            );
                            let _ = tx.send(WorkerEvent::TrashRemoved(performed));
                        });
                    }
                    Action::PreviewTrim(mount) => {
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| crate::maintenance::trim_plan(&mount));
                            let _ = tx.send(WorkerEvent::TrimPreview(result));
                        });
                    }
                    Action::RunTrim(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        thread::spawn(move || {
                            let performed =
                                crate::reports::perform_trim(&home, &plan, &plan.preview_token);
                            let _ = tx.send(WorkerEvent::TrimFinished(performed));
                        });
                    }
                    Action::StartContainers => {
                        let tx = tx.clone();
                        let offline = ctx.offline;
                        let dry_run = ctx.dry_run;
                        thread::spawn(move || {
                            let _ = tx.send(WorkerEvent::Containers(
                                crate::containers::status_with_dry_run(offline, dry_run),
                            ));
                        });
                    }
                    Action::PreviewContainer(engine, id) => {
                        let tx = tx.clone();
                        let offline = ctx.offline;
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                crate::containers::removal_preview(&engine, &id, offline)
                            });
                            let _ = tx.send(WorkerEvent::ContainerPreview(result));
                        });
                    }
                    Action::RemoveContainer(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        thread::spawn(move || {
                            let performed = crate::reports::perform_container_removal(
                                &home,
                                &plan,
                                &plan.preview_token,
                            );
                            let _ = tx.send(WorkerEvent::ContainerRemoved(performed));
                        });
                    }
                    Action::PreviewBuildCache(builder, id) => {
                        let tx = tx.clone();
                        let offline = ctx.offline;
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                crate::containers::build_cache_preview(&builder, &id, offline)
                            });
                            let _ = tx.send(WorkerEvent::BuildCachePreview(result));
                        });
                    }
                    Action::RemoveBuildCache(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        thread::spawn(move || {
                            let performed = crate::reports::perform_build_cache_removal(
                                &home,
                                &plan,
                                &plan.preview_token,
                            );
                            let _ = tx.send(WorkerEvent::BuildCacheRemoved(performed));
                        });
                    }
                    Action::PreviewNetwork(engine, id) => {
                        let tx = tx.clone();
                        let offline = ctx.offline;
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                crate::containers::network_removal_preview(&engine, &id, offline)
                            });
                            let _ = tx.send(WorkerEvent::NetworkPreview(result));
                        });
                    }
                    Action::RemoveNetwork(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        thread::spawn(move || {
                            let performed = crate::reports::perform_network_removal(
                                &home,
                                &plan,
                                &plan.preview_token,
                            );
                            let _ = tx.send(WorkerEvent::NetworkRemoved(performed));
                        });
                    }
                    Action::PreviewScheduleEdit(frequency) => {
                        schedule_explicit = false;
                        app.schedule_read_only = false;
                        let tx = tx.clone();
                        let config = config.clone();
                        let profile = profile.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                let executable = std::env::current_exe()?.canonicalize()?;
                                crate::schedule::preview_configured_edit(
                                    &executable,
                                    config.as_deref(),
                                    profile.as_deref(),
                                    frequency,
                                )
                            });
                            let _ = tx.send(WorkerEvent::ScheduleEditPreview(result, frequency));
                        });
                    }
                    Action::EditSchedule(plan, frequency) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        let config = config.clone();
                        let profile = profile.clone();
                        let explicit = schedule_explicit;
                        thread::spawn(move || {
                            let executable =
                                std::env::current_exe().and_then(|path| path.canonicalize());
                            let performed = match executable {
                                Ok(executable) if explicit => {
                                    crate::reports::perform_schedule_edit(
                                        &home,
                                        &executable,
                                        &plan,
                                        &plan.preview_token,
                                        frequency,
                                    )
                                }
                                Ok(executable) => crate::reports::perform_configured_schedule_edit(
                                    &home,
                                    &executable,
                                    &plan,
                                    &plan.preview_token,
                                    frequency,
                                    config.as_deref(),
                                    profile.as_deref(),
                                ),
                                Err(error) => crate::reports::Performed {
                                    result: Err(format!("cannot resolve executable: {error}")),
                                    history_warning: None,
                                },
                            };
                            let _ = tx.send(WorkerEvent::ScheduleEdited(performed));
                        });
                    }
                    Action::PreviewScheduleRemove => {
                        schedule_explicit = false;
                        app.schedule_read_only = false;
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let result = operation_worker(crate::schedule::preview_remove);
                            let _ = tx.send(WorkerEvent::ScheduleRemovePreview(result));
                        });
                    }
                    Action::RemoveSchedule(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        thread::spawn(move || {
                            let performed = crate::reports::perform_schedule_removal(
                                &home,
                                &plan,
                                &plan.preview_token,
                            );
                            let _ = tx.send(WorkerEvent::ScheduleRemoved(performed));
                        });
                    }
                    Action::PreviewScheduleInstall(frequency, read_only) => {
                        schedule_explicit = false;
                        app.schedule_read_only = read_only;
                        let tx = tx.clone();
                        let config = config.clone();
                        let profile = profile.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                let executable = std::env::current_exe()?.canonicalize()?;
                                crate::schedule::preview_configured_install(
                                    &executable,
                                    config.as_deref(),
                                    profile.as_deref(),
                                    frequency,
                                )
                            });
                            let _ = tx.send(WorkerEvent::ScheduleInstallPreview(result, frequency));
                        });
                    }
                    Action::InstallSchedule(plan, frequency) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        let config = config.clone();
                        let profile = profile.clone();
                        let explicit = schedule_explicit;
                        thread::spawn(move || {
                            let executable =
                                std::env::current_exe().and_then(|path| path.canonicalize());
                            let performed = match executable {
                                Ok(executable) if explicit => {
                                    crate::reports::perform_schedule_install(
                                        &home,
                                        &executable,
                                        &plan,
                                        &plan.preview_token,
                                        frequency,
                                    )
                                }
                                Ok(executable) => {
                                    crate::reports::perform_configured_schedule_install(
                                        &home,
                                        &executable,
                                        &plan,
                                        &plan.preview_token,
                                        frequency,
                                        config.as_deref(),
                                        profile.as_deref(),
                                    )
                                }
                                Err(error) => crate::reports::Performed {
                                    result: Err(format!("cannot resolve executable: {error}")),
                                    history_warning: None,
                                },
                            };
                            let _ = tx.send(WorkerEvent::ScheduleInstalled(performed));
                        });
                    }
                    Action::PreviewScheduleEnable(frequency) => {
                        schedule_explicit = false;
                        app.schedule_read_only = false;
                        let tx = tx.clone();
                        let config = config.clone();
                        let profile = profile.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                let executable = std::env::current_exe()?.canonicalize()?;
                                crate::schedule::preview_configured_enable(
                                    &executable,
                                    config.as_deref(),
                                    profile.as_deref(),
                                    frequency,
                                )
                            });
                            let _ = tx.send(WorkerEvent::ScheduleEnablePreview(result, frequency));
                        });
                    }
                    Action::EnableSchedule(plan, frequency) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        let config = config.clone();
                        let profile = profile.clone();
                        let explicit = schedule_explicit;
                        thread::spawn(move || {
                            let executable =
                                std::env::current_exe().and_then(|path| path.canonicalize());
                            let performed = match executable {
                                Ok(executable) if explicit => {
                                    crate::reports::perform_schedule_enable(
                                        &home,
                                        &executable,
                                        &plan,
                                        &plan.preview_token,
                                        frequency,
                                    )
                                }
                                Ok(executable) => {
                                    crate::reports::perform_configured_schedule_enable(
                                        &home,
                                        &executable,
                                        &plan,
                                        &plan.preview_token,
                                        frequency,
                                        config.as_deref(),
                                        profile.as_deref(),
                                    )
                                }
                                Err(error) => crate::reports::Performed {
                                    result: Err(format!("cannot resolve executable: {error}")),
                                    history_warning: None,
                                },
                            };
                            let _ = tx.send(WorkerEvent::ScheduleEnabled(performed));
                        });
                    }
                    Action::PreviewScheduleDisable => {
                        schedule_explicit = false;
                        app.schedule_read_only = false;
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let result = operation_worker(crate::schedule::preview_disable);
                            let _ = tx.send(WorkerEvent::ScheduleDisablePreview(result));
                        });
                    }
                    Action::DisableSchedule(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        thread::spawn(move || {
                            let performed = crate::reports::perform_schedule_disable(
                                &home,
                                &plan,
                                &plan.preview_token,
                            );
                            let _ = tx.send(WorkerEvent::ScheduleDisabled(performed));
                        });
                    }
                    #[cfg(target_os = "linux")]
                    Action::PreviewTrashRetentionInstall(location, age) => {
                        app.schedule_read_only = false;
                        let tx = tx.clone();
                        let config = config.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                let executable = std::env::current_exe()?.canonicalize()?;
                                let config_path = crate::config::config_path(config.as_deref())?;
                                crate::schedule::trash_retention::preview_trash_retention(
                                    &executable,
                                    &config_path,
                                    &location,
                                    age,
                                )
                            })
                            .map(TrashRetentionReviewPlan::Install);
                            let _ = tx.send(WorkerEvent::TrashRetentionPreview(result, false));
                        });
                    }
                    #[cfg(target_os = "linux")]
                    Action::PreviewTrashRetentionEnable => {
                        app.schedule_read_only = false;
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                crate::schedule::trash_retention::preview_trash_retention_enable()
                            })
                            .map(TrashRetentionReviewPlan::Enable);
                            let _ = tx.send(WorkerEvent::TrashRetentionPreview(result, false));
                        });
                    }
                    #[cfg(target_os = "linux")]
                    Action::PreviewTrashRetentionDisable => {
                        app.schedule_read_only = false;
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                crate::schedule::trash_retention::preview_trash_retention_disable()
                            })
                            .map(TrashRetentionReviewPlan::Disable);
                            let _ = tx.send(WorkerEvent::TrashRetentionPreview(result, false));
                        });
                    }
                    #[cfg(target_os = "linux")]
                    Action::PreviewTrashRetentionRemove => {
                        app.schedule_read_only = false;
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                crate::schedule::trash_retention::preview_trash_retention_remove()
                            })
                            .map(TrashRetentionReviewPlan::Remove);
                            let _ = tx.send(WorkerEvent::TrashRetentionPreview(result, false));
                        });
                    }
                    #[cfg(target_os = "linux")]
                    Action::InstallTrashRetention(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        thread::spawn(move || {
                            let performed = crate::reports::perform_trash_retention_install(
                                &home,
                                &plan,
                                &plan.preview_token,
                            );
                            let _ =
                                tx.send(WorkerEvent::TrashRetentionChanged("install", performed));
                        });
                    }
                    #[cfg(target_os = "linux")]
                    Action::EnableTrashRetention(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        thread::spawn(move || {
                            let performed = crate::reports::perform_trash_retention_enable(
                                &home,
                                &plan,
                                &plan.preview_token,
                            );
                            let _ =
                                tx.send(WorkerEvent::TrashRetentionChanged("enable", performed));
                        });
                    }
                    #[cfg(target_os = "linux")]
                    Action::DisableTrashRetention(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        thread::spawn(move || {
                            let performed = crate::reports::perform_trash_retention_disable(
                                &home,
                                &plan,
                                &plan.preview_token,
                            );
                            let _ =
                                tx.send(WorkerEvent::TrashRetentionChanged("disable", performed));
                        });
                    }
                    #[cfg(target_os = "linux")]
                    Action::RemoveTrashRetention(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        thread::spawn(move || {
                            let performed = crate::reports::perform_trash_retention_remove(
                                &home,
                                &plan,
                                &plan.preview_token,
                            );
                            let _ =
                                tx.send(WorkerEvent::TrashRetentionChanged("remove", performed));
                        });
                    }
                    Action::RefreshSchedule => {
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let _ = tx.send(WorkerEvent::Schedule(crate::schedule::status()));
                        });
                    }
                    Action::RefreshToolchains => {
                        check(worker_ctx.clone(), kinds.clone(), tx.clone());
                    }
                    Action::RefreshHistory => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        thread::spawn(move || {
                            let _ = tx.send(WorkerEvent::History(
                                crate::reports::read(&home).map_err(|err| format!("{err:#}")),
                            ));
                        });
                    }
                    Action::PreviewHistoryPurge(age) => {
                        history_purge_cancel.store(false, Ordering::Relaxed);
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        let cancel = history_purge_cancel.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                crate::reports::preview_history_purge(&home, age, &cancel)
                            });
                            let _ = tx.send(WorkerEvent::HistoryPurgePreview(result));
                        });
                    }
                    Action::PurgeHistory(plan) => {
                        history_purge_cancel.store(false, Ordering::Relaxed);
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        let cancel = history_purge_cancel.clone();
                        thread::spawn(move || {
                            let progress_tx = tx.clone();
                            let performed = operation_worker(|| {
                                Ok(crate::reports::perform_history_purge(
                                    &home,
                                    &plan,
                                    &plan.preview_token,
                                    &cancel,
                                    move |done, total| {
                                        let _ = progress_tx
                                            .send(WorkerEvent::HistoryPurgeProgress(done, total));
                                    },
                                ))
                            })
                            .unwrap_or_else(|error| {
                                crate::reports::Performed {
                                    result: Err(error),
                                    history_warning: None,
                                }
                            });
                            let _ = tx.send(WorkerEvent::HistoryPurged(performed));
                        });
                    }
                    Action::CancelHistoryPurge => {
                        history_purge_cancel.store(true, Ordering::Relaxed)
                    }
                    Action::RefreshDoctor => {
                        doctor_cancel.store(false, Ordering::Relaxed);
                        inspect_doctor(
                            doctor_ctx.clone(),
                            config.clone(),
                            profile.clone(),
                            doctor_cancel.clone(),
                            tx.clone(),
                        );
                    }
                    Action::LoadSettings => inspect_settings(config.clone(), tx.clone()),
                    Action::SaveSettings(snapshot, text) => {
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let result =
                                operation_worker(|| crate::config::save_document(&snapshot, &text));
                            let _ = tx.send(WorkerEvent::SettingsSaved(result));
                        });
                    }
                    Action::StartTrash(age) => {
                        trash_cancel.store(false, Ordering::Relaxed);
                        inspect_trash(trash_cancel.clone(), age, tx.clone());
                    }
                    Action::PreviewGoTest(path) => {
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                crate::cache::go_test_expiration_preview(&path)
                            });
                            let _ = tx.send(WorkerEvent::GoTestPreview(result));
                        });
                    }
                    Action::ExpireGoTest(plan) => {
                        let tx = tx.clone();
                        let home = ctx.home.clone();
                        thread::spawn(move || {
                            let performed = crate::reports::perform_go_test_expiration(
                                &home,
                                &plan,
                                &plan.preview_token,
                            );
                            let _ = tx.send(WorkerEvent::GoTestFinished(performed));
                        });
                    }
                    Action::StartCache => {
                        cache_cancel.store(false, Ordering::Relaxed);
                        let cancel = cache_cancel.clone();
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let _ = tx.send(WorkerEvent::Cache(crate::cache::inventory(&cancel)));
                        });
                    }
                    Action::Update(targets) => {
                        let ctx = worker_ctx.clone();
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let total = targets.len();
                            let results = targets
                                .into_iter()
                                .enumerate()
                                .map(|(index, tool)| {
                                    let _ = tx.send(WorkerEvent::Updating(tool, index + 1, total));
                                    let result = ensure_dirs(&ctx)
                                        .and_then(|()| update_tool(&ctx, tool))
                                        .map_err(|err| format!("{err:#}"));
                                    (tool, result)
                                })
                                .collect();
                            let _ = tx.send(WorkerEvent::Updated(results));
                        });
                    }
                    Action::PreviewSelfUpdate => {
                        inspect_self_update(worker_ctx.clone(), tx.clone());
                    }
                    Action::SelfUpdate(plan) => {
                        let ctx = worker_ctx.clone();
                        let tx = tx.clone();
                        thread::spawn(move || {
                            let result = operation_worker(|| {
                                crate::application::run_approved_self_update(&ctx, &plan)
                            });
                            let _ = tx.send(WorkerEvent::SelfUpdated(result));
                        });
                    }
                    Action::None => {}
                }
            }
        }
        if self_update_requested && self_update_failed {
            anyhow::bail!("self-update failed or its outcome is unknown");
        }
        Ok(())
    })();
    drop(terminal);
    let restore = session.restore();
    result.and(restore.map_err(Into::into))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Status, UpdateMethod};
    use ratatui::{Terminal, backend::TestBackend};
    #[cfg(target_os = "linux")]
    use std::path::Path;

    #[cfg(target_os = "linux")]
    fn visible_buffer_rows(terminal: &Terminal<TestBackend>) -> Vec<String> {
        let buffer = terminal.backend().buffer();
        let area = buffer.area;
        (area.y..area.y.saturating_add(area.height))
            .map(|y| {
                (area.x..area.x.saturating_add(area.width))
                    .map(|x| buffer.cell((x, y)).map_or(" ", |cell| cell.symbol()))
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn bytecode_cleanup_policy_token() -> String {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("workspace");
        let config = directory.path().join("upkit.toml");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            &config,
            format!(
                "version = 1\nworkspace_roots = ['{}']\nartifact_retention = '7d'\nenabled_ecosystems = ['python']\nscheduled_bytecode_cleanup = true\n",
                root.display(),
            ),
        )
        .unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let plan = crate::schedule::preview_configured_install(
            &executable,
            Some(&config),
            None,
            crate::schedule::Frequency::Daily,
        )
        .unwrap();
        assert!(plan.scheduled_scope_token.starts_with("v3."));
        plan.scheduled_scope_token
    }

    fn app() -> App {
        App {
            reports: Some(vec![ToolReport {
                tool: ToolKind::Go,
                installed: None,
                latest: None,
                status: Status::Unknown,
                method: UpdateMethod::DirectDownload,
                notes: vec![],
            }]),
            startup_checks: StartupChecks::default(),
            toolchain_check_failed: false,
            maintenance_check_failed: false,
            page: Start::Toolchains,
            help: false,
            help_scroll: 0,
            selected: 0,
            confirmation: false,
            updating: false,
            self_update_preparing: false,
            self_update_command: false,
            self_update_plan: None,
            message: String::new(),
            issues: None,
            doctor_available_bytes: None,
            doctor_capabilities: None,
            doctor_scroll: 0,
            doctor_filter: String::new(),
            doctor_search: None,
            dashboard_scroll: 0,
            marked: vec![],
            toolchain_filter: String::new(),
            toolchain_search: None,
            force: false,
            managed_mode: false,
            managed_scope: None,
            managed_preparing: false,
            managed_running: false,
            managed_plan: None,
            managed_batch_plans: Vec::new(),
            managed_batch_review_scroll: 0,
            managed_batch_review_rows: 0,
            managed_batch_review_lines: 0,
            managed_batch_review_area: Rect::default(),
            managed_batch_review_content: None,
            managed_current: None,
            managed_detail: false,
            managed_detail_scroll: 0,
            managed_result: None,
            managed_result_scroll: 0,
            scan: None,
            scan_running: false,
            scan_visited: 0,
            scan_scroll: 0,
            artifact_filter: String::new(),
            artifact_sort: ArtifactSort::default(),
            artifact_marks: Vec::new(),
            artifact_search: None,
            preview_mode: false,
            cli_preview_read_only: false,
            plan: None,
            plan_detail: false,
            detail_scroll: 0,
            artifact_preparing: false,
            artifact_running: false,
            artifact_plan: None,
            artifact_review_scroll: 0,
            artifact_review_rows: 0,
            artifact_review_lines: 0,
            artifact_review_width: 0,
            artifact_review_content: None,
            artifact_confirm: false,
            bytecode_preparing: false,
            bytecode_running: false,
            bytecode_plan: None,
            bytecode_batch_plan: None,
            bytecode_listing_running: false,
            bytecode_listing: None,
            bytecode_selected: 0,
            bytecode_marks: Vec::new(),
            maintenance: None,
            trim_selected: 0,
            trim_preparing: false,
            trim_running: false,
            trim_plan: None,
            trim_read_only: false,
            dry_run: false,
            temp_mode: false,
            temp_plan: None,
            temp_marks: Vec::new(),
            temp_selected: 0,
            temp_preparing: false,
            temp_running: false,
            temp_review_plan: None,
            temp_review_confirm: false,
            temp_review_scroll: 0,
            temp_review_rows: 0,
            temp_review_lines: 0,
            temp_review_area: Rect::default(),
            temp_result: None,
            temp_result_scroll: 0,
            temp_inventory_scroll_offset: 0,
            cache: None,
            cache_running: false,
            cache_scroll: 0,
            cache_filter: String::new(),
            cache_sort: CacheSort::default(),
            cache_details: false,
            cache_search: None,
            cache_choosing: false,
            cache_selected: None,
            go_test_preparing: false,
            go_test_running: false,
            go_test_plan: None,
            go_test_read_only: false,
            trash: None,
            trash_preview: None,
            trash_age: None,
            trash_running: false,
            trash_scroll: 0,
            trash_selected: 0,
            trash_review: false,
            trash_review_scroll: 0,
            trash_removal_preparing: false,
            trash_marking: false,
            trash_removing: false,
            trash_removal_plan: None,
            trash_last_result: None,
            containers: None,
            containers_running: false,
            containers_scroll: 0,
            container_selected: 0,
            container_filter: String::new(),
            container_search: None,
            container_preparing: false,
            container_removing: false,
            container_plan: None,
            network_preparing: false,
            network_removing: false,
            network_plan: None,
            build_cache_preparing: false,
            build_cache_removing: false,
            build_cache_plan: None,
            build_cache_read_only: false,
            schedule: None,
            schedule_running: false,
            schedule_scroll: 0,
            schedule_read_only: false,
            schedule_preview_scroll: 0,
            schedule_confirmation_scroll: 0,
            schedule_confirmation_area: Rect::default(),
            schedule_confirmation_identity: None,
            schedule_confirmation_content: None,
            schedule_edit_preparing: false,
            schedule_edit_running: false,
            schedule_edit_plan: None,
            schedule_remove_preparing: false,
            schedule_remove_running: false,
            schedule_remove_plan: None,
            schedule_disable_preparing: false,
            schedule_disable_running: false,
            schedule_disable_plan: None,
            schedule_install_preparing: false,
            schedule_install_running: false,
            schedule_install_plan: None,
            schedule_enable_preparing: false,
            schedule_enable_running: false,
            schedule_enable_plan: None,
            #[cfg(target_os = "linux")]
            trash_retention_status: None,
            #[cfg(target_os = "linux")]
            trash_retention_status_loading: false,
            #[cfg(target_os = "linux")]
            trash_retention_preparing: false,
            #[cfg(target_os = "linux")]
            trash_retention_running: false,
            #[cfg(target_os = "linux")]
            trash_retention_plan: None,
            history: None,
            history_running: false,
            history_scroll: 0,
            history_oldest_first: false,
            history_filter: String::new(),
            history_search: None,
            history_purge_preparing: false,
            history_purging: false,
            history_purge_read_only: false,
            history_purge_plan: None,
            history_purge_result: None,
            history_purge_warning: None,
            history_purge_scroll: 0,
            history_purge_area: Rect::default(),
            history_purge_content: None,
            settings: None,
            settings_loading: false,
            theme: crate::config::Theme::Dark,
            settings_saving: false,
            settings_editor: None,
            settings_form: None,
            settings_pending_save: None,
            settings_prompt: None,
            settings_scroll: 0,
            settings_confirmation_scroll: 0,
            settings_confirmation_area: Rect::default(),
        }
    }

    #[cfg(target_os = "linux")]
    fn sealed_managed_tool_fixture(
        home: &Path,
        bindir: &Path,
        tool: ToolKind,
        extra_entries: usize,
    ) -> PathBuf {
        use std::os::unix::fs::{PermissionsExt, symlink};

        assert!(matches!(tool, ToolKind::Go | ToolKind::Node));
        std::fs::create_dir_all(home).unwrap();
        std::fs::create_dir_all(bindir).unwrap();
        std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o755)).unwrap();
        let root = home.join(tool.as_str());
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(bindir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let stage = crate::infrastructure::new_install_stage(&root).unwrap();
        let tool_dir = stage.path().join(tool.as_str());
        let bin = tool_dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::set_permissions(&tool_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let executable = bin.join(tool.as_str());
        std::fs::write(&executable, "sealed fixture executable").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o644)).unwrap();
        crate::installation_identity::seal(&root, &stage, tool, "fixture").unwrap();

        let install = stage.keep();
        symlink(install.join(tool.as_str()), root.join("active")).unwrap();
        crate::installation_identity::record_active_link(&root, bindir, tool).unwrap();
        let link = bindir.join(tool.as_str());
        let target = root.join("active/bin").join(tool.as_str());
        symlink(&target, &link).unwrap();
        crate::installation_identity::record_created_links(&root, bindir, tool, &[(link, target)])
            .unwrap();

        for index in 0..extra_entries {
            std::fs::write(root.join(format!("entry-{index:02}")), "preserved fixture").unwrap();
        }
        install
    }

    #[cfg(target_os = "linux")]
    fn temp_cleanup_fixture(
        count: usize,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        crate::temp_cleanup::Plan,
    ) {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("upkit-home");
        let bindir = root.path().join("upkit-bin");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&bindir).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&bindir, std::fs::Permissions::from_mode(0o700)).unwrap();
        for index in 0..count {
            let staging = bindir.join(format!(".upkit-link-fixture-{index}"));
            std::fs::create_dir(&staging).unwrap();
            std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
            symlink(home.join("go/versions/1.2.3/bin/go"), staging.join("link")).unwrap();
            let modified = std::time::SystemTime::now()
                .checked_sub(Duration::from_secs(40 * 86_400))
                .unwrap();
            std::fs::File::open(&staging)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(modified))
                .unwrap();
        }
        let cancel = AtomicBool::new(false);
        let plan = crate::temp_cleanup::preview_for_tui_test(&home, &bindir, &[], &cancel).unwrap();
        (root, home, bindir, plan)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn temp_cleanup_candidate_scroll_keeps_selected_status_and_path_visible() {
        let (_root, _home, _bindir, plan) = temp_cleanup_fixture(6);
        let mut app = app();
        app.page = Start::Maintenance;
        app.temp_mode = true;
        app.temp_plan = Some(Ok(plan));
        app.temp_selected = 5;
        let mut terminal = Terminal::new(TestBackend::new(40, 14)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = visible_buffer_rows(&terminal);
        assert!(
            rendered.iter().any(|row| row.contains("eligible")),
            "{rendered:?}"
        );
        assert!(
            rendered.iter().any(|row| row.contains("age=40d")),
            "{rendered:?}"
        );
        assert!(
            rendered.iter().any(|row| row.contains("fixture-5")),
            "{rendered:?}"
        );
        assert!(rendered.iter().any(|row| row.contains("›")), "{rendered:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn temp_cleanup_inventory_can_scroll_to_warnings_then_follow_selection() {
        let (_root, _home, _bindir, mut plan) = temp_cleanup_fixture(6);
        plan.warnings
            .push("fixture inventory warning at the end".into());
        let mut app = app();
        app.page = Start::Maintenance;
        app.temp_mode = true;
        app.temp_plan = Some(Ok(plan));
        let mut terminal = Terminal::new(TestBackend::new(60, 12)).unwrap();

        app.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let bottom = visible_buffer_rows(&terminal);
        let bottom_text = bottom.join(" ");
        assert!(
            bottom_text.contains("Warning: fixture inventory warning at")
                && bottom_text.contains("the end"),
            "{bottom:?}"
        );

        let space = KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE);
        assert!(matches!(app.key(space), Action::None));
        assert!(app.temp_marks.is_empty());
        assert_eq!(app.temp_inventory_scroll_offset, 0);
        assert!(app.message.contains("press Space again to mark it"));
        assert!(matches!(app.key(space), Action::None));
        assert_eq!(
            app.temp_marks,
            vec![
                app.temp_plan.as_ref().unwrap().as_ref().unwrap().candidates[0]
                    .path
                    .clone()
            ]
        );

        app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.temp_inventory_scroll_offset, 0);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let selected = visible_buffer_rows(&terminal);
        assert!(
            selected.iter().any(|row| row.contains("fixture-1")),
            "{selected:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn temp_cleanup_requires_full_review_after_resize_before_confirming() {
        let (_root, home, bindir, inventory) = temp_cleanup_fixture(3);
        let selected = vec![inventory.candidates[0].path.clone()];
        let cancel = AtomicBool::new(false);
        let plan =
            crate::temp_cleanup::preview_for_tui_test(&home, &bindir, &selected, &cancel).unwrap();
        let fixture_path = selected[0].clone();
        let mut app = app();
        app.page = Start::Maintenance;
        app.temp_mode = true;
        app.temp_review_plan = Some(plan);

        let small = Rect::new(0, 0, 56, 10);
        app.update_temp_review(small);
        let mut terminal = Terminal::new(TestBackend::new(56, 10)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(
            visible_buffer_rows(&terminal)
                .iter()
                .any(|row| row.contains("Review temporary staging inventory"))
        );
        assert!(app.temp_review_lines > app.temp_review_rows);
        let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        assert!(matches!(app.key(enter), Action::None));
        assert!(!app.temp_review_confirm);

        app.temp_review_scroll = (app.temp_review_lines - app.temp_review_rows) as u16;
        app.key(enter);
        assert!(app.temp_review_confirm);
        app.temp_review_scroll = 1;
        let resized = Rect::new(0, 0, 60, 14);
        app.update_temp_review(resized);
        assert_eq!(app.temp_review_scroll, 0, "resize must restart the review");
        let mut terminal = Terminal::new(TestBackend::new(60, 14)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(!app.temp_running);

        app.temp_review_scroll = (app.temp_review_lines - app.temp_review_rows) as u16;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::RemoveTempCleanup(_)
        ));
        assert!(
            fixture_path.join("link").is_symlink(),
            "test must not execute cleanup"
        );
    }

    #[test]
    fn temp_cleanup_subview_closes_before_page_navigation() {
        let mut app = app();
        app.page = Start::Maintenance;
        app.temp_mode = true;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.page == Start::Cache);
        assert!(!app.temp_mode);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn temp_cleanup_result_scroll_reaches_history_warning() {
        let mut app = app();
        app.page = Start::Maintenance;
        app.temp_mode = true;
        app.temp_result = Some(
            (0..20)
                .map(|index| format!("fixture result detail {index}"))
                .chain(std::iter::once("fixture history warning".into()))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
        for _ in 0..20 {
            app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        }
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("fixture history warning"));
    }

    fn history_purge_plan(candidate_count: usize) -> crate::reports::HistoryPurgePlan {
        crate::reports::HistoryPurgePlan {
            older_than_seconds: 7 * 86_400,
            cutoff_unix: 1_000,
            record_count: candidate_count + 2,
            skipped_unfinished_records: 2,
            candidates: (0..candidate_count)
                .map(|index| crate::reports::HistoryPurgeCandidate {
                    id: index,
                    started_unix: 100 + index as u64,
                    finished_unix: Some(200 + index as u64),
                    operation: "fixture_cleanup".into(),
                    target: format!("/fixture/target-{index:02}"),
                    outcome: "completed".into(),
                })
                .collect(),
            preview_token: "fixture-token".into(),
            warning: "Fixture purge warning; records are permanently removed.",
        }
    }

    #[test]
    fn reports_offer_seven_thirty_and_ninety_day_purge_previews() {
        let mut app = app();
        app.page = Start::Reports;
        for (key, seconds) in [('7', 7 * 86_400), ('3', 30 * 86_400), ('9', 90 * 86_400)] {
            assert!(matches!(
                app.key(KeyEvent::new(KeyCode::Char(key), KeyModifiers::NONE)),
                Action::PreviewHistoryPurge(age) if age == Duration::from_secs(seconds)
            ));
            app.history_purge_preparing = false;
        }
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('7'), KeyModifiers::CONTROL)),
            Action::None
        ));
    }

    #[test]
    fn cli_history_preview_stays_read_only_in_reports_screen() {
        let mut app = app();
        app.page = Start::Reports;
        app.history_purge_read_only = true;
        app.history_purge_plan = Some(history_purge_plan(1));
        let area = Rect::new(0, 0, 120, 20);
        app.update_history_purge_review(area);

        let mut terminal = Terminal::new(TestBackend::new(120, 20)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("History purge preview"));
        assert!(output.contains("Preview only; records will not be removed."));
        assert!(!output.contains("Press y after reviewing every record"));
        assert!(!history_purge_ready(&app, area));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.history_purge_plan.is_some());
        assert!(!app.history_purging);

        app.key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        assert!(app.history_purge_plan.is_none());
        assert!(!app.history_purge_read_only);
    }

    #[test]
    fn history_purge_preview_requires_scrolling_through_all_candidates() {
        let mut app = app();
        app.page = Start::Reports;
        app.history_purge_plan = Some(history_purge_plan(12));
        let area = Rect::new(0, 0, 100, 10);
        app.update_history_purge_review(area);
        let mut terminal = Terminal::new(TestBackend::new(100, 10)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let first = format!("{:?}", terminal.backend().buffer());
        assert!(first.contains("target-00"));
        assert!(first.contains("unfinished records skipped"));
        assert!(!first.contains("target-11"));
        assert!(!history_purge_ready(&app, area));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.history_purge_plan.is_some());

        while !history_purge_ready(&app, area) {
            app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        }
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let last = format!("{:?}", terminal.backend().buffer());
        assert!(last.contains("target-11"));
        assert!(last.contains("Fixture purge warning"));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::PurgeHistory(_)
        ));
        assert!(app.history_purging);
    }

    #[test]
    fn repeated_vi_keys_only_scroll_a_destructive_review() {
        let mut app = app();
        app.page = Start::Reports;
        app.history_purge_plan = Some(history_purge_plan(12));
        let area = Rect::new(0, 0, 100, 10);
        app.update_history_purge_review(area);
        let repeated =
            |code| KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Repeat);

        assert!(matches!(
            app.key(repeated(KeyCode::Char('j'))),
            Action::None
        ));
        assert_eq!(app.history_purge_scroll, 1);
        assert!(app.history_purge_plan.is_some());
        assert!(!app.history_purging);

        assert!(matches!(
            app.key(repeated(KeyCode::Char('k'))),
            Action::None
        ));
        assert_eq!(app.history_purge_scroll, 0);
        assert!(app.history_purge_plan.is_some());
        assert!(!app.history_purging);
    }

    #[test]
    fn history_purge_review_never_confirms_after_scroll_saturates() {
        let mut app = app();
        app.page = Start::Reports;
        let mut plan = history_purge_plan(65);
        for candidate in &mut plan.candidates {
            candidate.target = "x".repeat(1_024);
        }
        app.history_purge_plan = Some(plan);
        let area = Rect::new(0, 0, 5, 12);
        app.update_history_purge_review(area);
        app.history_purge_scroll = u16::MAX;
        assert!(!history_purge_ready(&app, area));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.history_purge_plan.is_some());
    }

    #[test]
    fn history_purge_escape_requests_worker_cancellation() {
        let mut app = app();
        app.page = Start::Reports;
        app.history_purge_preparing = true;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            Action::CancelHistoryPurge
        ));
        assert!(app.message.contains("Cancelling history purge preview"));

        app.history_purge_preparing = false;
        app.history_purging = true;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            Action::CancelHistoryPurge
        ));
        let mut terminal = Terminal::new(TestBackend::new(120, 20)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(
            format!("{:?}", terminal.backend().buffer())
                .contains("Cancellation requested; removal may already be in progress.")
        );
    }

    #[test]
    fn history_purge_result_renders_each_item_and_history_warning() {
        let mut app = app();
        app.page = Start::Reports;
        app.history_purge_result = Some(crate::reports::HistoryPurgeResult {
            outcome: "partial",
            cancelled: true,
            items: vec![
                crate::reports::HistoryPurgeItem {
                    id: 41,
                    status: "removed",
                    error: None,
                },
                crate::reports::HistoryPurgeItem {
                    id: 42,
                    status: "not_attempted_cancelled",
                    error: Some("cancelled after the prior item".into()),
                },
            ],
        });
        app.history_purge_warning = Some("fixture history write warning".into());
        app.history_running = true;
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("History purge: partial (cancelled)"));
        assert!(output.contains("Record 41: removed"));
        assert!(output.contains("Record 42: not_attempted_cancelled"));
        assert!(output.contains("cancelled after the prior item"));
        assert!(output.contains("fixture history write warning"));
    }

    fn review_schedule_confirmation_to_end(app: &mut App, area: Rect) {
        app.update_schedule_confirmation(area);
        let (_, lines, _) = schedule_confirmation_review(app).expect("schedule plan exists");
        assert!(!schedule_confirmation_can_confirm(app, area, area));
        assert!(!schedule_confirmation_can_confirm(
            app,
            area,
            Rect::new(area.x, area.y, area.width.saturating_add(1), area.height)
        ));
        let visible = schedule_confirmation_visible_rows(area);
        let content_len = app
            .schedule_confirmation_content
            .as_ref()
            .expect("review content exists")
            .len();
        assert!(content_len > visible);
        while app.schedule_confirmation_scroll + visible < content_len {
            let previous_scroll = app.schedule_confirmation_scroll;
            app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
            assert!(app.schedule_confirmation_scroll < previous_scroll + visible);
        }
        assert!(schedule_confirmation_ready(app, &lines, area));
        assert!(schedule_confirmation_can_confirm(app, area, area));
    }

    fn container_reports() -> Vec<crate::containers::EngineStatus> {
        vec![crate::containers::EngineStatus {
            engine: "docker",
            state: "available",
            detail: None,
            usage: vec![],
            resources: vec![
                crate::containers::ResourceList {
                    kind: "containers",
                    items: vec![
                        serde_json::json!({
                            "ID": "a".repeat(64),
                            "State": "exited",
                            "Names": "worker-build-1",
                            "Image": "example/build:old"
                        }),
                        serde_json::json!({
                            "ID": "b".repeat(64),
                            "State": "running",
                            "Names": "hidden-running"
                        }),
                    ],
                    error: None,
                },
                crate::containers::ResourceList {
                    kind: "dangling images",
                    items: vec![serde_json::json!({
                        "ID": format!("sha256:{}", "c".repeat(64)),
                        "Size": "23MB"
                    })],
                    error: None,
                },
                crate::containers::ResourceList {
                    kind: "unattached custom networks (snapshot)",
                    items: vec![serde_json::json!({
                        "ID": "d".repeat(64),
                        "Name": "temporary-net",
                        "Driver": "bridge"
                    })],
                    error: None,
                },
                crate::containers::ResourceList {
                    kind: crate::containers::BUILD_CACHE,
                    items: vec![serde_json::json!({
                        "Builder": "builder-one",
                        "ID": "e".repeat(25),
                        "Type": "regular",
                        "Size": "42MB",
                        "Reclaimable": true,
                        "Mutable": false,
                        "Shared": false
                    })],
                    error: None,
                },
            ],
        }]
    }

    fn toolchain_reports() -> Vec<ToolReport> {
        let version = |major, minor, patch| crate::domain::Version {
            major,
            minor,
            patch,
            pre: None,
        };
        vec![
            ToolReport {
                tool: ToolKind::Go,
                installed: None,
                latest: None,
                status: Status::Unknown,
                method: UpdateMethod::DirectDownload,
                notes: vec![],
            },
            ToolReport {
                tool: ToolKind::Node,
                installed: None,
                latest: Some(version(24, 1, 0)),
                status: Status::NotInstalled,
                method: UpdateMethod::DirectDownload,
                notes: vec!["Windows: put node/active first on PATH.".into()],
            },
            ToolReport {
                tool: ToolKind::Java,
                installed: Some(version(21, 0, 0)),
                latest: Some(version(25, 0, 0)),
                status: Status::Outdated,
                method: UpdateMethod::DirectDownload,
                notes: vec![],
            },
        ]
    }

    #[test]
    fn artifact_review_requires_complete_visible_list_and_confirmation() {
        let mut app = app();
        let plan = crate::artifact_cleanup::ArtifactPlan {
            scope: crate::sweep::Scope {
                roots: vec!["/fixture".into()],
                exclusions: vec![],
                older_than_seconds: None,
                enabled: None,
            },
            project: "/fixture/project".into(),
            manifest: "/fixture/project/Cargo.toml".into(),
            target: "/fixture/project/target".into(),
            ecosystem: "cargo",
            classification: "review",
            logical_bytes: 42,
            entries: (0..20)
                .map(|i| crate::artifact_cleanup::ArtifactEntry {
                    path: format!("file-{i:02}"),
                    kind: "file",
                    logical_bytes: Some(1),
                })
                .collect(),
            preview_token: "fixture".into(),
            #[cfg(target_os = "linux")]
            cargo_config_identity: None,
            #[cfg(target_os = "linux")]
            cargo_workspace_evidence: None,
            #[cfg(target_os = "linux")]
            git_evidence_id: None,
            warning: "fixture",
            reproduction_warning: Some(
                "Deleting this Hypothesis database removes saved failure examples used to reproduce test failures.",
            ),
        };
        let review = DirectoryPlan::Artifact(plan.clone());
        assert_eq!(artifact_review_rows(&review, Rect::new(0, 0, 30, 24)), 0);
        assert_eq!(artifact_review_rows(&review, Rect::new(0, 0, 120, 6)), 0);
        assert!(!artifact_confirmation_fits(&plan, Rect::new(0, 0, 120, 8)));
        assert!(artifact_confirmation_fits(&plan, Rect::new(0, 0, 120, 16)));
        assert!(artifact_confirmation_fits(&plan, Rect::new(0, 0, 120, 24)));
        app.artifact_plan = Some(DirectoryPlan::Artifact(plan));
        app.update_artifact_review(Rect::new(0, 0, 120, 16));
        let mut terminal = Terminal::new(TestBackend::new(120, 16)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("file-00"));
        assert!(!output.contains("file-19"));
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(matches!(app.key(key(KeyCode::Enter)), Action::None));
        assert!(!app.artifact_confirm);
        for _ in 0..10 {
            app.key(key(KeyCode::Down));
        }
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("file-19"));
        app.key(key(KeyCode::Enter));
        assert!(app.artifact_confirm);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("including user data"));
        assert!(output.contains("saved failure examples used to reproduce test failures"));
        assert!(output.contains("quarantine"));
        app.key(key(KeyCode::Esc));
        assert!(app.artifact_plan.is_none());
    }

    #[test]
    fn artifact_review_wraps_long_names_and_restarts_after_width_change() {
        let mut app = app();
        let mut plan = crate::artifact_cleanup::ArtifactPlan {
            scope: crate::sweep::Scope {
                roots: vec!["/fixture".into()],
                exclusions: vec![],
                older_than_seconds: None,
                enabled: None,
            },
            project: "/fixture/project".into(),
            manifest: "/fixture/project/Cargo.toml".into(),
            target: "/fixture/project/target".into(),
            ecosystem: "cargo",
            classification: "review",
            logical_bytes: 1,
            entries: vec![],
            preview_token: "fixture".into(),
            #[cfg(target_os = "linux")]
            cargo_config_identity: None,
            #[cfg(target_os = "linux")]
            cargo_workspace_evidence: None,
            #[cfg(target_os = "linux")]
            git_evidence_id: None,
            warning: "fixture",
            reproduction_warning: None,
        };
        assert!(
            artifact_confirmation_lines(&plan)
                .iter()
                .all(|line| !line.contains("saved failure examples"))
        );
        plan.entries.push(crate::artifact_cleanup::ArtifactEntry {
            path: format!("{}%FF-END", "a".repeat(900)),
            kind: "file",
            logical_bytes: Some(1),
        });
        let size = Rect::new(0, 0, 80, 12);
        let lines = artifact_review_lines(&DirectoryPlan::Artifact(plan.clone()), size).unwrap();
        assert!(lines.len() > 6);
        assert_eq!(
            lines.iter().map(|line| &line[2..]).collect::<String>(),
            artifact_entry_line(&plan.entries[0])
        );
        assert!(lines.iter().skip(1).all(|line| line.starts_with("+ ")));
        app.artifact_plan = Some(DirectoryPlan::Artifact(plan));
        app.update_artifact_review(size);
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.key(key(KeyCode::Enter));
        assert!(!app.artifact_confirm);
        for _ in 0..3 {
            app.key(key(KeyCode::Down));
        }
        assert_eq!(app.artifact_review_scroll, 3);
        app.update_artifact_review(Rect::new(0, 0, 90, 12));
        assert_eq!(app.artifact_review_scroll, 0);
        app.key(key(KeyCode::Enter));
        assert!(!app.artifact_confirm);
        let mut terminal = Terminal::new(TestBackend::new(90, 12)).unwrap();
        while app.artifact_review_scroll + app.artifact_review_rows < app.artifact_review_lines {
            terminal.draw(|frame| draw(frame, &app)).unwrap();
            app.key(key(KeyCode::Down));
        }
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("%FF-END"));
        app.key(key(KeyCode::Enter));
        assert!(app.artifact_confirm);
    }

    #[test]
    fn shared_cache_requires_selection_full_review_and_confirmation() {
        let mut app = app();
        app.page = Start::Cache;
        app.cache = Some(crate::cache::CacheReport {
            entries: vec![crate::cache::CacheEntry {
                name: "Go build",
                path: "/fixture/cache".into(),
                ownership: "shared user cache",
                directory_owner_status: "current_user",
                classification: "shared build cache",
                consequence: "packages may need recompilation",
                status: "inventory only",
                logical_bytes: Some(20),
                allocated_bytes: None,
                size_complete: true,
                activity_status: "no_open_handles_or_cwd_observed",
                warnings: vec![],
                go_test_cache: None,
            }],
            warnings: vec![],
            cancelled: false,
        });
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.key(key(KeyCode::Char('d')));
        assert!(app.cache_choosing);
        assert!(
            matches!(app.key(key(KeyCode::Enter)), Action::PreviewSharedCache(path) if path == std::path::Path::new("/fixture/cache"))
        );
        app.artifact_preparing = false;
        let plan = crate::shared_cache_cleanup::CacheRemovalPlan {
            name: "Go build",
            target: "/fixture/cache".into(),
            classification: "shared build cache",
            consequence: "packages may need recompilation",
            logical_bytes: 20,
            entries: (0..20)
                .map(|i| crate::artifact_cleanup::ArtifactEntry {
                    path: format!("file-{i:02}"),
                    kind: "file",
                    logical_bytes: Some(1),
                })
                .collect(),
            preview_token: "fixture".into(),
            warning: "fixture",
        };
        app.artifact_plan = Some(DirectoryPlan::Cache(plan));
        app.update_artifact_review(Rect::new(0, 0, 120, 16));
        app.key(key(KeyCode::Enter));
        assert!(!app.artifact_confirm);
        for _ in 0..10 {
            app.key(key(KeyCode::Down));
        }
        app.key(key(KeyCode::Enter));
        assert!(app.artifact_confirm);
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Confirm permanent shared-cache removal"));
        assert!(output.contains("user data or source files"));
        assert!(output.contains("recompilation"));
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::RemoveSharedCache(_)
        ));
    }

    #[test]
    fn dashboard_renders_at_multiple_sizes() {
        for (width, height, cards) in [(120, 24, true), (80, 24, false), (30, 10, false)] {
            let mut app = app();
            app.page = Start::Dashboard;
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|frame| draw(frame, &app)).unwrap();
            let output = format!("{:?}", terminal.backend().buffer());
            assert!(output.contains("Upkit"));
            if cards {
                assert!(output.contains("Storage & maintenance"));
                assert!(output.contains("Recent activity"));
            } else if width >= 60 {
                assert!(output.contains("Developer environment overview"));
            }
        }
    }

    #[test]
    fn dashboard_marks_scan_with_warnings_as_partial() {
        let mut app = app();
        app.scan = Some(Ok(crate::sweep::ScanReport {
            roots: vec![],
            candidates: vec![],
            warnings: vec!["a subtree was skipped".into()],
            cancelled: false,
        }));
        assert!(
            dashboard_cards(&app)[2]
                .1
                .contains("0 candidates (partial)")
        );
        app.scan
            .as_mut()
            .unwrap()
            .as_mut()
            .unwrap()
            .warnings
            .clear();
        assert!(!dashboard_cards(&app)[2].1.contains("partial"));
    }

    #[test]
    fn dashboard_shows_three_recent_operations_without_targets() {
        let mut app = app();
        app.page = Start::Dashboard;
        app.history = Some(Ok(crate::reports::History {
            records: [
                (3, "newest_operation", "completed", "/private/newest"),
                (2, "middle_operation", "partial", "/private/middle"),
                (1, "older_operation", "failed", "/private/older"),
                (0, "oldest_operation", "completed", "/private/oldest"),
            ]
            .into_iter()
            .map(|(id, operation, outcome, target)| crate::reports::Record {
                id,
                started_unix: u64::try_from(id).unwrap(),
                finished_unix: None,
                duration_ms: 0,
                operation: operation.into(),
                target: target.into(),
                outcome: outcome.into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "fixture".into(),
            })
            .collect(),
            warnings: vec![],
            capacity: 100,
            known_reclaimed_bytes: None,
            records_without_verified_reclaimed_bytes: 0,
        }));

        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        let positions =
            ["newest_operation", "middle_operation", "older_operation"].map(|operation| {
                output
                    .find(operation)
                    .expect("recent operation is rendered")
            });
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(!output.contains("oldest_operation"));
        assert!(!output.contains("/private/"));
    }

    #[test]
    fn dashboard_cache_shortcut_opens_the_screen_and_starts_inventory() {
        let mut app = app();
        app.page = Start::Dashboard;
        app.key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("c opens Caches"));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));

        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE)),
            Action::StartCache
        ));
        assert!(app.page == Start::Cache);
        assert!(app.cache_running);
        assert!(app.cache.is_none());

        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Inventorying shared caches"));
        assert!(output.contains("Esc: cancel inventory"));
    }

    #[test]
    fn dashboard_scan_shortcut_reopens_an_active_scan_without_restarting_it() {
        let mut app = app();
        app.page = Start::Dashboard;
        app.scan_running = true;
        app.scan_visited = 17;

        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.page == Start::Artifacts);
        assert!(app.scan_running);
        assert_eq!(app.scan_visited, 17);

        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Scanning workspace… 17 directories inspected."));
        assert!(output.contains("Esc: cancel scan"));
    }

    #[test]
    fn navigation_and_shortcuts_remain_visible_after_refresh_and_status_expires() {
        let mut app = app();
        app.message = "Toolchain inventory refreshed.".into();
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Pages ←/→ Tab"));
        assert!(output.contains("←/→: sections"));
        assert!(output.contains("r: refresh"));
        assert!(output.contains("Enter: update"));
        assert!(output.contains("Status: Toolchain inventory refreshed."));
        let cell = terminal.backend().buffer().cell((1, 5)).unwrap();
        assert_eq!(
            cell.bg,
            Color::Cyan,
            "selected sidebar page should stand out"
        );

        let first = std::time::Instant::now();
        let mut seen = None;
        expire_toolchain_refresh_notice(&mut app.message, &mut seen, first);
        assert_eq!(app.message, "Toolchain inventory refreshed.");
        expire_toolchain_refresh_notice(
            &mut app.message,
            &mut seen,
            first + Duration::from_secs(5),
        );
        assert!(app.message.is_empty());
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("r: refresh"));
        assert!(!output.contains("Toolchain inventory refreshed."));

        app.message = "Shared-cache preview failed: unsafe path".into();
        expire_toolchain_refresh_notice(
            &mut app.message,
            &mut seen,
            first + Duration::from_secs(20),
        );
        assert!(
            app.message.contains("unsafe path"),
            "errors must not auto-dismiss"
        );
    }

    #[test]
    fn dashboard_footer_keeps_cache_shortcut_visible_at_boundary_widths() {
        let mut app = app();
        app.page = Start::Dashboard;
        for width in [30, 41, 42, 60, 64, 65, 80, 81] {
            let mut terminal = Terminal::new(TestBackend::new(width, 18)).unwrap();
            terminal.draw(|frame| draw(frame, &app)).unwrap();
            let output = format!("{:?}", terminal.backend().buffer());
            assert!(output.contains("cache"), "width {width}: {output}");
            assert!(output.contains("quit"), "width {width}: {output}");
        }
    }

    #[test]
    fn dashboard_surfaces_bounded_important_warnings_only() {
        let mut app = app();
        app.page = Start::Dashboard;
        app.issues = Some(vec![
            "missing tools in PATH: mojo".into(),
            format!(
                "Upkit home filesystem has 123 bytes (below 1 GiB); review storage before updating.\u{1b}{}",
                "x".repeat(200)
            ),
        ]);

        let warning = important_dashboard_warning(app.issues.as_deref().unwrap()).unwrap();
        assert!(warning.starts_with("Upkit home filesystem has 123 bytes"));
        assert!(warning.contains("\\x1B"));
        assert!(warning.chars().count() <= 161);

        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Important warning: Upkit home filesystem"));
        assert!(!output.contains("missing tools in PATH"));
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn compact_header_shows_platform_and_current_operation_status() {
        let mut app = app();
        app.reports = None;
        app.issues = None;
        app.maintenance = None;
        app.self_update_command = true;
        app.settings_loading = false;
        let mut terminal = Terminal::new(TestBackend::new(52, 24)).unwrap();

        assert_eq!(application_status(&app), "Idle");
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Idle"));
        assert!(output.contains(&format!(
            "{}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )));

        app.scan_running = true;
        assert_eq!(application_status(&app), "Working");
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("Working"));
        for width in [30, 20] {
            let mut compact = Terminal::new(TestBackend::new(width, 24)).unwrap();
            compact.draw(|frame| draw(frame, &app)).unwrap();
            assert!(format!("{:?}", compact.backend().buffer()).contains("Working"));
        }

        app.scan_running = false;
        app.reports = Some(Vec::new());
        app.issues = Some(Vec::new());
        app.maintenance = Some(crate::maintenance::TrimStatus {
            platform: "fixture".into(),
            fstrim_available: false,
            capability: "unknown".into(),
            timer: crate::maintenance::TimerStatus {
                state: "unknown".into(),
                load_state: None,
                unit_file_state: None,
                last_trigger: None,
                next_trigger: None,
                detail: None,
            },
            guidance: "fixture",
            mounts: Vec::new(),
            mounts_warning: None,
        });
        assert_eq!(application_status(&app), "Ready");
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("Ready"));
        app.confirmation = true;
        assert_eq!(application_status(&app), "Review");
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("Review"));
    }

    #[test]
    fn startup_status_distinguishes_explicit_pages_from_self_update() {
        let mut app = app();
        app.page = Start::Automation;
        app.reports = None;
        app.issues = None;
        app.maintenance = None;
        app.startup_checks = StartupChecks {
            toolchains: true,
            doctor: true,
            maintenance: true,
        };
        assert_eq!(application_status(&app), "Working");

        app.self_update_command = true;
        app.startup_checks = StartupChecks::default();
        assert_eq!(application_status(&app), "Idle");
        app.self_update_preparing = true;
        assert_eq!(application_status(&app), "Working");

        app.self_update_preparing = false;
        app.toolchain_check_failed = true;
        assert_eq!(application_status(&app), "Idle");
    }

    #[test]
    fn failed_startup_checks_render_unavailable_instead_of_loading_forever() {
        let mut app = app();
        app.reports = None;
        app.toolchain_check_failed = true;
        assert_eq!(application_status(&app), "Idle");
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Toolchain check failed; results are unavailable."));
        assert!(!output.contains("Checking toolchains in the background"));

        app.page = Start::Maintenance;
        app.maintenance_check_failed = true;
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Maintenance status is unavailable."));
        assert!(!output.contains("Checking TRIM timer status"));
    }

    #[test]
    fn dashboard_keeps_narrow_screen_scrolling_and_keyboard_help() {
        let mut app = app();
        app.page = Start::Dashboard;
        let mut terminal = Terminal::new(TestBackend::new(80, 13)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let before = format!("{:?}", terminal.backend().buffer());
        assert!(before.contains("Developer environment overview"));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)),
            Action::None
        ));
        assert_eq!(app.dashboard_scroll, 1);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert_ne!(before, format!("{:?}", terminal.backend().buffer()));
        app.dashboard_scroll = u16::MAX;
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(
            format!("{:?}", terminal.backend().buffer())
                .contains("Recent operations: not loaded; press r.")
        );

        app.key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("Keyboard help"));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.help);
    }

    #[test]
    fn dashboard_scroll_is_clamped_per_card() {
        let mut app = app();
        app.page = Start::Dashboard;
        app.history = Some(Ok(crate::reports::History {
            records: vec![crate::reports::Record {
                id: 0,
                started_unix: 1,
                finished_unix: None,
                duration_ms: 0,
                operation: "x".repeat(500),
                target: "fixture".into(),
                outcome: "ok".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "fixture".into(),
            }],
            warnings: vec![],
            capacity: 100,
            known_reclaimed_bytes: None,
            records_without_verified_reclaimed_bytes: 0,
        }));
        app.dashboard_scroll = u16::MAX;

        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Toolchains: 0/1 installed"));
        assert!(output.contains("Checking maintenance status…"));
        assert!(output.contains("Artifacts: no scan yet"));
        assert!(output.contains("Caches: inventory not yet loaded"));
    }

    #[test]
    fn dashboard_summarizes_loaded_data_and_unavailable_history() {
        let mut app = app();
        app.page = Start::Dashboard;
        app.issues = Some(vec!["fixture issue".into()]);
        app.history = Some(Err("private error".into()));
        app.maintenance = Some(crate::maintenance::TrimStatus {
            platform: "linux".into(),
            fstrim_available: true,
            capability: "unknown".into(),
            guidance: "fixture",
            timer: crate::maintenance::TimerStatus {
                state: "active".into(),
                load_state: None,
                unit_file_state: None,
                last_trigger: None,
                next_trigger: None,
                detail: None,
            },
            mounts: vec![crate::maintenance::MountStatus {
                mount_point: "/".into(),
                mount_path: "/".into(),
                filesystem: "ext4".into(),
                device: "8:1".into(),
                discard_max_bytes: None,
                available_bytes: Some(1234),
                device_discard: "unknown",
                filesystem_trim: "unknown",
                fstab_trim_exclusion: "unknown",
                online_discard_option: "unknown",
            }],
            mounts_warning: None,
        });
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Toolchains: 0/1 installed"));
        assert!(output.contains("Root free bytes: 1234"));
        assert!(output.contains("Doctor: 1 diagnostic"));
        assert!(output.contains("history unavailable"));
        assert!(!output.contains("private error"));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)),
            Action::RefreshHistory
        ));
        assert!(app.history_running);
    }

    #[test]
    fn schedule_edit_requires_visible_old_and_new_plans() {
        let mut app = app();
        app.page = Start::Automation;
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.updating = true;
        assert!(matches!(app.key(key(KeyCode::Char('e'))), Action::None));
        app.updating = false;
        assert!(matches!(
            app.key(key(KeyCode::Char('E'))),
            Action::PreviewScheduleEdit(crate::schedule::Frequency::Weekly)
        ));
        assert!(app.schedule_edit_preparing);
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
        app.schedule_edit_preparing = false;
        let old = crate::schedule::DisableSchedulePreview {
            unit_directory: "/tmp/units".into(),
            service_unit: "[Service]\nExecStart=/old\n".into(),
            timer_unit: "[Timer]\nOnCalendar=daily\n".into(),
            active_state: "inactive".into(),
            unit_file_state: Some("disabled".into()),
            preview_token: "disable".into(),
            warning: "fixture",
        };
        let replacement = crate::schedule::ScanSchedulePreview {
            roots: vec!["/tmp/workspace".into()],
            exclusions: vec!["private".into()],
            frequency: "weekly",
            unit_directory: "/tmp/units".into(),
            preview_token: "install".into(),
            scheduled_scope_token: "scope".into(),
            service_unit: "[Service]\nExecStart=/new\n".into(),
            timer_unit: "[Timer]\nOnCalendar=weekly\n".into(),
            warning: "fixture",
        };
        let plan = crate::schedule::EditSchedulePreview {
            previous: crate::schedule::RemoveSchedulePreview {
                existing: old,
                quarantine_paths: vec!["/tmp/units/.first".into(), "/tmp/units/.second".into()],
                preview_token: "remove".into(),
                warning: "fixture",
            },
            replacement,
            preview_token: "edit".into(),
            warning: "fixture",
        };
        app.schedule_edit_plan = Some((plan.clone(), crate::schedule::Frequency::Weekly));
        review_schedule_confirmation_to_end(&mut app, Rect::new(0, 0, 50, 8));
        let full_area = Rect::new(0, 0, 140, 40);
        app.update_schedule_confirmation(full_area);
        assert!(schedule_confirmation_can_confirm(
            &app, full_area, full_area
        ));
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Confirm timer replacement"));
        assert!(output.contains("ExecStart=/old"));
        assert!(output.contains("ExecStart=/new"));
        assert!(output.contains("/tmp/units/.first"));
        assert!(output.contains("no rollback"));
        assert!(matches!(app.key(key(KeyCode::Enter)), Action::None));
        assert!(matches!(app.key(key(KeyCode::Esc)), Action::None));
        assert!(app.schedule_edit_plan.is_none());
        app.schedule_edit_plan = Some((plan, crate::schedule::Frequency::Weekly));
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::EditSchedule(_, crate::schedule::Frequency::Weekly)
        ));
        assert!(app.schedule_edit_running);
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
    }

    #[test]
    fn schedule_removal_requires_visible_preview_and_explicit_confirmation() {
        let mut app = app();
        app.page = Start::Automation;
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.updating = true;
        assert!(matches!(app.key(key(KeyCode::Char('x'))), Action::None));
        app.updating = false;
        assert!(matches!(
            app.key(key(KeyCode::Char('x'))),
            Action::PreviewScheduleRemove
        ));
        assert!(app.schedule_remove_preparing);
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
        app.schedule_remove_preparing = false;
        let plan = crate::schedule::RemoveSchedulePreview {
            existing: crate::schedule::DisableSchedulePreview {
                unit_directory: "/tmp/units".into(),
                service_unit: "[Service]\nExecStart=/fixture\n".into(),
                timer_unit: "[Timer]\nOnCalendar=daily\n".into(),
                active_state: "inactive".into(),
                unit_file_state: Some("disabled".into()),
                preview_token: "disable".into(),
                warning: "fixture",
            },
            quarantine_paths: vec!["/tmp/units/.first".into(), "/tmp/units/.second".into()],
            preview_token: "remove".into(),
            warning: "Permanently removes the two shown unit files after checking the timer is disabled and the service is inactive. Changes may be partial; quarantine files may remain. Unit ownership is not independently proven.",
        };
        app.schedule_remove_plan = Some(plan.clone());
        review_schedule_confirmation_to_end(&mut app, Rect::new(0, 0, 50, 8));
        let full_area = Rect::new(0, 0, 120, 30);
        app.update_schedule_confirmation(full_area);
        assert!(schedule_confirmation_can_confirm(
            &app, full_area, full_area
        ));
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Confirm timer unit removal"));
        assert!(output.contains("/tmp/units/.first"));
        assert!(output.contains("partial") && output.contains("quarantine"));
        assert!(matches!(app.key(key(KeyCode::Enter)), Action::None));
        assert!(matches!(app.key(key(KeyCode::Esc)), Action::None));
        assert!(app.schedule_remove_plan.is_none());
        app.schedule_remove_plan = Some(plan);
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::RemoveSchedule(_)
        ));
        assert!(app.schedule_remove_running);
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
    }

    #[test]
    fn launchd_installation_uses_an_explicit_preview_and_confirmation() {
        let mut app = app();
        app.page = Start::Automation;
        let plan = crate::schedule::ScanSchedulePreview {
            roots: vec!["/fixture/workspace".into()],
            exclusions: vec![],
            frequency: "daily",
            unit_directory: "/fixture/LaunchAgents".into(),
            preview_token: "preview".into(),
            scheduled_scope_token: "scope".into(),
            service_unit: "<plist/>".into(),
            timer_unit: String::new(),
            warning: "The verified LaunchAgent will run a read-only scan at its next interval.",
        };
        app.show_schedule_install_preview(plan.clone(), crate::schedule::Frequency::Daily);
        assert!(!app.schedule_read_only);
        let lines = schedule_install_confirmation_lines_for(&plan, SchedulePlatform::LaunchAgent)
            .join("\n");
        assert!(lines.contains("LaunchAgent property list"));
        assert!(
            lines.contains("Launchd is enabled and bootstrapped only after explicit confirmation")
        );
        assert!(lines.contains("Press y to install"));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::InstallSchedule(_, crate::schedule::Frequency::Daily)
        ));
        assert!(app.schedule_install_running);
    }

    #[test]
    fn configured_schedule_install_requires_visible_preview_and_confirmation() {
        let mut app = app();
        app.page = Start::Automation;
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.updating = true;
        assert!(matches!(app.key(key(KeyCode::Char('a'))), Action::None));
        app.updating = false;
        assert!(matches!(
            app.key(key(KeyCode::Char('w'))),
            Action::PreviewScheduleInstall(crate::schedule::Frequency::Weekly, false)
        ));
        assert!(app.schedule_install_preparing);
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
        app.schedule_install_preparing = false;
        let plan = crate::schedule::ScanSchedulePreview {
            roots: vec!["/tmp/workspace".into()],
            exclusions: vec!["private".into()],
            frequency: "weekly",
            unit_directory: "/tmp/units".into(),
            preview_token: "install".into(),
            scheduled_scope_token: "scope".into(),
            service_unit: "[Service]\nExecStart=/fixture\n".into(),
            timer_unit: "[Timer]\nOnCalendar=weekly\n".into(),
            warning: "fixture",
        };
        app.schedule_read_only = true;
        app.schedule_install_plan = Some((plan.clone(), crate::schedule::Frequency::Weekly));
        app.update_schedule_confirmation(Rect::new(0, 0, 120, 30));
        let mut preview = Terminal::new(TestBackend::new(120, 30)).unwrap();
        preview.draw(|frame| draw(frame, &app)).unwrap();
        let text = format!("{:?}", preview.backend().buffer());
        assert!(text.contains("Preview timer installation"));
        assert!(text.contains("Preview token: install"));
        assert!(text.contains("Preview only"));
        assert!(matches!(app.key(key(KeyCode::Char('y'))), Action::None));
        assert!(!app.schedule_install_running);
        app.key(key(KeyCode::Down));
        assert_eq!(app.schedule_preview_scroll, 1);
        app.update_schedule_confirmation(Rect::new(0, 0, 122, 30));
        assert_eq!(app.schedule_preview_scroll, 0);
        app.key(key(KeyCode::Down));
        assert_eq!(app.schedule_preview_scroll, 1);
        if let Some((plan, _)) = &mut app.schedule_install_plan {
            plan.preview_token = "changed-preview".into();
        }
        app.update_schedule_confirmation(Rect::new(0, 0, 122, 30));
        assert_eq!(app.schedule_preview_scroll, 0);
        app.key(key(KeyCode::Esc));
        assert!(!app.schedule_read_only);
        assert!(app.schedule_install_plan.is_none());
        app.schedule_install_plan = Some((plan.clone(), crate::schedule::Frequency::Weekly));
        review_schedule_confirmation_to_end(&mut app, Rect::new(0, 0, 50, 8));
        let full_area = Rect::new(0, 0, 120, 30);
        app.update_schedule_confirmation(full_area);
        assert!(schedule_confirmation_can_confirm(
            &app, full_area, full_area
        ));
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Confirm timer installation"));
        assert!(output.contains("/tmp/workspace"));
        assert!(output.contains("private"));
        assert!(output.contains("failures may be partial"));
        assert!(matches!(app.key(key(KeyCode::Enter)), Action::None));
        assert!(matches!(app.key(key(KeyCode::Esc)), Action::None));
        assert!(app.schedule_install_plan.is_none());
        app.schedule_install_plan = Some((plan, crate::schedule::Frequency::Weekly));
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::InstallSchedule(_, crate::schedule::Frequency::Weekly)
        ));
        assert!(app.schedule_install_running);
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn automation_configured_plan_can_be_reviewed_read_only_without_installing() {
        let mut app = app();
        app.page = Start::Automation;
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(matches!(
            app.key(key(KeyCode::Char('p'))),
            Action::PreviewScheduleInstall(crate::schedule::Frequency::Daily, true)
        ));
        assert!(app.schedule_read_only && app.schedule_install_preparing);
        app.schedule_install_preparing = false;
        let plan = crate::schedule::ScanSchedulePreview {
            roots: vec!["/fixture/workspace".into()],
            exclusions: vec!["/fixture/workspace/target".into()],
            frequency: "weekly",
            unit_directory: "/fixture/units".into(),
            preview_token: "fixture-preview".into(),
            scheduled_scope_token: bytecode_cleanup_policy_token(),
            service_unit: "[Service]\nExecStart=/fixture/upkit --scheduled-bytecode-cleanup\n"
                .into(),
            timer_unit: "[Timer]\nOnCalendar=weekly\nPersistent=true\n".into(),
            warning: "fixture opt-in cleanup warning",
        };
        app.schedule_install_plan = Some((plan, crate::schedule::Frequency::Weekly));
        let area = Rect::new(0, 0, 120, 10);
        app.update_schedule_confirmation(area);
        let visible = schedule_confirmation_visible_rows(area);
        let mut terminal = Terminal::new(TestBackend::new(120, 10)).unwrap();
        let mut reviewed = String::new();
        loop {
            terminal.draw(|frame| draw(frame, &app)).unwrap();
            reviewed.push_str(&format!("{:?}", terminal.backend().buffer()));
            let content_len = app.schedule_confirmation_content.as_ref().unwrap().len();
            if app.schedule_preview_scroll as usize + visible >= content_len {
                break;
            }
            app.key(key(KeyCode::Down));
            app.update_schedule_confirmation(area);
        }
        assert!(reviewed.contains("/fixture/workspace"));
        assert!(reviewed.contains("[Service]"));
        assert!(reviewed.contains("[Timer]"));
        assert!(reviewed.contains("OnCalendar=weekly"));
        assert!(reviewed.contains("explicit opt-in"));
        assert!(reviewed.contains("Preview only"));
        assert!(matches!(app.key(key(KeyCode::Char('y'))), Action::None));
        assert!(app.schedule_install_plan.is_some());
        assert!(!app.schedule_install_running);
        assert!(matches!(app.key(key(KeyCode::Esc)), Action::None));
        assert!(app.schedule_install_plan.is_none());
        assert!(!app.schedule_read_only);
        assert!(matches!(
            app.key(key(KeyCode::Char('P'))),
            Action::PreviewScheduleInstall(crate::schedule::Frequency::Weekly, true)
        ));
    }

    #[test]
    fn configured_schedule_enable_requires_visible_preview_and_confirmation() {
        let mut app = app();
        app.page = Start::Automation;
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.updating = true;
        assert!(matches!(app.key(key(KeyCode::Char('1'))), Action::None));
        app.updating = false;
        assert!(matches!(
            app.key(key(KeyCode::Char('7'))),
            Action::PreviewScheduleEnable(crate::schedule::Frequency::Weekly)
        ));
        assert!(app.schedule_enable_preparing);
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
        app.schedule_enable_preparing = false;
        let plan = crate::schedule::EnableSchedulePreview {
            intended: crate::schedule::ScanSchedulePreview {
                roots: vec!["/tmp/workspace".into()],
                exclusions: vec!["private".into()],
                frequency: "weekly",
                unit_directory: "/tmp/units".into(),
                preview_token: "install".into(),
                scheduled_scope_token: "scope".into(),
                service_unit: "[Service]\nExecStart=/fixture\n".into(),
                timer_unit: "[Timer]\nOnCalendar=weekly\n".into(),
                warning: "fixture",
            },
            installed: crate::schedule::DisableSchedulePreview {
                unit_directory: "/tmp/units".into(),
                service_unit: "[Service]\nExecStart=/fixture\n".into(),
                timer_unit: "[Timer]\nOnCalendar=weekly\n".into(),
                active_state: "inactive".into(),
                unit_file_state: Some("disabled".into()),
                preview_token: "disable".into(),
                warning: "fixture",
            },
            preview_token: "enable".into(),
            warning: "fixture",
        };
        app.schedule_enable_plan = Some((plan.clone(), crate::schedule::Frequency::Weekly));
        review_schedule_confirmation_to_end(&mut app, Rect::new(0, 0, 50, 8));
        let full_area = Rect::new(0, 0, 120, 30);
        app.update_schedule_confirmation(full_area);
        assert!(schedule_confirmation_can_confirm(
            &app, full_area, full_area
        ));
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Confirm timer enable"));
        assert!(output.contains("/tmp/workspace"));
        assert!(output.contains("private"));
        assert!(output.contains("may start promptly"));
        assert!(matches!(app.key(key(KeyCode::Enter)), Action::None));
        assert!(matches!(app.key(key(KeyCode::Esc)), Action::None));
        assert!(app.schedule_enable_plan.is_none());
        app.schedule_enable_plan = Some((plan, crate::schedule::Frequency::Weekly));
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::EnableSchedule(_, crate::schedule::Frequency::Weekly)
        ));
        assert!(app.schedule_enable_running);
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn schedule_enable_dialog_shows_legacy_and_v2_warning_fields() {
        let make_plan = |scheduled_scope_token: &str,
                         intended_warning: &'static str,
                         enable_warning: &'static str| {
            crate::schedule::EnableSchedulePreview {
                intended: crate::schedule::ScanSchedulePreview {
                    roots: vec!["/tmp/workspace".into()],
                    exclusions: vec!["private".into()],
                    frequency: "weekly",
                    unit_directory: "/tmp/units".into(),
                    preview_token: "install".into(),
                    scheduled_scope_token: scheduled_scope_token.into(),
                    service_unit: format!(
                        "[Service]\nExecStart=/upkit --scope-token {scheduled_scope_token}\n"
                    ),
                    timer_unit: "[Timer]\nOnCalendar=weekly\n".into(),
                    warning: intended_warning,
                },
                installed: crate::schedule::DisableSchedulePreview {
                    unit_directory: "/tmp/units".into(),
                    service_unit: "[Service]\nExecStart=/upkit\n".into(),
                    timer_unit: "[Timer]\nOnCalendar=weekly\n".into(),
                    active_state: "inactive".into(),
                    unit_file_state: Some("disabled".into()),
                    preview_token: "disable".into(),
                    warning: "fixture origin warning",
                },
                preview_token: "enable".into(),
                warning: enable_warning,
            }
        };

        let legacy_intended_warning: &'static str = Box::leak(
            format!(
                "Legacy runtime checks executable and roots/exclusions but does not reload configuration or recheck retention/ecosystem policy. Keep policy empty. {}LEGACY-INTENDED-END",
                "policy ".repeat(200)
            )
            .into_boxed_str(),
        );
        let legacy_enable_warning: &'static str = Box::leak(
            format!(
                "Legacy schedule compatibility requires recreating the schedule after scope changes. {}LEGACY-ENABLE-END",
                "scope ".repeat(200)
            )
            .into_boxed_str(),
        );
        let legacy = make_plan(
            &"a".repeat(64),
            legacy_intended_warning,
            legacy_enable_warning,
        );
        let legacy_lines = schedule_enable_confirmation_lines(&legacy);
        assert!(
            legacy_lines
                .iter()
                .any(|line| line == &format!("Intended scan warning: {}", legacy.intended.warning))
        );
        assert!(
            legacy_lines
                .iter()
                .any(|line| line == &format!("Enable warning: {}", legacy.warning))
        );
        assert!(
            !legacy_lines
                .iter()
                .any(|line| line.contains("does not load user profiles"))
        );
        let area = Rect::new(0, 0, 80, 24);
        let mut legacy_ui = app();
        legacy_ui.schedule_enable_plan = Some((legacy.clone(), crate::schedule::Frequency::Weekly));
        legacy_ui.update_schedule_confirmation(area);
        let visible = schedule_confirmation_visible_rows(area);
        let content_len = legacy_ui
            .schedule_confirmation_content
            .as_ref()
            .unwrap()
            .len();
        assert!(!schedule_confirmation_ready(
            &legacy_ui,
            &legacy_lines,
            area
        ));
        assert!(!schedule_confirmation_can_confirm(&legacy_ui, area, area));
        while legacy_ui.schedule_confirmation_scroll + visible < content_len {
            legacy_ui.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        }
        assert!(schedule_confirmation_ready(&legacy_ui, &legacy_lines, area));
        assert!(schedule_confirmation_can_confirm(&legacy_ui, area, area));
        let reviewed = legacy_ui
            .schedule_confirmation_content
            .as_ref()
            .unwrap()
            .concat();
        assert!(reviewed.contains(legacy_intended_warning));
        assert!(reviewed.contains(legacy_enable_warning));

        let v2 = make_plan(
            "v2.policy-token",
            "Configured v2 runtime reloads the selected configuration/profile and rechecks scope and policy before scanning.",
            "Enabling the verified configured timer may start a scan promptly.",
        );
        let v2_lines = schedule_enable_confirmation_lines(&v2);
        assert!(
            v2_lines
                .iter()
                .any(|line| line == &format!("Intended scan warning: {}", v2.intended.warning))
        );
        assert!(
            v2_lines
                .iter()
                .any(|line| line == &format!("Enable warning: {}", v2.warning))
        );

        let install_lines = schedule_install_confirmation_lines(&v2.intended);
        assert!(
            install_lines
                .iter()
                .any(|line| { line == &format!("Scan warning: {}", v2.intended.warning) })
        );
        let edit = crate::schedule::EditSchedulePreview {
            previous: crate::schedule::RemoveSchedulePreview {
                existing: v2.installed.clone(),
                quarantine_paths: vec!["/tmp/units/.quarantine".into()],
                preview_token: "remove".into(),
                warning: "previous unit warning",
            },
            replacement: v2.intended.clone(),
            preview_token: "edit".into(),
            warning: "Edit-specific transactional warning.",
        };
        let edit_lines = schedule_edit_confirmation_lines(&edit);
        assert!(
            edit_lines.iter().any(|line| {
                line == &format!("Replacement scan warning: {}", v2.intended.warning)
            })
        );
        assert!(
            edit_lines
                .iter()
                .any(|line| line == "Edit warning: Edit-specific transactional warning.")
        );

        let cleanup_warning = "This timer automatically and permanently removes eligible Python bytecode after at least 7 days, at most 32 files per run. Each file is revalidated against project, Git, process, path, source and configuration policy. Unchecked-hash bytecode is excluded. V3_WARNING_END";
        let v3 = make_plan(
            &bytecode_cleanup_policy_token(),
            cleanup_warning,
            "Enabling the verified cleanup timer may start cleanup promptly.",
        );
        assert!(crate::schedule::schedules_bytecode_cleanup(&v3.intended));

        let install_lines = schedule_install_confirmation_lines(&v3.intended);
        let install_copy = install_lines.join("\n");
        assert!(
            install_copy.contains("automatically and permanently removes eligible Python bytecode")
        );
        assert!(install_copy.contains("at least 7 days"));
        assert!(install_copy.contains("32 files are removed per run"));
        assert!(
            install_copy.contains("project, Git, process, path, source and configuration policy")
        );
        assert!(install_copy.contains(cleanup_warning));
        assert!(!install_copy.contains("no workspace files are cleaned"));

        let enable_lines = schedule_enable_confirmation_lines(&v3);
        let enable_copy = enable_lines.join("\n");
        assert!(enable_copy.contains("Intended cleanup warning:"));
        assert!(!enable_copy.contains("No files are cleaned."));
        assert!(enable_copy.contains("V3_WARNING_END"));

        let edit = crate::schedule::EditSchedulePreview {
            previous: crate::schedule::RemoveSchedulePreview {
                existing: v3.installed.clone(),
                quarantine_paths: vec!["/tmp/units/.quarantine".into()],
                preview_token: "remove".into(),
                warning: "previous unit warning",
            },
            replacement: v3.intended.clone(),
            preview_token: "edit-v3".into(),
            warning: "Edit-specific transactional warning.",
        };
        let edit_lines = schedule_edit_confirmation_lines(&edit);
        let edit_copy = edit_lines.join("\n");
        assert!(edit_copy.contains("Replacement cleanup warning:"));
        assert!(
            edit_copy.contains("automatically and permanently removes eligible Python bytecode")
        );
        assert!(edit_copy.contains("32 files are removed per run"));
        assert!(!edit_copy.contains("no workspace files are cleaned"));

        let area = Rect::new(0, 0, 80, 12);
        let mut ui = app();
        ui.schedule_install_plan = Some((v3.intended.clone(), crate::schedule::Frequency::Weekly));
        ui.update_schedule_confirmation(area);
        assert!(!schedule_confirmation_can_confirm(&ui, area, area));
        review_schedule_confirmation_to_end(&mut ui, area);
        assert!(schedule_confirmation_can_confirm(&ui, area, area));
        let reviewed = ui.schedule_confirmation_content.as_ref().unwrap().concat();
        assert!(reviewed.contains("at least 7 days"));
        assert!(reviewed.contains("32 files per run"));
        assert!(reviewed.contains("V3_WARNING_END"));
        let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
        terminal.draw(|frame| draw(frame, &ui)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Confirm timer installation"));
        assert!(output.contains("V3_WARNING_END"));
        assert!(!output.contains("No files are cleaned"));
    }

    #[test]
    fn schedule_confirmation_wraps_long_tokens_and_requires_scrolling_to_the_end() {
        let token = format!("v2.{}", "a".repeat(24_000));
        let unit_line = format!("ExecStart=/upkit --scope-token {token}");
        let wrapped_unit = schedule_wrap_line(&unit_line, 76);
        assert_eq!(wrapped_unit.concat(), unit_line);
        assert!(
            wrapped_unit
                .iter()
                .all(|line| ratatui::text::Line::from(line.as_str()).width() <= 76)
        );
        let unicode_line = "α界e\u{301}🧪-profile";
        let wrapped_unicode = schedule_wrap_line(unicode_line, 5);
        assert_eq!(wrapped_unicode.concat(), unicode_line);
        assert!(
            wrapped_unicode
                .iter()
                .all(|line| ratatui::text::Line::from(line.as_str()).width() <= 5)
        );
        let controlled_line =
            "ExecStart=/bin/tool\t--color \u{1b}[31m literal \\x1B dir\u{202e}fix";
        assert_eq!(
            schedule_wrap_line(controlled_line, 40).concat(),
            "ExecStart=/bin/tool\\x09--color \\x1B[31m literal \\\\x1B dir\\u{202E}fix"
        );
        assert_eq!(
            schedule_wrap_line("\u{061c}\u{200e}\u{200f}\\u{200E}", 8).concat(),
            "\\u{61C}\\u{200E}\\u{200F}\\\\u{200E}"
        );
        for code in [
            0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068,
            0x2069,
        ] {
            let input = format!("x{}y", char::from_u32(code).unwrap());
            assert_eq!(
                schedule_escape_controls(&input),
                format!("x\\u{{{code:X}}}y")
            );
            assert_eq!(config_display_character(char::from_u32(code).unwrap()), '�');
        }
        assert_eq!(config_display_character('界'), '界');

        let plan = crate::schedule::ScanSchedulePreview {
            roots: vec!["/tmp/workspace".into()],
            exclusions: vec![],
            frequency: "weekly",
            unit_directory: "/tmp/units".into(),
            preview_token: "long-token-preview".into(),
            scheduled_scope_token: token.clone(),
            service_unit: format!("[Service]\n{unit_line}\n"),
            timer_unit: "[Timer]\nOnCalendar=weekly\n".into(),
            warning: "long-token warning tail",
        };
        let area = Rect::new(0, 0, 80, 24);

        let mut app = app();
        app.schedule_install_plan = Some((plan.clone(), crate::schedule::Frequency::Weekly));
        app.update_schedule_confirmation(area);
        let lines = schedule_install_confirmation_lines(&plan);
        assert!(!schedule_confirmation_ready(&app, &lines, area));
        assert!(!schedule_confirmation_can_confirm(&app, area, area));
        let visible = schedule_confirmation_visible_rows(area);
        let content_len = app.schedule_confirmation_content.as_ref().unwrap().len();
        assert!(content_len > visible);

        let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let first_page = format!("{:?}", terminal.backend().buffer());
        assert!(first_page.contains("ExecStart="));
        assert!(!first_page.contains("Press y to install"));

        app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.schedule_confirmation_scroll, visible - 1);
        while app.schedule_confirmation_scroll + visible < content_len {
            let previous_scroll = app.schedule_confirmation_scroll;
            app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
            assert!(app.schedule_confirmation_scroll < previous_scroll + visible);
        }
        assert!(schedule_confirmation_ready(&app, &lines, area));
        assert!(schedule_confirmation_can_confirm(&app, area, area));
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let last_page = format!("{:?}", terminal.backend().buffer());
        assert!(last_page.contains("long-token warning tail"));
        assert!(last_page.contains("Press y to install"));

        app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.schedule_confirmation_scroll, content_len - visible);
        app.update_schedule_confirmation(Rect::new(0, 0, 82, 24));
        assert_eq!(app.schedule_confirmation_scroll, 0);
        app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.schedule_confirmation_scroll, 1);
        if let Some((plan, _)) = &mut app.schedule_install_plan {
            plan.preview_token = "changed-preview".into();
        }
        app.update_schedule_confirmation(Rect::new(0, 0, 82, 24));
        assert_eq!(app.schedule_confirmation_scroll, 0);
    }

    #[test]
    fn schedule_confirmation_gate_rejects_scroll_offsets_beyond_widget_limit() {
        let area = Rect::new(0, 0, 5, 8);
        let content = vec!["x".repeat(u16::MAX as usize + 100)];
        let wrapped = schedule_confirmation_display_lines(&content, area);
        assert!(wrapped.len() > u16::MAX as usize + 6);
        assert!(wrapped.concat().contains("Widen terminal"));
        assert!(!schedule_confirmation_reviewed(
            &wrapped,
            area,
            u16::MAX as usize
        ));
        assert!(!schedule_confirmation_reviewed(
            &wrapped,
            area,
            u16::MAX as usize + 1
        ));
    }

    #[test]
    fn schedule_confirmation_escapes_controls_before_confirmation() {
        let plan = crate::schedule::DisableSchedulePreview {
            unit_directory: "/tmp/units".into(),
            service_unit: "[Service]\r\nExecStart=/bin/tool\t--color \u{1b}[31m literal \\x1B dir\u{061c}\u{200e}\u{200f}\u{202e}fix\r\n".into(),
            timer_unit: "[Timer]\nOnCalendar=daily\n".into(),
            active_state: "inactive".into(),
            unit_file_state: Some("disabled".into()),
            preview_token: "controls".into(),
            warning: "fixture",
        };
        let area = Rect::new(0, 0, 80, 8);
        let lines = schedule_disable_confirmation_lines(&plan);
        let displayed = schedule_confirmation_display_lines(&lines, area);
        assert!(displayed.concat().contains(
            "ExecStart=/bin/tool\\x09--color \\x1B[31m literal \\\\x1B dir\\u{61C}\\u{200E}\\u{200F}\\u{202E}fix\\x0D"
        ));
        assert!(displayed.concat().contains("[Service]\\x0D"));
        assert!(displayed.iter().all(|line| {
            ratatui::text::Line::from(line.as_str()).width()
                <= area.width.saturating_sub(4) as usize
        }));

        let mut app = app();
        app.schedule_disable_plan = Some(plan);
        app.update_schedule_confirmation(area);
        let visible = schedule_confirmation_visible_rows(area);
        assert!(!schedule_confirmation_ready(&app, &lines, area));
        while app.schedule_confirmation_scroll + visible
            < app.schedule_confirmation_content.as_ref().unwrap().len()
        {
            app.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        }
        assert!(schedule_confirmation_ready(&app, &lines, area));
        let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Press y to disable"));
    }

    #[test]
    fn schedule_disable_requires_visible_preview_and_explicit_confirmation() {
        let mut app = app();
        app.page = Start::Automation;
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.updating = true;
        assert!(matches!(app.key(key(KeyCode::Char('d'))), Action::None));
        app.updating = false;
        assert!(matches!(
            app.key(key(KeyCode::Char('d'))),
            Action::PreviewScheduleDisable
        ));
        assert!(app.schedule_disable_preparing);
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
        app.schedule_disable_preparing = false;
        let plan = crate::schedule::DisableSchedulePreview {
            unit_directory: "/tmp/fixture".into(), service_unit: "[Unit]\nDescription=fixture\n\n[Service]\nType=oneshot\nExecStart=/fixture\n".into(), timer_unit: "[Unit]\nDescription=fixture\n\n[Timer]\nOnCalendar=daily\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n".into(), active_state: "active".into(), unit_file_state: Some("enabled".into()), preview_token: "fixture".into(), warning: "Disable and stop this timer only; an already running service, including authorized cleanup, may continue. The unit files remain. Review both unit contents; ownership is not independently proven.",
        };
        app.schedule_disable_plan = Some(plan.clone());
        review_schedule_confirmation_to_end(&mut app, Rect::new(0, 0, 50, 8));
        app.update_schedule_confirmation(Rect::new(0, 0, 70, 12));
        let mut small = Terminal::new(TestBackend::new(70, 12)).unwrap();
        small.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", small.backend().buffer()).contains("Review all lines"));
        let full_area = Rect::new(0, 0, 120, 30);
        app.update_schedule_confirmation(full_area);
        assert!(schedule_confirmation_can_confirm(
            &app, full_area, full_area
        ));
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Confirm timer disable"));
        assert!(output.contains("ExecStart=/fixture"));
        assert!(
            output.contains("already running service, including authorized cleanup, may continue")
        );
        assert!(matches!(app.key(key(KeyCode::Enter)), Action::None));
        assert!(matches!(app.key(key(KeyCode::Esc)), Action::None));
        assert!(app.schedule_disable_plan.is_none());
        app.schedule_disable_plan = Some(plan);
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::DisableSchedule(_)
        ));
        assert!(app.schedule_disable_running);
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
    }

    #[test]
    fn automation_page_loads_and_renders_unverified_timer() {
        let mut app = app();
        app.page = Start::Containers;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)),
            Action::RefreshSchedule
        ));
        assert!(app.page == Start::Automation);
        assert!(app.schedule_running);
        app.schedule_running = false;
        app.schedule = Some(crate::maintenance::TimerStatus {
            state: "active".into(),
            load_state: Some("loaded".into()),
            unit_file_state: Some("enabled".into()),
            last_trigger: None,
            next_trigger: Some("tomorrow".into()),
            detail: None,
        });
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("upkit-scan.timer"));
        assert!(output.contains("tomorrow"));
        assert!(output.contains("ownership and action are not verified"));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)),
            Action::RefreshSchedule
        ));
    }

    #[test]
    fn automation_status_renders_synthetic_platform_fixtures() {
        let render = |platform, status| {
            let mut ui = app();
            ui.page = Start::Automation;
            ui.schedule = Some(status);
            let mut terminal = Terminal::new(TestBackend::new(160, 30)).unwrap();
            terminal
                .draw(|frame| draw_for_platform(frame, &ui, platform))
                .unwrap();
            format!("{:?}", terminal.backend().buffer())
        };
        let fixture =
            |state: &str,
             load_state: Option<&str>,
             unit_file_state: Option<&str>,
             last: Option<&str>,
             next: Option<&str>,
             detail: Option<&str>| crate::maintenance::TimerStatus {
                state: state.into(),
                load_state: load_state.map(str::to_owned),
                unit_file_state: unit_file_state.map(str::to_owned),
                last_trigger: last.map(str::to_owned),
                next_trigger: next.map(str::to_owned),
                detail: detail.map(str::to_owned),
            };

        let linux = render(
            SchedulePlatform::Systemd,
            fixture(
                "active",
                Some("loaded"),
                Some("enabled"),
                Some("yesterday"),
                Some("tomorrow"),
                None,
            ),
        );
        assert!(linux.contains("Timer: upkit-scan.timer"));
        assert!(linux.contains("Unit file state: enabled"));
        assert!(linux.contains("Last trigger: yesterday"));
        assert!(linux.contains("Name only: ownership and action are not verified."));

        let macos = render(
            SchedulePlatform::LaunchAgent,
            fixture("loaded", Some("loaded"), None, None, None, None),
        );
        assert!(macos.contains("LaunchAgent label: upkit-scan.timer"));
        assert!(macos.contains("Launch state: loaded"));
        assert!(!macos.contains("Unit file state:"));
        assert!(macos.contains("Name only: ownership and action are not verified."));

        let windows = render(
            SchedulePlatform::TaskScheduler,
            fixture(
                "ready",
                Some("registered"),
                Some("enabled"),
                Some("yesterday"),
                Some("tomorrow"),
                Some("Synthetic verified Task Scheduler fixture"),
            ),
        );
        assert!(windows.contains("Task Scheduler path: \\Upkit-Workspace-Scan"));
        assert!(windows.contains("Enabled: enabled"));
        assert!(windows.contains("Last run: yesterday"));
        assert!(windows.contains("Next run: tomorrow"));
        assert!(windows.contains("Task identity: verified."));
        assert!(!windows.contains("LaunchAgent"));
        assert!(!windows.contains("Unit file state:"));

        let unavailable = render(
            SchedulePlatform::TaskScheduler,
            fixture(
                "unavailable",
                None,
                None,
                None,
                None,
                Some("Task Scheduler state could not be verified"),
            ),
        );
        assert!(unavailable.contains("State: unavailable"));
        assert!(unavailable.contains("Task Scheduler state could not be verified"));
        assert!(unavailable.contains("Task identity: unavailable; task state was not verified."));
        assert!(!unavailable.contains("Task identity: verified."));

        let not_found = render(
            SchedulePlatform::TaskScheduler,
            fixture(
                "not_found",
                Some("not-found"),
                None,
                None,
                None,
                Some("No task is registered at the Upkit scan path"),
            ),
        );
        assert!(not_found.contains("State: not found"));
        assert!(not_found.contains("No task is registered at the Upkit scan path"));
        assert!(not_found.contains("Task identity: no task is registered at this path."));
        assert!(!not_found.contains("Task identity: verified."));

        let unknown_task_state = render(
            SchedulePlatform::TaskScheduler,
            fixture(
                "unknown",
                Some("registered"),
                Some("enabled"),
                None,
                None,
                None,
            ),
        );
        assert!(unknown_task_state.contains("Task identity: not verified."));
        assert!(!unknown_task_state.contains("Task identity: verified."));

        let unsupported = render(
            SchedulePlatform::Unsupported,
            fixture(
                "unsupported",
                None,
                None,
                None,
                None,
                Some("user maintenance schedules are unsupported on this platform"),
            ),
        );
        assert!(unsupported.contains("Schedule target: unsupported"));
        assert!(unsupported.contains("State: unsupported"));
        assert!(unsupported.contains("Automation is unsupported on this platform."));
        assert!(unsupported.contains("user maintenance schedules are unsupported"));
    }

    #[test]
    fn windows_task_scheduler_previews_and_confirmations_show_path_xml_and_warnings() {
        let warning = "Task Scheduler rechecks the task before the operation, but another process can still change its state after that check.";
        let plan = crate::schedule::ScanSchedulePreview {
            roots: vec!["C:\\fixture\\workspace".into()],
            exclusions: vec![],
            frequency: "daily",
            unit_directory: "\\Upkit-Workspace-Scan".into(),
            preview_token: "windows-preview".into(),
            scheduled_scope_token: "v2.synthetic".into(),
            service_unit: "<Task><Principals><Principal>InteractiveToken</Principal></Principals><Actions><Exec>upkit scan</Exec></Actions></Task>".into(),
            timer_unit: String::new(),
            warning,
        };
        let existing = crate::schedule::DisableSchedulePreview {
            unit_directory: plan.unit_directory.clone(),
            service_unit: plan.service_unit.clone(),
            timer_unit: String::new(),
            active_state: "ready".into(),
            unit_file_state: Some("enabled".into()),
            preview_token: "windows-disable".into(),
            warning,
        };
        let enable = crate::schedule::EnableSchedulePreview {
            intended: plan.clone(),
            installed: existing.clone(),
            preview_token: "windows-enable".into(),
            warning,
        };
        let remove = crate::schedule::RemoveSchedulePreview {
            existing: existing.clone(),
            quarantine_paths: vec![],
            preview_token: "windows-remove".into(),
            warning,
        };
        let edit = crate::schedule::EditSchedulePreview {
            previous: remove.clone(),
            replacement: plan.clone(),
            preview_token: "windows-edit".into(),
            warning,
        };
        let platform = SchedulePlatform::TaskScheduler;
        let scan_content = schedule_scan_confirmation_lines_for(&plan, platform).join("\n");
        assert!(scan_content.contains("Task Scheduler path: \\Upkit-Workspace-Scan"));
        assert!(scan_content.contains("Task Scheduler XML definition:"));
        assert!(scan_content.contains("<Task><Principals>"));
        assert!(!scan_content.contains("LaunchAgent"));
        let rendered_lines = [
            schedule_install_confirmation_lines_for(&plan, platform),
            schedule_enable_confirmation_lines_for(&enable, platform),
            schedule_disable_confirmation_lines_for(&existing, platform),
            schedule_remove_confirmation_lines_for(&remove, platform),
            schedule_edit_confirmation_lines_for(&edit, platform),
        ];
        for lines in rendered_lines {
            let content = lines.join("\n");
            assert!(content.contains("Task Scheduler path: \\Upkit-Workspace-Scan"));
            assert!(content.contains("Task Scheduler XML definition:"));
            assert!(content.contains("<Task><Principals>"));
            assert!(content.contains(warning));
            assert!(!content.contains("LaunchAgent"));
            assert!(!content.contains("Unit directory"));
            assert!(!content.contains("Service unit:"));
            assert!(!content.contains("Timer unit:"));
        }
        for lines in [
            schedule_install_confirmation_lines_for(&plan, platform),
            schedule_enable_confirmation_lines_for(&enable, platform),
            schedule_edit_confirmation_lines_for(&edit, platform),
        ] {
            let content = lines.join("\n");
            assert!(content.contains("next configured 03:00 local calendar trigger"));
            assert!(content.contains("standard output"));
            assert!(content.contains("history write can fail"));
            assert!(!content.contains("journal"));
            assert!(!content.contains("promptly"));
        }
        let edit_content = schedule_edit_confirmation_lines_for(&edit, platform).join("\n");
        assert!(edit_content.contains("old Task Scheduler task removed"));
        assert!(edit_content.contains("no rollback is performed"));
        let windows_result =
            schedule_operation_result_message(platform, "enable", Ok("active_and_enabled"));
        assert!(windows_result.contains("next configured 03:00 local calendar trigger"));
        assert!(!windows_result.contains("promptly"));
        let partial_edit_result = schedule_operation_result_message(
            platform,
            "replacement",
            Err("old task was removed; replacement registration may be partial".into()),
        );
        assert!(partial_edit_result.contains("Task Scheduler task replacement result"));
        assert!(partial_edit_result.contains("replacement registration may be partial"));

        assert_eq!(
            schedule_dialog_title(platform, "installation", true),
            " Preview Task Scheduler task installation "
        );
        assert_eq!(
            schedule_dialog_title(platform, "installation", false),
            " Confirm Task Scheduler task installation "
        );
        let mut ui = app();
        ui.page = Start::Automation;
        ui.schedule_install_plan = Some((plan, crate::schedule::Frequency::Daily));
        for (read_only, expected_title) in [
            (true, "Preview Task Scheduler task installation"),
            (false, "Confirm Task Scheduler task installation"),
        ] {
            ui.schedule_read_only = read_only;
            let mut terminal = Terminal::new(TestBackend::new(280, 40)).unwrap();
            terminal
                .draw(|frame| draw_for_platform(frame, &ui, platform))
                .unwrap();
            let output = format!("{:?}", terminal.backend().buffer());
            assert!(output.contains(expected_title));
            assert!(output.contains("Task Scheduler XML definition:"));
            assert!(output.contains("<Task><Principals>"));
            assert!(output.contains(warning));
            assert!(!output.contains("LaunchAgent property list"));
        }
    }

    #[test]
    fn launchagent_enable_and_edit_copy_uses_calendar_stdout_and_best_effort_history() {
        let warning = "The scan remains read-only; paths may change after validation.";
        let plan = crate::schedule::ScanSchedulePreview {
            roots: vec!["/fixture/workspace".into()],
            exclusions: vec![],
            frequency: "weekly",
            unit_directory: "/fixture/LaunchAgents".into(),
            preview_token: "launchd-plan".into(),
            scheduled_scope_token: "v2.synthetic".into(),
            service_unit: "<plist/>".into(),
            timer_unit: String::new(),
            warning,
        };
        let existing = crate::schedule::DisableSchedulePreview {
            unit_directory: plan.unit_directory.clone(),
            service_unit: plan.service_unit.clone(),
            timer_unit: String::new(),
            active_state: "loaded".into(),
            unit_file_state: Some("enabled".into()),
            preview_token: "launchd-disabled".into(),
            warning,
        };
        let enable = crate::schedule::EnableSchedulePreview {
            intended: plan.clone(),
            installed: existing,
            preview_token: "launchd-enable".into(),
            warning,
        };
        let previous = crate::schedule::RemoveSchedulePreview {
            existing: crate::schedule::DisableSchedulePreview {
                unit_directory: plan.unit_directory.clone(),
                service_unit: plan.service_unit.clone(),
                timer_unit: String::new(),
                active_state: "not_found".into(),
                unit_file_state: Some("disabled".into()),
                preview_token: "launchd-previous".into(),
                warning,
            },
            quarantine_paths: vec!["/fixture/LaunchAgents/.upkit-scan.plist".into()],
            preview_token: "launchd-remove".into(),
            warning,
        };
        let edit = crate::schedule::EditSchedulePreview {
            previous,
            replacement: plan,
            preview_token: "launchd-edit".into(),
            warning: "The old LaunchAgent may be removed before replacement installation fails.",
        };
        let enable_lines =
            schedule_enable_confirmation_lines_for(&enable, SchedulePlatform::LaunchAgent);
        let edit_lines = schedule_edit_confirmation_lines_for(&edit, SchedulePlatform::LaunchAgent);
        for lines in [&enable_lines, &edit_lines] {
            let content = lines.join("\n");
            assert!(content.contains("next configured 03:00 local calendar interval"));
            assert!(content.contains("standard output"));
            assert!(content.contains("history write can fail"));
            assert!(!content.contains("user journal"));
            assert!(!content.contains("may start promptly"));
        }
        let edit_content = edit_lines.join("\n");
        assert!(edit_content.contains("old LaunchAgent removed"));
        assert!(edit_content.contains("no rollback is performed"));
        let launchd_result = schedule_operation_result_message(
            SchedulePlatform::LaunchAgent,
            "replacement",
            Ok("active_and_enabled"),
        );
        assert!(launchd_result.contains("next configured 03:00 local calendar interval"));
        assert!(!launchd_result.contains("promptly"));

        let mut ui = app();
        ui.page = Start::Automation;
        ui.schedule_enable_plan = Some((enable, crate::schedule::Frequency::Weekly));
        let mut terminal = Terminal::new(TestBackend::new(280, 40)).unwrap();
        terminal
            .draw(|frame| draw_for_platform(frame, &ui, SchedulePlatform::LaunchAgent))
            .unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Confirm LaunchAgent enable"));
        assert!(output.contains("standard output"));
        assert!(output.contains("history write can fail"));
        assert!(output.contains("next configured 03:00 local calendar interval"));
        assert!(!output.contains("user journal"));
        assert!(!output.contains("may start promptly"));
    }

    #[test]
    fn contextual_help_is_modal_and_scrollable() {
        let mut app = app();
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.help);
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.page == Start::Toolchains);
        app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.help_scroll, 1);
        app.key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("Keyboard help"));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.help);
        app.confirmation = true;
        app.key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert!(!app.help);
        assert!(app.confirmation);
    }

    #[test]
    fn doctor_refresh_starts_once_and_clears_stale_results() {
        let mut app = app();
        app.page = Start::Doctor;
        app.issues = Some(vec!["stale issue".into()]);
        app.doctor_scroll = 5;
        let key = KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE);
        assert!(matches!(app.key(key), Action::RefreshDoctor));
        assert!(app.issues.is_none());
        assert_eq!(app.doctor_scroll, 0);
        assert!(matches!(app.key(key), Action::None));
    }

    #[test]
    fn doctor_escape_requests_cancellation_while_checks_run() {
        let mut app = app();
        app.page = Start::Doctor;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            Action::CancelDoctor
        ));
    }

    #[test]
    fn doctor_filter_is_case_insensitive_and_preserves_empty_state_and_safety_note() {
        let mut app = app();
        app.page = Start::Doctor;
        app.issues = Some(vec![
            "PATH entry is missing".into(),
            "Go binary was not found".into(),
        ]);
        app.doctor_filter = "path".into();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Filter: path (1 matching lines)"));
        assert!(output.contains("PATH entry is missing"));
        assert!(!output.contains("Go binary was not found"));
        assert!(output.contains("Write-permission probes were skipped"));

        app.doctor_filter = "no such diagnostic".into();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("No Doctor lines match this filter."));
        assert!(output.contains("Write-permission probes were skipped"));
    }

    #[test]
    fn doctor_filter_applies_and_resets_scroll() {
        let mut app = app();
        app.page = Start::Doctor;
        app.doctor_scroll = 7;
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(matches!(app.key(key(KeyCode::Char('/'))), Action::None));
        app.key(key(KeyCode::Char('p')));
        app.key(key(KeyCode::Char('a')));
        app.key(key(KeyCode::Char('t')));
        app.key(key(KeyCode::Char('h')));
        assert_eq!(app.doctor_search.as_deref(), Some("path"));
        assert!(matches!(app.key(key(KeyCode::Enter)), Action::None));
        assert_eq!(app.doctor_filter, "path");
        assert_eq!(app.doctor_scroll, 0);

        app.key(key(KeyCode::Char('/')));
        app.key(key(KeyCode::Char('x')));
        app.key(key(KeyCode::Esc));
        assert_eq!(app.doctor_filter, "path");
        assert!(app.doctor_search.is_none());
    }

    #[test]
    fn doctor_wraps_and_scrolls_a_single_long_diagnostic() {
        let mut app = app();
        app.page = Start::Doctor;
        app.issues = Some(vec![format!("{} END_MARKER", "x".repeat(120))]);
        for _ in 0..7 {
            app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        }
        assert_eq!(app.doctor_scroll, 7);
        let mut terminal = Terminal::new(TestBackend::new(25, 16)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("END_MARKER"));
    }

    #[test]
    fn doctor_scroll_clamps_to_the_last_wrapped_line() {
        let mut app = app();
        app.page = Start::Doctor;
        app.issues = Some(vec![format!("{} END_MARKER", "x".repeat(120))]);
        for _ in 0..250 {
            app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        }
        let area = Rect::new(0, 0, 25, 16);
        clamp_doctor_scroll(&mut app, area);
        let end_scroll = app.doctor_scroll;
        assert!(end_scroll > 0);
        let mut terminal = Terminal::new(TestBackend::new(25, 16)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(
            output.contains("dashboard."),
            "scroll passed the final Doctor text"
        );
        app.key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.doctor_scroll, end_scroll - 1);
    }

    #[test]
    fn reports_scroll_clamps_to_the_last_wrapped_line_after_resize() {
        let mut app = app();
        app.page = Start::Reports;
        app.history = Some(Ok(crate::reports::History {
            records: vec![crate::reports::Record {
                id: 0,
                started_unix: 1,
                finished_unix: None,
                duration_ms: 0,
                operation: "fixture_operation".into(),
                target: "fixture_target".into(),
                outcome: "completed".into(),
                detail: Some("x".repeat(1_200)),
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "test".into(),
            }],
            warnings: vec![],
            capacity: 100,
            known_reclaimed_bytes: None,
            records_without_verified_reclaimed_bytes: 0,
        }));
        app.history_scroll = u16::MAX;

        let narrow = Rect::new(0, 0, 25, 16);
        let mut terminal = Terminal::new(TestBackend::new(narrow.width, narrow.height)).unwrap();
        clamp_history_settings_scroll(&mut app, narrow);
        let narrow_limit =
            wrapped_content_scroll_limit(&reports_content(&app), content_area(narrow));
        assert!(narrow_limit > 0);
        assert_eq!(app.history_scroll, narrow_limit);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(
            output.contains("space."),
            "scroll={}/{narrow_limit}; output={output}",
            app.history_scroll
        );

        let larger = Rect::new(0, 0, 60, 24);
        terminal.backend_mut().resize(larger.width, larger.height);
        terminal.resize(larger).unwrap();
        clamp_history_settings_scroll(&mut app, larger);
        let larger_limit =
            wrapped_content_scroll_limit(&reports_content(&app), content_area(larger));
        assert!(larger_limit < narrow_limit);
        assert_eq!(app.history_scroll, larger_limit);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("space."));
    }

    #[test]
    fn reports_screen_formats_timestamps_as_readable_utc() {
        let mut app = app();
        app.page = Start::Reports;
        app.history = Some(Ok(crate::reports::History {
            records: vec![crate::reports::Record {
                id: 0,
                started_unix: 0,
                finished_unix: Some(1),
                duration_ms: 1,
                operation: "fixture_operation".into(),
                target: "fixture_target".into(),
                outcome: "completed".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "test".into(),
            }],
            warnings: Vec::new(),
            capacity: 100,
            known_reclaimed_bytes: None,
            records_without_verified_reclaimed_bytes: 1,
        }));

        let content = reports_content(&app);
        assert!(content.contains("started=1970-01-01 00:00:00 UTC"));
        assert!(content.contains("finished=1970-01-01 00:00:01 UTC"));
    }

    #[test]
    fn settings_form_persists_the_scheduled_artifact_cleanup_opt_in() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upkit.toml");
        std::fs::write(&path, "version = 1\n").unwrap();
        let document = crate::config::read_document(&path).unwrap();
        let mut form = SettingsForm::new(document).unwrap();

        assert!(
            settings_rows(&form)
                .iter()
                .any(|row| matches!(row, SettingsRow::ScheduledArtifactCleanup))
        );
        assert!(settings_form_content(&form).contains("Scheduled artifact cleanup: disabled"));
        settings_form_toggle(&mut form, SettingsRow::ScheduledArtifactCleanup);

        assert!(form.settings.scheduled_artifact_cleanup);
        let saved = form.save_text().unwrap();
        assert!(saved.contains("scheduled_artifact_cleanup = true"));
        assert!(form.cleanup_impacts().unwrap().iter().any(|impact| {
            impact.contains("Scheduled artifact cleanup policy will be enabled")
                && impact.contains("separate preview and confirmation")
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn artifact_schedule_confirmation_requires_full_review_before_activation() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("workspace");
        let config = dir.path().join("upkit.toml");
        std::fs::create_dir(&root).unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();

        for bytecode in [false, true] {
            std::fs::write(
                &config,
                format!(
                    "version = 1\nworkspace_roots = ['{}']\nartifact_retention = '30d'\nenabled_ecosystems = ['cargo', 'python']\nscheduled_artifact_cleanup = true\nscheduled_bytecode_cleanup = {bytecode}\n",
                    root.display(),
                ),
            )
            .unwrap();
            let plan = crate::schedule::preview_configured_install(
                &executable,
                Some(&config),
                None,
                crate::schedule::Frequency::Daily,
            )
            .unwrap();
            let disabled = crate::schedule::DisableSchedulePreview {
                unit_directory: plan.unit_directory.clone(),
                service_unit: plan.service_unit.clone(),
                timer_unit: plan.timer_unit.clone(),
                active_state: "inactive".into(),
                unit_file_state: Some("disabled".into()),
                preview_token: "fixture-disabled".into(),
                warning: "fixture",
            };
            let enable = crate::schedule::EnableSchedulePreview {
                intended: plan.clone(),
                installed: disabled.clone(),
                preview_token: "fixture-enable".into(),
                warning: "fixture",
            };
            let edit = crate::schedule::EditSchedulePreview {
                previous: crate::schedule::RemoveSchedulePreview {
                    existing: disabled,
                    quarantine_paths: vec![],
                    preview_token: "fixture-remove".into(),
                    warning: "fixture",
                },
                replacement: plan.clone(),
                preview_token: "fixture-edit".into(),
                warning: "fixture",
            };
            for content in [
                schedule_install_confirmation_lines_for(&plan, SchedulePlatform::Systemd)
                    .join("\n"),
                schedule_enable_confirmation_lines_for(&enable, SchedulePlatform::Systemd)
                    .join("\n"),
                schedule_edit_confirmation_lines_for(&edit, SchedulePlatform::Systemd).join("\n"),
            ] {
                assert!(content.contains("Press y to"));
                assert!(content.contains("reserves local history first"));
                assert!(content.contains(
                    "permanently removes explicitly scoped rebuildable project artifacts"
                ));
                assert!(content.contains("at most 8 directories"));
                assert!(!content.contains("No workspace files are cleaned"));
                assert!(!content.contains("no workspace files are cleaned"));
                if bytecode {
                    assert!(content.contains("permanently removes eligible Python bytecode"));
                } else {
                    assert!(!content.contains("Python bytecode"));
                }
            }

            let unsupported =
                schedule_install_confirmation_lines_for(&plan, SchedulePlatform::TaskScheduler)
                    .join("\n");
            assert!(unsupported.contains("only be installed on Linux with systemd"));
            assert!(!unsupported.contains("Press y to"));
            assert!(!unsupported.contains("workspace files are not cleaned"));

            let mut app = app();
            app.schedule_install_plan = Some((plan, crate::schedule::Frequency::Daily));
            assert!(!schedule_activation_is_preview_only(&app));
            let area = Rect::new(0, 0, 120, 30);
            app.update_schedule_confirmation(area);
            assert!(!schedule_confirmation_can_confirm(&app, area, area));
            review_schedule_confirmation_to_end(&mut app, area);
            assert!(schedule_confirmation_can_confirm(&app, area, area));
            assert!(matches!(
                app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
                Action::InstallSchedule(_, _)
            ));
        }
    }

    #[test]
    fn plain_settings_scroll_clamps_to_the_last_wrapped_line_after_resize() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upkit.toml");
        let lines = (0..40)
            .map(|index| format!("# {index} {}", "x".repeat(80)))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(
            &path,
            format!("version = 1\n{lines}\n# SETTINGS_END_MARKER"),
        )
        .unwrap();

        let mut app = app();
        app.page = Start::Settings;
        app.settings = Some(Ok(crate::config::read_document(&path).unwrap()));
        app.settings_scroll = u16::MAX;

        let narrow = Rect::new(0, 0, 25, 16);
        let mut terminal = Terminal::new(TestBackend::new(narrow.width, narrow.height)).unwrap();
        clamp_history_settings_scroll(&mut app, narrow);
        let narrow_limit =
            wrapped_content_scroll_limit(&settings_content(&app), content_area(narrow));
        assert!(narrow_limit > 0);
        assert_eq!(app.settings_scroll, narrow_limit);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(
            output.contains("SETTINGS_END_MARKER"),
            "scroll={}/{narrow_limit}; output={output}",
            app.settings_scroll
        );

        let larger = Rect::new(0, 0, 60, 24);
        terminal.backend_mut().resize(larger.width, larger.height);
        terminal.resize(larger).unwrap();
        clamp_history_settings_scroll(&mut app, larger);
        let larger_limit =
            wrapped_content_scroll_limit(&settings_content(&app), content_area(larger));
        assert!(larger_limit < narrow_limit);
        assert_eq!(app.settings_scroll, larger_limit);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("SETTINGS_END_MARKER"));
    }

    #[test]
    fn automation_scroll_clamps_to_the_last_wrapped_line_after_resize() {
        let mut app = app();
        app.page = Start::Automation;
        app.schedule = Some(crate::maintenance::TimerStatus {
            state: "active".into(),
            load_state: None,
            unit_file_state: Some("enabled".into()),
            last_trigger: None,
            next_trigger: None,
            detail: None,
        });
        app.schedule_scroll = u16::MAX;
        let platform = SchedulePlatform::LaunchAgent;
        let end_marker = if cfg!(target_os = "linux") {
            "status."
        } else {
            "profile."
        };

        let narrow = Rect::new(0, 0, 25, 16);
        let mut terminal = Terminal::new(TestBackend::new(narrow.width, narrow.height)).unwrap();
        clamp_schedule_scroll(&mut app, narrow, platform);
        let narrow_limit =
            wrapped_content_scroll_limit(&automation_content(&app, platform), content_area(narrow));
        assert!(narrow_limit > 0);
        assert_eq!(app.schedule_scroll, narrow_limit);
        terminal
            .draw(|frame| draw_for_platform(frame, &app, platform))
            .unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(
            output.contains(end_marker),
            "scroll={}; output={output}",
            app.schedule_scroll
        );

        let larger = Rect::new(0, 0, 60, 24);
        terminal.backend_mut().resize(larger.width, larger.height);
        terminal.resize(larger).unwrap();
        clamp_schedule_scroll(&mut app, larger, platform);
        let larger_limit =
            wrapped_content_scroll_limit(&automation_content(&app, platform), content_area(larger));
        assert!(larger_limit < narrow_limit);
        assert_eq!(app.schedule_scroll, larger_limit);
        terminal
            .draw(|frame| draw_for_platform(frame, &app, platform))
            .unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(
            output.contains(end_marker),
            "scroll={}; output={output}",
            app.schedule_scroll
        );
    }

    #[test]
    fn settings_form_first_row_remains_visible_on_short_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upkit.toml");
        std::fs::write(&path, "version = 1\n").unwrap();
        let form = SettingsForm::new(crate::config::read_document(&path).unwrap()).unwrap();
        let area = Rect::new(0, 0, 100, 5);
        let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
        terminal
            .draw(|frame| {
                let paragraph = Paragraph::new(settings_form_content(&form))
                    .block(Block::default().borders(Borders::ALL))
                    .wrap(Wrap { trim: false })
                    .scroll((settings_form_scroll(&form, area), 0));
                frame.render_widget(paragraph, area);
            })
            .unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("Profile scope"));
    }

    #[test]
    fn toolchain_confirmation_requires_every_full_line_and_target() {
        let mut app = app();
        app.reports.as_mut().unwrap()[0].latest = Some(crate::domain::Version {
            major: 1,
            minor: 2,
            patch: 3,
            pre: Some("x".repeat(80)),
        });
        assert!(!toolchain_confirmation_fits(&app, Rect::new(0, 0, 60, 24)));
        assert!(toolchain_confirmation_fits(&app, Rect::new(0, 0, 120, 24)));
        assert!(!toolchain_confirmation_fits(&app, Rect::new(0, 0, 120, 4)));
        app.marked.push(ToolKind::Node);
        assert!(!toolchain_confirmation_fits(&app, Rect::new(0, 0, 120, 24)));
    }

    #[test]
    fn toolchain_filter_matches_names_versions_status_and_notes() {
        let reports = toolchain_reports();
        assert!(toolchain_matches(&reports[1], "NODE"));
        assert!(toolchain_matches(&reports[1], "24.1"));
        assert!(toolchain_matches(
            &reports[1],
            "put node/active first on path"
        ));
        assert!(toolchain_matches(&reports[2], "OUTDATED"));
        assert!(toolchain_matches(&reports[2], "25.0.0"));
    }

    #[test]
    fn toolchain_inventory_refresh_preserves_filter_selection_and_marks() {
        let mut app = app();
        app.toolchain_filter = "go".into();
        app.selected = 0;
        app.marked = vec![ToolKind::Go];

        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)),
            Action::RefreshToolchains
        ));
        assert!(app.startup_checks.toolchains);
        assert!(app.reports.is_none());
        assert_eq!(app.toolchain_filter, "go");
        assert_eq!(app.selected, 0);
        assert_eq!(app.marked, [ToolKind::Go]);

        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Checking toolchains in the background"));
        assert!(output.contains("Refreshing toolchain inventory"));

        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.message.contains("already loading"));
    }

    #[test]
    fn narrow_toolchain_footer_keeps_refresh_update_and_quit_visible() {
        let app = app();
        for width in [58, 59, 60, 61] {
            let mut terminal = Terminal::new(TestBackend::new(width, 18)).unwrap();
            terminal.draw(|frame| draw(frame, &app)).unwrap();
            let output = format!("{:?}", terminal.backend().buffer());
            assert!(output.contains("r: refresh"), "width {width}: {output}");
            assert!(output.contains("Enter: update"), "width {width}: {output}");
            assert!(output.contains("q: quit"), "width {width}: {output}");
        }
    }

    #[test]
    fn toolchain_filter_keeps_hidden_marks_and_shows_them_in_confirmation() {
        let mut app = app();
        app.reports = Some(toolchain_reports());
        app.marked = vec![ToolKind::Go];
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        for code in [
            KeyCode::Char('/'),
            KeyCode::Char('n'),
            KeyCode::Char('o'),
            KeyCode::Char('d'),
            KeyCode::Char('e'),
            KeyCode::Enter,
        ] {
            app.key(key(code));
        }
        assert_eq!(app.selected, 1);
        assert_eq!(app.marked, [ToolKind::Go]);
        app.key(key(KeyCode::Down));
        assert_eq!(app.selected, 1);

        let mut terminal = Terminal::new(TestBackend::new(120, 16)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Filter: node (1/3 toolchains)"));
        assert!(output.contains("node"));
        assert!(!output.contains("java"));
        assert!(output.contains("1 tool(s) marked for update or cleanup (1 hidden by filter)"));

        app.key(key(KeyCode::Enter));
        let lines = toolchain_confirmation_lines(&app).unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("1 marked target(s) are hidden"))
        );
        assert!(lines.iter().any(|line| line.starts_with("go:")));
        assert!(!lines.iter().any(|line| line.starts_with("node:")));
        assert!(toolchain_confirmation_fits(&app, Rect::new(0, 0, 120, 16)));
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Confirm toolchain update"));
        assert!(output.contains("go: - → unknown"));
        assert!(output.contains("marked target(s) are hidden"));
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::Update(targets) if targets == [ToolKind::Go]
        ));
    }

    #[test]
    fn marked_tools_start_one_combined_managed_cleanup_review() {
        let mut app = app();
        app.reports = Some(toolchain_reports());
        app.marked = vec![ToolKind::Go, ToolKind::Node];
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('D'), KeyModifiers::NONE)),
            Action::PreviewManagedBatch(tools) if tools == [ToolKind::Go, ToolKind::Node]
        ));
        assert!(app.managed_preparing);
        assert!(app.managed_batch_plans.is_empty());
    }

    #[test]
    fn managed_batch_review_fails_closed_past_widget_scroll_range() {
        let max = u16::MAX as usize;
        assert!(managed_batch_review_scroll_supported(max + 1, 1, max));
        assert!(!managed_batch_review_scroll_supported(max + 2, 1, max));
        assert!(!managed_batch_review_scroll_supported(max + 2, 1, max + 1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn managed_batch_review_requires_the_end_and_restarts_after_resize() {
        use crate::test_support::{TestPrompt, base_ctx};

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("māngled");
        let bindir = dir.path().join("bin");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&bindir).unwrap();
        for tool in [ToolKind::Go, ToolKind::Node] {
            sealed_managed_tool_fixture(&home, &bindir, tool, 12);
        }
        let ctx = base_ctx(home.clone(), bindir, Arc::new(TestPrompt::default()));
        let targets = preview_managed_batch(
            &ctx,
            &[ToolKind::Go, ToolKind::Node],
            &AtomicBool::new(false),
        )
        .unwrap();
        let mut app = app();
        app.managed_batch_plans = targets;
        let large = Rect::new(0, 0, 120, 12);
        app.update_managed_batch_review(large);
        let mut terminal = Terminal::new(TestBackend::new(120, 12)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Review all 2 managed cleanup targets"));
        assert!(output.contains("Selected tool 1/2: go"));
        let content = app
            .managed_batch_review_content
            .as_ref()
            .unwrap()
            .join("\n");
        assert!(content.contains("Selected tool 1/2: go"));
        assert!(content.contains("Selected tool 2/2: node"));
        let displayed_home = crate::sweep::display_path(&home);
        assert!(displayed_home.contains("%C4%81"));
        assert!(content.contains(&displayed_home));
        assert!(content.contains("Top-level entries:"));
        assert!(content.contains("entry-11"));
        assert!(content.contains("recorded links"));
        assert!(content.contains("Warning:"));
        assert!(app.managed_batch_review_lines > app.managed_batch_review_rows);
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.message.contains("Scroll through every selected tool"));

        for _ in 0..app.managed_batch_review_lines {
            if managed_batch_review_complete(&app, large) {
                break;
            }
            app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        }
        assert!(managed_batch_review_complete(&app, large));
        let resized = Rect::new(0, 0, 120, 10);
        assert!(!managed_batch_review_complete(&app, resized));
        app.update_managed_batch_review(resized);
        assert_eq!(app.managed_batch_review_scroll, 0);
        assert!(!managed_batch_review_complete(&app, resized));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::None
        ));
        for _ in 0..app.managed_batch_review_lines {
            if managed_batch_review_complete(&app, resized) {
                break;
            }
            app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        }
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::RemoveManagedBatch(_)
        ));
        assert!(home.join("go").exists());
        assert!(home.join("node").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_managed_batch_preflight_leaves_every_root_untouched() {
        use crate::test_support::{TestPrompt, base_ctx};

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("managed");
        let bindir = dir.path().join("bin");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&bindir).unwrap();
        let mut executables = Vec::new();
        for tool in [ToolKind::Go, ToolKind::Node] {
            let install = sealed_managed_tool_fixture(&home, &bindir, tool, 0);
            executables.push(install.join(tool.as_str()).join("bin").join(tool.as_str()));
        }
        let ctx = base_ctx(home.clone(), bindir, Arc::new(TestPrompt::default()));
        let targets = preview_managed_batch(
            &ctx,
            &[ToolKind::Go, ToolKind::Node],
            &AtomicBool::new(false),
        )
        .unwrap();
        std::fs::write(&executables[0], "changed after review").unwrap();

        let result = run_managed_batch(&ctx, &targets, &AtomicBool::new(false));

        assert_eq!(result.items[0].status, "failed/uncertain");
        assert_eq!(result.items[1].status, "skipped");
        assert!(home.join("go").exists());
        assert!(home.join("node").exists());
        assert_eq!(
            std::fs::read_to_string(&executables[0]).unwrap(),
            "changed after review"
        );
        assert_eq!(
            std::fs::read_to_string(&executables[1]).unwrap(),
            "sealed fixture executable"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn active_later_managed_target_blocks_confirmation_and_first_removal() {
        use crate::test_support::{TestPrompt, base_ctx};

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("managed");
        let bindir = dir.path().join("bin");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&bindir).unwrap();
        let mut executables = Vec::new();
        for tool in [ToolKind::Go, ToolKind::Node] {
            let install = sealed_managed_tool_fixture(&home, &bindir, tool, 0);
            executables.push(install.join(tool.as_str()).join("bin").join(tool.as_str()));
        }
        let held_open = std::fs::File::open(&executables[1]).unwrap();
        let ctx = base_ctx(home.clone(), bindir, Arc::new(TestPrompt::default()));
        let targets = preview_managed_batch(
            &ctx,
            &[ToolKind::Go, ToolKind::Node],
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(
            targets[1].plan.activity_status,
            "open_handles_or_cwd_observed"
        );

        let mut app = app();
        app.managed_batch_plans = targets.clone();
        let area = Rect::new(0, 0, 180, 50);
        app.update_managed_batch_review(area);
        while !managed_batch_review_complete(&app, area) {
            app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        }
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.message.contains("using node"));

        let result = run_managed_batch(&ctx, &targets, &AtomicBool::new(false));

        assert_eq!(result.items[0].status, "skipped");
        assert_eq!(result.items[1].status, "failed/uncertain");
        assert!(home.join("go").exists());
        assert!(home.join("node").exists());
        drop(held_open);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shared_writable_managed_home_blocks_the_whole_cleanup_batch() {
        use crate::test_support::{TestPrompt, base_ctx};
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("managed");
        let bindir = dir.path().join("bin");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&bindir).unwrap();
        let mut installs = Vec::new();
        for tool in [ToolKind::Go, ToolKind::Node] {
            installs.push(sealed_managed_tool_fixture(&home, &bindir, tool, 0));
        }
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o775)).unwrap();
        let ctx = base_ctx(
            home.clone(),
            bindir.clone(),
            Arc::new(TestPrompt::default()),
        );
        let targets = preview_managed_batch(
            &ctx,
            &[ToolKind::Go, ToolKind::Node],
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(targets.iter().all(|target| target.plan.writable_by_others));

        let result = run_managed_batch(&ctx, &targets, &AtomicBool::new(false));

        assert_eq!(result.items[0].status, "failed/uncertain");
        assert_eq!(result.items[1].status, "skipped");
        for (tool, install) in [ToolKind::Go, ToolKind::Node].into_iter().zip(installs) {
            assert!(home.join(tool.as_str()).join("active").exists());
            assert!(install.exists());
            assert!(std::fs::symlink_metadata(bindir.join(tool.as_str())).is_ok());
        }
    }

    #[test]
    fn toolchain_filter_selects_visible_update_and_cancel_keeps_filter() {
        let mut app = app();
        app.reports = Some(toolchain_reports());
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        for code in [
            KeyCode::Char('/'),
            KeyCode::Char('j'),
            KeyCode::Char('a'),
            KeyCode::Char('v'),
            KeyCode::Char('a'),
            KeyCode::Enter,
        ] {
            app.key(key(code));
        }
        assert_eq!(app.selected, 2);
        app.key(key(KeyCode::Char('/')));
        app.key(key(KeyCode::Char('x')));
        app.key(key(KeyCode::Esc));
        assert_eq!(app.toolchain_filter, "java");
        assert!(app.toolchain_search.is_none());
        app.key(key(KeyCode::Down));
        assert_eq!(app.selected, 2);
        app.key(key(KeyCode::Enter));
        let lines = toolchain_confirmation_lines(&app).unwrap();
        assert!(lines.iter().any(|line| line.starts_with("java:")));
        assert!(!lines.iter().any(|line| line.starts_with("node:")));
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::Update(targets) if targets == [ToolKind::Java]
        ));
    }

    #[test]
    fn go_confirmation_shows_windows_goroot_warning() {
        let mut app = app();
        let report = &mut app.reports.as_mut().unwrap()[0];
        report.tool = ToolKind::Go;
        report.notes = vec![
            "Windows installation requires permission to create symbolic links.".into(),
            "Existing GOROOT settings can override the managed Go installation.".into(),
        ];
        let lines = toolchain_confirmation_lines(&app).unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("permission to create symbolic links"))
        );
        assert!(lines.iter().any(|line| line.contains("GOROOT settings")));
    }

    #[test]
    fn flutter_confirmation_shows_windows_archive_limitation() {
        let mut app = app();
        let report = &mut app.reports.as_mut().unwrap()[0];
        report.tool = ToolKind::Flutter;
        report.notes = vec![
            "Windows installation requires permission to create symbolic links.".into(),
            "Windows: put flutter/active/bin first on PATH.".into(),
            "Windows Flutter requires Git and PowerShell on PATH.".into(),
        ];
        let lines = toolchain_confirmation_lines(&app).unwrap();
        assert!(lines.iter().any(|line| {
            line.contains("Windows installation requires permission to create symbolic links")
        }));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("put flutter/active/bin first on PATH"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Flutter requires Git and PowerShell on PATH"))
        );
    }

    #[test]
    fn node_confirmation_shows_windows_path_requirement() {
        let mut app = app();
        let report = &mut app.reports.as_mut().unwrap()[0];
        report.tool = ToolKind::Node;
        report.notes = vec!["Windows: put node/active first on PATH.".into()];
        assert!(
            toolchain_confirmation_lines(&app)
                .unwrap()
                .iter()
                .any(|line| line.contains("put node/active first on PATH"))
        );
    }

    #[test]
    fn java_confirmation_shows_windows_symlink_requirement() {
        let mut app = app();
        let report = &mut app.reports.as_mut().unwrap()[0];
        report.tool = ToolKind::Java;
        report.notes =
            vec!["Windows installation requires permission to create symbolic links.".into()];
        let lines = toolchain_confirmation_lines(&app).unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Windows installation requires permission"))
        );
        assert!(!toolchain_confirmation_fits(&app, Rect::new(0, 0, 40, 16)));
        assert!(toolchain_confirmation_fits(&app, Rect::new(0, 0, 100, 16)));
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.key(key(KeyCode::Enter));
        assert!(app.confirmation);
        assert!(
            matches!(app.key(key(KeyCode::Char('y'))), Action::Update(tools) if tools == [ToolKind::Java])
        );
    }

    #[test]
    fn dotnet_confirmation_shows_windows_symlink_requirement() {
        let mut app = app();
        let report = &mut app.reports.as_mut().unwrap()[0];
        report.tool = ToolKind::Dotnet;
        report.notes =
            vec!["Windows installation requires permission to create symbolic links.".into()];
        let lines = toolchain_confirmation_lines(&app).unwrap();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Windows installation requires permission"))
        );
        assert!(!toolchain_confirmation_fits(&app, Rect::new(0, 0, 40, 16)));
        assert!(toolchain_confirmation_fits(&app, Rect::new(0, 0, 100, 16)));
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.key(key(KeyCode::Enter));
        assert!(app.confirmation);
        assert!(
            matches!(app.key(key(KeyCode::Char('y'))), Action::Update(tools) if tools == [ToolKind::Dotnet])
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn managed_cleanup_previews_one_selected_tool_and_requires_visible_confirmation() {
        use crate::test_support::{TestPrompt, base_ctx};
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("managed");
        let bindir = dir.path().join("bin");
        let root = home.join("go");
        sealed_managed_tool_fixture(&home, &bindir, ToolKind::Go, 0);
        let ctx = base_ctx(home, bindir, Arc::new(TestPrompt::default()));
        let plan =
            crate::managed_cleanup::preview(&ctx, ToolKind::Go, &AtomicBool::new(false)).unwrap();
        let mut app = app();
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE)),
            Action::PreviewManaged(ToolKind::Go)
        ));
        app.managed_preparing = false;
        app.managed_plan = Some(plan.clone());
        assert!(!managed_confirmation_fits(&plan, Rect::new(0, 0, 50, 8)));
        assert!(managed_confirmation_fits(&plan, Rect::new(0, 0, 160, 24)));
        app.key(KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE));
        assert!(app.managed_detail);
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::None
        ));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::RemoveManaged(_)
        ));
        assert!(app.managed_running);
        assert!(root.exists());
    }

    #[test]
    fn managed_cleanup_error_remains_scrollable_until_closed() {
        let mut app = app();
        app.managed_result = Some(format!(
            "partial failure; inspect {}",
            "/long/path/".repeat(40)
        ));
        let mut terminal = Terminal::new(TestBackend::new(50, 12)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("Cleanup result"));
        app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.managed_result_scroll, 1);
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.managed_result.is_none());
    }

    #[test]
    fn report_filter_is_editable_cancelable_and_preserves_totals() {
        let mut app = app();
        app.page = Start::Reports;
        let record = |id, operation: &str| crate::reports::Record {
            id,
            started_unix: 1,
            finished_unix: None,
            duration_ms: 0,
            operation: operation.into(),
            target: "fixture".into(),
            outcome: "completed".into(),
            detail: None,
            estimated_bytes: None,
            verified_reclaimed_bytes: Some(5),
            platform: "test".into(),
        };
        app.history = Some(Ok(crate::reports::History {
            records: vec![record(0, "trim"), record(1, "container_remove")],
            warnings: vec![],
            capacity: 100,
            known_reclaimed_bytes: Some(10),
            records_without_verified_reclaimed_bytes: 0,
        }));
        for code in [
            KeyCode::Char('/'),
            KeyCode::Char('T'),
            KeyCode::Char('R'),
            KeyCode::Char('I'),
            KeyCode::Char('M'),
            KeyCode::Enter,
        ] {
            app.key(KeyEvent::new(code, KeyModifiers::NONE));
        }
        assert_eq!(app.history_filter, "TRIM");
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("trim"));
        assert!(!output.contains("container_remove"));
        assert!(output.contains("subtotal: 10"));
        app.key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.history_filter, "TRIM");
        assert!(app.history_search.is_none());
    }

    #[test]
    fn reports_can_switch_chronological_order_in_test_backend() {
        let mut app = app();
        app.page = Start::Reports;
        let record = |id, started_unix, target: &str| crate::reports::Record {
            id,
            started_unix,
            finished_unix: None,
            duration_ms: 0,
            operation: "fixture_operation".into(),
            target: target.into(),
            outcome: "completed".into(),
            detail: None,
            estimated_bytes: None,
            verified_reclaimed_bytes: Some(5),
            platform: "test".into(),
        };
        app.history = Some(Ok(crate::reports::History {
            records: vec![
                record(1, 100, "fixture-oldest"),
                record(2, 200, "fixture-newest"),
            ],
            warnings: vec![],
            capacity: 100,
            known_reclaimed_bytes: Some(10),
            records_without_verified_reclaimed_bytes: 0,
        }));
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let newest_output = format!("{:?}", terminal.backend().buffer());
        assert!(newest_output.contains("Order: newest first"));
        assert!(newest_output.find("fixture-newest") < newest_output.find("fixture-oldest"));
        assert!(newest_output.contains("subtotal: 10"));

        app.history_scroll = 5;
        app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
        assert!(app.history_oldest_first);
        assert_eq!(app.history_scroll, 0);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let oldest_output = format!("{:?}", terminal.backend().buffer());
        assert!(oldest_output.contains("Order: oldest first"));
        assert!(oldest_output.find("fixture-oldest") < oldest_output.find("fixture-newest"));
        assert!(oldest_output.contains("subtotal: 10"));
    }

    #[test]
    fn cache_filter_only_selects_visible_paths_and_keeps_global_warnings() {
        let entry = |name, path: &str| crate::cache::CacheEntry {
            name,
            path: path.into(),
            ownership: "shared user cache",
            directory_owner_status: "current_user",
            classification: "shared cache",
            consequence: "downloads may be needed",
            status: "inventory only",
            logical_bytes: Some(5),
            allocated_bytes: None,
            size_complete: true,
            activity_status: "no_open_handles_or_cwd_observed",
            warnings: vec![],
            go_test_cache: None,
        };
        let mut app = app();
        app.page = Start::Cache;
        app.cache = Some(crate::cache::CacheReport {
            entries: vec![
                entry("Go build", "/fixture/go"),
                entry("Cargo registry", "/fixture/reg"),
                entry("Cargo git", "/fixture/git"),
            ],
            warnings: vec!["global warning".into()],
            cancelled: false,
        });
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.key(key(KeyCode::Char('/')));
        for ch in "CARGO".chars() {
            app.key(key(KeyCode::Char(ch)));
        }
        app.key(key(KeyCode::Enter));
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("2 of 3 caches"));
        assert!(output.contains("Cargo registry") && output.contains("Cargo git"));
        assert!(!output.contains("Go build"));
        assert!(output.contains("1 diagnostic warning(s)"));
        assert!(!output.contains("global warning"));
        app.key(key(KeyCode::Char('w')));
        assert!(app.cache_details);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let details = format!("{:?}", terminal.backend().buffer());
        assert!(details.contains("global warning"));
        app.key(key(KeyCode::Char('w')));
        assert!(!app.cache_details);
        assert!(matches!(app.key(key(KeyCode::Char('e'))), Action::None));
        app.key(key(KeyCode::Char('d')));
        assert!(app.cache_choosing);
        app.key(key(KeyCode::Down));
        assert!(
            matches!(app.key(key(KeyCode::Enter)), Action::PreviewSharedCache(path) if path == std::path::Path::new("/fixture/reg"))
        );
        app.artifact_preparing = false;
        app.key(key(KeyCode::Char('/')));
        app.key(key(KeyCode::Backspace));
        app.key(key(KeyCode::Esc));
        assert_eq!(app.cache_filter, "CARGO");
        app.key(key(KeyCode::Char('/')));
        for _ in 0..5 {
            app.key(key(KeyCode::Backspace));
        }
        for ch in "absent".chars() {
            app.key(key(KeyCode::Char(ch)));
        }
        app.key(key(KeyCode::Enter));
        app.key(key(KeyCode::Char('d')));
        assert!(!app.cache_choosing);
        assert!(cache_matches(
            &entry("example", "/fixture/%name"),
            "%25name"
        ));
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let mut non_utf8 = entry("example", "/fixture");
            non_utf8.path = std::ffi::OsString::from_vec(b"/fixture/\xff".to_vec()).into();
            assert!(cache_matches(&non_utf8, "%FF"));
            assert!(!cache_matches(&entry("example", "/fixture/%FF"), "%FF"));
        }
    }

    #[test]
    fn cache_content_wraps_clamps_and_keeps_filtered_selection_usable() {
        let active_path = PathBuf::from(format!(
            "/fixture/{}CACHE_PATH_END_MARKER",
            "long-cache-segment/".repeat(8)
        ));
        let other_path = PathBuf::from("/fixture/cargo-cache");
        let entry = |name, path: PathBuf, status| crate::cache::CacheEntry {
            name,
            path,
            ownership: "shared user cache",
            directory_owner_status: "current_user",
            classification: "shared cache",
            consequence: "Removing this cache may require downloads and rebuilds for later work.",
            status,
            logical_bytes: Some(64),
            allocated_bytes: Some(48),
            size_complete: true,
            activity_status: "CACHE_ACTIVITY_END_MARKER",
            warnings: vec![],
            go_test_cache: None,
        };
        let mut app = app();
        app.page = Start::Cache;
        app.cache = Some(crate::cache::CacheReport {
            entries: vec![
                entry(
                    "Active Go cache",
                    active_path.clone(),
                    "CACHE_STATUS_END_MARKER",
                ),
                entry("Cargo cache", other_path.clone(), "inventory only"),
            ],
            warnings: vec![],
            cancelled: false,
        });
        app.cache_selected = Some(active_path.clone());
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(!cache_content(&app).contains("Directory owner (snapshot)"));
        app.key(key(KeyCode::Char('w')));
        assert!(app.cache_details);
        app.key(key(KeyCode::Char('/')));
        for character in "cache".chars() {
            app.key(key(KeyCode::Char(character)));
        }
        app.key(key(KeyCode::Enter));
        assert_eq!(app.cache_filter, "cache");
        assert_eq!(app.cache_selected.as_ref(), Some(&active_path));

        let narrow = Rect::new(0, 0, 25, 16);
        let mut terminal = Terminal::new(TestBackend::new(narrow.width, narrow.height)).unwrap();
        clamp_cache_scroll(&mut app, narrow);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("› Active Go cache"));

        let content = cache_content(&app);
        let wrap_width = content_area(narrow).width.saturating_sub(2);
        let path_prefix = &content[..content.find("CACHE_PATH_END_MARKER").unwrap()];
        let path_line = Paragraph::new(path_prefix)
            .wrap(Wrap { trim: false })
            .line_count(wrap_width)
            .saturating_sub(1);
        app.cache_scroll = u16::try_from(path_line.saturating_sub(2)).unwrap();
        clamp_cache_scroll(&mut app, narrow);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("CACHE_PATH_END_MARKER"));

        let content = cache_content(&app);
        let status_prefix = &content[..content.find("CACHE_STATUS_END_MARKER").unwrap()];
        let status_line = Paragraph::new(status_prefix)
            .wrap(Wrap { trim: false })
            .line_count(wrap_width)
            .saturating_sub(1);
        app.cache_scroll = u16::try_from(status_line.saturating_sub(2)).unwrap();
        clamp_cache_scroll(&mut app, narrow);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let status_output = format!("{:?}", terminal.backend().buffer());
        assert!(status_output.contains("CACHE_STATUS_END_MARKER"));

        app.cache_scroll = u16::MAX;
        clamp_cache_scroll(&mut app, narrow);
        let narrow_limit = wrapped_content_scroll_limit(&cache_content(&app), content_area(narrow));
        assert!(narrow_limit > 0);
        assert_eq!(app.cache_scroll, narrow_limit);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("reclaimed bytes."));

        let larger = Rect::new(0, 0, 60, 24);
        terminal.backend_mut().resize(larger.width, larger.height);
        terminal.resize(larger).unwrap();
        clamp_cache_scroll(&mut app, larger);
        let larger_limit = wrapped_content_scroll_limit(&cache_content(&app), content_area(larger));
        assert!(larger_limit < narrow_limit);
        assert_eq!(app.cache_scroll, larger_limit);
        assert_eq!(app.cache_selected.as_ref(), Some(&active_path));
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("reclaimed bytes."));

        app.cache_scroll = 0;
        assert!(matches!(app.key(key(KeyCode::Char('d'))), Action::None));
        assert!(app.cache_choosing);
        let scroll_before_selection = app.cache_scroll;
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("› Active Go cache"));
        app.key(key(KeyCode::Down));
        assert_eq!(app.cache_scroll, scroll_before_selection);
        assert_eq!(app.cache_selected.as_ref(), Some(&other_path));
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("› Cargo cache"));
        assert!(matches!(
            app.key(key(KeyCode::Enter)),
            Action::PreviewSharedCache(path) if path == other_path
        ));
    }

    #[test]
    fn cache_sort_keeps_selection_through_filter_and_refresh_and_puts_unknown_size_last() {
        let entry =
            |name, path: &str, logical_bytes, size_complete, owner, activity, status, warnings| {
                crate::cache::CacheEntry {
                    name,
                    path: path.into(),
                    ownership: "shared user cache",
                    directory_owner_status: owner,
                    classification: "shared cache",
                    consequence: "downloads may be needed",
                    status,
                    logical_bytes,
                    allocated_bytes: None,
                    size_complete,
                    activity_status: activity,
                    warnings,
                    go_test_cache: None,
                }
            };
        let active = entry(
            "Active cache",
            "/fixture/active",
            Some(200),
            true,
            "current_user",
            "open_handles_or_cwd_observed",
            "inventory only",
            vec![],
        );
        let unknown = entry(
            "Unknown cache",
            "/fixture/unknown",
            None,
            false,
            "unavailable",
            "inspection_incomplete",
            "unavailable",
            vec!["size unavailable".into()],
        );
        let registry = entry(
            "Cargo registry",
            "/fixture/registry",
            Some(100),
            true,
            "current_user",
            "no_open_handles_or_cwd_observed",
            "inventory only",
            vec![],
        );
        let alias = entry(
            "Cargo alias",
            "/fixture/cache-link",
            Some(50),
            true,
            "current_user",
            "no_open_handles_or_cwd_observed",
            "inventory only",
            vec![],
        );
        let partial = entry(
            "Partial cache",
            "/fixture/partial",
            Some(75),
            false,
            "current_user",
            "no_open_handles_or_cwd_observed",
            "inventory only",
            vec![],
        );
        let mut app = app();
        app.page = Start::Cache;
        app.cache = Some(crate::cache::CacheReport {
            entries: vec![unknown, alias, active, registry, partial],
            warnings: vec![],
            cancelled: false,
        });
        app.cache_selected = Some(PathBuf::from("/fixture/cache-link"));
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);

        let name_order = visible_cache_entries(app.cache.as_ref().unwrap(), "", app.cache_sort)
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            name_order,
            vec![
                PathBuf::from("/fixture/active"),
                PathBuf::from("/fixture/cache-link"),
                PathBuf::from("/fixture/registry"),
                PathBuf::from("/fixture/partial"),
                PathBuf::from("/fixture/unknown"),
            ]
        );

        app.key(key(KeyCode::Char('s')));
        assert_eq!(app.cache_sort, CacheSort::Size);
        let size_order = visible_cache_entries(app.cache.as_ref().unwrap(), "", app.cache_sort)
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            size_order,
            vec![
                PathBuf::from("/fixture/active"),
                PathBuf::from("/fixture/registry"),
                PathBuf::from("/fixture/cache-link"),
                PathBuf::from("/fixture/partial"),
                PathBuf::from("/fixture/unknown"),
            ]
        );
        assert_eq!(
            app.cache_selected.as_deref(),
            Some(std::path::Path::new("/fixture/cache-link"))
        );

        app.key(key(KeyCode::Char('s')));
        assert_eq!(app.cache_sort, CacheSort::Risk);
        let risk_order = visible_cache_entries(app.cache.as_ref().unwrap(), "", app.cache_sort)
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            risk_order,
            vec![
                PathBuf::from("/fixture/active"),
                PathBuf::from("/fixture/partial"),
                PathBuf::from("/fixture/unknown"),
                PathBuf::from("/fixture/cache-link"),
                PathBuf::from("/fixture/registry"),
            ]
        );
        assert_eq!(
            visible_cache_entries(app.cache.as_ref().unwrap(), "", app.cache_sort).len(),
            5
        );
        assert!(!cache_content(&app).contains("Directory owner (snapshot)"));
        app.key(key(KeyCode::Char('w')));
        let mut terminal = Terminal::new(TestBackend::new(160, 40)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Sort: risk"));
        assert!(output.contains("logical snapshot") && output.contains("allocated snapshot"));
        assert!(output.contains("unknown"));
        assert!(output.contains("not reclaimed bytes"));

        app.key(key(KeyCode::Char('s')));
        assert_eq!(app.cache_sort, CacheSort::Name);
        assert_eq!(
            app.cache_selected.as_deref(),
            Some(std::path::Path::new("/fixture/cache-link"))
        );

        app.key(key(KeyCode::Char('/')));
        for ch in "active".chars() {
            app.key(key(KeyCode::Char(ch)));
        }
        app.key(key(KeyCode::Enter));
        assert_eq!(
            app.cache_selected.as_deref(),
            Some(std::path::Path::new("/fixture/cache-link"))
        );
        let visible = visible_cache_entries(
            app.cache.as_ref().unwrap(),
            &app.cache_filter,
            app.cache_sort,
        );
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].path, PathBuf::from("/fixture/active"));
        let mut terminal = Terminal::new(TestBackend::new(160, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Current selection is hidden by this filter"));
        assert!(!output.contains("› Active cache"));

        app.key(key(KeyCode::Char('/')));
        for _ in 0.."active".len() {
            app.key(key(KeyCode::Backspace));
        }
        app.key(key(KeyCode::Enter));
        assert!(app.cache_filter.is_empty());
        assert_eq!(
            app.cache_selected.as_deref(),
            Some(std::path::Path::new("/fixture/cache-link"))
        );

        assert!(matches!(
            app.key(key(KeyCode::Char('r'))),
            Action::StartCache
        ));
        assert!(app.cache.is_none());
        assert_eq!(
            app.cache_selected.as_deref(),
            Some(std::path::Path::new("/fixture/cache-link"))
        );
        app.cache = Some(crate::cache::CacheReport {
            entries: vec![
                entry(
                    "Active cache",
                    "/fixture/active",
                    Some(200),
                    true,
                    "current_user",
                    "open_handles_or_cwd_observed",
                    "inventory only",
                    vec![],
                ),
                entry(
                    "Unknown cache",
                    "/fixture/unknown",
                    None,
                    false,
                    "unavailable",
                    "inspection_incomplete",
                    "unavailable",
                    vec!["size unavailable".into()],
                ),
                entry(
                    "Cargo registry",
                    "/fixture/registry",
                    Some(100),
                    true,
                    "current_user",
                    "no_open_handles_or_cwd_observed",
                    "inventory only",
                    vec![],
                ),
                entry(
                    "Partial cache",
                    "/fixture/partial",
                    Some(75),
                    false,
                    "current_user",
                    "no_open_handles_or_cwd_observed",
                    "inventory only",
                    vec![],
                ),
            ],
            warnings: vec![],
            cancelled: false,
        });
        app.cache_running = false;
        app.normalize_cache_selection();
        assert_eq!(
            app.cache_selected.as_deref(),
            Some(std::path::Path::new("/fixture/active"))
        );
        app.key(key(KeyCode::Char('d')));
        assert!(matches!(
            app.key(key(KeyCode::Enter)),
            Action::PreviewSharedCache(path) if path == std::path::Path::new("/fixture/active")
        ));
    }

    #[test]
    fn cache_sort_and_duplicate_names_keep_the_exact_preview_target() {
        let entry = |path: &str, logical_bytes| crate::cache::CacheEntry {
            name: "Cargo registry",
            path: path.into(),
            ownership: "shared user cache",
            directory_owner_status: "current_user",
            classification: "shared dependencies",
            consequence: "packages may need to be downloaded again",
            status: "inventory only",
            logical_bytes,
            allocated_bytes: None,
            size_complete: true,
            activity_status: "no_open_handles_or_cwd_observed",
            warnings: vec![],
            go_test_cache: None,
        };
        let alias = PathBuf::from("/fixture/cache-alias");
        let mut app = app();
        app.page = Start::Cache;
        app.cache = Some(crate::cache::CacheReport {
            entries: vec![
                entry("/fixture/cache", Some(100)),
                entry("/fixture/cache-alias", Some(20)),
            ],
            warnings: vec![],
            cancelled: false,
        });
        app.cache_selected = Some(alias.clone());
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let duplicate_paths = crate::cache::CacheReport {
            entries: vec![
                entry("/fixture/shared", Some(100)),
                entry("/fixture/shared", Some(20)),
            ],
            warnings: vec![],
            cancelled: false,
        };
        assert_eq!(
            visible_cache_entries(&duplicate_paths, "", CacheSort::Size).len(),
            1
        );
        app.key(key(KeyCode::Char('s')));
        assert_eq!(app.cache_sort, CacheSort::Size);
        assert_eq!(app.cache_selected.as_ref(), Some(&alias));
        app.key(key(KeyCode::Char('d')));
        assert!(app.cache_choosing);
        let mut terminal = Terminal::new(TestBackend::new(120, 16)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("› Cargo registry  /fixture/cache-alias"));
        assert!(matches!(
            app.key(key(KeyCode::Enter)),
            Action::PreviewSharedCache(path) if path == alias
        ));

        app.artifact_preparing = false;
        app.artifact_plan = Some(DirectoryPlan::Cache(
            crate::shared_cache_cleanup::CacheRemovalPlan {
                name: "Cargo registry",
                target: alias.clone(),
                classification: "shared dependencies",
                consequence: "packages may need to be downloaded again",
                logical_bytes: 20,
                entries: vec![],
                preview_token: "fixture".into(),
                warning: "fixture",
            },
        ));
        app.key(key(KeyCode::Char('s')));
        assert_eq!(app.cache_sort, CacheSort::Size);
        let DirectoryPlan::Cache(plan) = app.artifact_plan.as_ref().unwrap() else {
            panic!("cache preview was replaced");
        };
        assert_eq!(plan.target, alias);
        app.artifact_confirm = true;
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Confirm permanent shared-cache removal"));
        assert!(output.contains("/fixture/cache-alias"));
        assert!(output.contains("Logical size: 20 bytes; reclaimed space is unknown."));
        assert!(!output.contains("20 bytes reclaimed"));
        app.key(key(KeyCode::Char('n')));
        assert!(app.artifact_plan.is_none());
        assert_eq!(app.cache_selected.as_ref(), Some(&alias));
    }

    #[test]
    fn artifact_filter_keeps_selection_bound_to_the_visible_item() {
        let dir = tempfile::tempdir().unwrap();
        let cargo = dir.path().join("rust");
        let python = dir.path().join("python");
        std::fs::create_dir_all(cargo.join("target")).unwrap();
        std::fs::create_dir_all(python.join("__pycache__")).unwrap();
        std::fs::write(cargo.join("Cargo.toml"), "[workspace]").unwrap();
        std::fs::write(python.join("pyproject.toml"), "[project]").unwrap();
        let scan = crate::sweep::scan(&[dir.path().to_owned()]).unwrap();
        let plan = crate::sweep::preview(scan, &[]).unwrap();
        assert_eq!(plan.items.len(), 2);
        let mut app = app();
        app.page = Start::Artifacts;
        app.preview_mode = true;
        app.plan = Some(Ok(plan));
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        for code in [
            KeyCode::Char('/'),
            KeyCode::Char('c'),
            KeyCode::Char('a'),
            KeyCode::Char('r'),
            KeyCode::Char('g'),
            KeyCode::Char('o'),
            KeyCode::Enter,
            KeyCode::Char(' '),
        ] {
            app.key(key(code));
        }
        let plan = app.plan.as_ref().unwrap().as_ref().unwrap();
        assert!(
            plan.items
                .iter()
                .find(|item| item.candidate.ecosystem == "cargo")
                .unwrap()
                .selected
        );
        assert!(
            !plan
                .items
                .iter()
                .find(|item| item.candidate.ecosystem == "python")
                .unwrap()
                .selected
        );
        app.key(key(KeyCode::Char('/')));
        for _ in 0..5 {
            app.key(key(KeyCode::Backspace));
        }
        for ch in "python".chars() {
            app.key(key(KeyCode::Char(ch)));
        }
        app.key(key(KeyCode::Enter));
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("1 selected, 1 hidden"));
        app.key(key(KeyCode::Char(' ')));
        assert_eq!(
            app.plan
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .items
                .iter()
                .filter(|item| item.selected)
                .count(),
            2
        );
        app.key(key(KeyCode::Enter));
        assert!(app.plan_detail);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("python"));
    }

    #[cfg(unix)]
    #[test]
    fn artifact_filter_distinguishes_non_utf8_paths_before_removal_review() {
        use std::os::unix::ffi::OsStringExt;
        let dir = tempfile::tempdir().unwrap();
        let invalid = dir
            .path()
            .join(std::ffi::OsString::from_vec(b"project-\xff".to_vec()));
        let literal = dir.path().join("project-%FF");
        for project in [&invalid, &literal] {
            std::fs::create_dir_all(project.join("target")).unwrap();
            std::fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
        }
        let scan = crate::sweep::scan(&[dir.path().to_owned()]).unwrap();
        assert_eq!(scan.candidates.len(), 2);
        let mut app = app();
        app.page = Start::Artifacts;
        app.artifact_filter = "%FF".into();
        app.scan = Some(Ok(scan));
        let action = app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        assert!(matches!(action, Action::PreviewArtifact(path) if path == invalid.join("target")));
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("project-%FF/target"));
        assert!(!output.contains("project-%25FF/target"));
    }

    #[test]
    fn artifact_batch_marks_follow_targets_across_filter_and_sort() {
        let dir = tempfile::tempdir().unwrap();
        for (name, contents) in [
            ("project-a", "small"),
            ("project-b", "a larger fixture file"),
            ("project-c", "other"),
        ] {
            let root = dir.path().join(name);
            std::fs::create_dir_all(root.join("target")).unwrap();
            std::fs::write(root.join("Cargo.toml"), "[workspace]").unwrap();
            std::fs::write(root.join("target").join("fixture"), contents).unwrap();
        }
        let scan = crate::sweep::scan(&[dir.path().to_owned()]).unwrap();
        let targets = scan
            .candidates
            .iter()
            .map(|candidate| candidate.target.clone())
            .collect::<Vec<_>>();
        assert_eq!(targets.len(), 3);

        let mut app = app();
        app.page = Start::Artifacts;
        app.scan = Some(Ok(scan));
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.key(key(KeyCode::Char(' ')));
        app.key(key(KeyCode::Down));
        app.key(key(KeyCode::Char(' ')));
        assert_eq!(app.artifact_marks, targets[..2]);

        app.artifact_filter = "project-c".into();
        app.scan_scroll = 0;
        app.key(key(KeyCode::Char('s')));
        assert_eq!(app.artifact_marks, targets[..2]);
        assert!(matches!(
            app.key(key(KeyCode::Char('d'))),
            Action::PreviewArtifactBatch(marked) if marked == targets[..2]
        ));
    }

    #[test]
    fn artifact_batch_reviews_every_target_and_requires_scrolled_confirmation() {
        let scope = crate::sweep::Scope {
            roots: vec!["/fixture".into()],
            exclusions: vec![],
            older_than_seconds: None,
            enabled: None,
        };
        let items = (0..3)
            .map(|index| crate::artifact_cleanup::ArtifactPlan {
                scope: scope.clone(),
                project: format!("/fixture/project-{index}").into(),
                manifest: format!("/fixture/project-{index}/Cargo.toml").into(),
                target: format!("/fixture/project-{index}/target").into(),
                ecosystem: "cargo",
                classification: "review",
                logical_bytes: 42,
                entries: vec![crate::artifact_cleanup::ArtifactEntry {
                    path: format!("file-{index}"),
                    kind: "file",
                    logical_bytes: Some(42),
                }],
                preview_token: format!("item-{index}"),
                #[cfg(target_os = "linux")]
                cargo_config_identity: None,
                #[cfg(target_os = "linux")]
                cargo_workspace_evidence: None,
                #[cfg(target_os = "linux")]
                git_evidence_id: None,
                warning: "fixture warning",
                reproduction_warning: None,
            })
            .collect::<Vec<_>>();
        let plan = crate::artifact_cleanup::ArtifactBatchPlan {
            scope,
            items,
            preview_token: "batch".into(),
            warning: "Each selected directory is removed permanently and reported separately.",
        };
        let area = Rect::new(0, 0, 80, 12);
        let mut cancelled = app();
        let mut app = app();
        app.artifact_plan = Some(DirectoryPlan::ArtifactBatch(plan.clone()));
        app.update_artifact_review(area);
        let review = app.artifact_review_content.as_ref().unwrap().join("\n");
        for index in 0..3 {
            assert!(review.contains(&format!("project-{index}/target")));
            assert!(review.contains(&format!("file-{index}")));
        }

        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        while app.artifact_review_scroll + app.artifact_review_rows < app.artifact_review_lines {
            app.key(key(KeyCode::Down));
        }
        app.key(key(KeyCode::Enter));
        assert!(app.artifact_confirm);
        app.update_artifact_review(area);
        assert!(matches!(app.key(key(KeyCode::Char('y'))), Action::None));
        assert!(app.artifact_plan.is_some());
        let confirmation = app.artifact_review_content.as_ref().unwrap().join("\n");
        for index in 0..3 {
            assert!(confirmation.contains(&format!("project-{index}/target")));
        }
        while app.artifact_review_scroll + app.artifact_review_rows < app.artifact_review_lines {
            app.key(key(KeyCode::Down));
        }
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::RemoveArtifactBatch(reviewed) if reviewed.items.len() == 3
        ));

        cancelled.artifact_plan = Some(DirectoryPlan::ArtifactBatch(plan));
        assert!(matches!(cancelled.key(key(KeyCode::Esc)), Action::None));
        assert!(cancelled.artifact_plan.is_none());
    }

    #[test]
    fn artifact_sort_preserves_filtered_selection_and_action_target() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["project-a", "project-b", "project-c"] {
            let root = dir.path().join(name);
            std::fs::create_dir_all(root.join("target")).unwrap();
            std::fs::write(root.join("Cargo.toml"), "[workspace]").unwrap();
        }
        let scan = crate::sweep::scan(&[dir.path().to_owned()]).unwrap();
        let mut plan = crate::sweep::preview(scan, &[]).unwrap();
        assert_eq!(plan.items.len(), 3);
        plan.items
            .sort_by(|a, b| a.candidate.target.cmp(&b.candidate.target));
        for (item, (size, complete, modified)) in plan.items.iter_mut().zip([
            (10, true, Some(20)),
            (100, true, Some(10)),
            (1000, false, None),
        ]) {
            item.candidate.logical_bytes = size;
            item.candidate.size_complete = complete;
            item.candidate.modified_unix = modified;
        }
        let a = plan.items[0].candidate.target.clone();
        let b = plan.items[1].candidate.target.clone();
        let c = plan.items[2].candidate.target.clone();
        let mut app = app();
        app.page = Start::Artifacts;
        app.preview_mode = true;
        app.artifact_filter = "project".into();
        app.plan = Some(Ok(plan));
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.key(key(KeyCode::Char(' ')));
        app.key(key(KeyCode::Char('s')));
        let plan = app.plan.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(
            plan.items
                .iter()
                .map(|item| &item.candidate.target)
                .collect::<Vec<_>>(),
            vec![&b, &a, &c]
        );
        assert!(plan.items[1].selected);
        assert_eq!(app.scan_scroll, 1);
        app.key(key(KeyCode::Char('s')));
        let plan = app.plan.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(
            plan.items
                .iter()
                .map(|item| &item.candidate.target)
                .collect::<Vec<_>>(),
            vec![&b, &a, &c]
        );
        assert!(plan.items[1].selected);
        assert!(matches!(
            app.key(key(KeyCode::Char('d'))),
            Action::PreviewArtifactBatch(paths) if paths == vec![a.clone()]
        ));
        app.artifact_preparing = false;
        app.scan_scroll = 99;
        app.key(key(KeyCode::Char('s')));
        assert_eq!(app.scan_scroll, 0);
        let plan = app.plan.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(
            plan.items
                .iter()
                .map(|item| &item.candidate.target)
                .collect::<Vec<_>>(),
            vec![&a, &b, &c]
        );
        app.scan_running = true;
        app.key(key(KeyCode::Char('s')));
        assert!(matches!(app.artifact_sort, ArtifactSort::Path));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn artifact_details_show_cargo_workspace_evidence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("target")).unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        let scan = crate::sweep::scan(&[dir.path().to_owned()]).unwrap();
        let plan = crate::sweep::preview(scan, &[]).unwrap();
        let mut app = app();
        app.page = Start::Artifacts;
        app.preview_mode = true;
        app.plan = Some(Ok(plan));
        app.plan_detail = true;
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Cargo workspace"));
        assert!(output.contains("workspace_manifest"));
    }

    #[test]
    fn worker_event_batches_are_bounded_fifo_and_keep_completion() {
        let (tx, rx) = mpsc::channel();
        let queued_progress = MAX_WORKER_EVENTS_PER_FRAME + 3;
        for visited in 0..queued_progress {
            tx.send(WorkerEvent::Updating(
                ToolKind::Go,
                visited,
                queued_progress,
            ))
            .unwrap();
        }
        tx.send(WorkerEvent::Scanned(Err("scan complete".into())))
            .unwrap();

        let first = worker_events_for_frame(&rx);
        assert_eq!(first.len(), MAX_WORKER_EVENTS_PER_FRAME);
        assert_eq!(
            first
                .iter()
                .map(|event| match event {
                    WorkerEvent::Updating(ToolKind::Go, visited, _) => *visited,
                    _ => panic!("unexpected worker event before scan completion"),
                })
                .collect::<Vec<_>>(),
            (0..MAX_WORKER_EVENTS_PER_FRAME).collect::<Vec<_>>()
        );

        let second = worker_events_for_frame(&rx);
        assert_eq!(second.len(), 4);
        assert_eq!(
            second[..3]
                .iter()
                .map(|event| match event {
                    WorkerEvent::Updating(ToolKind::Go, visited, _) => *visited,
                    _ => panic!("unexpected worker event before scan completion"),
                })
                .collect::<Vec<_>>(),
            (MAX_WORKER_EVENTS_PER_FRAME..queued_progress).collect::<Vec<_>>()
        );
        assert!(matches!(
            second.last(),
            Some(WorkerEvent::Scanned(Err(error))) if error == "scan complete"
        ));
        assert!(rx.try_iter().next().is_none());
    }

    #[test]
    fn confirmation_frame_discards_input_queued_before_and_during_draw() {
        use std::cell::RefCell;

        let pending = RefCell::new(vec![Event::Key(KeyEvent::new(
            KeyCode::Char('y'),
            KeyModifiers::NONE,
        ))]);
        let calls = RefCell::new(Vec::new());
        let kept = draw_confirmation_frame(
            true,
            |retain_navigation_and_cancellation| {
                calls.borrow_mut().push("discard");
                let mut pending = pending.borrow_mut();
                Ok(pending
                    .drain(..)
                    .filter(|event| {
                        retain_navigation_and_cancellation
                            && is_confirmation_navigation_or_cancellation(event)
                    })
                    .collect())
            },
            || {
                assert!(pending.borrow().is_empty());
                calls.borrow_mut().push("draw");
                pending.borrow_mut().push(Event::Key(KeyEvent::new(
                    KeyCode::Char('y'),
                    KeyModifiers::NONE,
                )));
                pending
                    .borrow_mut()
                    .push(Event::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*calls.borrow(), ["discard", "draw", "discard"]);
        assert!(pending.borrow().is_empty());
        assert!(matches!(kept.front(), Some(Event::Key(key)) if key.code == KeyCode::Esc));
        assert_eq!(kept.len(), 1);

        pending.borrow_mut().push(Event::Key(KeyEvent::new(
            KeyCode::Char('y'),
            KeyModifiers::NONE,
        )));
        assert!(
            draw_confirmation_frame(false, |_| panic!("unexpected discard"), || Ok(()))
                .unwrap()
                .is_empty()
        );
        assert_eq!(pending.borrow().len(), 1);
    }

    #[test]
    fn only_navigation_and_cancellation_are_retained_from_a_confirmation_frame() {
        for code in [
            KeyCode::Esc,
            KeyCode::Char('n'),
            KeyCode::Char('q'),
            KeyCode::Char('j'),
            KeyCode::Up,
            KeyCode::PageDown,
        ] {
            assert!(is_confirmation_navigation_or_cancellation(&Event::Key(
                KeyEvent::new(code, KeyModifiers::NONE)
            )));
        }
        assert!(is_confirmation_navigation_or_cancellation(&Event::Key(
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
        )));
        for code in [KeyCode::Enter, KeyCode::Char('y'), KeyCode::Char('d')] {
            assert!(!is_confirmation_navigation_or_cancellation(&Event::Key(
                KeyEvent::new(code, KeyModifiers::NONE)
            )));
        }
    }

    #[test]
    fn scan_progress_keeps_only_the_latest_snapshot() {
        let progress = AtomicUsize::new(0);
        let mut visited = 0;
        report_scan_progress(&progress, &mut visited);
        assert_eq!(progress.load(Ordering::Relaxed), 1);
        for _ in 1..16_384 {
            report_scan_progress(&progress, &mut visited);
        }
        assert_eq!(progress.load(Ordering::Relaxed), 16_384);
        report_scan_progress(&progress, &mut visited);
        assert_eq!(progress.load(Ordering::Relaxed), 16_384);
    }

    #[test]
    fn operation_worker_reports_panics_as_unknown_outcomes() {
        let error = operation_worker::<()>(|| panic!("fixture panic")).unwrap_err();
        assert!(error.contains("outcome may be unknown"));
        assert_eq!(operation_worker(|| Ok(7)).unwrap(), 7);
    }

    #[test]
    fn bytecode_confirmation_displays_the_exact_file_and_requires_confirmation() {
        let mut app = app();
        let plan = crate::bytecode::BytecodePlan {
            project: "/project".into(),
            manifest: "/project/pyproject.toml".into(),
            cache: "/project/__pycache__".into(),
            source: "/project/example.py".into(),
            file: "/project/__pycache__/example.cpython-311.pyc".into(),
            python: "3.11",
            invalidation: "timestamp",
            logical_bytes: 42,
            preview_token: "token".into(),
            #[cfg(target_os = "linux")]
            git_evidence_id: None,
            warning: "fixture",
            scope: crate::bytecode::Scope {
                roots: vec!["/project".into()],
                exclusions: vec![],
                older_than_seconds: None,
                enabled: None,
            },
        };
        assert!(!bytecode_confirmation_fits(&plan, Rect::new(0, 0, 40, 8)));
        assert!(bytecode_confirmation_fits(&plan, Rect::new(0, 0, 110, 24)));
        let mut unchecked = plan.clone();
        unchecked.invalidation = "hash-unchecked";
        assert!(
            bytecode_confirmation_lines(&unchecked)
                .iter()
                .any(|line| line.contains("Unchecked hash"))
        );
        assert!(bytecode_confirmation_fits(
            &unchecked,
            Rect::new(0, 0, 110, 24)
        ));
        app.bytecode_plan = Some(plan.clone());
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("example.cpython-311.pyc"));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.bytecode_plan.is_none());
        app.bytecode_plan = Some(plan);
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::RemoveBytecode(_)
        ));
        assert!(app.bytecode_running);
    }

    #[test]
    fn artifact_screen_lists_the_selected_cache_and_previews_only_the_chosen_file() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("python");
        let cache = project.join("__pycache__");
        std::fs::create_dir_all(&cache).unwrap();
        let cache = cache.canonicalize().unwrap();
        std::fs::write(project.join("pyproject.toml"), "[project]").unwrap();
        let mut app = app();
        app.page = Start::Artifacts;
        app.scan = Some(Ok(crate::sweep::scan(&[project]).unwrap()));
        assert!(
            matches!(app.key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE)), Action::ListBytecode(path) if path == cache)
        );
        app.bytecode_listing_running = false;
        let first = cache.join("a.cpython-311.pyc");
        let second = cache.join("b.cpython-311.pyc");
        app.bytecode_listing = Some(BytecodeListing {
            cache,
            files: vec![first, second.clone()],
        });
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("a.cpython-311.pyc"));
        assert!(output.contains("b.cpython-311.pyc"));
        app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert!(
            matches!(app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)), Action::PreviewBytecode(path) if path == second)
        );
        assert!(app.bytecode_preparing);
    }

    #[test]
    fn bytecode_listing_marks_multiple_files_and_confirms_complete_batch() {
        let mut app = app();
        let first = PathBuf::from("/project/__pycache__/a.cpython-311.pyc");
        let second = PathBuf::from("/project/__pycache__/b.cpython-311.pyc");
        app.bytecode_listing = Some(BytecodeListing {
            cache: "/project/__pycache__".into(),
            files: vec![first.clone(), second.clone()],
        });
        app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(
            matches!(app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)), Action::PreviewBytecodeBatch(files) if files == vec![first.clone(), second.clone()])
        );
        let scope = crate::bytecode::Scope {
            roots: vec!["/project".into()],
            exclusions: vec![],
            older_than_seconds: None,
            enabled: None,
        };
        let file_plan = |file: PathBuf| crate::bytecode::BytecodePlan {
            project: "/project".into(),
            manifest: "/project/pyproject.toml".into(),
            cache: "/project/__pycache__".into(),
            source: "/project/a.py".into(),
            file,
            python: "3.11",
            invalidation: "timestamp",
            logical_bytes: 42,
            preview_token: "fixture".into(),
            #[cfg(target_os = "linux")]
            git_evidence_id: None,
            warning: "fixture",
            scope: scope.clone(),
        };
        let files = vec![file_plan(first), file_plan(second)];
        let plan = crate::bytecode::BytecodeBatchPlan {
            scope,
            files,
            preview_token: "fixture".into(),
            warning: "fixture",
            guards: vec![],
        };
        assert!(!bytecode_batch_confirmation_fits(
            &plan,
            Rect::new(0, 0, 40, 8)
        ));
        assert!(bytecode_batch_confirmation_fits(
            &plan,
            Rect::new(0, 0, 120, 24)
        ));
        let mut unchecked = plan.clone();
        unchecked.files[0].invalidation = "hash-unchecked";
        assert!(
            bytecode_batch_confirmation_lines(&unchecked)
                .iter()
                .any(|line| line.contains("Unchecked hash"))
        );
        assert!(bytecode_batch_confirmation_fits(
            &unchecked,
            Rect::new(0, 0, 120, 24)
        ));
        app.bytecode_preparing = false;
        app.bytecode_listing = None;
        app.bytecode_batch_plan = Some(plan);
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("a.cpython-311.pyc") && rendered.contains("b.cpython-311.pyc"));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::RemoveBytecodeBatch(_)
        ));
    }

    #[test]
    fn dashboard_starts_configured_scan_and_artifact_screen_can_rescan() {
        let mut app = app();
        app.page = Start::Dashboard;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE)),
            Action::StartArtifactScan { configured: true }
        ));
        assert!(app.page == Start::Artifacts && app.scan_running && !app.preview_mode);
        app.scan_running = false;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)),
            Action::StartArtifactScan { configured: false }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn settings_editor_validates_and_confirms_save_and_discard() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 1\n").unwrap();
        let document = crate::config::read_document(&path).unwrap();
        let mut app = app();
        app.page = Start::Settings;
        app.settings = Some(Ok(document));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE)),
            Action::None
        ));
        app.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(app.settings_prompt.is_none());
        assert!(app.message.contains("Invalid configuration"));
        app.key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        for character in " #é".chars() {
            app.key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(app.settings_prompt == Some(SettingsPrompt::Save));
        let editor = app.settings_editor.as_ref().unwrap();
        assert!(!settings_confirmation_fits(Rect::new(0, 0, 30, 5)));
        assert!(settings_confirmation_ready(
            &editor.snapshot,
            SettingsPrompt::Save,
            &[],
            &[],
            0,
            Rect::new(0, 0, 120, 24)
        ));
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("Confirm settings"));
        app.key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.settings_prompt == Some(SettingsPrompt::Discard));
        app.key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(
            matches!(app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)), Action::SaveSettings(_, text) if text == "version = 1 #é\n")
        );
        assert!(app.settings_saving);
        assert_eq!(std::fs::read_to_string(path).unwrap(), "version = 1\n");
    }

    #[test]
    fn settings_editor_can_create_the_default_and_edit_unicode_lines() {
        let dir = tempfile::tempdir().unwrap();
        let document = crate::config::read_document(&dir.path().join("missing.toml")).unwrap();
        let mut app = app();
        app.page = Start::Settings;
        app.settings = Some(Ok(document));
        app.key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(app.settings_prompt == Some(SettingsPrompt::Save));
        app.key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        let editor = app.settings_editor.as_mut().unwrap();
        editor.key(KeyCode::End);
        editor.key(KeyCode::Enter);
        editor.key(KeyCode::Char('é'));
        editor.key(KeyCode::Left);
        editor.key(KeyCode::Backspace);
        assert_eq!(editor.text(), "version = 1é\n");
        assert_eq!(editor.bytes, editor.text().len());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn settings_theme_is_reviewed_and_uses_legible_palettes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 1\n# keep\n").unwrap();
        let document = crate::config::read_document(&path).unwrap();
        assert_eq!(document_theme(&document), Some(crate::config::Theme::Dark));
        let mut app = app();
        app.page = Start::Settings;
        app.settings = Some(Ok(document));
        app.key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        let form = app.settings_form.as_mut().unwrap();
        form.selected = settings_rows(form)
            .iter()
            .position(|row| matches!(row, SettingsRow::Theme))
            .unwrap();
        app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert_eq!(app.theme, crate::config::Theme::Dark);
        app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        let pending = app.settings_pending_save.as_ref().unwrap();
        assert!(pending.text.contains("theme = \"light\""));
        assert!(pending.text.contains("# keep"));
        assert!(
            pending
                .changes
                .iter()
                .any(|line| line.contains("global defaults.theme")
                    && line.contains("dark")
                    && line.contains("light"))
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "version = 1\n# keep\n"
        );
        let reopened = dir.path().join("reopened.toml");
        std::fs::write(&reopened, &pending.text).unwrap();
        assert_eq!(
            document_theme(&crate::config::read_document(&reopened).unwrap()),
            Some(crate::config::Theme::Light)
        );

        let mut terminal = Terminal::new(TestBackend::new(20, 3)).unwrap();
        terminal
            .draw(|frame| {
                frame.render_widget(Paragraph::new("Warning").yellow(), frame.area());
                apply_theme(frame, crate::config::Theme::Light);
            })
            .unwrap();
        let light = terminal.backend().buffer().content[0].clone();
        assert_eq!(light.fg, Color::Rgb(110, 65, 0));
        assert_eq!(light.bg, Color::Rgb(248, 249, 251));
        terminal
            .draw(|frame| {
                frame.render_widget(Paragraph::new("Warning").yellow(), frame.area());
                apply_theme(frame, crate::config::Theme::Dark);
            })
            .unwrap();
        let dark = &terminal.backend().buffer().content[0];
        assert_eq!(dark.fg, Color::Rgb(255, 210, 100));
        assert_eq!(dark.bg, Color::Rgb(20, 24, 30));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn structured_settings_add_profile_preserves_document_and_reviews_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let before = "version = 1\nworkspace_roots = ['/fixture/work'] # keep\n\n[profiles.existing]\n# keep profile\n";
        std::fs::write(&path, before).unwrap();
        let mut app = app();
        app.page = Start::Settings;
        app.settings = Some(Ok(crate::config::read_document(&path).unwrap()));
        app.key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        for character in "bad name".chars() {
            app.key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.message.contains("profile names"));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        for character in "existing".chars() {
            app.key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.message.contains("already exists"));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
        for character in "work".chars() {
            app.key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(
            app.settings_form.as_ref().unwrap().profile.as_deref(),
            Some("work")
        );
        app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        for character in "/fixture/work".chars() {
            app.key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        let pending = app.settings_pending_save.as_ref().unwrap();
        assert!(pending.text.starts_with(before));
        assert!(
            pending
                .text
                .contains("[profiles.work]\nworkspace_roots = [\"/fixture/work\"]")
        );
        assert!(
            pending
                .changes
                .iter()
                .any(|line| line.contains("profile work.workspace_roots")
                    && line.contains("profile absent")
                    && line.contains("/fixture/work"))
        );
        assert!(crate::config::validate_document(&pending.text).is_ok());
        assert_eq!(std::fs::read_to_string(path).unwrap(), before);
    }

    #[test]
    fn structured_settings_can_save_an_empty_new_profile() {
        let dir = tempfile::tempdir().unwrap();
        let document = crate::config::read_document(&dir.path().join("config.toml")).unwrap();
        let mut form = SettingsForm::new(document).unwrap();
        let input = SettingsInput {
            target: form.target(SettingsField::WorkspaceRoots),
            new_profile: true,
            index: None,
            value: "work".chars().collect(),
            cursor: 4,
        };
        settings_input_apply(&mut form, &input).unwrap();
        assert!(form.has_changes().unwrap());
        let text = form.save_text().unwrap();
        let settings: crate::config::Settings = toml::from_str(&text).unwrap();
        assert!(settings.profiles["work"].workspace_roots.is_empty());
        assert!(!settings.profiles["work"].scheduled_bytecode_cleanup);
    }

    #[test]
    fn settings_form_edits_schedule_frequency_by_scope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "version = 1\n# keep\n[profiles.work]\nworkspace_roots = []\n",
        )
        .unwrap();
        let mut form = SettingsForm::new(crate::config::read_document(&path).unwrap()).unwrap();
        settings_form_toggle(&mut form, SettingsRow::ScheduleFrequency);
        assert_eq!(
            form.settings.schedule_frequency,
            Some(crate::config::ScheduleFrequency::Daily)
        );
        form.move_profile(true);
        settings_form_toggle(&mut form, SettingsRow::ScheduleFrequency);
        settings_form_toggle(&mut form, SettingsRow::ScheduleFrequency);
        assert_eq!(
            form.settings.profiles["work"].schedule_frequency,
            Some(crate::config::ScheduleFrequency::Weekly)
        );
        let text = form.save_text().unwrap();
        assert!(text.contains("# keep"));
        let parsed: crate::config::Settings = toml::from_str(&text).unwrap();
        assert_eq!(
            crate::config::schedule_frequency(&parsed, None).unwrap(),
            crate::config::ScheduleFrequency::Daily
        );
        assert_eq!(
            crate::config::schedule_frequency(&parsed, Some("work")).unwrap(),
            crate::config::ScheduleFrequency::Weekly
        );
        let changes = settings_change_lines(&form.snapshot, &text);
        assert!(
            changes
                .iter()
                .any(|line| line.contains("global defaults.schedule_frequency"))
        );
        assert!(
            changes
                .iter()
                .any(|line| line.contains("profile work.schedule_frequency"))
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), form.snapshot.text);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scheduled_trash_retention_setting_is_available_and_reviews_its_impact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 1\nscheduled_trash_retention = true\n").unwrap();
        let mut form = SettingsForm::new(crate::config::read_document(&path).unwrap()).unwrap();
        let row = SettingsRow::ScheduledTrashRetention;

        assert!(
            settings_rows(&form)
                .iter()
                .any(|candidate| matches!(candidate, SettingsRow::ScheduledTrashRetention))
        );
        assert!(settings_target_for_row(&form, row).is_some());
        assert!(settings_form_content(&form).contains("opt-in: enabled"));
        settings_form_toggle(&mut form, row);
        assert!(!form.settings.scheduled_trash_retention);
        assert!(form.has_changes().unwrap());
        assert!(
            form.cleanup_impacts()
                .unwrap()
                .iter()
                .any(|impact| impact.contains("fail closed"))
        );
        assert!(
            form.save_text()
                .unwrap()
                .contains("scheduled_trash_retention = false")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn automation_trash_retention_keys_only_start_previews() {
        let mut app = app();
        app.page = Start::Automation;
        if let Some(data_dir) = dirs::data_local_dir() {
            assert!(matches!(
                app.key(KeyEvent::new(KeyCode::Char('T'), KeyModifiers::NONE)),
                Action::PreviewTrashRetentionInstall(location, age)
                    if location == data_dir.join("Trash")
                        && age == Duration::from_secs(TRASH_RETENTION_DEFAULT_AGE_SECONDS)
            ));
            assert!(app.trash_retention_preparing);
            assert!(matches!(
                app.key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)),
                Action::None
            ));
        } else {
            assert!(matches!(
                app.key(KeyEvent::new(KeyCode::Char('T'), KeyModifiers::NONE)),
                Action::None
            ));
        }
        app.trash_retention_preparing = false;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE)),
            Action::PreviewTrashRetentionEnable
        ));
        app.trash_retention_preparing = false;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('D'), KeyModifiers::NONE)),
            Action::PreviewTrashRetentionDisable
        ));
        app.trash_retention_preparing = false;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('X'), KeyModifiers::NONE)),
            Action::PreviewTrashRetentionRemove
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trash_retention_preview_and_confirmation_show_full_reviewed_plan() {
        let mut app = app();
        app.page = Start::Automation;
        let plan = crate::schedule::trash_retention::test_schedule_preview();
        let area = Rect::new(0, 0, 52, 9);

        app.schedule_read_only = true;
        app.trash_retention_plan = Some(TrashRetentionReviewPlan::Install(plan.clone()));
        app.update_schedule_confirmation(area);
        assert!(!schedule_confirmation_can_confirm(&app, area, area));
        let mut preview = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
        let mut preview_text = String::new();
        loop {
            preview.draw(|frame| draw(frame, &app)).unwrap();
            preview_text.push_str(&format!("{:?}", preview.backend().buffer()));
            let visible = schedule_confirmation_visible_rows(area);
            let length = app.schedule_confirmation_content.as_ref().unwrap().len();
            if app.schedule_preview_scroll as usize + visible >= length {
                break;
            }
            app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
            app.update_schedule_confirmation(area);
        }
        assert!(preview_text.contains("Preview only"));
        assert!(preview_text.contains("old-file"));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.trash_retention_plan.is_none());
        assert!(!app.schedule_read_only);

        app.trash_retention_plan = Some(TrashRetentionReviewPlan::Install(plan));
        review_schedule_confirmation_to_end(&mut app, area);
        assert!(schedule_confirmation_can_confirm(&app, area, area));
        let review =
            trash_retention_review_lines(app.trash_retention_plan.as_ref().unwrap()).join("\n");
        for detail in [
            "Trash location:",
            "Age threshold:",
            "eligible;",
            "old-file",
            "descendants=",
            "future matching Trash items",
            "persistent daily timer can catch up",
            "[Service]",
            "[Timer]",
            "Filesystem warning:",
        ] {
            assert!(review.contains(detail), "missing {detail} in {review}");
        }
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::InstallTrashRetention(_)
        ));
        assert!(app.trash_retention_running);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn trash_retention_lifecycle_error_message_does_not_echo_paths() {
        let message = trash_retention_change_message(
            "install",
            Err("/home/alice/.local/share/Trash/private-name was replaced".into()),
        );
        assert!(!message.contains("/home/alice"));
        assert!(!message.contains("private-name"));
        assert!(message.contains("operation history"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn structured_settings_edit_preserves_unmodified_profiles_and_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let global = dir.path().join("global-workspace");
        let profile = dir.path().join("profile-workspace");
        let replacement = dir.path().join("replacement-workspace");
        let global_value = toml_string(&global.to_string_lossy());
        let profile_value = toml_string(&profile.to_string_lossy());
        let text = format!(
            "version = 1\nworkspace_roots = [{global_value}] # keep global root comment\nexclusions = [\"glob:target/**\"] # keep exclusions\nartifact_retention = \"30d\" # keep retention\n\n[profiles.alpha]\nworkspace_roots = [{profile_value}] # keep profile root\nscheduled_bytecode_cleanup = false\n\n# keep beta marker\n[profiles.beta]\nworkspace_roots = []\n"
        );
        std::fs::write(&path, &text).unwrap();
        let document = crate::config::read_document(&path).unwrap();
        let mut app = app();
        app.page = Start::Settings;
        app.settings = Some(Ok(document));
        app.key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        assert!(app.settings_form.is_some());

        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("Workspace root 1"));

        app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        for _ in 0..global.to_string_lossy().chars().count() {
            app.key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        }
        for character in replacement.to_string_lossy().chars() {
            app.key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert_eq!(app.settings_prompt, Some(SettingsPrompt::Save));
        let pending = app.settings_pending_save.as_ref().unwrap();
        let replacement_value = toml_string(&replacement.to_string_lossy());
        assert!(pending.text.contains(&format!(
            "workspace_roots = [{replacement_value}] # keep global root comment"
        )));
        assert!(pending.text.contains("# keep exclusions"));
        assert!(
            pending
                .text
                .contains("artifact_retention = \"30d\" # keep retention")
        );
        assert!(pending.text.contains(&format!(
            "workspace_roots = [{profile_value}] # keep profile root"
        )));
        assert!(pending.text.contains("# keep beta marker"));
        assert!(crate::config::validate_document(&pending.text).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn settings_confirmation_displays_bidi_controls_in_changed_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let before = "version = 1\nworkspace_roots = [\"/old\u{200e}\"]\n";
        std::fs::write(&path, before).unwrap();
        let snapshot = crate::config::read_document(&path).unwrap();
        let after = "version = 1\nworkspace_roots = [\"/new\u{061c}\u{200e}\u{200f}\"]\n";
        let changes = settings_change_lines(&snapshot, after);
        let review =
            settings_confirmation_lines(&snapshot, SettingsPrompt::Save, &[], &changes).join("\n");
        assert!(
            review.contains("/new\\u{61C}\\u{200E}\\u{200F}"),
            "{review}"
        );
        assert!(!review.contains('\u{061c}'));
        assert!(!review.contains('\u{200e}'));
        assert!(!review.contains('\u{200f}'));
        let editor = ConfigEditor::new(snapshot);
        assert_eq!(editor.text(), before);
        let mut ui = app();
        ui.page = Start::Settings;
        ui.settings_editor = Some(editor);
        let mut terminal = Terminal::new(TestBackend::new(100, 20)).unwrap();
        terminal.draw(|frame| draw(frame, &ui)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("may denote a control"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn settings_save_confirmation_lists_every_changed_scope_field_and_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let before = "version = 1\nworkspace_roots = [\"/global-old\"]\nexclusions = [\"/global-exclude\"]\nartifact_retention = \"30d\"\nenabled_ecosystems = [\"python\"]\nscheduled_bytecode_cleanup = false\n\n[profiles.alpha]\nworkspace_roots = [\"/alpha-old\"]\nexclusions = [\"/alpha-exclude\"]\nartifact_retention = \"14d\"\nenabled_ecosystems = [\"python\"]\nscheduled_bytecode_cleanup = false\n";
        let after = before
            .replace("/global-old", "/global-new")
            .replace("/global-exclude", "/global-exclude-new")
            .replace(
                "artifact_retention = \"30d\"",
                "artifact_retention = \"90d\"",
            )
            .replace(
                "enabled_ecosystems = [\"python\"]",
                "enabled_ecosystems = [\"go\"]",
            )
            .replace(
                "scheduled_bytecode_cleanup = false",
                "scheduled_bytecode_cleanup = true",
            )
            .replace("/alpha-old", "/alpha-new")
            .replace("/alpha-exclude", "/alpha-exclude-new")
            .replace(
                "artifact_retention = \"14d\"",
                "artifact_retention = \"7d\"",
            )
            .replace(
                "enabled_ecosystems = [\"go\"]",
                "enabled_ecosystems = [\"cargo\"]",
            );
        std::fs::write(&path, before).unwrap();
        let snapshot = crate::config::read_document(&path).unwrap();
        assert!(crate::config::validate_document(&after).is_ok());
        let changes = settings_change_lines(&snapshot, &after);
        for field in [
            "workspace_roots",
            "exclusions",
            "artifact_retention",
            "enabled_ecosystems",
            "scheduled_bytecode_cleanup",
        ] {
            assert!(changes.iter().any(|line| line.contains(field)), "{field}");
        }
        assert!(changes.iter().any(|line| {
            line.contains("global defaults.workspace_roots")
                && line.contains("/global-old")
                && line.contains("/global-new")
        }));
        assert!(changes.iter().any(|line| {
            line.contains("profile alpha.exclusions")
                && line.contains("/alpha-exclude")
                && line.contains("/alpha-exclude-new")
        }));
        let mut app = app();
        app.page = Start::Settings;
        app.settings_pending_save = Some(SettingsPendingSave {
            snapshot: snapshot.clone(),
            text: after,
            cleanup_impacts: vec![],
            changes: changes.clone(),
        });
        app.settings_prompt = Some(SettingsPrompt::Save);
        let area = Rect::new(0, 0, 120, 12);
        assert!(!settings_confirmation_ready(
            &snapshot,
            SettingsPrompt::Save,
            &[],
            &changes,
            0,
            area,
        ));
        let max_scroll = settings_confirmation_scroll_limit(
            &snapshot,
            SettingsPrompt::Save,
            &[],
            &changes,
            area,
        );
        let mut terminal = Terminal::new(TestBackend::new(120, 12)).unwrap();
        let mut reviewed = String::new();
        for _ in 0..=max_scroll {
            terminal.draw(|frame| draw(frame, &app)).unwrap();
            reviewed.push_str(&format!("{:?}", terminal.backend().buffer()));
            app.settings_confirmation_scroll = app.settings_confirmation_scroll.saturating_add(1);
        }
        assert!(reviewed.contains("/global-old") && reviewed.contains("/global-new"));
        assert!(reviewed.contains("/alpha-exclude") && reviewed.contains("/alpha-exclude-new"));
        assert!(reviewed.contains("scheduled_bytecode_cleanup"));
        assert!(settings_confirmation_ready(
            &snapshot,
            SettingsPrompt::Save,
            &[],
            &changes,
            app.settings_confirmation_scroll,
            area,
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn settings_form_ctrl_d_does_not_remove_a_path_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "version = 1\nworkspace_roots = [\"/fixture/root\"]\n",
        )
        .unwrap();
        let document = crate::config::read_document(&path).unwrap();
        let mut app = app();
        app.page = Start::Settings;
        app.settings = Some(Ok(document));
        app.key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL));
        assert_eq!(
            settings_roots(&app.settings_form.as_ref().unwrap().settings, None).len(),
            1
        );
        app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        assert!(settings_roots(&app.settings_form.as_ref().unwrap().settings, None).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn settings_save_confirmation_refuses_when_wrapped_content_exceeds_scroll_range() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "version = 1\n").unwrap();
        let snapshot = crate::config::read_document(&path).unwrap();
        let changes = vec!["x".repeat(1_600_000)];
        let area = Rect::new(0, 0, 30, 10);
        assert_eq!(
            settings_confirmation_scroll_limit(
                &snapshot,
                SettingsPrompt::Save,
                &[],
                &changes,
                area
            ),
            u16::MAX
        );
        assert!(!settings_confirmation_ready(
            &snapshot,
            SettingsPrompt::Save,
            &[],
            &changes,
            u16::MAX,
            area,
        ));
    }

    #[test]
    fn settings_confirmation_resize_resets_review_scroll() {
        let mut app = app();
        app.settings_prompt = Some(SettingsPrompt::Save);
        app.update_settings_confirmation_area(Rect::new(0, 0, 30, 6));
        app.settings_confirmation_scroll = u16::MAX;
        app.update_settings_confirmation_area(Rect::new(0, 0, 120, 24));
        assert_eq!(app.settings_confirmation_scroll, 0);
        assert_eq!(app.settings_confirmation_area, Rect::new(0, 0, 120, 24));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn structured_settings_cleanup_confirmation_lists_and_reviews_each_profile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let root = toml_string(&dir.path().join("workspace").to_string_lossy());
        let text = format!(
            "version = 1\nartifact_retention = \"14d\"\nenabled_ecosystems = [\"python\"]\n\n[profiles.alpha]\nworkspace_roots = [{root}]\nscheduled_bytecode_cleanup = false # alpha cleanup\n\n[profiles.beta]\nworkspace_roots = [{root}]\nscheduled_bytecode_cleanup = false # beta cleanup\n"
        );
        std::fs::write(&path, &text).unwrap();
        let document = crate::config::read_document(&path).unwrap();
        let mut app = app();
        app.page = Start::Settings;
        app.settings = Some(Ok(document));
        app.key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));

        for profile in ["alpha", "beta"] {
            if app.settings_form.as_ref().unwrap().profile.as_deref() != Some(profile) {
                while app.settings_form.as_ref().unwrap().selected > 0 {
                    app.key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
                }
                app.key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
            }
            let cleanup_row = settings_rows(app.settings_form.as_ref().unwrap())
                .iter()
                .position(|row| matches!(row, SettingsRow::ScheduledCleanup))
                .unwrap();
            for _ in app.settings_form.as_ref().unwrap().selected..cleanup_row {
                app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
            }
            app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
            assert!(
                settings_cleanup_value(
                    &app.settings_form.as_ref().unwrap().settings,
                    Some(profile)
                ),
                "cleanup did not toggle for {profile}"
            );
        }
        app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(app.settings_pending_save.is_some(), "{}", app.message);
        let (snapshot, cleanup_impacts, pending_text, pending_changes) = {
            let pending = app.settings_pending_save.as_ref().unwrap();
            (
                pending.snapshot.clone(),
                pending.cleanup_impacts.clone(),
                pending.text.clone(),
                pending.changes.clone(),
            )
        };
        assert_eq!(cleanup_impacts.len(), 2);
        assert!(cleanup_impacts[0].contains("alpha"));
        assert!(cleanup_impacts[1].contains("beta"));
        assert!(pending_text.contains("scheduled_bytecode_cleanup = true # alpha cleanup"));
        assert!(pending_text.contains("scheduled_bytecode_cleanup = true # beta cleanup"));
        assert!(pending_text.contains("[profiles.alpha]"));
        assert!(pending_text.contains("[profiles.beta]"));

        let terminal_area = Rect::new(0, 0, 100, 10);
        let mut terminal = Terminal::new(TestBackend::new(100, 10)).unwrap();
        assert!(!settings_confirmation_ready(
            &snapshot,
            SettingsPrompt::Save,
            &cleanup_impacts,
            &pending_changes,
            0,
            terminal_area,
        ));
        let max_scroll = settings_confirmation_scroll_limit(
            &snapshot,
            SettingsPrompt::Save,
            &cleanup_impacts,
            &pending_changes,
            terminal_area,
        );
        assert!(max_scroll > 0);
        let mut reviewed = String::new();
        for _ in 0..=max_scroll {
            terminal.draw(|frame| draw(frame, &app)).unwrap();
            reviewed.push_str(&format!("{:?}", terminal.backend().buffer()));
            app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        }
        assert!(reviewed.contains("alpha") && reviewed.contains("beta"));
        assert!(settings_confirmation_ready(
            &snapshot,
            SettingsPrompt::Save,
            &cleanup_impacts,
            &pending_changes,
            app.settings_confirmation_scroll,
            terminal_area,
        ));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::SaveSettings(_, _)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn structured_settings_refuses_multiline_field_rewrite_without_mutating_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let root = toml_string(&dir.path().join("workspace").to_string_lossy());
        let text = format!("version = 1\nworkspace_roots = [\n  {root},\n]\n");
        std::fs::write(&path, &text).unwrap();
        let document = crate::config::read_document(&path).unwrap();
        let mut app = app();
        app.page = Start::Settings;
        app.settings = Some(Ok(document));
        app.key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(app.settings_prompt.is_none());
        assert!(app.settings_pending_save.is_none());
        assert!(app.message.contains("use the TOML editor"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), text);

        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("TOML editor"));
    }

    #[test]
    fn toml_editor_cleanup_changes_are_reported_for_each_scope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = "version = 1\nscheduled_bytecode_cleanup = false\n\n[profiles.alpha]\nscheduled_bytecode_cleanup = false\n\n[profiles.beta]\nscheduled_bytecode_cleanup = true\n";
        std::fs::write(&path, original).unwrap();
        let document = crate::config::read_document(&path).unwrap();
        let changed = original
            .replace(
                "scheduled_bytecode_cleanup = false\n",
                "scheduled_bytecode_cleanup = true\n",
            )
            .replace(
                "[profiles.beta]\nscheduled_bytecode_cleanup = true",
                "[profiles.beta]\nscheduled_bytecode_cleanup = false",
            );
        let impacts = settings_cleanup_impacts_between(&document, &changed).unwrap();
        assert_eq!(impacts.len(), 3);
        assert!(impacts[0].contains("global defaults") && impacts[0].contains("enabled"));
        assert!(impacts[1].contains("profile alpha") && impacts[1].contains("enabled"));
        assert!(impacts[2].contains("profile beta") && impacts[2].contains("disabled"));
    }

    #[test]
    fn settings_page_loads_when_navigating_from_dashboard() {
        let mut app = app();
        app.page = Start::Dashboard;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT)),
            Action::LoadSettings
        ));
        assert!(app.page == Start::Settings && app.settings_loading);
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)),
            Action::None
        ));
    }

    #[test]
    fn terminal_session_restores_after_unwind_in_pty() {
        if std::env::var_os("UPKIT_TEST_TERMINAL_UNWIND").is_none() {
            return;
        }
        let result = std::panic::catch_unwind(|| {
            let _session = TerminalSession::start().unwrap();
            panic!("terminal restoration fixture");
        });
        assert!(result.is_err());
    }

    #[test]
    fn terminal_session_restores_after_initialization_error_in_pty() {
        if std::env::var_os("UPKIT_TEST_TERMINAL_UNWIND").is_none() {
            return;
        }
        let result = TerminalSession::start_with(|| Err(std::io::Error::other("fixture failure")));
        assert!(result.is_err());
    }

    #[test]
    fn container_inventory_renders_and_refreshes() {
        let mut app = app();
        app.page = Start::Containers;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            Action::StartContainers
        ));
        assert!(app.containers_running);
        app.containers_running = false;
        app.containers = Some(vec![crate::containers::EngineStatus {
            engine: "docker",
            state: "available",
            detail: None,
            resources: vec![crate::containers::ResourceList {
                kind: "build cache (selected Buildx builder; snapshot)",
                items: vec![serde_json::json!({"ID": "cache-fixture", "Reclaimable": true})],
                error: None,
            }],
            usage: vec![serde_json::json!({"Type": "Images", "Total": "2", "Size": "12MB"})],
        }]);
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Images"));
        assert!(output.contains("12MB"));
        assert!(output.contains("cache-fixture"));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)),
            Action::RefreshSchedule
        ));
        assert!(app.page == Start::Automation);
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)),
            Action::RefreshHistory
        ));
        assert!(app.page == Start::Reports);
    }

    #[test]
    fn container_inventory_escapes_bidi_controls_without_changing_json() {
        let bidi = '\u{202e}';
        let mut app = app();
        app.page = Start::Containers;
        let mut report = container_reports();
        report[0].usage = vec![serde_json::json!({"Type": format!("Images{bidi}"), "Total": "1"})];
        report[0]
            .resources
            .iter_mut()
            .find(|list| list.kind == "containers")
            .unwrap()
            .items[0]["Names"] = format!("worker{bidi}build").into();
        report[0]
            .resources
            .iter_mut()
            .find(|list| list.kind == "dangling images")
            .unwrap()
            .items[0]["Size"] = format!("23MB{bidi}").into();
        report[0]
            .resources
            .iter_mut()
            .find(|list| list.kind == "unattached custom networks (snapshot)")
            .unwrap()
            .items[0]["Name"] = format!("temporary{bidi}net").into();
        report[0]
            .resources
            .iter_mut()
            .find(|list| list.kind == crate::containers::BUILD_CACHE)
            .unwrap()
            .items[0]["Type"] = format!("regular{bidi}cache").into();
        report[0].resources.push(crate::containers::ResourceList {
            kind: "unattached volumes (snapshot)",
            items: vec![
                serde_json::json!({"Name": format!("data{bidi}volume"), "Driver": "local"}),
            ],
            error: None,
        });
        app.containers = Some(report);

        let report = app.containers.as_ref().unwrap();
        let content = container_screen_content(&app, report);
        assert!(!content.contains(bidi));
        for value in ["worker", "temporary", "regular", "23MB", "data"] {
            assert!(
                content.contains(&format!("{value}\\u{{202E}}")),
                "{content}"
            );
        }
        let json = serde_json::to_value(report).unwrap();
        let volumes = json[0]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|list| list["kind"] == "unattached volumes (snapshot)")
            .unwrap();
        assert_eq!(volumes["items"][0]["Name"], format!("data{bidi}volume"));

        let mut terminal = Terminal::new(TestBackend::new(140, 50)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(!rendered.contains(bidi));
        assert!(rendered.contains("data\\u{202E}volume"), "{rendered}");
    }

    #[test]
    fn container_filter_maps_visible_rows_to_their_exact_preview_actions() {
        let cases = [
            ("WORKER-BUILD-1", 0, "container"),
            ("temporary-net", 1, "network"),
            ("builder-one", 2, "build-cache"),
        ];
        for (query, selected, kind) in cases {
            let mut app = app();
            app.page = Start::Containers;
            app.containers = Some(container_reports());
            let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
            app.key(key(KeyCode::Char('/')));
            for character in query.chars() {
                app.key(key(KeyCode::Char(character)));
            }
            app.key(key(KeyCode::Enter));
            assert_eq!(app.container_filter, query);
            assert_eq!(app.container_selected, selected);

            let report = app.containers.as_ref().unwrap();
            let list = container_screen_content(&app, report);
            let selectable = list.split("Full engine inventory").next().unwrap();
            assert!(!selectable.contains("hidden-running"));
            match kind {
                "container" => assert!(selectable.contains("worker-build-1")),
                "network" => assert!(selectable.contains("temporary-net")),
                "build-cache" => assert!(selectable.contains("builder-one")),
                _ => unreachable!(),
            }
            let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();
            terminal.draw(|frame| draw(frame, &app)).unwrap();
            assert!(format!("{:?}", terminal.backend().buffer()).contains("eligible resources"));

            let action = app.key(key(KeyCode::Char('d')));
            match (kind, action) {
                ("container", Action::PreviewContainer(engine, id)) => {
                    assert_eq!(engine, "docker");
                    assert_eq!(id, "a".repeat(64));
                }
                ("network", Action::PreviewNetwork(engine, id)) => {
                    assert_eq!(engine, "docker");
                    assert_eq!(id, "d".repeat(64));
                }
                ("build-cache", Action::PreviewBuildCache(builder, id)) => {
                    assert_eq!(builder, "builder-one");
                    assert_eq!(id, "e".repeat(25));
                }
                (kind, _) => panic!("unexpected preview action for {kind}"),
            }
        }

        let mut app = app();
        app.page = Start::Containers;
        app.containers = Some(container_reports());
        app.container_filter = "no-such-resource".into();
        app.normalize_container_selection();
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(!app.container_preparing);
        assert!(app.message.contains("visible resource"));
    }

    #[test]
    fn container_filter_and_refresh_do_not_retarget_an_open_removal_preview() {
        let mut app = app();
        app.page = Start::Containers;
        app.containers = Some(container_reports());
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        for code in [
            KeyCode::Char('/'),
            KeyCode::Char('w'),
            KeyCode::Char('o'),
            KeyCode::Char('r'),
            KeyCode::Char('k'),
            KeyCode::Char('e'),
            KeyCode::Char('r'),
            KeyCode::Enter,
        ] {
            app.key(key(code));
        }
        assert_eq!(app.container_filter, "worker");
        assert_eq!(app.container_selected, 0);
        app.key(key(KeyCode::Char('/')));
        app.key(key(KeyCode::Char('x')));
        app.key(key(KeyCode::Esc));
        assert_eq!(app.container_filter, "worker");
        assert!(app.container_search.is_none());

        assert!(matches!(
            app.key(key(KeyCode::Char('d'))),
            Action::PreviewContainer(engine, id)
                if engine == "docker" && id == "a".repeat(64)
        ));
        app.container_preparing = false;
        app.container_plan = Some(crate::containers::test_removal_plan());

        let mut refreshed = container_reports();
        refreshed[0].resources[0].items[0]["Names"] = "other-container".into();
        refreshed[0].resources[0].items[1]["State"] = "exited".into();
        refreshed[0].resources[0].items[1]["Names"] = "worker-after-refresh".into();
        app.containers = Some(refreshed);
        app.normalize_container_selection();
        assert_eq!(app.container_selected, 1);
        assert!(matches!(app.key(key(KeyCode::Char('/'))), Action::None));
        assert_eq!(app.container_filter, "worker");

        let lines = container_confirmation_lines(app.container_plan.as_ref().unwrap());
        assert!(
            lines
                .iter()
                .any(|line| line == &format!("ID: {}", "a".repeat(64)))
        );
        assert!(container_confirmation_fits(
            app.container_plan.as_ref().unwrap(),
            Rect::new(0, 0, 120, 24)
        ));
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("worker-after-refresh"));
        assert!(output.contains("a".repeat(64).as_str()));
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::RemoveContainer(plan) if plan.container_id == "a".repeat(64)
        ));
    }

    #[test]
    fn build_cache_selection_and_confirmation_require_visible_plan() {
        let mut app = app();
        app.page = Start::Containers;
        let id = "a".repeat(25);
        app.containers = Some(vec![crate::containers::EngineStatus {
            engine: "docker",
            state: "available",
            detail: None,
            usage: vec![],
            resources: vec![crate::containers::ResourceList {
                kind: crate::containers::BUILD_CACHE,
                items: vec![
                    serde_json::json!({"Builder":"fixture", "ID":id, "Reclaimable":true, "Mutable":false, "Shared":false}),
                ],
                error: None,
            }],
        }]);
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let report = app.containers.as_ref().unwrap();
        let selection_line = container_selection_line(report, "", 0);
        let content = container_screen_content(&app, report);
        let selected_line = content.lines().nth(selection_line).unwrap();
        assert!(selected_line.contains(&id));
        assert!(selected_line.starts_with('›'));
        assert!(
            matches!(app.key(key(KeyCode::Char('d'))), Action::PreviewBuildCache(builder, selected) if builder == "fixture" && selected == id)
        );
        app.build_cache_preparing = false;
        app.build_cache_plan = Some(crate::containers::test_build_cache_removal_plan());
        let plan = app.build_cache_plan.as_ref().unwrap();
        assert!(!build_cache_confirmation_fits(
            plan,
            false,
            Rect::new(0, 0, 50, 24)
        ));
        assert!(build_cache_confirmation_fits(
            plan,
            false,
            Rect::new(0, 0, 110, 24)
        ));
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("Confirm build cache removal"));
        assert!(text.contains("garbage collection"));
        app.build_cache_read_only = true;
        assert!(matches!(app.key(key(KeyCode::Char('y'))), Action::None));
        assert!(app.build_cache_plan.is_some());
        app.build_cache_read_only = false;
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::RemoveBuildCache(_)
        ));
        assert!(app.build_cache_removing);
    }

    #[test]
    fn go_test_preview_is_read_only_but_cache_preview_can_confirm() {
        let mut app = app();
        app.page = Start::Cache;
        app.cache = Some(crate::cache::CacheReport {
            entries: vec![crate::cache::CacheEntry {
                name: "Go build",
                path: PathBuf::from("/tmp/example-cache"),
                ownership: "user",
                directory_owner_status: "current_user",
                classification: "shared",
                consequence: "rebuild",
                status: "available",
                logical_bytes: None,
                allocated_bytes: None,
                size_complete: false,
                activity_status: "unavailable",
                warnings: vec![],
                go_test_cache: None,
            }],
            warnings: vec![],
            cancelled: false,
        });
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(!cache_content(&app).contains("Directory owner (snapshot)"));
        app.key(key(KeyCode::Char('w')));
        let mut inventory = Terminal::new(TestBackend::new(110, 24)).unwrap();
        inventory.draw(|frame| draw(frame, &app)).unwrap();
        assert!(
            format!("{:?}", inventory.backend().buffer())
                .contains("Directory owner (snapshot): current_user")
        );
        assert!(
            matches!(app.key(key(KeyCode::Char('e'))), Action::PreviewGoTest(path) if path == std::path::Path::new("/tmp/example-cache"))
        );
        assert!(app.go_test_preparing);
        assert!(!app.go_test_read_only);
        app.go_test_preparing = false;
        let plan = crate::cache::GoTestExpirationPlan {
            cache_path: "/tmp/example-cache".into(),
            marker_path: "/tmp/example-cache/testexpire.txt".into(),
            current_expiration_unix_nanos: None,
            preview_token: "fixture".into(),
            warning: "fixture",
        };
        assert!(!go_test_confirmation_fits(
            &plan,
            false,
            Rect::new(0, 0, 40, 8)
        ));
        assert!(go_test_confirmation_fits(
            &plan,
            false,
            Rect::new(0, 0, 110, 24)
        ));
        assert!(go_test_confirmation_fits(
            &plan,
            true,
            Rect::new(0, 0, 110, 24)
        ));
        app.go_test_plan = Some(plan.clone());
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("Confirm Go test expiration"));
        assert!(rendered.contains("does not free disk space"));
        assert!(matches!(app.key(key(KeyCode::Enter)), Action::None));
        assert!(matches!(app.key(key(KeyCode::Esc)), Action::None));
        assert!(app.go_test_plan.is_none());

        app.go_test_plan = Some(plan.clone());
        app.go_test_read_only = true;
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("Go test cache preview"));
        assert!(rendered.contains("Preview only; Esc/n closes."));
        assert!(!rendered.contains("Press y to expire these results"));
        assert!(matches!(app.key(key(KeyCode::Char('y'))), Action::None));
        assert!(app.go_test_plan.is_some());
        assert!(!app.go_test_running);
        assert!(matches!(app.key(key(KeyCode::Esc)), Action::None));
        assert!(app.go_test_plan.is_none());
        assert!(!app.go_test_read_only);

        assert!(matches!(
            app.key(key(KeyCode::Char('e'))),
            Action::PreviewGoTest(_)
        ));
        assert!(!app.go_test_read_only);
        app.go_test_preparing = false;
        app.go_test_plan = Some(plan);
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::ExpireGoTest(_)
        ));
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
    }

    #[test]
    fn network_removal_requires_selection_and_visible_confirmation() {
        let mut app = app();
        app.page = Start::Containers;
        let id = "b".repeat(64);
        app.containers = Some(vec![crate::containers::EngineStatus {
            engine: "docker",
            state: "available",
            detail: None,
            usage: vec![],
            resources: vec![crate::containers::ResourceList {
                kind: "unattached custom networks (snapshot)",
                error: None,
                items: vec![serde_json::json!({"ID": id})],
            }],
        }]);
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(
            matches!(app.key(key(KeyCode::Char('d'))), Action::PreviewNetwork(engine, selected) if engine == "docker" && selected == id)
        );
        app.network_preparing = false;
        app.network_plan = Some(crate::containers::test_network_removal_plan());
        let plan = app.network_plan.as_ref().unwrap();
        assert!(!network_confirmation_fits(plan, Rect::new(0, 0, 50, 24)));
        assert!(network_confirmation_fits(plan, Rect::new(0, 0, 110, 24)));
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("Confirm network removal"));
        assert!(matches!(app.key(key(KeyCode::Enter)), Action::None));
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::RemoveNetwork(_)
        ));
        assert!(app.network_removing);
    }

    #[test]
    fn dangling_images_are_read_only_and_not_selectable_for_removal() {
        let mut app = app();
        app.page = Start::Containers;
        let id = "a".repeat(64);
        app.containers = Some(vec![crate::containers::EngineStatus {
            engine: "docker",
            state: "available",
            detail: None,
            usage: vec![],
            resources: vec![crate::containers::ResourceList {
                kind: "dangling images",
                error: None,
                items: vec![serde_json::json!({"ID": format!("sha256:{id}")})],
            }],
        }]);
        let report = app.containers.as_ref().unwrap();
        let content = container_screen_content(&app, report);
        assert!(content.contains("Dangling images (read-only; removal unsupported):"));
        assert!(content.contains(&id[..12]));
        assert!(container_resources(report).is_empty());
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(matches!(app.key(key(KeyCode::Char('d'))), Action::None));
        assert!(app.message.contains("visible resource"));
    }

    #[test]
    fn container_removal_requires_stopped_selection_and_visible_confirmation() {
        let mut app = app();
        app.page = Start::Containers;
        let id = "a".repeat(64);
        app.containers = Some(vec![crate::containers::EngineStatus {
            engine: "docker",
            state: "available",
            detail: None,
            usage: vec![],
            resources: vec![crate::containers::ResourceList {
                kind: "containers",
                error: None,
                items: vec![
                    serde_json::json!({"ID": id, "State": "exited", "Names": "fixture"}),
                    serde_json::json!({"ID": "b".repeat(64), "State": "running"}),
                    serde_json::json!({"ID": "short", "State": "exited"}),
                ],
            }],
        }]);
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(
            matches!(app.key(key(KeyCode::Char('d'))), Action::PreviewContainer(engine, selected) if engine == "docker" && selected == id)
        );
        assert!(app.container_preparing);
        app.container_preparing = false;
        app.container_plan = Some(crate::containers::test_removal_plan());
        assert!(!container_confirmation_fits(
            app.container_plan.as_ref().unwrap(),
            Rect::new(0, 0, 50, 24)
        ));
        assert!(container_confirmation_fits(
            app.container_plan.as_ref().unwrap(),
            Rect::new(0, 0, 110, 24)
        ));
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("Confirm container removal"));
        assert!(rendered.contains("configuration and logs"));
        assert!(matches!(app.key(key(KeyCode::Enter)), Action::None));
        assert!(matches!(app.key(key(KeyCode::Esc)), Action::None));
        assert!(app.container_plan.is_none());
        app.container_plan = Some(crate::containers::test_removal_plan());
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::RemoveContainer(_)
        ));
        assert!(app.container_removing);
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
    }

    #[test]
    fn trim_requires_selection_preview_and_visible_confirmation() {
        let mut app = app();
        app.page = Start::Maintenance;
        app.maintenance = Some(crate::maintenance::TrimStatus {
            platform: "linux".into(),
            fstrim_available: true,
            capability: "unknown".into(),
            timer: crate::maintenance::TimerStatus {
                state: "active".into(),
                load_state: None,
                unit_file_state: None,
                last_trigger: None,
                next_trigger: None,
                detail: None,
            },
            guidance: "test",
            mounts_warning: None,
            mounts: vec![crate::maintenance::MountStatus {
                mount_point: "/fixture".into(),
                mount_path: PathBuf::from("/fixture"),
                filesystem: "ext4".into(),
                device: "8:1".into(),
                discard_max_bytes: None,
                available_bytes: None,
                device_discard: "unknown",
                filesystem_trim: "unknown",
                fstab_trim_exclusion: "unknown",
                online_discard_option: "unknown",
            }],
        });
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(
            matches!(app.key(key(KeyCode::Enter)), Action::PreviewTrim(path) if path == std::path::Path::new("/fixture"))
        );
        assert!(app.trim_preparing);
        app.trim_preparing = false;
        let plan = || crate::maintenance::TrimPlan {
            mount: PathBuf::from("/fixture"),
            filesystem: "ext4".into(),
            device: "8:1".into(),
            preview_token: "fixture".into(),
            warning: "test",
        };
        app.trim_plan = Some(plan());
        assert!(!trim_confirmation_fits(
            app.trim_plan.as_ref().unwrap(),
            false,
            Rect::new(0, 0, 30, 8)
        ));
        assert!(trim_confirmation_fits(
            app.trim_plan.as_ref().unwrap(),
            false,
            Rect::new(0, 0, 100, 24)
        ));
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("/fixture"));
        assert!(output.contains("entire filesystem"));
        assert!(matches!(app.key(key(KeyCode::Esc)), Action::None));
        assert!(app.trim_plan.is_none());

        app.trim_plan = Some(plan());
        app.trim_read_only = true;
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("TRIM preview"));
        assert!(output.contains("Read-only preview"));
        assert!(matches!(app.key(key(KeyCode::Char('y'))), Action::None));
        assert!(app.trim_plan.is_some());
        assert!(matches!(app.key(key(KeyCode::Esc)), Action::None));
        assert!(app.trim_plan.is_none());

        app.trim_plan = Some(plan());
        assert!(matches!(app.key(key(KeyCode::Enter)), Action::None));
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Action::RunTrim(_)
        ));
        assert!(app.trim_running);
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
    }

    #[test]
    fn update_requires_confirmation_and_cannot_quit_while_running() {
        let mut app = app();
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(matches!(app.key(key(KeyCode::Enter)), Action::None));
        assert!(app.confirmation);
        assert!(matches!(app.key(key(KeyCode::Esc)), Action::None));
        assert!(!app.confirmation);
        app.key(key(KeyCode::Enter));
        for code in [KeyCode::Char('y'), KeyCode::Enter] {
            for modifiers in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
                assert!(matches!(
                    app.key(KeyEvent::new(code, modifiers)),
                    Action::None
                ));
                assert!(app.confirmation);
                assert!(!app.updating);
            }
        }
        assert!(matches!(app.key(key(KeyCode::Enter)), Action::Update(_)));
        assert!(!app.confirmation);
        assert!(app.updating);
        app.updating = false;
        app.key(key(KeyCode::Enter));
        assert!(
            matches!(app.key(key(KeyCode::Char('y'))), Action::Update(tools) if tools == [ToolKind::Go])
        );
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
    }

    #[test]
    fn held_navigation_repeats_but_confirmation_keys_do_not() {
        let mut app = app();
        app.page = Start::Dashboard;
        let repeated =
            |code| KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Repeat);
        for _ in 0..3 {
            app.key(repeated(KeyCode::Down));
        }
        for _ in 0..3 {
            app.key(repeated(KeyCode::Char('j')));
        }
        assert_eq!(app.dashboard_scroll, 6);
        for _ in 0..2 {
            app.key(repeated(KeyCode::Char('k')));
        }
        assert_eq!(app.dashboard_scroll, 4);
        for code in [KeyCode::Char('j'), KeyCode::Char('k')] {
            app.key(KeyEvent::new_with_kind(
                code,
                KeyModifiers::CONTROL,
                KeyEventKind::Repeat,
            ));
        }
        assert_eq!(app.dashboard_scroll, 4);

        app.page = Start::Toolchains;
        app.confirmation = true;
        for code in [
            KeyCode::Enter,
            KeyCode::Char('y'),
            KeyCode::Char(' '),
            KeyCode::Char('j'),
            KeyCode::Char('k'),
        ] {
            assert!(matches!(app.key(repeated(code)), Action::None));
            assert!(app.confirmation);
            assert!(!app.updating);
        }
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE)),
            Action::Update(_)
        ));
    }

    #[test]
    fn self_update_requires_a_visible_plan_and_explicit_confirmation() {
        let mut app = app();
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert!(matches!(
            app.key(key(KeyCode::Char('U'))),
            Action::PreviewSelfUpdate
        ));
        assert!(app.self_update_preparing);
        app.self_update_preparing = false;
        let plan = crate::application::SelfUpdatePlan {
            program: "cargo".into(),
            program_path: PathBuf::from("/fixture/bin/cargo"),
            args: vec!["install".into(), "--force".into(), "upkit".into()],
            destination: PathBuf::from("/fixture/bin"),
            prompt: "fixture".into(),
            description: "fixture".into(),
            via: "cargo",
            release_source: None,
        };
        app.self_update_plan = Some(plan.clone());
        assert!(!self_update_confirmation_fits(
            &plan,
            Rect::new(0, 0, 30, 8)
        ));
        assert!(self_update_confirmation_fits(
            &plan,
            Rect::new(0, 0, 120, 20)
        ));
        let mut terminal = Terminal::new(TestBackend::new(120, 20)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("Confirm Upkit self-update"));
        assert!(output.contains("/fixture/bin/cargo"));
        let mut github = plan.clone();
        github.via = "github";
        github.release_source =
            Some("https://user:secret@example.invalid/releases?token=hidden".into());
        let source = self_update_confirmation_lines(&github).join("\n");
        assert!(source.contains("https://example.invalid/releases"));
        assert!(!source.contains("secret"));
        assert!(!source.contains("token=hidden"));
        let ftp = self_update_source_display(std::ffi::OsStr::new(
            "ftp://user:secret@example.invalid/releases?token=hidden",
        ));
        assert!(!ftp.contains("secret"));
        assert!(!ftp.contains("token=hidden"));
        assert!(matches!(app.key(key(KeyCode::Esc)), Action::None));
        assert!(app.self_update_plan.is_none());
        app.self_update_plan = Some(plan.clone());
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::CONTROL)),
            Action::None
        ));
        assert!(app.self_update_plan.is_some());
        assert!(matches!(app.key(key(KeyCode::Char('y'))), Action::SelfUpdate(p) if p == plan));
        assert!(app.updating);
        assert!(matches!(app.key(key(KeyCode::Char('q'))), Action::None));
    }

    #[test]
    fn each_new_confirmation_surface_requires_fresh_input() {
        let mut app = app();
        let before = confirmation_surfaces(&app);
        app.confirmation = true;
        let toolchain = confirmation_surfaces(&app);
        assert!(newly_visible_confirmation(&before, &toolchain));
        assert!(!newly_visible_confirmation(&toolchain, &toolchain));
        app.confirmation = false;
        app.container_plan = Some(crate::containers::test_removal_plan());
        let container = confirmation_surfaces(&app);
        assert!(newly_visible_confirmation(&toolchain, &container));
        app.container_plan = None;
        assert!(!newly_visible_confirmation(
            &container,
            &confirmation_surfaces(&app)
        ));
    }

    #[test]
    fn marked_tools_are_confirmed_as_one_plan() {
        let mut app = app();
        let mut second = app.reports.as_ref().unwrap()[0].clone();
        second.tool = ToolKind::Rust;
        app.reports.as_mut().unwrap().push(second);
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.key(key(KeyCode::Char(' ')));
        app.key(key(KeyCode::Down));
        app.key(key(KeyCode::Char(' ')));
        app.key(key(KeyCode::Enter));
        assert!(
            matches!(app.key(key(KeyCode::Enter)), Action::Update(tools) if tools == [ToolKind::Go, ToolKind::Rust])
        );
    }

    #[test]
    fn doctor_navigation_and_diagnostics_render() {
        let mut app = app();
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.key(key(KeyCode::Tab));
        assert!(matches!(app.page, Start::Doctor));
        app.issues = Some(vec!["bindir is not on PATH".into()]);
        let timer = || crate::maintenance::TimerStatus {
            state: "active".into(),
            load_state: None,
            unit_file_state: None,
            last_trigger: None,
            next_trigger: None,
            detail: None,
        };
        app.doctor_capabilities = Some(crate::doctor::Capabilities {
            cancelled: false,
            cache_removal_probe: "openat2_available",
            cache_removal_note: "target still requires review",
            fstrim_available: true,
            fstrim_timer: timer(),
            scan_timer: timer(),
            installation_integrity: crate::doctor::InstallationIntegrityStatus::new(true),
            actionable_diagnostics: Vec::new(),
            containers: vec![crate::doctor::ContainerCapability {
                engine: "docker",
                executable_found: true,
                endpoint: "no_environment_override_detected",
                connection: "not_checked",
            }],
        });
        assert!(
            doctor_content(&app).contains("no managed roots found; no installations were checked")
        );
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let output = format!("{:?}", terminal.backend().buffer());
        assert!(output.contains("bindir is not on PATH"));
        assert!(output.contains("openat2_available"));
        assert!(output.contains("docker executable: true; connection: not_checked"));
        assert!(output.contains("docker endpoint: no_environment_override_detected"));
        app.key(key(KeyCode::BackTab));
        assert!(matches!(app.page, Start::Toolchains));
    }

    #[test]
    fn maintenance_screen_renders_detected_timer() {
        let mut app = app();
        app.page = Start::Maintenance;
        app.maintenance = Some(crate::maintenance::TrimStatus {
            platform: "linux".into(),
            fstrim_available: true,
            capability: "unknown".into(),
            guidance: "status only",
            mounts: vec![crate::maintenance::MountStatus {
                mount_point: "/fixture".into(),
                mount_path: "/fixture".into(),
                filesystem: "ext4".into(),
                device: "8:1".into(),
                discard_max_bytes: None,
                available_bytes: None,
                device_discard: "advertised",
                filesystem_trim: "unknown",
                fstab_trim_exclusion: "observed",
                online_discard_option: "enabled",
            }],
            mounts_warning: None,
            timer: crate::maintenance::TimerStatus {
                state: "active".into(),
                load_state: Some("loaded".into()),
                unit_file_state: None,
                last_trigger: None,
                next_trigger: None,
                detail: None,
            },
        });
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("System timer: active"));
        assert!(rendered.contains("filesystem ext4"));
        assert!(rendered.contains("FITRIM: unknown"));
        assert!(rendered.contains("online discard option: enabled"));
        assert!(rendered.contains("fstab TRIM exclusion: observed"));
        assert!(rendered.contains("press Enter for a TRIM preview"));

        app.maintenance.as_mut().unwrap().fstrim_available = false;
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("Volume inventory is read-only"));
        assert!(!rendered.contains("press Enter for a TRIM preview"));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.message.contains("TRIM preview is unavailable"));
        assert!(!app.trim_preparing);
    }

    #[test]
    fn cache_screen_renders_and_supports_cancellation() {
        let mut app = app();
        app.page = Start::Cache;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            Action::StartCache
        ));
        assert!(app.cache_running);
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            Action::CancelCache
        ));
        app.cache_running = false;
        app.cache = Some(crate::cache::CacheReport {
            entries: vec![],
            warnings: vec!["fixture warning".into()],
            cancelled: true,
        });
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("fixture warning"));
        assert!(rendered.contains("Inventory cancelled"));
    }

    #[test]
    fn trash_screen_is_read_only_and_cancellable() {
        let mut app = app();
        app.page = Start::Trash;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            Action::StartTrash(None)
        ));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            Action::CancelTrash
        ));
        app.trash_running = false;
        app.trash = Some(crate::trash::TrashReport {
            platform: "linux",
            locations: vec![],
            warnings: vec!["fixture warning".into()],
            cancelled: true,
        });
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("fixture warning"));
        assert!(rendered.contains("review old items"));
    }

    #[test]
    fn macos_trash_inventory_does_not_enable_selection_actions() {
        let mut app = app();
        app.page = Start::Trash;
        app.trash = Some(crate::trash::TrashReport {
            platform: "macos",
            locations: vec![crate::trash::TrashLocation {
                path: PathBuf::from("/home/test/.Trash"),
                kind: "macOS home Trash",
                item_count: Some(1),
                logical_bytes: Some(0),
                allocated_bytes: None,
                size_complete: true,
                warnings: vec![],
                items: vec![crate::trash::snapshot_item_for_test("fixture-item")],
                items_complete: true,
            }],
            warnings: vec![],
            cancelled: false,
        });

        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("read-only snapshot"));
        assert!(rendered.contains("fixture-item"));
        assert!(!rendered.contains("review old items"));
        assert_eq!(app.trash.as_ref().unwrap().locations[0].items.len(), 1);
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('A'), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(!app.trash_marking);
        assert!(app.trash_preview.is_none());
    }

    #[test]
    fn virtual_trash_location_shows_no_filesystem_path_and_has_no_removal_target() {
        let mut app = app();
        app.page = Start::Trash;
        app.trash = Some(crate::trash::TrashReport {
            platform: "windows",
            locations: vec![crate::trash::TrashLocation {
                path: PathBuf::new(),
                kind: "Windows Recycle Bin (virtual)",
                item_count: Some(23),
                logical_bytes: None,
                allocated_bytes: None,
                size_complete: false,
                warnings: vec!["item-level actions are unsupported".into()],
                items: vec![],
                items_complete: false,
            }],
            warnings: vec![],
            cancelled: false,
        });
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("Windows Recycle Bin (virtual)"));
        assert!(rendered.contains("(virtual; no filesystem path)"));
        assert!(rendered.contains("items=23"));
        assert!(app.trash.as_ref().unwrap().locations[0].items.is_empty());
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('A'), KeyModifiers::NONE)),
            Action::None
        ));
        assert!(!app.trash_marking);
    }

    #[test]
    fn trash_batch_allows_cancelling_remaining_items() {
        let mut app = app();
        app.trash_removing = true;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            Action::CancelTrash
        ));
        assert!(app.message.contains("current item"));
    }

    #[test]
    fn trash_retention_presets_render_unselected_preview() {
        let mut app = app();
        app.page = Start::Trash;
        assert!(
            matches!(app.key(KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE)), Action::StartTrash(Some(age)) if age == Duration::from_secs(14 * 86400))
        );
        app.trash_running = false;
        app.trash_preview = Some(Ok(crate::trash::RetentionPreview {
            older_than_seconds: 14 * 86400,
            items: vec![crate::trash::RetentionItem {
                location: PathBuf::from("/trash"),
                name: "fixture".into(),
                deletion_date: None,
                age_status: "unknown_or_ambiguous",
                location_complete: true,
                selected: false,
                #[cfg(target_os = "linux")]
                identity: None,
            }],
            warnings: vec!["fixture warning".into()],
            cancelled: false,
            complete: true,
        }));
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("unknown_or_ambiguous"));
        assert!(rendered.contains("request a deletion preview"));
        app.trash_preview.as_mut().unwrap().as_mut().unwrap().items[0].selected = true;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.trash_review);
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        assert!(format!("{:?}", terminal.backend().buffer()).contains("Marked items"));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.trash_review);
        app.trash_preview.as_mut().unwrap().as_mut().unwrap().items[0].selected = false;
        app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(!app.trash_preview.as_ref().unwrap().as_ref().unwrap().items[0].selected);
        let preview = app.trash_preview.as_mut().unwrap().as_mut().unwrap();
        preview.items[0].age_status = "older_than_threshold";
        app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(!app.trash_preview.as_ref().unwrap().as_ref().unwrap().items[0].selected);
        assert!(app.message.contains("identity is unavailable"));
        app.trash_preview.as_mut().unwrap().as_mut().unwrap().items[0].location_complete = false;
        app.key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(app.message.contains("incomplete"));
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Char('0'), KeyModifiers::NONE)),
            Action::StartTrash(None)
        ));
    }

    #[test]
    fn artifact_screen_renders_results_and_cancels_active_scan() {
        let mut app = app();
        app.page = Start::Artifacts;
        app.scan_running = true;
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            Action::CancelScan
        ));
        app.scan_running = false;
        app.scan = Some(Ok(crate::sweep::ScanReport {
            roots: vec![],
            candidates: vec![],
            warnings: vec!["permission denied".into()],
            cancelled: true,
        }));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("permission denied"));
        assert!(rendered.contains("Scan cancelled"));
    }

    #[test]
    fn preview_selection_and_details_are_read_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("target")).unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
        let report = crate::sweep::scan(&[dir.path().to_owned()]).unwrap();
        let mut app = app();
        app.page = Start::Artifacts;
        app.preview_mode = true;
        app.plan = Some(Ok(crate::sweep::preview(report, &[]).unwrap()));
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.key(key(KeyCode::Char(' ')));
        assert!(app.plan.as_ref().unwrap().as_ref().unwrap().items[0].selected);
        app.key(key(KeyCode::Enter));
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());
        assert!(rendered.contains("Process activity"));
        assert!(rendered.contains("verify no active build"));
        assert!(rendered.contains("Inspection only"));
        app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(!app.plan_detail);
        assert!(dir.path().join("target").exists());
    }

    #[test]
    fn explicit_cli_preview_blocks_cleanup_and_page_navigation() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
        let report = crate::sweep::scan(&[dir.path().to_owned()]).unwrap();
        let mut app = app();
        app.page = Start::Artifacts;
        app.preview_mode = true;
        app.cli_preview_read_only = true;
        app.plan = Some(Ok(crate::sweep::preview(report, &[]).unwrap()));

        for code in ['d', 'b', 'r'] {
            assert!(matches!(
                app.key(KeyEvent::new(KeyCode::Char(code), KeyModifiers::NONE)),
                Action::None
            ));
            assert_eq!(
                app.message,
                "Read-only CLI preview; use the dashboard for cleanup."
            );
            assert!(target.exists());
        }
        assert!(matches!(
            app.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)),
            Action::None
        ));
        assert!(app.page == Start::Artifacts);
        assert_eq!(
            app.message,
            "This CLI preview is read-only; press q to close it."
        );

        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            app.plan_detail,
            "read-only inspection details remain available"
        );
        assert!(target.exists());
    }
}
