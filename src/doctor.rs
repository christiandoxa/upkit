//! Read-only snapshots of optional maintenance capabilities.
use serde::Serialize;
#[cfg(not(unix))]
use std::sync::atomic::Ordering;
use std::{path::Path, sync::atomic::AtomicBool};

#[cfg(unix)]
const DOCTOR_ROOT_ENTRY_LIMIT: usize = 2_000;
#[cfg(unix)]
const DOCTOR_SEAL_LIMIT: usize = 16;
#[cfg(unix)]
const DOCTOR_VERIFY_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(unix)]
const DOCTOR_VERIFY_ENTRIES: usize = 50_000;
#[cfg(unix)]
const DOCTOR_VERIFY_DEPTH: usize = 64;

#[cfg(unix)]
#[derive(Clone, Copy)]
struct IntegrityLimits {
    root_entries: usize,
    seals: usize,
    bytes: u64,
    entries: usize,
    depth: usize,
}

#[cfg(unix)]
impl IntegrityLimits {
    const DOCTOR: Self = Self {
        root_entries: DOCTOR_ROOT_ENTRY_LIMIT,
        seals: DOCTOR_SEAL_LIMIT,
        bytes: DOCTOR_VERIFY_BYTES,
        entries: DOCTOR_VERIFY_ENTRIES,
        depth: DOCTOR_VERIFY_DEPTH,
    };
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct InstallationIntegrityStatus {
    pub supported: bool,
    pub complete: bool,
    pub cancelled: bool,
    pub truncated: bool,
    pub roots_inspected: usize,
    pub verified_seals: usize,
    pub unknown_seals: usize,
    pub legacy_unsealed: usize,
    pub unknown_roots: usize,
    pub unknown_entries: usize,
    pub skipped_seals: usize,
}

impl InstallationIntegrityStatus {
    pub(crate) fn new(supported: bool) -> Self {
        Self {
            supported,
            complete: supported,
            cancelled: false,
            truncated: false,
            roots_inspected: 0,
            verified_seals: 0,
            unknown_seals: 0,
            legacy_unsealed: 0,
            unknown_roots: 0,
            unknown_entries: 0,
            skipped_seals: 0,
        }
    }

    fn has_unknowns(&self) -> bool {
        self.unknown_seals > 0
            || self.legacy_unsealed > 0
            || self.unknown_roots > 0
            || self.unknown_entries > 0
            || self.skipped_seals > 0
            || self.truncated
            || !self.complete
    }

    fn line(&self) -> String {
        if !self.supported {
            return "Managed installation seal verification: unsupported on this platform.".into();
        }
        if self.cancelled {
            return format!(
                "Managed installation seal verification: cancelled after checking {} seal(s); remaining installations are unknown. Cancellation is cooperative and waits for the current filesystem call.",
                self.verified_seals + self.unknown_seals
            );
        }
        if self.roots_inspected == 0 && self.unknown_roots == 0 {
            return "Managed installation seal verification: no managed roots found; no installations were checked. This is not a health assessment.".into();
        }
        format!(
            "Managed installation seals: {} verified, {} unverified, {} legacy/unsealed unknown, {} unknown root(s), {} unknown entry(s), {} skipped; inventory {}{}. A matching seal does not test whether a tool runs or works.",
            self.verified_seals,
            self.unknown_seals,
            self.legacy_unsealed,
            self.unknown_roots,
            self.unknown_entries,
            self.skipped_seals,
            if self.complete {
                "complete"
            } else {
                "incomplete"
            },
            if self.truncated {
                " (limit reached)"
            } else {
                ""
            },
        )
    }
}

#[cfg(unix)]
fn installation_integrity(home: &Path, cancel: &AtomicBool) -> InstallationIntegrityStatus {
    installation_integrity_with_limits(home, cancel, IntegrityLimits::DOCTOR)
}

#[cfg(not(unix))]
fn installation_integrity(_: &Path, cancel: &AtomicBool) -> InstallationIntegrityStatus {
    let mut status = InstallationIntegrityStatus::new(false);
    status.cancelled = cancel.load(Ordering::Relaxed);
    status
}

#[cfg(unix)]
fn installation_integrity_with_limits(
    home: &Path,
    cancel: &AtomicBool,
    limits: IntegrityLimits,
) -> InstallationIntegrityStatus {
    use std::sync::atomic::Ordering;
    use std::{fs, os::unix::fs::MetadataExt};

    let mut status = InstallationIntegrityStatus::new(true);
    let mut budget = crate::installation_identity::VerificationBudget::new(
        limits.bytes,
        limits.entries,
        limits.depth,
    );
    let mut root_entries = 0usize;
    let mut seals = 0usize;
    let tools = [
        crate::ToolKind::Go,
        crate::ToolKind::Node,
        crate::ToolKind::Python,
        crate::ToolKind::Flutter,
        crate::ToolKind::Java,
        crate::ToolKind::Dotnet,
    ];

    'tools: for tool in tools {
        if cancel.load(Ordering::Relaxed) {
            status.cancelled = true;
            status.complete = false;
            break;
        }
        let root = home.join(tool.as_str());
        let root_meta = match fs::symlink_metadata(&root) {
            Ok(metadata)
                if metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == rustix::process::geteuid().as_raw() =>
            {
                metadata
            }
            Ok(_) => {
                status.unknown_roots += 1;
                status.complete = false;
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                status.unknown_roots += 1;
                status.complete = false;
                continue;
            }
        };
        if !root.canonicalize().is_ok_and(|path| path == root) {
            status.unknown_roots += 1;
            status.complete = false;
            continue;
        }
        let home_device = fs::metadata(home).map(|metadata| metadata.dev());
        if !home_device.is_ok_and(|device| device == root_meta.dev()) {
            status.unknown_roots += 1;
            status.complete = false;
            continue;
        }
        status.roots_inspected += 1;

        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(_) => {
                status.unknown_roots += 1;
                status.complete = false;
                continue;
            }
        };
        for entry in entries {
            if cancel.load(Ordering::Relaxed) {
                status.cancelled = true;
                status.complete = false;
                break 'tools;
            }
            root_entries += 1;
            if root_entries > limits.root_entries {
                status.truncated = true;
                status.complete = false;
                break 'tools;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    status.unknown_entries += 1;
                    status.complete = false;
                    continue;
                }
            };
            let name = entry.file_name();
            let path = entry.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => {
                    status.unknown_entries += 1;
                    status.complete = false;
                    continue;
                }
            };

            let reserved = match name.to_str() {
                Some("active") => metadata.file_type().is_symlink(),
                Some(".upkit-managed-links") => {
                    metadata.is_dir() && !metadata.file_type().is_symlink()
                }
                Some("wrappers") if tool == crate::ToolKind::Go => {
                    metadata.is_dir() && !metadata.file_type().is_symlink()
                }
                Some("pip-globals.txt") if tool == crate::ToolKind::Python => {
                    metadata.is_file() && !metadata.file_type().is_symlink()
                }
                _ => false,
            };
            if reserved {
                continue;
            }

            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                status.unknown_entries += 1;
                status.complete = false;
                continue;
            }
            let name = name.to_str();
            let is_install_stage = name.is_some_and(|name| name.starts_with("install-"));
            if !is_install_stage {
                status.legacy_unsealed += 1;
                continue;
            }

            let marker = path.join(".upkit-install.json");
            match fs::symlink_metadata(&marker) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    status.legacy_unsealed += 1;
                    continue;
                }
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
                _ => {
                    status.unknown_seals += 1;
                    status.complete = false;
                    continue;
                }
            }

            seals += 1;
            if seals > limits.seals {
                status.skipped_seals += 1;
                status.truncated = true;
                status.complete = false;
                break 'tools;
            }
            if budget.remaining_bytes == 0 || budget.remaining_entries == 0 {
                status.skipped_seals += 1;
                status.truncated = true;
                status.complete = false;
                break 'tools;
            }
            match crate::installation_identity::inspect_with_budget(
                &root,
                &path,
                tool,
                cancel,
                &mut budget,
            ) {
                Ok(_) => status.verified_seals += 1,
                Err(_) if cancel.load(Ordering::Relaxed) => {
                    status.cancelled = true;
                    status.complete = false;
                    break 'tools;
                }
                Err(_) => {
                    status.unknown_seals += 1;
                    status.complete = false;
                    status.truncated |= budget.limit_hit.is_some();
                    if budget.remaining_bytes == 0 || budget.remaining_entries == 0 {
                        status.truncated = true;
                        break 'tools;
                    }
                }
            }
        }
    }

    status
}

/// Compare only completed scans with the same bound scope and policy.
pub(crate) fn artifact_growth_warning(home: &std::path::Path) -> Option<String> {
    let history = match crate::reports::read(home) {
        Ok(history) => history,
        Err(_) => {
            return Some(
                "Maintenance history could not be read safely; inspect `upkit report` before relying on historical totals.".into(),
            );
        }
    };
    if !history.warnings.is_empty() {
        return Some(format!(
            "Maintenance history contains {} warning(s); inspect `upkit report` before relying on historical totals.",
            history.warnings.len()
        ));
    }
    artifact_growth_from_records(&history.records)
}

fn artifact_growth_from_records(records: &[crate::reports::Record]) -> Option<String> {
    use std::collections::HashMap;

    let mut samples = records
        .iter()
        .filter(|record| record.operation == "scheduled_scan" && record.outcome == "completed")
        .filter_map(|record| {
            let finished = record
                .finished_unix
                .filter(|time| *time >= record.started_unix)?;
            let data = record.detail.as_deref()?.rsplit_once("; scan-v1 ")?.1;
            let mut fields = data.split_whitespace();
            let scope = fields.next()?;
            if scope.len() != 64 || !scope.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            let bytes: u64 = fields.next()?.parse().ok()?;
            if fields.next().is_some() {
                return None;
            }
            Some((finished, record.id, scope, bytes))
        })
        .collect::<Vec<_>>();
    samples.sort_unstable_by_key(|sample| (sample.0, sample.1));
    let mut previous = HashMap::new();
    for (finished, id, scope, bytes) in samples {
        let entry = previous
            .entry(scope)
            .or_insert((None, (finished, id, bytes)));
        if entry.1 != (finished, id, bytes) {
            entry.0 = Some(entry.1);
            entry.1 = (finished, id, bytes);
        }
    }
    let latest_growth = previous
        .values()
        .filter_map(|(old, new)| {
            let (old_finished, old_id, old_bytes) = (*old)?;
            let (finished, id, bytes) = *new;
            (finished > old_finished
                && bytes.saturating_sub(old_bytes) >= 1024 * 1024 * 1024
                && u128::from(bytes) * 2 >= u128::from(old_bytes) * 3)
                .then_some((finished, old_id, id, bytes - old_bytes))
        })
        .max_by_key(|value| (value.0, value.2));
    latest_growth.map(|(_, old, new, growth)| {
        format!("Scheduled scan records {old} and {new} report {growth} more logical artifact bytes for the same recorded scope. Inspect the Reports and Artifacts screens; sizes are estimates, not reclaimed space.")
    })
}

#[derive(Debug, Serialize)]
pub(crate) struct Capabilities {
    pub cancelled: bool,
    pub cache_removal_probe: &'static str,
    pub cache_removal_note: &'static str,
    /// True only when Linux's `fstrim` executable is discoverable.
    pub fstrim_available: bool,
    pub fstrim_timer: crate::maintenance::TimerStatus,
    pub scan_timer: crate::maintenance::TimerStatus,
    pub containers: Vec<ContainerCapability>,
    pub installation_integrity: InstallationIntegrityStatus,
    pub actionable_diagnostics: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ContainerCapability {
    pub engine: &'static str,
    pub executable_found: bool,
    pub endpoint: &'static str,
    pub connection: &'static str,
}

fn container_endpoint(engine: &str) -> &'static str {
    let selected_context = match engine {
        "docker" => std::env::var_os("DOCKER_CONTEXT").is_some_and(|value| !value.is_empty()),
        "podman" => std::env::var_os("CONTAINER_CONNECTION").is_some_and(|value| !value.is_empty()),
        _ => false,
    };
    if selected_context {
        return "named_context_unverified";
    }

    let endpoint = match engine {
        "docker" => std::env::var_os("DOCKER_HOST"),
        "podman" => std::env::var_os("CONTAINER_HOST").or_else(|| std::env::var_os("DOCKER_HOST")),
        _ => None,
    };
    let Some(endpoint) = endpoint.filter(|value| !value.is_empty()) else {
        return "no_environment_override_detected";
    };
    let Some(endpoint) = endpoint.to_str() else {
        return "configured_endpoint_unverified";
    };
    if let Some(path) = endpoint.strip_prefix("unix://") {
        return unix_socket_status(path);
    }
    if endpoint.starts_with("tcp://") || endpoint.starts_with("ssh://") {
        "network_endpoint_unverified"
    } else {
        "configured_endpoint_unverified"
    }
}

#[cfg(unix)]
fn unix_socket_status(path: &str) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    let path = std::path::Path::new(path);
    if !path.is_absolute() {
        return "unix_endpoint_invalid";
    }
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => "unix_socket_present_unverified",
        Ok(_) => "unix_endpoint_not_socket",
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "unix_socket_missing",
        Err(_) => "unix_socket_unavailable",
    }
}

#[cfg(not(unix))]
fn unix_socket_status(_: &str) -> &'static str {
    "unix_endpoint_unsupported"
}

#[cfg(target_os = "linux")]
fn cache_removal_probe() -> &'static str {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
    if openat2(
        CWD,
        ".",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .is_ok()
    {
        "openat2_available"
    } else {
        "openat2_unavailable_or_denied"
    }
}

#[cfg(not(target_os = "linux"))]
fn cache_removal_probe() -> &'static str {
    "unsupported_platform"
}

fn timer_status(state: &str, detail: &str) -> crate::maintenance::TimerStatus {
    crate::maintenance::TimerStatus {
        state: state.into(),
        load_state: None,
        unit_file_state: None,
        last_trigger: None,
        next_trigger: None,
        detail: Some(detail.into()),
    }
}

fn verified_windows_scan_task(status: &crate::maintenance::TimerStatus) -> bool {
    status.load_state.as_deref() == Some("registered")
        && matches!(
            status.state.as_str(),
            "ready" | "queued" | "running" | "disabled"
        )
}

fn scan_schedule_line(status: &crate::maintenance::TimerStatus, windows: bool) -> String {
    if !windows {
        return format!(
            "Upkit scan schedule: {} (name only; ownership and action unverified)",
            status.state
        );
    }
    if verified_windows_scan_task(status) {
        format!(
            "Upkit Task Scheduler task: {} (path, owner, access rights, principal and read-only action verified)",
            status.state
        )
    } else if status.state == "not_found" {
        "Upkit Task Scheduler task: not found".into()
    } else {
        format!(
            "Upkit Task Scheduler task: {} (task identity and action could not be verified)",
            status.state
        )
    }
}

fn scan_schedule_diagnostic(
    status: &crate::maintenance::TimerStatus,
    windows: bool,
) -> Option<String> {
    if windows {
        if verified_windows_scan_task(status) {
            Some("An Upkit Task Scheduler task is registered and verified; review `upkit schedule list` before adding another scan schedule.".into())
        } else if status.state == "unavailable" {
            Some("Task Scheduler status could not be verified; check that the service is available and the current user can inspect the task, then rerun `upkit schedule list` before changing the scan schedule.".into())
        } else {
            None
        }
    } else if status.state == "active" {
        Some(
            "An Upkit scan schedule appears active by name; review `upkit schedule list` before adding another scan schedule.".into(),
        )
    } else if status.state == "unavailable" {
        Some("The platform schedule manager could not be queried; check that it is available and the current user can inspect it, then rerun `upkit schedule list` before changing the scan schedule.".into())
    } else if status.state == "failed" {
        Some("The Upkit scan schedule failed; inspect `upkit --non-interactive schedule list` before relying on scheduled scans.".into())
    } else {
        None
    }
}

fn skipped_probe_diagnostic(
    label: &str,
    status: &crate::maintenance::TimerStatus,
    command: &str,
) -> Option<String> {
    if status.state != "skipped" {
        return None;
    }
    let reason = status.detail.as_deref()?;
    let skipped_because = if reason.contains("dry-run") {
        "dry-run mode skipped the scheduler query"
    } else if reason.contains("offline mode") {
        "offline mode skipped the scheduler query"
    } else {
        return None;
    };
    Some(format!(
        "{label} status is unknown because {skipped_because}; skipped does not mean absent. If the configured scheduler is safe to query, inspect its status with `{command}`."
    ))
}

fn go_goroot_override_is_set(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

fn actionable_diagnostics(capabilities: &Capabilities) -> Vec<String> {
    let mut diagnostics = Vec::new();
    if capabilities.cancelled {
        if !capabilities.installation_integrity.cancelled {
            diagnostics.push(
                "Doctor checks were cancelled after the seal scan; checks already started may have completed."
                    .into(),
            );
        }
        return diagnostics;
    }
    if !capabilities.installation_integrity.supported {
        diagnostics.push(
            "Managed installation seal verification is unsupported on this platform; installation integrity remains unknown. Consult the toolchain provider's verification guidance before relying on a managed installation.".into(),
        );
    }
    if capabilities.cache_removal_probe == "openat2_unavailable_or_denied" {
        diagnostics.push(
            "Linux secure cache removal could not use openat2; check kernel support and filesystem permissions before retrying a cache preview.".into(),
        );
    }
    if cfg!(target_os = "linux") {
        if !capabilities.fstrim_available {
            diagnostics.push(
                "fstrim was not found; install the platform package that provides fstrim if you need manual TRIM.".into(),
            );
        }
        match capabilities.fstrim_timer.state.as_str() {
            "active" => diagnostics.push(
                "The system fstrim.timer is active; keep using the OS schedule instead of adding another TRIM schedule.".into(),
            ),
            "not_found" => diagnostics.push(
                "No system fstrim.timer was found; if scheduled TRIM is needed, configure the OS-provided timer.".into(),
            ),
            "inactive" | "failed" => diagnostics.push(
                "The system fstrim.timer is not active; inspect `systemctl status fstrim.timer` if periodic TRIM is expected.".into(),
            ),
            "unavailable" => diagnostics.push(
                "System TRIM scheduling could not be inspected; check that systemd is available and `systemctl show fstrim.timer` works.".into(),
            ),
            _ => {}
        }
    }
    if let Some(diagnostic) =
        scan_schedule_diagnostic(&capabilities.scan_timer, cfg!(target_os = "windows"))
    {
        diagnostics.push(diagnostic);
    }
    if cfg!(target_os = "linux")
        && let Some(diagnostic) = skipped_probe_diagnostic(
            "System TRIM timer",
            &capabilities.fstrim_timer,
            "systemctl show fstrim.timer --no-pager --property=LoadState,ActiveState,UnitFileState",
        )
    {
        diagnostics.push(diagnostic);
    }
    if let Some(diagnostic) = skipped_probe_diagnostic(
        "Upkit scan schedule",
        &capabilities.scan_timer,
        "upkit --non-interactive schedule list",
    ) {
        diagnostics.push(diagnostic);
    }
    for container in &capabilities.containers {
        if !container.executable_found {
            diagnostics.push(format!(
                "{} was not found; install it only if you use that container engine.",
                container.engine
            ));
            continue;
        }
        let endpoint_action = match container.endpoint {
            "unix_socket_missing" => Some(
                "the configured local socket is missing; start the engine or correct its context",
            ),
            "unix_endpoint_invalid" | "unix_endpoint_not_socket" => {
                Some("the configured local socket path is invalid; correct the engine context")
            }
            "unix_socket_unavailable" => Some(
                "the configured local socket cannot be inspected; check its permissions and engine state",
            ),
            "named_context_unverified" | "network_endpoint_unverified" => Some(
                "a named or remote context is configured; verify its target before inspecting or cleaning resources",
            ),
            "unix_socket_present_unverified" | "no_environment_override_detected" => Some(
                "the engine connection was not tested; verify the selected context with its `info` command",
            ),
            _ => None,
        };
        if let Some(action) = endpoint_action {
            diagnostics.push(format!("{}: {action}.", container.engine));
        }
    }
    diagnostics
}

fn fstrim_available_on(
    is_linux: bool,
    cancelled: bool,
    executable_found: impl FnOnce() -> bool,
) -> bool {
    is_linux && !cancelled && executable_found()
}

pub(crate) fn capabilities(home: &Path, offline: bool, cancel: &AtomicBool) -> Capabilities {
    capabilities_with_dry_run(home, offline, false, cancel)
}

pub(crate) fn capabilities_with_dry_run(
    home: &Path,
    offline: bool,
    dry_run: bool,
    cancel: &AtomicBool,
) -> Capabilities {
    use std::sync::atomic::Ordering;

    let installation_integrity = installation_integrity(home, cancel);
    let mut cancelled = installation_integrity.cancelled || cancel.load(Ordering::Relaxed);
    let (fstrim_timer, scan_timer) = if cancelled {
        let skipped = || timer_status("skipped", "Doctor verification was cancelled");
        (skipped(), skipped())
    } else if dry_run {
        let skipped = || {
            timer_status(
                "skipped",
                "dry-run skips platform scheduler queries; timer state was not inspected",
            )
        };
        (skipped(), skipped())
    } else if offline && cfg!(target_os = "linux") {
        let skipped = || {
            timer_status(
                "skipped",
                "offline mode skips systemd queries; manager endpoints may be remote",
            )
        };
        (skipped(), skipped())
    } else {
        let (trim, scan) = std::thread::scope(|scope| {
            let trim = scope.spawn(|| {
                if cfg!(target_os = "linux") {
                    crate::maintenance::timer_command("fstrim.timer", false)
                } else {
                    timer_status(
                        "unsupported",
                        "systemd timer status is only available on Linux",
                    )
                }
            });
            let scan = scope.spawn(|| crate::schedule::status_with_cancel(cancel));
            (trim.join(), scan.join())
        });
        let failed = || timer_status("unavailable", "timer status worker failed");
        (
            trim.unwrap_or_else(|_| failed()),
            scan.unwrap_or_else(|_| failed()),
        )
    };
    cancelled |= cancel.load(Ordering::Relaxed);
    let mut capabilities = Capabilities {
        cancelled,
        cache_removal_probe: if cancelled {
            "skipped_cancelled"
        } else {
            cache_removal_probe()
        },
        cache_removal_note: if cancelled {
            "Remaining capability probes were skipped after Doctor verification was cancelled."
        } else if cfg!(target_os = "linux") {
            "This only probes openat2; target eligibility, process inspection, and filesystem safety are checked during preview."
        } else {
            "Secure cache removal is unsupported on this platform."
        },
        fstrim_available: fstrim_available_on(cfg!(target_os = "linux"), cancelled, || {
            which::which("fstrim").is_ok()
        }),
        fstrim_timer,
        scan_timer,
        installation_integrity,
        containers: if cancelled {
            Vec::new()
        } else {
            ["docker", "podman"]
                .into_iter()
                .map(|engine| ContainerCapability {
                    engine,
                    executable_found: which::which(engine).is_ok(),
                    endpoint: container_endpoint(engine),
                    connection: "not_checked",
                })
                .collect()
        },
        actionable_diagnostics: Vec::new(),
    };
    capabilities.actionable_diagnostics = actionable_diagnostics(&capabilities);
    if !capabilities.cancelled && go_goroot_override_is_set(std::env::var_os("GOROOT").as_deref()) {
        capabilities.actionable_diagnostics.push(
            "GOROOT is set in Upkit's environment. Go honors a non-empty GOROOT when resolving its root; inspect or unset it if Go commands resolve unexpectedly. This diagnostic does not inspect or display the value.".into(),
        );
    }
    capabilities
}

impl Capabilities {
    pub(crate) fn installation_diagnostic(&self) -> Option<String> {
        let status = &self.installation_integrity;
        if !status.supported {
            None
        } else if status.cancelled {
            Some(
                "Managed installation seal verification was cancelled; unchecked installations remain unknown."
                    .into(),
            )
        } else if status.has_unknowns() {
            Some(
                "Some managed installations are legacy, unsealed, unreadable, or outside Doctor's verification limits; review the managed cleanup preview. A matching seal does not prove that a tool runs or works."
                    .into(),
            )
        } else {
            None
        }
    }

    pub(crate) fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Cache removal: {}", self.cache_removal_probe),
            self.cache_removal_note.into(),
            self.installation_integrity.line(),
        ];
        if self.cancelled {
            lines.push(
                "Remaining capability and diagnostic checks were not started after cancellation."
                    .into(),
            );
        } else {
            lines.push(format!(
                "fstrim executable: {}; system timer: {}",
                self.fstrim_available, self.fstrim_timer.state
            ));
        }
        lines.push(scan_schedule_line(
            &self.scan_timer,
            cfg!(target_os = "windows"),
        ));
        if let Some(detail) = &self.fstrim_timer.detail {
            lines.push(format!("System timer: {detail}"));
        }
        if let Some(detail) = &self.scan_timer.detail {
            lines.push(format!("Scan timer: {detail}"));
        }
        lines.extend(self.containers.iter().map(|engine| {
            format!(
                "{} executable: {}; connection: {}",
                engine.engine, engine.executable_found, engine.connection
            )
        }));
        lines.extend(
            self.containers
                .iter()
                .map(|engine| format!("{} endpoint: {}", engine.engine, engine.endpoint)),
        );
        lines.extend(
            self.actionable_diagnostics
                .iter()
                .map(|diagnostic| format!("Recommended action: {diagnostic}")),
        );
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::path::PathBuf;

    fn scan_record(id: usize, finished: u64, scope: &str, bytes: u64) -> crate::reports::Record {
        crate::reports::Record {
            id,
            started_unix: finished.saturating_sub(1),
            finished_unix: Some(finished),
            duration_ms: 1,
            operation: "scheduled_scan".into(),
            target: "fixture".into(),
            outcome: "completed".into(),
            detail: Some(format!("1 candidates; 0 warnings; scan-v1 {scope} {bytes}")),
            estimated_bytes: None,
            verified_reclaimed_bytes: None,
            platform: "fixture".into(),
        }
    }

    #[test]
    fn compares_only_latest_complete_scan_samples_from_the_same_scope() {
        let scope = "a".repeat(64);
        let other = "b".repeat(64);
        let gib = 1024 * 1024 * 1024;
        let mut records = vec![
            scan_record(1, 10, &scope, gib),
            scan_record(2, 20, &other, 8 * gib),
            scan_record(3, 30, &scope, 2 * gib),
        ];
        let warning = artifact_growth_from_records(&records).unwrap();
        assert!(warning.contains("1 and 3"));
        assert!(warning.contains("not reclaimed space"));
        records.push(scan_record(4, 40, &scope, 2 * gib));
        assert!(artifact_growth_from_records(&records).is_none());
        records[3].outcome = "partial".into();
        assert!(artifact_growth_from_records(&records).is_some());
        records[2].finished_unix = Some(10);
        records[2].started_unix = 9;
        assert!(artifact_growth_from_records(&records).is_none());
        records[2].detail = Some("1 candidates; 0 warnings; scan-v1 invalid 99".into());
        assert!(artifact_growth_from_records(&records).is_none());
    }

    #[test]
    fn doctor_reports_incomplete_history_without_echoing_record_contents() {
        use std::fs;

        let dir = tempfile::tempdir().unwrap();
        let history = dir.path().join("history");
        fs::create_dir(&history).unwrap();
        let record = history.join("000.json");
        fs::write(&record, b"private-fixture-marker").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let warning = artifact_growth_warning(dir.path()).unwrap();
        assert!(warning.contains("Maintenance history contains 1 warning"));
        assert!(warning.contains("upkit report"));
        assert!(!warning.contains("private-fixture-marker"));
    }

    #[test]
    fn doctor_reports_unsafe_history_directory_without_echoing_its_path() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("private-fixture-target");
            std::fs::create_dir(&target).unwrap();
            symlink(&target, dir.path().join("history")).unwrap();

            let warning = artifact_growth_warning(dir.path()).unwrap();
            assert!(warning.contains("could not be read safely"));
            assert!(warning.contains("upkit report"));
            assert!(!warning.contains(&target.to_string_lossy().to_string()));
        }
    }

    fn timer(state: &str) -> crate::maintenance::TimerStatus {
        super::timer_status(state, "fixture")
    }

    #[test]
    fn fstrim_probe_is_linux_only_and_skips_cancelled_lookup() {
        assert!(!fstrim_available_on(false, false, || panic!(
            "non-Linux probe ran"
        )));
        assert!(!fstrim_available_on(true, true, || panic!(
            "cancelled probe ran"
        )));
        assert!(fstrim_available_on(true, false, || true));
        assert!(!fstrim_available_on(true, false, || false));
    }

    fn task_status(state: &str, load_state: Option<&str>) -> crate::maintenance::TimerStatus {
        let mut status = timer(state);
        status.load_state = load_state.map(str::to_owned);
        status
    }

    #[test]
    fn windows_scan_schedule_summary_and_diagnostics_require_a_verified_registered_task() {
        let ready = task_status("ready", Some("registered"));
        let line = scan_schedule_line(&ready, true);
        assert!(line.contains("Task Scheduler task: ready"));
        assert!(line.contains("owner, access rights, principal and read-only action verified"));
        let diagnostic = scan_schedule_diagnostic(&ready, true).unwrap();
        assert!(diagnostic.contains("registered and verified"));
        assert!(diagnostic.contains("upkit schedule list"));

        let disabled = task_status("disabled", Some("registered"));
        assert!(verified_windows_scan_task(&disabled));
        assert!(scan_schedule_diagnostic(&disabled, true).is_some());

        let absent = task_status("not_found", Some("not-found"));
        assert_eq!(
            scan_schedule_line(&absent, true),
            "Upkit Task Scheduler task: not found"
        );
        assert!(scan_schedule_diagnostic(&absent, true).is_none());

        let unavailable = task_status("unavailable", None);
        assert!(scan_schedule_line(&unavailable, true).contains("could not be verified"));
        let diagnostic = scan_schedule_diagnostic(&unavailable, true).unwrap();
        assert!(diagnostic.contains("could not be verified"));
        assert!(diagnostic.contains("service is available"));
        assert!(diagnostic.contains("current user can inspect"));
        assert!(diagnostic.contains("upkit schedule list"));
        assert!(!diagnostic.contains("registered and verified"));

        let unverified_ready = task_status("ready", None);
        assert!(!verified_windows_scan_task(&unverified_ready));
        assert!(scan_schedule_line(&unverified_ready, true).contains("could not be verified"));

        assert!(
            scan_schedule_line(&ready, false)
                .contains("name only; ownership and action unverified")
        );
        assert!(
            scan_schedule_diagnostic(&timer("active"), false)
                .unwrap()
                .contains("appears active by name")
        );

        let unavailable = scan_schedule_diagnostic(&timer("unavailable"), false).unwrap();
        assert!(unavailable.contains("schedule manager could not be queried"));
        assert!(unavailable.contains("check that it is available"));
        assert!(unavailable.contains("current user can inspect"));
        assert!(unavailable.contains("upkit schedule list"));
    }

    #[test]
    fn skipped_scheduler_probes_explain_the_unknown_state_and_give_read_only_commands() {
        let dry_run = timer_status(
            "skipped",
            "dry-run skips platform scheduler queries; timer state was not inspected",
        );
        let diagnostic = skipped_probe_diagnostic(
            "Upkit scan schedule",
            &dry_run,
            "upkit --non-interactive schedule list",
        )
        .unwrap();
        assert!(diagnostic.contains("unknown"));
        assert!(diagnostic.contains("skipped does not mean absent"));
        assert!(diagnostic.contains("upkit --non-interactive schedule list"));
        assert!(diagnostic.contains("scheduler is safe to query"));

        let offline = timer_status(
            "skipped",
            "offline mode skips systemd queries; manager endpoints may be remote",
        );
        assert!(
            skipped_probe_diagnostic("System TRIM timer", &offline, "systemctl show fstrim.timer")
                .unwrap()
                .contains("offline mode skipped")
        );
        assert!(skipped_probe_diagnostic("timer", &timer("active"), "read-only command").is_none());
        assert!(
            skipped_probe_diagnostic("timer", &timer("skipped"), "read-only command").is_none()
        );
    }

    #[test]
    fn recommendations_are_specific_and_never_echo_container_endpoints() {
        let capabilities = Capabilities {
            cancelled: false,
            cache_removal_probe: "openat2_available",
            cache_removal_note: "fixture",
            fstrim_available: true,
            fstrim_timer: timer("active"),
            scan_timer: timer("active"),
            installation_integrity: InstallationIntegrityStatus::new(true),
            containers: vec![ContainerCapability {
                engine: "docker",
                executable_found: true,
                endpoint: "network_endpoint_unverified",
                connection: "not_checked",
            }],
            actionable_diagnostics: Vec::new(),
        };
        let diagnostics = actionable_diagnostics(&capabilities).join("\n");

        #[cfg(target_os = "linux")]
        assert!(diagnostics.contains("OS schedule"));
        assert!(diagnostics.contains("upkit schedule list"));
        assert!(diagnostics.contains("appears active by name"));
        assert!(!diagnostics.contains("systemd upkit-scan.timer"));
        assert!(diagnostics.contains("verify its target"));
        assert!(!diagnostics.contains("tcp://"));
    }

    #[test]
    fn unsupported_installation_integrity_is_unknown_and_has_a_safe_next_step() {
        let capabilities = Capabilities {
            cancelled: false,
            cache_removal_probe: "unsupported_platform",
            cache_removal_note: "fixture",
            fstrim_available: false,
            fstrim_timer: timer("unsupported"),
            scan_timer: timer("not_found"),
            containers: Vec::new(),
            installation_integrity: InstallationIntegrityStatus::new(false),
            actionable_diagnostics: Vec::new(),
        };

        let diagnostics = actionable_diagnostics(&capabilities).join("\n");
        assert!(diagnostics.contains("integrity remains unknown"));
        assert!(diagnostics.contains("provider's verification guidance"));
        assert!(!diagnostics.contains("verified"));
    }

    #[test]
    fn empty_goroot_is_ignored_but_any_nonempty_value_is_an_override() {
        use std::ffi::OsStr;

        assert!(!go_goroot_override_is_set(None));
        assert!(!go_goroot_override_is_set(Some(OsStr::new(""))));
        assert!(go_goroot_override_is_set(Some(OsStr::new("/custom/go"))));
    }

    #[test]
    fn unavailable_capabilities_include_safe_next_steps() {
        let capabilities = Capabilities {
            cancelled: false,
            cache_removal_probe: "openat2_unavailable_or_denied",
            cache_removal_note: "fixture",
            fstrim_available: false,
            fstrim_timer: timer("not_found"),
            scan_timer: timer("not_found"),
            installation_integrity: InstallationIntegrityStatus::new(true),
            containers: vec![ContainerCapability {
                engine: "podman",
                executable_found: false,
                endpoint: "no_environment_override_detected",
                connection: "not_checked",
            }],
            actionable_diagnostics: Vec::new(),
        };
        let diagnostics = actionable_diagnostics(&capabilities).join("\n");

        assert!(diagnostics.contains("kernel support"));
        #[cfg(target_os = "linux")]
        assert!(diagnostics.contains("OS-provided timer"));
        assert!(diagnostics.contains("podman was not found"));
    }

    #[cfg(unix)]
    fn sealed_fixture(home: &Path, tool: crate::ToolKind, payload: &[u8]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let root = home.join(tool.as_str());
        crate::infrastructure::ensure_tool_root(&root).unwrap();
        let stage = crate::infrastructure::new_install_stage(&root).unwrap();
        let payload_path = stage.path().join("payload");
        std::fs::write(&payload_path, payload).unwrap();
        std::fs::set_permissions(payload_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        crate::installation_identity::seal(&root, &stage, tool, "fixture").unwrap();
        stage.keep()
    }

    #[cfg(unix)]
    #[test]
    fn installation_integrity_keeps_legacy_unknown_and_does_not_call_seals_health() {
        let home = tempfile::tempdir().unwrap();
        let sealed = sealed_fixture(home.path(), crate::ToolKind::Go, b"fixture");
        let legacy = home.path().join("node/old-version");
        std::fs::create_dir_all(&legacy).unwrap();

        let status = installation_integrity(home.path(), &AtomicBool::new(false));

        assert_eq!(status.verified_seals, 1);
        assert_eq!(status.legacy_unsealed, 1);
        assert!(status.complete);
        assert!(status.line().contains("1 verified"));
        assert!(status.line().contains("1 legacy/unsealed unknown"));
        assert!(
            status
                .line()
                .contains("does not test whether a tool runs or works")
        );
        assert!(status.line().find("fixture").is_none());
        assert_eq!(std::fs::read(sealed.join("payload")).unwrap(), b"fixture");
    }

    #[cfg(unix)]
    #[test]
    fn installation_integrity_reports_tampering_and_enforces_an_aggregate_byte_budget() {
        let home = tempfile::tempdir().unwrap();
        let first = sealed_fixture(home.path(), crate::ToolKind::Go, b"first");
        std::fs::write(first.join("payload"), b"modified").unwrap();

        let tampered = installation_integrity(home.path(), &AtomicBool::new(false));
        assert_eq!(tampered.unknown_seals, 1);
        assert_eq!(tampered.verified_seals, 0);
        assert!(!tampered.complete);

        let budget_home = tempfile::tempdir().unwrap();
        sealed_fixture(budget_home.path(), crate::ToolKind::Go, b"first");
        let second = sealed_fixture(budget_home.path(), crate::ToolKind::Node, b"second");
        let limits = IntegrityLimits {
            bytes: 5,
            ..IntegrityLimits::DOCTOR
        };
        let status =
            installation_integrity_with_limits(budget_home.path(), &AtomicBool::new(false), limits);
        assert_eq!(status.unknown_seals, 0);
        assert_eq!(status.verified_seals, 1);
        assert_eq!(status.skipped_seals, 1);
        assert!(status.truncated);
        assert!(!status.complete);
        let diagnostic = Capabilities {
            cancelled: false,
            cache_removal_probe: "fixture",
            cache_removal_note: "fixture",
            fstrim_available: true,
            fstrim_timer: timer("not_found"),
            scan_timer: timer("not_found"),
            containers: Vec::new(),
            installation_integrity: status,
            actionable_diagnostics: Vec::new(),
        }
        .installation_diagnostic()
        .unwrap();
        assert!(diagnostic.contains("verification limits"));
        assert_eq!(std::fs::read(second.join("payload")).unwrap(), b"second");
    }

    #[cfg(unix)]
    fn nested_sealed_fixture(home: &Path, depth: usize) {
        use std::os::unix::fs::PermissionsExt;

        let root = home.join(crate::ToolKind::Go.as_str());
        crate::infrastructure::ensure_tool_root(&root).unwrap();
        let stage = crate::infrastructure::new_install_stage(&root).unwrap();
        let mut nested = stage.path().to_path_buf();
        for _ in 0..depth {
            nested.push("nested");
            std::fs::create_dir(&nested).unwrap();
            std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let payload = nested.join("payload");
        std::fs::write(&payload, b"fixture").unwrap();
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o644)).unwrap();
        crate::installation_identity::seal(&root, &stage, crate::ToolKind::Go, "fixture").unwrap();
        let _ = stage.keep();
    }

    #[cfg(unix)]
    #[test]
    fn installation_integrity_marks_depth_and_entry_limits_as_truncated() {
        use std::os::unix::fs::PermissionsExt;

        let depth_home = tempfile::tempdir().unwrap();
        nested_sealed_fixture(depth_home.path(), 2);
        let depth_limits = IntegrityLimits {
            depth: 1,
            ..IntegrityLimits::DOCTOR
        };
        let depth_status = installation_integrity_with_limits(
            depth_home.path(),
            &AtomicBool::new(false),
            depth_limits,
        );
        assert_eq!(depth_status.unknown_seals, 1);
        assert!(depth_status.truncated);
        assert!(!depth_status.complete);

        let entries_home = tempfile::tempdir().unwrap();
        let root = entries_home.path().join(crate::ToolKind::Go.as_str());
        crate::infrastructure::ensure_tool_root(&root).unwrap();
        let stage = crate::infrastructure::new_install_stage(&root).unwrap();
        for name in ["first", "second"] {
            let payload = stage.path().join(name);
            std::fs::write(&payload, b"fixture").unwrap();
            std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        crate::installation_identity::seal(&root, &stage, crate::ToolKind::Go, "fixture").unwrap();
        let _ = stage.keep();

        let entry_limits = IntegrityLimits {
            entries: 1,
            ..IntegrityLimits::DOCTOR
        };
        let entry_status = installation_integrity_with_limits(
            entries_home.path(),
            &AtomicBool::new(false),
            entry_limits,
        );
        assert_eq!(entry_status.unknown_seals, 1);
        assert!(entry_status.truncated);
        assert!(!entry_status.complete);
    }

    #[cfg(unix)]
    #[test]
    fn installation_integrity_rejects_linked_roots_and_cancels_without_traversing() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("install-secret")).unwrap();
        std::fs::write(
            outside.path().join("install-secret/.upkit-install.json"),
            b"fixture",
        )
        .unwrap();
        symlink(outside.path(), home.path().join("go")).unwrap();

        let linked = installation_integrity(home.path(), &AtomicBool::new(false));
        assert_eq!(linked.unknown_roots, 1);
        assert_eq!(linked.verified_seals, 0);
        assert_eq!(linked.unknown_seals, 0);

        let cancel = AtomicBool::new(true);
        let cancelled = installation_integrity(home.path(), &cancel);
        assert!(cancelled.cancelled);
        assert!(!cancelled.complete);
        assert_eq!(cancelled.roots_inspected, 0);
    }

    #[cfg(unix)]
    #[test]
    fn installation_integrity_applies_root_and_seal_count_caps() {
        let home = tempfile::tempdir().unwrap();
        sealed_fixture(home.path(), crate::ToolKind::Go, b"one");
        sealed_fixture(home.path(), crate::ToolKind::Node, b"two");
        let root_limits = IntegrityLimits {
            seals: 1,
            root_entries: 0,
            ..IntegrityLimits::DOCTOR
        };

        let root_limited =
            installation_integrity_with_limits(home.path(), &AtomicBool::new(false), root_limits);

        assert!(root_limited.truncated);
        assert!(!root_limited.complete);
        assert_eq!(root_limited.verified_seals, 0);

        let seal_limits = IntegrityLimits {
            seals: 1,
            ..IntegrityLimits::DOCTOR
        };
        let seal_limited =
            installation_integrity_with_limits(home.path(), &AtomicBool::new(false), seal_limits);
        assert!(seal_limited.truncated);
        assert!(!seal_limited.complete);
        assert_eq!(seal_limited.verified_seals, 1);
        assert_eq!(seal_limited.skipped_seals, 1);
    }

    #[cfg(unix)]
    #[test]
    fn cancelled_doctor_skips_remaining_capability_probes() {
        let home = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(true);

        let report = capabilities(home.path(), false, &cancel);

        assert!(report.cancelled);
        assert!(report.installation_integrity.cancelled);
        assert!(!report.installation_integrity.complete);
        assert_eq!(report.cache_removal_probe, "skipped_cancelled");
        assert!(!report.fstrim_available);
        assert!(report.containers.is_empty());
        assert!(report.lines().join("\n").contains("were not started"));
    }
}
