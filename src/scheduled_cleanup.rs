//! Opt-in scheduled removal of reviewed workspace artifacts and Python bytecode.
#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{Result, bail};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[derive(Debug, Serialize)]
pub struct Item {
    // Scheduled output may be copied into a system journal.
    #[serde(skip_serializing)]
    pub file: PathBuf,
    pub status: &'static str,
    #[serde(skip_serializing)]
    pub detail: Option<String>,
    #[serde(skip_serializing)]
    pub history_warning: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub candidates: usize,
    pub inspected: usize,
    pub items: Vec<Item>,
    pub complete: bool,
    pub dry_run: bool,
    pub warnings: Vec<String>,
}

#[cfg(target_os = "linux")]
pub(crate) fn redacted_bytecode_report(report: &Report) -> serde_json::Value {
    serde_json::json!({
        "candidates": report.candidates,
        "inspected": report.inspected,
        "complete": report.complete,
        "dry_run": report.dry_run,
        "items": report.items.iter().enumerate().map(|(index, item)| serde_json::json!({
            "ordinal": index + 1,
            "status": item.status,
        })).collect::<Vec<_>>(),
        "warnings": &report.warnings,
    })
}

#[derive(Debug, Serialize)]
pub struct ArtifactItem {
    pub ordinal: usize,
    pub ecosystem: &'static str,
    pub status: &'static str,
    pub logical_bytes: Option<u64>,
    pub detail: Option<String>,
    pub history_warning: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ArtifactReport {
    pub candidates: usize,
    pub selected: usize,
    pub inspected: usize,
    pub items: Vec<ArtifactItem>,
    pub complete: bool,
    pub cancelled: bool,
    pub dry_run: bool,
    pub warnings: Vec<String>,
    /// Allows only the combined command's bytecode leg or dry-run preview.
    #[serde(skip_serializing)]
    #[cfg(target_os = "linux")]
    pub(crate) continue_with_bytecode: bool,
}

// shortcut: inspect at most 32 files per run; paginate policy execution before raising the limit.
#[cfg(target_os = "linux")]
const MAX_INSPECTIONS: usize = 32;

#[cfg(target_os = "linux")]
const BYTECODE_DRY_RUN_WARNING: &str = "During --dry-run, inspected counts only filenames enumerated from eligible caches; bytecode, source, process, and Git safety checks were skipped.";

// shortcut: remove at most 8 artifact directories per run; raise only with pagination and history capacity.
#[cfg(target_os = "linux")]
const MAX_ARTIFACTS_PER_RUN: usize = 8;

#[cfg(target_os = "linux")]
fn rotate_caches<T>(items: &mut [T], week: u64) {
    // shortcut: rotation changes weekly; use a persisted cursor for per-run progress.
    if items.len() > 1 {
        let start = (u128::from(week) % items.len() as u128) as usize;
        items.rotate_left(start);
    }
}

#[cfg(target_os = "linux")]
fn rotate_files<T>(items: &mut [T], week: u64, cache_count: usize) {
    if items.len() > MAX_INSPECTIONS {
        let cache_cycle = u128::from(week) / cache_count.max(1) as u128;
        let start = ((cache_cycle * MAX_INSPECTIONS as u128) % items.len() as u128) as usize;
        items.rotate_left(start);
    }
}

#[cfg(target_os = "linux")]
pub fn run(
    home: &Path,
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    token: &str,
    dry_run: bool,
    cancel: &AtomicBool,
) -> Result<Report> {
    use std::sync::atomic::Ordering;

    let scope = crate::schedule::verified_bytecode_scope(executable, roots, exclusions, token)?;
    let week = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock predates the Unix epoch")?
        .as_secs()
        / (7 * 24 * 60 * 60);
    let scan = crate::sweep::scan_with_policy(
        &scope.roots,
        &scope.exclusions,
        scope.older_than_seconds.map(std::time::Duration::from_secs),
        scope.enabled.as_deref(),
        cancel,
        |_| {},
    )?;
    if !scan.is_complete() {
        bail!("scheduled cleanup inventory is incomplete; nothing was removed");
    }
    let mut caches = scan
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.ecosystem == "python"
                && candidate
                    .target
                    .file_name()
                    .is_some_and(|name| name == "__pycache__")
        })
        .map(|candidate| candidate.target.clone())
        .collect::<Vec<_>>();
    caches.sort();
    caches.dedup();
    let cache_count = caches.len();
    rotate_caches(&mut caches, week);
    let mut report = Report {
        candidates: caches.len(),
        inspected: 0,
        items: vec![],
        complete: true,
        dry_run,
        warnings: vec!["Python bytecode header validation cannot prove the bytecode body matches its source; concurrent filesystem or process changes can race checks. Reclaimed space is unknown.".into()],
    };
    let mut plans = Vec::new();
    if caches.len() > MAX_INSPECTIONS {
        report.complete = false;
        report
            .warnings
            .push("Per-run cache limit reached; remaining caches were not inspected.".into());
    }
    for (cache_index, cache) in caches.into_iter().take(MAX_INSPECTIONS).enumerate() {
        if cancel.load(Ordering::Relaxed) {
            bail!("scheduled cleanup cancelled before removal");
        }
        let mut remaining_files = false;
        let mut files = crate::bytecode::list(&cache, cancel)?;
        rotate_files(&mut files, week, cache_count);
        for file in files {
            if report.inspected == MAX_INSPECTIONS {
                remaining_files = true;
                break;
            }
            report.inspected += 1;
            if dry_run {
                report.complete = false;
                if !report
                    .warnings
                    .iter()
                    .any(|warning| warning == BYTECODE_DRY_RUN_WARNING)
                {
                    report.warnings.push(BYTECODE_DRY_RUN_WARNING.into());
                }
                report.items.push(Item {
                    file,
                    status: "skipped_unverified",
                    detail: Some(
                        "Listed only; bytecode, source, process, and Git checks were skipped, so no safety plan was created.".into(),
                    ),
                    history_warning: None,
                });
                continue;
            }
            match crate::bytecode::preview(&scope, &file, cancel) {
                Ok(plan) if plan.invalidation != "hash-unchecked" => {
                    plans.push(plan);
                    // Removing one file changes the cache directory's age; review at most one per cache.
                    break;
                }
                Ok(_) => report.items.push(Item {
                    file,
                    status: "skipped_unchecked_hash",
                    detail: Some(
                        "Unchecked hash bytecode can run code different from its source.".into(),
                    ),
                    history_warning: None,
                }),
                Err(error) => {
                    report.complete = false;
                    report.items.push(Item {
                        file,
                        status: "skipped_unverified",
                        detail: Some(format!("{error:#}")),
                        history_warning: None,
                    });
                }
            }
        }
        if report.inspected == MAX_INSPECTIONS && (remaining_files || cache_index + 1 < cache_count)
        {
            report.complete = false;
            if remaining_files || cache_count <= MAX_INSPECTIONS {
                report.warnings.push(
                    "Per-run inspection limit reached; remaining files may not have been inspected."
                        .into(),
                );
            }
            break;
        }
    }
    let guard = || {
        let current =
            crate::schedule::verified_bytecode_scope(executable, roots, exclusions, token)?;
        if current != scope {
            bail!("scheduled cleanup policy changed");
        }
        Ok(())
    };
    let mut stopped = false;
    for plan in plans {
        if stopped || cancel.load(Ordering::Relaxed) {
            report.complete = false;
            report.items.push(Item {
                file: plan.file,
                status: "not_attempted",
                detail: None,
                history_warning: None,
            });
            continue;
        }
        if let Err(error) = guard() {
            stopped = true;
            report.complete = false;
            report.items.push(Item {
                file: plan.file,
                status: "not_attempted",
                detail: Some(format!("{error:#}")),
                history_warning: None,
            });
            continue;
        }
        if dry_run {
            report.items.push(Item {
                file: plan.file,
                status: "previewed",
                detail: None,
                history_warning: None,
            });
            continue;
        }
        let performed =
            crate::reports::perform_scheduled_bytecode_removal(home, &plan, cancel, &guard);
        if performed.history_warning.is_some() {
            stopped = true;
            report.complete = false;
        }
        let (status, detail) = match performed.result {
            Ok("verified_absent") => ("verified_absent", None),
            Ok(other) => {
                stopped = true;
                report.complete = false;
                ("unverified", Some(other.into()))
            }
            Err(error) => {
                stopped = true;
                report.complete = false;
                ("failed", Some(error))
            }
        };
        report.items.push(Item {
            file: plan.file,
            status,
            detail,
            history_warning: performed.history_warning,
        });
    }
    Ok(report)
}

#[cfg(target_os = "linux")]
fn scheduled_artifact_target(ecosystem: &str, target: &Path, classification: &str) -> bool {
    if classification != "rebuildable" {
        return false;
    }
    matches!(
        (ecosystem, target.file_name().and_then(|name| name.to_str())),
        ("maven", Some("target"))
            | ("zig", Some(".zig-cache"))
            | ("dart", Some(".dart_tool"))
            | ("python", Some(".pytest_cache" | ".mypy_cache"))
    )
}

#[cfg(target_os = "linux")]
fn scheduled_artifact_candidate(candidate: &crate::sweep::Candidate) -> bool {
    scheduled_artifact_target(
        candidate.ecosystem,
        &candidate.target,
        candidate.classification,
    )
}

#[cfg(target_os = "linux")]
fn rotate_artifact_targets(targets: &mut [PathBuf], run_index: u64) {
    if !targets.is_empty() {
        targets.rotate_left((run_index % targets.len() as u64) as usize);
    }
}

#[cfg(target_os = "linux")]
fn select_artifact_targets(mut targets: Vec<PathBuf>, run_index: u64) -> (usize, Vec<PathBuf>) {
    targets.sort();
    targets.dedup();
    let candidates = targets.len();
    rotate_artifact_targets(&mut targets, run_index);
    targets.truncate(MAX_ARTIFACTS_PER_RUN);
    (candidates, targets)
}

#[cfg(target_os = "linux")]
fn scheduled_artifact_run_index(history: &crate::reports::History) -> u64 {
    history
        .records
        .iter()
        .filter(|record| record.operation == "scheduled_artifact_cleanup")
        .count() as u64
}

#[cfg(target_os = "linux")]
pub fn run_artifact_cleanup(
    home: &Path,
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    token: &str,
    dry_run: bool,
    cancel: &AtomicBool,
) -> Result<ArtifactReport> {
    let scope = crate::schedule::verified_artifact_scope(executable, roots, exclusions, token)?;
    let guard = || {
        let current =
            crate::schedule::verified_artifact_scope(executable, roots, exclusions, token)?;
        if current != scope {
            bail!("scheduled artifact cleanup policy changed");
        }
        Ok(())
    };
    run_artifact_cleanup_with_guard(home, &scope, dry_run, cancel, &guard)
}

#[cfg(target_os = "linux")]
fn run_artifact_cleanup_with_guard(
    home: &Path,
    scope: &crate::sweep::Scope,
    dry_run: bool,
    cancel: &AtomicBool,
    guard: &dyn Fn() -> Result<()>,
) -> Result<ArtifactReport> {
    use std::sync::atomic::Ordering;

    guard()?;
    let scan = crate::sweep::scan_with_policy(
        &scope.roots,
        &scope.exclusions,
        scope.older_than_seconds.map(std::time::Duration::from_secs),
        scope.enabled.as_deref(),
        cancel,
        |_| {},
    )?;
    let mut targets = scan
        .candidates
        .iter()
        .filter(|candidate| scheduled_artifact_candidate(candidate))
        .map(|candidate| candidate.target.clone())
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    let candidates = targets.len();
    let mut report = ArtifactReport {
        candidates,
        selected: 0,
        inspected: 0,
        items: Vec::new(),
        complete: scan.is_complete(),
        cancelled: scan.cancelled,
        dry_run,
        warnings: Vec::new(),
        continue_with_bytecode: false,
    };
    if !report.complete {
        report
            .warnings
            .push("Artifact inventory was incomplete; no directories were removed.".into());
        return Ok(report);
    }
    if targets.is_empty() {
        report.continue_with_bytecode = true;
        return Ok(report);
    }
    let history = match crate::reports::read(home) {
        Ok(history) => Some(history),
        Err(_) if dry_run => None,
        Err(error) => return Err(error),
    };
    let run_index = history.as_ref().map_or(0, scheduled_artifact_run_index);
    let (_, targets) = select_artifact_targets(targets, run_index);
    report.selected = targets.len();
    if candidates > MAX_ARTIFACTS_PER_RUN {
        report.complete = false;
        report.warnings.push(format!(
            "The per-run limit is {MAX_ARTIFACTS_PER_RUN}; remaining eligible directories were deferred."
        ));
    }
    if cancel.load(Ordering::Relaxed) {
        report.cancelled = true;
        report.complete = false;
        report
            .warnings
            .push("Scheduled artifact cleanup was cancelled before preview.".into());
        return Ok(report);
    }
    if dry_run {
        if crate::sweep::validate_preview_selection(&scan, &targets, cancel).is_err() {
            report.complete = false;
            report.warnings.push(
                "Dry-run selection could not be validated; no removal plan was created.".into(),
            );
            return Ok(report);
        }
        report.inspected = targets.len();
        report.items = targets
            .into_iter()
            .enumerate()
            .map(|(index, _)| ArtifactItem {
                ordinal: index + 1,
                ecosystem: "scheduled artifact",
                status: "skipped_unverified",
                logical_bytes: None,
                detail: Some(
                    "Listed only; Git, process, identity, and deletion checks were skipped.".into(),
                ),
                history_warning: None,
            })
            .collect();
        report.complete = false;
        report.continue_with_bytecode = true;
        report.warnings.push(
            "Dry-run only lists eligible paths; it creates no removal plan and performs no deletion.".into(),
        );
        return Ok(report);
    }
    let plan = match crate::artifact_cleanup::preview_batch_from_scan(scope, scan, &targets, cancel)
    {
        Ok(plan) => plan,
        Err(_) => {
            report.complete = false;
            report.warnings.push(
                "Artifact preview failed; no directories were removed. Review the current workspace and process state.".into(),
            );
            report.items = targets
                .into_iter()
                .enumerate()
                .map(|(index, _)| ArtifactItem {
                    ordinal: index + 1,
                    ecosystem: "scheduled artifact",
                    status: "not_attempted_unverified",
                    logical_bytes: None,
                    detail: Some("A required safety check was unavailable or failed.".into()),
                    history_warning: None,
                })
                .collect();
            return Ok(report);
        }
    };
    if plan
        .items
        .iter()
        .any(|item| !scheduled_artifact_target(item.ecosystem, &item.target, item.classification))
    {
        bail!("scheduled artifact plan exceeded its rebuildable allowlist");
    }
    if !crate::reports::history_targets_are_safe(
        home,
        &plan
            .items
            .iter()
            .map(|item| item.target.clone())
            .collect::<Vec<_>>(),
    ) {
        report.complete = false;
        report.warnings.push(
            "Local history overlaps a scheduled artifact; no directories were removed.".into(),
        );
        return Ok(report);
    }
    report.inspected = plan.items.len();
    for (index, item) in plan.items.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            report.complete = false;
            report.items.extend(
                plan.items[index..]
                    .iter()
                    .enumerate()
                    .map(|(offset, item)| ArtifactItem {
                        ordinal: index + offset + 1,
                        ecosystem: item.ecosystem,
                        status: "not_attempted_cancelled",
                        logical_bytes: Some(item.logical_bytes),
                        detail: None,
                        history_warning: None,
                    }),
            );
            break;
        }
        if guard().is_err() {
            report.complete = false;
            report.warnings.push(
                "The scheduled scope or policy changed; later targets were not attempted.".into(),
            );
            report.items.extend(
                plan.items[index..]
                    .iter()
                    .enumerate()
                    .map(|(offset, item)| ArtifactItem {
                        ordinal: index + offset + 1,
                        ecosystem: item.ecosystem,
                        status: "not_attempted_policy_changed",
                        logical_bytes: Some(item.logical_bytes),
                        detail: None,
                        history_warning: None,
                    }),
            );
            break;
        }
        let performed =
            crate::reports::perform_scheduled_artifact_removal(home, item, cancel, guard);
        let history_warning = performed
            .history_warning
            .map(|_| "history write failed".into());
        match performed.result {
            Ok("verified_absent") if history_warning.is_none() => report.items.push(ArtifactItem {
                ordinal: index + 1,
                ecosystem: item.ecosystem,
                status: "verified_absent",
                logical_bytes: Some(item.logical_bytes),
                detail: None,
                history_warning,
            }),
            Ok(_) => {
                report.complete = false;
                report.items.push(ArtifactItem {
                    ordinal: index + 1,
                    ecosystem: item.ecosystem,
                    status: "unverified",
                    logical_bytes: Some(item.logical_bytes),
                    detail: Some("Removal outcome or history could not be verified.".into()),
                    history_warning,
                });
                report
                    .items
                    .extend(
                        plan.items[index + 1..]
                            .iter()
                            .enumerate()
                            .map(|(offset, item)| ArtifactItem {
                                ordinal: index + offset + 2,
                                ecosystem: item.ecosystem,
                                status: "not_attempted_after_failure",
                                logical_bytes: Some(item.logical_bytes),
                                detail: None,
                                history_warning: None,
                            }),
                    );
                break;
            }
            Err(_) => {
                report.complete = false;
                report.items.push(ArtifactItem {
                    ordinal: index + 1,
                    ecosystem: item.ecosystem,
                    status: "failed",
                    logical_bytes: Some(item.logical_bytes),
                    detail: Some("Removal failed; later targets were not attempted.".into()),
                    history_warning,
                });
                report
                    .items
                    .extend(
                        plan.items[index + 1..]
                            .iter()
                            .enumerate()
                            .map(|(offset, item)| ArtifactItem {
                                ordinal: index + offset + 2,
                                ecosystem: item.ecosystem,
                                status: "not_attempted_after_failure",
                                logical_bytes: Some(item.logical_bytes),
                                detail: None,
                                history_warning: None,
                            }),
                    );
                break;
            }
        }
    }
    report.continue_with_bytecode = !report.cancelled
        && report.items.len() == report.selected
        && report
            .items
            .iter()
            .all(|item| item.status == "verified_absent" && item.history_warning.is_none());
    Ok(report)
}

#[cfg(not(target_os = "linux"))]
pub fn run_artifact_cleanup(
    _: &Path,
    _: &Path,
    _: &[PathBuf],
    _: &[PathBuf],
    _: &str,
    _: bool,
    _: &AtomicBool,
) -> Result<ArtifactReport> {
    bail!("scheduled artifact cleanup is supported only on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn run(
    _: &Path,
    _: &Path,
    _: &[PathBuf],
    _: &[PathBuf],
    _: &str,
    _: bool,
    _: &AtomicBool,
) -> Result<Report> {
    bail!("scheduled bytecode cleanup is supported only on Linux")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{
        MAX_ARTIFACTS_PER_RUN, MAX_INSPECTIONS, rotate_caches, rotate_files,
        run_artifact_cleanup_with_guard, scheduled_artifact_run_index, scheduled_artifact_target,
        select_artifact_targets,
    };
    use anyhow::bail;
    use std::{
        fs,
        io::Read,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::Command,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    fn run_in_private_directory(test: &str) -> bool {
        const CHILD: &str = "UPKIT_TEST_PRIVATE_SCHEDULE_CASE";
        if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new(test)) {
            return false;
        }
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .current_dir(directory.path())
            .env(CHILD, test);
        if Path::new("/usr/bin/git").is_file() || Path::new("/bin/git").is_file() {
            command.env("PATH", "/usr/bin:/bin");
        }
        let output = command.output().unwrap();
        eprint!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(output.status.success(), "private schedule fixture failed");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "private schedule fixture did not run exactly one test"
        );
        true
    }

    macro_rules! private_git_test {
        ($name:ident) => {
            if run_in_private_directory(concat!("scheduled_cleanup::tests::", stringify!($name))) {
                return;
            }
        };
    }

    struct ArtifactFixture {
        _directory: tempfile::TempDir,
        root: PathBuf,
        projects: Vec<PathBuf>,
        home: PathBuf,
    }

    impl ArtifactFixture {
        fn new(project_count: usize) -> Option<Self> {
            let git = which::which("git").ok()?.canonicalize().ok()?;
            let mut file = fs::File::open(&git).ok()?;
            let mut magic = [0; 4];
            (file.read_exact(&mut magic).is_ok() && magic == *b"\x7fELF").then_some(())?;

            let directory = tempfile::tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let root = directory.path().join("workspace");
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let mut projects = Vec::new();
            for index in 0..project_count {
                let project = root.join(format!("project-{index:02}"));
                let target_dir = project.join("target");
                let target = target_dir.join("debug");
                fs::create_dir_all(&target).unwrap();
                for path in [project.as_path(), target_dir.as_path(), target.as_path()] {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
                }
                fs::write(project.join("pom.xml"), "<project></project>").unwrap();
                fs::write(project.join(".gitignore"), "target/\n").unwrap();
                fs::write(target.join("output"), "rebuildable fixture").unwrap();
                for name in ["pom.xml", ".gitignore"] {
                    fs::set_permissions(project.join(name), fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                fs::set_permissions(target.join("output"), fs::Permissions::from_mode(0o600))
                    .unwrap();

                let git_command = |args: &[&str]| {
                    let output = Command::new(&git)
                        .args([
                            "-c",
                            "user.name=Fixture",
                            "-c",
                            "user.email=fixture@example.invalid",
                            "-C",
                        ])
                        .arg(&project)
                        .args(args)
                        .env("GIT_CONFIG_NOSYSTEM", "1")
                        .env("GIT_CONFIG_GLOBAL", "/dev/null")
                        .output()
                        .unwrap();
                    assert!(
                        output.status.success(),
                        "{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                };
                git_command(&["init", "-q"]);
                git_command(&["add", "pom.xml", ".gitignore"]);
                git_command(&["commit", "-qm", "fixture"]);
                projects.push(project);
            }
            let home = directory.path().join("home");
            fs::create_dir(&home).unwrap();
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
            Some(Self {
                _directory: directory,
                root,
                projects,
                home,
            })
        }

        fn scope(&self) -> crate::sweep::Scope {
            crate::sweep::Scope {
                roots: vec![self.root.clone()],
                exclusions: Vec::new(),
                older_than_seconds: None,
                enabled: Some(vec![crate::sweep::Ecosystem::Maven]),
            }
        }

        fn trusted_git_available(&self) -> bool {
            crate::git_index::available(&AtomicBool::new(false), std::slice::from_ref(&self.root))
                .ok()
                .flatten()
                .is_some()
        }
    }

    fn fixture_or_skip(project_count: usize) -> Option<ArtifactFixture> {
        let fixture = ArtifactFixture::new(project_count);
        if fixture.is_none() {
            eprintln!("SKIP: trusted ELF Git is unavailable");
        }
        fixture
    }

    #[test]
    fn scheduled_artifact_allowlist_accepts_only_rebuildable_targets() {
        for (ecosystem, name) in [
            ("maven", "target"),
            ("zig", ".zig-cache"),
            ("dart", ".dart_tool"),
            ("python", ".pytest_cache"),
            ("python", ".mypy_cache"),
        ] {
            assert!(scheduled_artifact_target(
                ecosystem,
                Path::new("/workspace").join(name).as_path(),
                "rebuildable"
            ));
        }
        for (ecosystem, name, classification) in [
            ("go", "target", "rebuildable"),
            ("cargo", "target", "rebuildable"),
            ("cargo", "target", "review"),
            ("python", "__pycache__", "rebuildable"),
            ("python", ".tox", "rebuildable"),
        ] {
            assert!(!scheduled_artifact_target(
                ecosystem,
                Path::new("/workspace").join(name).as_path(),
                classification,
            ));
        }
    }

    #[test]
    fn scheduled_artifact_report_serialization_does_not_include_workspace_paths() {
        let report = super::ArtifactReport {
            candidates: 1,
            selected: 1,
            inspected: 1,
            items: vec![super::ArtifactItem {
                ordinal: 1,
                ecosystem: "cargo",
                status: "verified_absent",
                logical_bytes: Some(12),
                detail: None,
                history_warning: None,
            }],
            complete: true,
            cancelled: false,
            dry_run: false,
            warnings: vec![],
            continue_with_bytecode: true,
        };
        let output = serde_json::to_string(&report).unwrap();
        assert!(output.contains("\"ordinal\":1"));
        assert!(!output.contains("workspace"));
        assert!(!output.contains("target"));
    }

    #[test]
    fn scheduled_artifact_real_run_rejects_invalid_scope_before_removal() {
        let Some(fixture) = fixture_or_skip(1) else {
            return;
        };
        let target = fixture.projects[0].join("target");
        let result = super::run_artifact_cleanup(
            &fixture.home,
            Path::new("/missing/upkit"),
            std::slice::from_ref(&fixture.root),
            &[],
            "invalid-token",
            false,
            &AtomicBool::new(false),
        );
        assert!(result.is_err());
        assert!(target.exists());
    }

    #[test]
    fn scheduled_artifact_dry_run_still_accepts_a_v4_policy() {
        let Some(fixture) = fixture_or_skip(1) else {
            return;
        };
        let config = fixture.home.join("settings.toml");
        fs::write(
            &config,
            format!(
                "version = 1\nworkspace_roots = ['{}']\nartifact_retention = '30d'\nenabled_ecosystems = ['maven']\nscheduled_artifact_cleanup = true\n",
                fixture.root.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let plan = crate::schedule::preview_configured_install(
            &executable,
            Some(&config),
            None,
            crate::schedule::Frequency::Daily,
        )
        .unwrap();
        assert!(plan.scheduled_scope_token.starts_with("v4."));
        let report = super::run_artifact_cleanup(
            &fixture.home,
            &executable,
            &plan.roots,
            &plan.exclusions,
            &plan.scheduled_scope_token,
            true,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(report.dry_run);
        assert!(fixture.projects[0].join("target").exists());
    }

    #[test]
    fn configured_artifact_cleanup_records_the_attempt_before_removing_a_fixture() {
        private_git_test!(
            configured_artifact_cleanup_records_the_attempt_before_removing_a_fixture
        );
        let Some(fixture) = fixture_or_skip(1) else {
            return;
        };
        if !fixture.trusted_git_available() {
            eprintln!("SKIP: trusted Git could not be inspected from this process namespace");
            return;
        }
        let _activity = crate::activity::TestActivityStatus::set("no_open_handles_or_cwd_observed");
        let target = fixture.projects[0].join("target");
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(31 * 24 * 60 * 60);
        for path in [
            target.join("debug/output"),
            target.join("debug"),
            target.clone(),
        ] {
            fs::File::open(path)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(old))
                .unwrap();
        }
        let config = fixture.home.join("settings.toml");
        fs::write(
            &config,
            format!(
                "version = 1\nworkspace_roots = ['{}']\nartifact_retention = '30d'\nenabled_ecosystems = ['maven']\nscheduled_artifact_cleanup = true\n",
                fixture.root.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let plan = crate::schedule::preview_configured_install(
            &executable,
            Some(&config),
            None,
            crate::schedule::Frequency::Daily,
        )
        .unwrap();
        let result = crate::reports::perform_scheduled_artifact_cleanup(
            &fixture.home,
            &executable,
            &plan.roots,
            &plan.exclusions,
            &plan.scheduled_scope_token,
            &AtomicBool::new(false),
        );
        assert!(
            result.history_warning.is_none(),
            "{:?}",
            result.history_warning
        );
        let report = result.result.unwrap();
        assert!(report.complete, "{report:?}");
        assert_eq!(report.items[0].status, "verified_absent");
        assert!(!target.exists());
        let history = crate::reports::read(&fixture.home).unwrap();
        assert_eq!(history.records.len(), 2);
        assert!(history.records.iter().any(|record| {
            record.operation == "scheduled_artifact_cleanup" && record.outcome == "completed"
        }));
        assert!(history.records.iter().any(|record| {
            record.operation == "scheduled_artifact_removal" && record.outcome == "completed"
        }));
    }

    #[test]
    fn combined_scheduled_bytecode_summary_redacts_paths_and_error_details() {
        let report = super::Report {
            candidates: 1,
            inspected: 1,
            items: vec![super::Item {
                file: PathBuf::from("/workspace/private/src/__pycache__/module.pyc"),
                status: "skipped_unverified",
                detail: Some("could not inspect /workspace/private/src".into()),
                history_warning: None,
            }],
            complete: false,
            dry_run: false,
            warnings: vec![],
        };
        let output = serde_json::to_string(&super::redacted_bytecode_report(&report)).unwrap();
        assert!(output.contains("\"ordinal\":1"));
        assert!(!output.contains("/workspace/private"));
        assert!(!output.contains("module.pyc"));
    }

    #[test]
    fn scheduled_bytecode_report_serialization_redacts_paths_and_error_details() {
        let report = super::Report {
            candidates: 1,
            inspected: 1,
            items: vec![super::Item {
                file: PathBuf::from("/home/alice/private-project/src/__pycache__/module.pyc"),
                status: "skipped_unverified",
                detail: Some("could not inspect /home/alice/private-project/src".into()),
                history_warning: Some("history warning for /home/alice/private-project".into()),
            }],
            complete: false,
            dry_run: false,
            warnings: vec![],
        };
        let output = serde_json::to_string(&report).unwrap();
        assert!(output.contains("skipped_unverified"));
        assert!(!output.contains("/home/alice"));
        assert!(!output.contains("module.pyc"));
    }

    #[test]
    fn per_run_rotation_keeps_the_eight_target_cap_and_covers_deferred_targets() {
        let targets = (0..12)
            .map(|index| PathBuf::from(format!("/workspace/{index:02}")))
            .collect::<Vec<_>>();
        let (count, first_day) = select_artifact_targets(targets.clone(), 40);
        let (same_count, next_day) = select_artifact_targets(targets.clone(), 41);
        assert_eq!(count, 12);
        assert_eq!(same_count, count);
        assert_eq!(first_day.len(), MAX_ARTIFACTS_PER_RUN);
        assert_eq!(next_day.len(), MAX_ARTIFACTS_PER_RUN);
        assert_ne!(first_day, next_day);
        assert_eq!(
            first_day
                .iter()
                .chain(&next_day)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            9
        );
        let covered = (40..52)
            .flat_map(|run| select_artifact_targets(targets.clone(), run).1)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(covered.len(), 12);
    }

    #[test]
    fn file_rotation_selects_the_weekly_window_without_exposing_file_names() {
        let window = |week| {
            let mut files = (0..33).collect::<Vec<_>>();
            rotate_files(&mut files, week, 1);
            files
        };
        let first_week = 91;
        let second_week = first_week + 1;
        let first = window(first_week);
        let second = window(second_week);
        let expected_start = |week| (u128::from(week) * 32 % 33) as usize;

        assert_eq!(first[0], expected_start(first_week));
        assert_eq!(second[0], expected_start(second_week));
        assert_ne!(first[0], second[0]);
        assert_eq!(first[MAX_INSPECTIONS], (first[0] + MAX_INSPECTIONS) % 33);
        assert_eq!(second[MAX_INSPECTIONS], (second[0] + MAX_INSPECTIONS) % 33);
    }

    #[test]
    fn successive_weekly_runs_rotate_the_first_target_after_a_failed_item() {
        let targets = (0..7)
            .map(|index| PathBuf::from(format!("/workspace/{index:02}")))
            .collect::<Vec<_>>();
        let mut history = crate::reports::History {
            records: Vec::new(),
            warnings: Vec::new(),
            capacity: 100,
            known_reclaimed_bytes: None,
            records_without_verified_reclaimed_bytes: 0,
        };
        let mut first_attempts = std::collections::BTreeSet::new();
        for week in 0..7 {
            let run_index = scheduled_artifact_run_index(&history);
            assert_eq!(run_index, week);
            let (_, selected) = select_artifact_targets(targets.clone(), run_index);
            first_attempts.insert(selected[0].clone());
            history.records.push(crate::reports::Record {
                id: week as usize,
                started_unix: week,
                finished_unix: Some(week),
                duration_ms: 1,
                operation: "scheduled_artifact_cleanup".into(),
                target: "configured project artifacts".into(),
                outcome: "partial".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "linux".into(),
            });
        }
        assert_eq!(first_attempts.len(), 7);

        // History purge resets the best-effort cursor; concurrent recorded runs advance it once each.
        history.records.clear();
        assert_eq!(scheduled_artifact_run_index(&history), 0);
        history
            .records
            .extend((0..2).map(|id| crate::reports::Record {
                id,
                started_unix: 100,
                finished_unix: Some(101),
                duration_ms: 1,
                operation: "scheduled_artifact_cleanup".into(),
                target: "configured project artifacts".into(),
                outcome: "partial".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "linux".into(),
            }));
        assert_eq!(scheduled_artifact_run_index(&history), 2);
    }

    #[test]
    fn cancelled_or_stale_policy_runs_leave_temporary_targets_untouched() {
        let Some(fixture) = fixture_or_skip(1) else {
            return;
        };
        let target = fixture.projects[0].join("target");
        let cancel = AtomicBool::new(true);
        let report = run_artifact_cleanup_with_guard(
            &fixture.home,
            &fixture.scope(),
            false,
            &cancel,
            &|| Ok(()),
        );
        assert!(report.is_err() || report.is_ok_and(|report| report.cancelled || !report.complete));
        assert!(target.exists());

        let stale = run_artifact_cleanup_with_guard(
            &fixture.home,
            &fixture.scope(),
            false,
            &AtomicBool::new(false),
            &|| bail!("stale policy fixture"),
        );
        assert!(
            stale
                .unwrap_err()
                .to_string()
                .contains("stale policy fixture")
        );
        assert!(target.exists());
    }

    #[test]
    fn full_or_unreadable_history_prevents_scheduled_artifact_removal() {
        private_git_test!(full_or_unreadable_history_prevents_scheduled_artifact_removal);
        let Some(fixture) = fixture_or_skip(1) else {
            return;
        };
        if !fixture.trusted_git_available() {
            eprintln!("SKIP: trusted Git could not be inspected from this process namespace");
            return;
        }
        let _activity = crate::activity::TestActivityStatus::set("no_open_handles_or_cwd_observed");
        let target = fixture.projects[0].join("target");
        let history_dir = fixture.home.join("history");
        fs::create_dir(&history_dir).unwrap();
        fs::set_permissions(&history_dir, fs::Permissions::from_mode(0o700)).unwrap();
        for id in 0..100 {
            let record = serde_json::json!({
                "id": id,
                "started_unix": id,
                "finished_unix": id,
                "duration_ms": 1,
                "operation": "scheduled_artifact_cleanup",
                "target": "configured project artifacts",
                "outcome": "partial",
                "detail": null,
                "estimated_bytes": null,
                "verified_reclaimed_bytes": null,
                "platform": "linux",
            });
            let path = history_dir.join(format!("{id:03}.json"));
            fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let report = run_artifact_cleanup_with_guard(
            &fixture.home,
            &fixture.scope(),
            false,
            &AtomicBool::new(false),
            &|| Ok(()),
        )
        .unwrap();
        assert!(!report.complete);
        assert_eq!(report.items[0].status, "failed");
        assert!(report.items[0].history_warning.is_some());
        assert!(target.exists());

        fs::remove_dir_all(&history_dir).unwrap();
        fs::write(&history_dir, "not a history directory").unwrap();
        let unreadable = run_artifact_cleanup_with_guard(
            &fixture.home,
            &fixture.scope(),
            false,
            &AtomicBool::new(false),
            &|| Ok(()),
        );
        assert!(unreadable.is_err());
        assert!(target.exists());
    }

    #[test]
    fn reserved_summary_does_not_count_twice_against_history_capacity() {
        private_git_test!(reserved_summary_does_not_count_twice_against_history_capacity);
        let Some(fixture) = fixture_or_skip(1) else {
            return;
        };
        if !fixture.trusted_git_available() {
            eprintln!("SKIP: trusted Git could not be inspected from this process namespace");
            return;
        }
        let _activity = crate::activity::TestActivityStatus::set("no_open_handles_or_cwd_observed");
        let history_dir = fixture.home.join("history");
        fs::create_dir(&history_dir).unwrap();
        fs::set_permissions(&history_dir, fs::Permissions::from_mode(0o700)).unwrap();
        for id in 0..98 {
            let record = crate::reports::Record {
                id,
                started_unix: 1,
                finished_unix: Some(2),
                duration_ms: 1,
                operation: "fixture".into(),
                target: "fixture".into(),
                outcome: "completed".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "fixture".into(),
            };
            let path = history_dir.join(format!("{id:03}.json"));
            fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let _summary = crate::reports::reserve_history_record(
            &fixture.home,
            crate::reports::Record {
                id: 0,
                started_unix: 1,
                finished_unix: None,
                duration_ms: 0,
                operation: "scheduled_artifact_cleanup".into(),
                target: "configured project artifacts".into(),
                outcome: "in_progress".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "fixture".into(),
            },
        )
        .unwrap();
        let target = fixture.projects[0].join("target");
        let report = run_artifact_cleanup_with_guard(
            &fixture.home,
            &fixture.scope(),
            false,
            &AtomicBool::new(false),
            &|| Ok(()),
        )
        .unwrap();
        if !report.complete {
            let scope = fixture.scope();
            let scan = crate::sweep::scan_with_policy(
                &scope.roots,
                &scope.exclusions,
                None,
                scope.enabled.as_deref(),
                &AtomicBool::new(false),
                |_| {},
            )
            .unwrap();
            let diagnostic = crate::artifact_cleanup::preview_batch_from_scan(
                &scope,
                scan,
                std::slice::from_ref(&target),
                &AtomicBool::new(false),
            )
            .err();
            panic!("{report:?}; fixture preview: {diagnostic:?}");
        }
        assert_eq!(report.items[0].status, "verified_absent");
        assert!(!target.exists());
    }

    #[test]
    fn scheduled_artifact_run_removes_only_a_clean_rebuildable_target() {
        private_git_test!(scheduled_artifact_run_removes_only_a_clean_rebuildable_target);
        let Some(fixture) = fixture_or_skip(1) else {
            return;
        };
        if !fixture.trusted_git_available() {
            eprintln!("SKIP: trusted Git could not be inspected from this process namespace");
            return;
        }
        let _activity = crate::activity::TestActivityStatus::set("no_open_handles_or_cwd_observed");
        let target = fixture.projects[0].join("target");
        let report = run_artifact_cleanup_with_guard(
            &fixture.home,
            &fixture.scope(),
            false,
            &AtomicBool::new(false),
            &|| Ok(()),
        )
        .unwrap();
        assert!(report.complete, "{report:?}");
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].status, "verified_absent");
        assert!(!target.exists());
    }

    #[test]
    fn unknown_activity_prevents_scheduled_artifact_removal() {
        private_git_test!(unknown_activity_prevents_scheduled_artifact_removal);
        let Some(fixture) = fixture_or_skip(1) else {
            return;
        };
        if !fixture.trusted_git_available() {
            eprintln!("SKIP: trusted Git could not be inspected from this process namespace");
            return;
        }
        let _activity = crate::activity::TestActivityStatus::set("inspection_incomplete");
        let target = fixture.projects[0].join("target");
        let report = run_artifact_cleanup_with_guard(
            &fixture.home,
            &fixture.scope(),
            false,
            &AtomicBool::new(false),
            &|| Ok(()),
        )
        .unwrap();
        assert!(!report.complete);
        assert_eq!(report.items[0].status, "not_attempted_unverified");
        assert!(target.exists());
    }

    #[test]
    fn active_process_prevents_scheduled_artifact_removal() {
        private_git_test!(active_process_prevents_scheduled_artifact_removal);
        let Some(fixture) = fixture_or_skip(1) else {
            return;
        };
        if !fixture.trusted_git_available() {
            eprintln!("SKIP: trusted Git could not be inspected from this process namespace");
            return;
        }
        let target = fixture.projects[0].join("target");
        let mut process = Command::new("/bin/sleep")
            .arg("30")
            .current_dir(&target)
            .spawn()
            .unwrap();
        let report = run_artifact_cleanup_with_guard(
            &fixture.home,
            &fixture.scope(),
            false,
            &AtomicBool::new(false),
            &|| Ok(()),
        )
        .unwrap();
        let _ = process.kill();
        let _ = process.wait();
        assert!(!report.complete);
        assert_eq!(report.items[0].status, "not_attempted_unverified");
        assert!(target.exists());
    }

    #[test]
    fn a_failed_guard_after_quarantine_stops_later_artifact_targets() {
        private_git_test!(a_failed_guard_after_quarantine_stops_later_artifact_targets);
        let Some(fixture) = fixture_or_skip(2) else {
            return;
        };
        if !fixture.trusted_git_available() {
            eprintln!("SKIP: trusted Git could not be inspected from this process namespace");
            return;
        }
        let _activity = crate::activity::TestActivityStatus::set("no_open_handles_or_cwd_observed");
        let checks = AtomicUsize::new(0);
        let report = run_artifact_cleanup_with_guard(
            &fixture.home,
            &fixture.scope(),
            false,
            &AtomicBool::new(false),
            &|| {
                if checks.fetch_add(1, Ordering::Relaxed) + 1 == 5 {
                    bail!("stale policy after quarantine");
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(!report.complete);
        assert_eq!(report.items.len(), 2);
        assert_eq!(report.items[0].status, "failed");
        assert_eq!(report.items[1].status, "not_attempted_after_failure");
        assert!(
            fixture
                .projects
                .iter()
                .all(|project| project.join("target").exists())
        );
    }

    #[test]
    fn concurrent_artifact_runs_never_confirm_the_same_target_twice() {
        private_git_test!(concurrent_artifact_runs_never_confirm_the_same_target_twice);
        let Some(fixture) = fixture_or_skip(1) else {
            return;
        };
        if !fixture.trusted_git_available() {
            eprintln!("SKIP: trusted Git could not be inspected from this process namespace");
            return;
        }
        let target = fixture.projects[0].join("target");
        let scope = fixture.scope();
        let reports = std::thread::scope(|threads| {
            (0..2)
                .map(|_| {
                    threads.spawn(|| {
                        let _activity = crate::activity::TestActivityStatus::set(
                            "no_open_handles_or_cwd_observed",
                        );
                        run_artifact_cleanup_with_guard(
                            &fixture.home,
                            &scope,
                            false,
                            &AtomicBool::new(false),
                            &|| Ok(()),
                        )
                        .unwrap()
                    })
                })
                .map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        let verified_removals = reports
            .iter()
            .flat_map(|report| &report.items)
            .filter(|item| item.status == "verified_absent")
            .count();
        assert_eq!(verified_removals, 1, "{reports:?}");
        assert!(!target.exists());
    }

    #[test]
    fn weekly_rotation_covers_each_cache_even_if_one_uses_the_entire_budget() {
        for cache_count in [1, 2, 4, 32, 33, 64] {
            for file_count in [1, 32, 33, 65] {
                let mut seen = vec![vec![false; file_count]; cache_count];
                let weeks = cache_count * (file_count.div_ceil(MAX_INSPECTIONS) + 1);
                for week in 91..91 + weeks as u64 {
                    let mut caches = (0..cache_count).collect::<Vec<_>>();
                    rotate_caches(&mut caches, week);
                    let cache = caches[0];
                    let mut files = (0..file_count).collect::<Vec<_>>();
                    rotate_files(&mut files, week, cache_count);
                    for file in files.into_iter().take(MAX_INSPECTIONS) {
                        seen[cache][file] = true;
                    }
                }
                assert!(
                    seen.into_iter().flatten().all(|visited| visited),
                    "caches={cache_count}, files={file_count}"
                );
            }
        }
    }
}
