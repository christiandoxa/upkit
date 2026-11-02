//! Opt-in scheduled removal of reviewed Python bytecode within configured workspaces.
use anyhow::{Result, bail};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[derive(Debug, Serialize)]
pub struct Item {
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub file: PathBuf,
    pub status: &'static str,
    pub detail: Option<String>,
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

// shortcut: inspect at most 32 files per run; paginate policy execution before raising the limit.
#[cfg(target_os = "linux")]
const MAX_INSPECTIONS: usize = 32;

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
    use anyhow::Context;
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
                    .any(|warning| warning.contains("Git evidence was not collected"))
                {
                    report.warnings.push(
                        "During --dry-run, inspected counts only filenames enumerated from eligible caches; bytecode, source, process, and Git safety checks were skipped.".into(),
                    );
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
        let history = crate::reports::read(home);
        if match &history {
            Ok(history) => {
                history
                    .records
                    .len()
                    .saturating_add(history.warnings.len())
                    .saturating_add(2)
                    > history.capacity
            }
            Err(_) => true,
        } {
            stopped = true;
            report.complete = false;
            report.items.push(Item {
                file: plan.file,
                status: "not_attempted",
                detail: Some(
                    "History is unavailable or lacks room for the removal and its summary.".into(),
                ),
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
    use super::{MAX_INSPECTIONS, rotate_caches, rotate_files};

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
