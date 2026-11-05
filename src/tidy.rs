//! Zero-configuration, read-only-first cleanup guidance for one project and
//! discovered shared caches. Every removal uses the existing guarded engine.
use crate::{
    application::Cli,
    cache,
    infrastructure::{Ctx, emit_json, info},
    sweep,
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::{
    env,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[derive(Serialize)]
struct Target {
    kind: &'static str,
    name: String,
    #[serde(serialize_with = "sweep::serialize_path")]
    path: PathBuf,
    logical_bytes: Option<u64>,
    status: &'static str,
    guidance: &'static str,
}

#[derive(Serialize)]
struct Overview {
    #[serde(serialize_with = "serialize_roots")]
    workspace_roots: Vec<PathBuf>,
    artifacts: Vec<Target>,
    shared_caches: Vec<Target>,
    warnings: Vec<String>,
    next_steps: Vec<&'static str>,
    executed: bool,
}

fn serialize_roots<S: serde::Serializer>(
    paths: &[PathBuf],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut result = serializer.serialize_seq(Some(paths.len()))?;
    for path in paths {
        result.serialize_element(&PathForJson(path))?;
    }
    result.end()
}

struct PathForJson<'a>(&'a Path);
impl Serialize for PathForJson<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        sweep::serialize_path(self.0, serializer)
    }
}

fn auto_scope(cli: &Cli, roots: &[PathBuf]) -> Result<Option<sweep::Scope>> {
    // With no user-defined configuration and no manifest-backed project, we
    // still show shared caches; never widen a scan to $HOME or /.
    if roots.is_empty() && cli.config.is_none() && cli.profile.is_none() {
        let cwd = env::current_dir().context("find current workspace")?;
        if sweep::nearest_project_root(&cwd, dirs::home_dir().as_deref()).is_none() {
            return Ok(None);
        }
    }
    let (roots, exclusions, age, enabled) = crate::application::resolve_scan_config(
        cli.config.as_deref(),
        cli.profile.as_deref(),
        roots,
        &[],
        None,
    )?;
    Ok(Some(sweep::Scope {
        roots,
        exclusions,
        older_than_seconds: age.map(|age| age.as_secs()),
        enabled,
    }))
}

fn artifact_status(candidate: &sweep::Candidate) -> (&'static str, &'static str) {
    if candidate.classification != "rebuildable" {
        return ("review_only", "Contents may be user data; inspection only");
    }
    if !candidate.size_complete {
        return (
            "blocked",
            "Size or filesystem inspection incomplete; no removal allowed",
        );
    }
    if candidate.nested_project_marker.is_some() || candidate.nested_vcs_marker.is_some() {
        return (
            "blocked",
            "Nested project or Git repository detected; protect source files",
        );
    }
    if candidate.symlink_marker.is_some() {
        return (
            "blocked",
            "Symbolic link inside build output; inspect manually",
        );
    }
    if candidate.hard_link_marker.is_some() {
        return (
            "blocked",
            "Hard-linked file found; shared data must not be deleted",
        );
    }
    (
        "preview_available",
        "Rebuildable candidate, not yet safe: Git/process/permissions will be verified during preview",
    )
}

fn report(
    cli: &Cli,
    root: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<(
    Overview,
    Option<sweep::Scope>,
    Option<sweep::ScanReport>,
    cache::CacheReport,
)> {
    let scope = auto_scope(cli, root)?;
    let scan = if let Some(scope) = &scope {
        Some(sweep::scan_with_policy(
            &scope.roots,
            &scope.exclusions,
            scope.older_than_seconds.map(std::time::Duration::from_secs),
            scope.enabled.as_deref(),
            cancel,
            |_| {},
        )?)
    } else {
        None
    };
    let caches = cache::inventory(cancel);
    let mut warnings = scan
        .as_ref()
        .map_or_else(Vec::new, |scan| scan.warnings.clone());
    warnings.extend(caches.warnings.clone());
    if scope.is_none() {
        warnings.push(
            "No project detected here. Run inside a manifest-backed project or pass --root PATH; shared cache inventory still works. No configuration file is required.".into(),
        );
    }
    let artifacts = scan.as_ref().map_or_else(Vec::new, |scan| {
        scan.candidates
            .iter()
            .map(|candidate| {
                let (status, guidance) = artifact_status(candidate);
                Target {
                    kind: "artifact",
                    name: candidate.ecosystem.to_owned(),
                    path: candidate.target.clone(),
                    logical_bytes: Some(candidate.logical_bytes),
                    status,
                    guidance,
                }
            })
            .collect()
    });
    let shared_caches = caches
        .entries
        .iter()
        .map(|entry| Target {
            kind: "shared_cache",
            name: entry.name.to_owned(),
            path: entry.path.clone(),
            logical_bytes: entry.logical_bytes,
            status: "inventory_only",
            guidance: "Shared with other projects; use --select for guarded eligibility review",
        })
        .collect();
    let overview = Overview {
        workspace_roots: scope.as_ref().map_or_else(Vec::new, |s| s.roots.clone()),
        artifacts,
        shared_caches,
        warnings,
        next_steps: vec![
            "upkit tidy -- selects no files and never deletes by default",
            "upkit tidy --select NAME_OR_ABSOLUTE_PATH previews one unique discovered target",
            "upkit --yes --non-interactive tidy --select NAME_OR_ABSOLUTE_PATH --run --preview-token TOKEN removes only after safety revalidation",
        ],
        executed: false,
    };
    Ok((overview, scope, scan, caches))
}

fn show_overview(ctx: &Ctx, summary: &Overview) -> Result<()> {
    if ctx.json {
        return emit_json(ctx, serde_json::to_value(summary)?);
    }
    if summary.workspace_roots.is_empty() {
        info(
            ctx,
            "No project configured or detected here. Run in a project, or add --root PATH.",
        );
    } else {
        for root in &summary.workspace_roots {
            info(ctx, format!("Project: {}", sweep::display_path(root)));
        }
    }
    info(
        ctx,
        "Rebuildable artifacts (logical size snapshots, not guaranteed reclaimed space):",
    );
    for item in &summary.artifacts {
        info(
            ctx,
            format!(
                "  {:<18} {:<17} {:>10}  {}",
                item.name,
                item.status,
                item.logical_bytes
                    .map_or("unknown".to_owned(), |size| format!(
                        "{} MiB",
                        size / 1_048_576
                    )),
                sweep::display_path(&item.path),
            ),
        );
        if item.status != "preview_available" {
            info(ctx, format!("    Reason: {}", item.guidance));
        }
    }
    if summary.artifacts.is_empty() {
        info(ctx, "  (none found in this project)");
    }
    info(
        ctx,
        "Shared caches (inventory only; may require downloading dependencies again):",
    );
    for item in &summary.shared_caches {
        info(
            ctx,
            format!(
                "  {:<18} {:>10}  {}",
                item.name,
                item.logical_bytes
                    .map_or("unknown".to_owned(), |size| format!(
                        "{} MiB",
                        size / 1_048_576
                    )),
                sweep::display_path(&item.path),
            ),
        );
    }
    if summary.shared_caches.is_empty() {
        info(ctx, "  (none found)");
    }
    if !summary.warnings.is_empty() {
        info(
            ctx,
            format!(
                "{} diagnostic warning(s); no unsupported location will be deleted.",
                summary.warnings.len()
            ),
        );
        if ctx.verbose > 0 {
            for warning in summary.warnings.iter().take(20) {
                info(ctx, format!("  ⚠ {warning}"));
            }
        }
    }
    info(ctx, "Preview: upkit cleanup --select NAME_OR_ABSOLUTE_PATH");
    info(
        ctx,
        "After preview: upkit --yes --non-interactive tidy --select PATH --run --preview-token TOKEN.",
    );
    Ok(())
}

pub(crate) fn run(
    cli: &Cli,
    ctx: &Ctx,
    root: &[PathBuf],
    select: Option<&Path>,
    execute: bool,
    token: Option<&str>,
) -> Result<()> {
    if execute && select.is_none() {
        bail!("--run requires --select with one exact path from upkit tidy");
    }
    if execute && !ctx.dry_run && (!cli.yes || token.is_none()) {
        bail!("tidy removal requires --yes, --run and --preview-token from an exact prior preview");
    }
    if execute && !ctx.dry_run && !cli.non_interactive && !ctx.json {
        bail!("tidy removal requires --non-interactive (or --json) for an explicit CLI operation");
    }
    let cancel = AtomicBool::new(false);
    let (summary, scope, scan, caches) = report(cli, root, &cancel)?;
    let Some(select) = select else {
        return show_overview(ctx, &summary);
    };
    // A unique ecosystem/cache name is easier than copying an absolute path.
    // Ambiguous names are refused, never chosen by inventory order.
    let selected = if select.is_absolute() {
        select.to_path_buf()
    } else {
        let name = select
            .to_str()
            .context("tidy selection must be a cache name or an absolute target path")?;
        let matches = summary
            .artifacts
            .iter()
            .chain(summary.shared_caches.iter())
            .filter(|item| item.name.eq_ignore_ascii_case(name))
            .map(|item| item.path.clone())
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [only] => only.clone(),
            [] => bail!("unknown tidy selection; choose a name or exact path shown by upkit tidy"),
            _ => bail!("ambiguous tidy selection; use the exact path shown by upkit tidy"),
        }
    };
    let select = selected.as_path();
    let metadata = std::fs::symlink_metadata(select).context("inspect selected tidy target")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("select a discovered, non-symlink directory from upkit tidy");
    }
    let target = select
        .canonicalize()
        .context("resolve selected tidy target")?;
    let matching_artifact = scan.as_ref().is_some_and(|scan| {
        scan.candidates
            .iter()
            .any(|candidate| candidate.target == target)
    });
    let matching_cache = caches.entries.iter().any(|cache| cache.path == target);
    if matching_artifact == matching_cache {
        bail!(
            "selected path is missing or ambiguous in this inventory; refresh upkit tidy and use one exact target"
        );
    }
    if matching_artifact {
        let candidate = scan
            .as_ref()
            .and_then(|scan| {
                scan.candidates
                    .iter()
                    .find(|candidate| candidate.target == target)
            })
            .context("selected artifact is no longer in the inventory")?;
        let (status, reason) = artifact_status(candidate);
        if status != "preview_available" {
            bail!(
                "safe tidy mode refuses this artifact: {reason}; use upkit sweep preview for a detailed inspection"
            );
        }
    }
    if ctx.dry_run {
        if ctx.json {
            return emit_json(
                ctx,
                serde_json::json!({"dry_run": true, "executed": false, "target": sweep::display_path(&target), "detail": "dry-run never creates a deletion preview or token; run --select without --dry-run"}),
            );
        }
        info(
            ctx,
            "Dry-run: inventory only; no deletion preview token or removal was created.",
        );
        return Ok(());
    }
    if matching_artifact {
        let scope = scope.context("workspace scope unavailable")?;
        let plan = crate::artifact_cleanup::preview(&scope, &target, &cancel)
            .context("artifact is not eligible for guarded cleanup; inspect Git/process/permissions and try again")?;
        let mut history_warning = None;
        let result = if execute {
            let performed = crate::reports::perform_artifact_removal(
                &ctx.home,
                &plan,
                token.unwrap_or_default(),
                &cancel,
            );
            history_warning = performed.history_warning;
            Some(performed.result.map_err(anyhow::Error::msg)?)
        } else {
            None
        };
        if ctx.json {
            emit_json(
                ctx,
                serde_json::json!({"plan": plan, "executed": execute, "verification": result, "history_warning": history_warning}),
            )?;
        } else {
            info(ctx, serde_json::to_string_pretty(&plan)?);
            if let Some(warning) = &history_warning {
                info(ctx, format!("History warning: {warning}"));
            }
            info(
                ctx,
                result.map_or("Preview only. No artifact removed.".to_owned(), |s| {
                    format!("Artifact cleanup: {s}")
                }),
            );
        }
        if result.is_some_and(|result| result != "verified_absent") {
            bail!("artifact cleanup could not verify absence; inspect target before retrying");
        }
    } else {
        let plan = crate::shared_cache_cleanup::preview(&target, &cancel)
            .context("shared cache is not eligible for guarded cleanup; inspect the cache configuration and process activity")?;
        let mut history_warning = None;
        let result = if execute {
            let performed = crate::reports::perform_shared_cache_removal(
                &ctx.home,
                &plan,
                token.unwrap_or_default(),
                &cancel,
            );
            history_warning = performed.history_warning;
            Some(performed.result.map_err(anyhow::Error::msg)?)
        } else {
            None
        };
        if ctx.json {
            emit_json(
                ctx,
                serde_json::json!({"plan": plan, "executed": execute, "verification": result, "history_warning": history_warning}),
            )?;
        } else {
            info(ctx, serde_json::to_string_pretty(&plan)?);
            if let Some(warning) = &history_warning {
                info(ctx, format!("History warning: {warning}"));
            }
            info(
                ctx,
                result.map_or("Preview only. No cache removed.".to_owned(), |s| {
                    format!("Shared cache cleanup: {s}")
                }),
            );
        }
        if result.is_some_and(|result| result != "verified_absent") {
            bail!("cache cleanup could not verify absence; inspect target before retrying");
        }
    }
    Ok(())
}
