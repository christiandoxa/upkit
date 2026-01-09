use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, home_dir, http_get_json, info,
    maybe_path_hint_for_dir, run_output, run_status, which_or_none,
};
use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::{env, path::PathBuf};

#[derive(Debug, Deserialize)]
struct FlutterReleases {
    releases: Vec<FlutterReleaseEntry>,
}

#[derive(Debug, Deserialize)]
struct FlutterReleaseEntry {
    channel: String,
    version: String,
    // archive, hash, dart_sdk_version, release_date, etc. exist, but we only need version+channel
}

pub fn flutter_releases_url(ctx: &Ctx) -> Result<&'static str> {
    // official buckets provide per-OS JSON
    match ctx.os.as_str() {
        "linux" => {
            Ok("https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json")
        }
        "macos" => {
            Ok("https://storage.googleapis.com/flutter_infra_release/releases/releases_macos.json")
        }
        "windows" => Ok(
            "https://storage.googleapis.com/flutter_infra_release/releases/releases_windows.json",
        ),
        _ => bail!("flutter releases json not supported for {}", ctx.os),
    }
}

pub fn flutter_latest_stable(ctx: &Ctx) -> Result<Version> {
    let url = flutter_releases_url(ctx)?;
    let data: FlutterReleases = http_get_json(ctx, url)?;
    let mut best: Option<Version> = None;
    for r in data.releases.into_iter().filter(|r| r.channel == "stable") {
        if let Some(v) = Version::parse_loose(&r.version) {
            if best.as_ref().map(|b| &v > b).unwrap_or(true) {
                best = Some(v);
            }
        }
    }
    best.ok_or_else(|| anyhow!("could not determine flutter latest stable"))
}

pub fn flutter_installed_version() -> Option<Version> {
    // flutter --version --machine outputs JSON
    let out = run_output("flutter", &["--version", "--machine"]).ok()?;
    if !out.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let s = v.get("frameworkVersion")?.as_str()?;
    Version::parse_loose(s)
}

pub fn check_flutter(ctx: &Ctx) -> Result<ToolReport> {
    let installed = if which_or_none("flutter").is_some() {
        flutter_installed_version()
    } else {
        None
    };

    let latest = flutter_latest_stable(ctx).ok();
    let status = match (&installed, &latest) {
        (None, Some(_)) => Status::NotInstalled,
        (Some(i), Some(l)) if i >= l => Status::UpToDate,
        (Some(_), Some(_)) => Status::Outdated,
        _ => Status::Unknown,
    };

    Ok(ToolReport {
        tool: ToolKind::Flutter,
        installed,
        latest,
        status,
        method: UpdateMethod::BuiltIn,
        notes: vec!["Uses flutter upgrade (built-in updater).".into()],
    })
}

pub fn update_flutter(ctx: &Ctx) -> Result<()> {
    if ctx.offline {
        bail!("offline mode enabled; Flutter update requires network access");
    }
    let report = check_flutter(ctx)?;
    if which_or_none("flutter").is_none() {
        bail!("flutter not found in PATH; install Flutter SDK first");
    }

    if matches!(report.status, Status::UpToDate) && !ctx.force {
        info(ctx, "flutter is up-to-date");
        return Ok(());
    }

    info(ctx, "Updating flutter via flutter upgrade");
    if ctx.dry_run {
        info(ctx, "[dry-run] would run: flutter upgrade");
        return Ok(());
    }

    let status = run_status("flutter", &["upgrade"]).context("failed to run flutter upgrade")?;
    if !status.success() {
        bail!("flutter upgrade failed");
    }
    maybe_hint_flutter_bins(ctx);
    info(ctx, "flutter updated");
    Ok(())
}

fn maybe_hint_flutter_bins(ctx: &Ctx) {
    if let Some(pub_cache) = pub_cache_dir() {
        maybe_path_hint_for_dir(ctx, &pub_cache.join("bin"), "pub cache bin");
    }
}

fn pub_cache_dir() -> Option<PathBuf> {
    env::var("PUB_CACHE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".pub-cache")))
}
