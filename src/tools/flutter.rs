use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::process::{Command, Stdio};

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, http_get_json, info, which_or_none,
};

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

fn flutter_releases_url(ctx: &Ctx) -> Result<&'static str> {
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

fn flutter_latest_stable(ctx: &Ctx) -> Result<Version> {
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

fn flutter_installed_version() -> Option<Version> {
    // flutter --version --machine outputs JSON
    let out = Command::new("flutter")
        .args(["--version", "--machine"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let s = v.get("frameworkVersion")?.as_str()?;
    Version::parse_loose(s)
}

pub(crate) fn check_flutter(ctx: &Ctx) -> Result<ToolReport> {
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

pub(crate) fn update_flutter(ctx: &Ctx) -> Result<()> {
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

    let status = Command::new("flutter")
        .arg("upgrade")
        .status()
        .context("failed to run flutter upgrade")?;
    if !status.success() {
        bail!("flutter upgrade failed");
    }
    info(ctx, "flutter updated");
    Ok(())
}
