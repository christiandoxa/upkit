use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::{collections::HashMap, ffi::OsStr, fs, path::PathBuf};

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, atomic_symlink, download_to_temp,
    ensure_clean_dir, http_get_json, info, keep_latest_version, link_dir_bins, prune_tool_versions,
    run_capture, sha256_file, warn, which_or_none,
};

const ZIG_INDEX_URL: &str = "https://ziglang.org/download/index.json";

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
pub struct ZigArtifact {
    pub tarball: String,
    pub shasum: String,
    #[allow(dead_code)]
    pub size: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ZigRelease {
    version: String,
    #[serde(default)]
    date: Option<String>,
    #[serde(default)]
    docs: Option<String>,
    #[serde(rename = "stdDocs", default)]
    std_docs: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    src: Option<ZigArtifact>,
    #[serde(default)]
    bootstrap: Option<ZigArtifact>,
    #[serde(flatten)]
    targets: HashMap<String, ZigArtifact>,
}

fn zig_releases(ctx: &Ctx) -> Result<HashMap<String, ZigRelease>> {
    let releases: HashMap<String, ZigRelease> = http_get_json(ctx, ZIG_INDEX_URL)?;
    Ok(releases)
}

pub fn zig_target(ctx: &Ctx) -> Result<&'static str> {
    match (ctx.os.as_str(), ctx.arch.as_str()) {
        ("linux", "x86_64") => Ok("x86_64-linux"),
        ("linux", "aarch64") => Ok("aarch64-linux"),
        ("macos", "x86_64") => Ok("x86_64-macos"),
        ("macos", "aarch64") => Ok("aarch64-macos"),
        ("windows", _) => bail!("zig direct install is not supported yet for Windows in this MVP"),
        _ => bail!(
            "zig target not supported in this MVP for {} {}",
            ctx.os,
            ctx.arch
        ),
    }
}

pub fn zig_latest(ctx: &Ctx) -> Result<Version> {
    let releases = zig_releases(ctx)?;
    let mut best: Option<Version> = None;
    for (name, release) in releases {
        if name == "master" {
            continue;
        }
        let Some(version) = Version::parse_loose(&release.version) else {
            continue;
        };
        if version.pre.is_some() {
            continue;
        }
        keep_latest_version(&mut best, version);
    }
    best.ok_or_else(|| anyhow!("could not determine latest Zig stable release"))
}

pub fn zig_pick_asset(ctx: &Ctx, want: &Version) -> Result<ZigArtifact> {
    let releases = zig_releases(ctx)?;
    let target = zig_target(ctx)?;

    for (name, release) in releases {
        if name == "master" {
            continue;
        }
        let Some(version) = Version::parse_loose(&release.version) else {
            continue;
        };
        if &version != want || version.pre.is_some() {
            continue;
        }
        if let Some(asset) = release.targets.get(target) {
            return Ok(asset.clone());
        }
        bail!(
            "no Zig artifact found for {} target {}",
            want.to_string(),
            target
        );
    }

    bail!("no Zig release found for {}", want.to_string());
}

pub fn check_zig(ctx: &Ctx) -> Result<ToolReport> {
    let installed = if let Some(bin) = zig_bin_in_bindir(ctx) {
        let args = [OsStr::new("version")];
        run_capture(bin.as_os_str(), &args).ok()
    } else {
        which_or_none("zig").and_then(|_| run_capture("zig", &["version"]).ok())
    }
    .and_then(|out| Version::parse_loose(&out));

    let latest = zig_latest(ctx).ok();
    let status = Status::from_versions(installed.as_ref(), latest.as_ref());

    Ok(ToolReport {
        tool: ToolKind::Zig,
        installed,
        latest,
        status,
        method: UpdateMethod::DirectDownload,
        notes: vec!["Uses official ziglang.org stable release index and checks shasum.".into()],
    })
}

pub fn update_zig(ctx: &Ctx) -> Result<()> {
    if ctx.offline {
        bail!("offline mode enabled; Zig update requires network access");
    }
    let report = check_zig(ctx)?;
    let latest = report
        .latest
        .clone()
        .ok_or_else(|| anyhow!("latest unknown"))?;

    if matches!(report.status, Status::UpToDate) && !ctx.force {
        info(ctx, format!("zig is up-to-date ({})", latest.to_string()));
        return Ok(());
    }

    let asset = zig_pick_asset(ctx, &latest)?;
    if !asset.tarball.ends_with(".tar.xz") {
        bail!("unsupported Zig archive format: {}", asset.tarball);
    }

    info(ctx, format!("Updating zig -> {}", latest.to_string()));
    if ctx.dry_run {
        info(
            ctx,
            format!("[dry-run] would download {} and install", asset.tarball),
        );
        return Ok(());
    }

    let tmp = download_to_temp(ctx, &asset.tarball)
        .with_context(|| format!("download Zig archive from {}", asset.tarball))?;
    let got = sha256_file(tmp.path())?;
    if !got.eq_ignore_ascii_case(&asset.shasum) {
        bail!("Zig sha256 mismatch: expected {}, got {got}", asset.shasum);
    }

    let tool_root = ctx.home.join("zig");
    fs::create_dir_all(&tool_root).with_context(|| format!("create {}", tool_root.display()))?;
    let ver_dir = tool_root.join(latest.to_string());
    ensure_clean_dir(&ver_dir).with_context(|| format!("prepare {}", ver_dir.display()))?;

    {
        let f = fs::File::open(tmp.path()).context("open Zig archive")?;
        let xz = xz2::read::XzDecoder::new(f);
        let mut ar = tar::Archive::new(xz);
        ar.unpack(&ver_dir)
            .with_context(|| format!("extract Zig archive to {}", ver_dir.display()))?;
    }

    let extracted = fs::read_dir(&ver_dir)?
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .ok_or_else(|| anyhow!("unexpected Zig archive layout"))?
        .path();

    let zig_bin = extracted.join("zig");
    if !zig_bin.exists() {
        bail!(
            "unexpected Zig archive layout (missing {}/zig)",
            extracted.display()
        );
    }

    let active = tool_root.join("active");
    atomic_symlink(&extracted, &active).with_context(|| {
        format!(
            "link zig active {} -> {}",
            active.display(),
            extracted.display()
        )
    })?;
    link_dir_bins(&active, &ctx.bindir, &["zig"]).context("link zig binary")?;

    if let Err(err) = prune_tool_versions(&tool_root, &ver_dir, &["active"]) {
        warn(ctx, format!("Failed to remove old zig versions: {err}"));
    }

    info(ctx, format!("zig updated to {}", latest.to_string()));
    Ok(())
}

fn zig_bin_in_bindir(ctx: &Ctx) -> Option<PathBuf> {
    let candidate = ctx.bindir.join("zig");
    if candidate.exists() {
        return Some(candidate);
    }
    None
}
