use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, atomic_symlink, download_to_temp,
    ensure_clean_dir, home_dir, http_get_json, info, link_dir_bins, maybe_path_hint_for_dir,
    run_output, run_status, sha256_file, which_or_none,
};
use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize)]
struct FlutterReleases {
    releases: Vec<FlutterReleaseEntry>,
}

#[derive(Debug, Deserialize)]
struct FlutterReleaseEntry {
    channel: String,
    version: String,
    archive: String,
    hash: String,
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

fn flutter_latest_stable_release(ctx: &Ctx) -> Result<FlutterReleaseEntry> {
    let url = flutter_releases_url(ctx)?;
    let data: FlutterReleases = http_get_json(ctx, url)?;
    let mut best: Option<(Version, FlutterReleaseEntry)> = None;
    for r in data.releases.into_iter().filter(|r| r.channel == "stable") {
        if let Some(v) = Version::parse_loose(&r.version) {
            if best.as_ref().map(|(b, _)| &v > b).unwrap_or(true) {
                best = Some((v, r));
            }
        }
    }
    best.map(|(_, r)| r)
        .ok_or_else(|| anyhow!("could not determine flutter latest stable"))
}

pub fn flutter_latest_stable(ctx: &Ctx) -> Result<Version> {
    let release = flutter_latest_stable_release(ctx)?;
    Version::parse_loose(&release.version)
        .ok_or_else(|| anyhow!("could not parse flutter version {}", release.version))
}

pub fn flutter_installed_version(bin: Option<&Path>) -> Option<Version> {
    // flutter --version --machine outputs JSON
    let args = [OsStr::new("--version"), OsStr::new("--machine")];
    let out = match bin {
        Some(bin) => run_output(bin.as_os_str(), &args).ok()?,
        None => run_output("flutter", &["--version", "--machine"]).ok()?,
    };
    if !out.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let s = v.get("frameworkVersion")?.as_str()?;
    Version::parse_loose(s)
}

pub fn check_flutter(ctx: &Ctx) -> Result<ToolReport> {
    let installed = if let Some(bin) = flutter_bin_in_bindir(ctx) {
        flutter_installed_version(Some(&bin))
    } else if which_or_none("flutter").is_some() {
        flutter_installed_version(None)
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
    let bindir_flutter = flutter_bin_in_bindir(ctx);
    let flutter_in_path = which_or_none("flutter").is_some();

    if bindir_flutter.is_none() && !flutter_in_path {
        let release = flutter_latest_stable_release(ctx)?;
        info(ctx, format!("Installing flutter {}", release.version));
        let download_url = format!(
            "https://storage.googleapis.com/flutter_infra_release/releases/{}",
            release.archive
        );
        if ctx.dry_run {
            info(ctx, format!("[dry-run] would download {download_url}"));
            return Ok(());
        }

        let tmp = download_to_temp(ctx, &download_url)?;
        let got = sha256_file(tmp.path())?;
        if !got.eq_ignore_ascii_case(&release.hash) {
            bail!("Flutter sha256 mismatch: expected {}, got {got}", release.hash);
        }

        let tool_root = ctx.home.join("flutter");
        fs::create_dir_all(&tool_root)?;
        let ver_dir = tool_root.join(&release.version);
        ensure_clean_dir(&ver_dir)?;

        let archive = release.archive.as_str();
        if archive.ends_with(".tar.xz") {
            let f = fs::File::open(tmp.path())?;
            let xz = xz2::read::XzDecoder::new(f);
            let mut ar = tar::Archive::new(xz);
            ar.unpack(&ver_dir)?;
        } else if archive.ends_with(".tar.gz") {
            let f = fs::File::open(tmp.path())?;
            let gz = flate2::read::GzDecoder::new(f);
            let mut ar = tar::Archive::new(gz);
            ar.unpack(&ver_dir)?;
        } else {
            bail!("unsupported flutter archive format: {}", release.archive);
        }

        let extracted = ver_dir.join("flutter");
        if !extracted.exists() {
            bail!("unexpected flutter archive layout (missing flutter/ directory)");
        }

        let active = tool_root.join("active");
        atomic_symlink(&extracted, &active)?;
        let bin_dir = active.join("bin");
        link_dir_bins(&bin_dir, &ctx.bindir, &["flutter", "dart", "pub"])?;
        maybe_path_hint_for_dir(ctx, &bin_dir, "flutter bin");
        maybe_hint_flutter_bins(ctx);

        info(ctx, "flutter installed");
        return Ok(());
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

    let status = if let Some(bin) = bindir_flutter {
        let args = [OsStr::new("upgrade")];
        run_status(bin.as_os_str(), &args).context("failed to run flutter upgrade")?
    } else {
        run_status("flutter", &["upgrade"]).context("failed to run flutter upgrade")?
    };
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

fn flutter_bin_in_bindir(ctx: &Ctx) -> Option<PathBuf> {
    let candidate = ctx.bindir.join("flutter");
    if candidate.exists() {
        return Some(candidate);
    }
    None
}
