use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::{env, fs};

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, atomic_symlink, download_to_temp,
    ensure_clean_dir, http_get_json, info, link_dir_bins, maybe_path_hint_for_dir, run_capture,
    sha256_file, which_or_none,
};

#[derive(Debug, Deserialize)]
struct GoRelease {
    version: String, // "go1.22.5"
    stable: bool,
    files: Vec<GoFile>,
}

#[derive(Debug, Deserialize)]
struct GoFile {
    filename: String,
    os: String,
    arch: String,
    kind: String, // "archive", "installer", ...
    sha256: String,
}

pub fn go_os_arch(ctx: &Ctx) -> (String, String) {
    let os = match ctx.os.as_str() {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        other => other,
    }
    .to_string();

    let arch = match ctx.arch.as_str() {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
    .to_string();

    (os, arch)
}

pub fn check_go(ctx: &Ctx) -> Result<ToolReport> {
    let installed = which_or_none("go")
        .and_then(|_| run_capture("go", &["version"]).ok())
        .and_then(|out| Version::parse_loose(&out));

    let latest = go_latest(ctx).ok();
    let status = match (&installed, &latest) {
        (None, Some(_)) => Status::NotInstalled,
        (Some(i), Some(l)) if i >= l => Status::UpToDate,
        (Some(_), Some(_)) => Status::Outdated,
        _ => Status::Unknown,
    };

    let mut notes = vec!["Installs into upkit home and symlinks binaries into bindir.".into()];
    if latest.is_none() {
        notes.push("Could not fetch the latest Go release; status may be unknown.".into());
    }

    Ok(ToolReport {
        tool: ToolKind::Go,
        installed,
        latest,
        status,
        method: UpdateMethod::DirectDownload,
        notes,
    })
}

pub fn go_latest(ctx: &Ctx) -> Result<Version> {
    let url = "https://go.dev/dl/?mode=json";
    let releases: Vec<GoRelease> = http_get_json(ctx, url)?;
    let stable = releases
        .into_iter()
        .filter(|r| r.stable)
        .collect::<Vec<_>>();
    let mut best: Option<Version> = None;
    for r in stable {
        if let Some(v) = Version::parse_loose(&r.version) {
            if best.as_ref().map(|b| &v > b).unwrap_or(true) {
                best = Some(v);
            }
        }
    }
    best.ok_or_else(|| anyhow!("could not determine latest Go version"))
}

pub fn go_pick_file(ctx: &Ctx, want_version: &Version) -> Result<(String, String)> {
    // returns (download_url, sha256)
    let url = "https://go.dev/dl/?mode=json";
    let releases: Vec<GoRelease> = http_get_json(ctx, url)?;
    let (os, arch) = go_os_arch(ctx);
    let want_prefix = format!(
        "go{}.{}.{}",
        want_version.major, want_version.minor, want_version.patch
    );

    for r in releases.into_iter().filter(|r| r.stable) {
        if !r.version.starts_with(&want_prefix) {
            continue;
        }
        let file = r.files.iter().find(|f| {
            f.kind == "archive" && f.os == os && f.arch == arch && f.filename.ends_with(".tar.gz")
        });
        if let Some(f) = file {
            let dl = format!("https://go.dev/dl/{}", f.filename);
            return Ok((dl, f.sha256.clone()));
        }
    }

    bail!("no Go archive found for this OS/arch")
}

pub fn update_go(ctx: &Ctx) -> Result<()> {
    if ctx.offline {
        bail!("offline mode enabled; Go update requires network access");
    }
    let report = check_go(ctx)?;
    let latest = report
        .latest
        .clone()
        .ok_or_else(|| anyhow!("latest unknown"))?;

    if matches!(report.status, Status::UpToDate) && !ctx.force {
        info(ctx, format!("go is up-to-date ({})", latest.to_string()));
        return Ok(());
    }

    info(ctx, format!("Updating go -> {}", latest.to_string()));
    let (dl, expected_sha) = go_pick_file(ctx, &latest)?;
    if ctx.dry_run {
        info(ctx, format!("[dry-run] would download {dl} and install"));
        return Ok(());
    }

    let tmp = download_to_temp(ctx, &dl)?;
    let got = sha256_file(tmp.path())?;
    if !got.eq_ignore_ascii_case(&expected_sha) {
        bail!("Go sha256 mismatch: expected {expected_sha}, got {got}");
    }

    let tool_root = ctx.home.join("go");
    fs::create_dir_all(&tool_root)?;
    let ver_dir = tool_root.join(latest.to_string());
    ensure_clean_dir(&ver_dir)?;

    // extract tar.gz into ver_dir; tar contains top-level "go/"
    {
        let f = fs::File::open(tmp.path())?;
        let gz = flate2::read::GzDecoder::new(f);
        let mut ar = tar::Archive::new(gz);
        ar.unpack(&ver_dir)?;
    }

    // Active directory points to ver_dir/go
    let active = tool_root.join("active");
    let extracted_go_dir = ver_dir.join("go");
    atomic_symlink(&extracted_go_dir, &active)?;

    // link binaries
    link_dir_bins(&active.join("bin"), &ctx.bindir, &["go", "gofmt"])?;
    maybe_hint_go_bins(ctx);

    info(ctx, format!("go updated to {}", latest.to_string()));
    Ok(())
}

fn maybe_hint_go_bins(ctx: &Ctx) {
    let gobin = go_env_value("GOBIN");
    if let Some(dir) = gobin {
        maybe_path_hint_for_dir(ctx, std::path::Path::new(&dir), "go GOBIN");
        return;
    }
    for gopath in go_env_paths("GOPATH") {
        maybe_path_hint_for_dir(ctx, &gopath.join("bin"), "go GOPATH/bin");
    }
}

fn go_env_value(key: &str) -> Option<String> {
    run_capture("go", &["env", key])
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn go_env_paths(key: &str) -> Vec<std::path::PathBuf> {
    go_env_value(key)
        .map(|value| env::split_paths(&value).collect())
        .unwrap_or_default()
}
