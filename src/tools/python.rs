use anyhow::{Result, anyhow, bail};
use regex::Regex;
use serde::Deserialize;
use std::{
    env,
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
};

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, atomic_symlink, download_to_temp,
    ensure_clean_dir, home_dir, http_get_json, http_get_text, info, keep_latest_version,
    link_dir_bins, maybe_path_hint_for_dir, prune_tool_versions, run_capture, run_output, warn,
    which_or_none,
};

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize)]
pub struct GhAsset {
    pub name: String,
    pub browser_download_url: String,
}

const PIP_GLOBALS_SNAPSHOT: &str = "pip-globals.txt";
const PYTHON_RELEASES_LATEST_URL: &str =
    "https://github.com/astral-sh/python-build-standalone/releases/latest";
const PYTHON_RELEASES_API_URL: &str =
    "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
const PYTHON_RELEASES_BASE_URL: &str = "https://github.com";

pub fn check_python(ctx: &Ctx) -> Result<ToolReport> {
    let installed = if let Some(bin) = python_bin_in_bindir(ctx, "python3") {
        let args = [OsStr::new("--version")];
        run_capture(bin.as_os_str(), &args).ok()
    } else {
        which_or_none("python3").and_then(|_| run_capture("python3", &["--version"]).ok())
    }
    .and_then(|out| Version::parse_loose(&out))
    .or_else(|| {
        if let Some(bin) = python_bin_in_bindir(ctx, "python") {
            let args = [OsStr::new("--version")];
            run_capture(bin.as_os_str(), &args).ok()
        } else {
            which_or_none("python").and_then(|_| run_capture("python", &["--version"]).ok())
        }
        .and_then(|out| Version::parse_loose(&out))
    });

    let mut notes = vec![
        "Uses astral-sh/python-build-standalone assets (.tar.zst).".into(),
        "Note: Upstream release assets don't reliably publish sha256; this MVP does best-effort verification (download integrity via TLS)."
            .into(),
    ];
    let latest = match python_latest(ctx) {
        Ok(version) => Some(version),
        Err(err) => {
            notes.push(format!("Latest check failed: {err}"));
            None
        }
    };
    let status = Status::from_versions(installed.as_ref(), latest.as_ref());

    Ok(ToolReport {
        tool: ToolKind::Python,
        installed,
        latest,
        status,
        method: UpdateMethod::DirectDownload,
        notes,
    })
}

pub fn python_target(ctx: &Ctx) -> Result<&'static str> {
    // Minimal targets; extend as needed.
    match (ctx.os.as_str(), ctx.arch.as_str()) {
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        _ => bail!(
            "python target not supported in this MVP for {} {}",
            ctx.os,
            ctx.arch
        ),
    }
}

pub fn python_latest(ctx: &Ctx) -> Result<Version> {
    // Pick the highest CPython version found in latest release assets.
    let rel = python_release_assets(ctx)?;

    let target = python_target(ctx)?;
    let re = Regex::new(r"^cpython-(\d+)\.(\d+)\.(\d+).*-([A-Za-z0-9_+-]+)\.tar\.zst$")?;

    let mut best: Option<Version> = None;
    for a in &rel.assets {
        if !a.name.ends_with(".tar.zst") {
            continue;
        }
        if !a.name.contains(target) {
            continue;
        }
        if let Some(c) = re.captures(&a.name) {
            let v = Version {
                major: c[1].parse()?,
                minor: c[2].parse()?,
                patch: c[3].parse()?,
                pre: None,
            };
            keep_latest_version(&mut best, v);
        }
    }

    best.ok_or_else(|| {
        anyhow!(
            "could not determine latest python version from python-build-standalone assets (tag {})",
            rel.tag_name
        )
    })
}

pub fn python_pick_asset(ctx: &Ctx, want: &Version) -> Result<GhAsset> {
    let rel = python_release_assets(ctx)?;

    let target = python_target(ctx)?;
    // Prefer smaller runtime installs, then optimized non-debug builds.
    let want_prefix = format!("cpython-{}.{}.{}", want.major, want.minor, want.patch);

    let mut candidates = rel
        .assets
        .into_iter()
        .filter(|a| {
            a.name.starts_with(&want_prefix)
                && a.name.contains(target)
                && a.name.ends_with(".tar.zst")
        })
        .collect::<Vec<_>>();

    candidates.sort_by_key(|a| (python_asset_priority(&a.name), a.name.clone()));

    candidates
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no python asset found for {}", want.to_string()))
}

fn python_asset_priority(name: &str) -> u8 {
    let debug = name.contains("debug");
    let freethreaded = name.contains("freethreaded");
    if name.contains("install_only") && !debug {
        return 0;
    }
    if name.contains("pgo+lto") && !debug && !freethreaded {
        return 1;
    }
    if !debug && !freethreaded {
        return 2;
    }
    if name.contains("pgo+lto") && !debug {
        return 3;
    }
    if !debug {
        return 4;
    }
    5
}

fn python_release_assets(ctx: &Ctx) -> Result<GhRelease> {
    match http_get_json(ctx, PYTHON_RELEASES_API_URL) {
        Ok(release) => Ok(release),
        Err(api_err) => python_release_assets_from_html(ctx).map_err(|html_err| {
            anyhow!("GitHub API failed: {api_err}; HTML fallback failed: {html_err}")
        }),
    }
}

fn python_release_assets_from_html(ctx: &Ctx) -> Result<GhRelease> {
    let latest_page = http_get_text(ctx, PYTHON_RELEASES_LATEST_URL)?;
    let expanded_re = Regex::new(r#"expanded_assets/([0-9A-Za-z._+-]+)"#)?;
    let tag = expanded_re
        .captures(&latest_page)
        .and_then(|captures| captures.get(1).map(|value| value.as_str().to_string()))
        .ok_or_else(|| anyhow!("could not find python-build-standalone expanded assets link"))?;

    let assets_url = format!(
        "{PYTHON_RELEASES_BASE_URL}/astral-sh/python-build-standalone/releases/expanded_assets/{tag}"
    );
    let assets_page = http_get_text(ctx, &assets_url)?;
    let asset_re = Regex::new(
        r#"/astral-sh/python-build-standalone/releases/download/([0-9A-Za-z._+-]+)/([^"<>]+\.tar\.zst)"#,
    )?;
    let mut assets = Vec::new();
    for captures in asset_re.captures_iter(&assets_page) {
        let Some(asset_tag) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        let Some(name) = captures.get(2).map(|value| value.as_str()) else {
            continue;
        };
        if assets.iter().any(|asset: &GhAsset| asset.name == name) {
            continue;
        }
        assets.push(GhAsset {
            name: name.to_string(),
            browser_download_url: format!(
                "{PYTHON_RELEASES_BASE_URL}/astral-sh/python-build-standalone/releases/download/{asset_tag}/{name}"
            ),
        });
    }
    if assets.is_empty() {
        bail!("could not find python-build-standalone assets in expanded assets page");
    }

    Ok(GhRelease {
        tag_name: tag,
        assets,
    })
}

pub fn update_python(ctx: &Ctx) -> Result<()> {
    if ctx.offline {
        bail!("offline mode enabled; Python update requires network access");
    }
    let report = check_python(ctx)?;
    let latest = report
        .latest
        .clone()
        .ok_or_else(|| anyhow!("latest unknown"))?;

    if matches!(report.status, Status::UpToDate) && !ctx.force {
        info(
            ctx,
            format!("python is up-to-date ({})", latest.to_string()),
        );
        return Ok(());
    }

    info(ctx, format!("Updating python -> {}", latest.to_string()));

    let tool_root = ctx.home.join("python");
    let prior_globals = collect_prior_pip_globals(ctx, &tool_root, !ctx.dry_run);
    let asset = python_pick_asset(ctx, &latest)?;
    let dl = asset.browser_download_url;

    if ctx.dry_run {
        info(
            ctx,
            format!("[dry-run] would download {} and install", asset.name),
        );
        return Ok(());
    }

    let tmp = download_to_temp(ctx, &dl)?;

    fs::create_dir_all(&tool_root)?;
    let ver_dir = tool_root.join(latest.to_string());
    ensure_clean_dir(&ver_dir)?;

    // Extract .tar.zst; per docs, tar content is prefixed with "python/".
    {
        let f = fs::File::open(tmp.path())?;
        let zst = zstd::Decoder::new(f)?;
        let mut ar = tar::Archive::new(zst);
        ar.unpack(&ver_dir)?;
    }

    let extracted = ver_dir.join("python");
    if !extracted.exists() {
        bail!(
            "unexpected python-build-standalone layout (expected {}/python)",
            ver_dir.display()
        );
    }

    let active = tool_root.join("active");
    atomic_symlink(&extracted, &active)?;

    // Link python + pip (the best effort; python-build-standalone uses install/bin).
    let bin = active.join("install").join("bin");
    let bin = if bin.exists() {
        bin
    } else {
        active.join("bin")
    };
    link_dir_bins(&bin, &ctx.bindir, &["python", "python3", "pip", "pip3"])?;
    maybe_hint_python_bins(ctx, &active);
    if let Err(err) = restore_pip_globals(&active, &prior_globals) {
        warn(ctx, format!("Failed to restore pip globals: {err}"));
    } else if let Err(err) = write_pip_globals_snapshot(&tool_root, &prior_globals) {
        warn(ctx, format!("Failed to write pip globals snapshot: {err}"));
    }

    if let Err(err) = prune_tool_versions(&tool_root, &ver_dir, &["active"]) {
        warn(ctx, format!("Failed to remove old python versions: {err}"));
    }

    info(ctx, format!("python updated to {}", latest.to_string()));
    Ok(())
}

fn collect_prior_pip_globals(ctx: &Ctx, tool_root: &Path, write_snapshot: bool) -> Vec<String> {
    let active = tool_root.join("active");
    if python_executable(&active).is_some() {
        match pip_global_packages(&active) {
            Ok(list) => {
                if write_snapshot {
                    if let Err(err) = write_pip_globals_snapshot(tool_root, &list) {
                        warn(ctx, format!("Failed to write pip globals snapshot: {err}"));
                    }
                }
                return list;
            }
            Err(err) => warn(ctx, format!("Failed to list pip globals: {err}")),
        }
    }

    match read_pip_globals_snapshot(tool_root) {
        Ok(list) => {
            if !list.is_empty() {
                info(
                    ctx,
                    format!(
                        "Restoring {} pip global package(s) from saved snapshot",
                        list.len()
                    ),
                );
            }
            list
        }
        Err(err) => {
            warn(ctx, format!("Failed to read pip globals snapshot: {err}"));
            Vec::new()
        }
    }
}

fn pip_globals_snapshot_path(tool_root: &Path) -> PathBuf {
    tool_root.join(PIP_GLOBALS_SNAPSHOT)
}

fn read_pip_globals_snapshot(tool_root: &Path) -> Result<Vec<String>> {
    let path = pip_globals_snapshot_path(tool_root);
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut packages = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect::<Vec<_>>();
    packages.sort();
    packages.dedup();
    Ok(packages)
}

fn write_pip_globals_snapshot(tool_root: &Path, packages: &[String]) -> Result<()> {
    let path = pip_globals_snapshot_path(tool_root);
    fs::create_dir_all(tool_root)?;
    if packages.is_empty() {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        return Ok(());
    }

    let mut packages = packages.to_vec();
    packages.sort();
    packages.dedup();
    let mut output = packages.join("\n");
    output.push('\n');
    fs::write(path, output)?;
    Ok(())
}

fn maybe_hint_python_bins(ctx: &Ctx, active: &Path) {
    let user_base = python_user_base(active).or_else(default_python_user_base);
    if let Some(base) = user_base {
        maybe_path_hint_for_dir(ctx, &base.join("bin"), "python user base bin");
    }
}

fn python_user_base(active: &Path) -> Option<PathBuf> {
    let python = active.join("install").join("bin").join("python3");
    let python = if python.exists() {
        python
    } else {
        active.join("bin").join("python3")
    };
    let args = [
        OsStr::new("-m"),
        OsStr::new("site"),
        OsStr::new("--user-base"),
    ];
    run_capture(python.as_os_str(), &args)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn default_python_user_base() -> Option<PathBuf> {
    env::var("PYTHONUSERBASE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".local")))
}

fn python_bin_in_bindir(ctx: &Ctx, name: &str) -> Option<PathBuf> {
    let candidate = ctx.bindir.join(name);
    if candidate.exists() {
        return Some(candidate);
    }
    None
}

fn python_executable(active: &Path) -> Option<PathBuf> {
    let install_bin = active.join("install").join("bin").join("python3");
    if install_bin.exists() {
        return Some(install_bin);
    }
    let bin = active.join("bin").join("python3");
    if bin.exists() {
        return Some(bin);
    }
    None
}

pub fn pip_global_packages(active: &Path) -> Result<Vec<String>> {
    let python = match python_executable(active) {
        Some(path) => path,
        None => return Ok(Vec::new()),
    };
    let args = [
        OsStr::new("-m"),
        OsStr::new("pip"),
        OsStr::new("list"),
        OsStr::new("--format=json"),
    ];
    let output = run_output(python.as_os_str(), &args)?;
    if !output.status.success() {
        bail!(
            "pip list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    if output.stdout.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let Some(list) = value.as_array() else {
        return Ok(Vec::new());
    };
    let mut packages = Vec::new();
    for entry in list {
        let Some(name) = entry.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if lower == "pip" || lower == "setuptools" || lower == "wheel" {
            continue;
        }
        let version = entry.get("version").and_then(|v| v.as_str()).unwrap_or("");
        if version.is_empty() {
            packages.push(name.to_string());
        } else {
            packages.push(format!("{name}=={version}"));
        }
    }
    packages.sort();
    packages.dedup();
    Ok(packages)
}

pub fn restore_pip_globals(active: &Path, packages: &[String]) -> Result<()> {
    if packages.is_empty() {
        return Ok(());
    }
    let python = match python_executable(active) {
        Some(path) => path,
        None => return Ok(()),
    };
    let program = python.to_string_lossy().to_string();
    let mut args = vec!["-m".to_string(), "pip".to_string(), "install".to_string()];
    args.extend(packages.iter().cloned());
    run_capture(program, &args)?;
    Ok(())
}
