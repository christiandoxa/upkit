use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde::Deserialize;
use std::{
    env,
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
};

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, download_to_temp, home_dir,
    http_get_json, http_get_text, info, keep_latest_version, link_managed_tool_bins,
    maybe_path_hint_for_dir, prune_tool_versions, run_capture, run_output, sha256_file, warn,
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
    pub digest: Option<String>,
}

const PIP_GLOBALS_SNAPSHOT: &str = "pip-globals.txt";
const PYTHON_ASSET_VERSION_RE: &str =
    r"^cpython-(\d+)\.(\d+)\.(\d+)([A-Za-z][0-9A-Za-z.-]*)?(?:\+[^-]+)?-[A-Za-z0-9_+-]+\.tar\.zst$";
const PYTHON_RELEASES_LATEST_URL: &str =
    "https://github.com/astral-sh/python-build-standalone/releases/latest";
const PYTHON_RELEASES_API_URL: &str =
    "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
const PYTHON_RELEASES_BASE_URL: &str = "https://github.com";

pub fn check_python(ctx: &Ctx) -> Result<ToolReport> {
    let names: &[&str] = if ctx.os == "windows" {
        &["python.exe", "python"]
    } else {
        &["python3", "python"]
    };
    let mut executable_found = false;
    let installed = names.iter().find_map(|name| {
        let bindir_bin = python_bin_in_bindir(ctx, name);
        let path_bin = if bindir_bin.is_none() {
            which_or_none(name)
        } else {
            None
        };
        if bindir_bin.is_none() && path_bin.is_none() {
            return None;
        }
        executable_found = true;
        if ctx.dry_run {
            return None;
        }
        let args = [OsStr::new("--version")];
        let output = if let Some(bin) = bindir_bin {
            run_capture(bin.as_os_str(), &args).ok()
        } else {
            run_capture(*name, &["--version"]).ok()
        }?;
        Version::parse_loose(&output)
    });

    let mut notes = vec![
        "Uses astral-sh/python-build-standalone assets (.tar.zst).".into(),
        "Archive installation requires a SHA-256 digest from GitHub release metadata.".into(),
    ];
    if ctx.os == "windows" {
        notes.push(
            "Windows installs link python.exe into Upkit bin; use python -m pip because the archive has no pip.exe launcher.".into(),
        );
        notes.push("Windows installation requires permission to create symbolic links.".into());
    }
    let latest = match python_latest(ctx) {
        Ok(version) => Some(version),
        Err(err) => {
            notes.push(format!("Latest check failed: {err}"));
            None
        }
    };
    let status = if ctx.dry_run && executable_found {
        Status::Unknown
    } else {
        Status::from_versions(installed.as_ref(), latest.as_ref())
    };
    if ctx.dry_run && executable_found {
        notes.push(
            "Dry-run found a Python executable; its version was not checked and is unknown.".into(),
        );
    }

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
    match (ctx.os.as_str(), ctx.arch.as_str()) {
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Ok("aarch64-unknown-linux-gnu"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("windows", "x86_64") => Ok("x86_64-pc-windows-msvc"),
        ("windows", "aarch64") => Ok("aarch64-pc-windows-msvc"),
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
    let re = Regex::new(PYTHON_ASSET_VERSION_RE)?;

    let mut best: Option<Version> = None;
    for a in &rel.assets {
        if !a.name.ends_with(".tar.zst") {
            continue;
        }
        if !python_asset_target_matches(&a.name, target) {
            continue;
        }
        if let Some(v) = python_asset_version(&re, &a.name)
            && v.pre.is_none()
        {
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
    let re = Regex::new(PYTHON_ASSET_VERSION_RE)?;

    let mut candidates = rel
        .assets
        .into_iter()
        .filter(|a| {
            python_asset_matches(&re, &a.name, want)
                && python_asset_target_matches(&a.name, target)
                && a.name.ends_with(".tar.zst")
        })
        .collect::<Vec<_>>();

    candidates.sort_by_key(|a| (python_asset_priority(&a.name), a.name.clone()));

    candidates
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no python asset found for {}", want))
}

fn python_asset_version(re: &Regex, name: &str) -> Option<Version> {
    let captures = re.captures(name)?;
    Some(Version {
        major: captures.get(1)?.as_str().parse().ok()?,
        minor: captures.get(2)?.as_str().parse().ok()?,
        patch: captures.get(3)?.as_str().parse().ok()?,
        pre: captures.get(4).map(|value| value.as_str().to_string()),
    })
}

fn python_asset_matches(re: &Regex, name: &str, want: &Version) -> bool {
    let Some(version) = python_asset_version(re, name) else {
        return false;
    };
    version == *want
}

fn python_asset_target_matches(name: &str, target: &str) -> bool {
    name.strip_prefix("cpython-")
        .and_then(|name| name.split_once('-'))
        .and_then(|(_, suffix)| suffix.strip_prefix(target))
        .is_some_and(|suffix| suffix.starts_with('-') || suffix == ".tar.zst")
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
            digest: None,
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
        info(ctx, format!("python is up-to-date ({})", latest));
        return Ok(());
    }

    info(ctx, format!("Updating python -> {}", latest));

    let tool_root = ctx.home.join("python");
    crate::infrastructure::validate_active_install(&tool_root)?;
    let asset = python_pick_asset(ctx, &latest)?;

    if ctx.dry_run {
        if matches!(report.status, Status::Unknown) {
            info(
                ctx,
                "[dry-run] Python executable found; installed version is unknown because it was not checked",
            );
        }
        info(
            ctx,
            format!("[dry-run] would download {} and install", asset.name),
        );
        return Ok(());
    }

    let expected = asset
        .digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow!("Python release metadata lacks a valid SHA-256 asset digest"))?;

    let tmp = download_to_temp(ctx, &asset.browser_download_url)?;
    if !sha256_file(tmp.path())?.eq_ignore_ascii_case(expected) {
        bail!("Python archive SHA-256 mismatch");
    }
    let prior_globals = collect_prior_pip_globals(ctx, &tool_root, true);

    crate::infrastructure::ensure_tool_root(&tool_root)?;
    crate::infrastructure::validate_active_install(&tool_root)?;
    let stage = crate::infrastructure::new_install_stage(&tool_root)?;

    // python-build-standalone archives are prefixed with "python/".
    super::archive::unpack_tar_zst(tmp.path(), stage.path(), 1)?;

    if !fs::symlink_metadata(stage.path().join("python"))
        .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
    {
        bail!(
            "unexpected python-build-standalone layout (expected {}/python)",
            stage.path().display()
        );
    }
    let active = tool_root.join("active");
    let stage_python = stage.path().join("python");
    let subdir = if ctx.os == "windows" {
        "install"
    } else if stage_python.join("install/bin").exists() {
        "install/bin"
    } else {
        "bin"
    };
    let launcher = if ctx.os == "windows" {
        "python.exe"
    } else {
        "python3"
    };
    let python_root = stage_python
        .canonicalize()
        .context("resolve staged Python installation")?;
    let python3 = stage_python
        .join(subdir)
        .join(launcher)
        .canonicalize()
        .context("inspect staged Python launcher")?;
    let metadata = fs::metadata(&python3)?;
    if !python3.starts_with(&python_root) || !metadata.is_file() || metadata.len() == 0 {
        bail!("staged Python launcher is missing or invalid inside its installation");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            bail!("staged python3 is not executable");
        }
    }
    let bin_names: &[&str] = if ctx.os == "windows" {
        &["python.exe"]
    } else {
        &["python", "python3", "pip", "pip3"]
    };
    crate::infrastructure::preflight_bin_links(
        Some(&stage_python.join(subdir)),
        &active.join(subdir),
        &ctx.bindir,
        bin_names,
    )?;
    crate::infrastructure::seal_managed_install(
        ctx,
        &tool_root,
        &stage,
        ToolKind::Python,
        &latest.to_string(),
    );
    let ver_dir = stage.keep();
    let extracted = ver_dir.join("python");
    crate::infrastructure::activate_managed_install(ctx, &tool_root, &extracted, ToolKind::Python)?;

    // Link python + pip (the best effort; python-build-standalone uses install/bin).
    let bin = active.join(subdir);
    link_managed_tool_bins(
        ctx,
        &tool_root,
        ToolKind::Python,
        &bin,
        &ctx.bindir,
        bin_names,
    )?;
    if ctx.os != "windows" {
        maybe_hint_python_bins(ctx, &active);
    }
    if let Err(err) = restore_pip_globals(&active, &prior_globals) {
        warn(ctx, format!("Failed to restore pip globals: {err}"));
    } else if let Err(err) = write_pip_globals_snapshot(&tool_root, &prior_globals) {
        warn(ctx, format!("Failed to write pip globals snapshot: {err}"));
    }

    if let Err(err) = prune_tool_versions(&tool_root, &ver_dir, &["active"]) {
        warn(ctx, format!("Failed to remove old python versions: {err}"));
    }

    info(ctx, format!("python updated to {}", latest));
    Ok(())
}

fn collect_prior_pip_globals(ctx: &Ctx, tool_root: &Path, write_snapshot: bool) -> Vec<String> {
    let active = tool_root.join("active");
    if python_executable(&active).is_some() {
        match pip_global_packages(&active) {
            Ok(list) => {
                if write_snapshot && let Err(err) = write_pip_globals_snapshot(tool_root, &list) {
                    warn(ctx, format!("Failed to write pip globals snapshot: {err}"));
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
    let python = python_executable(active)?;
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
    [
        "install/bin/python3",
        "install/python.exe",
        "bin/python3",
        "python.exe",
    ]
    .iter()
    .map(|path| active.join(path))
    .find(|path| path.exists())
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

#[cfg(test)]
mod windows_archive_fixture {
    use std::{fs, path::Path};

    #[test]
    #[ignore = "set UPKIT_PYTHON_WINDOWS_ARCHIVE to an official Windows CPython .tar.zst"]
    fn official_windows_archive_fits_extractor_limits_and_contains_launcher() {
        let archive = std::env::var_os("UPKIT_PYTHON_WINDOWS_ARCHIVE")
            .expect("official Python Windows archive path");
        let stage = tempfile::tempdir().unwrap();
        super::super::archive::unpack_tar_zst(Path::new(&archive), stage.path(), 1).unwrap();

        let descriptor: serde_json::Value =
            serde_json::from_slice(&fs::read(stage.path().join("python/PYTHON.json")).unwrap())
                .unwrap();
        assert!(matches!(
            descriptor["target_triple"].as_str(),
            Some("aarch64-pc-windows-msvc" | "x86_64-pc-windows-msvc")
        ));
        let launcher = fs::metadata(stage.path().join("python/install/python.exe")).unwrap();
        assert!(launcher.is_file() && launcher.len() > 0);
        #[cfg(windows)]
        {
            let native_target = match std::env::consts::ARCH {
                "x86_64" => "x86_64-pc-windows-msvc",
                "aarch64" => "aarch64-pc-windows-msvc",
                _ => "",
            };
            if descriptor["target_triple"].as_str() == Some(native_target) {
                let output =
                    std::process::Command::new(stage.path().join("python/install/python.exe"))
                        .arg("--version")
                        .output()
                        .unwrap();
                assert!(output.status.success());
                let version = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(version.starts_with("Python "));
            }
        }
    }
}
