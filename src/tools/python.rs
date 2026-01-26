use anyhow::{Result, anyhow, bail};
use regex::Regex;
use serde::Deserialize;
use std::{env, ffi::OsStr, fs, path::PathBuf};

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, atomic_symlink, download_to_temp,
    ensure_clean_dir, home_dir, http_get_json, info, keep_latest_version, link_dir_bins,
    maybe_path_hint_for_dir, prune_tool_versions, run_capture, run_output, warn, which_or_none,
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

    let latest = python_latest(ctx).ok();
    let status = Status::from_versions(installed.as_ref(), latest.as_ref());

    Ok(ToolReport {
        tool: ToolKind::Python,
        installed,
        latest,
        status,
        method: UpdateMethod::DirectDownload,
        notes: vec![
            "Uses astral-sh/python-build-standalone assets (.tar.zst).".into(),
            "Note: Upstream release assets don't reliably publish sha256; this MVP does best-effort verification (download integrity via TLS)."
                .into(),
        ],
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
    // API: /releases/latest
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let rel: GhRelease = http_get_json(ctx, url)?;

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
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let rel: GhRelease = http_get_json(ctx, url)?;

    let target = python_target(ctx)?;
    // prefer "install_only" if present; otherwise take first match
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

    candidates.sort_by_key(|a| {
        if a.name.contains("install_only") {
            0
        } else {
            1
        }
    });

    candidates
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no python asset found for {}", want.to_string()))
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
    let prior_globals = match pip_global_packages(&tool_root.join("active")) {
        Ok(list) => list,
        Err(err) => {
            warn(ctx, format!("Failed to list pip globals: {err}"));
            Vec::new()
        }
    };
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
    }

    if let Err(err) = prune_tool_versions(&tool_root, &ver_dir, &["active"]) {
        warn(ctx, format!("Failed to remove old python versions: {err}"));
    }

    info(ctx, format!("python updated to {}", latest.to_string()));
    Ok(())
}

fn maybe_hint_python_bins(ctx: &Ctx, active: &std::path::Path) {
    let user_base = python_user_base(active).or_else(default_python_user_base);
    if let Some(base) = user_base {
        maybe_path_hint_for_dir(ctx, &base.join("bin"), "python user base bin");
    }
}

fn python_user_base(active: &std::path::Path) -> Option<PathBuf> {
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

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::test_support::{output_with_status, reset_guard, set_run_output};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn pip_globals_filters_and_versions() {
        let _guard = reset_guard();
        let dir = tempdir().unwrap();
        let active = dir.path().join("active");
        let python = active.join("install").join("bin").join("python3");
        fs::create_dir_all(python.parent().unwrap()).unwrap();
        fs::write(&python, b"").unwrap();

        let json = r#"[{"name":"pip","version":"23.2"},{"name":"setuptools","version":"65.5"},{"name":"wheel","version":"0.41"},{"name":"requests","version":"2.31.0"},{"name":"black","version":"23.7"}]"#;
        set_run_output(
            python.to_string_lossy().as_ref(),
            &["-m", "pip", "list", "--format=json"],
            output_with_status(0, json.as_bytes(), b""),
        );
        let packages = pip_global_packages(&active).unwrap();
        assert_eq!(
            packages,
            vec!["black==23.7".to_string(), "requests==2.31.0".to_string()]
        );
    }

    #[test]
    fn pip_globals_errors_on_failed_list() {
        let _guard = reset_guard();
        let dir = tempdir().unwrap();
        let active = dir.path().join("active");
        let python = active.join("bin").join("python3");
        fs::create_dir_all(python.parent().unwrap()).unwrap();
        fs::write(&python, b"").unwrap();

        set_run_output(
            python.to_string_lossy().as_ref(),
            &["-m", "pip", "list", "--format=json"],
            output_with_status(1, b"", b"boom"),
        );
        let err = pip_global_packages(&active).unwrap_err();
        assert!(err.to_string().contains("pip list failed"));
    }

    #[test]
    fn restore_pip_globals_runs_install() {
        let _guard = reset_guard();
        let dir = tempdir().unwrap();
        let active = dir.path().join("active");
        let python = active.join("bin").join("python3");
        fs::create_dir_all(python.parent().unwrap()).unwrap();
        fs::write(&python, b"").unwrap();

        set_run_output(
            python.to_string_lossy().as_ref(),
            &["-m", "pip", "install", "requests==2.31.0", "black==23.7"],
            output_with_status(0, b"", b""),
        );
        let packages = vec!["requests==2.31.0".to_string(), "black==23.7".to_string()];
        restore_pip_globals(&active, &packages).unwrap();
    }
}

fn python_executable(active: &std::path::Path) -> Option<PathBuf> {
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

fn pip_global_packages(active: &std::path::Path) -> Result<Vec<String>> {
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

fn restore_pip_globals(active: &std::path::Path, packages: &[String]) -> Result<()> {
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
