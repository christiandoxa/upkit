use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::{collections::HashMap, ffi::OsStr, fs, path::PathBuf};

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, atomic_symlink, download_to_temp,
    ensure_clean_dir, http_get_json, http_get_text, info, keep_latest_version, link_dir_bins,
    maybe_path_hint_for_dir, prune_tool_versions, run_capture, run_output, sha256_file, warn,
    which_or_none,
};

#[derive(Debug, Deserialize)]
struct NodeIndexEntry {
    version: String,        // "v24.11.1"
    lts: serde_json::Value, // false or string (codename)
}

pub fn node_os_arch(ctx: &Ctx) -> (String, String) {
    let os = match ctx.os.as_str() {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "win",
        other => other,
    }
    .to_string();

    let arch = match ctx.arch.as_str() {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    }
    .to_string();

    (os, arch)
}

pub fn check_node(ctx: &Ctx) -> Result<ToolReport> {
    let installed = if let Some(bin) = node_bin_in_bindir(ctx) {
        let args = [OsStr::new("--version")];
        run_capture(bin.as_os_str(), &args).ok()
    } else {
        which_or_none("node").and_then(|_| run_capture("node", &["--version"]).ok())
    }
    .and_then(|out| Version::parse_loose(&out));

    let latest = node_latest_lts(ctx).ok();
    let status = Status::from_versions(installed.as_ref(), latest.as_ref());

    Ok(ToolReport {
        tool: ToolKind::Node,
        installed,
        latest,
        status,
        method: UpdateMethod::DirectDownload,
        notes: vec!["Targets LTS line from nodejs.org dist index.".into()],
    })
}

pub fn node_latest_lts(ctx: &Ctx) -> Result<Version> {
    let url = "https://nodejs.org/dist/index.json";
    let idx: Vec<NodeIndexEntry> = http_get_json(ctx, url)?;
    // Index is usually newest-first, but we'll be defensive.
    let mut best: Option<Version> = None;
    for e in idx {
        // lts != false
        let is_lts = match &e.lts {
            serde_json::Value::Bool(b) => *b,
            serde_json::Value::String(_) => true,
            _ => false,
        };
        if !is_lts {
            continue;
        }
        if let Some(v) = Version::parse_loose(&e.version) {
            keep_latest_version(&mut best, v);
        }
    }
    best.ok_or_else(|| anyhow!("could not determine latest Node LTS"))
}

pub fn node_artifact_name(ctx: &Ctx, v: &Version) -> Result<String> {
    let (os, arch) = node_os_arch(ctx);
    // Prefer .tar.xz for unix, but fall back to .tar.gz.
    let base = format!("node-v{}-{}-{}", v.to_string(), os, arch);
    if os == "win" {
        // For simplicity, use zip on Windows (not fully handled in this MVP).
        bail!("windows node install not implemented in this MVP");
    }
    Ok(format!("{base}.tar.xz"))
}

pub fn node_shasums(ctx: &Ctx, version_tag: &str) -> Result<HashMap<String, String>> {
    // version_tag like "v24.11.1"
    let url = format!("https://nodejs.org/dist/{}/SHASUMS256.txt", version_tag);
    let text = http_get_text(ctx, &url)?;
    let mut map = HashMap::new();
    for line in text.lines() {
        // "<sha>  <filename>"
        let mut parts = line.split_whitespace();
        let sha = parts.next();
        let file = parts.next();
        if let (Some(sha), Some(file)) = (sha, file) {
            map.insert(file.to_string(), sha.to_string());
        }
    }
    Ok(map)
}

pub fn update_node(ctx: &Ctx) -> Result<()> {
    if ctx.offline {
        bail!("offline mode enabled; Node update requires network access");
    }
    let report = check_node(ctx)?;
    let latest = report
        .latest
        .clone()
        .ok_or_else(|| anyhow!("latest unknown"))?;

    if matches!(report.status, Status::UpToDate) && !ctx.force {
        info(ctx, format!("node is up-to-date ({})", latest.to_string()));
        return Ok(());
    }

    info(
        ctx,
        format!("Updating node (LTS) -> {}", latest.to_string()),
    );
    let artifact = node_artifact_name(ctx, &latest)?;
    let version_tag = format!("v{}", latest.to_string());
    let dl = format!("https://nodejs.org/dist/{}/{}", version_tag, artifact);

    if ctx.dry_run {
        info(ctx, format!("[dry-run] would download {dl} and install"));
        return Ok(());
    }

    let tool_root = ctx.home.join("node");
    let prior_globals = match npm_global_packages(&tool_root.join("active")) {
        Ok(list) => list,
        Err(err) => {
            warn(ctx, format!("Failed to list npm globals: {err}"));
            Vec::new()
        }
    };

    // verify sha256 from SHASUMS256.txt
    let sums = node_shasums(ctx, &version_tag)?;
    let expected = sums
        .get(&artifact)
        .ok_or_else(|| anyhow!("could not find checksum for {artifact} in SHASUMS256.txt"))?
        .to_string();

    let tmp = download_to_temp(ctx, &dl)?;
    let got = sha256_file(tmp.path())?;
    if !got.eq_ignore_ascii_case(&expected) {
        bail!("Node sha256 mismatch: expected {expected}, got {got}");
    }

    fs::create_dir_all(&tool_root)?;
    let ver_dir = tool_root.join(latest.to_string());
    ensure_clean_dir(&ver_dir)?;

    // extract tar.xz into ver_dir; tar contains top-level "node-vX.Y.Z-OS-ARCH/"
    {
        let f = fs::File::open(tmp.path())?;
        let xz = xz2::read::XzDecoder::new(f);
        let mut ar = tar::Archive::new(xz);
        ar.unpack(&ver_dir)?;
    }

    let extracted = fs::read_dir(&ver_dir)?
        .filter_map(|e| e.ok())
        .find(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .ok_or_else(|| anyhow!("unexpected node archive layout"))?
        .path();

    let active = tool_root.join("active");
    atomic_symlink(&extracted, &active)?;

    let bin_dir = active.join("bin");
    link_dir_bins(&bin_dir, &ctx.bindir, &["node", "npm", "npx", "corepack"])?;
    if let Err(err) = ensure_npm_prefix(&active) {
        warn(ctx, format!("Failed to set npm prefix: {err}"));
    }
    if let Err(err) = restore_npm_globals(&active, &prior_globals) {
        warn(ctx, format!("Failed to restore npm globals: {err}"));
    }
    maybe_path_hint_for_dir(ctx, &bin_dir, "npm global bin");

    if let Err(err) = prune_tool_versions(&tool_root, &ver_dir, &["active"]) {
        warn(ctx, format!("Failed to remove old node versions: {err}"));
    }

    info(ctx, format!("node updated to {}", latest.to_string()));
    Ok(())
}

fn npm_global_packages(active: &std::path::Path) -> Result<Vec<String>> {
    let npm_path = active.join("bin").join("npm");
    if !npm_path.exists() {
        return Ok(Vec::new());
    }
    let program = npm_path.to_string_lossy().to_string();
    let args = vec![
        "ls".to_string(),
        "-g".to_string(),
        "--depth=0".to_string(),
        "--json".to_string(),
    ];
    let output = run_output(program, &args)?;
    if output.stdout.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let Some(deps) = value.get("dependencies").and_then(|deps| deps.as_object()) else {
        return Ok(Vec::new());
    };
    let mut names = deps
        .keys()
        .filter(|name| *name != "npm" && *name != "corepack")
        .cloned()
        .collect::<Vec<_>>();
    names.sort();
    Ok(names)
}

fn restore_npm_globals(active: &std::path::Path, packages: &[String]) -> Result<()> {
    if packages.is_empty() {
        return Ok(());
    }
    let npm_path = active.join("bin").join("npm");
    if !npm_path.exists() {
        return Ok(());
    }
    let program = npm_path.to_string_lossy().to_string();
    let mut args = vec!["install".to_string(), "-g".to_string()];
    args.extend(packages.iter().cloned());
    run_capture(program, &args)?;
    Ok(())
}

pub fn ensure_npm_prefix(active: &std::path::Path) -> Result<()> {
    let desired_prefix = active.to_string_lossy().to_string();
    let npm_path = active.join("bin").join("npm");
    if !npm_path.exists() {
        return Ok(());
    }
    let current_prefix = {
        let args = [
            OsStr::new("config"),
            OsStr::new("get"),
            OsStr::new("prefix"),
        ];
        run_capture(npm_path.as_os_str(), &args)
    }
    .ok()
    .map(|value| value.trim().to_string());
    if current_prefix.as_deref() == Some(desired_prefix.as_str()) {
        return Ok(());
    }
    let args = [
        OsStr::new("config"),
        OsStr::new("set"),
        OsStr::new("prefix"),
        OsStr::new(desired_prefix.as_str()),
    ];
    run_capture(npm_path.as_os_str(), &args)?;
    Ok(())
}

fn node_bin_in_bindir(ctx: &Ctx) -> Option<PathBuf> {
    let candidate = ctx.bindir.join("node");
    if candidate.exists() {
        return Some(candidate);
    }
    None
}
