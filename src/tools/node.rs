use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::{collections::HashMap, ffi::OsStr, fs, path::PathBuf};

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, download_to_temp, http_get_json,
    http_get_text, info, keep_latest_version, link_managed_tool_bins, maybe_path_hint_for_dir,
    prune_tool_versions, run_capture, run_output, sha256_file, warn, which_or_none,
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
    let bindir_bin = node_bin_in_bindir(ctx);
    let path_bin = bindir_bin.is_none() && which_or_none("node").is_some();
    let executable_found = bindir_bin.is_some() || path_bin;
    let installed = if ctx.dry_run {
        None
    } else if let Some(bin) = bindir_bin {
        let args = [OsStr::new("--version")];
        run_capture(bin.as_os_str(), &args).ok()
    } else if path_bin {
        run_capture("node", &["--version"]).ok()
    } else {
        None
    }
    .and_then(|out| Version::parse_loose(&out));

    let latest = node_latest_lts(ctx).ok();
    let version_unverified = executable_found && installed.is_none();
    let status = if version_unverified {
        Status::Unknown
    } else {
        Status::from_versions(installed.as_ref(), latest.as_ref())
    };

    let mut notes = vec!["Targets LTS line from nodejs.org dist index.".into()];
    if ctx.dry_run && executable_found {
        notes.push(
            "Dry-run found a Node executable; its version was not checked and is unknown.".into(),
        );
    } else if version_unverified {
        notes.push("A Node executable was found, but its version could not be verified.".into());
    }
    if ctx.os == "windows" {
        notes.push("Windows installation requires permission to create symbolic links.".into());
        notes.push("Windows: put node/active first on PATH.".into());
        notes.push(format!(
            "Windows Node PATH: {}",
            crate::sweep::display_path(&ctx.home.join("node/active"))
        ));
    }
    Ok(ToolReport {
        tool: ToolKind::Node,
        installed,
        latest,
        status,
        method: UpdateMethod::DirectDownload,
        notes,
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
    let base = format!("node-v{}-{}-{}", v, os, arch);
    if os == "win" && !matches!(arch.as_str(), "x64" | "arm64") {
        bail!("unsupported Windows Node.js architecture: {arch}");
    }
    Ok(format!(
        "{base}{}",
        if os == "win" { ".zip" } else { ".tar.xz" }
    ))
}

pub fn node_shasums(ctx: &Ctx, version_tag: &str) -> Result<HashMap<String, String>> {
    // version_tag like "v24.11.1"
    let url = format!("https://nodejs.org/dist/{}/SHASUMS256.txt", version_tag);
    let text = http_get_text(ctx, &url)?;
    parse_node_shasums(&text)
}

fn parse_node_shasums(text: &str) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for (line_number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let sha = parts.next().unwrap_or_default();
        let file = parts.next().unwrap_or_default();
        if sha.len() != 64
            || !sha.bytes().all(|byte| byte.is_ascii_hexdigit())
            || file.is_empty()
            || parts.next().is_some()
        {
            bail!(
                "malformed SHA-256 checksum entry on SHASUMS line {}",
                line_number + 1
            );
        }
        if map.contains_key(file) {
            bail!(
                "duplicate checksum entry on SHASUMS line {}",
                line_number + 1
            );
        }
        map.insert(file.to_owned(), sha.to_owned());
    }
    if map.is_empty() {
        bail!("SHASUMS256.txt contains no checksum entries");
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
        info(ctx, format!("node is up-to-date ({})", latest));
        return Ok(());
    }

    info(ctx, format!("Updating node (LTS) -> {}", latest));
    let artifact = node_artifact_name(ctx, &latest)?;
    let version_tag = format!("v{}", latest);
    let dl = format!("https://nodejs.org/dist/{}/{}", version_tag, artifact);

    if ctx.dry_run {
        if matches!(report.status, Status::Unknown) {
            info(
                ctx,
                "[dry-run] Node executable found; installed version is unknown because it was not checked",
            );
        }
        info(ctx, format!("[dry-run] would download {dl} and install"));
        return Ok(());
    }

    let tool_root = ctx.home.join("node");
    crate::infrastructure::validate_active_install(&tool_root)?;
    let prior_globals = if ctx.os == "windows" {
        Vec::new()
    } else {
        match npm_global_packages(&tool_root.join("active")) {
            Ok(list) => list,
            Err(err) => {
                warn(ctx, format!("Failed to list npm globals: {err}"));
                Vec::new()
            }
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

    crate::infrastructure::ensure_tool_root(&tool_root)?;
    crate::infrastructure::validate_active_install(&tool_root)?;
    let stage = crate::infrastructure::new_install_stage(&tool_root)?;

    if ctx.os == "windows" {
        super::archive::unpack_windows_zip(tmp.path(), stage.path())?;
    } else {
        let xz = xz2::read::XzDecoder::new(fs::File::open(tmp.path())?);
        super::archive::unpack_tar(xz, stage.path(), 1)?;
    }
    let extracted_name = artifact
        .strip_suffix(if ctx.os == "windows" {
            ".zip"
        } else {
            ".tar.xz"
        })
        .context("unexpected node archive format")?;
    let mut entries = fs::read_dir(stage.path())?;
    let entry = entries.next().context("unexpected node archive layout")??;
    if entry.file_name() != extracted_name
        || !entry.file_type()?.is_dir()
        || entries.next().transpose()?.is_some()
    {
        bail!("unexpected node archive layout");
    }
    let extracted = entry.path();
    if ctx.os == "windows" {
        for name in [
            "node.exe",
            "npm.cmd",
            "npx.cmd",
            "node_modules/npm/bin/npm-cli.js",
            "node_modules/npm/bin/npx-cli.js",
            "node_modules/npm/bin/npm-prefix.js",
        ] {
            let path = extracted.join(name);
            let metadata =
                fs::symlink_metadata(&path).with_context(|| format!("inspect staged {name}"))?;
            if !metadata.is_file() || metadata.len() == 0 {
                bail!("staged {name} is not a nonempty regular file");
            }
        }
        crate::infrastructure::seal_managed_install(
            ctx,
            &tool_root,
            &stage,
            ToolKind::Node,
            &latest.to_string(),
        );
        let ver_dir = stage.keep();
        crate::infrastructure::activate_managed_install(
            ctx,
            &tool_root,
            &ver_dir.join(extracted_name),
            ToolKind::Node,
        )?;
        warn(
            ctx,
            format!(
                "Put {} first on PATH for node, npm and npx; restart your terminal.",
                crate::sweep::display_path(&tool_root.join("active"))
            ),
        );
        if let Err(err) = prune_tool_versions(&tool_root, &ver_dir, &["active"]) {
            warn(ctx, format!("Failed to remove old node versions: {err}"));
        }
        info(ctx, format!("node updated to {}", latest));
        return Ok(());
    }
    let canonical_root = extracted.canonicalize()?;
    for name in ["node", "npm", "npx", "corepack"] {
        let path = extracted.join("bin").join(name);
        match fs::symlink_metadata(&path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && name != "node" => continue,
            Err(err) => return Err(err).with_context(|| format!("inspect staged {name}")),
            Ok(_) => {}
        }
        let resolved = path
            .canonicalize()
            .with_context(|| format!("resolve staged {name}"))?;
        if !resolved.starts_with(&canonical_root) || !resolved.is_file() {
            bail!("staged {name} is not a file inside the Node installation");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if resolved.metadata()?.permissions().mode() & 0o111 == 0 {
                bail!("staged {name} is not executable");
            }
        }
    }
    let active = tool_root.join("active");
    crate::infrastructure::preflight_bin_links(
        Some(&extracted.join("bin")),
        &active.join("bin"),
        &ctx.bindir,
        &["node", "npm", "npx", "corepack"],
    )?;
    crate::infrastructure::seal_managed_install(
        ctx,
        &tool_root,
        &stage,
        ToolKind::Node,
        &latest.to_string(),
    );
    let ver_dir = stage.keep();
    let extracted = ver_dir.join(extracted_name);

    crate::infrastructure::activate_managed_install(ctx, &tool_root, &extracted, ToolKind::Node)?;

    let bin_dir = active.join("bin");
    link_managed_tool_bins(
        ctx,
        &tool_root,
        ToolKind::Node,
        &bin_dir,
        &ctx.bindir,
        &["node", "npm", "npx", "corepack"],
    )?;
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

    info(ctx, format!("node updated to {}", latest));
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
    if ctx.os == "windows" {
        let root = ctx.home.join("node");
        let active = root.join("active");
        let binary = active.join("node.exe");
        if crate::infrastructure::validate_active_install(&root).is_ok()
            && let (Ok(dir), Ok(resolved)) = (active.canonicalize(), binary.canonicalize())
            && resolved.starts_with(dir)
            && resolved.is_file()
        {
            return Some(binary);
        }
    }
    let candidate = ctx.bindir.join(if ctx.os == "windows" {
        "node.exe"
    } else {
        "node"
    });
    if candidate.exists() {
        return Some(candidate);
    }
    None
}
