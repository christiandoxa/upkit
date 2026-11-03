use anyhow::{Result, anyhow, bail};
use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

#[cfg(windows)]
use crate::sha256_file;
use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, home_dir, http_get_text, info,
    maybe_path_hint_for_dir, run_capture, which_or_none,
};

pub fn check_rust(ctx: &Ctx) -> Result<ToolReport> {
    let skip_execution = ctx.dry_run || ctx.offline;
    let rustc_found = which_or_none("rustc").is_some();
    let installed = if skip_execution {
        None
    } else if rustc_found {
        run_capture("rustc", &["--version"])
            .ok()
            .and_then(|out| Version::parse_loose(&out))
    } else {
        None
    };

    let channel = if skip_execution || (rustc_found && installed.is_none()) {
        None
    } else {
        installed
            .as_ref()
            .map(rust_channel)
            .unwrap_or(Some("stable"))
    };
    let latest = channel.and_then(|channel| rust_latest(ctx, channel).ok());
    let status = if !rustc_found {
        Status::NotInstalled
    } else if installed.is_none() {
        Status::Unknown
    } else {
        match channel {
            Some("beta" | "nightly") => Status::Unknown,
            Some(_) => Status::from_versions(installed.as_ref(), latest.as_ref()),
            None => Status::Unknown,
        }
    };
    let mut notes = vec![
        "Rust updates use the active rustup toolchain when rustc is managed by rustup.".into(),
    ];
    if !rustc_found {
        notes.push("No rustc executable was found on PATH.".into());
    } else if skip_execution {
        notes.push(format!(
            "Rust version and channel were not inspected in {} mode.",
            if ctx.dry_run { "dry-run" } else { "offline" }
        ));
    } else if installed.is_none() {
        notes.push("Rust executable was found, but its version could not be verified.".into());
    } else {
        match channel {
            Some(channel @ ("beta" | "nightly")) => notes.push(format!(
                "Detected the Rust {} channel; version numbers cannot reliably show whether this toolchain is current.",
                channel
            )),
            None => notes.push("Could not identify this rustc release channel.".into()),
            _ => {}
        }
    }
    if latest.is_none()
        && let Some(channel) = channel
    {
        notes.push(format!(
            "Could not fetch the latest Rust {} release; status may be unknown.",
            channel
        ));
    }

    Ok(ToolReport {
        tool: ToolKind::Rust,
        installed,
        latest,
        status,
        method: UpdateMethod::BuiltIn,
        notes,
    })
}

pub fn rust_latest_stable(ctx: &Ctx) -> Result<Version> {
    rust_latest(ctx, "stable")
}

fn rust_latest(ctx: &Ctx, channel: &str) -> Result<Version> {
    let url = format!("https://static.rust-lang.org/dist/channel-rust-{channel}.toml");
    let text = http_get_text(ctx, &url)?;
    let v = toml::from_str::<toml::Value>(&text)?;
    let s = v
        .get("pkg")
        .and_then(|p| p.get("rustc"))
        .and_then(|r| r.get("version"))
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("could not find pkg.rustc.version in manifest"))?;

    // Example: "1.85.0 (4d91de4e4 2025-02-17)"
    Version::parse_loose(s)
        .ok_or_else(|| anyhow!("could not parse rustc version from manifest: {s}"))
}

pub fn update_rust(ctx: &Ctx) -> Result<()> {
    if ctx.offline {
        bail!("offline mode enabled; Rust update requires network access");
    }
    let report = check_rust(ctx)?;
    let rustup = which_or_none("rustup")
        .ok_or_else(|| anyhow!("rustup not found in PATH; install Rust via rustup first"))?;

    if ctx.dry_run {
        info(
            ctx,
            "[dry-run] Rust status and active toolchain were not inspected; update plan is unknown.",
        );
        return Ok(());
    }

    if matches!(report.status, Status::UpToDate) && !ctx.force {
        info(ctx, "rust is up-to-date");
        return Ok(());
    }

    let toolchain = if let Some(rustc) = which_or_none("rustc") {
        if !rustup_manages_rustc(&rustc, &rustup)? {
            bail!(
                "rustc on PATH is not managed by the rustup on PATH; refusing to update a potentially unrelated toolchain"
            );
        }
        active_rustup_toolchain(&rustup)?
    } else {
        "stable".to_string()
    };
    if rustup_toolchain_is_pinned(&toolchain, &rustup)? {
        bail!(
            "Rust toolchain '{toolchain}' is pinned or could not be verified as a moving Rustup channel; change the rust-toolchain override to stable, beta, or nightly before updating"
        );
    }

    info(
        ctx,
        format!("Updating Rust through rustup update {toolchain}"),
    );
    let args = [OsStr::new("update"), OsStr::new(&toolchain)];
    let _ = run_capture(rustup.as_os_str(), &args)?;
    maybe_hint_rust_bins(ctx);
    info(ctx, format!("Rust toolchain {toolchain} updated"));
    Ok(())
}

fn active_rustup_toolchain(rustup: &Path) -> Result<String> {
    let args = [OsStr::new("show"), OsStr::new("active-toolchain")];
    let output = run_capture(rustup.as_os_str(), &args)?;
    let toolchain = output
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("rustup did not report an active toolchain"))?;
    if toolchain.is_empty()
        || !toolchain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        bail!("rustup reported an invalid active toolchain name");
    }
    Ok(toolchain.to_string())
}

fn rustup_toolchain_is_pinned(toolchain: &str, rustup: &Path) -> Result<bool> {
    for channel in ["stable", "beta", "nightly"] {
        if toolchain == channel {
            return Ok(false);
        }
        if let Some(target_or_date) = toolchain
            .strip_prefix(channel)
            .and_then(|suffix| suffix.strip_prefix('-'))
        {
            let bytes = target_or_date.as_bytes();
            let is_date = bytes.len() >= 10
                && bytes[0..4].iter().all(u8::is_ascii_digit)
                && bytes[4] == b'-'
                && bytes[5..7].iter().all(u8::is_ascii_digit)
                && bytes[7] == b'-'
                && bytes[8..10].iter().all(u8::is_ascii_digit)
                && (bytes.len() == 10 || bytes[10] == b'-');
            if is_date {
                return Ok(true);
            }

            let args = [
                OsStr::new("target"),
                OsStr::new("list"),
                OsStr::new("--toolchain"),
                OsStr::new(toolchain),
            ];
            let Ok(targets) = run_capture(rustup.as_os_str(), &args) else {
                return Ok(true);
            };
            return Ok(!targets
                .lines()
                .any(|line| line.split_whitespace().next() == Some(target_or_date)));
        }
    }
    Ok(true)
}

fn rustup_manages_rustc(rustc: &Path, rustup: &Path) -> Result<bool> {
    if same_file(rustc, rustup) {
        return Ok(true);
    }

    let args = [OsStr::new("which"), OsStr::new("rustc")];
    let Ok(output) = run_capture(rustup.as_os_str(), &args) else {
        return Ok(false);
    };
    Ok(same_file(rustc, Path::new(output.trim())))
}

fn same_file(left: &Path, right: &Path) -> bool {
    if let (Ok(left), Ok(right)) = (fs::canonicalize(left), fs::canonicalize(right))
        && left == right
    {
        return true;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(left), Ok(right)) = (fs::metadata(left), fs::metadata(right)) {
            return left.dev() == right.dev() && left.ino() == right.ino();
        }
    }

    #[cfg(windows)]
    {
        let (Ok(left_metadata), Ok(right_metadata)) = (fs::metadata(left), fs::metadata(right))
        else {
            return false;
        };
        if left_metadata.len() == right_metadata.len()
            && sha256_file(left).ok().is_some_and(|left_hash| {
                sha256_file(right)
                    .ok()
                    .is_some_and(|right_hash| left_hash == right_hash)
            })
        {
            return true;
        }
    }

    false
}

fn rust_channel(version: &Version) -> Option<&'static str> {
    match version.pre.as_deref() {
        None => Some("stable"),
        Some(value) if value == "beta" || value.starts_with("beta.") => Some("beta"),
        Some(value) if value == "nightly" || value.starts_with("nightly.") => Some("nightly"),
        _ => None,
    }
}

fn maybe_hint_rust_bins(ctx: &Ctx) {
    if let Some(cargo_bin) = cargo_bin_dir() {
        maybe_path_hint_for_dir(ctx, &cargo_bin, "cargo bin");
    }
}

fn cargo_bin_dir() -> Option<PathBuf> {
    let cargo_home = env::var("CARGO_HOME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".cargo")))?;
    Some(cargo_home.join("bin"))
}
