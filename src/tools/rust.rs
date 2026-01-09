use anyhow::{Result, anyhow, bail};

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, home_dir, http_get_text, info,
    maybe_path_hint_for_dir, run_capture, which_or_none,
};
use std::{env, path::PathBuf};

pub fn check_rust(ctx: &Ctx) -> Result<ToolReport> {
    let installed = which_or_none("rustc")
        .and_then(|_| run_capture("rustc", &["--version"]).ok())
        .and_then(|out| Version::parse_loose(&out));

    let latest = rust_latest_stable(ctx).ok();
    let status = match (&installed, &latest) {
        (None, Some(_)) => Status::NotInstalled,
        (Some(i), Some(l)) if i >= l => Status::UpToDate,
        (Some(_), Some(_)) => Status::Outdated,
        _ => Status::Unknown,
    };

    Ok(ToolReport {
        tool: ToolKind::Rust,
        installed,
        latest,
        status,
        method: UpdateMethod::BuiltIn,
        notes: vec!["Uses rustup (built-in updater).".into()],
    })
}

pub fn rust_latest_stable(ctx: &Ctx) -> Result<Version> {
    // Parse stable channel manifest.
    // URL is documented in Rust Forge channel layout.
    let url = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
    let text = http_get_text(ctx, url)?;
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
    if which_or_none("rustup").is_none() {
        bail!("rustup not found in PATH; install Rust via rustup first");
    }

    if matches!(report.status, Status::UpToDate) && !ctx.force {
        info(ctx, "rust is up-to-date");
        return Ok(());
    }

    info(ctx, "Updating rust via rustup update stable");
    if ctx.dry_run {
        info(ctx, "[dry-run] would run: rustup update stable");
        return Ok(());
    }

    let _ = run_capture("rustup", &["update", "stable"])?;
    maybe_hint_rust_bins(ctx);
    info(ctx, "rust updated");
    Ok(())
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
