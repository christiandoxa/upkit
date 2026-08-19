use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, http_get_text, info, run_capture,
    run_status, which_or_none,
};

const MOJO_RELEASES_URL: &str = "https://mojolang.org/releases/";
const PIXI_ADD_ARGS: &[&str] = &["add", "mojo"];
const PIXI_UPDATE_ARGS: &[&str] = &["update", "mojo"];
const UV_INSTALL_ARGS: &[&str] = &["pip", "install", "--upgrade", "mojo"];
const PIP_INSTALL_ARGS: &[&str] = &["install", "--upgrade", "mojo"];

pub fn mojo_latest(ctx: &Ctx) -> Result<Version> {
    let page = http_get_text(ctx, MOJO_RELEASES_URL)?;
    let re = Regex::new(r"Latest release:\s*([^<\s]+)")?;
    let raw = re
        .captures(&page)
        .and_then(|captures| captures.get(1).map(|value| value.as_str()))
        .ok_or_else(|| anyhow!("could not find latest Mojo release"))?;
    Version::parse_loose(raw)
        .ok_or_else(|| anyhow!("could not parse Mojo version from releases page: {raw}"))
}

pub fn check_mojo(ctx: &Ctx) -> Result<ToolReport> {
    let installed = which_or_none("mojo")
        .and_then(|_| run_capture("mojo", &["--version"]).ok())
        .and_then(|out| Version::parse_loose(&out));

    let mut notes =
        vec!["Uses the official mojolang.org stable release page; updates via pixi or uv.".into()];
    let latest = match mojo_latest(ctx) {
        Ok(version) => Some(version),
        Err(err) => {
            notes.push(format!("Latest check failed: {err}"));
            None
        }
    };
    let status = Status::from_versions(installed.as_ref(), latest.as_ref());

    Ok(ToolReport {
        tool: ToolKind::Mojo,
        installed,
        latest,
        status,
        method: UpdateMethod::BuiltIn,
        notes,
    })
}

pub fn update_mojo(ctx: &Ctx) -> Result<()> {
    if ctx.offline {
        bail!("offline mode enabled; Mojo update requires network access");
    }
    let report = check_mojo(ctx)?;
    let latest = report
        .latest
        .clone()
        .ok_or_else(|| anyhow!("latest unknown"))?;

    if matches!(report.status, Status::UpToDate) && !ctx.force {
        info(ctx, format!("mojo is up-to-date ({})", latest.to_string()));
        return Ok(());
    }

    let (program, args): (&str, &[&str]) = if which_or_none("pixi").is_some() {
        if report.installed.is_some() {
            ("pixi", PIXI_UPDATE_ARGS)
        } else {
            ("pixi", PIXI_ADD_ARGS)
        }
    } else if which_or_none("uv").is_some() {
        ("uv", UV_INSTALL_ARGS)
    } else if which_or_none("pip3").is_some() {
        ("pip3", PIP_INSTALL_ARGS)
    } else if which_or_none("pip").is_some() {
        ("pip", PIP_INSTALL_ARGS)
    } else {
        bail!("Mojo update requires pixi, uv, or pip; see https://mojolang.org/install/");
    };

    info(
        ctx,
        format!("Updating mojo via {} {}", program, args.join(" ")),
    );
    if ctx.dry_run {
        info(
            ctx,
            format!("[dry-run] would run: {} {}", program, args.join(" ")),
        );
        return Ok(());
    }

    let status = run_status(program, args)
        .with_context(|| format!("failed to run {program} update command"))?;
    if !status.success() {
        bail!("{program} Mojo update failed");
    }
    info(ctx, "mojo updated");
    Ok(())
}
