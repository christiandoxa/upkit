//! Eclipse Temurin LTS JDK discovery and archive installation.
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, download_to_temp, http_get_json,
    info, link_managed_tool_bins, run_output, sha256_file, which_or_none,
};

const RELEASES: &str = "https://api.adoptium.net/v3/info/available_releases";

#[derive(Deserialize)]
struct Available {
    most_recent_lts: u64,
}

#[derive(Deserialize)]
struct Asset {
    binary: Binary,
    version: AssetVersion,
    vendor: String,
}

#[derive(Deserialize)]
struct Binary {
    architecture: String,
    os: String,
    image_type: String,
    jvm_impl: String,
    heap_size: String,
    package: Package,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    link: String,
    checksum: String,
}

#[derive(Deserialize)]
struct AssetVersion {
    major: u64,
    minor: u64,
    security: u64,
}

struct Release {
    version: Version,
    package: Package,
}

fn platform(ctx: &Ctx) -> Result<(&'static str, &'static str)> {
    let os = match ctx.os.as_str() {
        "linux" => "linux",
        "macos" => "mac",
        "windows" => "windows",
        _ => bail!("Temurin JDK is unavailable for this operating system"),
    };
    let arch = match ctx.arch.as_str() {
        "x86_64" => "x64",
        "aarch64" => "aarch64",
        _ => bail!("Temurin JDK is unavailable for this architecture"),
    };
    Ok((os, arch))
}

fn release(ctx: &Ctx) -> Result<Release> {
    let (os, arch) = platform(ctx)?;
    let available: Available = http_get_json(ctx, RELEASES)?;
    if !(11..=999).contains(&available.most_recent_lts) {
        bail!("Temurin metadata has an invalid LTS version");
    }
    let url = format!(
        "https://api.adoptium.net/v3/assets/latest/{}/hotspot?architecture={arch}&heap_size=normal&image_type=jdk&os={os}&vendor=eclipse",
        available.most_recent_lts
    );
    let assets: Vec<Asset> = http_get_json(ctx, &url)?;
    let mut matches = assets.into_iter().filter(|asset| {
        asset.binary.os == os
            && asset.binary.architecture == arch
            && asset.binary.image_type == "jdk"
            && asset.binary.jvm_impl == "hotspot"
            && asset.binary.heap_size == "normal"
            && asset.vendor == "eclipse"
            && asset.version.major == available.most_recent_lts
    });
    let asset = matches
        .next()
        .context("no matching Temurin LTS JDK archive")?;
    if matches.next().is_some() {
        bail!("Temurin metadata contains multiple matching JDK archives");
    }
    let package = asset.binary.package;
    let url = reqwest::Url::parse(&package.link).context("invalid Temurin download URL")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
        || !matches!(url.host_str(), Some("github.com" | "api.adoptium.net"))
        || package.checksum.len() != 64
        || !package
            .checksum
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("Temurin metadata lacks an official HTTPS archive URL or valid SHA-256 checksum");
    }
    Ok(Release {
        version: Version {
            major: asset.version.major,
            minor: asset.version.minor,
            patch: asset.version.security,
            pre: None,
        },
        package,
    })
}

fn installed(ctx: &Ctx) -> (Option<Version>, bool) {
    let managed = ctx.bindir.join(if ctx.os == "windows" {
        "javac.exe"
    } else {
        "javac"
    });
    let executable = if managed.is_file() {
        Some(managed)
    } else if ctx.os == "macos" {
        let path = which_or_none("javac");
        match path {
            Some(path) if path != Path::new("/usr/bin/javac") => Some(path),
            _ => macos_javac(),
        }
    } else {
        which_or_none("javac")
    };
    let Some(executable) = executable else {
        return (None, false);
    };
    let Ok(output) = run_output(executable.as_os_str(), &[OsStr::new("-version")]) else {
        return (None, true);
    };
    if !output.status.success() {
        return (None, true);
    }
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (parse_version(&text), true)
}

fn macos_javac() -> Option<PathBuf> {
    let args = vec!["--failfast".to_owned()];
    let output = if let Some(output) =
        crate::test_support::take_run_output("/usr/libexec/java_home", &args)
    {
        output
    } else {
        // Older Apple builds may turn --failfast into an install request when ISMAC is set.
        Command::new("/usr/libexec/java_home")
            .arg("--failfast")
            .env_remove("ISMAC")
            .output()
            .ok()?
    };
    if !output.status.success() {
        return None;
    }
    let home = String::from_utf8_lossy(&output.stdout);
    let home = Path::new(home.trim());
    home.is_absolute().then(|| home.join("bin/javac"))
}

fn parse_version(text: &str) -> Option<Version> {
    let token = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("javac "))?
        .split_whitespace()
        .next()?;
    let core = token.split(['+', '-']).next()?;
    let mut pieces = core.split(['.', '_']);
    let first: u64 = pieces.next()?.parse().ok()?;
    let second = pieces.next().unwrap_or("0").parse().ok()?;
    let third = pieces.next().unwrap_or("0").parse().ok()?;
    let (major, minor, patch) = if first == 1 && second == 8 {
        (8, third, pieces.next().unwrap_or("0").parse().ok()?)
    } else {
        (first, second, third)
    };
    Some(Version {
        major,
        minor,
        patch,
        pre: token.split_once('-').map(|(_, pre)| pre.to_owned()),
    })
}

pub fn check_java(ctx: &Ctx) -> Result<ToolReport> {
    let (installed, executable_found) = if ctx.dry_run {
        (None, false)
    } else {
        installed(ctx)
    };
    let latest = release(ctx).ok().map(|release| release.version);
    let status = if ctx.dry_run || (executable_found && installed.is_none()) {
        Status::Unknown
    } else {
        Status::from_versions(installed.as_ref(), latest.as_ref())
    };
    let mut notes = vec!["Targets Eclipse Temurin LTS JDK; JAVA_HOME is not changed.".into()];
    if ctx.dry_run {
        notes.push("Installed JDK version was not verified during dry-run.".into());
    } else if executable_found && installed.is_none() {
        notes.push("A javac executable was found, but its version could not be verified.".into());
    }
    if ctx.os == "windows" {
        notes.push("Windows installation requires permission to create symbolic links.".into());
    }
    if latest.is_none() {
        notes.push("Could not determine the latest compatible Temurin LTS JDK.".into());
    }
    Ok(ToolReport {
        tool: ToolKind::Java,
        installed,
        latest,
        status,
        method: UpdateMethod::DirectDownload,
        notes,
    })
}

pub fn update_java(ctx: &Ctx) -> Result<()> {
    if ctx.offline {
        bail!("offline mode enabled; JDK update requires network access");
    }
    let (os, _) = platform(ctx)?;
    let release = release(ctx)?;
    if !release
        .package
        .name
        .ends_with(if os == "windows" { ".zip" } else { ".tar.gz" })
    {
        bail!("unexpected Temurin archive format");
    }
    if !ctx.dry_run
        && installed(ctx)
            .0
            .is_some_and(|version| version >= release.version)
        && !ctx.force
    {
        info(ctx, format!("JDK is up-to-date ({})", release.version));
        return Ok(());
    }
    if ctx.dry_run {
        info(
            ctx,
            format!(
                "[dry-run] would check the installed JDK and, if needed, download and install Temurin JDK {}",
                release.version
            ),
        );
        return Ok(());
    }
    let root = ctx.home.join("java");
    crate::infrastructure::validate_active_install(&root)?;
    let archive = download_to_temp(ctx, &release.package.link)?;
    if !sha256_file(archive.path())?.eq_ignore_ascii_case(&release.package.checksum) {
        bail!("Temurin JDK archive SHA-256 mismatch");
    }
    crate::infrastructure::ensure_tool_root(&root)?;
    crate::infrastructure::validate_active_install(&root)?;
    let stage = crate::infrastructure::new_install_stage(&root)?;
    if os == "windows" {
        super::archive::unpack_windows_zip(archive.path(), stage.path())?;
    } else {
        super::archive::unpack_tar_gz(archive.path(), stage.path(), 1)?;
    }
    let mut entries = fs::read_dir(stage.path())?;
    let entry = entries.next().context("empty Temurin archive")??;
    if entries.next().transpose()?.is_some() || !entry.file_type()?.is_dir() {
        bail!("unexpected Temurin archive layout");
    }
    let home = if os == "mac" {
        entry.path().join("Contents/Home")
    } else {
        entry.path()
    };
    let canonical_home = home.canonicalize().context("resolve staged JDK home")?;
    let canonical_stage = stage.path().canonicalize()?;
    if !canonical_home.starts_with(&canonical_stage) || canonical_home == canonical_stage {
        bail!("JDK home resolves outside its staging directory");
    }
    let names = crate::infrastructure::tool_bin_names_for_os(ToolKind::Java, &ctx.os);
    for name in names {
        let path = home.join("bin").join(name);
        let required = matches!(*name, "java" | "javac" | "java.exe" | "javac.exe");
        if !path.exists() && !required {
            continue;
        }
        let resolved = path
            .canonicalize()
            .with_context(|| format!("inspect staged {name}"))?;
        if !resolved.starts_with(&canonical_home)
            || !resolved.is_file()
            || (required && resolved.metadata()?.len() == 0)
        {
            bail!("staged {name} is not a file inside the JDK");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if os != "windows" && resolved.metadata()?.permissions().mode() & 0o111 == 0 {
                bail!("staged {name} is not executable");
            }
        }
    }
    let active = root.join("active");
    crate::infrastructure::preflight_bin_links(
        Some(&home.join("bin")),
        &active.join("bin"),
        &ctx.bindir,
        names,
    )?;
    let relative = home.strip_prefix(stage.path())?.to_owned();
    crate::infrastructure::seal_managed_install(
        ctx,
        &root,
        &stage,
        ToolKind::Java,
        &release.version.to_string(),
    );
    let kept = stage.keep();
    crate::infrastructure::activate_managed_install(
        ctx,
        &root,
        &kept.join(relative),
        ToolKind::Java,
    )?;
    link_managed_tool_bins(
        ctx,
        &root,
        ToolKind::Java,
        &active.join("bin"),
        &ctx.bindir,
        names,
    )?;
    info(
        ctx,
        format!(
            "Temurin JDK {} installed; JAVA_HOME was not changed",
            release.version
        ),
    );
    Ok(())
}
