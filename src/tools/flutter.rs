use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, download_to_temp, home_dir,
    http_get_json, info, keep_latest_with_version, link_managed_tool_bins, maybe_path_hint_for_dir,
    prune_tool_versions, run_output, run_status, sha256_file, warn, which_or_none,
};
use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize)]
struct FlutterReleases {
    releases: Vec<FlutterReleaseEntry>,
}

#[derive(Debug, Deserialize)]
struct FlutterReleaseEntry {
    channel: String,
    version: String,
    archive: String,
    sha256: Option<String>,
    dart_sdk_arch: Option<String>,
}

pub fn flutter_releases_url(ctx: &Ctx) -> Result<&'static str> {
    // official buckets provide per-OS JSON
    match ctx.os.as_str() {
        "linux" => {
            Ok("https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json")
        }
        "macos" => {
            Ok("https://storage.googleapis.com/flutter_infra_release/releases/releases_macos.json")
        }
        "windows" => Ok(
            "https://storage.googleapis.com/flutter_infra_release/releases/releases_windows.json",
        ),
        _ => bail!("flutter releases json not supported for {}", ctx.os),
    }
}

fn flutter_latest_stable_release(ctx: &Ctx) -> Result<FlutterReleaseEntry> {
    let arch = match ctx.arch.as_str() {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => bail!("Flutter archive architecture is unsupported: {other}"),
    };
    let url = flutter_releases_url(ctx)?;
    let data: FlutterReleases = http_get_json(ctx, url)?;
    let mut best: Option<(Version, FlutterReleaseEntry)> = None;
    let mut latest = None;
    for r in data.releases.into_iter().filter(|r| r.channel == "stable") {
        if let Some(v) = Version::parse_loose(&r.version) {
            crate::keep_latest_version(&mut latest, v.clone());
            if r.dart_sdk_arch.as_deref() == Some(arch) {
                keep_latest_with_version(&mut best, v, r);
            }
        }
    }
    let latest = latest.ok_or_else(|| anyhow!("could not determine flutter latest stable"))?;
    match best {
        Some((version, release)) if version == latest => Ok(release),
        _ => bail!(
            "Flutter latest stable {latest} has no archive for {} / {arch}",
            ctx.os
        ),
    }
}

pub fn flutter_latest_stable(ctx: &Ctx) -> Result<Version> {
    let release = flutter_latest_stable_release(ctx)?;
    Version::parse_loose(&release.version)
        .ok_or_else(|| anyhow!("could not parse flutter version {}", release.version))
}

pub fn flutter_installed_version(bin: &Path) -> Option<Version> {
    // flutter --version --machine outputs JSON
    let args = [OsStr::new("--version"), OsStr::new("--machine")];
    if let Ok(out) = run_output(bin.as_os_str(), &args)
        && out.status.success()
    {
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
        let s = v.get("frameworkVersion")?.as_str()?;
        if let Some(parsed) = Version::parse_loose(s) {
            return Some(parsed);
        }
    }
    flutter_version_from_root(bin)
}

fn flutter_version_from_root(bin: &Path) -> Option<Version> {
    let canonical = fs::canonicalize(bin).ok()?;
    let bin_dir = canonical.parent()?;
    let root = bin_dir.parent()?;
    let version_path = root.join("version");
    let contents = fs::read_to_string(version_path).ok()?;
    Version::parse_loose(contents.trim())
}

pub fn check_flutter(ctx: &Ctx) -> Result<ToolReport> {
    let managed_windows = managed_windows_flutter(ctx);
    let bindir_flutter = flutter_bin_in_bindir(ctx);
    let path_flutter = if managed_windows.is_none() && bindir_flutter.is_none() {
        which_or_none("flutter")
    } else {
        None
    };
    let installed = if let Some(root) = &managed_windows {
        flutter_metadata_version(root)
            .ok()
            .and_then(|v| Version::parse_loose(&v))
    } else if ctx.dry_run {
        // Flutter's version command can write its SDK cache.
        None
    } else if let Some(bin) = &bindir_flutter {
        flutter_installed_version(bin)
    } else if let Some(bin) = &path_flutter {
        flutter_installed_version(bin)
    } else {
        None
    };
    let version_unverified = ctx.dry_run
        && if managed_windows.is_some() {
            installed.is_none()
        } else {
            bindir_flutter.is_some() || path_flutter.is_some()
        };

    let archive_update = ctx.os == "windows"
        && (managed_windows.is_some() || (bindir_flutter.is_none() && path_flutter.is_none()));
    let mut notes = vec![if archive_update {
        "Installs the stable Flutter archive into Upkit home.".into()
    } else {
        "Uses flutter upgrade (built-in updater).".into()
    }];
    if archive_update {
        notes.push("Windows installation requires permission to create symbolic links.".into());
        notes.push("Windows: put flutter/active/bin first on PATH.".into());
        notes.push(format!(
            "Windows Flutter PATH: {}",
            crate::sweep::display_path(&ctx.home.join("flutter/active/bin"))
        ));
    }
    if ctx.os == "windows" {
        notes.push("Windows Flutter requires Git and PowerShell on PATH.".into());
    }
    if version_unverified {
        notes.push("Installed Flutter version was not verified.".into());
    }
    let latest = match flutter_latest_stable(ctx) {
        Ok(version) => Some(version),
        Err(err) => {
            notes.push(format!("Latest check failed: {err}"));
            None
        }
    };
    let status = if version_unverified {
        Status::Unknown
    } else {
        Status::from_versions(installed.as_ref(), latest.as_ref())
    };

    Ok(ToolReport {
        tool: ToolKind::Flutter,
        installed,
        latest,
        status,
        method: if archive_update {
            UpdateMethod::DirectDownload
        } else {
            UpdateMethod::BuiltIn
        },
        notes,
    })
}

pub fn update_flutter(ctx: &Ctx) -> Result<()> {
    if ctx.offline {
        bail!("offline mode enabled; Flutter update requires network access");
    }
    let report = check_flutter(ctx)?;
    let bindir_flutter = flutter_bin_in_bindir(ctx);
    let flutter_in_path = which_or_none("flutter").is_some();
    let managed_windows = managed_windows_flutter(ctx).is_some();

    if managed_windows && matches!(report.status, Status::UpToDate) && !ctx.force {
        info(ctx, "flutter is up-to-date");
        return Ok(());
    }

    if managed_windows || (bindir_flutter.is_none() && !flutter_in_path) {
        let release = flutter_latest_stable_release(ctx)?;
        info(ctx, format!("Installing flutter {}", release.version));
        let download_url = format!(
            "https://storage.googleapis.com/flutter_infra_release/releases/{}",
            release.archive
        );
        if ctx.dry_run {
            info(ctx, format!("[dry-run] would download {download_url}"));
            return Ok(());
        }

        let expected = release
            .sha256
            .as_deref()
            .filter(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            .ok_or_else(|| {
                anyhow!("Flutter release metadata lacks a valid SHA-256 archive checksum")
            })?;
        let tmp = download_to_temp(ctx, &download_url)
            .with_context(|| format!("download flutter archive from {download_url}"))?;
        let actual = sha256_file(tmp.path())?;
        if !actual.eq_ignore_ascii_case(expected) {
            bail!("Flutter archive SHA-256 mismatch");
        }

        let tool_root = ctx.home.join("flutter");
        crate::infrastructure::validate_active_install(&tool_root)?;
        crate::infrastructure::ensure_tool_root(&tool_root)
            .with_context(|| format!("create {}", tool_root.display()))?;
        crate::infrastructure::validate_active_install(&tool_root)?;
        let stage = crate::infrastructure::new_install_stage(&tool_root)
            .with_context(|| format!("prepare staging directory in {}", tool_root.display()))?;

        let archive = release.archive.as_str();
        if archive.ends_with(".tar.xz") {
            let f = fs::File::open(tmp.path()).context("open flutter archive")?;
            let xz = xz2::read::XzDecoder::new(f);
            super::archive::unpack_tar_with_limit(xz, stage.path(), 1, 8 * 1024 * 1024 * 1024)
                .context("extract Flutter archive")?;
        } else if archive.ends_with(".tar.gz") {
            let f = fs::File::open(tmp.path()).context("open flutter archive")?;
            let gz = flate2::read::GzDecoder::new(f);
            super::archive::unpack_tar_with_limit(gz, stage.path(), 1, 8 * 1024 * 1024 * 1024)
                .context("extract Flutter archive")?;
        } else if archive.ends_with(".zip") && ctx.os == "macos" {
            #[cfg(unix)]
            super::archive::unpack_flutter_macos_zip(tmp.path(), stage.path())
                .context("extract Flutter archive")?;
            #[cfg(not(unix))]
            bail!("macOS Flutter ZIP extraction requires a Unix host");
        } else if archive.ends_with(".zip") && ctx.os == "windows" {
            super::archive::unpack_flutter_windows_zip(tmp.path(), stage.path())
                .context("extract Flutter archive")?;
        } else {
            bail!("unsupported flutter archive format: {}", release.archive);
        }

        validate_flutter_archive(stage.path(), &release.version, ctx.os == "windows")?;
        let active = tool_root.join("active");
        if ctx.os != "windows" {
            crate::infrastructure::preflight_bin_links(
                Some(&stage.path().join("flutter/bin")),
                &active.join("bin"),
                &ctx.bindir,
                &["flutter", "dart", "pub"],
            )?;
        }
        crate::infrastructure::seal_managed_install(
            ctx,
            &tool_root,
            &stage,
            ToolKind::Flutter,
            &release.version.to_string(),
        );
        let ver_dir = stage.keep();
        let extracted = ver_dir.join("flutter");
        crate::infrastructure::activate_managed_install(
            ctx,
            &tool_root,
            &extracted,
            ToolKind::Flutter,
        )
        .with_context(|| {
            format!(
                "link flutter active {} -> {}",
                active.display(),
                extracted.display()
            )
        })?;
        let bin_dir = active.join("bin");
        if ctx.os == "windows" {
            warn(
                ctx,
                format!(
                    "Put {} first on PATH for Flutter and Dart; restart your terminal.",
                    crate::sweep::display_path(&bin_dir)
                ),
            );
        } else {
            link_managed_tool_bins(
                ctx,
                &tool_root,
                ToolKind::Flutter,
                &bin_dir,
                &ctx.bindir,
                &["flutter", "dart", "pub"],
            )
            .context("link flutter binaries")?;
            maybe_path_hint_for_dir(ctx, &bin_dir, "flutter bin");
            maybe_hint_flutter_bins(ctx);
        }

        if let Err(err) = prune_tool_versions(&tool_root, &ver_dir, &["active"]) {
            warn(ctx, format!("Failed to remove old flutter versions: {err}"));
        }

        info(ctx, "flutter installed");
        return Ok(());
    }

    if matches!(report.status, Status::UpToDate) && !ctx.force {
        info(ctx, "flutter is up-to-date");
        return Ok(());
    }

    info(ctx, "Updating flutter via flutter upgrade");
    if ctx.dry_run {
        info(ctx, "[dry-run] would run: flutter upgrade");
        return Ok(());
    }

    let status = if let Some(bin) = bindir_flutter {
        let args = [OsStr::new("upgrade")];
        run_status(bin.as_os_str(), &args).context("failed to run flutter upgrade")?
    } else {
        run_status("flutter", &["upgrade"]).context("failed to run flutter upgrade")?
    };
    if !status.success() {
        bail!("flutter upgrade failed");
    }
    maybe_hint_flutter_bins(ctx);
    info(ctx, "flutter updated");
    Ok(())
}

fn validate_flutter_archive(stage: &Path, version: &str, windows: bool) -> Result<()> {
    let mut entries = fs::read_dir(stage)?;
    let entry = entries.next().context("missing flutter/ directory")??;
    if entry.file_name() != "flutter"
        || !entry.file_type()?.is_dir()
        || entries.next().transpose()?.is_some()
    {
        bail!("unexpected flutter archive layout (expected only flutter/ directory)");
    }
    let root = entry.path().canonicalize()?;
    let mut pending = vec![root.clone()];
    let mut visited = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            visited += 1;
            // shortcut: bound post-extraction inspection; raise this for larger official SDKs.
            if visited > 100_000 {
                bail!("Flutter archive exceeds inspection limits");
            }
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                let resolved = entry
                    .path()
                    .canonicalize()
                    .context("resolve staged Flutter symbolic link")?;
                if !resolved.starts_with(&root) {
                    bail!("Flutter symbolic link resolves outside its SDK");
                }
            } else if kind.is_dir() {
                pending.push(entry.path());
            } else if !kind.is_file() {
                bail!("Flutter archive contains a special file");
            }
        }
    }
    for (relative, executable) in [
        (
            if windows {
                "bin/flutter.bat"
            } else {
                "bin/flutter"
            },
            !windows,
        ),
        (if windows { "bin/dart.bat" } else { "bin/dart" }, !windows),
        (
            if windows {
                "bin/internal/shared.bat"
            } else {
                "bin/internal/shared.sh"
            },
            false,
        ),
        ("packages/flutter_tools/pubspec.yaml", false),
        (
            if windows {
                "bin/cache/dart-sdk/bin/dart.exe"
            } else {
                "bin/cache/dart-sdk/bin/dart"
            },
            !windows,
        ),
        ("bin/cache/flutter_tools.snapshot", false),
        ("bin/cache/engine.stamp", false),
        ("bin/cache/flutter.version.json", false),
        (".git/HEAD", false),
        (".git/config", false),
    ] {
        let file = root
            .join(relative)
            .canonicalize()
            .with_context(|| format!("inspect staged Flutter component {relative}"))?;
        if !file.starts_with(&root) || !file.is_file() || file.metadata()?.len() == 0 {
            bail!("invalid staged Flutter component: {relative}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if executable && file.metadata()?.permissions().mode() & 0o111 == 0 {
                bail!("staged Flutter component is not executable: {relative}");
            }
        }
        #[cfg(not(unix))]
        let _ = executable;
    }
    if flutter_metadata_version(&root)? != version {
        bail!("staged Flutter version does not match the selected release");
    }
    Ok(())
}

fn flutter_metadata_version(root: &Path) -> Result<String> {
    use std::io::Read;
    let root = root.canonicalize()?;
    let version_path = root.join("bin/cache/flutter.version.json").canonicalize()?;
    if !version_path.starts_with(&root) || !version_path.is_file() {
        bail!("Flutter version metadata is outside the SDK");
    }
    let mut version_file = fs::File::open(version_path)?;
    let mut version_bytes = Vec::new();
    version_file
        .by_ref()
        .take(65_537)
        .read_to_end(&mut version_bytes)?;
    // shortcut: cap version metadata at 64 KiB; raise it if Flutter expands this format.
    if version_bytes.len() > 65_536 {
        bail!("staged Flutter version metadata is oversized");
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&version_bytes).context("parse staged Flutter version metadata")?;
    metadata
        .get("frameworkVersion")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .context("Flutter version metadata is missing frameworkVersion")
}

fn managed_windows_flutter(ctx: &Ctx) -> Option<PathBuf> {
    if ctx.os != "windows" {
        return None;
    }
    let root = ctx.home.join("flutter");
    crate::infrastructure::validate_active_install(&root).ok()?;
    let active = root.join("active").canonicalize().ok()?;
    let binary = active.join("bin/flutter.bat").canonicalize().ok()?;
    if binary.starts_with(&active) && binary.is_file() {
        Some(active)
    } else {
        None
    }
}

fn maybe_hint_flutter_bins(ctx: &Ctx) {
    if let Some(pub_cache) = pub_cache_dir() {
        maybe_path_hint_for_dir(ctx, &pub_cache.join("bin"), "pub cache bin");
    }
}

fn pub_cache_dir() -> Option<PathBuf> {
    env::var("PUB_CACHE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".pub-cache")))
}

fn flutter_bin_in_bindir(ctx: &Ctx) -> Option<PathBuf> {
    let candidate = ctx.bindir.join("flutter");
    if candidate.exists() {
        return Some(candidate);
    }
    None
}

#[cfg(test)]
mod windows_archive_fixture {
    #[test]
    #[ignore = "requires a checksum-verified Flutter Windows ZIP in UPKIT_FLUTTER_ARCHIVE"]
    fn official_windows_flutter_archive() {
        let archive = std::path::PathBuf::from(std::env::var_os("UPKIT_FLUTTER_ARCHIVE").unwrap());
        let version = std::env::var("UPKIT_FLUTTER_VERSION").unwrap();
        let expected = std::env::var("UPKIT_FLUTTER_SHA256").unwrap();
        assert_eq!(crate::sha256_file(&archive).unwrap(), expected);
        let stage = tempfile::tempdir().unwrap();
        super::super::archive::unpack_flutter_windows_zip(&archive, stage.path()).unwrap();
        super::validate_flutter_archive(stage.path(), &version, true).unwrap();
    }
}
