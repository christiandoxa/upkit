//! Microsoft .NET LTS SDK discovery and archive installation.
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha512};
use std::{fs, io::Read, path::Path};

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, download_to_temp, http_get_json,
    info, link_managed_tool_bins, which_or_none,
};

const INDEX: &str =
    "https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json";

#[derive(Deserialize)]
struct Index {
    #[serde(rename = "releases-index")]
    channels: Vec<Channel>,
}

#[derive(Deserialize)]
struct Channel {
    #[serde(rename = "channel-version")]
    channel: String,
    #[serde(rename = "latest-sdk")]
    latest_sdk: String,
    #[serde(rename = "release-type")]
    release_type: String,
    #[serde(rename = "support-phase")]
    support_phase: String,
}

#[derive(Deserialize)]
struct ReleaseList {
    releases: Vec<ReleaseEntry>,
}

#[derive(Deserialize)]
struct ReleaseEntry {
    #[serde(default)]
    sdks: Vec<Sdk>,
    sdk: Option<Sdk>,
}

#[derive(Deserialize)]
struct Sdk {
    version: String,
    files: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    rid: String,
    url: String,
    hash: String,
}

struct Selected {
    version: Version,
    version_text: String,
    asset: Asset,
}

enum InstalledSdk {
    HostMissing,
    Unknown,
    Version(Version),
}

fn stable_version(value: &str) -> Option<Version> {
    let mut parts = value.split('.');
    let mut number = || {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let version = Version {
        major: number()?,
        minor: number()?,
        patch: number()?,
        pre: None,
    };
    parts.next().is_none().then_some(version)
}

fn rid(ctx: &Ctx) -> Result<String> {
    let os = match ctx.os.as_str() {
        "linux" => "linux",
        "macos" => "osx",
        "windows" => "win",
        _ => bail!(".NET SDK is unavailable for this operating system"),
    };
    let arch = match ctx.arch.as_str() {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        _ => bail!(".NET SDK is unavailable for this architecture"),
    };
    Ok(format!("{os}-{arch}"))
}

fn release(ctx: &Ctx) -> Result<Selected> {
    let rid = rid(ctx)?;
    let index: Index = http_get_json(ctx, INDEX)?;
    let mut channels = index
        .channels
        .into_iter()
        .filter_map(|channel| {
            let version = stable_version(&channel.latest_sdk)?;
            if channel.release_type != "lts"
                || !matches!(channel.support_phase.as_str(), "active" | "maintenance")
                || version.major > 999
                || version.minor > 999
                || channel.channel != format!("{}.{}", version.major, version.minor)
            {
                return None;
            }
            Some((version, channel))
        })
        .collect::<Vec<_>>();
    channels.sort_by(|a, b| b.0.cmp(&a.0));
    let (version, channel) = channels
        .into_iter()
        .next()
        .context("no supported .NET LTS SDK channel")?;
    let metadata_url = format!(
        "https://builds.dotnet.microsoft.com/dotnet/release-metadata/{}/releases.json",
        channel.channel
    );
    let metadata: ReleaseList = http_get_json(ctx, &metadata_url)?;
    let extension = if ctx.os == "windows" {
        ".zip"
    } else {
        ".tar.gz"
    };
    let mut matching = metadata
        .releases
        .into_iter()
        .flat_map(|entry| {
            if entry.sdks.is_empty() {
                entry.sdk.into_iter().collect::<Vec<_>>()
            } else {
                entry.sdks
            }
        })
        .filter(|sdk| sdk.version == channel.latest_sdk)
        .flat_map(|sdk| sdk.files)
        .filter(|file| file.rid == rid && file.name.ends_with(extension));
    let asset = matching.next().context("no matching .NET SDK archive")?;
    if matching.next().is_some() {
        bail!("multiple matching .NET SDK archives");
    }
    let url = reqwest::Url::parse(&asset.url).context("invalid .NET SDK download URL")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
        || !matches!(
            url.host_str(),
            Some(
                "builds.dotnet.microsoft.com"
                    | "download.visualstudio.microsoft.com"
                    | "dotnetcli.azureedge.net"
            )
        )
        || asset.hash.len() != 128
        || !asset.hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!(".NET metadata lacks an official HTTPS archive URL or valid SHA-512 hash");
    }
    Ok(Selected {
        version,
        version_text: channel.latest_sdk,
        asset,
    })
}

fn installed(ctx: &Ctx) -> InstalledSdk {
    let managed = ctx.bindir.join(if ctx.os == "windows" {
        "dotnet.exe"
    } else {
        "dotnet"
    });
    let executable = if managed.is_file() {
        Some(managed)
    } else {
        which_or_none("dotnet")
    };
    let Some(executable) = executable else {
        return InstalledSdk::HostMissing;
    };
    let Ok(resolved) = executable.canonicalize() else {
        return InstalledSdk::Unknown;
    };
    let Some(root) = resolved.parent() else {
        return InstalledSdk::Unknown;
    };
    let sdk_dir = root.join("sdk");
    let entries = match fs::read_dir(sdk_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return InstalledSdk::Unknown,
        Err(_) => return InstalledSdk::Unknown,
    };

    let mut best: Option<Version> = None;
    for entry in entries {
        let Ok(entry) = entry else {
            return InstalledSdk::Unknown;
        };
        let filename = entry.file_name();
        let Some(version) = filename.to_str().and_then(stable_version) else {
            continue;
        };
        let sdk_path = entry.path();
        // A version-named directory link could make an older SDK appear current.
        let is_directory = match fs::symlink_metadata(&sdk_path) {
            Ok(metadata) => {
                #[cfg(windows)]
                let is_reparse_point = {
                    use std::os::windows::fs::MetadataExt;
                    metadata.file_attributes() & 0x400 != 0
                };
                #[cfg(not(windows))]
                let is_reparse_point = false;
                metadata.is_dir() && !metadata.file_type().is_symlink() && !is_reparse_point
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return InstalledSdk::Unknown,
        };
        if !is_directory {
            continue;
        }
        let sdk_root = match sdk_path.canonicalize() {
            Ok(path) if path.starts_with(root) && path != root => path,
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return InstalledSdk::Unknown,
        };
        let sdk_dll = match sdk_path.join("dotnet.dll").canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return InstalledSdk::Unknown,
        };
        let metadata = match fs::metadata(&sdk_dll) {
            Ok(metadata) => metadata,
            Err(_) => return InstalledSdk::Unknown,
        };
        if !sdk_dll.starts_with(&sdk_root) || !metadata.is_file() || metadata.len() == 0 {
            continue;
        }
        best = Some(match best {
            Some(current) => current.max(version),
            None => version,
        });
    }

    match best {
        Some(version) => InstalledSdk::Version(version),
        None => InstalledSdk::Unknown,
    }
}

pub fn check_dotnet(ctx: &Ctx) -> Result<ToolReport> {
    let installed = installed(ctx);
    let installed_version = match &installed {
        InstalledSdk::Version(version) => Some(version),
        _ => None,
    };
    let latest = release(ctx).ok().map(|release| release.version);
    let status = if matches!(&installed, InstalledSdk::Unknown) {
        Status::Unknown
    } else {
        Status::from_versions(installed_version, latest.as_ref())
    };
    let mut notes = vec!["Targets the latest supported Microsoft .NET LTS SDK. Installed versions are inferred from SDK directories without running dotnet; DOTNET_ROOT is not changed.".into()];
    if matches!(&installed, InstalledSdk::Unknown) {
        notes.push(
            "A dotnet host was found, but no complete stable SDK directory could be confirmed beside it; the layout may be incomplete, the SDK may be stored elsewhere, or only prerelease SDKs may be present.".into(),
        );
    }
    notes.push("SDK detection checks layout and a nonempty dotnet.dll file; it does not verify SDK integrity.".into());
    if ctx.os == "windows" {
        notes.push("Windows installation requires permission to create symbolic links.".into());
    }
    if latest.is_none() {
        notes.push("Could not determine the latest compatible .NET LTS SDK.".into());
    }
    Ok(ToolReport {
        tool: ToolKind::Dotnet,
        installed: installed_version.cloned(),
        latest,
        status,
        method: UpdateMethod::DirectDownload,
        notes,
    })
}

fn sha512_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha512::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn update_dotnet(ctx: &Ctx) -> Result<()> {
    if ctx.offline {
        bail!("offline mode enabled; .NET SDK update requires network access");
    }
    rid(ctx)?;
    let selected = release(ctx)?;
    if matches!(installed(ctx), InstalledSdk::Version(version) if version >= selected.version)
        && !ctx.force
    {
        info(
            ctx,
            format!(".NET SDK is up-to-date ({})", selected.version),
        );
        return Ok(());
    }
    if ctx.dry_run {
        info(
            ctx,
            format!(
                "[dry-run] would download and install .NET SDK {}",
                selected.version
            ),
        );
        return Ok(());
    }
    let root = ctx.home.join("dotnet");
    crate::infrastructure::validate_active_install(&root)?;
    let archive = download_to_temp(ctx, &selected.asset.url)?;
    if !sha512_file(archive.path())?.eq_ignore_ascii_case(&selected.asset.hash) {
        bail!(".NET SDK archive SHA-512 mismatch");
    }
    crate::infrastructure::ensure_tool_root(&root)?;
    crate::infrastructure::validate_active_install(&root)?;
    let stage = crate::infrastructure::new_install_stage(&root)?;
    if ctx.os == "windows" {
        super::archive::unpack_windows_zip(archive.path(), stage.path())?;
    } else {
        super::archive::unpack_tar_gz(archive.path(), stage.path(), 0)?;
    }
    let stage_root = stage.path().canonicalize()?;
    for (relative, directory) in [
        (
            if ctx.os == "windows" {
                "dotnet.exe"
            } else {
                "dotnet"
            }
            .to_string(),
            false,
        ),
        (format!("sdk/{}/dotnet.dll", selected.version_text), false),
        ("host/fxr".to_string(), true),
        ("shared/Microsoft.NETCore.App".to_string(), true),
    ] {
        let path = stage
            .path()
            .join(&relative)
            .canonicalize()
            .with_context(|| format!("inspect staged {relative}"))?;
        if !path.starts_with(&stage_root)
            || path == stage_root
            || (directory && !path.is_dir())
            || (!directory && (!path.is_file() || path.metadata()?.len() == 0))
        {
            bail!("staged .NET component is outside the SDK or has an unexpected type: {relative}");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if ctx.os != "windows"
            && stage.path().join("dotnet").metadata()?.permissions().mode() & 0o111 == 0
        {
            bail!("staged dotnet is not executable");
        }
    }
    let active = root.join("active");
    let names = crate::infrastructure::tool_bin_names_for_os(ToolKind::Dotnet, &ctx.os);
    crate::infrastructure::preflight_bin_links(Some(stage.path()), &active, &ctx.bindir, names)?;
    crate::infrastructure::seal_managed_install(
        ctx,
        &root,
        &stage,
        ToolKind::Dotnet,
        &selected.version_text,
    );
    let kept = stage.keep();
    crate::infrastructure::activate_managed_install(ctx, &root, &kept, ToolKind::Dotnet)?;
    link_managed_tool_bins(ctx, &root, ToolKind::Dotnet, &active, &ctx.bindir, names)?;
    info(
        ctx,
        format!(
            ".NET SDK {} installed; DOTNET_ROOT was not changed",
            selected.version
        ),
    );
    Ok(())
}
