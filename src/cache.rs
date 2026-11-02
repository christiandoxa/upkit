//! Inventory shared developer caches without deleting or invoking package managers.
use serde::Serialize;
#[cfg(windows)]
use std::fs;
use std::{
    collections::{HashMap, HashSet},
    env,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Serialize)]
pub struct CacheEntry {
    pub name: &'static str,
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub path: PathBuf,
    pub ownership: &'static str,
    /// Ownership of the cache directory itself, observed during inventory.
    pub directory_owner_status: &'static str,
    pub classification: &'static str,
    pub consequence: &'static str,
    pub status: &'static str,
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
    pub size_complete: bool,
    /// A bounded observation, not proof that the cache is idle.
    pub activity_status: &'static str,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub go_test_cache: Option<GoTestCache>,
}

#[derive(Debug, Serialize)]
pub struct GoTestCache {
    pub status: &'static str,
    pub expired_before_unix_nanos: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GoTestExpirationPlan {
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub cache_path: PathBuf,
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub marker_path: PathBuf,
    pub current_expiration_unix_nanos: Option<u64>,
    pub preview_token: String,
    pub warning: &'static str,
}

/// Inspect one explicitly supplied cache directory; this does not change it.
#[cfg(target_os = "linux")]
pub fn go_test_expiration_preview(path: &Path) -> anyhow::Result<GoTestExpirationPlan> {
    Ok(prepare_go_test_expiration(path, false)?.0)
}

#[cfg(target_os = "linux")]
fn prepare_go_test_expiration(
    path: &Path,
    exclusive: bool,
) -> anyhow::Result<(GoTestExpirationPlan, std::fs::File, Option<std::fs::File>)> {
    use anyhow::{Context, bail};
    use sha2::{Digest, Sha256};
    use std::{
        io::Read,
        os::unix::{ffi::OsStrExt, fs::MetadataExt},
    };
    if !path.is_absolute()
        || path.parent().is_none()
        || path.canonicalize().context("resolve cache path")? != path
    {
        bail!("cache path must be absolute, canonical, and not a filesystem root");
    }
    if dirs::home_dir()
        .and_then(|home| home.canonicalize().ok())
        .as_deref()
        == Some(path)
    {
        bail!("refusing to use the user home as a cache");
    }
    let mounts = std::fs::read("/proc/self/mountinfo").context("read mount table")?;
    let marker_path = path.join("testexpire.txt");
    if crate::application::mount_points(&mounts)?
        .iter()
        .any(|mount| mount == path || mount == &marker_path)
    {
        bail!("cache or marker is a mount point");
    }
    let directory = std::fs::File::from(
        rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )
        .context("open cache without following links")?,
    );
    let meta = directory.metadata().context("inspect cache directory")?;
    let uid = rustix::process::geteuid().as_raw();
    if meta.uid() != uid || meta.mode() & 0o022 != 0 {
        bail!(
            "cache directory must be owned by the current user and not writable by group or others"
        );
    }
    let mut hash = Sha256::new();
    hash.update(b"upkit-go-test-expiration-preview-v1\0");
    hash.update(std::fs::read("/proc/sys/kernel/random/boot_id").context("read boot identity")?);
    hash.update(path.as_os_str().as_bytes());
    hash.update(meta.dev().to_le_bytes());
    hash.update(meta.ino().to_le_bytes());
    let flags = if exclusive {
        rustix::fs::OFlags::RDWR
    } else {
        rustix::fs::OFlags::RDONLY
    };
    let (marker, marker_file) = match rustix::fs::openat2(
        &directory,
        "testexpire.txt",
        flags | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::BENEATH
            | rustix::fs::ResolveFlags::NO_SYMLINKS
            | rustix::fs::ResolveFlags::NO_XDEV,
    ) {
        Err(rustix::io::Errno::NOENT) => {
            hash.update(b"missing");
            (None, None)
        }
        Err(err) => return Err(err).context("open Go test-cache marker safely"),
        Ok(fd) => {
            let mut file = std::fs::File::from(fd);
            let lock = if exclusive {
                rustix::fs::FlockOperation::NonBlockingLockExclusive
            } else {
                rustix::fs::FlockOperation::NonBlockingLockShared
            };
            rustix::fs::flock(&file, lock).context("lock Go test-cache marker")?;
            let metadata = file.metadata().context("inspect Go test-cache marker")?;
            if !metadata.is_file()
                || metadata.uid() != uid
                || metadata.nlink() != 1
                || metadata.len() > 64
                || metadata.mode() & 0o022 != 0
            {
                bail!(
                    "Go test-cache marker must be a small, singly linked, user-owned regular file not writable by group or others"
                );
            }
            let mut data = Vec::new();
            (&mut file)
                .take(65)
                .read_to_end(&mut data)
                .context("read Go test-cache marker")?;
            if data.len() > 64 {
                bail!("Go test-cache marker is too large");
            }
            let value = std::str::from_utf8(&data)
                .ok()
                .and_then(|text| text.trim().parse::<i64>().ok())
                .filter(|value| *value >= 0)
                .context("invalid Go test-cache marker")? as u64;
            hash.update(b"present");
            hash.update(metadata.dev().to_le_bytes());
            hash.update(metadata.ino().to_le_bytes());
            hash.update(metadata.ctime().to_le_bytes());
            hash.update(metadata.ctime_nsec().to_le_bytes());
            hash.update(&data);
            (Some(value), Some(file))
        }
    };
    Ok((
        GoTestExpirationPlan {
            cache_path: path.to_owned(),
            marker_path,
            current_expiration_unix_nanos: marker,
            preview_token: hex::encode(hash.finalize()),
            warning: "Expiration affects shared Go test results in this selected cache; tests may run again. It does not delete cached bytes or guarantee reclaimed space. This preview does not verify Go uses this path.",
        },
        directory,
        marker_file,
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn go_test_expiration_preview(_: &Path) -> anyhow::Result<GoTestExpirationPlan> {
    anyhow::bail!("Go test-cache expiration preview is supported only on Linux")
}

#[derive(Debug, Serialize)]
pub struct GoTestExpirationResult {
    pub expired_before_unix_nanos: u64,
    pub changed: bool,
    pub verification: &'static str,
}

/// Apply a previously inspected scope; callers must obtain explicit confirmation first.
#[cfg(target_os = "linux")]
pub fn expire_go_test_cache(
    plan: &GoTestExpirationPlan,
    token: &str,
) -> anyhow::Result<GoTestExpirationResult> {
    use anyhow::{Context, bail};
    use std::{
        io::{Read, Seek, SeekFrom, Write},
        os::unix::fs::MetadataExt,
        time::{SystemTime, UNIX_EPOCH},
    };
    if token != plan.preview_token {
        bail!("preview token does not match");
    }
    let (current, directory, marker) = prepare_go_test_expiration(&plan.cache_path, true)?;
    if current.preview_token != token {
        bail!("cache changed since preview; preview again");
    }
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before Unix epoch")?
            .as_nanos(),
    )
    .context("system clock is outside Go timestamp range")? as u64;
    let mut file = match marker {
        Some(file) => file,
        None => {
            let fd = rustix::fs::openat2(
                &directory,
                "testexpire.txt",
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                rustix::fs::ResolveFlags::BENEATH
                    | rustix::fs::ResolveFlags::NO_SYMLINKS
                    | rustix::fs::ResolveFlags::NO_XDEV,
            )
            .context("create Go test-cache marker without replacing a path")?;
            let file = std::fs::File::from(fd);
            rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .context("lock new Go test-cache marker; marker may have been created")?;
            file
        }
    };
    let marker_meta = file.metadata().context("inspect locked marker")?;
    let root_meta = directory.metadata().context("inspect opened cache")?;
    if !marker_meta.is_file()
        || marker_meta.nlink() != 1
        || marker_meta.uid() != rustix::process::geteuid().as_raw()
        || marker_meta.mode() & 0o022 != 0
    {
        bail!("marker identity or permissions changed; marker may have been created");
    }
    let same_paths = || -> bool {
        let root = rustix::fs::openat2(
            rustix::fs::CWD,
            &plan.cache_path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )
        .ok()
        .map(std::fs::File::from);
        let Some(root) = root else {
            return false;
        };
        let Ok(meta) = root.metadata() else {
            return false;
        };
        if meta.dev() != root_meta.dev()
            || meta.ino() != root_meta.ino()
            || meta.uid() != root_meta.uid()
            || meta.mode() & 0o022 != 0
        {
            return false;
        }
        let marker = rustix::fs::openat2(
            &root,
            "testexpire.txt",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::BENEATH
                | rustix::fs::ResolveFlags::NO_SYMLINKS
                | rustix::fs::ResolveFlags::NO_XDEV,
        )
        .ok()
        .map(std::fs::File::from);
        marker
            .and_then(|file| file.metadata().ok())
            .is_some_and(|meta| {
                meta.dev() == marker_meta.dev()
                    && meta.ino() == marker_meta.ino()
                    && meta.nlink() == 1
                    && meta.uid() == marker_meta.uid()
                    && meta.mode() & 0o022 == 0
            })
    };
    if !same_paths() {
        bail!("cache or marker changed; marker may have been created");
    }
    let previous = current.current_expiration_unix_nanos.unwrap_or(0);
    let changed = now > previous;
    let expiry = now.max(previous);
    if changed {
        file.set_len(0)
            .context("truncate Go marker; outcome may be partial")?;
        file.seek(SeekFrom::Start(0))
            .context("seek Go marker; outcome may be partial")?;
        writeln!(file, "{expiry}").context("write Go marker; outcome may be partial")?;
        file.sync_all()
            .context("sync Go marker; outcome may be unknown")?;
    }
    file.seek(SeekFrom::Start(0))
        .context("verify Go marker; outcome may be unknown")?;
    let mut text = String::new();
    (&mut file)
        .take(65)
        .read_to_string(&mut text)
        .context("verify Go marker; outcome may be unknown")?;
    let verified = text.trim().parse::<u64>().ok() == Some(expiry) && same_paths();
    Ok(GoTestExpirationResult {
        expired_before_unix_nanos: expiry,
        changed,
        verification: if verified {
            "marker_matches"
        } else {
            "unverified"
        },
    })
}

#[cfg(not(target_os = "linux"))]
pub fn expire_go_test_cache(
    _: &GoTestExpirationPlan,
    _: &str,
) -> anyhow::Result<GoTestExpirationResult> {
    anyhow::bail!("Go test-cache expiration is supported only on Linux")
}

#[cfg(target_os = "linux")]
fn go_test_cache(path: &Path) -> GoTestCache {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let unavailable = || GoTestCache {
        status: "unavailable",
        expired_before_unix_nanos: None,
    };
    let Ok(expected) = std::fs::symlink_metadata(path) else {
        return unavailable();
    };
    let Ok(fd) = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) else {
        return unavailable();
    };
    let directory = std::fs::File::from(fd);
    let Ok(actual) = directory.metadata() else {
        return unavailable();
    };
    if !expected.is_dir()
        || expected.file_type().is_symlink()
        || expected.dev() != actual.dev()
        || expected.ino() != actual.ino()
    {
        return unavailable();
    }
    let fd = match rustix::fs::openat(
        &directory,
        "testexpire.txt",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => {
            return GoTestCache {
                status: "no_expiration_marker",
                expired_before_unix_nanos: None,
            };
        }
        Err(_) => return unavailable(),
    };
    let file = std::fs::File::from(fd);
    if rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockShared).is_err() {
        return unavailable();
    }
    if !file
        .metadata()
        .is_ok_and(|meta| meta.is_file() && meta.len() <= 64)
    {
        return unavailable();
    }
    let mut contents = String::new();
    if file.take(65).read_to_string(&mut contents).is_err() || contents.len() > 64 {
        return unavailable();
    }
    match contents.trim().parse::<u64>() {
        Ok(value) => GoTestCache {
            status: "expiration_marker",
            expired_before_unix_nanos: Some(value),
        },
        Err(_) => unavailable(),
    }
}

#[derive(Debug, Serialize)]
pub struct CacheReport {
    pub entries: Vec<CacheEntry>,
    pub warnings: Vec<String>,
    pub cancelled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Spec {
    pub(crate) name: &'static str,
    pub(crate) path: PathBuf,
    pub(crate) classification: &'static str,
    pub(crate) consequence: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Platform {
    Linux,
    Macos,
    Windows,
}

fn zig_absolute_path(
    value: &std::ffi::OsStr,
    setting: &'static str,
) -> Result<PathBuf, &'static str> {
    use std::path::Component;

    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(setting);
    }
    Ok(path)
}

fn zig_global_cache_path(
    platform: Platform,
    override_path: Option<&std::ffi::OsStr>,
    xdg_cache: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
    xdg_data: Option<&std::ffi::OsStr>,
    local_app_data: Option<&std::ffi::OsStr>,
) -> Result<PathBuf, &'static str> {
    if let Some(path) = override_path {
        return zig_absolute_path(path, "ZIG_GLOBAL_CACHE_DIR must be an absolute path");
    }
    if platform != Platform::Windows {
        if let Some(path) = xdg_cache.filter(|value| !value.is_empty()) {
            return zig_absolute_path(path, "XDG_CACHE_HOME for Zig must be absolute")
                .map(|path| path.join("zig"));
        }
        if let Some(path) = home {
            return zig_absolute_path(path, "HOME for Zig must be absolute")
                .map(|path| path.join(".cache/zig"));
        }
    }
    match platform {
        Platform::Linux => xdg_data
            .filter(|value| !value.is_empty())
            .ok_or("Zig global cache default is unavailable")
            .and_then(|path| zig_absolute_path(path, "XDG_DATA_HOME for Zig must be absolute"))
            .map(|path| path.join("zig")),
        Platform::Macos => Err("Zig global cache default is unavailable"),
        Platform::Windows => local_app_data
            .ok_or("LOCALAPPDATA for Zig is unavailable")
            .and_then(|path| zig_absolute_path(path, "LOCALAPPDATA for Zig must be absolute"))
            .map(|path| path.join("zig")),
    }
}

fn zig_global_cache(platform: Platform) -> Result<PathBuf, &'static str> {
    zig_global_cache_path(
        platform,
        env::var_os("ZIG_GLOBAL_CACHE_DIR").as_deref(),
        env::var_os("XDG_CACHE_HOME").as_deref(),
        env::var_os("HOME").as_deref(),
        env::var_os("XDG_DATA_HOME").as_deref(),
        env::var_os("LOCALAPPDATA").as_deref(),
    )
}

fn npm_default(platform: Platform, home: &Path, local: &Path) -> PathBuf {
    if platform == Platform::Windows {
        local.join("npm-cache")
    } else {
        home.join(".npm")
    }
}

fn pip_default(platform: Platform, cache: &Path, local: &Path) -> PathBuf {
    if platform == Platform::Windows {
        local.join("pip/Cache")
    } else {
        cache.join("pip")
    }
}

fn pub_default(platform: Platform, home: &Path, local: &Path) -> PathBuf {
    if platform == Platform::Windows {
        local.join("Pub/Cache")
    } else {
        home.join(".pub-cache")
    }
}

fn yarn_default(
    platform: Platform,
    home: &Path,
    cache: &Path,
    local: &Path,
    xdg_cache: Option<&Path>,
) -> PathBuf {
    match platform {
        Platform::Linux => cache.join("yarn"),
        Platform::Macos => xdg_cache.map_or_else(
            || home.join("Library/Caches/Yarn"),
            |cache| cache.join("yarn"),
        ),
        Platform::Windows => local.join("Yarn/Cache"),
    }
}

fn ccache_default(
    platform: Platform,
    home: &Path,
    cache: &Path,
    local: &Path,
    xdg_cache: Option<&Path>,
) -> PathBuf {
    let legacy = home.join(".ccache");
    if std::fs::metadata(&legacy).is_ok_and(|metadata| metadata.is_dir()) {
        legacy
    } else {
        match platform {
            Platform::Windows => local.join("ccache"),
            Platform::Linux => cache.join("ccache"),
            Platform::Macos => xdg_cache
                .map_or_else(|| cache.to_owned(), Path::to_path_buf)
                .join("ccache"),
        }
    }
}

fn sccache_default(platform: Platform, home: &Path, cache: &Path, local: &Path) -> PathBuf {
    match platform {
        Platform::Linux => cache.join("sccache"),
        Platform::Macos => home.join("Library/Caches/Mozilla.sccache"),
        Platform::Windows => local.join("Mozilla/sccache"),
    }
}

fn pnpm_store_path(
    platform: Platform,
    home: &Path,
    data: &Path,
    store_dir: Option<&std::ffi::OsStr>,
    pnpm_home: Option<&std::ffi::OsStr>,
    xdg_data_home: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    let absolute = |value: &std::ffi::OsStr| {
        let path = PathBuf::from(value);
        path.is_absolute().then_some(path)
    };
    if let Some(value) = store_dir.filter(|value| !value.is_empty()) {
        return absolute(value);
    }
    if let Some(value) = pnpm_home.filter(|value| !value.is_empty()) {
        return absolute(value).map(|path| path.join("store"));
    }
    if let Some(value) = xdg_data_home.filter(|value| !value.is_empty()) {
        return absolute(value).map(|path| path.join("pnpm/store"));
    }
    Some(match platform {
        Platform::Linux => data.join("pnpm/store"),
        Platform::Macos => home.join("Library/pnpm/store"),
        Platform::Windows => data.join("pnpm/store"),
    })
}

fn pnpm_configured_store_dir() -> Option<std::ffi::OsString> {
    env::var_os("pnpm_config_store_dir")
        .filter(|value| !value.is_empty())
        .or_else(|| env::var_os("PNPM_CONFIG_STORE_DIR").filter(|value| !value.is_empty()))
}

fn uv_cache_path(
    platform: Platform,
    home: &Path,
    cache: &Path,
    xdg_cache: Option<&Path>,
    override_dir: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    if let Some(path) = override_dir {
        let path = PathBuf::from(path);
        return path.is_absolute().then_some(path);
    }
    Some(match platform {
        Platform::Linux => xdg_cache
            .map_or_else(|| cache.to_owned(), Path::to_path_buf)
            .join("uv"),
        Platform::Macos => xdg_cache
            .map_or_else(|| home.join(".cache"), Path::to_path_buf)
            .join("uv"),
        Platform::Windows => cache.join("uv/cache"),
    })
}

fn uv_spec(
    platform: Platform,
    home: &Path,
    cache: &Path,
    xdg_cache: Option<&Path>,
    override_dir: Option<&std::ffi::OsStr>,
) -> Option<Spec> {
    Some(Spec {
        name: "uv",
        path: uv_cache_path(platform, home, cache, xdg_cache, override_dir)?,
        classification: "shared package cache",
        consequence: "do not delete directly; uv cache clean or prune may require later downloads or rebuilds",
    })
}

fn resolve_bun_path(
    home: &Path,
    value: &std::ffi::OsStr,
    setting: &'static str,
) -> Result<PathBuf, &'static str> {
    use std::path::Component;

    if value.is_empty() {
        return Err(setting);
    }
    let path = PathBuf::from(value);
    let path = if path.is_absolute() {
        path
    } else if let Some(rest) = value.to_str().and_then(|value| value.strip_prefix("~/")) {
        home.join(rest)
    } else {
        return Err(setting);
    };
    if path
        .components()
        .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(setting);
    }
    Ok(path)
}

fn bun_install_cache_path(
    home: &Path,
    cache_dir: Option<&std::ffi::OsStr>,
) -> Result<PathBuf, &'static str> {
    match cache_dir {
        Some(value) => resolve_bun_path(
            home,
            value,
            "BUN_INSTALL_CACHE_DIR is not safely resolvable",
        ),
        None => Ok(home.join(".bun/install/cache")),
    }
}

fn bun_cache_command_path(
    home: &Path,
    cache_dir: Option<&std::ffi::OsStr>,
    install_root: Option<&std::ffi::OsStr>,
) -> Result<PathBuf, &'static str> {
    if let Some(value) = cache_dir {
        return resolve_bun_path(
            home,
            value,
            "BUN_INSTALL_CACHE_DIR is not safely resolvable",
        );
    }
    if let Some(value) = install_root {
        return resolve_bun_path(home, value, "BUN_INSTALL is not safely resolvable")
            .map(|path| path.join("install/cache"));
    }
    Ok(home.join(".bun/install/cache"))
}

fn env_dir(name: &str, default: PathBuf) -> Option<PathBuf> {
    match env::var_os(name) {
        Some(value) if value == "off" || value.is_empty() => None,
        Some(value) => {
            let path = PathBuf::from(value);
            path.is_absolute().then_some(path)
        }
        None => Some(default),
    }
}

const MAX_MAVEN_SETTINGS_BYTES: u64 = 256 * 1024;
const MAX_MAVEN_REPOSITORY_BYTES: usize = 4096;
const MAX_NUGET_CONFIG_PATH_BYTES: usize = 4096;
const MAX_NUGET_CONFIG_DIR_ENTRIES: usize = 256;
const MAX_NUGET_SOLUTION_CONFIG_DEPTH: usize = 128;
const MAX_NUGET_SOLUTION_CONFIG_FILES: usize = 128;
const MAX_NUGET_SOLUTION_CONFIG_TOTAL_BYTES: usize = 4 * 1024 * 1024;
#[cfg(windows)]
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
#[cfg(windows)]
const WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

fn maven_repository(home: &Path) -> Result<PathBuf, &'static str> {
    use std::path::Component;

    let maven_home = home.join(".m2");
    match std::fs::symlink_metadata(&maven_home) {
        Ok(metadata) => {
            #[cfg(windows)]
            let is_reparse_point = {
                use std::os::windows::fs::MetadataExt;
                metadata.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
            };
            #[cfg(not(windows))]
            let is_reparse_point = false;
            if metadata.file_type().is_symlink() || !metadata.is_dir() || is_reparse_point {
                return Err("Maven user home is not a regular directory");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(maven_home.join("repository"));
        }
        Err(_) => return Err("Maven user home could not be inspected safely"),
    }

    let settings = maven_home.join("settings.xml");
    let Some(settings) = read_maven_settings(&settings)? else {
        return Ok(maven_home.join("repository"));
    };
    let Some(value) = parse_maven_settings(&settings.bytes)? else {
        return Ok(maven_home.join("repository"));
    };
    let value = if value.contains("${user.home}") {
        value.replace(
            "${user.home}",
            home.to_str()
                .ok_or("Maven user home cannot be represented in settings.xml")?,
        )
    } else {
        value
    };
    if value.contains("${") {
        return Err("Maven localRepository uses unsupported property expansion");
    }
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path.parent().is_none()
        || path == home
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err("Maven localRepository must be a safe absolute path");
    }
    Ok(path)
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct SettingsFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl SettingsFileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

struct MavenSettingsFile {
    bytes: Vec<u8>,
    identity: Option<SettingsFileIdentity>,
}

fn read_maven_settings(path: &Path) -> Result<Option<MavenSettingsFile>, &'static str> {
    use std::io::Read;

    #[cfg(unix)]
    let file = {
        let fd = match rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err("Maven user settings could not be read without following links"),
        };
        let file = std::fs::File::from(fd);
        let before = file
            .metadata()
            .map_err(|_| "Maven user settings could not be inspected safely")?;
        if !before.is_file() || before.len() > MAX_MAVEN_SETTINGS_BYTES {
            return Err("Maven user settings is not a regular file or exceeds the size limit");
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&file)
            .take(MAX_MAVEN_SETTINGS_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Maven user settings could not be read safely")?;
        let after = file
            .metadata()
            .map_err(|_| "Maven user settings could not be inspected safely")?;
        use std::os::unix::fs::MetadataExt;
        let identity = SettingsFileIdentity::from_metadata(&before);
        if bytes.len() as u64 > MAX_MAVEN_SETTINGS_BYTES
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err("Maven user settings changed while being read");
        }
        (bytes, Some(identity))
    };

    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT);
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("Maven user settings could not be read safely"),
        };
        let before = file
            .metadata()
            .map_err(|_| "Maven user settings could not be inspected safely")?;
        if !before.is_file()
            || before.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
            || before.file_size() > MAX_MAVEN_SETTINGS_BYTES
        {
            return Err("Maven user settings is not a regular file or exceeds the size limit");
        }
        let mut bytes = Vec::with_capacity(before.file_size() as usize);
        (&file)
            .take(MAX_MAVEN_SETTINGS_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Maven user settings could not be read safely")?;
        let after = file
            .metadata()
            .map_err(|_| "Maven user settings could not be inspected safely")?;
        if bytes.len() as u64 > MAX_MAVEN_SETTINGS_BYTES
            || before.file_size() != after.file_size()
            || before.last_write_time() != after.last_write_time()
        {
            return Err("Maven user settings changed while being read");
        }
        (bytes, None)
    };

    Ok(Some(MavenSettingsFile {
        bytes: file.0,
        identity: file.1,
    }))
}

fn parse_maven_settings(bytes: &[u8]) -> Result<Option<String>, &'static str> {
    use quick_xml::{Reader, events::Event};

    if bytes.len() as u64 > MAX_MAVEN_SETTINGS_BYTES {
        return Err("Maven user settings exceeds the size limit");
    }
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut stack = Vec::<Vec<u8>>::new();
    let mut root_seen = false;
    let mut root_closed = false;
    let mut repository_seen = false;
    let mut repository_text = String::new();
    let mut repository = None;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(event)) => {
                let name = event.name().as_ref().as_bytes().to_vec();
                if stack.is_empty() {
                    if root_seen || root_closed || name != b"settings" {
                        return Err("Maven user settings has an unsupported XML root");
                    }
                    root_seen = true;
                }
                if name == b"localRepository" {
                    if stack.len() != 1 || repository_seen {
                        return Err("Maven user settings has an ambiguous localRepository");
                    }
                    repository_seen = true;
                } else if stack.last().is_some_and(|tag| tag == b"localRepository") {
                    return Err("Maven localRepository contains nested XML");
                }
                if stack.len() >= 128 {
                    return Err("Maven user settings XML is nested too deeply");
                }
                stack.push(name);
            }
            Ok(Event::Empty(event)) => {
                let name = event.name().as_ref().as_bytes().to_vec();
                if stack.is_empty() {
                    if root_seen || root_closed || name != b"settings" {
                        return Err("Maven user settings has an unsupported XML root");
                    }
                    root_seen = true;
                    root_closed = true;
                } else if name == b"localRepository" {
                    return Err("Maven localRepository is empty or ambiguous");
                } else if stack.last().is_some_and(|tag| tag == b"localRepository") {
                    return Err("Maven localRepository contains nested XML");
                }
            }
            Ok(Event::Text(event)) if stack.last().is_some_and(|tag| tag == b"localRepository") => {
                let text = event.xml10_content();
                if repository_text.len().saturating_add(text.len()) > MAX_MAVEN_REPOSITORY_BYTES {
                    return Err("Maven localRepository exceeds the size limit");
                }
                repository_text.push_str(&text);
            }
            Ok(Event::CData(_)) if stack.last().is_some_and(|tag| tag == b"localRepository") => {
                return Err("Maven localRepository uses unsupported CDATA");
            }
            Ok(Event::GeneralRef(_))
                if stack.last().is_some_and(|tag| tag == b"localRepository") =>
            {
                return Err("Maven localRepository uses unsupported XML entities");
            }
            Ok(Event::DocType(_)) => {
                return Err("Maven user settings with a DTD are not inspected");
            }
            Ok(Event::End(event)) => {
                let name = event.name().as_ref().as_bytes().to_vec();
                let Some(open) = stack.pop() else {
                    return Err("Maven user settings has malformed XML");
                };
                if open != name {
                    return Err("Maven user settings has malformed XML");
                }
                if name == b"localRepository" {
                    repository = Some(std::mem::take(&mut repository_text));
                }
                if stack.is_empty() {
                    root_closed = true;
                }
            }
            Ok(Event::Text(event)) if stack.is_empty() => {
                if !event.xml10_content().trim().is_empty() {
                    return Err("Maven user settings has text outside its XML root");
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err("Maven user settings contains malformed or unsupported XML"),
        }
        buffer.clear();
    }
    if !root_seen || !root_closed || !stack.is_empty() {
        return Err("Maven user settings contains incomplete XML");
    }
    repository
        .map(|value| {
            let value = value.trim();
            if value.is_empty() {
                Err("Maven localRepository is empty")
            } else {
                Ok(value.to_owned())
            }
        })
        .transpose()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NugetConfigValue {
    global_packages: Option<PathBuf>,
    additional_global_packages: Vec<PathBuf>,
    clears_global_packages: bool,
    fallback_package_folders: Vec<(String, PathBuf)>,
    package_sources: Vec<PathBuf>,
    repository_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NugetSolutionConfigPaths {
    global_packages: Vec<PathBuf>,
    fallback_package_folders: Vec<PathBuf>,
    package_sources: Vec<PathBuf>,
    repository_paths: Vec<PathBuf>,
}

#[derive(Default)]
struct NugetConfigApplyState {
    result: NugetConfigValue,
    observed: NugetSolutionConfigPaths,
    seen_global: bool,
    seen_fallback_keys: HashSet<String>,
    seen_source_keys: HashSet<String>,
    seen_default_push: bool,
    seen_repository_path: bool,
    seen_disabled_keys: HashSet<String>,
}

enum NugetConfigAction {
    Add(Option<String>, Option<String>),
    Remove(Option<String>),
    Clear,
}

fn nuget_config_action(
    event: &quick_xml::events::BytesStart<'_>,
    name: &[u8],
    section: &[u8],
) -> Result<NugetConfigAction, &'static str> {
    use quick_xml::events::attributes::Attribute;

    let mut key = None;
    let mut value = None;
    let mut protocol_version = None;
    let mut allow_insecure = None;
    let mut disable_tls_validation = None;
    let mut attrs = 0;
    for result in event.attributes().with_checks(true) {
        let attribute: Attribute<'_> = result.map_err(|_| "NuGet user config has malformed XML")?;
        attrs += 1;
        let decoded = attribute
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|_| "NuGet user config has malformed XML")?
            .into_owned();
        match attribute.key.as_ref().as_bytes() {
            b"key" if key.is_none() => key = Some(decoded),
            b"value" if value.is_none() => value = Some(decoded),
            b"protocolVersion"
                if name == b"add" && section == b"packageSources" && protocol_version.is_none() =>
            {
                protocol_version = Some(decoded)
            }
            b"allowInsecureConnections"
                if name == b"add" && section == b"packageSources" && allow_insecure.is_none() =>
            {
                allow_insecure = Some(decoded)
            }
            b"disableTLSCertificateValidation"
                if name == b"add"
                    && section == b"packageSources"
                    && disable_tls_validation.is_none() =>
            {
                disable_tls_validation = Some(decoded)
            }
            _ => return Err("NuGet user config has unsupported attributes"),
        }
    }
    if attrs > 5 {
        return Err("NuGet user config has too many attributes");
    }
    if protocol_version
        .as_deref()
        .is_some_and(|version| !matches!(version, "2" | "3"))
    {
        return Err("NuGet package source has an unsupported protocol version");
    }
    if [allow_insecure.as_deref(), disable_tls_validation.as_deref()]
        .into_iter()
        .flatten()
        .any(|value| !value.eq_ignore_ascii_case("true") && !value.eq_ignore_ascii_case("false"))
    {
        return Err("NuGet package source has an unsupported security attribute");
    }
    match name {
        b"add" => Ok(NugetConfigAction::Add(key, value)),
        b"remove" => Ok(NugetConfigAction::Remove(key)),
        b"clear" if attrs == 0 => Ok(NugetConfigAction::Clear),
        b"clear" => Err("NuGet user config has unsupported clear attributes"),
        _ => Err("NuGet user config has an unsupported config entry"),
    }
}

fn apply_nuget_config_action(
    action: NugetConfigAction,
    section: &[u8],
    state: &mut NugetConfigApplyState,
    strict_solution_config: bool,
) -> Result<(), &'static str> {
    let key = match &action {
        NugetConfigAction::Add(Some(key), _) | NugetConfigAction::Remove(Some(key)) => Some(key),
        _ => None,
    };
    if key.is_some_and(|key| !key.is_ascii() || key.trim().is_empty())
        && (section == b"config" || strict_solution_config)
    {
        return Err("NuGet config contains an unsupported key");
    }
    match (section, action) {
        (b"config", NugetConfigAction::Clear) => {
            state.result.global_packages = None;
            state.result.clears_global_packages = true;
            state.seen_global = false;
            state.seen_default_push = false;
            state.seen_repository_path = false;
        }
        (section, NugetConfigAction::Remove(Some(key)))
            if section == b"config" && key.eq_ignore_ascii_case("globalPackagesFolder") =>
        {
            state.result.global_packages = None;
            state.result.clears_global_packages = true;
            state.seen_global = false;
        }
        (b"config", NugetConfigAction::Add(Some(key), value))
            if key.eq_ignore_ascii_case("globalPackagesFolder") =>
        {
            if state.seen_global {
                return Err("NuGet user config has ambiguous globalPackagesFolder entries");
            }
            let value = value.ok_or("NuGet globalPackagesFolder has no value")?;
            let path = expand_nuget_config_path(&value, !strict_solution_config)?;
            if strict_solution_config {
                state.observed.global_packages.push(path.clone());
            }
            state.result.global_packages = Some(path);
            state.seen_global = true;
        }
        (b"config", NugetConfigAction::Add(Some(key), Some(value)))
            if key.eq_ignore_ascii_case("defaultPushSource") =>
        {
            if state.seen_default_push {
                return Err("NuGet solution config has ambiguous default package sources");
            }
            if let Some(path) = nuget_package_source_path(&value)? {
                state.result.package_sources.push(path.clone());
                if strict_solution_config {
                    state.observed.package_sources.push(path);
                }
            }
            state.seen_default_push = true;
        }
        (b"config", NugetConfigAction::Remove(Some(key)))
            if key.eq_ignore_ascii_case("defaultPushSource") =>
        {
            state.seen_default_push = false;
        }
        (b"config", NugetConfigAction::Add(Some(key), Some(value)))
            if key.eq_ignore_ascii_case("repositoryPath") =>
        {
            if state.seen_repository_path {
                return Err("NuGet config has ambiguous repositoryPath entries");
            }
            let path = expand_nuget_config_path(&value, false)?;
            if strict_solution_config {
                state.observed.repository_paths.push(path.clone());
            }
            state.result.repository_paths.push(path);
            state.seen_repository_path = true;
        }
        (b"config", NugetConfigAction::Remove(Some(key)))
            if key.eq_ignore_ascii_case("repositoryPath") =>
        {
            state.seen_repository_path = false;
        }
        (b"fallbackPackageFolders", NugetConfigAction::Clear) => {
            state.result.fallback_package_folders.clear();
            state.seen_fallback_keys.clear();
        }
        (b"fallbackPackageFolders", NugetConfigAction::Remove(_)) => {
            return Err("NuGet fallbackPackageFolders does not support remove entries");
        }
        (b"fallbackPackageFolders", NugetConfigAction::Add(Some(key), Some(value))) => {
            if strict_solution_config && !state.seen_fallback_keys.insert(key.to_ascii_lowercase())
            {
                return Err("NuGet solution config has ambiguous fallback folder entries");
            }
            let path = expand_nuget_config_path(&value, !strict_solution_config)?;
            if strict_solution_config {
                state.observed.fallback_package_folders.push(path.clone());
            }
            state.result.fallback_package_folders.push((key, path));
        }
        (b"fallbackPackageFolders", NugetConfigAction::Add(_, _)) => {
            return Err("NuGet fallback package entry is missing its key or path");
        }
        (b"packageSources", NugetConfigAction::Clear) => {
            state.seen_source_keys.clear();
        }
        (b"packageSources", NugetConfigAction::Remove(Some(key))) if strict_solution_config => {
            state.seen_source_keys.remove(&key.to_ascii_lowercase());
        }
        (b"packageSources", NugetConfigAction::Remove(_)) if strict_solution_config => {
            return Err("NuGet solution config has an unsupported package source removal");
        }
        (b"packageSources", NugetConfigAction::Add(Some(key), Some(value))) => {
            if strict_solution_config && !state.seen_source_keys.insert(key.to_ascii_lowercase()) {
                return Err("NuGet solution config has ambiguous package source entries");
            }
            if let Some(path) = nuget_package_source_path(&value)? {
                state.result.package_sources.push(path.clone());
                if strict_solution_config {
                    state.observed.package_sources.push(path);
                }
            }
        }
        (b"packageSources", NugetConfigAction::Add(_, _)) => {
            return Err("NuGet package source entry is missing its key or value");
        }
        (b"disabledPackageSources", NugetConfigAction::Clear) if strict_solution_config => {
            state.seen_disabled_keys.clear();
        }
        (b"disabledPackageSources", NugetConfigAction::Remove(Some(key)))
            if strict_solution_config =>
        {
            state.seen_disabled_keys.remove(&key.to_ascii_lowercase());
        }
        (b"disabledPackageSources", NugetConfigAction::Add(Some(key), Some(value)))
            if strict_solution_config =>
        {
            if !matches!(value.trim().to_ascii_lowercase().as_str(), "true" | "false")
                || !state.seen_disabled_keys.insert(key.to_ascii_lowercase())
            {
                return Err("NuGet defaults config has an ambiguous disabled source entry");
            }
        }
        (b"disabledPackageSources", _) if strict_solution_config => {
            return Err("NuGet defaults config has an unsupported disabled source entry");
        }
        (b"config", NugetConfigAction::Add(_, _) | NugetConfigAction::Remove(_))
            if strict_solution_config =>
        {
            return Err("NuGet solution config has an unsupported config setting");
        }
        _ => {}
    }
    Ok(())
}

fn nuget_package_source_path(value: &str) -> Result<Option<PathBuf>, &'static str> {
    if value.is_empty() {
        return Err("NuGet package source is empty");
    }
    if value != value.trim() {
        return Err("NuGet package source has unsupported surrounding whitespace");
    }
    if ["http://", "https://"].iter().any(|scheme| {
        value
            .get(..scheme.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
    }) {
        return Ok(None);
    }
    if value.contains(['%', '$']) || value.contains("://") {
        return Err("NuGet package source path is dynamic or uses an unsupported URI");
    }
    nuget_safe_absolute_path(PathBuf::from(value))
        .map(Some)
        .map_err(|_| "NuGet package source path is not a safe absolute path")
}

fn nuget_package_source_paths(value: &str) -> Result<Vec<PathBuf>, &'static str> {
    value
        .split(';')
        .map(nuget_package_source_path)
        .collect::<Result<Vec<_>, _>>()
        .map(|paths| paths.into_iter().flatten().collect())
}

fn parse_nuget_config(bytes: &[u8]) -> Result<NugetConfigValue, &'static str> {
    parse_nuget_config_with_policy(bytes, false).map(|(result, _)| result)
}

fn parse_nuget_solution_config(bytes: &[u8]) -> Result<NugetSolutionConfigPaths, &'static str> {
    parse_nuget_config_with_policy(bytes, true).map(|(_, observed)| observed)
}

fn parse_nuget_config_with_policy(
    bytes: &[u8],
    strict_solution_config: bool,
) -> Result<(NugetConfigValue, NugetSolutionConfigPaths), &'static str> {
    use quick_xml::{Reader, events::Event};

    if bytes.len() as u64 > MAX_MAVEN_SETTINGS_BYTES {
        return Err("NuGet user config exceeds the size limit");
    }
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut stack = Vec::<Vec<u8>>::new();
    let mut root_seen = false;
    let mut root_closed = false;
    let mut config_sections = 0usize;
    let mut fallback_sections = 0usize;
    let mut source_sections = 0usize;
    let mut disabled_source_sections = 0usize;
    let mut state = NugetConfigApplyState::default();
    let mut pending_action = None;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(event)) => {
                let name = event.name().as_ref().as_bytes().to_vec();
                if stack.is_empty() {
                    if root_seen || root_closed || name != b"configuration" {
                        return Err("NuGet user config has an unsupported XML root");
                    }
                    if strict_solution_config
                        && event.attributes().with_checks(true).next().is_some()
                    {
                        return Err("NuGet solution config has unsupported root attributes");
                    }
                    root_seen = true;
                } else if stack.as_slice() == [b"configuration".as_slice()] {
                    if !matches!(
                        name.as_slice(),
                        b"config"
                            | b"fallbackPackageFolders"
                            | b"packageSources"
                            | b"disabledPackageSources"
                    ) {
                        if strict_solution_config {
                            return Err("NuGet solution config has an unsupported section");
                        }
                    } else {
                        if strict_solution_config
                            && event.attributes().with_checks(true).next().is_some()
                        {
                            return Err("NuGet solution config has unsupported section attributes");
                        }
                        let count = match name.as_slice() {
                            b"config" => &mut config_sections,
                            b"fallbackPackageFolders" => &mut fallback_sections,
                            b"packageSources" => &mut source_sections,
                            _ => &mut disabled_source_sections,
                        };
                        *count += 1;
                        if *count > 1 {
                            return Err("NuGet user config has ambiguous sections");
                        }
                    }
                } else if stack.len() == 2
                    && stack[0] == b"configuration"
                    && matches!(
                        stack[1].as_slice(),
                        b"config"
                            | b"fallbackPackageFolders"
                            | b"packageSources"
                            | b"disabledPackageSources"
                    )
                {
                    if matches!(name.as_slice(), b"add" | b"remove" | b"clear") {
                        pending_action = Some(nuget_config_action(&event, &name, &stack[1])?);
                    } else if strict_solution_config {
                        return Err("NuGet solution config has an unsupported setting");
                    }
                } else if stack.last().is_some_and(|parent| {
                    matches!(parent.as_slice(), b"add" | b"remove" | b"clear")
                }) {
                    return Err("NuGet user config has nested config entries");
                } else if strict_solution_config {
                    return Err("NuGet solution config has an unsupported setting");
                }
                if stack.len() >= 128 {
                    return Err("NuGet user config is nested too deeply");
                }
                stack.push(name);
            }
            Ok(Event::Empty(event)) => {
                let name = event.name().as_ref().as_bytes().to_vec();
                if stack.is_empty() {
                    if root_seen || root_closed || name != b"configuration" {
                        return Err("NuGet user config has an unsupported XML root");
                    }
                    if strict_solution_config
                        && event.attributes().with_checks(true).next().is_some()
                    {
                        return Err("NuGet solution config has unsupported root attributes");
                    }
                    root_seen = true;
                    root_closed = true;
                } else if stack.as_slice() == [b"configuration".as_slice()] {
                    if !matches!(
                        name.as_slice(),
                        b"config"
                            | b"fallbackPackageFolders"
                            | b"packageSources"
                            | b"disabledPackageSources"
                    ) {
                        if strict_solution_config {
                            return Err("NuGet solution config has an unsupported section");
                        }
                    } else {
                        if strict_solution_config
                            && event.attributes().with_checks(true).next().is_some()
                        {
                            return Err("NuGet solution config has unsupported section attributes");
                        }
                        let count = match name.as_slice() {
                            b"config" => &mut config_sections,
                            b"fallbackPackageFolders" => &mut fallback_sections,
                            b"packageSources" => &mut source_sections,
                            _ => &mut disabled_source_sections,
                        };
                        *count += 1;
                        if *count > 1 {
                            return Err("NuGet user config has ambiguous sections");
                        }
                    }
                } else if stack.len() == 2
                    && stack[0] == b"configuration"
                    && matches!(
                        stack[1].as_slice(),
                        b"config"
                            | b"fallbackPackageFolders"
                            | b"packageSources"
                            | b"disabledPackageSources"
                    )
                    && matches!(name.as_slice(), b"add" | b"remove" | b"clear")
                {
                    let action = nuget_config_action(&event, &name, &stack[1])?;
                    apply_nuget_config_action(
                        action,
                        &stack[1],
                        &mut state,
                        strict_solution_config,
                    )?;
                } else if strict_solution_config {
                    return Err("NuGet solution config has an unsupported setting");
                }
            }
            Ok(Event::Text(event)) => {
                let text = event.xml10_content();
                if (stack.is_empty() || strict_solution_config) && !text.trim().is_empty() {
                    return Err("NuGet user config has unsupported text");
                }
                if stack
                    .last()
                    .is_some_and(|tag| matches!(tag.as_slice(), b"add" | b"remove" | b"clear"))
                    && !text.trim().is_empty()
                {
                    return Err("NuGet user config has non-empty config entries");
                }
            }
            Ok(Event::CData(_)) if strict_solution_config => {
                return Err("NuGet solution config has unsupported CDATA");
            }
            Ok(Event::DocType(_)) => return Err("NuGet user config with a DTD is not inspected"),
            Ok(Event::End(event)) => {
                let name = event.name().as_ref().as_bytes().to_vec();
                let Some(open) = stack.pop() else {
                    return Err("NuGet user config has malformed XML");
                };
                if open != name {
                    return Err("NuGet user config has malformed XML");
                }
                if matches!(name.as_slice(), b"add" | b"remove" | b"clear")
                    && stack.len() == 2
                    && stack[0] == b"configuration"
                    && matches!(
                        stack[1].as_slice(),
                        b"config"
                            | b"fallbackPackageFolders"
                            | b"packageSources"
                            | b"disabledPackageSources"
                    )
                {
                    apply_nuget_config_action(
                        pending_action
                            .take()
                            .ok_or("NuGet user config has malformed XML")?,
                        &stack[1],
                        &mut state,
                        strict_solution_config,
                    )?;
                }
                if stack.is_empty() {
                    root_closed = true;
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err("NuGet user config has malformed or unsupported XML"),
        }
        buffer.clear();
    }
    if !root_seen || !root_closed || !stack.is_empty() {
        return Err("NuGet user config is incomplete");
    }
    Ok((state.result, state.observed))
}

fn nuget_user_package_folders(
    platform: Platform,
    home: &Path,
    dotnet_cli_home: Option<&Path>,
    appdata: Option<&std::ffi::OsStr>,
    xdg_config: Option<&std::ffi::OsStr>,
    machine_config_directories: &[PathBuf],
) -> Result<NugetConfigValue, &'static str> {
    let locations =
        nuget_user_config_locations(platform, home, dotnet_cli_home, appdata, xdg_config)?;
    let mut values = Vec::new();
    for (group, settings, additional) in locations {
        if nuget_additional_configs_exist(&additional)? {
            return Err("additional NuGet user config files make the package location ambiguous");
        }
        let Some(settings) = read_maven_settings(&settings)
            .map_err(|_| "NuGet user config could not be read safely")?
        else {
            continue;
        };
        let parsed = parse_nuget_config(&settings.bytes)?;
        values.push((group, parsed));
    }
    for (index, (group, value)) in values.iter().enumerate() {
        if values.iter().skip(index + 1).any(|(other_group, other)| {
            group == other_group
                && (value.global_packages != other.global_packages
                    || value.clears_global_packages != other.clears_global_packages
                    || value.fallback_package_folders != other.fallback_package_folders)
        }) {
            return Err("NuGet user config locations disagree about package locations");
        }
    }
    for machine in machine_config_directories {
        if nuget_additional_configs_exist(machine)? {
            return Err("machine-level NuGet config may change package locations");
        }
    }
    let mut result = NugetConfigValue::default();
    let mut seen_groups = HashSet::new();
    for (group, value) in &values {
        if !seen_groups.insert(*group) {
            continue;
        }
        if result.global_packages.is_none() {
            result.global_packages = value.global_packages.clone();
            result.clears_global_packages = value.clears_global_packages;
        } else if let Some(path) = &value.global_packages
            && result.global_packages.as_ref() != Some(path)
        {
            result.additional_global_packages.push(path.clone());
        }
        result
            .fallback_package_folders
            .extend(value.fallback_package_folders.iter().cloned());
    }
    result.package_sources = values
        .iter()
        .flat_map(|(_, value)| value.package_sources.iter().cloned())
        .collect();
    let mut seen_sources = HashSet::new();
    result
        .package_sources
        .retain(|path| seen_sources.insert(path.clone()));
    result.repository_paths = values
        .iter()
        .flat_map(|(_, value)| value.repository_paths.iter().cloned())
        .collect();
    let mut seen_repository_paths = HashSet::new();
    result
        .repository_paths
        .retain(|path| seen_repository_paths.insert(path.clone()));
    Ok(result)
}

fn same_nuget_config_case_alias(
    platform: Platform,
    first: &MavenSettingsFile,
    candidate: &MavenSettingsFile,
) -> bool {
    platform == Platform::Macos
        && first.identity.is_some()
        && first.identity == candidate.identity
        && first.bytes == candidate.bytes
}

fn nuget_solution_config_paths(
    platform: Platform,
    cwd: &Path,
) -> Result<NugetSolutionConfigPaths, &'static str> {
    let cwd = cwd
        .canonicalize()
        .map_err(|_| "current directory could not be resolved safely")?;
    if !cwd.is_dir() {
        return Err("current directory could not be resolved safely");
    }
    let mut paths = NugetSolutionConfigPaths::default();
    let mut file_count = 0usize;
    let mut total_bytes = 0usize;
    for (depth, directory) in cwd.ancestors().enumerate() {
        if depth >= MAX_NUGET_SOLUTION_CONFIG_DEPTH {
            return Err("NuGet solution config search exceeded its depth limit");
        }
        let mut found: Option<MavenSettingsFile> = None;
        #[cfg(windows)]
        let names = ["NuGet.Config"];
        #[cfg(not(windows))]
        let names = ["NuGet.Config", "NuGet.config", "nuget.config"];
        for name in names {
            let Some(candidate) = read_maven_settings(&directory.join(name))
                .map_err(|_| "NuGet solution config could not be read safely")?
            else {
                continue;
            };
            if found
                .as_ref()
                .is_some_and(|first| same_nuget_config_case_alias(platform, first, &candidate))
            {
                continue;
            }
            if found.is_some() {
                return Err("NuGet solution config has ambiguous files at one directory level");
            }
            found = Some(candidate);
        }
        let Some(settings) = found else {
            continue;
        };
        if file_count >= MAX_NUGET_SOLUTION_CONFIG_FILES {
            return Err("NuGet solution config search exceeded its file limit");
        }
        file_count += 1;
        total_bytes = total_bytes.saturating_add(settings.bytes.len());
        if total_bytes > MAX_NUGET_SOLUTION_CONFIG_TOTAL_BYTES {
            return Err("NuGet solution configs exceed the aggregate size limit");
        }
        let observed = parse_nuget_solution_config(&settings.bytes)?;
        paths.global_packages.extend(observed.global_packages);
        paths
            .fallback_package_folders
            .extend(observed.fallback_package_folders);
        paths.package_sources.extend(observed.package_sources);
        paths.repository_paths.extend(observed.repository_paths);
    }
    Ok(paths)
}

fn nuget_defaults_config_paths(
    platform: Platform,
    home: &Path,
    dotnet_cli_home: Option<&Path>,
    xdg_data_home: Option<&std::ffi::OsStr>,
    program_files_x86: Option<&std::ffi::OsStr>,
) -> Result<NugetSolutionConfigPaths, &'static str> {
    let data_homes = match platform {
        Platform::Linux | Platform::Macos => {
            let mut data_homes = Vec::new();
            if let Some(value) = xdg_data_home.filter(|value| !value.is_empty()) {
                data_homes.push(
                    nuget_safe_absolute_path(PathBuf::from(value))
                        .map_err(|_| "NuGet defaults config location is not absolute")?,
                );
            }
            for root in nuget_home_roots(home, dotnet_cli_home)? {
                let data_home = nuget_safe_absolute_path(root.join(".local/share"))
                    .map_err(|_| "NuGet defaults config location is not absolute")?;
                if !data_homes.contains(&data_home) {
                    data_homes.push(data_home);
                }
            }
            data_homes
        }
        Platform::Windows => {
            let root = program_files_x86
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .ok_or("NuGet defaults config location is unavailable")?;
            vec![root.join("NuGet")]
        }
    };
    let mut paths = NugetSolutionConfigPaths::default();
    for data_home in data_homes {
        let Some(settings) = read_maven_settings(&data_home.join("NuGetDefaults.Config"))
            .map_err(|_| "NuGet defaults config could not be read safely")?
        else {
            continue;
        };
        let observed = parse_nuget_solution_config(&settings.bytes)?;
        if !observed.global_packages.is_empty()
            || !observed.fallback_package_folders.is_empty()
            || !observed.repository_paths.is_empty()
        {
            return Err("NuGet defaults config has unsupported package location settings");
        }
        paths.package_sources.extend(observed.package_sources);
    }
    let mut seen_sources = HashSet::new();
    paths
        .package_sources
        .retain(|path| seen_sources.insert(path.clone()));
    Ok(paths)
}

#[derive(Default)]
struct GoEnvironment {
    values: HashMap<&'static str, std::ffi::OsString>,
    warning: Option<&'static str>,
}

impl GoEnvironment {
    fn value(&self, name: &'static str) -> Option<std::ffi::OsString> {
        let process = env::var_os(name);
        // GOTOOLCHAIN can select another root, so do not guess which system go.env applies.
        merge_go_value(
            process.as_deref(),
            self.values.get(name).map(std::ffi::OsString::as_os_str),
            None,
        )
    }

    fn key_known(&self, name: &'static str) -> bool {
        env::var_os(name).is_some_and(|value| !value.is_empty()) || self.values.contains_key(name)
    }

    fn cache_paths_known(&self, cache: &Path) -> bool {
        if !self.key_known("GOCACHE") || !self.key_known("GOMODCACHE") {
            return false;
        }
        let build_known = match self.value("GOCACHE") {
            Some(value) if value == "off" => true,
            Some(value) if value.is_empty() => go_default_cache(cache).is_some(),
            Some(value) => PathBuf::from(value).is_absolute(),
            None => false,
        };
        let modules_known = match self.value("GOMODCACHE") {
            Some(value) if value.is_empty() => go_path(self.value("GOPATH")).is_some(),
            Some(value) => PathBuf::from(value).is_absolute(),
            None => false,
        };
        build_known && modules_known && self.key_known("GOCACHEPROG")
    }

    #[cfg(target_os = "linux")]
    fn safe_for_cache_removal(&self, cache: &Path) -> bool {
        self.cache_paths_known(cache)
            && self
                .value("GOCACHEPROG")
                .is_none_or(|value| value.is_empty())
    }
}

fn merge_go_value(
    process: Option<&std::ffi::OsStr>,
    user: Option<&std::ffi::OsStr>,
    system: Option<&std::ffi::OsStr>,
) -> Option<std::ffi::OsString> {
    process
        .filter(|value| !value.is_empty())
        .or(user)
        .or(system)
        .map(std::ffi::OsStr::to_os_string)
}

#[cfg(target_os = "linux")]
fn go_user_dir(
    home: Option<&std::ffi::OsStr>,
    xdg: Option<&std::ffi::OsStr>,
    fallback: &str,
) -> Option<PathBuf> {
    match xdg.filter(|value| !value.is_empty()) {
        Some(value) => {
            let path = PathBuf::from(value);
            path.is_absolute().then_some(path)
        }
        None => home
            .filter(|value| !value.is_empty())
            .map(|value| PathBuf::from(value).join(fallback)),
    }
}

#[cfg(target_os = "linux")]
fn go_environment() -> GoEnvironment {
    use std::{io::Read, os::unix::fs::MetadataExt};
    let selected = env::var_os("GOENV").filter(|value| !value.is_empty());
    if selected.as_deref() == Some(std::ffi::OsStr::new("off")) {
        return GoEnvironment::default();
    }
    if selected.is_none()
        && env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .is_some_and(|value| !Path::new(&value).is_absolute())
    {
        return GoEnvironment {
            warning: Some(
                "Go ignores its persistent environment when XDG_CONFIG_HOME is relative; inferred cache paths may be inaccurate",
            ),
            ..Default::default()
        };
    }
    let path = match selected.map(PathBuf::from).or_else(|| {
        go_user_dir(
            env::var_os("HOME").as_deref(),
            env::var_os("XDG_CONFIG_HOME").as_deref(),
            ".config",
        )
        .map(|path| path.join("go/env"))
    }) {
        Some(path) => path,
        None => {
            return GoEnvironment {
                warning: Some(
                    "Go persistent environment location is unavailable; inferred cache paths may be inaccurate",
                ),
                ..Default::default()
            };
        }
    };
    let fd = match rustix::fs::openat2(
        rustix::fs::CWD,
        &path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return GoEnvironment::default(),
        Err(_) => {
            return GoEnvironment {
                warning: Some(
                    "Go persistent environment could not be read without following links; inferred cache paths may be inaccurate",
                ),
                ..Default::default()
            };
        }
    };
    let inspected = std::fs::File::from(fd);
    let read = || -> std::io::Result<Vec<u8>> {
        let expected = inspected.metadata()?;
        // shortcut: cap the Go environment file at 256 KiB; stream larger configurations if needed.
        if !expected.is_file() || expected.len() > 256 * 1024 {
            return Err(std::io::Error::other("invalid Go environment file"));
        }
        let file = std::fs::File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            &path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )?);
        let before = file.metadata()?;
        if !before.is_file() || before.dev() != expected.dev() || before.ino() != expected.ino() {
            return Err(std::io::Error::other("Go environment file changed"));
        }
        let mut bytes = Vec::new();
        (&file).take(256 * 1024 + 1).read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        if bytes.len() > 256 * 1024
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(std::io::Error::other("Go environment file changed"));
        }
        Ok(bytes)
    };
    let bytes = match read() {
        Ok(bytes) => bytes,
        Err(_) => {
            return GoEnvironment {
                warning: Some(
                    "Go persistent environment is unreadable, unsafe, too large, or changed; inferred cache paths may be inaccurate",
                ),
                ..Default::default()
            };
        }
    };
    parse_go_environment(&bytes)
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn read_go_environment_file(path: &Path) -> Result<Option<Vec<u8>>, ()> {
    use std::{io::Read, os::unix::fs::MetadataExt, path::Component};

    // shortcut: cap Go config reads at 256 KiB; stream larger files if Go supports them.
    const LIMIT: u64 = 256 * 1024;
    if !path.is_absolute() {
        return Err(());
    }
    let mut parts = path.components().peekable();
    let mut directory = std::fs::File::from(
        rustix::fs::open(
            "/",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| ())?,
    );
    while let Some(part) = parts.next() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) if parts.peek().is_some() => {
                let fd = match rustix::fs::openat(
                    &directory,
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                ) {
                    Ok(fd) => fd,
                    Err(rustix::io::Errno::NOENT) => return Ok(None),
                    Err(_) => return Err(()),
                };
                directory = std::fs::File::from(fd);
            }
            Component::Normal(name) => {
                let fd = match rustix::fs::openat(
                    &directory,
                    name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NONBLOCK
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                ) {
                    Ok(fd) => fd,
                    Err(rustix::io::Errno::NOENT) => return Ok(None),
                    Err(_) => return Err(()),
                };
                let file = std::fs::File::from(fd);
                let before = file.metadata().map_err(|_| ())?;
                if !before.is_file() || before.nlink() != 1 || before.len() > LIMIT {
                    return Err(());
                }
                let mut bytes = Vec::with_capacity(before.len() as usize);
                (&file)
                    .take(LIMIT + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| ())?;
                let after = file.metadata().map_err(|_| ())?;
                if bytes.len() as u64 > LIMIT
                    || before.dev() != after.dev()
                    || before.ino() != after.ino()
                    || before.nlink() != after.nlink()
                    || before.len() != after.len()
                    || before.mtime() != after.mtime()
                    || before.mtime_nsec() != after.mtime_nsec()
                    || before.ctime() != after.ctime()
                    || before.ctime_nsec() != after.ctime_nsec()
                {
                    return Err(());
                }
                return Ok(Some(bytes));
            }
            Component::ParentDir | Component::Prefix(_) => return Err(()),
        }
    }
    Err(())
}

#[cfg(target_os = "macos")]
fn go_environment() -> GoEnvironment {
    let selected = env::var_os("GOENV").filter(|value| !value.is_empty());
    if selected.as_deref() == Some(std::ffi::OsStr::new("off")) {
        return GoEnvironment::default();
    }
    let path = selected.map(PathBuf::from).or_else(|| {
        env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(|home| PathBuf::from(home).join("Library/Application Support/go/env"))
    });
    let Some(path) = path else {
        return GoEnvironment {
            warning: Some(
                "Go persistent environment location is unavailable; inferred cache paths may be inaccurate",
            ),
            ..Default::default()
        };
    };
    let bytes = match read_go_environment_file(&path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return GoEnvironment::default(),
        Err(()) => {
            return GoEnvironment {
                warning: Some(
                    "Go persistent environment is unreadable, unsafe, too large, or changed; inferred cache paths may be inaccurate",
                ),
                ..Default::default()
            };
        }
    };
    parse_go_environment(&bytes)
}

#[cfg(target_os = "windows")]
fn go_environment() -> GoEnvironment {
    let selected = env::var_os("GOENV");
    let app_data = env::var_os("APPDATA");
    let path = match windows_go_environment_path(selected.as_deref(), app_data.as_deref()) {
        Ok(Some(path)) => path,
        Ok(None) => return GoEnvironment::default(),
        Err(()) => {
            return GoEnvironment {
                warning: Some(
                    "Go persistent environment location is unsafe or unavailable on Windows; inferred cache paths may be inaccurate",
                ),
                ..Default::default()
            };
        }
    };
    let bytes = match read_go_environment_file_windows(&path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return GoEnvironment::default(),
        Err(()) => {
            return GoEnvironment {
                warning: Some(
                    "Go persistent environment is unreadable, unsafe, too large, or changed on Windows; inferred cache paths may be inaccurate",
                ),
                ..Default::default()
            };
        }
    };
    match parse_go_environment_windows(&bytes) {
        Ok(environment) => environment,
        Err(()) => GoEnvironment {
            warning: Some(
                "Go persistent environment contains unsupported values; inferred cache paths may be inaccurate",
            ),
            ..Default::default()
        },
    }
}

#[cfg(any(windows, test))]
fn windows_go_environment_path(
    selected: Option<&std::ffi::OsStr>,
    app_data: Option<&std::ffi::OsStr>,
) -> Result<Option<PathBuf>, ()> {
    use std::path::Component;

    if selected == Some(std::ffi::OsStr::new("off")) {
        return Ok(None);
    }

    let path = selected
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            app_data
                .filter(|value| !value.is_empty())
                .map(|value| PathBuf::from(value).join("go/env"))
        })
        .ok_or(())?;
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(());
    }
    Ok(Some(path))
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowsGoPathIdentity {
    volume: u64,
    index: u64,
    links: u64,
    created: u64,
    attributes: u64,
}

#[cfg(windows)]
fn windows_go_path_identity(path: &Path, directory: bool) -> Result<WindowsGoPathIdentity, ()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_SHARE_ALL: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
    let expected = fs::symlink_metadata(path).map_err(|_| ())?;
    if expected.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
        || expected.is_dir() != directory
        || expected.is_file() == directory
    {
        return Err(());
    }
    let mut options = fs::OpenOptions::new();
    options
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(
            WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
        );
    let file = options.open(path).map_err(|_| ())?;
    let actual = file.metadata().map_err(|_| ())?;
    let information = winapi_util::file::information(&file).map_err(|_| ())?;
    let identity = WindowsGoPathIdentity {
        volume: information.volume_serial_number(),
        index: information.file_index(),
        links: information.number_of_links(),
        created: information.creation_time().ok_or(())?,
        attributes: information.file_attributes(),
    };
    if actual.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
        || actual.is_dir() != directory
        || actual.is_file() == directory
        || actual.file_attributes() != expected.file_attributes()
    {
        return Err(());
    }
    Ok(identity)
}

#[cfg(windows)]
fn windows_go_environment_components(
    path: &Path,
) -> Result<Option<Vec<WindowsGoPathIdentity>>, ()> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(());
    }
    let components = path.components().collect::<Vec<_>>();
    if components
        .iter()
        .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(());
    }
    let last_normal = components
        .iter()
        .rposition(|part| matches!(part, Component::Normal(_)))
        .ok_or(())?;
    let mut current = PathBuf::new();
    let mut identities = Vec::new();
    for (index, part) in components.into_iter().enumerate() {
        current.push(part.as_os_str());
        if !matches!(part, Component::Normal(_)) {
            continue;
        }
        let directory = index != last_normal;
        if fs::symlink_metadata(&current)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(None);
        }
        identities.push(windows_go_path_identity(&current, directory)?);
    }
    Ok(Some(identities))
}

#[cfg(windows)]
fn read_go_environment_file_windows(path: &Path) -> Result<Option<Vec<u8>>, ()> {
    use std::{
        io::Read,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
    };

    const LIMIT: u64 = 256 * 1024;
    const FILE_SHARE_ALL: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;

    let before_components = match windows_go_environment_components(path)? {
        Some(components) => components,
        None => return Ok(None),
    };
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|_| ())?;
    let before_identity = winapi_util::file::information(&file).map_err(|_| ())?;
    let before = file.metadata().map_err(|_| ())?;
    let expected = *before_components.last().ok_or(())?;
    let identity = WindowsGoPathIdentity {
        volume: before_identity.volume_serial_number(),
        index: before_identity.file_index(),
        links: before_identity.number_of_links(),
        created: before_identity.creation_time().ok_or(())?,
        attributes: before_identity.file_attributes(),
    };
    if identity != expected
        || !before.is_file()
        || before.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
        || before_identity.number_of_links() != 1
        || before.file_size() > LIMIT
    {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(before.file_size() as usize);
    (&file)
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    let after = file.metadata().map_err(|_| ())?;
    let after_identity = winapi_util::file::information(&file).map_err(|_| ())?;
    let after_identity = WindowsGoPathIdentity {
        volume: after_identity.volume_serial_number(),
        index: after_identity.file_index(),
        links: after_identity.number_of_links(),
        created: after_identity.creation_time().ok_or(())?,
        attributes: after_identity.file_attributes(),
    };
    if bytes.len() as u64 > LIMIT
        || after_identity != identity
        || before.file_size() != after.file_size()
        || before.last_write_time() != after.last_write_time()
        || windows_go_environment_components(path)? != Some(before_components)
    {
        return Err(());
    }
    Ok(Some(bytes))
}

#[cfg(any(windows, test))]
fn parse_go_environment_windows(bytes: &[u8]) -> Result<GoEnvironment, ()> {
    let mut values = HashMap::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        let Some(index) = line.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let key = match &line[..index] {
            b"GOCACHE" => "GOCACHE",
            b"GOMODCACHE" => "GOMODCACHE",
            b"GOPATH" => "GOPATH",
            b"GOCACHEPROG" => "GOCACHEPROG",
            _ => continue,
        };
        let value = std::str::from_utf8(&line[index + 1..]).map_err(|_| ())?;
        if value.contains('\0') {
            return Err(());
        }
        values.insert(key, std::ffi::OsString::from(value));
    }
    Ok(GoEnvironment {
        values,
        warning: None,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn parse_go_environment(bytes: &[u8]) -> GoEnvironment {
    use std::os::unix::ffi::OsStringExt;
    let mut values = HashMap::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        let Some(index) = line.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let key = match &line[..index] {
            b"GOCACHE" => "GOCACHE",
            b"GOMODCACHE" => "GOMODCACHE",
            b"GOPATH" => "GOPATH",
            b"GOCACHEPROG" => "GOCACHEPROG",
            _ => continue,
        };
        values.insert(
            key,
            std::ffi::OsString::from_vec(line[index + 1..].to_vec()),
        );
    }
    GoEnvironment {
        values,
        warning: None,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn go_environment() -> GoEnvironment {
    GoEnvironment {
        warning: Some(
            "Go persistent environment is not inspected on this platform; inferred cache paths may be inaccurate",
        ),
        ..Default::default()
    }
}

fn go_path(gopath: Option<std::ffi::OsString>) -> Option<PathBuf> {
    match gopath {
        // The default GOPATH may equal the active GOROOT, which is unknown here.
        Some(value) if value.is_empty() => None,
        Some(value) => env::split_paths(&value).next().filter(|p| p.is_absolute()),
        None => None,
    }
}

fn go_default_cache(cache: &Path) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let _ = cache;
        go_user_dir(
            env::var_os("HOME").as_deref(),
            env::var_os("XDG_CACHE_HOME").as_deref(),
            ".cache",
        )
        .map(|path| path.join("go-build"))
    }
    #[cfg(target_os = "windows")]
    {
        let _ = cache;
        env::var_os("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .map(|path| path.join("go-build"))
    }
    #[cfg(target_os = "macos")]
    {
        let _ = cache;
        env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .map(|path| path.join("Library/Caches/go-build"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Some(cache.join("go-build"))
    }
}

fn nuget_default_packages_path(
    platform: Platform,
    home: &Path,
    user_profile: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    let base = if platform == Platform::Windows {
        let path = PathBuf::from(user_profile?);
        path.is_absolute().then_some(path)?
    } else {
        home.to_owned()
    };
    Some(base.join(".nuget/packages"))
}

fn nuget_packages_paths(
    platform: Platform,
    home: &Path,
    packages: Option<&std::ffi::OsStr>,
    user_profile: Option<&std::ffi::OsStr>,
    user_config_paths: (Vec<PathBuf>, Vec<PathBuf>),
    fallback_overrides: impl IntoIterator<Item = PathBuf>,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>), &'static str> {
    let (config_overrides, fallback_config) = user_config_paths;
    let mut global = Vec::new();
    if let Some(value) = packages {
        global.push(
            nuget_safe_absolute_path(PathBuf::from(value))
                .map_err(|_| "NUGET_PACKAGES is not a safe absolute path")?,
        );
    }
    for path in config_overrides {
        global.push(nuget_safe_absolute_path(path)?);
    }
    let default = nuget_default_packages_path(platform, home, user_profile)
        .ok_or("NuGet default package location is unavailable")?;
    let default = nuget_safe_absolute_path(default)?;
    if !global.contains(&default) {
        global.push(default);
    }
    let mut fallback = fallback_overrides
        .into_iter()
        .map(nuget_safe_absolute_path)
        .collect::<Result<Vec<_>, _>>()?;
    fallback.extend(
        fallback_config
            .into_iter()
            .map(nuget_safe_absolute_path)
            .collect::<Result<Vec<_>, _>>()?,
    );
    for path in global.iter().chain(&fallback) {
        if path == home {
            return Err("NuGet package location resolves to the user home directory");
        }
    }
    let mut seen_global = HashSet::new();
    global.retain(|path| seen_global.insert(path.clone()));
    let mut seen_fallback = HashSet::new();
    fallback.retain(|path| !seen_global.contains(path) && seen_fallback.insert(path.clone()));
    if global.is_empty() {
        return Err("NuGet global package locations are unavailable");
    }
    Ok((global, fallback))
}

fn nuget_fallback_packages_paths(
    value: Option<&std::ffi::OsStr>,
) -> Result<Vec<PathBuf>, &'static str> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    nuget_path_list(
        value,
        "NUGET_FALLBACK_PACKAGES requires absolute safe paths",
    )
}

fn nuget_path_list(
    value: &std::ffi::OsStr,
    error: &'static str,
) -> Result<Vec<PathBuf>, &'static str> {
    let value = value.to_str().ok_or(error)?;
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(';')
        .map(|path| {
            if path.is_empty() {
                return Err(error);
            }
            nuget_safe_absolute_path(PathBuf::from(path)).map_err(|_| error)
        })
        .collect()
}

fn nuget_environment_property(name: &str) -> Result<Option<std::ffi::OsString>, &'static str> {
    nuget_environment_property_from(env::vars_os(), name)
}

fn nuget_environment_property_from(
    variables: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    name: &str,
) -> Result<Option<std::ffi::OsString>, &'static str> {
    let mut value = None;
    for (key, candidate) in variables {
        if key
            .to_str()
            .is_some_and(|key| key.eq_ignore_ascii_case(name))
        {
            if value.as_ref().is_some_and(|value| value != &candidate) {
                return Err("NuGet MSBuild environment properties are ambiguous");
            }
            value = Some(candidate);
        }
    }
    Ok(value)
}

fn nuget_dotnet_cli_home(value: Option<&std::ffi::OsStr>) -> Result<Option<PathBuf>, &'static str> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty() {
        return Err("DOTNET_CLI_HOME is empty and its NuGet paths are ambiguous");
    }
    nuget_safe_absolute_path(PathBuf::from(value))
        .map(Some)
        .map_err(|_| "DOTNET_CLI_HOME must be a safe absolute path")
}

fn nuget_home_roots(
    home: &Path,
    dotnet_cli_home: Option<&Path>,
) -> Result<Vec<PathBuf>, &'static str> {
    let mut roots = vec![nuget_safe_absolute_path(home.to_owned())?];
    if let Some(dotnet_cli_home) = dotnet_cli_home {
        let dotnet_cli_home = nuget_safe_absolute_path(dotnet_cli_home.to_owned())?;
        if !roots.contains(&dotnet_cli_home) {
            roots.push(dotnet_cli_home);
        }
    }
    Ok(roots)
}

fn nuget_msbuild_environment_paths() -> Result<NugetSolutionConfigPaths, &'static str> {
    if nuget_environment_property("NUGET_RESTORE_MSBUILD_ARGS")?
        .is_some_and(|value| !value.is_empty())
    {
        return Err("NUGET_RESTORE_MSBUILD_ARGS may change NuGet package locations");
    }
    if nuget_environment_property("RestoreConfigFile")?.is_some_and(|value| !value.is_empty()) {
        return Err("MSBuild RestoreConfigFile package locations are unverified");
    }

    let mut global = Vec::new();
    for name in ["RestorePackagesPath", "RestoreRepositoryPath"] {
        let Some(value) = nuget_environment_property(name)? else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        let value = value
            .to_str()
            .ok_or("MSBuild package path property is not valid Unicode")?;
        global.push(
            nuget_safe_absolute_path(PathBuf::from(value))
                .map_err(|_| "MSBuild package path property is not a safe absolute path")?,
        );
    }

    let mut fallback = Vec::new();
    for name in [
        "RestoreFallbackFolders",
        "RestoreAdditionalProjectFallbackFolders",
    ] {
        if let Some(value) = nuget_environment_property(name)? {
            fallback.extend(nuget_path_list(
                &value,
                "MSBuild fallback folder property requires absolute safe paths",
            )?);
        }
    }
    let mut sources = Vec::new();
    for name in ["RestoreSources", "RestoreAdditionalProjectSources"] {
        let Some(value) = nuget_environment_property(name)? else {
            continue;
        };
        let value = value
            .to_str()
            .ok_or("MSBuild package source property is not valid Unicode")?;
        if value.is_empty() {
            continue;
        }
        sources.extend(nuget_package_source_paths(value)?);
    }
    Ok(NugetSolutionConfigPaths {
        global_packages: global,
        fallback_package_folders: fallback,
        package_sources: sources,
        repository_paths: Vec::new(),
    })
}

fn nuget_safe_absolute_path(path: PathBuf) -> Result<PathBuf, &'static str> {
    use std::path::Component;

    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err("NuGet globalPackagesFolder is not a safe absolute path");
    }
    Ok(path)
}

fn nuget_xdg_config_roots(
    home: &Path,
    xdg_config: Option<&std::ffi::OsStr>,
) -> Result<Vec<PathBuf>, &'static str> {
    let mut roots = vec![
        nuget_safe_absolute_path(home.join(".config"))
            .map_err(|_| "NuGet default user config location is not absolute")?,
    ];
    if let Some(value) = xdg_config.filter(|value| !value.is_empty()) {
        let root = nuget_safe_absolute_path(PathBuf::from(value))
            .map_err(|_| "XDG_CONFIG_HOME must be a safe absolute path")?;
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    Ok(roots)
}

fn nuget_user_config_locations(
    platform: Platform,
    home: &Path,
    dotnet_cli_home: Option<&Path>,
    appdata: Option<&std::ffi::OsStr>,
    xdg_config: Option<&std::ffi::OsStr>,
) -> Result<Vec<(usize, PathBuf, PathBuf)>, &'static str> {
    if platform == Platform::Windows {
        let Some(appdata) = appdata.filter(|value| !value.is_empty()) else {
            return Ok(Vec::new());
        };
        let root = nuget_safe_absolute_path(PathBuf::from(appdata))
            .map_err(|_| "NuGet user config location is not absolute")?
            .join("NuGet");
        return Ok(vec![(0, root.join("NuGet.Config"), root.join("config"))]);
    }
    let homes = nuget_home_roots(home, dotnet_cli_home)?;
    let mut locations = Vec::new();
    for root in homes {
        let group = locations.len();
        locations.push((
            group,
            root.join(".nuget/NuGet/NuGet.Config"),
            root.join(".nuget/config"),
        ));
    }
    for root in nuget_xdg_config_roots(home, xdg_config)? {
        let root = root.join("NuGet");
        let group = locations.len();
        locations.push((group, root.join("NuGet.Config"), root.join("config")));
    }
    let mut seen = HashSet::new();
    locations.retain(|(_, settings, _)| seen.insert(settings.clone()));
    Ok(locations)
}

fn expand_nuget_config_path(
    value: &str,
    allow_environment_expansion: bool,
) -> Result<PathBuf, &'static str> {
    if value != value.trim() {
        return Err("NuGet package path has unsupported surrounding whitespace");
    }
    if value.is_empty() || value.len() > MAX_NUGET_CONFIG_PATH_BYTES {
        return Err("NuGet globalPackagesFolder is empty or exceeds the size limit");
    }
    if value.contains('$') || (!allow_environment_expansion && value.contains('%')) {
        return Err("NuGet package path uses unsupported dynamic expansion");
    }
    let mut expanded = String::with_capacity(value.len());
    let mut remaining = value;
    while let Some(start) = remaining.find('%') {
        expanded.push_str(&remaining[..start]);
        let variable = &remaining[start + 1..];
        let end = variable
            .find('%')
            .ok_or("NuGet globalPackagesFolder has an unresolved environment variable")?;
        let name = &variable[..end];
        if name.is_empty() {
            return Err("NuGet globalPackagesFolder has an unresolved environment variable");
        }
        let replacement = env::var_os(name)
            .and_then(|value| value.into_string().ok())
            .ok_or("NuGet globalPackagesFolder has an unresolved environment variable")?;
        if expanded.len().saturating_add(replacement.len()) > MAX_NUGET_CONFIG_PATH_BYTES {
            return Err("NuGet globalPackagesFolder exceeds the size limit");
        }
        expanded.push_str(&replacement);
        remaining = &variable[end + 1..];
    }
    expanded.push_str(remaining);
    if expanded.len() > MAX_NUGET_CONFIG_PATH_BYTES {
        return Err("NuGet globalPackagesFolder exceeds the size limit");
    }
    nuget_safe_absolute_path(PathBuf::from(expanded))
}

fn nuget_additional_configs_exist(path: &Path) -> Result<bool, &'static str> {
    use std::io::ErrorKind;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("additional NuGet settings could not be inspected safely"),
    };
    #[cfg(windows)]
    let is_reparse_point = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
    };
    #[cfg(not(windows))]
    let is_reparse_point = false;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || is_reparse_point {
        return Err("additional NuGet settings directory is not a regular directory");
    }
    let entries = std::fs::read_dir(path)
        .map_err(|_| "additional NuGet settings could not be inspected safely")?;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_NUGET_CONFIG_DIR_ENTRIES {
            return Err("additional NuGet settings directory exceeds its entry limit");
        }
        let entry = entry.map_err(|_| "additional NuGet settings could not be inspected safely")?;
        let is_config = entry
            .path()
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("config"));
        if !is_config {
            continue;
        }
        let metadata = std::fs::symlink_metadata(entry.path())
            .map_err(|_| "additional NuGet settings could not be inspected safely")?;
        #[cfg(windows)]
        let is_reparse_point = {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
        };
        #[cfg(not(windows))]
        let is_reparse_point = false;
        if metadata.file_type().is_symlink() || !metadata.is_file() || is_reparse_point {
            return Err("additional NuGet settings contain a non-regular config file");
        }
        return Ok(true);
    }
    Ok(false)
}

fn nuget_machine_config_directories(
    platform: Platform,
    common_application_data: Option<&std::ffi::OsStr>,
    program_files_x86: Option<&std::ffi::OsStr>,
    default_config_directory: Option<&Path>,
) -> Result<Vec<PathBuf>, &'static str> {
    let default = match default_config_directory {
        Some(path) => path.to_owned(),
        None => match platform {
            Platform::Linux => PathBuf::from("/etc/opt/NuGet/Config"),
            Platform::Macos => PathBuf::from("/Library/Application Support/NuGet/Config"),
            Platform::Windows => {
                let path = program_files_x86
                    .map(PathBuf::from)
                    .filter(|path| path.is_absolute())
                    .ok_or("NuGet machine config path is unavailable")?;
                path.join("NuGet/Config")
            }
        },
    };
    let mut directories = vec![
        nuget_safe_absolute_path(default)
            .map_err(|_| "NuGet machine config path is not absolute")?,
    ];
    if let Some(value) = common_application_data.filter(|value| !value.is_empty()) {
        let root = nuget_safe_absolute_path(PathBuf::from(value))
            .map_err(|_| "NuGet common application data path is not absolute")?;
        let override_directory = root.join("NuGet/Config");
        if !directories.contains(&override_directory) {
            directories.push(override_directory);
        }
    }
    Ok(directories)
}

fn specs(
    platform: Platform,
    home: &Path,
    cache: &Path,
    data: &Path,
    go_env: &GoEnvironment,
    nuget_paths: (Vec<PathBuf>, Vec<PathBuf>),
    optional_paths: [Option<PathBuf>; 2],
) -> Vec<Spec> {
    let (nuget_packages, nuget_fallback_packages) = nuget_paths;
    let [maven_repository, zig_global_cache] = optional_paths;
    let mut specs = Vec::new();
    let cargo = env_dir("CARGO_HOME", home.join(".cargo"));
    let xdg_cache = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute());
    let mut add = |name, path: Option<PathBuf>, classification, consequence| {
        if let Some(path) = path {
            specs.push(Spec {
                name,
                path,
                classification,
                consequence,
            });
        }
    };
    add(
        "Cargo registry",
        cargo.as_ref().map(|p| p.join("registry")),
        "shared dependencies",
        "packages may need to be downloaded again",
    );
    add(
        "Cargo git",
        cargo.as_ref().map(|p| p.join("git")),
        "shared dependencies",
        "Git dependencies may need to be fetched again",
    );
    add(
        "Go build",
        match go_env.value("GOCACHE") {
            Some(value) if value == "off" => None,
            Some(value) if value.is_empty() => go_default_cache(cache),
            Some(value) => {
                let path = PathBuf::from(value);
                path.is_absolute().then_some(path)
            }
            None => None,
        },
        "shared build cache",
        "packages may need recompilation",
    );
    add(
        "Go modules",
        match go_env.value("GOMODCACHE") {
            Some(value) if value.is_empty() => {
                go_path(go_env.value("GOPATH")).map(|p| p.join("pkg/mod"))
            }
            Some(value) => {
                let path = PathBuf::from(value);
                path.is_absolute().then_some(path)
            }
            None => None,
        },
        "shared dependencies",
        "modules may need to be downloaded again",
    );
    add(
        "npm",
        env_dir("npm_config_cache", npm_default(platform, home, data)).map(|p| p.join("_cacache")),
        "shared package cache",
        "packages may need to be downloaded again",
    );
    add(
        "pnpm",
        pnpm_store_path(
            platform,
            home,
            data,
            pnpm_configured_store_dir().as_deref(),
            env::var_os("PNPM_HOME").as_deref(),
            env::var_os("XDG_DATA_HOME").as_deref(),
        ),
        "shared dependencies",
        "packages may need to be downloaded again",
    );
    add(
        "Yarn classic",
        env_dir(
            "YARN_CACHE_FOLDER",
            yarn_default(platform, home, cache, data, xdg_cache.as_deref()),
        ),
        "shared package cache",
        "packages may need to be downloaded again",
    );
    add(
        "pip",
        env_dir("PIP_CACHE_DIR", pip_default(platform, cache, data)),
        "shared package cache",
        "packages may need to be downloaded again",
    );
    add(
        "Gradle",
        env_dir("GRADLE_USER_HOME", home.join(".gradle")).map(|p| p.join("caches")),
        "shared dependencies",
        "dependencies may need downloading and rebuilding",
    );
    add(
        "Maven",
        maven_repository,
        "shared dependencies",
        "dependencies may need to be downloaded again",
    );
    for path in nuget_packages {
        add(
            "NuGet global packages",
            Some(path),
            "shared dependencies",
            "packages may need to be restored or downloaded again",
        );
    }
    for path in nuget_fallback_packages {
        add(
            "NuGet fallback packages",
            Some(path),
            "shared dependencies",
            "packages may be read from this folder during restore",
        );
    }
    add(
        "Zig",
        zig_global_cache,
        "shared build cache",
        "artifacts may need recompilation and packages may need to be downloaded again",
    );
    add(
        "ccache",
        env_dir(
            "CCACHE_DIR",
            ccache_default(platform, home, cache, data, xdg_cache.as_deref()),
        ),
        "shared build cache",
        "files may need recompilation",
    );
    add(
        "sccache",
        env_dir("SCCACHE_DIR", sccache_default(platform, home, cache, data)),
        "shared build cache",
        "files may need recompilation",
    );
    add(
        "Dart pub",
        env_dir("PUB_CACHE", pub_default(platform, home, data)),
        "shared dependencies",
        "packages may need to be downloaded again",
    );
    specs
}

fn bun_specs(cache: Option<PathBuf>, command_cache: Option<PathBuf>) -> Vec<Spec> {
    let command_cache = command_cache.filter(|path| Some(path) != cache.as_ref());
    let mut specs = Vec::new();
    if let Some(path) = cache {
        specs.push(Spec {
            name: "Bun",
            path,
            classification: "shared package cache",
            consequence: "packages may need downloading again; hard-linked project files may keep using the same storage",
        });
    }
    if let Some(path) = command_cache {
        specs.push(Spec {
            name: "Bun cache command target",
            path,
            classification: "shared package cache",
            consequence: "Bun cache rm/prune may target this location; Upkit only inventories it",
        });
    }
    specs
}

#[cfg(target_os = "linux")]
pub(crate) fn selected_cache(path: &Path) -> anyhow::Result<Spec> {
    use anyhow::{Context, bail};
    let nuget_solution = nuget_solution_config_paths(
        Platform::Linux,
        &env::current_dir().context("current directory is unavailable")?,
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "NuGet solution config is unverified ({error}); shared-cache removal is blocked"
        )
    })?;
    let home = dirs::home_dir().context("user home is unavailable")?;
    let cache = dirs::cache_dir().context("user cache directory is unavailable")?;
    let data = dirs::data_local_dir().context("user data directory is unavailable")?;
    let dotnet_home = nuget_environment_property("DOTNET_CLI_HOME")
        .map_err(|error| anyhow::anyhow!("NuGet package locations are unverified ({error})"))?;
    let dotnet_home = nuget_dotnet_cli_home(dotnet_home.as_deref()).map_err(|error| {
        anyhow::anyhow!(
            "NuGet package locations are unverified ({error}); shared-cache removal is blocked"
        )
    })?;
    let machine_common_data = nuget_environment_property("NUGET_COMMON_APPLICATION_DATA")
        .map_err(|error| anyhow::anyhow!("NuGet machine config is unverified ({error})"))?;
    let machine_config_directories = nuget_machine_config_directories(
        Platform::Linux,
        machine_common_data.as_deref(),
        env::var_os("ProgramFiles(x86)").as_deref(),
        None,
    )
    .map_err(|error| anyhow::anyhow!("NuGet machine config is unverified ({error})"))?;
    let nuget_defaults = nuget_defaults_config_paths(
        Platform::Linux,
        &home,
        dotnet_home.as_deref(),
        env::var_os("XDG_DATA_HOME").as_deref(),
        env::var_os("ProgramFiles(x86)").as_deref(),
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "NuGet defaults config is unverified ({error}); shared-cache removal is blocked"
        )
    })?;
    let nuget_env = env::var_os("NUGET_PACKAGES");
    let nuget_fallback_env = env::var_os("NUGET_FALLBACK_PACKAGES");
    let nuget_config = nuget_user_package_folders(
        Platform::Linux,
        &home,
        dotnet_home.as_deref(),
        env::var_os("APPDATA").as_deref(),
        env::var_os("XDG_CONFIG_HOME").as_deref(),
        &machine_config_directories,
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "NuGet package locations are unverified ({error}); shared-cache removal is blocked"
        )
    })?;
    let nuget_fallbacks =
        nuget_fallback_packages_paths(nuget_fallback_env.as_deref()).map_err(|error| {
            anyhow::anyhow!(
                "NuGet package locations are unverified ({error}); shared-cache removal is blocked"
            )
        })?;
    let msbuild_paths = nuget_msbuild_environment_paths().map_err(|error| {
        anyhow::anyhow!(
            "NuGet package locations are unverified ({error}); shared-cache removal is blocked"
        )
    })?;
    let mut config_global_paths = nuget_config.global_packages.into_iter().collect::<Vec<_>>();
    config_global_paths.extend(nuget_config.additional_global_packages);
    if let Some(dotnet_home) = &dotnet_home {
        config_global_paths.push(dotnet_home.join(".nuget/packages"));
    }
    config_global_paths.extend(nuget_solution.global_packages.iter().cloned());
    config_global_paths.extend(nuget_defaults.global_packages.iter().cloned());
    let mut nuget_repository_paths = nuget_config.repository_paths;
    nuget_repository_paths.extend(nuget_solution.repository_paths.iter().cloned());
    let mut seen_repository_paths = HashSet::new();
    nuget_repository_paths.retain(|path| seen_repository_paths.insert(path.clone()));
    config_global_paths.extend(nuget_repository_paths.iter().cloned());
    config_global_paths.extend(msbuild_paths.global_packages);
    let mut config_fallback_paths = nuget_config
        .fallback_package_folders
        .into_iter()
        .map(|(_, path)| path)
        .collect::<Vec<_>>();
    config_fallback_paths.extend(nuget_solution.fallback_package_folders.iter().cloned());
    config_fallback_paths.extend(nuget_defaults.fallback_package_folders.iter().cloned());
    config_fallback_paths.extend(msbuild_paths.fallback_package_folders);
    let mut nuget_source_paths = nuget_config.package_sources;
    nuget_source_paths.extend(nuget_solution.package_sources.iter().cloned());
    nuget_source_paths.extend(nuget_defaults.package_sources.iter().cloned());
    nuget_source_paths.extend(msbuild_paths.package_sources);
    let mut seen_sources = HashSet::new();
    nuget_source_paths.retain(|path| seen_sources.insert(path.clone()));
    let (mut nuget_packages, nuget_fallback_packages) = nuget_packages_paths(
        Platform::Linux,
        &home,
        nuget_env.as_deref(),
        env::var_os("USERPROFILE").as_deref(),
        (config_global_paths, config_fallback_paths),
        nuget_fallbacks,
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "NuGet global package location is unknown ({error}); shared-cache removal is blocked"
        )
    })?;
    nuget_packages.retain(|path| !nuget_repository_paths.contains(path));
    let go_env = go_environment();
    if !go_env.safe_for_cache_removal(&cache) {
        bail!(
            "Go cache locations are unknown or an external cache program is configured; resolve them before removing any shared cache"
        );
    }
    let pnpm_store_dir = pnpm_configured_store_dir();
    let pnpm_home = env::var_os("PNPM_HOME");
    let xdg_data_home = env::var_os("XDG_DATA_HOME");
    if pnpm_store_path(
        Platform::Linux,
        &home,
        &data,
        pnpm_store_dir.as_deref(),
        pnpm_home.as_deref(),
        xdg_data_home.as_deref(),
    )
    .is_none()
    {
        bail!(
            "pnpm store configuration is not absolute; resolve it before removing any shared cache"
        );
    }
    let maven_repository = maven_repository(&home).map_err(|error| {
        anyhow::anyhow!("Maven cache configuration is unverified ({error}); resolve it before removing any shared cache")
    })?;
    let zig_global_cache = zig_global_cache(Platform::Linux).map_err(|error| {
        anyhow::anyhow!("Zig global cache configuration is unverified ({error}); resolve it before removing any shared cache")
    })?;
    let bun_cache = bun_install_cache_path(
        &home,
        env::var_os("BUN_INSTALL_CACHE_DIR").as_deref(),
    )
    .map_err(|error| {
        anyhow::anyhow!("Bun cache configuration is unverified ({error}); resolve it before removing any shared cache")
    })?;
    let bun_command_cache = bun_cache_command_path(
        &home,
        env::var_os("BUN_INSTALL_CACHE_DIR").as_deref(),
        env::var_os("BUN_INSTALL").as_deref(),
    )
    .map_err(|error| {
        anyhow::anyhow!("Bun cache command path is unverified ({error}); resolve it before removing any shared cache")
    })?;
    let mut discovered = specs(
        Platform::Linux,
        &home,
        &cache,
        &data,
        &go_env,
        (nuget_packages, nuget_fallback_packages),
        [Some(maven_repository), Some(zig_global_cache)],
    );
    discovered.extend(bun_specs(Some(bun_cache.clone()), Some(bun_command_cache)));
    discovered.extend(nuget_repository_paths.into_iter().map(|path| Spec {
        name: "NuGet packages.config repository",
        path,
        classification: "shared dependencies",
        consequence: "packages.config packages may need to be restored or downloaded again",
    }));
    discovered.extend(nuget_source_paths.into_iter().map(|path| Spec {
        name: "NuGet local package source",
        path,
        classification: "local package feed",
        consequence: "packages may be restored from this local source",
    }));
    let mut matches = discovered.iter().filter(|spec| spec.path == path);
    let first = matches
        .next()
        .context("selected path is not a discovered shared cache")?
        .clone();
    if matches.next().is_some() {
        bail!("selected path matches more than one cache");
    }
    if first.name == "pnpm" && pnpm_configured_store_dir().is_none() {
        bail!(
            "pnpm's store can be configured per workspace or filesystem; only an explicit PNPM_CONFIG_STORE_DIR can be removed safely"
        );
    }
    if matches!(first.name, "Bun" | "Bun cache command target") {
        bail!(
            "Upkit inventories the Bun cache but does not remove it; its hard-linked package files may still be used by project node_modules"
        );
    }
    if matches!(
        first.name,
        "NuGet global packages" | "NuGet fallback packages" | "NuGet packages.config repository"
    ) {
        bail!(
            "Upkit inventories NuGet package folders but does not remove them; use NuGet's own cache cleanup command"
        );
    }
    if first.name == "NuGet local package source" {
        bail!("Upkit inventories local NuGet package sources but does not remove them");
    }
    let xdg_cache = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute());
    let uv_override = env::var_os("UV_CACHE_DIR");
    if let Some(uv) = uv_spec(
        Platform::Linux,
        &home,
        &cache,
        xdg_cache.as_deref(),
        uv_override.as_deref(),
    ) {
        discovered.push(uv);
    } else if uv_override.is_some() {
        bail!("uv cache configuration is relative; resolve it before removing a cache");
    }
    for other in discovered.iter().filter(|other| other.name != first.name) {
        if other.path.starts_with(path)
            || path.starts_with(&other.path)
            || other
                .path
                .canonicalize()
                .ok()
                .is_some_and(|resolved| resolved.starts_with(path) || path.starts_with(&resolved))
        {
            bail!("selected cache overlaps another discovered cache location");
        }
    }
    Ok(first)
}

pub fn inventory(cancel: &AtomicBool) -> CacheReport {
    if cancel.load(Ordering::Relaxed) {
        return CacheReport {
            entries: vec![],
            warnings: vec![],
            cancelled: true,
        };
    }
    let platform = match std::env::consts::OS {
        "linux" => Platform::Linux,
        "macos" => Platform::Macos,
        "windows" => Platform::Windows,
        _ => {
            return CacheReport {
                entries: vec![],
                warnings: vec!["cache discovery is not implemented for this platform".into()],
                cancelled: cancel.load(Ordering::Relaxed),
            };
        }
    };
    let Some(home) = dirs::home_dir() else {
        return CacheReport {
            entries: vec![],
            warnings: vec!["cannot determine the user home directory".into()],
            cancelled: false,
        };
    };
    let cache = dirs::cache_dir();
    let data = dirs::data_local_dir();
    let (Some(cache), Some(data)) = (cache, data) else {
        return CacheReport {
            entries: vec![],
            warnings: vec!["cannot determine the user cache or local data directory".into()],
            cancelled: false,
        };
    };
    let go_env = go_environment();
    let nuget_env = env::var_os("NUGET_PACKAGES");
    let nuget_fallback_env = env::var_os("NUGET_FALLBACK_PACKAGES");
    let dotnet_home_result = nuget_environment_property("DOTNET_CLI_HOME")
        .and_then(|value| nuget_dotnet_cli_home(value.as_deref()));
    let machine_config_directories_result =
        nuget_environment_property("NUGET_COMMON_APPLICATION_DATA").and_then(|common_data| {
            nuget_machine_config_directories(
                platform,
                common_data.as_deref(),
                env::var_os("ProgramFiles(x86)").as_deref(),
                None,
            )
        });
    let nuget_config = match (&dotnet_home_result, &machine_config_directories_result) {
        (Ok(dotnet_home), Ok(machine_config_directories)) => nuget_user_package_folders(
            platform,
            &home,
            dotnet_home.as_deref(),
            env::var_os("APPDATA").as_deref(),
            env::var_os("XDG_CONFIG_HOME").as_deref(),
            machine_config_directories,
        ),
        (Err(error), _) | (_, Err(error)) => Err(*error),
    };
    let nuget_defaults_result = match &dotnet_home_result {
        Ok(dotnet_home) => nuget_defaults_config_paths(
            platform,
            &home,
            dotnet_home.as_deref(),
            env::var_os("XDG_DATA_HOME").as_deref(),
            env::var_os("ProgramFiles(x86)").as_deref(),
        ),
        Err(error) => Err(*error),
    };
    let nuget_defaults_warning = nuget_defaults_result.as_ref().err().copied();
    let nuget_defaults = nuget_defaults_result.unwrap_or_default();
    let nuget_solution_result = env::current_dir()
        .map_err(|_| "current directory is unavailable")
        .and_then(|cwd| nuget_solution_config_paths(platform, &cwd));
    let nuget_solution_warning = nuget_solution_result.as_ref().err().copied();
    let nuget_solution = nuget_solution_result.unwrap_or_default();
    let mut nuget_source_paths = nuget_config
        .as_ref()
        .map(|config| config.package_sources.clone())
        .unwrap_or_default();
    nuget_source_paths.extend(nuget_solution.package_sources.iter().cloned());
    nuget_source_paths.extend(nuget_defaults.package_sources.iter().cloned());
    let mut nuget_repository_paths = nuget_config
        .as_ref()
        .map(|config| config.repository_paths.clone())
        .unwrap_or_default();
    nuget_repository_paths.extend(nuget_solution.repository_paths.iter().cloned());
    let mut seen_repository_paths = HashSet::new();
    nuget_repository_paths.retain(|path| seen_repository_paths.insert(path.clone()));
    let nuget_fallbacks = nuget_fallback_packages_paths(nuget_fallback_env.as_deref());
    let nuget_msbuild_paths = nuget_msbuild_environment_paths();
    if let Ok(paths) = &nuget_msbuild_paths {
        nuget_source_paths.extend(paths.package_sources.iter().cloned());
    }
    let nuget_paths = nuget_config.and_then(|config| {
        let fallbacks = nuget_fallbacks?;
        let msbuild_paths = nuget_msbuild_paths?;
        let mut config_global_paths = config.global_packages.into_iter().collect::<Vec<_>>();
        config_global_paths.extend(config.additional_global_packages);
        if let Ok(Some(dotnet_home)) = &dotnet_home_result {
            config_global_paths.push(dotnet_home.join(".nuget/packages"));
        }
        config_global_paths.extend(nuget_solution.global_packages.iter().cloned());
        config_global_paths.extend(nuget_defaults.global_packages.iter().cloned());
        config_global_paths.extend(config.repository_paths);
        config_global_paths.extend(nuget_solution.repository_paths.iter().cloned());
        config_global_paths.extend(msbuild_paths.global_packages);
        let mut config_fallback_paths = config
            .fallback_package_folders
            .into_iter()
            .map(|(_, path)| path)
            .collect::<Vec<_>>();
        config_fallback_paths.extend(nuget_solution.fallback_package_folders.iter().cloned());
        config_fallback_paths.extend(nuget_defaults.fallback_package_folders.iter().cloned());
        config_fallback_paths.extend(msbuild_paths.fallback_package_folders);
        nuget_packages_paths(
            platform,
            &home,
            nuget_env.as_deref(),
            env::var_os("USERPROFILE").as_deref(),
            (config_global_paths, config_fallback_paths),
            fallbacks,
        )
    });
    let nuget_location_warning = nuget_paths.as_ref().err().copied();
    let mut fallback_nuget_global_paths =
        nuget_default_packages_path(platform, &home, env::var_os("USERPROFILE").as_deref())
            .and_then(|path| nuget_safe_absolute_path(path).ok())
            .into_iter()
            .collect::<Vec<_>>();
    if let Ok(Some(dotnet_home)) = &dotnet_home_result
        && let Ok(path) = nuget_safe_absolute_path(dotnet_home.join(".nuget/packages"))
        && !fallback_nuget_global_paths.contains(&path)
    {
        fallback_nuget_global_paths.push(path);
    }
    if let Some(value) = nuget_env.as_deref()
        && let Ok(path) = nuget_safe_absolute_path(PathBuf::from(value))
        && !fallback_nuget_global_paths.contains(&path)
    {
        fallback_nuget_global_paths.push(path);
    }
    let fallback_nuget_paths =
        if let Ok(fallbacks) = nuget_fallback_packages_paths(nuget_fallback_env.as_deref()) {
            fallbacks.into_iter().filter(|path| path != &home).collect()
        } else {
            Vec::new()
        };
    let (mut nuget_packages, nuget_fallback_packages) =
        nuget_paths.unwrap_or((fallback_nuget_global_paths, fallback_nuget_paths));
    nuget_packages.retain(|path| !nuget_repository_paths.contains(path));
    let xdg_cache = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute());
    let uv_cache_override = env::var_os("UV_CACHE_DIR");
    let maven_repository = maven_repository(&home);
    let maven_warning = maven_repository.as_ref().err().copied();
    let zig_global_cache = zig_global_cache(platform);
    let zig_cache_warning = zig_global_cache.as_ref().err().copied();
    let bun_cache = bun_install_cache_path(&home, env::var_os("BUN_INSTALL_CACHE_DIR").as_deref());
    let bun_cache_warning = bun_cache.as_ref().err().copied();
    let bun_command_cache = bun_cache_command_path(
        &home,
        env::var_os("BUN_INSTALL_CACHE_DIR").as_deref(),
        env::var_os("BUN_INSTALL").as_deref(),
    );
    let bun_command_cache_warning = bun_command_cache.as_ref().err().copied();
    let bun_cache = bun_cache.ok();
    let bun_command_cache = bun_command_cache.ok();
    let mut discovered = specs(
        platform,
        &home,
        &cache,
        &data,
        &go_env,
        (nuget_packages.clone(), nuget_fallback_packages.clone()),
        [maven_repository.ok(), zig_global_cache.ok()],
    );
    discovered.extend(bun_specs(bun_cache, bun_command_cache));
    discovered.extend(nuget_source_paths.into_iter().map(|path| Spec {
        name: "NuGet local package source",
        path,
        classification: "local package feed",
        consequence: "packages may be restored from this local source",
    }));
    discovered.extend(nuget_repository_paths.into_iter().map(|path| Spec {
        name: "NuGet packages.config repository",
        path,
        classification: "shared dependencies",
        consequence: "packages.config packages may need to be restored or downloaded again",
    }));
    if let Some(uv) = uv_spec(
        platform,
        &home,
        &cache,
        xdg_cache.as_deref(),
        uv_cache_override.as_deref(),
    ) {
        discovered.push(uv);
    }
    let mut report = inventory_specs(discovered, &home, cancel, platform);
    if uv_cache_override.is_some()
        && uv_cache_path(
            platform,
            &home,
            &cache,
            xdg_cache.as_deref(),
            uv_cache_override.as_deref(),
        )
        .is_none()
    {
        report
            .warnings
            .push("uv: UV_CACHE_DIR is not absolute; cache location skipped".into());
    }
    if (pnpm_configured_store_dir().is_some()
        || env::var_os("PNPM_HOME").is_some()
        || env::var_os("XDG_DATA_HOME").is_some())
        && pnpm_store_path(
            platform,
            &home,
            &data,
            pnpm_configured_store_dir().as_deref(),
            env::var_os("PNPM_HOME").as_deref(),
            env::var_os("XDG_DATA_HOME").as_deref(),
        )
        .is_none()
    {
        report
            .warnings
            .push("pnpm: configured store location is not absolute; cache location skipped".into());
    }
    if let Some(warning) = go_env.warning {
        report.warnings.push(warning.into());
    }
    if let Some(warning) = maven_warning {
        report
            .warnings
            .push(format!("Maven cache: {warning}; location skipped"));
    }
    if let Some(warning) = zig_cache_warning {
        report
            .warnings
            .push(format!("Zig global cache: {warning}; location skipped"));
    }
    if let Some(warning) = bun_cache_warning {
        report
            .warnings
            .push(format!("Bun install cache: {warning}; location skipped"));
    }
    if let Some(warning) = bun_command_cache_warning {
        report.warnings.push(format!(
            "Bun cache command target: {warning}; shared-cache removal is blocked"
        ));
    }
    report.warnings.push("NuGet inventory includes environment, user config, defaults, known MSBuild environment paths, and safe paths observed across NuGet.Config files in the current directory's ancestor chain. It keeps the union across those config levels, including local package feeds. Config files outside that chain and project-file restore properties are not inspected, including MSBuild restore settings; they may select other paths.".into());
    report.warnings.push("NuGet command-line `--source` and `-Source` values are not inspected and may select local package feeds outside this inventory.".into());
    if let Some(error) = nuget_solution_warning {
        report.warnings.push(format!(
            "NuGet solution configuration is unverified; its additional locations are skipped and shared-cache removal is blocked ({error})."
        ));
    }
    if let Some(error) = nuget_defaults_warning {
        report.warnings.push(format!(
            "NuGet defaults configuration is unverified; its local package sources are skipped and shared-cache removal is blocked ({error})."
        ));
    }
    if let Some(error) = nuget_location_warning {
        report.warnings.push(format!(
            "NuGet package locations or restore sources are ambiguous or unavailable; extra locations skipped ({error})."
        ));
    }
    if nuget_packages.is_empty() {
        report.warnings.push(
            "NuGet: the configured cache path is relative or the Windows USERPROFILE is unavailable or relative; the global package location is skipped and shared-cache removal is blocked.".into(),
        );
    }
    let default_build_cache = go_env.value("GOCACHE");
    if go_env.key_known("GOCACHE")
        && default_build_cache
            .as_deref()
            .is_none_or(|value| value.is_empty())
        && go_default_cache(&cache).is_none()
    {
        report.warnings.push(if cfg!(target_os = "windows") {
            "Go's default build cache is unavailable because LOCALAPPDATA is unset or relative."
        } else {
            "Go's default build cache is unavailable because XDG_CACHE_HOME is relative or HOME is unset."
        }.into());
    }
    let default_module_cache = go_env.value("GOMODCACHE");
    if go_env.key_known("GOMODCACHE")
        && default_module_cache
            .as_deref()
            .is_none_or(|value| value.is_empty())
        && go_path(go_env.value("GOPATH")).is_none()
    {
        report.warnings.push(
            "Go's default module cache cannot be inferred safely because the effective GOPATH is unavailable or may equal the active GOROOT."
                .into(),
        );
    }
    if !go_env.cache_paths_known(&cache) {
        report.warnings.push(
            "Go: cache configuration is incomplete; one or more locations are unknown or unresolved, and shared-cache removal is blocked."
                .into(),
        );
    }
    if go_env
        .value("GOCACHEPROG")
        .is_some_and(|value| !value.is_empty())
    {
        report.warnings.push("An external Go build-cache program is configured; its contents and behavior are not inspected or executed, and Linux shared-cache removal is blocked.".into());
    }
    report.warnings.push("Cache locations are inferred from environment variables, Go's persistent environment when accessible, Maven user settings when readable, and platform defaults. Bun user/workspace bunfig.toml and .npmrc, Maven global settings, command-line overrides, and other tool-specific configuration can select different locations.".into());
    report
}

fn inventory_specs(
    specs: Vec<Spec>,
    home: &Path,
    cancel: &AtomicBool,
    platform: Platform,
) -> CacheReport {
    let mut report = CacheReport {
        entries: vec![],
        warnings: vec![],
        cancelled: false,
    };
    let mut seen = HashSet::new();
    let canonical_home = home.canonicalize().ok();
    for spec in specs {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if !spec.path.is_absolute() || spec.path.parent().is_none() || spec.path == home {
            report
                .warnings
                .push(format!("{}: unsafe cache path skipped", spec.name));
            continue;
        }
        let metadata = match std::fs::symlink_metadata(&spec.path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                report.warnings.push(format!("{}: {err}", spec.name));
                continue;
            }
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            report.warnings.push(format!(
                "{}: cache path is not a non-symlink directory",
                spec.name
            ));
            continue;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                report
                    .warnings
                    .push(format!("{}: reparse-point cache path skipped", spec.name));
                continue;
            }
        }
        let canonical = match spec.path.canonicalize() {
            Ok(path) => path,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                report.warnings.push(format!("{}: {}", spec.name, err));
                continue;
            }
        };
        if canonical.parent().is_none() || canonical_home.as_ref() == Some(&canonical) {
            report
                .warnings
                .push(format!("{}: unsafe cache path skipped", spec.name));
            continue;
        }
        if !seen.insert(canonical) {
            continue;
        }
        #[cfg(target_os = "linux")]
        let directory_owner_status = {
            use std::os::unix::fs::MetadataExt;
            if platform != Platform::Linux {
                "unavailable"
            } else if metadata.uid() == rustix::process::geteuid().as_raw() {
                "current_user"
            } else {
                "other_user"
            }
        };
        #[cfg(not(target_os = "linux"))]
        let directory_owner_status = "unavailable";
        let mut entry = CacheEntry {
            name: spec.name,
            path: spec.path,
            ownership: "shared user cache",
            directory_owner_status,
            classification: spec.classification,
            consequence: spec.consequence,
            status: "inventory only",
            logical_bytes: None,
            allocated_bytes: None,
            size_complete: false,
            activity_status: "unavailable",
            warnings: vec![],
            go_test_cache: None,
        };
        if platform == Platform::Windows {
            entry.warnings.push(
                "Windows size is a read-only partial estimate; reparse points and other volumes are skipped, and path-based traversal cannot rule out concurrent directory replacement"
                    .into(),
            );
        }
        if platform == Platform::Macos {
            entry.warnings.push(
                "macOS traversal checks device IDs but does not enumerate mounts; same-device mounted subtrees may be included"
                    .into(),
            );
        }
        if entry.name == "Bun" {
            entry.warnings.push(
                "Bun hard-links cached packages into projects on Linux and Windows, so project links may continue using the same storage".into(),
            );
        }
        if entry.name == "NuGet global packages" {
            entry.warnings.push(
                "Safe NuGet.Config paths in the current directory's ancestor chain are included; project-file RestorePackagesPath and configs outside that chain may select other locations. Ambiguous or additional user and machine NuGet configs block shared-cache removal.".into(),
            );
        }
        if entry.name == "NuGet fallback packages" {
            entry.warnings.push(
                "NuGet may read fallback package folders during restore; ancestor NuGet.Config paths are included, while project-file restore properties and configs outside that chain may select other locations.".into(),
            );
        }
        if entry.name == "NuGet local package source" {
            entry.warnings.push(
                "Local NuGet package sources are inventoried to prevent direct shared-cache removal.".into(),
            );
        }
        #[cfg(target_os = "linux")]
        if entry.name == "Go build" {
            entry.go_test_cache = Some(go_test_cache(&entry.path));
        }
        match crate::sweep::measure_directory(&entry.path, cancel) {
            Ok((logical, allocated, complete, warnings)) => {
                entry.logical_bytes = Some(logical);
                entry.allocated_bytes = allocated;
                entry.size_complete = complete && platform == Platform::Linux;
                entry.warnings.extend(warnings);
            }
            Err(err) => {
                entry.status = "unavailable";
                entry.warnings.push(err.to_string());
            }
        }
        report.entries.push(entry);
    }
    let paths = report
        .entries
        .iter()
        .map(|entry| entry.path.canonicalize().ok())
        .collect::<Vec<_>>();
    let targets = paths
        .iter()
        .map(|path| path.clone().unwrap_or_default())
        .collect::<Vec<_>>();
    let activity = if platform == Platform::Linux {
        crate::activity::inspect(&targets, cancel)
    } else {
        vec!["unavailable"; targets.len()]
    };
    for ((entry, path), status) in report.entries.iter_mut().zip(paths).zip(activity) {
        entry.activity_status = if path.is_some() {
            status
        } else {
            "unavailable"
        };
    }
    if !report.entries.is_empty() {
        report.warnings.push(if platform == Platform::Linux {
            "Process activity is a bounded snapshot of same-user handles, executables, and working directories only; no observation does not prove a cache is idle."
        } else {
            "Process activity inspection is unavailable on this platform; cache activity is unknown."
        }.into());
    }
    report.cancelled = cancel.load(Ordering::Relaxed);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_nuget_machine_config_directories(
        directory: &Path,
        common_application_data: Option<&std::ffi::OsStr>,
    ) -> Vec<PathBuf> {
        let default = directory.join("machine-default/NuGet/Config");
        nuget_machine_config_directories(
            Platform::Linux,
            common_application_data,
            None,
            Some(&default),
        )
        .unwrap()
    }

    #[test]
    fn nuget_path_uses_environment_override_and_windows_userprofile_default() {
        use std::ffi::OsStr;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("dirs-home");
        let user_profile = dir.path().join("user-profile");
        let override_path = dir.path().join("nuget-override");
        let configured_path = dir.path().join("configured-packages");
        let windows_default = user_profile.join(".nuget/packages");
        assert_eq!(
            nuget_packages_paths(
                Platform::Windows,
                &home,
                None,
                Some(user_profile.as_os_str()),
                (Vec::new(), Vec::new()),
                Vec::new(),
            )
            .unwrap(),
            (vec![windows_default.clone()], Vec::new())
        );
        assert_eq!(
            nuget_packages_paths(
                Platform::Windows,
                &home,
                Some(override_path.as_os_str()),
                Some(user_profile.as_os_str()),
                (Vec::new(), Vec::new()),
                Vec::new(),
            )
            .unwrap(),
            (vec![override_path, windows_default], Vec::new())
        );
        assert!(
            nuget_packages_paths(
                Platform::Windows,
                &home,
                None,
                Some(OsStr::new("relative-profile")),
                (Vec::new(), Vec::new()),
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            nuget_packages_paths(
                Platform::Windows,
                &home,
                None,
                None,
                (Vec::new(), Vec::new()),
                Vec::new(),
            )
            .is_err()
        );
        assert_eq!(
            nuget_packages_paths(
                Platform::Linux,
                &home,
                None,
                None,
                (Vec::new(), Vec::new()),
                Vec::new(),
            )
            .unwrap(),
            (vec![home.join(".nuget/packages")], Vec::new())
        );
        assert_eq!(
            nuget_packages_paths(
                Platform::Linux,
                &home,
                None,
                None,
                (vec![configured_path.clone()], Vec::new()),
                Vec::new(),
            )
            .unwrap(),
            (
                vec![configured_path, home.join(".nuget/packages")],
                Vec::new()
            )
        );
        assert!(
            nuget_packages_paths(
                Platform::Linux,
                &home,
                Some(OsStr::new("relative-packages")),
                None,
                (Vec::new(), Vec::new()),
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            nuget_packages_paths(
                Platform::Linux,
                &home,
                Some(home.as_os_str()),
                None,
                (Vec::new(), Vec::new()),
                Vec::new()
            )
            .is_err()
        );
        assert!(
            nuget_packages_paths(
                Platform::Linux,
                &home,
                None,
                None,
                (vec![home.clone()], Vec::new()),
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            nuget_packages_paths(
                Platform::Linux,
                &home,
                None,
                None,
                (Vec::new(), Vec::new()),
                vec![home.clone()],
            )
            .is_err()
        );
    }

    #[test]
    fn nuget_fallback_environment_paths_are_split_and_validated() {
        use std::ffi::OsStr;

        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("fallback-one");
        let second = dir.path().join("fallback-two");
        let value = format!("{};{}", first.display(), second.display());
        assert_eq!(
            nuget_fallback_packages_paths(Some(OsStr::new(&value))).unwrap(),
            vec![first, second]
        );
        let home = dir.path().join("home");
        let global = dir.path().join("global");
        let user_config = dir.path().join("user-config-packages");
        let config_fallback = dir.path().join("config-fallback");
        let fallback_value = format!(
            "{};{};{}",
            dir.path().join("fallback-one").display(),
            dir.path().join("fallback-two").display(),
            dir.path().join("fallback-one").display()
        );
        assert_eq!(
            nuget_packages_paths(
                Platform::Linux,
                &home,
                Some(global.as_os_str()),
                None,
                (vec![user_config.clone()], vec![config_fallback.clone()],),
                nuget_fallback_packages_paths(Some(OsStr::new(&fallback_value))).unwrap(),
            )
            .unwrap(),
            (
                vec![global, user_config, home.join(".nuget/packages")],
                vec![
                    dir.path().join("fallback-one"),
                    dir.path().join("fallback-two"),
                    config_fallback.clone()
                ]
            )
        );
        assert_eq!(
            nuget_packages_paths(
                Platform::Linux,
                &home,
                None,
                None,
                (Vec::new(), vec![config_fallback.clone()]),
                Vec::new(),
            )
            .unwrap()
            .1,
            vec![config_fallback]
        );
        assert!(nuget_fallback_packages_paths(Some(OsStr::new("relative/path"))).is_err());
        assert!(nuget_fallback_packages_paths(Some(OsStr::new("/safe/path;"))).is_err());
        assert!(
            nuget_fallback_packages_paths(Some(OsStr::new("")))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn nuget_user_config_paths_resolve_or_fail_closed_for_ambiguous_settings() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let machine_common = dir.path().join("machine-common");
        let machine_config_directories =
            test_nuget_machine_config_directories(dir.path(), Some(machine_common.as_os_str()));
        let configured = dir.path().join("custom-packages");
        let dotnet_config = home.join(".nuget/NuGet/NuGet.Config");
        std::fs::create_dir_all(dotnet_config.parent().unwrap()).unwrap();
        std::fs::write(
            &dotnet_config,
            format!(
                "<configuration><config><add key=\"globalPackagesFolder\" value=\"{}\" /></config></configuration>",
                configured.display()
            ),
        )
        .unwrap();
        assert_eq!(
            nuget_user_package_folders(
                Platform::Linux,
                &home,
                None,
                None,
                None,
                &machine_config_directories,
            )
            .unwrap(),
            NugetConfigValue {
                global_packages: Some(configured.clone()),
                additional_global_packages: Vec::new(),
                clears_global_packages: false,
                fallback_package_folders: Vec::new(),
                package_sources: Vec::new(),
                repository_paths: Vec::new(),
            }
        );

        let home_xdg_config = home.join(".config/NuGet/NuGet.Config");
        let home_xdg_packages = dir.path().join("home-xdg-packages");
        std::fs::create_dir_all(home_xdg_config.parent().unwrap()).unwrap();
        std::fs::write(
            &home_xdg_config,
            format!(
                "<configuration><config><add key=\"globalPackagesFolder\" value=\"{}\"/></config></configuration>",
                home_xdg_packages.display()
            ),
        )
        .unwrap();
        let parsed = nuget_user_package_folders(
            Platform::Linux,
            &home,
            None,
            None,
            None,
            &machine_config_directories,
        )
        .unwrap();
        assert_eq!(parsed.global_packages, Some(configured.clone()));
        assert_eq!(
            parsed.additional_global_packages,
            vec![home_xdg_packages.clone()]
        );

        let xdg = dir.path().join("xdg-config");
        let xdg_config = xdg.join("NuGet/NuGet.Config");
        let xdg_packages = dir.path().join("xdg-packages");
        std::fs::create_dir_all(xdg_config.parent().unwrap()).unwrap();
        std::fs::write(
            &xdg_config,
            format!(
                "<configuration><config><add key=\"globalPackagesFolder\" value=\"{}\"/></config></configuration>",
                xdg_packages.display()
            ),
        )
        .unwrap();
        let parsed = nuget_user_package_folders(
            Platform::Linux,
            &home,
            None,
            None,
            Some(xdg.as_os_str()),
            &machine_config_directories,
        )
        .unwrap();
        assert_eq!(parsed.global_packages, Some(configured.clone()));
        assert_eq!(
            parsed.additional_global_packages,
            vec![home_xdg_packages.clone(), xdg_packages]
        );

        std::fs::remove_file(&xdg_config).unwrap();
        std::fs::remove_file(&home_xdg_config).unwrap();
        std::fs::write(
            &dotnet_config,
            "<configuration><config><clear /></config></configuration>",
        )
        .unwrap();
        assert!(
            nuget_user_package_folders(
                Platform::Linux,
                &home,
                None,
                None,
                None,
                &machine_config_directories,
            )
            .unwrap()
            .global_packages
            .is_none()
        );

        std::fs::remove_file(&dotnet_config).unwrap();
        let additional = home.join(".nuget/config/extra.config");
        std::fs::create_dir_all(additional.parent().unwrap()).unwrap();
        std::fs::write(
            additional,
            "<configuration><config><add key=\"globalPackagesFolder\" value=\"/tmp/fixture\" /></config></configuration>",
        )
        .unwrap();
        assert!(
            nuget_user_package_folders(
                Platform::Linux,
                &home,
                None,
                None,
                None,
                &machine_config_directories,
            )
            .is_err()
        );

        let appdata = dir.path().join("appdata");
        let locations = nuget_user_config_locations(
            Platform::Windows,
            &home,
            None,
            Some(appdata.as_os_str()),
            None,
        )
        .unwrap();
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].1, appdata.join("NuGet/NuGet.Config"));
    }

    #[test]
    fn nuget_dotnet_cli_home_is_absolute_and_conflicting_environment_values_fail_closed() {
        use std::ffi::{OsStr, OsString};

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let dotnet_home = dir.path().join("dotnet-home");
        assert!(nuget_dotnet_cli_home(None).unwrap().is_none());
        assert!(nuget_dotnet_cli_home(Some(OsStr::new(""))).is_err());
        assert!(nuget_dotnet_cli_home(Some(OsStr::new("relative-home"))).is_err());
        assert_eq!(
            nuget_dotnet_cli_home(Some(dotnet_home.as_os_str())).unwrap(),
            Some(dotnet_home.clone())
        );
        assert_eq!(
            nuget_home_roots(&home, Some(&home)).unwrap(),
            vec![home.clone()]
        );
        assert_eq!(
            nuget_home_roots(&home, Some(&dotnet_home)).unwrap(),
            vec![home, dotnet_home]
        );
        assert!(
            nuget_environment_property_from(
                [
                    (
                        OsString::from("DOTNET_CLI_HOME"),
                        OsString::from("/tmp/one")
                    ),
                    (
                        OsString::from("dotnet_cli_home"),
                        OsString::from("/tmp/two")
                    ),
                ],
                "DOTNET_CLI_HOME",
            )
            .is_err()
        );
    }

    #[test]
    fn nuget_dotnet_cli_home_config_paths_union_distinct_global_package_locations() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let dotnet_home = dir.path().join("dotnet-home");
        let machine_config_directories = test_nuget_machine_config_directories(dir.path(), None);
        let home_packages = dir.path().join("home-packages");
        let dotnet_packages = dir.path().join("dotnet-packages");
        let home_config = home.join(".nuget/NuGet/NuGet.Config");
        let dotnet_config = dotnet_home.join(".nuget/NuGet/NuGet.Config");
        std::fs::create_dir_all(home_config.parent().unwrap()).unwrap();
        std::fs::create_dir_all(dotnet_config.parent().unwrap()).unwrap();
        for (config, packages) in [
            (&home_config, &home_packages),
            (&dotnet_config, &dotnet_packages),
        ] {
            std::fs::write(
                config,
                format!(
                    "<configuration><config><add key=\"globalPackagesFolder\" value=\"{}\"/></config></configuration>",
                    packages.display()
                ),
            )
            .unwrap();
        }
        let parsed = nuget_user_package_folders(
            Platform::Linux,
            &home,
            Some(&dotnet_home),
            None,
            None,
            &machine_config_directories,
        )
        .unwrap();
        assert_eq!(parsed.global_packages, Some(home_packages));
        assert_eq!(parsed.additional_global_packages, vec![dotnet_packages]);
    }

    #[test]
    fn nuget_xdg_config_paths_keep_home_default_and_reject_relative_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let xdg = dir.path().join("xdg-config");
        let roots = nuget_xdg_config_roots(&home, Some(xdg.as_os_str())).unwrap();
        assert_eq!(roots, vec![home.join(".config"), xdg.clone()]);
        assert!(nuget_xdg_config_roots(&home, Some(std::ffi::OsStr::new("relative"))).is_err());
    }

    #[test]
    fn nuget_machine_config_directories_union_defaults_and_deduplicate_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let default_root = dir.path().join("default-machine");
        let default_config = default_root.join("NuGet/Config");
        let override_root = dir.path().join("override-machine");
        let directories = nuget_machine_config_directories(
            Platform::Linux,
            Some(override_root.as_os_str()),
            None,
            Some(&default_config),
        )
        .unwrap();
        assert_eq!(
            directories,
            vec![default_config.clone(), override_root.join("NuGet/Config")]
        );
        let same_root = nuget_machine_config_directories(
            Platform::Linux,
            Some(default_root.as_os_str()),
            None,
            Some(&default_config),
        )
        .unwrap();
        assert_eq!(same_root, vec![default_config.clone()]);
        assert!(
            nuget_machine_config_directories(
                Platform::Linux,
                Some(std::ffi::OsStr::new("relative-machine-root")),
                None,
                Some(&default_config),
            )
            .is_err()
        );

        std::fs::create_dir_all(&directories[1]).unwrap();
        std::fs::write(directories[1].join("vendor.config"), "<configuration />").unwrap();
        let home = dir.path().join("user-home");
        assert!(
            nuget_user_package_folders(Platform::Linux, &home, None, None, None, &directories,)
                .is_err()
        );
        std::fs::remove_file(directories[1].join("vendor.config")).unwrap();
        std::fs::create_dir_all(&default_config).unwrap();
        std::fs::write(default_config.join("NuGet.Config"), "<configuration />").unwrap();
        assert!(
            nuget_user_package_folders(Platform::Linux, &home, None, None, None, &directories,)
                .is_err()
        );
    }

    #[test]
    fn nuget_user_config_local_sources_are_unioned_without_retaining_remote_urls() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let xdg = dir.path().join("xdg");
        let machine_common = dir.path().join("machine-common");
        let machine_config_directories =
            test_nuget_machine_config_directories(dir.path(), Some(machine_common.as_os_str()));
        let user_source = dir.path().join("user-feed");
        let xdg_source = dir.path().join("xdg-feed");
        let push_source = dir.path().join("push-feed");
        let first = home.join(".nuget/NuGet/NuGet.Config");
        let second = xdg.join("NuGet/NuGet.Config");
        std::fs::create_dir_all(first.parent().unwrap()).unwrap();
        std::fs::create_dir_all(second.parent().unwrap()).unwrap();
        std::fs::write(
            &first,
            format!(
                "<configuration><config><add key=\"defaultPushSource\" value=\"{}\"/></config><packageSources><add key=\"local\" value=\"{}\"/><add key=\"remote\" value=\"https://synthetic-token@example.test/v3/index.json\"/></packageSources></configuration>",
                push_source.display(),
                user_source.display()
            ),
        )
        .unwrap();
        std::fs::write(
            &second,
            format!(
                "<configuration><packageSources><add key=\"other\" value=\"{}\"/></packageSources></configuration>",
                xdg_source.display()
            ),
        )
        .unwrap();
        let parsed = nuget_user_package_folders(
            Platform::Linux,
            &home,
            None,
            None,
            Some(xdg.as_os_str()),
            &machine_config_directories,
        )
        .unwrap();
        assert_eq!(
            parsed.package_sources,
            vec![push_source, user_source, xdg_source]
        );
        assert!(!format!("{parsed:?}").contains("synthetic-token"));
    }

    #[test]
    fn nuget_user_repository_path_collects_static_paths_and_rejects_dynamic_values() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let machine_common = dir.path().join("machine-common");
        let machine_config_directories =
            test_nuget_machine_config_directories(dir.path(), Some(machine_common.as_os_str()));
        let config = home.join(".nuget/NuGet/NuGet.Config");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(
            &config,
            "<configuration><config><add key=\"RepositoryPATH\" value=\"/tmp/packages\"/></config></configuration>",
        )
        .unwrap();
        let parsed = nuget_user_package_folders(
            Platform::Linux,
            &home,
            None,
            None,
            None,
            &machine_config_directories,
        )
        .unwrap();
        assert_eq!(
            parsed.repository_paths,
            vec![PathBuf::from("/tmp/packages")]
        );
        for value in [
            "relative/packages",
            "$HOME/packages",
            "%PACKAGES%/cache",
            " /tmp/packages",
            "/tmp/packages ",
        ] {
            std::fs::write(
                &config,
                format!(
                    "<configuration><config><add key=\"RepositoryPATH\" value=\"{value}\"/></config></configuration>"
                ),
            )
            .unwrap();
            assert!(
                nuget_user_package_folders(
                    Platform::Linux,
                    &home,
                    None,
                    None,
                    None,
                    &machine_config_directories,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn nuget_solution_config_paths_keep_the_union_across_ancestor_clears_and_removes() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("solution/member");
        std::fs::create_dir_all(&project).unwrap();
        let solution = dir.path().join("solution");
        let old_global = dir.path().join("old-global");
        let new_global = dir.path().join("new-global");
        let old_fallback = dir.path().join("old-fallback");
        let new_fallback = dir.path().join("new-fallback");
        let old_source = dir.path().join("old-source");
        let new_source = dir.path().join("new-source");
        let old_repository = dir.path().join("old-repository");
        let new_repository = dir.path().join("new-repository");
        std::fs::write(
            solution.join("NuGet.config"),
            format!(
                "<configuration><config><add key=\"globalPackagesFolder\" value=\"{}\"/><add key=\"repositoryPath\" value=\"{}\"/></config><fallbackPackageFolders><add key=\"one\" value=\"{}\"/></fallbackPackageFolders><packageSources><add key=\"old\" value=\"{}\"/></packageSources></configuration>",
                old_global.display(), old_repository.display(), old_fallback.display(), old_source.display()
            ),
        )
        .unwrap();
        std::fs::write(
            project.join("nuget.config"),
            format!(
                "<configuration><config><clear/><add key=\"globalPackagesFolder\" value=\"{}\"/><add key=\"repositoryPath\" value=\"{}\"/></config><fallbackPackageFolders><clear/><add key=\"two\" value=\"{}\"/></fallbackPackageFolders><packageSources><remove key=\"old\"/><add key=\"new\" value=\"{}\"/></packageSources></configuration>",
                new_global.display(), new_repository.display(), new_fallback.display(), new_source.display()
            ),
        )
        .unwrap();
        assert_eq!(
            nuget_solution_config_paths(Platform::Linux, &project).unwrap(),
            NugetSolutionConfigPaths {
                global_packages: vec![new_global, old_global],
                fallback_package_folders: vec![new_fallback, old_fallback],
                package_sources: vec![new_source, old_source],
                repository_paths: vec![new_repository, old_repository],
            }
        );
    }

    #[cfg(unix)]
    fn nuget_config_case_alias_fixture(directory: &Path, content: &[u8]) -> (PathBuf, PathBuf) {
        let first = directory.join("NuGet.Config");
        let alias = directory.join("NuGet.config");
        std::fs::write(&first, content).unwrap();
        match std::fs::hard_link(&first, &alias) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let first_identity =
                    SettingsFileIdentity::from_metadata(&std::fs::metadata(&first).unwrap());
                let alias_identity =
                    SettingsFileIdentity::from_metadata(&std::fs::metadata(&alias).unwrap());
                assert!(first_identity == alias_identity);
            }
            Err(error) => panic!("could not create config alias fixture: {error}"),
        }
        (first, alias)
    }

    #[cfg(unix)]
    #[test]
    fn nuget_solution_config_deduplicates_only_same_macos_case_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let content =
            b"<configuration><packageSources><add key=\"local\" value=\"/tmp/feed\"/></packageSources></configuration>";
        nuget_config_case_alias_fixture(&project, content);

        let macos = nuget_solution_config_paths(Platform::Macos, &project).unwrap();
        assert_eq!(macos.package_sources, vec![PathBuf::from("/tmp/feed")]);
        assert!(nuget_solution_config_paths(Platform::Linux, &project).is_err());

        let first = read_maven_settings(&project.join("NuGet.Config"))
            .unwrap()
            .unwrap();
        let alias = read_maven_settings(&project.join("NuGet.config"))
            .unwrap()
            .unwrap();
        assert!(same_nuget_config_case_alias(
            Platform::Macos,
            &first,
            &alias
        ));
        assert!(!same_nuget_config_case_alias(
            Platform::Linux,
            &first,
            &alias
        ));
        let mut changed_content = alias;
        changed_content.bytes.push(b' ');
        assert!(!same_nuget_config_case_alias(
            Platform::Macos,
            &first,
            &changed_content
        ));

        let distinct_dir = dir.path().join("distinct");
        std::fs::create_dir(&distinct_dir).unwrap();
        std::fs::write(distinct_dir.join("NuGet.Config"), content).unwrap();
        std::fs::write(distinct_dir.join("nuget.config"), content).unwrap();
        assert!(nuget_solution_config_paths(Platform::Macos, &distinct_dir).is_err());
    }

    #[test]
    fn nuget_solution_config_reader_rejects_links_duplicates_and_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let config = project.join("NuGet.Config");
        #[cfg(unix)]
        {
            let target = dir.path().join("outside.config");
            std::fs::write(&target, "<configuration />").unwrap();
            std::os::unix::fs::symlink(&target, &config).unwrap();
            assert!(nuget_solution_config_paths(Platform::Linux, &project).is_err());
            std::fs::remove_file(&config).unwrap();
        }
        std::fs::create_dir(project.join("NuGet.Config")).unwrap();
        assert!(nuget_solution_config_paths(Platform::Linux, &project).is_err());
        std::fs::remove_dir(project.join("NuGet.Config")).unwrap();
        std::fs::write(&config, vec![b' '; MAX_MAVEN_SETTINGS_BYTES as usize + 1]).unwrap();
        assert!(nuget_solution_config_paths(Platform::Linux, &project).is_err());
        std::fs::remove_file(&config).unwrap();
        std::fs::write(&config, "<configuration />").unwrap();
        std::fs::write(project.join("nuget.config"), "<configuration />").unwrap();
        assert!(nuget_solution_config_paths(Platform::Linux, &project).is_err());
    }

    #[test]
    fn nuget_defaults_config_uses_xdg_data_home_without_host_paths() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let data = dir.path().join("xdg-data");
        let dotnet_home = dir.path().join("dotnet-home");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&dotnet_home).unwrap();
        let local_source = dir.path().join("feed");
        let secret = "synthetic-user:synthetic-token";
        std::fs::write(
            data.join("NuGetDefaults.Config"),
            format!(
                "<configuration><config><add key=\"defaultPushSource\" value=\"https://{secret}@example.test/push\"/></config><packageSources><add key=\"local\" value=\"{}\" protocolVersion=\"3\" allowInsecureConnections=\"false\" disableTLSCertificateValidation=\"false\"/><add key=\"remote\" value=\"https://{secret}@example.test/v3/index.json\" protocolVersion=\"3\"/></packageSources><disabledPackageSources><add key=\"remote\" value=\"false\"/></disabledPackageSources></configuration>",
                local_source.display()
            ),
        )
        .unwrap();
        let default_data = home.join(".local/share");
        let dotnet_data = dotnet_home.join(".local/share");
        std::fs::create_dir_all(&default_data).unwrap();
        std::fs::create_dir_all(&dotnet_data).unwrap();
        let default_source = dir.path().join("default-feed");
        let dotnet_source = dir.path().join("dotnet-feed");
        std::fs::write(
            default_data.join("NuGetDefaults.Config"),
            format!(
                "<configuration><packageSources><add key=\"local\" value=\"{}\"/></packageSources></configuration>",
                default_source.display()
            ),
        )
        .unwrap();
        std::fs::write(
            dotnet_data.join("NuGetDefaults.Config"),
            format!(
                "<configuration><packageSources><add key=\"local\" value=\"{}\"/></packageSources></configuration>",
                dotnet_source.display()
            ),
        )
        .unwrap();
        let paths = nuget_defaults_config_paths(
            Platform::Macos,
            &home,
            Some(&dotnet_home),
            Some(data.as_os_str()),
            None,
        )
        .unwrap();
        assert_eq!(
            paths.package_sources,
            vec![
                local_source.clone(),
                default_source.clone(),
                dotnet_source.clone()
            ]
        );
        assert!(!format!("{paths:?}").contains(secret));

        let paths =
            nuget_defaults_config_paths(Platform::Macos, &home, Some(&dotnet_home), None, None)
                .unwrap();
        assert_eq!(paths.package_sources, vec![default_source, dotnet_source]);
        assert!(
            nuget_defaults_config_paths(
                Platform::Macos,
                &home,
                Some(&dotnet_home),
                Some(std::ffi::OsStr::new("relative-xdg-data")),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn nuget_config_parser_uses_clear_then_add_and_rejects_unsafe_locations() {
        let dir = tempfile::tempdir().unwrap();
        let configured = dir.path().join("packages&cache");
        let bytes = format!(
            "<configuration><config><add key=\"globalPackagesFolder\" value=\"/tmp/old\"/><clear/><add key=\"globalPackagesFolder\" value=\"{}\"/></config></configuration>",
            configured.display().to_string().replace('&', "&amp;")
        );
        let parsed = parse_nuget_config(bytes.as_bytes()).unwrap();
        assert_eq!(parsed.global_packages, Some(configured));
        assert!(parsed.clears_global_packages);
        for value in [
            "relative/packages",
            "../packages",
            "%UPKIT_MISSING_VAR%/packages",
            " /tmp/packages",
            "/tmp/packages ",
        ] {
            let config = format!(
                "<configuration><config><add key=\"globalPackagesFolder\" value=\"{value}\"/></config></configuration>"
            );
            assert!(parse_nuget_config(config.as_bytes()).is_err());
        }
        assert!(parse_nuget_config(b"<configuration><config></configuration>").is_err());
        assert!(
            parse_nuget_config(b"<!DOCTYPE configuration><configuration></configuration>").is_err()
        );
        let first = dir.path().join("fallback-first");
        let last = dir.path().join("fallback-last");
        let fallback_config = format!(
            "<configuration><fallbackPackageFolders><add key=\"first\" value=\"{}\"/><clear/><add key=\"last\" value=\"{}\"/></fallbackPackageFolders></configuration>",
            first.display(),
            last.display()
        );
        let parsed = parse_nuget_config(fallback_config.as_bytes()).unwrap();
        assert_eq!(parsed.fallback_package_folders, vec![("last".into(), last)]);
        let remove_config =
            b"<configuration><fallbackPackageFolders><remove key=\"first\"/></fallbackPackageFolders></configuration>";
        assert!(parse_nuget_config(remove_config).is_err());
        let unsafe_fallback = b"<configuration><fallbackPackageFolders><add key=\"fixture\" value=\"relative/path\"/></fallbackPackageFolders></configuration>";
        assert!(parse_nuget_config(unsafe_fallback).is_err());
        for value in [" /tmp/fallback", "/tmp/fallback "] {
            let config = format!(
                "<configuration><fallbackPackageFolders><add key=\"fixture\" value=\"{value}\"/></fallbackPackageFolders></configuration>"
            );
            assert!(parse_nuget_config(config.as_bytes()).is_err());
        }
        let unicode_key = "<configuration><config><add key=\"globalPackageſFolder\" value=\"/tmp/packages\"/></config></configuration>";
        assert!(parse_nuget_config(unicode_key.as_bytes()).is_err());
    }

    #[test]
    fn nuget_solution_config_allows_remote_sources_and_rejects_unsafe_or_unsupported_values() {
        let secret = "synthetic-user:synthetic-token";
        let remote = format!(
            "<configuration><packageSources><add key=\"private\" value=\"https://{secret}@example.test/v3/index.json\" protocolVersion=\"3\" allowInsecureConnections=\"false\" disableTLSCertificateValidation=\"false\"/></packageSources></configuration>"
        );
        assert_eq!(
            parse_nuget_solution_config(remote.as_bytes()).unwrap(),
            NugetSolutionConfigPaths::default()
        );

        for source in [
            "relative/feed",
            "$HOME/feed",
            "%FEED%/feed",
            "file:///tmp/feed",
            " /tmp/feed",
            "/tmp/feed ",
        ] {
            let config = format!(
                "<configuration><packageSources><add key=\"local\" value=\"{source}\"/></packageSources></configuration>"
            );
            assert!(
                parse_nuget_solution_config(config.as_bytes()).is_err(),
                "{source}"
            );
        }
        for section in ["config", "fallbackPackageFolders"] {
            let entry = if section == "config" {
                "<add key=\"globalPackagesFolder\" value=\"{}\"/>".to_owned()
            } else {
                "<add key=\"fallback\" value=\"{}\"/>".to_owned()
            };
            for path in ["relative/packages", "$HOME/packages", "%PACKAGES%/cache"] {
                let config = format!(
                    "<configuration><{section}>{}</{section}></configuration>",
                    entry.replace("{}", path)
                );
                assert!(parse_nuget_solution_config(config.as_bytes()).is_err());
            }
        }
        assert!(parse_nuget_solution_config(
            b"<configuration><packageSources><add key=\"same\" value=\"/tmp/one\"/><add key=\"same\" value=\"/tmp/two\"/></packageSources></configuration>"
        )
        .is_err());
        assert_eq!(
            parse_nuget_solution_config(
                b"<configuration><config><add key=\"repositoryPath\" value=\"/tmp/packages\"/></config></configuration>"
            )
            .unwrap()
            .repository_paths,
            vec![PathBuf::from("/tmp/packages")]
        );
        assert!(parse_nuget_solution_config(
            b"<configuration><packageSourceCredentials><foo><add key=\"Password\" value=\"secret\"/></foo></packageSourceCredentials></configuration>"
        )
        .is_err());
        let parsed = parse_nuget_solution_config(remote.as_bytes()).unwrap();
        assert!(!format!("{parsed:?}").contains(secret));
    }

    #[test]
    fn nuget_msbuild_source_lists_keep_local_paths_and_discard_remote_urls() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("local-feed");
        let remote = "https://synthetic-user:synthetic-token@example.test/v3/index.json";
        let values = format!("{};{remote}", local.display());
        assert_eq!(nuget_package_source_paths(&values).unwrap(), vec![local]);
        assert!(nuget_package_source_paths("relative/feed").is_err());
        assert!(nuget_package_source_paths("file:///tmp/feed").is_err());
        assert!(nuget_package_source_paths(" /tmp/feed").is_err());
    }

    #[test]
    fn bun_cache_paths_keep_install_and_clear_targets_distinct() {
        use std::ffi::OsStr;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let default = home.join(".bun/install/cache");
        let bun_install = home.join("custom-bun");
        let override_path = home.join("bun-cache");

        assert_eq!(bun_install_cache_path(&home, None).unwrap(), default);
        assert_eq!(
            bun_cache_command_path(&home, None, Some(OsStr::new("~/custom-bun"))).unwrap(),
            bun_install.join("install/cache")
        );
        assert_eq!(
            bun_install_cache_path(&home, Some(OsStr::new("~/bun-cache"))).unwrap(),
            override_path
        );
        assert_eq!(
            bun_cache_command_path(
                &home,
                Some(OsStr::new("~/bun-cache")),
                Some(OsStr::new("~/custom-bun"))
            )
            .unwrap(),
            override_path
        );
        for platform in [Platform::Linux, Platform::Macos, Platform::Windows] {
            let command_cache = bun_install.join("install/cache");
            let mut entries = specs(
                platform,
                &home,
                &home.join("cache"),
                &home.join("data"),
                &GoEnvironment::default(),
                (Vec::new(), Vec::new()),
                [None, None],
            );
            entries.extend(bun_specs(
                Some(default.clone()),
                Some(command_cache.clone()),
            ));
            assert_eq!(
                entries
                    .iter()
                    .find(|entry| entry.name == "Bun")
                    .unwrap()
                    .path,
                default
            );
            assert_eq!(
                entries
                    .iter()
                    .find(|entry| entry.name == "Bun cache command target")
                    .unwrap()
                    .path,
                command_cache
            );
        }
    }

    #[test]
    fn unresolved_bun_cache_overrides_fail_closed() {
        use std::ffi::OsStr;

        let dir = tempfile::tempdir().unwrap();
        assert!(bun_install_cache_path(dir.path(), Some(OsStr::new("relative/cache"))).is_err());
        assert!(
            bun_cache_command_path(dir.path(), None, Some(OsStr::new("relative/bun"))).is_err()
        );
        assert!(bun_install_cache_path(dir.path(), Some(OsStr::new(""))).is_err());
    }

    #[test]
    fn go_value_merge_preserves_presence_while_ignoring_empty_process_values() {
        use std::ffi::{OsStr, OsString};

        let value = |process, user, system| merge_go_value(process, user, system);
        assert_eq!(
            value(
                Some(OsStr::new("process")),
                Some(OsStr::new("user")),
                Some(OsStr::new("system"))
            ),
            Some(OsString::from("process"))
        );
        assert_eq!(
            value(
                Some(OsStr::new("")),
                Some(OsStr::new("user")),
                Some(OsStr::new("system"))
            ),
            Some(OsString::from("user"))
        );
        assert_eq!(
            value(None, Some(OsStr::new("")), Some(OsStr::new("system"))),
            Some(OsString::new())
        );
        assert_eq!(
            value(None, None, Some(OsStr::new("system"))),
            Some(OsString::from("system"))
        );
        assert_eq!(value(Some(OsStr::new("")), None, None), None);
    }

    #[test]
    fn default_gopath_is_unknown_without_the_active_goroot() {
        use std::ffi::OsString;

        assert_eq!(go_path(Some(OsString::new())), None);
        assert_eq!(go_path(None), None);

        let dir = tempfile::tempdir().unwrap();
        let explicit = dir.path().join("gopath");
        assert_eq!(
            go_path(Some(explicit.as_os_str().to_os_string())),
            Some(explicit)
        );
    }

    #[test]
    fn windows_go_environment_path_uses_override_or_appdata_and_honors_off() {
        let dir = tempfile::tempdir().unwrap();
        let app_data = dir.path().join("appdata");
        let override_path = dir.path().join("go-env-override");
        assert_eq!(
            windows_go_environment_path(None, Some(app_data.as_os_str())).unwrap(),
            Some(app_data.join("go/env"))
        );
        assert_eq!(
            windows_go_environment_path(Some(override_path.as_os_str()), None).unwrap(),
            Some(override_path)
        );
        assert_eq!(
            windows_go_environment_path(Some(std::ffi::OsStr::new("off")), None).unwrap(),
            None
        );
        assert!(
            windows_go_environment_path(
                Some(std::ffi::OsStr::new("relative/env")),
                Some(app_data.as_os_str())
            )
            .is_err()
        );
        assert!(
            windows_go_environment_path(None, Some(std::ffi::OsStr::new("relative-appdata")))
                .is_err()
        );
        assert!(windows_go_environment_path(None, None).is_err());
    }

    #[test]
    fn windows_go_environment_parser_accepts_only_valid_utf8_cache_values() {
        let parsed = parse_go_environment_windows(
            b"GOCACHE=C:\\cache\nGOMODCACHE=C:\\modules\nGOCACHEPROG=C:\\private\\go.exe\n",
        )
        .unwrap();
        assert_eq!(
            parsed.values.get("GOCACHE").map(|value| value.as_os_str()),
            Some(std::ffi::OsStr::new("C:\\cache"))
        );
        assert_eq!(
            parsed
                .values
                .get("GOMODCACHE")
                .map(|value| value.as_os_str()),
            Some(std::ffi::OsStr::new("C:\\modules"))
        );
        assert_eq!(
            parsed
                .values
                .get("GOCACHEPROG")
                .map(|value| value.as_os_str()),
            Some(std::ffi::OsStr::new("C:\\private\\go.exe"))
        );
        assert!(parse_go_environment_windows(b"GOCACHE=bad\xff\n").is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn go_environment_parser_preserves_go_newline_value_bytes() {
        let parsed = parse_go_environment(b"GOCACHE=/first\nGOCACHE=/cache\r\n");
        assert_eq!(
            parsed.values.get("GOCACHE").map(|value| value.as_os_str()),
            Some(std::ffi::OsStr::new("/cache\r"))
        );
    }

    #[cfg(all(test, unix))]
    #[test]
    fn macos_go_environment_reader_bounds_reads_and_rejects_links_and_hardlinks() {
        use std::{fs, os::unix::fs::symlink};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let env_dir = root.join("config/go");
        fs::create_dir_all(&env_dir).unwrap();
        let env_file = env_dir.join("env");
        fs::write(&env_file, b"GOCACHE=/fixture\n").unwrap();
        assert_eq!(
            read_go_environment_file(&env_file).unwrap().as_deref(),
            Some(b"GOCACHE=/fixture\n".as_slice())
        );
        assert_eq!(fs::read(&env_file).unwrap(), b"GOCACHE=/fixture\n");

        let linked_file = root.join("linked-env");
        symlink(&env_file, &linked_file).unwrap();
        assert!(read_go_environment_file(&linked_file).is_err());
        let linked_dir = root.join("linked-config");
        symlink(&env_dir, &linked_dir).unwrap();
        assert!(read_go_environment_file(&linked_dir.join("env")).is_err());

        let second_link = root.join("second-env-link");
        fs::hard_link(&env_file, &second_link).unwrap();
        assert!(read_go_environment_file(&env_file).is_err());
        fs::remove_file(second_link).unwrap();

        let oversized = root.join("oversized-env");
        fs::write(&oversized, vec![b'x'; 256 * 1024 + 1]).unwrap();
        assert!(read_go_environment_file(&oversized).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_go_environment_reader_bounds_reads_and_rejects_reparse_points() {
        use std::{
            fs,
            os::windows::fs::{OpenOptionsExt, symlink_dir, symlink_file},
        };

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let env_dir = root.join("appdata/go");
        fs::create_dir_all(&env_dir).unwrap();
        let env_file = env_dir.join("env");
        fs::write(&env_file, b"GOCACHE=C:\\fixture\n").unwrap();
        assert_eq!(
            read_go_environment_file_windows(&env_file)
                .unwrap()
                .as_deref(),
            Some(b"GOCACHE=C:\\fixture\n".as_slice())
        );
        assert_eq!(fs::read(&env_file).unwrap(), b"GOCACHE=C:\\fixture\n");

        assert_eq!(
            read_go_environment_file_windows(&root.join("missing-env")).unwrap(),
            None
        );
        let mut exclusive = fs::OpenOptions::new();
        exclusive.read(true).share_mode(0);
        let exclusive_handle = exclusive.open(&env_file).unwrap();
        assert!(read_go_environment_file_windows(&env_file).is_err());
        drop(exclusive_handle);

        let hard_link = root.join("hard-linked-env");
        fs::hard_link(&env_file, &hard_link).unwrap();
        assert!(read_go_environment_file_windows(&env_file).is_err());
        fs::remove_file(&hard_link).unwrap();

        let linked_file = root.join("linked-env");
        match symlink_file(&env_file, &linked_file) {
            Ok(()) => assert!(read_go_environment_file_windows(&linked_file).is_err()),
            Err(error) if error.raw_os_error() == Some(1314) => {
                eprintln!("Windows symlink privilege unavailable; Go env file-link check skipped");
            }
            Err(error) => panic!("unable to create temporary Go env file reparse point: {error}"),
        }

        let linked_dir = root.join("linked-config");
        match symlink_dir(&env_dir, &linked_dir) {
            Ok(()) => assert!(read_go_environment_file_windows(&linked_dir.join("env")).is_err()),
            Err(error) if error.raw_os_error() == Some(1314) => {
                eprintln!(
                    "Windows symlink privilege unavailable; Go env directory-link check skipped"
                );
            }
            Err(error) => {
                panic!("unable to create temporary Go env directory reparse point: {error}")
            }
        }

        let oversized = root.join("oversized-env");
        fs::write(&oversized, vec![b'x'; 256 * 1024 + 1]).unwrap();
        assert!(read_go_environment_file_windows(&oversized).is_err());
    }

    #[test]
    fn maven_settings_parser_rejects_ambiguous_or_malformed_inputs() {
        for settings in [
            "<wrongRoot><localRepository>/tmp/cache</localRepository></wrongRoot>",
            "<settings><localRepository>/tmp/one</localRepository><localRepository>/tmp/two</localRepository></settings>",
            "<settings><localRepository>/tmp/cache</localRepository><profile></settings>",
            "<!DOCTYPE settings [<!ENTITY repo SYSTEM 'file:///secret'>]><settings><localRepository>&repo;</localRepository></settings>",
        ] {
            let error = parse_maven_settings(settings.as_bytes()).unwrap_err();
            assert!(!error.contains("secret"));
        }
    }

    #[test]
    fn zig_global_cache_resolution_matches_platform_defaults_and_rejects_relative_overrides() {
        use std::ffi::OsStr;

        fn path(name: &Path) -> &OsStr {
            name.as_os_str()
        }

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let xdg_cache = dir.path().join("xdg-cache");
        let xdg_data = dir.path().join("xdg-data");
        let local_app_data = dir.path().join("local-app-data");
        let custom = dir.path().join("custom-zig-cache");
        assert_eq!(
            zig_global_cache_path(
                Platform::Linux,
                None,
                Some(path(&xdg_cache)),
                Some(path(&home)),
                Some(path(&xdg_data)),
                None,
            )
            .unwrap(),
            xdg_cache.join("zig")
        );
        assert_eq!(
            zig_global_cache_path(
                Platform::Linux,
                None,
                None,
                Some(path(&home)),
                Some(path(&xdg_data)),
                None,
            )
            .unwrap(),
            home.join(".cache/zig")
        );
        assert_eq!(
            zig_global_cache_path(
                Platform::Linux,
                None,
                None,
                None,
                Some(path(&xdg_data)),
                None,
            )
            .unwrap(),
            xdg_data.join("zig")
        );
        assert_eq!(
            zig_global_cache_path(Platform::Macos, None, None, Some(path(&home)), None, None,)
                .unwrap(),
            home.join(".cache/zig")
        );
        assert_eq!(
            zig_global_cache_path(
                Platform::Windows,
                None,
                Some(path(&xdg_cache)),
                Some(path(&home)),
                Some(path(&xdg_data)),
                Some(path(&local_app_data)),
            )
            .unwrap(),
            local_app_data.join("zig")
        );
        assert_eq!(
            zig_global_cache_path(
                Platform::Linux,
                Some(path(&custom)),
                Some(path(&xdg_cache)),
                Some(path(&home)),
                None,
                None,
            )
            .unwrap(),
            custom
        );
        assert!(
            zig_global_cache_path(
                Platform::Linux,
                Some(OsStr::new("relative/zig")),
                None,
                Some(path(&home)),
                None,
                None,
            )
            .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn maven_user_home_rejects_windows_reparse_points() {
        use std::os::windows::fs::symlink_dir;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let target = dir.path().join("m2-target");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&target).unwrap();
        if let Err(error) = symlink_dir(&target, home.join(".m2")) {
            if error.raw_os_error() == Some(1314) {
                return;
            }
            panic!("unable to create temporary reparse point: {error}");
        }
        assert!(maven_repository(&home).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn cache_json_preserves_unpaired_windows_path_units() {
        use std::os::windows::ffi::OsStringExt;
        let path = PathBuf::from(std::ffi::OsString::from_wide(&[
            0x0043, 0x003a, 0x005c, 0xd800,
        ]));
        let entry = CacheEntry {
            name: "fixture",
            path: path.clone(),
            ownership: "fixture",
            directory_owner_status: "unavailable",
            classification: "fixture",
            consequence: "fixture",
            status: "fixture",
            logical_bytes: None,
            allocated_bytes: None,
            size_complete: false,
            activity_status: "unavailable",
            warnings: vec![],
            go_test_cache: None,
        };
        let value = serde_json::to_value(entry).unwrap();
        assert_eq!(value["path"]["encoding"], "windows-percent-utf16");
        assert!(value["path"]["value"].as_str().unwrap().ends_with("%uD800"));
        let plan = GoTestExpirationPlan {
            cache_path: path.clone(),
            marker_path: path.join("testexpire.txt"),
            current_expiration_unix_nanos: None,
            preview_token: "fixture".into(),
            warning: "fixture",
        };
        let value = serde_json::to_value(plan).unwrap();
        assert_eq!(value["cache_path"]["encoding"], "windows-percent-utf16");
        assert_eq!(value["marker_path"]["encoding"], "windows-percent-utf16");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn go_user_dirs_follow_go_home_and_xdg_rules() {
        use std::ffi::OsStr;
        assert_eq!(go_user_dir(None, None, ".cache"), None);
        assert_eq!(go_user_dir(Some(OsStr::new("")), None, ".cache"), None);
        assert_eq!(
            go_user_dir(Some(OsStr::new("/home/test-user")), None, ".cache"),
            Some(PathBuf::from("/home/test-user/.cache"))
        );
        assert_eq!(
            go_user_dir(
                Some(OsStr::new("/home/test-user")),
                Some(OsStr::new("relative")),
                ".cache"
            ),
            None
        );
        assert_eq!(
            go_user_dir(None, Some(OsStr::new("/custom")), ".cache"),
            Some(PathBuf::from("/custom"))
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn go_test_marker_is_bounded_and_does_not_follow_links_or_sockets() {
        use std::os::unix::{fs::symlink, net::UnixListener};
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("testexpire.txt");
        assert_eq!(go_test_cache(dir.path()).status, "no_expiration_marker");
        std::fs::write(&marker, "123456789\n").unwrap();
        let observed = go_test_cache(dir.path());
        assert_eq!(observed.status, "expiration_marker");
        assert_eq!(observed.expired_before_unix_nanos, Some(123456789));
        let locked = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&marker)
            .unwrap();
        rustix::fs::flock(
            &locked,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .unwrap();
        assert_eq!(go_test_cache(dir.path()).status, "unavailable");
        drop(locked);
        assert_eq!(
            go_test_cache(dir.path()).expired_before_unix_nanos,
            Some(123456789)
        );
        std::fs::write(&marker, "x".repeat(65)).unwrap();
        assert_eq!(go_test_cache(dir.path()).status, "unavailable");
        std::fs::remove_file(&marker).unwrap();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, "987654321").unwrap();
        symlink(&outside, &marker).unwrap();
        assert_eq!(go_test_cache(dir.path()).status, "unavailable");
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "987654321");
        std::fs::remove_file(&marker).unwrap();
        let _socket = UnixListener::bind(&marker).unwrap();
        assert_eq!(go_test_cache(dir.path()).status, "unavailable");
    }
    #[test]
    fn inventory_sizes_fixture_without_following_links() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let cache = home.join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("data"), b"abc").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.path(), cache.join("link")).unwrap();
        }
        let spec = Spec {
            name: "fixture",
            path: cache.clone(),
            classification: "shared",
            consequence: "redownload",
        };
        let report = inventory_specs(vec![spec], &home, &AtomicBool::new(false), Platform::Linux);
        assert_eq!(report.entries[0].logical_bytes, Some(3));
        assert!(cache.join("data").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn macos_cache_size_estimate_does_not_follow_nested_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let cache = home.join("cache");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(cache.join("data"), b"abc").unwrap();
        std::fs::write(outside.join("secret"), b"must not be counted").unwrap();
        symlink(&outside, cache.join("link")).unwrap();

        let report = inventory_specs(
            vec![Spec {
                name: "fixture",
                path: cache.clone(),
                classification: "shared",
                consequence: "redownload",
            }],
            &home,
            &AtomicBool::new(false),
            Platform::Macos,
        );
        let entry = &report.entries[0];
        assert_eq!(entry.logical_bytes, Some(3));
        assert!(!entry.size_complete);
        assert!(entry.warnings[0].contains("does not enumerate mounts"));
        assert_eq!(
            std::fs::read(outside.join("secret")).unwrap(),
            b"must not be counted"
        );
    }

    #[test]
    fn unsafe_home_and_cancelled_inventory_do_not_scan() {
        let dir = tempfile::tempdir().unwrap();
        let spec = || Spec {
            name: "fixture",
            path: dir.path().to_owned(),
            classification: "shared",
            consequence: "redownload",
        };
        let report = inventory_specs(
            vec![spec()],
            dir.path(),
            &AtomicBool::new(false),
            Platform::Linux,
        );
        assert!(report.entries.is_empty());
        let report = inventory_specs(
            vec![spec()],
            dir.path(),
            &AtomicBool::new(true),
            Platform::Linux,
        );
        assert!(report.cancelled);
    }

    #[test]
    fn platform_defaults_distinguish_windows_locations() {
        let home = Path::new("home");
        let local = Path::new("local");
        let cache = Path::new("cache");
        assert_eq!(
            npm_default(Platform::Windows, home, local),
            local.join("npm-cache")
        );
        assert_eq!(npm_default(Platform::Macos, home, local), home.join(".npm"));
        assert_eq!(
            pip_default(Platform::Windows, cache, local),
            local.join("pip/Cache")
        );
        assert_eq!(
            pip_default(Platform::Macos, cache, local),
            cache.join("pip")
        );
        assert_eq!(
            pub_default(Platform::Windows, home, local),
            local.join("Pub/Cache")
        );
        assert_eq!(
            pub_default(Platform::Macos, home, local),
            home.join(".pub-cache")
        );
    }

    #[test]
    fn pnpm_store_path_uses_platform_defaults_and_explicit_overrides() {
        use std::ffi::OsStr;

        let dir = tempfile::tempdir().unwrap();
        let home = Path::new("home");
        let data = Path::new("data");
        let xdg_data = dir.path().join("xdg-data");
        let pnpm_home = dir.path().join("pnpm-home");
        let store_dir = dir.path().join("store");
        assert_eq!(
            pnpm_store_path(Platform::Linux, home, data, None, None, None),
            Some(data.join("pnpm/store"))
        );
        assert_eq!(
            pnpm_store_path(Platform::Macos, home, data, None, None, None),
            Some(home.join("Library/pnpm/store"))
        );
        assert_eq!(
            pnpm_store_path(Platform::Windows, home, data, None, None, None),
            Some(data.join("pnpm/store"))
        );
        assert_eq!(
            pnpm_store_path(
                Platform::Macos,
                home,
                data,
                None,
                None,
                Some(xdg_data.as_os_str())
            ),
            Some(xdg_data.join("pnpm/store"))
        );
        assert_eq!(
            pnpm_store_path(
                Platform::Linux,
                home,
                data,
                None,
                Some(pnpm_home.as_os_str()),
                Some(OsStr::new("/ignored/data"))
            ),
            Some(pnpm_home.join("store"))
        );
        assert_eq!(
            pnpm_store_path(
                Platform::Linux,
                home,
                data,
                Some(store_dir.as_os_str()),
                Some(OsStr::new("/ignored/pnpm")),
                None
            ),
            Some(store_dir)
        );
        assert_eq!(
            pnpm_store_path(
                Platform::Linux,
                home,
                data,
                Some(OsStr::new("relative/store")),
                None,
                None
            ),
            None
        );
        assert_eq!(
            pnpm_store_path(
                Platform::Linux,
                home,
                data,
                None,
                Some(OsStr::new("relative/pnpm")),
                Some(OsStr::new("/ignored/data"))
            ),
            None
        );
        assert_eq!(
            pnpm_store_path(
                Platform::Linux,
                home,
                data,
                None,
                None,
                Some(OsStr::new("relative/data"))
            ),
            None
        );
    }

    #[test]
    fn uv_uses_standard_cache_locations_and_is_not_a_removal_candidate() {
        use std::ffi::OsStr;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let cache = home.join(".cache");
        let local = home.join("AppData/Local");
        let xdg = dir.path().join("xdg-cache");
        assert_eq!(
            uv_cache_path(Platform::Linux, &home, &cache, Some(&xdg), None),
            Some(xdg.join("uv"))
        );
        assert_eq!(
            uv_cache_path(Platform::Linux, &home, &cache, None, None),
            Some(cache.join("uv"))
        );
        assert_eq!(
            uv_cache_path(
                Platform::Macos,
                &home,
                &home.join("Library/Caches"),
                None,
                None
            ),
            Some(home.join(".cache/uv"))
        );
        assert_eq!(
            uv_cache_path(Platform::Macos, &home, &cache, Some(&xdg), None),
            Some(xdg.join("uv"))
        );
        assert_eq!(
            uv_cache_path(Platform::Windows, &home, &local, None, None),
            Some(local.join("uv/cache"))
        );
        let override_dir = dir.path().join("custom-uv-cache");
        assert_eq!(
            uv_cache_path(
                Platform::Linux,
                &home,
                &cache,
                Some(&xdg),
                Some(override_dir.as_os_str())
            ),
            Some(override_dir)
        );
        assert_eq!(
            uv_cache_path(
                Platform::Linux,
                &home,
                &cache,
                Some(&xdg),
                Some(OsStr::new("relative-cache"))
            ),
            None
        );

        let cleanup_candidates = specs(
            Platform::Linux,
            &home,
            &cache,
            &home.join(".local/share"),
            &GoEnvironment::default(),
            (Vec::new(), Vec::new()),
            [
                Some(home.join(".m2/repository")),
                Some(home.join(".cache/zig")),
            ],
        );
        assert!(!cleanup_candidates.iter().any(|spec| spec.name == "uv"));
    }

    #[test]
    fn yarn_and_compiler_cache_defaults_cover_macos_and_windows() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let cache = dir.path().join("cache");
        let local = dir.path().join("local");
        std::fs::create_dir_all(&home).unwrap();
        assert_eq!(
            yarn_default(Platform::Macos, &home, &cache, &local, None),
            home.join("Library/Caches/Yarn")
        );
        assert_eq!(
            yarn_default(Platform::Windows, &home, &cache, &local, None),
            local.join("Yarn/Cache")
        );
        assert_eq!(
            ccache_default(Platform::Macos, &home, &cache, &local, None),
            cache.join("ccache")
        );
        assert_eq!(
            ccache_default(Platform::Windows, &home, &cache, &local, None),
            local.join("ccache")
        );
        assert_eq!(
            sccache_default(Platform::Macos, &home, &cache, &local),
            home.join("Library/Caches/Mozilla.sccache")
        );
        assert_eq!(
            sccache_default(Platform::Windows, &home, &cache, &local),
            local.join("Mozilla/sccache")
        );

        let xdg = dir.path().join("xdg-cache");
        assert_eq!(
            yarn_default(Platform::Macos, &home, &cache, &local, Some(&xdg)),
            xdg.join("yarn")
        );
        assert_eq!(
            ccache_default(Platform::Macos, &home, &cache, &local, Some(&xdg)),
            xdg.join("ccache")
        );

        let legacy = home.join(".ccache");
        std::fs::write(&legacy, b"not a cache directory").unwrap();
        assert_eq!(
            ccache_default(Platform::Macos, &home, &cache, &local, None),
            cache.join("ccache")
        );
        assert_eq!(
            ccache_default(Platform::Windows, &home, &cache, &local, None),
            local.join("ccache")
        );
        std::fs::remove_file(&legacy).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let linked = dir.path().join("linked-ccache");
            std::fs::create_dir(&linked).unwrap();
            symlink(&linked, &legacy).unwrap();
            assert_eq!(
                ccache_default(Platform::Macos, &home, &cache, &local, None),
                legacy
            );
            assert_eq!(
                ccache_default(Platform::Windows, &home, &cache, &local, None),
                legacy
            );
            std::fs::remove_file(&legacy).unwrap();
        }
        std::fs::create_dir(&legacy).unwrap();
        assert_eq!(
            ccache_default(Platform::Macos, &home, &cache, &local, Some(&xdg)),
            legacy
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn macos_cache_candidates_report_partial_sizes() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let cache = home.join("cache");
        let local = home.join("local");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        let paths = [
            (
                "Yarn classic",
                yarn_default(Platform::Macos, &home, &cache, &local, None),
            ),
            (
                "ccache",
                ccache_default(Platform::Macos, &home, &cache, &local, None),
            ),
            (
                "sccache",
                sccache_default(Platform::Macos, &home, &cache, &local),
            ),
        ];
        for (name, path) in paths {
            std::fs::create_dir_all(&path).unwrap();
            let sentinel = path.join("fixture");
            std::fs::write(&sentinel, b"untouched").unwrap();
            let report = inventory_specs(
                vec![Spec {
                    name,
                    path,
                    classification: "shared build cache",
                    consequence: "may need rebuilding",
                }],
                &home,
                &AtomicBool::new(false),
                Platform::Macos,
            );
            let entry = &report.entries[0];
            assert_eq!(entry.status, "inventory only");
            assert_eq!(entry.logical_bytes, Some(b"untouched".len() as u64));
            assert!(!entry.size_complete);
            assert_eq!(entry.activity_status, "unavailable");
            assert!(entry.warnings[0].contains("does not enumerate mounts"));
            assert!(
                report.warnings.iter().any(|warning| {
                    warning.contains("Process activity inspection is unavailable")
                })
            );
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"untouched");
        }
    }

    #[cfg(unix)]
    #[test]
    fn macos_and_windows_inventory_skips_symlink_cache_roots() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let sentinel = outside.join("fixture");
        std::fs::write(&sentinel, b"untouched").unwrap();
        let link = home.join("linked-cache");
        std::fs::create_dir(&home).unwrap();
        symlink(&outside, &link).unwrap();
        for platform in [Platform::Macos, Platform::Windows] {
            let report = inventory_specs(
                vec![Spec {
                    name: "linked cache",
                    path: link.clone(),
                    classification: "shared",
                    consequence: "redownload",
                }],
                &home,
                &AtomicBool::new(false),
                platform,
            );
            assert!(report.entries.is_empty());
            assert!(
                report
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("symlink"))
            );
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"untouched");
        }
    }

    #[test]
    fn windows_inventory_reports_read_only_partial_size_estimates() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let cache = home.join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("data"), b"fixture").unwrap();
        let spec = Spec {
            name: "fixture",
            path: cache.clone(),
            classification: "shared",
            consequence: "redownload",
        };
        let report = inventory_specs(
            vec![spec],
            &home,
            &AtomicBool::new(false),
            Platform::Windows,
        );
        assert_eq!(report.entries[0].status, "inventory only");
        assert_eq!(report.entries[0].directory_owner_status, "unavailable");
        assert_eq!(
            report.entries[0].logical_bytes,
            Some(b"fixture".len() as u64)
        );
        assert!(!report.entries[0].size_complete);
        assert!(report.entries[0].warnings[0].contains("partial estimate"));
        assert!(cache.join("data").exists());
    }
}
