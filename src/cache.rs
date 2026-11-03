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

fn cargo_build_paths_from(
    target_dir: Option<std::ffi::OsString>,
    build_target_dir: Option<std::ffi::OsString>,
    build_dir: Option<std::ffi::OsString>,
) -> (Vec<PathBuf>, bool) {
    let mut paths = Vec::new();
    let mut target_paths = Vec::new();
    let mut unresolved = false;
    for value in [target_dir, build_target_dir].into_iter().flatten() {
        let path = PathBuf::from(&value);
        if value.is_empty() || !path.is_absolute() {
            unresolved = true;
            continue;
        }
        if !target_paths.contains(&path) {
            target_paths.push(path.clone());
        }
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    if target_paths.len() > 1 {
        unresolved = true;
    }
    if let Some(value) = build_dir {
        let path = PathBuf::from(&value);
        let text = value.to_string_lossy();
        if value.is_empty() || !path.is_absolute() || text.contains('{') || text.contains('}') {
            unresolved = true;
        } else if !paths.contains(&path) {
            paths.push(path);
        }
    }
    (paths, unresolved)
}

fn cargo_build_paths() -> (Vec<PathBuf>, bool) {
    let (paths, unresolved) = cargo_build_paths_from(
        env::var_os("CARGO_TARGET_DIR"),
        env::var_os("CARGO_BUILD_TARGET_DIR"),
        env::var_os("CARGO_BUILD_BUILD_DIR"),
    );
    #[cfg(target_os = "linux")]
    {
        let mut unresolved = unresolved;
        let mut resolved = Vec::new();
        for path in paths {
            match resolve_cargo_output_path(&path) {
                Ok(path) if !resolved.contains(&path) => resolved.push(path),
                Ok(_) => {}
                Err(_) => unresolved = true,
            }
        }
        (resolved, unresolved)
    }
    #[cfg(not(target_os = "linux"))]
    {
        (paths, unresolved)
    }
}

const CARGO_CONFIG_UNVERIFIED: &str =
    "Cargo output configuration is unverified; shared-cache removal is blocked";

#[cfg(target_os = "linux")]
const MAX_CARGO_CONFIG_DEPTH: usize = 256;
#[cfg(target_os = "linux")]
const MAX_CARGO_CONFIG_FILES: usize = 32;
#[cfg(target_os = "linux")]
const MAX_CARGO_CONFIG_BYTES: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_CARGO_CONFIG_TOTAL_BYTES: usize = 4 * 1024 * 1024;

#[cfg(target_os = "linux")]
fn read_cargo_config(path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let fd = match rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err("Cargo config could not be read without following links"),
    };
    let file = std::fs::File::from(fd);
    let before = file
        .metadata()
        .map_err(|_| "Cargo config could not be inspected safely")?;
    if !before.is_file() || before.len() > MAX_CARGO_CONFIG_BYTES {
        return Err("Cargo config is not a regular file or exceeds the size limit");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&file)
        .take(MAX_CARGO_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cargo config could not be read safely")?;
    let after = file
        .metadata()
        .map_err(|_| "Cargo config could not be inspected safely")?;
    if bytes.len() as u64 > MAX_CARGO_CONFIG_BYTES
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("Cargo config changed while being read");
    }
    Ok(Some(bytes))
}

#[cfg(target_os = "linux")]
fn read_cargo_config_in(directory: &Path) -> Result<Option<(PathBuf, Vec<u8>)>, &'static str> {
    let legacy = directory.join("config");
    if let Some(bytes) = read_cargo_config(&legacy)? {
        return Ok(Some((legacy, bytes)));
    }
    let modern = directory.join("config.toml");
    Ok(read_cargo_config(&modern)?.map(|bytes| (modern, bytes)))
}

#[cfg(target_os = "linux")]
fn cargo_config_output_path(
    value: &toml::Value,
    config_file: &Path,
    build_dir: bool,
) -> Result<PathBuf, &'static str> {
    let value = value
        .as_str()
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .ok_or("Cargo build output path is not a non-empty string")?;
    if build_dir && value.contains(['{', '}']) {
        return Err("Cargo build-dir template is unresolved");
    }
    let path = PathBuf::from(value);
    let path = if path.is_absolute() {
        path
    } else {
        let base = config_file
            .parent()
            .and_then(Path::parent)
            .ok_or("Cargo config-relative path has no base directory")?;
        base.join(path)
    };
    resolve_cargo_output_path(&path)
}

#[cfg(target_os = "linux")]
fn resolve_cargo_output_path(path: &Path) -> Result<PathBuf, &'static str> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err("Cargo build output path is not absolute after resolution");
    }
    let mut resolved = PathBuf::from("/");
    let mut missing = false;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir if missing => {
                return Err("Cargo build output path has unresolved parent components");
            }
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) if missing => resolved.push(name),
            Component::Normal(name) => match resolved.join(name).canonicalize() {
                Ok(path) => resolved = path,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    resolved.push(name);
                    missing = true;
                }
                Err(_) => return Err("Cargo build output path could not be resolved safely"),
            },
            Component::Prefix(_) => {
                return Err("Cargo build output path has an unsupported prefix");
            }
        }
    }
    Ok(resolved)
}

#[cfg(target_os = "linux")]
fn cargo_config_build_paths_from(
    cwd: &Path,
    cargo_home: &Path,
    target_dir_overridden: bool,
    build_dir_overridden: bool,
) -> (Vec<PathBuf>, bool) {
    if !cwd.is_absolute() || !cargo_home.is_absolute() {
        return (Vec::new(), true);
    }
    let mut paths = Vec::new();
    let mut target_dir_found = target_dir_overridden;
    let mut build_dir_found = build_dir_overridden;
    let mut directories = Vec::new();
    for (depth, ancestor) in cwd.ancestors().enumerate() {
        if depth >= MAX_CARGO_CONFIG_DEPTH {
            return (paths, true);
        }
        directories.push(ancestor.join(".cargo"));
    }
    directories.push(cargo_home.to_owned());
    let mut seen = HashSet::new();
    let mut file_count = 0usize;
    let mut total_bytes = 0usize;
    for directory in directories {
        if target_dir_found && build_dir_found {
            break;
        }
        if !seen.insert(directory.clone()) {
            continue;
        }
        let (config_file, bytes) = match read_cargo_config_in(&directory) {
            Ok(Some(config)) => config,
            Ok(None) => continue,
            Err(_) => return (paths, true),
        };
        file_count += 1;
        total_bytes = total_bytes.saturating_add(bytes.len());
        if file_count > MAX_CARGO_CONFIG_FILES || total_bytes > MAX_CARGO_CONFIG_TOTAL_BYTES {
            return (paths, true);
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return (paths, true);
        };
        let Ok(config) = toml::from_str::<toml::Value>(text) else {
            return (paths, true);
        };
        let Some(root) = config.as_table() else {
            return (paths, true);
        };
        let build = match root.get("build") {
            Some(value) => match value.as_table() {
                Some(table) => Some(table),
                None => return (paths, true),
            },
            None => None,
        };
        if !target_dir_found && let Some(value) = build.and_then(|table| table.get("target-dir")) {
            let Ok(path) = cargo_config_output_path(value, &config_file, false) else {
                return (paths, true);
            };
            if !paths.contains(&path) {
                paths.push(path);
            }
            target_dir_found = true;
        }
        if !build_dir_found && let Some(value) = build.and_then(|table| table.get("build-dir")) {
            let Ok(path) = cargo_config_output_path(value, &config_file, true) else {
                return (paths, true);
            };
            if !paths.contains(&path) {
                paths.push(path);
            }
            build_dir_found = true;
        }
        if root
            .get("include")
            .is_some_and(|value| !matches!(value.as_array(), Some(values) if values.is_empty()))
            && (!target_dir_found || !build_dir_found)
        {
            return (paths, true);
        }
    }
    (paths, false)
}

#[cfg(target_os = "linux")]
fn cargo_config_build_paths() -> (Vec<PathBuf>, bool) {
    let (Some(cwd), Some(home)) = (env::current_dir().ok(), dirs::home_dir()) else {
        return (Vec::new(), true);
    };
    let cargo_home = match env::var_os("CARGO_HOME") {
        Some(value) if Path::new(&value).is_absolute() => PathBuf::from(value),
        Some(_) => return (Vec::new(), true),
        None => home.join(".cargo"),
    };
    cargo_config_build_paths_from(
        &cwd,
        &cargo_home,
        env::var_os("CARGO_TARGET_DIR").is_some()
            || env::var_os("CARGO_BUILD_TARGET_DIR").is_some(),
        env::var_os("CARGO_BUILD_BUILD_DIR").is_some(),
    )
}

#[cfg(not(target_os = "linux"))]
fn cargo_config_build_paths() -> (Vec<PathBuf>, bool) {
    (Vec::new(), false)
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

fn npm_config_overrides(setting: &str) -> Vec<std::ffi::OsString> {
    let Some(expected) = setting.strip_prefix("npm_config_") else {
        return Vec::new();
    };
    env::vars_os()
        .filter_map(|(env_name, value)| {
            let name = env_name.to_str()?;
            let (prefix, name) = name.split_at_checked("npm_config_".len())?;
            let normalize = |byte: u8| match byte {
                b'_' => b'-',
                _ => byte.to_ascii_lowercase(),
            };
            (prefix.eq_ignore_ascii_case("npm_config_")
                && name.len() == expected.len()
                && name
                    .bytes()
                    .map(normalize)
                    .eq(expected.bytes().map(normalize)))
            .then_some(value)
        })
        .collect()
}

#[derive(Default)]
struct NpmConfig {
    cache_roots: Vec<PathBuf>,
    log_directories: Vec<PathBuf>,
    prefixes: Vec<PathBuf>,
    user_config_files: Vec<PathBuf>,
    global_config_files: Vec<PathBuf>,
    global_config_verified: bool,
}

const MAX_BUN_CONFIG_DEPTH: usize = 128;
const MAX_BUN_CONFIG_FILES: usize = 32;
const MAX_BUN_CONFIG_TOTAL_BYTES: usize = 4 * 1024 * 1024;

fn bun_config_cache_path(
    home: &Path,
    config_dir: &Path,
    value: &str,
) -> Result<PathBuf, &'static str> {
    if value.is_empty() || value.contains(['\0', '$', '%']) {
        return Err("Bun cache config path is unresolved");
    }
    #[cfg(not(target_os = "linux"))]
    if value
        .split(['/', '\\'])
        .any(|segment| matches!(segment, "." | ".."))
    {
        // Verbatim Windows paths do not normalize forward slashes. Validate
        // the untrusted Bun config text *before* joining it to a prefix.
        return Err("Bun cache config path has unresolved parent components");
    }
    let path = if let Some(rest) = value.strip_prefix("~/") {
        home.join(rest)
    } else {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            path
        } else {
            config_dir.join(path)
        }
    };
    if !path.is_absolute() || path.parent().is_none() {
        return Err("Bun cache config path is not a safe absolute directory");
    }

    #[cfg(target_os = "linux")]
    {
        resolve_cargo_output_path(&path)
            .map_err(|_| "Bun cache config path could not be resolved safely")
    }

    #[cfg(not(target_os = "linux"))]
    {
        use std::path::Component;

        // Without an equivalent component resolver, refuse `..` instead of guessing across links.
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err("Bun cache config path has unresolved parent components");
        }
    }

    #[cfg(not(target_os = "linux"))]
    let normalized = path;
    #[cfg(not(target_os = "linux"))]
    {
        // Canonicalize the deepest existing parent so links still overlap.
        let mut missing = Vec::new();
        let mut existing = normalized.as_path();
        loop {
            match existing.canonicalize() {
                Ok(mut resolved) => {
                    for component in missing.iter().rev() {
                        resolved.push(component);
                    }
                    return Ok(resolved);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let name = existing
                        .file_name()
                        .ok_or("Bun cache config parent could not be resolved")?;
                    missing.push(name.to_owned());
                    existing = existing
                        .parent()
                        .ok_or("Bun cache config parent could not be resolved")?;
                }
                Err(_) => return Err("Bun cache config parent could not be resolved safely"),
            }
        }
    }
}

fn parse_bun_cache_config(
    bytes: &[u8],
    home: &Path,
    config_dir: &Path,
) -> Result<Option<PathBuf>, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "Bun config is not UTF-8")?;
    let config =
        toml::from_str::<toml::Value>(text).map_err(|_| "Bun config is malformed or ambiguous")?;
    let Some(install) = config.get("install") else {
        return Ok(None);
    };
    let install = install
        .as_table()
        .ok_or("Bun install config is ambiguous")?;
    let Some(cache) = install.get("cache") else {
        return Ok(None);
    };
    let cache = cache.as_table().ok_or("Bun cache config is ambiguous")?;
    let Some(directory) = cache.get("dir") else {
        return Ok(None);
    };
    let directory = directory
        .as_str()
        .ok_or("Bun cache directory config is ambiguous")?;
    bun_config_cache_path(home, config_dir, directory).map(Some)
}

#[cfg(target_os = "linux")]
fn read_bun_config(path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    read_cargo_config(path).map_err(|_| "Bun config could not be read without following links")
}

#[cfg(not(target_os = "linux"))]
fn read_bun_config(path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    read_maven_settings(path)
        .map(|settings| settings.map(|settings| settings.bytes))
        .map_err(|_| "Bun config could not be read safely")
}

fn bun_config_cache_paths(
    home: &Path,
    cwd: &Path,
    xdg_config_home: Option<&std::ffi::OsStr>,
) -> Result<Vec<PathBuf>, &'static str> {
    let global = match xdg_config_home {
        Some(value) if value.is_empty() => return Err("Bun XDG config directory is unresolved"),
        Some(value) => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err("Bun XDG config directory is not absolute");
            }
            path.join(".bunfig.toml")
        }
        None => home.join(".bunfig.toml"),
    };
    let cwd = cwd
        .canonicalize()
        .map_err(|_| "Bun project config directory could not be resolved")?;
    if !cwd.is_dir() {
        return Err("Bun project config directory could not be resolved");
    }
    let mut configs = vec![(global.clone(), global.parent().unwrap_or(home).to_owned())];
    for (depth, directory) in cwd.ancestors().enumerate() {
        if depth >= MAX_BUN_CONFIG_DEPTH {
            return Err("Bun project config search exceeded its depth limit");
        }
        configs.push((directory.join("bunfig.toml"), directory.to_owned()));
    }
    let mut paths = Vec::new();
    let mut file_count = 0usize;
    let mut total_bytes = 0usize;
    for (path, config_dir) in configs {
        let Some(bytes) = read_bun_config(&path)? else {
            continue;
        };
        file_count += 1;
        total_bytes = total_bytes.saturating_add(bytes.len());
        if file_count > MAX_BUN_CONFIG_FILES || total_bytes > MAX_BUN_CONFIG_TOTAL_BYTES {
            return Err("Bun configs exceed the inspection limits");
        }
        if let Some(path) = parse_bun_cache_config(&bytes, home, &config_dir)?
            && !paths.contains(&path)
        {
            paths.push(path);
        }
    }
    Ok(paths)
}

const MAX_NPM_PROJECT_DEPTH: usize = 128;
const MAX_NPM_CONFIG_FILES: usize = 32;
const MAX_NPM_CONFIG_TOTAL_BYTES: usize = 1024 * 1024;
const MAX_NPM_CONFIG_LOCATIONS: usize = 64;

fn npm_trim(value: &str) -> &str {
    value.trim_matches(|ch| {
        matches!(
            ch,
            '\u{0009}'..='\u{000d}'
                | '\u{0020}'
                | '\u{00a0}'
                | '\u{1680}'
                | '\u{2000}'..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
        )
    })
}

fn npm_environment_path(value: &std::ffi::OsStr) -> Option<PathBuf> {
    use std::path::Component;

    let value = npm_trim(value.to_str()?);
    if value.is_empty() || value.contains('$') {
        return None;
    }
    let path = PathBuf::from(value);
    (path.is_absolute()
        && path.parent().is_some()
        && !path
            .components()
            .any(|part| matches!(part, Component::ParentDir)))
    .then_some(path)
}

fn npm_prefix_path(value: &std::ffi::OsStr) -> Option<PathBuf> {
    use std::path::Component;

    let value = value.to_str()?;
    if value.is_empty() || value != npm_trim(value) || value.contains('$') {
        return None;
    }
    let path = PathBuf::from(value);
    (path.is_absolute()
        && !path
            .components()
            .any(|part| matches!(part, Component::ParentDir)))
    .then_some(path)
}

fn npm_prefix_global_config(prefix: &Path) -> Result<PathBuf, &'static str> {
    use std::path::Component;

    if !prefix.is_absolute()
        || prefix
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("npm prefix is not a safe absolute path");
    }
    let global_config = prefix.join("etc/npmrc");
    // Use complete ancestor paths, rather than rebuilding a Windows verbatim
    // prefix one component at a time: a bare `\\?\C:` is not a valid
    // filesystem path, whereas `\\?\C:\` is.
    for current in global_config
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        match std::fs::symlink_metadata(current) {
            Ok(metadata) => {
                #[cfg(windows)]
                let is_link = {
                    use std::os::windows::fs::MetadataExt;
                    metadata.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
                };
                #[cfg(not(windows))]
                let is_link = metadata.file_type().is_symlink();
                if is_link {
                    return Err("npm global config path contains a symbolic link");
                }
                if current != global_config && !metadata.is_dir() {
                    return Err("npm global config path has a non-directory parent");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err("npm global config path could not be inspected safely"),
        }
    }
    Ok(global_config)
}

fn npm_prefix_override(overrides: &[std::ffi::OsString]) -> Result<Option<PathBuf>, &'static str> {
    let mut values = overrides.iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.any(|value| value != first) {
        return Err("npm prefix environment aliases conflict");
    }
    npm_prefix_path(first)
        .map(Some)
        .ok_or("npm prefix environment override is not an absolute path")
}

fn npm_prefix_environment(
    value: Option<&std::ffi::OsStr>,
) -> Result<Option<PathBuf>, &'static str> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    npm_prefix_path(value)
        .map(Some)
        .ok_or("npm PREFIX environment value is not an absolute path")
}

fn npm_config_path(
    value: &str,
    home: &Path,
    home_variable: Option<&std::ffi::OsStr>,
    allow_root: bool,
) -> Result<PathBuf, &'static str> {
    use std::path::Component;

    let value = npm_trim(value);
    let value = if value.contains("${HOME}") {
        if home_variable != Some(home.as_os_str()) {
            return Err("npm config has an unresolved HOME variable");
        }
        value.replace("${HOME}", home.to_str().ok_or("npm home is not Unicode")?)
    } else {
        value.to_owned()
    };
    if value.is_empty() || value.contains(['$', '\0']) {
        return Err("npm config contains an unresolved path");
    }
    let path = if let Some(rest) = value.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(value)
    };
    if !path.is_absolute()
        || (!allow_root && path.parent().is_none())
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("npm config path is not a safe absolute path");
    }
    Ok(path)
}

fn push_npm_config_path(paths: &mut Vec<PathBuf>, path: PathBuf) -> Result<(), &'static str> {
    if paths.contains(&path) {
        return Ok(());
    }
    if paths.len() >= MAX_NPM_CONFIG_LOCATIONS {
        return Err("npm config contains too many possible locations");
    }
    paths.push(path);
    Ok(())
}

fn parse_npm_config(
    bytes: &[u8],
    home: &Path,
    home_variable: Option<&std::ffi::OsStr>,
) -> Result<NpmConfig, &'static str> {
    let input = std::str::from_utf8(bytes).map_err(|_| "npm config is not UTF-8")?;
    let mut config = NpmConfig::default();
    for line in input.split(['\n', '\r']) {
        let line = npm_trim(line);
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('[') || line.contains('\0') {
            return Err("npm config uses unsupported syntax");
        }
        let (key, value) = line.split_once('=').unwrap_or((line, ""));
        let key = npm_trim(key);
        let key = key.strip_suffix("[]").unwrap_or(key);
        if key.contains(['\\', '$', '"', '\'', '[', ']', '#', ';']) {
            return Err("npm config contains an ambiguous key");
        }
        if !["cache", "logs-dir", "prefix", "userconfig", "globalconfig"]
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate))
        {
            continue;
        }
        let value = npm_trim(value);
        let value = if value.starts_with('"') && value.ends_with('"') {
            serde_json::from_str::<String>(value)
                .map_err(|_| "npm config contains an unsupported path")?
        } else if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
            value[1..value.len() - 1].to_owned()
        } else {
            if value.contains(['\\', '"', '\'']) {
                return Err("npm config contains an unsupported path");
            }
            npm_trim(value.split(['#', ';']).next().unwrap_or("")).to_owned()
        };
        let is_prefix = key.eq_ignore_ascii_case("prefix");
        let path = npm_config_path(&value, home, home_variable, is_prefix)?;
        let destination = if key.eq_ignore_ascii_case("cache") {
            &mut config.cache_roots
        } else if key.eq_ignore_ascii_case("logs-dir") {
            &mut config.log_directories
        } else if is_prefix {
            &mut config.prefixes
        } else if key.eq_ignore_ascii_case("userconfig") {
            &mut config.user_config_files
        } else {
            &mut config.global_config_files
        };
        push_npm_config_path(destination, path)?;
    }
    Ok(config)
}

fn npm_project_config_files(cwd: &Path) -> Result<Vec<PathBuf>, &'static str> {
    if !cwd.is_absolute() {
        return Err("npm project directory is not absolute");
    }
    // Workspace resolution can promote an ancestor to localPrefix, so inspect each ancestor.
    let mut files = Vec::new();
    for (depth, directory) in cwd.ancestors().enumerate() {
        if depth >= MAX_NPM_PROJECT_DEPTH {
            return Err("npm project config search exceeds the depth limit");
        }
        let file = directory.join(".npmrc");
        match std::fs::symlink_metadata(&file) {
            Ok(_) => files.push(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("npm project config could not be inspected safely"),
        }
    }
    Ok(files)
}

fn queue_npm_config_file(
    pending: &mut std::collections::VecDeque<(PathBuf, bool)>,
    known: &mut std::collections::HashMap<PathBuf, bool>,
    path: PathBuf,
    follow_redirects: bool,
) -> Result<(), &'static str> {
    match known.get(&path).copied() {
        Some(true) | Some(false) if !follow_redirects => return Ok(()),
        Some(true) => return Ok(()),
        Some(false) => {
            known.insert(path.clone(), true);
            pending.push_back((path, true));
        }
        None => {
            known.insert(path.clone(), follow_redirects);
            pending.push_back((path, follow_redirects));
        }
    }
    if known.len() > MAX_NPM_CONFIG_FILES {
        return Err("npm config refers to too many files");
    }
    Ok(())
}

fn npm_config_sources(
    home: &Path,
    cwd: &Path,
    home_variable: Option<&std::ffi::OsStr>,
    prefix_overrides: &[std::ffi::OsString],
    prefix_environment: Option<&std::ffi::OsStr>,
    userconfig_overrides: &[std::ffi::OsString],
    globalconfig_overrides: &[std::ffi::OsString],
) -> Result<NpmConfig, &'static str> {
    use std::collections::{HashMap, VecDeque};
    use std::path::Component;

    let npm_home = home_variable
        .filter(|value| !value.is_empty())
        .map_or_else(|| home.to_owned(), PathBuf::from);
    if !npm_home.is_absolute()
        || npm_home.parent().is_none()
        || npm_home
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("npm home is not an absolute path");
    }
    let prefix_override = npm_prefix_override(prefix_overrides)?;
    let default_prefix = match prefix_override.clone() {
        Some(prefix) => Some(prefix),
        None => npm_prefix_environment(prefix_environment)?,
    };
    let mut pending = VecDeque::new();
    let mut known = HashMap::new();
    queue_npm_config_file(&mut pending, &mut known, home.join(".npmrc"), true)?;
    queue_npm_config_file(&mut pending, &mut known, npm_home.join(".npmrc"), true)?;
    for path in npm_project_config_files(cwd)? {
        queue_npm_config_file(&mut pending, &mut known, path, true)?;
    }
    for value in userconfig_overrides {
        queue_npm_config_file(
            &mut pending,
            &mut known,
            npm_environment_path(value)
                .ok_or("npm user config override is not a resolved absolute file path")?,
            true,
        )?;
    }
    for value in globalconfig_overrides {
        queue_npm_config_file(
            &mut pending,
            &mut known,
            npm_environment_path(value)
                .ok_or("npm global config override is not a resolved absolute file path")?,
            false,
        )?;
    }
    let mut combined = NpmConfig {
        global_config_verified: !globalconfig_overrides.is_empty(),
        ..NpmConfig::default()
    };
    if globalconfig_overrides.is_empty()
        && let Some(prefix) = &default_prefix
    {
        let path = npm_prefix_global_config(prefix)?;
        push_npm_config_path(&mut combined.global_config_files, path.clone())?;
        queue_npm_config_file(&mut pending, &mut known, path, false)?;
    }
    let mut total_bytes = 0usize;
    while let Some((path, follow_redirects)) = pending.pop_front() {
        let Some(settings) =
            read_maven_settings(&path).map_err(|_| "npm config file could not be read safely")?
        else {
            continue;
        };
        total_bytes = total_bytes
            .checked_add(settings.bytes.len())
            .filter(|size| *size <= MAX_NPM_CONFIG_TOTAL_BYTES)
            .ok_or("npm config files exceed the total size limit")?;
        let config = parse_npm_config(&settings.bytes, &npm_home, home_variable)?;
        let user_redirects = config.user_config_files.clone();
        let global_redirects = config.global_config_files.clone();
        if follow_redirects && globalconfig_overrides.is_empty() && prefix_override.is_none() {
            for prefix in &config.prefixes {
                let path = npm_prefix_global_config(prefix)?;
                push_npm_config_path(&mut combined.global_config_files, path.clone())?;
                queue_npm_config_file(&mut pending, &mut known, path, false)?;
            }
        }
        for (values, destination) in [
            (config.cache_roots, &mut combined.cache_roots),
            (config.log_directories, &mut combined.log_directories),
            (config.user_config_files, &mut combined.user_config_files),
            (
                config.global_config_files,
                &mut combined.global_config_files,
            ),
        ] {
            for value in values {
                push_npm_config_path(destination, value)?;
            }
        }
        if follow_redirects {
            for redirect in user_redirects {
                queue_npm_config_file(&mut pending, &mut known, redirect, true)?;
            }
            for redirect in global_redirects {
                queue_npm_config_file(&mut pending, &mut known, redirect, false)?;
            }
        }
    }
    Ok(combined)
}

fn npm_config_from_environment(home: &Path, cwd: &Path) -> Result<NpmConfig, &'static str> {
    let home_variable = env::var_os("HOME");
    let prefix_overrides = npm_config_overrides("npm_config_prefix");
    let prefix_environment = env::var_os("PREFIX");
    let userconfig_overrides = npm_config_overrides("npm_config_userconfig");
    let globalconfig_overrides = npm_config_overrides("npm_config_globalconfig");
    let mut config = npm_config_sources(
        home,
        cwd,
        home_variable.as_deref(),
        &prefix_overrides,
        prefix_environment.as_deref(),
        &userconfig_overrides,
        &globalconfig_overrides,
    )?;
    if let Some(value) = env::var_os("XDG_CONFIG_HOME") {
        let xdg = npm_environment_path(&value)
            .ok_or("npm XDG config directory is not a resolved absolute path")?;
        if let Some(bytes) = read_bun_config(&xdg.join(".npmrc"))
            .map_err(|_| "npm XDG config file could not be read safely")?
        {
            let bun_config = parse_npm_config(&bytes, home, home_variable.as_deref())?;
            for path in bun_config.cache_roots {
                push_npm_config_path(&mut config.cache_roots, path)?;
            }
        }
    }
    Ok(config)
}

fn npm_config_log_paths(config: &NpmConfig) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for path in config
        .cache_roots
        .iter()
        .map(|root| root.join("_logs"))
        .chain(config.log_directories.iter().cloned())
    {
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths
}

fn add_npm_config_specs(specs: &mut Vec<Spec>, config: &NpmConfig) {
    for root in &config.cache_roots {
        let path = root.join("_cacache");
        if !specs
            .iter()
            .any(|spec| spec.name == "npm" && spec.path == path)
        {
            specs.push(Spec {
                name: "npm configured cache (possible)",
                path,
                classification: "possible shared package cache",
                consequence: "npm configuration may be overridden; verify the active npm cache before cleanup",
            });
        }
    }
    for path in npm_config_log_paths(config) {
        if !specs
            .iter()
            .any(|spec| spec.name == "npm logs" && spec.path == path)
        {
            specs.push(Spec {
                name: "npm logs",
                path,
                classification: "diagnostic logs",
                consequence: "logs may contain command output and local paths",
            });
        }
    }
}

fn npm_cache_roots(platform: Platform, home: &Path, data: &Path) -> Vec<PathBuf> {
    let overrides = npm_config_overrides("npm_config_cache");
    if overrides.is_empty() {
        return vec![npm_default(platform, home, data)];
    }
    let mut roots = Vec::new();
    for value in overrides {
        if let Some(path) = npm_environment_path(&value)
            && !roots.contains(&path)
        {
            roots.push(path);
        }
    }
    roots
}

fn npm_cache_paths(platform: Platform, home: &Path, data: &Path) -> Vec<PathBuf> {
    npm_cache_roots(platform, home, data)
        .into_iter()
        .map(|path| path.join("_cacache"))
        .collect()
}

fn npm_log_paths(platform: Platform, home: &Path, data: &Path) -> Vec<PathBuf> {
    let mut paths = vec![npm_default(platform, home, data).join("_logs")];
    paths.extend(
        npm_cache_roots(platform, home, data)
            .into_iter()
            .map(|path| path.join("_logs")),
    );
    paths.extend(
        npm_config_overrides("npm_config_logs_dir")
            .into_iter()
            .filter_map(|value| npm_environment_path(&value)),
    );
    let mut unique = Vec::new();
    for path in paths {
        if !unique.contains(&path) {
            unique.push(path);
        }
    }
    unique
}

// shortcut: include new single-path overrides here before allowing shared-cache removal.
const CACHE_DIRECTORY_OVERRIDES: &[&str] = &[
    "CARGO_HOME",
    "YARN_CACHE_FOLDER",
    "PIP_CACHE_DIR",
    "GRADLE_USER_HOME",
    "CCACHE_DIR",
    "SCCACHE_DIR",
    "PUB_CACHE",
];

const UNRESOLVED_CACHE_DIRECTORY_OVERRIDE: &str =
    "a cache directory environment setting is unresolved; shared-cache removal is blocked";

fn has_unresolved_cache_directory_override(platform: Platform) -> bool {
    CACHE_DIRECTORY_OVERRIDES.iter().any(|name| {
        env::var_os(name).is_some_and(|value| value.is_empty() || !Path::new(&value).is_absolute())
    }) || (platform != Platform::Windows
        && env::var_os("XDG_CACHE_HOME")
            .is_some_and(|value| value.is_empty() || !Path::new(&value).is_absolute()))
        || cargo_build_paths().1
        || npm_config_overrides("npm_config_cache")
            .iter()
            .any(|value| npm_environment_path(value).is_none())
        || npm_config_overrides("npm_config_logs_dir")
            .iter()
            .any(|value| npm_environment_path(value).is_none())
}

const MAX_MAVEN_SETTINGS_BYTES: u64 = 256 * 1024;
const MAX_MAVEN_REPOSITORY_BYTES: usize = 4096;
const MAX_MAVEN_PROJECT_CONFIG_DEPTH: usize = 128;
const MAX_NUGET_CONFIG_PATH_BYTES: usize = 4096;
const MAX_NUGET_CONFIG_DIR_ENTRIES: usize = 256;
const MAX_NUGET_SOLUTION_CONFIG_DEPTH: usize = 128;
const MAX_NUGET_SOLUTION_CONFIG_FILES: usize = 128;
const MAX_NUGET_SOLUTION_CONFIG_TOTAL_BYTES: usize = 4 * 1024 * 1024;
#[cfg(windows)]
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
#[cfg(windows)]
const WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

fn maven_options_may_override_local_repository(value: &std::ffi::OsStr, maven_args: bool) -> bool {
    let Some(value) = value.to_str() else {
        return true;
    };
    if value.is_empty() {
        return false;
    }
    if value
        .chars()
        .any(|character| matches!(character, '\'' | '"' | '\\'))
    {
        return true;
    }

    let mut arguments = value.split_ascii_whitespace();
    while let Some(argument) = arguments.next() {
        if argument.starts_with('@')
            || (argument == "-D" && !maven_args)
            || ["-javaagent:", "-agentlib:", "-agentpath:"]
                .iter()
                .any(|prefix| argument.starts_with(prefix))
        {
            return true;
        }
        if maven_args
            && (matches!(
                argument,
                "-f" | "--file"
                    | "-s"
                    | "--settings"
                    | "-gs"
                    | "--global-settings"
                    | "-ps"
                    | "--project-settings"
                    | "-is"
                    | "--install-settings"
            ) || [
                "--file=",
                "--settings=",
                "--global-settings=",
                "--project-settings=",
                "--install-settings=",
            ]
            .iter()
            .any(|prefix| argument.starts_with(prefix))
                || (argument.starts_with('-')
                    && !matches!(argument, "-ff" | "-fae" | "-fn")
                    && ["-f", "-s", "-gs", "-ps", "-is"]
                        .iter()
                        .any(|prefix| argument.starts_with(prefix))))
        {
            return true;
        }
        let property = if matches!(argument, "-D" | "--define") {
            let Some(property) = arguments.next() else {
                return true;
            };
            property
        } else if let Some(property) = argument.strip_prefix("--define=") {
            property
        } else if let Some(property) = argument.strip_prefix("-D") {
            property
        } else {
            continue;
        };
        if matches!(
            property.split('=').next(),
            Some(
                "maven.repo.local"
                    | "maven.repo.local.head"
                    | "maven.repo.local.tail"
                    | "maven.reactor.outputRepository"
                    | "maven.ext.class.path"
                    | "user.home"
                    | "user.dir"
                    | "java.system.class.loader"
                    | "java.class.path"
                    | "java.endorsed.dirs"
                    | "java.ext.dirs"
                    | "maven.home"
                    | "maven.conf"
                    | "maven.multiModuleProjectDirectory"
                    | "maven.installation.conf"
                    | "maven.installation.settings"
                    | "maven.installation.extensions"
                    | "maven.installation.toolchains"
                    | "maven.user.conf"
                    | "maven.user.settings"
                    | "maven.user.extensions"
                    | "maven.user.toolchains"
                    | "maven.project.conf"
                    | "maven.project.settings"
                    | "maven.project.extensions"
                    | "org.apache.maven.global-settings"
                    | "org.apache.maven.user-settings"
            )
        ) {
            return true;
        }
    }
    !maven_config_options_are_unambiguous(value, maven_args)
}

fn maven_system_property_is_safe(property: &str) -> bool {
    let Some((name, value)) = property.split_once('=') else {
        return false;
    };
    !value.is_empty()
        && matches!(
            name,
            "user.language"
                | "user.country"
                | "user.variant"
                | "user.timezone"
                | "file.encoding"
                | "java.awt.headless"
        )
}

fn maven_config_options_are_unambiguous(value: &str, maven_args: bool) -> bool {
    if maven_args {
        let mut arguments = value.split_ascii_whitespace();
        while let Some(argument) = arguments.next() {
            match argument {
                "-B"
                | "--batch-mode"
                | "-C"
                | "--strict-checksums"
                | "-c"
                | "--lax-checksums"
                | "-e"
                | "--errors"
                | "-ff"
                | "--fail-fast"
                | "-fae"
                | "--fail-at-end"
                | "-fn"
                | "--fail-never"
                | "-N"
                | "--non-recursive"
                | "-npr"
                | "--no-plugin-registry"
                | "-npu"
                | "--no-plugin-updates"
                | "-nsu"
                | "--no-snapshot-updates"
                | "-o"
                | "--offline"
                | "-q"
                | "--quiet"
                | "-U"
                | "--update-snapshots"
                | "-v"
                | "--version"
                | "-V"
                | "--show-version"
                | "-X"
                | "--debug"
                | "-ntp"
                | "--no-transfer-progress"
                | "-itr"
                | "--ignore-transitive-repositories"
                | "-am"
                | "--also-make"
                | "-amd"
                | "--also-make-dependents"
                | "-h"
                | "--help" => {}
                "-T" | "--threads" => {
                    if arguments
                        .next()
                        .is_none_or(|value| !maven_thread_count_is_valid(value))
                    {
                        return false;
                    }
                }
                "-pl" | "--projects" | "-rf" | "--resume-from" | "-l" | "--log-file" => {
                    if arguments.next().is_none_or(|value| value.starts_with('-')) {
                        return false;
                    }
                }
                "-D" | "--define" => {
                    let Some(property) = arguments.next() else {
                        return false;
                    };
                    if !maven_system_property_is_safe(property) {
                        return false;
                    }
                }
                _ if argument.starts_with("-D") && argument.len() > 2 => {
                    if !maven_system_property_is_safe(&argument[2..]) {
                        return false;
                    }
                }
                _ if argument.starts_with("--define=") && argument.len() > 9 => {
                    if !maven_system_property_is_safe(&argument[9..]) {
                        return false;
                    }
                }
                _ if argument.starts_with("--threads=") => {
                    if !maven_thread_count_is_valid(&argument[10..]) {
                        return false;
                    }
                }
                _ if argument.starts_with("-T") && argument.len() > 2 => {
                    if !maven_thread_count_is_valid(&argument[2..]) {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    } else {
        value.split_ascii_whitespace().all(|option| {
            let size = [
                "-Xmx",
                "-Xms",
                "-Xss",
                "-XX:MaxMetaspaceSize=",
                "-XX:ReservedCodeCacheSize=",
            ]
            .iter()
            .find_map(|prefix| option.strip_prefix(prefix));
            if let Some(size) = size {
                return maven_memory_size_is_valid(size);
            }
            if let Some(property) = option.strip_prefix("-D") {
                return maven_system_property_is_safe(property);
            }
            matches!(option, "-server" | "-client")
        })
    }
}

fn maven_thread_count_is_valid(value: &str) -> bool {
    let number = value
        .strip_suffix('C')
        .or_else(|| value.strip_suffix('c'))
        .unwrap_or(value);
    let mut decimal_points = 0;
    if number.is_empty()
        || !number.bytes().all(|byte| match byte {
            b'0'..=b'9' => true,
            b'.' => {
                decimal_points += 1;
                decimal_points <= 1
            }
            _ => false,
        })
    {
        return false;
    }
    number
        .parse::<f64>()
        .is_ok_and(|count| count.is_finite() && count > 0.0)
}

fn maven_memory_size_is_valid(value: &str) -> bool {
    let number = value
        .strip_suffix('k')
        .or_else(|| value.strip_suffix('K'))
        .or_else(|| value.strip_suffix('m'))
        .or_else(|| value.strip_suffix('M'))
        .or_else(|| value.strip_suffix('g'))
        .or_else(|| value.strip_suffix('G'))
        .or_else(|| value.strip_suffix('t'))
        .or_else(|| value.strip_suffix('T'))
        .unwrap_or(value);
    !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
}

fn maven_option_file_may_override_local_repository(
    path: &Path,
    maven_args: bool,
) -> Result<bool, &'static str> {
    let Some(file) = read_maven_settings(path)? else {
        return Ok(false);
    };
    let value = std::str::from_utf8(&file.bytes).map_err(|_| "Maven options file is not UTF-8")?;
    let options = std::ffi::OsStr::new(value);
    Ok(maven_options_may_override_local_repository(
        options, maven_args,
    ))
}

fn maven_settings_file_may_override_local_repository(path: &Path) -> Result<bool, &'static str> {
    let Some(file) = read_maven_settings(path)? else {
        return Ok(false);
    };
    Ok(parse_maven_settings(&file.bytes)?.is_some())
}

fn maven_directory_config_may_override_local_repository(
    directory: &Path,
    names: &[&str],
) -> Result<bool, &'static str> {
    match std::fs::symlink_metadata(directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("Maven configuration directory could not be inspected safely"),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err("Maven configuration directory is not a regular directory");
        }
        Ok(_) => {}
    }
    for name in names {
        match std::fs::symlink_metadata(directory.join(name)) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("Maven configuration file could not be inspected safely"),
        }
    }
    Ok(false)
}

fn maven_project_config_may_override_local_repository(cwd: &Path) -> Result<bool, &'static str> {
    for (depth, ancestor) in cwd.ancestors().enumerate() {
        if depth >= MAX_MAVEN_PROJECT_CONFIG_DEPTH {
            return Err("Maven project config search exceeded its depth limit");
        }
        let directory = ancestor.join(".mvn");
        if maven_directory_config_may_override_local_repository(
            &directory,
            &[
                "maven-system.properties",
                "maven-user.properties",
                "extensions.xml",
            ],
        )? || maven_option_file_may_override_local_repository(
            &directory.join("jvm.config"),
            false,
        )? || maven_option_file_may_override_local_repository(
            &directory.join("maven.config"),
            true,
        )? || maven_settings_file_may_override_local_repository(&directory.join("settings.xml"))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn maven_repository_may_be_overridden(cwd: &Path, home: &Path) -> Result<bool, &'static str> {
    for (name, maven_args) in [
        ("MAVEN_OPTS", false),
        ("MAVEN_ARGS", true),
        ("JAVA_TOOL_OPTIONS", false),
        ("JDK_JAVA_OPTIONS", false),
        ("_JAVA_OPTIONS", false),
    ] {
        if env::var_os(name)
            .is_some_and(|value| maven_options_may_override_local_repository(&value, maven_args))
        {
            return Ok(true);
        }
    }
    if maven_project_config_may_override_local_repository(cwd)?
        || maven_directory_config_may_override_local_repository(
            &home.join(".m2"),
            &["maven-system.properties", "maven-user.properties"],
        )?
    {
        return Ok(true);
    }
    for name in ["MAVEN_HOME", "M2_HOME"] {
        let Some(value) = env::var_os(name) else {
            continue;
        };
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err("Maven installation home is not an absolute path");
        }
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err("Maven installation home is not a regular directory");
            }
            Ok(_) => {}
            Err(_) => return Err("Maven installation home could not be inspected safely"),
        }
        let conf = path.join("conf");
        if maven_directory_config_may_override_local_repository(
            &conf,
            &[
                "maven-system.properties",
                "maven-user.properties",
                "maven.properties",
            ],
        )? || maven_settings_file_may_override_local_repository(&conf.join("settings.xml"))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

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
    let mut cargo_output_paths = cargo_build_paths().0;
    for path in cargo_config_build_paths().0 {
        if !cargo_output_paths.contains(&path) {
            cargo_output_paths.push(path);
        }
    }
    for path in cargo_output_paths {
        add(
            "Cargo build output (possible)",
            Some(path),
            "configured output; scope unknown",
            "Cargo may place build artifacts or other user data here; Upkit only inventories this path",
        );
    }
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
    for path in npm_cache_paths(platform, home, data) {
        add(
            "npm",
            Some(path),
            "shared package cache",
            "packages may need to be downloaded again",
        );
    }
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

fn bun_specs(
    cache: Option<PathBuf>,
    command_cache: Option<PathBuf>,
    configured_caches: Vec<PathBuf>,
) -> Vec<Spec> {
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
    for path in configured_caches {
        if !specs.iter().any(|spec: &Spec| spec.path == path) {
            specs.push(Spec {
                name: "Bun configured cache",
                path,
                classification: "shared package cache",
                consequence: "Bun configuration may use this path; Upkit protects it from cache removal",
            });
        }
    }
    specs
}

#[cfg(target_os = "linux")]
pub(crate) fn selected_cache(path: &Path) -> anyhow::Result<Spec> {
    use anyhow::{Context, bail};
    if has_unresolved_cache_directory_override(Platform::Linux) {
        bail!(UNRESOLVED_CACHE_DIRECTORY_OVERRIDE);
    }
    if cargo_config_build_paths().1 {
        bail!(CARGO_CONFIG_UNVERIFIED);
    }
    let cwd = env::current_dir().context("current directory is unavailable")?;
    let home = dirs::home_dir().context("user home is unavailable")?;
    match maven_repository_may_be_overridden(&cwd, &home) {
        Ok(false) => {}
        Ok(true) => bail!(
            "Maven local repository may be overridden by Maven arguments or configuration; shared-cache removal is blocked"
        ),
        Err(error) => bail!(
            "Maven repository configuration is unverified ({error}); shared-cache removal is blocked"
        ),
    }
    let nuget_solution = nuget_solution_config_paths(Platform::Linux, &cwd).map_err(|error| {
        anyhow::anyhow!(
            "NuGet solution config is unverified ({error}); shared-cache removal is blocked"
        )
    })?;
    let cache = dirs::cache_dir().context("user cache directory is unavailable")?;
    let data = dirs::data_local_dir().context("user data directory is unavailable")?;
    let npm_config = npm_config_from_environment(&home, &cwd).map_err(|error| {
        anyhow::anyhow!(
            "npm cache configuration is unverified ({error}); shared-cache removal is blocked"
        )
    })?;
    let mut bun_configured_caches = bun_config_cache_paths(
        &home,
        &cwd,
        env::var_os("XDG_CONFIG_HOME").as_deref(),
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "Bun cache configuration is unverified ({error}); shared-cache removal is blocked"
        )
    })?;
    bun_configured_caches.extend(npm_config.cache_roots.iter().cloned());
    if !npm_config.global_config_verified {
        bail!(
            "npm global config location is unverified; set NPM_CONFIG_GLOBALCONFIG to an absolute path before removing a shared cache (a prefix-derived path is only a possible location)"
        );
    }
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
    add_npm_config_specs(&mut discovered, &npm_config);
    discovered.extend(bun_specs(
        Some(bun_cache.clone()),
        Some(bun_command_cache),
        bun_configured_caches,
    ));
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
    for path in npm_log_paths(Platform::Linux, &home, &data) {
        if !discovered
            .iter()
            .any(|spec| spec.name == "npm logs" && spec.path == path)
        {
            discovered.push(Spec {
                name: "npm logs",
                path,
                classification: "diagnostic logs",
                consequence: "logs may contain command output and local paths",
            });
        }
    }
    let mut matches = discovered
        .iter()
        .enumerate()
        .filter(|(_, spec)| spec.path == path);
    let (first_index, first) = matches
        .next()
        .context("selected path is not a discovered shared cache")?;
    if matches.next().is_some() {
        bail!("selected path matches more than one cache");
    }
    let first = first.clone();
    if first.name == "npm configured cache (possible)" {
        bail!("npm configuration may be overridden; this possible cache is inspection-only");
    }
    if first.name == "npm"
        && npm_config_overrides("npm_config_cache").is_empty()
        && !npm_config.cache_roots.is_empty()
        && (npm_config.cache_roots.len() != 1
            || npm_config.cache_roots[0].join("_cacache") != first.path)
    {
        bail!(
            "npm configuration may override the default cache; set an explicit cache environment path before removal"
        );
    }
    if first.name == "npm" && npm_cache_roots(Platform::Linux, &home, &data).len() > 1 {
        bail!("conflicting npm cache environment values must be resolved before removal");
    }
    if first.name == "npm logs" {
        bail!("npm log directories are protected and are not removable shared caches");
    }
    if first.name == "Cargo build output (possible)" {
        bail!(
            "Cargo build output is inventory-only because its contents may include project or other user data"
        );
    }
    if first.name == "pnpm" && pnpm_configured_store_dir().is_none() {
        bail!(
            "pnpm's store can be configured per workspace or filesystem; only an explicit PNPM_CONFIG_STORE_DIR can be removed safely"
        );
    }
    if matches!(
        first.name,
        "Bun" | "Bun cache command target" | "Bun configured cache"
    ) {
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
    for (index, other) in discovered.iter().enumerate() {
        if index == first_index {
            continue;
        }
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
    let cwd = env::current_dir().ok();
    let maven_override_warning =
        cwd.as_deref()
            .map_or(Some("current directory is unavailable"), |cwd| {
                match maven_repository_may_be_overridden(cwd, &home) {
                    Ok(true) => {
                        Some("Maven arguments or configuration may change the repository location")
                    }
                    Ok(false) => None,
                    Err(error) => Some(error),
                }
            });
    let nuget_solution_result = cwd
        .as_deref()
        .ok_or("current directory is unavailable")
        .and_then(|cwd| nuget_solution_config_paths(platform, cwd));
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
    let npm_config = cwd
        .as_deref()
        .ok_or("current directory is unavailable")
        .and_then(|cwd| npm_config_from_environment(&home, cwd));
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
    let bun_configured_caches = cwd
        .as_deref()
        .ok_or("current directory is unavailable")
        .and_then(|cwd| {
            bun_config_cache_paths(&home, cwd, env::var_os("XDG_CONFIG_HOME").as_deref())
        });
    let bun_config_warning = bun_configured_caches.as_ref().err().copied();
    let mut bun_configured_caches = bun_configured_caches.unwrap_or_default();
    if let Ok(config) = &npm_config {
        bun_configured_caches.extend(config.cache_roots.iter().cloned());
    }
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
    if let Ok(config) = &npm_config {
        add_npm_config_specs(&mut discovered, config);
    }
    discovered.extend(bun_specs(
        bun_cache,
        bun_command_cache,
        bun_configured_caches,
    ));
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
    if npm_config
        .as_ref()
        .is_ok_and(|config| !config.cache_roots.is_empty())
    {
        report.warnings.push(
            "npm configuration contains possible cache locations; npm may override or ignore these settings by source priority.".into(),
        );
    }
    if npm_config
        .as_ref()
        .is_ok_and(|config| !config.global_config_verified)
    {
        report.warnings.push(
            "npm global config location is unverified; shared-cache removal is blocked unless NPM_CONFIG_GLOBALCONFIG names an absolute config path. Prefix-derived global config paths are only possible locations.".into(),
        );
    }
    if let Err(error) = npm_config {
        report.warnings.push(format!(
            "npm cache configuration is unverified ({error}); shared-cache removal is blocked"
        ));
    }
    if has_unresolved_cache_directory_override(platform) {
        report
            .warnings
            .push(UNRESOLVED_CACHE_DIRECTORY_OVERRIDE.into());
    }
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
    if let Some(warning) = maven_override_warning {
        report.warnings.push(format!(
            "Maven local repository is unverified ({warning}); shared-cache removal is blocked"
        ));
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
    if let Some(error) = bun_config_warning {
        report.warnings.push(format!(
            "Bun cache configuration is unverified ({error}); shared-cache removal is blocked"
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
    report.warnings.push("Cache locations are inferred from environment variables, npm and Maven user settings when readable, Go's persistent environment when accessible, and platform defaults. npm project/global/builtin config and --cache/--logs-dir overrides may select unlisted paths. Bun global and workspace bunfig.toml cache paths and npm cache settings are protected as possible Bun caches; Bun --cache-dir, --config, and .env values may select unlisted paths. Maven global settings, command-line overrides, and other tool-specific configuration may select unlisted locations.".into());
    if npm_cache_paths(platform, &home, &data).len() > 1
        || npm_log_paths(platform, &home, &data).len() > 1
    {
        report.warnings.push(
            "npm: conflicting case-insensitive cache or logs environment values are treated as possible locations for removal checks; Upkit does not infer which values npm uses.".into(),
        );
    }
    if platform == Platform::Linux {
        report.warnings.push("Cargo build output inventory includes absolute CARGO_TARGET_DIR, CARGO_BUILD_TARGET_DIR, and CARGO_BUILD_BUILD_DIR paths plus effective build.target-dir/build.build-dir settings from the current directory's ancestor config files and CARGO_HOME. Cargo --target-dir/--config overrides and config files outside that search are not inspected; additional outputs may be unlisted. Configured output is not assumed shared or rebuildable, and Upkit does not remove it.".into());
        if cargo_config_build_paths().1 {
            report.warnings.push(CARGO_CONFIG_UNVERIFIED.into());
        }
    } else {
        report.warnings.push("Cargo build output inventory includes only absolute CARGO_TARGET_DIR, CARGO_BUILD_TARGET_DIR, and CARGO_BUILD_BUILD_DIR environment paths. Cargo config files and per-command --target-dir values are not inspected, so additional outputs may be unlisted; configured output is not assumed shared or rebuildable, and Upkit does not remove it.".into());
    }
    if cargo_build_paths().1 {
        report.warnings.push("Cargo build output environment settings are relative, templated, or conflicting; affected paths are unresolved and shared-cache removal is blocked.".into());
    }
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
            ownership: if spec.name == "Cargo build output (possible)" {
                "configured Cargo output; scope unknown"
            } else {
                "shared user cache"
            },
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
    let mut paths = Vec::with_capacity(report.entries.len());
    for entry in &report.entries {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        paths.push(entry.path.canonicalize().ok());
    }
    paths.resize_with(report.entries.len(), || None);
    let mut entries_by_path = HashMap::<PathBuf, Vec<usize>>::new();
    for (index, path) in paths.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if let Some(path) = path {
            entries_by_path.entry(path.clone()).or_default().push(index);
        }
    }
    let mut overlapping_paths = HashSet::new();
    if !cancel.load(Ordering::Relaxed) {
        'find_overlap: for path in entries_by_path.keys() {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            if entries_by_path
                .get(path)
                .is_some_and(|indices| indices.len() > 1)
            {
                overlapping_paths.insert(path.clone());
            }
            // Each path checks its nearest candidate ancestor, which is enough to mark every
            // member of a nested chain as its own path is visited.
            for ancestor in path.ancestors().skip(1) {
                if cancel.load(Ordering::Relaxed) {
                    break 'find_overlap;
                }
                if entries_by_path.contains_key(ancestor) {
                    overlapping_paths.insert(path.clone());
                    overlapping_paths.insert(ancestor.to_path_buf());
                    break;
                }
            }
        }
    }
    let mut overlapping = vec![false; paths.len()];
    'mark_overlap: for (path, indices) in &entries_by_path {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if overlapping_paths.contains(path) {
            for &index in indices {
                if cancel.load(Ordering::Relaxed) {
                    break 'mark_overlap;
                }
                overlapping[index] = true;
            }
        }
    }
    for (entry, overlaps) in report.entries.iter_mut().zip(overlapping) {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if overlaps {
            entry.warnings.push(
                "This cache path overlaps another discovered cache path; their size estimates may overlap, so do not add them without checking."
                    .into(),
            );
        }
    }
    let mut targets = Vec::with_capacity(paths.len());
    for path in &paths {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        targets.push(path.clone().unwrap_or_default());
    }
    targets.resize_with(paths.len(), PathBuf::new);
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

    fn npm_test_literal(path: &Path) -> String {
        // JSON string literals are also valid npmrc quoted values and retain
        // Windows backslashes. Unquoted backslashes are rejected by design.
        serde_json::to_string(&path.to_string_lossy()).unwrap()
    }

    #[test]
    fn cargo_build_output_paths_are_inventory_candidates_only_when_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("cargo-target");
        let build = dir.path().join("cargo-build");
        let (paths, unresolved) = cargo_build_paths_from(
            Some(target.clone().into_os_string()),
            Some(target.clone().into_os_string()),
            Some(build.clone().into_os_string()),
        );
        assert_eq!(paths, [target.clone(), build]);
        assert!(!unresolved);

        let conflicting = dir.path().join("other-target");
        let (paths, unresolved) = cargo_build_paths_from(
            Some(target.clone().into_os_string()),
            Some(conflicting.clone().into_os_string()),
            None,
        );
        assert_eq!(paths, [target.clone(), conflicting]);
        assert!(unresolved);

        let (paths, unresolved) = cargo_build_paths_from(
            Some("relative-target".into()),
            None,
            Some(dir.path().join("{workspace-root}").into_os_string()),
        );
        assert!(paths.is_empty());
        assert!(unresolved);
    }

    #[test]
    fn npm_config_extracts_only_supported_paths_without_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let logs = home.join("npm logs");
        let prefix = home.join("npm prefix");
        let user_config = home.join("user npmrc");
        let global_config = home.join("global npmrc");
        let input = format!(
            "# fixture\n//registry.example.invalid/:_authToken=${{SYNTHETIC_TOKEN}}\ncache=${{HOME}}/first # comment\ncache=~/second\n\u{feff}cache=\"${{HOME}}/third \u{feff}\"\nlogs-dir={}\nprefix={}\nuserconfig={}\nglobalconfig={}\n",
            serde_json::to_string(logs.to_str().unwrap()).unwrap(),
            serde_json::to_string(prefix.to_str().unwrap()).unwrap(),
            serde_json::to_string(user_config.to_str().unwrap()).unwrap(),
            serde_json::to_string(global_config.to_str().unwrap()).unwrap(),
        );
        let config = parse_npm_config(input.as_bytes(), home, Some(home.as_os_str())).unwrap();
        assert_eq!(
            config.cache_roots,
            [home.join("first"), home.join("second"), home.join("third")]
        );
        assert_eq!(config.log_directories, [logs]);
        assert_eq!(config.prefixes, [prefix]);
        assert_eq!(config.user_config_files, [user_config]);
        assert_eq!(config.global_config_files, [global_config]);
        assert!(parse_npm_config(input.as_bytes(), home, None).is_err());
        for input in [
            "cache=relative/path",
            "cache=${UNKNOWN}/private",
            "cache=~/../outside",
            "prefix=relative/path",
            "prefix=${UNKNOWN}/private",
            "prefix=~/../outside",
            "\"cache\"=/tmp/fixture",
            "${KEY}=/tmp/fixture",
            "[section]\ncache=/tmp/fixture",
            "logs-dir=",
        ] {
            assert!(parse_npm_config(input.as_bytes(), home, Some(home.as_os_str())).is_err());
        }
    }

    #[test]
    fn npm_prefix_adds_default_global_config_as_a_possible_location() {
        let dir = tempfile::tempdir().unwrap();
        // macOS can expose /var as a symlink to /private/var. Build
        // fixtures from the verified real root, never an aliased ancestor.
        let root = dir.path().canonicalize().unwrap();
        let home = root.join("home");
        let cwd = root.join("project");
        let prefix = root.join("npm-prefix");
        let global = prefix.join("etc/npmrc");
        let cache = root.join("npm-cache");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(global.parent().unwrap()).unwrap();
        std::fs::write(&global, format!("cache={}\n", npm_test_literal(&cache))).unwrap();

        let config = npm_config_sources(
            &home,
            &cwd,
            Some(home.as_os_str()),
            &[prefix.as_os_str().to_os_string()],
            None,
            &[],
            &[],
        )
        .unwrap();
        assert!(!config.global_config_verified);
        assert!(config.global_config_files.contains(&global));
        assert!(config.cache_roots.contains(&cache));

        let config =
            npm_config_sources(&home, &cwd, Some(home.as_os_str()), &[], None, &[], &[]).unwrap();
        assert!(!config.global_config_verified);

        let config = npm_config_sources(
            &home,
            &cwd,
            Some(home.as_os_str()),
            &[],
            Some(prefix.as_os_str()),
            &[],
            &[],
        )
        .unwrap();
        assert!(!config.global_config_verified);
        assert!(config.global_config_files.contains(&global));
        assert!(config.cache_roots.contains(&cache));
    }

    #[test]
    fn npm_config_prefix_adds_default_global_config_as_a_possible_location() {
        let dir = tempfile::tempdir().unwrap();
        // macOS can expose /var as a symlink to /private/var. Build
        // fixtures from the verified real root, never an aliased ancestor.
        let root = dir.path().canonicalize().unwrap();
        let home = root.join("home");
        let cwd = root.join("project");
        let prefix = root.join("configured-prefix");
        let global = prefix.join("etc/npmrc");
        let cache = root.join("npm-cache");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(global.parent().unwrap()).unwrap();
        std::fs::write(
            home.join(".npmrc"),
            format!("prefix={}\n", npm_test_literal(&prefix)),
        )
        .unwrap();
        std::fs::write(&global, format!("cache={}\n", npm_test_literal(&cache))).unwrap();

        let config =
            npm_config_sources(&home, &cwd, Some(home.as_os_str()), &[], None, &[], &[]).unwrap();
        assert!(!config.global_config_verified);
        assert!(config.global_config_files.contains(&global));
        assert!(config.cache_roots.contains(&cache));
    }

    #[test]
    fn npm_prefix_overrides_reject_conflicts_and_unresolved_paths() {
        use std::ffi::OsString;

        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first-prefix");
        let second = dir.path().join("second-prefix");
        for values in [
            vec![OsString::from("relative-prefix")],
            vec![OsString::from(format!("{} ", first.display()))],
            vec![first.join("../unsafe").into_os_string()],
            vec![
                OsString::from(first.as_os_str()),
                OsString::from(second.as_os_str()),
            ],
        ] {
            assert!(npm_prefix_override(&values).is_err());
        }
        assert!(npm_prefix_environment(Some(std::ffi::OsStr::new("relative"))).is_err());
        assert_eq!(npm_prefix_environment(None).unwrap(), None);
        assert_eq!(
            npm_prefix_override(&[
                first.as_os_str().to_os_string(),
                first.as_os_str().to_os_string()
            ])
            .unwrap(),
            Some(first)
        );
    }

    #[cfg(unix)]
    #[test]
    fn npm_global_config_default_rejects_symlinked_prefix_paths() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let actual_prefix = dir.path().join("actual-prefix");
        let linked_prefix = dir.path().join("linked-prefix");
        std::fs::create_dir_all(actual_prefix.join("etc")).unwrap();
        symlink(&actual_prefix, &linked_prefix).unwrap();
        assert!(npm_prefix_global_config(&linked_prefix).is_err());

        let linked_etc = dir.path().join("linked-etc");
        symlink(actual_prefix.join("etc"), &linked_etc).unwrap();
        assert!(npm_prefix_global_config(&linked_etc).is_err());
    }

    #[test]
    fn npm_config_sources_follow_bounded_project_and_user_redirects() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let project = dir.path().join("project");
        let workspace = project.join("nested");
        let cwd = workspace.join("work");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            project.join("package.json"),
            br#"{"workspaces":["nested"]}"#,
        )
        .unwrap();
        std::fs::write(workspace.join("package.json"), b"{}").unwrap();

        let redirected_user = home.join("redirected.npmrc");
        let user_global = home.join("user-global.npmrc");
        let project_cache = home.join("project-cache");
        let workspace_cache = home.join("workspace-cache");
        let user_cache = home.join("redirected-user-cache");
        let user_global_cache = home.join("user-global-cache");
        let env_global = home.join("env-global.npmrc");
        let env_global_cache = home.join("env-global-cache");
        let project_logs = home.join("project-logs");
        let global_logs = home.join("global-logs");
        std::fs::write(
            home.join(".npmrc"),
            format!(
                "//registry.example.invalid/:_authToken=synthetic-user-secret\nglobalconfig={}\ncache={}\n",
                npm_test_literal(&redirected_user),
                npm_test_literal(&user_global_cache),
            ),
        )
        .unwrap();
        std::fs::write(
            project.join(".npmrc"),
            format!(
                "userconfig={}\ncache={}\nlogs-dir={}\n//registry.example.invalid/:_authToken=synthetic-project-secret\n",
                npm_test_literal(&redirected_user),
                npm_test_literal(&project_cache),
                npm_test_literal(&project_logs),
            ),
        )
        .unwrap();
        std::fs::write(
            workspace.join(".npmrc"),
            format!("cache={}\n", npm_test_literal(&workspace_cache)),
        )
        .unwrap();
        std::fs::write(
            &redirected_user,
            format!(
                "cache={}\nuserconfig={}\nglobalconfig={}\n",
                npm_test_literal(&user_cache),
                npm_test_literal(&home.join(".npmrc")),
                npm_test_literal(&user_global),
            ),
        )
        .unwrap();
        std::fs::write(
            &user_global,
            format!(
                "cache={}\nlogs-dir={}\n",
                npm_test_literal(&user_global_cache),
                npm_test_literal(&global_logs)
            ),
        )
        .unwrap();
        std::fs::write(
            &env_global,
            format!("cache={}\n", npm_test_literal(&env_global_cache)),
        )
        .unwrap();

        let config = npm_config_sources(
            &home,
            &cwd,
            Some(home.as_os_str()),
            &[],
            None,
            &[],
            &[env_global.as_os_str().to_os_string()],
        )
        .unwrap();
        for path in [
            &project_cache,
            &workspace_cache,
            &user_cache,
            &user_global_cache,
            &env_global_cache,
        ] {
            assert!(config.cache_roots.contains(path));
        }
        assert!(config.log_directories.contains(&project_logs));
        assert!(config.log_directories.contains(&global_logs));
        assert_eq!(
            npm_project_config_files(&cwd).unwrap(),
            [workspace.join(".npmrc"), project.join(".npmrc")]
        );
        assert!(npm_config_log_paths(&config).contains(&global_logs));
        assert!(config.global_config_verified);

        let unverified =
            npm_config_sources(&home, &cwd, Some(home.as_os_str()), &[], None, &[], &[]).unwrap();
        assert!(!unverified.global_config_verified);

        let invalid_project = dir.path().join("invalid-project");
        std::fs::create_dir_all(&invalid_project).unwrap();
        std::fs::write(invalid_project.join("package.json"), b"{}").unwrap();
        std::fs::write(
            invalid_project.join(".npmrc"),
            b"userconfig=relative.npmrc\n",
        )
        .unwrap();
        assert!(
            npm_config_sources(
                &home,
                &invalid_project,
                Some(home.as_os_str()),
                &[],
                None,
                &[],
                &[home.join("explicit-global.npmrc").into_os_string()],
            )
            .is_err()
        );
    }

    #[test]
    fn npm_project_sources_include_cwd_fallback_and_lock_only_ancestors() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let global = dir.path().join("global.npmrc");
        std::fs::create_dir_all(&home).unwrap();

        let plain_cwd = dir.path().join("plain/nested");
        let plain_cache = dir.path().join("plain-cwd-cache");
        std::fs::create_dir_all(&plain_cwd).unwrap();
        std::fs::write(
            plain_cwd.join(".npmrc"),
            format!("cache={}\n", npm_test_literal(&plain_cache)),
        )
        .unwrap();
        assert_eq!(
            npm_project_config_files(&plain_cwd).unwrap(),
            [plain_cwd.join(".npmrc")]
        );
        let plain = npm_config_sources(
            &home,
            &plain_cwd,
            Some(home.as_os_str()),
            &[],
            None,
            &[],
            &[global.as_os_str().to_os_string()],
        )
        .unwrap();
        assert!(plain.cache_roots.contains(&plain_cache));

        let lock_parent = dir.path().join("lock-only");
        let lock_cwd = lock_parent.join("nested");
        let lock_parent_cache = dir.path().join("lock-parent-cache");
        let lock_cwd_cache = dir.path().join("lock-cwd-cache");
        std::fs::create_dir_all(&lock_cwd).unwrap();
        std::fs::write(lock_parent.join("package-lock.json"), b"{}").unwrap();
        std::fs::write(
            lock_parent.join(".npmrc"),
            format!("cache={}\n", npm_test_literal(&lock_parent_cache)),
        )
        .unwrap();
        std::fs::write(
            lock_cwd.join(".npmrc"),
            format!("cache={}\n", npm_test_literal(&lock_cwd_cache)),
        )
        .unwrap();
        assert_eq!(
            npm_project_config_files(&lock_cwd).unwrap(),
            [lock_cwd.join(".npmrc"), lock_parent.join(".npmrc")]
        );
        let lock_only = npm_config_sources(
            &home,
            &lock_cwd,
            Some(home.as_os_str()),
            &[],
            None,
            &[],
            &[global.as_os_str().to_os_string()],
        )
        .unwrap();
        assert!(lock_only.cache_roots.contains(&lock_cwd_cache));
        assert!(lock_only.cache_roots.contains(&lock_parent_cache));
    }

    #[test]
    fn npm_environment_paths_trim_like_npm_and_reject_unresolved_values() {
        use std::ffi::OsStr;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("npm cache");
        let padded = format!("\u{feff}{} \t", path.display());
        assert_eq!(npm_environment_path(OsStr::new(&padded)), Some(path));
        let dynamic = format!("{}/${{SECRET}}/cache", dir.path().display());
        let parent = format!("{}/nested/../cache", dir.path().display());
        for value in ["", "relative", &dynamic, &parent] {
            assert!(npm_environment_path(OsStr::new(value)).is_none());
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            assert!(npm_environment_path(OsStr::from_bytes(b"/fixture/\xff")).is_none());
        }
    }

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
        let repository = dir.path().join("packages");
        let config = home.join(".nuget/NuGet/NuGet.Config");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(
            &config,
            format!(
                "<configuration><config><add key=\"RepositoryPATH\" value=\"{}\"/></config></configuration>",
                repository.display()
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
        assert_eq!(parsed.repository_paths, vec![repository]);
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
        // macOS can expose /var as a symlink to /private/var. Build
        // fixtures from the verified real root, never an aliased ancestor.
        let root = dir.path().canonicalize().unwrap();
        let project = root.join("solution/member");
        std::fs::create_dir_all(&project).unwrap();
        let solution = root.join("solution");
        let old_global = root.join("old-global");
        let new_global = root.join("new-global");
        let old_fallback = root.join("old-fallback");
        let new_fallback = root.join("new-fallback");
        let old_source = root.join("old-source");
        let new_source = root.join("new-source");
        let old_repository = root.join("old-repository");
        let new_repository = root.join("new-repository");
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
            nuget_solution_config_paths(
                if cfg!(target_os = "macos") {
                    Platform::Macos
                } else {
                    Platform::Linux
                },
                &project,
            )
            .unwrap(),
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
        // macOS can expose /var as a symlink to /private/var. Build
        // fixtures from the verified real root, never an aliased ancestor.
        let root = dir.path().canonicalize().unwrap();
        let project = root.join("project");
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

        let distinct_dir = root.join("distinct");
        std::fs::create_dir(&distinct_dir).unwrap();
        std::fs::write(distinct_dir.join("NuGet.Config"), content).unwrap();
        std::fs::write(distinct_dir.join("nuget.config"), content).unwrap();
        // On case-insensitive APFS these spellings are the *same file*.
        // On case-sensitive volumes they can be two distinct files and must
        // fail closed. Exercise the behavior that the host can represent.
        let first = read_maven_settings(&distinct_dir.join("NuGet.Config"))
            .unwrap()
            .unwrap();
        let second = read_maven_settings(&distinct_dir.join("nuget.config"))
            .unwrap()
            .unwrap();
        if same_nuget_config_case_alias(Platform::Macos, &first, &second) {
            assert!(nuget_solution_config_paths(Platform::Macos, &distinct_dir).is_ok());
        } else {
            assert!(nuget_solution_config_paths(Platform::Macos, &distinct_dir).is_err());
        }
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
        #[cfg(not(windows))]
        assert!(nuget_solution_config_paths(Platform::Linux, &project).is_err());
        #[cfg(windows)]
        assert!(nuget_solution_config_paths(Platform::Windows, &project).is_ok());
        // Typical NTFS cannot hold distinct names that differ only in case;
        // native Windows enumeration inspects its canonical NuGet.Config.
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
        let old_packages = dir.path().join("old-packages");
        let configured = dir.path().join("packages&cache");
        let bytes = format!(
            "<configuration><config><add key=\"globalPackagesFolder\" value=\"{}\"/><clear/><add key=\"globalPackagesFolder\" value=\"{}\"/></config></configuration>",
            old_packages.display(),
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
        let fixture = tempfile::tempdir().unwrap();
        let repository = fixture.path().join("packages");
        let first_feed = fixture.path().join("first-feed");
        let second_feed = fixture.path().join("second-feed");
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
        let duplicates = format!(
            "<configuration><packageSources><add key=\"same\" value=\"{}\"/><add key=\"same\" value=\"{}\"/></packageSources></configuration>",
            first_feed.display(),
            second_feed.display()
        );
        assert!(parse_nuget_solution_config(duplicates.as_bytes()).is_err());
        let repository_config = format!(
            "<configuration><config><add key=\"repositoryPath\" value=\"{}\"/></config></configuration>",
            repository.display(),
        );
        assert_eq!(
            parse_nuget_solution_config(repository_config.as_bytes())
                .unwrap()
                .repository_paths,
            vec![repository]
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
                Vec::new(),
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
    fn bun_config_cache_paths_resolve_relative_and_home_values() {
        let dir = tempfile::tempdir().unwrap();
        // macOS can expose /var as a symlink to /private/var. Build
        // fixtures from the verified real root, never an aliased ancestor.
        let root = dir.path().canonicalize().unwrap();
        let home = root.join("home");
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&workspace).unwrap();

        let parent_relative = parse_bun_cache_config(
            br#"[install.cache]
dir = "../cache/bun"
"#,
            &home,
            &workspace,
        );
        if cfg!(target_os = "linux") {
            assert_eq!(parent_relative.unwrap(), Some(root.join("cache/bun")));
        } else {
            // Non-Linux platforms intentionally reject `..`: they lack the
            // descriptor-bound resolver that verifies its path components.
            assert!(parent_relative.is_err());
        }
        let absolute = root.join("cache/bun");
        let absolute_config = format!(
            "[install.cache]\ndir = {}\n",
            serde_json::to_string(&absolute.to_string_lossy()).unwrap(),
        );
        assert_eq!(
            parse_bun_cache_config(absolute_config.as_bytes(), &home, &workspace).unwrap(),
            Some(absolute)
        );
        assert_eq!(
            parse_bun_cache_config(
                br#"[install.cache]
dir = "~/bun-cache"
"#,
                &home,
                &workspace
            )
            .unwrap(),
            Some(home.join("bun-cache"))
        );
    }

    #[test]
    fn bun_global_and_workspace_configs_are_unioned() {
        use std::ffi::OsStr;

        let dir = tempfile::tempdir().unwrap();
        // macOS can expose /var as a symlink to /private/var. Build
        // fixtures from the verified real root, never an aliased ancestor.
        let root = dir.path().canonicalize().unwrap();
        let home = root.join("home");
        let xdg_config = root.join("xdg-config");
        let workspace = root.join("workspace");
        let nested = workspace.join("packages/app");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&xdg_config).unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            xdg_config.join(".bunfig.toml"),
            r#"[install.cache]
dir = "~/bun-global"
"#,
        )
        .unwrap();
        // Global/home and workspace configurations must union correctly on
        // every platform, using a path the platform can resolve safely.
        let workspace_cache = root.join("cache/bun-workspace");
        std::fs::write(
            workspace.join("bunfig.toml"),
            format!(
                "[install.cache]\ndir = {}\n",
                serde_json::to_string(&workspace_cache.to_string_lossy()).unwrap(),
            ),
        )
        .unwrap();

        let paths = bun_config_cache_paths(&home, &nested, Some(xdg_config.as_os_str())).unwrap();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&home.join("bun-global")));
        assert!(paths.contains(&root.join("cache/bun-workspace")));
        assert!(bun_config_cache_paths(&home, &nested, Some(OsStr::new("relative"))).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oversized_bunfig_is_rejected_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join(".bunfig.toml"),
            vec![b' '; MAX_CARGO_CONFIG_BYTES as usize + 1],
        )
        .unwrap();

        assert!(bun_config_cache_paths(&home, &home, None).is_err());
    }

    #[test]
    fn ambiguous_bun_cache_config_is_rejected_without_echoing_values() {
        let dir = tempfile::tempdir().unwrap();
        let private_value = "synthetic-secret-path";
        for config in [
            "[install.cache\ndir = \"/tmp/cache\"",
            "[install.cache]\ndir = 42",
            "[install.cache]\ndir = \"$HOME/cache\"",
            "[install.cache]\ndir = \"/\"",
        ] {
            let error = parse_bun_cache_config(
                config.replace("/tmp/cache", private_value).as_bytes(),
                dir.path(),
                dir.path(),
            )
            .unwrap_err();
            assert!(!error.contains(private_value));
        }
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
    fn maven_option_detection_catches_repository_overrides_and_ambiguous_arguments() {
        use std::ffi::OsStr;

        for options in [
            "-Dmaven.repo.local=/tmp/maven-cache",
            "-Dmaven.ext.class.path=/tmp/extension.jar",
            "-javaagent:/tmp/agent.jar",
            "-Duser.home=/tmp/maven-home",
            "-Djava.system.class.loader=example.Loader",
            "-Djava.class.path=/tmp/loader.jar",
            "-Djava.ext.dirs=/tmp/extensions",
            "-Dmaven.home=/tmp/maven-install",
            "-Dmaven.conf=/tmp/maven-conf",
            "-Dmaven.installation.conf=/tmp/install-conf",
            "-Dmaven.user.conf=/tmp/user-conf",
            "-Dmaven.project.conf=/tmp/project-conf",
            "-Dmaven.installation.extensions=/tmp/install-extensions.xml",
            "-Dmaven.user.extensions=/tmp/user-extensions.xml",
            "-Dmaven.project.extensions=/tmp/project-extensions.xml",
            "-Dmaven.repo.local.head=/tmp/maven-head",
            "-Dmaven.repo.local.tail=/tmp/maven-tail",
            "-Dmaven.reactor.outputRepository=/tmp/reactor-repository",
            "-Dmaven.project.settings=/tmp/project-settings.xml",
            "-Dmaven.user.settings=/tmp/user-settings.xml",
            "-Dmaven.installation.settings=/tmp/installation-settings.xml",
            "-Dorg.apache.maven.user-settings=/tmp/user-settings.xml",
            "-Dorg.apache.maven.global-settings=/tmp/global-settings.xml",
            "--define=maven.repo.local=/tmp/maven-cache",
            "--define maven.repo.local=/tmp/maven-cache",
            "-D maven.repo.local=/tmp/maven-cache",
            "-Dmaven.repo.local='/tmp/cache with spaces'",
            "@maven-args",
        ] {
            assert!(
                maven_options_may_override_local_repository(OsStr::new(options), false),
                "{options} must be treated as an override or ambiguous"
            );
        }
        for options in ["", "-Xmx2g", "-Duser.language=en"] {
            assert!(
                !maven_options_may_override_local_repository(OsStr::new(options), false),
                "{options} does not set the local repository"
            );
        }
        assert!(!maven_options_may_override_local_repository(
            OsStr::new("-D user.language=en"),
            true
        ));
        for options in [
            "-s /tmp/settings.xml",
            "--settings=/tmp/settings.xml",
            "-gs /tmp/global-settings.xml",
            "--global-settings=/tmp/global-settings.xml",
            "-f /tmp/other/pom.xml",
            "--file=/tmp/other/pom.xml",
            "-ps /tmp/project-settings.xml",
            "-is /tmp/install-settings.xml",
        ] {
            assert!(
                maven_options_may_override_local_repository(OsStr::new(options), true),
                "{options} may redirect Maven configuration or project root"
            );
        }
        assert!(!maven_options_may_override_local_repository(
            OsStr::new("-B -fn"),
            true
        ));
        assert!(!maven_options_may_override_local_repository(
            OsStr::new("-B -T2C"),
            true
        ));
        assert!(maven_options_may_override_local_repository(
            OsStr::new("-B -T invalid"),
            true
        ));
        assert!(maven_options_may_override_local_repository(
            OsStr::new("-Dcustom.property=value"),
            true
        ));
        assert!(maven_options_may_override_local_repository(
            OsStr::new("--unknown-maven-option"),
            true
        ));
    }

    #[test]
    fn maven_project_configs_allow_safe_options_and_settings_only() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().join("workspace/project/module");
        let project_config = root.path().join("workspace/project/.mvn");
        std::fs::create_dir_all(&cwd).unwrap();
        assert!(!maven_project_config_may_override_local_repository(&cwd).unwrap());

        std::fs::create_dir_all(&project_config).unwrap();
        std::fs::write(
            project_config.join("jvm.config"),
            "-Xmx2g\n-Xms512m\n-Duser.language=en\n",
        )
        .unwrap();
        std::fs::write(
            project_config.join("maven.config"),
            "--batch-mode -T 2 -Duser.language=en\n",
        )
        .unwrap();
        std::fs::write(
            project_config.join("settings.xml"),
            "<settings><offline>false</offline></settings>",
        )
        .unwrap();
        assert!(!maven_project_config_may_override_local_repository(&cwd).unwrap());

        std::fs::write(
            project_config.join("jvm.config"),
            "-javaagent:/tmp/agent.jar\n",
        )
        .unwrap();
        assert!(maven_project_config_may_override_local_repository(&cwd).unwrap());
        std::fs::write(project_config.join("jvm.config"), "-Xbogus\n").unwrap();
        assert!(maven_project_config_may_override_local_repository(&cwd).unwrap());
        std::fs::write(
            project_config.join("jvm.config"),
            "-Djava.system.class.loader=example.Loader\n",
        )
        .unwrap();
        assert!(maven_project_config_may_override_local_repository(&cwd).unwrap());
        std::fs::write(
            project_config.join("jvm.config"),
            "-Dcustom.property=value\n",
        )
        .unwrap();
        assert!(maven_project_config_may_override_local_repository(&cwd).unwrap());
        std::fs::write(project_config.join("jvm.config"), "-Xmx2g\n").unwrap();
        std::fs::write(project_config.join("maven.config"), "--unknown-option\n").unwrap();
        assert!(maven_project_config_may_override_local_repository(&cwd).unwrap());
        std::fs::write(
            project_config.join("maven.config"),
            "--batch-mode -T invalid\n",
        )
        .unwrap();
        assert!(maven_project_config_may_override_local_repository(&cwd).unwrap());
        std::fs::write(project_config.join("maven.config"), "--batch-mode\n").unwrap();
        std::fs::write(
            project_config.join("settings.xml"),
            "<settings><localRepository>/tmp/maven-cache</localRepository></settings>",
        )
        .unwrap();
        assert!(maven_project_config_may_override_local_repository(&cwd).unwrap());

        std::fs::write(project_config.join("settings.xml"), "<settings>").unwrap();
        assert!(maven_project_config_may_override_local_repository(&cwd).is_err());
        std::fs::remove_file(project_config.join("settings.xml")).unwrap();
        std::fs::write(
            project_config.join("maven-system.properties"),
            "maven.repo.local=/tmp/maven-cache\n",
        )
        .unwrap();
        assert!(maven_project_config_may_override_local_repository(&cwd).unwrap());
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
