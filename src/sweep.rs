//! Read-only discovery of project-local generated artifacts.
pub use crate::cargo_workspace::WorkspaceEvidence;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
struct Exclusions {
    paths: Vec<PathBuf>,
    patterns: Vec<(PathBuf, globset::GlobMatcher)>,
}

impl Exclusions {
    fn new(roots: &[PathBuf], exclusions: &[PathBuf]) -> Result<Self> {
        let mut result = Self::default();
        for path in exclusions {
            if let Some(pattern) = exclusion_pattern(path)? {
                result
                    .patterns
                    .extend(roots.iter().map(|root| (root.clone(), pattern.clone())));
            } else if path.is_absolute() {
                result
                    .paths
                    .push(path.canonicalize().unwrap_or_else(|_| path.clone()));
            } else {
                result
                    .paths
                    .extend(roots.iter().map(|root| root.join(path)));
            }
        }
        Ok(result)
    }

    fn matches(&self, path: &Path) -> bool {
        self.paths.iter().any(|excluded| path.starts_with(excluded))
            || self.patterns.iter().any(|(root, pattern)| {
                path.strip_prefix(root).is_ok_and(|relative| {
                    relative
                        .ancestors()
                        .any(|ancestor| pattern.is_match(ancestor))
                })
            })
    }
}

pub(crate) fn exclusion_pattern(path: &Path) -> Result<Option<globset::GlobMatcher>> {
    let Some(pattern) = path.to_str().and_then(|value| value.strip_prefix("glob:")) else {
        return Ok(None);
    };
    let pattern_path = Path::new(pattern);
    if pattern.is_empty()
        || pattern_path.is_absolute()
        || pattern_path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        bail!("glob exclusions must be nonempty relative patterns without '..'");
    }
    Ok(Some(
        globset::GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()?
            .compile_matcher(),
    ))
}

pub fn display_path(path: &Path) -> String {
    #[cfg(unix)]
    {
        use std::{fmt::Write, os::unix::ffi::OsStrExt};
        let mut display = String::new();
        for byte in path.as_os_str().as_bytes() {
            if (0x20..=0x7e).contains(byte) && *byte != b'%' {
                display.push(char::from(*byte));
            } else {
                let _ = write!(display, "%{byte:02X}");
            }
        }
        display
    }
    #[cfg(windows)]
    {
        use std::{fmt::Write, os::windows::ffi::OsStrExt};
        let mut display = String::new();
        for unit in path.as_os_str().encode_wide() {
            if (0x20..=0x7e).contains(&unit) && unit != b'%' as u16 {
                display.push(char::from(unit as u8));
            } else {
                let _ = write!(display, "%u{unit:04X}");
            }
        }
        display
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut display = String::new();
        for character in path.to_string_lossy().chars() {
            if character.is_control() {
                display.extend(character.escape_default());
            } else {
                display.push(character);
            }
        }
        display
    }
}

pub(crate) struct JsonPath<'a>(pub(crate) &'a Path);

impl Serialize for JsonPath<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if let Some(path) = self.0.to_str() {
            return serializer.serialize_str(path);
        }
        #[cfg(any(unix, windows))]
        {
            use serde::ser::SerializeStruct;
            let mut value = serializer.serialize_struct("EncodedPath", 2)?;
            #[cfg(unix)]
            value.serialize_field("encoding", "unix-percent-bytes")?;
            #[cfg(windows)]
            value.serialize_field("encoding", "windows-percent-utf16")?;
            value.serialize_field("value", &display_path(self.0))?;
            value.end()
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(serde::ser::Error::custom(
                "path cannot be represented as Unicode",
            ))
        }
    }
}

pub(crate) fn serialize_path<S: serde::Serializer>(
    path: &Path,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    JsonPath(path).serialize(serializer)
}

pub(crate) fn serialize_optional_path<S: serde::Serializer>(
    path: &Option<PathBuf>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    path.as_deref().map(JsonPath).serialize(serializer)
}

fn serialize_paths<S: serde::Serializer>(
    paths: &[PathBuf],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut sequence = serializer.serialize_seq(Some(paths.len()))?;
    for path in paths {
        sequence.serialize_element(&JsonPath(path))?;
    }
    sequence.end()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Cargo,
    Go,
    Zig,
    Cmake,
    Meson,
    Ninja,
    Gradle,
    Maven,
    Sbt,
    Dotnet,
    Flutter,
    Dart,
    Python,
    Javascript,
}

/// Explicit scan roots and policy used by artifact operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Scope {
    #[serde(serialize_with = "serialize_paths")]
    pub roots: Vec<PathBuf>,
    #[serde(serialize_with = "serialize_paths")]
    pub exclusions: Vec<PathBuf>,
    pub older_than_seconds: Option<u64>,
    pub enabled: Option<Vec<Ecosystem>>,
}

#[cfg(target_os = "linux")]
pub(crate) fn inspect_cargo_workspace(
    scope: &Scope,
    project: &Path,
    cancel: &AtomicBool,
) -> Result<WorkspaceEvidence> {
    let mut roots = Vec::new();
    for root in &scope.roots {
        let metadata = fs::symlink_metadata(root)
            .with_context(|| format!("inspect Cargo workspace scope {}", display_path(root)))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("Cargo workspace scope must be a non-symlink directory");
        }
        let root = root.canonicalize()?;
        if root.parent().is_none() {
            bail!("refusing to use a filesystem root as a Cargo workspace scope");
        }
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    let exclusions = Exclusions::new(&roots, &scope.exclusions)?;
    Ok(crate::cargo_workspace::Inspector::new(&roots).inspect(
        project,
        |path| exclusions.matches(path),
        cancel,
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn current_cargo_workspace_proof(scope: &Scope, project: &Path) -> Result<String> {
    let evidence = inspect_cargo_workspace(scope, project, &AtomicBool::new(false))?;
    evidence
        .proof()
        .map(str::to_owned)
        .context("Cargo workspace ancestry could not be verified")
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Go => "go",
            Self::Zig => "zig",
            Self::Cmake => "cmake",
            Self::Meson => "meson",
            Self::Ninja => "ninja",
            Self::Gradle => "gradle",
            Self::Maven => "maven",
            Self::Sbt => "sbt",
            Self::Dotnet => "dotnet",
            Self::Flutter => "flutter",
            Self::Dart => "dart",
            Self::Python => "python",
            Self::Javascript => "javascript",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Candidate {
    pub ecosystem: &'static str,
    #[serde(serialize_with = "serialize_path")]
    pub project_root: PathBuf,
    #[serde(serialize_with = "serialize_path")]
    pub target: PathBuf,
    pub logical_bytes: u64,
    /// Allocated blocks for distinct regular files, where supported; not reclaimed space.
    pub allocated_bytes: Option<u64>,
    pub size_complete: bool,
    /// Most recent modification in the measured tree; absent if any timestamps were unavailable.
    pub modified_unix: Option<u64>,
    pub classification: &'static str,
    pub operation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reproduction_warning: Option<&'static str>,
    /// Read-only manifest ancestry evidence; Cargo output configuration is checked separately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cargo_workspace: Option<WorkspaceEvidence>,
    /// First recognized manifest found during measurement, not an exhaustive inventory.
    #[serde(serialize_with = "serialize_optional_path")]
    pub nested_project_marker: Option<PathBuf>,
    /// First nested version-control marker found during measurement.
    #[serde(serialize_with = "serialize_optional_path")]
    pub nested_vcs_marker: Option<PathBuf>,
    /// First multiply linked regular file observed on Unix or Windows; other links may be outside the target.
    #[serde(serialize_with = "serialize_optional_path")]
    pub hard_link_marker: Option<PathBuf>,
    /// First symbolic link observed without following it.
    #[serde(serialize_with = "serialize_optional_path")]
    pub symlink_marker: Option<PathBuf>,
    #[serde(skip)]
    snapshot: Option<ArtifactSnapshot>,
}

fn reproduction_warning_for(ecosystem: &str, target: &Path) -> Option<&'static str> {
    if ecosystem == "ninja" {
        return Some(
            "A Ninja log suggests build state, but the directory can contain user files; removal is unsupported.",
        );
    }
    if ecosystem == "cmake" {
        return Some(
            "CMakeCache.txt identifies a CMake build tree, but build trees can contain user files; inspect every entry before removal.",
        );
    }
    if ecosystem == "meson" {
        return Some(
            "meson-private/coredata.dat identifies a Meson build tree, but build trees can contain user files; inspect every entry before removal.",
        );
    }
    if ecosystem == "javascript"
        && target
            .file_name()
            .is_some_and(|name| name == ".parcel-cache")
    {
        return Some(
            "This is Parcel's default cache name, but the name and package.json do not prove its contents are generated; inspect them before removal.",
        );
    }
    if ecosystem == "javascript" && target.file_name().is_some_and(|name| name == ".next") {
        return Some(
            "This is Next.js's default distDir name, but the name and package.json do not prove its contents are generated; distDir is configurable, so inspect every entry before removal.",
        );
    }
    if ecosystem == "javascript" && target.file_name().is_some_and(|name| name == ".nuxt") {
        return Some(
            "This is Nuxt's default buildDir name, but the name and package.json do not prove its contents are generated; buildDir is configurable, so inspect every entry before removal.",
        );
    }
    if ecosystem == "javascript" && target.file_name().is_some_and(|name| name == "coverage") {
        return Some(
            "A known coverage report filename suggests generated test output, but does not prove every entry is disposable; inspect all entries before removal.",
        );
    }
    if ecosystem == "javascript"
        && target.file_name().is_some_and(|name| name == ".vite")
        && target
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "node_modules")
    {
        return Some(
            "This is Vite's default cache location, but project settings can override it and the directory contents are not verified as generated; inspect them before removal.",
        );
    }
    if ecosystem == "javascript" && target.file_name().is_some_and(|name| name == ".svelte-kit") {
        return Some(
            "SvelteKit's configurable outDir defaults to .svelte-kit, but Upkit cannot verify every entry is disposable; inspect its contents before removal.",
        );
    }
    if ecosystem == "javascript"
        && target.file_name().is_some_and(|name| name == "cache")
        && target
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == ".angular")
    {
        return Some(
            "Angular CLI's cache path is configurable in angular.json; inspect its contents before removal.",
        );
    }
    if ecosystem == "zig" && target.file_name().is_some_and(|name| name == "zig-out") {
        return Some(
            "Zig's default install output can contain user data; inspect every entry before removal.",
        );
    }
    if ecosystem == "gradle" && target.file_name().is_some_and(|name| name == ".gradle") {
        return Some(
            "Gradle stores project state in this local .gradle directory; the directory name and build.gradle manifest do not prove every entry can be regenerated. Inspect its contents before removal.",
        );
    }
    if ecosystem == "sbt" && target.file_name().is_some_and(|name| name == "target") {
        return Some(
            "sbt's target directory contains generated build outputs and local state; inspect every entry before removal.",
        );
    }
    if ecosystem == "go"
        && target
            .file_name()
            .is_some_and(|name| matches!(name.to_str(), Some("build" | "bin")))
    {
        return Some(
            "Go build and bin directories are only possible output locations; they may contain tracked or user-authored files. Upkit can inventory them, but removal is unsupported until their contents can be attributed safely.",
        );
    }
    if ecosystem != "python" {
        return None;
    }
    if target
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name != ".egg-info" && name.ends_with(".egg-info"))
    {
        return Some(
            "Python .egg-info directories contain package metadata that may be needed by project workflows; inspect every entry before removal.",
        );
    }
    match target.file_name().and_then(|name| name.to_str()) {
        Some(".tox" | ".nox") => Some(
            "tox and Nox work directories can contain virtual environments, build logs, packages, and project-specific state; inspect every entry because it may include user data.",
        ),
        Some("build" | "dist") => Some(
            "Python build and distribution directories can contain release artifacts or project files; inspect every entry before removal.",
        ),
        Some(".hypothesis") => Some(
            "Deleting this Hypothesis database removes saved failure examples used to reproduce test failures.",
        ),
        Some(".pytype") => Some(
            "The default pytype output directory can contain generated .pyi stubs; inspect them before removal.",
        ),
        Some(".ruff_cache") => Some(
            "Ruff's .ruff_cache directory is local lint state, but the scanner cannot verify every entry is disposable; inspect its contents before removal.",
        ),
        _ => None,
    }
}

pub(crate) fn reproduction_warning(candidate: &Candidate) -> Option<&'static str> {
    candidate.reproduction_warning
}

#[cfg(target_os = "linux")]
pub(crate) fn candidate_manifest(candidate: &Candidate) -> Option<&Path> {
    candidate
        .snapshot
        .as_ref()
        .map(|snapshot| snapshot.manifest.as_path())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FileIdentityAtPath {
    #[serde(serialize_with = "serialize_path")]
    path: PathBuf,
    file: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactSnapshot {
    manifest: PathBuf,
    project: FileIdentity,
    manifest_identity: FileIdentity,
    target: FileIdentity,
    cargo_config: Option<FileIdentityAtPath>,
    cargo_workspace_manifest: Option<FileIdentityAtPath>,
    cargo_workspace_proof: Option<String>,
}

#[cfg(unix)]
fn identity(path: &Path, directory: bool) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return None;
    }
    Some(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanos: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
    })
}

// shortcut: stable Windows file IDs are unavailable in std, add handle-based identity before cleanup.
#[cfg(not(unix))]
fn identity(_: &Path, _: bool) -> Option<FileIdentity> {
    None
}

fn identity_at(path: &Path) -> Option<FileIdentityAtPath> {
    Some(FileIdentityAtPath {
        path: path.to_owned(),
        file: identity(path, false)?,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn candidate_cargo_config_identity(candidate: &Candidate) -> Option<FileIdentityAtPath> {
    candidate.snapshot.as_ref()?.cargo_config.clone()
}

#[cfg(target_os = "linux")]
pub(crate) fn candidate_cargo_workspace_proof(candidate: &Candidate) -> Option<&str> {
    candidate
        .snapshot
        .as_ref()?
        .cargo_workspace_proof
        .as_deref()
}

#[cfg(target_os = "linux")]
pub(crate) fn current_cargo_config_identity(root: &Path) -> Result<Option<FileIdentityAtPath>> {
    let project = project_at(root).context("Cargo project identity is unavailable")?;
    if !project.cargo || project.cargo_target_dir_unresolved {
        bail!("Cargo output configuration is unresolved");
    }
    project
        .cargo_config
        .as_deref()
        .map(|path| identity_at(path).context("Cargo config identity is unavailable"))
        .transpose()
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    #[serde(serialize_with = "serialize_paths")]
    pub roots: Vec<PathBuf>,
    pub candidates: Vec<Candidate>,
    pub warnings: Vec<String>,
    pub cancelled: bool,
}

impl ScanReport {
    /// Whether inventory finished without warnings or incomplete candidate measurements.
    pub fn is_complete(&self) -> bool {
        !self.cancelled
            && self.warnings.is_empty()
            && self
                .candidates
                .iter()
                .all(|candidate| candidate.size_complete)
    }
}

#[derive(Clone, Default)]
struct Project {
    root: PathBuf,
    cargo: bool,
    cargo_target_dir: Option<PathBuf>,
    cargo_config: Option<PathBuf>,
    cargo_target_dir_unresolved: bool,
    go: bool,
    cmake: bool,
    meson: bool,
    ninja: bool,
    zig: bool,
    gradle: bool,
    maven: bool,
    sbt: bool,
    dotnet: bool,
    flutter: bool,
    python: bool,
    javascript: bool,
    angular: bool,
    sveltekit: bool,
}

fn is_regular(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file())
}

fn is_dotnet_project_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            ["csproj", "fsproj", "vbproj"]
                .iter()
                .any(|expected| ext.eq_ignore_ascii_case(expected))
        })
}

const MAX_PACKAGE_MANIFEST_BYTES: usize = 1024 * 1024;

// shortcut: skip manifests over 1 MiB; use streaming JSON detection if real manifests exceed the cap.
#[cfg(target_os = "linux")]
fn package_manifest(path: &Path) -> Option<fs::File> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

    // shortcut: skip SvelteKit inventory when openat2 is unavailable; add a validated dirfd fallback for older kernels.
    Some(fs::File::from(
        openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .ok()?,
    ))
}

#[cfg(target_os = "macos")]
fn package_manifest(path: &Path) -> Option<fs::File> {
    use rustix::fs::{Mode, OFlags, open};

    Some(fs::File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .ok()?,
    ))
}

#[cfg(windows)]
fn package_manifest(path: &Path) -> Option<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::Component;

    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return None;
    }
    let expected = fs::symlink_metadata(&path).ok()?;
    if is_reparse_point(&expected)
        || !expected.is_file()
        || expected.len() > MAX_PACKAGE_MANIFEST_BYTES as u64
    {
        return None;
    }

    let parent = path.parent()?;
    let mut ancestors = parent.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    let mut volume = None;
    for ancestor in ancestors {
        let metadata = fs::symlink_metadata(ancestor).ok()?;
        if is_reparse_point(&metadata) || !metadata.is_dir() {
            return None;
        }
        let ancestor_volume = windows_volume(ancestor).ok()?;
        if volume.is_some_and(|expected| expected != ancestor_volume) {
            return None;
        }
        volume = Some(ancestor_volume);
    }

    // FILE_FLAG_OPEN_REPARSE_POINT only protects the final path component.
    // shortcut: path checks can race; require handle-relative traversal before using this as deletion proof.
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        // Avoid hydrating offline data just to inspect a project manifest.
        .custom_flags(
            WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT | winsafe::co::FILE_FLAG::OPEN_NO_RECALL.raw(),
        );
    let file = options.open(&path).ok()?;
    let metadata = file.metadata().ok()?;
    let file_type = winapi_util::file::typ(&file).ok()?;
    let information = winapi_util::file::information(&file).ok()?;
    if !metadata.is_file()
        || !file_type.is_disk()
        || is_reparse_point(&metadata)
        || has_windows_reparse_attribute(information.file_attributes())
        || information.file_size() > MAX_PACKAGE_MANIFEST_BYTES as u64
        || !volume.is_some_and(|volume| information.volume_serial_number() == volume)
    {
        return None;
    }
    Some(file)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn package_manifest(_: &Path) -> Option<fs::File> {
    None
}

fn package_declares(path: &Path, package: &str) -> bool {
    let Some(manifest) = read_json_manifest(&path.join("package.json")) else {
        return false;
    };
    [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ]
    .iter()
    .any(|section| {
        manifest
            .get(*section)
            .and_then(|dependencies| dependencies.get(package))
            .is_some()
    })
}

fn angular_workspace(path: &Path) -> bool {
    read_json_manifest(&path.join("angular.json")).is_some_and(|manifest| {
        manifest
            .get("projects")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|projects| !projects.is_empty())
    })
}

fn read_json_manifest(path: &Path) -> Option<serde_json::Value> {
    let mut file = package_manifest(path)?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_PACKAGE_MANIFEST_BYTES as u64 {
        return None;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    use std::io::Read;
    if file
        .by_ref()
        .take((MAX_PACKAGE_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > MAX_PACKAGE_MANIFEST_BYTES
    {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

const MAX_CARGO_CONFIG_ANCESTORS: usize = 256;

fn real_directory_path_exists(path: &Path) -> Result<bool> {
    use std::path::Component;

    if !path.is_absolute() {
        bail!("Cargo config directory path is not absolute");
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) => {
                current.push(component.as_os_str());
                continue;
            }
            Component::RootDir | Component::Normal(_) => current.push(component.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => bail!("Cargo config directory path contains '..'"),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !is_reparse_point(&metadata) => {}
            Ok(_) => bail!("Cargo config directory path contains a link or non-directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => bail!("Cargo config directory path could not be inspected safely"),
        }
    }
    Ok(true)
}

fn cargo_config_directory_has_config(directory: &Path) -> Result<bool> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() && !is_reparse_point(&metadata) => {}
        Ok(_) => bail!("Cargo config directory is a link or non-directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => bail!("Cargo config directory could not be inspected safely"),
    }
    for name in ["config", "config.toml"] {
        match fs::symlink_metadata(directory.join(name)) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => bail!("Cargo config file status could not be inspected safely"),
        }
    }
    Ok(false)
}

fn cargo_home_directory_from(
    cargo_home: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Result<PathBuf> {
    if let Some(cargo_home) = cargo_home {
        let path = PathBuf::from(cargo_home);
        if !path.is_absolute() {
            bail!("CARGO_HOME is not absolute");
        }
        return Ok(path);
    }
    let home = PathBuf::from(home.context("HOME is unavailable")?);
    if !home.is_absolute() || !real_directory_path_exists(&home)? {
        bail!("HOME is unavailable or cannot be inspected safely");
    }
    Ok(home.join(".cargo"))
}

fn cargo_home_directory() -> Result<PathBuf> {
    let cargo_home = std::env::var_os("CARGO_HOME");
    let home = std::env::var_os("HOME");
    cargo_home_directory_from(cargo_home.as_deref(), home.as_deref())
}

fn inherited_cargo_config_present(root: &Path, cargo_home: &Path) -> Result<bool> {
    if !real_directory_path_exists(root)? {
        bail!("Cargo project directory is unavailable");
    }
    for (depth, ancestor) in root.ancestors().enumerate() {
        if depth >= MAX_CARGO_CONFIG_ANCESTORS {
            bail!("Cargo config ancestor limit reached");
        }
        if ancestor != root && cargo_config_directory_has_config(&ancestor.join(".cargo"))? {
            return Ok(true);
        }
        if ancestor.parent().is_none() {
            break;
        }
    }
    if !cargo_home.is_absolute() {
        bail!("CARGO_HOME is not absolute");
    }
    let cargo_home_exists = real_directory_path_exists(cargo_home)?;
    if cargo_home_exists && cargo_config_directory_has_config(cargo_home)? {
        return Ok(true);
    }
    Ok(false)
}

// shortcut: only the project-local config is parsed; inherited, global, CLI, and environment overrides remain unresolved.
fn cargo_target_dir(root: &Path) -> (Option<PathBuf>, Option<PathBuf>, bool) {
    if [
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET_DIR",
        "CARGO_BUILD_BUILD_DIR",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some())
    {
        return (None, None, true);
    }
    let Ok(cargo_home) = cargo_home_directory() else {
        return (None, None, true);
    };
    cargo_target_dir_with_home(root, &cargo_home)
}

fn cargo_target_dir_with_home(
    root: &Path,
    cargo_home: &Path,
) -> (Option<PathBuf>, Option<PathBuf>, bool) {
    match inherited_cargo_config_present(root, cargo_home) {
        Ok(false) => {}
        Ok(true) | Err(_) => return (None, None, true),
    }
    let cargo_dir = root.join(".cargo");
    let cargo_meta = match fs::symlink_metadata(&cargo_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return (None, None, false),
        Err(_) => return (None, None, true),
    };
    let root_meta = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(_) => return (None, None, true),
    };
    if is_reparse_point(&cargo_meta)
        || !cargo_meta.is_dir()
        || !same_device(&cargo_meta, &root_meta)
    {
        return (None, None, true);
    }

    let modern_config = cargo_dir.join("config.toml");
    let legacy = cargo_dir.join("config");
    let toml_exists = match fs::symlink_metadata(&modern_config) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return (None, None, true),
    };
    let legacy_exists = match fs::symlink_metadata(&legacy) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return (None, None, true),
    };
    if toml_exists && legacy_exists {
        return (None, None, true);
    }
    if !toml_exists && !legacy_exists {
        return (None, None, false);
    }
    let config = if toml_exists && is_regular(&modern_config) {
        modern_config
    } else if legacy_exists && is_regular(&legacy) {
        legacy
    } else {
        return (None, None, true);
    };
    let Some(mut file) = package_manifest(&config) else {
        return (None, Some(config), true);
    };
    let Ok(metadata) = file.metadata() else {
        return (None, Some(config), true);
    };
    if !metadata.is_file() || metadata.len() > MAX_PACKAGE_MANIFEST_BYTES as u64 {
        return (None, Some(config), true);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    use std::io::Read;
    if file
        .by_ref()
        .take((MAX_PACKAGE_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > MAX_PACKAGE_MANIFEST_BYTES
    {
        return (None, Some(config), true);
    }
    let Ok(config_text) = std::str::from_utf8(&bytes) else {
        return (None, Some(config), true);
    };
    let Ok(value) = toml::from_str::<toml::Value>(config_text) else {
        return (None, Some(config), true);
    };
    if value.get("include").is_some() {
        return (None, Some(config), true);
    }
    let build = value.get("build");
    let Some(build) = build else {
        return (None, Some(config), false);
    };
    let Some(build) = build.as_table() else {
        return (None, Some(config), true);
    };
    if build.get("build-dir").is_some() {
        return (None, Some(config), true);
    }
    let Some(target_dir) = build.get("target-dir") else {
        return (None, Some(config), false);
    };
    let Some(target_dir) = target_dir.as_str() else {
        return (None, Some(config), true);
    };
    let relative = Path::new(target_dir);
    if target_dir.is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return (None, Some(config), true);
    }
    let target = root.join(relative);
    if target == root || !target.starts_with(root) {
        return (None, Some(config), true);
    }
    (Some(target), Some(config), false)
}

fn project_at(path: &Path) -> Option<Project> {
    let has = |name: &str| is_regular(&path.join(name));
    let dotnet = fs::read_dir(path)
        .ok()?
        .filter_map(|entry| entry.ok())
        .any(|entry| {
            let path = entry.path();
            is_dotnet_project_file(&path) && is_regular(&path)
        });
    let cargo = has("Cargo.toml");
    let (cargo_target_dir, cargo_config, cargo_target_dir_unresolved) = if cargo {
        cargo_target_dir(path)
    } else {
        (None, None, false)
    };
    let project = Project {
        root: path.to_owned(),
        cargo,
        cargo_target_dir,
        cargo_config,
        cargo_target_dir_unresolved,
        go: has("go.mod") || has("go.work"),
        cmake: has("CMakeLists.txt"),
        meson: has("meson.build"),
        ninja: has("build.ninja")
            && !has("CMakeLists.txt")
            && !has("meson.build")
            && !has("CMakeCache.txt"),
        zig: has("build.zig"),
        gradle: has("build.gradle") || has("build.gradle.kts"),
        maven: has("pom.xml"),
        sbt: has("build.sbt"),
        dotnet,
        flutter: has("pubspec.yaml"),
        python: has("pyproject.toml")
            || has("setup.py")
            || has("setup.cfg")
            || has("requirements.txt"),
        javascript: has("package.json"),
        angular: angular_workspace(path),
        sveltekit: package_declares(path, "@sveltejs/kit"),
    };
    (project.cargo
        || project.go
        || project.cmake
        || project.meson
        || project.ninja
        || project.zig
        || project.gradle
        || project.maven
        || project.sbt
        || project.dotnet
        || project.flutter
        || project.python
        || project.javascript)
        .then_some(project)
}

// shortcut: inspect only Vite's default cache path; revalidate path snapshots before cleanup and add config support for custom paths.
fn vite_cache_at(
    project: &Project,
    root: &Path,
    root_identity: (&fs::Metadata, Option<u64>),
    exclusions: &Exclusions,
    mounts: &HashSet<PathBuf>,
    cancel: &AtomicBool,
    warnings: &mut Vec<String>,
) -> Option<PathBuf> {
    let (root_metadata, _root_volume) = root_identity;
    if !project.javascript {
        return None;
    }
    let modules = root.join("node_modules");
    if exclusions.matches(&modules) {
        return None;
    }
    if mounts.contains(&modules) {
        warnings.push(format!(
            "{}: skipped filesystem boundary",
            display_path(&modules)
        ));
        return None;
    }
    if cancel.load(Ordering::Relaxed) {
        return None;
    }
    let metadata = match fs::symlink_metadata(&modules) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            warnings.push(format!("{}: {error}", display_path(&modules)));
            return None;
        }
    };
    if is_reparse_point(&metadata) {
        warnings.push(format!(
            "{}: skipped linked or reparse directory",
            display_path(&modules)
        ));
        return None;
    }
    if !metadata.is_dir() {
        return None;
    }
    if !same_device(&metadata, root_metadata) {
        warnings.push(format!(
            "{}: skipped filesystem boundary",
            display_path(&modules)
        ));
        return None;
    }
    #[cfg(windows)]
    if !scan_directory_has_root_volume(&modules, _root_volume, cancel, warnings) {
        return None;
    }
    if project_at(&modules).is_some() {
        return None;
    }
    let cache = modules.join(".vite");
    if exclusions.matches(&cache) {
        return None;
    }
    if mounts.contains(&cache) {
        warnings.push(format!(
            "{}: skipped filesystem boundary",
            display_path(&cache)
        ));
        return None;
    }
    if cancel.load(Ordering::Relaxed) {
        return None;
    }
    let metadata = match fs::symlink_metadata(&cache) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            warnings.push(format!("{}: {error}", display_path(&cache)));
            return None;
        }
    };
    if is_reparse_point(&metadata) {
        warnings.push(format!(
            "{}: skipped linked or reparse directory",
            display_path(&cache)
        ));
        return None;
    }
    if !metadata.is_dir() {
        return None;
    }
    if !same_device(&metadata, root_metadata) {
        warnings.push(format!(
            "{}: skipped filesystem boundary",
            display_path(&cache)
        ));
        return None;
    }
    #[cfg(windows)]
    if !scan_directory_has_root_volume(&cache, _root_volume, cancel, warnings) {
        return None;
    }
    if project_at(&cache).is_some() {
        return None;
    }
    Some(cache)
}

fn classify(project: &Project, path: &Path, name: &str) -> Vec<(&'static str, &'static str)> {
    let at_root = path.parent() == Some(project.root.as_path());
    let mut matches = Vec::new();
    if project.cargo_target_dir.as_deref() == Some(path)
        && path != project.root.join("target").as_path()
    {
        matches.push(("cargo", "review"));
    }
    if at_root && project.python && name != ".egg-info" && name.ends_with(".egg-info") {
        matches.push(("python", "review"));
    }
    match name {
        "target" if at_root => {
            if project.cargo {
                if project.cargo_target_dir_unresolved {
                    matches.push(("cargo", "review"));
                } else if project
                    .cargo_target_dir
                    .as_deref()
                    .is_none_or(|target_dir| target_dir == path)
                {
                    matches.push(("cargo", "rebuildable"));
                }
            }
            if project.maven {
                matches.push(("maven", "rebuildable"));
            }
            if project.sbt {
                matches.push(("sbt", "review"));
            }
        }
        ".zig-cache" if at_root && project.zig => matches.push(("zig", "rebuildable")),
        "zig-out" if at_root && project.zig => matches.push(("zig", "review")),
        "build" if at_root => {
            if project.go {
                matches.push(("go", "review"));
            }
            if project.python {
                matches.push(("python", "review"));
            }
            if project.flutter {
                matches.push(("flutter", "review"));
            }
            if project.gradle {
                matches.push(("gradle", "review"));
            }
            if project.ninja && is_regular(&path.join(".ninja_log")) {
                matches.push(("ninja", "review"));
            }
        }
        ".gradle" if at_root && project.gradle => matches.push(("gradle", "review")),
        "bin" if at_root => {
            if project.go {
                matches.push(("go", "review"));
            }
            if project.dotnet {
                matches.push(("dotnet", "review"));
            }
        }
        "obj" if at_root && project.dotnet => matches.push(("dotnet", "review")),
        ".hypothesis" if project.python => matches.push(("python", "review")),
        ".tox" | ".nox" if at_root && project.python => matches.push(("python", "review")),
        "dist" if at_root && project.python => matches.push(("python", "review")),
        ".pytype" if project.python => matches.push(("python", "review")),
        ".ruff_cache" if project.python => matches.push(("python", "review")),
        "__pycache__" | ".pytest_cache" | ".mypy_cache" if project.python => {
            matches.push(("python", "rebuildable"))
        }
        ".dart_tool" if at_root && project.flutter => matches.push(("dart", "rebuildable")),
        ".next" | ".nuxt" | ".parcel-cache" if at_root && project.javascript => {
            matches.push(("javascript", "review"))
        }
        "coverage"
            if at_root
                && project.javascript
                && ["lcov.info", "coverage-final.json", "clover.xml"]
                    .iter()
                    .any(|name| is_regular(&path.join(name))) =>
        {
            matches.push(("javascript", "review"));
        }
        ".svelte-kit" if at_root && project.sveltekit => matches.push(("javascript", "review")),
        "cache"
            if project.angular
                && path
                    .parent()
                    .is_some_and(|parent| parent == project.root.join(".angular")) =>
        {
            matches.push(("javascript", "review"));
        }
        ".vite"
            if project.javascript
                && path
                    .parent()
                    .is_some_and(|parent| parent == project.root.join("node_modules")) =>
        {
            matches.push(("javascript", "review"));
        }
        _ => {}
    }
    if project.cmake && is_regular(&path.join("CMakeCache.txt")) {
        matches.push(("cmake", "review"));
    }
    if project.meson
        && fs::symlink_metadata(path.join("meson-private")).is_ok_and(|meta| meta.is_dir())
        && is_regular(&path.join("meson-private/coredata.dat"))
    {
        matches.push(("meson", "review"));
    }
    matches
}

fn manifest_for(project: &Project, ecosystem: &str) -> Option<PathBuf> {
    let names: &[&str] = match ecosystem {
        "cargo" => &["Cargo.toml"],
        "go" => &["go.work", "go.mod"],
        "zig" => &["build.zig"],
        "maven" => &["pom.xml"],
        "sbt" => &["build.sbt"],
        "gradle" => &["build.gradle", "build.gradle.kts"],
        "cmake" => &["CMakeLists.txt"],
        "meson" => &["meson.build"],
        "ninja" => &["build.ninja"],
        "dart" | "flutter" => &["pubspec.yaml"],
        "python" => &[
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "requirements.txt",
        ],
        "javascript" => &["package.json"],
        "dotnet" => {
            let mut manifests = fs::read_dir(&project.root)
                .ok()?
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|path| is_dotnet_project_file(path) && is_regular(path))
                .take(2);
            let first = manifests.next()?;
            return if manifests.next().is_none() {
                Some(first)
            } else {
                None
            };
        }
        _ => return None,
    };
    names
        .iter()
        .map(|name| project.root.join(name))
        .find(|path| is_regular(path))
}

fn snapshot(project: &Project, target: &Path, ecosystem: &str) -> Option<ArtifactSnapshot> {
    if ecosystem == "cargo" && project.cargo_target_dir_unresolved {
        return None;
    }
    if project.root.canonicalize().ok()? != project.root || target.canonicalize().ok()? != target {
        return None;
    }
    if !target.starts_with(&project.root) || target == project.root {
        return None;
    }
    let manifest = manifest_for(project, ecosystem)?;
    Some(ArtifactSnapshot {
        project: identity(&project.root, true)?,
        manifest_identity: identity(&manifest, false)?,
        target: identity(target, true)?,
        cargo_config: match project.cargo_config.as_deref() {
            Some(path) => Some(identity_at(path)?),
            None => None,
        },
        cargo_workspace_manifest: None,
        cargo_workspace_proof: None,
        manifest,
    })
}

#[cfg(unix)]
fn same_device(meta: &fs::Metadata, root: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.dev() == root.dev()
}
#[cfg(not(unix))]
fn same_device(_: &fs::Metadata, _: &fs::Metadata) -> bool {
    true
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn decode_macos_mount_name(bytes: &[u8]) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .context("macOS mount name is not NUL-terminated")?;
    let mount = PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..end]));
    if !mount.is_absolute() {
        bail!("macOS mount name is not absolute");
    }
    Ok(mount)
}

#[cfg(target_os = "macos")]
fn macos_mount_point(path: &Path) -> Result<PathBuf> {
    let stat = rustix::fs::statfs(path)
        .with_context(|| format!("inspect filesystem mount for {}", display_path(path)))?;
    let bytes = stat
        .f_mntonname
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    decode_macos_mount_name(&bytes)
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn warn_if_mount_scan_cancelled(
    path: &Path,
    cancel: &AtomicBool,
    warnings: &mut Vec<String>,
) -> bool {
    if cancel.load(Ordering::Relaxed) {
        warnings.push(format!(
            "{}: scan cancelled during mount inspection",
            display_path(path)
        ));
        true
    } else {
        false
    }
}

#[cfg(target_os = "macos")]
// shortcut: path-based statfs checks can race concurrent remounts; keep macOS scans inspection-only.
fn macos_mount_matches_root(
    path: &Path,
    root_mount: Option<&Path>,
    cancel: &AtomicBool,
    warnings: &mut Vec<String>,
) -> bool {
    if warn_if_mount_scan_cancelled(path, cancel, warnings) {
        return false;
    }
    let Some(root_mount) = root_mount else {
        warnings.push(format!(
            "{}: root mount identity unavailable; skipped",
            display_path(path)
        ));
        return false;
    };
    let mount = match macos_mount_point(path) {
        Ok(mount) => mount,
        Err(error) => {
            if !warn_if_mount_scan_cancelled(path, cancel, warnings) {
                warnings.push(format!(
                    "{}: mount identity unavailable; skipped: {error:#}",
                    display_path(path)
                ));
            }
            return false;
        }
    };
    if warn_if_mount_scan_cancelled(path, cancel, warnings) {
        return false;
    }
    if is_macos_mount_boundary(root_mount, &mount) {
        warnings.push(format!(
            "{}: skipped filesystem boundary",
            display_path(path)
        ));
        false
    } else {
        true
    }
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn is_macos_mount_boundary(root_mount: &Path, current_mount: &Path) -> bool {
    root_mount != current_mount
}

#[cfg(any(windows, test))]
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u64 = 0x400;
#[cfg(windows)]
const WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const WINDOWS_FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
#[cfg(windows)]
const WINDOWS_FILE_READ_ATTRIBUTES: u32 = 0x0080;

#[cfg(windows)]
fn windows_volume(path: &Path) -> Result<u64> {
    use std::os::windows::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options
        .access_mode(WINDOWS_FILE_READ_ATTRIBUTES)
        .custom_flags(WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT | WINDOWS_FILE_FLAG_BACKUP_SEMANTICS);
    let handle = options
        .open(path)
        .with_context(|| format!("open {} for volume inspection", display_path(path)))?;
    let information = winapi_util::file::information(&handle)?;
    if information.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("{} is a Windows reparse point", display_path(path));
    }
    Ok(information.volume_serial_number())
}

#[cfg(any(windows, test))]
fn windows_volume_matches(current: Option<u64>, root: Option<u64>) -> bool {
    matches!((current, root), (Some(current), Some(root)) if current == root)
}

#[cfg(any(windows, test))]
fn has_windows_reparse_attribute(attributes: u64) -> bool {
    attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn windows_file_link_count(path: &Path, expected: &fs::Metadata) -> Result<u64> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    let mut options = fs::OpenOptions::new();
    options
        .access_mode(WINDOWS_FILE_READ_ATTRIBUTES)
        .custom_flags(
            WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT | winsafe::co::FILE_FLAG::OPEN_NO_RECALL.raw(),
        );
    // shortcut: this informational scan cannot bind the path lookup to a prior directory handle.
    let file = options
        .open(path)
        .with_context(|| format!("open {} for hard-link inspection", display_path(path)))?;
    let actual = file.metadata()?;
    let information = winapi_util::file::information(&file)?;
    if !actual.is_file()
        || is_reparse_point(&actual)
        || has_windows_reparse_attribute(information.file_attributes())
        || actual.file_size() != expected.file_size()
        || actual.file_attributes() != expected.file_attributes()
    {
        bail!("file changed or became a reparse point during inspection");
    }
    Ok(information.number_of_links())
}

#[cfg(windows)]
fn same_windows_volume(path: &Path, root_volume: Option<u64>) -> bool {
    let Some(root_volume) = root_volume else {
        return false;
    };
    windows_volume(path).is_ok_and(|volume| windows_volume_matches(Some(volume), Some(root_volume)))
}

#[cfg(windows)]
fn scan_directory_has_root_volume(
    path: &Path,
    root_volume: Option<u64>,
    cancel: &AtomicBool,
    warnings: &mut Vec<String>,
) -> bool {
    if cancel.load(Ordering::Relaxed) {
        return false;
    }
    let matches = same_windows_volume(path, root_volume);
    if cancel.load(Ordering::Relaxed) {
        return false;
    }
    if !matches {
        warnings.push(format!(
            "{}: skipped directory because its volume differs or could not be verified",
            display_path(path)
        ));
    }
    matches
}

#[cfg(windows)]
fn is_reparse_point(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    has_windows_reparse_attribute(meta.file_attributes() as u64)
}

#[cfg(not(windows))]
fn is_reparse_point(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

fn children(path: &Path, cancel: &AtomicBool, warnings: &mut Vec<String>) -> Vec<PathBuf> {
    if cancel.load(Ordering::Relaxed) {
        warnings.push(format!(
            "{}: directory listing cancelled",
            display_path(path)
        ));
        return Vec::new();
    }
    match fs::read_dir(path) {
        Ok(entries) => {
            let mut children = Vec::new();
            for entry in entries {
                if cancel.load(Ordering::Relaxed) {
                    warnings.push(format!(
                        "{}: directory listing cancelled",
                        display_path(path)
                    ));
                    break;
                }
                match entry {
                    Ok(entry) => children.push(entry.path()),
                    Err(error) => warnings.push(format!("{}: {error}", display_path(path))),
                }
            }
            children
        }
        Err(e) => {
            warnings.push(format!("{}: {e}", display_path(path)));
            Vec::new()
        }
    }
}

struct Measurement {
    logical: u64,
    allocated: Option<u64>,
    modified: Option<SystemTime>,
    complete: bool,
    nested_project_marker: Option<PathBuf>,
    nested_vcs_marker: Option<PathBuf>,
    hard_link_marker: Option<PathBuf>,
    symlink_marker: Option<PathBuf>,
}

pub(crate) fn is_project_marker(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        name,
        "Cargo.toml"
            | "build.zig"
            | "build.zig.zon"
            | "go.mod"
            | "go.work"
            | "CMakeLists.txt"
            | "meson.build"
            | "build.gradle"
            | "build.gradle.kts"
            | "build.sbt"
            | "pom.xml"
            | "pubspec.yaml"
            | "pyproject.toml"
            | "setup.py"
            | "setup.cfg"
            | "requirements.txt"
            | "package.json"
            | "angular.json"
    ) || is_dotnet_project_file(path)
}

pub(crate) fn measure_directory(
    path: &Path,
    cancel: &AtomicBool,
) -> Result<(u64, Option<u64>, bool, Vec<String>)> {
    let meta = fs::symlink_metadata(path)?;
    if is_reparse_point(&meta) || !meta.is_dir() {
        bail!("cache path is not a non-symlink directory");
    }
    let canonical = path.canonicalize()?;
    #[cfg(target_os = "linux")]
    let mounts: HashSet<PathBuf> =
        crate::application::mount_points(&fs::read("/proc/self/mountinfo")?)?
            .into_iter()
            .filter(|mount| mount != &canonical)
            .collect();
    #[cfg(not(target_os = "linux"))]
    let mounts: HashSet<PathBuf> = HashSet::new();
    let mut warnings = Vec::new();
    #[cfg(target_os = "macos")]
    let mount_root = match macos_mount_point(&canonical) {
        Ok(mount) => Some(mount),
        Err(error) => {
            warnings.push(format!(
                "{}: mount identity unavailable: {error:#}",
                display_path(&canonical)
            ));
            None
        }
    };
    #[cfg(not(target_os = "macos"))]
    let mount_root: Option<PathBuf> = None;
    let measurement = size(
        &canonical,
        &meta,
        (&mounts, mount_root.as_deref()),
        &Exclusions::default(),
        cancel,
        &mut |_| {},
        &mut warnings,
    );
    #[cfg(windows)]
    // shortcut: path-based enumeration can race directory replacement; upgrade to handle-relative traversal before reporting complete cache sizes.
    warnings.push(
        "Windows cache size is a partial estimate because path-based traversal cannot rule out concurrent directory replacement".into(),
    );
    Ok((
        measurement.logical,
        measurement.allocated,
        measurement.complete && !cfg!(windows),
        warnings,
    ))
}

fn size<F: FnMut(&Path)>(
    path: &Path,
    root_meta: &fs::Metadata,
    mount_info: (&HashSet<PathBuf>, Option<&Path>),
    exclusions: &Exclusions,
    cancel: &AtomicBool,
    progress: &mut F,
    warnings: &mut Vec<String>,
) -> Measurement {
    let (mounts, mount_root) = mount_info;
    #[cfg(not(target_os = "macos"))]
    let _ = mount_root;
    let before = warnings.len();
    let mut bytes = 0u64;
    #[cfg(unix)]
    let mut allocated = 0u64;
    #[cfg(unix)]
    let mut inodes = HashSet::new();
    let mut latest = None::<SystemTime>;
    let mut timestamps_complete = true;
    let mut nested_project_marker: Option<PathBuf> = None;
    let mut nested_vcs_marker: Option<PathBuf> = None;
    let mut symlink_marker: Option<PathBuf> = None;
    #[cfg(unix)]
    let mut hard_link_marker: Option<PathBuf> = None;
    #[cfg(windows)]
    let mut hard_link_marker: Option<PathBuf> = None;
    #[cfg(not(any(unix, windows)))]
    let hard_link_marker: Option<PathBuf> = None;
    #[cfg(windows)]
    let root_volume = windows_volume(path).ok();
    #[cfg(windows)]
    if root_volume.is_none() {
        warnings.push(format!(
            "{}: volume identity unavailable; skipped",
            display_path(path)
        ));
    }
    let mut stack = vec![path.to_owned()];
    while let Some(path) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            warnings.push("scan cancelled during size estimation".into());
            break;
        }
        if exclusions.matches(&path) {
            warnings.push(format!(
                "{}: excluded from size estimate",
                display_path(&path)
            ));
            continue;
        }
        if mounts.contains(&path) {
            warnings.push(format!("{}: skipped mount point", display_path(&path)));
            continue;
        }
        if path
            .file_name()
            .is_some_and(|name| matches!(name.to_str(), Some(".git" | ".hg" | ".svn")))
            && nested_vcs_marker
                .as_ref()
                .is_none_or(|current| path < *current)
        {
            nested_vcs_marker = Some(path.clone());
        }
        match fs::symlink_metadata(&path) {
            Ok(meta) if is_reparse_point(&meta) => {
                if symlink_marker
                    .as_ref()
                    .is_none_or(|current| path < *current)
                {
                    symlink_marker = Some(path.clone());
                }
                #[cfg(windows)]
                warnings.push(format!(
                    "{}: skipped Windows reparse point",
                    display_path(&path)
                ));
                match meta.modified() {
                    Ok(modified) => {
                        latest = Some(latest.map_or(modified, |previous| previous.max(modified)))
                    }
                    Err(_) => timestamps_complete = false,
                }
            }
            #[cfg(windows)]
            Ok(meta) if meta.is_dir() && !same_windows_volume(&path, root_volume) => {
                warnings.push(format!(
                    "{}: skipped directory because its volume differs or could not be verified",
                    display_path(&path)
                ));
            }
            Ok(meta) if !same_device(&meta, root_meta) => warnings.push(format!(
                "{}: skipped filesystem boundary",
                display_path(&path)
            )),
            Ok(meta) if meta.is_dir() || meta.is_file() => {
                match meta.modified() {
                    Ok(modified) => {
                        latest = Some(latest.map_or(modified, |previous| previous.max(modified)))
                    }
                    Err(_) => timestamps_complete = false,
                }
                if meta.is_file() {
                    if is_project_marker(&path)
                        && nested_project_marker
                            .as_ref()
                            .is_none_or(|current| path < *current)
                    {
                        nested_project_marker = Some(path.clone());
                    }
                    bytes = bytes.saturating_add(meta.len());
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        if meta.nlink() > 1
                            && hard_link_marker
                                .as_ref()
                                .is_none_or(|current| path < *current)
                        {
                            hard_link_marker = Some(path.clone());
                        }
                        if inodes.insert((meta.dev(), meta.ino())) {
                            allocated = allocated.saturating_add(meta.blocks().saturating_mul(512));
                        }
                    }
                    #[cfg(windows)]
                    match windows_file_link_count(&path, &meta) {
                        Ok(links)
                            if links > 1
                                && hard_link_marker
                                    .as_ref()
                                    .is_none_or(|current| path < *current) =>
                        {
                            hard_link_marker = Some(path.clone());
                        }
                        Ok(_) => {}
                        Err(error) => warnings.push(format!(
                            "{}: hard-link status unavailable: {error:#}",
                            display_path(&path)
                        )),
                    }
                    continue;
                }
                #[cfg(target_os = "macos")]
                if !macos_mount_matches_root(&path, mount_root, cancel, warnings) {
                    continue;
                }
                progress(&path);
                if cancel.load(Ordering::Relaxed) {
                    warnings.push("scan cancelled during size estimation".into());
                    break;
                }
                let entries = children(&path, cancel, warnings);
                #[cfg(target_os = "macos")]
                if !macos_mount_matches_root(&path, mount_root, cancel, warnings) {
                    continue;
                }
                #[cfg(windows)]
                if !same_windows_volume(&path, root_volume) {
                    warnings.push(format!(
                        "{}: directory volume changed or could not be verified during size estimation",
                        display_path(&path)
                    ));
                    continue;
                }
                stack.extend(entries);
            }
            Ok(_) => warnings.push(format!("{}: special file skipped", display_path(&path))),
            Err(err) => warnings.push(format!("{}: {err}", display_path(&path))),
        }
    }
    let complete = before == warnings.len();
    Measurement {
        logical: bytes,
        #[cfg(unix)]
        allocated: Some(allocated),
        #[cfg(not(unix))]
        allocated: None,
        modified: if complete && timestamps_complete {
            latest
        } else {
            None
        },
        complete,
        nested_project_marker,
        nested_vcs_marker,
        hard_link_marker,
        symlink_marker,
    }
}

pub fn parse_age(value: &str) -> std::result::Result<Duration, String> {
    let unit = value
        .chars()
        .last()
        .ok_or_else(|| "provide an age such as 30d".to_owned())?;
    let number = value.strip_suffix(unit).unwrap_or_default();
    let multiplier = match unit {
        'h' => 3600,
        'd' => 86400,
        'w' => 604800,
        _ => return Err("use an age such as 24h, 30d, or 4w".into()),
    };
    let amount = number
        .parse::<u64>()
        .map_err(|_| "age must be a nonnegative integer".to_owned())?;
    amount
        .checked_mul(multiplier)
        .map(Duration::from_secs)
        .ok_or_else(|| "age is too large".into())
}

pub fn scan(roots: &[PathBuf]) -> Result<ScanReport> {
    scan_with(roots, &[], &AtomicBool::new(false), |_| {})
}

/// Scan selected roots with up to four workers; progress callbacks run serially on worker threads.
/// Exclusions are absolute or relative to each root.
pub fn scan_with<F: FnMut(&Path) + Send>(
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    cancel: &AtomicBool,
    progress: F,
) -> Result<ScanReport> {
    scan_with_age(roots, exclusions, None, cancel, progress)
}

pub fn scan_with_age<F: FnMut(&Path) + Send>(
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    older_than: Option<Duration>,
    cancel: &AtomicBool,
    progress: F,
) -> Result<ScanReport> {
    scan_with_policy(roots, exclusions, older_than, None, cancel, progress)
}

pub fn scan_with_policy<F: FnMut(&Path) + Send>(
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    older_than: Option<Duration>,
    enabled: Option<&[Ecosystem]>,
    cancel: &AtomicBool,
    mut progress: F,
) -> Result<ScanReport> {
    if roots.is_empty() {
        bail!("provide at least one workspace root");
    }
    if exclusions.iter().any(|path| {
        path.as_os_str().is_empty()
            || path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
    }) {
        bail!("exclusions must be nonempty paths without '..' components");
    }
    #[cfg(target_os = "linux")]
    let mounts: HashSet<PathBuf> = crate::application::mount_points(
        &fs::read("/proc/self/mountinfo").context("read mount table before scanning")?,
    )?
    .into_iter()
    .collect();
    // shortcut: macOS path-based statfs checks can miss a concurrent remount during scanning.
    #[cfg(not(target_os = "linux"))]
    let mounts: HashSet<PathBuf> = HashSet::new();
    let mut normalized_roots = Vec::new();
    for root in roots {
        let original = fs::symlink_metadata(root)
            .with_context(|| format!("inspect scan root {}", display_path(root)))?;
        if original.file_type().is_symlink() || !original.is_dir() {
            bail!(
                "scan root must be a non-symlink directory: {}",
                display_path(root)
            );
        }
        let root = root
            .canonicalize()
            .with_context(|| format!("resolve scan root {}", display_path(root)))?;
        if root.parent().is_none() {
            bail!("refusing to scan a filesystem root");
        }
        if !normalized_roots.contains(&root) {
            normalized_roots.push(root);
        }
    }
    let excluded = Exclusions::new(&normalized_roots, exclusions)?;
    struct Job {
        root: usize,
        path: PathBuf,
        inherited: Vec<Project>,
    }
    struct Queue {
        pending: VecDeque<Job>,
        active: usize,
    }
    let root_metadata = normalized_roots
        .iter()
        .map(fs::metadata)
        .collect::<std::io::Result<Vec<_>>>()?;
    #[cfg(target_os = "macos")]
    let (root_mount_points, root_mount_warnings): (Vec<Option<PathBuf>>, Vec<String>) = {
        let mut warnings = Vec::new();
        let mount_points = normalized_roots
            .iter()
            .map(|root| {
                if cancel.load(Ordering::Relaxed) {
                    return None;
                }
                match macos_mount_point(root) {
                    Ok(mount) => Some(mount),
                    Err(error) => {
                        warnings.push(format!(
                            "{}: mount identity unavailable: {error:#}",
                            display_path(root)
                        ));
                        None
                    }
                }
            })
            .collect();
        (mount_points, warnings)
    };
    #[cfg(not(target_os = "macos"))]
    let root_mount_points: Vec<Option<PathBuf>> = vec![None; normalized_roots.len()];
    #[cfg(not(target_os = "macos"))]
    let root_mount_warnings: Vec<String> = Vec::new();
    #[cfg(windows)]
    let root_volumes = normalized_roots
        .iter()
        .map(|root| {
            (!cancel.load(Ordering::Relaxed))
                .then(|| windows_volume(root).ok())
                .flatten()
        })
        .collect::<Vec<_>>();
    let pending = normalized_roots
        .iter()
        .enumerate()
        .map(|(root, path)| Job {
            root,
            path: path.clone(),
            inherited: Vec::new(),
        })
        .collect();
    let queue = (Mutex::new(Queue { pending, active: 0 }), Condvar::new());
    let progress = Mutex::new(&mut progress);
    let failed = AtomicBool::new(false);
    let now = SystemTime::now();
    let mut report = ScanReport {
        roots: normalized_roots.clone(),
        candidates: vec![],
        warnings: vec![],
        cancelled: false,
    };
    #[cfg(target_os = "macos")]
    report.warnings.push(
        "macOS mount boundaries use path-based statfs checks; a concurrent remount can affect scan estimates".into(),
    );
    report.warnings.extend(root_mount_warnings);
    let worker_results = std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..4 {
            let queue = &queue;
            let progress = &progress;
            let roots = &normalized_roots;
            let root_mount_points = &root_mount_points;
            let metadata = &root_metadata;
            #[cfg(windows)]
            let root_volumes = &root_volumes;
            let excluded = &excluded;
            let mounts = &mounts;
            let failed = &failed;
            workers.push(scope.spawn(move || {
                let mut candidates = Vec::new();
                let mut warnings = Vec::new();
                let mut notify = |path: &Path| {
                    let mut callback = progress.lock().unwrap_or_else(|err| err.into_inner());
                    (*callback)(path);
                };
                loop {
                    let job = {
                        let (lock, ready) = queue;
                        let mut state = lock.lock().unwrap_or_else(|err| err.into_inner());
                        loop {
                            if cancel.load(Ordering::Relaxed) || failed.load(Ordering::Relaxed) {
                                return Ok((candidates, warnings));
                            }
                            if let Some(job) = state.pending.pop_front() {
                                state.active += 1;
                                break job;
                            }
                            if state.active == 0 {
                                return Ok((candidates, warnings));
                            }
                            state = ready.wait(state).unwrap_or_else(|err| err.into_inner());
                        }
                    };
                    let children_to_visit =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Vec<Job> {
                            let path = &job.path;
                            if excluded.matches(path) {
                                return vec![];
                            }
                            let meta = match fs::symlink_metadata(path) {
                                Ok(meta) => meta,
                                Err(err) => {
                                    warnings.push(format!("{}: {err}", display_path(path)));
                                    return vec![];
                                }
                            };
                            if is_reparse_point(&meta) {
                                #[cfg(windows)]
                                warnings.push(format!(
                                    "{}: skipped Windows reparse point",
                                    display_path(path)
                                ));
                                return vec![];
                            }
                            if !meta.is_dir() {
                                return vec![];
                            }
                            if !same_device(&meta, &metadata[job.root])
                                || (path != &roots[job.root] && mounts.contains(path))
                            {
                                warnings.push(format!(
                                    "{}: skipped filesystem boundary",
                                    display_path(path)
                                ));
                                return vec![];
                            }
                            #[cfg(target_os = "macos")]
                            if !macos_mount_matches_root(
                                path,
                                root_mount_points[job.root].as_deref(),
                                cancel,
                                &mut warnings,
                            ) {
                                return vec![];
                            }
                            #[cfg(windows)]
                            // shortcut: path traversal can race volume replacement; use handles before scan results authorize cleanup.
                            if !scan_directory_has_root_volume(
                                path,
                                root_volumes[job.root],
                                cancel,
                                &mut warnings,
                            ) {
                                return vec![];
                            }
                            notify(path);
                            if cancel.load(Ordering::Relaxed) {
                                return vec![];
                            }
                            let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
                            if matches!(
                                name,
                                ".git" | ".hg" | ".svn" | "node_modules" | ".venv" | "venv"
                            ) {
                                return vec![];
                            }
                            let project_here = project_at(path);
                            if project_here.as_ref().is_some_and(|project| {
                                project.cargo_target_dir_unresolved
                            }) && enabled.is_none_or(|enabled| {
                                enabled.contains(&Ecosystem::Cargo)
                            }) {
                                warnings.push(format!(
                                    "{}: Cargo target-dir configuration or a known environment override is unresolved; Cargo target directories are review-only",
                                    display_path(path)
                                ));
                            }
                            if project_here.is_none()
                                && let Some((project, matches)) =
                                    job.inherited.iter().rev().find_map(|project| {
                                        let nested_project = job.inherited.iter().any(|nested| {
                                            nested.root != project.root
                                                && nested.root.starts_with(&project.root)
                                                && path.starts_with(&nested.root)
                                        });
                                        if nested_project && (project.cmake || project.meson) {
                                            return None;
                                        }
                                        let matches = classify(project, path, name);
                                        (!matches.is_empty()).then_some((project, matches))
                                    })
                            {
                                if matches.len() > 1 {
                                    // shortcut: known overlapping signatures stay blocked until ownership can be attributed per entry.
                                    let ecosystems = matches
                                        .iter()
                                        .map(|(ecosystem, _)| *ecosystem)
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    warnings.push(format!(
                                        "{}: ambiguous artifact match ({ecosystems}); shared contents cannot be assigned to one ecosystem, so the target and its subtree were skipped",
                                        display_path(path)
                                    ));
                                    return vec![];
                                }
                                let (ecosystem, classification) = matches[0];
                                if enabled.is_some_and(|enabled| {
                                    !enabled.iter().any(|item| item.as_str() == ecosystem)
                                }) {
                                    warnings.push(format!(
                                        "{}: subtree skipped because {ecosystem} artifacts are disabled; nested projects may not be detected",
                                        display_path(path)
                                    ));
                                    return vec![];
                                }
                                let candidate_snapshot = snapshot(project, path, ecosystem);
                                let measurement = size(
                                    path,
                                    &metadata[job.root],
                                    (mounts, root_mount_points[job.root].as_deref()),
                                    excluded,
                                    cancel,
                                    &mut notify,
                                    &mut warnings,
                                );
                                if let Some(age) = older_than {
                                    match measurement
                                        .modified
                                        .and_then(|time| now.duration_since(time).ok())
                                    {
                                        Some(elapsed) if elapsed >= age => {}
                                        Some(_) => return vec![],
                                        None => {
                                            warnings.push(format!(
                                                "{}: age could not be verified",
                                                display_path(path)
                                            ));
                                            return vec![];
                                        }
                                    }
                                }
                                let modified_unix = measurement
                                    .modified
                                    .and_then(|v| v.duration_since(UNIX_EPOCH).ok())
                                    .map(|v| v.as_secs());
                                candidates.push(Candidate {
                                    ecosystem,
                                    project_root: project.root.clone(),
                                    target: path.clone(),
                                    logical_bytes: measurement.logical,
                                    allocated_bytes: measurement.allocated,
                                    size_complete: measurement.complete,
                                    modified_unix,
                                    classification,
                                    operation: "inspection only",
                                    reproduction_warning: if ecosystem == "cargo"
                                        && project.cargo_target_dir_unresolved
                                        && path == project.root.join("target").as_path()
                                    {
                                        Some("Cargo's project-local target-dir could not be resolved safely; this directory is shown for review only.")
                                    } else if ecosystem == "cargo"
                                        && project.cargo_target_dir.as_deref() == Some(path)
                                        && path != project.root.join("target").as_path()
                                    {
                                        Some("Cargo's project-local target-dir points here, but this custom directory may contain user data; Upkit only inventories it for review.")
                                    } else {
                                        reproduction_warning_for(ecosystem, path)
                                    },
                                    cargo_workspace: None,
                                    nested_project_marker: measurement.nested_project_marker,
                                    nested_vcs_marker: measurement.nested_vcs_marker,
                                    hard_link_marker: measurement.hard_link_marker,
                                    symlink_marker: measurement.symlink_marker,
                                    snapshot: candidate_snapshot,
                                });
                                return vec![];
                            }
                            #[cfg(windows)]
                            let root_volume = root_volumes[job.root];
                            #[cfg(not(windows))]
                            let root_volume = None;
                            if let Some(project) = project_here.as_ref()
                                && enabled.is_none_or(|enabled| {
                                    enabled.iter().any(|item| item == &Ecosystem::Javascript)
                                })
                                && let Some(vite_cache) = vite_cache_at(
                                    project,
                                    path,
                                    (&metadata[job.root], root_volume),
                                    excluded,
                                    mounts,
                                    cancel,
                                    &mut warnings,
                                )
                            {
                                let measurement = size(
                                    &vite_cache,
                                    &metadata[job.root],
                                    (mounts, root_mount_points[job.root].as_deref()),
                                    excluded,
                                    cancel,
                                    &mut notify,
                                    &mut warnings,
                                );
                                let age_matches = match (
                                    older_than,
                                    measurement
                                        .modified
                                        .and_then(|time| now.duration_since(time).ok()),
                                ) {
                                    (None, _) => true,
                                    (Some(age), Some(elapsed)) => elapsed >= age,
                                    (Some(_), None) => {
                                        warnings.push(format!(
                                            "{}: age could not be verified",
                                            display_path(&vite_cache)
                                        ));
                                        false
                                    }
                                };
                                if age_matches {
                                    let candidate_snapshot =
                                        snapshot(project, &vite_cache, "javascript");
                                    candidates.push(Candidate {
                                        ecosystem: "javascript",
                                        project_root: project.root.clone(),
                                        target: vite_cache.clone(),
                                        logical_bytes: measurement.logical,
                                        allocated_bytes: measurement.allocated,
                                        size_complete: measurement.complete,
                                        modified_unix: measurement
                                            .modified
                                            .and_then(|v| v.duration_since(UNIX_EPOCH).ok())
                                            .map(|v| v.as_secs()),
                                        classification: "review",
                                        operation: "inspection only",
                                        reproduction_warning: reproduction_warning_for(
                                            "javascript",
                                            &vite_cache,
                                        ),
                                        cargo_workspace: None,
                                        nested_project_marker: measurement.nested_project_marker,
                                        nested_vcs_marker: measurement.nested_vcs_marker,
                                        hard_link_marker: measurement.hard_link_marker,
                                        symlink_marker: measurement.symlink_marker,
                                        snapshot: candidate_snapshot,
                                    });
                                }
                            }
                            let mut projects = job.inherited;
                            if let Some(project) = project_here {
                                projects.push(project);
                            }
                            let children = children(path, cancel, &mut warnings);
                            #[cfg(target_os = "macos")]
                            if !macos_mount_matches_root(
                                path,
                                root_mount_points[job.root].as_deref(),
                                cancel,
                                &mut warnings,
                            ) {
                                return vec![];
                            }
                            children
                                .into_iter()
                                .map(|child| Job {
                                    root: job.root,
                                    path: child,
                                    inherited: projects.clone(),
                                })
                                .collect()
                        }));
                    let (lock, ready) = queue;
                    let mut state = lock.lock().unwrap_or_else(|err| err.into_inner());
                    state.active -= 1;
                    match children_to_visit {
                        Ok(children)
                            if !cancel.load(Ordering::Relaxed)
                                && !failed.load(Ordering::Relaxed) =>
                        {
                            state.pending.extend(children)
                        }
                        Ok(_) => {}
                        Err(_) => {
                            failed.store(true, Ordering::Relaxed);
                            ready.notify_all();
                            return Err(anyhow::anyhow!("scan worker panicked"));
                        }
                    }
                    ready.notify_all();
                }
            }));
        }
        workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("scan worker panicked"))?
            })
            .collect::<Result<Vec<_>>>()
    })?;
    for (candidates, warnings) in worker_results {
        report.candidates.extend(candidates);
        report.warnings.extend(warnings);
    }
    report.warnings.sort();
    report.candidates.sort_by(|a, b| a.target.cmp(&b.target));
    report.candidates.dedup_by(|a, b| a.target == b.target);
    let mut workspaces = crate::cargo_workspace::Inspector::new(&normalized_roots);
    for candidate in &mut report.candidates {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if candidate.ecosystem == "cargo" {
            let workspace = workspaces.inspect(
                &candidate.project_root,
                |path| excluded.matches(path),
                cancel,
            );
            let workspace_manifest_identity = workspace
                .workspace_root
                .as_deref()
                .and_then(|root| identity_at(&root.join("Cargo.toml")));
            let workspace_proof = workspace.proof().map(str::to_owned);
            let missing_workspace_identity =
                workspace.workspace_root.is_some() && workspace_manifest_identity.is_none();
            if let Some(snapshot) = candidate.snapshot.as_mut() {
                snapshot.cargo_workspace_manifest = workspace_manifest_identity;
                snapshot.cargo_workspace_proof = workspace_proof.clone();
            }
            if missing_workspace_identity || workspace_proof.is_none() {
                candidate.snapshot = None;
            }
            if candidate.classification == "rebuildable"
                && !matches!(
                    workspace.status,
                    "workspace_manifest" | "standalone_package"
                )
            {
                candidate.classification = "review";
                candidate.reproduction_warning = Some(match workspace.status {
                    "member_pattern_match" => {
                        "Cargo workspace member targets are review-only because Cargo may place their outputs under the workspace root."
                    }
                    "exclude_pattern_match" => {
                        "Cargo explicitly excluded packages remain review-only because the workspace exclusion does not establish output ownership."
                    }
                    "manifest_unavailable" | "ancestor_limit_reached" | "outside_scan_scope" => {
                        "Cargo workspace ancestry could not be inspected completely; this target is review-only."
                    }
                    _ => {
                        "Cargo workspace membership could not be confirmed safely; this target is review-only."
                    }
                });
            }
            candidate.cargo_workspace = Some(workspace);
        }
    }
    report.cancelled = cancel.load(Ordering::Relaxed);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn macos_mount_names_decode_paths_and_reject_unverified_values() {
        use std::os::unix::ffi::OsStrExt;

        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().to_owned();
        let child_mount = root.join("mounted");
        let encode = |path: &Path| {
            let mut bytes = path.as_os_str().as_bytes().to_vec();
            bytes.push(0);
            bytes
        };
        let root_mount = decode_macos_mount_name(&encode(&root)).unwrap();
        let same_mount = decode_macos_mount_name(&encode(&root)).unwrap();
        let nested_mount = decode_macos_mount_name(&encode(&child_mount)).unwrap();

        assert_eq!(root_mount, root);
        assert!(!is_macos_mount_boundary(&root_mount, &same_mount));
        assert!(is_macos_mount_boundary(&root_mount, &nested_mount));
        assert!(decode_macos_mount_name(b"relative\0").is_err());
        assert!(decode_macos_mount_name(root.as_os_str().as_bytes()).is_err());

        let mut warnings = Vec::new();
        assert!(warn_if_mount_scan_cancelled(
            &root,
            &AtomicBool::new(true),
            &mut warnings,
        ));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("scan cancelled during mount inspection"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn package_declares_only_bounded_dependency_manifests() {
        let fixture = tempfile::tempdir().unwrap();
        let project = fixture.path().join("project");
        fs::create_dir(&project).unwrap();
        let manifest = project.join("package.json");

        fs::write(&manifest, br#"{"devDependencies":{"@sveltejs/kit":"^2"}}"#).unwrap();
        #[cfg(target_os = "linux")]
        if package_manifest(&manifest).is_none() {
            eprintln!("Linux openat2 unavailable; package manifest reader test skipped");
            return;
        }
        assert!(package_declares(&project, "@sveltejs/kit"));

        fs::write(&manifest, br#"{"scripts":{"@sveltejs/kit":"^2"}}"#).unwrap();
        assert!(!package_declares(&project, "@sveltejs/kit"));
        fs::write(&manifest, b"not json").unwrap();
        assert!(!package_declares(&project, "@sveltejs/kit"));
        fs::write(&manifest, vec![b' '; MAX_PACKAGE_MANIFEST_BYTES + 1]).unwrap();
        assert!(!package_declares(&project, "@sveltejs/kit"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_package_manifest_rejects_final_and_ancestor_reparse_points() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let fixture = tempfile::tempdir().unwrap();
        let project = fixture.path().join("project");
        fs::create_dir(&project).unwrap();
        let manifest = project.join("package.json");
        fs::write(&manifest, br#"{"dependencies":{"@sveltejs/kit":"^2"}}"#).unwrap();

        let file_link_project = fixture.path().join("file-link-project");
        fs::create_dir(&file_link_project).unwrap();
        if let Err(error) = symlink_file(&manifest, file_link_project.join("package.json")) {
            if error.raw_os_error() == Some(1314) {
                eprintln!("Windows symlink privilege unavailable; reparse reader test skipped");
                return;
            }
            panic!("create package manifest symlink fixture: {error}");
        }
        assert!(!package_declares(&file_link_project, "@sveltejs/kit"));

        let directory_link = fixture.path().join("directory-link");
        if let Err(error) = symlink_dir(&project, &directory_link) {
            if error.raw_os_error() == Some(1314) {
                eprintln!("Windows symlink privilege unavailable; ancestor reparse check skipped");
                return;
            }
            panic!("create project directory symlink fixture: {error}");
        }
        assert!(!package_declares(&directory_link, "@sveltejs/kit"));
    }

    #[test]
    fn cargo_inherited_and_home_configs_make_default_target_unresolved() {
        let fixture = tempfile::tempdir().unwrap();
        let base = fixture.path().canonicalize().unwrap();
        let home = base.join("cargo-home");
        let workspace = base.join("workspace");
        let project = workspace.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("Cargo.toml"), "[workspace]\n").unwrap();

        assert_eq!(
            cargo_target_dir_with_home(&project, &home),
            (None, None, false)
        );

        let ancestor_config = workspace.join(".cargo/config");
        fs::create_dir_all(ancestor_config.parent().unwrap()).unwrap();
        fs::write(&ancestor_config, "not parsed by the target resolver").unwrap();
        assert_eq!(
            cargo_target_dir_with_home(&project, &home),
            (None, None, true),
            "an ancestor config added after a preview makes the target unresolved"
        );

        fs::remove_file(&ancestor_config).unwrap();
        fs::remove_dir(ancestor_config.parent().unwrap()).unwrap();
        fs::create_dir_all(&home).unwrap();
        let global_config = home.join("config.toml");
        fs::write(&global_config, "also intentionally not parsed").unwrap();
        assert_eq!(
            cargo_target_dir_with_home(&project, &home),
            (None, None, true),
            "a Cargo home config added after a preview is an unresolved override"
        );

        fs::remove_file(global_config).unwrap();
        fs::remove_dir(&home).unwrap();
        #[cfg(unix)]
        {
            let outside = fixture.path().join("outside");
            fs::create_dir(&outside).unwrap();
            std::os::unix::fs::symlink(outside, workspace.join(".cargo")).unwrap();
            assert_eq!(
                cargo_target_dir_with_home(&project, &home),
                (None, None, true),
                "an uninspectable ancestor config directory fails closed"
            );
        }
    }

    #[test]
    fn cargo_home_resolution_fails_closed_for_missing_or_relative_values() {
        use std::ffi::OsStr;

        assert!(cargo_home_directory_from(None, None).is_err());
        assert!(cargo_home_directory_from(None, Some(OsStr::new("relative-home"))).is_err());
        assert!(cargo_home_directory_from(Some(OsStr::new("relative-cargo")), None).is_err());

        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().canonicalize().unwrap();
        assert_eq!(
            cargo_home_directory_from(None, Some(home.as_os_str())).unwrap(),
            home.join(".cargo")
        );
        assert_eq!(
            cargo_home_directory_from(Some(home.as_os_str()), None).unwrap(),
            home
        );
    }

    #[cfg(unix)]
    #[test]
    fn identity_rejects_a_candidate_that_gains_a_second_ecosystem_match() {
        let fixture = tempfile::tempdir().unwrap();
        let project = fixture.path();
        let target = project.join("target");
        fs::create_dir(&target).unwrap();
        fs::write(project.join("Cargo.toml"), "[workspace]\n").unwrap();
        let mut candidate = scan(&[project.to_owned()]).unwrap().candidates.remove(0);
        assert_eq!(identity_status(&candidate), "metadata_match");

        fs::write(project.join("pom.xml"), "<project/>\n").unwrap();
        candidate.snapshot.as_mut().unwrap().project = identity(project, true).unwrap();

        assert_eq!(
            identity_status(&candidate),
            "changed_or_unavailable",
            "the saved project identity matches, so the second ecosystem match must reject it"
        );
    }

    #[test]
    fn cancelled_directory_listing_does_not_open_the_directory() {
        let fixture = tempfile::tempdir().unwrap();
        let missing = fixture.path().join("missing");
        let cancel = AtomicBool::new(true);
        let mut warnings = Vec::new();
        assert!(children(&missing, &cancel, &mut warnings).is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("directory listing cancelled"));

        cancel.store(false, Ordering::Relaxed);
        warnings.clear();
        assert!(children(&missing, &cancel, &mut warnings).is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(!warnings[0].contains("cancelled"));
    }

    #[test]
    fn windows_scan_volume_check_covers_roots_and_descendants() {
        let root_volume = Some(7);
        assert!(
            windows_volume_matches(root_volume, root_volume),
            "scan root"
        );
        assert!(
            windows_volume_matches(Some(7), root_volume),
            "same-volume descendant"
        );
        assert!(
            !windows_volume_matches(Some(8), root_volume),
            "different-volume descendant"
        );
        assert!(!windows_volume_matches(None, Some(7)));
        assert!(!windows_volume_matches(Some(7), None));
    }

    #[cfg(windows)]
    #[test]
    fn windows_scan_directory_volume_guard_rejects_unknown_and_changed_paths() {
        let fixture = tempfile::tempdir().unwrap();
        let child = fixture.path().join("child");
        fs::create_dir(&child).unwrap();
        let volume = windows_volume(fixture.path()).unwrap();
        let cancel = AtomicBool::new(false);
        let mut warnings = Vec::new();

        assert!(scan_directory_has_root_volume(
            fixture.path(),
            Some(volume),
            &cancel,
            &mut warnings,
        ));
        assert!(scan_directory_has_root_volume(
            &child,
            Some(volume),
            &cancel,
            &mut warnings,
        ));
        assert!(!scan_directory_has_root_volume(
            &child,
            Some(volume ^ 1),
            &cancel,
            &mut warnings,
        ));
        assert!(!scan_directory_has_root_volume(
            &child,
            None,
            &cancel,
            &mut warnings,
        ));

        let missing = fixture.path().join("missing");
        assert!(!scan_directory_has_root_volume(
            &missing,
            Some(volume),
            &cancel,
            &mut warnings,
        ));
        assert_eq!(warnings.len(), 3);
        assert!(
            warnings
                .iter()
                .all(|warning| warning.contains("volume differs or could not be verified"))
        );

        cancel.store(true, Ordering::Relaxed);
        warnings.clear();
        assert!(!scan_directory_has_root_volume(
            &child,
            Some(volume),
            &cancel,
            &mut warnings,
        ));
        assert!(warnings.is_empty());
    }

    #[test]
    fn windows_reparse_attributes_are_detected() {
        assert!(has_windows_reparse_attribute(0x400));
        assert!(has_windows_reparse_attribute(0x410));
        assert!(!has_windows_reparse_attribute(0x10));
    }

    #[test]
    fn unicode_paths_and_scope_keep_existing_token_serialization() {
        #[derive(Serialize)]
        struct PreviousScope<'a> {
            roots: &'a [PathBuf],
            exclusions: &'a [PathBuf],
            older_than_seconds: Option<u64>,
            enabled: Option<Vec<Ecosystem>>,
        }
        let path = PathBuf::from("/workspace/é%/target");
        assert_eq!(
            serde_json::to_vec(&JsonPath(&path)).unwrap(),
            serde_json::to_vec(&path).unwrap()
        );
        let scope = Scope {
            roots: vec![path],
            exclusions: vec![PathBuf::from("excluded")],
            older_than_seconds: Some(42),
            enabled: Some(vec![Ecosystem::Cargo]),
        };
        let previous = PreviousScope {
            roots: &scope.roots,
            exclusions: &scope.exclusions,
            older_than_seconds: scope.older_than_seconds,
            enabled: scope.enabled.clone(),
        };
        assert_eq!(
            serde_json::to_vec(&scope).unwrap(),
            serde_json::to_vec(&previous).unwrap()
        );
    }

    #[test]
    fn size_reports_skipped_mounts_as_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("file"), b"not counted").unwrap();
        let mounts = HashSet::from([nested]);
        let mut warnings = Vec::new();
        #[cfg(target_os = "macos")]
        let mount_root = Some(macos_mount_point(dir.path()).unwrap());
        #[cfg(not(target_os = "macos"))]
        let mount_root: Option<PathBuf> = None;
        let measurement = size(
            dir.path(),
            &fs::metadata(dir.path()).unwrap(),
            (&mounts, mount_root.as_deref()),
            &Exclusions::default(),
            &AtomicBool::new(false),
            &mut |_| {},
            &mut warnings,
        );
        assert_eq!(measurement.logical, 0);
        assert!(!measurement.complete);
        assert_eq!(warnings.len(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn size_skips_windows_reparse_directories() {
        use std::os::windows::fs::symlink_dir;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cache");
        let outside = dir.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"outside data").unwrap();
        if let Err(error) = symlink_dir(&outside, root.join("junction")) {
            if error.raw_os_error() == Some(1314) {
                eprintln!("SKIP: Windows symlink privilege is unavailable for reparse fixture");
                return;
            }
            panic!("unable to create temporary reparse point: {error}");
        }

        let (logical, _, complete, warnings) =
            measure_directory(&root, &AtomicBool::new(false)).unwrap();

        assert_eq!(logical, 0);
        assert!(!complete);
        assert!(warnings.iter().any(|warning| warning.contains("reparse")));
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"outside data");
    }
}

#[derive(Debug, Serialize)]
pub struct PlanItem {
    pub candidate: Candidate,
    pub selected: bool,
    pub risk: &'static str,
    pub proposed_operation: &'static str,
    pub execution_ready: bool,
    /// Metadata comparison only; it is not authorization or proof that cleanup is safe.
    pub identity_status: &'static str,
    /// Evidence from the current Git index; nested repositories are not included.
    pub git_index_status: &'static str,
    /// Limited evidence from HEAD and the index, unavailable on older Git versions.
    pub git_head_status: &'static str,
    /// Bounded history evidence for initially selected targets, not other VCS systems.
    pub git_history_status: &'static str,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    pub(crate) git_evidence_id: Option<String>,
    /// A bounded observation of same-user process handles and working directories.
    pub activity_status: &'static str,
    pub safeguards_required: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct CleanupPlan {
    #[serde(serialize_with = "serialize_paths")]
    pub roots: Vec<PathBuf>,
    pub items: Vec<PlanItem>,
    pub warnings: Vec<String>,
}

fn identity_status(candidate: &Candidate) -> &'static str {
    let Some(expected) = &candidate.snapshot else {
        return "unavailable";
    };
    if project_at(&candidate.target).is_some() {
        return "changed_or_unavailable";
    }
    let Some(project) = project_at(&candidate.project_root) else {
        return "changed_or_unavailable";
    };
    let Some(name) = candidate.target.file_name().and_then(|name| name.to_str()) else {
        return "changed_or_unavailable";
    };
    let matches = classify(&project, &candidate.target, name);
    if matches.len() != 1 || matches[0].0 != candidate.ecosystem {
        return "changed_or_unavailable";
    }
    let Some(mut current) = snapshot(&project, &candidate.target, candidate.ecosystem) else {
        return "changed_or_unavailable";
    };
    if candidate.ecosystem == "cargo" {
        let Some(expected_proof) = expected.cargo_workspace_proof.as_deref() else {
            return "changed_or_unavailable";
        };
        let roots = [candidate.project_root.clone()];
        let evidence = crate::cargo_workspace::Inspector::new(&roots).inspect(
            &candidate.project_root,
            |_| false,
            &AtomicBool::new(false),
        );
        let Some(current_proof) = evidence.proof() else {
            return "changed_or_unavailable";
        };
        if current_proof != expected_proof {
            return "changed_or_unavailable";
        }
        current.cargo_workspace_proof = Some(current_proof.to_owned());
    }
    if let Some(workspace_manifest) = &expected.cargo_workspace_manifest {
        if identity_at(&workspace_manifest.path).as_ref() != Some(workspace_manifest) {
            return "changed_or_unavailable";
        }
        current.cargo_workspace_manifest = Some(workspace_manifest.clone());
    }
    if &current == expected {
        "metadata_match"
    } else {
        "changed_or_unavailable"
    }
}

/// Build an inspection-only plan. Every selected path must match a discovered directory.
pub fn preview(report: ScanReport, selected: &[PathBuf]) -> Result<CleanupPlan> {
    preview_with_cancel(report, selected, &AtomicBool::new(false))
}

/// Validate selection paths and scan membership without collecting Git evidence.
pub fn validate_preview_selection(
    report: &ScanReport,
    selected: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<Vec<PathBuf>> {
    if cancel.load(Ordering::Relaxed) {
        bail!("preview cancelled");
    }
    if report.cancelled {
        bail!("cannot plan from a cancelled scan");
    }
    let mut targets = HashSet::new();
    for path in selected {
        if cancel.load(Ordering::Relaxed) {
            bail!("preview cancelled");
        }
        let meta = fs::symlink_metadata(path)
            .with_context(|| format!("inspect selected target {}", display_path(path)))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            bail!(
                "selected target is not a non-symlink directory: {}",
                display_path(path)
            );
        }
        let canonical = path
            .canonicalize()
            .with_context(|| format!("resolve selected target {}", display_path(path)))?;
        if !report
            .candidates
            .iter()
            .any(|candidate| candidate.target == canonical)
        {
            bail!(
                "selected target was not found in the scan: {}",
                display_path(path)
            );
        }
        targets.insert(canonical);
    }
    let mut targets = targets.into_iter().collect::<Vec<_>>();
    targets.sort();
    Ok(targets)
}

pub fn preview_with_cancel(
    report: ScanReport,
    selected: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<CleanupPlan> {
    let targets = validate_preview_selection(&report, selected, cancel)?
        .into_iter()
        .collect::<HashSet<_>>();
    let git = if report.candidates.is_empty() {
        None
    } else {
        crate::git_index::available(cancel, &report.roots)?
    };
    #[cfg(target_os = "linux")]
    let git_evidence_id = git.as_ref().map(crate::git_index::Git::evidence_id);
    let activity = crate::activity::inspect(
        &report
            .candidates
            .iter()
            .map(|candidate| candidate.target.clone())
            .collect::<Vec<_>>(),
        cancel,
    );
    let mut items = Vec::new();
    for (candidate, activity_status) in report.candidates.into_iter().zip(activity) {
        if cancel.load(Ordering::Relaxed) {
            bail!("preview cancelled");
        }
        let selected = targets.contains(&candidate.target);
        let identity_status = identity_status(&candidate);
        let (git_index_status, git_head_status) = crate::git_index::status(
            git.as_ref(),
            &candidate.project_root,
            &candidate.target,
            cancel,
        )?;
        let git_history_status = if selected {
            crate::git_index::history_status(
                git.as_ref(),
                &candidate.project_root,
                &candidate.target,
                cancel,
            )?
        } else {
            "not_checked"
        };
        let risk = if git_index_status == "tracked_in_index"
            || git_head_status == "matching_entry_in_head_or_index"
            || git_history_status == "matching_entry_in_git_history"
        {
            "tracked in Git index, HEAD, or reachable history; do not remove"
        } else if matches!(
            activity_status,
            "open_handles_or_cwd_observed" | "executable_observed"
        ) {
            "process handle, executable, or working directory observed; do not remove"
        } else if candidate.nested_project_marker.is_some() || candidate.nested_vcs_marker.is_some()
        {
            "nested project or version-control marker; do not remove"
        } else if identity_status != "metadata_match" {
            "identity changed or unavailable; do not remove"
        } else if !candidate.size_complete {
            "incomplete artifact inventory; do not remove"
        } else if candidate.symlink_marker.is_some() {
            "symbolic link observed; inspect without following it"
        } else if candidate.hard_link_marker.is_some() {
            "hard-linked file observed; allocated space may remain shared"
        } else if candidate.classification == "review" {
            "potentially destructive"
        } else {
            "rebuildable classification; safety unverified"
        };
        items.push(PlanItem {
            candidate,
            selected,
            risk,
            proposed_operation: "remove directory and its contents",
            execution_ready: false,
            identity_status,
            git_index_status,
            git_head_status,
            git_history_status,
            #[cfg(target_os = "linux")]
            git_evidence_id: git_evidence_id.clone(),
            activity_status,
            safeguards_required: vec![
                "verify project identity and version-controlled files",
                "verify no active build",
                "revalidate path, exclusions, permissions, links, and mounts",
                "confirm irreversible removal",
            ],
        });
    }
    if cancel.load(Ordering::Relaxed) {
        bail!("preview cancelled");
    }
    let mut warnings = report.warnings;
    if !items.is_empty() {
        warnings.push("Process activity is a bounded snapshot of same-user handles, executables, and working directories only; no observation does not prove a build is inactive.".into());
    }
    warnings.extend(items.iter().filter_map(|item| {
        reproduction_warning(&item.candidate)
            .map(|warning| format!("{}: {warning}", display_path(&item.candidate.target)))
    }));
    Ok(CleanupPlan {
        roots: report.roots,
        items,
        warnings,
    })
}
