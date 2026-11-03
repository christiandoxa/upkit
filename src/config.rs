//! Persistent, non-destructive scan settings.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::Duration,
};

pub type ResolvedScan = (
    Vec<PathBuf>,
    Vec<PathBuf>,
    Option<Duration>,
    Option<Vec<crate::sweep::Ecosystem>>,
);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ScheduleFrequency {
    Daily,
    #[default]
    Weekly,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    Dark,
    Light,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub version: u32,
    pub workspace_roots: Vec<PathBuf>,
    pub exclusions: Vec<PathBuf>,
    pub artifact_retention: Option<String>,
    #[serde(skip_serializing_if = "theme_is_dark")]
    pub theme: Theme,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled_ecosystems: Option<Vec<crate::sweep::Ecosystem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule_frequency: Option<ScheduleFrequency>,
    #[serde(skip_serializing_if = "is_false")]
    pub scheduled_bytecode_cleanup: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub scheduled_artifact_cleanup: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub scheduled_trash_retention: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Profile {
    pub workspace_roots: Vec<PathBuf>,
    pub exclusions: Vec<PathBuf>,
    pub artifact_retention: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled_ecosystems: Option<Vec<crate::sweep::Ecosystem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule_frequency: Option<ScheduleFrequency>,
    #[serde(skip_serializing_if = "is_false")]
    pub scheduled_bytecode_cleanup: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub scheduled_artifact_cleanup: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

fn theme_is_dark(value: &Theme) -> bool {
    *value == Theme::Dark
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: 1,
            workspace_roots: vec![],
            exclusions: vec![],
            artifact_retention: None,
            theme: Theme::Dark,
            enabled_ecosystems: None,
            schedule_frequency: None,
            scheduled_bytecode_cleanup: false,
            scheduled_artifact_cleanup: false,
            scheduled_trash_retention: false,
            profiles: BTreeMap::new(),
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported configuration version {}", self.version);
        }
        validate_policy(
            &self.workspace_roots,
            &self.exclusions,
            self.artifact_retention.as_deref(),
        )?;
        for (name, profile) in &self.profiles {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            {
                bail!(
                    "profile names must contain only ASCII letters, digits, '-' or '_' (maximum 64 characters)"
                );
            }
            validate_policy(
                &profile.workspace_roots,
                &profile.exclusions,
                profile.artifact_retention.as_deref(),
            )
            .with_context(|| format!("invalid profile {name}"))?;
        }
        Ok(())
    }
}

fn validate_policy(
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    retention: Option<&str>,
) -> Result<()> {
    for root in roots {
        if !root.is_absolute()
            || root.parent().is_none()
            || root.components().any(|c| matches!(c, Component::ParentDir))
        {
            bail!(
                "workspace roots must be absolute, non-root paths without '..': {}",
                crate::sweep::display_path(root)
            );
        }
    }
    for path in exclusions {
        crate::sweep::exclusion_pattern(path)?;
        if path.as_os_str().is_empty()
            || path.components().any(|c| matches!(c, Component::ParentDir))
        {
            bail!(
                "exclusions must be nonempty paths without '..': {}",
                crate::sweep::display_path(path)
            );
        }
    }
    if let Some(age) = retention {
        crate::sweep::parse_age(age)
            .map_err(|err| anyhow::anyhow!("invalid artifact_retention: {err}"))?;
    }
    Ok(())
}

pub fn config_path(override_path: Option<&Path>) -> Result<PathBuf> {
    match override_path {
        Some(path) if !path.as_os_str().is_empty() => Ok(path.to_owned()),
        Some(_) => bail!("configuration path cannot be empty"),
        None => Ok(dirs::config_dir()
            .context("cannot determine the configuration directory")?
            .join("upkit/config.toml")),
    }
}

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[cfg(unix)]
fn permitted_unix_config(path: &Path, metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    metadata.is_file() || (path == Path::new("/dev/null") && metadata.file_type().is_char_device())
}

pub fn load(path: &Path, required: bool) -> Result<Settings> {
    #[cfg(unix)]
    {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && !required => {
                return Ok(Settings::default());
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("read configuration {}", crate::sweep::display_path(path))
                });
            }
        };
        if !permitted_unix_config(path, &metadata) {
            bail!(
                "configuration must be a regular file: {}",
                crate::sweep::display_path(path)
            );
        }
    }
    #[cfg(unix)]
    let open = || -> std::io::Result<fs::File> {
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(fs::File::from)
        .map_err(std::io::Error::from)
    };
    #[cfg(not(unix))]
    let open = || fs::File::open(path);
    let file = match open() {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && !required => {
            return Ok(Settings::default());
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!("read configuration {}", crate::sweep::display_path(path))
            });
        }
    };
    #[cfg(unix)]
    if !permitted_unix_config(path, &file.metadata().context("inspect configuration")?) {
        bail!(
            "configuration must be a regular file: {}",
            crate::sweep::display_path(path)
        );
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read configuration {}", crate::sweep::display_path(path)))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        bail!("configuration exceeds the 1 MiB load limit");
    }
    let text = String::from_utf8(bytes)
        .with_context(|| format!("read configuration {}", crate::sweep::display_path(path)))?;
    let settings: Settings = toml::from_str(&text).context("parse configuration")?;
    settings.validate()?;
    Ok(settings)
}

pub fn create(path: &Path, settings: &Settings, dry_run: bool) -> Result<()> {
    settings.validate()?;
    let text = toml::to_string_pretty(settings).context("serialize configuration")?;
    if text.len() as u64 > MAX_CONFIG_BYTES {
        bail!("configuration exceeds the 1 MiB load limit");
    }
    if dry_run {
        match fs::symlink_metadata(path) {
            Ok(_) => bail!(
                "configuration already exists: {}",
                crate::sweep::display_path(path)
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err).context("inspect configuration path"),
        }
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    #[cfg(unix)]
    let created = {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
    };
    #[cfg(not(unix))]
    let created = fs::create_dir_all(parent);
    created.with_context(|| {
        format!(
            "create configuration directory {}",
            crate::sweep::display_path(parent)
        )
    })?;
    let mut temp =
        tempfile::NamedTempFile::new_in(parent).context("create temporary configuration")?;
    temp.write_all(text.as_bytes())
        .context("write configuration")?;
    temp.as_file().sync_all().context("sync configuration")?;
    temp.persist_noclobber(path)
        .map_err(|err| err.error)
        .with_context(|| {
            format!(
                "create configuration {} (existing files are not overwritten)",
                crate::sweep::display_path(path)
            )
        })?;
    Ok(())
}

pub(crate) const MAX_EDIT_BYTES: u64 = 128 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConfigIdentity {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    unix: (u64, u64, i64, i64, u32, u64),
    #[cfg(unix)]
    owner: (u32, u32),
    #[cfg(windows)]
    attributes: u32,
}

fn editable_identity(meta: &fs::Metadata) -> Result<ConfigIdentity> {
    if !meta.is_file() || meta.len() > MAX_EDIT_BYTES {
        bail!("configuration must be a regular file no larger than 128 KiB");
    }
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    #[cfg(unix)]
    if meta.nlink() != 1 {
        bail!("configuration with multiple hard links cannot be edited");
    }
    #[cfg(windows)]
    use std::os::windows::fs::MetadataExt;
    #[cfg(windows)]
    if meta.file_attributes() & 0x400 != 0 {
        bail!("configuration reparse points cannot be edited");
    }
    Ok(ConfigIdentity {
        len: meta.len(),
        modified: meta.modified().ok(),
        #[cfg(unix)]
        unix: (
            meta.dev(),
            meta.ino(),
            meta.ctime(),
            meta.ctime_nsec(),
            meta.mode(),
            meta.nlink(),
        ),
        #[cfg(unix)]
        owner: (meta.uid(), meta.gid()),
        #[cfg(windows)]
        attributes: meta.file_attributes(),
    })
}

/// An editor snapshot. The original text is retained for conflict checks and backups.
#[derive(Clone, Debug)]
pub struct ConfigDocument {
    pub path: PathBuf,
    pub text: String,
    identity: Option<ConfigIdentity>,
}

impl ConfigDocument {
    pub fn exists(&self) -> bool {
        self.identity.is_some()
    }
}

pub fn validate_document(text: &str) -> Result<()> {
    if text.len() as u64 > MAX_EDIT_BYTES {
        bail!("configuration exceeds 128 KiB");
    }
    let settings: Settings = toml::from_str(text).context("parse configuration")?;
    settings.validate()
}

#[cfg(target_os = "linux")]
fn reject_extended_attributes(file: &fs::File) -> Result<()> {
    let mut buffer = [0u8; 1];
    match rustix::fs::flistxattr(file, &mut buffer) {
        Ok(0) => Ok(()),
        Ok(_) | Err(rustix::io::Errno::RANGE) => {
            bail!("configuration with extended attributes or ACLs cannot be safely replaced")
        }
        Err(rustix::io::Errno::NOTSUP) => Ok(()),
        Err(error) => Err(error).context("inspect configuration extended attributes"),
    }
}

/// Read configuration text, including invalid TOML so it can be repaired.
pub fn read_document(path: &Path) -> Result<ConfigDocument> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_symlink() => meta,
        Ok(_) => bail!("linked configuration cannot be edited"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ConfigDocument {
                path: path.to_owned(),
                text: "version = 1\n".into(),
                identity: None,
            });
        }
        Err(error) => return Err(error).context("inspect configuration"),
    };
    let expected = editable_identity(&metadata)?;
    let mut file = fs::File::open(path).context("open configuration")?;
    if editable_identity(&file.metadata()?)? != expected {
        bail!("configuration changed while opening");
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_EDIT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_EDIT_BYTES || editable_identity(&file.metadata()?)? != expected {
        bail!("configuration changed while reading");
    }
    let current = fs::symlink_metadata(path)?;
    if current.file_type().is_symlink() || editable_identity(&current)? != expected {
        bail!("configuration path changed while reading");
    }
    let text = String::from_utf8(bytes).context("configuration must be UTF-8")?;
    Ok(ConfigDocument {
        path: path.to_owned(),
        text,
        identity: Some(expected),
    })
}

/// Save validated TOML after checking the original snapshot. Existing text is backed up.
pub fn save_document(
    snapshot: &ConfigDocument,
    text: &str,
) -> Result<(ConfigDocument, Option<PathBuf>)> {
    save_document_with_hook(snapshot, text, || {})
}

fn save_document_with_hook(
    snapshot: &ConfigDocument,
    text: &str,
    before_replace: impl FnOnce(),
) -> Result<(ConfigDocument, Option<PathBuf>)> {
    validate_document(text)?;
    #[cfg(not(target_os = "linux"))]
    if snapshot.identity.is_some() {
        bail!(
            "editing an existing configuration on this platform requires metadata-preserving replacement, which is not available"
        );
    }
    let parent = snapshot
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .context("create configuration directory")?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(parent).context("create configuration directory")?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let dir = fs::File::from(
            rustix::fs::openat2(
                rustix::fs::CWD,
                parent,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
                rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
            )
            .context("open configuration directory without links")?,
        );
        let metadata = dir.metadata()?;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
            bail!("configuration directory must be user-owned and not group/other writable");
        }
    }
    let current = read_document(&snapshot.path)?;
    if current.identity != snapshot.identity || current.text != snapshot.text {
        bail!("configuration changed since it was opened; reload before saving");
    }
    #[cfg(target_os = "linux")]
    if let Some(identity) = &snapshot.identity {
        let file =
            fs::File::open(&snapshot.path).context("open configuration for metadata check")?;
        if editable_identity(&file.metadata()?)? != *identity {
            bail!("configuration changed before metadata check");
        }
        reject_extended_attributes(&file)?;
    }
    let mut staged = tempfile::Builder::new()
        .prefix(".upkit-config-backup-")
        .suffix(".toml")
        .tempfile_in(parent)
        .context("create temporary configuration")?;
    staged
        .write_all(text.as_bytes())
        .context("write configuration")?;
    staged.as_file().sync_all().context("sync configuration")?;
    #[cfg(unix)]
    if let Some(identity) = &snapshot.identity {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = staged.as_file().metadata()?;
        if (metadata.uid(), metadata.gid()) != identity.owner {
            bail!("cannot preserve the configuration's owner or group");
        }
        fs::set_permissions(
            staged.path(),
            fs::Permissions::from_mode(identity.unix.4 & 0o7777),
        )?;
        #[cfg(target_os = "linux")]
        reject_extended_attributes(staged.as_file())?;
        staged
            .as_file()
            .sync_all()
            .context("sync configuration permissions")?;
    }
    let current = read_document(&snapshot.path)?;
    if current.identity != snapshot.identity || current.text != snapshot.text {
        bail!("configuration changed while saving; reload before retrying");
    }
    #[cfg(target_os = "linux")]
    if snapshot.identity.is_some() {
        return replace_document(snapshot, text, staged, parent, before_replace);
    }
    before_replace();
    staged
        .persist_noclobber(&snapshot.path)
        .map_err(|error| error.error)
        .context("create configuration without overwriting")?;
    #[cfg(unix)]
    fs::File::open(parent)?
        .sync_all()
        .context("sync configuration directory")?;
    let saved = read_document(&snapshot.path).context("verify saved configuration")?;
    if saved.text != text {
        bail!("saved configuration changed before verification");
    }
    Ok((saved, None))
}

#[cfg(target_os = "linux")]
fn same_after_rename(expected: &ConfigIdentity, actual: &ConfigIdentity) -> bool {
    expected.len == actual.len
        && expected.modified == actual.modified
        && expected.owner == actual.owner
        && expected.unix.0 == actual.unix.0
        && expected.unix.1 == actual.unix.1
        && expected.unix.4 == actual.unix.4
        && expected.unix.5 == actual.unix.5
}

#[cfg(target_os = "linux")]
fn replace_document(
    snapshot: &ConfigDocument,
    text: &str,
    staged: tempfile::NamedTempFile,
    parent: &Path,
    before_replace: impl FnOnce(),
) -> Result<(ConfigDocument, Option<PathBuf>)> {
    use rustix::fs::{
        AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, openat2, renameat_with, unlinkat,
    };
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory = fs::File::from(
        openat2(
            rustix::fs::CWD,
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .context("open configuration directory without links")?,
    );
    let directory_metadata = directory.metadata()?;
    let staged_metadata = staged.as_file().metadata()?;
    if directory_metadata.uid() != staged_metadata.uid() || directory_metadata.mode() & 0o022 != 0 {
        bail!("configuration directory must be user-owned and not group/other writable");
    }
    let name = snapshot
        .path
        .file_name()
        .context("configuration filename is missing")?;
    let staged_name = staged
        .path()
        .file_name()
        .context("temporary configuration filename is missing")?
        .to_owned();
    let staged_identity = editable_identity(&staged_metadata)?;
    let entry = fs::File::from(
        openat2(
            &directory,
            &staged_name,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .context("inspect staged configuration")?,
    );
    if editable_identity(&entry.metadata()?)? != staged_identity {
        bail!("staged configuration changed");
    }
    let (staged_file, backup_path) = staged
        .keep()
        .map_err(|error| error.error)
        .context("retain staged configuration")?;
    let cleanup_staged = || {
        let entry = openat2(
            &directory,
            &staged_name,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .map(fs::File::from);
        let same = entry
            .ok()
            .and_then(|file| file.metadata().ok())
            .and_then(|meta| editable_identity(&meta).ok())
            .is_some_and(|identity| same_after_rename(&staged_identity, &identity));
        same && unlinkat(&directory, &staged_name, AtFlags::empty()).is_ok()
    };
    before_replace();
    if let Err(error) = renameat_with(
        &directory,
        &staged_name,
        &directory,
        name,
        RenameFlags::EXCHANGE,
    ) {
        if cleanup_staged() {
            return Err(error).context("exchange configuration");
        }
        bail!(
            "exchange configuration: {error}; inspect retained file {}",
            crate::sweep::display_path(&backup_path)
        );
    }
    let verification = (|| -> Result<ConfigDocument> {
        let displaced = read_document(&backup_path).context("inspect previous configuration")?;
        let expected = snapshot
            .identity
            .as_ref()
            .context("missing original identity")?;
        if displaced
            .identity
            .as_ref()
            .is_none_or(|identity| !same_after_rename(expected, identity))
            || displaced.text != snapshot.text
        {
            bail!("configuration changed during replacement");
        }
        let original = fs::File::from(
            openat2(
                &directory,
                &staged_name,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )
            .context("inspect configuration backup metadata")?,
        );
        if !same_after_rename(expected, &editable_identity(&original.metadata()?)?) {
            bail!("configuration backup changed");
        }
        reject_extended_attributes(&original)?;
        let saved = read_document(&snapshot.path).context("verify saved configuration")?;
        if saved
            .identity
            .as_ref()
            .is_none_or(|identity| !same_after_rename(&staged_identity, identity))
            || saved.text != text
        {
            bail!("replacement changed during verification");
        }
        Ok(saved)
    })();
    match verification {
        Ok(saved) => {
            let result = (|| -> Result<()> {
                let original = fs::File::from(
                    openat2(
                        &directory,
                        &staged_name,
                        OFlags::RDONLY | OFlags::CLOEXEC,
                        Mode::empty(),
                        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
                    )
                    .context("open configuration backup")?,
                );
                let expected = snapshot
                    .identity
                    .as_ref()
                    .context("missing original identity")?;
                if !same_after_rename(expected, &editable_identity(&original.metadata()?)?) {
                    bail!("configuration backup changed");
                }
                reject_extended_attributes(&original)?;
                original
                    .set_permissions(fs::Permissions::from_mode(0o600))
                    .context("make configuration backup private")?;
                original.sync_all().context("sync configuration backup")?;
                directory
                    .sync_all()
                    .context("sync configuration directory")?;
                Ok(())
            })();
            if let Err(error) = result {
                bail!(
                    "configuration was replaced but backup verification failed: {error:#}; inspect {}",
                    crate::sweep::display_path(&backup_path)
                );
            }
            Ok((saved, Some(backup_path)))
        }
        Err(error) => {
            let installed = read_document(&snapshot.path).ok();
            let installed_is_ours = installed.as_ref().is_some_and(|document| {
                document.text == text
                    && document
                        .identity
                        .as_ref()
                        .is_some_and(|identity| same_after_rename(&staged_identity, identity))
            });
            if installed_is_ours
                && renameat_with(
                    &directory,
                    &staged_name,
                    &directory,
                    name,
                    RenameFlags::EXCHANGE,
                )
                .is_ok()
                && cleanup_staged()
            {
                let _ = directory.sync_all();
                return Err(error).context("configuration restored; reload before retrying");
            }
            drop(staged_file);
            bail!(
                "{error:#}; inspect configuration and retained file {}",
                crate::sweep::display_path(&backup_path)
            );
        }
    }
}

pub fn scan_options(
    settings: &Settings,
    paths: &[PathBuf],
    exclusions: &[PathBuf],
    age: Option<Duration>,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>, Option<Duration>)> {
    profile_scan_options(settings, None, paths, exclusions, age)
}

pub fn profile_scan_options(
    settings: &Settings,
    name: Option<&str>,
    paths: &[PathBuf],
    exclusions: &[PathBuf],
    age: Option<Duration>,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>, Option<Duration>)> {
    settings.validate()?;
    let profile = name
        .map(|name| {
            settings.profiles.get(name).ok_or_else(|| {
                anyhow::anyhow!("unknown workspace profile: {}", name.escape_default())
            })
        })
        .transpose()?;
    let roots = if paths.is_empty() {
        profile.map_or_else(
            || settings.workspace_roots.clone(),
            |profile| profile.workspace_roots.clone(),
        )
    } else {
        paths.to_vec()
    };
    if roots.is_empty() {
        bail!("provide workspace roots or configure workspace_roots before scanning");
    }
    let mut combined = settings.exclusions.clone();
    if let Some(profile) = profile {
        combined.extend_from_slice(&profile.exclusions);
    }
    combined.extend_from_slice(exclusions);
    let retention = profile
        .and_then(|profile| profile.artifact_retention.as_ref())
        .or(settings.artifact_retention.as_ref());
    let age = match (age, retention) {
        (Some(value), _) => Some(value),
        (None, Some(value)) => Some(crate::sweep::parse_age(value).map_err(anyhow::Error::msg)?),
        (None, None) => None,
    };
    Ok((roots, combined, age))
}

/// Profile ecosystem policies can narrow, but never widen, the global policy.
pub fn enabled_ecosystems(
    settings: &Settings,
    name: Option<&str>,
) -> Result<Option<Vec<crate::sweep::Ecosystem>>> {
    settings.validate()?;
    let profile = name
        .map(|name| {
            settings.profiles.get(name).ok_or_else(|| {
                anyhow::anyhow!("unknown workspace profile: {}", name.escape_default())
            })
        })
        .transpose()?;
    let profile_enabled = profile.and_then(|profile| profile.enabled_ecosystems.as_ref());
    Ok(match (&settings.enabled_ecosystems, profile_enabled) {
        (None, None) => None,
        (Some(global), None) => Some(global.clone()),
        (None, Some(profile)) => Some(profile.clone()),
        (Some(global), Some(profile)) => Some(
            global
                .iter()
                .copied()
                .filter(|item| profile.contains(item))
                .collect(),
        ),
    })
}

/// A profile must opt in itself; the global policy does not opt profiles in.
pub fn scheduled_bytecode_cleanup(settings: &Settings, name: Option<&str>) -> Result<bool> {
    settings.validate()?;
    match name {
        None => Ok(settings.scheduled_bytecode_cleanup),
        Some(name) => settings
            .profiles
            .get(name)
            .map(|profile| profile.scheduled_bytecode_cleanup)
            .ok_or_else(|| anyhow::anyhow!("unknown workspace profile: {}", name.escape_default())),
    }
}

/// A profile must opt in itself; the global policy does not opt profiles in.
pub fn scheduled_artifact_cleanup(settings: &Settings, name: Option<&str>) -> Result<bool> {
    settings.validate()?;
    match name {
        None => Ok(settings.scheduled_artifact_cleanup),
        Some(name) => settings
            .profiles
            .get(name)
            .map(|profile| profile.scheduled_artifact_cleanup)
            .ok_or_else(|| anyhow::anyhow!("unknown workspace profile: {}", name.escape_default())),
    }
}

/// Trash retention has its own global opt-in and is never implied by scan cleanup.
pub fn scheduled_trash_retention(settings: &Settings) -> Result<bool> {
    settings.validate()?;
    Ok(settings.scheduled_trash_retention)
}

/// Bind an enabled scheduled Trash policy to the current private config file.
///
/// This is intentionally stricter than `load`: scheduled deletion must not
/// follow a replaced or linked configuration path.
#[cfg(target_os = "linux")]
pub(crate) fn scheduled_trash_config_token(path: &Path) -> Result<String> {
    use anyhow::Context;
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;

    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || path
            .canonicalize()
            .context("resolve scheduled Trash configuration")?
            != path
    {
        bail!("scheduled Trash configuration path must be canonical and absolute");
    }

    let open = || -> Result<fs::File> {
        Ok(fs::File::from(
            openat2(
                rustix::fs::CWD,
                path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .context("open scheduled Trash configuration without links")?,
        ))
    };
    let file = open()?;
    let metadata = file
        .metadata()
        .context("inspect scheduled Trash configuration")?;
    if !metadata.is_file()
        || metadata.len() > MAX_EDIT_BYTES
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o400 == 0
        || metadata.nlink() != 1
    {
        bail!("scheduled Trash configuration must be a private, user-owned regular file");
    }
    reject_extended_attributes(&file)?;
    let initial = editable_identity(&metadata)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let reader = &file;
    reader
        .take(MAX_EDIT_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read scheduled Trash configuration")?;
    let after = file
        .metadata()
        .context("recheck scheduled Trash configuration")?;
    if bytes.len() as u64 > MAX_EDIT_BYTES || editable_identity(&after)? != initial {
        bail!("scheduled Trash configuration changed while reading");
    }
    let reopened = open()?;
    if editable_identity(&reopened.metadata()?)? != initial {
        bail!("scheduled Trash configuration path changed while reading");
    }
    let text =
        std::str::from_utf8(&bytes).context("scheduled Trash configuration must be UTF-8")?;
    let settings: Settings = toml::from_str(text).context("parse scheduled Trash configuration")?;
    if !scheduled_trash_retention(&settings)? {
        bail!("scheduled Trash retention is not enabled in the bound configuration");
    }

    let mut hash = Sha256::new();
    hash.update(b"upkit-scheduled-trash-config-v1\0");
    hash.update((path.as_os_str().as_encoded_bytes().len() as u64).to_be_bytes());
    hash.update(path.as_os_str().as_encoded_bytes());
    hash.update(metadata.dev().to_be_bytes());
    hash.update(metadata.ino().to_be_bytes());
    hash.update(metadata.uid().to_be_bytes());
    hash.update(metadata.gid().to_be_bytes());
    hash.update(metadata.mode().to_be_bytes());
    hash.update(metadata.nlink().to_be_bytes());
    hash.update(metadata.len().to_be_bytes());
    hash.update(metadata.ctime().to_be_bytes());
    hash.update(metadata.ctime_nsec().to_be_bytes());
    hash.update(metadata.mtime().to_be_bytes());
    hash.update(metadata.mtime_nsec().to_be_bytes());
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    Ok(hex::encode(hash.finalize()))
}

/// Profiles override the global frequency; an unset policy defaults to weekly.
pub fn schedule_frequency(settings: &Settings, name: Option<&str>) -> Result<ScheduleFrequency> {
    settings.validate()?;
    let profile = name
        .map(|name| {
            settings.profiles.get(name).ok_or_else(|| {
                anyhow::anyhow!("unknown workspace profile: {}", name.escape_default())
            })
        })
        .transpose()?;
    Ok(profile
        .and_then(|profile| profile.schedule_frequency)
        .or(settings.schedule_frequency)
        .unwrap_or_default())
}

#[cfg(all(test, target_os = "linux"))]
mod editor_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn exchange_restores_a_change_made_immediately_before_replacement() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "version = 1\n# initial\n").unwrap();
        let snapshot = read_document(&path).unwrap();
        let result = save_document_with_hook(&snapshot, "version = 1\n# ours\n", || {
            fs::write(&path, "version = 1\n# concurrent\n").unwrap();
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "version = 1\n# concurrent\n"
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn creation_never_replaces_a_file_created_after_the_check() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("config.toml");
        let snapshot = read_document(&path).unwrap();
        let result = save_document_with_hook(&snapshot, "version = 1\n# ours\n", || {
            fs::write(&path, "version = 1\n# concurrent\n").unwrap();
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "version = 1\n# concurrent\n"
        );
    }

    #[test]
    fn exchange_restores_attributes_added_immediately_before_replacement() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "version = 1\n").unwrap();
        match rustix::fs::setxattr(
            &path,
            "user.upkit-test",
            b"keep",
            rustix::fs::XattrFlags::empty(),
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::NOTSUP) => return,
            Err(error) => panic!("cannot set fixture attribute: {error}"),
        }
        rustix::fs::removexattr(&path, "user.upkit-test").unwrap();
        let snapshot = read_document(&path).unwrap();
        let result = save_document_with_hook(&snapshot, "version = 1\n# ours\n", || {
            rustix::fs::setxattr(
                &path,
                "user.upkit-test",
                b"keep",
                rustix::fs::XattrFlags::empty(),
            )
            .unwrap();
        });
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "version = 1\n");
        let mut value = [0u8; 4];
        assert_eq!(
            rustix::fs::getxattr(&path, "user.upkit-test", &mut value).unwrap(),
            4
        );
        assert_eq!(&value, b"keep");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn exchange_restores_a_concurrent_symlink_without_following_it() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("config.toml");
        let previous = dir.path().join("moved.toml");
        let outside = dir.path().join("outside.toml");
        fs::write(&path, "version = 1\n# original\n").unwrap();
        fs::write(&outside, "do not touch\n").unwrap();
        let snapshot = read_document(&path).unwrap();
        let result = save_document_with_hook(&snapshot, "version = 1\n# ours\n", || {
            fs::rename(&path, &previous).unwrap();
            symlink(&outside, &path).unwrap();
        });
        assert!(result.is_err());
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(&previous).unwrap(),
            "version = 1\n# original\n"
        );
        assert_eq!(fs::read_to_string(&outside).unwrap(), "do not touch\n");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod scheduled_trash_policy_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn scheduled_trash_config_token_binds_a_private_enabled_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "version = 1\nscheduled_trash_retention = true\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let first = scheduled_trash_config_token(&path).unwrap();
        assert_eq!(first.len(), 64);
        assert_eq!(first, scheduled_trash_config_token(&path).unwrap());

        let linked = dir.path().join("linked.toml");
        symlink(&path, &linked).unwrap();
        assert!(scheduled_trash_config_token(&linked).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(scheduled_trash_config_token(&path).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, "version = 1\n").unwrap();
        assert!(scheduled_trash_config_token(&path).is_err());
    }

    #[test]
    fn scheduled_trash_config_token_rejects_a_fifo_without_blocking() {
        use rustix::fs::{Mode, mkfifoat};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        mkfifoat(rustix::fs::CWD, &path, Mode::RUSR | Mode::WUSR).unwrap();
        assert!(scheduled_trash_config_token(&path).is_err());
    }
}
