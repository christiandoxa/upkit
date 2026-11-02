//! Review and remove abandoned Upkit symlink staging directories.
#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{Result, bail};
use serde::Serialize;
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::{
    collections::HashSet,
    fs,
    sync::atomic::Ordering,
    time::{Duration, SystemTime},
};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[cfg(target_os = "linux")]
const PREFIX: &str = ".upkit-link-";
// shortcut: cap reviews at 4096 entries and 128 candidates; paginate before raising either limit.
#[cfg(target_os = "linux")]
const MAX_SCAN_ENTRIES: usize = 4096;
#[cfg(target_os = "linux")]
const MAX_CANDIDATES: usize = 128;
// Staging directories must be at least 30 days old; age never substitutes for the process check.
#[cfg(target_os = "linux")]
const RETENTION_DAYS: u64 = 30;
#[cfg(target_os = "linux")]
const RETENTION: Duration = Duration::from_secs(RETENTION_DAYS * 24 * 60 * 60);

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub path: PathBuf,
    pub age_days: Option<u64>,
    pub status: &'static str,
    pub selected: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
pub struct Plan {
    pub supported: bool,
    pub retention_days: u64,
    pub candidates: Vec<Candidate>,
    pub selected_count: usize,
    pub complete: bool,
    pub warnings: Vec<String>,
    pub preview_token: String,
    #[serde(skip)]
    selected: Vec<Approved>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct DirectoryIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct EntryIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    links: u64,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
struct Approved {
    path: PathBuf,
    parent: PathBuf,
    name: String,
    parent_identity: DirectoryIdentity,
    identity: EntryIdentity,
    tree: crate::guarded_tree::TreeSnapshot,
}

#[cfg(target_os = "linux")]
fn directory_identity(metadata: &fs::Metadata) -> DirectoryIdentity {
    use std::os::unix::fs::MetadataExt;
    DirectoryIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
    }
}

#[cfg(target_os = "linux")]
fn entry_identity(metadata: &fs::Metadata) -> EntryIdentity {
    use std::os::unix::fs::MetadataExt;
    EntryIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        size: metadata.len(),
        mtime: metadata.mtime(),
        mtime_ns: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_ns: metadata.ctime_nsec(),
    }
}

#[cfg(target_os = "linux")]
fn same_moved_entry(current: &EntryIdentity, expected: &EntryIdentity) -> bool {
    current.dev == expected.dev
        && current.ino == expected.ino
        && current.uid == expected.uid
        && current.mode == expected.mode
        && current.links == expected.links
        && current.size == expected.size
        && current.mtime == expected.mtime
        && current.mtime_ns == expected.mtime_ns
}

#[cfg(target_os = "linux")]
fn same_entry_anchor(current: &EntryIdentity, expected: &EntryIdentity) -> bool {
    current.dev == expected.dev
        && current.ino == expected.ino
        && current.uid == expected.uid
        && current.mode == expected.mode
}

#[cfg(target_os = "linux")]
fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(target_os = "linux")]
fn open_directory(path: &Path) -> Result<fs::File> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    Ok(fs::File::from(openat2(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?))
}

#[cfg(target_os = "linux")]
fn validate_directory(path: &Path) -> Result<(fs::File, DirectoryIdentity)> {
    use std::os::unix::fs::MetadataExt;
    let canonical = path
        .canonicalize()
        .with_context(|| format!("resolve cleanup root {}", crate::sweep::display_path(path)))?;
    if canonical != path {
        bail!("cleanup roots must not use linked or non-canonical paths");
    }
    let path = canonical;
    let file = open_directory(&path)?;
    let metadata = file.metadata()?;
    let path_metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir()
        || metadata.uid() != uid()
        || metadata.mode() & 0o022 != 0
        || path_metadata.file_type().is_symlink()
        || directory_identity(&metadata) != directory_identity(&path_metadata)
    {
        bail!("cleanup root must be a canonical user-owned directory not writable by others");
    }
    Ok((file, directory_identity(&metadata)))
}

#[cfg(target_os = "linux")]
fn target_is_upkit(home: &Path, link: &Path) -> bool {
    let Ok(target) = fs::read_link(link) else {
        return false;
    };
    target.is_absolute()
        && target.starts_with(home)
        && !target
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
}

#[cfg(target_os = "linux")]
fn inspect_candidate(
    path: &Path,
    home: &Path,
    parent_identity: &DirectoryIdentity,
    cancel: &AtomicBool,
) -> Result<Option<(EntryIdentity, crate::guarded_tree::TreeSnapshot)>> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    use std::os::unix::fs::MetadataExt;
    if cancel.load(Ordering::Relaxed) {
        bail!("temporary cleanup preview cancelled");
    }
    let Some(name) = path.file_name() else {
        return Ok(None);
    };
    let Some(name_text) = name.to_str() else {
        return Ok(None);
    };
    let suffix = name_text.strip_prefix(PREFIX).unwrap_or_default();
    if suffix.is_empty()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Ok(None);
    }
    let parent = path.parent().context("staging directory has no parent")?;
    let (parent_fd, actual_parent_identity) = validate_directory(parent)?;
    if &actual_parent_identity != parent_identity {
        bail!("cleanup parent changed during preview");
    }
    let directory = fs::File::from(openat2(
        &parent_fd,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )?);
    let metadata = directory.metadata()?;
    if metadata.uid() != uid()
        || metadata.mode() & 0o777 != 0o700
        || metadata.dev() != parent_identity.dev
    {
        return Ok(None);
    }
    let mut entries = rustix::fs::Dir::read_from(&directory)?;
    let mut names = Vec::new();
    for entry in entries.by_ref() {
        if cancel.load(Ordering::Relaxed) {
            bail!("temporary cleanup preview cancelled");
        }
        let entry = entry?;
        let name = entry.file_name();
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name.to_bytes().to_vec());
            if names.len() > 1 {
                return Ok(None);
            }
        }
    }
    if names.as_slice() != [b"link".as_slice()] {
        return Ok(None);
    }
    let link_path = path.join("link");
    if !target_is_upkit(home, &link_path) {
        return Ok(None);
    }
    let tree = crate::guarded_tree::snapshot(directory.try_clone()?, uid(), cancel)?;
    let review = tree.review_entries();
    if review.len() != 1 || review[0].path != "link" || review[0].kind != "symlink" {
        return Ok(None);
    }
    Ok(Some((entry_identity(&metadata), tree)))
}

#[cfg(target_os = "linux")]
fn token(selected: &[Approved]) -> Result<String> {
    let mut selected = selected.to_vec();
    selected.sort_by(|a, b| a.path.cmp(&b.path));
    let mut hash = Sha256::new();
    hash.update(b"upkit-temp-cleanup-v1\0");
    hash.update((selected.len() as u64).to_be_bytes());
    for item in selected {
        for field in [
            item.path.as_os_str().as_encoded_bytes().to_vec(),
            serde_json::to_vec(&item.parent_identity)?,
            serde_json::to_vec(&item.identity)?,
            item.tree.digest.into_bytes(),
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field);
        }
    }
    Ok(hex::encode(hash.finalize()))
}

/// Preview only Upkit-created symlink staging directories under its tool roots and bindir.
#[cfg(target_os = "linux")]
pub fn preview(
    home: &Path,
    bindir: &Path,
    selected_paths: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<Plan> {
    preview_with_activity(
        home,
        bindir,
        selected_paths,
        cancel,
        crate::activity::inspect,
    )
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn preview_for_tui_test(
    home: &Path,
    bindir: &Path,
    selected_paths: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<Plan> {
    preview_with_activity(home, bindir, selected_paths, cancel, |paths, _| {
        vec!["no_open_handles_or_cwd_observed"; paths.len()]
    })
}

#[cfg(target_os = "linux")]
fn preview_with_activity(
    home: &Path,
    bindir: &Path,
    selected_paths: &[PathBuf],
    cancel: &AtomicBool,
    mut inspect_activity: impl FnMut(&[PathBuf], &AtomicBool) -> Vec<&'static str>,
) -> Result<Plan> {
    use std::os::unix::fs::MetadataExt;
    if !home.is_absolute() {
        bail!("managed Upkit home must be an existing canonical path");
    }
    match home.canonicalize() {
        Ok(canonical) if canonical == home => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && selected_paths.is_empty() => {
            return Ok(Plan {
                supported: true,
                retention_days: RETENTION_DAYS,
                candidates: Vec::new(),
                selected_count: 0,
                complete: true,
                warnings: vec![
                    "managed Upkit home does not exist; no staging directories were inspected"
                        .into(),
                ],
                preview_token: token(&[])?,
                selected: Vec::new(),
            });
        }
        Ok(_) => bail!("managed Upkit home must not use a linked or non-canonical path"),
        Err(error) => return Err(error).context("resolve managed Upkit home"),
    }
    let user_home = dirs::home_dir().and_then(|path| path.canonicalize().ok());
    if home.parent().is_none() || user_home.as_deref() == Some(home) {
        bail!("cleanup roots cannot be a filesystem or user-home root");
    }
    let mut warnings = Vec::new();
    let (_, home_identity) = validate_directory(home)?;
    let bindir = match bindir.canonicalize() {
        Ok(canonical) if canonical == bindir => Some(canonical),
        Ok(_) => bail!("Upkit bindir must not use a linked or non-canonical path"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            warnings.push("Upkit bindir does not exist; it was not scanned".into());
            None
        }
        Err(error) => return Err(error).context("resolve Upkit bindir"),
    };
    if bindir
        .as_deref()
        .is_some_and(|path| path.parent().is_none() || user_home.as_deref() == Some(path))
    {
        bail!("cleanup roots cannot be a filesystem or user-home root");
    }
    let bindir_identity = bindir
        .as_deref()
        .map(validate_directory)
        .transpose()?
        .map(|(_, identity)| identity);

    let mut parents = vec![(home.to_owned(), home_identity.clone())];
    let mut discovered_roots = 0usize;
    for entry in fs::read_dir(home).context("scan managed Upkit roots")? {
        if cancel.load(Ordering::Relaxed) {
            bail!("temporary cleanup preview cancelled");
        }
        let entry = entry?;
        discovered_roots += 1;
        if discovered_roots > MAX_SCAN_ENTRIES {
            bail!("managed home exceeds the 4096-entry root discovery limit");
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() && metadata.uid() == uid() {
            parents.push((path, directory_identity(&metadata)));
            if parents.len() > MAX_CANDIDATES {
                bail!("managed home has too many roots for a complete cleanup review");
            }
        }
    }
    if let (Some(bindir), Some(identity)) = (&bindir, bindir_identity) {
        parents.push((bindir.clone(), identity));
    }
    let mut seen_roots = HashSet::new();
    parents.retain(|(path, _)| seen_roots.insert(path.clone()));

    let mut approved = Vec::new();
    let mut candidates = Vec::new();
    let mut scanned_entries = 0usize;
    let mut complete = true;
    let now = SystemTime::now();
    for (parent, parent_identity) in parents {
        let (parent_fd, current_parent_identity) = match validate_directory(&parent) {
            Ok(value) => value,
            Err(err) => {
                warnings.push(format!("{}: {err:#}", crate::sweep::display_path(&parent)));
                complete = false;
                continue;
            }
        };
        if current_parent_identity != parent_identity {
            warnings.push(format!(
                "{} changed during preview",
                crate::sweep::display_path(&parent)
            ));
            complete = false;
            continue;
        }
        let mut entries = rustix::fs::Dir::read_from(&parent_fd)?;
        for entry in entries.by_ref() {
            if cancel.load(Ordering::Relaxed) {
                bail!("temporary cleanup preview cancelled");
            }
            let entry = entry?;
            let name = entry.file_name();
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            scanned_entries += 1;
            if scanned_entries > MAX_SCAN_ENTRIES {
                complete = false;
                warnings.push("managed roots exceed the 4096-entry review limit".into());
                break;
            }
            let Ok(name) = name.to_str() else { continue };
            if !name.starts_with(PREFIX) {
                continue;
            }
            let path = parent.join(name);
            let (identity, tree) = match inspect_candidate(&path, home, &parent_identity, cancel) {
                Ok(Some(value)) => value,
                Ok(None) => {
                    complete = false;
                    warnings.push(format!(
                        "{} did not match the expected Upkit staging layout",
                        crate::sweep::display_path(&path)
                    ));
                    continue;
                }
                Err(err) => {
                    warnings.push(format!("{}: {err:#}", crate::sweep::display_path(&path)));
                    complete = false;
                    continue;
                }
            };
            if candidates.len() >= MAX_CANDIDATES {
                complete = false;
                warnings.push("more than 128 stale link candidates were found".into());
                break;
            }
            let metadata = fs::symlink_metadata(&path)?;
            let age = metadata
                .modified()
                .ok()
                .and_then(|time| now.duration_since(time).ok());
            let status = if age.is_none() {
                "age_unknown"
            } else if age.is_some_and(|age| age < RETENTION) {
                "too_recent"
            } else {
                "checking_activity"
            };
            candidates.push(Candidate {
                path: path.clone(),
                age_days: age.map(|age| age.as_secs() / 86400),
                status,
                selected: false,
            });
            if status == "checking_activity" {
                approved.push(Approved {
                    path,
                    parent: parent.clone(),
                    name: name.into(),
                    parent_identity: parent_identity.clone(),
                    identity,
                    tree,
                });
            }
        }
        if !complete {
            break;
        }
    }
    let activity_paths = approved
        .iter()
        .map(|item| item.path.clone())
        .collect::<Vec<_>>();
    let statuses = inspect_activity(&activity_paths, cancel);
    let mut eligible = Vec::new();
    for (item, status) in approved.into_iter().zip(statuses) {
        let candidate = candidates
            .iter_mut()
            .find(|candidate| candidate.path == item.path)
            .context("candidate activity status is unavailable")?;
        candidate.status = match status {
            "no_open_handles_or_cwd_observed" => "eligible",
            "open_handles_or_cwd_observed" | "executable_observed" => "active",
            _ => "activity_unknown",
        };
        if candidate.status == "activity_unknown" {
            complete = false;
            warnings.push(format!(
                "activity for {} could not be ruled out",
                crate::sweep::display_path(&item.path)
            ));
        }
        eligible.push(item);
    }
    candidates.sort_by(|a, b| a.path.cmp(&b.path));

    let requested: HashSet<_> = selected_paths.iter().cloned().collect();
    if requested.len() != selected_paths.len() {
        bail!("duplicate temporary cleanup selection");
    }
    let mut selected = Vec::new();
    for path in requested {
        let candidate = candidates
            .iter_mut()
            .find(|candidate| candidate.path == path)
            .context("selected directory was not found in the staging inventory")?;
        if candidate.status != "eligible" || !complete {
            bail!("selected staging directory is not eligible for removal");
        }
        candidate.selected = true;
        selected.push(
            eligible
                .iter()
                .find(|item| item.path == path)
                .context("selected staging identity is unavailable")?
                .clone(),
        );
    }
    selected.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Plan {
        supported: true,
        retention_days: 30,
        candidates,
        selected_count: selected.len(),
        complete,
        warnings,
        preview_token: token(&selected)?,
        selected,
    })
}

#[derive(Debug, Serialize)]
pub struct ItemResult {
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub path: PathBuf,
    pub status: &'static str,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CleanupResult {
    pub outcome: &'static str,
    pub removed_count: usize,
    pub items: Vec<ItemResult>,
}

#[cfg(target_os = "linux")]
fn quarantine_name() -> String {
    use std::sync::atomic::AtomicU64;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        ".upkit-cleanup-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(target_os = "linux")]
fn check_quarantine(
    item: &Approved,
    parent: &fs::File,
    quarantine_name: &str,
    quarantine: &fs::File,
    quarantine_identity: &DirectoryIdentity,
    root_identity: Option<&EntryIdentity>,
    original_absent: bool,
) -> Result<()> {
    use anyhow::Context;
    use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags, openat2, statat};

    let current_parent = open_directory(&item.parent)?;
    if directory_identity(&current_parent.metadata()?) != item.parent_identity
        || directory_identity(&parent.metadata()?) != item.parent_identity
    {
        bail!("staging parent changed");
    }
    let current_quarantine = fs::File::from(openat2(
        parent,
        quarantine_name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )?);
    if directory_identity(&current_quarantine.metadata()?) != *quarantine_identity
        || directory_identity(&quarantine.metadata()?) != *quarantine_identity
        || quarantine_identity.dev != item.parent_identity.dev
        || quarantine_identity.uid != uid()
        || quarantine_identity.mode & 0o777 != 0o700
    {
        bail!("staging quarantine changed");
    }
    match statat(parent, item.name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) if original_absent => {}
        Ok(_) if !original_absent => {}
        Ok(_) => bail!("original staging path was replaced after quarantine"),
        Err(rustix::io::Errno::NOENT) => {
            bail!("original staging path disappeared before quarantine")
        }
        Err(error) => return Err(error).context("inspect original staging path"),
    }
    match (
        root_identity,
        statat(quarantine, "root", AtFlags::SYMLINK_NOFOLLOW),
    ) {
        (Some(expected), Ok(_)) => {
            let root = fs::File::from(openat2(
                quarantine,
                "root",
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )?);
            if !same_entry_anchor(&entry_identity(&root.metadata()?), expected) {
                bail!("quarantined staging root was replaced");
            }
        }
        (None, Err(rustix::io::Errno::NOENT)) => {}
        (None, Ok(_)) => bail!("unexpected entry in staging quarantine"),
        (Some(_), Err(rustix::io::Errno::NOENT)) => {
            bail!("quarantined staging root disappeared")
        }
        (_, Err(error)) => return Err(error).context("inspect quarantined staging root"),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_one(
    item: &Approved,
    cancel: &AtomicBool,
    inspect_activity: &mut impl FnMut(&[PathBuf], &AtomicBool) -> Vec<&'static str>,
) -> ItemResult {
    let mut status = "failed";
    let error = remove_one_inner(item, cancel, inspect_activity, &mut status).err();
    if cancel.load(Ordering::Relaxed) && error.is_some() && status == "failed" {
        status = "cancelled";
    }
    ItemResult {
        path: item.path.clone(),
        status,
        error: error.map(|error| format!("{error:#}")),
    }
}

#[cfg(target_os = "linux")]
fn remove_one_inner(
    item: &Approved,
    cancel: &AtomicBool,
    inspect_activity: &mut impl FnMut(&[PathBuf], &AtomicBool) -> Vec<&'static str>,
    status: &mut &'static str,
) -> Result<()> {
    use anyhow::Context;
    use rustix::fs::{
        AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, mkdirat, openat2, renameat_with, statat,
        unlinkat,
    };
    use std::ffi::OsStr;

    if cancel.load(Ordering::Relaxed) {
        bail!("cleanup cancelled before removal");
    }
    let parent = open_directory(&item.parent)?;
    if directory_identity(&parent.metadata()?) != item.parent_identity {
        bail!("staging parent changed since preview");
    }
    let basename = OsStr::new(&item.name);
    let original = fs::File::from(openat2(
        &parent,
        basename,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )?);
    if entry_identity(&original.metadata()?) != item.identity {
        bail!("staging directory changed since preview");
    }
    let tree = crate::guarded_tree::snapshot(original.try_clone()?, uid(), cancel)?;
    if tree.digest != item.tree.digest || tree.count() != item.tree.count() {
        bail!("staging contents changed since preview");
    }
    drop(original);
    if inspect_activity(std::slice::from_ref(&item.path), cancel)[0]
        != "no_open_handles_or_cwd_observed"
    {
        bail!("process activity was observed or could not be ruled out");
    }

    let quarantine_name = (0..16)
        .find_map(|_| {
            let name = quarantine_name();
            match mkdirat(&parent, name.as_str(), Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                Ok(()) => Some(Ok(name)),
                Err(rustix::io::Errno::EXIST) => None,
                Err(err) => Some(Err(err)),
            }
        })
        .context("could not reserve a cleanup quarantine")??;
    let quarantine = match openat2(
        &parent,
        quarantine_name.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    ) {
        Ok(file) => fs::File::from(file),
        Err(error) => {
            let cleanup_error = unlinkat(&parent, quarantine_name.as_str(), AtFlags::REMOVEDIR)
                .err()
                .map(|cleanup| format!("could not remove empty cleanup quarantine: {cleanup}"));
            let context = cleanup_error.map_or_else(
                || "open cleanup quarantine".to_owned(),
                |cleanup| format!("open cleanup quarantine; {cleanup}"),
            );
            return Err(error).context(context);
        }
    };
    let quarantine_identity = directory_identity(&quarantine.metadata()?);
    let quarantine_path = item.parent.join(&quarantine_name);
    let mut staged = false;
    let mut partial = false;
    let action = (|| -> Result<()> {
        if cancel.load(Ordering::Relaxed) {
            bail!("cleanup cancelled before quarantine");
        }
        check_quarantine(
            item,
            &parent,
            &quarantine_name,
            &quarantine,
            &quarantine_identity,
            None,
            false,
        )?;
        let current = fs::File::from(openat2(
            &parent,
            basename,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?);
        if entry_identity(&current.metadata()?) != item.identity {
            bail!("staging directory changed before quarantine");
        }
        let fresh = crate::guarded_tree::snapshot(current.try_clone()?, uid(), cancel)?;
        if fresh.digest != item.tree.digest {
            bail!("staging contents changed before quarantine");
        }
        drop(current);
        renameat_with(
            &parent,
            basename,
            &quarantine,
            "root",
            RenameFlags::NOREPLACE,
        )
        .context("quarantine staging directory")?;
        staged = true;
        check_quarantine(
            item,
            &parent,
            &quarantine_name,
            &quarantine,
            &quarantine_identity,
            Some(&item.identity),
            true,
        )?;
        let staged_root = fs::File::from(openat2(
            &quarantine,
            "root",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?);
        if !same_moved_entry(&entry_identity(&staged_root.metadata()?), &item.identity) {
            bail!("quarantined staging directory identity changed");
        }
        let fresh = crate::guarded_tree::snapshot(staged_root.try_clone()?, uid(), cancel)?;
        if fresh.digest != item.tree.digest || fresh.count() != item.tree.count() {
            bail!("quarantined staging contents changed");
        }
        drop(staged_root);
        if inspect_activity(&[quarantine_path.join("root")], cancel)[0]
            != "no_open_handles_or_cwd_observed"
        {
            bail!("process activity was observed after quarantine");
        }
        check_quarantine(
            item,
            &parent,
            &quarantine_name,
            &quarantine,
            &quarantine_identity,
            Some(&item.identity),
            true,
        )?;
        let staged_root = fs::File::from(openat2(
            &quarantine,
            "root",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?);
        if !same_moved_entry(&entry_identity(&staged_root.metadata()?), &item.identity) {
            bail!("quarantined staging directory changed before deletion");
        }
        let fresh = crate::guarded_tree::snapshot(staged_root.try_clone()?, uid(), cancel)?;
        if fresh.digest != item.tree.digest || fresh.count() != item.tree.count() {
            bail!("quarantined staging contents changed before deletion");
        }
        crate::guarded_tree::remove(
            &quarantine,
            OsStr::new("root"),
            &staged_root,
            &item.tree,
            cancel,
            &mut partial,
            |_| {
                check_quarantine(
                    item,
                    &parent,
                    &quarantine_name,
                    &quarantine,
                    &quarantine_identity,
                    Some(&item.identity),
                    true,
                )
            },
        )?;
        drop(staged_root);
        check_quarantine(
            item,
            &parent,
            &quarantine_name,
            &quarantine,
            &quarantine_identity,
            Some(&item.identity),
            true,
        )?;
        unlinkat(&quarantine, "root", AtFlags::REMOVEDIR)
            .context("remove empty staging quarantine root")?;
        check_quarantine(
            item,
            &parent,
            &quarantine_name,
            &quarantine,
            &quarantine_identity,
            None,
            true,
        )?;
        unlinkat(&parent, quarantine_name.as_str(), AtFlags::REMOVEDIR)
            .context("remove staging quarantine directory")?;
        Ok(())
    })();

    if let Err(error) = action {
        let mut restored = false;
        let mut recovery_error = None;
        if staged && !partial {
            let quarantined = match statat(&quarantine, "root", AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => true,
                Err(rustix::io::Errno::NOENT) => false,
                Err(err) => {
                    recovery_error = Some(format!("could not inspect quarantined root: {err}"));
                    false
                }
            };
            let original_absent = match statat(&parent, basename, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => true,
                Ok(_) => false,
                Err(err) => {
                    recovery_error = Some(format!("could not recheck original path: {err}"));
                    false
                }
            };
            if quarantined && original_absent {
                match renameat_with(
                    &quarantine,
                    "root",
                    &parent,
                    basename,
                    RenameFlags::NOREPLACE,
                ) {
                    Ok(()) => {
                        restored = true;
                        if let Err(err) =
                            unlinkat(&parent, quarantine_name.as_str(), AtFlags::REMOVEDIR)
                        {
                            recovery_error = Some(format!(
                                "restored original but could not remove empty quarantine: {err}"
                            ));
                        }
                    }
                    Err(err) => {
                        recovery_error =
                            Some(format!("could not restore quarantined directory: {err}"))
                    }
                }
            }
        }
        if partial {
            *status = "partial";
            bail!(
                "{error:#}; removal stopped after deleting some entries; inspect {}",
                crate::sweep::display_path(&quarantine_path)
            );
        }
        if staged && !restored {
            *status = "quarantined";
            bail!(
                "{error:#}; directory remains in quarantine at {}{}",
                crate::sweep::display_path(&quarantine_path),
                recovery_error.map_or(String::new(), |detail| format!(" ({detail})"))
            );
        }
        if !staged {
            let _ = unlinkat(&parent, quarantine_name.as_str(), AtFlags::REMOVEDIR);
        }
        if restored {
            bail!(
                "{error:#}; original staging directory was restored{}",
                recovery_error.map_or(String::new(), |detail| format!(" ({detail})"))
            );
        }
        if let Some(detail) = recovery_error {
            bail!("{error:#}; {detail}");
        }
        return Err(error);
    }
    *status = "removed";
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn run(plan: &Plan, supplied_token: &str, cancel: &AtomicBool) -> Result<CleanupResult> {
    run_with_activity(plan, supplied_token, cancel, crate::activity::inspect)
}

#[cfg(target_os = "linux")]
fn run_with_activity(
    plan: &Plan,
    supplied_token: &str,
    cancel: &AtomicBool,
    mut inspect_activity: impl FnMut(&[PathBuf], &AtomicBool) -> Vec<&'static str>,
) -> Result<CleanupResult> {
    if plan.selected.is_empty() {
        bail!("select at least one eligible staging directory in the preview");
    }
    if supplied_token != plan.preview_token {
        bail!("temporary cleanup preview changed; review it again");
    }
    let mut items = Vec::new();
    for selected in &plan.selected {
        items.push(remove_one(selected, cancel, &mut inspect_activity));
    }
    let removed_count = items.iter().filter(|item| item.status == "removed").count();
    let failed = items.len() != removed_count;
    Ok(CleanupResult {
        outcome: if failed {
            if removed_count == 0
                && items
                    .iter()
                    .all(|item| item.status == "failed" || item.status == "cancelled")
            {
                "failed"
            } else {
                "partial"
            }
        } else {
            "completed"
        },
        removed_count,
        items,
    })
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Serialize)]
pub struct Plan {
    pub supported: bool,
    pub warning: &'static str,
}

#[cfg(not(target_os = "linux"))]
pub fn preview(_: &Path, _: &Path, _: &[PathBuf], _: &AtomicBool) -> Result<Plan> {
    Ok(Plan {
        supported: false,
        warning: "stale Upkit symlink staging cleanup is available on Linux only; no files were inspected",
    })
}

#[cfg(not(target_os = "linux"))]
pub fn run(_: &Plan, _: &str, _: &AtomicBool) -> Result<CleanupResult> {
    bail!("stale Upkit symlink staging cleanup is available on Linux only")
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, time::UNIX_EPOCH};

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("upkit");
        let bindir = dir.path().join("bin");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&bindir).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&bindir, fs::Permissions::from_mode(0o700)).unwrap();
        (dir, home, bindir)
    }

    fn stale_link(parent: &Path, home: &Path, suffix: &str) -> PathBuf {
        use std::os::unix::fs::symlink;
        let target = home.join("go/versions/1.2.3/bin/go");
        let staging = tempfile::Builder::new()
            .prefix(PREFIX)
            .tempdir_in(parent)
            .unwrap();
        symlink(target, staging.path().join("link")).unwrap();
        fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let modified = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        fs::File::open(staging.path())
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
        let destination = parent.join(format!("{PREFIX}{suffix}"));
        fs::rename(staging.keep(), &destination).unwrap();
        destination
    }

    #[test]
    fn refuses_filesystem_root_as_bindir() {
        let (_dir, home, _) = fixture();
        let error = preview_with_activity(
            &home,
            Path::new("/"),
            &[],
            &AtomicBool::new(false),
            |paths, _| vec!["no_open_handles_or_cwd_observed"; paths.len()],
        )
        .unwrap_err();
        assert!(error.to_string().contains("filesystem or user-home root"));
    }

    #[test]
    fn previews_and_removes_only_explicitly_selected_staging_dirs() {
        let (_dir, home, bindir) = fixture();
        fs::create_dir(home.join("go")).unwrap();
        fs::set_permissions(home.join("go"), fs::Permissions::from_mode(0o700)).unwrap();
        let target = stale_link(&bindir, &home, "selectedfixture");
        let other = stale_link(&home.join("go"), &home, "otherfixture");
        let cancel = AtomicBool::new(false);
        let no_activity = |paths: &[PathBuf], _: &AtomicBool| {
            vec!["no_open_handles_or_cwd_observed"; paths.len()]
        };
        let inventory = preview_with_activity(&home, &bindir, &[], &cancel, no_activity).unwrap();
        assert_eq!(
            inventory
                .candidates
                .iter()
                .filter(|item| item.status == "eligible")
                .count(),
            2,
            "candidates={:#?}, warnings={:#?}",
            inventory.candidates,
            inventory.warnings
        );
        let plan = preview_with_activity(
            &home,
            &bindir,
            std::slice::from_ref(&target),
            &cancel,
            no_activity,
        )
        .unwrap();
        assert_eq!(plan.selected_count, 1);
        assert_eq!(
            plan.candidates
                .iter()
                .filter(|item| item.status == "eligible")
                .count(),
            2
        );
        assert!(run_with_activity(&plan, "wrong-token", &cancel, no_activity).is_err());
        assert!(target.exists());
        let result = run_with_activity(&plan, &plan.preview_token, &cancel, no_activity).unwrap();
        assert_eq!(result.outcome, "completed");
        assert!(!target.exists());
        assert!(other.exists());
    }

    #[test]
    fn rejects_active_and_changed_staging_entries() {
        let (_dir, home, bindir) = fixture();
        let active = stale_link(&bindir, &home, "activefixture");
        let cancel = AtomicBool::new(false);
        let active_check =
            |paths: &[PathBuf], _: &AtomicBool| vec!["open_handles_or_cwd_observed"; paths.len()];
        let error = preview_with_activity(
            &home,
            &bindir,
            std::slice::from_ref(&active),
            &cancel,
            active_check,
        )
        .unwrap_err();
        assert!(error.to_string().contains("not eligible"));

        let no_activity = |paths: &[PathBuf], _: &AtomicBool| {
            vec!["no_open_handles_or_cwd_observed"; paths.len()]
        };
        let plan = preview_with_activity(
            &home,
            &bindir,
            std::slice::from_ref(&active),
            &cancel,
            no_activity,
        )
        .unwrap();
        fs::remove_file(active.join("link")).unwrap();
        std::os::unix::fs::symlink(home.join("other/tool"), active.join("link")).unwrap();
        let result = run_with_activity(&plan, &plan.preview_token, &cancel, no_activity).unwrap();
        assert_eq!(result.items[0].status, "failed");
        assert!(active.exists());
    }

    #[test]
    fn a_real_open_directory_handle_is_never_marked_eligible() {
        let (_dir, home, bindir) = fixture();
        let active = stale_link(&bindir, &home, "real-handle-fixture");
        let handle = fs::File::open(&active).unwrap();
        let cancel = AtomicBool::new(false);
        let inventory = preview(&home, &bindir, &[], &cancel).unwrap();
        assert_ne!(
            inventory
                .candidates
                .iter()
                .find(|candidate| candidate.path == active)
                .unwrap()
                .status,
            "eligible"
        );
        assert!(preview(&home, &bindir, std::slice::from_ref(&active), &cancel).is_err());
        drop(handle);
        assert!(active.exists());
    }

    #[test]
    fn cancellation_after_quarantine_restores_the_directory() {
        let (_dir, home, bindir) = fixture();
        let target = stale_link(&bindir, &home, "cancel-fixture");
        let cancel = AtomicBool::new(false);
        let no_activity = |paths: &[PathBuf], _: &AtomicBool| {
            vec!["no_open_handles_or_cwd_observed"; paths.len()]
        };
        let plan = preview_with_activity(
            &home,
            &bindir,
            std::slice::from_ref(&target),
            &cancel,
            no_activity,
        )
        .unwrap();
        let mut cancel_after_quarantine = |paths: &[PathBuf], cancel: &AtomicBool| {
            if paths.iter().any(|path| {
                path.parent()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name.to_string_lossy().starts_with(".upkit-cleanup-"))
            }) {
                cancel.store(true, Ordering::Relaxed);
            }
            vec!["no_open_handles_or_cwd_observed"; paths.len()]
        };
        let result = run_with_activity(
            &plan,
            &plan.preview_token,
            &cancel,
            &mut cancel_after_quarantine,
        )
        .unwrap();
        assert_eq!(result.items[0].status, "cancelled");
        assert!(target.join("link").is_symlink());
        assert_eq!(fs::read_dir(&bindir).unwrap().count(), 1);
    }

    #[test]
    fn parent_replacement_after_quarantine_prevents_deletion_and_restores_the_tree() {
        let (_dir, home, bindir) = fixture();
        let target = stale_link(&bindir, &home, "anchor-fixture");
        let cancel = AtomicBool::new(false);
        let no_activity = |paths: &[PathBuf], _: &AtomicBool| {
            vec!["no_open_handles_or_cwd_observed"; paths.len()]
        };
        let plan = preview_with_activity(
            &home,
            &bindir,
            std::slice::from_ref(&target),
            &cancel,
            no_activity,
        )
        .unwrap();
        let moved_bindir = bindir.with_file_name("bin-moved");
        let mut replace_parent = |paths: &[PathBuf], _: &AtomicBool| {
            if paths.iter().any(|path| {
                path.parent()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name.to_string_lossy().starts_with(".upkit-cleanup-"))
            }) {
                fs::rename(&bindir, &moved_bindir).unwrap();
                fs::create_dir(&bindir).unwrap();
                fs::set_permissions(&bindir, fs::Permissions::from_mode(0o700)).unwrap();
            }
            vec!["no_open_handles_or_cwd_observed"; paths.len()]
        };
        let result =
            run_with_activity(&plan, &plan.preview_token, &cancel, &mut replace_parent).unwrap();
        assert_eq!(result.items[0].status, "failed");
        assert!(
            moved_bindir
                .join(target.file_name().unwrap())
                .join("link")
                .is_symlink()
        );
        assert_eq!(fs::read_dir(&bindir).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&moved_bindir).unwrap().count(), 1);
    }

    #[test]
    fn ignores_non_upkit_temp_names_and_malformed_staging_dirs() {
        let (_dir, home, bindir) = fixture();
        let user_dir = bindir.join(".upkit-link-userdata");
        fs::create_dir(&user_dir).unwrap();
        fs::write(user_dir.join("notes"), "preserve").unwrap();
        let unrelated = bindir.join("random");
        fs::create_dir(&unrelated).unwrap();
        let plan =
            preview_with_activity(&home, &bindir, &[], &AtomicBool::new(false), |paths, _| {
                vec!["no_open_handles_or_cwd_observed"; paths.len()]
            })
            .unwrap();
        assert!(plan.candidates.is_empty());
        assert_eq!(
            fs::read_to_string(user_dir.join("notes")).unwrap(),
            "preserve"
        );
    }
}
