//! FreeDesktop Trash inventory and explicitly confirmed item removal.
use serde::Serialize;
#[cfg(target_os = "linux")]
use std::{collections::HashSet, fs};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static TEST_DATA_DIRECTORY: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(target_os = "linux")]
fn linux_data_directory() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(path) = TEST_DATA_DIRECTORY.with(|slot| slot.borrow().clone()) {
        return Some(path);
    }
    dirs::data_dir()
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) struct TestDataDirectoryGuard(Option<PathBuf>);

#[cfg(all(test, target_os = "linux"))]
impl TestDataDirectoryGuard {
    pub(crate) fn install(path: &Path) -> Self {
        Self(TEST_DATA_DIRECTORY.with(|slot| slot.replace(Some(path.to_owned()))))
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for TestDataDirectoryGuard {
    fn drop(&mut self) {
        TEST_DATA_DIRECTORY.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}

fn serialize_trash_location_path<S: serde::Serializer>(
    path: &Path,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    if path.as_os_str().is_empty() {
        <S as serde::Serializer>::serialize_none(serializer)
    } else {
        crate::sweep::serialize_path(path, serializer)
    }
}

#[derive(Debug, Serialize)]
pub struct TrashLocation {
    #[serde(serialize_with = "serialize_trash_location_path")]
    pub path: PathBuf,
    pub kind: &'static str,
    pub item_count: Option<u64>,
    pub logical_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
    pub size_complete: bool,
    pub warnings: Vec<String>,
    pub items: Vec<TrashItem>,
    pub items_complete: bool,
}

#[derive(Debug, Serialize)]
pub struct TrashItem {
    pub name: String,
    pub deletion_date: Option<String>,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    identity: Option<TrashIdentity>,
}

#[cfg(test)]
pub(crate) fn snapshot_item_for_test(name: &str) -> TrashItem {
    TrashItem {
        name: name.into(),
        deletion_date: None,
        #[cfg(target_os = "linux")]
        identity: None,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RetentionItem {
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub location: PathBuf,
    pub name: String,
    pub deletion_date: Option<String>,
    pub age_status: &'static str,
    pub location_complete: bool,
    pub selected: bool,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    pub(crate) identity: Option<TrashIdentity>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub(crate) struct TrashIdentity {
    name: std::ffi::OsString,
    uid: u32,
    metadata: Vec<TrashFingerprint>,
    mount_ids: Vec<Option<u64>>,
    cutoff_unix_nanos: Option<i128>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct TrashFingerprint {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    links: u64,
    size: u64,
    changed_seconds: i64,
    changed_nanos: i64,
    modified_seconds: i64,
    modified_nanos: i64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub(crate) struct TrashDirectoryIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    birth_seconds: i64,
    birth_nanos: u32,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub(crate) struct TrashMountIdentity {
    digest: String,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub(crate) struct TrashLocationIdentity {
    path: String,
    uid: u32,
    root: TrashDirectoryIdentity,
    files: TrashDirectoryIdentity,
    info: TrashDirectoryIdentity,
    mount: TrashMountIdentity,
}

#[cfg(target_os = "linux")]
fn fingerprint(meta: &fs::Metadata) -> TrashFingerprint {
    use std::os::unix::fs::MetadataExt;
    TrashFingerprint {
        device: meta.dev(),
        inode: meta.ino(),
        mode: meta.mode(),
        uid: meta.uid(),
        links: meta.nlink(),
        size: meta.len(),
        changed_seconds: meta.ctime(),
        changed_nanos: meta.ctime_nsec(),
        modified_seconds: meta.mtime(),
        modified_nanos: meta.mtime_nsec(),
    }
}

#[cfg(target_os = "linux")]
fn same_fingerprint_except_ctime(current: &TrashFingerprint, expected: &TrashFingerprint) -> bool {
    current.device == expected.device
        && current.inode == expected.inode
        && current.mode == expected.mode
        && current.uid == expected.uid
        && current.links == expected.links
        && current.size == expected.size
        && current.modified_seconds == expected.modified_seconds
        && current.modified_nanos == expected.modified_nanos
}

#[cfg(target_os = "linux")]
fn read_quarantined_trashinfo(
    file: &fs::File,
    expected: &TrashFingerprint,
    expected_ctime: (i64, i64),
    expected_date: Option<&str>,
) -> anyhow::Result<Option<String>> {
    use anyhow::{Context, bail};
    use std::io::{Read, Seek, SeekFrom};

    let before = file
        .metadata()
        .context("inspect quarantined Trash metadata")?;
    let before_fingerprint = fingerprint(&before);
    if !before.is_file()
        || before.len() > 16_384
        || !same_fingerprint_except_ctime(&before_fingerprint, expected)
        || (
            before_fingerprint.changed_seconds,
            before_fingerprint.changed_nanos,
        ) != expected_ctime
    {
        bail!("quarantined Trash metadata changed after staging");
    }
    let mut reader = file
        .try_clone()
        .context("read quarantined Trash metadata")?;
    reader
        .seek(SeekFrom::Start(0))
        .context("read quarantined Trash metadata")?;
    let mut contents = String::new();
    reader
        .take(16_385)
        .read_to_string(&mut contents)
        .context("read quarantined Trash metadata")?;
    if contents.len() > 16_384 {
        bail!("quarantined Trash metadata is too large");
    }
    let after_fingerprint = fingerprint(
        &file
            .metadata()
            .context("recheck quarantined Trash metadata")?,
    );
    if before_fingerprint != after_fingerprint {
        bail!("quarantined Trash metadata changed while reading");
    }
    let actual_date = parse_deletion_date_contents(&contents);
    if actual_date.as_deref() != expected_date {
        bail!("Trash deletion date changed after preview");
    }
    Ok(actual_date)
}

#[cfg(target_os = "linux")]
fn statx_mount_id(file: &fs::File) -> anyhow::Result<u64> {
    use anyhow::{Context, bail};
    use rustix::fs::{AtFlags, StatxFlags, statx};
    let metadata = file.metadata().context("inspect Trash object")?;
    let stats = statx(
        file,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .context("inspect Trash mount identity")?;
    let required = StatxFlags::INO | StatxFlags::MODE | StatxFlags::UID | StatxFlags::MNT_ID;
    if stats.stx_mask & required.bits() != required.bits()
        || stats.stx_ino != std::os::unix::fs::MetadataExt::ino(&metadata)
        || u32::from(stats.stx_mode) != std::os::unix::fs::MetadataExt::mode(&metadata)
        || stats.stx_uid != std::os::unix::fs::MetadataExt::uid(&metadata)
        || rustix::fs::makedev(stats.stx_dev_major, stats.stx_dev_minor) as u64
            != std::os::unix::fs::MetadataExt::dev(&metadata)
    {
        bail!("Trash object changed while reading its mount identity");
    }
    Ok(stats.stx_mnt_id)
}

#[cfg(target_os = "linux")]
fn path_mount_id(path: &Path, expected: &fs::Metadata) -> Option<u64> {
    use rustix::fs::{AtFlags, StatxFlags, statx};
    use std::os::unix::fs::MetadataExt;
    let stats = statx(
        rustix::fs::CWD,
        path,
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
    )
    .ok()?;
    let required = StatxFlags::INO | StatxFlags::MODE | StatxFlags::UID | StatxFlags::MNT_ID;
    (stats.stx_mask & required.bits() == required.bits()
        && stats.stx_ino == expected.ino()
        && u32::from(stats.stx_mode) == expected.mode()
        && stats.stx_uid == expected.uid()
        && rustix::fs::makedev(stats.stx_dev_major, stats.stx_dev_minor) as u64 == expected.dev())
    .then_some(stats.stx_mnt_id)
}

#[cfg(target_os = "linux")]
fn manual_mount_ids_unchanged(expected: &[Option<u64>], current: &[Option<u64>]) -> bool {
    expected.len() == current.len()
        && expected
            .iter()
            .zip(current)
            .all(|(expected, current)| expected.is_none_or(|expected| *current == Some(expected)))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn display_item_name(name: &std::ffi::OsStr) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut result = String::new();
    for byte in name.as_bytes() {
        if (0x20..=0x7e).contains(byte) && *byte != b'%' {
            result.push(char::from(*byte));
        } else {
            use std::fmt::Write;
            let _ = write!(result, "%{byte:02X}");
        }
    }
    result
}

#[cfg(target_os = "linux")]
fn item_identity(location: &Path, name: &std::ffi::OsStr, uid: u32) -> Option<TrashIdentity> {
    let mut info_name = name.to_os_string();
    info_name.push(".trashinfo");
    let paths = [
        location.to_owned(),
        location.join("files"),
        location.join("info"),
        location.join("files").join(name),
        location.join("info").join(info_name),
    ];
    let metadata = paths
        .iter()
        .map(fs::symlink_metadata)
        .collect::<std::io::Result<Vec<_>>>()
        .ok()?;
    let mount_ids = paths
        .iter()
        .zip(&metadata)
        .map(|(path, metadata)| path_mount_id(path, metadata))
        .collect::<Vec<_>>();
    let mut observed_mount_id = None;
    let mounts_match = mount_ids.iter().flatten().all(|mount_id| {
        if let Some(observed) = observed_mount_id {
            observed == *mount_id
        } else {
            observed_mount_id = Some(*mount_id);
            true
        }
    });
    if metadata.iter().any(|meta| {
        meta.file_type().is_symlink() || std::os::unix::fs::MetadataExt::uid(meta) != uid
    }) || !metadata[..3].iter().all(fs::Metadata::is_dir)
        || !(metadata[3].is_file() || metadata[3].is_dir())
        || !metadata[4].is_file()
        || !mounts_match
    {
        return None;
    }
    Some(TrashIdentity {
        name: name.to_os_string(),
        uid,
        metadata: metadata.iter().map(fingerprint).collect(),
        mount_ids,
        cutoff_unix_nanos: None,
    })
}

#[cfg(target_os = "linux")]
impl TrashLocationIdentity {
    pub(crate) fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RetentionPreview {
    pub older_than_seconds: u64,
    pub items: Vec<RetentionItem>,
    pub warnings: Vec<String>,
    pub cancelled: bool,
    pub complete: bool,
}

#[cfg(target_os = "linux")]
const RETENTION_TIMEZONE_MARGIN_SECONDS: u64 = 48 * 60 * 60;

impl RetentionPreview {
    /// Mark only known-old entries in a complete location; this never authorizes deletion.
    pub fn toggle(&mut self, index: usize) -> anyhow::Result<()> {
        let item = self
            .items
            .get_mut(index)
            .ok_or_else(|| anyhow::anyhow!("item is not in the preview"))?;
        if item.selected {
            item.selected = false;
            return Ok(());
        }
        if self.cancelled || !item.location_complete {
            anyhow::bail!("cannot select items from an incomplete location");
        }
        validate_item(item, Some(self.older_than_seconds))?;
        item.selected = true;
        Ok(())
    }

    /// Select eligible old files and directories from one location without deleting them.
    pub fn select_old_files(
        &mut self,
        location: &std::path::Path,
        cancel: &AtomicBool,
    ) -> anyhow::Result<RetentionSelection> {
        if self.cancelled {
            anyhow::bail!("cannot select from a cancelled preview");
        }
        #[cfg(target_os = "linux")]
        {
            let mut eligible = Vec::new();
            let mut newer_or_unknown = 0usize;
            let mut unsupported = 0usize;
            let mut found = false;
            for (index, item) in self
                .items
                .iter()
                .enumerate()
                .filter(|(_, item)| item.location == location)
            {
                if cancel.load(Ordering::Relaxed) {
                    anyhow::bail!("selection cancelled; no items changed");
                }
                found = true;
                if !item.location_complete {
                    anyhow::bail!("cannot select items from an incomplete location");
                }
                if item.age_status != "older_than_threshold" {
                    newer_or_unknown += 1;
                    continue;
                }
                let Some(identity) = &item.identity else {
                    unsupported += 1;
                    continue;
                };
                let kind = identity.metadata[3].mode & 0o170000;
                if !matches!(kind, 0o100000 | 0o040000)
                    || identity
                        .metadata
                        .iter()
                        .any(|metadata| metadata.uid != identity.uid || metadata.mode & 0o022 != 0)
                    || (kind == 0o100000 && identity.metadata[3].links != 1)
                    || identity.metadata[4].links != 1
                {
                    unsupported += 1;
                    continue;
                }
                validate_item(item, Some(self.older_than_seconds))?;
                if kind == 0o040000 {
                    snapshot_item(item, cancel)?;
                }
                eligible.push(index);
            }
            if !found {
                anyhow::bail!("no items found in the selected location");
            }
            let already_elsewhere = self
                .items
                .iter()
                .filter(|item| item.selected && item.location != location)
                .count();
            if already_elsewhere + eligible.len() > 100 {
                anyhow::bail!("more than 100 eligible items; select a smaller set manually");
            }
            if cancel.load(Ordering::Relaxed) {
                anyhow::bail!("selection cancelled; no items changed");
            }
            for item in self
                .items
                .iter_mut()
                .filter(|item| item.location == location)
            {
                item.selected = false;
            }
            for index in &eligible {
                self.items[*index].selected = true;
            }
            Ok(RetentionSelection {
                location: location.to_owned(),
                eligible: eligible.len(),
                newer_or_unknown,
                unsupported,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (location, cancel);
            anyhow::bail!("Trash retention selection is unsupported on this platform")
        }
    }

    /// Prepare deletion of the explicitly selected items.
    pub fn batch_removal_plan(&self) -> anyhow::Result<TrashBatchPlan> {
        self.batch_removal_plan_with_cancel(&AtomicBool::new(false))
    }

    pub fn batch_removal_plan_with_cancel(
        &self,
        cancel: &AtomicBool,
    ) -> anyhow::Result<TrashBatchPlan> {
        if self.cancelled {
            anyhow::bail!("cannot remove from a cancelled preview");
        }
        let selected = self
            .items
            .iter()
            .filter(|item| item.selected)
            .collect::<Vec<_>>();
        if selected.is_empty() || selected.len() > 100 {
            anyhow::bail!("select between 1 and 100 items for removal");
        }
        #[cfg(target_os = "linux")]
        {
            let mut plans = Vec::with_capacity(selected.len());
            let mut seen = HashSet::new();
            for item in selected {
                if !item.location_complete {
                    anyhow::bail!("cannot remove from an incomplete location");
                }
                let identity = item
                    .identity
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("item identity unavailable"))?;
                if !seen.insert((item.location.clone(), identity.name.clone())) {
                    anyhow::bail!("duplicate Trash selection");
                }
                plans.push(removal_plan(item, Some(self.older_than_seconds), cancel)?);
            }
            batch_from_plans(plans)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cancel;
            anyhow::bail!("Trash deletion is unsupported on this platform")
        }
    }

    /// Prepare deletion of exactly one selected item.
    pub fn removal_plan(&self) -> anyhow::Result<TrashRemovalPlan> {
        let mut plan = self.batch_removal_plan()?;
        if plan.items.len() != 1 {
            anyhow::bail!("select exactly one item for removal");
        }
        Ok(plan.items.remove(0))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RetentionSelection {
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub location: PathBuf,
    pub eligible: usize,
    pub newer_or_unknown: usize,
    pub unsupported: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct TrashBatchPlan {
    pub items: Vec<TrashRemovalPlan>,
    pub preview_token: String,
    pub warning: &'static str,
    pub selection_note: Option<String>,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    empty_location: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    scheduled: Option<ScheduledTrashPlanIdentity>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
struct ScheduledTrashPlanIdentity {
    location_identity: TrashLocationIdentity,
    mount_id: u64,
    age: std::time::Duration,
    cutoff_unix_nanos: i128,
    snapshot_unix_nanos: i128,
    eligible: usize,
    deferred: usize,
    skipped: usize,
}

#[cfg(target_os = "linux")]
fn batch_token(items: &[TrashRemovalPlan], empty: bool) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(if empty {
        b"upkit-trash-empty-v1\0".as_slice()
    } else {
        b"upkit-trash-batch-v1\0".as_slice()
    });
    for item in items {
        hash.update((item.preview_token.len() as u64).to_be_bytes());
        hash.update(item.preview_token.as_bytes());
    }
    hex::encode(hash.finalize())
}

#[cfg(target_os = "linux")]
fn scheduled_batch_token(
    items: &[TrashRemovalPlan],
    scheduled: &ScheduledTrashPlanIdentity,
) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let location = serde_json::to_vec(&scheduled.location_identity)?;
    let base = batch_token(items, false);
    let age_seconds = scheduled.age.as_secs().to_be_bytes();
    let age_nanos = scheduled.age.subsec_nanos().to_be_bytes();
    let mount_id = scheduled.mount_id.to_be_bytes();
    let cutoff = scheduled.cutoff_unix_nanos.to_be_bytes();
    let snapshot = scheduled.snapshot_unix_nanos.to_be_bytes();
    let eligible = (scheduled.eligible as u64).to_be_bytes();
    let deferred = (scheduled.deferred as u64).to_be_bytes();
    let skipped = (scheduled.skipped as u64).to_be_bytes();
    let mut hash = Sha256::new();
    hash.update(b"upkit-scheduled-trash-batch-v1\0");
    for value in [
        base.as_bytes(),
        &age_seconds,
        &age_nanos,
        &mount_id,
        &cutoff,
        &snapshot,
        &eligible,
        &deferred,
        &skipped,
        &location,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(target_os = "linux")]
pub(crate) fn batch_from_plans(items: Vec<TrashRemovalPlan>) -> anyhow::Result<TrashBatchPlan> {
    if items.is_empty() || items.len() > 100 {
        anyhow::bail!("select between 1 and 100 items for removal");
    }
    Ok(TrashBatchPlan {
        preview_token: batch_token(&items, false),
        items,
        warning: "Deletion is permanent, including all contents of listed directories. Concurrent filesystem writers can race final checks; failures may leave partial trees or metadata in quarantine, so inspect individual results.",
        selection_note: None,
        empty_location: None,
        scheduled: None,
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct TrashRemovalPlan {
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub location: PathBuf,
    pub name: String,
    pub deletion_date: Option<String>,
    pub kind: &'static str,
    pub descendant_count: usize,
    pub logical_bytes: u64,
    pub preview_token: String,
    pub warning: &'static str,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    item: RetentionItem,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    older_than_seconds: Option<u64>,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    tree: Option<crate::guarded_tree::TreeSnapshot>,
}

#[cfg(target_os = "linux")]
fn snapshot_item(
    item: &RetentionItem,
    cancel: &AtomicBool,
) -> anyhow::Result<crate::guarded_tree::TreeSnapshot> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    let expected = item
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("item identity unavailable"))?;
    let root = fs::File::from(openat2(
        rustix::fs::CWD,
        &item.location,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    let files = fs::File::from(openat2(
        &root,
        "files",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )?);
    let directory = fs::File::from(openat2(
        &files,
        &expected.name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )?);
    let mount_ids = [
        statx_mount_id(&root).ok(),
        statx_mount_id(&files).ok(),
        None,
        statx_mount_id(&directory).ok(),
    ];
    if fingerprint(&root.metadata()?) != expected.metadata[0]
        || fingerprint(&files.metadata()?) != expected.metadata[1]
        || fingerprint(&directory.metadata()?) != expected.metadata[3]
        || [0, 1, 3].into_iter().any(|index| {
            expected.mount_ids[index].is_some_and(|expected| mount_ids[index] != Some(expected))
        })
    {
        anyhow::bail!("Trash directory changed; refresh the preview");
    }
    crate::guarded_tree::snapshot(directory, expected.uid, cancel)
}

#[cfg(target_os = "linux")]
fn removal_plan(
    item: &RetentionItem,
    age: Option<u64>,
    cancel: &AtomicBool,
) -> anyhow::Result<TrashRemovalPlan> {
    validate_item(item, age)?;
    let identity = item
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("item identity unavailable"))?;
    let mode = identity.metadata[3].mode & 0o170000;
    let tree = match mode {
        0o100000 if identity.metadata[3].links == 1 => None,
        0o040000 => Some(snapshot_item(item, cancel)?),
        _ => anyhow::bail!("Trash item is not a supported file or directory"),
    };
    if identity
        .metadata
        .iter()
        .any(|metadata| metadata.uid != identity.uid || metadata.mode & 0o022 != 0)
        || identity.metadata[4].links != 1
    {
        anyhow::bail!("Trash item and metadata must be user-owned, private and unlinked");
    }
    Ok(TrashRemovalPlan {
        location: item.location.clone(),
        name: item.name.clone(),
        deletion_date: item.deletion_date.clone(),
        kind: if tree.is_some() { "directory" } else { "file" },
        descendant_count: tree.as_ref().map_or(0, |tree| tree.count()),
        logical_bytes: tree
            .as_ref()
            .map_or(identity.metadata[3].size, |tree| tree.logical_bytes),
        preview_token: removal_token(item, age, tree.as_ref())?,
        warning: if tree.is_some() {
            "Permanent deletion removes the entire directory and its contents. Concurrent filesystem writers can race final checks. Interruption or failure can leave a partially removed tree in private quarantine."
        } else {
            "Permanent deletion cannot be undone. Concurrent filesystem writers can race final checks. If interrupted, an item may remain in a private quarantine directory."
        },
        item: item.clone(),
        older_than_seconds: age,
        tree,
    })
}

#[cfg(target_os = "linux")]
fn removal_token(
    item: &RetentionItem,
    age_seconds: Option<u64>,
    tree: Option<&crate::guarded_tree::TreeSnapshot>,
) -> anyhow::Result<String> {
    use anyhow::Context;
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    let identity = item
        .identity
        .as_ref()
        .context("item identity unavailable")?;
    let boot = fs::read("/proc/sys/kernel/random/boot_id").context("read boot identity")?;
    let metadata = serde_json::to_vec(&identity.metadata)?;
    let mount_ids = serde_json::to_vec(&identity.mount_ids)?;
    let cutoff = identity.cutoff_unix_nanos.unwrap_or_default().to_be_bytes();
    let age = age_seconds.unwrap_or_default().to_be_bytes();
    let uid = identity.uid.to_be_bytes();
    let mut hash = Sha256::new();
    for value in [
        if age_seconds.is_some() {
            b"upkit-trash-removal-v1".as_slice()
        } else {
            b"upkit-trash-removal-all-ages-v1".as_slice()
        },
        &boot,
        item.location.as_os_str().as_bytes(),
        identity.name.as_os_str().as_bytes(),
        &uid,
        &age,
        item.deletion_date.as_deref().unwrap_or("").as_bytes(),
        &metadata,
        &mount_ids,
        &cutoff,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    if let Some(tree) = tree {
        hash.update(b"upkit-trash-tree-v1\0");
        hash.update(tree.digest.as_bytes());
        hash.update(tree.logical_bytes.to_be_bytes());
        hash.update((tree.count() as u64).to_be_bytes());
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(target_os = "linux")]
fn validate_plan_integrity(plan: &TrashRemovalPlan, token: &str) -> anyhow::Result<()> {
    use anyhow::{Context, bail};
    if token != plan.preview_token
        || removal_token(&plan.item, plan.older_than_seconds, plan.tree.as_ref())? != token
        || plan.location != plan.item.location
        || plan.name != plan.item.name
        || plan.deletion_date != plan.item.deletion_date
    {
        bail!("Trash deletion plan does not match the preview");
    }
    let expected = plan
        .item
        .identity
        .as_ref()
        .context("item identity unavailable")?;
    let (kind, descendants, bytes) = plan
        .tree
        .as_ref()
        .map_or(("file", 0, expected.metadata[3].size), |tree| {
            ("directory", tree.count(), tree.logical_bytes)
        });
    if plan.kind != kind || plan.descendant_count != descendants || plan.logical_bytes != bytes {
        bail!("Trash deletion plan does not match the preview");
    }
    Ok(())
}

/// Permanently remove a previously reviewed item. The caller must confirm first.
#[cfg(target_os = "linux")]
pub fn remove_file(plan: &TrashRemovalPlan, token: &str) -> anyhow::Result<&'static str> {
    if plan
        .item
        .identity
        .as_ref()
        .is_some_and(|identity| identity.cutoff_unix_nanos.is_some())
    {
        anyhow::bail!("scheduled Trash items require the scheduled executor");
    }
    remove_file_with_cancel_and_hook(
        plan,
        token,
        &AtomicBool::new(false),
        &|| Ok(()),
        || {},
        || {},
    )
}

#[cfg(all(test, target_os = "linux"))]
fn remove_file_after_staging(
    plan: &TrashRemovalPlan,
    token: &str,
    after_staging: impl FnOnce(),
) -> anyhow::Result<&'static str> {
    remove_file_with_cancel_and_hook(
        plan,
        token,
        &AtomicBool::new(false),
        &|| Ok(()),
        after_staging,
        || {},
    )
}

#[cfg(target_os = "linux")]
fn remove_file_with_cancel_and_hook(
    plan: &TrashRemovalPlan,
    token: &str,
    cancel: &AtomicBool,
    guard: &dyn Fn() -> anyhow::Result<()>,
    after_staging: impl FnOnce(),
    mut after_tree_entry: impl FnMut(),
) -> anyhow::Result<&'static str> {
    use anyhow::{Context, bail};
    use rustix::fs::{
        AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, openat2, renameat_with, unlinkat,
    };
    use std::{
        os::unix::fs::MetadataExt,
        sync::atomic::AtomicU64,
        time::{SystemTime, UNIX_EPOCH},
    };

    validate_plan_integrity(plan, token)?;
    validate_item(&plan.item, plan.older_than_seconds)?;
    if let Some(cutoff) = plan
        .item
        .identity
        .as_ref()
        .and_then(|identity| identity.cutoff_unix_nanos)
    {
        scheduled_age_evidence(&plan.item, cutoff)?;
    }
    if let Some(tree) = &plan.tree {
        let fresh = snapshot_item(&plan.item, cancel)?;
        if fresh.digest != tree.digest
            || fresh.logical_bytes != tree.logical_bytes
            || fresh.count() != tree.count()
        {
            bail!("Trash directory contents changed; review the preview again");
        }
    }
    let expected = plan
        .item
        .identity
        .as_ref()
        .context("item identity unavailable")?;
    if expected.uid != rustix::process::geteuid().as_raw() {
        bail!("Trash owner changed");
    }
    let root = fs::File::from(
        openat2(
            rustix::fs::CWD,
            &plan.item.location,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .context("open Trash location without links")?,
    );
    let open = |directory: &fs::File, name: &std::ffi::OsStr, flags| -> anyhow::Result<fs::File> {
        Ok(fs::File::from(openat2(
            directory,
            name,
            flags | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?))
    };
    let files = open(
        &root,
        std::ffi::OsStr::new("files"),
        OFlags::RDONLY | OFlags::DIRECTORY,
    )
    .context("open Trash files directory")?;
    let info = open(
        &root,
        std::ffi::OsStr::new("info"),
        OFlags::RDONLY | OFlags::DIRECTORY,
    )
    .context("open Trash info directory")?;
    let mut info_name = expected.name.clone();
    info_name.push(".trashinfo");
    let item = open(&files, &expected.name, OFlags::PATH).context("open Trash item")?;
    let metadata_flags = if plan.older_than_seconds.is_some() {
        OFlags::RDONLY
    } else {
        OFlags::PATH
    };
    let metadata = open(&info, &info_name, metadata_flags).context("open Trash metadata")?;
    let opened = [&root, &files, &info, &item, &metadata]
        .into_iter()
        .map(|file| file.metadata())
        .collect::<std::io::Result<Vec<_>>>()?;
    let opened_mount_ids = [&root, &files, &info, &item, &metadata]
        .into_iter()
        .map(|file| statx_mount_id(file).ok())
        .collect::<Vec<_>>();
    if opened.iter().map(fingerprint).collect::<Vec<_>>() != expected.metadata
        || !manual_mount_ids_unchanged(&expected.mount_ids, &opened_mount_ids)
    {
        bail!("item or Trash location changed; refresh the preview");
    }
    if opened[..3]
        .iter()
        .any(|meta| meta.uid() != expected.uid || meta.mode() & 0o022 != 0)
        || opened[3].uid() != expected.uid
        || opened[3].mode() & 0o022 != 0
        || !(opened[3].is_file() && opened[3].nlink() == 1
            || opened[3].is_dir() && plan.tree.is_some())
        || !opened[4].is_file()
        || opened[4].uid() != expected.uid
        || opened[4].nlink() != 1
        || opened[4].mode() & 0o022 != 0
    {
        bail!("Trash directories and files must be user-owned, private and singly linked");
    }
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut private = None;
    for _ in 0..32 {
        let name = format!(
            ".upkit-delete-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        match rustix::fs::mkdirat(&files, name.as_str(), Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) => {
                private = Some(name);
                break;
            }
            Err(rustix::io::Errno::EXIST) => continue,
            Err(err) => return Err(err).context("create private Trash quarantine"),
        }
    }
    let private = private.context("could not allocate private Trash quarantine")?;
    let quarantine_path = plan.item.location.join("files").join(&private);
    let quarantine = match open(
        &files,
        std::ffi::OsStr::new(&private),
        OFlags::RDONLY | OFlags::DIRECTORY,
    ) {
        Ok(directory) => directory,
        Err(err) => {
            let _ = unlinkat(&files, private.as_str(), AtFlags::REMOVEDIR);
            return Err(err).context("open private Trash quarantine");
        }
    };
    let same = |file: &fs::File, expected: &fs::Metadata| -> bool {
        file.metadata().is_ok_and(|actual| {
            (actual.is_file() == expected.is_file() && actual.is_dir() == expected.is_dir())
                && actual.dev() == expected.dev()
                && actual.ino() == expected.ino()
                && actual.uid() == expected.uid()
                && actual.mode() == expected.mode()
                && actual.nlink() == expected.nlink()
                && actual.len() == expected.len()
                && actual.mtime() == expected.mtime()
                && actual.mtime_nsec() == expected.mtime_nsec()
        })
    };
    let mut staged_item = false;
    let mut staged_info = false;
    let mut removed_item = false;
    let mut partial_tree = false;
    let mut preserve_quarantine = false;
    let action = (|| -> anyhow::Result<&'static str> {
        guard().context("scheduled policy or Trash scope changed before staging")?;
        if let Some(cutoff) = plan
            .item
            .identity
            .as_ref()
            .and_then(|identity| identity.cutoff_unix_nanos)
        {
            scheduled_age_evidence(&plan.item, cutoff)?;
        }
        if plan.tree.is_none() && fingerprint(&item.metadata()?) != expected.metadata[3] {
            bail!("Trash file changed after preview");
        }
        renameat_with(
            &files,
            expected.name.as_os_str(),
            &quarantine,
            "item",
            RenameFlags::NOREPLACE,
        )
        .context("quarantine Trash item")?;
        staged_item = true;
        let moved = open(&quarantine, std::ffi::OsStr::new("item"), OFlags::PATH)
            .context("inspect quarantined item")?;
        if !same(&moved, &opened[3]) || !same(&item, &opened[3]) {
            bail!("quarantined item changed");
        }
        let staged_file_ctime = if plan.tree.is_none() {
            let staged = moved.metadata()?;
            Some((staged.ctime(), staged.ctime_nsec()))
        } else {
            None
        };
        after_staging();
        guard().context("scheduled policy or Trash scope changed after staging")?;
        if fingerprint(&metadata.metadata()?) != expected.metadata[4] {
            bail!("Trash metadata changed after preview");
        }
        renameat_with(
            &info,
            info_name.as_os_str(),
            &quarantine,
            "info",
            RenameFlags::NOREPLACE,
        )
        .context("quarantine Trash metadata")?;
        staged_info = true;
        let moved_info = open(&quarantine, std::ffi::OsStr::new("info"), OFlags::PATH)
            .context("inspect quarantined metadata")?;
        if !same(&moved_info, &opened[4])
            || !same(&metadata, &opened[4])
            || !same(&moved, &opened[3])
        {
            bail!("quarantined item or metadata changed");
        }
        let staged_info_ctime = if plan.older_than_seconds.is_some() {
            let baseline = metadata.metadata()?;
            let expected_date = plan.deletion_date.as_deref();
            let cutoff = plan
                .item
                .identity
                .as_ref()
                .and_then(|identity| identity.cutoff_unix_nanos);
            read_quarantined_trashinfo(
                &metadata,
                &expected.metadata[4],
                (baseline.ctime(), baseline.ctime_nsec()),
                expected_date,
            )?;
            if let Some(cutoff) = cutoff {
                scheduled_age_evidence(&plan.item, cutoff)?;
            }
            Some((baseline.ctime(), baseline.ctime_nsec()))
        } else {
            None
        };
        let verify_aged_metadata = || -> anyhow::Result<()> {
            if let Some(expected_ctime) = staged_info_ctime {
                read_quarantined_trashinfo(
                    &metadata,
                    &expected.metadata[4],
                    expected_ctime,
                    plan.deletion_date.as_deref(),
                )?;
                if let Some(cutoff) = expected.cutoff_unix_nanos {
                    scheduled_age_evidence(&plan.item, cutoff)?;
                }
            }
            Ok(())
        };
        if cancel.load(Ordering::Relaxed) {
            bail!("Trash removal cancelled");
        }
        guard().context("scheduled policy or Trash scope changed before permanent removal")?;
        verify_aged_metadata()?;
        if let Some(cutoff) = plan
            .item
            .identity
            .as_ref()
            .and_then(|identity| identity.cutoff_unix_nanos)
        {
            scheduled_age_evidence(&plan.item, cutoff)?;
        }
        if let Some(tree) = &plan.tree {
            let directory = open(
                &quarantine,
                std::ffi::OsStr::new("item"),
                OFlags::RDONLY | OFlags::DIRECTORY,
            )?;
            if !same(&directory, &opened[3]) {
                bail!("quarantined directory changed");
            }
            let fresh =
                crate::guarded_tree::snapshot(directory.try_clone()?, expected.uid, cancel)?;
            if fresh.digest != tree.digest
                || fresh.logical_bytes != tree.logical_bytes
                || fresh.count() != tree.count()
            {
                bail!("quarantined directory contents changed");
            }
            crate::guarded_tree::remove(
                &quarantine,
                std::ffi::OsStr::new("item"),
                &directory,
                tree,
                cancel,
                &mut partial_tree,
                |removed| {
                    if removed {
                        after_tree_entry();
                    }
                    guard().context(
                        "scheduled policy or Trash scope changed during directory removal",
                    )?;
                    verify_aged_metadata()
                },
            )?;
            if cancel.load(Ordering::Relaxed) {
                bail!("Trash directory removal cancelled");
            }
            let current = open(
                &quarantine,
                std::ffi::OsStr::new("item"),
                OFlags::PATH | OFlags::NOFOLLOW,
            )?
            .metadata()?;
            let original = directory.metadata()?;
            if current.dev() != original.dev()
                || current.ino() != original.ino()
                || current.uid() != original.uid()
                || current.mode() != original.mode()
            {
                bail!("quarantined Trash directory was replaced");
            }
            guard().context(
                "scheduled policy or Trash scope changed before removing quarantined directory",
            )?;
            verify_aged_metadata()?;
            unlinkat(&quarantine, "item", AtFlags::REMOVEDIR)
                .context("remove quarantined directory")?;
        } else {
            guard().context(
                "scheduled policy or Trash scope changed before removing quarantined item",
            )?;
            verify_aged_metadata()?;
            let current = open(
                &quarantine,
                std::ffi::OsStr::new("item"),
                OFlags::PATH | OFlags::NOFOLLOW,
            )?;
            let current_metadata = current.metadata()?;
            if !same(&current, &opened[3])
                || staged_file_ctime.is_some_and(|ctime| {
                    (current_metadata.ctime(), current_metadata.ctime_nsec()) != ctime
                })
            {
                bail!("quarantined Trash file changed while staged");
            }
            unlinkat(&quarantine, "item", AtFlags::empty()).context("remove quarantined item")?;
        }
        staged_item = false;
        removed_item = true;
        preserve_quarantine = true;
        guard().context(
            "scheduled policy or Trash scope changed before removing quarantined metadata",
        )?;
        verify_aged_metadata()?;
        unlinkat(&quarantine, "info", AtFlags::empty()).context("remove quarantined metadata")?;
        staged_info = false;
        let absent = |directory: &fs::File, name: &std::ffi::OsStr| {
            matches!(
                rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW),
                Err(rustix::io::Errno::NOENT)
            )
        };
        Ok(
            if absent(&files, &expected.name) && absent(&info, &info_name) {
                "verified_absent"
            } else {
                "unverified_replacement"
            },
        )
    })();
    let mut rollback_failed = false;
    if staged_info
        && !partial_tree
        && !preserve_quarantine
        && renameat_with(
            &quarantine,
            "info",
            &info,
            info_name.as_os_str(),
            RenameFlags::NOREPLACE,
        )
        .is_err()
    {
        rollback_failed = true;
    }
    if staged_item
        && !partial_tree
        && !preserve_quarantine
        && renameat_with(
            &quarantine,
            "item",
            &files,
            expected.name.as_os_str(),
            RenameFlags::NOREPLACE,
        )
        .is_err()
    {
        rollback_failed = true;
    }
    if partial_tree && staged_item {
        rollback_failed = true;
    }
    if preserve_quarantine && staged_info {
        rollback_failed = true;
    }
    if !rollback_failed && unlinkat(&files, private.as_str(), AtFlags::REMOVEDIR).is_err() {
        rollback_failed = true;
    }
    match action {
        Ok(status) if !rollback_failed => Ok(status),
        Ok(_) => bail!(
            "item removed; inspect quarantine {}",
            crate::sweep::display_path(&quarantine_path)
        ),
        Err(err) => bail!(
            "{err:#}; item {}{}",
            if partial_tree && staged_item {
                "may be partially removed"
            } else if removed_item {
                "was permanently removed"
            } else {
                "was not intentionally removed"
            },
            if rollback_failed {
                format!(
                    "; inspect quarantine {}",
                    crate::sweep::display_path(&quarantine_path)
                )
            } else {
                String::new()
            }
        ),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn remove_file(_: &TrashRemovalPlan, _: &str) -> anyhow::Result<&'static str> {
    anyhow::bail!("Trash deletion is unsupported on this platform")
}

#[derive(Debug, Serialize)]
pub struct TrashBatchItemResult {
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub location: PathBuf,
    pub name: String,
    pub status: &'static str,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TrashBatchResult {
    pub outcome: &'static str,
    pub items: Vec<TrashBatchItemResult>,
    pub selected_location_files_empty: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled_deferred: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled_skipped: Option<usize>,
}

/// Delete only the listed items after a single explicit batch confirmation.
#[cfg(target_os = "linux")]
pub fn remove_batch(plan: &TrashBatchPlan, token: &str) -> anyhow::Result<TrashBatchResult> {
    remove_batch_with_progress(plan, token, &AtomicBool::new(false), |_, _| {})
}

#[cfg(target_os = "linux")]
pub fn remove_batch_with_progress(
    plan: &TrashBatchPlan,
    token: &str,
    cancel: &AtomicBool,
    progress: impl FnMut(usize, usize),
) -> anyhow::Result<TrashBatchResult> {
    if plan.scheduled.is_some() {
        anyhow::bail!("scheduled Trash batches require the scheduled executor");
    }
    remove_batch_with_guard(plan, token, cancel, &|| Ok(()), false, progress)
}

#[cfg(target_os = "linux")]
pub(crate) fn remove_scheduled_batch_with_guard(
    plan: &TrashBatchPlan,
    token: &str,
    cancel: &AtomicBool,
    guard: &dyn Fn() -> anyhow::Result<()>,
    progress: impl FnMut(usize, usize),
) -> anyhow::Result<TrashBatchResult> {
    remove_scheduled_batch_with_guard_and_clock(
        plan,
        token,
        cancel,
        guard,
        || {
            crate::scheduled_trash_cleanup::clock_now()
                .timestamp_nanos_opt()
                .map(i128::from)
                .ok_or_else(|| anyhow::anyhow!("scheduled clock is outside the supported range"))
        },
        progress,
    )
}

#[cfg(target_os = "linux")]
fn validate_scheduled_batch(plan: &TrashBatchPlan) -> anyhow::Result<&ScheduledTrashPlanIdentity> {
    use anyhow::{Context, bail};
    let scheduled = plan
        .scheduled
        .as_ref()
        .context("scheduled Trash plan identity is missing")?;
    if plan.items.is_empty()
        || plan.items.len() > MAX_SCHEDULED_TRASH_REMOVALS
        || plan.empty_location.is_some()
    {
        bail!("scheduled Trash batch exceeds its safe item limit or is empty");
    }
    if scheduled.eligible != plan.items.len().saturating_add(scheduled.deferred) {
        bail!("scheduled Trash batch counters do not match the reviewed preview");
    }
    validate_scheduled_retention_age(scheduled.age)?;
    let conservative_age = scheduled
        .age
        .checked_add(std::time::Duration::from_secs(
            RETENTION_TIMEZONE_MARGIN_SECONDS,
        ))
        .ok_or_else(|| anyhow::anyhow!("retention age is too large"))?;
    let cutoff_delta = i128::try_from(conservative_age.as_nanos())
        .map_err(|_| anyhow::anyhow!("retention age is too large"))?;
    if scheduled.snapshot_unix_nanos.checked_sub(cutoff_delta) != Some(scheduled.cutoff_unix_nanos)
    {
        bail!("scheduled Trash plan age and snapshot do not match");
    }
    let location = Path::new(scheduled.location_identity.path());
    let mut seen = HashSet::new();
    for item in &plan.items {
        let identity = item
            .item
            .identity
            .as_ref()
            .context("scheduled Trash item identity is missing")?;
        if item.location != location
            || item.older_than_seconds != Some(scheduled.age.as_secs())
            || identity.uid != scheduled.location_identity.uid
            || identity.cutoff_unix_nanos != Some(scheduled.cutoff_unix_nanos)
            || identity.metadata.len() != 5
            || !scheduled_mount_ids_match(&identity.mount_ids, scheduled.mount_id)
            || !seen.insert(identity.name.clone())
        {
            bail!("scheduled Trash batch contains an item outside its reviewed scope");
        }
    }
    Ok(scheduled)
}

#[cfg(target_os = "linux")]
fn remove_scheduled_batch_with_guard_and_clock(
    plan: &TrashBatchPlan,
    token: &str,
    cancel: &AtomicBool,
    guard: &dyn Fn() -> anyhow::Result<()>,
    current_unix_nanos: impl Fn() -> anyhow::Result<i128>,
    progress: impl FnMut(usize, usize),
) -> anyhow::Result<TrashBatchResult> {
    let scheduled = validate_scheduled_batch(plan)?;
    let scheduled_guard = || {
        validate_scheduled_clock(scheduled.snapshot_unix_nanos, current_unix_nanos()?)?;
        let (current_identity, current_mount_id) =
            scheduled_location_identity_open(Path::new(scheduled.location_identity.path()))?;
        if current_identity != scheduled.location_identity || current_mount_id != scheduled.mount_id
        {
            anyhow::bail!("scheduled Trash location identity changed");
        }
        guard()
    };
    remove_batch_with_guard(plan, token, cancel, &scheduled_guard, true, progress)
}

#[cfg(target_os = "linux")]
fn remove_batch_with_guard(
    plan: &TrashBatchPlan,
    token: &str,
    cancel: &AtomicBool,
    guard: &dyn Fn() -> anyhow::Result<()>,
    stop_after_failure: bool,
    mut progress: impl FnMut(usize, usize),
) -> anyhow::Result<TrashBatchResult> {
    use anyhow::{Context, bail};
    let expected_token = if let Some(scheduled) = &plan.scheduled {
        scheduled_batch_token(&plan.items, scheduled)?
    } else {
        batch_token(&plan.items, plan.empty_location.is_some())
    };
    if plan.items.is_empty()
        || plan.items.len() > 100
        || token != plan.preview_token
        || expected_token != token
    {
        bail!("Trash batch does not match the preview");
    }
    guard()?;
    if let Some(location) = &plan.empty_location {
        if plan.items.iter().any(|item| &item.location != location) {
            bail!("Trash empty plan contains another location");
        }
        let fresh = empty_preview(location, cancel)?;
        if fresh
            .as_ref()
            .is_none_or(|fresh| fresh.preview_token != token)
        {
            bail!("Trash location changed; review the complete selection again");
        }
    }
    let mut seen = HashSet::new();
    for item in &plan.items {
        validate_plan_integrity(item, &item.preview_token)?;
        let identity = item
            .item
            .identity
            .as_ref()
            .context("item identity unavailable")?;
        if !seen.insert((item.location.clone(), identity.name.clone())) {
            bail!("duplicate Trash selection");
        }
    }
    let mut changed = HashSet::new();
    let mut blocked = HashSet::new();
    let mut stopped = false;
    let mut items = Vec::with_capacity(plan.items.len());
    for (index, original) in plan.items.iter().enumerate() {
        progress(index, plan.items.len());
        if stopped {
            items.push(TrashBatchItemResult {
                location: original.location.clone(),
                name: original.name.clone(),
                status: "not_attempted",
                error: None,
            });
            continue;
        }
        if cancel.load(Ordering::Relaxed) {
            items.push(TrashBatchItemResult {
                location: original.location.clone(),
                name: original.name.clone(),
                status: "cancelled",
                error: None,
            });
            stopped |= stop_after_failure;
            continue;
        }
        let outcome = if stopped || blocked.contains(&original.location) {
            Err(anyhow::anyhow!(
                "earlier scheduled result was not verified; inspect before retrying"
            ))
        } else {
            let refreshed = if changed.contains(&original.location) {
                refresh_batch_item(original)
            } else {
                Ok(original.clone())
            };
            guard().and_then(|()| {
                refreshed.and_then(|item| {
                    remove_file_with_cancel_and_hook(
                        &item,
                        &item.preview_token,
                        cancel,
                        guard,
                        || {},
                        || {},
                    )
                })
            })
        };
        let (status, error) = match outcome {
            Ok("verified_absent") => {
                changed.insert(original.location.clone());
                ("verified_absent", None)
            }
            Ok(status) => {
                blocked.insert(original.location.clone());
                stopped |= stop_after_failure;
                (status, None)
            }
            Err(error) => {
                blocked.insert(original.location.clone());
                stopped |= stop_after_failure;
                (
                    "failed_or_skipped",
                    Some(
                        format!("{error:#}")
                            .chars()
                            .flat_map(char::escape_default)
                            .collect(),
                    ),
                )
            }
        };
        items.push(TrashBatchItemResult {
            location: original.location.clone(),
            name: original.name.clone(),
            status,
            error,
        });
        if stopped {
            for remaining in plan.items.iter().skip(index + 1) {
                items.push(TrashBatchItemResult {
                    location: remaining.location.clone(),
                    name: remaining.name.clone(),
                    status: "not_attempted",
                    error: None,
                });
            }
            break;
        }
    }
    let successes = items
        .iter()
        .filter(|item| item.status == "verified_absent")
        .count();
    let files_empty = plan.empty_location.as_ref().map(|location| {
        let report = scoped_status(location, cancel);
        !report.cancelled
            && report.locations.iter().any(|entry| {
                &entry.path == location
                    && entry.items_complete
                    && entry.warnings.is_empty()
                    && entry.items.is_empty()
            })
    });
    let scheduled_deferred = plan.scheduled.as_ref().map(|scheduled| scheduled.deferred);
    let scheduled_skipped = plan.scheduled.as_ref().map(|scheduled| scheduled.skipped);
    let cancelled_before_change = successes == 0
        && items.iter().any(|item| item.status == "cancelled")
        && items
            .iter()
            .all(|item| matches!(item.status, "cancelled" | "not_attempted"));
    Ok(TrashBatchResult {
        outcome: if successes == items.len() {
            if files_empty == Some(false) || scheduled_deferred.is_some_and(|deferred| deferred > 0)
            {
                "partial"
            } else {
                "completed"
            }
        } else if cancelled_before_change {
            "cancelled"
        } else if stop_after_failure {
            "partial"
        } else if successes == 0 {
            "failed_or_unknown"
        } else {
            "partial"
        },
        items,
        selected_location_files_empty: files_empty,
        scheduled_deferred,
        scheduled_skipped,
    })
}

#[cfg(target_os = "linux")]
fn refresh_batch_item(original: &TrashRemovalPlan) -> anyhow::Result<TrashRemovalPlan> {
    use anyhow::{Context, bail};
    let old = original
        .item
        .identity
        .as_ref()
        .context("item identity unavailable")?;
    let mut current = item_identity(&original.location, &old.name, old.uid)
        .context("item or Trash location changed")?;
    current.cutoff_unix_nanos = old.cutoff_unix_nanos;
    let same_directory = |old: &TrashFingerprint, new: &TrashFingerprint| {
        old.device == new.device
            && old.inode == new.inode
            && old.mode == new.mode
            && old.uid == new.uid
    };
    if !old.metadata[..3]
        .iter()
        .zip(&current.metadata[..3])
        .all(|(old, new)| same_directory(old, new))
        || old.metadata[3..] != current.metadata[3..]
        || !manual_mount_ids_unchanged(&old.mount_ids, &current.mount_ids)
    {
        bail!("item or Trash directory changed after batch preview");
    }
    let mut plan = original.clone();
    plan.item.identity = Some(current);
    validate_item(&plan.item, plan.older_than_seconds)?;
    plan.preview_token = removal_token(&plan.item, plan.older_than_seconds, plan.tree.as_ref())?;
    Ok(plan)
}

#[cfg(not(target_os = "linux"))]
pub fn remove_batch(_: &TrashBatchPlan, _: &str) -> anyhow::Result<TrashBatchResult> {
    anyhow::bail!("Trash deletion is unsupported on this platform")
}

#[cfg(not(target_os = "linux"))]
pub fn remove_batch_with_progress(
    _: &TrashBatchPlan,
    _: &str,
    _: &AtomicBool,
    _: impl FnMut(usize, usize),
) -> anyhow::Result<TrashBatchResult> {
    anyhow::bail!("Trash deletion is unsupported on this platform")
}

#[cfg(target_os = "linux")]
fn validate_item(item: &RetentionItem, age_seconds: Option<u64>) -> anyhow::Result<()> {
    use chrono::{Local, NaiveDateTime, TimeZone, Utc};
    if age_seconds.is_some() && item.age_status != "older_than_threshold" {
        anyhow::bail!("only items older than the threshold can be selected");
    }
    let expected = item
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("item identity is unavailable; refresh the preview"))?;
    let current = item_identity(&item.location, &expected.name, expected.uid)
        .ok_or_else(|| anyhow::anyhow!("item or Trash location changed; refresh the preview"))?;
    if current.metadata != expected.metadata
        || !manual_mount_ids_unchanged(&expected.mount_ids, &current.mount_ids)
    {
        anyhow::bail!("item or Trash location changed; refresh the preview");
    }
    if let Some(cutoff) = expected.cutoff_unix_nanos {
        return scheduled_age_evidence(item, cutoff);
    }
    let Some(age_seconds) = age_seconds else {
        return Ok(());
    };
    let cutoff = chrono::TimeDelta::from_std(std::time::Duration::from_secs(age_seconds))
        .ok()
        .and_then(|age| Utc::now().checked_sub_signed(age))
        .ok_or_else(|| anyhow::anyhow!("retention age is too large"))?;
    let date = item
        .deletion_date
        .as_deref()
        .and_then(|date| NaiveDateTime::parse_from_str(date, "%Y-%m-%dT%H:%M:%S").ok())
        .and_then(|date| Local.from_local_datetime(&date).single());
    if !date.is_some_and(|date| date.with_timezone(&Utc) <= cutoff) {
        anyhow::bail!("item age is no longer verified; refresh the preview");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn timestamp_nanos(seconds: i64, nanos: i64) -> Option<i128> {
    (seconds >= 0 && (0..1_000_000_000).contains(&nanos))
        .then(|| i128::from(seconds) * 1_000_000_000 + i128::from(nanos))
}

#[cfg(not(target_os = "linux"))]
fn validate_item(_: &RetentionItem, _: Option<u64>) -> anyhow::Result<()> {
    anyhow::bail!("Trash selection is unsupported on this platform")
}

pub fn retention_preview(
    report: TrashReport,
    age: std::time::Duration,
) -> anyhow::Result<RetentionPreview> {
    #[cfg(target_os = "linux")]
    {
        retention_preview_at(report, age, chrono::Utc::now())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (report, age);
        anyhow::bail!("Trash retention preview is unsupported on this platform")
    }
}

#[cfg(target_os = "linux")]
fn retention_preview_at(
    report: TrashReport,
    age: std::time::Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<RetentionPreview> {
    use chrono::{Local, NaiveDateTime, TimeZone, Utc};
    if report.platform != "linux" {
        anyhow::bail!("Trash retention preview is unsupported on this platform");
    }
    let threshold = chrono::TimeDelta::from_std(age)
        .map_err(|_| anyhow::anyhow!("retention age is too large"))?;
    let cutoff = now
        .checked_sub_signed(threshold)
        .ok_or_else(|| anyhow::anyhow!("retention age is too large"))?;
    let mut warnings = report.warnings;
    let mut complete = !report.cancelled && warnings.is_empty();
    let mut items = Vec::new();
    for location in report.locations {
        let location_complete = location.items_complete && location.warnings.is_empty();
        complete &= location_complete;
        if !location.items_complete {
            warnings.push(format!(
                "{}: item inventory incomplete",
                crate::sweep::display_path(&location.path)
            ));
        }
        warnings.extend(location.warnings);
        for item in location.items {
            let instant = item
                .deletion_date
                .as_ref()
                .and_then(|date| NaiveDateTime::parse_from_str(date, "%Y-%m-%dT%H:%M:%S").ok())
                .and_then(|date| Local.from_local_datetime(&date).single());
            let age_status = match instant {
                Some(date) if date.with_timezone(&Utc) <= cutoff => "older_than_threshold",
                Some(_) => "newer_or_future",
                None => "unknown_or_ambiguous",
            };
            items.push(RetentionItem {
                location: location.path.clone(),
                name: item.name,
                deletion_date: item.deletion_date,
                age_status,
                location_complete,
                selected: false,
                identity: item.identity,
            });
        }
    }
    warnings.push("Dates are interpreted in the current local time zone, which may differ from the time zone at deletion; ambiguous and invalid dates are unknown. Preview does not authorize deletion.".into());
    Ok(RetentionPreview {
        older_than_seconds: age.as_secs(),
        items,
        warnings,
        cancelled: report.cancelled,
        complete,
    })
}

#[cfg(target_os = "linux")]
pub(crate) const MAX_SCHEDULED_TRASH_REMOVALS: usize = 32;

#[cfg(target_os = "linux")]
pub(crate) const MIN_SCHEDULED_TRASH_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

#[cfg(target_os = "linux")]
fn validate_scheduled_retention_age(age: std::time::Duration) -> anyhow::Result<()> {
    if age < std::time::Duration::from_secs(MIN_SCHEDULED_TRASH_RETENTION_SECONDS) {
        anyhow::bail!("scheduled Trash retention age must be at least 30 days");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn scheduled_mount_ids_match(mount_ids: &[Option<u64>], expected: u64) -> bool {
    mount_ids.len() == 5 && mount_ids.iter().all(|mount_id| *mount_id == Some(expected))
}

#[cfg(target_os = "linux")]
pub(crate) struct ScheduledTrashPreview {
    pub(crate) location_identity: TrashLocationIdentity,
    pub(crate) mount_id: u64,
    pub(crate) eligible: usize,
    pub(crate) deferred: usize,
    pub(crate) skipped: usize,
    pub(crate) candidate_digest: String,
    pub(crate) snapshot_unix_nanos: i128,
    pub(crate) plan: Option<TrashBatchPlan>,
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_scheduled_clock(
    snapshot_unix_nanos: i128,
    current_unix_nanos: i128,
) -> anyhow::Result<()> {
    if current_unix_nanos < snapshot_unix_nanos {
        anyhow::bail!("system clock moved backwards during scheduled Trash retention");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn scheduled_age_evidence(item: &RetentionItem, cutoff_nanos: i128) -> anyhow::Result<()> {
    use chrono::{Local, NaiveDateTime, TimeZone, Utc};
    if item.age_status != "older_than_threshold" {
        anyhow::bail!("Trash item is not in the reviewed scheduled age selection");
    }
    let identity = item
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Trash item identity unavailable"))?;
    let date_nanos = item
        .deletion_date
        .as_deref()
        .and_then(|date| NaiveDateTime::parse_from_str(date, "%Y-%m-%dT%H:%M:%S").ok())
        .and_then(|date| Local.from_local_datetime(&date).single())
        .and_then(|date| date.with_timezone(&Utc).timestamp_nanos_opt())
        .map(i128::from)
        .ok_or_else(|| anyhow::anyhow!("Trash deletion date is missing or ambiguous"))?;
    let info_ctime = identity
        .metadata
        .get(4)
        .and_then(|metadata| timestamp_nanos(metadata.changed_seconds, metadata.changed_nanos))
        .ok_or_else(|| anyhow::anyhow!("Trash metadata change time is unavailable"))?;
    let margin = i128::from(RETENTION_TIMEZONE_MARGIN_SECONDS) * 1_000_000_000;
    if date_nanos > cutoff_nanos
        || info_ctime > cutoff_nanos
        || (date_nanos - info_ctime).abs() > margin
    {
        anyhow::bail!("Trash deletion date and metadata age evidence disagree or are too recent");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn scheduled_candidate_digest(
    location_identity: &TrashLocationIdentity,
    age: std::time::Duration,
    eligible: usize,
    deferred: usize,
    skipped: usize,
    candidates: &[Vec<u8>],
) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};

    let location = serde_json::to_vec(location_identity)?;
    let age_seconds = age.as_secs().to_be_bytes();
    let age_nanos = age.subsec_nanos().to_be_bytes();
    let eligible = (eligible as u64).to_be_bytes();
    let deferred = (deferred as u64).to_be_bytes();
    let skipped = (skipped as u64).to_be_bytes();
    let mut hash = Sha256::new();
    hash.update(b"upkit-scheduled-trash-candidates-v1\0");
    for value in [
        location.as_slice(),
        age_seconds.as_slice(),
        age_nanos.as_slice(),
        eligible.as_slice(),
        deferred.as_slice(),
        skipped.as_slice(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    for candidate in candidates {
        hash.update((candidate.len() as u64).to_be_bytes());
        hash.update(candidate);
    }
    Ok(hex::encode(hash.finalize()))
}

/// Build the bounded, strictly age-verified plan used by the scheduled executor.
#[cfg(target_os = "linux")]
pub(crate) fn scheduled_retention_preview(
    location: &Path,
    age: std::time::Duration,
    cancel: &AtomicBool,
) -> anyhow::Result<ScheduledTrashPreview> {
    validate_scheduled_retention_age(age)?;
    let now = crate::scheduled_trash_cleanup::clock_now();
    let report = scoped_status(location, cancel);
    let (location_identity, mount_id) = scheduled_location_identity(location)?;
    scheduled_retention_preview_from_report(
        location,
        age,
        now,
        cancel,
        report,
        location_identity,
        mount_id,
    )
}

#[cfg(target_os = "linux")]
fn scheduled_retention_preview_from_report(
    location: &Path,
    age: std::time::Duration,
    now: chrono::DateTime<chrono::Utc>,
    cancel: &AtomicBool,
    report: TrashReport,
    location_identity: TrashLocationIdentity,
    mount_id: u64,
) -> anyhow::Result<ScheduledTrashPreview> {
    use anyhow::bail;
    validate_scheduled_retention_age(age)?;
    if cancel.load(Ordering::Relaxed) {
        bail!("scheduled Trash inventory cancelled");
    }
    let mut matches = report
        .locations
        .iter()
        .filter(|entry| entry.path == location);
    let entry = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("selected Trash location was not found"))?;
    if matches.next().is_some()
        || report.locations.len() != 1
        || report.cancelled
        || !entry.items_complete
        || !entry.warnings.is_empty()
    {
        bail!("scheduled Trash inventory is incomplete or ambiguous; nothing was removed");
    }
    let retention = retention_preview_at(report, age, now)?;
    if retention.cancelled
        || retention
            .items
            .iter()
            .any(|item| item.location == location && !item.location_complete)
    {
        bail!("scheduled Trash inventory is incomplete; nothing was removed");
    }
    let conservative_age = age
        .checked_add(std::time::Duration::from_secs(
            RETENTION_TIMEZONE_MARGIN_SECONDS,
        ))
        .ok_or_else(|| anyhow::anyhow!("retention age is too large"))?;
    let cutoff = now
        .checked_sub_signed(
            chrono::TimeDelta::from_std(conservative_age)
                .map_err(|_| anyhow::anyhow!("retention age is too large"))?,
        )
        .ok_or_else(|| anyhow::anyhow!("retention age is too large"))?
        .timestamp_nanos_opt()
        .ok_or_else(|| anyhow::anyhow!("retention cutoff is outside the supported range"))?
        as i128;
    let snapshot_unix_nanos = i128::from(
        now.timestamp_nanos_opt()
            .ok_or_else(|| anyhow::anyhow!("scheduled clock is outside the supported range"))?,
    );
    let mut plans = Vec::new();
    let mut candidate_details = Vec::new();
    let mut eligible = 0usize;
    let mut skipped = 0usize;
    for mut item in retention
        .items
        .into_iter()
        .filter(|item| item.location == location)
    {
        if cancel.load(Ordering::Relaxed) {
            bail!("scheduled Trash inventory cancelled; nothing was removed");
        }
        if item.age_status != "older_than_threshold" {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let supported = item.identity.as_ref().is_some_and(|identity| {
            scheduled_mount_ids_match(&identity.mount_ids, mount_id)
                && identity
                    .metadata
                    .iter()
                    .all(|metadata| metadata.uid == identity.uid && metadata.mode & 0o022 == 0)
                && identity.metadata[4].links == 1
                && ((identity.metadata[3].mode & 0o170000 == 0o100000
                    && identity.metadata[3].links == 1)
                    || identity.metadata[3].mode & 0o170000 == 0o040000)
        });
        if !supported {
            skipped = skipped.saturating_add(1);
            continue;
        }
        if scheduled_age_evidence(&item, cutoff).is_err() {
            skipped = skipped.saturating_add(1);
            continue;
        }
        if let Some(identity) = item.identity.as_mut() {
            identity.cutoff_unix_nanos = Some(cutoff);
        } else {
            skipped = skipped.saturating_add(1);
            continue;
        }
        eligible = eligible.saturating_add(1);
        let plan = if plans.len() < MAX_SCHEDULED_TRASH_REMOVALS {
            Some(removal_plan(&item, Some(age.as_secs()), cancel)?)
        } else {
            None
        };
        let identity = item
            .identity
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Trash item identity unavailable"))?;
        use std::os::unix::ffi::OsStrExt;
        let visible_plan = plan.as_ref().map(|plan| {
            (
                plan.kind,
                plan.descendant_count,
                plan.logical_bytes,
                plan.tree
                    .as_ref()
                    .map(|tree| (tree.digest.as_str(), tree.count(), tree.logical_bytes)),
            )
        });
        candidate_details.push(serde_json::to_vec(&(
            item.location.as_os_str().as_bytes(),
            item.name.as_str(),
            item.deletion_date.as_deref(),
            identity.name.as_os_str().as_bytes(),
            identity.uid,
            &identity.metadata,
            &identity.mount_ids,
            visible_plan,
        ))?);
        if let Some(plan) = plan {
            plans.push(plan);
        }
    }
    let deferred = eligible.saturating_sub(plans.len());
    candidate_details.sort_unstable();
    let candidate_digest = scheduled_candidate_digest(
        &location_identity,
        age,
        eligible,
        deferred,
        skipped,
        &candidate_details,
    )?;
    let plan = if plans.is_empty() {
        None
    } else {
        let mut plan = batch_from_plans(plans)?;
        plan.selection_note = Some(format!(
            "Scheduled policy: at most {MAX_SCHEDULED_TRASH_REMOVALS} items per run; {deferred} eligible items deferred and {skipped} newer, unknown-age, or unsupported items skipped. Deferred items make the run partial; all skipped items remain in Trash."
        ));
        let scheduled = ScheduledTrashPlanIdentity {
            location_identity: location_identity.clone(),
            mount_id,
            age,
            cutoff_unix_nanos: cutoff,
            snapshot_unix_nanos,
            eligible,
            deferred,
            skipped,
        };
        plan.preview_token = scheduled_batch_token(&plan.items, &scheduled)?;
        plan.scheduled = Some(scheduled);
        Some(plan)
    };
    Ok(ScheduledTrashPreview {
        location_identity,
        mount_id,
        eligible,
        deferred,
        skipped,
        candidate_digest,
        snapshot_unix_nanos,
        plan,
    })
}

/// Preview every supported item in one complete Trash location, regardless of age.
pub fn empty_preview(
    location: &std::path::Path,
    cancel: &AtomicBool,
) -> anyhow::Result<Option<TrashBatchPlan>> {
    #[cfg(target_os = "linux")]
    {
        let report = scoped_status(location, cancel);
        empty_preview_from_report(location, cancel, report)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (location, cancel);
        anyhow::bail!("Trash empty is unsupported on this platform")
    }
}

#[cfg(target_os = "linux")]
fn empty_preview_from_report(
    location: &Path,
    cancel: &AtomicBool,
    report: TrashReport,
) -> anyhow::Result<Option<TrashBatchPlan>> {
    let mut matches = report
        .locations
        .iter()
        .filter(|entry| entry.path == location);
    let entry = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("selected Trash location was not found"))?;
    if matches.next().is_some()
        || report.locations.len() != 1
        || report.cancelled
        || !entry.items_complete
        || !entry.warnings.is_empty()
    {
        anyhow::bail!("selected Trash location inventory is incomplete or ambiguous");
    }
    if entry.items.len() > 100 {
        anyhow::bail!("more than 100 items; remove a smaller selection first");
    }
    if entry.items.is_empty() {
        return Ok(None);
    }
    let preview = retention_preview(report, std::time::Duration::ZERO)?;
    let mut plans = Vec::new();
    for item in preview
        .items
        .iter()
        .filter(|item| item.location == location)
    {
        if cancel.load(Ordering::Relaxed) {
            anyhow::bail!("Trash empty preview cancelled");
        }
        plans.push(removal_plan(item, None, cancel)?);
    }
    let mut plan = batch_from_plans(plans)?;
    plan.empty_location = Some(location.to_owned());
    plan.preview_token = batch_token(&plan.items, true);
    plan.selection_note = Some(
        "All listed items and directory contents, regardless of age; orphan metadata may remain."
            .into(),
    );
    Ok(Some(plan))
}

/// Recreate a plan from an explicitly named item in the current inventory.
pub fn named_removal_preview(
    location: &std::path::Path,
    name: &str,
    age: std::time::Duration,
    cancel: &AtomicBool,
) -> anyhow::Result<TrashRemovalPlan> {
    let mut preview = retention_preview(scoped_status(location, cancel), age)?;
    let mut matches = preview
        .items
        .iter()
        .enumerate()
        .filter(|(_, item)| item.location == location && item.name == name)
        .map(|(index, _)| index);
    let index = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("selected item was not found in Trash inventory"))?;
    if matches.next().is_some() {
        anyhow::bail!("selected Trash item is ambiguous");
    }
    preview.toggle(index)?;
    let mut plan = preview.batch_removal_plan_with_cancel(cancel)?;
    if plan.items.len() != 1 {
        anyhow::bail!("select exactly one item for removal");
    }
    Ok(plan.items.remove(0))
}

pub fn named_batch_preview(
    location: &std::path::Path,
    names: &[String],
    age: std::time::Duration,
    cancel: &AtomicBool,
) -> anyhow::Result<TrashBatchPlan> {
    if names.is_empty() || names.len() > 100 {
        anyhow::bail!("select between 1 and 100 items for removal");
    }
    let mut unique = std::collections::HashSet::new();
    if names.iter().any(|name| !unique.insert(name)) {
        anyhow::bail!("duplicate Trash selection");
    }
    let mut preview = retention_preview(scoped_status(location, cancel), age)?;
    for name in names {
        let mut matches = preview
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.location == location && item.name == *name)
            .map(|(index, _)| index);
        let index = matches
            .next()
            .ok_or_else(|| anyhow::anyhow!("selected item was not found in Trash inventory"))?;
        if matches.next().is_some() {
            anyhow::bail!("selected Trash item is ambiguous");
        }
        preview.toggle(index)?;
    }
    preview.batch_removal_plan_with_cancel(cancel)
}

#[derive(Debug, Serialize)]
pub struct RetentionBatchPreview {
    pub selection: RetentionSelection,
    pub plan: Option<TrashBatchPlan>,
    pub warnings: Vec<String>,
}

/// Preview all eligible old files and directories within one explicitly selected Trash location.
pub fn retention_batch_preview(
    location: &std::path::Path,
    age: std::time::Duration,
    cancel: &AtomicBool,
) -> anyhow::Result<RetentionBatchPreview> {
    #[cfg(target_os = "linux")]
    {
        retention_batch_preview_from_report(location, age, cancel, scoped_status(location, cancel))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (location, age, cancel);
        anyhow::bail!("Trash retention is unsupported on this platform");
    }
}

#[cfg(target_os = "linux")]
fn retention_batch_preview_from_report(
    location: &Path,
    age: std::time::Duration,
    cancel: &AtomicBool,
    report: TrashReport,
) -> anyhow::Result<RetentionBatchPreview> {
    let mut matching = report
        .locations
        .iter()
        .filter(|entry| entry.path == location);
    let entry = matching
        .next()
        .ok_or_else(|| anyhow::anyhow!("selected Trash location was not found"))?;
    if matching.next().is_some() || report.locations.len() != 1 {
        anyhow::bail!("selected Trash location is ambiguous");
    }
    if report.cancelled || !entry.items_complete || !entry.warnings.is_empty() {
        anyhow::bail!("selected Trash location inventory is incomplete");
    }
    let empty = entry.items.is_empty();
    let mut preview = retention_preview(report, age)?;
    let selection = if empty {
        RetentionSelection {
            location: location.to_owned(),
            eligible: 0,
            newer_or_unknown: 0,
            unsupported: 0,
        }
    } else {
        preview.select_old_files(location, cancel)?
    };
    let plan = if selection.eligible == 0 {
        None
    } else {
        let mut plan = preview.batch_removal_plan_with_cancel(cancel)?;
        plan.selection_note = Some(format!(
            "Eligible: {}; newer/unknown: {}; unsupported: {}",
            selection.eligible, selection.newer_or_unknown, selection.unsupported
        ));
        Some(plan)
    };
    Ok(RetentionBatchPreview {
        selection,
        plan,
        warnings: preview.warnings,
    })
}

#[cfg(target_os = "linux")]
fn deletion_date(path: &Path, uid: u32) -> Option<String> {
    use std::{io::Read, os::unix::fs::MetadataExt};
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.uid() != uid || meta.len() > 16384 {
        return None;
    }
    let mut data = String::new();
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .ok()?;
    let file = fs::File::from(fd);
    let opened = file.metadata().ok()?;
    if !opened.is_file()
        || opened.uid() != uid
        || opened.dev() != meta.dev()
        || opened.ino() != meta.ino()
    {
        return None;
    }
    file.take(16385).read_to_string(&mut data).ok()?;
    parse_deletion_date_contents(&data)
}

#[cfg(target_os = "linux")]
fn parse_deletion_date_contents(data: &str) -> Option<String> {
    if data.len() > 16384 {
        return None;
    }
    let mut lines = data.lines();
    if lines.next()? != "[Trash Info]" {
        return None;
    }
    let mut dates = lines.filter_map(|line| line.strip_prefix("DeletionDate="));
    let value = dates.next()?;
    if dates.next().is_some() {
        return None;
    }
    let bytes = value.as_bytes();
    if bytes.len() != 19
        || [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')]
            .into_iter()
            .any(|(i, expected)| bytes[i] != expected)
        || !bytes
            .iter()
            .enumerate()
            .all(|(i, b)| [4, 7, 10, 13, 16].contains(&i) || b.is_ascii_digit())
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| value[range].parse::<u32>().ok();
    let (year, month, day, hour, minute, second) = (
        number(0..4)?,
        number(5..7)?,
        number(8..10)?,
        number(11..13)?,
        number(14..16)?,
        number(17..19)?,
    );
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return None,
    };
    if year == 0 || day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(value.into())
}

#[derive(Debug, Serialize)]
pub struct TrashReport {
    pub platform: &'static str,
    pub locations: Vec<TrashLocation>,
    pub warnings: Vec<String>,
    pub cancelled: bool,
}

// shortcut: cap size walks at 100,000 items; paginate inventory before raising the limit.
#[cfg(any(test, target_os = "windows"))]
const WINDOWS_RECYCLE_BIN_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
try {
    $shellType = [Type]::GetTypeFromProgID('Shell.Application')
    if ($null -eq $shellType) { throw 'Recycle Bin Shell type unavailable' }
    $shell = [Activator]::CreateInstance($shellType)
    if ($null -eq $shell) { throw 'Recycle Bin Shell activation failed' }
    $bin = $shell.NameSpace(10)
    if ($null -eq $bin) { throw 'Recycle Bin Shell folder unavailable' }
    $items = $bin.Items()
    $count = [int64]$items.Count
    $scanned = [int64]0
    $total = [decimal]0
    $complete = $count -le 100000
    foreach ($item in $items) {
        if ($scanned -ge 100000) { break }
        $scanned++
        if ($item.IsFolder) { $complete = $false; continue }
        $size = $item.Size
        if ($null -eq $size -or $size -isnot [ValueType] -or $size -is [bool]) {
            $complete = $false
            continue
        }
        try { $bytes = [decimal]$size } catch { $complete = $false; continue }
        if ($bytes -lt 0 -or [decimal]::Truncate($bytes) -ne $bytes) {
            $complete = $false
            continue
        }
        $total += $bytes
        if ($total -gt [decimal]([uint64]::MaxValue)) { $complete = $false }
    }
    if ($scanned -ne $count) { $complete = $false }
    $sizeText = if ($total -gt [decimal]([uint64]::MaxValue)) { '-' } else { $total.ToString([Globalization.CultureInfo]::InvariantCulture) }
    $countText = $count.ToString([Globalization.CultureInfo]::InvariantCulture)
    $completeText = if ($complete) { '1' } else { '0' }
    [Console]::Out.WriteLine($countText + "`t" + $sizeText + "`t" + $completeText)
} catch { exit 1 }"#;

#[cfg(any(test, target_os = "windows"))]
const WINDOWS_QUERY_OUTPUT_LIMIT: usize = 64;

#[cfg(any(test, target_os = "windows"))]
static WINDOWS_RECYCLE_BIN_QUERY_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(any(test, target_os = "windows"))]
struct WindowsRecycleBinQueryGuard;

#[cfg(any(test, target_os = "windows"))]
impl WindowsRecycleBinQueryGuard {
    fn acquire() -> anyhow::Result<Self> {
        if WINDOWS_RECYCLE_BIN_QUERY_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            anyhow::bail!("a Windows Recycle Bin query or output reader is still active");
        }
        Ok(Self)
    }
}

#[cfg(any(test, target_os = "windows"))]
impl Drop for WindowsRecycleBinQueryGuard {
    fn drop(&mut self) {
        WINDOWS_RECYCLE_BIN_QUERY_ACTIVE.store(false, Ordering::Release);
    }
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowsRecycleBinSummary {
    item_count: u64,
    logical_bytes: Option<u64>,
    size_complete: bool,
}

#[cfg(any(test, target_os = "windows"))]
fn parse_windows_recycle_bin_summary(output: &[u8]) -> anyhow::Result<WindowsRecycleBinSummary> {
    let text = std::str::from_utf8(output)?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    let mut fields = text.split('\t');
    let count = fields.next().unwrap_or_default();
    let bytes = fields.next().unwrap_or_default();
    let complete = fields.next().unwrap_or_default();
    let digits_only =
        |value: &str| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit());
    if fields.next().is_some() || !digits_only(count) || !matches!(complete, "0" | "1") {
        anyhow::bail!("PowerShell returned an invalid Recycle Bin summary");
    }
    let logical_bytes = if bytes == "-" {
        None
    } else if digits_only(bytes) {
        Some(bytes.parse()?)
    } else {
        anyhow::bail!("PowerShell returned an invalid Recycle Bin size");
    };
    let size_complete = complete == "1";
    if size_complete && logical_bytes.is_none() {
        anyhow::bail!("PowerShell marked an unknown Recycle Bin size complete");
    }
    Ok(WindowsRecycleBinSummary {
        item_count: count.parse()?,
        logical_bytes,
        size_complete,
    })
}

#[cfg(any(test, target_os = "windows"))]
fn windows_paths_within(directory: &Path, path: &Path) -> bool {
    let comparable = |path: &Path| {
        path.to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    };
    comparable(path)
        .strip_prefix(&comparable(directory))
        .is_some_and(|suffix| suffix.starts_with('\\'))
}

#[cfg(any(test, target_os = "windows"))]
fn reject_windows_reparse_components(path: &Path) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::path::Component;

    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        anyhow::bail!("Windows system path must be absolute and contain no parent components");
    }
    let mut ancestors = path.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    for current in ancestors {
        let metadata = std::fs::symlink_metadata(current)
            .with_context(|| format!("inspect system path component {}", current.display()))?;
        #[cfg(target_os = "windows")]
        let is_reparse = {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes() & 0x400 != 0
        };
        #[cfg(not(target_os = "windows"))]
        let is_reparse = metadata.file_type().is_symlink();
        if is_reparse {
            anyhow::bail!("Windows system path contains a reparse point");
        }
    }
    Ok(())
}

#[cfg(any(test, target_os = "windows"))]
fn windows_powershell_executable(system_directory: &Path) -> anyhow::Result<PathBuf> {
    use anyhow::Context;

    reject_windows_reparse_components(system_directory)?;
    let system_metadata =
        std::fs::symlink_metadata(system_directory).context("inspect Windows system directory")?;
    if !system_metadata.is_dir() {
        anyhow::bail!("Windows system directory is not a directory");
    }
    let canonical_system_directory = system_directory
        .canonicalize()
        .context("canonicalize Windows system directory")?;
    reject_windows_reparse_components(&canonical_system_directory)?;

    let candidate = canonical_system_directory
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    reject_windows_reparse_components(&candidate)?;
    let metadata =
        std::fs::symlink_metadata(&candidate).context("inspect Windows PowerShell executable")?;
    if !metadata.is_file() {
        anyhow::bail!("Windows PowerShell executable is not a regular file");
    }
    let executable = candidate
        .canonicalize()
        .context("canonicalize Windows PowerShell executable")?;
    reject_windows_reparse_components(&executable)?;
    let executable_metadata =
        std::fs::symlink_metadata(&executable).context("recheck Windows PowerShell executable")?;
    if !executable_metadata.is_file()
        || !windows_paths_within(&canonical_system_directory, &executable)
    {
        anyhow::bail!("Windows PowerShell executable is outside the system directory");
    }
    Ok(executable)
}

#[cfg(any(test, target_os = "windows"))]
fn query_windows_recycle_bin_with_executable(
    executable: &Path,
    cancel: &AtomicBool,
    timeout: std::time::Duration,
    isolated_home: Option<&Path>,
    active_guard: Option<WindowsRecycleBinQueryGuard>,
) -> anyhow::Result<Option<WindowsRecycleBinSummary>> {
    use std::{
        io::Read,
        process::{Child, Command, Stdio},
        sync::{Arc, mpsc},
        thread,
        time::Instant,
    };

    fn stop(child: &mut Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    if cancel.load(Ordering::Relaxed) {
        return Ok(None);
    }
    let mut command = Command::new(executable);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Sta",
            "-Command",
            WINDOWS_RECYCLE_BIN_SCRIPT,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(home) = isolated_home {
        command.env("HOME", home);
    }
    let deadline = Instant::now() + timeout;
    let active_guard = active_guard.map(Arc::new);
    let mut child = command.spawn()?;
    let Some(mut stdout) = child.stdout.take() else {
        stop(&mut child);
        anyhow::bail!("PowerShell output was unavailable");
    };
    let (send, receive) = mpsc::sync_channel(1);
    let reader_guard = active_guard.as_ref().map(Arc::clone);
    let reader = thread::Builder::new()
        .name("upkit-recycle-bin-output".into())
        .spawn(move || {
            let _active_guard = reader_guard;
            let output = (|| {
                let mut output = Vec::with_capacity(WINDOWS_QUERY_OUTPUT_LIMIT + 1);
                let mut buffer = [0; WINDOWS_QUERY_OUTPUT_LIMIT + 1];
                loop {
                    let remaining = WINDOWS_QUERY_OUTPUT_LIMIT + 1 - output.len();
                    if remaining == 0 {
                        break;
                    }
                    let limit = remaining.min(buffer.len());
                    let read = stdout.read(&mut buffer[..limit])?;
                    if read == 0 {
                        break;
                    }
                    output.extend_from_slice(&buffer[..read]);
                    if output.len() > WINDOWS_QUERY_OUTPUT_LIMIT {
                        break;
                    }
                }
                Ok::<_, std::io::Error>(output)
            })();
            let _ = send.send(output);
        });
    if let Err(error) = reader {
        stop(&mut child);
        return Err(error.into());
    }

    let mut output = None;
    let mut exit_status = None;
    loop {
        if cancel.load(Ordering::Relaxed) {
            stop(&mut child);
            return Ok(None);
        }
        if output.is_none() {
            match receive.recv_timeout(std::time::Duration::from_millis(20)) {
                Ok(Ok(bytes)) if bytes.len() <= WINDOWS_QUERY_OUTPUT_LIMIT => {
                    output = Some(bytes);
                }
                Ok(Ok(_)) => {
                    stop(&mut child);
                    anyhow::bail!("PowerShell Recycle Bin output exceeded the bounded limit");
                }
                Ok(Err(error)) => {
                    stop(&mut child);
                    return Err(error.into());
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    stop(&mut child);
                    anyhow::bail!("PowerShell Recycle Bin output reader stopped unexpectedly");
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
        if exit_status.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => exit_status = Some(status),
                Ok(None) => {}
                Err(error) => {
                    stop(&mut child);
                    return Err(error.into());
                }
            }
        }
        if let (Some(output), Some(status)) = (&output, exit_status.as_ref()) {
            if !status.success() {
                anyhow::bail!("PowerShell Recycle Bin query exited with {status}");
            }
            return parse_windows_recycle_bin_summary(output).map(Some);
        }
        if Instant::now() >= deadline {
            stop(&mut child);
            anyhow::bail!("PowerShell Recycle Bin query timed out");
        }
        if output.is_some() {
            thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

#[cfg(target_os = "windows")]
fn query_windows_recycle_bin(
    cancel: &AtomicBool,
) -> anyhow::Result<Option<WindowsRecycleBinSummary>> {
    use std::time::Duration;
    if cancel.load(Ordering::Relaxed) {
        return Ok(None);
    }
    let active_guard = WindowsRecycleBinQueryGuard::acquire()?;
    let system_directory = known_folders::get_known_folder_path(known_folders::KnownFolder::System)
        .ok_or_else(|| anyhow::anyhow!("cannot determine the Windows system directory"))?;
    let executable = windows_powershell_executable(&system_directory)?;
    query_windows_recycle_bin_with_executable(
        &executable,
        cancel,
        Duration::from_secs(2),
        None,
        Some(active_guard),
    )
}

#[cfg(any(test, target_os = "windows"))]
fn windows_recycle_bin_report(
    summary: anyhow::Result<WindowsRecycleBinSummary>,
    cancelled: bool,
) -> TrashReport {
    let mut report = TrashReport {
        platform: "windows",
        locations: vec![],
        warnings: vec![],
        cancelled,
    };
    if cancelled {
        report
            .warnings
            .push("Windows Recycle Bin inventory was cancelled.".into());
    } else {
        match summary {
            Ok(summary) => {
                let warning = if summary.size_complete {
                    "The Windows Shell measured every Recycle Bin file item; its filesystem path, item names, and deletion dates are unknown, and item-level actions are unsupported."
                } else if summary.logical_bytes.is_some() {
                    "Recycle Bin size is a partial sum of measurable file items; directories, unmeasured entries, or entries beyond the 100,000-item scan limit are omitted. Its filesystem path, item names, and deletion dates are unknown; item-level actions are unsupported."
                } else {
                    "Recycle Bin size is unavailable or exceeded the supported range; directory entries and scans above 100,000 items cannot be fully measured. Its filesystem path, item names, and deletion dates are unknown; item-level actions are unsupported."
                };
                report.locations.push(TrashLocation {
                    path: PathBuf::new(),
                    kind: "Windows Recycle Bin (virtual)",
                    item_count: Some(summary.item_count),
                    logical_bytes: summary.logical_bytes,
                    allocated_bytes: None,
                    size_complete: summary.size_complete,
                    warnings: vec![warning.into()],
                    items: vec![],
                    items_complete: false,
                });
            }
            Err(error) => report.warnings.push(format!(
                "Windows Recycle Bin inventory unavailable: {error:#}"
            )),
        }
    }
    report
}

#[cfg(target_os = "linux")]
fn effective_uid(status: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        line.strip_prefix("Uid:")
            .and_then(|v| v.split_whitespace().nth(1))?
            .parse()
            .ok()
    })
}

#[cfg(target_os = "linux")]
fn directory(path: &Path, owner: Option<u32>, sticky: bool) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(meta.is_dir()
            && !meta.file_type().is_symlink()
            && owner.is_none_or(|uid| meta.uid() == uid)
            && (!sticky || meta.mode() & 0o1000 != 0)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct LinuxTrashLocation {
    path: PathBuf,
    canonical: PathBuf,
    kind: &'static str,
}

#[cfg(target_os = "linux")]
fn discover_locations(
    home: &Path,
    mountpoints: &[PathBuf],
    uid: u32,
    cancel: &AtomicBool,
) -> (Vec<LinuxTrashLocation>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut seen = HashSet::new();
    let mut locations = vec![(home.to_owned(), "home")];
    for mount in mountpoints {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let shared = mount.join(".Trash");
        match directory(&shared, None, true) {
            Ok(true) => locations.push((shared.join(uid.to_string()), "mounted shared")),
            Ok(false) => {
                if fs::symlink_metadata(&shared).is_ok() {
                    warnings.push(format!(
                        "{}: shared Trash is linked, not a directory, or lacks the sticky bit",
                        crate::sweep::display_path(&shared)
                    ));
                }
            }
            Err(err) => warnings.push(format!("{}: {err}", crate::sweep::display_path(&shared))),
        }
        locations.push((mount.join(format!(".Trash-{uid}")), "mounted private"));
    }
    let mut discovered = Vec::new();
    for (path, kind) in locations {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        match directory(&path, Some(uid), false) {
            Ok(true) => {}
            Ok(false) => {
                if fs::symlink_metadata(&path).is_ok() {
                    warnings.push(format!(
                        "{}: Trash path is linked, not a directory, or owned by another user",
                        crate::sweep::display_path(&path)
                    ));
                }
                continue;
            }
            Err(err) => {
                warnings.push(format!("{}: {err}", crate::sweep::display_path(&path)));
                continue;
            }
        }
        let Ok(canonical) = path.canonicalize() else {
            warnings.push(format!(
                "{}: cannot resolve Trash directory",
                crate::sweep::display_path(&path)
            ));
            continue;
        };
        if !seen.insert(canonical.clone()) {
            continue;
        }
        discovered.push(LinuxTrashLocation {
            path,
            canonical,
            kind,
        });
    }
    (discovered, warnings)
}

#[cfg(target_os = "linux")]
fn inspect_location(location: &LinuxTrashLocation, uid: u32, cancel: &AtomicBool) -> TrashLocation {
    let files = location.path.join("files");
    let mut result = TrashLocation {
        path: location.path.clone(),
        kind: location.kind,
        item_count: None,
        logical_bytes: None,
        allocated_bytes: None,
        size_complete: false,
        warnings: vec![],
        items: vec![],
        items_complete: true,
    };
    let shared_valid = location.kind != "mounted shared"
        || location
            .path
            .parent()
            .is_some_and(|path| directory(path, None, true).unwrap_or(false));
    if !directory(&location.path, Some(uid), false).unwrap_or(false)
        || location.path.canonicalize().ok().as_ref() != Some(&location.canonical)
        || !shared_valid
    {
        result.items_complete = false;
        result
            .warnings
            .push("Trash location changed or is no longer a verified location".into());
        return result;
    }
    match directory(&files, Some(uid), false) {
        Ok(true) => {
            let info_dir = result.path.join("info");
            let info_available = directory(&info_dir, Some(uid), false).unwrap_or(false);
            match fs::read_dir(&files) {
                Ok(entries) => {
                    let mut count = 0u64;
                    let mut complete = true;
                    for entry in entries {
                        if cancel.load(Ordering::Relaxed) {
                            complete = false;
                            break;
                        }
                        match entry {
                            Ok(entry) => {
                                count = count.saturating_add(1);
                                if result.items.len() < 10000 {
                                    let mut info_name = entry.file_name();
                                    info_name.push(".trashinfo");
                                    let date = if info_available {
                                        deletion_date(&info_dir.join(&info_name), uid)
                                    } else {
                                        None
                                    };
                                    let identity =
                                        item_identity(&result.path, &entry.file_name(), uid)
                                            .filter(|before| {
                                                deletion_date(&info_dir.join(&info_name), uid)
                                                    == date
                                                    && item_identity(
                                                        &result.path,
                                                        &entry.file_name(),
                                                        uid,
                                                    )
                                                    .is_some_and(|after| {
                                                        after.metadata == before.metadata
                                                    })
                                            });
                                    result.items.push(TrashItem {
                                        name: display_item_name(&entry.file_name()),
                                        deletion_date: date,
                                        identity,
                                    });
                                } else {
                                    result.items_complete = false;
                                }
                            }
                            Err(err) => {
                                complete = false;
                                result.warnings.push(format!("cannot count item: {err}"));
                            }
                        }
                    }
                    if complete {
                        result.item_count = Some(count);
                    } else {
                        result.items_complete = false;
                        result.warnings.push("item count incomplete".into());
                    }
                }
                Err(err) => {
                    result.items_complete = false;
                    result
                        .warnings
                        .push(format!("cannot list Trash items: {err}"));
                }
            }
            match crate::sweep::measure_directory(&files, cancel) {
                Ok((logical, allocated, complete, warnings)) => {
                    result.logical_bytes = Some(logical);
                    result.allocated_bytes = allocated;
                    result.size_complete = complete;
                    result.warnings.extend(warnings);
                }
                Err(err) => result
                    .warnings
                    .push(format!("cannot estimate Trash size: {err}")),
            }
        }
        Ok(false) => {
            result.items_complete = false;
            result
                .warnings
                .push("Trash files directory is absent, linked, or owned by another user".into());
        }
        Err(err) => {
            result.items_complete = false;
            result
                .warnings
                .push(format!("cannot inspect Trash files directory: {err}"));
        }
    }
    result.items.sort_by(|a, b| a.name.cmp(&b.name));
    if !result.items_complete {
        result
            .warnings
            .push("item inventory incomplete or limited to 10000 entries".into());
    }
    result
}

#[cfg(target_os = "linux")]
fn inspect_with_scope(
    home: &Path,
    mountpoints: &[PathBuf],
    uid: u32,
    target: Option<&Path>,
    cancel: &AtomicBool,
) -> TrashReport {
    let (locations, warnings) = discover_locations(home, mountpoints, uid, cancel);
    let mut report = TrashReport {
        platform: "linux",
        locations: vec![],
        warnings,
        cancelled: false,
    };
    for location in locations {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        if target.is_some_and(|target| target != location.path) {
            continue;
        }
        report
            .locations
            .push(inspect_location(&location, uid, cancel));
    }
    report.cancelled = cancel.load(Ordering::Relaxed);
    report
}

#[cfg(target_os = "linux")]
fn inspect(home: &Path, mountpoints: &[PathBuf], uid: u32, cancel: &AtomicBool) -> TrashReport {
    inspect_with_scope(home, mountpoints, uid, None, cancel)
}

#[cfg(target_os = "linux")]
fn linux_status(cancel: &AtomicBool, target: Option<&Path>) -> TrashReport {
    let unavailable = || TrashReport {
        platform: "linux",
        locations: vec![],
        warnings: vec![
            "Trash inventory unavailable: cannot determine user, data directory, or mounts".into(),
        ],
        cancelled: cancel.load(Ordering::Relaxed),
    };
    let uid = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| effective_uid(&text));
    let home = linux_data_directory().map(|path| path.join("Trash"));
    let mounts = fs::read("/proc/self/mountinfo")
        .ok()
        .and_then(|bytes| crate::application::mount_points(&bytes).ok());
    match (uid, home, mounts) {
        (Some(uid), Some(home), Some(mounts)) => match target {
            Some(target) => inspect_with_scope(&home, &mounts, uid, Some(target), cancel),
            None => inspect(&home, &mounts, uid, cancel),
        },
        _ => unavailable(),
    }
}

#[cfg(target_os = "linux")]
fn scoped_status(location: &Path, cancel: &AtomicBool) -> TrashReport {
    linux_status(cancel, Some(location))
}

#[cfg(not(target_os = "linux"))]
fn scoped_status(_: &Path, cancel: &AtomicBool) -> TrashReport {
    status(cancel)
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_field(value: &str) -> anyhow::Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            let digits = bytes
                .get(index + 1..index + 4)
                .ok_or_else(|| anyhow::anyhow!("invalid mount information"))?;
            if !digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
                anyhow::bail!("invalid mount information");
            }
            let byte = u16::from(digits[0] - b'0') * 64
                + u16::from(digits[1] - b'0') * 8
                + u16::from(digits[2] - b'0');
            if byte > u16::from(u8::MAX) {
                anyhow::bail!("invalid mount information");
            }
            decoded.push(byte as u8);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| anyhow::anyhow!("mount path is not UTF-8"))
}

#[cfg(target_os = "linux")]
type StableMountIdentityFields = (String, String, String, String, String);

#[cfg(target_os = "linux")]
fn stable_mount_identity_from(
    path: &Path,
    mountinfo: &str,
    expected_mount_id: u64,
) -> anyhow::Result<TrashMountIdentity> {
    let mut selected: Option<(usize, StableMountIdentityFields)> = None;
    let mut found_mount_id = false;
    for line in mountinfo.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        let left = before.split_whitespace().collect::<Vec<_>>();
        let right = after.split_whitespace().collect::<Vec<_>>();
        if left.first().and_then(|id| id.parse::<u64>().ok()) != Some(expected_mount_id) {
            continue;
        }
        if found_mount_id {
            anyhow::bail!("Trash mount identity is ambiguous");
        }
        found_mount_id = true;
        if left.len() < 6 || right.len() < 2 {
            anyhow::bail!("invalid mount information for the selected Trash mount");
        }
        let point = decode_mountinfo_field(left[4])?;
        let point_path = PathBuf::from(&point);
        if !point_path.is_absolute() || !path.starts_with(&point_path) {
            continue;
        }
        let components = point_path.components().count();
        let identity = (
            point,
            decode_mountinfo_field(left[3])?,
            left[2].to_owned(),
            right[0].to_owned(),
            decode_mountinfo_field(right[1])?,
        );
        if selected
            .as_ref()
            .is_some_and(|(length, _)| *length == components)
        {
            anyhow::bail!("Trash mount identity is ambiguous");
        }
        if selected
            .as_ref()
            .is_none_or(|(length, _)| components > *length)
        {
            selected = Some((components, identity));
        }
    }
    let (_, (point, root, major_minor, filesystem, source)) =
        selected.ok_or_else(|| anyhow::anyhow!("Trash path has no stable mount identity"))?;
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"upkit-trash-mount-identity-v1\0");
    for value in [point, root, major_minor, filesystem, source] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    Ok(TrashMountIdentity {
        digest: hex::encode(hash.finalize()),
    })
}

#[cfg(target_os = "linux")]
fn stable_mount_identity(
    path: &Path,
    expected_mount_id: u64,
) -> anyhow::Result<TrashMountIdentity> {
    use anyhow::Context;
    let mountinfo =
        fs::read_to_string("/proc/self/mountinfo").context("read current mount information")?;
    stable_mount_identity_from(path, &mountinfo, expected_mount_id)
}

#[cfg(target_os = "linux")]
fn scheduled_directory_identity(
    file: &fs::File,
    uid: u32,
) -> anyhow::Result<(TrashDirectoryIdentity, u64)> {
    use anyhow::{Context, bail};
    use rustix::fs::{AtFlags, StatxFlags, statx};
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().context("inspect Trash directory")?;
    let stats = statx(
        file,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::BASIC_STATS | StatxFlags::MNT_ID | StatxFlags::BTIME,
    )
    .context("inspect Trash directory identity")?;
    let required = StatxFlags::INO
        | StatxFlags::MODE
        | StatxFlags::UID
        | StatxFlags::MNT_ID
        | StatxFlags::BTIME;
    if stats.stx_mask & required.bits() != required.bits()
        || stats.stx_ino != metadata.ino()
        || u32::from(stats.stx_mode) != metadata.mode()
        || stats.stx_uid != metadata.uid()
        || rustix::fs::makedev(stats.stx_dev_major, stats.stx_dev_minor) as u64 != metadata.dev()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
        || stats.stx_btime.tv_sec < 0
        || stats.stx_btime.tv_nsec >= 1_000_000_000
    {
        bail!("Trash directory lacks a stable private identity");
    }
    Ok((
        TrashDirectoryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            birth_seconds: stats.stx_btime.tv_sec,
            birth_nanos: stats.stx_btime.tv_nsec,
        },
        stats.stx_mnt_id,
    ))
}

/// Capture the durable scope for scheduled retention. This deliberately fails closed on
/// filesystems without statx mount and birth-time identity.
#[cfg(target_os = "linux")]
pub(crate) fn scheduled_location_identity(
    path: &Path,
) -> anyhow::Result<(TrashLocationIdentity, u64)> {
    use anyhow::{Context, bail};
    let canonical = path
        .canonicalize()
        .context("resolve selected Trash location")?;
    if canonical != path || path.to_str().is_none() {
        bail!("scheduled Trash location must be canonical and UTF-8");
    }
    let uid = rustix::process::geteuid().as_raw();
    let home = linux_data_directory()
        .context("cannot determine user data directory")?
        .join("Trash");
    let mountinfo = fs::read("/proc/self/mountinfo").context("read current mount information")?;
    let mounts = crate::application::mount_points(&mountinfo)?;
    let (locations, _) = discover_locations(&home, &mounts, uid, &AtomicBool::new(false));
    if !locations.iter().any(|location| location.path == path) {
        bail!("selected Trash location was not found or is no longer trusted");
    }
    scheduled_location_identity_open(path)
}

#[cfg(target_os = "linux")]
fn scheduled_location_identity_open(path: &Path) -> anyhow::Result<(TrashLocationIdentity, u64)> {
    use anyhow::{Context, bail};
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    let canonical = path
        .canonicalize()
        .context("resolve selected Trash location")?;
    if canonical != path || path.to_str().is_none() {
        bail!("scheduled Trash location must be canonical and UTF-8");
    }
    let uid = rustix::process::geteuid().as_raw();
    let root = fs::File::from(openat2(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    let child = |name: &str| -> anyhow::Result<fs::File> {
        Ok(fs::File::from(openat2(
            &root,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?))
    };
    let files = child("files").context("open Trash files directory")?;
    let info = child("info").context("open Trash info directory")?;
    let (root, root_mount_id) = scheduled_directory_identity(&root, uid)?;
    let (files, files_mount_id) = scheduled_directory_identity(&files, uid)?;
    let (info, info_mount_id) = scheduled_directory_identity(&info, uid)?;
    if root_mount_id != files_mount_id || root_mount_id != info_mount_id {
        bail!("Trash directories cross a mount boundary");
    }
    let mount = stable_mount_identity(path, root_mount_id)?;
    Ok((
        TrashLocationIdentity {
            path: path.to_str().unwrap_or_default().to_owned(),
            uid,
            root,
            files,
            info,
            mount,
        },
        root_mount_id,
    ))
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
const MACOS_HOME_TRASH_SIZE_ENTRY_LIMIT: usize = 100_000;

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
const MACOS_HOME_TRASH_SIZE_DEPTH_LIMIT: usize = 128;

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
struct MacHomeTrashSize {
    logical_bytes: u64,
    complete: bool,
    discovered: usize,
    warnings: Vec<String>,
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
fn macos_trash_names(
    directory: &std::fs::File,
    cancel: &AtomicBool,
    limit: usize,
) -> anyhow::Result<(Vec<std::ffi::OsString>, bool)> {
    use std::os::unix::ffi::OsStringExt;

    let mut names = Vec::new();
    let mut exceeded = false;
    for entry in rustix::fs::Dir::read_from(directory)? {
        if cancel.load(Ordering::Relaxed) {
            anyhow::bail!("inventory cancelled");
        }
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        if names.len() == limit {
            exceeded = true;
            break;
        }
        names.push(std::ffi::OsString::from_vec(bytes.to_vec()));
    }
    Ok((names, exceeded))
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
fn macos_trash_size_warning(size: &mut MacHomeTrashSize, warning: &'static str) {
    size.complete = false;
    if !size.warnings.iter().any(|item| item == warning) {
        size.warnings.push(warning.into());
    }
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
#[cfg_attr(all(test, target_os = "linux"), allow(clippy::useless_conversion))]
fn macos_trash_measure_directory(
    directory: &std::fs::File,
    names: Vec<std::ffi::OsString>,
    depth: usize,
    device: u64,
    cancel: &AtomicBool,
    limit: usize,
    size: &mut MacHomeTrashSize,
) -> anyhow::Result<()> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, openat, statat};
    use std::os::unix::fs::MetadataExt;

    for name in names {
        if cancel.load(Ordering::Relaxed) {
            anyhow::bail!("inventory cancelled");
        }
        let entry = match statat(directory, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(entry) => entry,
            Err(_) => {
                macos_trash_size_warning(
                    size,
                    "Some entries could not be inspected; size is incomplete.",
                );
                continue;
            }
        };
        if u64::try_from(entry.st_dev).ok() != Some(device) {
            macos_trash_size_warning(
                size,
                "Entries on another filesystem were skipped during size estimation.",
            );
            continue;
        }
        match FileType::from_raw_mode(entry.st_mode) {
            FileType::RegularFile => match u64::try_from(entry.st_size) {
                Ok(bytes) => match size.logical_bytes.checked_add(bytes) {
                    Some(total) => size.logical_bytes = total,
                    None => macos_trash_size_warning(
                        size,
                        "Some file sizes overflowed the size estimate.",
                    ),
                },
                Err(_) => macos_trash_size_warning(
                    size,
                    "Some file sizes were invalid; size is incomplete.",
                ),
            },
            FileType::Directory => {
                if depth >= MACOS_HOME_TRASH_SIZE_DEPTH_LIMIT {
                    macos_trash_size_warning(
                        size,
                        "Size estimation stopped at the safe directory-depth limit.",
                    );
                    continue;
                }
                let child = match openat(
                    directory,
                    name.as_os_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(child) => std::fs::File::from(child),
                    Err(_) => {
                        macos_trash_size_warning(
                            size,
                            "Some directories changed or could not be inspected; size is incomplete.",
                        );
                        continue;
                    }
                };
                let child_matches_entry = child.metadata().is_ok_and(|metadata| {
                    metadata.is_dir() && metadata.dev() == device && entry.st_ino == metadata.ino()
                });
                if !child_matches_entry {
                    macos_trash_size_warning(
                        size,
                        "Some directories changed or could not be inspected; size is incomplete.",
                    );
                    continue;
                }
                let remaining = limit.saturating_sub(size.discovered);
                let (children, exceeded) = match macos_trash_names(&child, cancel, remaining) {
                    Ok(result) => result,
                    Err(_) if cancel.load(Ordering::Relaxed) => {
                        anyhow::bail!("inventory cancelled")
                    }
                    Err(_) => {
                        macos_trash_size_warning(
                            size,
                            "Some directories could not be listed; size is incomplete.",
                        );
                        continue;
                    }
                };
                size.discovered = size.discovered.saturating_add(children.len());
                if exceeded {
                    macos_trash_size_warning(
                        size,
                        "Size estimation stopped at the safe entry limit.",
                    );
                }
                macos_trash_measure_directory(
                    &child,
                    children,
                    depth + 1,
                    device,
                    cancel,
                    limit,
                    size,
                )?;
            }
            FileType::Symlink => macos_trash_size_warning(
                size,
                "Symbolic links were skipped during size estimation.",
            ),
            _ => {
                macos_trash_size_warning(size, "Special files were skipped during size estimation.")
            }
        }
    }
    Ok(())
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
fn macos_trash_size(
    directory: &std::fs::File,
    mut names: Vec<std::ffi::OsString>,
    cancel: &AtomicBool,
    limit: usize,
) -> anyhow::Result<MacHomeTrashSize> {
    use std::os::unix::fs::MetadataExt;

    let metadata = directory.metadata()?;
    let mut size = MacHomeTrashSize {
        logical_bytes: 0,
        complete: true,
        discovered: names.len().min(limit),
        warnings: Vec::new(),
    };
    if names.len() > limit {
        names.truncate(limit);
        macos_trash_size_warning(
            &mut size,
            "Size estimation stopped at the safe entry limit.",
        );
    }
    macos_trash_measure_directory(
        directory,
        names,
        0,
        metadata.dev(),
        cancel,
        limit,
        &mut size,
    )?;
    Ok(size)
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
fn macos_trash_location_from_directory(
    path: &Path,
    kind: &'static str,
    directory: &std::fs::File,
    cancel: &AtomicBool,
    limit: u64,
    size_limit: usize,
) -> anyhow::Result<(TrashLocation, usize)> {
    let (names, exceeded) = macos_trash_names(
        directory,
        cancel,
        usize::try_from(limit).unwrap_or(usize::MAX),
    )?;
    if exceeded {
        anyhow::bail!("Trash exceeds the {limit}-item inventory limit");
    }
    let count = u64::try_from(names.len()).unwrap_or(u64::MAX);
    let items = names
        .iter()
        .map(|name| TrashItem {
            name: display_item_name(name),
            deletion_date: None,
            #[cfg(target_os = "linux")]
            identity: None,
        })
        .collect();
    let size = macos_trash_size(directory, names, cancel, size_limit)?;
    let mut warnings = vec![
        "Entry count includes any metadata files and may differ from Finder; entries may change during inspection.".into(),
        "Size estimation checks device IDs but does not detect same-device mounts.".into(),
    ];
    warnings.extend(size.warnings);
    let discovered = size.discovered;
    Ok((
        TrashLocation {
            path: path.to_path_buf(),
            kind,
            item_count: Some(count),
            logical_bytes: Some(size.logical_bytes),
            allocated_bytes: None,
            size_complete: size.complete,
            warnings,
            items,
            items_complete: true,
        },
        discovered,
    ))
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
fn macos_home_trash_report(home: &Path, cancel: &AtomicBool, limit: u64) -> TrashReport {
    use rustix::fs::{Mode, OFlags, open};

    let path = home.join(".Trash");
    let mut report = TrashReport {
        platform: "macos",
        locations: vec![],
        warnings: vec!["Trash names are a read-only snapshot; deletion dates and item actions are unavailable.".into()],
        cancelled: cancel.load(Ordering::Relaxed),
    };
    if report.cancelled {
        return report;
    }
    let inventory = (|| -> anyhow::Result<TrashLocation> {
        let directory = std::fs::File::from(open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        macos_trash_location_from_directory(
            &path,
            "macOS home Trash",
            &directory,
            cancel,
            limit,
            MACOS_HOME_TRASH_SIZE_ENTRY_LIMIT,
        )
        .map(|(location, _)| location)
    })();
    report.cancelled = cancel.load(Ordering::Relaxed);
    if report.cancelled {
        report
            .warnings
            .push("Trash inventory was cancelled.".into());
    } else {
        match inventory {
            Ok(location) => report.locations.push(location),
            Err(error) => report
                .warnings
                .push(format!("Home Trash inventory unavailable: {error:#}")),
        }
    }
    report
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
// shortcut: scan at most 256 /Volumes entries; raise the cap if users need larger mount inventories.
const MACOS_VOLUME_ENTRY_LIMIT: usize = 256;

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
#[cfg_attr(all(test, target_os = "linux"), allow(clippy::useless_conversion))]
fn macos_open_directory_at(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
) -> anyhow::Result<Option<std::fs::File>> {
    use anyhow::bail;
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, openat, statat};

    let before = match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if FileType::from_raw_mode(before.st_mode) != FileType::Directory {
        bail!("expected a directory");
    }
    let directory = std::fs::File::from(openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let opened = directory.metadata()?;
    if !opened.is_dir()
        || u64::try_from(before.st_dev).ok() != Some(std::os::unix::fs::MetadataExt::dev(&opened))
        || before.st_ino != std::os::unix::fs::MetadataExt::ino(&opened)
    {
        bail!("directory changed while being opened");
    }
    Ok(Some(directory))
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
fn macos_volume_trash_locations_with(
    volumes: &Path,
    uid: u32,
    cancel: &AtomicBool,
    limit: u64,
    size_limit: usize,
    mut device_id: impl FnMut(&std::fs::File) -> Option<u64>,
) -> (Vec<TrashLocation>, Vec<String>, bool) {
    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, open, statat};
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

    let mut locations = Vec::new();
    let mut incomplete = false;
    let mut cancelled = cancel.load(Ordering::Relaxed);
    let volumes_directory = if cancelled {
        None
    } else {
        match open(
            volumes,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(directory) => Some(std::fs::File::from(directory)),
            Err(_) => {
                incomplete = true;
                None
            }
        }
    };
    let Some(volumes_directory) = volumes_directory else {
        let warnings = if incomplete {
            vec!["Mounted-volume Trash inventory is incomplete because /Volumes could not be inspected.".into()]
        } else {
            vec![]
        };
        return (locations, warnings, cancelled);
    };
    let Some(volumes_device) = device_id(&volumes_directory) else {
        return (
            locations,
            vec!["Mounted-volume Trash inventory is incomplete because /Volumes identity could not be inspected.".into()],
            cancelled,
        );
    };
    let entries = match Dir::read_from(&volumes_directory) {
        Ok(entries) => entries,
        Err(_) => {
            return (
                locations,
                vec!["Mounted-volume Trash inventory is incomplete because /Volumes could not be read.".into()],
                cancelled,
            );
        }
    };
    let uid_name = uid.to_string();
    let mut inspected_entries = 0usize;
    let mut total_items = 0u64;
    let mut total_size_entries = 0usize;
    for entry in entries {
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                incomplete = true;
                continue;
            }
        };
        let name = std::ffi::OsStr::from_bytes(entry.file_name().to_bytes());
        if matches!(name.as_bytes(), b"." | b"..") {
            continue;
        }
        if inspected_entries == MACOS_VOLUME_ENTRY_LIMIT {
            incomplete = true;
            break;
        }
        inspected_entries += 1;
        let mount_metadata = match statat(&volumes_directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => metadata,
            Err(rustix::io::Errno::NOENT) => {
                incomplete = true;
                continue;
            }
            Err(_) => {
                incomplete = true;
                continue;
            }
        };
        if FileType::from_raw_mode(mount_metadata.st_mode) != FileType::Directory {
            if FileType::from_raw_mode(mount_metadata.st_mode) == FileType::Symlink {
                incomplete = true;
            }
            continue;
        }
        let volume_directory = match macos_open_directory_at(&volumes_directory, name) {
            Ok(Some(directory)) => directory,
            Ok(None) | Err(_) => {
                incomplete = true;
                continue;
            }
        };
        let Some(volume_device) = device_id(&volume_directory) else {
            incomplete = true;
            continue;
        };
        if volume_device == volumes_device {
            continue;
        }
        let volume_metadata = match volume_directory.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                incomplete = true;
                continue;
            }
        };
        let trash_root =
            match macos_open_directory_at(&volume_directory, std::ffi::OsStr::new(".Trashes")) {
                Ok(Some(directory)) => directory,
                Ok(None) => continue,
                Err(_) => {
                    incomplete = true;
                    continue;
                }
            };
        let trash_root_metadata = match trash_root.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                incomplete = true;
                continue;
            }
        };
        let shared_root_safe = (trash_root_metadata.uid() == 0 || trash_root_metadata.uid() == uid)
            && (trash_root_metadata.mode() & 0o022 == 0
                || (trash_root_metadata.uid() == 0 && trash_root_metadata.mode() & 0o1000 != 0));
        if !shared_root_safe || trash_root_metadata.dev() != volume_metadata.dev() {
            incomplete = true;
            continue;
        }
        let user_trash = match macos_open_directory_at(&trash_root, std::ffi::OsStr::new(&uid_name))
        {
            Ok(Some(directory)) => directory,
            Ok(None) => continue,
            Err(_) => {
                incomplete = true;
                continue;
            }
        };
        let user_trash_metadata = match user_trash.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                incomplete = true;
                continue;
            }
        };
        if user_trash_metadata.uid() != uid
            || user_trash_metadata.mode() & 0o022 != 0
            || user_trash_metadata.dev() != volume_metadata.dev()
        {
            incomplete = true;
            continue;
        }
        let path = volumes.join(name).join(".Trashes").join(&uid_name);
        let remaining_items = limit.saturating_sub(total_items);
        let remaining_size_entries = size_limit.saturating_sub(total_size_entries);
        match macos_trash_location_from_directory(
            &path,
            "macOS volume Trash",
            &user_trash,
            cancel,
            remaining_items,
            remaining_size_entries,
        ) {
            Ok((location, discovered_size_entries)) => {
                total_items = total_items.saturating_add(location.item_count.unwrap_or_default());
                total_size_entries = total_size_entries.saturating_add(discovered_size_entries);
                locations.push(location);
            }
            Err(_) if cancel.load(Ordering::Relaxed) => {
                cancelled = true;
                break;
            }
            Err(_) => {
                incomplete = true;
                break;
            }
        }
    }
    let warnings = if incomplete {
        vec!["Mounted-volume Trash inventory is incomplete; inaccessible, changing, linked, or over-limit /Volumes entries were skipped.".into()]
    } else {
        vec![]
    };
    (locations, warnings, cancelled)
}

#[cfg(any(target_os = "macos", all(test, target_os = "linux")))]
fn macos_trash_status_with(
    home: Option<&Path>,
    volumes: &Path,
    uid: u32,
    cancel: &AtomicBool,
    limit: u64,
    device_id: impl FnMut(&std::fs::File) -> Option<u64>,
) -> TrashReport {
    let mut report = match home {
        Some(home) => macos_home_trash_report(home, cancel, limit),
        None => TrashReport {
            platform: "macos",
            locations: vec![],
            warnings: vec!["Home Trash inventory unavailable: home directory is unknown".into()],
            cancelled: cancel.load(Ordering::Relaxed),
        },
    };
    report.warnings.insert(0, format!("Trash status is read-only. It inventories the current user's home Trash and direct mounted volumes under /Volumes; volume Trash lookup uses the undocumented .Trashes/<effective UID> layout as a heuristic, so this is not a complete Finder inventory. Volume scanning is capped at {MACOS_VOLUME_ENTRY_LIMIT} /Volumes entries, {limit} listed items, and {MACOS_HOME_TRASH_SIZE_ENTRY_LIMIT} size-walk entries total across mounted-volume locations. Same-device mounts and other mount locations may be omitted. Deletion dates and item actions are unavailable."));
    if !report.cancelled {
        let (locations, warnings, cancelled) = macos_volume_trash_locations_with(
            volumes,
            uid,
            cancel,
            limit,
            MACOS_HOME_TRASH_SIZE_ENTRY_LIMIT,
            device_id,
        );
        report.locations.extend(locations);
        report.warnings.extend(warnings);
        if cancelled {
            report.warnings.push(
                "Mounted-volume Trash inventory was cancelled; results may be partial.".into(),
            );
        }
        report.cancelled |= cancelled;
    } else if !report
        .warnings
        .iter()
        .any(|warning| warning.to_ascii_lowercase().contains("cancel"))
    {
        report
            .warnings
            .push("Trash inventory was cancelled.".into());
    }
    report
}

pub fn status(cancel: &AtomicBool) -> TrashReport {
    #[cfg(target_os = "linux")]
    {
        linux_status(cancel, None)
    }
    #[cfg(target_os = "windows")]
    {
        let result = query_windows_recycle_bin(cancel);
        let mut cancelled = cancel.load(Ordering::Relaxed);
        let summary = match result {
            Ok(Some(summary)) => Ok(summary),
            Ok(None) => {
                cancelled = true;
                Err(anyhow::anyhow!("inventory cancelled"))
            }
            Err(error) => Err(error),
        };
        windows_recycle_bin_report(summary, cancelled)
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;

        macos_trash_status_with(
            dirs::home_dir().as_deref(),
            Path::new("/Volumes"),
            rustix::process::geteuid().as_raw(),
            cancel,
            10_000,
            |directory| directory.metadata().ok().map(|metadata| metadata.dev()),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        TrashReport {
            platform: std::env::consts::OS,
            locations: vec![],
            warnings: vec![
                "native Trash or Recycle Bin inventory is not implemented on this platform".into(),
            ],
            cancelled: cancel.load(Ordering::Relaxed),
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod macos_home_trash_tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::os::unix::ffi::OsStringExt;
    use std::{fs, os::unix::fs::symlink};

    #[test]
    fn macos_status_includes_only_verified_volume_trash_without_following_links() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let uid = rustix::process::geteuid().as_raw();
        let home = tempfile::tempdir().unwrap();
        let home_trash = home.path().join(".Trash");
        fs::create_dir(&home_trash).unwrap();
        fs::write(home_trash.join("home-item"), b"home fixture").unwrap();

        let volumes = tempfile::tempdir().unwrap();
        #[cfg(target_os = "linux")]
        let mounted_name = std::ffi::OsString::from_vec(b"Disk-\xff".to_vec());
        #[cfg(target_os = "macos")]
        let mounted_name = std::ffi::OsString::from("Disk-%\n");
        let mounted = volumes.path().join(&mounted_name);
        let mounted_shared_trash = mounted.join(".Trashes");
        let mounted_trash = mounted_shared_trash.join(uid.to_string());
        fs::create_dir_all(&mounted_trash).unwrap();
        for path in [&mounted_shared_trash, &mounted_trash] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(mounted_trash.join("volume-item"), b"volume fixture").unwrap();

        let ordinary = volumes.path().join("ordinary-directory");
        let ordinary_shared_trash = ordinary.join(".Trashes");
        let ordinary_trash = ordinary_shared_trash.join(uid.to_string());
        fs::create_dir_all(&ordinary_trash).unwrap();
        for path in [&ordinary_shared_trash, &ordinary_trash] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(ordinary_trash.join("not-a-mount"), b"must not list").unwrap();

        let outside = tempfile::tempdir().unwrap();
        let outside_shared_trash = outside.path().join(".Trashes");
        let outside_trash = outside_shared_trash.join(uid.to_string());
        fs::create_dir_all(&outside_trash).unwrap();
        for path in [&outside_shared_trash, &outside_trash] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(outside_trash.join("outside-item"), b"must not follow").unwrap();
        let linked_volume = volumes.path().join("linked-volume");
        symlink(outside.path(), &linked_volume).unwrap();

        let unsafe_mount = volumes.path().join("unsafe-mount");
        fs::create_dir(&unsafe_mount).unwrap();
        symlink(outside.path(), unsafe_mount.join(".Trashes")).unwrap();

        let root_device = fs::metadata(volumes.path()).unwrap().dev();
        let mounted_inodes = [
            fs::metadata(&mounted).unwrap().ino(),
            fs::metadata(&unsafe_mount).unwrap().ino(),
        ];
        let report = macos_trash_status_with(
            Some(home.path()),
            volumes.path(),
            uid,
            &AtomicBool::new(false),
            10,
            |directory| {
                let metadata = directory.metadata().ok()?;
                Some(if mounted_inodes.contains(&metadata.ino()) {
                    root_device.wrapping_add(1)
                } else {
                    metadata.dev()
                })
            },
        );

        assert_eq!(report.locations.len(), 2);
        assert!(report.locations.iter().any(|location| {
            location.kind == "macOS home Trash"
                && location.items.iter().any(|item| item.name == "home-item")
        }));
        let volume_location = report
            .locations
            .iter()
            .find(|location| location.kind == "macOS volume Trash")
            .unwrap();
        assert_eq!(volume_location.item_count, Some(1));
        assert!(volume_location.items_complete);
        assert!(
            volume_location
                .items
                .iter()
                .any(|item| item.name == "volume-item")
        );
        assert!(!report.locations.iter().any(|location| {
            location
                .items
                .iter()
                .any(|item| matches!(item.name.as_str(), "not-a-mount" | "outside-item"))
        }));
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("not a complete Finder inventory"))
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("incomplete"))
        );
        assert_eq!(
            fs::read(mounted_trash.join("volume-item")).unwrap(),
            b"volume fixture"
        );
        assert_eq!(
            fs::read(outside_trash.join("outside-item")).unwrap(),
            b"must not follow"
        );
    }

    #[test]
    fn macos_volume_item_and_size_budgets_are_shared_and_cancellable() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let uid = rustix::process::geteuid().as_raw();
        let volumes = tempfile::tempdir().unwrap();
        let mut mount_inodes = Vec::new();
        let mut items = Vec::new();
        for name in ["disk-a", "disk-b"] {
            let mount = volumes.path().join(name);
            let shared_trash = mount.join(".Trashes");
            let trash = shared_trash.join(uid.to_string());
            fs::create_dir_all(&trash).unwrap();
            for path in [&shared_trash, &trash] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let item = trash.join(format!("{name}-item"));
            fs::write(&item, b"fixture").unwrap();
            mount_inodes.push(fs::metadata(&mount).unwrap().ino());
            items.push(item);
        }
        let root_device = fs::metadata(volumes.path()).unwrap().dev();
        let fake_device = |directory: &std::fs::File| {
            let metadata = directory.metadata().ok()?;
            Some(if mount_inodes.contains(&metadata.ino()) {
                root_device.wrapping_add(1)
            } else {
                metadata.dev()
            })
        };

        let (limited, warnings, cancelled) = macos_volume_trash_locations_with(
            volumes.path(),
            uid,
            &AtomicBool::new(false),
            1,
            100,
            |directory| fake_device(directory),
        );
        assert!(!cancelled);
        assert_eq!(limited.len(), 1);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("incomplete"))
        );

        let (sized, warnings, cancelled) = macos_volume_trash_locations_with(
            volumes.path(),
            uid,
            &AtomicBool::new(false),
            10,
            1,
            |directory| fake_device(directory),
        );
        assert!(!cancelled);
        assert_eq!(sized.len(), 2);
        assert!(warnings.is_empty());
        assert_eq!(
            sized
                .iter()
                .filter(|location| location.size_complete)
                .count(),
            1
        );
        assert_eq!(
            sized
                .iter()
                .filter(|location| !location.size_complete)
                .count(),
            1
        );

        let cancel = AtomicBool::new(false);
        let (cancelled_locations, _, cancelled) =
            macos_volume_trash_locations_with(volumes.path(), uid, &cancel, 10, 100, |directory| {
                let metadata = directory.metadata().ok()?;
                if mount_inodes.contains(&metadata.ino()) {
                    cancel.store(true, Ordering::Relaxed);
                    Some(root_device.wrapping_add(1))
                } else {
                    Some(metadata.dev())
                }
            });
        assert!(cancelled);
        assert!(cancelled_locations.is_empty());
        assert!(items.iter().all(|item| item.exists()));
    }

    #[test]
    fn macos_home_trash_lists_top_level_items_without_touching_them() {
        let home = tempfile::tempdir().unwrap();
        let trash = home.path().join(".Trash");
        fs::create_dir(&trash).unwrap();
        fs::write(trash.join("file"), b"fixture").unwrap();
        fs::create_dir(trash.join("directory")).unwrap();
        fs::write(trash.join("directory/nested"), b"fixture").unwrap();
        #[cfg(target_os = "linux")]
        let escaped_name = std::ffi::OsString::from_vec(b"name%\n\xff".to_vec());
        #[cfg(target_os = "macos")]
        let escaped_name = std::ffi::OsString::from("name%\n");
        #[cfg(target_os = "linux")]
        let escaped_label = "name%25%0A%FF";
        #[cfg(target_os = "macos")]
        let escaped_label = "name%25%0A";
        fs::write(trash.join(escaped_name), b"").unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"outside").unwrap();
        symlink(outside.path(), trash.join("link")).unwrap();

        let report = macos_home_trash_report(home.path(), &AtomicBool::new(false), 10);
        assert_eq!(report.locations.len(), 1);
        let location = &report.locations[0];
        assert_eq!(location.item_count, Some(4));
        assert!(location.items_complete);
        assert_eq!(location.items.len(), 4);
        assert!(location.items.iter().any(|item| item.name == "file"));
        assert!(location.items.iter().any(|item| item.name == "directory"));
        assert!(location.items.iter().any(|item| item.name == "link"));
        assert!(location.items.iter().any(|item| item.name == escaped_label));
        assert!(
            location
                .items
                .iter()
                .all(|item| item.deletion_date.is_none())
        );
        assert_eq!(location.logical_bytes, Some(14));
        assert!(!location.size_complete);
        assert!(
            location
                .warnings
                .iter()
                .any(|warning| warning.contains("does not detect same-device mounts"))
        );
        assert!(
            location
                .warnings
                .iter()
                .any(|warning| warning.contains("Symbolic links were skipped"))
        );
        assert_eq!(
            fs::read(trash.join("directory/nested")).unwrap(),
            b"fixture"
        );
        assert_eq!(fs::read(outside.path().join("keep")).unwrap(), b"outside");
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["locations"][0]["item_count"], 4);
        assert_eq!(json["locations"][0]["logical_bytes"], 14);
        assert_eq!(json["locations"][0]["items"].as_array().unwrap().len(), 4);
        assert!(
            json["locations"][0]["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["name"] == escaped_label)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn macos_item_snapshot_does_not_enable_linux_retention_preview() {
        let home = tempfile::tempdir().unwrap();
        let trash = home.path().join(".Trash");
        fs::create_dir(&trash).unwrap();
        fs::write(trash.join("file"), b"fixture").unwrap();

        let report = macos_home_trash_report(home.path(), &AtomicBool::new(false), 10);
        assert!(report.locations[0].items_complete);
        let error =
            retention_preview(report, std::time::Duration::from_secs(7 * 86_400)).unwrap_err();
        assert!(error.to_string().contains("unsupported"));
    }

    #[test]
    fn macos_home_trash_size_stops_at_a_bounded_entry_limit() {
        use rustix::fs::{Mode, OFlags, open};

        let home = tempfile::tempdir().unwrap();
        let trash = home.path().join(".Trash");
        fs::create_dir(&trash).unwrap();
        fs::write(trash.join("file"), b"fixture").unwrap();
        fs::create_dir(trash.join("directory")).unwrap();
        fs::write(trash.join("directory/nested"), b"fixture").unwrap();
        let directory = std::fs::File::from(
            open(
                &trash,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap(),
        );
        let (names, exceeded) = macos_trash_names(&directory, &AtomicBool::new(false), 10).unwrap();
        assert!(!exceeded);

        let measured = macos_trash_size(&directory, names, &AtomicBool::new(false), 1).unwrap();
        assert!(!measured.complete);
        assert!(
            measured
                .warnings
                .iter()
                .any(|warning| warning.contains("safe entry limit"))
        );
        assert_eq!(fs::read(trash.join("file")).unwrap(), b"fixture");
        assert_eq!(
            fs::read(trash.join("directory/nested")).unwrap(),
            b"fixture"
        );
    }

    #[test]
    fn macos_home_trash_refuses_links_limits_and_cancellation() {
        let home = tempfile::tempdir().unwrap();
        let trash = home.path().join(".Trash");
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("keep"), b"fixture").unwrap();
        symlink(outside.path(), &trash).unwrap();
        let cancel = AtomicBool::new(false);
        let linked = macos_home_trash_report(home.path(), &cancel, 10);
        assert!(linked.locations.is_empty());
        assert!(
            linked
                .warnings
                .iter()
                .any(|text| text.contains("unavailable"))
        );
        fs::remove_file(&trash).unwrap();
        fs::create_dir(&trash).unwrap();
        fs::write(trash.join("one"), b"one").unwrap();
        fs::write(trash.join("two"), b"two").unwrap();
        let exact_limit = macos_home_trash_report(home.path(), &cancel, 2);
        assert_eq!(exact_limit.locations.len(), 1);
        assert_eq!(exact_limit.locations[0].item_count, Some(2));
        assert_eq!(exact_limit.locations[0].items.len(), 2);
        assert!(exact_limit.locations[0].items_complete);
        let limited = macos_home_trash_report(home.path(), &cancel, 1);
        assert!(limited.locations.is_empty());
        assert!(limited.warnings.iter().any(|text| text.contains("limit")));
        cancel.store(true, Ordering::Relaxed);
        let cancelled = macos_home_trash_report(home.path(), &cancel, 10);
        assert!(cancelled.cancelled && cancelled.locations.is_empty());
        assert_eq!(fs::read(outside.path().join("keep")).unwrap(), b"fixture");
    }
}

#[cfg(all(test, unix))]
mod windows_inventory_tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    static GUARD_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn fake_powershell(dir: &Path, body: &str) -> PathBuf {
        let executable = dir.join("fake-powershell");
        std::fs::write(&executable, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        executable
    }

    #[test]
    fn system_powershell_resolution_rejects_fixture_reparse_components() {
        let dir = tempfile::tempdir().unwrap();
        let fixture_root = dir.path().canonicalize().unwrap();
        let system = fixture_root.join("system");
        let executable = system
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, b"synthetic executable").unwrap();
        let system_link = fixture_root.join("system-link");
        symlink(&system, &system_link).unwrap();
        assert!(windows_powershell_executable(&system_link).is_err());

        std::fs::remove_file(&executable).unwrap();
        let outside = fixture_root.join("outside-powershell.exe");
        std::fs::write(&outside, b"synthetic executable").unwrap();
        symlink(&outside, &executable).unwrap();
        assert!(windows_powershell_executable(&system).is_err());
    }

    #[test]
    fn windows_recycle_bin_fake_shell_inventory_uses_an_isolated_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("isolated-home");
        std::fs::create_dir(&home).unwrap();
        let executable = fake_powershell(
            dir.path(),
            "[ \"$1\" = \"-NoLogo\" ] || exit 11\n[ \"$2\" = \"-NoProfile\" ] || exit 12\n[ \"$3\" = \"-NonInteractive\" ] || exit 13\n[ \"$4\" = \"-Sta\" ] || exit 14\n[ \"$5\" = \"-Command\" ] || exit 15\nprintf '23\\t456\\t1\\n'",
        );
        assert!(WINDOWS_RECYCLE_BIN_SCRIPT.contains("NameSpace(10)"));
        assert!(WINDOWS_RECYCLE_BIN_SCRIPT.contains("$items = $bin.Items()"));
        assert!(WINDOWS_RECYCLE_BIN_SCRIPT.contains("$item.Size"));
        assert!(WINDOWS_RECYCLE_BIN_SCRIPT.contains("$item.IsFolder"));
        assert!(WINDOWS_RECYCLE_BIN_SCRIPT.contains("$scanned -ge 100000"));
        assert!(
            WINDOWS_RECYCLE_BIN_SCRIPT.contains("[Type]::GetTypeFromProgID('Shell.Application')")
        );
        assert!(WINDOWS_RECYCLE_BIN_SCRIPT.contains("[Activator]::CreateInstance($shellType)"));
        assert!(!WINDOWS_RECYCLE_BIN_SCRIPT.contains("New-Object"));
        assert!(!WINDOWS_RECYCLE_BIN_SCRIPT.contains("InvokeVerb"));
        assert!(!WINDOWS_RECYCLE_BIN_SCRIPT.contains("MoveHere"));
        assert!(!WINDOWS_RECYCLE_BIN_SCRIPT.contains("CopyHere"));

        let summary = query_windows_recycle_bin_with_executable(
            &executable,
            &AtomicBool::new(false),
            Duration::from_secs(1),
            Some(&home),
            None,
        )
        .unwrap()
        .unwrap();
        let report = windows_recycle_bin_report(Ok(summary), false);
        let location = &report.locations[0];
        assert!(location.path.as_os_str().is_empty());
        assert_eq!(location.kind, "Windows Recycle Bin (virtual)");
        assert_eq!(location.item_count, Some(23));
        assert_eq!(location.logical_bytes, Some(456));
        assert_eq!(location.allocated_bytes, None);
        assert!(location.size_complete);
        assert!(location.items.is_empty());
        assert!(!location.items_complete);
        assert!(location.warnings[0].contains("deletion dates are unknown"));
        assert_eq!(report.platform, "windows");
    }

    #[test]
    fn windows_recycle_bin_fake_shell_output_and_runtime_are_bounded_and_cancellable() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("isolated-home");
        std::fs::create_dir(&home).unwrap();

        let oversized = fake_powershell(dir.path(), "printf '%080d\\n' 1\nwhile :; do :; done");
        let error = query_windows_recycle_bin_with_executable(
            &oversized,
            &AtomicBool::new(false),
            Duration::from_secs(1),
            Some(&home),
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("bounded limit"));

        let slow = fake_powershell(dir.path(), "while :; do :; done");
        let started = Instant::now();
        let error = query_windows_recycle_bin_with_executable(
            &slow,
            &AtomicBool::new(false),
            Duration::from_millis(60),
            Some(&home),
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));

        let cancel = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&cancel);
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            signal.store(true, Ordering::Relaxed);
        });
        let started = Instant::now();
        let result = query_windows_recycle_bin_with_executable(
            &slow,
            &cancel,
            Duration::from_secs(1),
            Some(&home),
            None,
        )
        .unwrap();
        canceller.join().unwrap();
        assert!(result.is_none());
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn windows_recycle_bin_descendant_holding_stdout_keeps_the_single_query_guard() {
        let _serial = GUARD_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("isolated-home");
        std::fs::create_dir(&home).unwrap();
        let executable = fake_powershell(
            dir.path(),
            "(while [ ! -e \"$HOME/release-reader\" ]; do :; done) &\n( /bin/sleep 2; : > \"$HOME/release-reader\" ) >/dev/null 2>&1 &\nprintf '23\\n'",
        );
        let active = WindowsRecycleBinQueryGuard::acquire().unwrap();
        let error = query_windows_recycle_bin_with_executable(
            &executable,
            &AtomicBool::new(false),
            Duration::from_millis(60),
            Some(&home),
            Some(active),
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(WINDOWS_RECYCLE_BIN_QUERY_ACTIVE.load(Ordering::Relaxed));
        assert!(WindowsRecycleBinQueryGuard::acquire().is_err());

        std::fs::write(home.join("release-reader"), "release").unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while WINDOWS_RECYCLE_BIN_QUERY_ACTIVE.load(Ordering::Relaxed) && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!WINDOWS_RECYCLE_BIN_QUERY_ACTIVE.load(Ordering::Relaxed));
    }

    #[test]
    fn windows_recycle_bin_child_closing_stdout_keeps_the_guard_until_timeout_kills_it() {
        let _serial = GUARD_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("isolated-home");
        std::fs::create_dir(&home).unwrap();
        let executable = fake_powershell(dir.path(), "exec 1>&-\nwhile :; do :; done");
        let active = WindowsRecycleBinQueryGuard::acquire().unwrap();
        let executable_for_query = executable.clone();
        let home_for_query = home.clone();
        let query = std::thread::spawn(move || {
            query_windows_recycle_bin_with_executable(
                &executable_for_query,
                &AtomicBool::new(false),
                Duration::from_millis(200),
                Some(&home_for_query),
                Some(active),
            )
        });
        std::thread::sleep(Duration::from_millis(60));
        assert!(WINDOWS_RECYCLE_BIN_QUERY_ACTIVE.load(Ordering::Relaxed));
        assert!(WindowsRecycleBinQueryGuard::acquire().is_err());
        assert!(
            query
                .join()
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        assert!(!WINDOWS_RECYCLE_BIN_QUERY_ACTIVE.load(Ordering::Relaxed));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod trash_path_serialization_tests {
    use super::*;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    #[test]
    fn trash_location_paths_serialize_non_unicode_without_changing_removal_tokens() {
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"/trash-\xff".to_vec()));
        let identity = TrashIdentity {
            name: "fixture".into(),
            uid: 0,
            metadata: vec![],
            mount_ids: vec![],
            cutoff_unix_nanos: None,
        };
        let item = RetentionItem {
            location: path.clone(),
            name: "fixture".into(),
            deletion_date: None,
            age_status: "unknown_or_ambiguous",
            location_complete: true,
            selected: false,
            identity: Some(identity),
        };
        let token_before = removal_token(&item, None, None).unwrap();
        let expected = serde_json::json!({
            "encoding": "unix-percent-bytes",
            "value": "/trash-%FF"
        });
        let report = TrashReport {
            platform: "linux",
            locations: vec![TrashLocation {
                path: path.clone(),
                kind: "fixture",
                item_count: Some(1),
                logical_bytes: None,
                allocated_bytes: None,
                size_complete: false,
                warnings: vec![],
                items: vec![],
                items_complete: false,
            }],
            warnings: vec![],
            cancelled: false,
        };
        let selection = RetentionSelection {
            location: path.clone(),
            eligible: 0,
            newer_or_unknown: 0,
            unsupported: 0,
        };
        let plan = TrashRemovalPlan {
            location: path.clone(),
            name: "fixture".into(),
            deletion_date: None,
            kind: "file",
            descendant_count: 0,
            logical_bytes: 0,
            preview_token: token_before.clone(),
            warning: "fixture",
            item: item.clone(),
            older_than_seconds: None,
            tree: None,
        };
        let batch_item = TrashBatchItemResult {
            location: path.clone(),
            name: "fixture".into(),
            status: "fixture",
            error: None,
        };

        assert_eq!(
            serde_json::to_value(report).unwrap()["locations"][0]["path"],
            expected
        );
        assert_eq!(serde_json::to_value(&item).unwrap()["location"], expected);
        assert_eq!(
            serde_json::to_value(selection).unwrap()["location"],
            expected
        );
        assert_eq!(serde_json::to_value(plan).unwrap()["location"], expected);
        assert_eq!(
            serde_json::to_value(batch_item).unwrap()["location"],
            expected
        );
        assert_eq!(removal_token(&item, None, None).unwrap(), token_before);
        assert_eq!(path.as_os_str().as_bytes(), b"/trash-\xff");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    fn two_file_fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let trash = dir.path().join("trash");
        fs::create_dir_all(trash.join("files")).unwrap();
        fs::create_dir_all(trash.join("info")).unwrap();
        for path in [&trash, &trash.join("files"), &trash.join("info")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for name in ["first", "second"] {
            fs::write(trash.join("files").join(name), b"fixture").unwrap();
            fs::set_permissions(
                trash.join("files").join(name),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            fs::write(
                trash.join("info").join(format!("{name}.trashinfo")),
                "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n",
            )
            .unwrap();
            fs::set_permissions(
                trash.join("info").join(format!("{name}.trashinfo")),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        (dir, trash)
    }

    fn recent_file_fixture(count: usize) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let trash = dir.path().join("trash");
        fs::create_dir_all(trash.join("files")).unwrap();
        fs::create_dir_all(trash.join("info")).unwrap();
        for path in [&trash, &trash.join("files"), &trash.join("info")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for index in 0..count {
            let name = format!("item-{index:02}");
            fs::write(trash.join("files").join(&name), b"fixture").unwrap();
            fs::set_permissions(
                trash.join("files").join(&name),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let date = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S");
            fs::write(
                trash.join("info").join(format!("{name}.trashinfo")),
                format!("[Trash Info]\nDeletionDate={date}\n"),
            )
            .unwrap();
            fs::set_permissions(
                trash.join("info").join(format!("{name}.trashinfo")),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        (dir, trash)
    }

    fn rewrite_same_size_restore_mtime(path: &Path, contents: &str) {
        let before = fs::metadata(path).unwrap();
        assert_eq!(before.len(), contents.len() as u64);
        let modified = before.modified().unwrap();
        fs::write(path, contents).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified))
            .unwrap();
        let after = fs::metadata(path).unwrap();
        assert_eq!(after.len(), before.len());
        assert_eq!(after.modified().unwrap(), modified);
        assert_ne!(
            (after.ctime(), after.ctime_nsec()),
            (before.ctime(), before.ctime_nsec())
        );
    }

    fn change_trashinfo_date_same_size(contents: &str) -> String {
        let mut changed = contents.to_owned();
        let date = changed.find("DeletionDate=").unwrap() + "DeletionDate=".len();
        let last = date + 18;
        changed.replace_range(
            last..last + 1,
            if changed.as_bytes()[last] == b'0' {
                "1"
            } else {
                "0"
            },
        );
        changed
    }

    fn scheduled_fixture_preview(
        trash: &Path,
        now: chrono::DateTime<chrono::Utc>,
    ) -> ScheduledTrashPreview {
        let uid = fs::metadata(trash).unwrap().uid();
        let report = inspect(trash, &[], uid, &AtomicBool::new(false));
        let (identity, mount_id) = scheduled_location_identity_open(trash).unwrap();
        scheduled_retention_preview_from_report(
            trash,
            std::time::Duration::from_secs(30 * 24 * 60 * 60),
            now,
            &AtomicBool::new(false),
            report,
            identity,
            mount_id,
        )
        .unwrap()
    }

    fn scheduled_fixture_batch(trash: &Path) -> TrashBatchPlan {
        scheduled_fixture_preview(trash, chrono::Utc::now() + chrono::TimeDelta::days(70))
            .plan
            .unwrap()
    }

    fn scheduled_directory_fixture_batch(trash: &Path) -> TrashBatchPlan {
        let info = trash.join("info/folder.trashinfo");
        let date = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S");
        fs::write(&info, format!("[Trash Info]\nDeletionDate={date}\n")).unwrap();
        fs::set_permissions(&info, fs::Permissions::from_mode(0o600)).unwrap();
        let preview =
            scheduled_fixture_preview(trash, chrono::Utc::now() + chrono::TimeDelta::days(70));
        assert_eq!(preview.eligible, 1);
        preview.plan.unwrap()
    }

    fn manual_age_batch(trash: &Path, age: std::time::Duration) -> TrashBatchPlan {
        let uid = fs::metadata(trash).unwrap().uid();
        let preview =
            retention_preview(inspect(trash, &[], uid, &AtomicBool::new(false)), age).unwrap();
        let mut plans = Vec::new();
        for item in preview.items.iter().filter(|item| item.location == trash) {
            plans.push(removal_plan(item, Some(age.as_secs()), &AtomicBool::new(false)).unwrap());
        }
        batch_from_plans(plans).unwrap()
    }

    fn directory_fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let trash = dir.path().join("trash");
        let tree = trash.join("files/folder");
        fs::create_dir_all(tree.join("nested")).unwrap();
        fs::create_dir_all(trash.join("info")).unwrap();
        for path in [
            &trash,
            &trash.join("files"),
            &trash.join("info"),
            &tree,
            &tree.join("nested"),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(tree.join("nested/keep"), "original").unwrap();
        fs::set_permissions(tree.join("nested/keep"), fs::Permissions::from_mode(0o600)).unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, "outside").unwrap();
        symlink(&outside, tree.join("external-link")).unwrap();
        let info = trash.join("info/folder.trashinfo");
        fs::write(&info, "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n").unwrap();
        fs::set_permissions(info, fs::Permissions::from_mode(0o600)).unwrap();
        (dir, trash, outside)
    }

    #[test]
    fn scheduled_cutoff_rejects_a_recent_trashinfo_ctime() {
        let (_dir, trash) = recent_file_fixture(2);
        let mut plan = scheduled_fixture_batch(&trash);
        let now = i128::from(chrono::Utc::now().timestamp_nanos_opt().unwrap());
        let cutoff = now - i128::from(31 * 24 * 60 * 60) * 1_000_000_000;
        for item in &mut plan.items {
            item.item.identity.as_mut().unwrap().cutoff_unix_nanos = Some(cutoff);
            item.preview_token =
                removal_token(&item.item, item.older_than_seconds, item.tree.as_ref()).unwrap();
        }
        let scheduled = plan.scheduled.as_mut().unwrap();
        scheduled.cutoff_unix_nanos = cutoff;
        scheduled.snapshot_unix_nanos = cutoff
            + i128::from(
                (scheduled.age + std::time::Duration::from_secs(RETENTION_TIMEZONE_MARGIN_SECONDS))
                    .as_nanos() as u64,
            );
        plan.preview_token = scheduled_batch_token(&plan.items, scheduled).unwrap();
        let snapshot = scheduled.snapshot_unix_nanos;
        let result = remove_scheduled_batch_with_guard_and_clock(
            &plan,
            &plan.preview_token,
            &AtomicBool::new(false),
            &|| Ok(()),
            || Ok(snapshot),
            |_, _| {},
        )
        .unwrap();
        assert_ne!(result.outcome, "completed");
        assert_eq!(result.items[0].status, "failed_or_skipped");
        assert_eq!(result.items[1].status, "not_attempted");
        assert!(trash.join("files/item-00").exists());
        assert!(trash.join("files/item-01").exists());
    }

    #[test]
    fn scheduled_preview_deletes_an_item_proven_old_by_the_injected_clock() {
        let (_dir, trash) = recent_file_fixture(1);
        let now = chrono::Utc::now() + chrono::TimeDelta::days(70);
        let preview = scheduled_fixture_preview(&trash, now);
        assert_eq!(preview.eligible, 1);
        assert_eq!(preview.deferred, 0);
        let plan = preview.plan.unwrap();
        assert_eq!(plan.items.len(), 1);
        let snapshot = plan.scheduled.as_ref().unwrap().snapshot_unix_nanos;
        let result = remove_scheduled_batch_with_guard_and_clock(
            &plan,
            &plan.preview_token,
            &AtomicBool::new(false),
            &|| Ok(()),
            || Ok(snapshot),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(result.outcome, "completed");
        assert_eq!(result.items[0].status, "verified_absent");
        assert!(!trash.join("files/item-00").exists());
        assert!(!trash.join("info/item-00.trashinfo").exists());
    }

    #[test]
    fn scheduled_candidate_digest_ignores_clock_but_tracks_candidate_changes() {
        let (_dir, trash) = recent_file_fixture(1);
        let now = chrono::Utc::now() + chrono::TimeDelta::days(70);
        let first = scheduled_fixture_preview(&trash, now);
        let clock_only_change =
            scheduled_fixture_preview(&trash, now + chrono::TimeDelta::nanoseconds(1));
        assert_ne!(
            first.snapshot_unix_nanos,
            clock_only_change.snapshot_unix_nanos
        );
        assert_eq!(first.candidate_digest, clock_only_change.candidate_digest);
        assert_eq!(first.eligible, 1);

        let original_digest = clock_only_change.candidate_digest;
        rewrite_same_size_restore_mtime(&trash.join("files/item-00"), "changed");
        let changed_identity =
            scheduled_fixture_preview(&trash, now + chrono::TimeDelta::nanoseconds(2));
        assert_ne!(original_digest, changed_identity.candidate_digest);
        assert_eq!(changed_identity.eligible, 1);

        let future_date = chrono::Local::now() + chrono::TimeDelta::days(50);
        fs::write(
            trash.join("info/item-00.trashinfo"),
            format!(
                "[Trash Info]\nDeletionDate={}\n",
                future_date.format("%Y-%m-%dT%H:%M:%S")
            ),
        )
        .unwrap();
        fs::set_permissions(
            trash.join("info/item-00.trashinfo"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let no_longer_eligible =
            scheduled_fixture_preview(&trash, now + chrono::TimeDelta::nanoseconds(3));
        assert_eq!(no_longer_eligible.eligible, 0);
        assert_ne!(
            changed_identity.candidate_digest,
            no_longer_eligible.candidate_digest
        );
    }

    #[test]
    fn public_single_item_removal_rejects_a_scheduled_item() {
        let (_dir, trash) = recent_file_fixture(1);
        let batch = scheduled_fixture_batch(&trash);
        let item = &batch.items[0];
        let error = remove_file(item, &item.preview_token)
            .unwrap_err()
            .to_string();

        assert!(error.contains("scheduled Trash items require the scheduled executor"));
        assert!(trash.join("files/item-00").exists());
        assert!(trash.join("info/item-00.trashinfo").exists());
        assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 1);
    }

    #[test]
    fn scheduled_preview_rejects_retention_just_below_30_days() {
        let (_dir, trash) = recent_file_fixture(1);
        let uid = fs::metadata(&trash).unwrap().uid();
        let report = inspect(&trash, &[], uid, &AtomicBool::new(false));
        let (identity, mount_id) = scheduled_location_identity_open(&trash).unwrap();
        let age = std::time::Duration::from_secs(MIN_SCHEDULED_TRASH_RETENTION_SECONDS)
            .checked_sub(std::time::Duration::from_nanos(1))
            .unwrap();
        let result = scheduled_retention_preview_from_report(
            &trash,
            age,
            chrono::Utc::now() + chrono::TimeDelta::days(70),
            &AtomicBool::new(false),
            report,
            identity,
            mount_id,
        );

        let error = result.err().unwrap();
        assert!(error.to_string().contains("at least 30 days"));
        assert!(trash.join("files/item-00").exists());
    }

    #[test]
    fn scheduled_entrypoint_rejects_manual_batches_without_a_scheduled_identity() {
        let (_dir, trash) = two_file_fixture();
        let age = std::time::Duration::from_secs(MIN_SCHEDULED_TRASH_RETENTION_SECONDS);
        let plan = manual_age_batch(&trash, age);
        let guard_calls = std::sync::atomic::AtomicUsize::new(0);
        let error = remove_scheduled_batch_with_guard(
            &plan,
            &plan.preview_token,
            &AtomicBool::new(false),
            &|| {
                guard_calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            |_, _| {},
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("scheduled Trash plan identity is missing"));
        assert_eq!(guard_calls.load(Ordering::Relaxed), 0);
        for name in ["first", "second"] {
            assert!(trash.join(format!("files/{name}")).exists());
            assert!(trash.join(format!("info/{name}.trashinfo")).exists());
        }

        let short_age = std::time::Duration::from_secs(86400);
        let mut short = manual_age_batch(&trash, short_age);
        let snapshot = i128::from(chrono::Utc::now().timestamp_nanos_opt().unwrap())
            + i128::from(3 * 24 * 60 * 60) * 1_000_000_000;
        let cutoff = snapshot - i128::from(3 * 24 * 60 * 60) * 1_000_000_000;
        for item in &mut short.items {
            item.item.identity.as_mut().unwrap().cutoff_unix_nanos = Some(cutoff);
            item.preview_token =
                removal_token(&item.item, item.older_than_seconds, item.tree.as_ref()).unwrap();
        }
        let (location_identity, mount_id) = scheduled_location_identity_open(&trash).unwrap();
        let scheduled = ScheduledTrashPlanIdentity {
            location_identity,
            mount_id,
            age: short_age,
            cutoff_unix_nanos: cutoff,
            snapshot_unix_nanos: snapshot,
            eligible: short.items.len(),
            deferred: 0,
            skipped: 0,
        };
        short.preview_token = scheduled_batch_token(&short.items, &scheduled).unwrap();
        short.scheduled = Some(scheduled);
        let error = remove_scheduled_batch_with_guard(
            &short,
            &short.preview_token,
            &AtomicBool::new(false),
            &|| Ok(()),
            |_, _| {},
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("at least 30 days"));
        for name in ["first", "second"] {
            assert!(trash.join(format!("files/{name}")).exists());
            assert!(trash.join(format!("info/{name}.trashinfo")).exists());
        }
    }

    #[test]
    fn scheduled_entrypoint_rejects_a_33_item_batch() {
        let (_dir, trash) = recent_file_fixture(33);
        let now = chrono::Utc::now() + chrono::TimeDelta::days(70);
        let mut plan = scheduled_fixture_preview(&trash, now).plan.unwrap();
        assert_eq!(plan.items.len(), MAX_SCHEDULED_TRASH_REMOVALS);
        plan.items.push(plan.items[0].clone());
        plan.preview_token =
            scheduled_batch_token(&plan.items, plan.scheduled.as_ref().unwrap()).unwrap();
        let guard_calls = std::sync::atomic::AtomicUsize::new(0);
        let error = remove_scheduled_batch_with_guard(
            &plan,
            &plan.preview_token,
            &AtomicBool::new(false),
            &|| {
                guard_calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            |_, _| {},
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("safe item limit"));
        assert_eq!(guard_calls.load(Ordering::Relaxed), 0);
        assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 33);
        assert_eq!(fs::read_dir(trash.join("info")).unwrap().count(), 33);
    }

    #[test]
    fn scheduled_entrypoint_rejects_a_rolled_back_fake_clock() {
        let (_dir, trash) = recent_file_fixture(1);
        let plan = scheduled_fixture_batch(&trash);
        let snapshot = plan.scheduled.as_ref().unwrap().snapshot_unix_nanos;
        let guard_calls = std::sync::atomic::AtomicUsize::new(0);
        let error = remove_scheduled_batch_with_guard_and_clock(
            &plan,
            &plan.preview_token,
            &AtomicBool::new(false),
            &|| {
                guard_calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            || Ok(snapshot - 1),
            |_, _| {},
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("clock moved backwards"));
        assert_eq!(guard_calls.load(Ordering::Relaxed), 0);
        assert!(trash.join("files/item-00").exists());
        assert!(trash.join("info/item-00.trashinfo").exists());
        assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 1);
    }

    #[test]
    fn scheduled_preview_caps_a_33_item_fixture_at_32_without_removing() {
        let (_dir, trash) = recent_file_fixture(33);
        let now = chrono::Utc::now() + chrono::TimeDelta::days(70);
        let preview = scheduled_fixture_preview(&trash, now);
        assert_eq!(preview.eligible, 33);
        assert_eq!(preview.deferred, 1);
        assert_eq!(preview.plan.as_ref().unwrap().items.len(), 32);
        assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 33);
    }

    #[test]
    fn scheduled_batch_reports_deferred_items_as_partial() {
        let (_dir, trash) = recent_file_fixture(33);
        let preview =
            scheduled_fixture_preview(&trash, chrono::Utc::now() + chrono::TimeDelta::days(70));
        let plan = preview.plan.unwrap();
        let snapshot = plan.scheduled.as_ref().unwrap().snapshot_unix_nanos;
        let result = remove_scheduled_batch_with_guard_and_clock(
            &plan,
            &plan.preview_token,
            &AtomicBool::new(false),
            &|| Ok(()),
            || Ok(snapshot),
            |_, _| {},
        )
        .unwrap();

        assert_eq!(result.outcome, "partial");
        assert_eq!(result.scheduled_deferred, Some(1));
        assert_eq!(result.scheduled_skipped, Some(0));
        assert!(
            result
                .items
                .iter()
                .all(|item| item.status == "verified_absent")
        );
        assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 1);
        assert_eq!(fs::read_dir(trash.join("info")).unwrap().count(), 1);
    }

    #[test]
    fn scheduled_guard_stops_before_staging_when_policy_changes() {
        let (_dir, trash) = recent_file_fixture(2);
        let plan = scheduled_fixture_batch(&trash);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let guard = || {
            if calls.fetch_add(1, Ordering::Relaxed) == 2 {
                anyhow::bail!("fixture policy change");
            }
            Ok(())
        };
        let snapshot = plan.scheduled.as_ref().unwrap().snapshot_unix_nanos;
        let result = remove_scheduled_batch_with_guard_and_clock(
            &plan,
            &plan.preview_token,
            &AtomicBool::new(false),
            &guard,
            || Ok(snapshot),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        assert_eq!(result.items[0].status, "failed_or_skipped");
        assert_eq!(result.items[1].status, "not_attempted");
        assert!(trash.join("files/item-00").exists());
        assert!(trash.join("files/item-01").exists());
        assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 2);
    }

    #[test]
    fn scheduled_guard_reports_partial_when_opt_in_changes_between_items() {
        let (_dir, trash) = recent_file_fixture(2);
        let plan = scheduled_fixture_batch(&trash);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let guard = || {
            if calls.fetch_add(1, Ordering::Relaxed) == 7 {
                anyhow::bail!("fixture opt-in disabled after first item");
            }
            Ok(())
        };
        let snapshot = plan.scheduled.as_ref().unwrap().snapshot_unix_nanos;
        let result = remove_scheduled_batch_with_guard_and_clock(
            &plan,
            &plan.preview_token,
            &AtomicBool::new(false),
            &guard,
            || Ok(snapshot),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(result.outcome, "partial");
        assert_eq!(result.items[0].status, "verified_absent");
        assert_eq!(result.items[1].status, "failed_or_skipped");
        assert!(!trash.join("files/item-00").exists());
        assert!(trash.join("files/item-01").exists());
    }

    #[test]
    fn scheduled_cancel_before_first_item_is_not_reported_as_partial() {
        let (_dir, trash) = recent_file_fixture(2);
        let plan = scheduled_fixture_batch(&trash);
        let snapshot = plan.scheduled.as_ref().unwrap().snapshot_unix_nanos;
        let cancel = AtomicBool::new(true);
        let result = remove_scheduled_batch_with_guard_and_clock(
            &plan,
            &plan.preview_token,
            &cancel,
            &|| Ok(()),
            || Ok(snapshot),
            |_, _| {},
        )
        .unwrap();

        assert_eq!(result.outcome, "cancelled");
        assert_eq!(result.items[0].status, "cancelled");
        assert_eq!(result.items[1].status, "not_attempted");
        assert!(trash.join("files/item-00").exists());
        assert!(trash.join("files/item-01").exists());
        assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 2);
        assert_eq!(fs::read_dir(trash.join("info")).unwrap().count(), 2);
    }

    #[test]
    fn directory_removal_checks_every_descendant_and_does_not_follow_links() {
        let (_dir, trash, outside) = directory_fixture();
        let uid = fs::metadata(&trash).unwrap().uid();
        let make_plan = || {
            let mut preview = retention_preview(
                inspect(&trash, &[], uid, &AtomicBool::new(false)),
                std::time::Duration::from_secs(86400),
            )
            .unwrap();
            preview.toggle(0).unwrap();
            preview.removal_plan().unwrap()
        };
        let plan = make_plan();
        assert_eq!(plan.kind, "directory");
        assert_eq!(plan.descendant_count, 3);
        assert_eq!(plan.logical_bytes, 8);
        fs::write(trash.join("files/folder/nested/keep"), "changed").unwrap();
        assert!(remove_file(&plan, &plan.preview_token).is_err());
        assert_eq!(
            fs::read_to_string(trash.join("files/folder/nested/keep")).unwrap(),
            "changed"
        );
        let plan = make_plan();
        assert_eq!(
            remove_file(&plan, &plan.preview_token).unwrap(),
            "verified_absent"
        );
        assert!(!trash.join("files/folder").exists());
        assert!(!trash.join("info/folder.trashinfo").exists());
        assert_eq!(fs::read_to_string(outside).unwrap(), "outside");
    }

    #[test]
    fn changed_directory_after_staging_is_restored_without_deletion() {
        let (_dir, trash, outside) = directory_fixture();
        let uid = fs::metadata(&trash).unwrap().uid();
        let mut preview = retention_preview(
            inspect(&trash, &[], uid, &AtomicBool::new(false)),
            std::time::Duration::from_secs(86400),
        )
        .unwrap();
        preview.toggle(0).unwrap();
        let plan = preview.removal_plan().unwrap();
        let result = remove_file_after_staging(&plan, &plan.preview_token, || {
            let quarantine = fs::read_dir(trash.join("files"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".upkit-delete-")
                })
                .unwrap();
            fs::write(quarantine.join("item/nested/keep"), "changed while staged").unwrap();
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(trash.join("files/folder/nested/keep")).unwrap(),
            "changed while staged"
        );
        assert!(trash.join("info/folder.trashinfo").exists());
        assert_eq!(fs::read_to_string(outside).unwrap(), "outside");
    }

    #[test]
    fn manual_age_removal_rejects_same_size_trashinfo_change_after_staging() {
        let (_dir, trash) = two_file_fixture();
        let uid = fs::metadata(&trash).unwrap().uid();
        let mut preview = retention_preview(
            inspect(&trash, &[], uid, &AtomicBool::new(false)),
            std::time::Duration::from_secs(MIN_SCHEDULED_TRASH_RETENTION_SECONDS),
        )
        .unwrap();
        preview.toggle(0).unwrap();
        let plan = preview.removal_plan().unwrap();
        let info = trash.join("info").join(format!("{}.trashinfo", plan.name));
        let changed = change_trashinfo_date_same_size(&fs::read_to_string(&info).unwrap());
        let error = remove_file_after_staging(&plan, &plan.preview_token, || {
            rewrite_same_size_restore_mtime(&info, &changed);
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("Trash metadata changed after preview"));
        assert!(trash.join("files").join(&plan.name).exists());
        assert_eq!(fs::read_to_string(&info).unwrap(), changed);
        assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 2);
    }

    #[test]
    fn scheduled_age_removal_rejects_same_size_trashinfo_change_after_staging() {
        let (_dir, trash) = recent_file_fixture(1);
        let mut batch = scheduled_fixture_batch(&trash);
        let plan = batch.items.remove(0);
        let info = trash.join("info").join(format!("{}.trashinfo", plan.name));
        let changed = change_trashinfo_date_same_size(&fs::read_to_string(&info).unwrap());
        let error = remove_file_with_cancel_and_hook(
            &plan,
            &plan.preview_token,
            &AtomicBool::new(false),
            &|| Ok(()),
            || rewrite_same_size_restore_mtime(&info, &changed),
            || {},
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("Trash metadata changed after preview"));
        assert!(trash.join("files").join(&plan.name).exists());
        assert_eq!(fs::read_to_string(&info).unwrap(), changed);
        assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 1);
    }

    #[test]
    fn file_removal_rejects_same_size_content_change_after_staging() {
        let (_dir, trash) = two_file_fixture();
        let uid = fs::metadata(&trash).unwrap().uid();
        let mut preview = retention_preview(
            inspect(&trash, &[], uid, &AtomicBool::new(false)),
            std::time::Duration::from_secs(MIN_SCHEDULED_TRASH_RETENTION_SECONDS),
        )
        .unwrap();
        preview.toggle(0).unwrap();
        let plan = preview.removal_plan().unwrap();
        let error = remove_file_after_staging(&plan, &plan.preview_token, || {
            let quarantine = fs::read_dir(trash.join("files"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".upkit-delete-")
                })
                .unwrap();
            rewrite_same_size_restore_mtime(&quarantine.join("item"), "changed");
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("quarantined Trash file changed while staged"));
        assert_eq!(
            fs::read_to_string(trash.join("files").join(&plan.name)).unwrap(),
            "changed"
        );
        assert!(
            trash
                .join("info")
                .join(format!("{}.trashinfo", plan.name))
                .exists()
        );
        assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 2);
    }

    #[test]
    fn retention_bulk_selects_directories_and_rejects_nested_hardlinks() {
        let (_dir, trash, outside) = directory_fixture();
        let uid = fs::metadata(&trash).unwrap().uid();
        let make_preview = || {
            retention_preview(
                inspect(&trash, &[], uid, &AtomicBool::new(false)),
                std::time::Duration::from_secs(86400),
            )
            .unwrap()
        };
        let hardlink = trash.join("files/folder/nested/hardlink");
        fs::hard_link(&outside, &hardlink).unwrap();
        let mut preview = make_preview();
        assert!(
            preview
                .select_old_files(&trash, &AtomicBool::new(false))
                .is_err()
        );
        assert!(preview.items.iter().all(|item| !item.selected));
        assert_eq!(fs::read_to_string(&outside).unwrap(), "outside");
        fs::remove_file(&hardlink).unwrap();
        let mut preview = make_preview();
        let selected = preview
            .select_old_files(&trash, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(selected.eligible, 1);
        let plan = preview.batch_removal_plan().unwrap();
        assert_eq!(plan.items[0].kind, "directory");
        let result = remove_batch(&plan, &plan.preview_token).unwrap();
        assert_eq!(result.outcome, "completed");
        assert!(!trash.join("files/folder").exists());
        assert_eq!(fs::read_to_string(outside).unwrap(), "outside");
    }

    #[test]
    fn cancelled_directory_removal_keeps_partial_tree_in_quarantine() {
        let (_dir, trash, outside) = directory_fixture();
        let uid = fs::metadata(&trash).unwrap().uid();
        let mut preview = retention_preview(
            inspect(&trash, &[], uid, &AtomicBool::new(false)),
            std::time::Duration::from_secs(86400),
        )
        .unwrap();
        preview.toggle(0).unwrap();
        let plan = preview.removal_plan().unwrap();
        let cancel = AtomicBool::new(false);
        let error = remove_file_with_cancel_and_hook(
            &plan,
            &plan.preview_token,
            &cancel,
            &|| Ok(()),
            || {},
            || cancel.store(true, Ordering::Relaxed),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("partially removed") && error.contains("inspect quarantine"));
        assert!(!trash.join("files/folder").exists());
        let quarantine = fs::read_dir(trash.join("files"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".upkit-delete-")
            })
            .unwrap();
        assert!(quarantine.join("item/nested").is_dir());
        assert!(!quarantine.join("item/nested/keep").exists());
        assert!(quarantine.join("info").exists());
        assert_eq!(fs::read_to_string(outside).unwrap(), "outside");
    }

    #[test]
    fn scheduled_guard_change_after_a_descendant_keeps_the_partial_tree_quarantined() {
        let (_dir, trash, outside) = directory_fixture();
        let uid = fs::metadata(&trash).unwrap().uid();
        let mut preview = retention_preview(
            inspect(&trash, &[], uid, &AtomicBool::new(false)),
            std::time::Duration::from_secs(86400),
        )
        .unwrap();
        preview.toggle(0).unwrap();
        let plan = preview.removal_plan().unwrap();
        let policy_enabled = AtomicBool::new(true);
        let guard = || {
            if policy_enabled.load(Ordering::Relaxed) {
                Ok(())
            } else {
                anyhow::bail!("fixture scheduled policy changed")
            }
        };
        let error = remove_file_with_cancel_and_hook(
            &plan,
            &plan.preview_token,
            &AtomicBool::new(false),
            &guard,
            || {},
            || policy_enabled.store(false, Ordering::Relaxed),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("partially removed") && error.contains("inspect quarantine"));
        assert!(!trash.join("files/folder").exists());
        assert!(!trash.join("info/folder.trashinfo").exists());
        let quarantine = fs::read_dir(trash.join("files"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".upkit-delete-")
            })
            .unwrap();
        assert!(quarantine.join("item/nested").is_dir());
        assert!(!quarantine.join("item/nested/keep").exists());
        assert!(quarantine.join("item/external-link").is_symlink());
        assert!(quarantine.join("info").exists());
        assert_eq!(fs::read_to_string(outside).unwrap(), "outside");
    }

    #[test]
    fn scheduled_batch_reports_partial_and_keeps_descendants_in_quarantine() {
        let (_dir, trash, outside) = directory_fixture();
        let plan = scheduled_directory_fixture_batch(&trash);
        let snapshot = plan.scheduled.as_ref().unwrap().snapshot_unix_nanos;
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let guard = || {
            if calls.fetch_add(1, Ordering::Relaxed) == 6 {
                anyhow::bail!("fixture scheduled policy changed after a descendant");
            }
            Ok(())
        };
        let result = remove_scheduled_batch_with_guard_and_clock(
            &plan,
            &plan.preview_token,
            &AtomicBool::new(false),
            &guard,
            || Ok(snapshot),
            |_, _| {},
        )
        .unwrap();

        assert_eq!(result.outcome, "partial");
        assert_eq!(result.items[0].status, "failed_or_skipped");
        assert!(result.items[0].error.as_deref().is_some_and(|error| {
            error.contains("partially removed") && error.contains("inspect quarantine")
        }));
        assert!(!trash.join("files/folder").exists());
        assert!(!trash.join("info/folder.trashinfo").exists());
        let quarantine = fs::read_dir(trash.join("files"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".upkit-delete-")
            })
            .unwrap();
        assert!(quarantine.join("item/nested").is_dir());
        assert!(!quarantine.join("item/nested/keep").exists());
        assert!(quarantine.join("item/external-link").is_symlink());
        assert!(quarantine.join("info").exists());
        assert_eq!(fs::read_to_string(outside).unwrap(), "outside");
    }

    #[test]
    fn moved_quarantine_root_stops_removal_before_touching_replacement() {
        let (dir, trash, outside) = directory_fixture();
        let uid = fs::metadata(&trash).unwrap().uid();
        let mut preview = retention_preview(
            inspect(&trash, &[], uid, &AtomicBool::new(false)),
            std::time::Duration::from_secs(86400),
        )
        .unwrap();
        preview.toggle(0).unwrap();
        let plan = preview.removal_plan().unwrap();
        let escaped = dir.path().join("moved-tree");
        let mut called = false;
        let error = remove_file_with_cancel_and_hook(
            &plan,
            &plan.preview_token,
            &AtomicBool::new(false),
            &|| Ok(()),
            || {},
            || {
                if called {
                    return;
                }
                called = true;
                let quarantine = fs::read_dir(trash.join("files"))
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".upkit-delete-")
                    })
                    .unwrap();
                fs::rename(quarantine.join("item"), &escaped).unwrap();
                fs::create_dir(quarantine.join("item")).unwrap();
                fs::write(quarantine.join("item/keep"), "replacement").unwrap();
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("partially removed") && error.contains("inspect quarantine"));
        assert!(fs::symlink_metadata(escaped.join("external-link")).is_ok());
        let quarantine = fs::read_dir(trash.join("files"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".upkit-delete-")
            })
            .unwrap();
        assert_eq!(
            fs::read_to_string(quarantine.join("item/keep")).unwrap(),
            "replacement"
        );
        assert_eq!(fs::read_to_string(outside).unwrap(), "outside");
    }

    #[test]
    fn effective_user_id_uses_effective_not_real_uid() {
        assert_eq!(
            effective_uid("Name:\ttest\nUid:\t1000\t2000\t3000\t4000\n"),
            Some(2000)
        );
        assert_eq!(effective_uid("Uid:\tbroken\n"), None);
    }

    #[test]
    fn inventories_home_and_both_mount_trashes_without_following_links() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let home = dir.path().join("home-trash");
        let mount = dir.path().join("mount");
        let shared = mount.join(".Trash");
        let shared_user = shared.join(uid.to_string());
        let private = mount.join(format!(".Trash-{uid}"));
        for root in [&home, &shared_user, &private] {
            fs::create_dir_all(root.join("files")).unwrap();
            fs::write(root.join("files/item"), b"abc").unwrap();
        }
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"outside").unwrap();
        symlink(&outside, home.join("files/link")).unwrap();
        let report = inspect(&home, &[mount.clone(), mount], uid, &AtomicBool::new(false));
        assert_eq!(report.locations.len(), 3);
        let main = report
            .locations
            .iter()
            .find(|location| location.kind == "home")
            .unwrap();
        assert_eq!(main.item_count, Some(2));
        assert_eq!(main.logical_bytes, Some(3));
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"outside");
        assert!(home.join("files/item").exists());
    }

    #[test]
    fn explicit_previews_inventory_only_the_canonical_target_location() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let home = dir.path().join("home-trash");
        let mount = dir.path().join("mount");
        let alias = dir.path().join("mount-alias");
        let other_mount = dir.path().join("other-mount");
        fs::create_dir_all(&mount).unwrap();
        fs::create_dir_all(&other_mount).unwrap();
        symlink(&mount, &alias).unwrap();

        let make_root = |path: &Path| {
            fs::create_dir_all(path.join("files")).unwrap();
            fs::create_dir_all(path.join("info")).unwrap();
            for part in [path, &path.join("files"), &path.join("info")] {
                fs::set_permissions(part, fs::Permissions::from_mode(0o700)).unwrap();
            }
        };
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), "fixture").unwrap();

        make_root(&home);
        fs::remove_dir(home.join("files")).unwrap();
        symlink(&outside, home.join("files")).unwrap();
        let target = mount.join(format!(".Trash-{uid}"));
        make_root(&target);
        let item = target.join("files/item");
        let info = target.join("info/item.trashinfo");
        fs::write(&item, "fixture").unwrap();
        fs::write(&info, "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n").unwrap();
        for path in [&item, &info] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let other = other_mount.join(format!(".Trash-{uid}"));
        make_root(&other);
        fs::remove_dir(other.join("files")).unwrap();
        symlink(&outside, other.join("files")).unwrap();

        let mounts = [mount.clone(), alias.clone(), other_mount.clone()];
        let cancel = AtomicBool::new(false);
        let report = inspect_with_scope(&home, &mounts, uid, Some(&target), &cancel);
        assert_eq!(report.locations.len(), 1);
        assert_eq!(report.locations[0].path, target);
        assert!(report.locations[0].warnings.is_empty());

        let retention = retention_batch_preview_from_report(
            &target,
            std::time::Duration::from_secs(86400),
            &cancel,
            report,
        )
        .unwrap();
        assert_eq!(retention.selection.eligible, 1);
        let plan = retention.plan.as_ref().unwrap();
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.items[0].location, target);
        assert!(item.exists());
        assert!(
            retention
                .warnings
                .iter()
                .all(|warning| { !warning.contains("Trash files directory is absent") })
        );

        let report = inspect_with_scope(&home, &mounts, uid, Some(&target), &cancel);
        let empty = empty_preview_from_report(&target, &cancel, report)
            .unwrap()
            .unwrap();
        assert_eq!(empty.items.len(), 1);
        assert_eq!(empty.items[0].location, target);
        assert!(item.exists());
        assert_eq!(fs::read_to_string(outside.join("keep")).unwrap(), "fixture");

        let duplicate = inspect_with_scope(
            &home,
            &[mount, alias, other_mount],
            uid,
            Some(&dir.path().join("mount-alias").join(format!(".Trash-{uid}"))),
            &cancel,
        );
        assert!(duplicate.locations.is_empty());
    }

    #[test]
    fn shared_trash_without_sticky_bit_is_not_used() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let shared = dir.path().join(".Trash");
        fs::create_dir_all(shared.join(uid.to_string()).join("files")).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        let report = inspect(
            &dir.path().join("absent"),
            &[dir.path().to_owned()],
            uid,
            &AtomicBool::new(false),
        );
        assert!(report.locations.is_empty());
        let report = inspect(
            &dir.path().join("absent"),
            &[dir.path().to_owned()],
            uid,
            &AtomicBool::new(true),
        );
        assert!(report.cancelled);
    }

    #[test]
    fn inventory_pairs_valid_deletion_dates_without_reading_linked_info() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let trash = dir.path().join("trash");
        fs::create_dir_all(trash.join("files")).unwrap();
        fs::create_dir_all(trash.join("info")).unwrap();
        for name in ["valid", "bad", "linked"] {
            fs::write(trash.join("files").join(name), "fixture").unwrap();
        }
        fs::write(
            trash.join("info/valid.trashinfo"),
            "[Trash Info]\nPath=/secret\nDeletionDate=2024-02-29T12:34:56\n",
        )
        .unwrap();
        fs::write(
            trash.join("info/bad.trashinfo"),
            "[Trash Info]\nDeletionDate=2023-02-29T12:34:56\n",
        )
        .unwrap();
        symlink(
            trash.join("info/valid.trashinfo"),
            trash.join("info/linked.trashinfo"),
        )
        .unwrap();
        let report = inspect(&trash, &[], uid, &AtomicBool::new(false));
        let items = &report.locations[0].items;
        assert_eq!(items.len(), 3);
        assert_eq!(
            items
                .iter()
                .find(|item| item.name == "valid")
                .unwrap()
                .deletion_date
                .as_deref(),
            Some("2024-02-29T12:34:56")
        );
        assert!(
            items
                .iter()
                .filter(|item| item.name != "valid")
                .all(|item| item.deletion_date.is_none())
        );
        assert!(!serde_json::to_string(&report).unwrap().contains("/secret"));
        assert!(trash.join("files/valid").exists());
    }

    #[test]
    fn retention_selection_preserves_raw_names_and_rejects_replacements() {
        use std::os::unix::ffi::OsStringExt;
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let trash = dir.path().join("trash");
        fs::create_dir_all(trash.join("files")).unwrap();
        fs::create_dir_all(trash.join("info")).unwrap();
        let names = [
            std::ffi::OsString::from_vec(vec![0xff]),
            std::ffi::OsString::from_vec(vec![0xfe]),
        ];
        for name in &names {
            fs::write(trash.join("files").join(name), "fixture").unwrap();
            let mut info = name.clone();
            info.push(".trashinfo");
            fs::write(
                trash.join("info").join(info),
                "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n",
            )
            .unwrap();
        }
        let report = inspect(&trash, &[], uid, &AtomicBool::new(false));
        let mut preview = retention_preview(report, std::time::Duration::from_secs(86400)).unwrap();
        assert_ne!(preview.items[0].name, preview.items[1].name);
        assert_eq!(preview.items[0].name, "%FE");
        assert_eq!(preview.items[1].name, "%FF");
        preview.toggle(0).unwrap();
        assert!(preview.items[0].selected);
        assert!(!preview.items[1].selected);
        let name = preview.items[1].identity.as_ref().unwrap().name.clone();
        fs::remove_file(trash.join("files").join(&name)).unwrap();
        fs::write(trash.join("files").join(&name), "replacement").unwrap();
        assert!(
            preview
                .toggle(1)
                .unwrap_err()
                .to_string()
                .contains("changed")
        );
        assert!(!preview.items[1].selected);
        assert_eq!(
            fs::read_to_string(trash.join("files").join(&name)).unwrap(),
            "replacement"
        );
        preview.toggle(0).unwrap();
        assert!(!preview.items[0].selected);
        let report = inspect(&trash, &[], uid, &AtomicBool::new(false));
        let mut preview = retention_preview(report, std::time::Duration::from_secs(86400)).unwrap();
        let original = preview.items[0].identity.as_ref().unwrap().name.clone();
        let mut info = original;
        info.push(".trashinfo");
        fs::write(
            trash.join("info").join(info),
            "[Trash Info]\nDeletionDate=2999-01-01T00:00:00\n",
        )
        .unwrap();
        assert!(
            preview
                .toggle(0)
                .unwrap_err()
                .to_string()
                .contains("changed")
        );
        assert!(!preview.items[0].selected);
    }

    #[test]
    fn deletion_revalidates_one_regular_file_and_preserves_other_items() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let trash = dir.path().join("trash");
        fs::create_dir_all(trash.join("files")).unwrap();
        fs::create_dir_all(trash.join("info")).unwrap();
        for path in [&trash, &trash.join("files"), &trash.join("info")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for name in ["first", "second"] {
            fs::write(trash.join("files").join(name), name).unwrap();
            fs::write(
                trash.join("info").join(format!("{name}.trashinfo")),
                "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n",
            )
            .unwrap();
            for path in [
                trash.join("files").join(name),
                trash.join("info").join(format!("{name}.trashinfo")),
            ] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let make_preview = || {
            retention_preview(
                inspect(&trash, &[], uid, &AtomicBool::new(false)),
                std::time::Duration::from_secs(86400),
            )
            .unwrap()
        };
        let mut preview = make_preview();
        preview.toggle(0).unwrap();
        let stale = preview.removal_plan().unwrap();
        fs::write(trash.join("files/first"), "changed").unwrap();
        assert!(remove_file(&stale, &stale.preview_token).is_err());
        assert_eq!(
            fs::read_to_string(trash.join("files/first")).unwrap(),
            "changed"
        );
        let mut preview = make_preview();
        preview.toggle(0).unwrap();
        preview.toggle(1).unwrap();
        assert!(preview.removal_plan().is_err());
        preview.toggle(1).unwrap();
        let plan = preview.removal_plan().unwrap();
        assert!(remove_file(&plan, "incorrect").is_err());
        assert_eq!(
            remove_file(&plan, &plan.preview_token).unwrap(),
            "verified_absent"
        );
        assert!(!trash.join("files/first").exists());
        assert!(!trash.join("info/first.trashinfo").exists());
        assert_eq!(
            fs::read_to_string(trash.join("files/second")).unwrap(),
            "second"
        );
        assert!(trash.join("info/second.trashinfo").exists());
        assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 1);
    }

    #[test]
    fn deletion_rejects_hardlinks_and_linked_ancestors() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let trash = dir.path().join("real/trash");
        fs::create_dir_all(trash.join("files")).unwrap();
        fs::create_dir_all(trash.join("info")).unwrap();
        for path in [&trash, &trash.join("files"), &trash.join("info")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(trash.join("files/item"), "keep").unwrap();
        fs::write(
            trash.join("info/item.trashinfo"),
            "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n",
        )
        .unwrap();
        fs::set_permissions(trash.join("files/item"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(
            trash.join("info/item.trashinfo"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let other = dir.path().join("other");
        fs::hard_link(trash.join("files/item"), &other).unwrap();
        let mut preview = retention_preview(
            inspect(&trash, &[], uid, &AtomicBool::new(false)),
            std::time::Duration::from_secs(86400),
        )
        .unwrap();
        preview.toggle(0).unwrap();
        assert!(preview.removal_plan().is_err());
        assert_eq!(fs::read_to_string(&other).unwrap(), "keep");
        fs::remove_file(&other).unwrap();
        let alias = dir.path().join("alias");
        symlink(dir.path().join("real"), &alias).unwrap();
        let linked = alias.join("trash");
        let mut preview = retention_preview(
            inspect(&linked, &[], uid, &AtomicBool::new(false)),
            std::time::Duration::from_secs(86400),
        )
        .unwrap();
        preview.toggle(0).unwrap();
        let plan = preview.removal_plan().unwrap();
        assert!(remove_file(&plan, &plan.preview_token).is_err());
        assert_eq!(
            fs::read_to_string(trash.join("files/item")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn selection_requires_complete_target_location_but_not_unrelated_mounts() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let trash = dir.path().join("trash");
        fs::create_dir_all(trash.join("files")).unwrap();
        fs::create_dir_all(trash.join("info")).unwrap();
        fs::write(trash.join("files/item"), "fixture").unwrap();
        fs::write(
            trash.join("info/item.trashinfo"),
            "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n",
        )
        .unwrap();
        let mut report = inspect(&trash, &[], uid, &AtomicBool::new(false));
        report.warnings.push("unrelated mount unavailable".into());
        let mut preview = retention_preview(report, std::time::Duration::from_secs(86400)).unwrap();
        assert!(!preview.complete);
        preview.toggle(0).unwrap();
        preview.toggle(0).unwrap();
        preview.items[0].location_complete = false;
        assert!(preview.toggle(0).is_err());
        assert!(trash.join("files/item").exists());
    }

    #[test]
    fn changed_metadata_during_staging_restores_item_without_deleting_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let trash = dir.path().join("trash");
        fs::create_dir_all(trash.join("files")).unwrap();
        fs::create_dir_all(trash.join("info")).unwrap();
        for path in [&trash, &trash.join("files"), &trash.join("info")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let item = trash.join("files/item");
        let info = trash.join("info/item.trashinfo");
        let backup = trash.join("info/original.saved");
        fs::write(&item, "keep").unwrap();
        fs::write(&info, "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n").unwrap();
        for path in [&item, &info] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut preview = retention_preview(
            inspect(&trash, &[], uid, &AtomicBool::new(false)),
            std::time::Duration::from_secs(86400),
        )
        .unwrap();
        preview.toggle(0).unwrap();
        let plan = preview.removal_plan().unwrap();
        let result = remove_file_after_staging(&plan, &plan.preview_token, || {
            fs::rename(&info, &backup).unwrap();
            fs::write(&info, "replacement").unwrap();
        });
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&item).unwrap(), "keep");
        assert_eq!(fs::read_to_string(&info).unwrap(), "replacement");
        assert!(backup.exists());
        assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 1);

        fs::remove_file(&info).unwrap();
        fs::rename(&backup, &info).unwrap();
        let mut preview = retention_preview(
            inspect(&trash, &[], uid, &AtomicBool::new(false)),
            std::time::Duration::from_secs(86400),
        )
        .unwrap();
        preview.toggle(0).unwrap();
        let plan = preview.removal_plan().unwrap();
        let result = remove_file_after_staging(&plan, &plan.preview_token, || {
            fs::write(&item, "new item").unwrap();
            fs::rename(&info, &backup).unwrap();
            fs::write(&info, "new metadata").unwrap();
        })
        .unwrap_err()
        .to_string();
        assert!(result.contains("inspect quarantine"));
        assert_eq!(fs::read_to_string(&item).unwrap(), "new item");
        assert_eq!(fs::read_to_string(&info).unwrap(), "new metadata");
        let quarantine = fs::read_dir(trash.join("files"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.is_dir())
            .unwrap();
        assert_eq!(fs::read_to_string(quarantine.join("item")).unwrap(), "keep");
    }

    #[test]
    fn batch_revalidates_each_item_and_preserves_unselected_or_changed_files() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        for (root, names) in [
            (&first, vec!["a", "b", "c", "unselected"]),
            (&second, vec!["other"]),
        ] {
            fs::create_dir_all(root.join("files")).unwrap();
            fs::create_dir_all(root.join("info")).unwrap();
            for path in [root.to_owned(), root.join("files"), root.join("info")] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            for name in names {
                let item = root.join("files").join(name);
                let info = root.join("info").join(format!("{name}.trashinfo"));
                fs::write(&item, name).unwrap();
                fs::write(&info, "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n").unwrap();
                for path in [&item, &info] {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
        }
        let mut report = inspect(&first, &[], uid, &AtomicBool::new(false));
        let other_report = inspect(&second, &[], uid, &AtomicBool::new(false));
        report.locations.extend(other_report.locations);
        let mut preview = retention_preview(report, std::time::Duration::from_secs(86400)).unwrap();
        for index in 0..preview.items.len() {
            if preview.items[index].name != "unselected" {
                preview.toggle(index).unwrap();
            }
        }
        let plan = preview.batch_removal_plan().unwrap();
        assert!(remove_batch(&plan, "wrong").is_err());
        assert!(first.join("files/a").exists());
        fs::write(first.join("files/b"), "changed").unwrap();
        let result = remove_batch(&plan, &plan.preview_token).unwrap();
        assert_eq!(result.outcome, "partial");
        assert_eq!(
            result
                .items
                .iter()
                .find(|item| item.name == "a")
                .unwrap()
                .status,
            "verified_absent"
        );
        assert_eq!(
            result
                .items
                .iter()
                .find(|item| item.name == "b")
                .unwrap()
                .status,
            "failed_or_skipped"
        );
        assert_eq!(
            result
                .items
                .iter()
                .find(|item| item.name == "c")
                .unwrap()
                .status,
            "failed_or_skipped"
        );
        assert_eq!(
            result
                .items
                .iter()
                .find(|item| item.name == "other")
                .unwrap()
                .status,
            "verified_absent"
        );
        assert!(!first.join("files/a").exists());
        assert_eq!(
            fs::read_to_string(first.join("files/b")).unwrap(),
            "changed"
        );
        assert_eq!(fs::read_to_string(first.join("files/c")).unwrap(), "c");
        assert_eq!(
            fs::read_to_string(first.join("files/unselected")).unwrap(),
            "unselected"
        );
        assert!(!second.join("files/other").exists());
    }

    #[test]
    fn batch_cancellation_stops_before_the_next_item() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let trash = dir.path().join("trash");
        fs::create_dir_all(trash.join("files")).unwrap();
        fs::create_dir_all(trash.join("info")).unwrap();
        for path in [&trash, &trash.join("files"), &trash.join("info")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for name in ["a", "b"] {
            let item = trash.join("files").join(name);
            let info = trash.join("info").join(format!("{name}.trashinfo"));
            fs::write(&item, name).unwrap();
            fs::write(&info, "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n").unwrap();
            for path in [&item, &info] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let mut preview = retention_preview(
            inspect(&trash, &[], uid, &AtomicBool::new(false)),
            std::time::Duration::from_secs(86400),
        )
        .unwrap();
        preview.toggle(0).unwrap();
        preview.toggle(1).unwrap();
        let plan = preview.batch_removal_plan().unwrap();
        let cancel = AtomicBool::new(false);
        let result = remove_batch_with_progress(&plan, &plan.preview_token, &cancel, |index, _| {
            if index == 1 {
                cancel.store(true, Ordering::Relaxed);
            }
        })
        .unwrap();
        assert_eq!(result.outcome, "partial");
        assert_eq!(result.items[0].status, "verified_absent");
        assert_eq!(result.items[1].status, "cancelled");
        assert!(!trash.join("files/a").exists());
        assert_eq!(fs::read_to_string(trash.join("files/b")).unwrap(), "b");
    }

    #[test]
    fn retention_selection_skips_ineligible_and_changes_nothing_on_stale_or_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let trash = dir.path().join("trash");
        fs::create_dir_all(trash.join("files/directory")).unwrap();
        fs::set_permissions(
            trash.join("files/directory"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        fs::create_dir_all(trash.join("info")).unwrap();
        for path in [&trash, &trash.join("files"), &trash.join("info")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for (name, date) in [
            ("a", Some("2000-01-01T00:00:00")),
            ("b", Some("2000-01-01T00:00:00")),
            ("hard", Some("2000-01-01T00:00:00")),
            ("future", Some("2999-01-01T00:00:00")),
            ("unknown", None),
            ("directory", Some("2000-01-01T00:00:00")),
        ] {
            let item = trash.join("files").join(name);
            if name != "directory" {
                fs::write(&item, name).unwrap();
                fs::set_permissions(&item, fs::Permissions::from_mode(0o600)).unwrap();
            }
            if let Some(date) = date {
                let info = trash.join("info").join(format!("{name}.trashinfo"));
                fs::write(&info, format!("[Trash Info]\nDeletionDate={date}\n")).unwrap();
                fs::set_permissions(info, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        fs::hard_link(trash.join("files/hard"), dir.path().join("linked")).unwrap();
        let make_preview = || {
            retention_preview(
                inspect(&trash, &[], uid, &AtomicBool::new(false)),
                std::time::Duration::from_secs(86400),
            )
            .unwrap()
        };
        let mut preview = make_preview();
        assert!(
            preview
                .select_old_files(&trash, &AtomicBool::new(true))
                .is_err()
        );
        assert!(preview.items.iter().all(|item| !item.selected));
        fs::write(trash.join("files/b"), "changed").unwrap();
        assert!(
            preview
                .select_old_files(&trash, &AtomicBool::new(false))
                .is_err()
        );
        assert!(preview.items.iter().all(|item| !item.selected));
        let mut preview = make_preview();
        let selection = preview
            .select_old_files(&trash, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(
            (
                selection.eligible,
                selection.newer_or_unknown,
                selection.unsupported
            ),
            (2, 2, 2)
        );
        assert_eq!(
            preview
                .items
                .iter()
                .filter(|item| item.selected)
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(trash.join("files/a").exists());
    }

    #[test]
    fn retention_selection_refuses_over_limit_without_marking_anything() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let trash = dir.path().join("trash");
        fs::create_dir_all(trash.join("files")).unwrap();
        fs::create_dir_all(trash.join("info")).unwrap();
        for path in [&trash, &trash.join("files"), &trash.join("info")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for index in 0..101 {
            let item = trash.join("files").join(format!("{index:03}"));
            let info = trash.join("info").join(format!("{index:03}.trashinfo"));
            fs::write(&item, "fixture").unwrap();
            fs::write(&info, "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n").unwrap();
            for path in [&item, &info] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let mut preview = retention_preview(
            inspect(&trash, &[], uid, &AtomicBool::new(false)),
            std::time::Duration::from_secs(86400),
        )
        .unwrap();
        assert!(
            preview
                .select_old_files(&trash, &AtomicBool::new(false))
                .unwrap_err()
                .to_string()
                .contains("100")
        );
        assert!(preview.items.iter().all(|item| !item.selected));
    }

    #[test]
    fn retention_selection_stays_within_the_chosen_location() {
        let dir = tempfile::tempdir().unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        for root in [&first, &second] {
            fs::create_dir_all(root.join("files")).unwrap();
            fs::create_dir_all(root.join("info")).unwrap();
            for path in [root.to_owned(), root.join("files"), root.join("info")] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let item = root.join("files/item");
            let info = root.join("info/item.trashinfo");
            fs::write(&item, "fixture").unwrap();
            fs::write(&info, "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n").unwrap();
            for path in [&item, &info] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let mut report = inspect(&first, &[], uid, &AtomicBool::new(false));
        report
            .locations
            .extend(inspect(&second, &[], uid, &AtomicBool::new(false)).locations);
        let mut preview = retention_preview(report, std::time::Duration::from_secs(86400)).unwrap();
        let summary = preview
            .select_old_files(&first, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(summary.eligible, 1);
        assert!(
            preview
                .items
                .iter()
                .find(|item| item.location == first)
                .unwrap()
                .selected
        );
        assert!(
            !preview
                .items
                .iter()
                .find(|item| item.location == second)
                .unwrap()
                .selected
        );
        assert!(first.join("files/item").exists() && second.join("files/item").exists());
    }

    #[test]
    fn displayed_item_names_escape_control_bytes_and_percent_without_collisions() {
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(
            display_item_name(&std::ffi::OsString::from_vec(vec![0xff])),
            "%FF"
        );
        assert_eq!(display_item_name(std::ffi::OsStr::new("%FF")), "%25FF");
        assert_eq!(
            display_item_name(std::ffi::OsStr::new("a\n\u{1b}")),
            "a%0A%1B"
        );
    }
}

#[cfg(test)]
mod windows_recycle_bin_tests {
    use super::*;

    #[test]
    fn windows_recycle_bin_summary_parser_distinguishes_complete_partial_and_unknown_sizes() {
        assert_eq!(
            parse_windows_recycle_bin_summary(b"42\t1234\t1\r\n").unwrap(),
            WindowsRecycleBinSummary {
                item_count: 42,
                logical_bytes: Some(1234),
                size_complete: true,
            }
        );
        assert_eq!(
            parse_windows_recycle_bin_summary(b"42\t1234\t0\n").unwrap(),
            WindowsRecycleBinSummary {
                item_count: 42,
                logical_bytes: Some(1234),
                size_complete: false,
            }
        );
        assert_eq!(
            parse_windows_recycle_bin_summary(b"42\t-\t0\n").unwrap(),
            WindowsRecycleBinSummary {
                item_count: 42,
                logical_bytes: None,
                size_complete: false,
            }
        );
        for invalid in [
            b"42 items\n".as_slice(),
            b"42\t1,234\t1\n",
            b"42\t-\t1\n",
            b"42\t1234\t2\n",
            b"42\t1234\t0\textra\n",
            b"",
        ] {
            assert!(parse_windows_recycle_bin_summary(invalid).is_err());
        }
    }

    #[test]
    fn windows_recycle_bin_powershell_resolution_uses_a_synthetic_system_directory() {
        let dir = tempfile::tempdir().unwrap();
        let fixture_root = dir.path().canonicalize().unwrap();
        let system = fixture_root.join("synthetic-system");
        let executable = system
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, b"synthetic executable").unwrap();

        let resolved = windows_powershell_executable(&system).unwrap();
        assert_eq!(resolved, executable.canonicalize().unwrap());
        assert!(windows_paths_within(
            &system.canonicalize().unwrap(),
            &resolved
        ));
        assert!(windows_powershell_executable(Path::new("relative-system")).is_err());

        let not_a_directory = fixture_root.join("not-a-directory");
        std::fs::write(&not_a_directory, b"fixture").unwrap();
        assert!(windows_powershell_executable(&not_a_directory).is_err());
        assert!(windows_powershell_executable(&fixture_root.join("missing-system")).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_recycle_bin_powershell_resolution_walks_absolute_prefix_and_root() {
        let dir = tempfile::tempdir().unwrap();
        let fixture_root = dir.path().canonicalize().unwrap();
        let system = fixture_root.join("synthetic-system");
        let executable = system
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, b"synthetic executable").unwrap();

        assert!(system.is_absolute());
        let mut components = system.components();
        assert!(matches!(
            components.next(),
            Some(std::path::Component::Prefix(_))
        ));
        assert!(matches!(
            components.next(),
            Some(std::path::Component::RootDir)
        ));
        assert!(windows_powershell_executable(&system).is_ok());
    }

    #[test]
    fn windows_recycle_bin_report_serializes_partial_size_as_incomplete() {
        let report = windows_recycle_bin_report(
            Ok(WindowsRecycleBinSummary {
                item_count: 17,
                logical_bytes: Some(1536),
                size_complete: false,
            }),
            false,
        );
        let location = &report.locations[0];
        assert!(location.path.as_os_str().is_empty());
        assert_eq!(location.item_count, Some(17));
        assert_eq!(location.logical_bytes, Some(1536));
        assert_eq!(location.allocated_bytes, None);
        assert!(!location.size_complete);
        assert!(location.items.is_empty());
        assert!(!location.items_complete);
        assert!(location.warnings[0].contains("deletion dates are unknown"));
        assert!(location.warnings[0].contains("partial sum"));

        let json = serde_json::to_value(&report).unwrap();
        assert!(json["locations"][0]["path"].is_null());
        assert_eq!(json["locations"][0]["item_count"], 17);
        assert_eq!(json["locations"][0]["logical_bytes"], 1536);
        assert_eq!(json["locations"][0]["size_complete"], false);
        assert_eq!(json["locations"][0]["items"], serde_json::json!([]));
    }

    #[test]
    fn windows_recycle_bin_report_keeps_an_unrepresentable_size_unknown() {
        let report = windows_recycle_bin_report(
            Ok(WindowsRecycleBinSummary {
                item_count: 17,
                logical_bytes: None,
                size_complete: false,
            }),
            false,
        );
        assert_eq!(report.locations[0].logical_bytes, None);
        assert!(!report.locations[0].size_complete);
        assert!(report.locations[0].warnings[0].contains("size is unavailable"));
    }

    #[test]
    fn windows_recycle_bin_failure_or_cancellation_does_not_report_zero_items() {
        let failed = windows_recycle_bin_report(Err(anyhow::anyhow!("fixture failure")), false);
        assert!(failed.locations.is_empty());
        assert!(failed.warnings[0].contains("inventory unavailable"));

        let cancelled = windows_recycle_bin_report(
            Ok(WindowsRecycleBinSummary {
                item_count: 17,
                logical_bytes: Some(0),
                size_complete: true,
            }),
            true,
        );
        assert!(cancelled.cancelled);
        assert!(cancelled.locations.is_empty());
        assert!(cancelled.warnings[0].contains("cancelled"));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod scheduled_trash_identity_tests {
    use super::*;

    #[test]
    fn mountinfo_uses_the_statx_mount_id_when_mount_points_are_stacked() {
        let mountinfo = concat!(
            "40 1 8:1 /root-a /mnt rw - ext4 /dev/fixture-a rw\n",
            "41 1 8:1 /root-b /mnt rw - ext4 /dev/fixture-b rw\n",
        );
        let first = stable_mount_identity_from(Path::new("/mnt/Trash"), mountinfo, 40).unwrap();
        let second = stable_mount_identity_from(Path::new("/mnt/Trash"), mountinfo, 41).unwrap();
        assert_ne!(first, second);
        assert!(stable_mount_identity_from(Path::new("/mnt/Trash"), mountinfo, 42).is_err());
    }

    #[test]
    fn mountinfo_decoder_rejects_out_of_range_octal_escapes() {
        assert_eq!(decode_mountinfo_field("/mnt/a\\040b").unwrap(), "/mnt/a b");
        assert!(decode_mountinfo_field("/mnt/\\777").is_err());
    }

    #[test]
    fn scheduled_scope_requires_mount_ids_but_manual_can_keep_missing_ids() {
        assert!(scheduled_mount_ids_match(&[Some(9); 5], 9));
        assert!(!scheduled_mount_ids_match(&[None; 5], 9));
        assert!(!scheduled_mount_ids_match(
            &[Some(8), Some(9), Some(9), Some(9), Some(9)],
            9
        ));
        assert!(manual_mount_ids_unchanged(&[None; 5], &[None; 5]));
        assert!(manual_mount_ids_unchanged(&[None; 5], &[Some(9); 5]));
        assert!(!manual_mount_ids_unchanged(&[Some(9); 5], &[None; 5]));
        assert!(!manual_mount_ids_unchanged(&[Some(9); 5], &[Some(10); 5]));
    }

    #[test]
    fn scheduled_clock_guard_rejects_only_backwards_time() {
        assert!(validate_scheduled_clock(100, 101).is_ok());
        assert!(validate_scheduled_clock(100, 100).is_ok());
        assert!(validate_scheduled_clock(100, 99).is_err());
    }
}
