//! Preview and revalidate an explicitly selected managed toolchain cleanup.
#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{Result, bail};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use crate::{Ctx, ToolKind};

fn serialize_path<S: serde::Serializer>(
    path: &Path,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    crate::sweep::JsonPath(path).serialize(serializer)
}

fn serialize_paths<S: serde::Serializer>(
    paths: &[PathBuf],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.collect_seq(paths.iter().map(|path| crate::sweep::JsonPath(path)))
}

#[cfg(target_os = "linux")]
fn serialize_optional_path<S: serde::Serializer>(
    path: &Option<PathBuf>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    path.as_deref()
        .map(crate::sweep::JsonPath)
        .serialize(serializer)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct Identity {
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
fn identity(meta: &std::fs::Metadata) -> Identity {
    use std::os::unix::fs::MetadataExt;
    Identity {
        dev: meta.dev(),
        ino: meta.ino(),
        uid: meta.uid(),
        mode: meta.mode(),
        links: meta.nlink(),
        size: meta.len(),
        mtime: meta.mtime(),
        mtime_ns: meta.mtime_nsec(),
        ctime: meta.ctime(),
        ctime_ns: meta.ctime_nsec(),
    }
}

#[cfg(target_os = "linux")]
fn identity_from_link(link: &crate::installation_identity::LinkIdentity) -> Identity {
    Identity {
        dev: link.device,
        ino: link.file,
        uid: link.owner,
        mode: link.mode,
        links: link.links,
        size: link.size,
        mtime: link.mtime,
        mtime_ns: link.mtime_ns,
        ctime: link.ctime,
        ctime_ns: link.ctime_ns,
    }
}

#[cfg(target_os = "linux")]
fn is_directory(identity: &Identity) -> bool {
    identity.mode & 0o170000 == 0o040000
}

#[cfg(target_os = "linux")]
fn same_moved(expected: &Identity, actual: &Identity) -> bool {
    expected.dev == actual.dev
        && expected.ino == actual.ino
        && expected.uid == actual.uid
        && expected.mode == actual.mode
        && expected.links == actual.links
        && expected.size == actual.size
        && expected.mtime == actual.mtime
        && expected.mtime_ns == actual.mtime_ns
}

#[cfg(target_os = "linux")]
fn same_directory(expected: &Identity, actual: &Identity) -> bool {
    expected.dev == actual.dev
        && expected.ino == actual.ino
        && expected.uid == actual.uid
        && expected.mode == actual.mode
}

#[cfg(target_os = "linux")]
fn directory_anchor(identity: &Identity) -> (u64, u64, u32, u32) {
    // Removing one reviewed tool changes its parent timestamps during a batch.
    (identity.dev, identity.ino, identity.uid, identity.mode)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct Entry {
    #[serde(serialize_with = "serialize_path")]
    path: PathBuf,
    identity: Identity,
    #[serde(serialize_with = "serialize_optional_path")]
    link_target: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct SealedEntry {
    #[serde(serialize_with = "serialize_path")]
    path: PathBuf,
    identity: Identity,
    seal: crate::installation_identity::Seal,
}

#[cfg(target_os = "linux")]
fn root_snapshot(root: &Path, cancel: &AtomicBool) -> Result<(Vec<Entry>, String)> {
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::ffi::OsStrExt, sync::atomic::Ordering};
    let mut entries = Vec::new();
    for entry in fs::read_dir(root).context("list tool root")? {
        if cancel.load(Ordering::Relaxed) {
            bail!("toolchain preview cancelled");
        }
        if entries.len() >= 256 {
            bail!("tool root contains more than 256 top-level entries");
        }
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        let target = metadata
            .file_type()
            .is_symlink()
            .then(|| fs::read_link(&path))
            .transpose()?;
        entries.push(Entry {
            path,
            identity: identity(&metadata),
            link_target: target,
        });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let mut digest = Sha256::new();
    digest.update(b"upkit-managed-root-v3");
    for entry in &entries {
        for value in [
            entry
                .path
                .file_name()
                .map_or(&[][..], |name| name.as_bytes()),
            &serde_json::to_vec(&entry.identity)?,
            entry
                .link_target
                .as_deref()
                .map_or(&[][..], |path| path.as_os_str().as_bytes()),
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
    }
    Ok((entries, hex::encode(digest.finalize())))
}

#[cfg(all(target_os = "linux", test))]
fn remove_quarantined_tree(parent: &std::fs::File) -> Result<()> {
    remove_quarantined_entry(parent, std::ffi::OsStr::new("root"))
}

#[cfg(target_os = "linux")]
fn remove_quarantined_entry(parent: &std::fs::File, name: &std::ffi::OsStr) -> Result<()> {
    use rustix::fs::{AtFlags, Dir, Mode, OFlags, ResolveFlags, openat2, unlinkat};
    use std::{
        ffi::{OsStr, OsString},
        fs,
        os::unix::ffi::OsStringExt,
    };

    fn open(parent: &fs::File, name: &OsStr, flags: OFlags) -> Result<fs::File> {
        Ok(fs::File::from(openat2(
            parent,
            name,
            flags | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?))
    }
    fn directory(parent: &fs::File, name: &OsStr) -> Result<fs::File> {
        open(parent, name, OFlags::RDONLY | OFlags::DIRECTORY)
    }
    let root = directory(parent, name).context("open quarantined tool entry")?;
    let reader = Dir::read_from(&root)?;
    let mut stack = vec![(root, name.to_os_string(), reader)];
    let mut count = 0usize;
    while !stack.is_empty() {
        let entry = stack.last_mut().expect("nonempty stack").2.next();
        if let Some(entry) = entry {
            let entry = entry?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            count += 1;
            if count > 1_000_000 || stack.len() > 256 {
                bail!("tool root exceeds safe removal limits");
            }
            let name = OsString::from_vec(bytes.to_vec());
            let current = &stack.last().expect("nonempty stack").0;
            let descriptor = open(current, &name, OFlags::PATH | OFlags::NOFOLLOW)
                .context("inspect quarantined entry")?;
            let metadata = descriptor.metadata()?;
            if metadata.is_dir() {
                let child =
                    directory(current, &name).context("open quarantined child directory")?;
                if identity(&child.metadata()?) != identity(&metadata) {
                    bail!("quarantined directory changed");
                }
                let reader = Dir::read_from(&child)?;
                stack.push((child, name, reader));
            } else if metadata.is_file() || metadata.file_type().is_symlink() {
                let check = open(current, &name, OFlags::PATH | OFlags::NOFOLLOW)?;
                if identity(&check.metadata()?) != identity(&metadata) {
                    bail!("quarantined entry changed");
                }
                unlinkat(current, name.as_os_str(), AtFlags::empty())
                    .context("remove quarantined entry")?;
            } else {
                bail!("quarantined root contains a special file");
            }
        } else {
            let (finished, name, _) = stack.pop().expect("nonempty stack");
            let container = stack.last().map_or(parent, |frame| &frame.0);
            let check = directory(container, &name).context("recheck quarantined directory")?;
            if !same_directory(
                &identity(&finished.metadata()?),
                &identity(&check.metadata()?),
            ) {
                bail!("quarantined directory was replaced");
            }
            unlinkat(container, name.as_os_str(), AtFlags::REMOVEDIR)
                .context("remove quarantined directory")?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
pub struct CleanupPlan {
    pub tool: &'static str,
    #[serde(serialize_with = "serialize_path")]
    pub root: PathBuf,
    pub root_present: bool,
    #[serde(serialize_with = "serialize_paths")]
    pub entries: Vec<PathBuf>,
    #[serde(serialize_with = "serialize_paths")]
    pub selected_entries: Vec<PathBuf>,
    #[serde(serialize_with = "serialize_paths")]
    pub preserved_entries: Vec<PathBuf>,
    #[serde(serialize_with = "serialize_paths")]
    pub links: Vec<PathBuf>,
    #[serde(serialize_with = "serialize_paths")]
    pub preserved_links: Vec<PathBuf>,
    pub logical_bytes: u64,
    pub activity_status: &'static str,
    pub installation_status: &'static str,
    pub writable_by_others: bool,
    pub warning: &'static str,
    pub preview_token: String,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    kind: ToolKind,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    root_identity: Option<Identity>,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    home_identity: Identity,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    bindir_identity: Option<Identity>,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    link_entries: Vec<crate::installation_identity::RecordedLink>,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    root_entries: Vec<Entry>,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    sealed_entries: Vec<SealedEntry>,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    activity_statuses: Vec<&'static str>,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    tree_digest: String,
}

/// Inspect sealed installations and Upkit-recorded links; unverified data remains visible.
pub fn preview(ctx: &Ctx, tool: ToolKind, cancel: &AtomicBool) -> Result<CleanupPlan> {
    preview_including_absent(ctx, tool, cancel)
}

#[cfg(target_os = "linux")]
pub(crate) fn preview_including_absent(
    ctx: &Ctx,
    tool: ToolKind,
    cancel: &AtomicBool,
) -> Result<CleanupPlan> {
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::fs::MetadataExt, sync::atomic::Ordering};
    if cancel.load(Ordering::Relaxed) {
        bail!("toolchain preview cancelled");
    }
    if !ctx.home.is_absolute()
        || ctx.home.canonicalize().context("resolve managed home")? != ctx.home
        || ctx.home.parent().is_none()
    {
        bail!("managed home must be absolute, canonical, and not a filesystem root");
    }
    if dirs::home_dir()
        .and_then(|path| path.canonicalize().ok())
        .as_deref()
        == Some(ctx.home.as_path())
    {
        bail!("refusing to clean directly under the user home");
    }
    let home_meta = fs::symlink_metadata(&ctx.home)?;
    let uid = rustix::process::geteuid().as_raw();
    if !home_meta.is_dir() || home_meta.file_type().is_symlink() || home_meta.uid() != uid {
        bail!("managed home must be a user-owned directory");
    }
    let root = ctx.home.join(tool.as_str());
    let root_meta = match fs::symlink_metadata(&root) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() && meta.uid() == uid => {
            Some(meta)
        }
        Ok(_) => bail!("tool root must be a user-owned, non-linked directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("inspect tool root"),
    };
    let mounts = crate::application::mount_points(
        &fs::read("/proc/self/mountinfo").context("read mount table")?,
    )?;
    if mounts.iter().any(|mount| mount.starts_with(&root)) {
        bail!("tool root contains a mount point");
    }
    if let Some(meta) = &root_meta
        && (meta.dev() != home_meta.dev() || root.canonicalize()? != root)
    {
        bail!("tool root crosses a filesystem boundary or contains a link");
    }
    let (root_entries, tree_digest) = if root_meta.is_some() {
        root_snapshot(&root, cancel)?
    } else {
        (Vec::new(), String::new())
    };
    let entries = root_entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    let mut sealed_entries = Vec::new();
    if root_meta.is_some() {
        for entry in &root_entries {
            if cancel.load(Ordering::Relaxed) {
                bail!("toolchain preview cancelled");
            }
            if !is_directory(&entry.identity) {
                continue;
            }
            let Some(name) = entry.path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !name.starts_with("install-") {
                continue;
            }
            match crate::installation_identity::inspect_with_cancel(
                &root,
                &entry.path,
                tool,
                cancel,
            ) {
                Ok(seal) => sealed_entries.push(SealedEntry {
                    path: entry.path.clone(),
                    identity: entry.identity.clone(),
                    seal,
                }),
                Err(error) if cancel.load(Ordering::Relaxed) => {
                    return Err(error).context("verify tool installation seal");
                }
                Err(_) => {}
            }
        }
    }
    let installation_status = if root_meta.is_none() {
        "absent"
    } else if sealed_entries.is_empty() {
        "unverified_data_preserved"
    } else {
        "sealed_installations_verified"
    };
    let bindir_meta = match fs::symlink_metadata(&ctx.bindir) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() && meta.uid() == uid => {
            if !ctx.bindir.is_absolute()
                || ctx.bindir.canonicalize()? != ctx.bindir
                || ctx.bindir.starts_with(&root)
            {
                bail!("binary directory must be canonical and outside the tool root");
            }
            Some(meta)
        }
        Ok(_) => bail!("binary directory must be a user-owned, non-linked directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("inspect binary directory"),
    };
    let recorded_links = if root_meta.is_some() {
        crate::installation_identity::recorded_links(&root, &ctx.bindir, tool)?
    } else {
        Vec::new()
    };
    let sealed_paths = sealed_entries
        .iter()
        .map(|entry| entry.path.as_path())
        .collect::<Vec<_>>();
    let active_link = recorded_links.iter().find(|link| {
        link.role == crate::installation_identity::LinkRole::Active
            && sealed_paths
                .iter()
                .any(|path| link.target.starts_with(path))
    });
    let links = recorded_links
        .iter()
        .filter(|link| match link.role {
            crate::installation_identity::LinkRole::Active => {
                active_link.is_some_and(|active| active.path == link.path)
            }
            crate::installation_identity::LinkRole::Binary => {
                sealed_paths
                    .iter()
                    .any(|path| link.target.starts_with(path))
                    || active_link.is_some_and(|active| {
                        (link.target.starts_with(root.join("active"))
                            || (tool == ToolKind::Go
                                && link.path.file_name().is_some_and(|name| {
                                    link.target == root.join("wrappers").join(name)
                                })))
                            && active.target.starts_with(&root)
                    })
            }
        })
        .cloned()
        .collect::<Vec<_>>();
    let selected_entries = sealed_entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    if root_meta.is_some() && !sealed_entries.is_empty() {
        for name in std::iter::once("active").chain(crate::tool_bin_names(tool).iter().copied()) {
            let path = if name == "active" {
                root.join(name)
            } else {
                ctx.bindir.join(name)
            };
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() => metadata,
                Ok(_) => continue,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error).context("inspect links to managed installations"),
            };
            let target = fs::read_link(&path).context("read link to managed installation")?;
            if links.iter().any(|link| {
                link.path == path
                    && link.target == target
                    && identity_from_link(&link.identity) == identity(&metadata)
            }) {
                continue;
            }
            let resolved = path
                .parent()
                .unwrap_or(Path::new("/"))
                .join(&target)
                .canonicalize()
                .context("resolve link to managed installation")?;
            if sealed_paths
                .iter()
                .any(|sealed| resolved.starts_with(sealed))
                || (tool == ToolKind::Go
                    && active_link.is_some()
                    && ["go", "gofmt"]
                        .iter()
                        .any(|name| resolved == root.join("wrappers").join(name)))
            {
                bail!(
                    "unrecorded link {} refers to a selected installation or its Go wrapper; cleanup is refused to avoid leaving it unusable",
                    crate::sweep::display_path(&path)
                );
            }
        }
    }
    let selected_links = links
        .iter()
        .map(|link| link.path.clone())
        .collect::<Vec<_>>();
    let preserved_entries = entries
        .iter()
        .filter(|path| !selected_entries.contains(path) && !selected_links.contains(path))
        .cloned()
        .collect::<Vec<_>>();
    let mut preserved_links = Vec::new();
    if bindir_meta.is_some() {
        for name in crate::tool_bin_names(tool) {
            let path = ctx.bindir.join(name);
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_symlink() && !selected_links.contains(&path) => {
                    preserved_links.push(path)
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect tool link"),
            }
        }
    }
    let logical_bytes = sealed_entries.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(entry.seal.logical_bytes)
            .context("tool size overflow")
    })?;
    let activity_statuses = crate::activity::inspect(
        &sealed_entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>(),
        cancel,
    );
    let activity_status = if activity_statuses.is_empty() {
        "not_applicable"
    } else if let Some(status) = activity_statuses.iter().find(|status| {
        matches!(
            **status,
            "open_handles_or_cwd_observed" | "executable_observed"
        )
    }) {
        status
    } else if activity_statuses
        .iter()
        .any(|status| matches!(*status, "inspection_incomplete" | "unavailable"))
    {
        "inspection_incomplete"
    } else {
        "no_open_handles_or_cwd_observed"
    };
    let writable_by_others = home_meta.mode() & 0o022 != 0
        || root_meta
            .as_ref()
            .is_some_and(|meta| meta.mode() & 0o022 != 0)
        || bindir_meta
            .as_ref()
            .is_some_and(|meta| meta.mode() & 0o022 != 0);
    if cancel.load(Ordering::Relaxed) {
        bail!("toolchain preview cancelled");
    }
    let unchanged = |path: &Path, expected: Option<&std::fs::Metadata>| -> Result<bool> {
        match (std::fs::symlink_metadata(path), expected) {
            (Ok(actual), Some(expected)) => Ok(identity(&actual) == identity(expected)),
            (Err(error), None) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            (Err(error), _) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(false),
        }
    };
    if !unchanged(&ctx.home, Some(&home_meta))?
        || !unchanged(&root, root_meta.as_ref())?
        || !unchanged(&ctx.bindir, bindir_meta.as_ref())?
    {
        bail!("managed paths changed during preview");
    }
    let (final_root_entries, final_tree_digest) = if root_meta.is_some() {
        root_snapshot(&root, cancel)?
    } else {
        (Vec::new(), String::new())
    };
    if final_tree_digest != tree_digest || final_root_entries.len() != root_entries.len() {
        bail!("tool root changed during preview");
    }
    for (entry, final_entry) in root_entries.iter().zip(&final_root_entries) {
        if entry.path != final_entry.path
            || entry.identity != final_entry.identity
            || entry.link_target != final_entry.link_target
        {
            bail!("tool root changed during preview");
        }
    }
    let final_links = if root_meta.is_some() {
        crate::installation_identity::recorded_links(&root, &ctx.bindir, tool)?
    } else {
        Vec::new()
    };
    if final_links != recorded_links {
        bail!("recorded tool links changed during preview");
    }
    for entry in &sealed_entries {
        if crate::installation_identity::inspect_with_cancel(&root, &entry.path, tool, cancel)?
            != entry.seal
        {
            bail!("sealed tool installation changed during preview");
        }
    }
    for link in &links {
        let metadata = fs::symlink_metadata(&link.path).context("recheck preview link")?;
        let target = fs::read_link(&link.path)?;
        if identity(&metadata) != identity_from_link(&link.identity) || target != link.target {
            bail!("tool root or link changed during preview");
        }
    }
    let boot = fs::read("/proc/sys/kernel/random/boot_id").context("read boot identity")?;
    let mut hash = Sha256::new();
    for value in [
        b"upkit-managed-clean-v3".as_slice(),
        &boot,
        tool.as_str().as_bytes(),
        &serde_json::to_vec(&crate::sweep::JsonPath(&ctx.home))?,
        &serde_json::to_vec(&crate::sweep::JsonPath(&ctx.bindir))?,
        &serde_json::to_vec(&directory_anchor(&identity(&home_meta)))?,
        &serde_json::to_vec(&root_meta.as_ref().map(identity))?,
        &serde_json::to_vec(
            &bindir_meta
                .as_ref()
                .map(|meta| directory_anchor(&identity(meta))),
        )?,
        &serde_json::to_vec(&root_entries)?,
        &serde_json::to_vec(&sealed_entries)?,
        &serde_json::to_vec(&links)?,
        &serde_json::to_vec(&preserved_links)?,
        &logical_bytes.to_be_bytes(),
        tree_digest.as_bytes(),
        activity_status.as_bytes(),
        installation_status.as_bytes(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    Ok(CleanupPlan {
        tool: tool.as_str(),
        root,
        root_present: root_meta.is_some(),
        entries,
        selected_entries,
        preserved_entries,
        links: links.iter().map(|entry| entry.path.clone()).collect(),
        preserved_links,
        logical_bytes,
        activity_status,
        installation_status,
        writable_by_others,
        warning: "Permanently removes only listed hash-verified Upkit installations and receipt-matched links. Unverified root entries and unrecorded links are preserved. Shell PATH entries remain. Process and mount checks are snapshots and can race; interruption can leave private quarantine directories.",
        preview_token: hex::encode(hash.finalize()),
        kind: tool,
        root_identity: root_meta.as_ref().map(identity),
        home_identity: identity(&home_meta),
        bindir_identity: bindir_meta.as_ref().map(identity),
        link_entries: links,
        root_entries,
        sealed_entries,
        activity_statuses,
        tree_digest,
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn preview_including_absent(
    _: &Ctx,
    _: ToolKind,
    _: &AtomicBool,
) -> Result<CleanupPlan> {
    bail!("managed tool cleanup preview is supported only on Linux")
}

/// Remove the reviewed managed root and links after revalidation.
/// The caller must present the plan and obtain explicit confirmation first.
#[cfg(target_os = "linux")]
pub fn remove(ctx: &Ctx, plan: &CleanupPlan, cancel: &AtomicBool) -> Result<&'static str> {
    remove_with_hook(ctx, plan, cancel, |_| {})
}

#[cfg(target_os = "linux")]
fn remove_with_hook(
    ctx: &Ctx,
    plan: &CleanupPlan,
    cancel: &AtomicBool,
    after_staging: impl FnOnce(&Path),
) -> Result<&'static str> {
    use rustix::fs::{
        AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, mkdirat, openat2, readlinkat,
        renameat_with, unlinkat,
    };
    use std::{
        ffi::{OsStr, OsString},
        fs,
        os::unix::ffi::OsStrExt,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    if ctx.dry_run {
        bail!("dry-run mode does not execute managed cleanup");
    }
    let fresh = preview(ctx, plan.kind, cancel)?;
    if fresh.preview_token != plan.preview_token
        || fresh.root != plan.root
        || fresh.entries != plan.entries
        || fresh.selected_entries != plan.selected_entries
        || fresh.preserved_entries != plan.preserved_entries
        || fresh.links != plan.links
        || fresh.preserved_links != plan.preserved_links
        || fresh.tool != plan.tool
        || fresh.root_present != plan.root_present
        || fresh.logical_bytes != plan.logical_bytes
        || fresh.activity_status != plan.activity_status
        || fresh.installation_status != plan.installation_status
        || fresh.writable_by_others != plan.writable_by_others
        || fresh.warning != plan.warning
        || fresh.root_identity != plan.root_identity
        || directory_anchor(&fresh.home_identity) != directory_anchor(&plan.home_identity)
        || fresh.bindir_identity.as_ref().map(directory_anchor)
            != plan.bindir_identity.as_ref().map(directory_anchor)
        || fresh.link_entries != plan.link_entries
        || fresh.root_entries != plan.root_entries
        || fresh.sealed_entries != plan.sealed_entries
        || fresh.activity_statuses != plan.activity_statuses
        || fresh.tree_digest != plan.tree_digest
    {
        bail!("managed cleanup plan changed; review it again");
    }
    if fresh.selected_entries.is_empty() && fresh.link_entries.is_empty() {
        bail!(
            "no sealed Upkit installation or recorded link is eligible; unverified data was preserved"
        );
    }
    if matches!(
        fresh.activity_status,
        "open_handles_or_cwd_observed" | "executable_observed"
    ) {
        bail!("a process is using a selected installation; stop it before cleaning");
    }
    if !fresh.links.is_empty()
        && fresh
            .bindir_identity
            .as_ref()
            .is_some_and(|directory| directory.mode & 0o200 == 0)
    {
        bail!("binary directory is not owner-writable; no paths were removed");
    }
    if cancel.load(Ordering::Relaxed) {
        bail!("managed cleanup cancelled");
    }

    fn open_dir(path: &Path) -> Result<fs::File> {
        Ok(fs::File::from(openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?))
    }
    fn child_dir(parent: &fs::File, name: &OsStr) -> Result<fs::File> {
        Ok(fs::File::from(openat2(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?))
    }
    fn private_dir(parent: &fs::File, base: &Path) -> Result<(fs::File, OsString, PathBuf)> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _ in 0..32 {
            let name = OsString::from(format!(
                ".upkit-clean-{}-{stamp}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match mkdirat(
                parent,
                name.as_os_str(),
                Mode::RUSR | Mode::WUSR | Mode::XUSR,
            ) {
                Ok(()) => match child_dir(parent, name.as_os_str()) {
                    Ok(dir) => {
                        let metadata = dir.metadata()?;
                        use std::os::unix::fs::MetadataExt;
                        if metadata.uid() != rustix::process::geteuid().as_raw()
                            || metadata.mode() & 0o077 != 0
                        {
                            bail!(
                                "private cleanup directory is not user-owned and private; inspect {}",
                                crate::sweep::display_path(&base.join(name))
                            );
                        }
                        return Ok((dir, name.clone(), base.join(name)));
                    }
                    Err(error) => bail!(
                        "open private cleanup directory: {error:#}; inspect {}",
                        crate::sweep::display_path(&base.join(name))
                    ),
                },
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(error).context("create private cleanup directory"),
            }
        }
        bail!("could not allocate private cleanup directory")
    }
    fn remove_private(parent: &fs::File, name: &OsStr, directory: &fs::File) -> Result<()> {
        let current = child_dir(parent, name)?;
        if !same_directory(
            &identity(&current.metadata()?),
            &identity(&directory.metadata()?),
        ) {
            bail!("private cleanup directory changed");
        }
        unlinkat(parent, name, AtFlags::REMOVEDIR).context("remove private cleanup directory")?;
        Ok(())
    }
    fn directory_is_named(path: &Path, expected: &Identity) -> Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => Ok(same_directory(expected, &identity(&metadata))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    fn named_entry_identity(parent: &fs::File, name: &OsStr) -> Result<Option<Identity>> {
        match openat2(
            parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        ) {
            Ok(entry) => Ok(Some(identity(&fs::File::from(entry).metadata()?))),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    fn verify_link_at(
        parent: &fs::File,
        name: &OsStr,
        link: &crate::installation_identity::RecordedLink,
    ) -> Result<()> {
        let staged = fs::File::from(openat2(
            parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?);
        let current = identity(&staged.metadata()?);
        let target = readlinkat(&staged, "", Vec::new())?.into_bytes();
        if !same_moved(&identity_from_link(&link.identity), &current)
            || link.target.as_os_str().as_bytes() != target
        {
            bail!("recorded tool link changed after preview");
        }
        Ok(())
    }

    #[derive(Clone)]
    struct StagedInstall {
        source: OsString,
        stage: String,
        entry: SealedEntry,
    }
    #[derive(Clone)]
    struct StagedLink {
        source: OsString,
        stage: String,
        entry: crate::installation_identity::RecordedLink,
    }

    let home = open_dir(&ctx.home).context("open managed home")?;
    if identity(&home.metadata()?) != fresh.home_identity {
        bail!("managed home changed after preview");
    }
    let tool_name = OsStr::new(plan.kind.as_str());
    let root_dir = if let Some(expected) = &fresh.root_identity {
        let directory = child_dir(&home, tool_name).context("open tool root")?;
        if identity(&directory.metadata()?) != *expected {
            bail!("tool root changed after preview");
        }
        Some(directory)
    } else {
        None
    };
    let binary_links = fresh
        .link_entries
        .iter()
        .filter(|link| link.role == crate::installation_identity::LinkRole::Binary)
        .cloned()
        .collect::<Vec<_>>();
    let bindir = if binary_links.is_empty() {
        None
    } else {
        let directory = open_dir(&ctx.bindir).context("open binary directory")?;
        if identity(&directory.metadata()?)
            != *fresh
                .bindir_identity
                .as_ref()
                .context("missing binary directory identity")?
        {
            bail!("binary directory changed after preview");
        }
        Some(directory)
    };
    let needs_root_quarantine = !fresh.sealed_entries.is_empty()
        || fresh
            .link_entries
            .iter()
            .any(|link| link.role == crate::installation_identity::LinkRole::Active);
    let private_root = if needs_root_quarantine {
        Some(private_dir(&home, &ctx.home)?)
    } else {
        None
    };
    let private_bins = if let Some(bindir) = &bindir {
        match private_dir(bindir, &ctx.bindir) {
            Ok(private) => Some(private),
            Err(error) => {
                if let Some((private, name, _)) = &private_root {
                    let _ = remove_private(&home, name, private);
                }
                return Err(error);
            }
        }
    } else {
        None
    };
    let binary_slots = bindir
        .as_ref()
        .map(|bindir| {
            crate::infrastructure::tool_bin_names_for_os(plan.kind, &ctx.os)
                .iter()
                .map(|name| {
                    let name = OsString::from(*name);
                    Ok((name.clone(), named_entry_identity(bindir, &name)?))
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;

    let mut staged_installs = Vec::<StagedInstall>::new();
    let mut staged_active = Vec::<StagedLink>::new();
    let mut staged_binary = Vec::<StagedLink>::new();
    let root_path = plan.root.clone();
    let root_dir = root_dir.as_ref();
    let bindir = bindir.as_ref();
    let private_root = private_root.as_ref();
    let private_bins = private_bins.as_ref();

    let stage_result = (|| -> Result<()> {
        let root = root_dir.context("tool root disappeared after preview")?;
        let (private, _, _) = private_root.context("missing tool-root quarantine")?;
        for (index, entry) in fresh.sealed_entries.iter().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                bail!("managed cleanup cancelled");
            }
            let source = entry
                .path
                .file_name()
                .context("sealed installation name is missing")?
                .to_os_string();
            let stage = format!("installation-{index}");
            renameat_with(
                root,
                &source,
                private,
                stage.as_str(),
                RenameFlags::NOREPLACE,
            )
            .context("quarantine sealed installation")?;
            staged_installs.push(StagedInstall {
                source,
                stage,
                entry: entry.clone(),
            });
            if !directory_is_named(&root_path, fresh.root_identity.as_ref().unwrap())? {
                bail!("tool root was replaced during staging");
            }
        }
        for (index, link) in fresh
            .link_entries
            .iter()
            .filter(|link| link.role == crate::installation_identity::LinkRole::Active)
            .enumerate()
        {
            if cancel.load(Ordering::Relaxed) {
                bail!("managed cleanup cancelled");
            }
            let source = link
                .path
                .file_name()
                .context("active link name is missing")?
                .to_os_string();
            let stage = format!("active-link-{index}");
            renameat_with(
                root,
                &source,
                private,
                stage.as_str(),
                RenameFlags::NOREPLACE,
            )
            .context("quarantine recorded active link")?;
            staged_active.push(StagedLink {
                source,
                stage,
                entry: link.clone(),
            });
        }
        if let Some(bindir) = bindir {
            let (private, _, _) = private_bins.context("missing binary-link quarantine")?;
            for (index, link) in binary_links.iter().enumerate() {
                if cancel.load(Ordering::Relaxed) {
                    bail!("managed cleanup cancelled");
                }
                let source = link
                    .path
                    .file_name()
                    .context("binary link name is missing")?
                    .to_os_string();
                let stage = format!("binary-link-{index}");
                renameat_with(
                    bindir,
                    &source,
                    private,
                    stage.as_str(),
                    RenameFlags::NOREPLACE,
                )
                .context("quarantine recorded binary link")?;
                staged_binary.push(StagedLink {
                    source,
                    stage,
                    entry: link.clone(),
                });
            }
        }
        Ok(())
    })();

    let rollback = || -> Result<()> {
        let mut errors = Vec::new();
        if let (Some((private, _, _)), Some(bindir)) = (private_bins, bindir) {
            for staged in staged_binary.iter().rev() {
                if let Err(error) = renameat_with(
                    private,
                    staged.stage.as_str(),
                    bindir,
                    &staged.source,
                    RenameFlags::NOREPLACE,
                ) {
                    errors.push(format!("restore {}: {error}", staged.entry.path.display()));
                }
            }
        }
        if let (Some((private, _, _)), Some(root)) = (private_root, root_dir) {
            for staged in staged_active.iter().rev() {
                if let Err(error) = renameat_with(
                    private,
                    staged.stage.as_str(),
                    root,
                    &staged.source,
                    RenameFlags::NOREPLACE,
                ) {
                    errors.push(format!("restore {}: {error}", staged.entry.path.display()));
                }
            }
            for staged in staged_installs.iter().rev() {
                if let Err(error) = renameat_with(
                    private,
                    staged.stage.as_str(),
                    root,
                    &staged.source,
                    RenameFlags::NOREPLACE,
                ) {
                    errors.push(format!("restore {}: {error}", staged.entry.path.display()));
                }
            }
        }
        if errors.is_empty() {
            if let (Some((private, name, _)), Some(bindir)) = (private_bins, bindir) {
                remove_private(bindir, name, private)?;
            }
            if let Some((private, name, _)) = private_root {
                remove_private(&home, name, private)?;
            }
            Ok(())
        } else {
            bail!("{}", errors.join("; "))
        }
    };

    if let Err(error) = stage_result {
        return match rollback() {
            Ok(()) => Err(error).context("staged paths were restored; review the plan again"),
            Err(restore) => {
                let mut locations = [
                    private_root.map(|(_, _, path)| path),
                    private_bins.map(|(_, _, path)| path),
                ]
                .into_iter()
                .flatten()
                .map(|path| crate::sweep::display_path(path))
                .collect::<Vec<_>>();
                if locations.is_empty() {
                    locations.push(crate::sweep::display_path(&plan.root));
                }
                bail!(
                    "{error:#}; restore failed ({restore:#}); staged entries may remain; inspect quarantine paths: {}",
                    locations.join(", ")
                );
            }
        };
    }

    if let Some(first) = staged_installs.first()
        && let Some((_, _, private_path)) = private_root
    {
        after_staging(&private_path.join(&first.stage));
    }
    let validation = (|| -> Result<()> {
        if cancel.load(Ordering::Relaxed) {
            bail!("managed cleanup cancelled");
        }
        if let Some(expected) = &fresh.root_identity
            && !directory_is_named(&root_path, expected)?
        {
            bail!("tool root was replaced after staging");
        }
        let (private, _, private_path) = private_root.context("missing tool-root quarantine")?;
        for (index, staged) in staged_installs.iter().enumerate() {
            let path = private_path.join(&staged.stage);
            let moved = child_dir(private, OsStr::new(&staged.stage))?;
            if !same_moved(&staged.entry.identity, &identity(&moved.metadata()?)) {
                bail!("quarantined installation changed after preview");
            }
            drop(moved);
            crate::installation_identity::verify_at_with_cancel(&path, &staged.entry.seal, cancel)
                .context("revalidate sealed installation after staging")?;
            let status = crate::activity::inspect(std::slice::from_ref(&path), cancel)[0];
            if matches!(
                status,
                "open_handles_or_cwd_observed" | "executable_observed"
            ) {
                bail!("a process is using a quarantined installation");
            }
            if Some(status) != fresh.activity_statuses.get(index).copied() {
                bail!("process inspection changed since preview");
            }
            if cancel.load(Ordering::Relaxed) {
                bail!("managed cleanup cancelled");
            }
        }
        for staged in &staged_active {
            verify_link_at(private, OsStr::new(&staged.stage), &staged.entry)?;
        }
        if let Some(bindir) = bindir {
            let (private, _, _) = private_bins.context("missing binary-link quarantine")?;
            for staged in &staged_binary {
                verify_link_at(private, OsStr::new(&staged.stage), &staged.entry)?;
            }
            let expected = fresh.bindir_identity.as_ref().unwrap();
            if !same_directory(expected, &identity(&bindir.metadata()?))
                || !directory_is_named(&ctx.bindir, expected)?
            {
                bail!("binary directory changed after staging");
            }
            for (name, initial) in binary_slots.as_ref().unwrap() {
                let expected = if staged_binary.iter().any(|staged| staged.source == *name) {
                    None
                } else {
                    initial.as_ref()
                };
                if named_entry_identity(bindir, name)?.as_ref() != expected {
                    bail!("a known binary path changed during staging");
                }
            }
        }
        let removed_names = staged_installs
            .iter()
            .map(|entry| entry.source.as_os_str())
            .chain(staged_active.iter().map(|link| link.source.as_os_str()))
            .collect::<Vec<_>>();
        let current = root_snapshot(&root_path, cancel)?;
        let expected = fresh
            .root_entries
            .iter()
            .filter(|entry| {
                !removed_names
                    .iter()
                    .any(|name| *name == entry.path.file_name().unwrap())
            })
            .cloned()
            .collect::<Vec<_>>();
        if current.0 != expected {
            bail!("unselected tool-root entries changed during staging");
        }
        Ok(())
    })();
    if let Err(error) = validation {
        return match rollback() {
            Ok(()) => Err(error).context("staged paths were restored; review the plan again"),
            Err(restore) => {
                let mut locations = [
                    private_root.map(|(_, _, path)| path),
                    private_bins.map(|(_, _, path)| path),
                ]
                .into_iter()
                .flatten()
                .map(|path| crate::sweep::display_path(path))
                .collect::<Vec<_>>();
                if locations.is_empty() {
                    locations.push(crate::sweep::display_path(&plan.root));
                }
                bail!(
                    "{error:#}; restore failed ({restore:#}); staged entries may remain; inspect quarantine paths: {}",
                    locations.join(", ")
                );
            }
        };
    }

    if let Some((private, _, private_path)) = private_root {
        for staged in &staged_installs {
            if let Err(error) = remove_quarantined_entry(private, OsStr::new(&staged.stage)) {
                bail!(
                    "managed cleanup was partial: {error}; inspect quarantine {}",
                    crate::sweep::display_path(private_path)
                );
            }
        }
        for staged in &staged_active {
            if let Err(error) = unlinkat(private, staged.stage.as_str(), AtFlags::empty()) {
                bail!(
                    "selected installations were removed but active-link cleanup was partial: {error}; inspect quarantine {}",
                    crate::sweep::display_path(private_path)
                );
            }
        }
        if let Err(error) = remove_private(&home, private_root.unwrap().1.as_os_str(), private) {
            bail!(
                "selected installations were removed but quarantine cleanup failed: {error}; inspect {}",
                crate::sweep::display_path(private_path)
            );
        }
    }
    if let (Some((private, name, private_path)), Some(bindir)) = (private_bins, bindir) {
        for staged in &staged_binary {
            if let Err(error) = unlinkat(private, staged.stage.as_str(), AtFlags::empty()) {
                bail!(
                    "selected installations were removed but binary-link cleanup was partial: {error}; inspect quarantine {}",
                    crate::sweep::display_path(private_path)
                );
            }
        }
        if let Err(error) = remove_private(bindir, name.as_os_str(), private) {
            bail!(
                "selected paths were removed but binary-link quarantine cleanup failed: {error}; inspect {}",
                crate::sweep::display_path(private_path)
            );
        }
    }
    let links_absent = fresh.link_entries.iter().all(|link| {
        matches!(
            fs::symlink_metadata(&link.path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
    });
    let entries_absent = fresh.selected_entries.iter().all(|path| {
        matches!(
            fs::symlink_metadata(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
    });
    let root_unchanged = fresh.root_identity.as_ref().map_or(Ok(true), |expected| {
        directory_is_named(&root_path, expected)
    })?;
    Ok(if links_absent && entries_absent && root_unchanged {
        "verified_selected_absent"
    } else {
        "unverified_replacement"
    })
}

#[cfg(not(target_os = "linux"))]
pub fn remove(_: &Ctx, _: &CleanupPlan, _: &AtomicBool) -> Result<&'static str> {
    bail!("interactive managed tool cleanup is supported only on Linux")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::test_support::{TestPrompt, base_ctx};
    use std::{
        ffi::OsString,
        fs,
        os::unix::{ffi::OsStringExt, fs::symlink},
        sync::Arc,
    };

    fn fixture_identity() -> Identity {
        Identity {
            dev: 1,
            ino: 2,
            uid: 3,
            mode: 0o755,
            links: 1,
            size: 0,
            mtime: 0,
            mtime_ns: 0,
            ctime: 0,
            ctime_ns: 0,
        }
    }

    fn sealed_fixture(root: &Path, bindir: &Path, contents: &str) -> PathBuf {
        fs::create_dir_all(root).unwrap();
        fs::create_dir_all(bindir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(bindir, fs::Permissions::from_mode(0o755)).unwrap();
        let stage = tempfile::Builder::new()
            .prefix("install-")
            .tempdir_in(root)
            .unwrap();
        fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(stage.path().join("go/bin")).unwrap();
        fs::set_permissions(stage.path().join("go"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            stage.path().join("go/bin"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(stage.path().join("go/bin/go"), contents).unwrap();
        fs::set_permissions(
            stage.path().join("go/bin/go"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let _ = crate::installation_identity::seal(root, &stage, ToolKind::Go, "fixture").unwrap();
        let install = stage.keep();
        symlink(install.join("go"), root.join("active")).unwrap();
        crate::installation_identity::record_active_link(root, bindir, ToolKind::Go).unwrap();
        let link = bindir.join("go");
        let target = root.join("active/bin/go");
        symlink(&target, &link).unwrap();
        crate::installation_identity::record_created_links(
            root,
            bindir,
            ToolKind::Go,
            &[(link, target)],
        )
        .unwrap();
        install
    }

    fn serialization_plan(
        root: PathBuf,
        entries: Vec<PathBuf>,
        links: Vec<PathBuf>,
    ) -> CleanupPlan {
        CleanupPlan {
            tool: "go",
            root,
            root_present: true,
            entries,
            selected_entries: Vec::new(),
            preserved_entries: Vec::new(),
            links,
            preserved_links: Vec::new(),
            logical_bytes: 7,
            activity_status: "idle",
            installation_status: "unverified",
            writable_by_others: false,
            warning: "fixture",
            preview_token: "token".into(),
            kind: ToolKind::Go,
            root_identity: None,
            home_identity: fixture_identity(),
            bindir_identity: None,
            link_entries: Vec::new(),
            root_entries: Vec::new(),
            sealed_entries: Vec::new(),
            activity_statuses: Vec::new(),
            tree_digest: String::new(),
        }
    }

    #[test]
    fn unicode_path_serialization_keeps_legacy_plan_and_token_bytes() {
        #[derive(Serialize)]
        struct LegacyEntry<'a> {
            path: &'a PathBuf,
            identity: &'a Identity,
            link_target: &'a Option<PathBuf>,
        }

        let home = PathBuf::from("/tmp/managed");
        let bindir = PathBuf::from("/tmp/bin");
        let root = home.join("go");
        let entry_path = root.join("version");
        let link_target = root.join("active/bin/go");
        let identity = fixture_identity();
        let entry = Entry {
            path: entry_path.clone(),
            identity: identity.clone(),
            link_target: Some(link_target.clone()),
        };
        let legacy_entry = LegacyEntry {
            path: &entry.path,
            identity: &entry.identity,
            link_target: &entry.link_target,
        };

        // These are the exact serialized inputs used by the preview-token hash before JsonPath.
        for path in [&home, &bindir, &root, &link_target] {
            assert_eq!(
                serde_json::to_vec(&crate::sweep::JsonPath(path)).unwrap(),
                serde_json::to_vec(path).unwrap()
            );
        }
        assert_eq!(
            serde_json::to_vec(&[&entry]).unwrap(),
            serde_json::to_vec(&vec![legacy_entry]).unwrap()
        );

        let plan = serialization_plan(
            root.clone(),
            vec![entry_path.clone()],
            vec![link_target.clone()],
        );
        let value = serde_json::to_value(plan).unwrap();
        assert_eq!(value["root"], root.to_str().unwrap());
        assert_eq!(value["entries"][0], entry_path.to_str().unwrap());
        assert_eq!(value["links"][0], link_target.to_str().unwrap());
    }

    #[test]
    fn non_unicode_path_serialization_encodes_plan_and_token_entries() {
        let root = PathBuf::from(OsString::from_vec(b"/tmp/managed-\xff%/go".to_vec()));
        let entry_path = root.join(OsString::from_vec(b"version-\xfe%".to_vec()));
        let link_target = root.join(OsString::from_vec(b"active-\xfd%/bin/go".to_vec()));
        let entry = Entry {
            path: entry_path.clone(),
            identity: fixture_identity(),
            link_target: Some(link_target.clone()),
        };

        let json = serde_json::to_value(&entry).unwrap();
        for key in ["path", "link_target"] {
            assert_eq!(json[key]["encoding"], "unix-percent-bytes");
        }
        assert_eq!(
            json["path"]["value"],
            crate::sweep::display_path(&entry_path)
        );
        assert_eq!(
            json["link_target"]["value"],
            crate::sweep::display_path(&link_target)
        );

        let plan = serialization_plan(
            root.clone(),
            vec![entry_path.clone()],
            vec![link_target.clone()],
        );
        let value = serde_json::to_value(plan).unwrap();
        for (path, json_path) in [
            (&root, &value["root"]),
            (&entry_path, &value["entries"][0]),
            (&link_target, &value["links"][0]),
        ] {
            assert_eq!(json_path["encoding"], "unix-percent-bytes");
            assert_eq!(json_path["value"], crate::sweep::display_path(path));
        }
    }

    #[test]
    fn changed_quarantined_tree_is_restored_without_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("managed");
        let bindir = dir.path().join("bin");
        let root = home.join("go");
        let install = sealed_fixture(&root, &bindir, "initial");
        let ctx = base_ctx(
            home.clone(),
            bindir.clone(),
            Arc::new(TestPrompt::default()),
        );
        let cancel = AtomicBool::new(false);
        let plan = preview(&ctx, ToolKind::Go, &cancel).unwrap();
        let result = remove_with_hook(&ctx, &plan, &cancel, |staged| {
            fs::write(staged.join("go/bin/go"), "changed during quarantine").unwrap();
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(install.join("go/bin/go")).unwrap(),
            "changed during quarantine"
        );
        assert!(fs::symlink_metadata(bindir.join("go")).is_ok());
        assert!(root.join("active").exists());
    }

    #[test]
    fn cancellation_after_staging_restores_the_tool_root() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("managed");
        let bindir = dir.path().join("bin");
        let root = home.join("go");
        let install = sealed_fixture(&root, &bindir, "fixture");
        let ctx = base_ctx(home.clone(), bindir, Arc::new(TestPrompt::default()));
        let cancel = AtomicBool::new(false);
        let plan = preview(&ctx, ToolKind::Go, &cancel).unwrap();
        let result = remove_with_hook(&ctx, &plan, &cancel, |_| {
            cancel.store(true, Ordering::Relaxed)
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(install.join("go/bin/go")).unwrap(),
            "fixture"
        );
        assert!(root.join("active").exists());
    }

    #[test]
    fn replaced_binary_directory_is_detected_after_staging() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("managed");
        let bindir = dir.path().join("bin");
        let displaced_bindir = dir.path().join("bin-displaced");
        let root = home.join("go");
        let install = sealed_fixture(&root, &bindir, "fixture");
        let ctx = base_ctx(home, bindir.clone(), Arc::new(TestPrompt::default()));
        let cancel = AtomicBool::new(false);
        let plan = preview(&ctx, ToolKind::Go, &cancel).unwrap();

        let result = remove_with_hook(&ctx, &plan, &cancel, |_| {
            fs::rename(&bindir, &displaced_bindir).unwrap();
            fs::create_dir(&bindir).unwrap();
        });

        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(install.join("go/bin/go")).unwrap(),
            "fixture"
        );
        assert!(root.join("active").exists());
        assert!(fs::symlink_metadata(bindir.join("go")).is_err());
        assert!(fs::symlink_metadata(displaced_bindir.join("go")).is_ok());
    }

    #[test]
    fn new_known_binary_link_after_staging_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("managed");
        let bindir = dir.path().join("bin");
        let root = home.join("go");
        let outside = dir.path().join("outside");
        let install = sealed_fixture(&root, &bindir, "fixture");
        fs::write(&outside, "keep").unwrap();
        let ctx = base_ctx(home, bindir.clone(), Arc::new(TestPrompt::default()));
        let cancel = AtomicBool::new(false);
        let plan = preview(&ctx, ToolKind::Go, &cancel).unwrap();

        let result = remove_with_hook(&ctx, &plan, &cancel, |_| {
            symlink(&outside, bindir.join("gofmt")).unwrap();
        });

        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(install.join("go/bin/go")).unwrap(),
            "fixture"
        );
        assert!(root.join("active").exists());
        assert_eq!(fs::read_link(bindir.join("gofmt")).unwrap(), outside);
        assert_eq!(fs::read_to_string(&outside).unwrap(), "keep");
        assert_eq!(
            fs::read_link(bindir.join("go")).unwrap(),
            root.join("active/bin/go")
        );
    }

    #[test]
    fn replaced_binary_link_is_not_overwritten_during_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("managed");
        let bindir = dir.path().join("bin");
        let root = home.join("go");
        let outside = dir.path().join("outside");
        let install = sealed_fixture(&root, &bindir, "fixture");
        fs::write(&outside, "keep").unwrap();
        let ctx = base_ctx(home, bindir.clone(), Arc::new(TestPrompt::default()));
        let cancel = AtomicBool::new(false);
        let plan = preview(&ctx, ToolKind::Go, &cancel).unwrap();
        let result = remove_with_hook(&ctx, &plan, &cancel, |_| {
            symlink(&outside, bindir.join("go")).unwrap();
        });
        let error = result.unwrap_err().to_string();
        assert!(error.contains("staged entries may remain"));
        assert!(root.exists());
        assert!(install.join("go/bin/go").exists());
        assert_eq!(fs::read_link(bindir.join("go")).unwrap(), outside);
        assert_eq!(fs::read_to_string(&outside).unwrap(), "keep");
        let entries = fs::read_dir(&bindir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 2);
        let bindir_quarantine = entries
            .iter()
            .find(|path| {
                path.is_dir()
                    && path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with(".upkit-clean-"))
            })
            .unwrap();
        assert!(error.contains(&bindir_quarantine.display().to_string()));
    }

    #[test]
    fn recursive_removal_rejects_special_files_and_never_follows_links() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(&outside, "keep").unwrap();
        symlink(&outside, root.join("nested/link")).unwrap();
        let socket = root.join("socket");
        let listener = UnixListener::bind(&socket).unwrap();
        let parent = fs::File::open(dir.path()).unwrap();
        assert!(remove_quarantined_tree(&parent).is_err());
        assert!(fs::symlink_metadata(&socket).is_ok());
        assert_eq!(fs::read_to_string(&outside).unwrap(), "keep");
        drop(listener);
    }
}
