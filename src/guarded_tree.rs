//! Bounded, descriptor-relative inspection and removal of a reviewed directory.
use anyhow::{Context, Result, bail};
use rustix::fs::{AtFlags, Dir, Mode, OFlags, ResolveFlags, openat2, readlinkat, unlinkat};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::MetadataExt,
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
struct Identity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    links: u64,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

fn identity(meta: &fs::Metadata) -> Identity {
    Identity {
        device: meta.dev(),
        inode: meta.ino(),
        mode: meta.mode(),
        uid: meta.uid(),
        links: meta.nlink(),
        size: meta.len(),
        mtime: meta.mtime(),
        mtime_ns: meta.mtime_nsec(),
        ctime: meta.ctime(),
        ctime_ns: meta.ctime_nsec(),
    }
}

fn same_directory(a: &Identity, b: &Identity) -> bool {
    a.device == b.device && a.inode == b.inode && a.mode == b.mode && a.uid == b.uid
}

fn open(parent: &fs::File, path: &Path, flags: OFlags) -> Result<fs::File> {
    Ok(fs::File::from(openat2(
        parent,
        path,
        flags | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )?))
}

#[derive(Clone, Debug)]
struct Entry {
    path: PathBuf,
    identity: Identity,
    directory: bool,
    symlink: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct ReviewEntry {
    pub(crate) path: String,
    pub(crate) kind: &'static str,
    pub(crate) logical_bytes: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct TreeSnapshot {
    entries: Vec<Entry>,
    pub(crate) digest: String,
    pub(crate) logical_bytes: u64,
}

impl TreeSnapshot {
    pub(crate) fn count(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn has_symlinks(&self) -> bool {
        self.entries.iter().any(|entry| entry.symlink)
    }

    pub(crate) fn has_project_or_vcs_marker(&self) -> bool {
        self.has_vcs_marker()
            || self
                .entries
                .iter()
                .any(|entry| crate::sweep::is_project_marker(&entry.path))
    }

    pub(crate) fn has_project_manifest_at_root(&self) -> bool {
        self.entries.iter().any(|entry| {
            !entry.directory
                && !entry.symlink
                && entry
                    .path
                    .parent()
                    .is_some_and(|parent| parent.as_os_str().is_empty())
                && crate::sweep::is_project_marker(&entry.path)
        })
    }

    pub(crate) fn has_vcs_marker(&self) -> bool {
        self.entries.iter().any(|entry| entry.path.components().any(|component| {
            matches!(component, std::path::Component::Normal(name) if [".git", ".hg", ".svn", ".bzr"].iter().any(|marker| name == *marker))
        }))
    }

    pub(crate) fn review_entries(&self) -> Vec<ReviewEntry> {
        use std::fmt::Write;
        self.entries
            .iter()
            .map(|entry| {
                let mut path = String::new();
                for byte in entry.path.as_os_str().as_bytes() {
                    if (0x20..=0x7e).contains(byte) && *byte != b'%' {
                        path.push(char::from(*byte));
                    } else {
                        let _ = write!(path, "%{byte:02X}");
                    }
                }
                ReviewEntry {
                    path,
                    kind: if entry.directory {
                        "directory"
                    } else if entry.symlink {
                        "symlink"
                    } else {
                        "file"
                    },
                    logical_bytes: (!entry.directory && !entry.symlink)
                        .then_some(entry.identity.size),
                }
            })
            .collect()
    }
}

fn names(directory: &fs::File, cancel: &AtomicBool, remaining: usize) -> Result<Vec<OsString>> {
    let mut result = Vec::new();
    for entry in Dir::read_from(directory)? {
        if cancel.load(Ordering::Relaxed) {
            bail!("directory preview cancelled");
        }
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        // shortcut: bound the whole tree to 10,000 entries; paginate larger previews before raising the limit.
        if result.len() >= remaining {
            bail!("directory exceeds the 10,000-entry limit");
        }
        result.push(OsString::from_vec(bytes.to_vec()));
    }
    result.sort();
    Ok(result)
}

pub(crate) fn snapshot(root: fs::File, uid: u32, cancel: &AtomicBool) -> Result<TreeSnapshot> {
    let root_identity = identity(&root.metadata()?);
    if !root.metadata()?.is_dir() || root_identity.uid != uid || root_identity.mode & 0o022 != 0 {
        bail!("directory must be user-owned and not group/other writable");
    }
    let first = names(&root, cancel, 10_000)?;
    let mut discovered = first.len();
    let mut stack = vec![(root, PathBuf::new(), first.into_iter(), root_identity)];
    let mut entries = Vec::new();
    let mut hash = Sha256::new();
    let mut logical_bytes = 0u64;
    while !stack.is_empty() {
        if cancel.load(Ordering::Relaxed) {
            bail!("directory preview cancelled");
        }
        let Some(name) = stack.last_mut().expect("nonempty").2.next() else {
            let (dir, _, _, expected) = stack.pop().expect("nonempty");
            if identity(&dir.metadata()?) != expected {
                bail!("directory changed during preview");
            }
            continue;
        };
        // shortcut: cap a tree at 10,000 entries and 128 levels; paginate larger previews before raising limits.
        if entries.len() >= 10_000 || stack.len() > 128 {
            bail!("directory exceeds safe traversal limits");
        }
        let (parent, relative, _, _) = stack.last().expect("nonempty");
        let path = relative.join(&name);
        let descriptor = open(parent, Path::new(&name), OFlags::PATH | OFlags::NOFOLLOW)
            .context("inspect entry without following links or mounts")?;
        let metadata = descriptor.metadata()?;
        let current = identity(&metadata);
        let symlink = metadata.file_type().is_symlink();
        if current.uid != uid
            || (!symlink && current.mode & 0o022 != 0)
            || (!metadata.is_dir() && current.links != 1)
            || !(metadata.is_dir() || metadata.is_file() || symlink)
        {
            bail!("directory contains an unsafe owner, permission, hard link, or special file");
        }
        let target = if symlink {
            Some(readlinkat(&descriptor, "", Vec::new())?.into_bytes())
        } else {
            None
        };
        if metadata.is_file() {
            logical_bytes = logical_bytes
                .checked_add(metadata.len())
                .context("directory size overflow")?;
        }
        for value in [
            path.as_os_str().as_bytes(),
            &serde_json::to_vec(&current)?,
            target.as_deref().unwrap_or(&[]),
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        entries.push(Entry {
            path: path.clone(),
            identity: current.clone(),
            directory: metadata.is_dir(),
            symlink,
        });
        if metadata.is_dir() {
            if stack.len() >= 128 {
                bail!("directory exceeds safe traversal depth");
            }
            let child = open(parent, Path::new(&name), OFlags::RDONLY | OFlags::DIRECTORY)?;
            if identity(&child.metadata()?) != current {
                bail!("directory changed during preview");
            }
            let children = names(&child, cancel, 10_000 - discovered)?;
            discovered += children.len();
            stack.push((child, path, children.into_iter(), current));
        }
    }
    Ok(TreeSnapshot {
        entries,
        digest: hex::encode(hash.finalize()),
        logical_bytes,
    })
}

/// Delete only the previously inspected entries, reporting whether any removal occurred.
pub(crate) fn remove(
    container: &fs::File,
    root_name: &OsStr,
    root: &fs::File,
    tree: &TreeSnapshot,
    cancel: &AtomicBool,
    partial: &mut bool,
    mut check: impl FnMut(bool) -> Result<()>,
) -> Result<()> {
    for entry in tree.entries.iter().rev() {
        check(false)?;
        if cancel.load(Ordering::Relaxed) {
            bail!("directory removal cancelled");
        }
        let current_root = open(
            container,
            Path::new(root_name),
            OFlags::PATH | OFlags::NOFOLLOW,
        )?;
        if !same_directory(
            &identity(&current_root.metadata()?),
            &identity(&root.metadata()?),
        ) {
            bail!("quarantined directory was replaced");
        }
        let parent_path = entry
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = open(root, parent_path, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let name = entry.path.file_name().context("missing entry name")?;
        let current = open(&parent, Path::new(name), OFlags::PATH | OFlags::NOFOLLOW)?;
        let actual = identity(&current.metadata()?);
        if if entry.directory {
            !same_directory(&actual, &entry.identity)
        } else {
            actual != entry.identity
        } {
            bail!("directory entry changed during removal");
        }
        unlinkat(
            &parent,
            name,
            if entry.directory {
                AtFlags::REMOVEDIR
            } else {
                AtFlags::empty()
            },
        )?;
        *partial = true;
        check(true)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn changed_entry_after_a_removal_is_reported_as_partial() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("a"), "original").unwrap();
        fs::write(root.join("z"), "remove first").unwrap();
        for name in ["a", "z"] {
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let handle = fs::File::open(&root).unwrap();
        let cancel = AtomicBool::new(false);
        let tree = snapshot(
            handle.try_clone().unwrap(),
            handle.metadata().unwrap().uid(),
            &cancel,
        )
        .unwrap();
        fs::write(root.join("a"), "changed").unwrap();
        let mut partial = false;
        let parent = fs::File::open(dir.path()).unwrap();
        assert!(
            remove(
                &parent,
                OsStr::new("root"),
                &handle,
                &tree,
                &cancel,
                &mut partial,
                |_| Ok(())
            )
            .is_err()
        );
        assert!(partial);
        assert!(!root.join("z").exists());
        assert_eq!(fs::read_to_string(root.join("a")).unwrap(), "changed");
    }

    #[test]
    fn excessive_directory_depth_is_rejected_before_removal() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut path = root.clone();
        for _ in 0..128 {
            path.push("d");
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let handle = fs::File::open(&root).unwrap();
        let error = snapshot(
            handle.try_clone().unwrap(),
            handle.metadata().unwrap().uid(),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(error.to_string().contains("depth"));
        assert!(path.is_dir());
    }

    #[test]
    fn directory_listing_respects_remaining_tree_budget() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), "a").unwrap();
        fs::write(dir.path().join("b"), "b").unwrap();
        let open = || fs::File::open(dir.path()).unwrap();
        assert_eq!(names(&open(), &AtomicBool::new(false), 2).unwrap().len(), 2);
        assert!(names(&open(), &AtomicBool::new(false), 1).is_err());
        assert!(names(&open(), &AtomicBool::new(true), 2).is_err());
        assert!(dir.path().join("a").exists() && dir.path().join("b").exists());
    }
}
