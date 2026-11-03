//! Explicit, narrowly scoped removal of CPython bytecode.
#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{Result, bail};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};
#[cfg(target_os = "linux")]
use std::{sync::atomic::Ordering, time::Duration};

pub use crate::sweep::Scope;

#[derive(Clone, Debug, Serialize)]
pub struct BytecodePlan {
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub project: PathBuf,
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub manifest: PathBuf,
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub cache: PathBuf,
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub source: PathBuf,
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub file: PathBuf,
    pub python: &'static str,
    pub invalidation: &'static str,
    pub logical_bytes: u64,
    pub preview_token: String,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    pub(crate) git_evidence_id: Option<String>,
    pub warning: &'static str,
    pub scope: Scope,
}

#[derive(Clone, Debug, Serialize)]
pub struct BytecodeBatchPlan {
    pub scope: Scope,
    pub files: Vec<BytecodePlan>,
    pub preview_token: String,
    pub warning: &'static str,
    #[serde(skip)]
    pub(crate) guards: Vec<String>,
}

// shortcut: cap batches at 32 files; paginate confirmations before increasing the limit.
pub const MAX_BATCH_FILES: usize = 32;

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize, PartialEq, Eq)]
struct Fingerprint {
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
fn fingerprint(meta: &std::fs::Metadata) -> Fingerprint {
    use std::os::unix::fs::MetadataExt;
    Fingerprint {
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
fn bytecode_name(name: &str) -> Result<(&str, &'static str, u16)> {
    let name = name
        .strip_suffix(".pyc")
        .context("bytecode file must end in .pyc")?;
    let name = name
        .strip_suffix(".opt-1")
        .or_else(|| name.strip_suffix(".opt-2"))
        .unwrap_or(name);
    let (module, tag) = name
        .rsplit_once('.')
        .filter(|(module, _)| !module.is_empty())
        .context("unsupported bytecode filename")?;
    let (version, magic) = match tag {
        "cpython-310" => ("3.10", 3439),
        "cpython-311" => ("3.11", 3495),
        "cpython-312" => ("3.12", 3531),
        "cpython-313" => ("3.13", 3571),
        "cpython-314" => ("3.14", 3627),
        "cpython-315" => ("3.15", 3666),
        "cpython-316" => ("3.16a1", 3706),
        _ => bail!("unsupported CPython cache tag"),
    };
    Ok((module, version, magic))
}

/// List supported filenames without treating the listing as deletion authorization.
#[cfg(target_os = "linux")]
pub fn list(cache: &Path, cancel: &AtomicBool) -> Result<Vec<PathBuf>> {
    use rustix::fs::{Dir, Mode, OFlags, ResolveFlags, openat2};
    if !cache.is_absolute()
        || cache.file_name().and_then(|name| name.to_str()) != Some("__pycache__")
        || cache.canonicalize().context("resolve bytecode cache")? != cache
    {
        bail!("select an absolute __pycache__ directory");
    }
    let directory = std::fs::File::from(
        openat2(
            rustix::fs::CWD,
            cache,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .context("open bytecode cache without links")?,
    );
    let mut files = Vec::new();
    let entries = Dir::read_from(&directory).context("read bytecode cache")?;
    for (index, entry) in entries.enumerate() {
        if cancel.load(Ordering::Relaxed) {
            bail!("bytecode listing cancelled");
        }
        // shortcut: refuse more than 10,000 entries; paginate when larger caches need browsing.
        if index >= 10_000 {
            bail!("bytecode directory exceeds the 10,000-entry listing limit");
        }
        let entry = entry.context("read bytecode entry")?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if bytecode_name(name).is_err() {
            continue;
        }
        let fd = match openat2(
            &directory,
            name,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::XDEV | rustix::io::Errno::NOENT) => {
                continue;
            }
            Err(error) => return Err(error).context("inspect bytecode entry"),
        };
        if std::fs::File::from(fd).metadata()?.is_file() {
            files.push(cache.join(name));
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(not(target_os = "linux"))]
pub fn list(_: &Path, _: &AtomicBool) -> Result<Vec<PathBuf>> {
    bail!("bytecode listing is supported only on Linux")
}

#[cfg(target_os = "linux")]
struct Opened {
    directories: Vec<std::fs::File>,
    manifest: std::fs::File,
    source: std::fs::File,
    file: std::fs::File,
    fingerprints: Vec<Fingerprint>,
    digest: String,
    invalidation: &'static str,
}

#[cfg(target_os = "linux")]
fn open_checked(
    project: &Path,
    manifest: &Path,
    cache: &Path,
    file: &Path,
    magic: u16,
    source: &Path,
    cancel: &AtomicBool,
) -> Result<Opened> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    use sha2::{Digest, Sha256};
    use std::{fs, io::Read, os::unix::fs::MetadataExt};
    let project_fd = fs::File::from(
        openat2(
            rustix::fs::CWD,
            project,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .context("open project without links")?,
    );
    let relative = |path: &Path| -> Result<PathBuf> {
        let rel = path.strip_prefix(project).context("path outside project")?;
        Ok(if rel.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            rel.to_owned()
        })
    };
    let open = |path: &Path, flags| -> Result<fs::File> {
        Ok(fs::File::from(
            openat2(
                &project_fd,
                relative(path)?,
                flags | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )
            .context("open project path without links or mounts")?,
        ))
    };
    let source_dir = source.parent().context("source parent missing")?;
    if cache.parent() != Some(source_dir)
        || file.parent() != Some(cache)
        || manifest.parent() != Some(project)
    {
        bail!("bytecode and source directories do not match");
    }
    let relative_dir = source_dir
        .strip_prefix(project)
        .context("source outside project")?;
    let mut ancestors = Vec::new();
    let mut path = project.to_owned();
    for component in relative_dir.components() {
        let std::path::Component::Normal(name) = component else {
            bail!("invalid source directory");
        };
        path.push(name);
        ancestors.push(open(&path, OFlags::RDONLY | OFlags::DIRECTORY)?);
    }
    ancestors.push(open(cache, OFlags::RDONLY | OFlags::DIRECTORY)?);
    let manifest_fd = open(manifest, OFlags::RDONLY)?;
    let mut source_fd = open(source, OFlags::RDONLY)?;
    let mut file_fd = open(file, OFlags::RDONLY)?;
    let mut directories = vec![project_fd];
    directories.extend(ancestors);
    let metas = directories
        .iter()
        .chain([&manifest_fd, &source_fd, &file_fd])
        .map(|f| f.metadata())
        .collect::<std::io::Result<Vec<_>>>()?;
    let file_index = metas.len() - 1;
    let source_index = file_index - 1;
    let manifest_index = source_index - 1;
    let uid = rustix::process::geteuid().as_raw();
    if metas[..manifest_index]
        .iter()
        .any(|m| !m.is_dir() || m.uid() != uid || m.mode() & 0o022 != 0)
        || metas[manifest_index..]
            .iter()
            .any(|m| !m.is_file() || m.uid() != uid || m.mode() & 0o022 != 0 || m.nlink() != 1)
    {
        bail!(
            "project paths must be user-owned, non-group-writable directories and singly linked regular files"
        );
    }
    if metas[file_index].len() < 17 || metas[file_index].len() > 64 * 1024 * 1024 {
        bail!("bytecode size is outside the supported range");
    }
    let mut header = [0u8; 16];
    file_fd.read_exact(&mut header)?;
    if header[..2] != magic.to_le_bytes() || header[2..4] != *b"\r\n" {
        bail!("bytecode is not a supported CPython cache");
    }
    let invalidation = match u32::from_le_bytes(header[4..8].try_into()?) {
        0 => {
            if metas[source_index].mtime() < 0
                || u32::from_le_bytes(header[8..12].try_into()?)
                    != metas[source_index].mtime() as u32
                || u32::from_le_bytes(header[12..16].try_into()?)
                    != metas[source_index].len() as u32
            {
                bail!("bytecode timestamp or size does not match the source");
            }
            "timestamp"
        }
        flags @ (1 | 3) => {
            use std::hash::Hasher;
            // shortcut: reject sources over 64 MiB; raise the bound if larger modules need cleanup.
            if metas[source_index].len() > 64 * 1024 * 1024 {
                bail!("source exceeds the 64 MiB hash-verification limit");
            }
            let key = u32::from_le_bytes(header[..4].try_into()?) as u64;
            let mut hasher: Box<dyn Hasher> = if magic == 3439 {
                Box::new(siphasher::sip::SipHasher24::new_with_keys(key, 0))
            } else {
                Box::new(siphasher::sip::SipHasher13::new_with_keys(key, 0))
            };
            let mut source_bytes = 0u64;
            let mut buffer = [0u8; 65536];
            loop {
                if cancel.load(Ordering::Relaxed) {
                    bail!("bytecode preview cancelled");
                }
                let count = source_fd.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                source_bytes += count as u64;
                if source_bytes > metas[source_index].len() {
                    bail!("source grew during inspection");
                }
                hasher.write(&buffer[..count]);
            }
            if source_bytes != metas[source_index].len()
                || hasher.finish().to_le_bytes() != header[8..16]
            {
                bail!("bytecode hash does not match the source");
            }
            if flags == 3 {
                "hash-checked"
            } else {
                "hash-unchecked"
            }
        }
        _ => bail!("unsupported bytecode invalidation flags"),
    };
    let mut hash = Sha256::new();
    hash.update(header);
    let mut buffer = [0u8; 65536];
    let mut bytes_read = header.len() as u64;
    loop {
        if cancel.load(Ordering::Relaxed) {
            bail!("bytecode preview cancelled");
        }
        let n = file_fd.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes_read += n as u64;
        if bytes_read > metas[file_index].len() {
            bail!("bytecode grew during inspection");
        }
        hash.update(&buffer[..n]);
    }
    if bytes_read != metas[file_index].len() {
        bail!("bytecode changed during inspection");
    }
    let fingerprints = metas.iter().map(fingerprint).collect::<Vec<_>>();
    for (fd, expected) in directories
        .iter()
        .chain([&manifest_fd, &source_fd, &file_fd])
        .zip(&fingerprints)
    {
        if fingerprint(&fd.metadata()?) != *expected {
            bail!("project or bytecode changed during inspection");
        }
    }
    Ok(Opened {
        directories,
        manifest: manifest_fd,
        source: source_fd,
        file: file_fd,
        fingerprints,
        digest: hex::encode(hash.finalize()),
        invalidation,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn reject_other_vcs(project: &Path, cache: &Path) -> Result<()> {
    for dir in cache.ancestors() {
        for name in [".hg", ".svn", ".bzr"] {
            match std::fs::symlink_metadata(dir.join(name)) {
                Ok(_) => bail!("another version-control marker was found"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect version-control ancestry"),
            }
        }
        if dir != project && dir.starts_with(project) {
            match std::fs::symlink_metadata(dir.join(".git")) {
                Ok(_) => bail!("nested Git repository found"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect nested Git marker"),
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn token(
    scope: &Scope,
    project: &Path,
    manifest: &Path,
    file: &Path,
    git_evidence_id: &str,
    opened: &Opened,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let boot = std::fs::read("/proc/sys/kernel/random/boot_id").context("read boot identity")?;
    let mut hash = Sha256::new();
    for value in [
        b"upkit-bytecode-v2".as_slice(),
        &boot,
        &serde_json::to_vec(scope)?,
        &serde_json::to_vec(&crate::sweep::JsonPath(project))?,
        &serde_json::to_vec(&crate::sweep::JsonPath(manifest))?,
        &serde_json::to_vec(&crate::sweep::JsonPath(file))?,
        git_evidence_id.as_bytes(),
        &serde_json::to_vec(&opened.fingerprints)?,
        opened.digest.as_bytes(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(target_os = "linux")]
fn batch_guard(scope: &Scope, plan: &BytecodePlan, opened: &Opened) -> Result<String> {
    use sha2::{Digest, Sha256};
    // Earlier removals change directory timestamps, while each remaining file is rescanned.
    let directories = opened.fingerprints[..opened.directories.len()]
        .iter()
        .map(|entry| (entry.dev, entry.ino, entry.uid, entry.mode))
        .collect::<Vec<_>>();
    let boot = std::fs::read("/proc/sys/kernel/random/boot_id").context("read boot identity")?;
    let git_evidence_id = serde_json::to_vec(&plan.git_evidence_id)?;
    let mut hash = Sha256::new();
    for value in [
        b"upkit-bytecode-batch-item-v1".as_slice(),
        &boot,
        &serde_json::to_vec(scope)?,
        &serde_json::to_vec(&crate::sweep::JsonPath(&plan.project))?,
        &serde_json::to_vec(&crate::sweep::JsonPath(&plan.manifest))?,
        &serde_json::to_vec(&crate::sweep::JsonPath(&plan.file))?,
        &serde_json::to_vec(&directories)?,
        &serde_json::to_vec(&opened.fingerprints[opened.directories.len()..])?,
        &git_evidence_id,
        opened.digest.as_bytes(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(target_os = "linux")]
fn file_details(file: &Path) -> Result<(PathBuf, PathBuf, &'static str, u16)> {
    if !file.is_absolute() || file.canonicalize().context("resolve bytecode")? != file {
        bail!("bytecode path must be absolute and canonical");
    }
    let cache = file.parent().context("bytecode parent missing")?;
    if cache.file_name().and_then(|v| v.to_str()) != Some("__pycache__") {
        bail!("bytecode must be inside a discovered __pycache__ directory");
    }
    let (module, python, magic) = bytecode_name(
        file.file_name()
            .and_then(|v| v.to_str())
            .context("unsupported bytecode filename")?,
    )?;
    let source = cache
        .parent()
        .context("source directory missing")?
        .join(format!("{module}.py"));
    Ok((cache.to_owned(), source, python, magic))
}

#[cfg(target_os = "linux")]
type BytecodeFileDetails = (PathBuf, PathBuf, &'static str, u16);

#[cfg(target_os = "linux")]
type SelectedBytecodeFiles = (Vec<BytecodeFileDetails>, Vec<PathBuf>);

#[cfg(target_os = "linux")]
fn selected_file_details(files: &[PathBuf]) -> Result<SelectedBytecodeFiles> {
    use std::collections::HashSet;
    if files.is_empty() || files.len() > MAX_BATCH_FILES {
        bail!("select between 1 and {MAX_BATCH_FILES} bytecode files");
    }
    let mut unique = HashSet::new();
    let mut caches = Vec::new();
    let mut details = Vec::new();
    for file in files {
        if !unique.insert(file) {
            bail!("duplicate bytecode file");
        }
        let detail = file_details(file)?;
        if !caches.contains(&detail.0) {
            caches.push(detail.0.clone());
        }
        details.push(detail);
    }
    Ok((details, caches))
}

#[cfg(target_os = "linux")]
fn validate_dry_run_selection_linux(
    scope: &Scope,
    files: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<usize> {
    for file in files {
        if !std::fs::symlink_metadata(file)
            .context("inspect selected bytecode file")?
            .file_type()
            .is_file()
        {
            bail!("selected bytecode path is not a regular file");
        }
    }
    let (_, caches) = selected_file_details(files)?;
    let report = crate::sweep::scan_with_policy(
        &scope.roots,
        &scope.exclusions,
        scope.older_than_seconds.map(Duration::from_secs),
        scope.enabled.as_deref(),
        cancel,
        |_| {},
    )?;
    crate::sweep::validate_preview_selection(&report, &caches, cancel)?;
    Ok(files.len())
}

#[cfg(target_os = "linux")]
fn preview_files(
    scope: &Scope,
    files: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<Vec<(BytecodePlan, String)>> {
    let (details, caches) = selected_file_details(files)?;
    let report = crate::sweep::scan_with_policy(
        &scope.roots,
        &scope.exclusions,
        scope.older_than_seconds.map(Duration::from_secs),
        scope.enabled.as_deref(),
        cancel,
        |_| {},
    )?;
    let plan = crate::sweep::preview_with_cancel(report, &caches, cancel)?;
    let mut results = Vec::with_capacity(files.len());
    for (file, (cache, source, python, magic)) in files.iter().zip(details) {
        let item = plan
            .items
            .iter()
            .find(|item| item.selected && item.candidate.target == cache)
            .context("bytecode cache was not selected")?;
        let candidate = &item.candidate;
        let manifest = crate::sweep::candidate_manifest(candidate)
            .context("project manifest identity is unavailable")?
            .to_owned();
        if candidate.ecosystem != "python"
            || !candidate.size_complete
            || candidate.nested_project_marker.is_some()
            || candidate.nested_vcs_marker.is_some()
            || candidate.hard_link_marker.is_some()
            || candidate.symlink_marker.is_some()
            || item.identity_status != "metadata_match"
        {
            bail!("artifact inventory or identity is unsuitable for deletion");
        }
        if item.git_index_status != "no_matching_entries_in_git_index"
            || item.git_head_status != "no_matching_entries_in_head_or_index"
            || item.git_history_status != "no_matching_entries_in_git_history"
        {
            bail!(
                "Git index, HEAD, or complete reachable history could not rule out tracked files"
            );
        }
        if item.activity_status != "no_open_handles_or_cwd_observed" {
            bail!("process activity was observed or could not be inspected completely");
        }
        reject_other_vcs(&candidate.project_root, &cache)?;
        let opened = open_checked(
            &candidate.project_root,
            &manifest,
            &cache,
            file,
            magic,
            &source,
            cancel,
        )?;
        let git_evidence_id = item
            .git_evidence_id
            .as_deref()
            .context("trusted Git evidence identity is unavailable")?;
        let preview_token = token(
            scope,
            &candidate.project_root,
            &manifest,
            file,
            git_evidence_id,
            &opened,
        )?;
        let item_plan = BytecodePlan {
            project: candidate.project_root.clone(),
            manifest,
            cache,
            source,
            file: file.to_owned(),
            python,
            invalidation: opened.invalidation,
            logical_bytes: opened
                .fingerprints
                .last()
                .context("missing bytecode identity")?
                .size,
            preview_token,
            git_evidence_id: Some(git_evidence_id.to_owned()),
            warning: if opened.invalidation == "hash-unchecked" {
                "Permanent deletion; unchecked hash bytecode may run code different from the source. Python may rebuild it. Git and process checks are snapshots; interruption can leave a private quarantine file."
            } else {
                "Permanent deletion of this bytecode file; Python may rebuild it. Header validation does not prove bytecode matches source. Git and process checks are snapshots; interruption can leave a private quarantine file."
            },
            scope: scope.clone(),
        };
        let guard = batch_guard(scope, &item_plan, &opened)?;
        results.push((item_plan, guard));
    }
    Ok(results)
}

/// Inspect one exact bytecode file within an explicitly scanned scope.
#[cfg(target_os = "linux")]
pub fn preview(scope: &Scope, file: &Path, cancel: &AtomicBool) -> Result<BytecodePlan> {
    Ok(preview_files(scope, &[file.to_owned()], cancel)?
        .remove(0)
        .0)
}

#[cfg(target_os = "linux")]
pub(crate) fn preview_guarded(
    scope: &Scope,
    file: &Path,
    cancel: &AtomicBool,
) -> Result<(BytecodePlan, String)> {
    Ok(preview_files(scope, &[file.to_owned()], cancel)?.remove(0))
}

/// Preview an explicitly selected set; the token binds the complete selection.
#[cfg(target_os = "linux")]
pub fn preview_batch(
    scope: &Scope,
    files: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<BytecodeBatchPlan> {
    use sha2::{Digest, Sha256};
    let items = preview_files(scope, files, cancel)?;
    let mut hash = Sha256::new();
    hash.update(b"upkit-bytecode-batch-v1");
    for (plan, guard) in &items {
        hash.update(plan.preview_token.as_bytes());
        hash.update(guard.as_bytes());
    }
    let (files, guards) = items.into_iter().unzip();
    Ok(BytecodeBatchPlan {
        scope: scope.clone(),
        files,
        guards,
        preview_token: hex::encode(hash.finalize()),
        warning: "Permanently removes the listed bytecode files. Header validation does not prove bytecode matches source; unchecked caches may run different code. Each is rechecked; failures stop the remaining batch. Space reclaimed is unknown, and interruption may leave quarantine files.",
    })
}

/// Remove one explicitly approved bytecode file after repeating the preview checks.
#[cfg(target_os = "linux")]
pub fn remove(
    scope: &Scope,
    file: &Path,
    approved_token: &str,
    cancel: &AtomicBool,
) -> Result<&'static str> {
    remove_guarded(scope, file, approved_token, cancel, &|| Ok(()))
}

#[cfg(target_os = "linux")]
pub(crate) fn remove_guarded(
    scope: &Scope,
    file: &Path,
    approved_token: &str,
    cancel: &AtomicBool,
    guard: &dyn Fn() -> Result<()>,
) -> Result<&'static str> {
    guard()?;
    let plan = preview(scope, file, cancel)?;
    if approved_token != plan.preview_token {
        bail!("bytecode preview changed; review it again");
    }
    let (_, _, magic) = bytecode_name(
        file.file_name()
            .and_then(|v| v.to_str())
            .context("unsupported bytecode filename")?,
    )?;
    let opened = open_checked(
        &plan.project,
        &plan.manifest,
        &plan.cache,
        file,
        magic,
        &plan.source,
        cancel,
    )?;
    if token(
        scope,
        &plan.project,
        &plan.manifest,
        file,
        plan.git_evidence_id
            .as_deref()
            .context("trusted Git evidence identity is unavailable")?,
        &opened,
    )? != approved_token
    {
        bail!("bytecode or project changed after preview");
    }
    remove_opened(&plan, opened, cancel, &git_clear, || {}, || {}, guard)
}

#[cfg(target_os = "linux")]
fn git_clear(plan: &BytecodePlan, quarantine_item: &Path, cancel: &AtomicBool) -> Result<()> {
    let expected = plan
        .git_evidence_id
        .as_deref()
        .context("trusted Git evidence identity is unavailable")?;
    let git = crate::git_index::available(cancel, &plan.scope.roots)?
        .context("trusted Git became unavailable")?;
    if git.evidence_id() != expected {
        bail!("Git executable changed after bytecode preview");
    }
    crate::git_index::clear_for_removal(&git, &plan.project, &plan.file, cancel)?;
    crate::git_index::clear_for_removal(&git, &plan.project, quarantine_item, cancel)
}

#[cfg(target_os = "linux")]
fn remove_opened(
    plan: &BytecodePlan,
    opened: Opened,
    cancel: &AtomicBool,
    clear_git: &dyn Fn(&BytecodePlan, &Path, &AtomicBool) -> Result<()>,
    after_staging: impl FnOnce(),
    after_git_clear: impl FnOnce(),
    guard: &dyn Fn() -> Result<()>,
) -> Result<&'static str> {
    use rustix::fs::{
        AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, mkdirat, openat2, renameat_with, unlinkat,
    };
    use sha2::{Digest, Sha256};
    use std::{
        io::{Read, Seek, SeekFrom},
        sync::atomic::AtomicU64,
        time::{SystemTime, UNIX_EPOCH},
    };

    let cache = opened
        .directories
        .last()
        .context("missing cache directory")?;
    let name = plan.file.file_name().context("missing bytecode name")?;
    let expected = opened
        .fingerprints
        .last()
        .context("missing bytecode identity")?;
    let source_expected = &opened.fingerprints[opened.fingerprints.len() - 2];
    let manifest_expected = &opened.fingerprints[opened.fingerprints.len() - 3];
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut private = None;
    for _ in 0..32 {
        let name = format!(
            ".upkit-bytecode-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        match mkdirat(cache, name.as_str(), Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) => {
                private = Some(name);
                break;
            }
            Err(rustix::io::Errno::EXIST) => continue,
            Err(error) => return Err(error).context("create bytecode quarantine"),
        }
    }
    let private = private.context("could not allocate bytecode quarantine")?;
    let quarantine_path = plan.cache.join(&private);
    let quarantine_item = quarantine_path.join("item");
    let quarantine = match openat2(
        cache,
        private.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    ) {
        Ok(fd) => std::fs::File::from(fd),
        Err(error) => {
            let _ = unlinkat(cache, private.as_str(), AtFlags::REMOVEDIR);
            return Err(error).context("open bytecode quarantine");
        }
    };
    let quarantine_identity = match quarantine.metadata() {
        Ok(metadata) => fingerprint(&metadata),
        Err(error) => {
            let cleanup = unlinkat(cache, private.as_str(), AtFlags::REMOVEDIR);
            if cleanup.is_err() {
                bail!(
                    "inspect bytecode quarantine: {error}; inspect {}",
                    crate::sweep::display_path(&quarantine_path)
                );
            }
            return Err(error).context("inspect bytecode quarantine");
        }
    };
    let cache_identity = &opened.fingerprints[opened.fingerprints.len() - 4];
    let mut staged = false;
    let mut removed = false;
    let action = (|| -> Result<&'static str> {
        if cancel.load(Ordering::Relaxed) {
            bail!("bytecode removal cancelled");
        }
        guard()?;
        let check_ancestors = || -> Result<()> {
            for (directory, expected) in opened
                .directories
                .iter()
                .take(opened.directories.len() - 1)
                .zip(&opened.fingerprints)
            {
                if fingerprint(&directory.metadata()?) != *expected {
                    bail!("project directory changed");
                }
            }
            let actual_cache = fingerprint(&cache.metadata()?);
            let actual_quarantine = fingerprint(&quarantine.metadata()?);
            if actual_cache.dev != cache_identity.dev
                || actual_cache.ino != cache_identity.ino
                || actual_cache.uid != cache_identity.uid
                || actual_cache.mode != cache_identity.mode
                || actual_quarantine.dev != quarantine_identity.dev
                || actual_quarantine.ino != quarantine_identity.ino
                || actual_quarantine.uid != rustix::process::geteuid().as_raw()
                || actual_quarantine.mode & 0o777 != 0o700
            {
                bail!("cache or quarantine directory changed");
            }
            Ok(())
        };
        check_ancestors()?;
        if fingerprint(&opened.manifest.metadata()?) != *manifest_expected
            || fingerprint(&opened.source.metadata()?) != *source_expected
            || fingerprint(&opened.file.metadata()?) != *expected
        {
            bail!("source or bytecode changed");
        }
        renameat_with(cache, name, &quarantine, "item", RenameFlags::NOREPLACE)
            .context("quarantine bytecode")?;
        staged = true;
        after_staging();
        check_ancestors()?;
        let same = |actual: &Fingerprint| {
            actual.dev == expected.dev
                && actual.ino == expected.ino
                && actual.uid == expected.uid
                && actual.mode == expected.mode
                && actual.links == 1
                && actual.size == expected.size
                && actual.mtime == expected.mtime
                && actual.mtime_ns == expected.mtime_ns
        };
        let verify_quarantined = |moved: &mut std::fs::File| -> Result<Fingerprint> {
            let before = fingerprint(&moved.metadata()?);
            if !same(&before)
                || !same(&fingerprint(&opened.file.metadata()?))
                || fingerprint(&opened.source.metadata()?) != *source_expected
                || fingerprint(&opened.manifest.metadata()?) != *manifest_expected
            {
                bail!("quarantined bytecode or source changed");
            }
            let mut digest = Sha256::new();
            let mut buffer = [0u8; 65536];
            let mut bytes_read = 0u64;
            moved.seek(SeekFrom::Start(0))?;
            loop {
                if cancel.load(Ordering::Relaxed) {
                    bail!("bytecode removal cancelled");
                }
                let count = moved.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                bytes_read += count as u64;
                if bytes_read > expected.size {
                    bail!("quarantined bytecode grew during verification");
                }
                digest.update(&buffer[..count]);
            }
            if bytes_read != expected.size
                || hex::encode(digest.finalize()) != opened.digest
                || fingerprint(&moved.metadata()?) != before
                || fingerprint(&opened.source.metadata()?) != *source_expected
                || fingerprint(&opened.manifest.metadata()?) != *manifest_expected
            {
                bail!("quarantined bytecode changed during verification");
            }
            Ok(before)
        };
        let mut moved = std::fs::File::from(
            openat2(
                &quarantine,
                "item",
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )
            .context("inspect quarantined bytecode")?,
        );
        verify_quarantined(&mut moved)?;
        check_ancestors()?;
        if cancel.load(Ordering::Relaxed) {
            bail!("bytecode removal cancelled");
        }
        guard()?;
        clear_git(plan, &quarantine_item, cancel)?;
        after_git_clear();
        check_ancestors()?;
        if cancel.load(Ordering::Relaxed) {
            bail!("bytecode removal cancelled");
        }
        let mut moved_after_git = std::fs::File::from(
            openat2(
                &quarantine,
                "item",
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )
            .context("reopen quarantined bytecode after Git clearance")?,
        );
        let post_git_identity = verify_quarantined(&mut moved_after_git)?;
        check_ancestors()?;
        if cancel.load(Ordering::Relaxed) {
            bail!("bytecode removal cancelled");
        }
        if fingerprint(&moved_after_git.metadata()?) != post_git_identity
            || fingerprint(&opened.source.metadata()?) != *source_expected
            || fingerprint(&opened.manifest.metadata()?) != *manifest_expected
        {
            bail!("quarantined bytecode, source, or manifest changed before removal");
        }
        unlinkat(&quarantine, "item", AtFlags::empty()).context("remove quarantined bytecode")?;
        staged = false;
        removed = true;
        Ok(
            if matches!(
                rustix::fs::statat(cache, name, AtFlags::SYMLINK_NOFOLLOW),
                Err(rustix::io::Errno::NOENT)
            ) {
                "verified_absent"
            } else {
                "unverified_replacement"
            },
        )
    })();
    let rollback_failed =
        staged && renameat_with(&quarantine, "item", cache, name, RenameFlags::NOREPLACE).is_err();
    let cleanup_failed = unlinkat(cache, private.as_str(), AtFlags::REMOVEDIR).is_err();
    match action {
        Ok(status) if !cleanup_failed => Ok(status),
        Ok(_) => bail!(
            "bytecode removed; inspect quarantine {}",
            crate::sweep::display_path(&quarantine_path)
        ),
        Err(error) => bail!(
            "{error:#}; bytecode {}{}",
            if removed {
                "was permanently removed"
            } else {
                "was not intentionally removed"
            },
            if rollback_failed || cleanup_failed {
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

/// Validate bytecode selections during a dry-run without Git evidence or a plan.
pub(crate) fn validate_dry_run_selection(
    scope: &Scope,
    files: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<usize> {
    #[cfg(target_os = "linux")]
    {
        validate_dry_run_selection_linux(scope, files, cancel)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (scope, files, cancel);
        bail!("bytecode cleanup preview is supported only on Linux")
    }
}

#[cfg(not(target_os = "linux"))]
pub fn preview(_: &Scope, _: &Path, _: &AtomicBool) -> Result<BytecodePlan> {
    bail!("bytecode cleanup preview is supported only on Linux")
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn preview_guarded(
    _: &Scope,
    _: &Path,
    _: &AtomicBool,
) -> Result<(BytecodePlan, String)> {
    bail!("bytecode cleanup preview is supported only on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn preview_batch(_: &Scope, _: &[PathBuf], _: &AtomicBool) -> Result<BytecodeBatchPlan> {
    bail!("bytecode cleanup preview is supported only on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn remove(_: &Scope, _: &Path, _: &str, _: &AtomicBool) -> Result<&'static str> {
    bail!("bytecode cleanup is supported only on Linux")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    };

    fn system_elf_git() -> PathBuf {
        use std::io::Read;

        ["/usr/bin/git", "/bin/git"]
            .into_iter()
            .map(PathBuf::from)
            .chain(which::which("git"))
            .find(|path| {
                let Ok(mut file) = fs::File::open(path) else {
                    return false;
                };
                let mut magic = [0u8; 4];
                file.read_exact(&mut magic).is_ok() && magic == *b"\x7fELF"
            })
            .expect("ELF Git is required for bytecode tests")
    }

    fn fixture() -> (tempfile::TempDir, BytecodePlan) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        fs::set_permissions(&project, fs::Permissions::from_mode(0o700)).unwrap();
        let git = system_elf_git();
        let bin = root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
        fs::copy(&git, bin.join("git")).unwrap();
        fs::set_permissions(bin.join("git"), fs::Permissions::from_mode(0o755)).unwrap();
        let source_dir = project.join("src/pkg");
        let cache = source_dir.join("__pycache__");
        fs::create_dir_all(&cache).unwrap();
        for directory in [project.join("src"), source_dir.clone(), cache.clone()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let manifest = project.join("pyproject.toml");
        fs::write(&manifest, "[project]\n").unwrap();
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o644)).unwrap();
        let source = source_dir.join("example.py");
        fs::write(&source, "value = 1\n").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
        let run_git = |args: &[&str]| {
            let output = std::process::Command::new(&git)
                .env("HOME", root.path())
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .arg("-C")
                .arg(&project)
                .args([
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgSign=false",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run_git(&["init", "-q"]);
        run_git(&["add", "pyproject.toml", "src/pkg/example.py"]);
        run_git(&["commit", "-qm", "fixture"]);
        let metadata = fs::metadata(&source).unwrap();
        let file = cache.join("example.cpython-311.pyc");
        let mut bytes = Vec::from(3495u16.to_le_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(metadata.mtime() as u32).to_le_bytes());
        bytes.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
        bytes.push(0);
        fs::write(&file, &bytes).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let git_evidence_id = Some(
            crate::git_index::available_from_at(
                Path::new("bin/git"),
                Some(fs::File::open(root.path()).unwrap()),
                &AtomicBool::new(false),
                std::slice::from_ref(&project),
            )
            .unwrap()
            .expect("trusted relative Git")
            .evidence_id(),
        );
        let plan = BytecodePlan {
            project: project.clone(),
            manifest,
            cache,
            source,
            file,
            python: "3.11",
            invalidation: "timestamp",
            logical_bytes: bytes.len() as u64,
            preview_token: String::new(),
            git_evidence_id,
            warning: "fixture",
            scope: Scope {
                roots: vec![project],
                exclusions: vec![],
                older_than_seconds: None,
                enabled: None,
            },
        };
        (root, plan)
    }

    fn inspect(plan: &BytecodePlan) -> Result<Opened> {
        open_checked(
            &plan.project,
            &plan.manifest,
            &plan.cache,
            &plan.file,
            3495,
            &plan.source,
            &AtomicBool::new(false),
        )
    }

    fn test_git_clear(_: &BytecodePlan, _: &Path, _: &AtomicBool) -> Result<()> {
        Ok(())
    }

    #[test]
    fn bytecode_approval_token_binds_git_evidence_identity() {
        let (_root, plan) = fixture();
        let opened = inspect(&plan).unwrap();
        let first = token(
            &plan.scope,
            &plan.project,
            &plan.manifest,
            &plan.file,
            "git-evidence-a",
            &opened,
        )
        .unwrap();
        let second = token(
            &plan.scope,
            &plan.project,
            &plan.manifest,
            &plan.file,
            "git-evidence-b",
            &opened,
        )
        .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn bytecode_filenames_preserve_arbitrary_python_source_stems() {
        for (filename, source_stem) in [
            ("package.module.cpython-311.pyc", "package.module"),
            ("non-module-name.cpython-311.opt-1.pyc", "non-module-name"),
            ("módulo.cpython-311.pyc", "módulo"),
        ] {
            let (module, python, magic) = bytecode_name(filename).unwrap();
            assert_eq!(module, source_stem);
            assert_eq!(python, "3.11");
            assert_eq!(magic, 3495);
        }
        assert!(bytecode_name(".cpython-311.pyc").is_err());
    }

    #[test]
    fn validates_nested_directories_and_bytecode_identity() {
        let (_root, plan) = fixture();
        assert!(inspect(&plan).is_ok());
        let intermediate = plan.project.join("src");
        fs::set_permissions(&intermediate, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(inspect(&plan).is_err());
        fs::set_permissions(&intermediate, fs::Permissions::from_mode(0o755)).unwrap();
        let link = plan.project.join("linked.pyc");
        fs::hard_link(&plan.file, &link).unwrap();
        assert!(inspect(&plan).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_file(&plan.source).unwrap();
        symlink("other.py", &plan.source).unwrap();
        assert!(inspect(&plan).is_err());
        assert!(bytecode_name("example.cpython-311.opt-1.pyc").is_ok());
        assert_eq!(bytecode_name("example.cpython-314.pyc").unwrap().2, 3627);
        assert_eq!(bytecode_name("example.cpython-315.pyc").unwrap().2, 3666);
        assert_eq!(bytecode_name("example.cpython-316.pyc").unwrap().2, 3706);
        assert!(bytecode_name("example.cpython-317.pyc").is_err());
    }

    #[test]
    fn listing_is_bounded_read_only_and_skips_unsupported_or_linked_entries() {
        let (_root, plan) = fixture();
        let unsupported = plan.cache.join("other.cpython-317.pyc");
        fs::write(&unsupported, "keep").unwrap();
        symlink(&plan.file, plan.cache.join("linked.cpython-311.pyc")).unwrap();
        assert_eq!(
            list(&plan.cache, &AtomicBool::new(false)).unwrap(),
            vec![plan.file.clone()]
        );
        assert!(list(&plan.cache, &AtomicBool::new(true)).is_err());
        assert!(plan.file.exists());
        assert_eq!(fs::read(&unsupported).unwrap(), b"keep");
    }

    #[test]
    fn recent_cpython_headers_require_the_exact_magic() {
        let (_root, plan) = fixture();
        let original = fs::read(&plan.file).unwrap();
        for magic in [3627u16, 3666, 3706] {
            let mut bytes = original.clone();
            bytes[..2].copy_from_slice(&magic.to_le_bytes());
            fs::write(&plan.file, bytes).unwrap();
            assert!(
                open_checked(
                    &plan.project,
                    &plan.manifest,
                    &plan.cache,
                    &plan.file,
                    magic,
                    &plan.source,
                    &AtomicBool::new(false)
                )
                .is_ok()
            );
            assert!(inspect(&plan).is_err());
        }
    }

    #[test]
    fn validates_hash_based_headers_and_source_contents() {
        let (_root, plan) = fixture();
        let mut bytes = Vec::from(3706u16.to_le_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&3u32.to_le_bytes());
        // Generated by CPython 3.16a1 _imp.source_hash for b"value = 1\n".
        bytes.extend_from_slice(&[0xd6, 0x4d, 0x22, 0x49, 0xea, 0x36, 0xbb, 0x95]);
        bytes.push(0);
        for (flags, expected) in [(3u32, "hash-checked"), (1, "hash-unchecked")] {
            bytes[4..8].copy_from_slice(&flags.to_le_bytes());
            fs::write(&plan.file, &bytes).unwrap();
            let result = open_checked(
                &plan.project,
                &plan.manifest,
                &plan.cache,
                &plan.file,
                3706,
                &plan.source,
                &AtomicBool::new(false),
            )
            .unwrap();
            assert_eq!(result.invalidation, expected);
        }
        fs::write(&plan.source, "value = 2\n").unwrap();
        assert!(
            open_checked(
                &plan.project,
                &plan.manifest,
                &plan.cache,
                &plan.file,
                3706,
                &plan.source,
                &AtomicBool::new(false)
            )
            .is_err()
        );
        fs::write(&plan.source, "value = 1\n").unwrap();
        bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
        fs::write(&plan.file, &bytes).unwrap();
        assert!(
            open_checked(
                &plan.project,
                &plan.manifest,
                &plan.cache,
                &plan.file,
                3706,
                &plan.source,
                &AtomicBool::new(false)
            )
            .is_err()
        );
        bytes[4..8].copy_from_slice(&3u32.to_le_bytes());
        fs::write(&plan.file, &bytes).unwrap();
        assert!(
            open_checked(
                &plan.project,
                &plan.manifest,
                &plan.cache,
                &plan.file,
                3706,
                &plan.source,
                &AtomicBool::new(true)
            )
            .is_err()
        );
        fs::OpenOptions::new()
            .write(true)
            .open(&plan.source)
            .unwrap()
            .set_len(64 * 1024 * 1024 + 1)
            .unwrap();
        let error = open_checked(
            &plan.project,
            &plan.manifest,
            &plan.cache,
            &plan.file,
            3706,
            &plan.source,
            &AtomicBool::new(false),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("64 MiB"));
    }

    #[test]
    #[allow(deprecated)]
    fn python_310_hash_matches_standard_siphash24() {
        use std::hash::{Hasher, SipHasher};
        let (_root, plan) = fixture();
        let key = u32::from_le_bytes([0x6f, 0x0d, b'\r', b'\n']) as u64;
        for len in [0, 1, 7, 8, 9, 256, 65537] {
            let source = (0..len).map(|i| i as u8).collect::<Vec<_>>();
            fs::write(&plan.source, &source).unwrap();
            let mut hasher = SipHasher::new_with_keys(key, 0);
            hasher.write(&source);
            let mut bytes = Vec::from(3439u16.to_le_bytes());
            bytes.extend_from_slice(b"\r\n");
            bytes.extend_from_slice(&3u32.to_le_bytes());
            bytes.extend_from_slice(&hasher.finish().to_le_bytes());
            bytes.push(0);
            fs::write(&plan.file, &bytes).unwrap();
            assert!(
                open_checked(
                    &plan.project,
                    &plan.manifest,
                    &plan.cache,
                    &plan.file,
                    3439,
                    &plan.source,
                    &AtomicBool::new(false)
                )
                .is_ok(),
                "source length {len}"
            );
        }
    }

    #[test]
    fn removes_only_the_reviewed_file_and_preserves_source() {
        let (_root, plan) = fixture();
        let opened = inspect(&plan).unwrap();
        assert_eq!(
            remove_opened(
                &plan,
                opened,
                &AtomicBool::new(false),
                &test_git_clear,
                || {},
                || {},
                &|| Ok(())
            )
            .unwrap(),
            "verified_absent"
        );
        assert!(!plan.file.exists());
        assert_eq!(fs::read_to_string(&plan.source).unwrap(), "value = 1\n");
        assert_eq!(fs::read_dir(&plan.cache).unwrap().count(), 0);
    }

    #[test]
    fn restores_changed_file_after_staging() {
        let (_root, plan) = fixture();
        let opened = inspect(&plan).unwrap();
        let result = remove_opened(
            &plan,
            opened,
            &AtomicBool::new(false),
            &test_git_clear,
            || {
                let private = fs::read_dir(&plan.cache)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".upkit-bytecode-")
                    })
                    .unwrap();
                fs::write(private.join("item"), "changed").unwrap();
            },
            || {},
            &|| Ok(()),
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&plan.file).unwrap(), b"changed");
        assert_eq!(fs::read_to_string(&plan.source).unwrap(), "value = 1\n");
        assert_eq!(fs::read_dir(&plan.cache).unwrap().count(), 1);
    }

    #[test]
    fn restores_bytecode_if_source_is_replaced_during_removal() {
        let (_root, plan) = fixture();
        let opened = inspect(&plan).unwrap();
        let result = remove_opened(
            &plan,
            opened,
            &AtomicBool::new(false),
            &test_git_clear,
            || {
                fs::rename(&plan.source, plan.source.with_extension("old")).unwrap();
                fs::write(&plan.source, "replacement").unwrap();
            },
            || {},
            &|| Ok(()),
        );
        assert!(result.is_err());
        assert!(plan.file.exists());
        assert_eq!(fs::read_to_string(&plan.source).unwrap(), "replacement");
        assert_eq!(
            fs::read_to_string(plan.source.with_extension("old")).unwrap(),
            "value = 1\n"
        );
    }

    #[test]
    fn restores_bytecode_if_scheduled_policy_changes_after_staging() {
        let (_root, plan) = fixture();
        let opened = inspect(&plan).unwrap();
        let changed = AtomicBool::new(false);
        let result = remove_opened(
            &plan,
            opened,
            &AtomicBool::new(false),
            &test_git_clear,
            || changed.store(true, Ordering::Relaxed),
            || {},
            &|| {
                if changed.load(Ordering::Relaxed) {
                    bail!("policy changed");
                }
                Ok(())
            },
        );
        assert!(result.unwrap_err().to_string().contains("policy changed"));
        assert!(plan.file.exists());
        assert_eq!(fs::read_dir(&plan.cache).unwrap().count(), 1);
    }

    #[test]
    fn restores_bytecode_if_quarantined_file_changes_after_git_clearance() {
        let (_root, plan) = fixture();
        let opened = inspect(&plan).unwrap();
        let result = remove_opened(
            &plan,
            opened,
            &AtomicBool::new(false),
            &test_git_clear,
            || {},
            || {
                let private = fs::read_dir(&plan.cache)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".upkit-bytecode-")
                    })
                    .unwrap();
                fs::write(private.join("item"), "changed after Git").unwrap();
            },
            &|| Ok(()),
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&plan.file).unwrap(), b"changed after Git");
        assert_eq!(fs::read_to_string(&plan.source).unwrap(), "value = 1\n");
        assert_eq!(fs::read_dir(&plan.cache).unwrap().count(), 1);
    }

    #[test]
    fn refuses_cancellation_before_removal() {
        let (_root, plan) = fixture();
        let opened = inspect(&plan).unwrap();
        assert!(
            remove_opened(
                &plan,
                opened,
                &AtomicBool::new(true),
                &test_git_clear,
                || {},
                || {},
                &|| Ok(())
            )
            .is_err()
        );
        assert!(plan.file.exists());
        assert_eq!(fs::read_dir(&plan.cache).unwrap().count(), 1);
    }
}
