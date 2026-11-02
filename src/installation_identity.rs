//! Per-install receipts used by managed tool cleanup.
//!
//! A seal is written only into a fresh private `TempDir` created by an
//! installer. It binds the stage inode and complete extracted tree, so old
//! tool roots and user additions are never adopted by scanning.

#[cfg(unix)]
use anyhow::Context;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    sync::atomic::Ordering,
};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use crate::ToolKind;

#[cfg(unix)]
const INSTALL_MARKER: &str = ".upkit-install.json";
#[cfg(unix)]
const LINK_RECEIPTS: &str = ".upkit-managed-links";
#[cfg(unix)]
const MAX_MARKER_BYTES: u64 = 4096;
#[cfg(unix)]
const MAX_TREE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
#[cfg(unix)]
const MAX_TREE_ENTRIES: usize = 1_000_000;
#[cfg(unix)]
const MAX_TREE_DEPTH: usize = 256;
#[cfg(unix)]
const MAX_LINK_RECEIPTS: usize = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Seal {
    pub tool: String,
    pub version: String,
    pub stage_name: String,
    pub root_identity: RootIdentity,
    pub logical_bytes: u64,
    pub tree_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootIdentity {
    device: u64,
    file: u64,
    owner: u32,
    mode: u32,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkRole {
    Active,
    Binary,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkIdentity {
    pub device: u64,
    pub file: u64,
    pub owner: u32,
    pub mode: u32,
    pub links: u64,
    pub size: u64,
    pub mtime: i64,
    pub mtime_ns: i64,
    pub ctime: i64,
    pub ctime_ns: i64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RecordedLink {
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    #[serde(serialize_with = "serialize_path")]
    pub target: PathBuf,
    pub role: LinkRole,
    pub identity: LinkIdentity,
}

/// A bound that stopped verification.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerificationLimit {
    Bytes,
    Entries,
    Depth,
}

/// Aggregate budget for read-only seal verification. A caller may reuse it to
/// cap work across multiple installations.
#[cfg(unix)]
pub(crate) struct VerificationBudget {
    pub(crate) remaining_bytes: u64,
    pub(crate) remaining_entries: usize,
    max_depth: usize,
    pub(crate) limit_hit: Option<VerificationLimit>,
}

#[cfg(unix)]
impl VerificationBudget {
    pub(crate) fn new(max_bytes: u64, max_entries: usize, max_depth: usize) -> Self {
        Self {
            remaining_bytes: max_bytes,
            remaining_entries: max_entries,
            max_depth,
            limit_hit: None,
        }
    }
}

#[cfg(unix)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    seal: Seal,
}

#[cfg(unix)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkIndex {
    format: u32,
    tool: String,
    root_identity: RootIdentity,
    bindir_identity: RootIdentity,
}

#[cfg(unix)]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkReceipt {
    format: u32,
    tool: String,
    root_identity: RootIdentity,
    path: String,
    target: String,
    role: LinkRole,
    bindir_identity: RootIdentity,
    identity: LinkIdentity,
}

/// Seal an installer-owned, fresh staging directory before it is activated.
/// The directory must still be a private `TempDir` direct child of `tool_root`.
#[cfg(unix)]
pub fn seal(
    tool_root: &Path,
    stage: &tempfile::TempDir,
    tool: ToolKind,
    version: &str,
) -> Result<Seal> {
    if !matches!(
        tool,
        ToolKind::Go
            | ToolKind::Node
            | ToolKind::Python
            | ToolKind::Flutter
            | ToolKind::Java
            | ToolKind::Dotnet
    ) {
        bail!("this tool does not use Upkit-owned versioned installation roots");
    }
    if version.is_empty()
        || version.len() > 128
        || version.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("installation version identifier is invalid");
    }
    let stage_path = stage.path();
    let root_identity = validate_stage(tool_root, stage_path)?;
    let marker = stage_path.join(INSTALL_MARKER);
    match fs::symlink_metadata(&marker) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect installation identity marker"),
        Ok(_) => bail!("staging tree already contains the reserved Upkit identity marker"),
    }
    let stage_name = stage_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("installation staging directory name is not UTF-8")?
        .to_string();
    let cancel = AtomicBool::new(false);
    let (logical_bytes, tree_sha256) = tree_digest(stage_path, false, &cancel)?;
    let seal = Seal {
        tool: tool.as_str().to_owned(),
        version: version.to_owned(),
        stage_name,
        root_identity,
        logical_bytes,
        tree_sha256,
    };
    let manifest = serde_json::to_vec(&Manifest {
        format: 1,
        seal: seal.clone(),
    })?;
    if manifest.len() as u64 > MAX_MARKER_BYTES {
        bail!("installation identity marker is oversized");
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .context("create installation identity marker without replacing existing data")?;
    set_private_file(&file)?;
    file.write_all(&manifest)?;
    file.sync_all()?;
    File::open(stage_path)?.sync_all()?;
    Ok(seal)
}

#[cfg(not(unix))]
pub fn seal(
    _tool_root: &Path,
    _stage: &tempfile::TempDir,
    _tool: ToolKind,
    _version: &str,
) -> Result<Seal> {
    bail!("installation seals are supported only on Unix")
}

/// Inspect and fully verify one sealed install that is a direct child of its tool root.
#[cfg(unix)]
pub fn inspect(tool_root: &Path, path: &Path, tool: ToolKind) -> Result<Seal> {
    inspect_with_cancel(tool_root, path, tool, &AtomicBool::new(false))
}

#[cfg(not(unix))]
pub fn inspect(_tool_root: &Path, _path: &Path, _tool: ToolKind) -> Result<Seal> {
    bail!("installation seals are supported only on Unix")
}

#[cfg(unix)]
pub fn inspect_with_cancel(
    tool_root: &Path,
    path: &Path,
    tool: ToolKind,
    cancel: &AtomicBool,
) -> Result<Seal> {
    inspect_with_budget(
        tool_root,
        path,
        tool,
        cancel,
        &mut VerificationBudget::new(MAX_TREE_BYTES, MAX_TREE_ENTRIES, MAX_TREE_DEPTH),
    )
}

#[cfg(unix)]
pub(crate) fn inspect_with_budget(
    tool_root: &Path,
    path: &Path,
    tool: ToolKind,
    cancel: &AtomicBool,
    budget: &mut VerificationBudget,
) -> Result<Seal> {
    budget.limit_hit = None;
    if cancel.load(Ordering::Relaxed) {
        bail!("installation identity verification cancelled");
    }
    let root = plain_directory(tool_root)?;
    if root != tool_root {
        bail!("tool root must be canonical before inspecting an installation seal");
    }
    if path.parent() != Some(tool_root) || path.canonicalize()? != path {
        bail!("sealed installation must be a canonical direct child of its tool root");
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("installation directory name is not UTF-8")?;
    if !name.starts_with("install-") {
        bail!("installation path is not an Upkit staging directory");
    }
    let seal = read_manifest(path)?;
    if seal.tool != tool.as_str() || seal.stage_name != name {
        bail!("installation seal belongs to a different tool or staging path");
    }
    if root_identity(&fs::symlink_metadata(path)?)? != seal.root_identity {
        bail!("sealed installation directory identity changed");
    }
    verify_at_with_budget(path, &seal, cancel, budget)?;
    Ok(seal)
}

#[cfg(not(unix))]
pub fn inspect_with_cancel(
    _tool_root: &Path,
    _path: &Path,
    _tool: ToolKind,
    _cancel: &AtomicBool,
) -> Result<Seal> {
    bail!("installation seals are supported only on Unix")
}

/// Verify a seal after the reviewed directory has been moved to quarantine.
#[cfg(unix)]
pub fn verify_at(path: &Path, expected: &Seal) -> Result<()> {
    verify_at_with_cancel(path, expected, &AtomicBool::new(false))
}

#[cfg(not(unix))]
pub fn verify_at(_path: &Path, _expected: &Seal) -> Result<()> {
    bail!("installation seals are supported only on Unix")
}

#[cfg(unix)]
pub fn verify_at_with_cancel(path: &Path, expected: &Seal, cancel: &AtomicBool) -> Result<()> {
    verify_at_with_budget(
        path,
        expected,
        cancel,
        &mut VerificationBudget::new(MAX_TREE_BYTES, MAX_TREE_ENTRIES, MAX_TREE_DEPTH),
    )
}

#[cfg(unix)]
fn verify_at_with_budget(
    path: &Path,
    expected: &Seal,
    cancel: &AtomicBool,
    budget: &mut VerificationBudget,
) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        bail!("installation identity verification cancelled");
    }
    let metadata = fs::symlink_metadata(path).context("inspect sealed installation")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("sealed installation is no longer a plain directory");
    }
    if root_identity(&metadata)? != expected.root_identity {
        bail!("sealed installation directory identity changed");
    }
    let marker_path = path.join(INSTALL_MARKER);
    let marker_identity = fs::symlink_metadata(&marker_path)?;
    let actual = read_manifest(path)?;
    if actual != *expected {
        bail!("installation identity marker changed");
    }
    let (logical_bytes, digest) = tree_digest_with_budget(path, true, cancel, budget)?;
    if logical_bytes != expected.logical_bytes
        || digest != expected.tree_sha256
        || !same_file_metadata(&marker_identity, &fs::symlink_metadata(marker_path)?)
    {
        bail!("sealed installation contents changed");
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn verify_at_with_cancel(_path: &Path, _expected: &Seal, _cancel: &AtomicBool) -> Result<()> {
    bail!("installation seals are supported only on Unix")
}

/// Record a newly-created active link. Existing links are never adopted.
#[cfg(unix)]
pub fn record_active_link(tool_root: &Path, bindir: &Path, tool: ToolKind) -> Result<()> {
    let path = tool_root.join("active");
    let target = fs::read_link(&path).context("read newly activated tool link")?;
    record_link(tool_root, bindir, tool, &path, &target, LinkRole::Active)
}

#[cfg(not(unix))]
pub fn record_active_link(_tool_root: &Path, _bindir: &Path, _tool: ToolKind) -> Result<()> {
    bail!("managed link receipts are supported only on Unix")
}

/// Record only binary links created by this update. `links` comes from the link helper's
/// create-only result; pre-existing matching symlinks are intentionally omitted.
#[cfg(unix)]
pub fn record_created_links(
    tool_root: &Path,
    bindir: &Path,
    tool: ToolKind,
    links: &[(PathBuf, PathBuf)],
) -> Result<()> {
    for (path, target) in links {
        record_link(tool_root, bindir, tool, path, target, LinkRole::Binary)?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn record_created_links(
    _tool_root: &Path,
    _bindir: &Path,
    _tool: ToolKind,
    _links: &[(PathBuf, PathBuf)],
) -> Result<()> {
    bail!("managed link receipts are supported only on Unix")
}

/// Return receipts that still identify the exact Upkit-created symlink inode and target.
#[cfg(unix)]
pub fn recorded_links(
    tool_root: &Path,
    bindir: &Path,
    tool: ToolKind,
) -> Result<Vec<RecordedLink>> {
    let root_id = root_identity(&fs::symlink_metadata(plain_directory(tool_root)?)?)?;
    let directory = tool_root.join(LINK_RECEIPTS);
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if has_install_marker(tool_root)? {
                bail!(
                    "sealed installation is missing its managed link receipt index; inspect the original binary directory before cleanup"
                );
            }
            return Ok(Vec::new());
        }
        Err(error) => return Err(error).context("inspect managed link receipt directory"),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() || !private_directory(&metadata) {
        bail!("managed link receipt directory is untrusted; inspect it before cleanup");
    }
    let index_path = directory.join("index.json");
    let index = read_bounded_json::<LinkIndex>(&index_path, MAX_MARKER_BYTES)
        .context("read managed link receipt index")?;
    let bindir_identity = canonical_directory_identity(bindir)
        .context("resolve managed binary directory identity")?;
    if index.format != 1
        || index.tool != tool.as_str()
        || index.root_identity != root_id
        || index.bindir_identity != bindir_identity
    {
        bail!(
            "managed receipt identity changed; inspect the original binary directory before cleanup"
        );
    }

    let mut links = Vec::new();
    let mut count = 0usize;
    for entry in fs::read_dir(&directory).context("list managed link receipts")? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "index.json" {
            continue;
        }
        let filename = name
            .to_str()
            .context("managed link receipt name is not UTF-8")?;
        if !filename.starts_with("link-") || !filename.ends_with(".json") {
            bail!("unexpected file in managed link receipt directory");
        }
        count += 1;
        if count > MAX_LINK_RECEIPTS {
            bail!("managed link receipt directory contains too many entries");
        }
        let receipt = read_bounded_json::<LinkReceipt>(&entry.path(), MAX_MARKER_BYTES)
            .context("read managed link receipt")?;
        if receipt.format != 1
            || receipt.tool != tool.as_str()
            || receipt.root_identity != root_id
            || receipt.bindir_identity != bindir_identity
        {
            bail!("managed link receipt identity is inconsistent; inspect it before cleanup");
        }
        let (Ok(path_token), Ok(target_relative)) =
            (decode_path(&receipt.path), decode_path(&receipt.target))
        else {
            bail!("managed link receipt path is malformed; inspect it before cleanup");
        };
        if target_relative.is_absolute()
            || target_relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("managed link receipt target is malformed; inspect it before cleanup");
        }
        let path = match receipt.role {
            LinkRole::Active if path_token == Path::new("active") => tool_root.join(path_token),
            LinkRole::Binary
                if path_token.components().count() == 1
                    && matches!(
                        path_token.components().next(),
                        Some(std::path::Component::Normal(_))
                    ) =>
            {
                bindir.join(path_token)
            }
            _ => bail!("managed link receipt role/path mismatch; inspect it before cleanup"),
        };
        let target = tool_root.join(target_relative);
        if !valid_link(tool_root, bindir, tool, &path, &target, receipt.role) {
            bail!("managed link receipt points outside expected paths; inspect it before cleanup");
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("inspect recorded managed link"),
        };
        if !metadata.file_type().is_symlink() {
            continue;
        }
        let actual_target = fs::read_link(&path).context("read recorded managed link")?;
        if actual_target != target || link_identity(&metadata)? != receipt.identity {
            continue;
        }
        links.push(RecordedLink {
            path,
            target,
            role: receipt.role,
            identity: receipt.identity,
        });
    }
    links.sort_by(|a, b| a.path.cmp(&b.path));
    links.dedup_by(|a, b| a.path == b.path && a.identity == b.identity);
    Ok(links)
}

#[cfg(not(unix))]
pub fn recorded_links(
    _tool_root: &Path,
    _bindir: &Path,
    _tool: ToolKind,
) -> Result<Vec<RecordedLink>> {
    bail!("managed link receipts are supported only on Unix")
}

#[cfg(unix)]
fn record_link(
    tool_root: &Path,
    bindir: &Path,
    tool: ToolKind,
    path: &Path,
    target: &Path,
    role: LinkRole,
) -> Result<()> {
    #[cfg(not(unix))]
    bail!("managed link receipts require verified Unix ownership metadata");
    let root_meta = fs::symlink_metadata(plain_directory(tool_root)?)?;
    let root_id = root_identity(&root_meta)?;
    if !valid_link(tool_root, bindir, tool, path, target, role) {
        bail!("refusing to record a link outside the expected managed tool paths");
    }
    let bindir_identity = canonical_directory_identity(bindir)?;
    let before = fs::symlink_metadata(path).context("inspect newly-created tool link")?;
    if !before.file_type().is_symlink() || fs::read_link(path)? != target {
        bail!("new tool link does not match its expected target");
    }
    let identity = link_identity(&before)?;
    if link_identity(&fs::symlink_metadata(path)?)? != identity {
        bail!("new tool link changed while recording its identity");
    }
    let directory = ensure_receipt_directory(tool_root, tool, &root_id, &bindir_identity)?;
    let receipt = LinkReceipt {
        format: 1,
        tool: tool.as_str().to_owned(),
        root_identity: root_id,
        path: encode_path(match role {
            LinkRole::Active => Path::new("active"),
            LinkRole::Binary => Path::new(path.file_name().context("binary link has no name")?),
        }),
        target: encode_path(
            target
                .strip_prefix(tool_root)
                .context("link target is outside tool root")?,
        ),
        role,
        bindir_identity,
        identity,
    };
    let bytes = serde_json::to_vec(&receipt)?;
    if bytes.len() as u64 > MAX_MARKER_BYTES {
        bail!("managed link receipt is oversized");
    }
    let mut file = tempfile::Builder::new()
        .prefix("link-")
        .suffix(".json")
        .tempfile_in(directory)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.keep().context("keep managed link receipt")?;
    Ok(())
}

#[cfg(unix)]
fn ensure_receipt_directory(
    tool_root: &Path,
    tool: ToolKind,
    root_id: &RootIdentity,
    bindir_id: &RootIdentity,
) -> Result<PathBuf> {
    let directory = tool_root.join(LINK_RECEIPTS);
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(&directory) {
        Ok(()) => {
            set_private_directory(&directory)?;
            let index = LinkIndex {
                format: 1,
                tool: tool.as_str().to_owned(),
                root_identity: root_id.clone(),
                bindir_identity: bindir_id.clone(),
            };
            let path = directory.join("index.json");
            let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
            set_private_file(&file)?;
            serde_json::to_writer(&mut file, &index)?;
            file.sync_all()?;
            #[cfg(unix)]
            File::open(&directory)?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("create managed link receipt directory"),
    }
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || !private_directory(&metadata) {
        bail!("managed link receipt directory is not private and user-owned");
    }
    let index: LinkIndex = read_bounded_json(&directory.join("index.json"), MAX_MARKER_BYTES)?;
    if index.format != 1
        || index.tool != tool.as_str()
        || index.root_identity != *root_id
        || index.bindir_identity != *bindir_id
    {
        // shortcut: changed bindirs block cleanup; add prior-path receipts when bindir migration is needed.
        bail!(
            "managed link receipts do not match this binary directory; inspect it before cleanup"
        );
    }
    Ok(directory)
}

#[cfg(unix)]
fn valid_link(
    tool_root: &Path,
    bindir: &Path,
    tool: ToolKind,
    path: &Path,
    target: &Path,
    role: LinkRole,
) -> bool {
    if !path.is_absolute()
        || !target.is_absolute()
        || !target.starts_with(tool_root)
        || target
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return false;
    }
    match role {
        LinkRole::Active => path == tool_root.join("active") && target != tool_root,
        LinkRole::Binary => {
            !path.starts_with(tool_root)
                && path.parent() == Some(bindir)
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        ["linux", "macos", "windows"].iter().any(|os| {
                            crate::infrastructure::tool_bin_names_for_os(tool, os).contains(&name)
                        })
                    })
        }
    }
}

#[cfg(unix)]
fn validate_stage(tool_root: &Path, stage: &Path) -> Result<RootIdentity> {
    if plain_directory(tool_root)? != tool_root || stage.parent() != Some(tool_root) {
        bail!("installation staging must be a direct child of the canonical tool root");
    }
    let name = stage
        .file_name()
        .and_then(|name| name.to_str())
        .context("installation staging directory name is not UTF-8")?;
    if !name.starts_with("install-") {
        bail!("installation staging directory is not installer-created");
    }
    let metadata = fs::symlink_metadata(stage)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || !private_directory(&metadata) {
        bail!("installation staging directory is not a private, user-owned directory");
    }
    root_identity(&metadata)
}

#[cfg(unix)]
fn read_manifest(path: &Path) -> Result<Seal> {
    let manifest: Manifest = read_bounded_json(&path.join(INSTALL_MARKER), MAX_MARKER_BYTES)?;
    if manifest.format != 1
        || manifest.seal.version.is_empty()
        || manifest.seal.version.len() > 128
        || manifest
            .seal
            .version
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || manifest.seal.tree_sha256.len() != 64
        || !manifest
            .seal
            .tree_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("unsupported installation identity marker version");
    }
    Ok(manifest.seal)
}

#[cfg(unix)]
fn read_bounded_json<T: for<'de> Deserialize<'de>>(path: &Path, limit: u64) -> Result<T> {
    let before = fs::symlink_metadata(path).context("inspect identity receipt")?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > limit {
        bail!("identity receipt is not a bounded regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.nlink() != 1 || before.uid() != current_uid() || before.mode() & 0o077 != 0 {
            bail!("identity receipt must be private, user-owned, and single-linked");
        }
    }
    let file = File::open(path)?;
    if !same_file_metadata(&before, &file.metadata()?) {
        bail!("identity receipt changed while opening");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit || !same_file_metadata(&before, &fs::symlink_metadata(path)?) {
        bail!("identity receipt changed while reading");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(unix)]
fn tree_digest(root: &Path, skip_marker: bool, cancel: &AtomicBool) -> Result<(u64, String)> {
    tree_digest_with_budget(
        root,
        skip_marker,
        cancel,
        &mut VerificationBudget::new(MAX_TREE_BYTES, MAX_TREE_ENTRIES, MAX_TREE_DEPTH),
    )
}

#[cfg(unix)]
fn tree_digest_with_budget(
    root: &Path,
    skip_marker: bool,
    cancel: &AtomicBool,
    budget: &mut VerificationBudget,
) -> Result<(u64, String)> {
    use std::ffi::OsString;

    struct Frame {
        path: PathBuf,
        relative: PathBuf,
        identity: LinkIdentity,
        entries: std::vec::IntoIter<OsString>,
    }

    fn read_names(
        path: &Path,
        skip_marker: bool,
        relative: &Path,
        cancel: &AtomicBool,
        max_names: usize,
        budget: &mut VerificationBudget,
    ) -> Result<Vec<OsString>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(path)? {
            if cancel.load(Ordering::Relaxed) {
                bail!("installation identity verification cancelled");
            }
            let entry = entry?;
            let name = entry.file_name();
            if skip_marker && relative.as_os_str().is_empty() && name == INSTALL_MARKER {
                continue;
            }
            if names.len() >= max_names {
                budget.limit_hit = Some(VerificationLimit::Entries);
                bail!("installation verification entry budget exceeded");
            }
            names.push(name);
        }
        names.sort();
        Ok(names)
    }

    let root_meta = fs::symlink_metadata(root)?;
    if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
        bail!("installation tree root is not a plain directory");
    }
    if !private_directory(&root_meta) {
        bail!("installation tree root is not a private user-owned directory");
    }
    let root_id = link_identity(&root_meta)?;
    #[cfg(target_os = "linux")]
    {
        let mountinfo = fs::read("/proc/self/mountinfo")
            .context("read mount table before verifying installation identity")?;
        if crate::application::mount_points(&mountinfo)?
            .iter()
            .any(|mount| mount != root && mount.starts_with(root))
        {
            bail!("installation tree contains a mount point");
        }
    }
    let remaining_entries = budget.remaining_entries;
    let entries = read_names(
        root,
        skip_marker,
        Path::new(""),
        cancel,
        remaining_entries,
        budget,
    )?;
    let mut pending_names = entries.len();
    let mut stack = vec![Frame {
        path: root.to_path_buf(),
        relative: PathBuf::new(),
        identity: root_id.clone(),
        entries: entries.into_iter(),
    }];
    let mut hasher = Sha256::new();
    hasher.update(b"upkit-install-tree-v1");
    let mut logical_bytes = 0u64;
    let mut count = 0usize;

    loop {
        let depth = stack.len();
        let Some(frame) = stack.last_mut() else {
            break;
        };
        if cancel.load(Ordering::Relaxed) {
            bail!("installation identity verification cancelled");
        }
        if let Some(name) = frame.entries.next() {
            pending_names = pending_names.saturating_sub(1);
            if budget.remaining_entries == 0 {
                budget.limit_hit = Some(VerificationLimit::Entries);
                bail!("installation verification entry budget exceeded");
            }
            budget.remaining_entries -= 1;
            count += 1;
            if count > MAX_TREE_ENTRIES {
                budget.limit_hit = Some(VerificationLimit::Entries);
                bail!("installation tree exceeds safe traversal limits");
            }
            if depth > budget.max_depth {
                budget.limit_hit = Some(VerificationLimit::Depth);
                bail!("installation tree exceeds safe traversal limits");
            }
            let path = frame.path.join(&name);
            let relative = frame.relative.join(&name);
            let before = fs::symlink_metadata(&path)
                .with_context(|| format!("inspect installation entry {}", relative.display()))?;
            let private_entry = {
                #[cfg(unix)]
                {
                    if before.file_type().is_symlink() {
                        use std::os::unix::fs::MetadataExt;
                        // Symlink permission bits are ignored; ownership and target checks bind it.
                        before.uid() == current_uid()
                    } else {
                        private_owner(&before)
                    }
                }
                #[cfg(not(unix))]
                {
                    private_owner(&before)
                }
            };
            if !private_entry {
                bail!("installation tree contains an entry writable by other users");
            }
            let relative_bytes = path_bytes(&relative);
            hash_field(&mut hasher, &relative_bytes);
            let mode = entry_mode(&before);
            hasher.update(mode.to_be_bytes());
            hasher.update(before.len().to_be_bytes());
            let entry_identity = link_identity(&before)?;
            if entry_identity.device != root_id.device {
                bail!("installation tree crosses a filesystem boundary");
            }
            if before.is_dir() && !before.file_type().is_symlink() {
                hasher.update(b"d");
                let max_names = budget.remaining_entries.saturating_sub(pending_names);
                let names = read_names(&path, false, Path::new(""), cancel, max_names, budget)?;
                if !names.is_empty() && stack.len() >= budget.max_depth {
                    budget.limit_hit = Some(VerificationLimit::Depth);
                    bail!("installation tree exceeds safe traversal depth");
                }
                pending_names += names.len();
                stack.push(Frame {
                    path,
                    relative,
                    identity: entry_identity,
                    entries: names.into_iter(),
                });
            } else if before.is_file() {
                hasher.update(b"f");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if before.nlink() != 1 {
                        bail!("installation tree contains a hard-linked file");
                    }
                }
                if before.len() > budget.remaining_bytes {
                    budget.remaining_bytes = 0;
                    budget.limit_hit = Some(VerificationLimit::Bytes);
                    bail!("installation verification byte budget exceeded");
                }
                budget.remaining_bytes -= before.len();
                logical_bytes = logical_bytes
                    .checked_add(before.len())
                    .context("installation size overflow")?;
                let mut file = File::open(&path)
                    .with_context(|| format!("open installation file {}", relative.display()))?;
                let opened = file.metadata()?;
                if !same_file_metadata(&before, &opened) {
                    bail!("installation file changed while opening");
                }
                let mut remaining = before.len();
                let mut buffer = [0u8; 64 * 1024];
                while remaining > 0 {
                    if cancel.load(Ordering::Relaxed) {
                        bail!("installation identity verification cancelled");
                    }
                    let chunk_len = buffer.len().min(remaining as usize);
                    let count = file.read(&mut buffer[..chunk_len])?;
                    if count == 0 {
                        bail!("installation file was truncated while hashing");
                    }
                    hasher.update(&buffer[..count]);
                    remaining -= count as u64;
                }
                let mut extra = [0u8; 1];
                if file.read(&mut extra)? != 0
                    || !same_file_metadata(&before, &file.metadata()?)
                    || !same_file_metadata(&before, &fs::symlink_metadata(&path)?)
                {
                    bail!("installation file changed while hashing");
                }
            } else if before.file_type().is_symlink() {
                hasher.update(b"l");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if before.nlink() != 1 {
                        bail!("installation tree contains a hard-linked symbolic link");
                    }
                }
                let target = fs::read_link(&path)?;
                hash_field(&mut hasher, &path_bytes(&target));
                if !same_file_metadata(&before, &fs::symlink_metadata(&path)?) {
                    bail!("installation symbolic link changed while hashing");
                }
            } else {
                bail!("installation tree contains a special file");
            }
        } else {
            let finished = stack.pop().expect("nonempty traversal stack");
            if !same_frame_directory(&finished.identity, &fs::symlink_metadata(&finished.path)?)? {
                bail!("installation directory changed while hashing");
            }
        }
    }
    Ok((logical_bytes, hex::encode(hasher.finalize())))
}

#[cfg(unix)]
fn plain_directory(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).context("inspect tool root")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || !private_owner(&metadata) {
        bail!("tool root is not a user-owned, non-linked directory");
    }
    path.canonicalize().context("resolve tool root")
}

#[cfg(unix)]
fn canonical_directory_identity(path: &Path) -> Result<RootIdentity> {
    if !path.is_absolute() || path.canonicalize()? != path {
        bail!("managed binary directory must be canonical and absolute");
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || !private_owner(&metadata) {
        bail!("managed binary directory must be user-owned and non-linked");
    }
    root_identity(&metadata)
}

#[cfg(unix)]
fn has_install_marker(tool_root: &Path) -> Result<bool> {
    for entry in fs::read_dir(tool_root).context("check for sealed tool installations")? {
        let entry = entry?;
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("install-"))
        {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        match fs::symlink_metadata(entry.path().join(INSTALL_MARKER)) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).context("inspect possible installation identity marker");
            }
        }
    }
    Ok(false)
}

#[cfg(unix)]
fn root_identity(metadata: &fs::Metadata) -> Result<RootIdentity> {
    use std::os::unix::fs::MetadataExt;
    Ok(RootIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode() & 0o7777,
    })
}

#[cfg(unix)]
fn link_identity(metadata: &fs::Metadata) -> Result<LinkIdentity> {
    use std::os::unix::fs::MetadataExt;
    Ok(LinkIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        size: metadata.len(),
        mtime: metadata.mtime(),
        mtime_ns: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_ns: metadata.ctime_nsec(),
    })
}

#[cfg(unix)]
fn entry_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode() & 0o7777
}

#[cfg(unix)]
fn same_file_metadata(first: &fs::Metadata, second: &fs::Metadata) -> bool {
    link_identity(first).ok() == link_identity(second).ok()
}

#[cfg(unix)]
fn private_owner(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.uid() == current_uid() && metadata.mode() & 0o022 == 0
}

#[cfg(unix)]
fn private_directory(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.uid() == current_uid() && metadata.mode() & 0o077 == 0
}

#[cfg(unix)]
fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(unix)]
fn set_private_file(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(unix)]
fn encode_path(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    hex::encode(path.as_os_str().as_bytes())
}

#[cfg(unix)]
fn decode_path(path: &str) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(hex::decode(
        path,
    )?)))
}

fn serialize_path<S: serde::Serializer>(
    path: &Path,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    crate::sweep::JsonPath(path).serialize(serializer)
}

#[cfg(unix)]
fn same_frame_directory(expected: &LinkIdentity, actual: &fs::Metadata) -> Result<bool> {
    Ok(&link_identity(actual)? == expected)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn tool_root(parent: &Path, tool: ToolKind) -> PathBuf {
        let root = parent.join(tool.as_str());
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        }
        root
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn sealed_install_is_bound_to_its_fresh_tree_and_content() {
        let directory = tempfile::tempdir().unwrap();
        let root = tool_root(directory.path(), ToolKind::Node);
        let stage = crate::infrastructure::new_install_stage(&root).unwrap();
        fs::create_dir(stage.path().join("bin")).unwrap();
        set_mode(&stage.path().join("bin"), 0o755);
        fs::write(stage.path().join("bin/node"), b"verified binary").unwrap();
        set_mode(&stage.path().join("bin/node"), 0o644);

        let seal = seal(&root, &stage, ToolKind::Node, "24.0.0").unwrap();
        let path = stage.keep();
        assert_eq!(inspect(&root, &path, ToolKind::Node).unwrap(), seal);

        fs::write(path.join("bin/node"), b"user replacement").unwrap();
        assert!(inspect(&root, &path, ToolKind::Node).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn sealed_install_accepts_owned_internal_symlinks_and_rejects_target_changes() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let root = tool_root(directory.path(), ToolKind::Java);
        let stage = crate::infrastructure::new_install_stage(&root).unwrap();
        let bin = stage.path().join("bin");
        let lib = stage.path().join("lib");
        fs::create_dir(&bin).unwrap();
        fs::create_dir(&lib).unwrap();
        set_mode(&bin, 0o755);
        set_mode(&lib, 0o755);
        fs::write(lib.join("java"), b"fixture binary").unwrap();
        set_mode(&lib.join("java"), 0o644);
        fs::write(lib.join("other"), b"other binary").unwrap();
        set_mode(&lib.join("other"), 0o644);
        let link = bin.join("java");
        symlink("../lib/java", &link).unwrap();

        let seal = seal(&root, &stage, ToolKind::Java, "21.0.0").unwrap();
        let path = stage.keep();
        assert_eq!(inspect(&root, &path, ToolKind::Java).unwrap(), seal);

        fs::remove_file(&link).unwrap();
        symlink("../lib/other", &link).unwrap();
        assert!(inspect(&root, &path, ToolKind::Java).is_err());
    }

    #[test]
    fn legacy_roots_and_copied_markers_are_not_adopted() {
        let directory = tempfile::tempdir().unwrap();
        let root = tool_root(directory.path(), ToolKind::Go);
        let bindir = directory.path().join("bin");
        fs::create_dir(&bindir).unwrap();
        set_mode(&bindir, 0o755);
        let legacy = root.join("install-legacy");
        fs::create_dir(&legacy).unwrap();
        fs::write(legacy.join("VERSION"), b"user data").unwrap();
        assert!(inspect(&root, &legacy, ToolKind::Go).is_err());
        assert!(
            recorded_links(&root, &bindir, ToolKind::Go)
                .unwrap()
                .is_empty()
        );

        let stage = crate::infrastructure::new_install_stage(&root).unwrap();
        fs::write(stage.path().join("payload"), b"archive").unwrap();
        set_mode(&stage.path().join("payload"), 0o644);
        seal(&root, &stage, ToolKind::Go, "1.0.0").unwrap();
        let original = stage.keep();
        assert!(recorded_links(&root, &bindir, ToolKind::Go).is_err());
        let copy = root.join("install-copy");
        fs::create_dir(&copy).unwrap();
        fs::copy(original.join(INSTALL_MARKER), copy.join(INSTALL_MARKER)).unwrap();
        fs::copy(original.join("payload"), copy.join("payload")).unwrap();
        assert!(inspect(&root, &copy, ToolKind::Go).is_err());
    }

    #[test]
    fn seal_never_overwrites_an_archive_marker_or_accepts_cancelled_verification() {
        let directory = tempfile::tempdir().unwrap();
        let root = tool_root(directory.path(), ToolKind::Python);
        let stage = crate::infrastructure::new_install_stage(&root).unwrap();
        fs::write(stage.path().join(INSTALL_MARKER), b"archive data").unwrap();
        assert!(seal(&root, &stage, ToolKind::Python, "3.0.0").is_err());

        fs::remove_file(stage.path().join(INSTALL_MARKER)).unwrap();
        fs::write(stage.path().join("python"), b"verified").unwrap();
        set_mode(&stage.path().join("python"), 0o644);
        seal(&root, &stage, ToolKind::Python, "3.0.0").unwrap();
        let path = stage.keep();
        assert!(
            inspect_with_cancel(&root, &path, ToolKind::Python, &AtomicBool::new(true)).is_err()
        );
    }

    #[test]
    fn size_limit_only_disqualifies_the_seal() {
        let directory = tempfile::tempdir().unwrap();
        let root = tool_root(directory.path(), ToolKind::Java);
        let stage = crate::infrastructure::new_install_stage(&root).unwrap();
        let large_file = stage.path().join("large-file");
        File::create(&large_file)
            .unwrap()
            .set_len(MAX_TREE_BYTES + 1)
            .unwrap();
        set_mode(&large_file, 0o644);
        assert!(seal(&root, &stage, ToolKind::Java, "21.0.0").is_err());
        assert!(stage.path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn only_receipted_links_with_the_same_target_and_inode_are_returned() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let root = tool_root(directory.path(), ToolKind::Node);
        let bindir = directory.path().join("bin");
        fs::create_dir(&bindir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bindir, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let target = root.join("install-1/bin/node");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"binary").unwrap();
        let link = bindir.join("node");
        symlink(&target, &link).unwrap();

        assert!(
            recorded_links(&root, &bindir, ToolKind::Node)
                .unwrap()
                .is_empty()
        );
        record_link(
            &root,
            &bindir,
            ToolKind::Node,
            &link,
            &target,
            LinkRole::Binary,
        )
        .unwrap();
        let recorded = recorded_links(&root, &bindir, ToolKind::Node).unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].role, LinkRole::Binary);
        assert_eq!(recorded[0].target, target);
        let copied_bindir = directory.path().join("other-bin");
        fs::create_dir(&copied_bindir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&copied_bindir, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert!(recorded_links(&root, &copied_bindir, ToolKind::Node).is_err());
        let receipt_dir = root.join(LINK_RECEIPTS);
        let receipt = fs::read_dir(receipt_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("link-"))
            })
            .unwrap();
        let contents = fs::read_to_string(&receipt).unwrap();
        assert!(!contents.contains(directory.path().to_str().unwrap()));
        let index = root.join(LINK_RECEIPTS).join("index.json");
        let index_contents = fs::read(&index).unwrap();
        set_mode(&index, 0o644);
        assert!(recorded_links(&root, &bindir, ToolKind::Node).is_err());
        set_mode(&index, 0o600);
        fs::write(&index, b"corrupt index").unwrap();
        assert!(recorded_links(&root, &bindir, ToolKind::Node).is_err());
        fs::write(&index, index_contents).unwrap();

        fs::remove_file(&link).unwrap();
        let replacement = root.join("install-2/bin/node");
        fs::create_dir_all(replacement.parent().unwrap()).unwrap();
        fs::write(&replacement, b"other binary").unwrap();
        symlink(&replacement, &link).unwrap();
        assert!(
            recorded_links(&root, &bindir, ToolKind::Node)
                .unwrap()
                .is_empty()
        );
        set_mode(&receipt, 0o644);
        assert!(recorded_links(&root, &bindir, ToolKind::Node).is_err());
        set_mode(&receipt, 0o600);
        fs::write(&receipt, b"corrupt receipt").unwrap();
        assert!(recorded_links(&root, &bindir, ToolKind::Node).is_err());
    }
}
