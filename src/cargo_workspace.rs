//! Bounded, read-only evidence about Cargo workspaces for projects in selected scan roots.
#[cfg(target_os = "linux")]
use anyhow::{Result, anyhow};
use serde::Serialize;
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[derive(Clone, Debug, Serialize)]
pub struct WorkspaceEvidence {
    pub status: &'static str,
    #[serde(serialize_with = "crate::sweep::serialize_optional_path")]
    pub workspace_root: Option<PathBuf>,
    pub warning: &'static str,
    #[serde(skip)]
    proof: Option<String>,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    anchors: Option<WorkspaceAnchors>,
}

impl WorkspaceEvidence {
    pub(crate) fn proof(&self) -> Option<&str> {
        self.proof.as_deref()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn metadata_matches(&self) -> bool {
        self.anchors
            .as_ref()
            .is_some_and(WorkspaceAnchors::metadata_matches)
    }
}

impl WorkspaceEvidence {
    pub fn description(&self) -> String {
        format!(
            "{}{}; {}",
            self.status,
            self.workspace_root
                .as_deref()
                .map_or(String::new(), |root| format!(
                    " ({})",
                    crate::sweep::display_path(root)
                )),
            self.warning
        )
    }
}

const WARNING: &str = "Cargo workspace status is based on the readable manifest chain; package.workspace overrides are unresolved. This does not authorize cleanup.";
// shortcut: cap all Cargo ancestry manifests at 8 MiB; raise only if real manifests exceed it.
#[cfg(target_os = "linux")]
const MAX_ANCESTOR_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone)]
#[cfg(target_os = "linux")]
struct Workspace {
    members: Option<Vec<globset::GlobMatcher>>,
    exclude: Option<Vec<globset::GlobMatcher>>,
}

#[derive(Clone)]
#[cfg(target_os = "linux")]
struct Manifest {
    workspace: Option<Workspace>,
    has_workspace_override: bool,
    has_package: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ManifestIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct ManifestSnapshot {
    manifest: Manifest,
    identity: ManifestIdentity,
    content_hash: [u8; 32],
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
enum ReadManifest {
    Missing,
    Unavailable,
    Parsed(ManifestSnapshot),
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
struct WorkspaceAnchors {
    directories: Vec<(PathBuf, DirectoryIdentity)>,
    manifests: Vec<(PathBuf, Option<ManifestIdentity>)>,
}

#[cfg(target_os = "linux")]
impl WorkspaceAnchors {
    fn metadata_matches(&self) -> bool {
        self.directories
            .iter()
            .all(|(path, expected)| directory_identity(path).as_ref() == Some(expected))
            && self.manifests.iter().all(|(path, expected)| {
                matches!(manifest_identity(path), Ok(actual) if actual.as_ref() == expected.as_ref())
            })
    }
}

#[cfg(target_os = "linux")]
fn directory_identity(path: &Path) -> Option<DirectoryIdentity> {
    use std::os::unix::fs::MetadataExt;
    let descriptor = rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .ok()?;
    let metadata = std::fs::File::from(descriptor).metadata().ok()?;
    metadata.is_dir().then(|| DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
    })
}

#[cfg(target_os = "linux")]
fn manifest_identity(path: &Path) -> Result<Option<ManifestIdentity>> {
    use std::os::unix::fs::MetadataExt;
    let descriptor = match rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(anyhow!("could not inspect Cargo manifest: {error}")),
    };
    let metadata = std::fs::File::from(descriptor)
        .metadata()
        .map_err(|error| anyhow!("could not inspect Cargo manifest: {error}"))?;
    if !metadata.is_file() {
        return Err(anyhow!("Cargo manifest is not a regular file"));
    }
    Ok(Some(ManifestIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        modified_seconds: metadata.mtime(),
        modified_nanos: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
    }))
}

#[cfg(target_os = "linux")]
fn hash_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

#[cfg(target_os = "linux")]
fn hash_path(hash: &mut Sha256, path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    hash_bytes(hash, path.as_os_str().as_bytes());
}

#[cfg(target_os = "linux")]
fn patterns(value: Option<&toml::Value>) -> Option<Vec<globset::GlobMatcher>> {
    let Some(value) = value else {
        return Some(Vec::new());
    };
    let values = value.as_array()?;
    if values.len() > 1024 {
        return None;
    }
    values
        .iter()
        .map(|value| {
            let value = value.as_str()?;
            let value = value.strip_prefix("./").unwrap_or(value);
            if value.is_empty()
                || value.len() > 4096
                || Path::new(value).is_absolute()
                || Path::new(value)
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
            {
                return None;
            }
            Some(
                globset::GlobBuilder::new(value)
                    .literal_separator(true)
                    .build()
                    .ok()?
                    .compile_matcher(),
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn valid_package_version(value: &str) -> bool {
    if value.len() > 256 {
        return false;
    }
    let (without_build, build) = value.split_once('+').unwrap_or((value, ""));
    if value.matches('+').count() > 1
        || (!build.is_empty() && !valid_version_identifiers(build, false))
        || value.ends_with('+')
    {
        return false;
    }
    let (core, prerelease) = without_build.split_once('-').unwrap_or((without_build, ""));
    if (!prerelease.is_empty() && !valid_version_identifiers(prerelease, true))
        || without_build.ends_with('-')
    {
        return false;
    }
    let mut numbers = core.split('.');
    let Some(major) = numbers.next() else {
        return false;
    };
    let Some(minor) = numbers.next() else {
        return false;
    };
    let Some(patch) = numbers.next() else {
        return false;
    };
    numbers.next().is_none()
        && [major, minor, patch].iter().all(|number| {
            !number.is_empty()
                && (number == &"0" || !number.starts_with('0'))
                && number.bytes().all(|byte| byte.is_ascii_digit())
                && number.parse::<u64>().is_ok()
        })
}

#[cfg(target_os = "linux")]
fn valid_version_identifiers(value: &str, prerelease: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !(prerelease
                    && identifier.len() > 1
                    && identifier.starts_with('0')
                    && identifier.bytes().all(|byte| byte.is_ascii_digit()))
        })
}

#[cfg(target_os = "linux")]
fn read_manifest(path: &Path) -> ReadManifest {
    use std::{io::Read, os::unix::fs::MetadataExt};
    let descriptor = match rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return ReadManifest::Missing,
        Err(_) => return ReadManifest::Unavailable,
    };
    let file = std::fs::File::from(descriptor);
    let Ok(before) = file.metadata() else {
        return ReadManifest::Unavailable;
    };
    // shortcut: skip manifests above 1 MiB; stream larger files when needed.
    if !before.is_file() || before.len() > 1_048_576 {
        return ReadManifest::Unavailable;
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    if (&file).take(1_048_577).read_to_end(&mut bytes).is_err() || bytes.len() > 1_048_576 {
        return ReadManifest::Unavailable;
    }
    let Ok(after) = file.metadata() else {
        return ReadManifest::Unavailable;
    };
    let identity = |metadata: &std::fs::Metadata| ManifestIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        modified_seconds: metadata.mtime(),
        modified_nanos: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
    };
    let before_identity = identity(&before);
    if before_identity != identity(&after) {
        return ReadManifest::Unavailable;
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return ReadManifest::Unavailable;
    };
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return ReadManifest::Unavailable;
    };
    let Some(root) = value.as_table() else {
        return ReadManifest::Unavailable;
    };
    let workspace = match root.get("workspace") {
        Some(value) => {
            let Some(table) = value.as_table() else {
                return ReadManifest::Unavailable;
            };
            Some(Workspace {
                members: patterns(table.get("members")),
                exclude: patterns(table.get("exclude")),
            })
        }
        None => None,
    };
    let has_workspace_override = root
        .get("package")
        .and_then(toml::Value::as_table)
        .is_some_and(|package| package.contains_key("workspace"));
    let has_package = root
        .get("package")
        .and_then(toml::Value::as_table)
        .is_some_and(|package| {
            package
                .get("name")
                .and_then(toml::Value::as_str)
                .is_some_and(|value| {
                    !value.is_empty()
                        && value.len() <= 64
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                })
                && package
                    .get("version")
                    .and_then(toml::Value::as_str)
                    .is_some_and(valid_package_version)
        });
    ReadManifest::Parsed(ManifestSnapshot {
        manifest: Manifest {
            workspace,
            has_workspace_override,
            has_package,
        },
        identity: before_identity,
        content_hash: Sha256::digest(&bytes).into(),
    })
}

pub struct Inspector<'a> {
    roots: &'a [PathBuf],
    #[cfg(target_os = "linux")]
    manifests: HashMap<PathBuf, ReadManifest>,
    #[cfg(target_os = "linux")]
    directories: HashMap<PathBuf, Option<DirectoryIdentity>>,
}

impl<'a> Inspector<'a> {
    pub fn new(roots: &'a [PathBuf]) -> Self {
        Self {
            roots,
            #[cfg(target_os = "linux")]
            manifests: HashMap::new(),
            #[cfg(target_os = "linux")]
            directories: HashMap::new(),
        }
    }

    pub fn inspect(
        &mut self,
        project: &Path,
        excluded: impl Fn(&Path) -> bool,
        cancel: &AtomicBool,
    ) -> WorkspaceEvidence {
        #[cfg(target_os = "linux")]
        {
            self.inspect_linux(project, excluded, cancel)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self.roots;
            let _ = (project, excluded, cancel);
            WorkspaceEvidence {
                status: "unsupported_platform",
                workspace_root: None,
                warning: WARNING,
                proof: None,
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn inspect_linux(
        &mut self,
        project: &Path,
        excluded: impl Fn(&Path) -> bool,
        cancel: &AtomicBool,
    ) -> WorkspaceEvidence {
        let evidence = |status,
                        workspace_root: Option<&Path>,
                        proof: Option<String>,
                        anchors: Option<WorkspaceAnchors>| {
            WorkspaceEvidence {
                status,
                workspace_root: workspace_root.map(Path::to_owned),
                warning: WARNING,
                proof,
                anchors,
            }
        };
        if !self.roots.iter().any(|root| project.starts_with(root)) {
            return evidence("outside_scan_scope", None, None, None);
        }
        if !project.is_absolute() || !project.canonicalize().is_ok_and(|path| path == project) {
            return evidence("manifest_unavailable", None, None, None);
        }
        let mut proof = Sha256::new();
        hash_bytes(&mut proof, b"upkit-cargo-workspace-proof-v1");
        let mut directories = Vec::new();
        let mut manifests = Vec::new();
        let mut manifest_bytes = 0u64;
        let mut project_has_package = false;
        let mut workspace_override = false;
        let mut nearest_workspace: Option<(PathBuf, Workspace)> = None;
        for (depth, ancestor) in project.ancestors().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                return evidence("cancelled", None, None, None);
            }
            // shortcut: stop after 256 ancestors; deeper projects remain inspection-only.
            if depth >= 256 {
                return evidence("ancestor_limit_reached", None, None, None);
            }
            let directory = self
                .directories
                .entry(ancestor.to_owned())
                .or_insert_with(|| directory_identity(ancestor))
                .clone();
            let Some(directory) = directory else {
                return evidence("manifest_unavailable", None, None, None);
            };
            directories.push((ancestor.to_owned(), directory.clone()));
            hash_path(&mut proof, ancestor);
            hash_bytes(&mut proof, b"directory");
            let Ok(directory) = serde_json::to_vec(&directory) else {
                return evidence("manifest_unavailable", None, None, None);
            };
            hash_bytes(&mut proof, &directory);

            let path = ancestor.join("Cargo.toml");
            if excluded(&path) {
                return evidence("manifest_unavailable", None, None, None);
            }
            let manifest = self
                .manifests
                .entry(path.clone())
                .or_insert_with(|| read_manifest(&path));
            match manifest {
                ReadManifest::Missing if ancestor != project => {
                    hash_path(&mut proof, &path);
                    hash_bytes(&mut proof, b"missing");
                    manifests.push((path, None));
                }
                ReadManifest::Missing | ReadManifest::Unavailable => {
                    return evidence("manifest_unavailable", None, None, None);
                }
                ReadManifest::Parsed(snapshot) => {
                    manifest_bytes = match manifest_bytes.checked_add(snapshot.identity.size) {
                        Some(total) if total <= MAX_ANCESTOR_MANIFEST_BYTES => total,
                        _ => return evidence("manifest_limit_reached", None, None, None),
                    };
                    hash_path(&mut proof, &path);
                    hash_bytes(&mut proof, b"parsed");
                    manifests.push((path, Some(snapshot.identity.clone())));
                    let Ok(identity) = serde_json::to_vec(&snapshot.identity) else {
                        return evidence("manifest_unavailable", None, None, None);
                    };
                    hash_bytes(&mut proof, &identity);
                    hash_bytes(&mut proof, &snapshot.content_hash);
                    let manifest = &snapshot.manifest;
                    if ancestor == project {
                        project_has_package = manifest.has_package;
                        workspace_override = manifest.has_workspace_override;
                    }
                    if nearest_workspace.is_none()
                        && let Some(workspace) = &manifest.workspace
                    {
                        nearest_workspace = Some((ancestor.to_owned(), workspace.clone()));
                    }
                }
            }
            if ancestor.parent().is_none() {
                break;
            }
        }
        let (status, workspace_root) = if workspace_override {
            ("workspace_override_unresolved", None)
        } else if let Some((root, workspace)) = nearest_workspace {
            if root == project {
                ("workspace_manifest", Some(root))
            } else {
                let Ok(relative) = project.strip_prefix(&root) else {
                    return evidence("membership_unresolved", Some(&root), None, None);
                };
                let status = match (&workspace.members, &workspace.exclude) {
                    (Some(members), Some(excludes)) => match (
                        members.iter().any(|pattern| pattern.is_match(relative)),
                        excludes.iter().any(|pattern| pattern.is_match(relative)),
                    ) {
                        (_, true) => "exclude_pattern_match",
                        (true, false) => "member_pattern_match",
                        _ => "membership_unresolved",
                    },
                    _ => "membership_unresolved",
                };
                (status, Some(root))
            }
        } else if project_has_package {
            ("standalone_package", None)
        } else {
            return evidence("manifest_unavailable", None, None, None);
        };
        hash_bytes(&mut proof, status.as_bytes());
        if let Some(root) = &workspace_root {
            hash_path(&mut proof, root);
        }
        let anchors = WorkspaceAnchors {
            directories,
            manifests,
        };
        if !anchors.metadata_matches() {
            return evidence("manifest_unavailable", None, None, None);
        }
        evidence(
            status,
            workspace_root.as_deref(),
            Some(hex::encode(proof.finalize())),
            Some(anchors),
        )
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn package_version_requires_semver_shape() {
        assert!(valid_package_version("1.2.3"));
        assert!(valid_package_version("0.1.0-rc.1+build.2"));
        for invalid in ["", "1", "1.2", "01.2.3", "1.2.3-01", "1.2.3+"] {
            assert!(!valid_package_version(invalid), "accepted {invalid:?}");
        }
    }

    #[test]
    fn unreadable_ancestor_manifest_cannot_prove_a_standalone_package() {
        if rustix::process::geteuid().as_raw() == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("parent");
        let project = parent.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        let parent_manifest = parent.join("Cargo.toml");
        std::fs::write(&parent_manifest, "[workspace]\nmembers=['project']\n").unwrap();
        std::fs::set_permissions(&parent_manifest, std::fs::Permissions::from_mode(0o000)).unwrap();

        let roots = [project.clone()];
        let evidence = Inspector::new(&roots).inspect(&project, |_| false, &AtomicBool::new(false));
        std::fs::set_permissions(&parent_manifest, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(evidence.status, "manifest_unavailable");
        assert!(evidence.proof().is_none());
    }

    #[test]
    fn ancestry_manifest_byte_budget_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut parent = dir.path().to_owned();
        let padding = " ".repeat(1_048_000);
        for index in 0..9 {
            parent.push(format!("level-{index}"));
            std::fs::create_dir(&parent).unwrap();
            std::fs::write(
                parent.join("Cargo.toml"),
                format!("[package]\nname='parent{index}'\nversion='0.1.0'\n{padding}"),
            )
            .unwrap();
        }
        let project = parent.join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        let roots = [project.clone()];
        let evidence = Inspector::new(&roots).inspect(&project, |_| false, &AtomicBool::new(false));
        assert_eq!(evidence.status, "manifest_limit_reached");
        assert!(evidence.proof().is_none());
    }
}
