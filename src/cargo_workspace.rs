//! Bounded, read-only evidence about Cargo workspaces within selected scan roots.
use serde::Serialize;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Debug, Serialize)]
pub struct WorkspaceEvidence {
    pub status: &'static str,
    #[serde(serialize_with = "crate::sweep::serialize_optional_path")]
    pub workspace_root: Option<PathBuf>,
    pub warning: &'static str,
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

const WARNING: &str = "Scan-time manifest evidence only: path dependencies, workspace overrides, Cargo configuration, and custom target directories are not resolved. This does not authorize cleanup.";

struct Workspace {
    members: Option<Vec<globset::GlobMatcher>>,
    exclude: Option<Vec<globset::GlobMatcher>>,
}

struct Manifest {
    workspace: Option<Workspace>,
    has_workspace_override: bool,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum ReadManifest {
    Missing,
    Unavailable,
    Parsed(Manifest),
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
    let mut text = String::new();
    if (&file).take(1_048_577).read_to_string(&mut text).is_err() || text.len() > 1_048_576 {
        return ReadManifest::Unavailable;
    }
    let Ok(after) = file.metadata() else {
        return ReadManifest::Unavailable;
    };
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return ReadManifest::Unavailable;
    }
    let Ok(value) = toml::from_str::<toml::Value>(&text) else {
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
    ReadManifest::Parsed(Manifest {
        workspace,
        has_workspace_override,
    })
}

// shortcut: workspace manifest inspection is Linux-only until no-follow reads are available on other platforms.
#[cfg(not(target_os = "linux"))]
fn read_manifest(_: &Path) -> ReadManifest {
    ReadManifest::Unavailable
}

pub struct Inspector<'a> {
    roots: &'a [PathBuf],
    manifests: HashMap<PathBuf, ReadManifest>,
}

impl<'a> Inspector<'a> {
    pub fn new(roots: &'a [PathBuf]) -> Self {
        Self {
            roots,
            manifests: HashMap::new(),
        }
    }

    pub fn inspect(
        &mut self,
        project: &Path,
        excluded: impl Fn(&Path) -> bool,
        cancel: &AtomicBool,
    ) -> WorkspaceEvidence {
        let evidence = |status, workspace_root: Option<&Path>| WorkspaceEvidence {
            status,
            workspace_root: workspace_root.map(Path::to_owned),
            warning: WARNING,
        };
        if !cfg!(target_os = "linux") {
            return evidence("unsupported_platform", None);
        }
        let Some(boundary) = self
            .roots
            .iter()
            .filter(|root| project.starts_with(root))
            .min_by_key(|root| root.components().count())
        else {
            return evidence("outside_scan_scope", None);
        };
        for (depth, ancestor) in project.ancestors().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                return evidence("cancelled", None);
            }
            // shortcut: stop after 256 ancestors; support deeper workspaces if needed.
            if depth >= 256 {
                return evidence("ancestor_limit_reached", None);
            }
            if !ancestor.starts_with(boundary) {
                break;
            }
            let path = ancestor.join("Cargo.toml");
            if excluded(&path) {
                return evidence("manifest_unavailable", None);
            }
            let manifest = self
                .manifests
                .entry(path.clone())
                .or_insert_with(|| read_manifest(&path));
            match manifest {
                ReadManifest::Missing if ancestor != project => {}
                ReadManifest::Missing | ReadManifest::Unavailable => {
                    return evidence("manifest_unavailable", None);
                }
                ReadManifest::Parsed(manifest) => {
                    if ancestor == project {
                        if manifest.workspace.is_some() {
                            return evidence("workspace_manifest", Some(ancestor));
                        }
                        if manifest.has_workspace_override {
                            return evidence("workspace_override_unresolved", None);
                        }
                    } else if let Some(workspace) = &manifest.workspace {
                        let Ok(relative) = project.strip_prefix(ancestor) else {
                            return evidence("membership_unresolved", Some(ancestor));
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
                        return evidence(status, Some(ancestor));
                    }
                }
            }
            if ancestor == boundary {
                break;
            }
        }
        evidence("workspace_not_observed_within_scope", None)
    }
}
