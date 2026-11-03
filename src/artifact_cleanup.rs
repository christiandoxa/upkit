//! Explicit, reviewed removal of discovered project artifact directories.
use anyhow::{Result, bail};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactEntry {
    pub path: String,
    pub kind: &'static str,
    pub logical_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactPlan {
    pub scope: crate::sweep::Scope,
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub project: PathBuf,
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub manifest: PathBuf,
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub target: PathBuf,
    pub ecosystem: &'static str,
    pub classification: &'static str,
    pub logical_bytes: u64,
    pub entries: Vec<ArtifactEntry>,
    pub preview_token: String,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    pub(crate) cargo_config_identity: Option<Box<crate::sweep::FileIdentityAtPath>>,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    pub(crate) cargo_workspace_evidence: Option<Box<crate::sweep::WorkspaceEvidence>>,
    #[cfg(target_os = "linux")]
    #[serde(skip)]
    pub(crate) git_evidence_id: Option<String>,
    pub warning: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reproduction_warning: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactBatchPlan {
    pub scope: crate::sweep::Scope,
    pub items: Vec<ArtifactPlan>,
    pub preview_token: String,
    pub warning: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactBatchOutcome {
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub target: PathBuf,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ArtifactBatchResult {
    pub preview_token: String,
    pub outcomes: Vec<ArtifactBatchOutcome>,
    pub cancelled: bool,
}

// shortcut: cap selected artifact batches at 32; paginate confirmations before increasing the limit.
pub const MAX_BATCH_ARTIFACTS: usize = 32;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::Context;
    use rustix::fs::{
        AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, mkdirat, openat2, renameat_with, statat,
        unlinkat,
    };
    use sha2::{Digest, Sha256};
    use std::{
        collections::HashSet,
        fs,
        os::unix::fs::MetadataExt,
        path::Component,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    #[derive(Debug, Serialize, PartialEq, Eq)]
    struct Fingerprint {
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
    fn fingerprint(meta: &fs::Metadata) -> Fingerprint {
        Fingerprint {
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
    fn anchor(a: &Fingerprint, b: &Fingerprint) -> bool {
        a.device == b.device && a.inode == b.inode && a.mode == b.mode && a.uid == b.uid
    }
    fn moved(a: &Fingerprint, b: &Fingerprint) -> bool {
        anchor(a, b)
            && a.links == b.links
            && a.size == b.size
            && a.mtime == b.mtime
            && a.mtime_ns == b.mtime_ns
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
    struct Opened {
        parents: Vec<fs::File>,
        manifest: fs::File,
        target: fs::File,
        fingerprints: Vec<Fingerprint>,
        tree: crate::guarded_tree::TreeSnapshot,
    }
    fn inspect(
        project: &Path,
        manifest: &Path,
        target: &Path,
        cancel: &AtomicBool,
    ) -> Result<Opened> {
        if !project.is_absolute()
            || !target.is_absolute()
            || project.canonicalize()? != project
            || target.canonicalize()? != target
            || project.parent().is_none()
            || dirs::home_dir()
                .and_then(|path| path.canonicalize().ok())
                .as_deref()
                == Some(project)
        {
            bail!(
                "project and target must be canonical paths, and project cannot be a filesystem or user-home root"
            );
        }
        let relative = target
            .strip_prefix(project)
            .context("artifact target is outside its project")?;
        let parent = relative.parent().context("artifact target has no parent")?;
        if relative.as_os_str().is_empty() || manifest.parent() != Some(project) {
            bail!("invalid artifact or manifest scope");
        }
        let project_fd = fs::File::from(openat2(
            rustix::fs::CWD,
            project,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        let mut parents = vec![project_fd];
        for component in parent.components() {
            let Component::Normal(name) = component else {
                bail!("invalid artifact path");
            };
            let next = open(
                parents.last().expect("project opened"),
                Path::new(name),
                OFlags::RDONLY | OFlags::DIRECTORY,
            )?;
            parents.push(next);
        }
        let target_fd = open(
            parents.last().expect("project opened"),
            Path::new(relative.file_name().context("missing artifact name")?),
            OFlags::RDONLY | OFlags::DIRECTORY,
        )?;
        let manifest_fd = open(
            &parents[0],
            Path::new(manifest.file_name().context("missing manifest name")?),
            OFlags::RDONLY | OFlags::NONBLOCK,
        )?;
        let metadata = parents
            .iter()
            .chain([&manifest_fd, &target_fd])
            .map(|file| file.metadata())
            .collect::<std::io::Result<Vec<_>>>()?;
        let uid = rustix::process::geteuid().as_raw();
        if metadata[..parents.len()]
            .iter()
            .any(|meta| !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o022 != 0)
            || !metadata[parents.len()].is_file()
            || metadata[parents.len()].uid() != uid
            || metadata[parents.len()].mode() & 0o022 != 0
            || metadata[parents.len()].nlink() != 1
            || !metadata[parents.len() + 1].is_dir()
            || metadata[parents.len() + 1].uid() != uid
            || metadata[parents.len() + 1].mode() & 0o022 != 0
        {
            bail!(
                "project, manifest and artifact must be user-owned and not group/other writable; manifest must be singly linked"
            );
        }
        let fingerprints = metadata.iter().map(fingerprint).collect::<Vec<_>>();
        let tree = crate::guarded_tree::snapshot(target_fd.try_clone()?, uid, cancel)?;
        if tree.has_symlinks() || tree.has_project_or_vcs_marker() {
            bail!("artifact contains a symlink, nested project or version-control marker");
        }
        for (file, expected) in parents
            .iter()
            .chain([&manifest_fd, &target_fd])
            .zip(&fingerprints)
        {
            if fingerprint(&file.metadata()?) != *expected {
                bail!("project or artifact changed during inspection");
            }
        }
        Ok(Opened {
            parents,
            manifest: manifest_fd,
            target: target_fd,
            fingerprints,
            tree,
        })
    }
    fn token(
        scope: &crate::sweep::Scope,
        project: &Path,
        manifest: &Path,
        target: &Path,
        git_evidence_id: &str,
        cargo_evidence: (Option<&crate::sweep::FileIdentityAtPath>, Option<&str>),
        opened: &Opened,
    ) -> Result<String> {
        let boot = fs::read("/proc/sys/kernel/random/boot_id").context("read boot identity")?;
        let mut hash = Sha256::new();
        for value in [
            b"upkit-artifact-directory-v5".as_slice(),
            &boot,
            &serde_json::to_vec(scope)?,
            &serde_json::to_vec(&crate::sweep::JsonPath(project))?,
            &serde_json::to_vec(&crate::sweep::JsonPath(manifest))?,
            &serde_json::to_vec(&crate::sweep::JsonPath(target))?,
            git_evidence_id.as_bytes(),
            &serde_json::to_vec(&cargo_evidence)?,
            &serde_json::to_vec(&opened.fingerprints)?,
            opened.tree.digest.as_bytes(),
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        Ok(hex::encode(hash.finalize()))
    }
    fn git_clear(
        scope: &crate::sweep::Scope,
        project: &Path,
        target: &Path,
        quarantine_target: &Path,
        expected_git_evidence_id: &str,
        cancel: &AtomicBool,
    ) -> Result<()> {
        let git = crate::git_index::available(cancel, &scope.roots)?
            .context("trusted Git became unavailable")?;
        if git.evidence_id() != expected_git_evidence_id {
            bail!("Git executable changed after artifact preview");
        }
        crate::git_index::clear_for_removal(&git, project, target, cancel)?;
        crate::git_index::clear_for_removal(&git, project, quarantine_target, cancel)
    }
    pub(super) fn preview(
        scope: &crate::sweep::Scope,
        target: &Path,
        cancel: &AtomicBool,
    ) -> Result<ArtifactPlan> {
        preview_batch(scope, &[target.to_owned()], cancel)?
            .items
            .into_iter()
            .next()
            .context("artifact was not selected from the scan")
    }
    fn selected_targets(targets: &[PathBuf]) -> Result<Vec<PathBuf>> {
        if targets.is_empty() || targets.len() > MAX_BATCH_ARTIFACTS {
            bail!("select between 1 and {MAX_BATCH_ARTIFACTS} artifact directories");
        }
        let mut selected = Vec::with_capacity(targets.len());
        let mut unique = HashSet::with_capacity(targets.len());
        for target in targets {
            let metadata = fs::symlink_metadata(target).with_context(|| {
                format!(
                    "inspect selected artifact {}",
                    crate::sweep::display_path(target)
                )
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!("selected artifact must be a non-symlink directory");
            }
            let canonical = target.canonicalize().with_context(|| {
                format!(
                    "resolve selected artifact {}",
                    crate::sweep::display_path(target)
                )
            })?;
            if !unique.insert(canonical.clone()) {
                bail!("duplicate artifact selection");
            }
            selected.push(canonical);
        }
        selected.sort();
        if selected
            .windows(2)
            .any(|pair| pair[1].starts_with(&pair[0]))
        {
            bail!("selected artifact directories overlap");
        }
        Ok(selected)
    }
    pub(super) fn validate_dry_run_selection(
        scope: &crate::sweep::Scope,
        targets: &[PathBuf],
        cancel: &AtomicBool,
    ) -> Result<usize> {
        let targets = selected_targets(targets)?;
        let report = crate::sweep::scan_with_policy(
            &scope.roots,
            &scope.exclusions,
            scope.older_than_seconds.map(Duration::from_secs),
            scope.enabled.as_deref(),
            cancel,
            |_| {},
        )?;
        crate::sweep::validate_preview_selection(&report, &targets, cancel)?;
        Ok(targets.len())
    }
    fn plan_item(
        scope: &crate::sweep::Scope,
        item: &crate::sweep::PlanItem,
        cancel: &AtomicBool,
    ) -> Result<ArtifactPlan> {
        let candidate = &item.candidate;
        let target = &candidate.target;
        if candidate.ecosystem == "cargo"
            && (candidate.classification != "rebuildable"
                || target.as_path() != candidate.project_root.join("target").as_path())
        {
            bail!(
                "custom or unresolved Cargo target directories are inspection-only until configuration identity is part of cleanup authorization"
            );
        }
        if candidate.ecosystem == "go" && candidate.classification == "review" {
            bail!(
                "Go build and bin directories are inspection-only because their contents may be user data"
            );
        }
        if candidate.ecosystem == "ninja" {
            bail!(
                "Ninja build directories are inspection-only because their contents may be user data"
            );
        }
        if candidate.ecosystem == "javascript"
            && target.file_name().is_some_and(|name| name == ".svelte-kit")
        {
            bail!(
                "SvelteKit output is inspection-only because its contents are not verified as disposable"
            );
        }
        if !item.selected
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
            bail!("Git index, HEAD, or reachable history could not rule out tracked files");
        }
        if item.activity_status != "no_open_handles_or_cwd_observed" {
            bail!("process activity was observed or could not be inspected completely");
        }
        crate::bytecode::reject_other_vcs(&candidate.project_root, target)?;
        let manifest = crate::sweep::candidate_manifest(candidate)
            .context("project manifest identity is unavailable")?
            .to_owned();
        let opened = inspect(&candidate.project_root, &manifest, target, cancel)?;
        if opened.tree.logical_bytes != candidate.logical_bytes {
            bail!("artifact size changed during preview");
        }
        let git_evidence_id = item
            .git_evidence_id
            .as_deref()
            .context("trusted Git evidence identity is unavailable")?;
        let cargo_config_identity = if candidate.ecosystem == "cargo" {
            crate::sweep::candidate_cargo_config_identity(candidate).map(Box::new)
        } else {
            None
        };
        let cargo_workspace_evidence = if candidate.ecosystem == "cargo" {
            if !candidate.cargo_workspace.as_ref().is_some_and(|workspace| {
                matches!(
                    workspace.status,
                    "standalone_package" | "workspace_manifest"
                )
            }) {
                bail!("Cargo workspace ancestry is unresolved");
            }
            let expected = crate::sweep::candidate_cargo_workspace_proof(candidate)
                .context("Cargo workspace ancestry proof is unavailable")?;
            let current =
                crate::sweep::inspect_cargo_workspace(scope, &candidate.project_root, cancel)?;
            let current_proof = current
                .proof()
                .context("Cargo workspace ancestry could not be verified")?;
            if current_proof != expected
                || !matches!(current.status, "standalone_package" | "workspace_manifest")
            {
                bail!("Cargo workspace manifests changed during preview");
            }
            Some(Box::new(current))
        } else {
            None
        };
        let preview_token = token(
            scope,
            &candidate.project_root,
            &manifest,
            target,
            git_evidence_id,
            (
                cargo_config_identity.as_deref(),
                cargo_workspace_evidence
                    .as_deref()
                    .and_then(crate::sweep::WorkspaceEvidence::proof),
            ),
            &opened,
        )?;
        let entries = opened
            .tree
            .review_entries()
            .into_iter()
            .map(|entry| ArtifactEntry {
                path: entry.path,
                kind: entry.kind,
                logical_bytes: entry.logical_bytes,
            })
            .collect();
        Ok(ArtifactPlan {
            scope: scope.clone(),
            project: candidate.project_root.clone(),
            manifest,
            target: target.to_owned(),
            ecosystem: candidate.ecosystem,
            classification: candidate.classification,
            logical_bytes: opened.tree.logical_bytes,
            entries,
            preview_token,
            cargo_config_identity,
            cargo_workspace_evidence,
            git_evidence_id: Some(git_evidence_id.to_owned()),
            warning: "Permanently deletes every listed entry and the selected directory, including any user data. Git and process checks are snapshots and cannot rule out all races or hidden processes. Failure can leave a partially removed directory in quarantine; reclaimed space is unknown.",
            reproduction_warning: crate::sweep::reproduction_warning(candidate),
        })
    }
    fn batch_token(items: &[ArtifactPlan]) -> String {
        let mut hash = Sha256::new();
        hash.update(b"upkit-artifact-batch-v1");
        for item in items {
            hash.update((item.preview_token.len() as u64).to_be_bytes());
            hash.update(item.preview_token.as_bytes());
        }
        hex::encode(hash.finalize())
    }
    pub(super) fn preview_batch(
        scope: &crate::sweep::Scope,
        targets: &[PathBuf],
        cancel: &AtomicBool,
    ) -> Result<ArtifactBatchPlan> {
        let report = crate::sweep::scan_with_policy(
            &scope.roots,
            &scope.exclusions,
            scope.older_than_seconds.map(Duration::from_secs),
            scope.enabled.as_deref(),
            cancel,
            |_| {},
        )?;
        preview_batch_from_scan(scope, report, targets, cancel)
    }
    pub(super) fn preview_batch_from_scan(
        scope: &crate::sweep::Scope,
        report: crate::sweep::ScanReport,
        targets: &[PathBuf],
        cancel: &AtomicBool,
    ) -> Result<ArtifactBatchPlan> {
        let targets = selected_targets(targets)?;
        if report.roots != scope.roots || !report.is_complete() {
            bail!("artifact cleanup requires a complete scan of the approved roots");
        }
        let plan = crate::sweep::preview_with_cancel(report, &targets, cancel)?;
        let mut items = plan
            .items
            .iter()
            .filter(|item| item.selected)
            .map(|item| plan_item(scope, item, cancel))
            .collect::<Result<Vec<_>>>()?;
        if items.len() != targets.len() {
            bail!("one or more selected artifacts were not found in the scan");
        }
        items.sort_by(|left, right| left.target.cmp(&right.target));
        let preview_token = batch_token(&items);
        Ok(ArtifactBatchPlan {
            scope: scope.clone(),
            items,
            preview_token,
            warning: "Permanently deletes the listed artifact directories. All selections are revalidated before removal; each directory is quarantined and reported separately. A failure may leave other directories completed or leave a partial directory in quarantine. Reclaimed space is unknown.",
        })
    }
    pub(super) fn remove_guarded(
        scope: &crate::sweep::Scope,
        target: &Path,
        approved: &str,
        cancel: &AtomicBool,
        guard: &dyn Fn() -> Result<()>,
    ) -> Result<&'static str> {
        let plan = preview(scope, target, cancel)?;
        if plan.preview_token != approved {
            bail!("artifact preview changed; review it again");
        }
        let opened = open_approved(&plan, cancel)?;
        guard()?;
        remove_opened(&plan, opened, cancel, guard, || {}, || {})
    }
    fn check_anchors(
        plan: &ArtifactPlan,
        parents: &[fs::File],
        fingerprints: &[Fingerprint],
        manifest: &fs::File,
    ) -> Result<()> {
        check_cargo_config_identity(plan)?;
        check_cargo_workspace_metadata(plan)?;
        let mut current = fs::File::from(openat2(
            rustix::fs::CWD,
            &plan.project,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        if !anchor(&fingerprint(&current.metadata()?), &fingerprints[0]) {
            bail!("project path changed");
        }
        let relative = plan.target.strip_prefix(&plan.project)?;
        let mut index = 1usize;
        for component in relative
            .parent()
            .context("missing artifact parent")?
            .components()
        {
            let Component::Normal(name) = component else {
                bail!("invalid artifact path");
            };
            current = open(
                &current,
                Path::new(name),
                OFlags::RDONLY | OFlags::DIRECTORY,
            )?;
            if !anchor(&fingerprint(&current.metadata()?), &fingerprints[index]) {
                bail!("artifact parent changed");
            }
            index += 1;
        }
        let current_manifest = open(
            &parents[0],
            Path::new(plan.manifest.file_name().context("missing manifest name")?),
            OFlags::RDONLY | OFlags::NONBLOCK,
        )?;
        if index != parents.len()
            || !anchor(
                &fingerprint(&current.metadata()?),
                &fingerprint(&parents.last().expect("project opened").metadata()?),
            )
            || fingerprint(&manifest.metadata()?) != fingerprints[parents.len()]
            || fingerprint(&current_manifest.metadata()?) != fingerprints[parents.len()]
        {
            bail!("project, manifest, or artifact parent changed");
        }
        Ok(())
    }
    fn check_cargo_config_identity(plan: &ArtifactPlan) -> Result<()> {
        if plan.ecosystem == "cargo" {
            let current = crate::sweep::current_cargo_config_identity(&plan.project)?;
            if current.as_ref() != plan.cargo_config_identity.as_deref() {
                bail!("Cargo configuration changed after artifact preview");
            }
        }
        Ok(())
    }
    fn check_cargo_workspace_identity(plan: &ArtifactPlan) -> Result<()> {
        if plan.ecosystem == "cargo" {
            let evidence = plan
                .cargo_workspace_evidence
                .as_deref()
                .context("Cargo workspace ancestry proof is unavailable")?;
            let expected = evidence
                .proof()
                .context("Cargo workspace ancestry proof is unavailable")?;
            if !evidence.metadata_matches()
                || crate::sweep::current_cargo_workspace_proof(&plan.scope, &plan.project)?
                    != expected
            {
                bail!("Cargo workspace manifests changed after artifact preview");
            }
        }
        Ok(())
    }
    fn check_cargo_workspace_metadata(plan: &ArtifactPlan) -> Result<()> {
        if plan.ecosystem == "cargo"
            && !plan
                .cargo_workspace_evidence
                .as_deref()
                .is_some_and(crate::sweep::WorkspaceEvidence::metadata_matches)
        {
            bail!("Cargo workspace manifests changed after artifact preview");
        }
        Ok(())
    }
    fn check_quarantine(
        parent: &fs::File,
        name: &str,
        quarantine: &fs::File,
        expected: &Fingerprint,
    ) -> Result<()> {
        let current = open(parent, Path::new(name), OFlags::RDONLY | OFlags::DIRECTORY)?;
        let actual = fingerprint(&current.metadata()?);
        if !anchor(&actual, expected)
            || !anchor(&fingerprint(&quarantine.metadata()?), expected)
            || actual.uid != rustix::process::geteuid().as_raw()
            || actual.mode & 0o777 != 0o700
        {
            bail!("artifact quarantine changed");
        }
        Ok(())
    }
    fn target_absent(parent: &fs::File, name: &std::ffi::OsStr) -> bool {
        matches!(
            statat(parent, name, AtFlags::SYMLINK_NOFOLLOW),
            Err(rustix::io::Errno::NOENT)
        )
    }
    pub(super) fn remove(
        scope: &crate::sweep::Scope,
        target: &Path,
        approved: &str,
        cancel: &AtomicBool,
    ) -> Result<&'static str> {
        remove_guarded(scope, target, approved, cancel, &|| Ok(()))
    }
    fn open_approved(plan: &ArtifactPlan, cancel: &AtomicBool) -> Result<Opened> {
        check_cargo_config_identity(plan)?;
        check_cargo_workspace_identity(plan)?;
        let opened = inspect(&plan.project, &plan.manifest, &plan.target, cancel)?;
        check_cargo_config_identity(plan)?;
        check_cargo_workspace_identity(plan)?;
        if token(
            &plan.scope,
            &plan.project,
            &plan.manifest,
            &plan.target,
            plan.git_evidence_id
                .as_deref()
                .context("trusted Git evidence identity is unavailable")?,
            (
                plan.cargo_config_identity.as_deref(),
                plan.cargo_workspace_evidence
                    .as_deref()
                    .and_then(crate::sweep::WorkspaceEvidence::proof),
            ),
            &opened,
        )? != plan.preview_token
        {
            bail!("artifact changed after preview");
        }
        Ok(opened)
    }
    pub(super) fn remove_batch(
        scope: &crate::sweep::Scope,
        targets: &[PathBuf],
        approved: &str,
        cancel: &AtomicBool,
    ) -> Result<ArtifactBatchResult> {
        #[cfg(test)]
        {
            remove_batch_impl(scope, targets, approved, cancel, || {})
        }
        #[cfg(not(test))]
        {
            remove_batch_impl(scope, targets, approved, cancel)
        }
    }
    #[cfg(test)]
    fn remove_batch_with_test_hook(
        scope: &crate::sweep::Scope,
        targets: &[PathBuf],
        approved: &str,
        cancel: &AtomicBool,
        after_removed_entry: impl FnMut(),
    ) -> Result<ArtifactBatchResult> {
        remove_batch_impl(scope, targets, approved, cancel, after_removed_entry)
    }
    fn remove_batch_impl(
        scope: &crate::sweep::Scope,
        targets: &[PathBuf],
        approved: &str,
        cancel: &AtomicBool,
        #[cfg(test)] mut after_removed_entry: impl FnMut(),
    ) -> Result<ArtifactBatchResult> {
        let plan = preview_batch(scope, targets, cancel)?;
        if plan.preview_token != approved {
            bail!("artifact batch preview changed; review it again");
        }
        let mut opened = Vec::with_capacity(plan.items.len());
        for item in &plan.items {
            if cancel.load(Ordering::Relaxed) {
                bail!("artifact batch removal cancelled before execution");
            }
            opened.push(open_approved(item, cancel)?);
        }
        let mut outcomes = Vec::with_capacity(plan.items.len());
        let mut cancelled = false;
        for (item, opened) in plan.items.into_iter().zip(opened) {
            if cancel.load(Ordering::Relaxed) {
                cancelled = true;
                outcomes.push(ArtifactBatchOutcome {
                    target: item.target,
                    status: "not_attempted_cancelled",
                    error: None,
                });
                continue;
            }
            let target = item.target.clone();
            let result = {
                #[cfg(test)]
                {
                    remove_opened(
                        &item,
                        opened,
                        cancel,
                        &|| Ok(()),
                        || {},
                        &mut after_removed_entry,
                    )
                }
                #[cfg(not(test))]
                {
                    remove_opened(&item, opened, cancel, &|| Ok(()), || {}, || {})
                }
            };
            match result {
                Ok(status) => outcomes.push(ArtifactBatchOutcome {
                    target,
                    status,
                    error: None,
                }),
                Err(error) => {
                    cancelled |= cancel.load(Ordering::Relaxed);
                    outcomes.push(ArtifactBatchOutcome {
                        target,
                        status: "failed",
                        error: Some(format!("{error:#}")),
                    });
                }
            }
        }
        Ok(ArtifactBatchResult {
            preview_token: plan.preview_token,
            outcomes,
            cancelled,
        })
    }
    fn remove_opened(
        plan: &ArtifactPlan,
        opened: Opened,
        cancel: &AtomicBool,
        guard: &dyn Fn() -> Result<()>,
        after_staging: impl FnOnce(),
        mut after_removed_entry: impl FnMut(),
    ) -> Result<&'static str> {
        let Opened {
            parents,
            manifest,
            target,
            fingerprints,
            tree,
        } = opened;
        let parent = parents.last().context("missing artifact parent")?;
        let name = plan.target.file_name().context("missing artifact name")?;
        let expected_target = fingerprints.last().context("missing artifact identity")?;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut private = None;
        for _ in 0..32 {
            let candidate = format!(
                ".upkit-artifact-{}-{stamp}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            match mkdirat(
                parent,
                candidate.as_str(),
                Mode::RUSR | Mode::WUSR | Mode::XUSR,
            ) {
                Ok(()) => {
                    private = Some(candidate);
                    break;
                }
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(error).context("create artifact quarantine"),
            }
        }
        let private = private.context("could not allocate artifact quarantine")?;
        let quarantine_path = plan
            .target
            .parent()
            .context("missing artifact parent")?
            .join(&private);
        let quarantine_target = quarantine_path.join("root");
        let quarantine = match open(
            parent,
            Path::new(&private),
            OFlags::RDONLY | OFlags::DIRECTORY,
        ) {
            Ok(directory) => directory,
            Err(error) => {
                if unlinkat(parent, private.as_str(), AtFlags::REMOVEDIR).is_err() {
                    bail!(
                        "open quarantine: {error:#}; inspect {}",
                        crate::sweep::display_path(&quarantine_path)
                    );
                }
                return Err(error).context("open artifact quarantine");
            }
        };
        let q_identity = match quarantine.metadata() {
            Ok(metadata) => fingerprint(&metadata),
            Err(error) => {
                if unlinkat(parent, private.as_str(), AtFlags::REMOVEDIR).is_err() {
                    bail!(
                        "inspect quarantine: {error}; inspect {}",
                        crate::sweep::display_path(&quarantine_path)
                    );
                }
                return Err(error).context("inspect artifact quarantine");
            }
        };
        let check = || -> Result<()> {
            check_anchors(plan, &parents, &fingerprints, &manifest)?;
            check_quarantine(parent, &private, &quarantine, &q_identity)?;
            if !target_absent(parent, name) {
                bail!("artifact path was replaced after preview");
            }
            Ok(())
        };
        let mut staged = false;
        let mut partial = false;
        let mut removed = false;
        let action = (|| -> Result<&'static str> {
            if cancel.load(Ordering::Relaxed) {
                bail!("artifact removal cancelled");
            }
            guard()?;
            check_cargo_workspace_identity(plan)?;
            check_anchors(plan, &parents, &fingerprints, &manifest)?;
            check_quarantine(parent, &private, &quarantine, &q_identity)?;
            if fingerprint(&target.metadata()?) != *expected_target {
                bail!("artifact identity changed");
            }
            renameat_with(parent, name, &quarantine, "root", RenameFlags::NOREPLACE)
                .context("quarantine artifact directory")?;
            staged = true;
            after_staging();
            guard()?;
            check()?;
            let staged_dir = open(
                &quarantine,
                Path::new("root"),
                OFlags::RDONLY | OFlags::DIRECTORY,
            )?;
            if !moved(&fingerprint(&staged_dir.metadata()?), expected_target)
                || !moved(&fingerprint(&target.metadata()?), expected_target)
            {
                bail!("quarantined artifact changed");
            }
            let fresh = crate::guarded_tree::snapshot(
                staged_dir.try_clone()?,
                expected_target.uid,
                cancel,
            )?;
            if fresh.digest != tree.digest
                || fresh.count() != tree.count()
                || fresh.logical_bytes != tree.logical_bytes
            {
                bail!("quarantined artifact contents changed");
            }
            drop(staged_dir);
            drop(target);
            git_clear(
                &plan.scope,
                &plan.project,
                &plan.target,
                &quarantine_target,
                plan.git_evidence_id
                    .as_deref()
                    .context("trusted Git evidence identity is unavailable")?,
                cancel,
            )?;
            check()?;
            if crate::activity::inspect(std::slice::from_ref(&quarantine_target), cancel)[0]
                != "no_open_handles_or_cwd_observed"
            {
                bail!(
                    "process activity was observed or could not be inspected completely after quarantine"
                );
            }
            let staged_dir = open(
                &quarantine,
                Path::new("root"),
                OFlags::RDONLY | OFlags::DIRECTORY,
            )?;
            if !moved(&fingerprint(&staged_dir.metadata()?), expected_target) {
                bail!("quarantined artifact changed");
            }
            let fresh = crate::guarded_tree::snapshot(
                staged_dir.try_clone()?,
                expected_target.uid,
                cancel,
            )?;
            if fresh.digest != tree.digest
                || fresh.count() != tree.count()
                || fresh.logical_bytes != tree.logical_bytes
            {
                bail!("quarantined artifact contents changed");
            }
            guard()?;
            check_cargo_workspace_identity(plan)?;
            check_cargo_workspace_metadata(plan)?;
            crate::guarded_tree::remove(
                &quarantine,
                std::ffi::OsStr::new("root"),
                &staged_dir,
                &tree,
                cancel,
                &mut partial,
                |removed| {
                    check()?;
                    if removed {
                        after_removed_entry();
                    }
                    Ok(())
                },
            )?;
            if cancel.load(Ordering::Relaxed) {
                bail!("artifact removal cancelled");
            }
            check()?;
            let current = open(
                &quarantine,
                Path::new("root"),
                OFlags::PATH | OFlags::NOFOLLOW,
            )?;
            if !anchor(
                &fingerprint(&current.metadata()?),
                &fingerprint(&staged_dir.metadata()?),
            ) {
                bail!("quarantined artifact root was replaced");
            }
            unlinkat(&quarantine, "root", AtFlags::REMOVEDIR)
                .context("remove quarantined artifact directory")?;
            staged = false;
            removed = true;
            Ok(if target_absent(parent, name) {
                "verified_absent"
            } else {
                "unverified_replacement"
            })
        })();
        let mut cleanup_failed = false;
        if staged && !partial {
            if renameat_with(&quarantine, "root", parent, name, RenameFlags::NOREPLACE).is_ok() {
                staged = false;
            } else {
                cleanup_failed = true;
            }
        }
        if staged {
            cleanup_failed = true;
        }
        if !cleanup_failed && unlinkat(parent, private.as_str(), AtFlags::REMOVEDIR).is_err() {
            cleanup_failed = true;
        }
        match action {
            Ok(result) if !cleanup_failed => Ok(result),
            Ok(_) => bail!(
                "artifact was removed; inspect quarantine {}",
                crate::sweep::display_path(&quarantine_path)
            ),
            Err(error) => bail!(
                "{error:#}; artifact {}{}",
                if partial && staged {
                    "may be partially removed"
                } else if removed {
                    "was removed"
                } else {
                    "was not intentionally removed"
                },
                if cleanup_failed {
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{PermissionsExt, symlink};

        fn system_elf_git() -> Option<PathBuf> {
            use std::io::Read;

            [PathBuf::from("/usr/bin/git"), PathBuf::from("/bin/git")]
                .into_iter()
                .chain(which::which("git"))
                .find(|path| {
                    let Ok(mut file) = fs::File::open(path) else {
                        return false;
                    };
                    let mut magic = [0u8; 4];
                    file.read_exact(&mut magic).is_ok() && magic == *b"\x7fELF"
                })
        }

        fn fixture() -> (tempfile::TempDir, ArtifactPlan, Opened) {
            let dir = tempfile::tempdir().unwrap();
            let project = dir.path().join("project");
            let target = project.join("target");
            fs::create_dir_all(target.join("debug")).unwrap();
            for path in [&project, &target, &target.join("debug")] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let manifest = project.join("Cargo.toml");
            fs::write(
                &manifest,
                "[package]\nname='fixture'\nversion='0.1.0'\n[workspace]\n",
            )
            .unwrap();
            fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(target.join("debug/output"), "fixture").unwrap();
            fs::set_permissions(
                target.join("debug/output"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let scope = crate::sweep::Scope {
                roots: vec![project.clone()],
                exclusions: vec![],
                older_than_seconds: None,
                enabled: None,
            };
            let git_evidence_id = crate::git_index::available(
                &AtomicBool::new(false),
                std::slice::from_ref(&project),
            )
            .unwrap()
            .map(|git| git.evidence_id());
            let workspace =
                crate::sweep::inspect_cargo_workspace(&scope, &project, &AtomicBool::new(false))
                    .unwrap();
            let cargo_workspace_evidence = Some(Box::new(workspace));
            let opened = inspect(&project, &manifest, &target, &AtomicBool::new(false)).unwrap();
            let preview_token = token(
                &scope,
                &project,
                &manifest,
                &target,
                git_evidence_id.as_deref().unwrap_or("test-git-unavailable"),
                (
                    None,
                    cargo_workspace_evidence
                        .as_deref()
                        .and_then(crate::sweep::WorkspaceEvidence::proof),
                ),
                &opened,
            )
            .unwrap();
            let plan = ArtifactPlan {
                scope,
                project,
                manifest,
                target,
                ecosystem: "cargo",
                classification: "rebuildable",
                logical_bytes: opened.tree.logical_bytes,
                entries: vec![],
                preview_token,
                cargo_config_identity: None,
                cargo_workspace_evidence,
                git_evidence_id,
                warning: "fixture",
                reproduction_warning: None,
            };
            (dir, plan, opened)
        }

        #[test]
        fn artifact_approval_token_binds_git_evidence_identity() {
            let (_dir, plan, opened) = fixture();
            let first = token(
                &plan.scope,
                &plan.project,
                &plan.manifest,
                &plan.target,
                "git-evidence-a",
                (
                    plan.cargo_config_identity.as_deref(),
                    plan.cargo_workspace_evidence
                        .as_deref()
                        .and_then(crate::sweep::WorkspaceEvidence::proof),
                ),
                &opened,
            )
            .unwrap();
            let second = token(
                &plan.scope,
                &plan.project,
                &plan.manifest,
                &plan.target,
                "git-evidence-b",
                (
                    plan.cargo_config_identity.as_deref(),
                    plan.cargo_workspace_evidence
                        .as_deref()
                        .and_then(crate::sweep::WorkspaceEvidence::proof),
                ),
                &opened,
            )
            .unwrap();

            assert_ne!(first, second);
        }

        #[test]
        fn artifact_approval_rejects_changed_local_cargo_config() {
            let (_dir, mut plan, _opened) = fixture();
            if crate::sweep::current_cargo_config_identity(&plan.project).is_err() {
                eprintln!("Cargo config environment is unresolved; local-config fixture skipped");
                return;
            }
            let cargo_dir = plan.project.join(".cargo");
            fs::create_dir(&cargo_dir).unwrap();
            let config = cargo_dir.join("config.toml");
            fs::write(&config, "[net]\noffline = true\n").unwrap();
            plan.cargo_config_identity = crate::sweep::current_cargo_config_identity(&plan.project)
                .unwrap()
                .map(Box::new);
            let opened = inspect(
                &plan.project,
                &plan.manifest,
                &plan.target,
                &AtomicBool::new(false),
            )
            .unwrap();
            plan.preview_token = token(
                &plan.scope,
                &plan.project,
                &plan.manifest,
                &plan.target,
                plan.git_evidence_id
                    .as_deref()
                    .unwrap_or("test-git-unavailable"),
                (
                    plan.cargo_config_identity.as_deref(),
                    plan.cargo_workspace_evidence
                        .as_deref()
                        .and_then(crate::sweep::WorkspaceEvidence::proof),
                ),
                &opened,
            )
            .unwrap();

            fs::write(&config, "[net]\noffline = false\n").unwrap();

            let error = open_approved(&plan, &AtomicBool::new(false))
                .err()
                .expect("changed Cargo config must invalidate the preview");
            assert!(format!("{error:#}").contains("Cargo configuration changed"));
        }

        #[test]
        fn artifact_approval_rejects_inherited_config_added_after_preview() {
            let (_dir, plan, _opened) = fixture();
            if crate::sweep::current_cargo_config_identity(&plan.project).is_err() {
                eprintln!(
                    "Cargo config environment is unresolved; inherited-config fixture skipped"
                );
                return;
            }
            let config_dir = plan.project.parent().unwrap().join(".cargo");
            fs::create_dir(&config_dir).unwrap();
            fs::write(config_dir.join("config.toml"), "not parsed by cleanup").unwrap();

            let error = open_approved(&plan, &AtomicBool::new(false))
                .err()
                .expect("new inherited Cargo config must block cleanup");
            assert!(format!("{error:#}").contains("Cargo output configuration is unresolved"));
            assert!(plan.target.is_dir());
            assert!(plan.target.join("debug/output").is_file());
        }

        #[test]
        fn removal_rejects_workspace_membership_change_after_preview() {
            let (_dir, mut plan, _old_opened) = fixture();
            if crate::sweep::current_cargo_config_identity(&plan.project).is_err() {
                eprintln!("Cargo config environment is unresolved; workspace fixture skipped");
                return;
            }
            let git_evidence_id = "fixture-git-evidence";
            plan.git_evidence_id = Some(git_evidence_id.to_owned());
            fs::write(
                &plan.manifest,
                "[package]\nname='fixture'\nversion='0.1.0'\n[workspace]\nmembers=['member']\n",
            )
            .unwrap();
            let opened = inspect(
                &plan.project,
                &plan.manifest,
                &plan.target,
                &AtomicBool::new(false),
            )
            .unwrap();
            plan.cargo_workspace_evidence = Some(Box::new(
                crate::sweep::inspect_cargo_workspace(
                    &plan.scope,
                    &plan.project,
                    &AtomicBool::new(false),
                )
                .unwrap(),
            ));
            plan.preview_token = token(
                &plan.scope,
                &plan.project,
                &plan.manifest,
                &plan.target,
                git_evidence_id,
                (
                    plan.cargo_config_identity.as_deref(),
                    plan.cargo_workspace_evidence
                        .as_deref()
                        .and_then(crate::sweep::WorkspaceEvidence::proof),
                ),
                &opened,
            )
            .unwrap();

            fs::write(
                &plan.manifest,
                "[package]\nname='fixture'\nversion='0.1.0'\n[workspace]\nmembers=['member', 'other']\n",
            )
            .unwrap();

            let error = remove_opened(
                &plan,
                opened,
                &AtomicBool::new(false),
                &|| Ok(()),
                || {},
                || {},
            )
            .expect_err("workspace membership change must block staging");
            assert!(format!("{error:#}").contains("manifest"));
            assert!(plan.target.is_dir());
            assert_eq!(
                fs::read(plan.target.join("debug/output")).unwrap(),
                b"fixture"
            );
        }

        #[test]
        fn changed_tree_after_staging_is_restored_without_deleting_it() {
            let (_dir, plan, opened) = fixture();
            let result = remove_opened(
                &plan,
                opened,
                &AtomicBool::new(false),
                &|| Ok(()),
                || {
                    let quarantine = fs::read_dir(&plan.project)
                        .unwrap()
                        .map(|entry| entry.unwrap().path())
                        .find(|path| {
                            path.file_name()
                                .unwrap()
                                .to_string_lossy()
                                .starts_with(".upkit-artifact-")
                        })
                        .unwrap();
                    fs::write(quarantine.join("root/debug/output"), "changed while staged")
                        .unwrap();
                },
                || {},
            );
            assert!(result.is_err());
            assert_eq!(
                fs::read_to_string(plan.target.join("debug/output")).unwrap(),
                "changed while staged"
            );
            assert!(plan.manifest.exists());
        }

        #[test]
        fn changed_manifest_after_staging_restores_the_artifact() {
            let (_dir, plan, opened) = fixture();
            let result = remove_opened(
                &plan,
                opened,
                &AtomicBool::new(false),
                &|| Ok(()),
                || {
                    fs::rename(&plan.manifest, plan.project.join("old-manifest")).unwrap();
                    fs::write(&plan.manifest, "replacement").unwrap();
                },
                || {},
            );
            assert!(result.is_err());
            assert_eq!(
                fs::read_to_string(plan.target.join("debug/output")).unwrap(),
                "fixture"
            );
            assert_eq!(fs::read_to_string(&plan.manifest).unwrap(), "replacement");
        }

        #[test]
        fn cancellation_before_deletion_restores_the_artifact() {
            let (_dir, plan, opened) = fixture();
            let cancelled = AtomicBool::new(false);
            let result = remove_opened(
                &plan,
                opened,
                &cancelled,
                &|| Ok(()),
                || {
                    cancelled.store(true, Ordering::Relaxed);
                },
                || {},
            );
            assert!(result.is_err());
            assert_eq!(
                fs::read_to_string(plan.target.join("debug/output")).unwrap(),
                "fixture"
            );
            assert!(fs::read_dir(&plan.project).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".upkit-artifact-")
            }));
        }

        #[test]
        fn partial_deletion_reports_quarantine_and_preserves_sibling_target() {
            use std::process::{Command, Stdio};

            if system_elf_git().is_none() {
                eprintln!("SKIP: Git is required for the isolated artifact fixture");
                return;
            }
            if !Command::new("unshare")
                .args([
                    "--user",
                    "--map-root-user",
                    "--pid",
                    "--fork",
                    "--mount-proc",
                    "/bin/true",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
            {
                eprintln!("SKIP: isolated user/PID namespace unavailable for artifact fixture");
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().join("home");
            fs::create_dir(&home).unwrap();
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
            let git_bin = home.join("bin");
            fs::create_dir(&git_bin).unwrap();
            fs::set_permissions(&git_bin, fs::Permissions::from_mode(0o700)).unwrap();
            let system_git = system_elf_git().expect("isolated fixture requires ELF Git");
            let fixture_git = git_bin.join("git");
            fs::copy(system_git, &fixture_git).unwrap();
            fs::set_permissions(&fixture_git, fs::Permissions::from_mode(0o755)).unwrap();
            let path =
                std::env::join_paths([Path::new("bin"), Path::new("/usr/bin"), Path::new("/bin")])
                    .unwrap();
            let output = Command::new("unshare")
                .current_dir(&home)
                .args([
                    "--user",
                    "--map-root-user",
                    "--pid",
                    "--fork",
                    "--mount-proc",
                ])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "artifact_cleanup::linux::tests::partial_worker",
                    "--nocapture",
                ])
                .env_clear()
                .env("HOME", &home)
                .env("PATH", path)
                .env("XDG_CONFIG_HOME", home.join("config"))
                .env("XDG_CACHE_HOME", home.join("cache"))
                .env("XDG_DATA_HOME", home.join("data"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("ARTIFACT_PARTIAL_FIXTURE_OK"),
                "isolated worker skipped or did not reach its final assertions: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        #[test]
        #[ignore = "executed by the isolated partial-deletion fixture"]
        fn partial_worker() {
            use std::process::Command;

            let (_dir, mut plan, original_opened) = fixture();
            assert!(
                plan.git_evidence_id.is_some(),
                "trusted Git evidence is unavailable in the isolated fixture"
            );
            drop(original_opened);
            let sibling_target = plan.project.join(".pytest_cache");
            fs::create_dir(&sibling_target).unwrap();
            fs::set_permissions(&sibling_target, fs::Permissions::from_mode(0o700)).unwrap();
            let sibling_entry = sibling_target.join("keep");
            fs::write(&sibling_entry, "unselected sibling target").unwrap();
            fs::set_permissions(&sibling_entry, fs::Permissions::from_mode(0o600)).unwrap();
            let next = plan.target.join("debug/a");
            fs::write(&next, "preserved").unwrap();
            fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).unwrap();
            let git_path = which::which("git").expect("isolated fixture requires Git in PATH");
            let run_git = |args: &[&str]| {
                let output = Command::new(&git_path)
                    .arg("-C")
                    .arg(&plan.project)
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
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            };
            run_git(&["init", "-q"]);
            run_git(&["add", "Cargo.toml"]);
            run_git(&["commit", "-qm", "fixture"]);
            let cancel = AtomicBool::new(false);
            let opened = inspect(&plan.project, &plan.manifest, &plan.target, &cancel).unwrap();
            plan.logical_bytes = opened.tree.logical_bytes;
            plan.preview_token = token(
                &plan.scope,
                &plan.project,
                &plan.manifest,
                &plan.target,
                plan.git_evidence_id.as_deref().unwrap(),
                (
                    plan.cargo_config_identity.as_deref(),
                    plan.cargo_workspace_evidence
                        .as_deref()
                        .and_then(crate::sweep::WorkspaceEvidence::proof),
                ),
                &opened,
            )
            .unwrap();
            let mut injected = false;
            let error = remove_opened(
                &plan,
                opened,
                &cancel,
                &|| Ok(()),
                || {},
                || {
                    if !injected {
                        injected = true;
                        let quarantine = fs::read_dir(&plan.project)
                            .unwrap()
                            .map(|entry| entry.unwrap().path())
                            .find(|path| {
                                path.file_name()
                                    .unwrap()
                                    .to_string_lossy()
                                    .starts_with(".upkit-artifact-")
                            })
                            .unwrap();
                        fs::set_permissions(
                            quarantine.join("root/debug/a"),
                            fs::Permissions::from_mode(0o400),
                        )
                        .unwrap();
                    }
                },
            )
            .unwrap_err()
            .to_string();
            assert!(injected, "{error}");
            assert!(
                error.contains("directory entry changed during removal"),
                "{error}"
            );
            assert!(error.contains("may be partially removed"), "{error}");
            assert!(error.contains("inspect quarantine"), "{error}");
            assert!(!plan.target.exists());
            assert!(plan.manifest.is_file());
            assert_eq!(
                fs::read_to_string(&sibling_entry).unwrap(),
                "unselected sibling target"
            );
            let quarantine = fs::read_dir(&plan.project)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".upkit-artifact-")
                })
                .unwrap();
            assert_eq!(
                fs::read_to_string(quarantine.join("root/debug/a")).unwrap(),
                "preserved"
            );
            assert!(!quarantine.join("root/debug/output").exists());
            println!("ARTIFACT_PARTIAL_FIXTURE_OK");
        }

        #[test]
        fn partial_batch_failure_keeps_later_and_unselected_targets() {
            use std::process::{Command, Stdio};

            if system_elf_git().is_none() {
                eprintln!("SKIP: Git is required for the isolated artifact fixture");
                return;
            }
            if !Command::new("unshare")
                .args([
                    "--user",
                    "--map-root-user",
                    "--pid",
                    "--fork",
                    "--mount-proc",
                    "/bin/true",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
            {
                eprintln!("SKIP: isolated user/PID namespace unavailable for artifact fixture");
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().join("home");
            fs::create_dir(&home).unwrap();
            fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
            let git_bin = home.join("bin");
            fs::create_dir(&git_bin).unwrap();
            fs::set_permissions(&git_bin, fs::Permissions::from_mode(0o700)).unwrap();
            let fixture_git = git_bin.join("git");
            fs::copy(system_elf_git().unwrap(), &fixture_git).unwrap();
            fs::set_permissions(&fixture_git, fs::Permissions::from_mode(0o755)).unwrap();
            let path =
                std::env::join_paths([Path::new("bin"), Path::new("/usr/bin"), Path::new("/bin")])
                    .unwrap();
            let output = Command::new("unshare")
                .current_dir(&home)
                .args([
                    "--user",
                    "--map-root-user",
                    "--pid",
                    "--fork",
                    "--mount-proc",
                ])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "artifact_cleanup::linux::tests::partial_batch_worker",
                    "--nocapture",
                ])
                .env_clear()
                .env("HOME", &home)
                .env("PATH", path)
                .env("XDG_CONFIG_HOME", home.join("config"))
                .env("XDG_CACHE_HOME", home.join("cache"))
                .env("XDG_DATA_HOME", home.join("data"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains("ARTIFACT_PARTIAL_BATCH_FIXTURE_OK"),
                "isolated worker skipped or did not reach its final assertions: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        #[test]
        #[ignore = "executed by the isolated partial-batch fixture"]
        fn partial_batch_worker() {
            use std::process::Command;

            let (_dir, plan, opened) = fixture();
            assert!(
                plan.git_evidence_id.is_some(),
                "trusted Git evidence is unavailable in the isolated batch fixture"
            );
            drop(opened);
            let python_manifest = plan.project.join("pyproject.toml");
            fs::write(&python_manifest, "[project]\nname='fixture'\n").unwrap();
            fs::set_permissions(&python_manifest, fs::Permissions::from_mode(0o600)).unwrap();
            let selected_cache = plan.project.join(".pytest_cache");
            let unselected_cache = plan.project.join(".mypy_cache");
            for cache in [&selected_cache, &unselected_cache] {
                fs::create_dir(cache).unwrap();
                fs::set_permissions(cache, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let selected_entry = selected_cache.join("state");
            let unselected_entry = unselected_cache.join("keep");
            fs::write(&selected_entry, "selected").unwrap();
            fs::write(&unselected_entry, "unselected").unwrap();
            for entry in [&selected_entry, &unselected_entry] {
                fs::set_permissions(entry, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let git = which::which("git").expect("trusted Git fixture requires Git in PATH");
            let run_git = |args: &[&str]| {
                let output = Command::new(&git)
                    .arg("-C")
                    .arg(&plan.project)
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
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            };
            run_git(&["init", "-q"]);
            run_git(&["add", "Cargo.toml", "pyproject.toml"]);
            run_git(&["commit", "-qm", "fixture"]);

            let targets = vec![selected_cache.clone(), plan.target.clone()];
            let cancel = AtomicBool::new(false);
            let batch = preview_batch(&plan.scope, &targets, &cancel).unwrap();
            assert_eq!(batch.items[0].target, selected_cache);
            assert_eq!(batch.items[1].target, plan.target);
            let changed_target = plan.target.join("changed-after-prevalidation");
            let mut injected = false;
            let result = remove_batch_with_test_hook(
                &plan.scope,
                &targets,
                &batch.preview_token,
                &cancel,
                || {
                    if !injected {
                        injected = true;
                        fs::write(&changed_target, "preserve").unwrap();
                        fs::set_permissions(&changed_target, fs::Permissions::from_mode(0o600))
                            .unwrap();
                    }
                },
            )
            .unwrap();

            assert!(injected);
            assert_eq!(result.outcomes[0].status, "verified_absent");
            assert_eq!(result.outcomes[1].status, "failed");
            assert!(
                result.outcomes[1]
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains("artifact identity changed"))
            );
            assert!(!result.cancelled);
            assert!(!selected_cache.exists());
            assert!(plan.target.join("debug/output").is_file());
            assert!(changed_target.is_file());
            assert_eq!(fs::read_to_string(&unselected_entry).unwrap(), "unselected");
            assert!(plan.manifest.is_file() && python_manifest.is_file());
            println!("ARTIFACT_PARTIAL_BATCH_FIXTURE_OK");
        }

        #[test]
        fn inspection_rejects_hard_links_and_nested_vcs() {
            let (dir, plan, _opened) = fixture();
            let outside = dir.path().join("outside");
            fs::hard_link(plan.target.join("debug/output"), &outside).unwrap();
            assert!(
                inspect(
                    &plan.project,
                    &plan.manifest,
                    &plan.target,
                    &AtomicBool::new(false)
                )
                .is_err()
            );
            fs::remove_file(outside).unwrap();
            fs::create_dir(plan.target.join("debug/.git")).unwrap();
            assert!(
                inspect(
                    &plan.project,
                    &plan.manifest,
                    &plan.target,
                    &AtomicBool::new(false)
                )
                .is_err()
            );
        }

        #[test]
        fn inspection_rejects_symlinks_and_nested_projects() {
            let (dir, plan, _opened) = fixture();
            let outside = dir.path().join("outside");
            fs::write(&outside, "keep").unwrap();
            symlink(&outside, plan.target.join("debug/link")).unwrap();
            assert!(
                inspect(
                    &plan.project,
                    &plan.manifest,
                    &plan.target,
                    &AtomicBool::new(false)
                )
                .is_err()
            );
            fs::remove_file(plan.target.join("debug/link")).unwrap();
            fs::write(plan.target.join("debug/Cargo.toml"), "[package]").unwrap();
            fs::set_permissions(
                plan.target.join("debug/Cargo.toml"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            assert!(
                inspect(
                    &plan.project,
                    &plan.manifest,
                    &plan.target,
                    &AtomicBool::new(false)
                )
                .is_err()
            );
            fs::remove_file(plan.target.join("debug/Cargo.toml")).unwrap();
            fs::write(plan.target.join("debug/go.work"), "go 1.24\n").unwrap();
            fs::set_permissions(
                plan.target.join("debug/go.work"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            assert!(
                inspect(
                    &plan.project,
                    &plan.manifest,
                    &plan.target,
                    &AtomicBool::new(false)
                )
                .is_err()
            );
            assert_eq!(fs::read_to_string(outside).unwrap(), "keep");
        }
    }
}

/// Inspect all entries of one explicitly selected, discovered artifact directory.
pub fn preview(
    scope: &crate::sweep::Scope,
    target: &Path,
    cancel: &AtomicBool,
) -> Result<ArtifactPlan> {
    #[cfg(target_os = "linux")]
    {
        linux::preview(scope, target, cancel)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (scope, target, cancel);
        bail!("artifact cleanup is supported only on Linux")
    }
}

/// Validate artifact selection during a dry-run without Git evidence or a removal plan.
pub(crate) fn validate_dry_run_selection(
    scope: &crate::sweep::Scope,
    targets: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<usize> {
    #[cfg(target_os = "linux")]
    {
        linux::validate_dry_run_selection(scope, targets, cancel)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (scope, targets, cancel);
        bail!("artifact cleanup is supported only on Linux")
    }
}

/// Preview an explicitly selected set of discovered artifact directories.
pub fn preview_batch(
    scope: &crate::sweep::Scope,
    targets: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<ArtifactBatchPlan> {
    #[cfg(target_os = "linux")]
    {
        linux::preview_batch(scope, targets, cancel)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (scope, targets, cancel);
        bail!("artifact cleanup is supported only on Linux")
    }
}

/// Build a removal plan from the scan already used to select scheduled targets.
#[cfg(target_os = "linux")]
pub(crate) fn preview_batch_from_scan(
    scope: &crate::sweep::Scope,
    report: crate::sweep::ScanReport,
    targets: &[PathBuf],
    cancel: &AtomicBool,
) -> Result<ArtifactBatchPlan> {
    linux::preview_batch_from_scan(scope, report, targets, cancel)
}

/// Remove the previously reviewed directory after revalidation and explicit confirmation.
pub fn remove(
    scope: &crate::sweep::Scope,
    target: &Path,
    token: &str,
    cancel: &AtomicBool,
) -> Result<&'static str> {
    #[cfg(target_os = "linux")]
    {
        linux::remove(scope, target, token, cancel)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (scope, target, token, cancel);
        bail!("artifact cleanup is supported only on Linux")
    }
}

/// Remove one approved artifact while rechecking a schedule policy before and after quarantine.
#[cfg(target_os = "linux")]
pub(crate) fn remove_guarded(
    scope: &crate::sweep::Scope,
    target: &Path,
    token: &str,
    cancel: &AtomicBool,
    guard: &dyn Fn() -> Result<()>,
) -> Result<&'static str> {
    linux::remove_guarded(scope, target, token, cancel, guard)
}

/// Remove a reviewed batch after revalidating every target before the first mutation.
pub fn remove_batch(
    scope: &crate::sweep::Scope,
    targets: &[PathBuf],
    token: &str,
    cancel: &AtomicBool,
) -> Result<ArtifactBatchResult> {
    #[cfg(target_os = "linux")]
    {
        linux::remove_batch(scope, targets, token, cancel)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (scope, targets, token, cancel);
        bail!("artifact cleanup is supported only on Linux")
    }
}
