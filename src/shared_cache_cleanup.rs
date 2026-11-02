//! Explicit, reviewed removal of one discovered shared cache directory.
use anyhow::{Result, bail};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[derive(Clone, Debug, Serialize)]
pub struct CacheRemovalPlan {
    pub name: &'static str,
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub target: PathBuf,
    pub classification: &'static str,
    pub consequence: &'static str,
    pub logical_bytes: u64,
    pub entries: Vec<crate::artifact_cleanup::ArtifactEntry>,
    pub preview_token: String,
    pub warning: &'static str,
}

pub fn display_path(path: &Path) -> String {
    crate::sweep::display_path(path)
}

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
        fs,
        os::unix::{ffi::OsStrExt, fs::MetadataExt},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
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
        parent: fs::File,
        target: fs::File,
        parent_id: Fingerprint,
        target_id: Fingerprint,
        tree: crate::guarded_tree::TreeSnapshot,
    }
    fn inspect(target: &Path, cancel: &AtomicBool) -> Result<Opened> {
        if !target.is_absolute()
            || target.parent().is_none()
            || target.canonicalize()? != target
            || dirs::home_dir()
                .and_then(|p| p.canonicalize().ok())
                .as_deref()
                == Some(target)
        {
            bail!(
                "cache must be an absolute canonical directory, not a filesystem or user-home root"
            );
        }
        let parent_path = target.parent().context("cache parent is unavailable")?;
        let parent = fs::File::from(openat2(
            rustix::fs::CWD,
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?);
        let target_fd = open(
            &parent,
            Path::new(target.file_name().context("cache name is unavailable")?),
            OFlags::RDONLY | OFlags::DIRECTORY,
        )?;
        let parent_id = fingerprint(&parent.metadata()?);
        let target_id = fingerprint(&target_fd.metadata()?);
        let uid = rustix::process::geteuid().as_raw();
        if parent_id.uid != uid
            || parent_id.mode & 0o022 != 0
            || target_id.uid != uid
            || target_id.mode & 0o022 != 0
        {
            bail!("cache and parent must be user-owned and not group/other writable");
        }
        let tree = crate::guarded_tree::snapshot(target_fd.try_clone()?, uid, cancel)?;
        if tree.has_project_manifest_at_root() {
            bail!(
                "cache root contains a project manifest; it may be a source project or an unusual cache layout, so removal is refused"
            );
        }
        if tree.has_symlinks() || tree.has_vcs_marker() {
            bail!("cache contains a symlink or version-control marker");
        }
        if fingerprint(&parent.metadata()?) != parent_id
            || fingerprint(&target_fd.metadata()?) != target_id
        {
            bail!("cache changed during inspection");
        }
        Ok(Opened {
            parent,
            target: target_fd,
            parent_id,
            target_id,
            tree,
        })
    }
    fn token(spec: &crate::cache::Spec, opened: &Opened) -> Result<String> {
        let mut hash = Sha256::new();
        for value in [
            b"upkit-shared-cache-v2".as_slice(),
            &fs::read("/proc/sys/kernel/random/boot_id")?,
            spec.name.as_bytes(),
            spec.path.as_os_str().as_bytes(),
            spec.classification.as_bytes(),
            spec.consequence.as_bytes(),
            &serde_json::to_vec(&opened.parent_id)?,
            &serde_json::to_vec(&opened.target_id)?,
            opened.tree.digest.as_bytes(),
        ] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        Ok(hex::encode(hash.finalize()))
    }
    pub(super) fn preview(target: &Path, cancel: &AtomicBool) -> Result<CacheRemovalPlan> {
        if cancel.load(Ordering::Relaxed) {
            bail!("cache preview cancelled");
        }
        let spec = crate::cache::selected_cache(target)?;
        if crate::activity::inspect(&[target.to_owned()], cancel)[0]
            != "no_open_handles_or_cwd_observed"
        {
            bail!("cache process activity was observed or could not be inspected completely");
        }
        let opened = inspect(target, cancel)?;
        let preview_token = token(&spec, &opened)?;
        let entries = opened
            .tree
            .review_entries()
            .into_iter()
            .map(|entry| crate::artifact_cleanup::ArtifactEntry {
                path: entry.path,
                kind: entry.kind,
                logical_bytes: entry.logical_bytes,
            })
            .collect();
        Ok(CacheRemovalPlan {
            name: spec.name,
            target: target.to_owned(),
            classification: spec.classification,
            consequence: spec.consequence,
            logical_bytes: opened.tree.logical_bytes,
            entries,
            preview_token,
            warning: "Permanently removes the selected shared cache and every listed entry, including any user data, source files, or other caches inside it. Upkit cannot distinguish dependency source from your own source inside a cache; inspect the listed paths before confirming. Dependencies may need downloading or recompilation. Workspace scan exclusions and profiles do not apply. The detected path is inferred; external cache programs are not run and their contents may remain. Concurrent filesystem or process activity can race. Failure can leave a partially removed cache in quarantine; reclaimed space is unknown.",
        })
    }
    fn target_absent(parent: &fs::File, name: &std::ffi::OsStr) -> bool {
        matches!(
            statat(parent, name, AtFlags::SYMLINK_NOFOLLOW),
            Err(rustix::io::Errno::NOENT)
        )
    }
    pub(super) fn remove(
        target: &Path,
        approved: &str,
        cancel: &AtomicBool,
    ) -> Result<&'static str> {
        let plan = preview(target, cancel)?;
        if plan.preview_token != approved {
            bail!("cache preview changed; review it again");
        }
        let spec = crate::cache::selected_cache(target)?;
        let opened = inspect(target, cancel)?;
        if token(&spec, &opened)? != approved {
            bail!("cache changed after preview");
        }
        remove_opened(&plan, spec, opened, cancel, |_| Ok(()))
    }
    fn remove_opened(
        plan: &CacheRemovalPlan,
        spec: crate::cache::Spec,
        opened: Opened,
        cancel: &AtomicBool,
        mut after_entry: impl FnMut(bool) -> Result<()>,
    ) -> Result<&'static str> {
        let Opened {
            parent,
            target,
            parent_id,
            target_id,
            tree,
        } = opened;
        let parent_path = plan
            .target
            .parent()
            .context("cache parent is unavailable")?;
        let name = plan
            .target
            .file_name()
            .context("cache name is unavailable")?;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut private = None;
        for _ in 0..32 {
            let candidate = format!(
                ".upkit-cache-{}-{stamp}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            match mkdirat(
                &parent,
                candidate.as_str(),
                Mode::RUSR | Mode::WUSR | Mode::XUSR,
            ) {
                Ok(()) => {
                    private = Some(candidate);
                    break;
                }
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(error).context("create cache quarantine"),
            }
        }
        let private = private.context("could not allocate cache quarantine")?;
        let quarantine_path = parent_path.join(&private);
        let quarantine = match open(
            &parent,
            Path::new(&private),
            OFlags::RDONLY | OFlags::DIRECTORY,
        ) {
            Ok(directory) => directory,
            Err(error) => {
                if unlinkat(&parent, private.as_str(), AtFlags::REMOVEDIR).is_err() {
                    bail!(
                        "open quarantine: {error:#}; inspect {}",
                        super::display_path(&quarantine_path)
                    );
                }
                return Err(error).context("open cache quarantine");
            }
        };
        let q_id = match quarantine.metadata() {
            Ok(meta) => fingerprint(&meta),
            Err(error) => {
                if unlinkat(&parent, private.as_str(), AtFlags::REMOVEDIR).is_err() {
                    bail!(
                        "inspect quarantine: {error}; inspect {}",
                        super::display_path(&quarantine_path)
                    );
                }
                return Err(error).context("inspect cache quarantine");
            }
        };
        let check = || -> Result<()> {
            let current_parent = fs::File::from(openat2(
                rustix::fs::CWD,
                parent_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )?);
            let current_q = open(
                &parent,
                Path::new(&private),
                OFlags::RDONLY | OFlags::DIRECTORY,
            )?;
            let q_current_id = fingerprint(&current_q.metadata()?);
            if !anchor(&fingerprint(&current_parent.metadata()?), &parent_id)
                || !anchor(&fingerprint(&parent.metadata()?), &parent_id)
                || !anchor(&q_current_id, &q_id)
                || !anchor(&fingerprint(&quarantine.metadata()?), &q_id)
                || q_current_id.mode & 0o777 != 0o700
                || !target_absent(&parent, name)
            {
                bail!("cache parent, quarantine, or original path changed");
            }
            Ok(())
        };
        let mut staged = false;
        let mut partial = false;
        let mut removed = false;
        let action = (|| -> Result<&'static str> {
            if cancel.load(Ordering::Relaxed) {
                bail!("cache removal cancelled");
            }
            if crate::cache::selected_cache(&plan.target)? != spec {
                bail!("cache configuration changed");
            }
            let current_parent = fs::File::from(openat2(
                rustix::fs::CWD,
                parent_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )?);
            let current_q = open(
                &parent,
                Path::new(&private),
                OFlags::RDONLY | OFlags::DIRECTORY,
            )?;
            if !anchor(&fingerprint(&current_parent.metadata()?), &parent_id)
                || !anchor(&fingerprint(&current_q.metadata()?), &q_id)
                || fingerprint(&target.metadata()?) != target_id
            {
                bail!("cache or parent changed");
            }
            renameat_with(&parent, name, &quarantine, "root", RenameFlags::NOREPLACE)
                .context("quarantine cache")?;
            staged = true;
            check()?;
            let staged_dir = open(
                &quarantine,
                Path::new("root"),
                OFlags::RDONLY | OFlags::DIRECTORY,
            )?;
            if !moved(&fingerprint(&staged_dir.metadata()?), &target_id)
                || !moved(&fingerprint(&target.metadata()?), &target_id)
            {
                bail!("quarantined cache changed");
            }
            let fresh =
                crate::guarded_tree::snapshot(staged_dir.try_clone()?, target_id.uid, cancel)?;
            if fresh.digest != tree.digest
                || fresh.count() != tree.count()
                || fresh.logical_bytes != tree.logical_bytes
            {
                bail!("quarantined cache contents changed");
            }
            drop(staged_dir);
            drop(target);
            if crate::cache::selected_cache(&plan.target)? != spec {
                bail!("cache configuration changed");
            }
            if crate::activity::inspect(&[quarantine_path.join("root")], cancel)[0]
                != "no_open_handles_or_cwd_observed"
            {
                bail!(
                    "cache process activity was observed or could not be inspected completely after quarantine"
                );
            }
            check()?;
            let staged_dir = open(
                &quarantine,
                Path::new("root"),
                OFlags::RDONLY | OFlags::DIRECTORY,
            )?;
            if !moved(&fingerprint(&staged_dir.metadata()?), &target_id) {
                bail!("quarantined cache changed");
            }
            let fresh =
                crate::guarded_tree::snapshot(staged_dir.try_clone()?, target_id.uid, cancel)?;
            if fresh.digest != tree.digest
                || fresh.count() != tree.count()
                || fresh.logical_bytes != tree.logical_bytes
            {
                bail!("quarantined cache contents changed");
            }
            crate::guarded_tree::remove(
                &quarantine,
                std::ffi::OsStr::new("root"),
                &staged_dir,
                &tree,
                cancel,
                &mut partial,
                |removed| {
                    check()?;
                    after_entry(removed)
                },
            )?;
            if cancel.load(Ordering::Relaxed) {
                bail!("cache removal cancelled");
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
                bail!("quarantined cache root was replaced");
            }
            unlinkat(&quarantine, "root", AtFlags::REMOVEDIR)
                .context("remove quarantined cache")?;
            staged = false;
            removed = true;
            Ok(if target_absent(&parent, name) {
                "verified_absent"
            } else {
                "unverified_replacement"
            })
        })();
        let mut cleanup_failed = false;
        if staged && !partial {
            if renameat_with(&quarantine, "root", &parent, name, RenameFlags::NOREPLACE).is_ok() {
                staged = false;
            } else {
                cleanup_failed = true;
            }
        }
        if staged {
            cleanup_failed = true;
        }
        if !cleanup_failed && unlinkat(&parent, private.as_str(), AtFlags::REMOVEDIR).is_err() {
            cleanup_failed = true;
        }
        match action {
            Ok(result) if !cleanup_failed => Ok(result),
            Ok(_) => bail!(
                "cache was removed; inspect quarantine {}",
                super::display_path(&quarantine_path)
            ),
            Err(error) => bail!(
                "{error:#}; cache {}{}",
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
                        super::display_path(&quarantine_path)
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
        use std::{os::unix::fs::PermissionsExt, process::Command};

        #[test]
        fn cancellation_after_first_entry_preserves_partial_quarantine() {
            if !Command::new("unshare")
                .args([
                    "--user",
                    "--map-root-user",
                    "--pid",
                    "--fork",
                    "--mount-proc",
                    "/bin/true",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
            {
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().join("home");
            let target = home.join("cache/go-build");
            fs::create_dir_all(&target).unwrap();
            let go_env = home.join("config/go/env");
            fs::create_dir_all(go_env.parent().unwrap()).unwrap();
            let modules = home.join("go/pkg/mod");
            fs::write(
                &go_env,
                format!("GOMODCACHE={}\nGOCACHEPROG=\n", modules.display()),
            )
            .unwrap();
            for path in [&home, &home.join("cache"), &target] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            for name in ["a", "z"] {
                fs::write(target.join(name), name).unwrap();
                fs::set_permissions(target.join(name), fs::Permissions::from_mode(0o600)).unwrap();
            }
            let output = Command::new("unshare")
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
                    "shared_cache_cleanup::linux::tests::partial_worker",
                    "--nocapture",
                ])
                .env_clear()
                .env("HOME", &home)
                .env("PATH", "/usr/bin:/bin")
                .env("GOENV", &go_env)
                .env("GOCACHE", &target)
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
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "isolated worker did not run"
            );
        }

        #[test]
        #[ignore = "executed by the isolated partial-removal fixture"]
        fn partial_worker() {
            let target = PathBuf::from(std::env::var_os("GOCACHE").unwrap());
            let cancel = AtomicBool::new(false);
            let spec = crate::cache::selected_cache(&target).unwrap();
            let opened = inspect(&target, &cancel).unwrap();
            let plan = CacheRemovalPlan {
                name: spec.name,
                target: target.clone(),
                classification: spec.classification,
                consequence: spec.consequence,
                logical_bytes: opened.tree.logical_bytes,
                entries: vec![],
                preview_token: token(&spec, &opened).unwrap(),
                warning: "fixture",
            };
            cancel.store(true, Ordering::Relaxed);
            assert!(remove_opened(&plan, spec, opened, &cancel, |_| Ok(())).is_err());
            assert!(target.join("a").exists() && target.join("z").exists());
            assert!(
                !fs::read_dir(target.parent().unwrap())
                    .unwrap()
                    .any(|entry| entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".upkit-cache-"))
            );
            cancel.store(false, Ordering::Relaxed);
            let spec = crate::cache::selected_cache(&target).unwrap();
            let opened = inspect(&target, &cancel).unwrap();
            let plan = CacheRemovalPlan {
                name: spec.name,
                target: target.clone(),
                classification: spec.classification,
                consequence: spec.consequence,
                logical_bytes: opened.tree.logical_bytes,
                entries: vec![],
                preview_token: token(&spec, &opened).unwrap(),
                warning: "fixture",
            };
            let error = remove_opened(&plan, spec, opened, &cancel, |removed| {
                if removed {
                    cancel.store(true, Ordering::Relaxed);
                }
                Ok(())
            })
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("partially removed") && error.contains("inspect quarantine"),
                "{error}"
            );
            assert!(!target.exists());
            let quarantine = fs::read_dir(target.parent().unwrap())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".upkit-cache-")
                })
                .unwrap();
            assert_eq!(fs::read_to_string(quarantine.join("root/a")).unwrap(), "a");
            assert!(!quarantine.join("root/z").exists());
        }
    }
}

pub fn preview(target: &Path, cancel: &AtomicBool) -> Result<CacheRemovalPlan> {
    #[cfg(target_os = "linux")]
    {
        linux::preview(target, cancel)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (target, cancel);
        bail!("shared-cache removal is supported only on Linux")
    }
}

pub fn remove(target: &Path, approved: &str, cancel: &AtomicBool) -> Result<&'static str> {
    #[cfg(target_os = "linux")]
    {
        linux::remove(target, approved, cancel)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (target, approved, cancel);
        bail!("shared-cache removal is supported only on Linux")
    }
}
