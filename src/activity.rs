//! Bounded process observations; absence of evidence does not prove inactivity.
use std::{path::PathBuf, sync::atomic::AtomicBool};

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static TEST_ACTIVITY_STATUS: std::cell::Cell<Option<&'static str>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) struct TestActivityStatus(Option<&'static str>);

#[cfg(all(test, target_os = "linux"))]
impl TestActivityStatus {
    pub(crate) fn set(status: &'static str) -> Self {
        Self(TEST_ACTIVITY_STATUS.with(|value| value.replace(Some(status))))
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for TestActivityStatus {
    fn drop(&mut self) {
        TEST_ACTIVITY_STATUS.with(|value| value.set(self.0));
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn inspect(paths: &[PathBuf], cancel: &AtomicBool) -> Vec<&'static str> {
    #[cfg(test)]
    if let Some(status) = TEST_ACTIVITY_STATUS.with(std::cell::Cell::get) {
        return vec![status; paths.len()];
    }
    scan(
        std::path::Path::new("/proc"),
        rustix::process::geteuid().as_raw(),
        paths,
        cancel,
        4096,
        131_072,
    )
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn inspect(paths: &[PathBuf], _: &AtomicBool) -> Vec<&'static str> {
    vec!["unavailable"; paths.len()]
}

#[cfg(target_os = "linux")]
fn scan(
    proc_root: &std::path::Path,
    uid: u32,
    paths: &[PathBuf],
    cancel: &AtomicBool,
    max_processes: usize,
    max_handles: usize,
) -> Vec<&'static str> {
    use std::{
        collections::HashMap,
        fs,
        os::unix::{ffi::OsStrExt, fs::MetadataExt},
        path::Path,
        sync::atomic::Ordering,
    };
    if paths.is_empty() {
        return Vec::new();
    }
    let Ok(processes) = fs::read_dir(proc_root) else {
        return vec!["unavailable"; paths.len()];
    };
    let mut targets: HashMap<&Path, Vec<usize>> = HashMap::new();
    for (index, path) in paths.iter().enumerate() {
        targets.entry(path.as_path()).or_default().push(index);
    }
    let mut found = vec![false; paths.len()];
    let mut executable_found = vec![false; paths.len()];
    let mut incomplete = false;
    let mut process_count = 0usize;
    let mut handle_count = 0usize;
    'processes: for entry in processes {
        if cancel.load(Ordering::Relaxed) {
            incomplete = true;
            break;
        }
        let Ok(entry) = entry else {
            incomplete = true;
            continue;
        };
        let name = entry.file_name();
        if name.as_bytes().is_empty() || !name.as_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        process_count += 1;
        if process_count > max_processes {
            incomplete = true;
            break;
        }
        let process = entry.path();
        match fs::metadata(&process) {
            Ok(metadata) if metadata.uid() != uid => continue,
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                incomplete = true;
                continue;
            }
        }
        incomplete |= !observe(&process.join("cwd"), &targets, &mut found);
        incomplete |= !observe(&process.join("exe"), &targets, &mut executable_found);
        let handles = match fs::read_dir(process.join("fd")) {
            Ok(handles) => handles,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                incomplete = true;
                continue;
            }
        };
        for handle in handles {
            if cancel.load(Ordering::Relaxed) {
                incomplete = true;
                break 'processes;
            }
            handle_count += 1;
            if handle_count > max_handles {
                incomplete = true;
                break 'processes;
            }
            match handle {
                Ok(handle) => incomplete |= !observe(&handle.path(), &targets, &mut found),
                Err(_) => incomplete = true,
            }
        }
    }
    found
        .into_iter()
        .zip(executable_found)
        .map(|(found, executable)| {
            if found {
                "open_handles_or_cwd_observed"
            } else if executable {
                "executable_observed"
            } else if incomplete {
                "inspection_incomplete"
            } else {
                "no_open_handles_or_cwd_observed"
            }
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn observe(
    link: &std::path::Path,
    targets: &std::collections::HashMap<&std::path::Path, Vec<usize>>,
    found: &mut [bool],
) -> bool {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    match std::fs::read_link(link) {
        Ok(path) => {
            let deleted = path
                .as_os_str()
                .as_bytes()
                .strip_suffix(b" (deleted)")
                .map(|p| PathBuf::from(std::ffi::OsString::from_vec(p.to_vec())));
            for candidate in std::iter::once(path.as_path()).chain(deleted.as_deref()) {
                if !candidate.is_absolute() {
                    continue;
                }
                for ancestor in candidate.ancestors() {
                    if let Some(indexes) = targets.get(ancestor) {
                        for &index in indexes {
                            found[index] = true;
                        }
                    }
                }
            }
            true
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink, sync::atomic::Ordering};

    #[test]
    fn reports_handles_deleted_paths_limits_and_cancellation() {
        let root = tempfile::tempdir().unwrap();
        let proc = root.path().join("proc");
        let process = proc.join("123");
        fs::create_dir_all(process.join("fd")).unwrap();
        let target = root.path().join("target");
        let other = root.path().join("other");
        symlink(root.path(), process.join("cwd")).unwrap();
        symlink(target.join("object (deleted)"), process.join("fd/1")).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let cancel = AtomicBool::new(false);
        let run = |processes, handles| {
            scan(
                &proc,
                uid,
                &[target.clone(), other.clone()],
                &cancel,
                processes,
                handles,
            )
        };
        assert_eq!(
            run(10, 10),
            [
                "open_handles_or_cwd_observed",
                "no_open_handles_or_cwd_observed"
            ]
        );
        fs::write(process.join("fd/2"), "not a proc link").unwrap();
        assert_eq!(
            run(10, 10),
            ["open_handles_or_cwd_observed", "inspection_incomplete"]
        );
        fs::remove_file(process.join("fd/2")).unwrap();
        assert_eq!(
            run(10, 0),
            ["inspection_incomplete", "inspection_incomplete"]
        );
        assert_eq!(
            run(0, 10),
            ["inspection_incomplete", "inspection_incomplete"]
        );
        cancel.store(true, Ordering::Relaxed);
        assert_eq!(
            run(10, 10),
            ["inspection_incomplete", "inspection_incomplete"]
        );
        assert_eq!(
            scan(
                &root.path().join("missing"),
                uid,
                &[target],
                &cancel,
                10,
                10
            ),
            ["unavailable"]
        );
    }

    #[test]
    fn reports_running_executable_and_incomplete_executable_inspection() {
        let root = tempfile::tempdir().unwrap();
        let proc = root.path().join("proc");
        let process = proc.join("123");
        fs::create_dir_all(process.join("fd")).unwrap();
        let target = root.path().join("tool");
        symlink(root.path(), process.join("cwd")).unwrap();
        symlink(target.join("bin/tool (deleted)"), process.join("exe")).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let cancel = AtomicBool::new(false);
        assert_eq!(
            scan(&proc, uid, std::slice::from_ref(&target), &cancel, 10, 10),
            ["executable_observed"]
        );
        fs::remove_file(process.join("exe")).unwrap();
        fs::write(process.join("exe"), "not a proc link").unwrap();
        assert_eq!(
            scan(&proc, uid, &[target], &cancel, 10, 10),
            ["inspection_incomplete"]
        );
    }
}
