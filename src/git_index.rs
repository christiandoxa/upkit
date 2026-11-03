//! Limited, read-only evidence from Git's index. This does not prove a target is safe.
//! Linux accepts protected ELF Git only; same-UID-owned code and its runtime dependencies are trusted.
use anyhow::{Result, bail};
#[cfg(target_os = "linux")]
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

#[cfg(target_os = "linux")]
mod mount_provenance;

fn command(git: &Path, cwd: Option<&fs::File>) -> Command {
    #[cfg(target_os = "linux")]
    let program = if git.is_relative() && git.components().count() == 1 {
        PathBuf::from(".").join(git)
    } else {
        git.to_owned()
    };
    #[cfg(not(target_os = "linux"))]
    let program = git;
    let mut command = Command::new(program);
    #[cfg(target_os = "linux")]
    if let Some(cwd) = cwd {
        use std::os::fd::AsRawFd;

        command.current_dir(format!("/proc/self/fd/{}", cwd.as_raw_fd()));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cwd;
    for (key, _) in env::vars_os() {
        let name = key.to_string_lossy().to_ascii_uppercase();
        if name.starts_with("GIT_") || (cfg!(target_os = "linux") && name.starts_with("LD_")) {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "")
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_0", "false")
        .env("GIT_CONFIG_KEY_1", "core.hooksPath")
        .env(
            "GIT_CONFIG_VALUE_1",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped());
    command
}

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn wait(child: &mut Child, cancel: &AtomicBool) -> Result<Option<std::process::ExitStatus>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if cancel.load(Ordering::Relaxed) {
            stop(child);
            bail!("preview cancelled");
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {}
            Err(_) => {
                stop(child);
                return Ok(None);
            }
        }
        if Instant::now() >= deadline {
            stop(child);
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn supported_version(version: &str) -> Option<bool> {
    let version = version.trim().strip_prefix("git version ")?;
    if version.contains(".rc") || version.contains("-rc") {
        return None;
    }
    let mut parts = version.split('.');
    let (Some(major), Some(minor)) = (
        parts.next().and_then(|v| v.parse::<u32>().ok()),
        parts.next().and_then(|v| v.parse::<u32>().ok()),
    ) else {
        return None;
    };
    (major == 2 && minor >= 36).then_some(minor >= 45)
}

pub struct Git {
    path: PathBuf,
    identity: ExecutableIdentity,
    #[cfg(target_os = "linux")]
    cwd: Option<fs::File>,
    #[cfg(all(test, target_os = "linux"))]
    allow_test_mocks: bool,
    #[cfg(target_os = "linux")]
    version: String,
    no_lazy_fetch: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExecutableIdentity {
    path: PathBuf,
    size: u64,
    modified: Option<SystemTime>,
    #[cfg(target_os = "linux")]
    resolved_path: PathBuf,
    #[cfg(target_os = "linux")]
    cwd: Option<WorkingDirectoryIdentity>,
    #[cfg(target_os = "linux")]
    device: u64,
    #[cfg(target_os = "linux")]
    inode: u64,
    #[cfg(target_os = "linux")]
    uid: u32,
    #[cfg(target_os = "linux")]
    mode: u32,
    #[cfg(target_os = "linux")]
    ctime: i64,
    #[cfg(target_os = "linux")]
    ctime_ns: i64,
    #[cfg(target_os = "linux")]
    mount_proofs: Vec<mount_provenance::MountProof>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct WorkingDirectoryIdentity {
    device: u64,
    inode: u64,
    mount: mount_provenance::MountProof,
}

impl ExecutableIdentity {
    #[cfg(not(target_os = "linux"))]
    fn capture(path: &Path) -> Option<Self> {
        let metadata = fs::symlink_metadata(path).ok()?;
        if !metadata.file_type().is_file() {
            return None;
        }
        Some(Self {
            path: path.to_owned(),
            size: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }

    #[cfg(target_os = "linux")]
    fn capture_at(path: &Path, cwd: Option<&fs::File>) -> Option<Self> {
        Self::capture_at_with_mocks(path, cwd, false)
    }

    #[cfg(all(test, target_os = "linux"))]
    fn capture_at_for_test(path: &Path, cwd: Option<&fs::File>) -> Option<Self> {
        Self::capture_at_with_mocks(path, cwd, true)
    }

    #[cfg(target_os = "linux")]
    fn capture_at_with_mocks(
        path: &Path,
        cwd: Option<&fs::File>,
        allow_test_mocks: bool,
    ) -> Option<Self> {
        let cwd_file = match cwd {
            Some(cwd) => cwd.try_clone().ok()?,
            None => fs::File::open(".").ok()?,
        };
        let execution_path = if path.is_absolute() {
            path.canonicalize().ok()?
        } else {
            path.to_owned()
        };
        let (metadata, resolved_path, working_directory, mount_proofs) =
            if execution_path.is_absolute() {
                trusted_linux_absolute_executable(&execution_path, &cwd_file, allow_test_mocks)?
            } else {
                trusted_linux_relative_executable(&execution_path, &cwd_file, allow_test_mocks)?
            };
        if !metadata.file_type().is_file() {
            return None;
        }
        Some(Self {
            path: execution_path,
            size: metadata.len(),
            modified: metadata.modified().ok(),
            resolved_path,
            cwd: Some(working_directory),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            ctime: metadata.ctime(),
            ctime_ns: metadata.ctime_nsec(),
            mount_proofs,
        })
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct LinuxOwnerTrust {
    euid: u32,
    overflow_uid: u32,
    host_root_mapped: bool,
}

#[cfg(target_os = "linux")]
fn linux_owner_trust() -> Option<LinuxOwnerTrust> {
    let euid = rustix::process::geteuid().as_raw();
    let overflow_uid = fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if euid == overflow_uid {
        return None;
    }
    let host_root_mapped =
        fs::read_to_string("/proc/self/uid_map").is_ok_and(|map| uid_map_proves_host_root(&map));
    Some(LinuxOwnerTrust {
        euid,
        overflow_uid,
        host_root_mapped,
    })
}

#[cfg(target_os = "linux")]
fn uid_map_proves_host_root(map: &str) -> bool {
    map.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next().and_then(|value| value.parse::<u64>().ok()) == Some(0)
            && fields.next().and_then(|value| value.parse::<u64>().ok()) == Some(0)
            && fields.next().and_then(|value| value.parse::<u64>().ok()) == Some(u32::MAX as u64)
    })
}

#[cfg(target_os = "linux")]
fn trusted_linux_owner(owner: u32, trust: LinuxOwnerTrust) -> bool {
    trust.euid != trust.overflow_uid
        && owner != trust.overflow_uid
        && ((owner == trust.euid) || (owner == 0 && trust.host_root_mapped))
}

#[cfg(target_os = "linux")]
fn trusted_linux_parent(metadata: &fs::Metadata, trust: LinuxOwnerTrust) -> bool {
    trusted_linux_owner(metadata.uid(), trust)
}

#[cfg(target_os = "linux")]
fn trusted_relative_directory(owner: u32, mode: u32, trust: LinuxOwnerTrust) -> bool {
    trust.euid != trust.overflow_uid && owner == trust.euid && mode & 0o022 == 0
}

#[cfg(target_os = "linux")]
fn trusted_linux_absolute_executable(
    path: &Path,
    cwd: &fs::File,
    allow_test_mocks: bool,
) -> Option<(
    fs::Metadata,
    PathBuf,
    WorkingDirectoryIdentity,
    Vec<mount_provenance::MountProof>,
)> {
    use rustix::fs::CWD;
    use std::os::unix::fs::MetadataExt;

    let trust = linux_owner_trust()?;
    let mount_table = mount_provenance::MountTable::read_current().ok()?;
    let working_directory = trusted_working_directory(cwd, &mount_table, trust)?;
    if !path.is_absolute() {
        return None;
    }
    let mut directory = fs::File::from(
        openat2(
            CWD,
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .ok()?,
    );
    let root = directory.metadata().ok()?;
    if !root.is_dir() || !trusted_linux_parent(&root, trust) || root.mode() & 0o022 != 0 {
        return None;
    }
    let mut mount_proofs = vec![mount_table.prove(&directory).ok()?];
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name),
            _ => return None,
        }
    }
    if components.is_empty() {
        return None;
    }
    for (index, component) in components.iter().enumerate() {
        let executable = index + 1 == components.len();
        let flags = if executable {
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK
        } else {
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC
        };
        let mut opened = fs::File::from(
            openat2(
                &directory,
                *component,
                flags,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .ok()?,
        );
        let metadata = opened.metadata().ok()?;
        mount_proofs.push(mount_table.prove(&opened).ok()?);
        let mode = metadata.mode();
        if executable {
            if !trusted_linux_owner(metadata.uid(), trust)
                || !metadata.file_type().is_file()
                || mode & 0o111 == 0
                || mode & 0o022 != 0
                || mode & 0o6000 != 0
                || (!allow_test_mocks && !linux_elf(&mut opened))
            {
                return None;
            }
            let fd_path = PathBuf::from(format!(
                "/proc/self/fd/{}",
                std::os::fd::AsRawFd::as_raw_fd(&opened)
            ));
            let resolved_path = fs::read_link(fd_path).ok()?;
            if !resolved_path.is_absolute()
                || resolved_path.to_string_lossy().ends_with(" (deleted)")
            {
                return None;
            }
            return Some((metadata, resolved_path, working_directory, mount_proofs));
        }
        if !metadata.is_dir() || !trusted_linux_parent(&metadata, trust) {
            return None;
        }
        if mode & 0o022 != 0 && !(mode & 0o1000 != 0 && trusted_linux_parent(&metadata, trust)) {
            return None;
        }
        directory = opened;
    }
    None
}

#[cfg(target_os = "linux")]
fn trusted_linux_relative_executable(
    path: &Path,
    cwd: &fs::File,
    allow_test_mocks: bool,
) -> Option<(
    fs::Metadata,
    PathBuf,
    WorkingDirectoryIdentity,
    Vec<mount_provenance::MountProof>,
)> {
    use std::os::fd::AsRawFd;

    let trust = linux_owner_trust()?;
    let mount_table = mount_provenance::MountTable::read_current().ok()?;
    let cwd_identity = trusted_working_directory(cwd, &mount_table, trust)?;
    let mut mount_proofs = Vec::new();
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => components.push(name),
            _ => return None,
        }
    }
    if components.is_empty() {
        return None;
    }
    let mut prefix = PathBuf::new();
    let mut final_metadata = None;
    let mut resolved_path = None;
    for (index, component) in components.iter().enumerate() {
        prefix.push(component);
        let executable = index + 1 == components.len();
        let flags = if executable {
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK
        } else {
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC
        };
        let mut opened = fs::File::from(
            openat2(
                cwd,
                &prefix,
                flags,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .ok()?,
        );
        let metadata = opened.metadata().ok()?;
        mount_proofs.push(mount_table.prove(&opened).ok()?);
        if metadata.uid() != trust.euid || metadata.uid() == trust.overflow_uid {
            return None;
        }
        let mode = metadata.mode();
        if executable {
            if !metadata.file_type().is_file()
                || mode & 0o111 == 0
                || mode & 0o022 != 0
                || mode & 0o6000 != 0
                || (!allow_test_mocks && !linux_elf(&mut opened))
            {
                return None;
            }
            let fd_path = PathBuf::from(format!("/proc/self/fd/{}", opened.as_raw_fd()));
            let actual = fs::read_link(fd_path).ok()?;
            if !actual.is_absolute() || actual.to_string_lossy().ends_with(" (deleted)") {
                return None;
            }
            final_metadata = Some(metadata);
            resolved_path = Some(actual);
        } else if !metadata.is_dir() || !trusted_relative_directory(metadata.uid(), mode, trust) {
            return None;
        }
    }
    Some((final_metadata?, resolved_path?, cwd_identity, mount_proofs))
}

#[cfg(target_os = "linux")]
fn trusted_working_directory(
    cwd: &fs::File,
    mount_table: &mount_provenance::MountTable,
    trust: LinuxOwnerTrust,
) -> Option<WorkingDirectoryIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = cwd.metadata().ok()?;
    if !metadata.is_dir() || !trusted_relative_directory(metadata.uid(), metadata.mode(), trust) {
        return None;
    }
    Some(WorkingDirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mount: mount_table.prove(cwd).ok()?,
    })
}

#[cfg(target_os = "linux")]
fn linux_elf(file: &mut fs::File) -> bool {
    // shortcut: reject shebang wrappers until their interpreters and PATH-resolved helpers can be trusted.
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).is_ok() && magic == *b"\x7fELF"
}

impl Git {
    #[cfg(target_os = "linux")]
    pub(crate) fn evidence_id(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"upkit-git-evidence-v1");
        hash_bytes(&mut hash, &path_bytes(&self.identity.path));
        hash_bytes(&mut hash, &path_bytes(&self.identity.resolved_path));
        match &self.identity.cwd {
            Some(cwd) => {
                hash.update([1]);
                hash.update(cwd.device.to_be_bytes());
                hash.update(cwd.inode.to_be_bytes());
                hash.update(cwd.mount.id.to_be_bytes());
                hash.update(cwd.mount.signature);
            }
            None => hash.update([0]),
        }
        hash.update(self.identity.size.to_be_bytes());
        if let Some(modified) = self.identity.modified {
            hash.update(
                modified
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .to_be_bytes(),
            );
        }
        #[cfg(target_os = "linux")]
        {
            hash.update(self.identity.device.to_be_bytes());
            hash.update(self.identity.inode.to_be_bytes());
            hash.update(self.identity.uid.to_be_bytes());
            hash.update(self.identity.mode.to_be_bytes());
            hash.update(self.identity.ctime.to_be_bytes());
            hash.update(self.identity.ctime_ns.to_be_bytes());
            for mount in &self.identity.mount_proofs {
                hash.update(mount.id.to_be_bytes());
                hash.update(mount.signature);
            }
        }
        hash_bytes(&mut hash, self.version.as_bytes());
        hash.update([u8::from(self.no_lazy_fetch)]);
        hex::encode(hash.finalize())
    }

    fn identity_matches(&self) -> bool {
        #[cfg(target_os = "linux")]
        #[cfg(test)]
        let current = if self.allow_test_mocks {
            ExecutableIdentity::capture_at_for_test(&self.path, self.cwd.as_ref())
        } else {
            ExecutableIdentity::capture_at(&self.path, self.cwd.as_ref())
        };
        #[cfg(all(target_os = "linux", not(test)))]
        let current = ExecutableIdentity::capture_at(&self.path, self.cwd.as_ref());
        #[cfg(not(target_os = "linux"))]
        let current = ExecutableIdentity::capture(&self.path);
        current.as_ref() == Some(&self.identity)
    }

    #[cfg(all(test, unix))]
    fn for_test(path: PathBuf, no_lazy_fetch: bool) -> Self {
        #[cfg(target_os = "linux")]
        let (path, cwd) = if path.is_relative() {
            (
                PathBuf::from(".").join(path),
                Some(fs::File::open(".").expect("test Git cwd")),
            )
        } else {
            let anchored = path.parent().and_then(|parent| {
                let cwd = fs::File::open(parent).ok()?;
                let metadata = cwd.metadata().ok()?;
                let trust = linux_owner_trust()?;
                let name = path.file_name()?;
                trusted_relative_directory(metadata.uid(), metadata.mode(), trust)
                    .then(|| (PathBuf::from(".").join(name), Some(cwd)))
            });
            anchored.unwrap_or((path, None))
        };
        #[cfg(target_os = "linux")]
        let cwd = Some(cwd.unwrap_or_else(|| fs::File::open(".").expect("test Git cwd")));
        #[cfg(target_os = "linux")]
        let identity = ExecutableIdentity::capture_at_for_test(&path, cwd.as_ref())
            .expect("test Git identity");
        #[cfg(not(target_os = "linux"))]
        let identity = ExecutableIdentity::capture(&path).expect("test Git identity");
        Self {
            path,
            identity,
            #[cfg(target_os = "linux")]
            cwd,
            #[cfg(target_os = "linux")]
            allow_test_mocks: true,
            #[cfg(target_os = "linux")]
            version: "git version 2.45.0".into(),
            no_lazy_fetch,
        }
    }
}

fn git_command(git: &Git) -> Command {
    #[cfg(target_os = "linux")]
    {
        command(&git.path, git.cwd.as_ref())
    }
    #[cfg(not(target_os = "linux"))]
    {
        command(&git.path, None)
    }
}

#[cfg(target_os = "linux")]
fn hash_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

#[cfg(target_os = "linux")]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

pub fn available(cancel: &AtomicBool, roots: &[PathBuf]) -> Result<Option<Git>> {
    let Some(git) = git_candidate_from_path() else {
        return Ok(None);
    };
    available_from(&git, cancel, roots)
}

fn git_candidate_from_path() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        git_candidate_from_search_path(&env::var_os("PATH")?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        which::which("git").ok()
    }
}

#[cfg(target_os = "linux")]
fn git_candidate_from_search_path(path: &OsStr) -> Option<PathBuf> {
    if path.is_empty() {
        return None;
    }
    env::split_paths(path).find_map(|directory| {
        let candidate = directory.join("git");
        let candidate = if candidate.components().count() == 1 {
            PathBuf::from(".").join(candidate)
        } else {
            candidate
        };
        let metadata = fs::metadata(&candidate).ok()?;
        (metadata.is_file() && metadata.mode() & 0o111 != 0).then_some(candidate)
    })
}

fn available_from(candidate: &Path, cancel: &AtomicBool, roots: &[PathBuf]) -> Result<Option<Git>> {
    #[cfg(target_os = "linux")]
    let cwd = if candidate.is_relative() {
        let Ok(cwd) = fs::File::open(".") else {
            return Ok(None);
        };
        Some(cwd)
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let cwd: Option<fs::File> = None;
    available_from_at(candidate, cwd, cancel, roots)
}

pub(crate) fn available_from_at(
    candidate: &Path,
    cwd: Option<fs::File>,
    cancel: &AtomicBool,
    roots: &[PathBuf],
) -> Result<Option<Git>> {
    if cancel.load(Ordering::Relaxed) {
        bail!("preview cancelled");
    }
    if candidate.is_relative() && cwd.is_none() {
        return Ok(None);
    }
    let Some(cwd) = cwd.or_else(|| fs::File::open(".").ok()) else {
        return Ok(None);
    };

    let git = if candidate.is_absolute() {
        let Ok(git) = candidate.canonicalize() else {
            return Ok(None);
        };
        git
    } else if candidate.components().count() == 1 {
        PathBuf::from(".").join(candidate)
    } else {
        candidate.to_owned()
    };
    #[cfg(target_os = "linux")]
    let Some(identity) = ExecutableIdentity::capture_at(&git, Some(&cwd)) else {
        return Ok(None);
    };
    #[cfg(not(target_os = "linux"))]
    let Some(identity) = ExecutableIdentity::capture(&git) else {
        return Ok(None);
    };
    #[cfg(target_os = "linux")]
    let resolved_path = &identity.resolved_path;
    #[cfg(not(target_os = "linux"))]
    let resolved_path = &git;
    if roots.iter().any(|root| resolved_path.starts_with(root)) {
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    let current = ExecutableIdentity::capture_at(&git, Some(&cwd));
    #[cfg(not(target_os = "linux"))]
    let current = ExecutableIdentity::capture(&git);
    if current.as_ref() != Some(&identity) {
        return Ok(None);
    }
    let Ok(mut child) = command(&git, Some(&cwd)).arg("--version").spawn() else {
        return Ok(None);
    };
    let waited = wait(&mut child, cancel);
    #[cfg(target_os = "linux")]
    let current = ExecutableIdentity::capture_at(&git, Some(&cwd));
    #[cfg(not(target_os = "linux"))]
    let current = ExecutableIdentity::capture(&git);
    if current.as_ref() != Some(&identity) {
        return Ok(None);
    }
    let status = waited?;
    if !status.is_some_and(|status| status.success()) {
        return Ok(None);
    }
    let mut version = String::new();
    if child
        .stdout
        .take()
        .is_none_or(|mut output| output.read_to_string(&mut version).is_err())
    {
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    let current = ExecutableIdentity::capture_at(&git, Some(&cwd));
    #[cfg(not(target_os = "linux"))]
    let current = ExecutableIdentity::capture(&git);
    if current.as_ref() != Some(&identity) {
        return Ok(None);
    }
    Ok(supported_version(&version).map(|no_lazy_fetch| Git {
        path: git,
        identity,
        #[cfg(target_os = "linux")]
        cwd: Some(cwd),
        #[cfg(all(test, target_os = "linux"))]
        allow_test_mocks: false,
        #[cfg(target_os = "linux")]
        version,
        no_lazy_fetch,
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Query {
    Found,
    NoMatch,
    Unavailable,
}

fn literal_pathspec(project: &Path, target: &Path) -> Option<OsString> {
    let relative = target.strip_prefix(project).ok()?;
    let mut literal = OsString::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return None;
        };
        if !literal.is_empty() {
            literal.push(OsStr::new("/"));
        }
        literal.push(part);
    }
    if literal.is_empty() {
        return None;
    }
    let mut pathspec = OsString::from(":(literal,icase)");
    pathspec.push(literal);
    Some(pathspec)
}

fn query(
    git: &Git,
    project: &Path,
    target: &Path,
    head: bool,
    cancel: &AtomicBool,
) -> Result<Query> {
    if cancel.load(Ordering::Relaxed) {
        bail!("preview cancelled");
    }
    let Some(pathspec) = literal_pathspec(project, target) else {
        return Ok(Query::Unavailable);
    };
    let mut git_command = git_command(git);
    git_command.arg("--no-optional-locks");
    if git.no_lazy_fetch {
        git_command.arg("--no-lazy-fetch");
    }
    git_command.arg("--no-replace-objects");
    git_command
        .arg("-C")
        .arg(project)
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("ls-files")
        .arg("--cached");
    if head {
        git_command.arg("--with-tree=HEAD");
    }
    git_command.arg("-z").arg("--").arg(pathspec);
    stream_query(git, &mut git_command, cancel)
}

fn stream_query(git: &Git, command: &mut Command, cancel: &AtomicBool) -> Result<Query> {
    if !git.identity_matches() {
        return Ok(Query::Unavailable);
    }
    let result = stream_query_inner(command, cancel);
    if !git.identity_matches() && !cancel.load(Ordering::Relaxed) {
        return Ok(Query::Unavailable);
    }
    result
}

fn stream_query_inner(command: &mut Command, cancel: &AtomicBool) -> Result<Query> {
    let Ok(mut child) = command.spawn() else {
        return Ok(Query::Unavailable);
    };
    let Some(mut stdout) = child.stdout.take() else {
        stop(&mut child);
        return Ok(Query::Unavailable);
    };
    let (send, receive) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut byte = [0u8; 1];
        let _ = send.send(stdout.read(&mut byte));
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if cancel.load(Ordering::Relaxed) {
            stop(&mut child);
            bail!("preview cancelled");
        }
        match receive.recv_timeout(Duration::from_millis(20)) {
            Ok(Ok(count)) if count > 0 => {
                stop(&mut child);
                return Ok(Query::Found);
            }
            Ok(Ok(_)) => {
                let status = wait(&mut child, cancel)?;
                return Ok(match status.and_then(|status| status.code()) {
                    Some(0) => Query::NoMatch,
                    _ => Query::Unavailable,
                });
            }
            Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                stop(&mut child);
                return Ok(Query::Unavailable);
            }
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() >= deadline => {
                stop(&mut child);
                return Ok(Query::Unavailable);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

fn capture_bounded(
    git: &Git,
    command: &mut Command,
    cancel: &AtomicBool,
    limit: usize,
) -> Result<Option<Vec<u8>>> {
    if !git.identity_matches() {
        return Ok(None);
    }
    let result = capture_bounded_inner(command, cancel, limit);
    if !git.identity_matches() && !cancel.load(Ordering::Relaxed) {
        return Ok(None);
    }
    result
}

fn capture_bounded_inner(
    command: &mut Command,
    cancel: &AtomicBool,
    limit: usize,
) -> Result<Option<Vec<u8>>> {
    let Ok(mut child) = command.spawn() else {
        return Ok(None);
    };
    let Some(mut output) = child.stdout.take() else {
        stop(&mut child);
        return Ok(None);
    };
    let (send, receive) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = output
            .by_ref()
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes);
        let _ = send.send((result, bytes));
    });
    let status = wait(&mut child, cancel)?;
    let Ok((Ok(_), bytes)) = receive.recv_timeout(Duration::from_millis(100)) else {
        return Ok(None);
    };
    Ok((status.is_some_and(|status| status.success()) && bytes.len() <= limit).then_some(bytes))
}

/// Older Git cannot disable lazy fetch itself; reject repositories configured as partial clones.
fn legacy_repo_complete(git: &Git, project: &Path, cancel: &AtomicBool) -> Result<bool> {
    if git.no_lazy_fetch {
        return Ok(true);
    }
    let mut config = git_command(git);
    config
        .args(["--no-optional-locks", "--no-replace-objects", "-C"])
        .arg(project)
        .args([
            "-c",
            "upkit.safetycheck=present",
            "config",
            "--name-only",
            "-z",
            "--get-regexp",
            r"^(upkit\.safetycheck$|extensions\.|remote\.)",
        ]);
    // shortcut: reject over 64 KiB of matching config keys; stream them if unusually large configurations need support.
    let Some(keys) = capture_bounded(git, &mut config, cancel, 64 * 1024)? else {
        return Ok(false);
    };
    if !keys.ends_with(b"\0") {
        return Ok(false);
    }
    let mut sentinel = false;
    for key in keys.split(|byte| *byte == 0).filter(|key| !key.is_empty()) {
        if key == b"upkit.safetycheck" {
            sentinel = true;
        }
        if key == b"extensions.partialclone"
            || (key.starts_with(b"remote.")
                && (key.ends_with(b".promisor") || key.ends_with(b".partialclonefilter")))
        {
            return Ok(false);
        }
    }
    Ok(sentinel)
}

fn no_grafts(git: &Git, project: &Path, cancel: &AtomicBool) -> Result<bool> {
    let mut query = git_command(git);
    query
        .args(["--no-optional-locks", "--no-replace-objects", "-C"])
        .arg(project)
        .args([
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "info/grafts",
        ]);
    // shortcut: reject paths over 16 KiB; increase the limit if supported filesystems need longer paths.
    let Some(mut output) = capture_bounded(git, &mut query, cancel, 16 * 1024)? else {
        return Ok(false);
    };
    if output.pop() != Some(b'\n') || output.contains(&0) {
        return Ok(false);
    }
    #[cfg(unix)]
    let path = {
        use std::os::unix::ffi::OsStringExt;
        PathBuf::from(OsString::from_vec(output))
    };
    #[cfg(not(unix))]
    let path = match String::from_utf8(output) {
        Ok(path) => PathBuf::from(path),
        Err(_) => return Ok(false),
    };
    if !path.is_absolute()
        || !path.ends_with(Path::new("info/grafts"))
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        || !path.parent().is_some_and(|parent| parent.is_dir())
    {
        return Ok(false);
    }
    Ok(
        matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
    )
}

/// Conservative evidence from every reachable ref. Missing history remains unavailable.
pub fn history_status(
    git: Option<&Git>,
    project: &Path,
    target: &Path,
    cancel: &AtomicBool,
) -> Result<&'static str> {
    if cancel.load(Ordering::Relaxed) {
        bail!("preview cancelled");
    }
    let Some(git) = git else {
        return Ok("unavailable");
    };
    if !legacy_repo_complete(git, project, cancel)? || !no_grafts(git, project, cancel)? {
        return Ok("unavailable");
    }
    let Some(pathspec) = literal_pathspec(project, target) else {
        return Ok("unavailable");
    };
    let mut shallow = git_command(git);
    shallow.arg("--no-optional-locks");
    if git.no_lazy_fetch {
        shallow.arg("--no-lazy-fetch");
    }
    shallow
        .args(["--no-replace-objects", "-C"])
        .arg(project)
        .args(["rev-parse", "--is-shallow-repository"]);
    if capture_bounded(git, &mut shallow, cancel, 32)?.as_deref() != Some(b"false\n") {
        return Ok("unavailable");
    }
    let mut log = git_command(git);
    log.arg("--no-optional-locks");
    if git.no_lazy_fetch {
        log.arg("--no-lazy-fetch");
    }
    log.args(["--no-replace-objects", "-C"])
        .arg(project)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "log.showSignature=false",
            "log",
            "--all",
            "--format=",
            "--name-only",
            "-z",
            "--full-history",
            "--no-renames",
            "--no-ext-diff",
            "--no-notes",
            "--root",
            "--",
        ])
        .arg(pathspec);
    let result = stream_query(git, &mut log, cancel)?;
    if !legacy_repo_complete(git, project, cancel)? || !no_grafts(git, project, cancel)? {
        return Ok("unavailable");
    }
    Ok(match result {
        Query::Found => "matching_entry_in_git_history",
        Query::NoMatch => "no_matching_entries_in_git_history",
        Query::Unavailable => "unavailable",
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn clear_for_removal(
    git: &Git,
    project: &Path,
    target: &Path,
    cancel: &AtomicBool,
) -> Result<()> {
    let (index, head) = status(Some(git), project, target, cancel)?;
    let history = history_status(Some(git), project, target, cancel)?;
    if index != "no_matching_entries_in_git_index"
        || head != "no_matching_entries_in_head_or_index"
        || history != "no_matching_entries_in_git_history"
    {
        bail!("Git index, HEAD, or reachable history could not rule out tracked files");
    }
    Ok(())
}

pub fn status(
    git: Option<&Git>,
    project: &Path,
    target: &Path,
    cancel: &AtomicBool,
) -> Result<(&'static str, &'static str)> {
    if cancel.load(Ordering::Relaxed) {
        bail!("preview cancelled");
    }
    let Some(git) = git else {
        return Ok(("unavailable", "unavailable"));
    };
    let index = query(git, project, target, false, cancel)?;
    let index_status = match index {
        Query::Found => "tracked_in_index",
        Query::NoMatch => "no_matching_entries_in_git_index",
        Query::Unavailable => "unavailable",
    };
    let head_status = if !legacy_repo_complete(git, project, cancel)? {
        "unavailable"
    } else {
        let result = query(git, project, target, true, cancel)?;
        if !legacy_repo_complete(git, project, cancel)? {
            return Ok((index_status, "unavailable"));
        }
        match result {
            Query::Found => "matching_entry_in_head_or_index",
            Query::NoMatch => "no_matching_entries_in_head_or_index",
            Query::Unavailable => "unavailable",
        }
    };
    Ok((index_status, head_status))
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::clear_for_removal;
    use super::supported_version;
    #[cfg(target_os = "linux")]
    use super::{Query, query};
    #[cfg(target_os = "linux")]
    use std::sync::atomic::AtomicBool;

    #[cfg(unix)]
    fn private_tempdir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[cfg(target_os = "linux")]
    fn real_git_path() -> Option<std::path::PathBuf> {
        use std::os::unix::fs::MetadataExt;

        ["/usr/bin/git", "/bin/git"]
            .into_iter()
            .map(std::path::PathBuf::from)
            .chain(which::which("git"))
            .find_map(|candidate| {
                let path = candidate.canonicalize().ok()?;
                let metadata = std::fs::metadata(&path).ok()?;
                if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
                    return None;
                }
                let mut file = std::fs::File::open(&path).ok()?;
                super::linux_elf(&mut file).then_some(path)
            })
    }

    #[cfg(unix)]
    fn copy_git(dir: &tempfile::TempDir, source: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let bin = dir.path().join("fixture-bin");
        std::fs::create_dir(&bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
        let git = bin.join("git");
        std::fs::copy(source, &git).unwrap();
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
        git
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn real_git_path() -> Option<std::path::PathBuf> {
        which::which("git").ok()?.canonicalize().ok()
    }

    #[test]
    fn git_version_detects_lazy_fetch_control() {
        assert_eq!(supported_version("git version 2.35.9"), None);
        assert_eq!(
            supported_version("git version 2.36.0.windows.1"),
            Some(false)
        );
        assert_eq!(supported_version("git version 2.45.0"), Some(true));
        assert_eq!(supported_version("git version 2.45.0-rc1"), None);
        assert_eq!(supported_version("unexpected"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_owner_trust_rejects_overflow_and_unproven_namespace_root() {
        use super::{LinuxOwnerTrust, trusted_linux_owner, trusted_relative_directory};

        let rootless = LinuxOwnerTrust {
            euid: 0,
            overflow_uid: 65534,
            host_root_mapped: false,
        };
        assert!(trusted_linux_owner(0, rootless));
        assert!(!trusted_linux_owner(1000, rootless));
        assert!(trusted_relative_directory(0, 0o700, rootless));
        assert!(!trusted_relative_directory(65534, 0o700, rootless));
        assert!(!trusted_relative_directory(0, 0o770, rootless));

        let ordinary_user = LinuxOwnerTrust {
            euid: 1000,
            overflow_uid: 65534,
            host_root_mapped: false,
        };
        assert!(trusted_linux_owner(1000, ordinary_user));
        assert!(!trusted_linux_owner(0, ordinary_user));
        assert!(!trusted_linux_owner(65534, ordinary_user));

        let ambiguous_euid = LinuxOwnerTrust {
            euid: 65534,
            overflow_uid: 65534,
            host_root_mapped: true,
        };
        assert!(!trusted_linux_owner(65534, ambiguous_euid));
        assert!(!trusted_linux_owner(0, ambiguous_euid));

        let ambiguous_root = LinuxOwnerTrust {
            euid: 1000,
            overflow_uid: 0,
            host_root_mapped: true,
        };
        assert!(!trusted_linux_owner(0, ambiguous_root));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn uid_map_must_prove_full_identity_before_trusting_host_root() {
        use super::uid_map_proves_host_root;

        assert!(uid_map_proves_host_root("0 0 4294967295\n"));
        assert!(!uid_map_proves_host_root("0 0 1\n"));
        assert!(!uid_map_proves_host_root("0 1000 4294967295\n"));
        assert!(!uid_map_proves_host_root("1 0 4294967295\n"));
        assert!(!uid_map_proves_host_root("not a uid map\n"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn git_path_search_preserves_relative_entries_and_rejects_empty_path() {
        use std::os::unix::fs::PermissionsExt;

        let real_git = real_git_path().expect("ELF Git is required for this test");
        let dir = tempfile::tempdir_in(".").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let git = copy_git(&dir, &real_git);
        let relative_bin = std::path::Path::new(".")
            .join(dir.path().file_name().unwrap())
            .join("fixture-bin");
        let path = std::env::join_paths([relative_bin.as_path()]).unwrap();

        assert_eq!(
            super::git_candidate_from_search_path(&path),
            Some(relative_bin.join("git"))
        );
        assert!(git.exists());
        assert!(super::git_candidate_from_search_path(std::ffi::OsStr::new("")).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn available_rejects_world_writable_git_path_without_running_it() {
        use std::os::unix::fs::PermissionsExt;

        let dir = private_tempdir();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o777)).unwrap();
        let marker = dir.path().join("ran");
        let executable = bin.join("git");
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\nprintf x > '{}'\nprintf 'git version 2.45.0\\n'\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            super::available_from_at(
                std::path::Path::new("bin/git"),
                Some(std::fs::File::open(dir.path()).unwrap()),
                &AtomicBool::new(false),
                &[],
            )
            .unwrap()
            .is_none()
        );
        assert!(!marker.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn relative_git_execution_does_not_research_a_later_path_entry() {
        use std::{os::unix::fs::PermissionsExt, path::Path};

        let dir = private_tempdir();
        let real_git = real_git_path().expect("ELF Git is required for this test");
        let trusted = copy_git(&dir, &real_git);
        let cwd = std::fs::File::open(trusted.parent().unwrap()).unwrap();
        let git =
            super::available_from_at(Path::new("git"), Some(cwd), &AtomicBool::new(false), &[])
                .unwrap()
                .expect("protected relative Git");
        assert_eq!(git.path, Path::new("./git"));

        let earlier = dir.path().join("earlier");
        std::fs::create_dir(&earlier).unwrap();
        std::fs::set_permissions(&earlier, std::fs::Permissions::from_mode(0o700)).unwrap();
        let marker = dir.path().join("replacement-ran");
        let replacement = earlier.join("git");
        std::fs::write(
            &replacement,
            format!(
                "#!/bin/sh\nprintf x > '{}'\nprintf 'git version 2.45.0\\n'\n",
                marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o755)).unwrap();

        let path = std::env::join_paths([
            earlier.as_path(),
            Path::new(""),
            Path::new("/usr/bin"),
            Path::new("/bin"),
        ])
        .unwrap();
        let output = super::git_command(&git)
            .env("PATH", path)
            .arg("--version")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).starts_with("git version "));
        assert!(!marker.exists(), "replacement Git from PATH was executed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn replacing_git_after_preview_makes_queries_unavailable_without_running_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let dir = private_tempdir();
        let real_git = real_git_path().expect("ELF Git is required for this test");
        let executable = copy_git(&dir, &real_git);
        let bin = executable.parent().unwrap();
        let marker = dir.path().join("replacement-ran");
        let git = super::available_from_at(
            std::path::Path::new("git"),
            Some(std::fs::File::open(bin).unwrap()),
            &AtomicBool::new(false),
            &[],
        )
        .unwrap()
        .expect("protected fixture Git");
        let replacement = dir.path().join("replacement");
        std::fs::write(
            &replacement,
            format!("#!/bin/sh\nprintf x > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(replacement, &executable).unwrap();

        assert_eq!(
            query(
                &git,
                dir.path(),
                &dir.path().join("target"),
                false,
                &AtomicBool::new(false),
            )
            .unwrap(),
            Query::Unavailable
        );
        assert!(!marker.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn relative_git_identity_stays_anchored_when_its_directory_moves() {
        use std::os::unix::fs::PermissionsExt;

        let real_git = real_git_path().expect("ELF Git is required for this test");
        let dir = private_tempdir();
        let executable = copy_git(&dir, &real_git);
        let bin = executable.parent().unwrap();
        let cwd = std::fs::File::open(bin).unwrap();
        let roots = [bin.to_path_buf()];
        assert!(
            super::available_from_at(
                std::path::Path::new("git"),
                Some(cwd.try_clone().unwrap()),
                &AtomicBool::new(false),
                &roots,
            )
            .unwrap()
            .is_none()
        );
        let git = super::available_from_at(
            std::path::Path::new("git"),
            Some(cwd.try_clone().unwrap()),
            &AtomicBool::new(false),
            &[],
        )
        .unwrap()
        .expect("private relative Git");

        let old_root = dir.path().to_owned();
        let moved_root = old_root.with_file_name(format!("moved-{}", std::process::id()));
        std::fs::rename(&old_root, &moved_root).unwrap();
        std::fs::create_dir(&old_root).unwrap();
        let replacement_bin = old_root.join("fixture-bin");
        std::fs::create_dir(&replacement_bin).unwrap();
        std::fs::set_permissions(&replacement_bin, std::fs::Permissions::from_mode(0o700)).unwrap();
        let marker = old_root.join("replacement-ran");
        let replacement = replacement_bin.join("git");
        std::fs::write(
            &replacement,
            format!("#!/bin/sh\nprintf x > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(!git.identity_matches());
        assert_eq!(
            query(
                &git,
                &old_root,
                &old_root.join("target"),
                false,
                &AtomicBool::new(false),
            )
            .unwrap(),
            Query::Unavailable
        );
        assert!(!marker.exists());
        std::fs::remove_dir_all(&old_root).unwrap();
        std::fs::remove_dir_all(&moved_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn staged_quarantine_path_is_not_mistaken_for_a_clear_original_path() {
        use std::process::Command;

        let real_git = real_git_path().expect("ELF Git is required for this test");
        let dir = private_tempdir();
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("Cargo.toml"), "[workspace]\n").unwrap();
        let run_git = |args: &[&str]| {
            let output = Command::new(&real_git)
                .env("HOME", dir.path())
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
        run_git(&["add", "Cargo.toml"]);
        run_git(&["commit", "-qm", "fixture"]);
        let quarantine_target = project.join(".upkit-artifact-fixture/root");
        std::fs::create_dir_all(&quarantine_target).unwrap();
        std::fs::write(quarantine_target.join("keep"), "fixture").unwrap();
        run_git(&["add", ".upkit-artifact-fixture/root/keep"]);

        let cancel = AtomicBool::new(false);
        let fixture_git = copy_git(&dir, &real_git);
        let Some(git) = super::available_from_at(
            std::path::Path::new("git"),
            Some(std::fs::File::open(fixture_git.parent().unwrap()).unwrap()),
            &cancel,
            std::slice::from_ref(&project),
        )
        .unwrap() else {
            return;
        };
        let original_target = project.join("target");
        assert!(clear_for_removal(&git, &project, &original_target, &cancel).is_ok());
        assert!(clear_for_removal(&git, &project, &quarantine_target, &cancel).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn head_query_uses_git_safety_flags_and_treats_exit_one_as_unavailable() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::AtomicBool;

        let dir = private_tempdir();
        let executable = dir.path().join("mock-git");
        std::fs::write(
            &executable,
            r#"#!/bin/sh
{
printf 'GIT_NO_LAZY_FETCH=%s\n' "$GIT_NO_LAZY_FETCH"
printf 'GIT_ALLOW_PROTOCOL_PRESENT=%s\n' "${GIT_ALLOW_PROTOCOL+x}"
printf 'GIT_ALLOW_PROTOCOL=%s\n' "$GIT_ALLOW_PROTOCOL"
printf '%s\n' "$@"
} > git-invocation
exit 1
"#,
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let git = super::Git::for_test(executable, true);
        assert_eq!(
            super::query(
                &git,
                dir.path(),
                &dir.path().join("target"),
                true,
                &AtomicBool::new(false),
            )
            .unwrap(),
            super::Query::Unavailable
        );

        let invocation = std::fs::read_to_string(dir.path().join("git-invocation")).unwrap();
        let lines = invocation.lines().collect::<Vec<_>>();
        assert_eq!(
            &lines[..3],
            [
                "GIT_NO_LAZY_FETCH=1",
                "GIT_ALLOW_PROTOCOL_PRESENT=x",
                "GIT_ALLOW_PROTOCOL=",
            ]
        );
        assert_eq!(
            &lines[3..],
            [
                "--no-optional-locks",
                "--no-lazy-fetch",
                "--no-replace-objects",
                "-C",
                dir.path().to_str().unwrap(),
                "-c",
                "core.fsmonitor=false",
                "ls-files",
                "--cached",
                "--with-tree=HEAD",
                "-z",
                "--",
                ":(literal,icase)target",
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn history_check_finds_deleted_ref_entries_and_rejects_shallow_repositories() {
        use std::{
            ffi::OsString, fs, os::unix::ffi::OsStringExt, process::Command,
            sync::atomic::AtomicBool,
        };
        let real_git = real_git_path().expect("ELF Git is required for this test");
        let dir = private_tempdir();
        let repo = dir.path().join(OsString::from_vec(b"repo-\xff".to_vec()));
        fs::create_dir(&repo).unwrap();
        let run = |args: &[&str]| {
            Command::new(&real_git)
                .env("HOME", dir.path())
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .output()
                .unwrap()
        };
        assert!(run(&["init", "-q"]).status.success());
        fs::write(repo.join("tracked"), "fixture").unwrap();
        assert!(run(&["add", "tracked"]).status.success());
        assert!(
            run(&[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgSign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-qm",
                "fixture"
            ])
            .status
            .success()
        );
        assert!(run(&["rm", "-q", "tracked"]).status.success());
        assert!(
            run(&[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgSign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-qm",
                "delete"
            ])
            .status
            .success()
        );
        let git = super::Git::for_test(copy_git(&dir, &real_git), false);
        let cancel = AtomicBool::new(false);
        assert_eq!(
            super::history_status(Some(&git), &repo, &repo.join("tracked"), &cancel).unwrap(),
            "matching_entry_in_git_history"
        );
        assert_eq!(
            super::history_status(Some(&git), &repo, &repo.join("absent"), &cancel).unwrap(),
            "no_matching_entries_in_git_history"
        );
        let head = run(&["rev-parse", "HEAD"]);
        assert!(head.status.success());
        let grafts = repo.join(".git/info/grafts");
        fs::write(&grafts, &head.stdout).unwrap();
        assert_eq!(
            super::history_status(Some(&git), &repo, &repo.join("tracked"), &cancel).unwrap(),
            "unavailable"
        );
        let worktree = dir.path().join("worktree");
        assert!(
            run(&[
                "worktree",
                "add",
                "--detach",
                worktree.to_str().unwrap(),
                "HEAD"
            ])
            .status
            .success()
        );
        assert_eq!(
            super::history_status(Some(&git), &worktree, &worktree.join("tracked"), &cancel)
                .unwrap(),
            "unavailable"
        );
        fs::remove_file(&grafts).unwrap();
        std::os::unix::fs::symlink("missing", &grafts).unwrap();
        assert_eq!(
            super::history_status(Some(&git), &repo, &repo.join("tracked"), &cancel).unwrap(),
            "unavailable"
        );
        fs::remove_file(&grafts).unwrap();
        assert_eq!(
            super::history_status(Some(&git), &worktree, &worktree.join("tracked"), &cancel)
                .unwrap(),
            "matching_entry_in_git_history"
        );
        fs::write(repo.join(".git/shallow"), head.stdout).unwrap();
        assert_eq!(
            super::history_status(Some(&git), &repo, &repo.join("absent"), &cancel).unwrap(),
            "unavailable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn graft_check_rejects_bad_git_path_output() {
        use std::{fs, os::unix::fs::PermissionsExt, sync::atomic::AtomicBool};
        let dir = private_tempdir();
        let executable = dir.path().join("mock-git");
        for output in [
            "",
            "relative/info/grafts\\n",
            "/missing/info/grafts\\n",
            "/tmp/info/grafts",
        ] {
            fs::write(&executable, format!("#!/bin/sh\nprintf '{output}'\n")).unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
            let git = super::Git::for_test(executable.clone(), true);
            assert!(!super::no_grafts(&git, dir.path(), &AtomicBool::new(false)).unwrap());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_git_blocks_partial_clones_and_transport_helpers() {
        use std::{fs, os::unix::fs::PermissionsExt, process::Command, sync::atomic::AtomicBool};
        let real_git = real_git_path().expect("ELF Git is required for this test");
        let dir = private_tempdir();
        let repo = dir.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let run = |args: &[&str]| {
            let result = Command::new(&real_git)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", dir.path())
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            result.stdout
        };
        run(&["init", "-q"]);
        fs::write(repo.join("source"), "fixture").unwrap();
        run(&["add", "source"]);
        run(&[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-qm",
            "fixture",
        ]);
        let remote = dir.path().join("remote.git");
        let clone = Command::new(&real_git)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", dir.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["clone", "--bare", "--quiet"])
            .arg(&repo)
            .arg(&remote)
            .output()
            .unwrap();
        assert!(
            clone.status.success(),
            "{}",
            String::from_utf8_lossy(&clone.stderr)
        );
        run(&[
            "config",
            "remote.origin.url",
            &format!("file://{}", remote.display()),
        ]);
        run(&[
            "config",
            "remote.origin.fetch",
            "+refs/heads/*:refs/remotes/origin/*",
        ]);
        let git = super::Git::for_test(copy_git(&dir, &real_git), false);
        let cancel = AtomicBool::new(false);
        assert!(super::legacy_repo_complete(&git, &repo, &cancel).unwrap());
        assert_eq!(
            super::status(Some(&git), &repo, &repo.join("absent"), &cancel)
                .unwrap()
                .1,
            "no_matching_entries_in_head_or_index"
        );
        assert_eq!(
            super::history_status(Some(&git), &repo, &repo.join("absent"), &cancel).unwrap(),
            "no_matching_entries_in_git_history"
        );

        run(&["config", "remote.Origin.partialCloneFilter", "blob:none"]);
        assert!(!super::legacy_repo_complete(&git, &repo, &cancel).unwrap());
        run(&["config", "--unset", "remote.Origin.partialCloneFilter"]);
        run(&["config", "extensions.partialClone", "origin"]);
        assert!(!super::legacy_repo_complete(&git, &repo, &cancel).unwrap());
        run(&["config", "--unset", "extensions.partialClone"]);
        let included = dir.path().join("included-git-config");
        fs::write(&included, "[remote \"MixedCase\"]\n  promisor = true\n").unwrap();
        run(&["config", "include.path", included.to_str().unwrap()]);
        assert!(!super::legacy_repo_complete(&git, &repo, &cancel).unwrap());
        run(&["config", "--unset", "include.path"]);

        let marker = dir.path().join("helper-ran");
        let helper = dir.path().join("helper");
        fs::write(
            &helper,
            format!("#!/bin/sh\nprintf ran > '{}'\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        run(&["config", "remote.origin.promisor", "true"]);
        run(&[
            "config",
            "remote.origin.url",
            &format!("ext::{}", helper.display()),
        ]);
        run(&["config", "protocol.ext.allow", "always"]);
        let tree = String::from_utf8(run(&["rev-parse", "HEAD^{tree}"])).unwrap();
        let tree = tree.trim();
        let object = repo.join(".git/objects").join(&tree[..2]).join(&tree[2..]);
        fs::remove_file(&object).unwrap();
        assert!(!super::legacy_repo_complete(&git, &repo, &cancel).unwrap());
        assert_eq!(
            super::status(Some(&git), &repo, &repo.join("absent"), &cancel)
                .unwrap()
                .1,
            "unavailable"
        );
        assert_eq!(
            super::history_status(Some(&git), &repo, &repo.join("absent"), &cancel).unwrap(),
            "unavailable"
        );
        assert_eq!(
            super::query(&git, &repo, &repo.join("absent"), true, &cancel).unwrap(),
            super::Query::Unavailable
        );
        assert!(
            !marker.exists(),
            "remote helper executed despite protocol guard"
        );
        assert!(!object.exists(), "missing fixture object was fetched");
        run(&[
            "config",
            "remote.origin.url",
            &format!("file://{}", remote.display()),
        ]);
        run(&["config", "protocol.file.allow", "always"]);
        assert_eq!(
            super::query(&git, &repo, &repo.join("absent"), true, &cancel).unwrap(),
            super::Query::Unavailable
        );
        assert!(
            !object.exists(),
            "fixture object was fetched from local remote"
        );
        assert_eq!(fs::read_to_string(repo.join("source")).unwrap(), "fixture");
    }

    #[cfg(unix)]
    #[test]
    fn history_check_reports_failed_queries_as_unavailable() {
        use std::{fs, os::unix::fs::PermissionsExt, sync::atomic::AtomicBool};

        let dir = private_tempdir();
        let executable = dir.path().join("mock-git");
        fs::write(
            &executable,
            "#!/bin/sh\ncase \"$*\" in *--is-shallow-repository*) printf 'false\\n';; *) exit 1;; esac\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let git = super::Git::for_test(executable, true);
        assert_eq!(
            super::history_status(
                Some(&git),
                dir.path(),
                &dir.path().join("target"),
                &AtomicBool::new(false),
            )
            .unwrap(),
            "unavailable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_stops_a_hanging_index_query() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use std::time::{Duration, Instant};
        let dir = private_tempdir();
        let git = dir.path().join("mock-git");
        std::fs::write(&git, "#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = cancel.clone();
        let setter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            signal.store(true, Ordering::Relaxed);
        });
        let start = Instant::now();
        let git = super::Git::for_test(git, false);
        let result = super::status(Some(&git), dir.path(), &dir.path().join("target"), &cancel);
        setter.join().unwrap();
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
