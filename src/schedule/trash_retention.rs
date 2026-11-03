//! Linux systemd user manager for explicitly scoped Trash retention.
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const SERVICE: &str = "upkit-trash-retention.service";
const TIMER: &str = "upkit-trash-retention.timer";
const MIN_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const UNIT_LIMIT: u64 = 65536;
const DESCRIPTION: &str = "Upkit scheduled Trash retention";
const INSTALL_WARNING: &str = "Current item counts and the first 32 candidates are a read-only sample, not a promise about future items. Installation authorizes this location and age policy; eligible future Trash items can be permanently deleted once per day, and a missed run may run soon after enabling. The executor rechecks config, Trash identity, and manager state; age must be at least 30 days.";
const ENABLE_WARNING: &str = "The current candidate list is a read-only sample. Enabling authorizes this location and age policy; future matching Trash items can be permanently deleted once per day. The executor rechecks config, Trash identity, and manager state.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct TrashRetentionItemPreview {
    pub(crate) name: String,
    pub(crate) deletion_date: Option<String>,
    pub(crate) kind: &'static str,
    pub(crate) descendant_count: usize,
    pub(crate) logical_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct TrashRetentionCurrentPreview {
    pub(crate) eligible: usize,
    pub(crate) deferred: usize,
    pub(crate) skipped: usize,
    pub(crate) next_run_items: Vec<TrashRetentionItemPreview>,
    #[serde(skip)]
    candidate_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Policy {
    executable: PathBuf,
    config: PathBuf,
    location: PathBuf,
    age_seconds: u64,
    scope_token: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct TrashRetentionSchedulePreview {
    pub(crate) location: PathBuf,
    pub(crate) age_seconds: u64,
    pub(crate) unit_directory: PathBuf,
    pub(crate) service_unit: String,
    pub(crate) timer_unit: String,
    pub(crate) current_preview: TrashRetentionCurrentPreview,
    pub(crate) preview_token: String,
    pub(crate) warning: &'static str,
    #[serde(skip)]
    policy: Policy,
    #[serde(skip)]
    planned_unit_directory: PathBuf,
    #[serde(skip)]
    unit_directory_identity: Vec<u8>,
    #[serde(skip)]
    bus_identity: BusIdentity,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct TrashRetentionActionPreview {
    pub(crate) action: &'static str,
    pub(crate) location: PathBuf,
    pub(crate) age_seconds: u64,
    pub(crate) unit_directory: PathBuf,
    pub(crate) service_unit: String,
    pub(crate) timer_unit: String,
    pub(crate) current_preview: Option<TrashRetentionCurrentPreview>,
    pub(crate) active_state: String,
    pub(crate) unit_file_state: Option<String>,
    pub(crate) quarantine_paths: Vec<PathBuf>,
    pub(crate) preview_token: String,
    pub(crate) warning: &'static str,
    #[serde(skip)]
    policy: Policy,
    #[serde(skip)]
    planned_unit_directory: PathBuf,
    #[serde(skip)]
    unit_directory_identity: Vec<u8>,
    #[serde(skip)]
    bus_identity: BusIdentity,
}

pub(crate) type TrashRetentionStatus = crate::maintenance::TimerStatus;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BusIdentity {
    address: String,
    device: u64,
    inode: u64,
    uid: u32,
    ctime: i64,
    ctime_nanos: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct FileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    size: u64,
    ctime: i64,
    ctime_nanos: i64,
}

impl FileIdentity {
    fn same_inode(&self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

#[derive(Debug)]
struct UnitFile {
    text: String,
    identity: FileIdentity,
}

struct ExistingUnitState {
    policy: Policy,
    service: UnitFile,
    timer: UnitFile,
    timer_active_state: String,
    timer_unit_file_state: String,
    directory_metadata: fs::Metadata,
    unit_directory_identity: Vec<u8>,
}

#[cfg(test)]
thread_local! {
    static TEST_POLICY_PREVIEW: std::cell::RefCell<Option<(Policy, TrashRetentionCurrentPreview)>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
#[derive(Clone)]
struct TestScheduleContext {
    manager: PathBuf,
    unit_directory: PathBuf,
    runtime_directory: PathBuf,
}

#[cfg(test)]
thread_local! {
    static TEST_SCHEDULE_CONTEXT: std::cell::RefCell<Option<TestScheduleContext>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
pub(crate) struct TestScheduleContextGuard(Option<TestScheduleContext>);

#[cfg(test)]
impl TestScheduleContextGuard {
    pub(crate) fn install(manager: &Path, unit_directory: &Path, runtime_directory: &Path) -> Self {
        Self(TEST_SCHEDULE_CONTEXT.with(|slot| {
            slot.replace(Some(TestScheduleContext {
                manager: manager.to_owned(),
                unit_directory: unit_directory.to_owned(),
                runtime_directory: runtime_directory.to_owned(),
            }))
        }))
    }
}

#[cfg(test)]
impl Drop for TestScheduleContextGuard {
    fn drop(&mut self) {
        TEST_SCHEDULE_CONTEXT.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}

#[cfg(test)]
struct TestPolicyPreviewGuard;

#[cfg(test)]
impl TestPolicyPreviewGuard {
    fn install(policy: Policy, preview: TrashRetentionCurrentPreview) -> Self {
        TEST_POLICY_PREVIEW.with(|slot| *slot.borrow_mut() = Some((policy, preview)));
        Self
    }
}

#[cfg(test)]
impl Drop for TestPolicyPreviewGuard {
    fn drop(&mut self) {
        TEST_POLICY_PREVIEW.with(|slot| *slot.borrow_mut() = None);
    }
}

fn unit_names() -> [&'static str; 2] {
    [SERVICE, TIMER]
}

fn unit_directory() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = TEST_SCHEDULE_CONTEXT.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|context| context.unit_directory.clone())
    }) {
        if !path.is_absolute() || path.canonicalize().ok().as_deref() != Some(path.as_path()) {
            bail!("test user systemd unit directory must be canonical and absolute");
        }
        return Ok(path);
    }
    let path = dirs::config_dir()
        .context("cannot determine the user configuration directory")?
        .join("systemd/user");
    if !path.is_absolute() {
        bail!("user systemd unit directory must be absolute");
    }
    Ok(path)
}

fn systemctl_path() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = TEST_SCHEDULE_CONTEXT.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|context| context.manager.clone())
    }) {
        if !path.is_absolute() || path.canonicalize().ok().as_deref() != Some(path.as_path()) {
            bail!("test systemctl path must be canonical and absolute");
        }
        return Ok(path);
    }
    let candidate = ["/usr/bin/systemctl", "/bin/systemctl"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .context("trusted systemctl was not found in /usr/bin or /bin")?;
    let path = candidate
        .canonicalize()
        .context("resolve trusted systemctl")?;
    verify_trusted_systemctl(&path)?;
    Ok(path)
}

fn verify_trusted_systemctl(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() || path.canonicalize().ok().as_deref() != Some(path) {
        bail!("systemctl path is not canonical");
    }
    let metadata = fs::symlink_metadata(path).context("inspect systemctl")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7000 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        bail!("systemctl is not a trusted root-owned executable");
    }
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent).context("inspect systemctl parent")?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            bail!("systemctl parent is not protected from user replacement");
        }
    }
    Ok(())
}

fn local_user_bus_address() -> Result<String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    #[cfg(test)]
    let test_runtime = TEST_SCHEDULE_CONTEXT.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|context| context.runtime_directory.clone())
    });
    #[cfg(not(test))]
    let test_runtime = None;
    let runtime = test_runtime
        .or_else(|| std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from))
        .context("XDG_RUNTIME_DIR is required for the local user manager")?;
    if !runtime.is_absolute() || runtime.canonicalize().ok().as_deref() != Some(runtime.as_path()) {
        bail!("user runtime directory must be canonical and absolute");
    }
    let runtime_meta = fs::symlink_metadata(&runtime).context("inspect user runtime directory")?;
    if runtime_meta.file_type().is_symlink()
        || !runtime_meta.is_dir()
        || runtime_meta.uid() != rustix::process::geteuid().as_raw()
        || runtime_meta.mode() & 0o077 != 0
    {
        bail!("user runtime directory is not a private current-user directory");
    }
    validate_runtime_parents(&runtime)?;
    let bus = runtime.join("bus");
    let bus_meta = fs::symlink_metadata(&bus).context("inspect the local user manager socket")?;
    if bus_meta.file_type().is_symlink()
        || !bus_meta.file_type().is_socket()
        || bus_meta.uid() != rustix::process::geteuid().as_raw()
    {
        bail!("user manager bus is not a current-user Unix socket");
    }
    let path = bus
        .to_str()
        .context("user manager socket path must be UTF-8")?;
    if path.chars().any(|character| {
        !(character.is_ascii_alphanumeric() || matches!(character, '/' | '_' | '-' | '.'))
    }) {
        bail!("user manager socket path cannot be represented safely");
    }
    Ok(format!("unix:path={path}"))
}

fn validate_bus_address(address: &str) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let path = address
        .strip_prefix("unix:path=")
        .context("only a local Unix user-manager bus is supported")?;
    if path.is_empty()
        || !Path::new(path).is_absolute()
        || path.chars().any(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '/' | '_' | '-' | '.'))
        })
    {
        bail!("invalid local user-manager bus address");
    }
    let path = Path::new(path);
    if !path.is_absolute() || path.canonicalize().ok().as_deref() != Some(path) {
        bail!("user-manager socket path must be canonical and absolute");
    }
    let metadata = fs::symlink_metadata(path).context("inspect local user-manager socket")?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        bail!("user-manager address is not a current-user Unix socket");
    }
    validate_runtime_parents(
        path.parent()
            .context("user-manager socket parent is missing")?,
    )?;
    Ok(())
}

impl BusIdentity {
    fn capture(address: &str) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        validate_bus_address(address)?;
        let path = address
            .strip_prefix("unix:path=")
            .context("only a local Unix user-manager bus is supported")?;
        let metadata = fs::symlink_metadata(path).context("inspect user-manager bus identity")?;
        Ok(Self {
            address: address.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            ctime: metadata.ctime(),
            ctime_nanos: metadata.ctime_nsec(),
        })
    }

    fn verify_current(&self) -> Result<()> {
        if Self::capture(&self.address)? != *self {
            bail!("user-manager bus changed since preview");
        }
        Ok(())
    }
}

fn validate_runtime_parents(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let uid = rustix::process::geteuid().as_raw();
    let metadata = fs::symlink_metadata(path).context("inspect user runtime directory")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
    {
        bail!("user runtime directory is not a private current-user directory");
    }
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent).context("inspect user runtime parent")?;
        let protected = (metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
            || (metadata.uid() == uid && metadata.mode() & 0o022 == 0)
            || (metadata.uid() == 0
                && metadata.mode() & 0o1000 != 0
                && metadata.mode() & 0o002 != 0);
        if metadata.file_type().is_symlink() || !metadata.is_dir() || !protected {
            bail!("user runtime parent is not protected from another user");
        }
    }
    Ok(())
}

fn systemctl_with(manager: &Path, bus: &BusIdentity, args: &[&str]) -> Result<String> {
    systemctl_with_timeout(manager, bus, args, Duration::from_secs(10))
}

fn systemctl_with_timeout(
    manager: &Path,
    bus: &BusIdentity,
    args: &[&str],
    timeout: Duration,
) -> Result<String> {
    let command = (|| -> Result<String> {
        bus.verify_current()
            .context("verify user-manager bus before systemctl")?;
        #[cfg(not(test))]
        verify_trusted_systemctl(manager)?;
        let socket = bus
            .address
            .strip_prefix("unix:path=")
            .context("only a local Unix user-manager bus is supported")?;
        let runtime = Path::new(socket)
            .parent()
            .context("user-manager socket parent is missing")?;
        let mut child = Command::new(manager)
            .arg("--user")
            .args(args)
            .env_clear()
            .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
            .env("XDG_RUNTIME_DIR", runtime)
            .env("LC_ALL", "C")
            .env("SYSTEMD_PAGER", "cat")
            .env("SYSTEMD_COLORS", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("start the current user's local systemd manager")?;
        let mut stdout = child.stdout.take().context("capture systemctl output")?;
        let (send, receive) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout.by_ref().take(UNIT_LIMIT + 1).read_to_end(&mut bytes);
            let _ = send.send((result, bytes));
        });
        let deadline = Instant::now() + timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!("systemctl timed out; manager outcome may be unknown");
                }
            }
        };
        let (read, bytes) = receive
            .recv_timeout(Duration::from_millis(100))
            .context("systemctl output unavailable")?;
        read.context("read systemctl output")?;
        if bytes.len() as u64 > UNIT_LIMIT {
            bail!("systemctl output exceeded its size limit");
        }
        if !status.success() {
            bail!("systemctl failed; inspect the user manager before retrying");
        }
        String::from_utf8(bytes).context("systemctl output is not UTF-8")
    })();
    let bus_check = bus
        .verify_current()
        .context("verify user-manager bus after systemctl");
    match (command, bus_check) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(command_error), Err(bus_error)) => Err(bus_error.context(format!(
            "systemctl outcome may be unknown (command also failed: {command_error})"
        ))),
    }
}

fn manager() -> Result<(PathBuf, BusIdentity)> {
    let manager = systemctl_path()?;
    Ok((manager, current_trash_retention_bus_identity()?))
}

pub(crate) fn current_trash_retention_bus_identity() -> Result<BusIdentity> {
    let address = local_user_bus_address()?;
    BusIdentity::capture(&address)
}

fn property_with(manager: &Path, bus: &BusIdentity, name: &str, property: &str) -> Result<String> {
    let argument = format!("--property={property}");
    let value = systemctl_with(
        manager,
        bus,
        &["show", name, "--no-pager", &argument, "--value"],
    )?;
    let value = value.trim_end_matches(['\n', '\r']);
    if value.chars().any(char::is_control) {
        bail!("systemd returned an invalid unit property");
    }
    Ok(value.to_owned())
}

fn preview_token(
    action: &str,
    directory: &fs::Metadata,
    parts: &[&[u8]],
    manager_path: &Path,
    bus: &BusIdentity,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    let mut hash = Sha256::new();
    hash.update(b"upkit-trash-retention-manager-preview-v1\0");
    let mut add = |bytes: &[u8]| {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    };
    add(action.as_bytes());
    add(&fs::read("/proc/sys/kernel/random/boot_id").context("read boot identity")?);
    add(&directory.dev().to_le_bytes());
    add(&directory.ino().to_le_bytes());
    for part in parts {
        add(part);
    }
    let manager_meta = fs::metadata(manager_path).context("inspect systemctl identity")?;
    add(manager_path.as_os_str().as_encoded_bytes());
    add(&manager_meta.dev().to_le_bytes());
    add(&manager_meta.ino().to_le_bytes());
    add(&manager_meta.ctime().to_le_bytes());
    add(&manager_meta.ctime_nsec().to_le_bytes());
    bus.verify_current()?;
    add(bus.address.as_bytes());
    add(&bus.device.to_le_bytes());
    add(&bus.inode.to_le_bytes());
    add(&bus.uid.to_le_bytes());
    add(&bus.ctime.to_le_bytes());
    add(&bus.ctime_nanos.to_le_bytes());
    Ok(hex::encode(hash.finalize()))
}

fn open_unit_directory(path: &Path) -> Result<(fs::File, fs::Metadata)> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() || path.canonicalize().ok().as_deref() != Some(path) {
        bail!("user unit directory must be an existing canonical path without links");
    }
    let descriptor = rustix::fs::openat2(
        rustix::fs::CWD,
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .context("open existing user unit directory without links")?;
    let file = fs::File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        bail!("user unit directory must be current-user owned and not writable by others");
    }
    let path_metadata = fs::symlink_metadata(path).context("recheck user unit directory path")?;
    if path_metadata.file_type().is_symlink()
        || path_metadata.dev() != metadata.dev()
        || path_metadata.ino() != metadata.ino()
        || path_metadata.uid() != metadata.uid()
        || path_metadata.mode() != metadata.mode()
    {
        bail!("user unit directory changed while it was opened");
    }
    unit_directory_identity(path)?;
    Ok((file, metadata))
}

fn unit_directory_identity(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let uid = rustix::process::geteuid().as_raw();
    if !path.is_absolute() || path.canonicalize().ok().as_deref() != Some(path) {
        bail!("user unit directory must be an existing canonical path without links");
    }
    let mut identity = Vec::new();
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).context("inspect user unit path parent")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("user unit path parents must be real directories");
        }
        let protected = if ancestor == path {
            metadata.uid() == uid && metadata.mode() & 0o022 == 0
        } else {
            (metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
                || (metadata.uid() == uid && metadata.mode() & 0o022 == 0)
                || (metadata.uid() == 0
                    && metadata.mode() & 0o1000 != 0
                    && metadata.mode() & 0o022 != 0)
        };
        if !protected {
            bail!("user unit path parent is not protected from replacement by another user");
        }
        identity.extend_from_slice(
            &(ancestor.as_os_str().as_encoded_bytes().len() as u64).to_be_bytes(),
        );
        identity.extend_from_slice(ancestor.as_os_str().as_encoded_bytes());
        identity.extend_from_slice(&metadata.dev().to_be_bytes());
        identity.extend_from_slice(&metadata.ino().to_be_bytes());
        identity.extend_from_slice(&metadata.uid().to_be_bytes());
        identity.extend_from_slice(&metadata.gid().to_be_bytes());
        identity.extend_from_slice(&metadata.mode().to_be_bytes());
    }
    Ok(identity)
}

fn same_unit_directory_identity(path: &Path, expected: &[u8]) -> bool {
    // These snapshots catch path changes between checkpoints, not races by another same-UID process.
    unit_directory_identity(path).is_ok_and(|current| current == expected)
}

fn same_unit_directory(path: &Path, expected: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    open_unit_directory(path).is_ok_and(|(_, current)| {
        current.dev() == expected.dev()
            && current.ino() == expected.ino()
            && current.uid() == expected.uid()
            && current.mode() & 0o022 == 0
    })
}

fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        size: metadata.len(),
        ctime: metadata.ctime(),
        ctime_nanos: metadata.ctime_nsec(),
    }
}

fn read_unit(directory: &fs::File, name: &str) -> Result<UnitFile> {
    use std::os::unix::fs::MetadataExt;
    let open = || {
        rustix::fs::openat2(
            directory,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::BENEATH
                | rustix::fs::ResolveFlags::NO_SYMLINKS
                | rustix::fs::ResolveFlags::NO_XDEV,
        )
    };
    let mut file = fs::File::from(open().with_context(|| format!("open {name} without links"))?);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > UNIT_LIMIT
    {
        bail!("{name} must be a private current-user regular file");
    }
    let identity = file_identity(&metadata);
    let mut bytes = Vec::new();
    (&mut file)
        .take(UNIT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .context("read user unit")?;
    if bytes.len() as u64 > UNIT_LIMIT {
        bail!("user unit exceeds its size limit");
    }
    let text = String::from_utf8(bytes).context("user unit is not UTF-8")?;
    if text
        .chars()
        .any(|character| character.is_control() && character != '\n')
    {
        bail!("user unit contains control characters");
    }
    let after = file.metadata()?;
    let reopened =
        fs::File::from(open().context("reopen user unit after inspection")?).metadata()?;
    if file_identity(&after) != identity || file_identity(&reopened) != identity {
        bail!("user unit changed during inspection");
    }
    Ok(UnitFile { text, identity })
}

fn absent_at(directory: &fs::File, name: &str) -> Result<bool> {
    use rustix::fs::AtFlags;
    Ok(matches!(
        rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW),
        Err(rustix::io::Errno::NOENT)
    ))
}

fn marker(policy: &Policy) -> Result<String> {
    let encode = |path: &Path| -> Result<String> {
        let value = path
            .to_str()
            .context("scheduled Trash paths must be UTF-8")?;
        Ok(hex::encode(value.as_bytes()))
    };
    Ok(format!(
        "# upkit-trash-retention-v1 {} {} {} {} {}",
        encode(&policy.executable)?,
        encode(&policy.config)?,
        encode(&policy.location)?,
        policy.age_seconds,
        policy.scope_token
    ))
}

fn render_units(policy: &Policy) -> Result<(String, String)> {
    let arg = |path: &Path| -> Result<String> {
        super::unit_arg(path.to_str().context("systemd paths must be UTF-8")?)
    };
    if policy.age_seconds < MIN_AGE.as_secs()
        || policy.scope_token.len() != 64
        || !policy
            .scope_token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("scheduled Trash scope token is malformed");
    }
    let marker = marker(policy)?;
    let executable = super::unit_arg(&format!(
        ":{}",
        policy
            .executable
            .to_str()
            .context("executable path must be UTF-8")?
    ))?;
    let service = format!(
        "[Unit]\nDescription={DESCRIPTION}\n{marker}\n\n[Service]\nType=oneshot\nExecStart={executable} --non-interactive --offline --json --config {} trash scheduled-retention --location {} --age-seconds {} --scope-token {}\n",
        arg(&policy.config)?,
        arg(&policy.location)?,
        policy.age_seconds,
        policy.scope_token
    );
    let timer = format!(
        "[Unit]\nDescription={DESCRIPTION} timer\n\n[Timer]\nOnCalendar=daily\nPersistent=true\nUnit={SERVICE}\n\n[Install]\nWantedBy=timers.target\n"
    );
    if service.len() > UNIT_LIMIT as usize || timer.len() > UNIT_LIMIT as usize {
        bail!("generated Trash retention unit exceeds the supported size limit");
    }
    Ok((service, timer))
}

fn parse_marker(service: &str) -> Result<Policy> {
    let mut markers = service
        .lines()
        .filter_map(|line| line.strip_prefix("# upkit-trash-retention-v1 "));
    let fields = markers
        .next()
        .context("Trash retention unit marker is missing")?
        .split_whitespace()
        .collect::<Vec<_>>();
    if markers.next().is_some() || fields.len() != 5 {
        bail!("Trash retention unit marker is malformed");
    }
    let decode = |value: &str| -> Result<PathBuf> {
        let bytes = hex::decode(value).context("decode Trash retention unit path")?;
        let value = String::from_utf8(bytes).context("Trash retention paths must be UTF-8")?;
        let path = PathBuf::from(value);
        if !path.is_absolute() || path.to_str().is_none() {
            bail!("Trash retention unit path is not absolute UTF-8");
        }
        Ok(path)
    };
    let age_seconds = fields[3]
        .parse::<u64>()
        .context("invalid retention age in Trash retention unit")?;
    if age_seconds < MIN_AGE.as_secs() {
        bail!("Trash retention unit age is below the 30-day minimum");
    }
    if fields[4].len() != 64 || !fields[4].bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Trash retention unit scope token is malformed");
    }
    Ok(Policy {
        executable: decode(fields[0])?,
        config: decode(fields[1])?,
        location: decode(fields[2])?,
        age_seconds,
        scope_token: fields[4].to_owned(),
    })
}

fn checked_policy(
    executable: &Path,
    config: &Path,
    location: &Path,
    age: Duration,
) -> Result<Policy> {
    if age < MIN_AGE || age.subsec_nanos() != 0 {
        bail!("scheduled Trash retention age must be at least 30 whole days");
    }
    let canonical_file = |path: &Path, label: &str| -> Result<PathBuf> {
        let canonical = path
            .canonicalize()
            .with_context(|| format!("resolve {label}"))?;
        let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
        if !path.is_absolute()
            || canonical != path
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
        {
            bail!("{label} must be an existing canonical regular file");
        }
        Ok(canonical)
    };
    let executable = canonical_file(executable, "Upkit executable")?;
    let config = canonical_file(config, "configuration file")?;
    let canonical_location = location
        .canonicalize()
        .context("resolve explicit Trash location")?;
    if !location.is_absolute()
        || canonical_location != location
        || canonical_location.as_os_str().is_empty()
    {
        bail!("Trash location must be an absolute canonical path");
    }
    let location = canonical_location;
    let scope_token =
        crate::scheduled_trash_cleanup::scope_token(&executable, &config, &location, age)?;
    if scope_token.len() != 64 || !scope_token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("scheduled Trash scope token is malformed");
    }
    Ok(Policy {
        executable,
        config,
        location,
        age_seconds: age.as_secs(),
        scope_token,
    })
}

fn verify_policy(policy: &Policy) -> Result<()> {
    #[cfg(test)]
    if TEST_POLICY_PREVIEW.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|(expected, _)| expected == policy)
    }) {
        return Ok(());
    }
    let current = checked_policy(
        &policy.executable,
        &policy.config,
        &policy.location,
        Duration::from_secs(policy.age_seconds),
    )?;
    if current != *policy {
        bail!("scheduled Trash policy or location identity changed; preview again");
    }
    Ok(())
}

fn current_preview(policy: &Policy) -> Result<TrashRetentionCurrentPreview> {
    #[cfg(test)]
    if let Some(preview) = TEST_POLICY_PREVIEW.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|(expected, _)| expected == policy)
            .map(|(_, preview)| preview.clone())
    }) {
        return Ok(preview);
    }
    let snapshot = crate::trash::scheduled_retention_preview(
        &policy.location,
        Duration::from_secs(policy.age_seconds),
        &std::sync::atomic::AtomicBool::new(false),
    )?;
    let eligible = snapshot.eligible;
    let deferred = snapshot.deferred;
    let skipped = snapshot.skipped;
    let candidate_digest = snapshot.candidate_digest.clone();
    let plans = snapshot.plan.map(|plan| plan.items).unwrap_or_default();
    if plans.len() > 32 || plans.len() != eligible.saturating_sub(deferred) {
        bail!("scheduled Trash preview returned inconsistent candidate counts");
    }
    let mut next_run_items = plans
        .into_iter()
        .map(|item| TrashRetentionItemPreview {
            name: item.name,
            deletion_date: item.deletion_date,
            kind: item.kind,
            descendant_count: item.descendant_count,
            logical_bytes: item.logical_bytes,
        })
        .collect::<Vec<_>>();
    next_run_items.sort_by(|left, right| {
        (&left.name, &left.deletion_date).cmp(&(&right.name, &right.deletion_date))
    });
    Ok(TrashRetentionCurrentPreview {
        eligible,
        deferred,
        skipped,
        next_run_items,
        candidate_digest,
    })
}

fn candidate_digest(preview: &TrashRetentionCurrentPreview) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};
    let summary = serde_json::to_vec(preview).context("encode current Trash candidate preview")?;
    let mut hash = Sha256::new();
    hash.update(b"upkit-trash-retention-candidate-preview-v1\0");
    hash.update((summary.len() as u64).to_be_bytes());
    hash.update(summary);
    hash.update((preview.candidate_digest.len() as u64).to_be_bytes());
    hash.update(preview.candidate_digest.as_bytes());
    Ok(hash.finalize().to_vec())
}

fn validate_unit_state(
    manager: &Path,
    bus: &BusIdentity,
    directory: &Path,
    timer_active: Option<&str>,
    timer_file_state: Option<&str>,
    service_active: Option<&str>,
) -> Result<()> {
    for name in unit_names() {
        let timer = name == TIMER;
        if property_with(manager, bus, name, "LoadState")? != "loaded"
            || property_with(manager, bus, name, "NeedDaemonReload")? != "no"
            || !property_with(manager, bus, name, "DropInPaths")?.is_empty()
            || property_with(manager, bus, name, "FragmentPath")?
                != directory
                    .join(name)
                    .to_str()
                    .context("unit path must be UTF-8")?
        {
            bail!("user manager does not load the exact Trash retention {name} without drop-ins");
        }
        let active = property_with(manager, bus, name, "ActiveState")?;
        if timer && timer_active.is_some_and(|expected| active != expected) {
            bail!("Trash retention timer state changed");
        }
        if !timer && service_active.is_some_and(|expected| active != expected) {
            bail!("Trash retention service state changed");
        }
        let file_state = property_with(manager, bus, name, "UnitFileState")?;
        if timer && timer_file_state.is_some_and(|expected| file_state != expected) {
            bail!("Trash retention timer enablement changed");
        }
    }
    Ok(())
}

fn verify_files(
    directory_path: &Path,
    directory: &fs::File,
    directory_meta: &fs::Metadata,
    policy: &Policy,
) -> Result<[UnitFile; 2]> {
    use std::os::unix::fs::MetadataExt;
    let (expected_service, expected_timer) = render_units(policy)?;
    let service = read_unit(directory, SERVICE)?;
    let timer = read_unit(directory, TIMER)?;
    if service.text != expected_service || timer.text != expected_timer {
        bail!("Trash retention unit contents do not match the reviewed policy");
    }
    let after = directory.metadata()?;
    if after.dev() != directory_meta.dev()
        || after.ino() != directory_meta.ino()
        || after.uid() != directory_meta.uid()
        || !same_unit_directory(directory_path, directory_meta)
    {
        bail!("user unit directory changed during inspection");
    }
    Ok([service, timer])
}

fn verify_loaded(
    manager: &Path,
    bus: &BusIdentity,
    directory: &Path,
    timer_active: Option<&str>,
    timer_file_state: Option<&str>,
    service_active: Option<&str>,
) -> Result<()> {
    validate_unit_state(
        manager,
        bus,
        directory,
        timer_active,
        timer_file_state,
        service_active,
    )
}

fn verify_installed_with(
    manager: &Path,
    bus: &BusIdentity,
    directory_path: &Path,
    policy: &Policy,
    require_active: bool,
) -> Result<()> {
    verify_policy(policy)?;
    let (directory, metadata) = open_unit_directory(directory_path)?;
    let unit_directory_identity = unit_directory_identity(directory_path)?;
    let units = verify_files(directory_path, &directory, &metadata, policy)?;
    verify_loaded(
        manager,
        bus,
        directory_path,
        if require_active { Some("active") } else { None },
        Some("enabled"),
        None,
    )?;
    if !same_unit_directory(directory_path, &metadata)
        || !same_unit_directory_identity(directory_path, &unit_directory_identity)
        || verify_files(directory_path, &directory, &metadata, policy)?
            .iter()
            .zip(units.iter())
            .any(|(now, before)| now.identity != before.identity || now.text != before.text)
    {
        bail!("Trash retention unit identity changed during manager verification");
    }
    Ok(())
}

/// Verify the active user timer and exact policy before a scheduled executor touches Trash.
pub(crate) fn verify_trash_retention_schedule(
    executable: &Path,
    config: &Path,
    location: &Path,
    age: Duration,
    scope_token: &str,
    bus_identity: &BusIdentity,
) -> Result<()> {
    let policy = checked_policy(executable, config, location, age)?;
    if policy.scope_token != scope_token {
        bail!("scheduled Trash scope token does not match current policy");
    }
    let directory = unit_directory()?;
    let manager = systemctl_path()?;
    verify_installed_with(&manager, bus_identity, &directory, &policy, true)
        .context("scheduled Trash timer is not the exact enabled current-user schedule")
}

pub(crate) fn preview_trash_retention(
    executable: &Path,
    config: &Path,
    location: &Path,
    age: Duration,
) -> Result<TrashRetentionSchedulePreview> {
    let policy = checked_policy(executable, config, location, age)?;
    let directory = unit_directory()?;
    let (manager, bus) = manager()?;
    preview_install_with(&policy, &directory, &manager, &bus)
}

fn preview_install_with(
    policy: &Policy,
    unit_directory: &Path,
    manager: &Path,
    bus: &BusIdentity,
) -> Result<TrashRetentionSchedulePreview> {
    use std::os::unix::fs::MetadataExt;
    verify_policy(policy)?;
    let (directory, metadata) = open_unit_directory(unit_directory)?;
    let unit_directory_identity = unit_directory_identity(unit_directory)?;
    for name in unit_names() {
        let load = property_with(manager, bus, name, "LoadState")?;
        let fragment = property_with(manager, bus, name, "FragmentPath")?;
        let dropins = property_with(manager, bus, name, "DropInPaths")?;
        if load != "not-found" || !fragment.is_empty() || !dropins.is_empty() {
            bail!(
                "a unit, fragment, or drop-in named {name} already exists; refusing to overwrite it"
            );
        }
        if !absent_at(&directory, name)? {
            bail!("a file named {name} already exists; refusing to overwrite it");
        }
    }
    if !same_unit_directory(unit_directory, &metadata) {
        bail!("user unit directory changed during preview");
    }
    let current_preview = current_preview(policy)?;
    let candidate_digest = candidate_digest(&current_preview)?;
    let (service_unit, timer_unit) = render_units(policy)?;
    let manager_identity = manager.as_os_str().as_encoded_bytes();
    let preview_token = preview_token(
        "install",
        &metadata,
        &[
            policy.scope_token.as_bytes(),
            service_unit.as_bytes(),
            timer_unit.as_bytes(),
            &candidate_digest,
            manager_identity,
            &unit_directory_identity,
        ],
        manager,
        bus,
    )?;
    if directory.metadata()?.dev() != metadata.dev()
        || !same_unit_directory_identity(unit_directory, &unit_directory_identity)
    {
        bail!("user unit directory changed during preview");
    }
    Ok(TrashRetentionSchedulePreview {
        location: policy.location.clone(),
        age_seconds: policy.age_seconds,
        unit_directory: unit_directory.to_owned(),
        service_unit,
        timer_unit,
        current_preview,
        preview_token,
        warning: INSTALL_WARNING,
        policy: policy.clone(),
        planned_unit_directory: unit_directory.to_owned(),
        unit_directory_identity,
        bus_identity: bus.clone(),
    })
}

pub(crate) fn install_trash_retention(
    plan: &TrashRetentionSchedulePreview,
    token: &str,
) -> Result<&'static str> {
    validate_install_fields(plan)?;
    let (manager, bus) = manager()?;
    install_with(plan, token, &manager, &bus)
}

fn validate_install_fields(plan: &TrashRetentionSchedulePreview) -> Result<()> {
    let (service_unit, timer_unit) = render_units(&plan.policy)?;
    if plan.location != plan.policy.location
        || plan.age_seconds != plan.policy.age_seconds
        || plan.unit_directory != plan.planned_unit_directory
        || plan.service_unit != service_unit
        || plan.timer_unit != timer_unit
        || plan.warning != INSTALL_WARNING
        || !same_unit_directory_identity(&plan.unit_directory, &plan.unit_directory_identity)
    {
        bail!("Trash retention preview fields changed; preview again");
    }
    Ok(())
}

fn validate_install_preview(
    plan: &TrashRetentionSchedulePreview,
    current: &TrashRetentionSchedulePreview,
    token: &str,
) -> Result<()> {
    validate_install_fields(plan)?;
    if token != plan.preview_token
        || current.preview_token != token
        || current.location != plan.location
        || current.age_seconds != plan.age_seconds
        || current.unit_directory != plan.unit_directory
        || current.service_unit != plan.service_unit
        || current.timer_unit != plan.timer_unit
        || current.current_preview != plan.current_preview
        || current.warning != plan.warning
        || current.unit_directory_identity != plan.unit_directory_identity
        || current.bus_identity != plan.bus_identity
    {
        bail!("Trash retention policy or candidate preview changed since review");
    }
    Ok(())
}

fn install_with(
    plan: &TrashRetentionSchedulePreview,
    token: &str,
    manager: &Path,
    bus: &BusIdentity,
) -> Result<&'static str> {
    if bus != &plan.bus_identity {
        bail!("user-manager bus changed since Trash retention preview");
    }
    if token != plan.preview_token {
        bail!("Trash retention preview token does not match");
    }
    validate_install_fields(plan)?;
    let current = preview_install_with(&plan.policy, &plan.unit_directory, manager, bus)?;
    validate_install_preview(plan, &current, token)?;
    verify_policy(&current.policy)?;
    let (directory, metadata) = open_unit_directory(&current.unit_directory)?;
    let mut written = Vec::new();
    for (name, content) in [
        (SERVICE, current.service_unit.as_str()),
        (TIMER, current.timer_unit.as_str()),
    ] {
        if !same_unit_directory_identity(&current.unit_directory, &current.unit_directory_identity)
        {
            bail!("user unit path changed; installation may be partial");
        }
        let descriptor = rustix::fs::openat2(
            &directory,
            name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            rustix::fs::ResolveFlags::BENEATH
                | rustix::fs::ResolveFlags::NO_SYMLINKS
                | rustix::fs::ResolveFlags::NO_XDEV,
        )
        .with_context(|| format!("create {name}; installation may be partial"))?;
        let mut file = fs::File::from(descriptor);
        file.write_all(content.as_bytes())
            .with_context(|| format!("write {name}; installation may be partial"))?;
        file.sync_all()
            .with_context(|| format!("sync {name}; installation may be partial"))?;
        written.push((name, content.to_owned(), file_identity(&file.metadata()?)));
    }
    directory
        .sync_all()
        .context("sync unit directory; installation may be partial")?;
    let verify_written = || -> Result<()> {
        if !same_unit_directory(&current.unit_directory, &metadata)
            || !same_unit_directory_identity(
                &current.unit_directory,
                &current.unit_directory_identity,
            )
        {
            bail!("unit directory changed; installation may be partial");
        }
        for (name, expected, identity) in &written {
            let unit = read_unit(&directory, name)?;
            if unit.text != *expected || unit.identity != *identity {
                bail!("{name} changed after installation; installation may be partial");
            }
        }
        Ok(())
    };
    verify_written()?;
    systemctl_with(manager, bus, &["daemon-reload"])
        .context("reload user manager; unit files may remain")?;
    verify_written()?;
    verify_loaded(
        manager,
        bus,
        &current.unit_directory,
        Some("inactive"),
        Some("disabled"),
        Some("inactive"),
    )
    .context("unit files remain but the timer was not enabled")?;
    verify_policy(&current.policy).context("unit files remain but Trash policy changed")?;
    if current_preview(&current.policy).context(
        "unit files remain but the current Trash candidate preview could not be verified",
    )? != current.current_preview
    {
        bail!("unit files remain but Trash candidates changed; preview again before enabling");
    }
    if !same_unit_directory_identity(&current.unit_directory, &current.unit_directory_identity) {
        bail!("unit directory parents changed; unit files remain but the timer was not enabled");
    }
    systemctl_with(manager, bus, &["enable", "--now", TIMER])
        .context("enable timer; outcome may be partial or unknown")?;
    verify_installed_with(manager, bus, &current.unit_directory, &current.policy, true)
        .context("installation may be partial; inspect the user manager")?;
    Ok("active_and_enabled")
}

fn read_existing_with(
    manager: &Path,
    bus: &BusIdentity,
    unit_directory: &Path,
) -> Result<ExistingUnitState> {
    let (directory, metadata) = open_unit_directory(unit_directory)?;
    let unit_directory_identity = unit_directory_identity(unit_directory)?;
    let service = read_unit(&directory, SERVICE)?;
    let timer = read_unit(&directory, TIMER)?;
    let policy = parse_marker(&service.text)?;
    let (expected_service, expected_timer) = render_units(&policy)?;
    if expected_service != service.text || expected_timer != timer.text {
        bail!("unit content does not match the canonical Upkit Trash retention policy");
    }
    let load_timer = property_with(manager, bus, TIMER, "LoadState")?;
    let fragment_timer = property_with(manager, bus, TIMER, "FragmentPath")?;
    let dropins_timer = property_with(manager, bus, TIMER, "DropInPaths")?;
    let active_timer = property_with(manager, bus, TIMER, "ActiveState")?;
    let file_state_timer = property_with(manager, bus, TIMER, "UnitFileState")?;
    let load_service = property_with(manager, bus, SERVICE, "LoadState")?;
    let fragment_service = property_with(manager, bus, SERVICE, "FragmentPath")?;
    let dropins_service = property_with(manager, bus, SERVICE, "DropInPaths")?;
    if load_timer != "loaded"
        || load_service != "loaded"
        || fragment_timer
            != unit_directory
                .join(TIMER)
                .to_str()
                .context("unit path must be UTF-8")?
        || fragment_service
            != unit_directory
                .join(SERVICE)
                .to_str()
                .context("unit path must be UTF-8")?
        || !dropins_timer.is_empty()
        || !dropins_service.is_empty()
        || property_with(manager, bus, TIMER, "NeedDaemonReload")? != "no"
        || property_with(manager, bus, SERVICE, "NeedDaemonReload")? != "no"
    {
        bail!("systemd does not load the exact Trash retention units without drop-ins");
    }
    if !same_unit_directory(unit_directory, &metadata)
        || !same_unit_directory_identity(unit_directory, &unit_directory_identity)
    {
        bail!("user unit directory changed during manager inspection");
    }
    Ok(ExistingUnitState {
        policy,
        service,
        timer,
        timer_active_state: active_timer,
        timer_unit_file_state: file_state_timer,
        directory_metadata: metadata,
        unit_directory_identity,
    })
}

fn preview_action_with(
    action: &'static str,
    unit_directory: &Path,
    manager: &Path,
    bus: &BusIdentity,
) -> Result<TrashRetentionActionPreview> {
    let ExistingUnitState {
        policy,
        service,
        timer,
        timer_active_state: active_state,
        timer_unit_file_state: unit_file_state,
        directory_metadata: metadata,
        unit_directory_identity,
    } = read_existing_with(manager, bus, unit_directory)?;
    let service_active = property_with(manager, bus, SERVICE, "ActiveState")?;
    match action {
        "enable" => {
            if active_state != "inactive"
                || unit_file_state != "disabled"
                || service_active != "inactive"
            {
                bail!(
                    "Trash retention timer and service must be inactive and the timer disabled before enable"
                );
            }
            verify_policy(&policy).context("Trash retention policy changed; preview again")?;
        }
        "disable" => {
            if !matches!(active_state.as_str(), "active" | "inactive")
                || unit_file_state != "enabled"
            {
                bail!("Trash retention timer must be enabled before disable");
            }
        }
        "remove" => {
            if active_state != "inactive"
                || unit_file_state != "disabled"
                || service_active != "inactive"
            {
                bail!(
                    "Trash retention timer must be disabled and its service inactive before remove"
                );
            }
        }
        _ => bail!("unsupported Trash retention action"),
    }
    let current_preview = if action == "enable" {
        Some(current_preview(&policy)?)
    } else {
        None
    };
    let candidate_digest = current_preview
        .as_ref()
        .map(candidate_digest)
        .transpose()?
        .unwrap_or_default();
    let quarantine_paths = if action == "remove" {
        let mut hash = sha2::Sha256::new();
        use sha2::Digest;
        hash.update(b"upkit-trash-retention-remove-v1\0");
        hash.update(policy.scope_token.as_bytes());
        hash.update(service.identity.inode.to_le_bytes());
        hash.update(timer.identity.inode.to_le_bytes());
        let suffix = hex::encode(hash.finalize());
        vec![
            unit_directory.join(format!(".upkit-trash-remove-{}.service", &suffix[..24])),
            unit_directory.join(format!(".upkit-trash-remove-{}.timer", &suffix[..24])),
        ]
    } else {
        Vec::new()
    };
    let manager_identity = manager.as_os_str().as_encoded_bytes();
    let file_identities = serde_json::to_vec(&[&service.identity, &timer.identity])?;
    let preview_token = preview_token(
        action,
        &metadata,
        &[
            service.text.as_bytes(),
            timer.text.as_bytes(),
            active_state.as_bytes(),
            unit_file_state.as_bytes(),
            service_active.as_bytes(),
            &file_identities,
            &candidate_digest,
            manager_identity,
            &unit_directory_identity,
        ],
        manager,
        bus,
    )?;
    if !same_unit_directory(unit_directory, &metadata)
        || !same_unit_directory_identity(unit_directory, &unit_directory_identity)
    {
        bail!("user unit directory changed during preview");
    }
    Ok(TrashRetentionActionPreview {
        action,
        location: policy.location.clone(),
        age_seconds: policy.age_seconds,
        unit_directory: unit_directory.to_owned(),
        service_unit: service.text,
        timer_unit: timer.text,
        current_preview,
        active_state,
        unit_file_state: Some(unit_file_state),
        quarantine_paths,
        preview_token,
        warning: match action {
            "enable" => ENABLE_WARNING,
            "disable" => {
                "Preview only; disable stops this timer, but an already running service may continue. Unit files remain installed."
            }
            _ => {
                "Preview only; removal requires a disabled timer and inactive service. The two exact private unit files are quarantined before removal; errors may leave quarantine files."
            }
        },
        policy,
        planned_unit_directory: unit_directory.to_owned(),
        unit_directory_identity,
        bus_identity: bus.clone(),
    })
}

pub(crate) fn preview_trash_retention_enable() -> Result<TrashRetentionActionPreview> {
    let directory = unit_directory()?;
    let (manager, bus) = manager()?;
    preview_action_with("enable", &directory, &manager, &bus)
}

pub(crate) fn preview_trash_retention_disable() -> Result<TrashRetentionActionPreview> {
    let directory = unit_directory()?;
    let (manager, bus) = manager()?;
    preview_action_with("disable", &directory, &manager, &bus)
}

pub(crate) fn preview_trash_retention_remove() -> Result<TrashRetentionActionPreview> {
    let directory = unit_directory()?;
    let (manager, bus) = manager()?;
    preview_action_with("remove", &directory, &manager, &bus)
}

fn recheck_action(
    plan: &TrashRetentionActionPreview,
    token: &str,
    manager: &Path,
    bus: &BusIdentity,
) -> Result<TrashRetentionActionPreview> {
    if bus != &plan.bus_identity {
        bail!("user-manager bus changed since Trash retention preview");
    }
    if plan.unit_directory != plan.planned_unit_directory {
        bail!("Trash retention action preview directory changed; preview again");
    }
    if token != plan.preview_token {
        bail!("Trash retention preview token does not match");
    }
    let current = preview_action_with(plan.action, &plan.unit_directory, manager, bus)?;
    if current.preview_token != token
        || current.action != plan.action
        || current.location != plan.location
        || current.age_seconds != plan.age_seconds
        || current.unit_directory != plan.unit_directory
        || current.service_unit != plan.service_unit
        || current.timer_unit != plan.timer_unit
        || current.current_preview != plan.current_preview
        || current.active_state != plan.active_state
        || current.unit_file_state != plan.unit_file_state
        || current.quarantine_paths != plan.quarantine_paths
        || current.warning != plan.warning
        || current.unit_directory_identity != plan.unit_directory_identity
        || current.bus_identity != plan.bus_identity
    {
        bail!("Trash retention preview fields, units, or manager state changed; preview again");
    }
    Ok(current)
}

pub(crate) fn enable_trash_retention(
    plan: &TrashRetentionActionPreview,
    token: &str,
) -> Result<&'static str> {
    let (manager, bus) = manager()?;
    enable_with(plan, token, &manager, &bus)
}

fn enable_with(
    plan: &TrashRetentionActionPreview,
    token: &str,
    manager: &Path,
    bus: &BusIdentity,
) -> Result<&'static str> {
    if plan.action != "enable" {
        bail!("preview is not for enabling Trash retention");
    }
    let current = recheck_action(plan, token, manager, bus)?;
    verify_policy(&current.policy)?;
    if Some(current_preview(&current.policy)?) != current.current_preview {
        bail!("Trash candidates changed; preview again before enabling");
    }
    if !same_unit_directory_identity(&current.unit_directory, &current.unit_directory_identity) {
        bail!("user unit path changed; timer was not enabled");
    }
    systemctl_with(manager, bus, &["enable", "--now", TIMER])
        .context("enable timer; outcome may be partial or unknown")?;
    verify_installed_with(manager, bus, &current.unit_directory, &current.policy, true)
        .context("enable outcome may be partial; inspect the user manager")?;
    Ok("active_and_enabled")
}

pub(crate) fn disable_trash_retention(
    plan: &TrashRetentionActionPreview,
    token: &str,
) -> Result<&'static str> {
    let (manager, bus) = manager()?;
    disable_with(plan, token, &manager, &bus)
}

fn disable_with(
    plan: &TrashRetentionActionPreview,
    token: &str,
    manager: &Path,
    bus: &BusIdentity,
) -> Result<&'static str> {
    if plan.action != "disable" {
        bail!("preview is not for disabling Trash retention");
    }
    let current = recheck_action(plan, token, manager, bus)?;
    if !same_unit_directory_identity(&current.unit_directory, &current.unit_directory_identity) {
        bail!("user unit path changed; timer was not disabled");
    }
    systemctl_with(manager, bus, &["disable", "--now", TIMER])
        .context("disable timer; outcome may be partial or unknown")?;
    let existing = read_existing_with(manager, bus, &current.unit_directory)
        .context("timer may be disabled; inspect manager state before retrying")?;
    if existing.timer_active_state != "inactive"
        || existing.timer_unit_file_state != "disabled"
        || !same_unit_directory_identity(&current.unit_directory, &current.unit_directory_identity)
    {
        return Ok("unverified");
    }
    Ok("inactive_and_disabled")
}

pub(crate) fn remove_trash_retention(
    plan: &TrashRetentionActionPreview,
    token: &str,
) -> Result<&'static str> {
    let (manager, bus) = manager()?;
    remove_with(plan, token, &manager, &bus)
}

fn remove_with(
    plan: &TrashRetentionActionPreview,
    token: &str,
    manager: &Path,
    bus: &BusIdentity,
) -> Result<&'static str> {
    use rustix::fs::{AtFlags, RenameFlags};
    if plan.action != "remove" {
        bail!("preview is not for removing Trash retention");
    }
    let current = recheck_action(plan, token, manager, bus)?;
    let (directory, metadata) = open_unit_directory(&current.unit_directory)?;
    let units = verify_files(
        &current.unit_directory,
        &directory,
        &metadata,
        &current.policy,
    )?;
    if !same_unit_directory_identity(&current.unit_directory, &current.unit_directory_identity) {
        bail!("user unit path changed; no Trash retention files were removed");
    }
    if property_with(manager, bus, SERVICE, "ActiveState")? != "inactive"
        || preview_action_with("remove", &current.unit_directory, manager, bus)?.preview_token
            != token
    {
        bail!("unit or service changed; no Trash retention files were removed");
    }
    let names = current
        .quarantine_paths
        .iter()
        .map(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .context("invalid quarantine name")
        })
        .collect::<Result<Vec<_>>>()?;
    for (index, name) in unit_names().iter().enumerate() {
        let unit = read_unit(&directory, name)?;
        if unit.identity != units[index].identity
            || unit.text != units[index].text
            || !same_unit_directory(&current.unit_directory, &metadata)
            || !same_unit_directory_identity(
                &current.unit_directory,
                &current.unit_directory_identity,
            )
        {
            bail!("unit changed before quarantine; files may remain under quarantine names");
        }
        rustix::fs::renameat_with(
            &directory,
            *name,
            &directory,
            names[index],
            RenameFlags::NOREPLACE,
        )
        .with_context(|| format!("quarantine {name}; removal may be partial"))?;
        let quarantined = read_unit(&directory, names[index])
            .context("inspect quarantined unit; inspect quarantine files before retrying")?;
        if !quarantined.identity.same_inode(&units[index].identity)
            || quarantined.text != units[index].text
            || !same_unit_directory_identity(
                &current.unit_directory,
                &current.unit_directory_identity,
            )
        {
            bail!("quarantined unit identity changed; inspect the quarantine files");
        }
    }
    if !same_unit_directory(&current.unit_directory, &metadata)
        || !same_unit_directory_identity(&current.unit_directory, &current.unit_directory_identity)
        || property_with(manager, bus, TIMER, "ActiveState")
            .context("check timer; inspect quarantine files before retrying")?
            != "inactive"
        || property_with(manager, bus, TIMER, "UnitFileState")
            .context("check timer enablement; inspect quarantine files before retrying")?
            != "disabled"
        || property_with(manager, bus, SERVICE, "ActiveState")
            .context("check service; inspect quarantine files before retrying")?
            != "inactive"
    {
        bail!("unit directory changed or service started; inspect quarantine files");
    }
    for (index, name) in names.iter().enumerate() {
        let quarantined = read_unit(&directory, name)?;
        if !quarantined.identity.same_inode(&units[index].identity)
            || quarantined.text != units[index].text
            || !same_unit_directory_identity(
                &current.unit_directory,
                &current.unit_directory_identity,
            )
        {
            bail!("quarantined unit changed; removal may be partial");
        }
        rustix::fs::unlinkat(&directory, *name, AtFlags::empty())
            .context("remove quarantined unit; removal may be partial")?;
    }
    directory
        .sync_all()
        .context("sync unit directory; removal may be partial")?;
    if !same_unit_directory_identity(&current.unit_directory, &current.unit_directory_identity) {
        bail!("user unit path changed; unit files may already be removed");
    }
    systemctl_with(manager, bus, &["daemon-reload"])
        .context("reload user manager; unit files may already be removed")?;
    let verified = same_unit_directory(&current.unit_directory, &metadata)
        && same_unit_directory_identity(&current.unit_directory, &current.unit_directory_identity)
        && unit_names()
            .iter()
            .all(|name| absent_at(&directory, name).unwrap_or(false))
        && names
            .iter()
            .all(|name| absent_at(&directory, name).unwrap_or(false))
        && property_with(manager, bus, SERVICE, "LoadState")
            .is_ok_and(|value| value == "not-found")
        && property_with(manager, bus, TIMER, "LoadState").is_ok_and(|value| value == "not-found")
        && property_with(manager, bus, SERVICE, "FragmentPath").is_ok_and(|value| value.is_empty())
        && property_with(manager, bus, TIMER, "FragmentPath").is_ok_and(|value| value.is_empty())
        && property_with(manager, bus, SERVICE, "DropInPaths").is_ok_and(|value| value.is_empty())
        && property_with(manager, bus, TIMER, "DropInPaths").is_ok_and(|value| value.is_empty())
        && property_with(manager, bus, SERVICE, "NeedDaemonReload")
            .is_ok_and(|value| value == "no")
        && property_with(manager, bus, TIMER, "NeedDaemonReload").is_ok_and(|value| value == "no");
    Ok(if verified {
        "units_absent"
    } else {
        "unverified"
    })
}

pub(crate) fn trash_retention_status() -> Result<TrashRetentionStatus> {
    let (manager, bus) = manager()?;
    let load_state = property_with(&manager, &bus, TIMER, "LoadState")?;
    let state = if load_state == "not-found" {
        "not_found".to_owned()
    } else if load_state == "loaded" {
        property_with(&manager, &bus, TIMER, "ActiveState")?
    } else {
        "unavailable".to_owned()
    };
    let unit_file_state = property_with(&manager, &bus, TIMER, "UnitFileState").ok();
    let last_trigger = property_with(&manager, &bus, TIMER, "LastTriggerUSec").ok();
    let next_trigger = property_with(&manager, &bus, TIMER, "NextElapseUSecRealtime").ok();
    Ok(crate::maintenance::TimerStatus {
        state,
        load_state: Some(load_state),
        unit_file_state,
        last_trigger,
        next_trigger,
        detail: None,
    })
}

#[cfg(test)]
pub(crate) fn test_schedule_preview() -> TrashRetentionSchedulePreview {
    let policy = test_policy();
    let (service_unit, timer_unit) = render_units(&policy).unwrap();
    let unit_directory = PathBuf::from("/fixture/systemd/user");
    TrashRetentionSchedulePreview {
        location: policy.location.clone(),
        age_seconds: policy.age_seconds,
        unit_directory: unit_directory.clone(),
        service_unit,
        timer_unit,
        current_preview: test_current_preview(),
        preview_token: "fixture-schedule-preview".into(),
        warning: INSTALL_WARNING,
        policy,
        planned_unit_directory: unit_directory,
        unit_directory_identity: Vec::new(),
        bus_identity: test_bus_identity(),
    }
}

#[cfg(test)]
pub(crate) fn test_action_preview(action: &'static str) -> TrashRetentionActionPreview {
    let policy = test_policy();
    let (service_unit, timer_unit) = render_units(&policy).unwrap();
    let unit_directory = PathBuf::from("/fixture/systemd/user");
    TrashRetentionActionPreview {
        action,
        location: policy.location.clone(),
        age_seconds: policy.age_seconds,
        unit_directory: unit_directory.clone(),
        service_unit,
        timer_unit,
        current_preview: (action == "enable").then(test_current_preview),
        active_state: if action == "disable" {
            "active"
        } else {
            "inactive"
        }
        .into(),
        unit_file_state: Some(
            if action == "disable" {
                "enabled"
            } else {
                "disabled"
            }
            .into(),
        ),
        quarantine_paths: if action == "remove" {
            vec![unit_directory.join(".upkit-trash-remove-fixture.service")]
        } else {
            Vec::new()
        },
        preview_token: "fixture-action-preview".into(),
        warning: match action {
            "enable" => ENABLE_WARNING,
            "disable" => {
                "Preview only; disable stops this timer, but an already running service may continue. Unit files remain installed."
            }
            _ => {
                "Preview only; removal requires a disabled timer and inactive service. The two exact private unit files are quarantined before removal; errors may leave quarantine files."
            }
        },
        policy,
        planned_unit_directory: unit_directory,
        unit_directory_identity: Vec::new(),
        bus_identity: test_bus_identity(),
    }
}

#[cfg(test)]
fn test_policy() -> Policy {
    Policy {
        executable: PathBuf::from("/fixture/upkit"),
        config: PathBuf::from("/fixture/config.toml"),
        location: PathBuf::from("/fixture/Trash"),
        age_seconds: MIN_AGE.as_secs(),
        scope_token: "a".repeat(64),
    }
}

#[cfg(test)]
fn test_bus_identity() -> BusIdentity {
    BusIdentity {
        address: "unix:path=/fixture/bus".into(),
        device: 0,
        inode: 0,
        uid: rustix::process::geteuid().as_raw(),
        ctime: 0,
        ctime_nanos: 0,
    }
}

#[cfg(test)]
fn test_current_preview() -> TrashRetentionCurrentPreview {
    TrashRetentionCurrentPreview {
        eligible: 1,
        deferred: 0,
        skipped: 1,
        next_run_items: vec![TrashRetentionItemPreview {
            name: "old-file".into(),
            deletion_date: Some("2025-01-01T00:00:00".into()),
            kind: "file",
            descendant_count: 0,
            logical_bytes: 7,
        }],
        candidate_digest: "fixture-candidate-digest".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};

    fn fake_systemctl(directory: &Path, body: &str) -> PathBuf {
        let path = directory.join("systemctl-fixture");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn shell_quote(value: &Path) -> String {
        format!("'{}'", value.to_string_lossy().replace('\'', "'\\''"))
    }

    #[test]
    fn render_units_executes_the_hidden_executor_without_a_shell() {
        let policy = Policy {
            executable: PathBuf::from("/opt/Upkit/upkit"),
            config: PathBuf::from("/home/test/.config/upkit.toml"),
            location: PathBuf::from("/home/test/.local/share/Trash"),
            age_seconds: MIN_AGE.as_secs(),
            scope_token: "a".repeat(64),
        };
        let (service, timer) = render_units(&policy).unwrap();
        assert!(service.contains("trash scheduled-retention --location"));
        assert!(service.contains(" --age-seconds 2592000 --scope-token "));
        assert!(!service.contains("sh -c"));
        assert!(
            timer.contains("OnCalendar=daily\nPersistent=true\nUnit=upkit-trash-retention.service")
        );
        assert_eq!(parse_marker(&service).unwrap(), policy);
    }

    #[test]
    fn candidate_preview_digest_is_stable_without_clock_and_binds_candidates() {
        let preview = TrashRetentionCurrentPreview {
            eligible: 2,
            deferred: 0,
            skipped: 1,
            next_run_items: vec![TrashRetentionItemPreview {
                name: "old-file".into(),
                deletion_date: Some("2025-01-01T00:00:00".into()),
                kind: "file",
                descendant_count: 0,
                logical_bytes: 7,
            }],
            candidate_digest: "stable-candidate-identities".into(),
        };
        let next_preview = preview.clone();
        assert_eq!(
            candidate_digest(&preview).unwrap(),
            candidate_digest(&next_preview).unwrap()
        );

        let mut changed = preview.clone();
        changed.next_run_items[0].name = "replacement".into();
        assert_ne!(
            candidate_digest(&preview).unwrap(),
            candidate_digest(&changed).unwrap()
        );
        changed = preview.clone();
        changed.eligible += 1;
        assert_ne!(
            candidate_digest(&preview).unwrap(),
            candidate_digest(&changed).unwrap()
        );
        changed = preview.clone();
        changed.candidate_digest.push('!');
        assert_ne!(
            candidate_digest(&preview).unwrap(),
            candidate_digest(&changed).unwrap()
        );
    }

    #[test]
    fn action_fixture_shows_candidates_only_for_enable() {
        assert!(test_action_preview("enable").current_preview.is_some());
        assert!(test_action_preview("disable").current_preview.is_none());
        assert!(test_action_preview("remove").current_preview.is_none());
    }

    #[test]
    fn install_rejects_mutated_displayed_units_before_manager_or_filesystem_changes() {
        let fixture = tempfile::tempdir().unwrap();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let unit_directory = fixture.path().join("systemd-user");
        fs::create_dir(&unit_directory).unwrap();
        fs::set_permissions(&unit_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = fixture.path().join("bus");
        let _listener = UnixListener::bind(&socket).unwrap();
        let bus = BusIdentity::capture(&format!("unix:path={}", socket.display())).unwrap();
        let manager_calls = fixture.path().join("manager-calls");
        let manager = fake_systemctl(
            fixture.path(),
            &format!(" : > '{}'\nexit 0", manager_calls.display()),
        );
        let policy = Policy {
            executable: PathBuf::from("/opt/upkit"),
            config: PathBuf::from("/home/test/upkit.toml"),
            location: PathBuf::from("/home/test/Trash"),
            age_seconds: MIN_AGE.as_secs(),
            scope_token: "e".repeat(64),
        };
        let (service, timer) = render_units(&policy).unwrap();
        let mut plan = TrashRetentionSchedulePreview {
            location: policy.location.clone(),
            age_seconds: policy.age_seconds,
            unit_directory: unit_directory.clone(),
            service_unit: service,
            timer_unit: timer,
            current_preview: TrashRetentionCurrentPreview {
                eligible: 0,
                deferred: 0,
                skipped: 0,
                next_run_items: Vec::new(),
                candidate_digest: "fixture".into(),
            },
            preview_token: "f".repeat(64),
            warning: INSTALL_WARNING,
            policy,
            planned_unit_directory: unit_directory.clone(),
            unit_directory_identity: Vec::new(),
            bus_identity: bus.clone(),
        };
        let token = plan.preview_token.clone();
        let reviewed_service = plan.service_unit.clone();
        let reviewed_timer = plan.timer_unit.clone();
        plan.service_unit.push_str("# changed after review\n");
        assert!(install_with(&plan, &token, &manager, &bus,).is_err());
        assert!(!manager_calls.exists());
        assert!(!unit_directory.join(SERVICE).exists());
        assert!(!unit_directory.join(TIMER).exists());

        plan.service_unit = reviewed_service;
        plan.timer_unit = reviewed_timer;
        plan.timer_unit.push_str("# changed after review\n");
        assert!(install_with(&plan, &token, &manager, &bus,).is_err());
        assert!(!manager_calls.exists());
        assert!(!unit_directory.join(SERVICE).exists());
        assert!(!unit_directory.join(TIMER).exists());
    }

    #[test]
    fn preview_token_binds_the_local_bus_socket_identity() {
        use std::os::unix::fs::MetadataExt;

        let fixture = tempfile::tempdir().unwrap();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let directory = fixture.path().join("units");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let manager = fake_systemctl(fixture.path(), "exit 0");
        let bus_a = fixture.path().join("bus-a");
        let bus_b = fixture.path().join("bus-b");
        let _listener_a = UnixListener::bind(&bus_a).unwrap();
        let listener_b = UnixListener::bind(&bus_b).unwrap();
        let metadata = fs::metadata(&directory).unwrap();
        let identity_a = BusIdentity::capture(&format!("unix:path={}", bus_a.display())).unwrap();
        let identity_b = BusIdentity::capture(&format!("unix:path={}", bus_b.display())).unwrap();
        let token_a = preview_token(
            "install",
            &metadata,
            &[b"same reviewed plan"],
            &manager,
            &identity_a,
        )
        .unwrap();
        fs::set_permissions(&bus_a, fs::Permissions::from_mode(0o600)).unwrap();
        let identity_a_after_chmod =
            BusIdentity::capture(&format!("unix:path={}", bus_a.display())).unwrap();
        assert_eq!(identity_a.device, identity_a_after_chmod.device);
        assert_eq!(identity_a.inode, identity_a_after_chmod.inode);
        assert_ne!(
            (identity_a.ctime, identity_a.ctime_nanos),
            (
                identity_a_after_chmod.ctime,
                identity_a_after_chmod.ctime_nanos
            )
        );
        let token_a_after_chmod = preview_token(
            "install",
            &metadata,
            &[b"same reviewed plan"],
            &manager,
            &identity_a_after_chmod,
        )
        .unwrap();
        assert_ne!(token_a, token_a_after_chmod);
        let token_b = preview_token(
            "install",
            &metadata,
            &[b"same reviewed plan"],
            &manager,
            &identity_b,
        )
        .unwrap();
        assert_ne!(token_a, token_b);
        let original_inode = fs::metadata(&bus_b).unwrap().ino();
        drop(listener_b);
        let old_socket_path = fixture.path().join("bus-b-old");
        fs::rename(&bus_b, &old_socket_path).unwrap();
        let _replacement_listener = UnixListener::bind(&bus_b).unwrap();
        assert_ne!(original_inode, fs::metadata(&bus_b).unwrap().ino());
        let replacement_identity =
            BusIdentity::capture(&format!("unix:path={}", bus_b.display())).unwrap();
        let token_replaced = preview_token(
            "install",
            &metadata,
            &[b"same reviewed plan"],
            &manager,
            &replacement_identity,
        )
        .unwrap();
        assert_ne!(token_b, token_replaced);
    }

    #[test]
    fn action_preview_rejects_a_replaced_bus_before_calling_manager() {
        let fixture = tempfile::tempdir().unwrap();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = fixture.path().join("bus");
        let listener = UnixListener::bind(&socket).unwrap();
        let reviewed_bus =
            BusIdentity::capture(&format!("unix:path={}", socket.display())).unwrap();
        drop(listener);
        let old_socket = fixture.path().join("bus-old");
        fs::rename(&socket, &old_socket).unwrap();
        let _replacement_listener = UnixListener::bind(&socket).unwrap();
        let replacement_bus =
            BusIdentity::capture(&format!("unix:path={}", socket.display())).unwrap();
        assert_ne!(reviewed_bus, replacement_bus);

        let manager_calls = fixture.path().join("manager-calls");
        let manager = fake_systemctl(
            fixture.path(),
            &format!(" : > '{}'; exit 0", manager_calls.display()),
        );
        let mut plan = test_action_preview("disable");
        plan.bus_identity = reviewed_bus;
        assert!(disable_with(&plan, &plan.preview_token, &manager, &replacement_bus).is_err());
        assert!(!manager_calls.exists());
    }

    #[test]
    fn manager_replacement_during_systemctl_stops_before_next_call() {
        let fixture = tempfile::tempdir().unwrap();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let unit_directory = fixture.path().join("systemd-user");
        fs::create_dir(&unit_directory).unwrap();
        fs::set_permissions(&unit_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = fixture.path().join("bus");
        let _listener = UnixListener::bind(&socket).unwrap();
        let bus = BusIdentity::capture(&format!("unix:path={}", socket.display())).unwrap();
        let calls = fixture.path().join("manager-calls");
        let old_socket = fixture.path().join("bus-old");
        let script = format!(
            "[ \"$1\" = '--user' ] || exit 90\nshift\n[ \"$1\" = show ] || exit 91\nprintf 'called\\n' >> '{}'\n/bin/mv '{}' '{}'\n: > '{}'\nexit 42",
            calls.display(),
            socket.display(),
            old_socket.display(),
            socket.display(),
        );
        let manager = fake_systemctl(fixture.path(), &script);
        let policy = test_policy();
        let _preview_guard =
            TestPolicyPreviewGuard::install(policy.clone(), test_current_preview());

        let error = preview_install_with(&policy, &unit_directory, &manager, &bus).unwrap_err();
        assert!(format!("{error:#}").contains("outcome may be unknown"));
        assert_eq!(fs::read_to_string(calls).unwrap(), "called\n");
    }

    #[test]
    fn unit_directory_rejects_an_unprotected_parent() {
        let fixture = tempfile::tempdir().unwrap();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let unsafe_parent = fixture.path().join("unsafe-parent");
        fs::create_dir(&unsafe_parent).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        let directory = unsafe_parent.join("systemd-user");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(open_unit_directory(&directory).is_err());
    }

    #[test]
    fn lifecycle_install_disable_enable_disable_remove_uses_only_fake_manager() {
        let fixture = tempfile::tempdir().unwrap();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let unit_directory = fixture.path().join("systemd-user");
        fs::create_dir(&unit_directory).unwrap();
        fs::set_permissions(&unit_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = fixture.path().join("bus");
        let _listener = UnixListener::bind(&socket).unwrap();
        let bus = BusIdentity::capture(&format!("unix:path={}", socket.display())).unwrap();
        let manager_state = fixture.path().join("manager-state");
        fs::write(&manager_state, "inactive\ndisabled\n").unwrap();
        let manager_body = format!(
            "[ \"$1\" = '--user' ] || exit 90\nshift\ncommand=$1\nshift\ncase \"$command\" in\n  daemon-reload) exit 0 ;;\n  enable) printf 'active\\nenabled\\n' > {state} ;;\n  disable) printf 'inactive\\ndisabled\\n' > {state} ;;\n  show)\n    unit=$1\n    property=\n    for argument in \"$@\"; do case \"$argument\" in --property=*) property=${{argument#--property=}} ;; esac; done\n    file={directory}/$unit\n    case \"$property\" in\n      LoadState) if [ -f \"$file\" ]; then printf 'loaded\\n'; else printf 'not-found\\n'; fi ;;\n      FragmentPath) if [ -f \"$file\" ]; then printf '%s\\n' \"$file\"; else printf '\\n'; fi ;;\n      DropInPaths) printf '\\n' ;;\n      NeedDaemonReload) printf 'no\\n' ;;\n      ActiveState) if [ \"$unit\" = '{timer}' ]; then IFS= read -r state_value < {state}; printf '%s\\n' \"$state_value\"; else printf 'inactive\\n'; fi ;;\n      UnitFileState) if [ \"$unit\" = '{timer}' ]; then while IFS= read -r state_value && IFS= read -r file_state; do printf '%s\\n' \"$file_state\"; done < {state}; else printf 'static\\n'; fi ;;\n      *) exit 91 ;;\n    esac\n    ;;\n  *) exit 92 ;;\nesac",
            state = shell_quote(&manager_state),
            directory = shell_quote(&unit_directory),
            timer = TIMER,
        );
        let manager = fake_systemctl(fixture.path(), &manager_body);
        let policy = test_policy();
        let policy_preview = test_current_preview();
        let _preview_guard = TestPolicyPreviewGuard::install(policy.clone(), policy_preview);

        let install_plan = preview_install_with(&policy, &unit_directory, &manager, &bus).unwrap();
        assert_eq!(
            install_with(&install_plan, &install_plan.preview_token, &manager, &bus,).unwrap(),
            "active_and_enabled"
        );
        assert!(unit_directory.join(SERVICE).is_file());
        assert!(unit_directory.join(TIMER).is_file());

        let disable_plan = preview_action_with("disable", &unit_directory, &manager, &bus).unwrap();
        assert_eq!(
            disable_with(&disable_plan, &disable_plan.preview_token, &manager, &bus).unwrap(),
            "inactive_and_disabled"
        );

        let enable_plan = preview_action_with("enable", &unit_directory, &manager, &bus).unwrap();
        assert_eq!(
            enable_with(&enable_plan, &enable_plan.preview_token, &manager, &bus).unwrap(),
            "active_and_enabled"
        );

        let disable_plan = preview_action_with("disable", &unit_directory, &manager, &bus).unwrap();
        assert_eq!(
            disable_with(&disable_plan, &disable_plan.preview_token, &manager, &bus).unwrap(),
            "inactive_and_disabled"
        );

        let remove_plan = preview_action_with("remove", &unit_directory, &manager, &bus).unwrap();
        assert_eq!(
            remove_with(&remove_plan, &remove_plan.preview_token, &manager, &bus).unwrap(),
            "units_absent"
        );
        assert!(!unit_directory.join(SERVICE).exists());
        assert!(!unit_directory.join(TIMER).exists());
        assert!(fs::read_dir(&unit_directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".upkit-trash-remove-")
        }));
        assert_eq!(
            fs::read_to_string(&manager_state).unwrap(),
            "inactive\ndisabled\n"
        );
    }

    #[test]
    fn systemd_parser_accepts_quoted_paths_with_spaces_dollars_and_percent() {
        let analyzer = ["/usr/bin/systemd-analyze", "/bin/systemd-analyze"]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file());
        let Some(analyzer) = analyzer else {
            return;
        };
        let fixture = tempfile::tempdir().unwrap();
        let executable = fixture.path().join("upkit $%.bin");
        fs::write(&executable, "fixture").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let config = fixture.path().join("settings $%.toml");
        fs::write(&config, "fixture").unwrap();
        let location = fixture.path().join("Trash $%");
        fs::create_dir(&location).unwrap();
        let policy = Policy {
            executable,
            config,
            location,
            age_seconds: MIN_AGE.as_secs(),
            scope_token: "d".repeat(64),
        };
        let (service, timer) = render_units(&policy).unwrap();
        let service_path = fixture.path().join(SERVICE);
        let timer_path = fixture.path().join(TIMER);
        fs::write(&service_path, service).unwrap();
        fs::write(&timer_path, timer).unwrap();
        let output = Command::new(analyzer)
            .args(["verify"])
            .arg(service_path)
            .arg(timer_path)
            .env_clear()
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "systemd-analyze verify failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn systemctl_fixture_receives_only_the_validated_local_bus_and_user_scope() {
        let fixture = tempfile::tempdir().unwrap();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = fixture.path().join("bus");
        let _listener = UnixListener::bind(&socket).unwrap();
        let bus = BusIdentity::capture(&format!("unix:path={}", socket.display())).unwrap();
        let log = fixture.path().join("args");
        let script = format!(
            "printf '%s\\n' \"$DBUS_SESSION_BUS_ADDRESS\" \"$XDG_RUNTIME_DIR\" \"$LD_PRELOAD\" \"$DBUS_STARTER_ADDRESS\" \"$*\" > '{}'\nprintf 'active\\n'",
            log.display()
        );
        let manager = fake_systemctl(fixture.path(), &script);
        let output = systemctl_with(
            &manager,
            &bus,
            &[
                "show",
                TIMER,
                "--no-pager",
                "--property=ActiveState",
                "--value",
            ],
        )
        .unwrap();
        assert_eq!(output, "active\n");
        assert_eq!(
            fs::read_to_string(log).unwrap(),
            format!(
                "unix:path={}\n{}\n\n\n--user show {TIMER} --no-pager --property=ActiveState --value\n",
                socket.display(),
                fixture.path().display()
            )
        );
    }

    #[test]
    fn systemctl_timeout_kills_the_fake_manager_and_checks_bus_afterward() {
        let fixture = tempfile::tempdir().unwrap();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = fixture.path().join("bus");
        let _listener = UnixListener::bind(&socket).unwrap();
        let bus = BusIdentity::capture(&format!("unix:path={}", socket.display())).unwrap();
        let manager = fake_systemctl(fixture.path(), "exec /bin/sleep 2");
        let start = Instant::now();
        let error =
            systemctl_with_timeout(&manager, &bus, &["show", TIMER], Duration::from_millis(50))
                .unwrap_err();
        assert!(format!("{error:#}").contains("systemctl timed out"));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(bus.verify_current().is_ok());
    }

    #[test]
    fn action_preview_accepts_only_the_exact_private_unit_and_manager_state() {
        let fixture = tempfile::tempdir().unwrap();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let unit_directory = fixture.path().join("systemd-user");
        fs::create_dir(&unit_directory).unwrap();
        fs::set_permissions(&unit_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = fixture.path().join("bus");
        let _listener = UnixListener::bind(&socket).unwrap();
        let bus = BusIdentity::capture(&format!("unix:path={}", socket.display())).unwrap();
        let policy = Policy {
            executable: PathBuf::from("/opt/upkit"),
            config: PathBuf::from("/home/test/upkit.toml"),
            location: PathBuf::from("/home/test/Trash"),
            age_seconds: MIN_AGE.as_secs(),
            scope_token: "b".repeat(64),
        };
        let (service, timer) = render_units(&policy).unwrap();
        fs::write(unit_directory.join(SERVICE), &service).unwrap();
        fs::write(unit_directory.join(TIMER), &timer).unwrap();
        for name in unit_names() {
            fs::set_permissions(unit_directory.join(name), fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let service_name = SERVICE;
        let timer_name = TIMER;
        let body = format!(
            "case \"$*\" in\n  *--property=LoadState*) printf 'loaded\\n' ;;\n  *--property=NeedDaemonReload*) printf 'no\\n' ;;\n  *--property=DropInPaths*) printf '\\n' ;;\n  *--property=FragmentPath*) case \"$*\" in *{timer_name}*) printf '%s\\n' '{unit_directory}/{timer_name}' ;; *) printf '%s\\n' '{unit_directory}/{service_name}' ;; esac ;;\n  *--property=ActiveState*) case \"$*\" in *{timer_name}*) printf 'active\\n' ;; *) printf 'inactive\\n' ;; esac ;;\n  *--property=UnitFileState*) case \"$*\" in *{timer_name}*) printf 'enabled\\n' ;; *) printf 'static\\n' ;; esac ;;\n  *) exit 9 ;;\nesac",
            unit_directory = unit_directory.display(),
        );
        let manager = fake_systemctl(fixture.path(), &body);
        let plan = preview_action_with("disable", &unit_directory, &manager, &bus).unwrap();
        assert_eq!(plan.action, "disable");
        assert_eq!(plan.active_state, "active");
        assert_eq!(plan.unit_file_state.as_deref(), Some("enabled"));
        assert_eq!(plan.service_unit, service);

        let manager_with_drop_in = fake_systemctl(
            fixture.path(),
            &body.replace(
                "DropInPaths*) printf '\\n'",
                "DropInPaths*) printf '/tmp/foreign.conf\\n'",
            ),
        );
        assert!(
            preview_action_with("disable", &unit_directory, &manager_with_drop_in, &bus,).is_err()
        );
    }

    #[test]
    fn remote_bus_addresses_fail_closed_without_starting_a_manager() {
        let fixture = tempfile::tempdir().unwrap();
        let manager = fake_systemctl(fixture.path(), "exit 99");
        let bus = BusIdentity {
            address: "tcp:host=example.com,port=1234".into(),
            device: 0,
            inode: 0,
            uid: rustix::process::geteuid().as_raw(),
            ctime: 0,
            ctime_nanos: 0,
        };
        assert!(systemctl_with(&manager, &bus, &["show", TIMER]).is_err());
    }

    #[test]
    fn unit_directory_rejects_a_link_or_other_user_writes() {
        let fixture = tempfile::tempdir().unwrap();
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let directory = fixture.path().join("units");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(open_unit_directory(&directory).is_ok());
        let link = fixture.path().join("link");
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        assert!(open_unit_directory(&link).is_err());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(open_unit_directory(&directory).is_err());
    }
}
