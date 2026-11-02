//! Read-only system maintenance status.
use serde::Serialize;
#[cfg(any(test, target_os = "windows"))]
use std::sync::atomic::AtomicBool;
use std::{
    collections::BTreeMap,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Serialize)]
pub struct TrimStatus {
    pub platform: String,
    pub fstrim_available: bool,
    pub capability: String,
    pub timer: TimerStatus,
    pub guidance: &'static str,
    pub mounts: Vec<MountStatus>,
    pub mounts_warning: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MountStatus {
    pub mount_point: String,
    #[serde(
        serialize_with = "crate::sweep::serialize_path",
        skip_serializing_if = "mount_path_uses_legacy_display"
    )]
    pub mount_path: std::path::PathBuf,
    pub filesystem: String,
    pub device: String,
    pub discard_max_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub device_discard: &'static str,
    pub filesystem_trim: &'static str,
    pub fstab_trim_exclusion: &'static str,
    pub online_discard_option: &'static str,
}

fn mount_path_uses_legacy_display(path: &Path) -> bool {
    path.to_str().is_some()
}

fn mountinfo_lines(input: &[u8]) -> impl Iterator<Item = &[u8]> {
    input
        .strip_suffix(b"\n")
        .unwrap_or(input)
        .split(|byte| *byte == b'\n')
}

fn mountinfo_fields(line: &[u8]) -> Vec<&[u8]> {
    line.split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect()
}

fn decode_mountinfo_path(value: &[u8]) -> anyhow::Result<std::path::PathBuf> {
    use anyhow::{Context, bail};

    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'\\' {
            decoded.push(value[index]);
            index += 1;
            continue;
        }
        let escape = value
            .get(index + 1..index + 4)
            .context("invalid mount table path escape")?;
        decoded.push(match escape {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => bail!("invalid mount table path escape"),
        });
        index += 4;
    }
    if !decoded.starts_with(b"/") || decoded.contains(&0) {
        bail!("mount table path is not absolute");
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(std::path::PathBuf::from(std::ffi::OsString::from_vec(
            decoded,
        )))
    }
    #[cfg(windows)]
    {
        Ok(std::path::PathBuf::from(
            String::from_utf8(decoded).context("mount path is not UTF-8 on Windows")?,
        ))
    }
}

pub(crate) fn display_mount_path(path: &Path) -> String {
    match path.to_str() {
        Some(value) => {
            let mut display = String::new();
            for character in value.chars() {
                if character == '%' {
                    // Keep literal percent signs distinct from encoded filesystem bytes.
                    display.push_str("%25");
                } else if character == '\\' || character.is_control() {
                    display.extend(character.escape_default());
                } else {
                    display.push(character);
                }
            }
            display
        }
        None => crate::sweep::display_path(path),
    }
}

fn fstab_trim_excluded(fstab: &str, mount_point: &Path, filesystem: &str) -> Option<bool> {
    let mut matched = None;
    for line in fstab.lines() {
        let line = line.split_once('#').map_or(line, |(before, _)| before);
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if !(3..=6).contains(&fields.len())
            || fields
                .get(3)
                .is_some_and(|options| options.bytes().all(|byte| byte.is_ascii_digit()))
            || fields
                .get(4)
                .is_some_and(|value| value.parse::<u32>().is_err())
            || fields
                .get(5)
                .is_some_and(|value| value.parse::<u32>().is_err())
        {
            return None;
        }
        if decode_mountinfo_path(fields[1].as_bytes()).ok()? != mount_point
            || fields[2] != filesystem
        {
            continue;
        }
        let excluded = fields
            .get(3)
            .is_some_and(|options| options.split(',').any(|option| option == "X-fstrim.notrim"));
        if matched.replace(excluded).is_some() {
            return None;
        }
    }
    matched
}

fn online_discard_option(mount_options: &str, super_options: Option<&str>) -> &'static str {
    let mut state = None;
    for option in mount_options.split(',').chain(
        super_options
            .into_iter()
            .flat_map(|options| options.split(',')),
    ) {
        let value = match option {
            "discard" | "discard=async" | "discard=sync" => Some(true),
            "nodiscard" => Some(false),
            _ => None,
        };
        if let Some(value) = value {
            if state.is_some_and(|previous| previous != value) {
                return "unknown";
            }
            state = Some(value);
        }
    }
    match state {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "unknown",
    }
}

fn mounts_from(
    mountinfo: &[u8],
    sys_dev_block: &Path,
    fstab: Option<&str>,
) -> (Vec<MountStatus>, Option<String>) {
    let mut result = Vec::new();
    let mut malformed = false;
    for line in mountinfo_lines(mountinfo) {
        if line.is_empty() {
            malformed = true;
            continue;
        }
        let fields = mountinfo_fields(line);
        let Some(separator) = fields.iter().position(|field| *field == b"-") else {
            malformed = true;
            continue;
        };
        if fields.len() <= separator + 2 || separator < 6 {
            malformed = true;
            continue;
        }
        let Ok(device) = std::str::from_utf8(fields[2]) else {
            malformed = true;
            continue;
        };
        let Some((major, minor)) = device.split_once(':') else {
            malformed = true;
            continue;
        };
        if major.parse::<u32>().is_err() || minor.parse::<u32>().is_err() {
            malformed = true;
            continue;
        }
        let block = sys_dev_block.join(device);
        let Ok(resolved) = block.canonicalize() else {
            continue;
        };
        let mut queue = resolved.join("queue/discard_max_bytes");
        if !queue.exists()
            && resolved.join("partition").is_file()
            && let Some(parent) = resolved.parent()
        {
            queue = parent.join("queue/discard_max_bytes");
        }
        let limit = std::fs::read_to_string(queue)
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok());
        let (Ok(mount_path), Ok(filesystem), Ok(mount_options)) = (
            decode_mountinfo_path(fields[4]),
            std::str::from_utf8(fields[separator + 1]),
            std::str::from_utf8(fields[5]),
        ) else {
            malformed = true;
            continue;
        };
        let super_options = match fields
            .get(separator + 3)
            .map(|options| std::str::from_utf8(options))
            .transpose()
        {
            Ok(options) => options,
            Err(_) => {
                malformed = true;
                continue;
            }
        };
        let mount_point = mount_path
            .to_str()
            .map(clean)
            .unwrap_or_else(|| crate::sweep::display_path(&mount_path));
        let fstab_trim_exclusion =
            match fstab.and_then(|fstab| fstab_trim_excluded(fstab, &mount_path, filesystem)) {
                Some(true) => "observed",
                Some(false) => "not_observed",
                None => "unknown",
            };
        result.push(MountStatus {
            mount_point,
            mount_path,
            filesystem: clean(filesystem),
            device: device.into(),
            discard_max_bytes: limit,
            available_bytes: None,
            online_discard_option: online_discard_option(mount_options, super_options),
            device_discard: match limit {
                Some(0) => "disabled_or_unsupported",
                Some(_) => "advertised",
                None => "unknown",
            },
            filesystem_trim: "unknown: filesystem FITRIM support and permissions not tested",
            fstab_trim_exclusion,
        });
    }
    result.sort_by(|a, b| {
        a.mount_point
            .cmp(&b.mount_point)
            .then(a.device.cmp(&b.device))
    });
    (
        result,
        malformed.then(|| "some mount records could not be parsed".into()),
    )
}

fn linux_mounts() -> (Vec<MountStatus>, Option<String>) {
    match std::fs::read("/proc/self/mountinfo") {
        Ok(mountinfo) => {
            let fstab = std::fs::read_to_string("/etc/fstab").ok();
            let (mounts, mut warning) =
                mounts_from(&mountinfo, Path::new("/sys/dev/block"), fstab.as_deref());
            if fstab.is_none() {
                let warning_text =
                    "cannot read /etc/fstab; explicit fstrim exclusions could not be checked";
                warning = Some(match warning {
                    Some(previous) => format!("{previous}; {warning_text}"),
                    None => warning_text.into(),
                });
            }
            (mounts, warning)
        }
        Err(err) => (
            Vec::new(),
            Some(format!("cannot read mount information: {err}")),
        ),
    }
}

#[derive(Debug, Serialize)]
pub struct TimerStatus {
    pub state: String,
    pub load_state: Option<String>,
    pub unit_file_state: Option<String>,
    pub last_trigger: Option<String>,
    pub next_trigger: Option<String>,
    pub detail: Option<String>,
}

impl TimerStatus {
    pub(crate) fn skipped(detail: impl Into<String>) -> Self {
        Self {
            state: "skipped".into(),
            load_state: None,
            unit_file_state: None,
            last_trigger: None,
            next_trigger: None,
            detail: Some(detail.into()),
        }
    }
}

fn timer_unavailable(detail: &str) -> TimerStatus {
    TimerStatus {
        state: "unavailable".into(),
        load_state: None,
        unit_file_state: None,
        last_trigger: None,
        next_trigger: None,
        detail: Some(detail.into()),
    }
}

fn parse_timer(output: &str) -> TimerStatus {
    let fields: BTreeMap<_, _> = output
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let Some(load) = fields.get("LoadState").copied() else {
        return timer_unavailable("systemd did not return a load state");
    };
    if load == "not-found" {
        return TimerStatus {
            state: "not_found".into(),
            load_state: Some(load.into()),
            unit_file_state: None,
            last_trigger: None,
            next_trigger: None,
            detail: None,
        };
    }
    let Some(active) = fields.get("ActiveState").copied() else {
        return timer_unavailable("systemd did not return an active state");
    };
    let value = |key| {
        fields
            .get(key)
            .filter(|value| !value.is_empty() && **value != "n/a" && **value != "0")
            .map(|value| clean(value))
    };
    TimerStatus {
        state: clean(active),
        load_state: Some(clean(load)),
        unit_file_state: value("UnitFileState"),
        last_trigger: value("LastTriggerUSec"),
        next_trigger: value("NextElapseUSecRealtime"),
        detail: None,
    }
}

fn clean(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if character.is_control() {
            output.extend(character.escape_default());
        } else {
            output.push(character);
        }
    }
    output
}

pub(crate) fn timer_command(unit: &str, user: bool) -> TimerStatus {
    let Some(systemctl) = which::which("systemctl").ok() else {
        return timer_unavailable("systemctl not found");
    };
    let mut command = Command::new(systemctl);
    if user {
        command.arg("--user");
    }
    let Ok(mut child) = command
        .args([
            "show",
            unit,
            "--no-pager",
            "--property=LoadState,ActiveState,UnitFileState,LastTriggerUSec,NextElapseUSecRealtime",
        ])
        .env("SYSTEMD_PAGER", "cat")
        .env("SYSTEMD_COLORS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return timer_unavailable("could not start systemctl");
    };
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return timer_unavailable("systemctl output unavailable");
    };
    let (send, receive) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.by_ref().take(65537).read_to_end(&mut bytes);
        let _ = send.send((result, bytes));
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let Ok((Ok(_), bytes)) = receive.recv_timeout(Duration::from_millis(100)) else {
        return timer_unavailable("could not read systemctl output");
    };
    if bytes.len() > 65536 {
        return timer_unavailable("systemctl output exceeded limit");
    }
    if !status.is_some_and(|status| status.success()) {
        return timer_unavailable("systemd manager unavailable or query failed");
    }
    match String::from_utf8(bytes) {
        Ok(text) => parse_timer(&text),
        Err(_) => timer_unavailable("systemctl output was not UTF-8"),
    }
}

pub fn trim_status() -> TrimStatus {
    trim_status_with_dry_run(false)
}

pub fn trim_status_with_dry_run(dry_run: bool) -> TrimStatus {
    if cfg!(target_os = "linux") {
        let (mut mounts, mounts_warning) = linux_mounts();
        for mount in &mut mounts {
            mount.available_bytes = available_space(&mount.mount_path);
        }
        TrimStatus {
            platform: std::env::consts::OS.into(),
            fstrim_available: which::which("fstrim").is_ok(),
            capability: "unknown: filesystem FITRIM support and permissions have not been tested"
                .into(),
            timer: if dry_run {
                TimerStatus::skipped(
                    "dry-run skips the systemd query; timer state was not inspected",
                )
            } else {
                timer_command("fstrim.timer", false)
            },
            guidance: "Reuse an existing system-managed timer. A unique, well-formed /etc/fstab entry matching a mount point and filesystem type reports whether X-fstrim.notrim was observed; duplicate, malformed, or missing entries remain unknown. This entry observation does not prove the entry applies or a timer honors it. Online discard mount options are separate from FITRIM; absent options and filesystem support remain unknown. TRIM does not increase filesystem free space.",
            mounts,
            mounts_warning,
        }
    } else {
        #[cfg(target_os = "windows")]
        {
            windows_trim_status(dry_run)
        }
        #[cfg(not(target_os = "windows"))]
        {
            TrimStatus {
                platform: std::env::consts::OS.into(),
                fstrim_available: false,
                capability: "unsupported: platform-specific detection is not implemented".into(),
                timer: timer_unavailable("systemd timer status is only available on Linux"),
                guidance: "Use the operating system's storage maintenance tools.",
                mounts: Vec::new(),
                mounts_warning: Some(
                    "mount capability detection is unsupported on this platform".into(),
                ),
            }
        }
    }
}

#[cfg(any(test, target_os = "windows"))]
fn windows_trim_notification_status_with(
    dry_run: bool,
    query: impl FnOnce() -> Option<String>,
) -> String {
    if dry_run {
        return "Windows filesystem TRIM notification query skipped by dry-run; device support is unknown.".into();
    }
    query().map_or_else(
        || {
            "Windows filesystem TRIM notification setting unavailable; device support is unknown."
                .into()
        },
        |output| parse_windows_trim_notification_status(&output),
    )
}

#[cfg(target_os = "windows")]
fn windows_trim_status(dry_run: bool) -> TrimStatus {
    let capability = windows_trim_notification_status_with(dry_run, || {
        let executable = windows_fsutil_executable()?;
        query_fsutil_with(&executable)
    });
    TrimStatus {
        platform: std::env::consts::OS.into(),
        fstrim_available: false,
        capability,
        timer: timer_unavailable("systemd timer status is only available on Linux"),
        guidance: "fsutil reports Windows filesystem delete-notification settings, not SSD or storage-device TRIM support. Upkit does not run manual TRIM on Windows.",
        mounts: Vec::new(),
        mounts_warning: Some(
            "per-volume and storage-device TRIM support were not inspected".into(),
        ),
    }
}

#[cfg(any(test, target_os = "windows"))]
fn parse_windows_trim_notification_status(output: &str) -> String {
    fn record(previous: &mut Option<&'static str>, state: &'static str) {
        *previous = Some(match *previous {
            None => state,
            Some("ambiguous") => "ambiguous",
            Some(existing) if existing == state => existing,
            Some(_) => "ambiguous",
        });
    }

    let mut ntfs = None;
    let mut refs = None;
    for line in output.lines() {
        let line = line.trim();
        let lower = line.to_ascii_lowercase();
        let (state, value) = if lower.starts_with("ntfs disabledeletenotify") {
            (&mut ntfs, line)
        } else if lower.starts_with("refs disabledeletenotify") {
            (&mut refs, line)
        } else {
            continue;
        };
        let value = if lower.contains("is not currently set") {
            "not explicitly set"
        } else if let Some((_, value)) = value.split_once('=') {
            match value.split_whitespace().next() {
                Some("0") => "enabled",
                Some("1") => "disabled",
                _ => "unknown",
            }
        } else {
            "unknown"
        };
        record(state, value);
    }
    let label = |state: Option<&'static str>| state.unwrap_or("not reported");
    format!(
        "Windows filesystem TRIM notification policy: NTFS {}; ReFS {}; storage-device support is not verified.",
        label(ntfs),
        label(refs),
    )
}

#[cfg(target_os = "windows")]
fn windows_fsutil_executable() -> Option<std::path::PathBuf> {
    let system = known_folders::get_known_folder_path(known_folders::KnownFolder::System)?;
    verified_windows_system_executable(&system, "fsutil.exe")
}

#[cfg(any(test, target_os = "windows"))]
fn verified_windows_system_executable(
    system_directory: &Path,
    name: &str,
) -> Option<std::path::PathBuf> {
    use std::path::Component;

    let mut name_components = Path::new(name).components();
    if !system_directory.is_absolute()
        || !matches!(name_components.next(), Some(Component::Normal(_)))
        || name_components.next().is_some()
    {
        return None;
    }
    for component in system_directory
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let metadata = std::fs::symlink_metadata(component).ok()?;
        #[cfg(target_os = "windows")]
        let reparse = {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes() & 0x400 != 0
        };
        #[cfg(not(target_os = "windows"))]
        let reparse = metadata.file_type().is_symlink();
        if reparse {
            return None;
        }
    }
    let system_directory = system_directory.canonicalize().ok()?;
    let executable = system_directory.join(name);
    let metadata = std::fs::symlink_metadata(&executable).ok()?;
    #[cfg(target_os = "windows")]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    };
    #[cfg(not(target_os = "windows"))]
    let reparse = metadata.file_type().is_symlink();
    if reparse || !metadata.is_file() || metadata.len() == 0 {
        return None;
    }
    let executable = executable.canonicalize().ok()?;
    (executable.parent() == Some(system_directory.as_path())).then_some(executable)
}

#[cfg(any(test, target_os = "windows"))]
fn query_fsutil_with(executable: &Path) -> Option<String> {
    const OUTPUT_LIMIT: usize = 65_536;
    let reader_guard = FsutilOutputReaderGuard::acquire()?;
    let mut child = Command::new(executable)
        .args(["behavior", "query", "DisableDeleteNotify"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let (send, receive) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .by_ref()
            .take((OUTPUT_LIMIT + 1) as u64)
            .read_to_end(&mut bytes);
        drop(reader_guard);
        let _ = send.send((result, bytes));
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let Ok((Ok(_), bytes)) = receive.recv_timeout(Duration::from_millis(100)) else {
        return None;
    };
    if bytes.len() > OUTPUT_LIMIT || !status.is_some_and(|status| status.success()) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(any(test, target_os = "windows"))]
static FSUTIL_OUTPUT_READER_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(any(test, target_os = "windows"))]
struct FsutilOutputReaderGuard;

#[cfg(any(test, target_os = "windows"))]
impl FsutilOutputReaderGuard {
    fn acquire() -> Option<Self> {
        FSUTIL_OUTPUT_READER_ACTIVE
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::Acquire,
                std::sync::atomic::Ordering::Relaxed,
            )
            .ok()
            .map(|_| Self)
    }
}

#[cfg(any(test, target_os = "windows"))]
impl Drop for FsutilOutputReaderGuard {
    fn drop(&mut self) {
        FSUTIL_OUTPUT_READER_ACTIVE.store(false, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn available_space(path: &Path) -> Option<u64> {
    let stats = rustix::fs::statvfs(path).ok()?;
    stats.f_bavail.checked_mul(stats.f_frsize)
}

#[cfg(any(test, target_os = "windows"))]
fn available_space_with(path: &Path, query: impl FnOnce(&str) -> Option<u64>) -> Option<u64> {
    let path = path.to_str()?;
    if path.is_empty() || path.contains('\0') {
        return None;
    }
    if is_unc_share_root(path) && !path.ends_with(['\\', '/']) {
        // Windows' disk-space API requires a trailing separator on UNC share roots.
        return query(&format!("{path}\\"));
    }
    query(path)
}

#[cfg(any(test, target_os = "windows"))]
fn is_unc_share_root(path: &str) -> bool {
    let Some(mut path) = path.strip_prefix("\\\\") else {
        return false;
    };
    if let Some(rest) = path.strip_prefix("?\\") {
        let Some(prefix) = rest.get(..4) else {
            return false;
        };
        if !prefix.eq_ignore_ascii_case("UNC\\") {
            return false;
        }
        path = &rest[4..];
    }
    let mut components = path.split(['\\', '/']).filter(|part| !part.is_empty());
    components.next().is_some() && components.next().is_some() && components.next().is_none()
}

#[cfg(target_os = "windows")]
pub(crate) fn available_space(path: &Path) -> Option<u64> {
    available_space_with(path, |path| {
        let mut available = 0;
        winsafe::GetDiskFreeSpaceEx(Some(path), Some(&mut available), None, None).ok()?;
        Some(available)
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn available_space(_: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_trim_notification_parser_reports_os_policy_without_claiming_device_support() {
        assert_eq!(
            parse_windows_trim_notification_status(
                "NTFS DisableDeleteNotify = 0 (Disabled)\nReFS DisableDeleteNotify = 1 (Enabled)\n"
            ),
            "Windows filesystem TRIM notification policy: NTFS enabled; ReFS disabled; storage-device support is not verified."
        );
        assert_eq!(
            parse_windows_trim_notification_status(
                "NTFS DisableDeleteNotify = 1\nReFS DisableDeleteNotify is not currently set\n"
            ),
            "Windows filesystem TRIM notification policy: NTFS disabled; ReFS not explicitly set; storage-device support is not verified."
        );
        assert!(
            parse_windows_trim_notification_status(
                "NTFS DisableDeleteNotify = 0\nNTFS DisableDeleteNotify = 1\n"
            )
            .contains("NTFS ambiguous")
        );
        assert!(
            parse_windows_trim_notification_status("DisableDeleteNotify = 0\n")
                .contains("NTFS not reported")
        );
        assert!(
            parse_windows_trim_notification_status("not localized output\n")
                .contains("NTFS not reported")
        );
    }

    #[test]
    fn windows_trim_notification_dry_run_does_not_query_the_system() {
        let status = windows_trim_notification_status_with(true, || {
            panic!("dry-run must not resolve or execute fsutil")
        });
        assert!(status.contains("skipped by dry-run"));
    }

    #[test]
    fn verified_windows_system_executable_requires_a_regular_file_inside_the_system_directory() {
        let root = tempfile::tempdir().unwrap();
        let system = root.path().join("System32");
        std::fs::create_dir(&system).unwrap();
        let fsutil = system.join("fsutil.exe");
        std::fs::write(&fsutil, b"fixture executable").unwrap();
        assert_eq!(
            verified_windows_system_executable(&system, "fsutil.exe"),
            Some(fsutil.canonicalize().unwrap())
        );
        assert!(verified_windows_system_executable(&system, "../fsutil.exe").is_none());
        assert!(verified_windows_system_executable(&system, "missing.exe").is_none());

        #[cfg(unix)]
        {
            std::fs::remove_file(&fsutil).unwrap();
            std::os::unix::fs::symlink(root.path().join("outside.exe"), &fsutil).unwrap();
            std::fs::write(root.path().join("outside.exe"), b"outside fixture").unwrap();
            assert!(verified_windows_system_executable(&system, "fsutil.exe").is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn fsutil_query_uses_only_the_fake_executable_and_bounds_output() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("fsutil-fixture");
        let mut release_file = executable.as_os_str().to_os_string();
        release_file.push(".release");
        let release_file = std::path::PathBuf::from(release_file);
        struct ReleaseReaderOnDrop(std::path::PathBuf);
        impl Drop for ReleaseReaderOnDrop {
            fn drop(&mut self) {
                let _ = std::fs::write(&self.0, b"release");
            }
        }
        let _release_on_drop = ReleaseReaderOnDrop(release_file.clone());
        std::fs::write(
            &executable,
            "#!/bin/sh\n[ \"$1/$2/$3\" = behavior/query/DisableDeleteNotify ] || exit 9\nprintf 'NTFS DisableDeleteNotify = 0\\n'\n",
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            query_fsutil_with(&executable).as_deref(),
            Some("NTFS DisableDeleteNotify = 0\n")
        );

        std::fs::write(
            &executable,
            "#!/bin/sh\n(while [ ! -e \"$0.release\" ]; do /bin/sleep 0.05; done) &\nexit 0\n",
        )
        .unwrap();
        let descendant_holds_pipe = query_fsutil_with(&executable).is_none();
        std::fs::write(
            &executable,
            "#!/bin/sh\nprintf 'NTFS DisableDeleteNotify = 0\\n'\n",
        )
        .unwrap();
        let blocked_during_reader = query_fsutil_with(&executable).is_none();
        std::fs::write(&release_file, b"release").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut resumes_after_reader = false;
        while Instant::now() < deadline {
            if query_fsutil_with(&executable).is_some() {
                resumes_after_reader = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(descendant_holds_pipe);
        assert!(blocked_during_reader);
        assert!(resumes_after_reader);

        std::fs::write(&executable, "#!/bin/sh\nprintf '%65537s' ''\n").unwrap();
        assert!(query_fsutil_with(&executable).is_none());
    }

    #[test]
    fn available_space_query_preserves_path_and_rejects_unusable_paths() {
        let path = Path::new("C:\\mounted\\workspace");
        assert_eq!(
            available_space_with(path, |value| {
                assert_eq!(value, "C:\\mounted\\workspace");
                Some(123)
            }),
            Some(123)
        );
        assert_eq!(available_space_with(path, |_| None), None);
        assert_eq!(
            available_space_with(Path::new("C:\\invalid\0path"), |_| panic!(
                "queried NUL path"
            )),
            None
        );
        assert_eq!(
            available_space_with(Path::new(""), |_| panic!("queried empty path")),
            None
        );
        assert_eq!(
            available_space_with(Path::new("\\\\server\\share"), |value| {
                assert_eq!(value, "\\\\server\\share\\");
                Some(456)
            }),
            Some(456)
        );
        assert_eq!(
            available_space_with(Path::new("\\\\server\\share\\workspace"), |value| {
                assert_eq!(value, "\\\\server\\share\\workspace");
                Some(789)
            }),
            Some(789)
        );
        assert_eq!(
            available_space_with(Path::new("\\\\?\\UNC\\server\\share"), |value| {
                assert_eq!(value, "\\\\?\\UNC\\server\\share\\");
                Some(789)
            }),
            Some(789)
        );

        #[cfg(unix)]
        let path = {
            use std::os::unix::ffi::OsStringExt;
            std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![0xff]))
        };
        #[cfg(windows)]
        let path = {
            use std::os::windows::ffi::OsStringExt;
            std::path::PathBuf::from(std::ffi::OsString::from_wide(&[0xd800]))
        };
        #[cfg(any(unix, windows))]
        assert_eq!(
            available_space_with(&path, |_| panic!("queried non-Unicode path")),
            None
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn available_space_reports_filesystem_value_and_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        let stats = rustix::fs::statvfs(dir.path()).unwrap();
        let available =
            available_space(dir.path()).expect("filesystem capacity should be measurable");
        if let Some(capacity) = stats.f_blocks.checked_mul(stats.f_frsize) {
            assert!(available <= capacity);
        }
        assert_eq!(available_space(&dir.path().join("missing")), None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_available_space_queries_only_existing_fixture_paths() {
        let dir = tempfile::tempdir().unwrap();
        assert!(available_space(dir.path()).is_some());
        let missing = dir.path().join("missing");
        assert_eq!(available_space(&missing), None);
        assert!(!missing.exists());
    }
    #[test]
    fn timer_parser_distinguishes_active_missing_and_invalid() {
        let timer = parse_timer(
            "LoadState=loaded\nActiveState=active\nLastTriggerUSec=Mon 2026-01-01\nNextElapseUSecRealtime=Tue 2026-01-02\n",
        );
        assert_eq!(timer.state, "active");
        assert_eq!(timer.last_trigger.as_deref(), Some("Mon 2026-01-01"));
        assert_eq!(timer.next_trigger.as_deref(), Some("Tue 2026-01-02"));
        assert_eq!(parse_timer("LoadState=not-found\n").state, "not_found");
        assert_eq!(parse_timer("garbage").state, "unavailable");
        assert_eq!(
            parse_timer("LoadState=loaded\nActiveState=active\u{1b}[2J\n").state,
            "active\\u{1b}[2J"
        );
    }

    #[cfg(unix)]
    #[test]
    fn trim_preview_and_execution_revalidate_a_selected_mount() {
        use sha2::{Digest, Sha256};
        use std::cell::Cell;
        let dir = tempfile::tempdir().unwrap();
        let mount = dir.path().canonicalize().unwrap();
        let escaped = mount
            .to_str()
            .unwrap()
            .replace('\\', "\\134")
            .replace(' ', "\\040")
            .replace('\t', "\\011")
            .replace('\n', "\\012");
        let line = format!("42 1 8:1 / {escaped} rw - ext4 /dev/test rw");
        let plan = trim_plan_from(&mount, line.as_bytes(), "boot-a").unwrap();
        let mut expected = Sha256::new();
        expected.update(b"upkit-trim-preview-v1\0boot-a\0");
        expected.update(line.as_bytes());
        assert_eq!(plan.preview_token, hex::encode(expected.finalize()));
        assert_eq!(
            serde_json::to_value(&plan).unwrap()["mount"],
            mount.to_str().unwrap()
        );
        let called = Cell::new(false);
        run_trim_with(
            &plan,
            &plan.preview_token,
            |path| trim_plan_from(path, line.as_bytes(), "boot-a"),
            |path| {
                assert_eq!(path, mount);
                called.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(called.replace(false));
        assert!(
            run_trim_with(
                &plan,
                &plan.preview_token,
                |path| trim_plan_from(path, line.as_bytes(), "boot-b"),
                |_| {
                    called.set(true);
                    Ok(())
                },
            )
            .is_err()
        );
        assert!(!called.get());
        assert!(
            run_trim_with(
                &plan,
                "wrong",
                |_| panic!("must not revalidate"),
                |_| panic!("must not execute")
            )
            .is_err()
        );
        let duplicate = format!("{line}\n{line}");
        assert!(trim_plan_from(&mount, duplicate.as_bytes(), "boot-a").is_err());
        let bind_mount = line.replace("8:1 / ", "8:1 /subdir ");
        assert!(trim_plan_from(&mount, bind_mount.as_bytes(), "boot-a").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mount_inventory_and_trim_preview_preserve_non_unicode_paths() {
        use std::{
            ffi::OsString,
            os::unix::ffi::{OsStrExt, OsStringExt},
        };

        let dir = tempfile::tempdir().unwrap();
        let mount = dir.path().join(OsString::from_vec(b"mount-\xff".to_vec()));
        std::fs::create_dir(&mount).unwrap();
        let sys = dir.path().join("sys");
        std::fs::create_dir_all(sys.join("8:1/queue")).unwrap();
        std::fs::write(sys.join("8:1/queue/discard_max_bytes"), "4096\n").unwrap();

        let mut mountinfo = b"42 1 8:1 / ".to_vec();
        for byte in mount.as_os_str().as_bytes() {
            match byte {
                b' ' => mountinfo.extend_from_slice(b"\\040"),
                b'\t' => mountinfo.extend_from_slice(b"\\011"),
                b'\n' => mountinfo.extend_from_slice(b"\\012"),
                b'\\' => mountinfo.extend_from_slice(b"\\134"),
                _ => mountinfo.push(*byte),
            }
        }
        mountinfo.extend_from_slice(b" rw - ext4 /dev/test rw\n");

        let (mounts, warning) = mounts_from(&mountinfo, &sys, None);
        assert!(warning.is_none());
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mount_path, mount);
        let displayed = crate::sweep::display_path(&mount);
        assert_eq!(mounts[0].mount_point, displayed);
        let status_json = serde_json::to_value(&mounts[0]).unwrap();
        assert_eq!(status_json["mount_point"], displayed);
        assert_eq!(status_json["mount_path"]["encoding"], "unix-percent-bytes");
        assert_eq!(status_json["mount_path"]["value"], displayed);

        let literal_percent = dir.path().join("mount-%FF");
        std::fs::create_dir(&literal_percent).unwrap();
        assert_ne!(
            display_mount_path(&literal_percent),
            display_mount_path(&mount)
        );
        assert!(display_mount_path(&literal_percent).ends_with("mount-%25FF"));
        assert!(display_mount_path(&mount).ends_with("mount-%FF"));

        let plan = trim_plan_from(&mount, &mountinfo, "boot-a").unwrap();
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!(plan.mount, mount);
        assert_eq!(json["mount"]["encoding"], "unix-percent-bytes");
        assert_eq!(json["mount"]["value"], displayed);
        let mut called = false;
        run_trim_with(
            &plan,
            &plan.preview_token,
            |path| trim_plan_from(path, &mountinfo, "boot-a"),
            |path| {
                assert_eq!(path, mount);
                called = true;
                Ok(())
            },
        )
        .unwrap();
        assert!(called);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mount_display_distinguishes_every_control_from_its_literal_escape() {
        for value in 0..=0x9f {
            let Some(character) = char::from_u32(value) else {
                continue;
            };
            if !character.is_control() {
                continue;
            }
            let path = std::path::PathBuf::from(format!("/fixture/{character}"));
            let literal =
                std::path::PathBuf::from(format!("/fixture/{}", character.escape_default()));
            assert_ne!(
                display_mount_path(&path),
                display_mount_path(&literal),
                "control U+{value:04X} collided with its literal escape"
            );
        }

        let newline = Path::new("/fixture/line\nnext");
        let literal_backslash = Path::new("/fixture/line\\nnext");
        assert_eq!(display_mount_path(newline), "/fixture/line\\nnext");
        assert_eq!(
            display_mount_path(literal_backslash),
            "/fixture/line\\\\nnext"
        );

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let invalid = std::path::PathBuf::from(std::ffi::OsString::from_vec(
                b"/fixture/line\\n\xff".to_vec(),
            ));
            let literal = Path::new("/fixture/line\n%FF");
            assert_ne!(display_mount_path(&invalid), display_mount_path(literal));
        }
    }

    #[cfg(unix)]
    #[test]
    fn trim_invocation_passes_one_literal_mount_to_mock() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mount = dir.path().join("mount space");
        std::fs::create_dir(&mount).unwrap();
        let mock = dir.path().join("fstrim");
        std::fs::write(
            &mock,
            "#!/bin/sh\n[ \"$#\" = 2 ] || exit 1\nprintf '%s' \"$1\" > \"$2/args\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&mock, std::fs::Permissions::from_mode(0o755)).unwrap();
        invoke_fstrim(&mock, &mount).unwrap();
        assert_eq!(std::fs::read_to_string(mount.join("args")).unwrap(), "--");
    }

    #[cfg(unix)]
    #[test]
    fn mount_parser_reports_device_limits_without_claiming_filesystem_support() {
        let dir = tempfile::tempdir().unwrap();
        let sys = dir.path();
        std::fs::create_dir_all(sys.join("8:0/queue")).unwrap();
        std::fs::write(sys.join("8:0/queue/discard_max_bytes"), "4096\n").unwrap();
        std::fs::create_dir_all(sys.join("8:1/queue")).unwrap();
        std::fs::write(sys.join("8:1/queue/discard_max_bytes"), "0\n").unwrap();
        std::fs::create_dir_all(sys.join("8:2")).unwrap();
        std::fs::create_dir_all(sys.join("8:3")).unwrap();
        let input = "10 1 8:0 / /work\\040space rw - ext4 /dev/a rw\n11 1 8:1 / /no rw - xfs /dev/b rw\n12 1 8:2 / /unknown rw - ext4 /dev/c rw\n14 1 8:3 / /literal%FF rw - ext4 /dev/d rw\n13 1 0:1 / /proc rw - proc proc rw\nbroken\n";
        let (mounts, warning) = mounts_from(input.as_bytes(), sys, None);
        assert_eq!(mounts.len(), 4);
        assert!(warning.is_some());
        let supported = mounts.iter().find(|mount| mount.device == "8:0").unwrap();
        assert_eq!(supported.mount_point, "/work space");
        assert_eq!(supported.device_discard, "advertised");
        assert_eq!(supported.discard_max_bytes, Some(4096));
        assert!(supported.filesystem_trim.starts_with("unknown"));
        assert!(
            serde_json::to_value(supported)
                .unwrap()
                .get("mount_path")
                .is_none()
        );
        let literal_percent = mounts.iter().find(|mount| mount.device == "8:3").unwrap();
        assert_eq!(literal_percent.mount_point, "/literal%FF");
        assert_eq!(
            display_mount_path(&literal_percent.mount_path),
            "/literal%25FF"
        );
        assert_eq!(
            serde_json::to_value(literal_percent).unwrap()["mount_point"],
            "/literal%FF"
        );
        assert_eq!(
            mounts
                .iter()
                .find(|mount| mount.device == "8:1")
                .unwrap()
                .device_discard,
            "disabled_or_unsupported"
        );
        assert_eq!(
            mounts
                .iter()
                .find(|mount| mount.device == "8:2")
                .unwrap()
                .device_discard,
            "unknown"
        );
    }

    #[cfg(unix)]
    #[test]
    fn partition_uses_parent_queue_only_when_identified_as_partition() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("disk/8:1")).unwrap();
        std::fs::create_dir_all(dir.path().join("disk/queue")).unwrap();
        std::fs::write(dir.path().join("disk/queue/discard_max_bytes"), "8192").unwrap();
        let input = "1 0 8:1 / /data rw - ext4 /dev/a rw\n";
        let (mounts, _) = mounts_from(input.as_bytes(), &dir.path().join("disk"), None);
        assert_eq!(mounts[0].device_discard, "unknown");
        std::fs::write(dir.path().join("disk/8:1/partition"), "1").unwrap();
        let (mounts, _) = mounts_from(input.as_bytes(), &dir.path().join("disk"), None);
        assert_eq!(mounts[0].discard_max_bytes, Some(8192));
    }

    #[test]
    fn fstab_trim_marker_is_reported_only_for_matching_entries() {
        let dir = tempfile::tempdir().unwrap();
        let sys = dir.path();
        std::fs::create_dir_all(sys.join("8:0")).unwrap();
        std::fs::create_dir_all(sys.join("8:1")).unwrap();
        std::fs::create_dir_all(sys.join("8:2")).unwrap();
        let mountinfo = concat!(
            "10 1 8:0 / /work\\040space rw - ext4 /dev/a rw\n",
            "11 1 8:1 / /data rw - ext4 /dev/b rw\n",
            "12 1 8:2 / /other rw - xfs /dev/c rw\n",
        );
        let fstab = concat!(
            "# mount point with no trim exception\n",
            "UUID=one /work\\040space ext4 defaults 0 2\n",
            "UUID=two /data ext4 defaults,X-fstrim.notrim 0 2 # opt out\n",
            "UUID=three /other ext4 defaults,X-fstrim.notrim 0 2\n",
        );
        let (mounts, _) = mounts_from(mountinfo.as_bytes(), sys, Some(fstab));
        assert_eq!(
            mounts
                .iter()
                .find(|mount| mount.mount_point == "/work space")
                .unwrap()
                .filesystem_trim,
            "unknown: filesystem FITRIM support and permissions not tested"
        );
        assert_eq!(
            mounts
                .iter()
                .find(|mount| mount.mount_point == "/data")
                .unwrap()
                .filesystem_trim,
            "unknown: filesystem FITRIM support and permissions not tested"
        );
        assert!(
            mounts
                .iter()
                .find(|mount| mount.mount_point == "/data")
                .unwrap()
                .fstab_trim_exclusion
                == "observed"
        );
        assert_eq!(
            mounts
                .iter()
                .find(|mount| mount.mount_point == "/other")
                .unwrap()
                .filesystem_trim,
            "unknown: filesystem FITRIM support and permissions not tested"
        );
        assert_eq!(
            fstab_trim_excluded(fstab, Path::new("/work space"), "ext4"),
            Some(false)
        );
        assert_eq!(
            fstab_trim_excluded(
                "UUID=one /work\\040space ext4\n",
                Path::new("/work space"),
                "ext4"
            ),
            Some(false)
        );
        let work_mount = mounts
            .iter()
            .find(|mount| mount.mount_point == "/work space")
            .unwrap();
        assert_eq!(work_mount.fstab_trim_exclusion, "not_observed");
        assert_eq!(
            serde_json::to_value(work_mount).unwrap()["fstab_trim_exclusion"],
            "not_observed"
        );
        assert_eq!(
            fstab_trim_excluded(fstab, Path::new("/missing"), "ext4"),
            None
        );
        assert_eq!(fstab_trim_excluded(fstab, Path::new("/other"), "xfs"), None);
        assert_eq!(
            fstab_trim_excluded(
                "UUID=one /work\\040space ext4 defaults 0 2\nUUID=two /work\\040space ext4 defaults,X-fstrim.notrim 0 2\n",
                Path::new("/work space"),
                "ext4"
            ),
            None
        );
        assert_eq!(
            fstab_trim_excluded(
                "UUID=one /work\\040space ext4 defaults 0 2\nUUID=bad /other ext4 defaults invalid 2\n",
                Path::new("/work space"),
                "ext4"
            ),
            None
        );
        assert_eq!(
            fstab_trim_excluded(
                "UUID=one /work\\040space ext4 0 2\n",
                Path::new("/work space"),
                "ext4"
            ),
            None
        );
        for fstab in [
            "UUID=one /work\\040space ext4 defaults 0 2\nUUID=two /work\\040space ext4 defaults,X-fstrim.notrim 0 2\n",
            "UUID=one /work\\040space ext4 defaults 0 2\nUUID=bad /other ext4 defaults invalid 2\n",
        ] {
            let (ambiguous, _) = mounts_from(mountinfo.as_bytes(), sys, Some(fstab));
            assert_eq!(
                ambiguous
                    .iter()
                    .find(|mount| mount.mount_point == "/work space")
                    .unwrap()
                    .fstab_trim_exclusion,
                "unknown"
            );
        }
        assert!(
            mounts_from(mountinfo.as_bytes(), sys, None)
                .0
                .iter()
                .all(|mount| mount.fstab_trim_exclusion == "unknown")
        );
    }

    #[test]
    fn online_discard_mount_option_is_separate_from_fittrim_support() {
        let dir = tempfile::tempdir().unwrap();
        for device in ["8:0", "8:1", "8:2", "8:3"] {
            std::fs::create_dir_all(dir.path().join(device)).unwrap();
        }
        let input = concat!(
            "1 0 8:0 / /sync rw,discard - ext4 /dev/a rw\n",
            "2 0 8:1 / /async rw - btrfs /dev/b rw,discard=async\n",
            "3 0 8:2 / /disabled rw - ext4 /dev/c rw,nodiscard\n",
            "4 0 8:3 / /unknown rw - ext4 /dev/d rw\n",
        );
        let (mounts, _) = mounts_from(input.as_bytes(), dir.path(), None);
        for (path, expected) in [
            ("/sync", "enabled"),
            ("/async", "enabled"),
            ("/disabled", "disabled"),
            ("/unknown", "unknown"),
        ] {
            let mount = mounts
                .iter()
                .find(|mount| mount.mount_point == path)
                .unwrap();
            assert_eq!(mount.online_discard_option, expected);
            assert!(mount.filesystem_trim.starts_with("unknown"));
        }
    }
}

/// A preview binds an explicit mount to the current boot and mount-table entry.
#[derive(Debug, Serialize)]
pub struct TrimPlan {
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub mount: std::path::PathBuf,
    pub filesystem: String,
    pub device: String,
    pub preview_token: String,
    pub warning: &'static str,
}

fn trim_plan_from(mount: &Path, mountinfo: &[u8], boot_id: &str) -> anyhow::Result<TrimPlan> {
    use anyhow::{Context, bail};
    use sha2::{Digest, Sha256};
    if !mount.is_absolute() || mount.canonicalize().context("resolve mount")? != mount {
        bail!("mount must be an absolute canonical path without links");
    }
    let metadata = std::fs::symlink_metadata(mount).context("inspect mount")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("mount must be a non-symlink directory");
    }
    if boot_id.trim().is_empty() {
        bail!("boot identity unavailable");
    }
    let mut selected = None;
    for line in mountinfo_lines(mountinfo) {
        let fields = mountinfo_fields(line);
        let separator = fields
            .iter()
            .position(|field| *field == b"-")
            .context("invalid mount table")?;
        if separator < 6 || fields.len() <= separator + 2 {
            bail!("invalid mount table");
        }
        let point = decode_mountinfo_path(fields[4])?;
        if point != mount {
            continue;
        }
        if selected.is_some() {
            bail!("stacked mounts at the selected path are ambiguous");
        }
        if fields[3] != b"/" {
            bail!("refusing a subdirectory or bind mount; select the filesystem root mount");
        }
        let device = std::str::from_utf8(fields[2]).context("invalid mount device")?;
        let Some((major, minor)) = device.split_once(':') else {
            bail!("invalid mount device");
        };
        if std::str::from_utf8(fields[0])
            .context("invalid mount ID")?
            .parse::<u64>()
            .is_err()
            || major.parse::<u32>().is_err()
            || minor.parse::<u32>().is_err()
        {
            bail!("invalid mount identity");
        }
        let mut hash = Sha256::new();
        hash.update(b"upkit-trim-preview-v1\0");
        hash.update(boot_id.trim().as_bytes());
        hash.update(b"\0");
        hash.update(line);
        selected = Some(TrimPlan {
            mount: mount.to_owned(),
            filesystem: clean(
                std::str::from_utf8(fields[separator + 1])
                    .context("mount filesystem name is not UTF-8")?,
            ),
            device: device.into(),
            preview_token: hex::encode(hash.finalize()),
            warning: "TRIM affects unused blocks across this filesystem; capability and permissions are not verified, and free space will not increase.",
        });
    }
    selected.context("selected path is not an unambiguous filesystem root mount")
}

pub fn trim_plan(mount: &Path) -> anyhow::Result<TrimPlan> {
    use anyhow::{Context, bail};
    if !cfg!(target_os = "linux") {
        bail!("manual TRIM is supported only on Linux");
    }
    let mounts = std::fs::read("/proc/self/mountinfo").context("read mount table")?;
    let boot =
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id").context("read boot identity")?;
    trim_plan_from(mount, &mounts, &boot)
}

pub fn run_trim(plan: &TrimPlan, token: &str) -> anyhow::Result<()> {
    use anyhow::Context;
    run_trim_with(plan, token, trim_plan, |mount| {
        let program = which::which("fstrim").context("fstrim not found")?;
        invoke_fstrim(&program, mount)
    })
}

fn invoke_fstrim(program: &Path, mount: &Path) -> anyhow::Result<()> {
    use anyhow::{Context, bail};
    let status = Command::new(program)
        .arg("--")
        .arg(mount)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("start fstrim")?;
    if !status.success() {
        bail!("fstrim failed ({status}); check filesystem support and permissions");
    }
    Ok(())
}

fn run_trim_with(
    plan: &TrimPlan,
    token: &str,
    current_plan: impl FnOnce(&Path) -> anyhow::Result<TrimPlan>,
    execute: impl FnOnce(&Path) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    use anyhow::bail;
    if plan.preview_token != token {
        bail!("preview token does not match the selected mount");
    }
    let current = current_plan(&plan.mount)?;
    if current.preview_token != token {
        bail!("mount changed since preview; preview again");
    }
    execute(&current.mount)
}
