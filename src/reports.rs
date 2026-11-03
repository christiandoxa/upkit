//! Bounded local records for explicitly confirmed maintenance operations.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::atomic::Ordering;
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    sync::atomic::AtomicBool,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const MAX_RECORDS: usize = 100;
const MAX_BYTES: u64 = 16384;
const MAX_HISTORY_DIRECTORY_ENTRIES: usize = MAX_RECORDS * 3 + 32;
#[cfg(windows)]
const WINDOWS_REPARSE_POINT: u32 = 0x400;

fn staged_history_id(name: &str) -> Option<usize> {
    let mut parts = name.strip_prefix(".history-purge-")?.split('-');
    let (pid, counter, id) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || pid.is_empty()
        || counter.is_empty()
        || !pid.bytes().all(|byte| byte.is_ascii_digit())
        || !counter.bytes().all(|byte| byte.is_ascii_digit())
        || !id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    id.parse::<usize>().ok().filter(|id| *id < MAX_RECORDS)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub id: usize,
    pub started_unix: u64,
    #[serde(default)]
    pub finished_unix: Option<u64>,
    pub duration_ms: u64,
    pub operation: String,
    pub target: String,
    pub outcome: String,
    pub detail: Option<String>,
    pub estimated_bytes: Option<u64>,
    pub verified_reclaimed_bytes: Option<u64>,
    pub platform: String,
}

#[derive(Debug, Serialize)]
pub struct History {
    pub records: Vec<Record>,
    pub warnings: Vec<String>,
    pub capacity: usize,
    pub known_reclaimed_bytes: Option<u64>,
    pub records_without_verified_reclaimed_bytes: usize,
}

#[derive(Debug, Serialize)]
pub struct HistoryPurgePlan {
    pub older_than_seconds: u64,
    pub cutoff_unix: u64,
    pub record_count: usize,
    pub skipped_unfinished_records: usize,
    pub candidates: Vec<HistoryPurgeCandidate>,
    pub preview_token: String,
    pub warning: &'static str,
}

#[derive(Debug, Serialize)]
pub struct HistoryPurgeCandidate {
    pub id: usize,
    pub started_unix: u64,
    pub finished_unix: Option<u64>,
    pub operation: String,
    pub target: String,
    pub outcome: String,
}

#[derive(Debug, Serialize)]
pub struct HistoryPurgeItem {
    pub id: usize,
    pub status: &'static str,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HistoryPurgeResult {
    pub outcome: &'static str,
    pub cancelled: bool,
    pub items: Vec<HistoryPurgeItem>,
}

pub struct Performed<T> {
    pub result: std::result::Result<T, String>,
    pub history_warning: Option<String>,
}

#[cfg(target_os = "linux")]
pub(crate) struct HistoryReservation {
    home: std::path::PathBuf,
    id: usize,
    directory: history_purge::Fingerprint,
    identity: history_purge::Fingerprint,
    pending_bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl HistoryReservation {
    pub(crate) fn finish(self, record: Record) -> Result<()> {
        history_purge::finish_record(self, record)
    }
}

pub(crate) fn format_timestamp(unix_seconds: u64) -> String {
    let formatted = i64::try_from(unix_seconds)
        .ok()
        .and_then(|seconds| chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0))
        .map(|timestamp| timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string());
    formatted.unwrap_or_else(|| format!("Unix seconds {unix_seconds}"))
}

fn safe_text(value: &str) -> String {
    let mut result = String::new();
    for character in value.chars() {
        let escaped = if character.is_control() {
            character.escape_default().to_string()
        } else if matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        ) {
            format!("\\u{{{:x}}}", character as u32)
        } else {
            character.to_string()
        };
        if result.len() + escaped.len() > 1024 {
            result.push_str("...[truncated]");
            break;
        }
        result.push_str(&escaped);
    }
    result
}

fn history_dir(home: &Path, create: bool) -> Result<Option<std::path::PathBuf>> {
    let dir = home.join("history");
    if create {
        fs::create_dir_all(home).context("create Upkit data directory")?;
        #[cfg(unix)]
        let mut builder = fs::DirBuilder::new();
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err).context("create history directory"),
        }
    }
    match fs::symlink_metadata(&dir) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if meta.file_attributes() & WINDOWS_REPARSE_POINT != 0 {
                    bail!("history path is a reparse point");
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.mode() & 0o077 != 0 {
                    bail!("history directory must not be accessible to group or other users");
                }
            }
            Ok(Some(dir))
        }
        Ok(_) => bail!("history path is linked or not a directory"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && !create => Ok(None),
        Err(err) => Err(err).context("inspect history directory"),
    }
}

#[cfg(not(target_os = "linux"))]
fn staged_history_ids(dir: &Path) -> Result<[bool; MAX_RECORDS]> {
    let mut ids = [false; MAX_RECORDS];
    let mut entries = 0;
    for entry in fs::read_dir(dir).context("list history directory")? {
        let entry = entry.context("read history directory entry")?;
        entries += 1;
        if entries > MAX_HISTORY_DIRECTORY_ENTRIES {
            bail!("history directory contains too many entries");
        }
        if let Some(id) = entry.file_name().to_str().and_then(staged_history_id) {
            ids[id] = true;
        }
    }
    Ok(ids)
}

#[cfg(target_os = "windows")]
fn open_report_file(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const SHARE_READ: u32 = 0x0000_0001;
        options
            .custom_flags(OPEN_REPARSE_POINT)
            .share_mode(SHARE_READ);
    }
    options.open(path)
}

#[cfg(target_os = "macos")]
fn write_record(home: &Path, mut record: Record) -> Result<()> {
    sanitize_record(&mut record);
    history_purge::write_record(home, record)
}

#[cfg(not(target_os = "macos"))]
fn write_record(home: &Path, mut record: Record) -> Result<()> {
    sanitize_record(&mut record);
    let dir = history_dir(home, true)?.context("history directory unavailable")?;
    #[cfg(target_os = "linux")]
    let directory = {
        use std::os::unix::fs::MetadataExt;
        let expected = fs::symlink_metadata(&dir).context("inspect history directory")?;
        let fd = rustix::fs::open(
            &dir,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .context("open history directory")?;
        let file = fs::File::from(fd);
        let actual = file
            .metadata()
            .context("inspect opened history directory")?;
        if !expected.is_dir()
            || expected.file_type().is_symlink()
            || expected.dev() != actual.dev()
            || expected.ino() != actual.ino()
            || actual.mode() & 0o077 != 0
        {
            bail!("history directory changed or is not private");
        }
        history_purge::lock_directory(&file, None)?;
        let current = fs::symlink_metadata(&dir).context("recheck history directory path")?;
        if !current.is_dir()
            || current.file_type().is_symlink()
            || current.dev() != actual.dev()
            || current.ino() != actual.ino()
        {
            bail!("history directory changed while acquiring its lock");
        }
        file
    };
    #[cfg(target_os = "linux")]
    let staged_ids = history_purge::staged_history_ids(&directory)?;
    #[cfg(not(target_os = "linux"))]
    let staged_ids = staged_history_ids(&dir)?;
    for (id, staged) in staged_ids.iter().enumerate() {
        if *staged {
            continue;
        }
        #[cfg(target_os = "linux")]
        match rustix::fs::openat(
            &directory,
            format!("{id:03}.reserve").as_str(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(_) | Err(rustix::io::Errno::LOOP) => continue,
            Err(rustix::io::Errno::NOENT) => {}
            Err(err) => return Err(err).context("inspect history reservation"),
        }
        #[cfg(not(target_os = "linux"))]
        match fs::symlink_metadata(dir.join(format!("{id:03}.reserve"))) {
            Ok(_) => continue,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).context("inspect history reservation"),
        }
        let filename = format!("{id:03}.json");
        record.id = id;
        let bytes = serde_json::to_vec(&record).context("serialize history record")?;
        if bytes.len() as u64 > MAX_BYTES {
            bail!("history record exceeds size limit");
        }
        #[cfg(target_os = "linux")]
        let mut file = match rustix::fs::openat(
            &directory,
            filename.as_str(),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        ) {
            Ok(fd) => fs::File::from(fd),
            Err(rustix::io::Errno::EXIST) => continue,
            Err(err) => return Err(err).context("create history record"),
        };
        #[cfg(not(target_os = "linux"))]
        let mut file = {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(dir.join(&filename)) {
                Ok(file) => file,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err).context("create history record"),
            }
        };
        file.write_all(&bytes).context("write history record")?;
        file.sync_all().context("sync history record")?;
        return Ok(());
    }
    bail!("history is full (100 records); archive or remove records before recording more")
}

fn sanitize_record(record: &mut Record) {
    record.operation = safe_text(&record.operation);
    record.target = safe_text(&record.target);
    record.outcome = safe_text(&record.outcome);
    record.detail = record.detail.take().map(|detail| safe_text(&detail));
    record.platform = safe_text(&record.platform);
}

#[cfg(target_os = "linux")]
pub(crate) fn reserve_history_record(home: &Path, record: Record) -> Result<HistoryReservation> {
    history_purge::reserve_record(home, record)
}

pub fn read(home: &Path) -> Result<History> {
    let mut history = History {
        records: vec![],
        warnings: vec![],
        capacity: MAX_RECORDS,
        known_reclaimed_bytes: None,
        records_without_verified_reclaimed_bytes: 0,
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let Some(directory) = history_purge::open_report_directory(home)? else {
        return Ok(history);
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let staged_names = history_purge::report_staged_names(&directory)?;
    #[cfg(target_os = "windows")]
    let staged_names = [(); MAX_RECORDS];
    #[cfg(target_os = "windows")]
    let Some(dir) = history_dir(home, false)? else {
        return Ok(history);
    };
    for (id, _staged) in staged_names.iter().enumerate() {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let bytes = match history_purge::read_report_record(&directory, id, _staged) {
            Ok(Some(history_purge::ReportRecordRead::Record(
                bytes,
                history_purge::ReportRecordSource::Final,
            ))) => bytes,
            Ok(Some(history_purge::ReportRecordRead::Record(
                bytes,
                history_purge::ReportRecordSource::Pending,
            ))) => {
                history.warnings.push(format!(
                    "record {id:03} has an unfinished attempt; its reservation is shown"
                ));
                bytes
            }
            Ok(Some(history_purge::ReportRecordRead::Record(
                bytes,
                history_purge::ReportRecordSource::RecoveredFinalWrite,
            ))) => {
                history.warnings.push(format!(
                    "record {id:03} has an incomplete final write; its pending attempt is shown"
                ));
                bytes
            }
            Ok(Some(history_purge::ReportRecordRead::Record(
                bytes,
                history_purge::ReportRecordSource::FinalWithReservation,
            ))) => {
                history.warnings.push(format!(
                    "record {id:03} has a matching reservation after finalization; the final record is shown"
                ));
                bytes
            }
            Ok(Some(history_purge::ReportRecordRead::Record(
                bytes,
                history_purge::ReportRecordSource::Staged,
            ))) => {
                history.warnings.push(format!(
                    "record {id:03} was interrupted during history purge; its staged record is shown"
                ));
                bytes
            }
            Ok(Some(history_purge::ReportRecordRead::Warning(warning))) => {
                history.warnings.push(format!("record {id:03} {warning}"));
                continue;
            }
            Ok(None) => continue,
            Err(_) => {
                history.warnings.push(format!(
                    "record {id:03} is linked, invalid, unreadable, or not private"
                ));
                continue;
            }
        };
        #[cfg(target_os = "windows")]
        let bytes = {
            let record_path = dir.join(format!("{id:03}.json"));
            let path = if matches!(
                fs::symlink_metadata(&record_path),
                Err(ref err) if err.kind() == std::io::ErrorKind::NotFound
            ) {
                dir.join(format!("{id:03}.reserve"))
            } else {
                record_path
            };
            let meta = match fs::symlink_metadata(&path) {
                Ok(meta)
                    if meta.is_file()
                        && !meta.file_type().is_symlink()
                        && meta.len() <= MAX_BYTES =>
                {
                    meta
                }
                Ok(_) => {
                    history
                        .warnings
                        .push(format!("record {id:03} is linked, invalid, or too large"));
                    continue;
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {
                    history
                        .warnings
                        .push(format!("record {id:03} is unreadable"));
                    continue;
                }
            };
            let file = match open_report_file(&path) {
                Ok(file) => file,
                Err(_) => {
                    history
                        .warnings
                        .push(format!("record {id:03} is unreadable"));
                    continue;
                }
            };
            let opened = match file.metadata() {
                Ok(opened) if opened.is_file() && opened.len() <= MAX_BYTES => opened,
                _ => {
                    history
                        .warnings
                        .push(format!("record {id:03} changed or is invalid"));
                    continue;
                }
            };
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if opened.dev() != meta.dev() || opened.ino() != meta.ino() {
                    history
                        .warnings
                        .push(format!("record {id:03} changed while reading"));
                    continue;
                }
            }
            #[cfg(target_os = "macos")]
            {
                use std::os::unix::fs::MetadataExt;
                if opened.uid() != rustix::process::geteuid().as_raw()
                    || opened.mode() & 0o077 != 0
                    || opened.nlink() != 1
                {
                    history.warnings.push(format!(
                        "record {id:03} is not private or has multiple links"
                    ));
                    continue;
                }
            }
            #[cfg(windows)]
            let before = {
                use std::os::windows::fs::MetadataExt;
                let info = winapi_util::file::information(&file);
                match info {
                    Ok(info)
                        if meta.file_attributes() & WINDOWS_REPARSE_POINT == 0
                            && opened.file_attributes() & WINDOWS_REPARSE_POINT == 0
                            && info.number_of_links() == 1 =>
                    {
                        info
                    }
                    _ => {
                        history
                            .warnings
                            .push(format!("record {id:03} is linked or cannot be inspected"));
                        continue;
                    }
                }
            };
            #[cfg(not(any(unix, windows)))]
            let _ = (opened, meta);
            let mut bytes = Vec::new();
            if (&file).take(MAX_BYTES + 1).read_to_end(&mut bytes).is_err()
                || bytes.len() as u64 > MAX_BYTES
            {
                history
                    .warnings
                    .push(format!("record {id:03} is unreadable or too large"));
                continue;
            }
            #[cfg(target_os = "macos")]
            {
                use std::os::unix::fs::MetadataExt;
                let unchanged = file.metadata().is_ok_and(|after| {
                    after.is_file()
                        && after.dev() == opened.dev()
                        && after.ino() == opened.ino()
                        && after.uid() == opened.uid()
                        && after.mode() == opened.mode()
                        && after.nlink() == opened.nlink()
                        && after.len() == opened.len()
                        && after.mtime() == opened.mtime()
                        && after.mtime_nsec() == opened.mtime_nsec()
                        && after.ctime() == opened.ctime()
                        && after.ctime_nsec() == opened.ctime_nsec()
                });
                if !unchanged {
                    history
                        .warnings
                        .push(format!("record {id:03} changed while reading"));
                    continue;
                }
            }
            #[cfg(windows)]
            {
                let unchanged = winapi_util::file::information(&file).is_ok_and(|after| {
                    after.file_attributes() & u64::from(WINDOWS_REPARSE_POINT) == 0
                        && after.number_of_links() == 1
                        && after.volume_serial_number() == before.volume_serial_number()
                        && after.file_index() == before.file_index()
                        && after.creation_time() == before.creation_time()
                        && after.last_write_time() == before.last_write_time()
                        && after.file_size() == before.file_size()
                });
                if !unchanged {
                    history
                        .warnings
                        .push(format!("record {id:03} changed while reading"));
                    continue;
                }
            }
            bytes
        };
        match serde_json::from_slice::<Record>(&bytes) {
            Ok(mut record) if record.id == id => {
                if record
                    .finished_unix
                    .is_some_and(|finished| finished < record.started_unix)
                {
                    history.warnings.push(format!(
                        "record {id:03} has a finish timestamp earlier than its start timestamp; the system clock may have changed"
                    ));
                }
                record.operation = safe_text(&record.operation);
                record.target = safe_text(&record.target);
                record.outcome = safe_text(&record.outcome);
                record.detail = record.detail.map(|detail| safe_text(&detail));
                record.platform = safe_text(&record.platform);
                history.records.push(record);
            }
            _ => history.warnings.push(format!("record {id:03} is invalid")),
        }
    }
    history
        .records
        .sort_by(|a, b| b.started_unix.cmp(&a.started_unix).then(b.id.cmp(&a.id)));
    history.records_without_verified_reclaimed_bytes = history
        .records
        .iter()
        .filter(|record| record.verified_reclaimed_bytes.is_none())
        .count();
    let mut known = None::<u64>;
    for bytes in history
        .records
        .iter()
        .filter_map(|record| record.verified_reclaimed_bytes)
    {
        known = match known {
            None => Some(bytes),
            Some(total) => match total.checked_add(bytes) {
                Some(total) => Some(total),
                None => {
                    history.warnings.push(
                        "verified reclaimed-byte subtotal exceeds the supported range".into(),
                    );
                    return Ok(history);
                }
            },
        };
    }
    history.known_reclaimed_bytes = known;
    Ok(history)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod history_purge {
    const MAX_STALE_WRITE_PROBES: usize = 32;

    use super::*;
    use anyhow::anyhow;
    use rustix::fs::{
        AtFlags, Dir, Mode, OFlags, RenameFlags, open, openat, renameat_with, unlinkat,
    };
    #[cfg(target_os = "linux")]
    use rustix::fs::{ResolveFlags, openat2};
    use sha2::{Digest, Sha256};
    use std::{os::unix::fs::MetadataExt, sync::atomic::AtomicU64};

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    pub(super) struct Fingerprint {
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

    impl Fingerprint {
        fn from(meta: &fs::Metadata) -> Self {
            Self {
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

        fn same_object(&self, other: &Self) -> bool {
            self.device == other.device
                && self.inode == other.inode
                && self.mode == other.mode
                && self.uid == other.uid
        }

        fn same_after_rename(&self, other: &Self) -> bool {
            self.same_object(other)
                && self.links == other.links
                && self.size == other.size
                && self.mtime == other.mtime
                && self.mtime_ns == other.mtime_ns
        }

        fn is_private_record(&self, directory: &Self) -> bool {
            self.device == directory.device
                && self.uid == rustix::process::geteuid().as_raw()
                && self.mode & 0o170000 == 0o100000
                && self.links == 1
                && self.size <= MAX_BYTES
                && self.mode & 0o077 == 0
                && self.mode & 0o600 == 0o600
        }
    }

    pub(super) struct Directory {
        file: fs::File,
        identity: Fingerprint,
    }

    fn open_directory_path(path: &Path) -> Result<fs::File> {
        #[cfg(target_os = "linux")]
        let fd = openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?;
        #[cfg(target_os = "macos")]
        let fd = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(fs::File::from(fd))
    }

    fn open_record_fd(
        directory: &Directory,
        name: &str,
    ) -> rustix::io::Result<rustix::fd::OwnedFd> {
        #[cfg(target_os = "linux")]
        let fd = openat2(
            &directory.file,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )?;
        #[cfg(target_os = "macos")]
        let fd = openat(
            &directory.file,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        Ok(fd)
    }

    pub(super) fn report_staged_names(directory: &Directory) -> Result<[Vec<String>; MAX_RECORDS]> {
        staged_history_names(&directory.file)
    }

    struct Entry {
        record: Record,
        bytes: Vec<u8>,
        identity: Fingerprint,
        source: String,
        reservation: Option<(Vec<u8>, Fingerprint)>,
        blocked_by_final: bool,
    }

    struct Evidence {
        source: String,
        bytes: Vec<u8>,
        identity: Fingerprint,
    }

    struct Snapshot {
        directory: Option<Directory>,
        entries: Vec<Entry>,
        evidence: Vec<Evidence>,
    }

    pub(super) enum ReportRecordSource {
        Final,
        Pending,
        RecoveredFinalWrite,
        FinalWithReservation,
        Staged,
    }

    pub(super) enum ReportRecordRead {
        Record(Vec<u8>, ReportRecordSource),
        Warning(&'static str),
    }

    fn is_stale_write_probe(name: &[u8]) -> bool {
        let Some(rest) = name.strip_prefix(b".upkit-write-probe-") else {
            return false;
        };
        let Some(separator) = rest.iter().position(|byte| *byte == b'-') else {
            return false;
        };
        let (pid, counter) = rest.split_at(separator);
        let counter = &counter[1..];
        !pid.is_empty()
            && !counter.is_empty()
            && pid.iter().all(u8::is_ascii_digit)
            && counter.iter().all(u8::is_ascii_digit)
    }

    enum RemovalFailure {
        Cancelled(String),
        Failed(String),
    }

    impl From<anyhow::Error> for RemovalFailure {
        fn from(error: anyhow::Error) -> Self {
            Self::Failed(format!("{error:#}"))
        }
    }

    pub(super) fn lock_directory(file: &fs::File, cancel: Option<&AtomicBool>) -> Result<()> {
        let started = Instant::now();
        loop {
            match rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(()),
                Err(rustix::io::Errno::AGAIN) => {}
                Err(error) => return Err(error).context("lock history directory"),
            }
            if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                bail!("history operation cancelled while waiting for the directory lock");
            }
            if started.elapsed() >= std::time::Duration::from_secs(2) {
                bail!("history directory is busy; retry after other operations finish");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    pub(super) fn staged_history_names(file: &fs::File) -> Result<[Vec<String>; MAX_RECORDS]> {
        let mut names: [Vec<String>; MAX_RECORDS] = std::array::from_fn(|_| Vec::new());
        let mut count = 0;
        for entry in Dir::read_from(file).context("list history directory")? {
            let entry = entry.context("read history directory entry")?;
            let name = entry.file_name();
            let bytes = name.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            count += 1;
            if count > MAX_HISTORY_DIRECTORY_ENTRIES {
                bail!("history directory contains too many entries");
            }
            if let Some(id) = std::str::from_utf8(bytes)
                .ok()
                .and_then(super::staged_history_id)
            {
                names[id].push(String::from_utf8(bytes.to_vec()).expect("validated stage name"));
            }
        }
        Ok(names)
    }

    pub(super) fn staged_history_ids(file: &fs::File) -> Result<[bool; MAX_RECORDS]> {
        let names = staged_history_names(file)?;
        Ok(std::array::from_fn(|id| !names[id].is_empty()))
    }

    pub(super) fn open_directory(home: &Path) -> Result<Option<Directory>> {
        let Some(path) = history_dir(home, false)? else {
            return Ok(None);
        };
        let expected = fs::symlink_metadata(&path).context("inspect history directory")?;
        let file = open_directory_path(&path)?;
        let actual = file
            .metadata()
            .context("inspect opened history directory")?;
        let expected_id = Fingerprint::from(&expected);
        let actual_id = Fingerprint::from(&actual);
        let uid = rustix::process::geteuid().as_raw();
        if !expected.is_dir()
            || expected.file_type().is_symlink()
            || expected_id != actual_id
            || !actual.is_dir()
            || actual_id.uid != uid
            || actual_id.mode & 0o077 != 0
            || actual_id.mode & 0o700 != 0o700
        {
            bail!("history directory changed or is not private and user-owned");
        }
        Ok(Some(Directory {
            file,
            identity: actual_id,
        }))
    }

    pub(super) fn open_report_directory(home: &Path) -> Result<Option<Directory>> {
        let Some(path) = history_dir(home, false)? else {
            return Ok(None);
        };
        let expected = fs::symlink_metadata(&path).context("inspect history directory")?;
        let file = fs::File::from(
            open(
                &path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .context("open history directory")?,
        );
        let actual = file
            .metadata()
            .context("inspect opened history directory")?;
        let expected_id = Fingerprint::from(&expected);
        let actual_id = Fingerprint::from(&actual);
        let uid = rustix::process::geteuid().as_raw();
        if !expected.is_dir()
            || expected.file_type().is_symlink()
            || expected_id != actual_id
            || !actual.is_dir()
            || actual_id.uid != uid
            || actual_id.mode & 0o077 != 0
            || actual_id.mode & 0o500 != 0o500
        {
            bail!("history directory changed or is not private and user-owned");
        }
        Ok(Some(Directory {
            file,
            identity: actual_id,
        }))
    }

    fn open_write_directory(home: &Path) -> Result<Option<Directory>> {
        let Some(directory) = open_report_directory(home)? else {
            return Ok(None);
        };
        if directory.identity.mode & 0o300 != 0o300 {
            bail!("history directory is not writable by its owner");
        }
        Ok(Some(directory))
    }

    fn verify_report_directory_path(home: &Path, directory: &Directory) -> Result<()> {
        let Some(current_directory) = open_write_directory(home)? else {
            bail!("history directory disappeared");
        };
        if !current_directory.identity.same_object(&directory.identity) {
            bail!("history directory changed");
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub(super) fn write_record(home: &Path, mut record: Record) -> Result<()> {
        history_dir(home, true)?.context("history directory unavailable")?;
        let directory = open_write_directory(home)?.context("history directory unavailable")?;
        lock_directory(&directory.file, None)?;
        verify_report_directory_path(home, &directory)?;
        let staged_ids = staged_history_ids(&directory.file)?;

        for (id, staged) in staged_ids.iter().enumerate() {
            if *staged {
                continue;
            }
            let record_name = format!("{id:03}.json");
            match openat(
                &directory.file,
                record_name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(_) | Err(rustix::io::Errno::LOOP) => continue,
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(error).context("inspect history slot"),
            }
            let reservation_name = format!("{id:03}.reserve");
            match openat(
                &directory.file,
                reservation_name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(_) | Err(rustix::io::Errno::LOOP) => continue,
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(error).context("inspect history reservation"),
            }

            record.id = id;
            let bytes = serde_json::to_vec(&record).context("serialize history record")?;
            if bytes.len() as u64 > MAX_BYTES {
                bail!("history record exceeds size limit");
            }
            let mut file = match openat(
                &directory.file,
                record_name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => fs::File::from(fd),
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(error).context("create history record"),
            };
            file.write_all(&bytes).context("write history record")?;
            file.sync_all().context("sync history record")?;
            let identity = Fingerprint::from(&file.metadata().context("inspect history record")?);
            if !identity.is_private_record(&directory.identity) {
                bail!("history record is not private and user-owned");
            }
            let Some((_, observed_bytes, observed_identity)) =
                open_record(&directory, &record_name)?
            else {
                bail!("history record disappeared after writing");
            };
            if observed_bytes != bytes || observed_identity != identity {
                bail!("history record changed while being written");
            }
            verify_report_directory_path(home, &directory)?;
            return Ok(());
        }
        bail!("history is full (100 records); archive or remove records before recording more")
    }

    #[cfg(target_os = "linux")]
    pub(super) fn reserve_record(
        home: &Path,
        mut record: Record,
    ) -> Result<super::HistoryReservation> {
        history_dir(home, true)?.context("history directory unavailable")?;
        let directory = open_write_directory(home)?.context("history directory unavailable")?;
        lock_directory(&directory.file, None)?;
        verify_report_directory_path(home, &directory)?;
        let staged_ids = staged_history_ids(&directory.file)?;

        record.finished_unix = None;
        record.duration_ms = 0;
        record.outcome = "in_progress".into();
        record.detail = None;
        record.verified_reclaimed_bytes = None;
        sanitize_record(&mut record);

        for (id, staged) in staged_ids.iter().enumerate() {
            if *staged {
                continue;
            }
            let record_name = format!("{id:03}.json");
            match openat(
                &directory.file,
                record_name.as_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(_) | Err(rustix::io::Errno::LOOP) => continue,
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(error).context("inspect history slot"),
            }
            let reservation_name = format!("{id:03}.reserve");
            record.id = id;
            let bytes = serde_json::to_vec(&record).context("serialize pending history record")?;
            if bytes.len() as u64 > MAX_BYTES {
                bail!("history record exceeds size limit");
            }
            let mut file = match openat(
                &directory.file,
                reservation_name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => fs::File::from(fd),
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(error).context("reserve history slot"),
            };
            file.write_all(&bytes)
                .context("write pending history record")?;
            file.sync_all().context("sync pending history record")?;
            let file_identity =
                Fingerprint::from(&file.metadata().context("inspect pending history record")?);
            if !file_identity.is_private_record(&directory.identity) {
                bail!("pending history record is not private and user-owned");
            }
            directory
                .file
                .sync_all()
                .context("sync history directory after reservation")?;
            let Some((_, observed_bytes, observed_identity)) =
                open_record(&directory, &reservation_name)?
            else {
                bail!("pending history reservation disappeared");
            };
            if observed_bytes != bytes || observed_identity != file_identity {
                bail!("pending history reservation changed while being written");
            }
            return Ok(super::HistoryReservation {
                home: home.to_path_buf(),
                id,
                directory: directory.identity.clone(),
                identity: file_identity,
                pending_bytes: bytes,
            });
        }
        bail!("history is full (100 records); archive or remove records before cleanup")
    }

    #[cfg(target_os = "linux")]
    pub(super) fn finish_record(
        reservation: super::HistoryReservation,
        mut record: Record,
    ) -> Result<()> {
        let directory = open_write_directory(&reservation.home)?
            .context("history directory unavailable while finishing reservation")?;
        if !directory.identity.same_object(&reservation.directory) {
            bail!("history directory changed while cleanup was running");
        }
        lock_directory(&directory.file, None)?;
        verify_report_directory_path(&reservation.home, &directory)?;

        let pending: Record = serde_json::from_slice(&reservation.pending_bytes)
            .context("decode pending history record")?;
        record.id = reservation.id;
        sanitize_record(&mut record);
        if record.finished_unix.is_none()
            || record.started_unix != pending.started_unix
            || record.operation != pending.operation
            || record.target != pending.target
            || record.estimated_bytes != pending.estimated_bytes
            || record.platform != pending.platform
        {
            bail!("final history record does not match its reservation");
        }
        let bytes = serde_json::to_vec(&record).context("serialize final history record")?;
        if bytes.len() as u64 > MAX_BYTES {
            bail!("history record exceeds size limit");
        }

        let reservation_name = format!("{:03}.reserve", reservation.id);
        let Some((_, pending_bytes, pending_identity)) =
            open_record(&directory, &reservation_name)?
        else {
            bail!("pending history reservation disappeared");
        };
        if pending_identity != reservation.identity || pending_bytes != reservation.pending_bytes {
            bail!("pending history reservation changed; refusing to overwrite it");
        }

        let record_name = format!("{:03}.json", reservation.id);
        let mut file = match openat(
            &directory.file,
            record_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => fs::File::from(fd),
            Err(rustix::io::Errno::EXIST) => {
                bail!("reserved history slot was occupied before finalization")
            }
            Err(error) => return Err(error).context("create final history record"),
        };
        file.write_all(&bytes)
            .context("write final history record")?;
        file.sync_all().context("sync final history record")?;
        if !Fingerprint::from(&file.metadata().context("inspect final history record")?)
            .is_private_record(&directory.identity)
        {
            bail!("final history record is not private and user-owned");
        }
        directory
            .file
            .sync_all()
            .context("sync history directory after final record")?;

        let Some((_, pending_bytes, pending_identity)) =
            open_record(&directory, &reservation_name)?
        else {
            bail!("pending history reservation disappeared after final write");
        };
        if pending_identity != reservation.identity || pending_bytes != reservation.pending_bytes {
            bail!("pending history reservation changed during finalization");
        }
        unlinkat(&directory.file, reservation_name.as_str(), AtFlags::empty())
            .context("remove completed history reservation")?;
        directory
            .file
            .sync_all()
            .context("sync history directory after reservation removal")?;
        Ok(())
    }

    pub(super) fn open_record(
        directory: &Directory,
        name: &str,
    ) -> Result<Option<(fs::File, Vec<u8>, Fingerprint)>> {
        let fd = match open_record_fd(directory, name) {
            Ok(fd) => fs::File::from(fd),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("open history record {name}")),
        };
        Ok(Some(read_opened_record(directory, name, fd, true)?))
    }

    fn read_opened_record(
        directory: &Directory,
        name: &str,
        fd: fs::File,
        require_write: bool,
    ) -> Result<(fs::File, Vec<u8>, Fingerprint)> {
        let before = fd.metadata().context("inspect opened history record")?;
        let before_id = Fingerprint::from(&before);
        let uid = rustix::process::geteuid().as_raw();
        if !before.is_file()
            || before_id.device != directory.identity.device
            || before_id.uid != uid
            || before_id.links != 1
            || before_id.size > MAX_BYTES
            || before_id.mode & 0o077 != 0
            || before_id.mode & 0o400 == 0
            || require_write && before_id.mode & 0o200 == 0
        {
            bail!("history record {name} is linked, invalid, or not private");
        }
        let mut bytes = Vec::new();
        (&fd)
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("read history record")?;
        let after_id = Fingerprint::from(&fd.metadata().context("recheck history record")?);
        if before_id != after_id || bytes.len() as u64 > MAX_BYTES {
            bail!("history record {name} changed while reading");
        }
        Ok((fd, bytes, after_id))
    }

    fn read_report_record_named(directory: &Directory, name: &str) -> Result<Option<Vec<u8>>> {
        let fd = match openat(
            &directory.file,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fs::File::from(fd),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("open history record {name}")),
        };
        read_opened_record(directory, name, fd, false).map(|(_, bytes, _)| Some(bytes))
    }

    fn read_evidence(directory: &Directory, name: &str) -> Result<Evidence> {
        let Some((_, bytes, identity)) = open_record(directory, name)? else {
            bail!("history file {name} disappeared during preview");
        };
        Ok(Evidence {
            source: name.to_owned(),
            bytes,
            identity,
        })
    }

    fn reservation_matches_final(pending: &Record, final_record: &Record) -> bool {
        final_record.finished_unix.is_some()
            && pending.finished_unix.is_none()
            && pending.id == final_record.id
            && pending.started_unix == final_record.started_unix
            && pending.operation == safe_text(&final_record.operation)
            && pending.target == safe_text(&final_record.target)
            && pending.estimated_bytes == final_record.estimated_bytes
            && pending.platform == safe_text(&final_record.platform)
    }

    pub(super) fn read_report_record(
        directory: &Directory,
        id: usize,
        staged_names: &[String],
    ) -> Result<Option<ReportRecordRead>> {
        let record_name = format!("{id:03}.json");
        let reservation_name = format!("{id:03}.reserve");
        if staged_names.len() > 1
            || !staged_names.is_empty()
                && (read_report_record_named(directory, &record_name)?.is_some()
                    || read_report_record_named(directory, &reservation_name)?.is_some())
        {
            return Ok(Some(ReportRecordRead::Warning(
                "has conflicting staged files; they are preserved",
            )));
        }
        if let Some(staged_name) = staged_names.first() {
            let bytes = match read_report_record_named(directory, staged_name) {
                Ok(Some(bytes)) => bytes,
                _ => {
                    return Ok(Some(ReportRecordRead::Warning(
                        "has an unreadable staged file; it is preserved",
                    )));
                }
            };
            if !serde_json::from_slice::<Record>(&bytes).is_ok_and(|record| record.id == id) {
                return Ok(Some(ReportRecordRead::Warning(
                    "has an invalid staged file; it is preserved",
                )));
            }
            return Ok(Some(ReportRecordRead::Record(
                bytes,
                ReportRecordSource::Staged,
            )));
        }
        let record_result = read_report_record_named(directory, &record_name);
        let reservation_result = read_report_record_named(directory, &reservation_name);
        let final_record = record_result
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .and_then(|bytes| serde_json::from_slice::<Record>(bytes).ok())
            .filter(|record| record.id == id);
        let pending_record = reservation_result
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .and_then(|bytes| serde_json::from_slice::<Record>(bytes).ok())
            .filter(|record| record.id == id && record.finished_unix.is_none());

        match (
            record_result,
            reservation_result,
            final_record,
            pending_record,
        ) {
            (Ok(Some(bytes)), Ok(None), Some(_), _) => Ok(Some(ReportRecordRead::Record(
                bytes,
                ReportRecordSource::Final,
            ))),
            (Ok(Some(bytes)), Ok(Some(_)), Some(final_record), Some(pending))
                if reservation_matches_final(&pending, &final_record) =>
            {
                Ok(Some(ReportRecordRead::Record(
                    bytes,
                    ReportRecordSource::FinalWithReservation,
                )))
            }
            (Ok(None), Ok(Some(bytes)), None, Some(_)) => Ok(Some(ReportRecordRead::Record(
                bytes,
                ReportRecordSource::Pending,
            ))),
            (Ok(Some(final_bytes)), Ok(Some(pending_bytes)), None, Some(_))
                if serde_json::from_slice::<Record>(&final_bytes).is_err()
                    || serde_json::from_slice::<Record>(&final_bytes)
                        .is_ok_and(|record| record.id != id) =>
            {
                Ok(Some(ReportRecordRead::Record(
                    pending_bytes,
                    ReportRecordSource::RecoveredFinalWrite,
                )))
            }
            (Ok(None), Ok(None), None, None) => Ok(None),
            (Ok(None), Ok(Some(_)), None, None) => Ok(Some(ReportRecordRead::Warning(
                "has an invalid reservation; it is preserved",
            ))),
            (Err(_), _, _, _) | (_, Err(_), _, _) => Ok(Some(ReportRecordRead::Warning(
                "has an unverified final or reservation file; it is preserved",
            ))),
            _ => Ok(Some(ReportRecordRead::Warning(
                "has an invalid or mismatched final and reservation pair; both are preserved",
            ))),
        }
    }

    fn snapshot(home: &Path, cancel: &AtomicBool) -> Result<Snapshot> {
        let Some(directory) = open_directory(home)? else {
            return Ok(Snapshot {
                directory: None,
                entries: Vec::new(),
                evidence: Vec::new(),
            });
        };
        let before = directory.identity.clone();
        let mut names = Vec::new();
        let mut entry_count = 0;
        let mut stale_probe_count = 0;
        for entry in Dir::read_from(&directory.file).context("list history directory")? {
            if cancel.load(Ordering::Relaxed) {
                bail!("history preview cancelled");
            }
            let entry = entry.context("read history directory entry")?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            entry_count += 1;
            if entry_count > MAX_HISTORY_DIRECTORY_ENTRIES {
                bail!("history directory contains too many entries");
            }
            if is_stale_write_probe(name) {
                stale_probe_count += 1;
                if stale_probe_count > MAX_STALE_WRITE_PROBES {
                    bail!("history directory contains too many stale write probes");
                }
                continue;
            }
            if names.len() >= MAX_RECORDS * 3
                || !(0..MAX_RECORDS).any(|id| {
                    name == format!("{id:03}.json").as_bytes()
                        || name == format!("{id:03}.reserve").as_bytes()
                }) && std::str::from_utf8(name)
                    .ok()
                    .and_then(super::staged_history_id)
                    .is_none()
            {
                bail!("history directory contains an unexpected entry");
            }
            names.push(name.to_vec());
        }
        for id in 0..MAX_RECORDS {
            let stage_count = names
                .iter()
                .filter(|name| {
                    std::str::from_utf8(name)
                        .ok()
                        .and_then(super::staged_history_id)
                        == Some(id)
                })
                .count();
            let has_record = names
                .iter()
                .any(|name| name == format!("{id:03}.json").as_bytes());
            let has_reservation = names
                .iter()
                .any(|name| name == format!("{id:03}.reserve").as_bytes());
            if stage_count > 1 || stage_count == 1 && (has_record || has_reservation) {
                bail!("history slot {id:03} has conflicting staged entries");
            }
        }
        let mut entries = Vec::new();
        let mut evidence = Vec::new();
        for id in 0..MAX_RECORDS {
            if cancel.load(Ordering::Relaxed) {
                bail!("history preview cancelled");
            }
            let record_name = format!("{id:03}.json");
            let reservation_name = format!("{id:03}.reserve");
            let has_record = names
                .iter()
                .any(|candidate| candidate == record_name.as_bytes());
            let has_reservation = names
                .iter()
                .any(|candidate| candidate == reservation_name.as_bytes());
            let staged_name = names.iter().find_map(|name| {
                let name = std::str::from_utf8(name).ok()?;
                (super::staged_history_id(name) == Some(id)).then(|| name.to_owned())
            });
            if let Some(source) = staged_name {
                let staged = read_evidence(&directory, &source)?;
                if let Ok(mut record) = serde_json::from_slice::<Record>(&staged.bytes)
                    && record.id == id
                    && record
                        .finished_unix
                        .is_none_or(|finished| finished >= record.started_unix)
                {
                    record.operation = safe_text(&record.operation);
                    record.target = safe_text(&record.target);
                    record.outcome = safe_text(&record.outcome);
                    record.detail = record.detail.map(|detail| safe_text(&detail));
                    record.platform = safe_text(&record.platform);
                    entries.push(Entry {
                        record,
                        bytes: staged.bytes,
                        identity: staged.identity,
                        source: staged.source,
                        reservation: None,
                        blocked_by_final: false,
                    });
                } else {
                    evidence.push(staged);
                }
                continue;
            }
            if !has_record && !has_reservation {
                continue;
            }
            let read = |name: &str, pending: bool| -> Result<(Record, Vec<u8>, Fingerprint)> {
                let Some((_, bytes, identity)) = open_record(&directory, name)? else {
                    bail!("history record {name} changed during preview");
                };
                let record: Record = serde_json::from_slice(&bytes)
                    .with_context(|| format!("history record {name} is invalid"))?;
                if record.id != id || pending && record.finished_unix.is_some() {
                    bail!("history record {name} has an invalid ID");
                }
                Ok((record, bytes, identity))
            };
            let record_entry = has_record.then(|| read(&record_name, false));
            let reservation_entry = if has_reservation {
                Some(read(&reservation_name, true))
            } else {
                None
            };
            if !has_record {
                match reservation_entry.expect("reservation is present") {
                    Ok((mut record, bytes, identity)) => {
                        record.operation = safe_text(&record.operation);
                        record.target = safe_text(&record.target);
                        record.outcome = safe_text(&record.outcome);
                        record.detail = record.detail.map(|detail| safe_text(&detail));
                        record.platform = safe_text(&record.platform);
                        entries.push(Entry {
                            record,
                            bytes,
                            identity,
                            source: reservation_name,
                            reservation: None,
                            blocked_by_final: false,
                        });
                    }
                    Err(_) => evidence.push(read_evidence(&directory, &reservation_name)?),
                }
                continue;
            }
            let record_entry = record_entry.expect("record is present");
            let reservation_entry = reservation_entry
                .map(|result| result.map(Some))
                .unwrap_or(Ok(None));
            if let (Ok((final_record, _, _)), Ok(Some((pending, _, _)))) =
                (&record_entry, &reservation_entry)
                && !reservation_matches_final(pending, final_record)
            {
                evidence.push(read_evidence(&directory, &record_name)?);
                evidence.push(read_evidence(&directory, &reservation_name)?);
                continue;
            }
            let (mut record, bytes, identity, source, reservation, blocked_by_final) =
                match (record_entry, reservation_entry) {
                    (Ok((record, bytes, identity)), Ok(reservation)) => (
                        record,
                        bytes,
                        identity,
                        record_name.clone(),
                        reservation.map(|(_, bytes, identity)| (bytes, identity)),
                        false,
                    ),
                    (Err(_), Ok(Some((record, bytes, identity)))) => {
                        evidence.push(read_evidence(&directory, &record_name)?);
                        (
                            record,
                            bytes,
                            identity,
                            reservation_name.clone(),
                            None,
                            true,
                        )
                    }
                    (Err(error), _) => return Err(error),
                    (_, Err(error)) => return Err(error),
                };
            if record.id != id
                || record
                    .finished_unix
                    .is_some_and(|finished| finished < record.started_unix)
            {
                bail!("history record {id:03} is invalid");
            }
            record.operation = safe_text(&record.operation);
            record.target = safe_text(&record.target);
            record.outcome = safe_text(&record.outcome);
            record.detail = record.detail.map(|detail| safe_text(&detail));
            record.platform = safe_text(&record.platform);
            entries.push(Entry {
                record,
                bytes,
                identity,
                source,
                reservation,
                blocked_by_final,
            });
        }
        if Fingerprint::from(&directory.file.metadata()?) != before {
            bail!("history directory changed during preview");
        }
        entries.sort_by_key(|entry| entry.record.id);
        evidence.sort_by(|left, right| left.source.cmp(&right.source));
        Ok(Snapshot {
            directory: Some(directory),
            entries,
            evidence,
        })
    }

    fn selected(entry: &Entry, cutoff: u64) -> bool {
        if entry.blocked_by_final {
            return false;
        }
        match entry.record.finished_unix {
            Some(finished) => finished <= cutoff,
            None => false,
        }
    }

    fn token(snapshot: &Snapshot, age_seconds: u64, cutoff: u64) -> Result<String> {
        let mut hash = Sha256::new();
        hash.update(b"upkit-history-purge-v2\0");
        hash.update(age_seconds.to_be_bytes());
        if let Some(directory) = &snapshot.directory {
            hash.update([1]);
            hash.update(serde_json::to_vec(&directory.identity)?);
        } else {
            hash.update([0]);
        }
        hash.update((snapshot.entries.len() as u64).to_be_bytes());
        for entry in &snapshot.entries {
            hash.update(b"record\0");
            hash.update((entry.record.id as u64).to_be_bytes());
            hash.update((entry.bytes.len() as u64).to_be_bytes());
            hash.update(&entry.bytes);
            hash.update(serde_json::to_vec(&entry.identity)?);
            hash.update((entry.source.len() as u64).to_be_bytes());
            hash.update(entry.source.as_bytes());
            hash.update([u8::from(entry.blocked_by_final)]);
            if let Some((bytes, identity)) = &entry.reservation {
                hash.update([1]);
                let reservation_name = format!("{:03}.reserve", entry.record.id);
                hash.update((reservation_name.len() as u64).to_be_bytes());
                hash.update(reservation_name.as_bytes());
                hash.update((bytes.len() as u64).to_be_bytes());
                hash.update(bytes);
                hash.update(serde_json::to_vec(identity)?);
            } else {
                hash.update([0]);
            }
            hash.update([u8::from(selected(entry, cutoff))]);
        }
        hash.update((snapshot.evidence.len() as u64).to_be_bytes());
        for evidence in &snapshot.evidence {
            hash.update(b"evidence\0");
            hash.update((evidence.source.len() as u64).to_be_bytes());
            hash.update(evidence.source.as_bytes());
            hash.update((evidence.bytes.len() as u64).to_be_bytes());
            hash.update(&evidence.bytes);
            hash.update(serde_json::to_vec(&evidence.identity)?);
        }
        Ok(hex::encode(hash.finalize()))
    }

    fn read_now() -> Result<u64> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock predates Unix epoch")?
            .as_secs())
    }

    pub(super) fn preview(
        home: &Path,
        older_than: std::time::Duration,
        cancel: &AtomicBool,
    ) -> Result<HistoryPurgePlan> {
        let age_seconds = older_than.as_secs();
        let now = read_now()?;
        let cutoff = now.saturating_sub(age_seconds);
        let snapshot = snapshot(home, cancel)?;
        let skipped_unfinished_records = snapshot
            .entries
            .iter()
            .filter(|entry| entry.record.finished_unix.is_none() && !selected(entry, cutoff))
            .count();
        let candidates = snapshot
            .entries
            .iter()
            .filter(|entry| selected(entry, cutoff))
            .map(|entry| HistoryPurgeCandidate {
                id: entry.record.id,
                started_unix: entry.record.started_unix,
                finished_unix: entry.record.finished_unix,
                operation: entry.record.operation.clone(),
                target: entry.record.target.clone(),
                outcome: entry.record.outcome.clone(),
            })
            .collect();
        Ok(HistoryPurgePlan {
            older_than_seconds: age_seconds,
            cutoff_unix: cutoff,
            record_count: snapshot.entries.len(),
            skipped_unfinished_records,
            candidates,
            preview_token: token(&snapshot, age_seconds, cutoff)?,
            warning: "This permanently removes selected records. Unfinished records and verifiable staged records are reviewed here; incomplete or invalid history files are preserved.",
        })
    }

    fn verify_directory_path(home: &Path, directory: &Directory) -> Result<()> {
        let Some(current_directory) = open_directory(home)? else {
            bail!("history directory disappeared after preview");
        };
        if !current_directory.identity.same_object(&directory.identity) {
            bail!("history directory changed after preview");
        }
        Ok(())
    }

    fn same_file(home: &Path, directory: &Directory, entry: &Entry) -> Result<()> {
        same_record(home, directory, entry)?;
        if let Some((expected_bytes, expected_identity)) = &entry.reservation {
            let reservation = format!("{:03}.reserve", entry.record.id);
            let Some((_, bytes, identity)) = open_record(directory, &reservation)? else {
                bail!(
                    "history reservation {} disappeared after preview",
                    entry.record.id
                );
            };
            if &bytes != expected_bytes || &identity != expected_identity {
                bail!(
                    "history reservation {} changed after preview",
                    entry.record.id
                );
            }
        }
        Ok(())
    }

    fn same_record(home: &Path, directory: &Directory, entry: &Entry) -> Result<()> {
        verify_directory_path(home, directory)?;
        let name = &entry.source;
        let Some((_, bytes, identity)) = open_record(directory, name)? else {
            bail!(
                "history record {} disappeared after preview",
                entry.record.id
            );
        };
        if identity != entry.identity || bytes != entry.bytes {
            bail!("history record {} changed after preview", entry.record.id);
        }
        Ok(())
    }

    fn remove_reservation_before_final(
        home: &Path,
        directory: &Directory,
        entry: &Entry,
    ) -> Result<()> {
        let Some((expected_bytes, expected_identity)) = &entry.reservation else {
            return Ok(());
        };
        same_record(home, directory, entry)?;
        let reservation = format!("{:03}.reserve", entry.record.id);
        let Some((_, bytes, identity)) = open_record(directory, &reservation)? else {
            bail!(
                "history reservation {} disappeared before removal",
                entry.record.id
            );
        };
        if &bytes != expected_bytes || &identity != expected_identity {
            bail!(
                "history reservation {} changed before removal",
                entry.record.id
            );
        }
        unlinkat(&directory.file, reservation.as_str(), AtFlags::empty())
            .context("remove completed history reservation before final record")?;
        directory
            .file
            .sync_all()
            .context("sync history directory after reservation removal")?;
        Ok(())
    }

    fn restore(directory: &Directory, staged: &str, original: &str) -> Result<()> {
        renameat_with(
            &directory.file,
            staged,
            &directory.file,
            original,
            RenameFlags::NOREPLACE,
        )
        .map_err(Into::into)
    }

    static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);

    fn remove_one(
        home: &Path,
        directory: &Directory,
        entry: &Entry,
        cancel: &AtomicBool,
    ) -> std::result::Result<(), RemovalFailure> {
        let original = entry.source.clone();
        same_file(home, directory, entry)?;
        remove_reservation_before_final(home, directory, entry)?;
        same_record(home, directory, entry)?;
        if cancel.load(Ordering::Relaxed) {
            return Err(RemovalFailure::Cancelled(
                "history removal cancelled after reservation removal; final record retained".into(),
            ));
        }
        let stage = loop {
            let candidate = format!(
                ".history-purge-{}-{}-{}",
                std::process::id(),
                NEXT_STAGE.fetch_add(1, Ordering::Relaxed),
                entry.record.id
            );
            if candidate != original {
                break candidate;
            }
        };
        renameat_with(
            &directory.file,
            original.as_str(),
            &directory.file,
            stage.as_str(),
            RenameFlags::NOREPLACE,
        )
        .context("stage history record for removal")?;
        directory
            .file
            .sync_all()
            .context("sync history directory after staging record")?;

        let staged_result = open_record(directory, &stage).and_then(|opened| {
            let Some((_, bytes, identity)) = opened else {
                bail!("staged history record disappeared");
            };
            if !entry.identity.same_after_rename(&identity) || bytes != entry.bytes {
                bail!("staged history record changed after preview");
            }
            Ok(())
        });
        if let Err(error) = staged_result {
            return Err(match restore(directory, &stage, &original) {
                Ok(()) => error.into(),
                Err(restore_error) => {
                    anyhow!("{error:#}; could not restore staged record {stage}: {restore_error:#}")
                        .into()
                }
            });
        }
        if let Err(error) = verify_directory_path(home, directory) {
            return Err(match restore(directory, &stage, &original) {
                Ok(()) => error.into(),
                Err(restore_error) => {
                    anyhow!("{error:#}; could not restore staged record {stage}: {restore_error:#}")
                        .into()
                }
            });
        }
        if cancel.load(Ordering::Relaxed) {
            return Err(match restore(directory, &stage, &original) {
                Ok(()) => {
                    RemovalFailure::Cancelled("history removal cancelled before unlink".into())
                }
                Err(restore_error) => RemovalFailure::Failed(format!(
                    "history removal cancelled before unlink; could not restore {stage}: {restore_error:#}"
                )),
            });
        }
        if let Err(error) = unlinkat(&directory.file, stage.as_str(), AtFlags::empty()) {
            return Err(match restore(directory, &stage, &original) {
                Ok(()) => anyhow!("remove staged history record: {error}").into(),
                Err(restore_error) => anyhow!(
                    "remove staged history record: {error}; could not restore {stage}: {restore_error:#}"
                )
                .into(),
            });
        }
        directory
            .file
            .sync_all()
            .context("sync history directory after removal")?;
        Ok(())
    }

    pub(super) fn remove(
        home: &Path,
        older_than: std::time::Duration,
        token_value: &str,
        cancel: &AtomicBool,
        mut progress: impl FnMut(usize, usize),
    ) -> Result<HistoryPurgeResult> {
        let age_seconds = older_than.as_secs();
        let now = read_now()?;
        let cutoff = now.saturating_sub(age_seconds);
        let first_snapshot = snapshot(home, cancel)?;
        if let Some(directory) = &first_snapshot.directory {
            lock_directory(&directory.file, Some(cancel))?;
        }
        let snapshot = snapshot(home, cancel)?;
        match (&first_snapshot.directory, &snapshot.directory) {
            (Some(first), Some(current)) if first.identity.same_object(&current.identity) => {}
            (None, None) => {}
            _ => bail!("history directory changed while acquiring its lock"),
        }
        if token(&snapshot, age_seconds, cutoff)? != token_value {
            bail!("history changed or parameters differ from the preview; review it again");
        }
        let candidates = snapshot
            .entries
            .iter()
            .filter(|entry| selected(entry, cutoff))
            .collect::<Vec<_>>();
        if !candidates.is_empty() && snapshot.directory.is_none() {
            bail!("history directory disappeared after preview");
        }
        if cancel.load(Ordering::Relaxed) {
            bail!("history removal cancelled before any records were removed");
        }
        let Some(directory) = snapshot.directory.as_ref() else {
            return Ok(HistoryPurgeResult {
                outcome: "completed",
                cancelled: false,
                items: Vec::new(),
            });
        };
        for entry in &candidates {
            same_file(home, directory, entry)?;
        }
        let mut items = Vec::with_capacity(candidates.len());
        let mut cancelled = false;
        let total = candidates.len();
        for (index, entry) in candidates.iter().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                cancelled = true;
                items.extend(
                    candidates[index..]
                        .iter()
                        .map(|remaining| HistoryPurgeItem {
                            id: remaining.record.id,
                            status: "not_attempted_cancelled",
                            error: None,
                        }),
                );
                break;
            }
            match remove_one(home, directory, entry, cancel) {
                Ok(()) => items.push(HistoryPurgeItem {
                    id: entry.record.id,
                    status: "removed",
                    error: None,
                }),
                Err(RemovalFailure::Cancelled(error)) => {
                    cancelled = true;
                    items.push(HistoryPurgeItem {
                        id: entry.record.id,
                        status: "not_attempted_cancelled",
                        error: Some(error),
                    });
                    items.extend(candidates[index + 1..].iter().map(|remaining| {
                        HistoryPurgeItem {
                            id: remaining.record.id,
                            status: "not_attempted_cancelled",
                            error: None,
                        }
                    }));
                    break;
                }
                Err(RemovalFailure::Failed(error)) => {
                    items.push(HistoryPurgeItem {
                        id: entry.record.id,
                        status: "failed_or_unknown",
                        error: Some(error),
                    });
                    items.extend(candidates[index + 1..].iter().map(|remaining| {
                        HistoryPurgeItem {
                            id: remaining.record.id,
                            status: "not_attempted_after_failure",
                            error: None,
                        }
                    }));
                    break;
                }
            }
            progress(index + 1, total);
        }
        let removed = items.iter().filter(|item| item.status == "removed").count();
        let complete = removed == total && !cancelled;
        let outcome = if complete {
            "completed"
        } else if cancelled && removed == 0 {
            "cancelled"
        } else if removed == 0 {
            "failed_or_unknown"
        } else {
            "partial"
        };
        Ok(HistoryPurgeResult {
            outcome,
            cancelled,
            items,
        })
    }

    #[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn reservation_must_match_all_fields_checked_at_finalization() {
            let pending = Record {
                id: 0,
                started_unix: 1,
                finished_unix: None,
                duration_ms: 0,
                operation: "fixture_operation".into(),
                target: "fixture_target".into(),
                outcome: "in_progress".into(),
                detail: None,
                estimated_bytes: Some(10),
                verified_reclaimed_bytes: None,
                platform: "fixture".into(),
            };
            let mut completed = pending.clone();
            completed.finished_unix = Some(2);
            completed.duration_ms = 1;
            completed.outcome = "completed".into();
            assert!(reservation_matches_final(&pending, &completed));

            let mismatches = [
                Record {
                    operation: "different_operation".into(),
                    ..pending.clone()
                },
                Record {
                    target: "different_target".into(),
                    ..pending.clone()
                },
                Record {
                    started_unix: 0,
                    ..pending.clone()
                },
                Record {
                    estimated_bytes: Some(11),
                    ..pending.clone()
                },
                Record {
                    platform: "different_platform".into(),
                    ..pending.clone()
                },
            ];
            assert!(
                mismatches
                    .iter()
                    .all(|mismatch| !reservation_matches_final(mismatch, &completed))
            );
        }

        #[test]
        fn mismatched_final_and_reservation_are_tokenized_and_preserved() {
            let fixture = tempfile::tempdir().unwrap();
            let home = fixture.path().join("data");
            super::super::write_record(
                &home,
                Record {
                    id: 0,
                    started_unix: 1,
                    finished_unix: Some(2),
                    duration_ms: 1,
                    operation: "fixture_operation".into(),
                    target: "fixture_target".into(),
                    outcome: "completed".into(),
                    detail: None,
                    estimated_bytes: None,
                    verified_reclaimed_bytes: None,
                    platform: "fixture".into(),
                },
            )
            .unwrap();
            let final_path = home.join("history/000.json");
            let reservation_path = home.join("history/000.reserve");
            let final_bytes = fs::read(&final_path).unwrap();
            let pending = Record {
                id: 0,
                started_unix: 1,
                finished_unix: None,
                duration_ms: 0,
                operation: "different_operation".into(),
                target: "fixture_target".into(),
                outcome: "in_progress".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "fixture".into(),
            };
            fs::write(&reservation_path, serde_json::to_vec(&pending).unwrap()).unwrap();
            fs::set_permissions(&reservation_path, fs::Permissions::from_mode(0o600)).unwrap();
            let original_reservation = fs::read(&reservation_path).unwrap();
            let cancel = AtomicBool::new(false);

            let initial =
                super::super::preview_history_purge(&home, std::time::Duration::ZERO, &cancel)
                    .unwrap();
            assert!(initial.candidates.is_empty());

            let mut changed_pending = pending;
            changed_pending.operation = "another_unmatched_operation".into();
            fs::write(
                &reservation_path,
                serde_json::to_vec(&changed_pending).unwrap(),
            )
            .unwrap();
            fs::set_permissions(&reservation_path, fs::Permissions::from_mode(0o600)).unwrap();
            let changed_reservation = fs::read(&reservation_path).unwrap();
            let fresh =
                super::super::preview_history_purge(&home, std::time::Duration::ZERO, &cancel)
                    .unwrap();
            assert!(fresh.candidates.is_empty());
            assert_ne!(initial.preview_token, fresh.preview_token);

            assert!(
                super::super::purge_history(
                    &home,
                    std::time::Duration::ZERO,
                    &initial.preview_token,
                    &cancel,
                    |_, _| {},
                )
                .is_err()
            );
            assert_eq!(fs::read(&final_path).unwrap(), final_bytes);
            assert_eq!(fs::read(&reservation_path).unwrap(), changed_reservation);

            let result = super::super::purge_history(
                &home,
                std::time::Duration::ZERO,
                &fresh.preview_token,
                &cancel,
                |_, _| {},
            )
            .unwrap();
            assert_eq!(result.outcome, "completed");
            assert!(result.items.is_empty());
            assert_eq!(fs::read(&final_path).unwrap(), final_bytes);
            assert_ne!(changed_reservation, original_reservation);
            assert_eq!(fs::read(&reservation_path).unwrap(), changed_reservation);
        }

        #[test]
        fn purge_uses_private_fixtures_and_recovers_interrupted_stages() {
            let fixture = tempfile::tempdir().unwrap();
            let home = fixture.path().join("data");
            let record = |id, finished_unix| Record {
                id,
                started_unix: 1,
                finished_unix,
                duration_ms: 1,
                operation: "fixture_operation".into(),
                target: "fixture_target".into(),
                outcome: "completed".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "fixture".into(),
            };
            write_record(&home, record(0, Some(2))).unwrap();
            write_record(
                &home,
                record(
                    1,
                    Some(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    ),
                ),
            )
            .unwrap();
            write_record(&home, record(2, None)).unwrap();
            let cancel = AtomicBool::new(false);
            let plan =
                preview_history_purge(&home, std::time::Duration::from_secs(30 * 86400), &cancel)
                    .unwrap();
            assert_eq!(
                plan.candidates
                    .iter()
                    .map(|item| item.id)
                    .collect::<Vec<_>>(),
                [0]
            );
            let result = purge_history(
                &home,
                std::time::Duration::from_secs(30 * 86400),
                &plan.preview_token,
                &cancel,
                |_, _| {},
            )
            .unwrap();
            assert_eq!(result.outcome, "completed");
            assert!(!home.join("history/000.json").exists());
            assert!(home.join("history/001.json").exists());
            assert!(home.join("history/002.json").exists());

            write_record(&home, record(0, Some(2))).unwrap();
            let history = home.join("history");
            let staged = history.join(".history-purge-999999999-999999999-0");
            fs::rename(history.join("000.json"), &staged).unwrap();
            let visible = read(&home).unwrap();
            assert_eq!(visible.records.len(), 3);
            assert!(
                visible
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("interrupted during history purge"))
            );
            let plan =
                preview_history_purge(&home, std::time::Duration::from_secs(30 * 86400), &cancel)
                    .unwrap();
            assert_eq!(
                plan.candidates
                    .iter()
                    .map(|item| item.id)
                    .collect::<Vec<_>>(),
                [0]
            );
            let result = purge_history(
                &home,
                std::time::Duration::from_secs(30 * 86400),
                &plan.preview_token,
                &cancel,
                |_, _| {},
            )
            .unwrap();
            assert_eq!(result.outcome, "completed");
            assert!(!staged.exists());
            assert!(home.join("history/001.json").exists());
            assert!(home.join("history/002.json").exists());
        }

        #[test]
        fn writer_preserves_an_unfinished_reservation_after_a_crash() {
            let fixture = tempfile::tempdir().unwrap();
            let home = fixture.path().join("data");
            history_dir(&home, true).unwrap();
            let pending = Record {
                id: 0,
                started_unix: 1,
                finished_unix: None,
                duration_ms: 0,
                operation: "fixture_operation".into(),
                target: "fixture_target".into(),
                outcome: "in_progress".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "fixture".into(),
            };
            let reservation = home.join("history/000.reserve");
            let pending_bytes = serde_json::to_vec(&pending).unwrap();
            fs::write(&reservation, &pending_bytes).unwrap();
            fs::set_permissions(&reservation, fs::Permissions::from_mode(0o600)).unwrap();

            write_record(
                &home,
                Record {
                    finished_unix: Some(2),
                    outcome: "completed".into(),
                    ..pending.clone()
                },
            )
            .unwrap();

            assert_eq!(fs::read(&reservation).unwrap(), pending_bytes);
            assert!(!home.join("history/000.json").exists());
            assert!(home.join("history/001.json").exists());
        }

        #[test]
        fn report_writer_waits_for_the_shared_history_directory_lock() {
            let fixture = tempfile::tempdir().unwrap();
            let home = fixture.path().join("data");
            history_dir(&home, true).unwrap();
            let directory = open_write_directory(&home).unwrap().unwrap();
            lock_directory(&directory.file, None).unwrap();

            let (started, wait_started) = std::sync::mpsc::channel();
            let worker_home = home.clone();
            let worker = std::thread::spawn(move || {
                started.send(()).unwrap();
                write_record(
                    &worker_home,
                    Record {
                        id: 0,
                        started_unix: 1,
                        finished_unix: Some(2),
                        duration_ms: 1,
                        operation: "fixture_operation".into(),
                        target: "fixture_target".into(),
                        outcome: "completed".into(),
                        detail: None,
                        estimated_bytes: None,
                        verified_reclaimed_bytes: None,
                        platform: "fixture".into(),
                    },
                )
            });
            wait_started.recv().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
            assert!(!home.join("history/000.json").exists());

            drop(directory);
            worker.join().unwrap().unwrap();
            assert!(home.join("history/000.json").exists());
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn final_record_remains_purgeable_if_interrupted_after_reservation_removal() {
            let fixture = tempfile::tempdir().unwrap();
            let home = fixture.path().join("data");
            let pending = super::super::Record {
                id: 0,
                started_unix: 1,
                finished_unix: None,
                duration_ms: 0,
                operation: "scheduled_artifact_removal".into(),
                target: "scheduled Rust artifact".into(),
                outcome: "in_progress".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "fixture".into(),
            };
            let reservation = super::super::reserve_history_record(&home, pending.clone()).unwrap();
            let pending_bytes = reservation.pending_bytes.clone();
            let mut completed = pending;
            completed.finished_unix = Some(2);
            completed.duration_ms = 1;
            completed.outcome = "completed".into();
            reservation.finish(completed).unwrap();
            let reservation_path = home.join("history/000.reserve");
            fs::write(&reservation_path, pending_bytes).unwrap();
            fs::set_permissions(&reservation_path, fs::Permissions::from_mode(0o600)).unwrap();

            let cancel = AtomicBool::new(false);
            let snapshot = snapshot(&home, &cancel).unwrap();
            let directory = snapshot.directory.as_ref().unwrap();
            lock_directory(&directory.file, None).unwrap();
            let entry = snapshot.entries.first().unwrap();
            assert!(entry.reservation.is_some());
            remove_reservation_before_final(&home, directory, entry).unwrap();
            assert!(home.join("history/000.json").exists());
            assert!(!reservation_path.exists());
            drop(snapshot);

            let plan =
                super::super::preview_history_purge(&home, std::time::Duration::ZERO, &cancel)
                    .unwrap();
            assert_eq!(plan.candidates.len(), 1);
            let result = super::super::purge_history(
                &home,
                std::time::Duration::ZERO,
                &plan.preview_token,
                &cancel,
                |_, _| {},
            )
            .unwrap();
            assert_eq!(result.outcome, "completed");
            assert!(!home.join("history/000.json").exists());
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn preview_history_purge(
    home: &Path,
    older_than: std::time::Duration,
    cancel: &AtomicBool,
) -> Result<HistoryPurgePlan> {
    history_purge::preview(home, older_than, cancel)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn purge_history(
    home: &Path,
    older_than: std::time::Duration,
    token: &str,
    cancel: &AtomicBool,
    progress: impl FnMut(usize, usize),
) -> Result<HistoryPurgeResult> {
    history_purge::remove(home, older_than, token, cancel, progress)
}

pub fn perform_history_purge(
    home: &Path,
    plan: &HistoryPurgePlan,
    token: &str,
    cancel: &AtomicBool,
    progress: impl FnMut(usize, usize),
) -> Performed<HistoryPurgeResult> {
    let older_than = std::time::Duration::from_secs(plan.older_than_seconds);
    if plan.candidates.is_empty() {
        return Performed {
            result: purge_history(home, older_than, token, cancel, progress)
                .map_err(|error| format!("{error:#}")),
            history_warning: None,
        };
    }
    let target = format!(
        "history records older than {} seconds",
        plan.older_than_seconds
    );
    perform(
        home,
        "history_purge",
        target,
        None,
        || purge_history(home, older_than, token, cancel, progress),
        |result| {
            let removed = result
                .items
                .iter()
                .filter(|item| item.status == "removed")
                .count();
            (
                result.outcome,
                Some(format!(
                    "removed={removed}; selected={}; cancelled={}",
                    result.items.len(),
                    result.cancelled
                )),
            )
        },
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn preview_history_purge(
    _: &Path,
    _: std::time::Duration,
    _: &AtomicBool,
) -> Result<HistoryPurgePlan> {
    bail!("history purge preview is supported on Linux and macOS only")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn purge_history(
    _: &Path,
    _: std::time::Duration,
    _: &str,
    _: &AtomicBool,
    _: impl FnMut(usize, usize),
) -> Result<HistoryPurgeResult> {
    bail!("history removal is supported on Linux and macOS only")
}

fn perform<T>(
    home: &Path,
    operation: &str,
    target: String,
    estimate: Option<u64>,
    action: impl FnOnce() -> Result<T>,
    classify: impl FnOnce(&T) -> (&'static str, Option<String>),
) -> Performed<T> {
    perform_with_failure_detail(home, operation, target, estimate, None, action, classify)
}

fn perform_with_failure_detail<T>(
    home: &Path,
    operation: &str,
    target: String,
    estimate: Option<u64>,
    failure_detail: Option<&'static str>,
    action: impl FnOnce() -> Result<T>,
    classify: impl FnOnce(&T) -> (&'static str, Option<String>),
) -> Performed<T> {
    let started_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |v| v.as_secs());
    let started = Instant::now();
    let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(result) => result.map_err(|err| format!("{err:#}")),
        Err(_) => Err("operation worker panicked; outcome may be unknown".into()),
    };
    let (outcome, detail) = match &result {
        Ok(value) => classify(value),
        Err(err) => (
            "failed_or_unknown",
            Some(failure_detail.map_or_else(
                || {
                    err.chars()
                        .flat_map(char::escape_default)
                        .take(1024)
                        .collect()
                },
                str::to_owned,
            )),
        ),
    };
    let record = Record {
        id: 0,
        started_unix,
        finished_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|value| value.as_secs()),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        operation: operation.into(),
        target,
        outcome: outcome.into(),
        detail,
        estimated_bytes: estimate,
        verified_reclaimed_bytes: None,
        platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
    };
    let history_warning = write_record(home, record)
        .err()
        .map(|err| format!("operation history was not recorded: {err:#}"));
    Performed {
        result,
        history_warning,
    }
}

#[cfg(target_os = "linux")]
fn perform_reserved_with_failure_detail<T>(
    home: &Path,
    operation: &str,
    target: String,
    estimate: Option<u64>,
    failure_detail: Option<&'static str>,
    action: impl FnOnce() -> Result<T>,
    classify: impl FnOnce(&T) -> (&'static str, Option<String>),
) -> Performed<T> {
    let started_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_secs());
    let started = Instant::now();
    let record = Record {
        id: 0,
        started_unix,
        finished_unix: None,
        duration_ms: 0,
        operation: operation.into(),
        target,
        outcome: "in_progress".into(),
        detail: None,
        estimated_bytes: estimate,
        verified_reclaimed_bytes: None,
        platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
    };
    let reservation = match reserve_history_record(home, record.clone()) {
        Ok(reservation) => reservation,
        Err(error) => {
            let warning =
                format!("operation history could not be reserved before action: {error:#}");
            return Performed {
                result: Err(warning.clone()),
                history_warning: Some(warning),
            };
        }
    };
    let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(result) => result.map_err(|err| format!("{err:#}")),
        Err(_) => Err("operation worker panicked; outcome may be unknown".into()),
    };
    let (outcome, detail) = match &result {
        Ok(value) => classify(value),
        Err(err) => (
            "failed_or_unknown",
            Some(failure_detail.map_or_else(
                || {
                    err.chars()
                        .flat_map(char::escape_default)
                        .take(1024)
                        .collect()
                },
                str::to_owned,
            )),
        ),
    };
    let mut record = record;
    record.finished_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs());
    record.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    record.outcome = outcome.into();
    record.detail = detail;
    let history_warning = reservation
        .finish(record)
        .err()
        .map(|error| format!("operation history could not be finalized: {error:#}"));
    Performed {
        result,
        history_warning,
    }
}

pub fn perform_scheduled_scan(
    home: &Path,
    executable: &Path,
    roots: &[std::path::PathBuf],
    exclusions: &[std::path::PathBuf],
    token: &str,
) -> Performed<crate::sweep::ScanReport> {
    perform_with_failure_detail(
        home,
        "scheduled_scan",
        format!("configured workspace scan (roots: {})", roots.len()),
        None,
        Some("scheduled scan failed; inspect the command result for details"),
        || crate::schedule::run_guarded_scan(executable, roots, exclusions, token),
        |report| {
            let outcome = if report.cancelled {
                "cancelled"
            } else if !report.is_complete() {
                "partial"
            } else {
                "completed"
            };
            let mut detail = format!(
                "{} candidates; {} warnings",
                report.candidates.len(),
                report.warnings.len()
            );
            if report.is_complete()
                && let Some(bytes) = report
                    .candidates
                    .iter()
                    .try_fold(0u64, |sum, item| sum.checked_add(item.logical_bytes))
            {
                use sha2::{Digest, Sha256};
                let scope = hex::encode(Sha256::digest(token.as_bytes()));
                detail.push_str(&format!("; scan-v1 {scope} {bytes}"));
            }
            (outcome, Some(detail))
        },
    )
}

pub fn perform_scheduled_cleanup(
    home: &Path,
    executable: &Path,
    roots: &[std::path::PathBuf],
    exclusions: &[std::path::PathBuf],
    token: &str,
    cancel: &std::sync::atomic::AtomicBool,
) -> Performed<crate::scheduled_cleanup::Report> {
    let mut performed = {
        #[cfg(target_os = "linux")]
        let performed = perform_reserved_with_failure_detail(
            home,
            "scheduled_bytecode_cleanup",
            format!("configured workspace scan (roots: {})", roots.len()),
            None,
            Some("scheduled bytecode cleanup failed; inspect the command result"),
            || {
                crate::scheduled_cleanup::run(
                    home, executable, roots, exclusions, token, false, cancel,
                )
            },
            |report| {
                (
                    if report.complete {
                        "completed"
                    } else {
                        "partial"
                    },
                    Some(format!(
                        "{} files inspected; {} results",
                        report.inspected,
                        report.items.len()
                    )),
                )
            },
        );
        #[cfg(not(target_os = "linux"))]
        let performed = perform_with_failure_detail(
            home,
            "scheduled_bytecode_cleanup",
            format!("configured workspace scan (roots: {})", roots.len()),
            None,
            Some("scheduled bytecode cleanup failed; inspect the command result"),
            || {
                crate::scheduled_cleanup::run(
                    home, executable, roots, exclusions, token, false, cancel,
                )
            },
            |report| {
                (
                    if report.complete {
                        "completed"
                    } else {
                        "partial"
                    },
                    Some(format!(
                        "{} files inspected; {} results",
                        report.inspected,
                        report.items.len()
                    )),
                )
            },
        );
        performed
    };
    if performed.history_warning.is_some()
        && let Ok(report) = &mut performed.result
    {
        report.complete = false;
        report
            .warnings
            .push("Scheduled cleanup summary could not be recorded in local history.".into());
    }
    performed
}

#[cfg(target_os = "linux")]
fn scheduled_artifact_outcome(report: &crate::scheduled_cleanup::ArtifactReport) -> &'static str {
    if report.complete {
        "completed"
    } else if report.cancelled
        && report
            .items
            .iter()
            .all(|item| item.status.starts_with("not_attempted"))
    {
        "cancelled"
    } else {
        "partial"
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn perform_scheduled_artifact_cleanup(
    home: &Path,
    executable: &Path,
    roots: &[std::path::PathBuf],
    exclusions: &[std::path::PathBuf],
    token: &str,
    cancel: &std::sync::atomic::AtomicBool,
) -> Performed<crate::scheduled_cleanup::ArtifactReport> {
    let mut performed = perform_reserved_with_failure_detail(
        home,
        "scheduled_artifact_cleanup",
        format!("configured project artifacts (roots: {})", roots.len()),
        None,
        Some("scheduled artifact cleanup failed; inspect the command result"),
        || {
            crate::scheduled_cleanup::run_artifact_cleanup(
                home, executable, roots, exclusions, token, false, cancel,
            )
        },
        |report| {
            (
                scheduled_artifact_outcome(report),
                Some(format!(
                    "{} eligible; {} selected; {} results",
                    report.candidates,
                    report.selected,
                    report.items.len()
                )),
            )
        },
    );
    if performed.history_warning.is_some()
        && let Ok(report) = &mut performed.result
    {
        report.complete = false;
        report
            .warnings
            .push("Scheduled artifact cleanup history could not be fully recorded.".into());
        report.continue_with_bytecode = false;
    }
    performed
}

pub fn perform_trim(
    home: &Path,
    plan: &crate::maintenance::TrimPlan,
    token: &str,
) -> Performed<()> {
    perform(
        home,
        "trim",
        crate::sweep::display_path(&plan.mount),
        None,
        || crate::maintenance::run_trim(plan, token),
        |_| ("completed", None),
    )
}

pub fn perform_bytecode_removal(
    home: &Path,
    plan: &crate::bytecode::BytecodePlan,
    token: &str,
    cancel: &std::sync::atomic::AtomicBool,
) -> Performed<&'static str> {
    perform(
        home,
        "bytecode_removal",
        crate::sweep::display_path(&plan.file),
        Some(plan.logical_bytes),
        || crate::bytecode::remove(&plan.scope, &plan.file, token, cancel),
        |status| {
            if *status == "verified_absent" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn perform_scheduled_bytecode_removal(
    home: &Path,
    plan: &crate::bytecode::BytecodePlan,
    cancel: &std::sync::atomic::AtomicBool,
    guard: &dyn Fn() -> Result<()>,
) -> Performed<&'static str> {
    perform_reserved_with_failure_detail(
        home,
        "scheduled_bytecode_removal",
        "scheduled Python bytecode".into(),
        Some(plan.logical_bytes),
        Some("scheduled bytecode removal failed; inspect the command result"),
        || {
            crate::bytecode::remove_guarded(
                &plan.scope,
                &plan.file,
                &plan.preview_token,
                cancel,
                guard,
            )
        },
        |status| {
            if *status == "verified_absent" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_artifact_removal(
    home: &Path,
    plan: &crate::artifact_cleanup::ArtifactPlan,
    token: &str,
    cancel: &std::sync::atomic::AtomicBool,
) -> Performed<&'static str> {
    if !history_targets_are_safe(home, std::slice::from_ref(&plan.target)) {
        return Performed {
            result: Err(
                "operation history location is inside a selected artifact or cannot be resolved"
                    .into(),
            ),
            history_warning: None,
        };
    }
    perform(
        home,
        "artifact_removal",
        crate::sweep::display_path(&plan.target),
        Some(plan.logical_bytes),
        || crate::artifact_cleanup::remove(&plan.scope, &plan.target, token, cancel),
        |status| {
            if *status == "verified_absent" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn perform_scheduled_artifact_removal(
    home: &Path,
    plan: &crate::artifact_cleanup::ArtifactPlan,
    cancel: &std::sync::atomic::AtomicBool,
    guard: &dyn Fn() -> Result<()>,
) -> Performed<&'static str> {
    if !history_targets_are_safe(home, std::slice::from_ref(&plan.target)) {
        return Performed {
            result: Err("operation history location overlaps a scheduled artifact".into()),
            history_warning: None,
        };
    }
    perform_reserved_with_failure_detail(
        home,
        "scheduled_artifact_removal",
        format!("scheduled {} artifact", plan.ecosystem),
        Some(plan.logical_bytes),
        Some("scheduled artifact removal failed; inspect the scheduled command result"),
        || {
            crate::artifact_cleanup::remove_guarded(
                &plan.scope,
                &plan.target,
                &plan.preview_token,
                cancel,
                guard,
            )
        },
        |status| {
            if *status == "verified_absent" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

#[derive(Debug, Serialize)]
pub struct ArtifactBatchItemReport {
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub target: std::path::PathBuf,
    pub status: &'static str,
    pub attempted: bool,
    pub error: Option<String>,
    pub history_warning: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ArtifactBatchReport {
    pub items: Vec<ArtifactBatchItemReport>,
    pub complete: bool,
    pub cancelled: bool,
    pub error: Option<String>,
}

fn resolve_path(path: &Path) -> Option<std::path::PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    if absolute
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return None;
    }
    let mut existing = absolute.as_path();
    let canonical = loop {
        match existing.canonicalize() {
            Ok(path) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::symlink_metadata(existing) {
                    Ok(_) => return None,
                    Err(metadata_error)
                        if metadata_error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return None,
                }
                existing = existing.parent()?;
            }
            Err(_) => return None,
        }
    };
    let suffix = absolute.strip_prefix(existing).ok()?;
    if !suffix.as_os_str().is_empty() && !std::fs::metadata(existing).ok()?.is_dir() {
        return None;
    }
    Some(canonical.join(suffix))
}

fn absolute_normalized_path(path: &Path) -> Option<std::path::PathBuf> {
    use std::path::Component;

    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let mut normalized = std::path::PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir if !normalized.pop() => return None,
            Component::ParentDir => {}
            Component::Normal(_) => normalized.push(component.as_os_str()),
        }
    }
    normalized.is_absolute().then_some(normalized)
}

fn resolved_path_prefixes(path: &Path) -> Option<Vec<std::path::PathBuf>> {
    use std::path::Component;

    let normalized = absolute_normalized_path(path)?;
    let mut prefix = std::path::PathBuf::new();
    let mut resolved = Vec::new();
    for component in normalized.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => prefix.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => return None,
            Component::Normal(_) => {
                prefix.push(component.as_os_str());
                resolved.push(resolve_path(&prefix)?);
            }
        }
    }
    Some(resolved)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

pub(crate) fn history_targets_are_safe(home: &Path, targets: &[std::path::PathBuf]) -> bool {
    let Some(lexical_history) = absolute_normalized_path(&home.join("history")) else {
        return false;
    };
    let Some(history) = resolve_path(&home.join("history")) else {
        return false;
    };
    let Some(history_prefixes) = resolved_path_prefixes(&home.join("history")) else {
        return false;
    };
    targets.iter().all(|target| {
        let Some(lexical_target) = absolute_normalized_path(target) else {
            return false;
        };
        if paths_overlap(&lexical_history, &lexical_target) {
            return false;
        }
        let Some(target_prefixes) = resolved_path_prefixes(target) else {
            return false;
        };
        let Some(resolved_target) = resolve_path(target) else {
            return false;
        };
        !paths_overlap(&history, &resolved_target)
            && !history_prefixes
                .iter()
                .any(|prefix| prefix.starts_with(&resolved_target))
            && !target_prefixes
                .iter()
                .any(|prefix| prefix.starts_with(&history))
    })
}

/// Execute the selected artifact batch and record each target's result separately.
pub fn perform_artifact_batch(
    home: &Path,
    plan: &crate::artifact_cleanup::ArtifactBatchPlan,
    token: &str,
    cancel: &std::sync::atomic::AtomicBool,
) -> ArtifactBatchReport {
    let paths = plan
        .items
        .iter()
        .map(|item| item.target.clone())
        .collect::<Vec<_>>();
    if !history_targets_are_safe(home, &paths) {
        let error =
            "operation history location is inside a selected artifact or cannot be resolved";
        return ArtifactBatchReport {
            items: plan
                .items
                .iter()
                .map(|item| ArtifactBatchItemReport {
                    target: item.target.clone(),
                    status: "not_attempted",
                    attempted: false,
                    error: Some(error.into()),
                    history_warning: None,
                })
                .collect(),
            complete: false,
            cancelled: false,
            error: Some(error.into()),
        };
    }

    let started_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_secs());
    let started = Instant::now();
    let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::artifact_cleanup::remove_batch(&plan.scope, &paths, token, cancel)
    }));
    let (mut items, complete, cancelled, error) = match execution {
        Ok(Ok(result)) => {
            let complete = result.outcomes.len() == plan.items.len()
                && result
                    .outcomes
                    .iter()
                    .all(|item| item.status == "verified_absent");
            let items: Vec<ArtifactBatchItemReport> = result
                .outcomes
                .into_iter()
                .map(|item| ArtifactBatchItemReport {
                    target: item.target,
                    status: item.status,
                    attempted: item.status != "not_attempted_cancelled",
                    error: item.error,
                    history_warning: None,
                })
                .collect();
            (items, complete, result.cancelled, None)
        }
        Ok(Err(error)) => {
            let error = format!("{error:#}");
            let cancelled = cancel.load(std::sync::atomic::Ordering::Relaxed);
            let status = if cancelled {
                "not_attempted_cancelled"
            } else {
                "not_attempted"
            };
            let items: Vec<ArtifactBatchItemReport> = plan
                .items
                .iter()
                .map(|item| ArtifactBatchItemReport {
                    target: item.target.clone(),
                    status,
                    attempted: false,
                    error: Some(error.clone()),
                    history_warning: None,
                })
                .collect();
            (items, false, cancelled, Some(error))
        }
        Err(_) => {
            let error = "artifact batch worker panicked; outcome may be unknown".to_owned();
            let items: Vec<ArtifactBatchItemReport> = plan
                .items
                .iter()
                .map(|item| ArtifactBatchItemReport {
                    target: item.target.clone(),
                    status: "failed_or_unknown",
                    attempted: true,
                    error: Some(error.clone()),
                    history_warning: None,
                })
                .collect();
            (items, false, false, Some(error))
        }
    };
    let finished_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs());
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    for (item, planned) in items.iter_mut().zip(&plan.items) {
        let outcome = match item.status {
            "verified_absent" => "completed",
            "unverified_replacement" => "unverified",
            "not_attempted" => "not_attempted",
            "not_attempted_cancelled" => "cancelled",
            _ => "failed_or_unknown",
        };
        let detail = item.error.clone().or_else(|| Some(item.status.to_owned()));
        if let Err(error) = write_record(
            home,
            Record {
                id: 0,
                started_unix,
                finished_unix,
                duration_ms,
                operation: "artifact_removal".into(),
                target: crate::sweep::display_path(&item.target),
                outcome: outcome.into(),
                detail,
                estimated_bytes: Some(planned.logical_bytes),
                verified_reclaimed_bytes: None,
                platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
            },
        ) {
            item.history_warning = Some(format!("operation history was not recorded: {error:#}"));
        }
    }
    ArtifactBatchReport {
        items,
        complete,
        cancelled,
        error,
    }
}

pub fn perform_shared_cache_removal(
    home: &Path,
    plan: &crate::shared_cache_cleanup::CacheRemovalPlan,
    token: &str,
    cancel: &std::sync::atomic::AtomicBool,
) -> Performed<&'static str> {
    if !history_targets_are_safe(home, std::slice::from_ref(&plan.target)) {
        return Performed {
            result: Err(
                "operation history location is inside the selected cache or cannot be resolved"
                    .into(),
            ),
            history_warning: None,
        };
    }
    perform(
        home,
        "shared_cache_removal",
        crate::shared_cache_cleanup::display_path(&plan.target),
        Some(plan.logical_bytes),
        || crate::shared_cache_cleanup::remove(&plan.target, token, cancel),
        |status| {
            if *status == "verified_absent" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

#[derive(Debug, Serialize)]
pub struct BytecodeBatchItem {
    #[serde(serialize_with = "crate::sweep::serialize_path")]
    pub file: std::path::PathBuf,
    pub status: &'static str,
    pub attempted: bool,
    pub error: Option<String>,
    pub history_warning: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BytecodeBatchResult {
    pub items: Vec<BytecodeBatchItem>,
    pub complete: bool,
}

/// Revalidate the full selection and then record each attempted deletion separately.
pub fn perform_bytecode_batch(
    home: &Path,
    plan: &crate::bytecode::BytecodeBatchPlan,
    token: &str,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<BytecodeBatchResult> {
    perform_bytecode_batch_with_progress(home, plan, token, cancel, |_, _| {})
}

pub fn perform_bytecode_batch_with_progress(
    home: &Path,
    plan: &crate::bytecode::BytecodeBatchPlan,
    token: &str,
    cancel: &std::sync::atomic::AtomicBool,
    mut progress: impl FnMut(usize, usize),
) -> Result<BytecodeBatchResult> {
    use std::sync::atomic::Ordering;
    let paths = plan
        .files
        .iter()
        .map(|file| file.file.clone())
        .collect::<Vec<_>>();
    let fresh = crate::bytecode::preview_batch(&plan.scope, &paths, cancel)?;
    if token != plan.preview_token || token != fresh.preview_token {
        anyhow::bail!("bytecode batch changed; review the complete selection again");
    }
    let mut items = Vec::with_capacity(paths.len());
    let mut stopped = false;
    for (file, guard) in fresh.files.iter().zip(&fresh.guards) {
        if stopped || cancel.load(Ordering::Relaxed) {
            items.push(BytecodeBatchItem {
                file: file.file.clone(),
                status: if stopped { "skipped" } else { "cancelled" },
                attempted: false,
                error: None,
                history_warning: None,
            });
            stopped = true;
            continue;
        }
        let checked = crate::bytecode::preview_guarded(&fresh.scope, &file.file, cancel);
        let current = match checked {
            Ok((current, current_guard)) if &current_guard == guard => current,
            result => {
                let error = match result {
                    Ok(_) => "bytecode or project changed after batch preview".into(),
                    Err(error) => format!("{error:#}"),
                };
                items.push(BytecodeBatchItem {
                    file: file.file.clone(),
                    status: "failed",
                    attempted: false,
                    error: Some(error),
                    history_warning: None,
                });
                stopped = true;
                progress(items.len(), paths.len());
                continue;
            }
        };
        let performed = perform_bytecode_removal(home, &current, &current.preview_token, cancel);
        let (status, error) = match performed.result {
            Ok(status) => (status, None),
            Err(error) => ("failed", Some(error)),
        };
        stopped = status != "verified_absent";
        items.push(BytecodeBatchItem {
            file: file.file.clone(),
            status,
            attempted: true,
            error,
            history_warning: performed.history_warning,
        });
        progress(items.len(), paths.len());
    }
    Ok(BytecodeBatchResult {
        complete: !stopped,
        items,
    })
}

pub fn perform_managed_cleanup(
    ctx: &crate::Ctx,
    plan: &crate::managed_cleanup::CleanupPlan,
    cancel: &std::sync::atomic::AtomicBool,
) -> Performed<&'static str> {
    let preserved = plan
        .preserved_entries
        .iter()
        .map(|path| crate::sweep::display_path(path))
        .chain(
            plan.preserved_links
                .iter()
                .map(|path| crate::sweep::display_path(path)),
        )
        .collect::<Vec<_>>();
    perform(
        &ctx.home,
        "managed_tool_cleanup",
        crate::sweep::display_path(&plan.root),
        Some(plan.logical_bytes),
        || crate::managed_cleanup::remove(ctx, plan, cancel),
        |status| {
            if *status == "verified_selected_absent" {
                (
                    "completed",
                    Some(format!(
                        "{status}; managed root retained; preserved paths: {}",
                        if preserved.is_empty() {
                            "none listed".into()
                        } else {
                            preserved.join(", ")
                        }
                    )),
                )
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

#[cfg(target_os = "linux")]
pub fn perform_temp_cleanup(
    home: &Path,
    plan: &crate::temp_cleanup::Plan,
    token: &str,
    cancel: &AtomicBool,
) -> Performed<crate::temp_cleanup::CleanupResult> {
    let selected = plan
        .candidates
        .iter()
        .filter(|candidate| candidate.selected)
        .map(|candidate| candidate.path.clone())
        .collect::<Vec<_>>();
    perform_temp_cleanup_with(home, &selected, || {
        crate::temp_cleanup::run(plan, token, cancel)
    })
}

#[cfg(target_os = "linux")]
fn perform_temp_cleanup_with(
    home: &Path,
    selected: &[std::path::PathBuf],
    action: impl FnOnce() -> Result<crate::temp_cleanup::CleanupResult>,
) -> Performed<crate::temp_cleanup::CleanupResult> {
    let started_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_secs());
    let started = Instant::now();
    let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(result) => result.map_err(|error| format!("{error:#}")),
        Err(_) => Err("operation worker panicked; outcome may be unknown".into()),
    };
    let finished_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs());
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut warnings = Vec::new();
    for target in selected {
        let (outcome, detail) = match &result {
            Ok(result) => match result.items.iter().find(|item| item.path == *target) {
                Some(item) => (
                    match item.status {
                        "removed" => "completed",
                        "cancelled" => "cancelled",
                        _ => "failed_or_unknown",
                    },
                    item.error.clone().or_else(|| Some(item.status.to_owned())),
                ),
                None => (
                    "failed_or_unknown",
                    Some("cleanup result omitted the selected target".into()),
                ),
            },
            Err(error) => ("failed_or_unknown", Some(error.clone())),
        };
        let display_target = crate::sweep::display_path(target);
        if let Err(error) = write_record(
            home,
            Record {
                id: 0,
                started_unix,
                finished_unix,
                duration_ms,
                operation: "upkit_temp_cleanup".into(),
                target: display_target.clone(),
                outcome: outcome.into(),
                detail,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
            },
        ) {
            warnings.push(format!(
                "{display_target}: operation history was not recorded: {error:#}"
            ));
        }
    }
    Performed {
        result,
        history_warning: (!warnings.is_empty()).then(|| safe_text(&warnings.join("; "))),
    }
}

pub fn perform_schedule_enable(
    home: &Path,
    executable: &Path,
    plan: &crate::schedule::EnableSchedulePreview,
    token: &str,
    frequency: crate::schedule::Frequency,
) -> Performed<&'static str> {
    perform(
        home,
        "schedule_enable",
        crate::sweep::display_path(&plan.intended.unit_directory),
        None,
        || crate::schedule::enable_scan(executable, plan, token, frequency),
        |status| {
            if *status == "active_and_enabled" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_configured_schedule_enable(
    home: &Path,
    executable: &Path,
    plan: &crate::schedule::EnableSchedulePreview,
    token: &str,
    frequency: crate::schedule::Frequency,
    config: Option<&Path>,
    profile: Option<&str>,
) -> Performed<&'static str> {
    perform(
        home,
        "schedule_enable",
        crate::sweep::display_path(&plan.intended.unit_directory),
        None,
        || {
            crate::schedule::enable_configured_scan(
                executable, plan, token, frequency, config, profile,
            )
        },
        |status| {
            if *status == "active_and_enabled" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_configured_schedule_edit(
    home: &Path,
    executable: &Path,
    plan: &crate::schedule::EditSchedulePreview,
    token: &str,
    frequency: crate::schedule::Frequency,
    config: Option<&Path>,
    profile: Option<&str>,
) -> Performed<&'static str> {
    perform(
        home,
        "schedule_edit",
        crate::sweep::display_path(&plan.replacement.unit_directory),
        None,
        || {
            crate::schedule::edit_configured_scan(
                executable, plan, token, frequency, config, profile,
            )
        },
        |status| {
            if *status == "active_and_enabled" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_schedule_edit(
    home: &Path,
    executable: &Path,
    plan: &crate::schedule::EditSchedulePreview,
    token: &str,
    frequency: crate::schedule::Frequency,
) -> Performed<&'static str> {
    perform(
        home,
        "schedule_edit",
        crate::sweep::display_path(&plan.replacement.unit_directory),
        None,
        || crate::schedule::edit_scan(executable, plan, token, frequency),
        |status| {
            if *status == "active_and_enabled" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_schedule_removal(
    home: &Path,
    plan: &crate::schedule::RemoveSchedulePreview,
    token: &str,
) -> Performed<&'static str> {
    perform(
        home,
        "schedule_remove",
        crate::sweep::display_path(&plan.existing.unit_directory),
        None,
        || crate::schedule::remove_scan(plan, token),
        |status| {
            if *status == "units_absent" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_schedule_disable(
    home: &Path,
    plan: &crate::schedule::DisableSchedulePreview,
    token: &str,
) -> Performed<&'static str> {
    perform(
        home,
        "schedule_disable",
        crate::sweep::display_path(&plan.unit_directory),
        None,
        || crate::schedule::disable_scan(plan, token),
        |status| {
            if *status == "inactive_and_disabled" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_configured_schedule_install(
    home: &Path,
    executable: &Path,
    plan: &crate::schedule::ScanSchedulePreview,
    token: &str,
    frequency: crate::schedule::Frequency,
    config: Option<&Path>,
    profile: Option<&str>,
) -> Performed<&'static str> {
    perform(
        home,
        "schedule_install",
        crate::sweep::display_path(&plan.unit_directory),
        None,
        || {
            crate::schedule::install_configured_scan(
                executable, plan, token, frequency, config, profile,
            )
        },
        |status| {
            if *status == "active_and_enabled" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_schedule_install(
    home: &Path,
    executable: &Path,
    plan: &crate::schedule::ScanSchedulePreview,
    token: &str,
    frequency: crate::schedule::Frequency,
) -> Performed<&'static str> {
    perform(
        home,
        "schedule_install",
        crate::sweep::display_path(&plan.unit_directory),
        None,
        || crate::schedule::install_scan(executable, plan, token, frequency),
        |status| {
            if *status == "active_and_enabled" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_go_test_expiration(
    home: &Path,
    plan: &crate::cache::GoTestExpirationPlan,
    token: &str,
) -> Performed<crate::cache::GoTestExpirationResult> {
    perform(
        home,
        "go_test_cache_expiration",
        crate::sweep::display_path(&plan.cache_path),
        None,
        || crate::cache::expire_go_test_cache(plan, token),
        |result| {
            if result.verification == "marker_matches" {
                (
                    "completed",
                    Some(format!(
                        "{}; changed={}",
                        result.verification, result.changed
                    )),
                )
            } else {
                ("unverified", Some(result.verification.into()))
            }
        },
    )
}

pub fn perform_container_removal(
    home: &Path,
    plan: &crate::containers::RemovalPlan,
    token: &str,
) -> Performed<&'static str> {
    perform(
        home,
        "container_remove",
        format!("{}:{}", plan.engine, plan.container_id),
        plan.writable_bytes,
        || crate::containers::remove_stopped(plan, token),
        |status| {
            if *status == "verified_absent" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_image_removal(
    home: &Path,
    plan: &crate::containers::ImageRemovalPlan,
    token: &str,
) -> Performed<&'static str> {
    perform(
        home,
        "container_image_remove",
        format!("{}:{}", plan.engine, plan.image_id),
        plan.size_bytes,
        || crate::containers::remove_image(plan, token),
        |status| {
            if *status == "verified_absent" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_build_cache_removal(
    home: &Path,
    plan: &crate::containers::BuildCacheRemovalPlan,
    token: &str,
) -> Performed<&'static str> {
    perform(
        home,
        "build_cache_remove",
        format!("docker:{}:{}", plan.builder, plan.cache_id),
        plan.size_bytes,
        || crate::containers::remove_build_cache(plan, token),
        |status| {
            if *status == "verified_absent" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_network_removal(
    home: &Path,
    plan: &crate::containers::NetworkRemovalPlan,
    token: &str,
) -> Performed<&'static str> {
    perform(
        home,
        "container_network_remove",
        format!("{}:{}", plan.engine, plan.network_id),
        None,
        || crate::containers::remove_network(plan, token),
        |status| {
            if *status == "verified_absent" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_trash_removal(
    home: &Path,
    plan: &crate::trash::TrashRemovalPlan,
    token: &str,
) -> Performed<&'static str> {
    if !history_targets_are_safe(home, &[plan.location.join("files")]) {
        return Performed {
            result: Err(
                "operation history location overlaps the selected Trash data or cannot be resolved"
                    .into(),
            ),
            history_warning: None,
        };
    }
    perform(
        home,
        "trash_remove",
        format!(
            "{} / {}",
            crate::sweep::display_path(&plan.location),
            plan.name
        ),
        Some(plan.logical_bytes),
        || crate::trash::remove_file(plan, token),
        |status| {
            if *status == "verified_absent" {
                ("completed", Some((*status).into()))
            } else {
                ("unverified", Some((*status).into()))
            }
        },
    )
}

pub fn perform_trash_batch(
    home: &Path,
    plan: &crate::trash::TrashBatchPlan,
    token: &str,
) -> Performed<crate::trash::TrashBatchResult> {
    perform_trash_batch_with_progress(
        home,
        plan,
        token,
        &std::sync::atomic::AtomicBool::new(false),
        |_, _| {},
    )
}

pub fn perform_trash_batch_with_progress(
    home: &Path,
    plan: &crate::trash::TrashBatchPlan,
    token: &str,
    cancel: &std::sync::atomic::AtomicBool,
    progress: impl FnMut(usize, usize),
) -> Performed<crate::trash::TrashBatchResult> {
    let files = plan
        .items
        .iter()
        .map(|item| item.location.join("files"))
        .collect::<Vec<_>>();
    if !history_targets_are_safe(home, &files) {
        return Performed {
            result: Err(
                "operation history location overlaps selected Trash data or cannot be resolved"
                    .into(),
            ),
            history_warning: None,
        };
    }
    let target = plan
        .items
        .iter()
        .map(|item| {
            format!(
                "{} / {}",
                crate::sweep::display_path(&item.location),
                item.name
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let estimate = plan
        .items
        .iter()
        .try_fold(0u64, |sum, item| sum.checked_add(item.logical_bytes));
    perform(
        home,
        "trash_batch_remove",
        target,
        estimate,
        || crate::trash::remove_batch_with_progress(plan, token, cancel, progress),
        |result| {
            (
                result.outcome,
                Some(
                    result
                        .items
                        .iter()
                        .map(|item| {
                            format!(
                                "{} / {}: {}{}",
                                crate::sweep::display_path(&item.location),
                                item.name,
                                item.status,
                                item.error
                                    .as_ref()
                                    .map_or(String::new(), |error| format!(" ({error})"))
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                ),
            )
        },
    )
}

#[cfg(target_os = "linux")]
pub fn perform_scheduled_trash_retention(
    home: &Path,
    executable: &Path,
    config_path: &Path,
    location: &Path,
    age: std::time::Duration,
    scope_token: &str,
    cancel: &std::sync::atomic::AtomicBool,
) -> Performed<crate::scheduled_trash_cleanup::Report> {
    if !history_targets_are_safe(home, &[location.join("files")]) {
        return Performed {
            result: Err(
                "operation history location overlaps scheduled Trash data or cannot be resolved"
                    .into(),
            ),
            history_warning: None,
        };
    }
    let mut performed = perform_with_failure_detail(
        home,
        "scheduled_trash_retention",
        "scheduled Trash retention".into(),
        None,
        Some("scheduled Trash retention failed; inspect the command result for details"),
        || {
            crate::scheduled_trash_cleanup::run(
                executable,
                config_path,
                location,
                age,
                scope_token,
                false,
                cancel,
            )
        },
        |report| {
            (
                report.outcome,
                Some(format!(
                    "{} eligible; {} removed; {} deferred; {} skipped",
                    report.eligible, report.removed, report.deferred, report.skipped
                )),
            )
        },
    );
    if performed.history_warning.is_some()
        && let Ok(report) = &mut performed.result
    {
        if report.outcome == "completed" {
            report.outcome = "partial";
        }
        report.warnings.push(
            "Scheduled Trash retention summary could not be recorded in local history.".into(),
        );
    }
    performed
}

#[cfg(target_os = "linux")]
fn perform_trash_retention_schedule_change(
    home: &Path,
    operation: &'static str,
    action: impl FnOnce() -> Result<&'static str>,
) -> Performed<&'static str> {
    perform_with_failure_detail(
        home,
        operation,
        "scheduled Trash retention".into(),
        None,
        Some("scheduled Trash timer change failed; inspect the command result for details"),
        action,
        |status| {
            (
                if matches!(
                    *status,
                    "active_and_enabled" | "inactive_and_disabled" | "units_absent"
                ) {
                    "completed"
                } else {
                    "unverified"
                },
                Some((*status).into()),
            )
        },
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn perform_trash_retention_install(
    home: &Path,
    plan: &crate::schedule::trash_retention::TrashRetentionSchedulePreview,
    token: &str,
) -> Performed<&'static str> {
    perform_trash_retention_schedule_change(home, "scheduled_trash_retention_install", || {
        crate::schedule::trash_retention::install_trash_retention(plan, token)
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn perform_trash_retention_enable(
    home: &Path,
    plan: &crate::schedule::trash_retention::TrashRetentionActionPreview,
    token: &str,
) -> Performed<&'static str> {
    perform_trash_retention_schedule_change(home, "scheduled_trash_retention_enable", || {
        crate::schedule::trash_retention::enable_trash_retention(plan, token)
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn perform_trash_retention_disable(
    home: &Path,
    plan: &crate::schedule::trash_retention::TrashRetentionActionPreview,
    token: &str,
) -> Performed<&'static str> {
    perform_trash_retention_schedule_change(home, "scheduled_trash_retention_disable", || {
        crate::schedule::trash_retention::disable_trash_retention(plan, token)
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn perform_trash_retention_remove(
    home: &Path,
    plan: &crate::schedule::trash_retention::TrashRetentionActionPreview,
    token: &str,
) -> Performed<&'static str> {
    perform_trash_retention_schedule_change(home, "scheduled_trash_retention_remove", || {
        crate::schedule::trash_retention::remove_trash_retention(plan, token)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::path::PathBuf;

    #[test]
    fn formats_timestamps_as_utc_and_preserves_out_of_range_values() {
        assert_eq!(format_timestamp(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_timestamp(1), "1970-01-01 00:00:01 UTC");
        for timestamp in [i64::MAX as u64, u64::MAX] {
            assert_eq!(
                format_timestamp(timestamp),
                format!("Unix seconds {timestamp}")
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn history_target_overlap_detects_components_and_symlink_aliases() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let history = home.join("history");
        let descendant = history.join("cache");
        let sibling = dir.path().join("sibling");
        std::fs::create_dir_all(&descendant).unwrap();
        std::fs::create_dir(&sibling).unwrap();
        assert!(!history_targets_are_safe(
            &home,
            std::slice::from_ref(&descendant)
        ));
        assert!(!history_targets_are_safe(
            &home,
            std::slice::from_ref(&home)
        ));
        assert!(history_targets_are_safe(
            &home,
            std::slice::from_ref(&sibling)
        ));
        let missing_home = dir.path().join("missing-home");
        assert!(history_targets_are_safe(
            &missing_home,
            std::slice::from_ref(&sibling)
        ));
        let relative_parent = PathBuf::from("../cache");
        assert!(!history_targets_are_safe(
            &home,
            std::slice::from_ref(&relative_parent)
        ));

        let dangling_home = dir.path().join("dangling-home");
        std::fs::create_dir(&dangling_home).unwrap();
        symlink(
            dir.path().join("missing-target"),
            dangling_home.join("history"),
        )
        .unwrap();
        assert!(resolve_path(&dangling_home.join("history")).is_none());
        assert!(!history_targets_are_safe(
            &dangling_home,
            std::slice::from_ref(&sibling)
        ));

        let file_prefix = dir.path().join("file-prefix");
        std::fs::write(&file_prefix, "fixture").unwrap();
        assert!(resolve_path(&file_prefix.join("child")).is_none());

        let alias_home = dir.path().join("alias-home");
        std::fs::create_dir(&alias_home).unwrap();
        symlink(&sibling, alias_home.join("history")).unwrap();
        assert!(!history_targets_are_safe(
            &alias_home,
            std::slice::from_ref(&sibling)
        ));

        let selected = dir.path().join("selected");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&selected).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let linked_home = selected.join("home");
        symlink(&outside, &linked_home).unwrap();
        assert!(
            resolve_path(&linked_home.join("history"))
                .unwrap()
                .starts_with(&outside)
        );
        assert!(!history_targets_are_safe(
            &linked_home,
            std::slice::from_ref(&selected)
        ));

        let real = dir.path().join("real");
        let target = real.join("item");
        let alias = dir.path().join("alias");
        let outside = dir.path().join("outside-history");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&real, &alias).unwrap();
        symlink(&outside, target.join("upkit")).unwrap();
        let linked_home = alias.join("item/upkit");
        let history_path = linked_home.join("history");
        let lexical_history = absolute_normalized_path(&history_path).unwrap();
        let lexical_target = absolute_normalized_path(&target).unwrap();
        let resolved_history = resolve_path(&history_path).unwrap();
        let resolved_target = resolve_path(&target).unwrap();
        assert!(!paths_overlap(&lexical_history, &lexical_target));
        assert!(!paths_overlap(&resolved_history, &resolved_target));
        assert!(!history_targets_are_safe(
            &linked_home,
            std::slice::from_ref(&target)
        ));

        let plan = crate::shared_cache_cleanup::CacheRemovalPlan {
            name: "Go build",
            target: target.clone(),
            classification: "shared build cache",
            consequence: "rebuild",
            logical_bytes: 0,
            entries: Vec::new(),
            preview_token: "fixture".into(),
            warning: "fixture",
        };
        let performed = perform_shared_cache_removal(
            &linked_home,
            &plan,
            "fixture",
            &std::sync::atomic::AtomicBool::new(false),
        );
        assert!(performed.result.unwrap_err().contains("history location"));
        assert!(!outside.join("history").exists());
        assert!(
            std::fs::symlink_metadata(target.join("upkit"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn records_outcomes_without_claiming_reclaimed_space() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        assert!(read(&home).unwrap().records.is_empty());
        assert!(!home.exists());
        let success = perform(
            &home,
            "fixture",
            "target\u{1b}[2J".into(),
            Some(123),
            || Ok(7),
            |_| ("completed", Some("verified".into())),
        );
        assert_eq!(success.result.unwrap(), 7);
        assert!(success.history_warning.is_none());
        let failure = perform::<()>(
            &home,
            "fixture",
            "other".into(),
            None,
            || anyhow::bail!("fixture failure"),
            |_| unreachable!(),
        );
        assert!(failure.result.is_err());
        let history = read(&home).unwrap();
        assert_eq!(history.records.len(), 2);
        let complete = history
            .records
            .iter()
            .find(|record| record.outcome == "completed")
            .unwrap();
        assert_eq!(complete.estimated_bytes, Some(123));
        assert!(!complete.target.contains('\u{1b}'));
        assert_eq!(complete.verified_reclaimed_bytes, None);
        assert!(
            history
                .records
                .iter()
                .any(|record| record.outcome == "failed_or_unknown")
        );
    }

    #[test]
    fn scheduled_trash_history_redacts_paths_from_failures() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let performed = perform_with_failure_detail::<()>(
            &home,
            "scheduled_trash_retention",
            "scheduled Trash retention".into(),
            None,
            Some("scheduled Trash retention failed; inspect the command result for details"),
            || anyhow::bail!("/home/alice/.local/share/Trash/files/private-name changed"),
            |_| unreachable!(),
        );
        assert!(performed.result.is_err());
        let history = read(&home).unwrap();
        let record = history.records.first().unwrap();
        assert_eq!(record.target, "scheduled Trash retention");
        assert_eq!(
            record.detail.as_deref(),
            Some("scheduled Trash retention failed; inspect the command result for details")
        );
        assert!(!record.detail.as_deref().unwrap().contains("private-name"));
    }

    #[test]
    fn scheduled_scan_history_redacts_paths_from_failures() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let root = dir.path().join("private-workspace");
        let failure_detail = "scheduled scan failed; inspect the command result for details";
        let performed = perform_with_failure_detail::<()>(
            &home,
            "scheduled_scan",
            "configured workspace scan (roots: 1)".into(),
            None,
            Some(failure_detail),
            || anyhow::bail!("inspect scan root {}", root.display()),
            |_| unreachable!(),
        );
        assert!(performed.result.is_err());
        let history = read(&home).unwrap();
        let record = history.records.first().unwrap();
        assert_eq!(record.target, "configured workspace scan (roots: 1)");
        assert_eq!(record.detail.as_deref(), Some(failure_detail));
        assert!(
            !serde_json::to_string(&history)
                .unwrap()
                .contains(&root.display().to_string())
        );
    }

    #[test]
    fn subtotal_excludes_estimates_and_reports_overflow() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let record = |verified| Record {
            id: 0,
            started_unix: 1,
            finished_unix: Some(2),
            duration_ms: 1,
            operation: "fixture".into(),
            target: "target".into(),
            outcome: "completed".into(),
            detail: None,
            estimated_bytes: Some(1000),
            verified_reclaimed_bytes: verified,
            platform: "fixture".into(),
        };
        write_record(home, record(Some(12))).unwrap();
        write_record(home, record(None)).unwrap();
        write_record(home, record(Some(3))).unwrap();
        let history = read(home).unwrap();
        assert_eq!(history.known_reclaimed_bytes, Some(15));
        assert_eq!(history.records_without_verified_reclaimed_bytes, 1);
        write_record(home, record(Some(u64::MAX))).unwrap();
        let history = read(home).unwrap();
        assert_eq!(history.known_reclaimed_bytes, None);
        assert!(
            history
                .warnings
                .iter()
                .any(|warning| warning.contains("exceeds"))
        );
    }

    #[test]
    fn concurrent_writers_use_distinct_slots_and_capacity_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let home = &home;
                scope.spawn(move || {
                    let result = perform(
                        home,
                        "fixture",
                        "target".into(),
                        None,
                        || Ok(()),
                        |_| ("completed", None),
                    );
                    assert!(result.history_warning.is_none());
                });
            }
        });
        assert_eq!(read(&home).unwrap().records.len(), 8);
        let path = home.join("history");
        for id in 8..MAX_RECORDS {
            fs::write(path.join(format!("{id:03}.json")), "occupied").unwrap();
        }
        let full = perform(
            &home,
            "fixture",
            "target".into(),
            None,
            || Ok(()),
            |_| ("completed", None),
        );
        assert!(full.result.is_ok());
        assert!(full.history_warning.unwrap().contains("history is full"));
        assert_eq!(fs::read_dir(path).unwrap().count(), MAX_RECORDS);
    }

    #[test]
    fn history_directory_scans_fail_closed_after_the_entry_limit() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let history_dir = home.join("history");
        fs::create_dir_all(&history_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&history_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for index in 0..=MAX_HISTORY_DIRECTORY_ENTRIES {
            fs::write(history_dir.join(format!("fixture-{index}")), b"fixture").unwrap();
        }
        let record = Record {
            id: 0,
            started_unix: 1,
            finished_unix: Some(2),
            duration_ms: 1,
            operation: "fixture".into(),
            target: "fixture".into(),
            outcome: "completed".into(),
            detail: None,
            estimated_bytes: None,
            verified_reclaimed_bytes: None,
            platform: "fixture".into(),
        };

        let error = write_record(&home, record).unwrap_err();
        assert!(format!("{error:#}").contains("too many entries"));
        assert!(!history_dir.join("000.json").exists());
        #[cfg(target_os = "linux")]
        assert!(read(&home).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn history_reservation_is_visible_and_keeps_other_writers_out_of_its_slot() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let pending = Record {
            id: 91,
            started_unix: 1,
            finished_unix: Some(2),
            duration_ms: 7,
            operation: "scheduled_artifact_removal".into(),
            target: "scheduled Rust artifact".into(),
            outcome: "completed".into(),
            detail: Some("would be ignored while pending".into()),
            estimated_bytes: Some(50),
            verified_reclaimed_bytes: Some(50),
            platform: "fixture".into(),
        };
        let reservation = reserve_history_record(&home, pending.clone()).unwrap();
        let history = read(&home).unwrap();
        assert_eq!(history.records.len(), 1);
        assert_eq!(history.records[0].id, 0);
        assert_eq!(history.records[0].outcome, "in_progress");
        assert_eq!(history.records[0].finished_unix, None);
        assert_eq!(history.records[0].duration_ms, 0);
        assert_eq!(history.records[0].verified_reclaimed_bytes, None);

        std::thread::scope(|scope| {
            for _ in 0..8 {
                let home = &home;
                scope.spawn(move || {
                    write_record(
                        home,
                        Record {
                            id: 0,
                            started_unix: 3,
                            finished_unix: Some(4),
                            duration_ms: 1,
                            operation: "parallel".into(),
                            target: "parallel writer".into(),
                            outcome: "completed".into(),
                            detail: None,
                            estimated_bytes: None,
                            verified_reclaimed_bytes: None,
                            platform: "fixture".into(),
                        },
                    )
                    .unwrap();
                });
            }
        });
        let parallel = read(&home)
            .unwrap()
            .records
            .into_iter()
            .filter(|record| record.operation == "parallel")
            .collect::<Vec<_>>();
        assert_eq!(parallel.len(), 8);
        assert!(parallel.iter().all(|record| record.id != 0));
        assert_eq!(
            parallel
                .iter()
                .map(|record| record.id)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            8
        );

        let mut completed = pending;
        completed.finished_unix = Some(10);
        completed.duration_ms = 9;
        completed.outcome = "completed".into();
        completed.detail = Some("verified_absent".into());
        completed.verified_reclaimed_bytes = None;
        reservation.finish(completed).unwrap();
        let history = read(&home).unwrap();
        let completed = history
            .records
            .iter()
            .find(|record| record.operation == "scheduled_artifact_removal")
            .unwrap();
        assert_eq!(completed.id, 0);
        assert_eq!(completed.outcome, "completed");
        assert_eq!(completed.finished_unix, Some(10));
        assert!(!home.join("history/000.reserve").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reserved_operation_writes_pending_history_before_running() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let performed = perform_reserved_with_failure_detail(
            &home,
            "scheduled_fixture",
            "configured fixture".into(),
            None,
            Some("scheduled fixture failed"),
            || {
                let history = read(&home).unwrap();
                assert_eq!(history.records.len(), 1);
                assert_eq!(history.records[0].outcome, "in_progress");
                assert_eq!(history.records[0].finished_unix, None);
                Ok(())
            },
            |_| ("completed", Some("fixture result".into())),
        );
        assert!(performed.result.is_ok());
        assert!(performed.history_warning.is_none());
        let history = read(&home).unwrap();
        assert_eq!(history.records.len(), 1);
        assert_eq!(history.records[0].outcome, "completed");
        assert!(history.records[0].finished_unix.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn crashed_history_reservation_remains_visible_and_purge_skips_it() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let reservation = reserve_history_record(
            &home,
            Record {
                id: 0,
                started_unix: 1,
                finished_unix: None,
                duration_ms: 0,
                operation: "scheduled_artifact_cleanup".into(),
                target: "configured project artifacts (roots: 1)".into(),
                outcome: "in_progress".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "fixture".into(),
            },
        )
        .unwrap();
        drop(reservation);
        let history = read(&home).unwrap();
        assert_eq!(history.records.len(), 1);
        assert_eq!(history.records[0].outcome, "in_progress");
        assert_eq!(history.records[0].finished_unix, None);
        let plan = preview_history_purge(&home, std::time::Duration::ZERO, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(plan.record_count, 1);
        assert_eq!(plan.skipped_unfinished_records, 1);
        assert!(plan.candidates.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn torn_final_record_falls_back_to_the_pending_attempt() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let reservation = reserve_history_record(
            &home,
            Record {
                id: 0,
                started_unix: 1,
                finished_unix: None,
                duration_ms: 0,
                operation: "scheduled_artifact_cleanup".into(),
                target: "configured project artifacts (roots: 1)".into(),
                outcome: "in_progress".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "fixture".into(),
            },
        )
        .unwrap();
        drop(reservation);
        let final_path = home.join("history/000.json");
        fs::write(&final_path, b"{partial").unwrap();
        fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600)).unwrap();

        let history = read(&home).unwrap();
        assert_eq!(history.records.len(), 1);
        assert_eq!(history.records[0].id, 0);
        assert_eq!(history.records[0].outcome, "in_progress");
        assert!(
            history
                .warnings
                .iter()
                .any(|warning| warning.contains("incomplete final write"))
        );
        let plan = preview_history_purge(&home, std::time::Duration::ZERO, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(plan.skipped_unfinished_records, 1);
        assert!(plan.candidates.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn purge_removes_a_stale_reservation_with_its_completed_record() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let pending = Record {
            id: 0,
            started_unix: 1,
            finished_unix: None,
            duration_ms: 0,
            operation: "scheduled_artifact_removal".into(),
            target: "scheduled Rust artifact".into(),
            outcome: "in_progress".into(),
            detail: None,
            estimated_bytes: None,
            verified_reclaimed_bytes: None,
            platform: "fixture".into(),
        };
        let reservation = reserve_history_record(&home, pending.clone()).unwrap();
        let pending_bytes = reservation.pending_bytes.clone();
        let mut completed = pending;
        completed.finished_unix = Some(2);
        completed.duration_ms = 1;
        completed.outcome = "completed".into();
        reservation.finish(completed).unwrap();
        let reservation_path = home.join("history/000.reserve");
        fs::write(&reservation_path, pending_bytes).unwrap();
        fs::set_permissions(&reservation_path, fs::Permissions::from_mode(0o600)).unwrap();

        let plan = preview_history_purge(&home, std::time::Duration::ZERO, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(plan.candidates.len(), 1);
        let result = purge_history(
            &home,
            std::time::Duration::ZERO,
            &plan.preview_token,
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(result.outcome, "completed");
        assert!(!home.join("history/000.json").exists());
        assert!(!reservation_path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reservation_does_not_follow_a_symlinked_slot() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let outside = dir.path().join("outside.json");
        fs::write(&outside, "private fixture").unwrap();
        fs::create_dir_all(home.join("history")).unwrap();
        fs::set_permissions(home.join("history"), fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&outside, home.join("history/000.reserve")).unwrap();

        let reservation = reserve_history_record(
            &home,
            Record {
                id: 0,
                started_unix: 1,
                finished_unix: None,
                duration_ms: 0,
                operation: "scheduled_artifact_cleanup".into(),
                target: "configured project artifacts".into(),
                outcome: "in_progress".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "fixture".into(),
            },
        )
        .unwrap();
        assert_eq!(reservation.id, 1);
        assert_eq!(fs::read(&outside).unwrap(), b"private fixture");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reservation_refuses_to_finalize_after_its_pending_file_changes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let pending = Record {
            id: 0,
            started_unix: 1,
            finished_unix: None,
            duration_ms: 0,
            operation: "scheduled_artifact_removal".into(),
            target: "scheduled Rust artifact".into(),
            outcome: "in_progress".into(),
            detail: None,
            estimated_bytes: None,
            verified_reclaimed_bytes: None,
            platform: "fixture".into(),
        };
        let reservation = reserve_history_record(&home, pending.clone()).unwrap();
        let changed_path = home.join("history/000.reserve");
        let mut changed = pending.clone();
        changed.target = "different target".into();
        fs::write(&changed_path, serde_json::to_vec(&changed).unwrap()).unwrap();
        fs::set_permissions(&changed_path, fs::Permissions::from_mode(0o600)).unwrap();

        let mut completed = pending;
        completed.finished_unix = Some(2);
        completed.outcome = "completed".into();
        assert!(reservation.finish(completed).is_err());
        assert!(!home.join("history/000.json").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scheduled_action_does_not_start_when_history_cannot_reserve_a_slot() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let record = || Record {
            id: 0,
            started_unix: 1,
            finished_unix: Some(2),
            duration_ms: 1,
            operation: "fixture".into(),
            target: "fixture".into(),
            outcome: "completed".into(),
            detail: None,
            estimated_bytes: None,
            verified_reclaimed_bytes: None,
            platform: "fixture".into(),
        };
        for _ in 0..MAX_RECORDS {
            write_record(&home, record()).unwrap();
        }
        let ran = AtomicBool::new(false);
        let performed = perform_reserved_with_failure_detail(
            &home,
            "scheduled_fixture",
            "fixture target".into(),
            None,
            Some("scheduled fixture failed"),
            || {
                ran.store(true, Ordering::Relaxed);
                Ok(())
            },
            |_| ("completed", None),
        );
        assert!(!ran.load(Ordering::Relaxed));
        assert!(performed.result.is_err());
        assert!(
            performed
                .history_warning
                .unwrap()
                .contains("history is full")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scheduled_artifact_cancellation_distinguishes_partial_work() {
        let mut report = crate::scheduled_cleanup::ArtifactReport {
            candidates: 1,
            selected: 1,
            inspected: 1,
            items: vec![crate::scheduled_cleanup::ArtifactItem {
                ordinal: 1,
                ecosystem: "cargo",
                status: "not_attempted_cancelled",
                logical_bytes: None,
                detail: None,
                history_warning: None,
            }],
            complete: false,
            cancelled: true,
            dry_run: false,
            warnings: Vec::new(),
            continue_with_bytecode: false,
        };
        assert_eq!(scheduled_artifact_outcome(&report), "cancelled");
        report.items[0].status = "verified_absent";
        assert_eq!(scheduled_artifact_outcome(&report), "partial");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scheduled_bytecode_paths_do_not_start_when_history_is_full() {
        let dir = tempfile::tempdir().unwrap();
        let record = || Record {
            id: 0,
            started_unix: 1,
            finished_unix: Some(2),
            duration_ms: 1,
            operation: "fixture".into(),
            target: "fixture".into(),
            outcome: "completed".into(),
            detail: None,
            estimated_bytes: None,
            verified_reclaimed_bytes: None,
            platform: "fixture".into(),
        };

        let cleanup_home = dir.path().join("cleanup-home");
        for _ in 0..MAX_RECORDS {
            write_record(&cleanup_home, record()).unwrap();
        }
        let cleanup = perform_scheduled_cleanup(
            &cleanup_home,
            Path::new("unused-executable"),
            &[],
            &[],
            "invalid-policy-token",
            &AtomicBool::new(false),
        );
        assert!(
            cleanup
                .result
                .unwrap_err()
                .contains("history could not be reserved before action")
        );

        let removal_home = dir.path().join("removal-home");
        for _ in 0..MAX_RECORDS {
            write_record(&removal_home, record()).unwrap();
        }
        let plan = crate::bytecode::BytecodePlan {
            project: PathBuf::new(),
            manifest: PathBuf::new(),
            cache: PathBuf::new(),
            source: PathBuf::new(),
            file: PathBuf::new(),
            python: "python",
            invalidation: "checked-hash",
            logical_bytes: 1,
            preview_token: String::new(),
            git_evidence_id: None,
            warning: "fixture",
            scope: crate::sweep::Scope {
                roots: vec![],
                exclusions: vec![],
                older_than_seconds: None,
                enabled: None,
            },
        };
        let guard_ran = AtomicBool::new(false);
        let removal = perform_scheduled_bytecode_removal(
            &removal_home,
            &plan,
            &AtomicBool::new(false),
            &|| {
                guard_ran.store(true, Ordering::Relaxed);
                Ok(())
            },
        );
        assert!(!guard_ran.load(Ordering::Relaxed));
        assert!(
            removal
                .result
                .unwrap_err()
                .contains("history could not be reserved before action")
        );
    }

    #[test]
    fn oversized_target_is_truncated_and_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let result = perform(
            &home,
            "fixture",
            "é\\\u{1b}".repeat(MAX_BYTES as usize),
            None,
            || Ok(()),
            |_| ("completed", None),
        );
        assert!(result.history_warning.is_none());
        let history = read(&home).unwrap();
        assert_eq!(history.records.len(), 1);
        assert!(history.records[0].target.ends_with("...[truncated]"));
        assert!(!history.records[0].target.contains('\u{1b}'));
        assert!(fs::metadata(home.join("history/000.json")).unwrap().len() <= MAX_BYTES);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn history_writes_and_reads_through_a_symlinked_home_ancestor() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real_home = dir.path().join("real-home");
        let home_alias = dir.path().join("home-alias");
        fs::create_dir(&real_home).unwrap();
        symlink(&real_home, &home_alias).unwrap();

        let performed = perform(
            &home_alias,
            "fixture_operation",
            "fixture_target".into(),
            None,
            || Ok(()),
            |_| ("completed", None),
        );
        assert!(performed.history_warning.is_none());
        let history = read(&home_alias).unwrap();
        assert_eq!(history.records.len(), 1);
        assert_eq!(history.records[0].operation, "fixture_operation");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn temporary_cleanup_records_each_target_and_result() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let selected = vec![
            PathBuf::from("fixture-host-path/.upkit-link-removed"),
            PathBuf::from("fixture-host-path/.upkit-link-quarantined"),
        ];
        let result = crate::temp_cleanup::CleanupResult {
            outcome: "partial",
            removed_count: 1,
            items: vec![
                crate::temp_cleanup::ItemResult {
                    path: selected[0].clone(),
                    status: "removed",
                    error: None,
                },
                crate::temp_cleanup::ItemResult {
                    path: selected[1].clone(),
                    status: "quarantined",
                    error: Some("directory remains in quarantine".into()),
                },
            ],
        };
        let performed = perform_temp_cleanup_with(&home, &selected, || Ok(result));
        assert_eq!(performed.result.unwrap().outcome, "partial");
        let mut records = read(&home).unwrap().records;
        records.sort_by_key(|record| record.id);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].target, selected[0].display().to_string());
        assert_eq!(records[0].outcome, "completed");
        assert_eq!(records[0].detail.as_deref(), Some("removed"));
        assert_eq!(records[1].target, selected[1].display().to_string());
        assert_eq!(records[1].outcome, "failed_or_unknown");
        assert_eq!(
            records[1].detail.as_deref(),
            Some("directory remains in quarantine")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn temporary_cleanup_runs_once_and_reports_history_capacity_failure() {
        use std::cell::Cell;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        for _ in 0..MAX_RECORDS {
            let result = perform(
                &home,
                "fixture",
                "target".into(),
                None,
                || Ok(()),
                |_| ("completed", None),
            );
            assert!(result.history_warning.is_none());
        }
        let selected = vec![PathBuf::from("fixture/.upkit-link-selected")];
        let executions = Cell::new(0);
        let performed = perform_temp_cleanup_with(&home, &selected, || {
            executions.set(executions.get() + 1);
            Ok(crate::temp_cleanup::CleanupResult {
                outcome: "completed",
                removed_count: 1,
                items: vec![crate::temp_cleanup::ItemResult {
                    path: selected[0].clone(),
                    status: "removed",
                    error: None,
                }],
            })
        });
        assert_eq!(executions.get(), 1);
        assert_eq!(performed.result.unwrap().outcome, "completed");
        assert!(
            performed
                .history_warning
                .unwrap()
                .contains("history is full")
        );
        assert_eq!(read(&home).unwrap().records.len(), MAX_RECORDS);
    }

    #[cfg(target_os = "linux")]
    fn purge_fixture(home: &Path, finished_unix: u64) {
        let started_unix = finished_unix.saturating_sub(1);
        write_record(
            home,
            Record {
                id: 0,
                started_unix,
                finished_unix: Some(finished_unix),
                duration_ms: 1,
                operation: "fixture_operation".into(),
                target: "fixture_target".into(),
                outcome: "completed".into(),
                detail: None,
                estimated_bytes: None,
                verified_reclaimed_bytes: None,
                platform: "fixture".into(),
            },
        )
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn history_purge_ignores_only_bounded_probe_names_without_following_them() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let outside = dir.path().join("outside");
        fs::write(&outside, "private fixture").unwrap();
        purge_fixture(&home, 1);
        let probe = home.join("history/.upkit-write-probe-4242-0");
        symlink(&outside, &probe).unwrap();

        let plan = preview_history_purge(&home, std::time::Duration::ZERO, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(plan.candidates.len(), 1);
        let result = purge_history(
            &home,
            std::time::Duration::ZERO,
            &plan.preview_token,
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(result.outcome, "completed");
        assert_eq!(fs::read(&outside).unwrap(), b"private fixture");
        assert!(
            fs::symlink_metadata(&probe)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn history_purge_preserves_and_tokens_a_partial_reservation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        purge_fixture(&home, 1);
        let partial = home.join("history/001.reserve");
        fs::write(&partial, b"{partial").unwrap();
        fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).unwrap();
        let original = fs::read(&partial).unwrap();

        let initial =
            preview_history_purge(&home, std::time::Duration::ZERO, &AtomicBool::new(false))
                .unwrap();
        assert_eq!(initial.candidates.len(), 1);
        assert_eq!(initial.candidates[0].id, 0);
        assert_eq!(fs::read(&partial).unwrap(), original);

        fs::write(&partial, b"{changed").unwrap();
        fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).unwrap();
        let fresh =
            preview_history_purge(&home, std::time::Duration::ZERO, &AtomicBool::new(false))
                .unwrap();
        assert_ne!(initial.preview_token, fresh.preview_token);
        assert!(
            purge_history(
                &home,
                std::time::Duration::ZERO,
                &initial.preview_token,
                &AtomicBool::new(false),
                |_, _| {},
            )
            .is_err()
        );
        assert!(home.join("history/000.json").exists());
        assert!(partial.exists());
        assert_eq!(fs::read(&partial).unwrap(), b"{changed");

        let result = purge_history(
            &home,
            std::time::Duration::ZERO,
            &fresh.preview_token,
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        assert_eq!(result.outcome, "completed");
        assert_eq!(result.items[0].id, 0);
        assert_eq!(result.items[0].status, "removed");
        assert!(!home.join("history/000.json").exists());
        assert!(partial.exists());
        assert_eq!(fs::read(&partial).unwrap(), b"{changed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn history_purge_bounds_ignored_probe_entries() {
        const LIMIT: usize = 32;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let history = home.join("history");
        fs::create_dir_all(&history).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for index in 0..LIMIT {
            fs::write(
                history.join(format!(".upkit-write-probe-4242-{index}")),
                b"fixture",
            )
            .unwrap();
        }

        assert!(
            preview_history_purge(&home, std::time::Duration::ZERO, &AtomicBool::new(false),)
                .is_ok()
        );
        fs::write(
            history.join(format!(".upkit-write-probe-4242-{LIMIT}")),
            b"fixture",
        )
        .unwrap();

        assert!(
            preview_history_purge(&home, std::time::Duration::ZERO, &AtomicBool::new(false),)
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn history_purge_reports_partial_results_when_cancelled_between_records() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        purge_fixture(&home, 1);
        purge_fixture(&home, 2);
        let age = std::time::Duration::from_secs(30 * 86400);
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let plan = preview_history_purge(&home, age, &cancel).unwrap();
        let callback_cancel = std::sync::Arc::clone(&cancel);

        let performed = perform_history_purge(
            &home,
            &plan,
            &plan.preview_token,
            &cancel,
            move |done, _| {
                if done == 1 {
                    callback_cancel.store(true, Ordering::Relaxed);
                }
            },
        );
        assert!(performed.history_warning.is_none());
        let result = performed.result.unwrap();

        assert_eq!(result.outcome, "partial");
        assert!(result.cancelled);
        assert_eq!(result.items[0].status, "removed");
        assert_eq!(result.items[1].status, "not_attempted_cancelled");
        let records = read(&home).unwrap().records;
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|record| record.id == 1));
        let summary = records
            .iter()
            .find(|record| record.operation == "history_purge")
            .unwrap();
        assert_eq!(summary.outcome, "partial");
        assert!(summary.detail.as_deref().unwrap().contains("removed=1"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn history_purge_waits_cancellably_for_directory_lock() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        purge_fixture(&home, 1);
        let age = std::time::Duration::from_secs(30 * 86400);
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let plan = preview_history_purge(&home, age, &cancel).unwrap();
        let history_dir = fs::File::open(home.join("history")).unwrap();
        rustix::fs::flock(
            &history_dir,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .unwrap();
        let thread_cancel = std::sync::Arc::clone(&cancel);
        let thread_home = home.clone();
        let token = plan.preview_token;
        let worker = std::thread::spawn(move || {
            purge_history(&thread_home, age, &token, &thread_cancel, |_, _| {})
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        cancel.store(true, Ordering::Relaxed);
        assert!(worker.join().unwrap().is_err());
        assert!(home.join("history/000.json").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn empty_history_purge_does_not_create_an_operation_record() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let age = std::time::Duration::from_secs(30 * 86400);
        let cancel = AtomicBool::new(false);
        let plan = preview_history_purge(&home, age, &cancel).unwrap();

        let performed =
            perform_history_purge(&home, &plan, &plan.preview_token, &cancel, |_, _| {});

        assert_eq!(performed.result.unwrap().outcome, "completed");
        assert!(performed.history_warning.is_none());
        assert!(!home.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn history_purge_without_eligible_records_does_not_write_a_summary() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        purge_fixture(&home, now);
        let before = fs::read(home.join("history/000.json")).unwrap();
        let cancel = AtomicBool::new(false);
        let plan =
            preview_history_purge(&home, std::time::Duration::from_secs(86400), &cancel).unwrap();
        assert!(plan.candidates.is_empty());

        let performed =
            perform_history_purge(&home, &plan, &plan.preview_token, &cancel, |_, _| {});

        assert_eq!(performed.result.unwrap().outcome, "completed");
        assert!(performed.history_warning.is_none());
        assert_eq!(fs::read(home.join("history/000.json")).unwrap(), before);
        assert_eq!(fs::read_dir(home.join("history")).unwrap().count(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_purge_warns_when_a_full_history_cannot_record_the_attempt() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for id in 0..MAX_RECORDS {
            let finished_unix = if id == 0 { 1 } else { now };
            write_record(
                &home,
                Record {
                    id,
                    started_unix: finished_unix.saturating_sub(1),
                    finished_unix: Some(finished_unix),
                    duration_ms: 1,
                    operation: "fixture_operation".into(),
                    target: format!("fixture_target_{id}"),
                    outcome: "completed".into(),
                    detail: None,
                    estimated_bytes: None,
                    verified_reclaimed_bytes: None,
                    platform: "fixture".into(),
                },
            )
            .unwrap();
        }
        let age = std::time::Duration::from_secs(30 * 86400);
        let cancel = AtomicBool::new(false);
        let plan = preview_history_purge(&home, age, &cancel).unwrap();
        assert_eq!(plan.candidates.len(), 1);
        let outside = dir.path().join("keep.json");
        fs::write(&outside, "fixture outside data").unwrap();
        fs::remove_file(home.join("history/000.json")).unwrap();
        symlink(&outside, home.join("history/000.json")).unwrap();
        fs::set_permissions(home.join("history"), fs::Permissions::from_mode(0o700)).unwrap();

        let performed =
            perform_history_purge(&home, &plan, &plan.preview_token, &cancel, |_, _| {});

        assert!(performed.result.is_err());
        assert!(
            performed
                .history_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("history is full"))
        );
        assert_eq!(fs::read_to_string(outside).unwrap(), "fixture outside data");
        assert_eq!(
            fs::read_dir(home.join("history")).unwrap().count(),
            MAX_RECORDS
        );
    }

    #[test]
    fn cancelled_artifact_batch_records_items_as_not_attempted() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let project = dir.path().join("project");
        let target = project.join("target");
        fs::create_dir(&project).unwrap();
        fs::create_dir(&target).unwrap();
        let scope = crate::sweep::Scope {
            roots: vec![project.clone()],
            exclusions: Vec::new(),
            older_than_seconds: None,
            enabled: None,
        };
        let plan = crate::artifact_cleanup::ArtifactBatchPlan {
            scope: scope.clone(),
            items: vec![crate::artifact_cleanup::ArtifactPlan {
                scope: scope.clone(),
                project: project.clone(),
                manifest: project.join("Cargo.toml"),
                target: target.clone(),
                ecosystem: "cargo",
                classification: "fixture",
                logical_bytes: 0,
                entries: Vec::new(),
                preview_token: "fixture".into(),
                #[cfg(target_os = "linux")]
                cargo_config_identity: None,
                #[cfg(target_os = "linux")]
                cargo_workspace_evidence: None,
                #[cfg(target_os = "linux")]
                git_evidence_id: None,
                warning: "fixture",
                reproduction_warning: None,
            }],
            preview_token: "fixture".into(),
            warning: "fixture",
        };
        let cancelled = std::sync::atomic::AtomicBool::new(true);

        let report = perform_artifact_batch(&home, &plan, "fixture", &cancelled);

        assert!(report.cancelled);
        assert!(!report.complete);
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].status, "not_attempted_cancelled");
        assert!(!report.items[0].attempted);
        assert!(target.is_dir());
        let history = read(&home).unwrap();
        assert_eq!(history.records.len(), 1);
        assert_eq!(history.records[0].outcome, "cancelled");
    }

    #[cfg(unix)]
    #[test]
    fn linked_history_directory_and_records_are_not_followed() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("data");
        let outside = dir.path().join("outside");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink(&outside, home.join("history")).unwrap();
        let result = perform(
            &home,
            "fixture",
            "target".into(),
            None,
            || Ok(()),
            |_| ("completed", None),
        );
        assert!(result.result.is_ok());
        assert!(result.history_warning.is_some());
        assert!(fs::read_dir(&outside).unwrap().next().is_none());
        fs::remove_file(home.join("history")).unwrap();
        fs::create_dir(home.join("history")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(home.join("history"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(outside.join("keep"), "secret").unwrap();
        symlink(outside.join("keep"), home.join("history/000.json")).unwrap();
        let history = read(&home).unwrap();
        assert!(history.records.is_empty());
        assert_eq!(history.warnings.len(), 1);
        assert_eq!(fs::read_to_string(outside.join("keep")).unwrap(), "secret");
    }
}
