//! Opt-in, bounded scheduled retention for one verified Linux Trash location.
use serde::Serialize;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::{path::Path, sync::atomic::AtomicBool, time::Duration};

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static TEST_CLOCK_UNIX_NANOS: std::cell::Cell<Option<i128>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(all(test, target_os = "linux"))]
#[derive(Clone)]
struct TestBusReplacement {
    root: PathBuf,
    socket: PathBuf,
    backup: PathBuf,
    calls: PathBuf,
    baseline: PathBuf,
}

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static TEST_BUS_REPLACEMENT: std::cell::RefCell<Option<TestBusReplacement>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(target_os = "linux")]
pub(crate) fn clock_now() -> chrono::DateTime<chrono::Utc> {
    #[cfg(test)]
    if let Some(nanos) = TEST_CLOCK_UNIX_NANOS.with(std::cell::Cell::get)
        && let Ok(seconds) = i64::try_from(nanos.div_euclid(1_000_000_000))
        && let Some(now) = chrono::DateTime::<chrono::Utc>::from_timestamp(
            seconds,
            nanos.rem_euclid(1_000_000_000) as u32,
        )
    {
        return now;
    }
    chrono::Utc::now()
}

#[cfg(all(test, target_os = "linux"))]
fn test_fixture_root(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path).ok()?;
    let root = path.canonicalize().ok()?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || root != path
    {
        return None;
    }
    Some(root)
}

#[cfg(all(test, target_os = "linux"))]
fn test_fixture_path(root: &Path, path: &Path, allow_missing: bool) -> Option<PathBuf> {
    use std::path::Component;

    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return None;
    }
    let metadata = std::fs::symlink_metadata(path);
    let resolved = match metadata {
        Ok(metadata) if !metadata.file_type().is_symlink() => path.canonicalize().ok()?,
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent()?.canonicalize().ok()?;
            parent.join(path.file_name()?)
        }
        _ => return None,
    };
    (resolved == path && resolved.starts_with(root)).then_some(resolved)
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) struct TestClockGuard(Option<i128>);

#[cfg(all(test, target_os = "linux"))]
impl TestClockGuard {
    fn set(now: chrono::DateTime<chrono::Utc>) -> Self {
        let nanos = now
            .timestamp_nanos_opt()
            .expect("test clock must be in the supported range");
        Self(TEST_CLOCK_UNIX_NANOS.with(|clock| clock.replace(Some(i128::from(nanos)))))
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for TestClockGuard {
    fn drop(&mut self) {
        TEST_CLOCK_UNIX_NANOS.with(|clock| clock.set(self.0));
    }
}

#[cfg(all(test, target_os = "linux"))]
struct TestBusReplacementGuard(Option<TestBusReplacement>);

#[cfg(all(test, target_os = "linux"))]
impl TestBusReplacementGuard {
    fn install(root: &Path, socket: &Path, backup: &Path, calls: &Path, baseline: &Path) -> Self {
        Self(TEST_BUS_REPLACEMENT.with(|slot| {
            slot.replace(Some(TestBusReplacement {
                root: root.to_owned(),
                socket: socket.to_owned(),
                backup: backup.to_owned(),
                calls: calls.to_owned(),
                baseline: baseline.to_owned(),
            }))
        }))
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for TestBusReplacementGuard {
    fn drop(&mut self) {
        TEST_BUS_REPLACEMENT.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}

#[derive(Debug, Serialize)]
pub struct ItemResult {
    pub ordinal: usize,
    pub status: &'static str,
    pub warning: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub outcome: &'static str,
    pub eligible: usize,
    pub removed: usize,
    pub deferred: usize,
    pub skipped: usize,
    pub cancelled: bool,
    pub dry_run: bool,
    pub items: Vec<ItemResult>,
    pub warnings: Vec<String>,
}

fn validate_age(age: Duration) -> anyhow::Result<()> {
    if age < Duration::from_secs(crate::trash::MIN_SCHEDULED_TRASH_RETENTION_SECONDS) {
        anyhow::bail!("scheduled Trash retention age must be at least 30 days");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn trusted_executable_parents(path: &Path) -> anyhow::Result<Vec<(PathBuf, Vec<u8>)>> {
    use anyhow::{Context, bail};
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    use std::os::unix::fs::MetadataExt;

    let uid = rustix::process::geteuid().as_raw();
    let mut directories = Vec::new();
    for parent in path.ancestors().skip(1) {
        if parent.as_os_str().is_empty() {
            continue;
        }
        let directory = std::fs::File::from(
            openat2(
                rustix::fs::CWD,
                parent,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .with_context(|| format!("open scheduled executable parent {parent:?}"))?,
        );
        let metadata = directory
            .metadata()
            .context("inspect scheduled executable parent")?;
        let trusted_owner = metadata.uid() == 0 || metadata.uid() == uid;
        let trusted_sticky_directory = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || !trusted_owner
            || (metadata.mode() & 0o022 != 0 && !trusted_sticky_directory)
        {
            bail!("scheduled executable parent is writable by an untrusted user");
        }
        let mut identity = Vec::new();
        identity.extend_from_slice(&metadata.dev().to_be_bytes());
        identity.extend_from_slice(&metadata.ino().to_be_bytes());
        identity.extend_from_slice(&metadata.uid().to_be_bytes());
        identity.extend_from_slice(&metadata.mode().to_be_bytes());
        identity.extend_from_slice(&metadata.ctime().to_be_bytes());
        identity.extend_from_slice(&metadata.ctime_nsec().to_be_bytes());
        directories.push((parent.to_owned(), identity));
    }
    Ok(directories)
}

#[cfg(target_os = "linux")]
fn executable_identity(path: &Path) -> anyhow::Result<Vec<u8>> {
    use anyhow::{Context, bail};
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    use std::os::unix::fs::MetadataExt;

    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        || path
            .canonicalize()
            .context("resolve scheduled executable")?
            != path
    {
        bail!("scheduled executable path must be canonical and absolute");
    }
    let parents = trusted_executable_parents(path)?;
    let file = std::fs::File::from(
        openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .context("open scheduled executable without links")?,
    );
    let before = file.metadata().context("inspect scheduled executable")?;
    let uid = rustix::process::geteuid().as_raw();
    if !before.is_file()
        || (before.uid() != 0 && before.uid() != uid)
        || before.mode() & 0o022 != 0
        || before.mode() & 0o111 == 0
        || before.nlink() != 1
    {
        bail!("scheduled executable is not a trusted single-link executable file");
    }
    let after = file.metadata().context("recheck scheduled executable")?;
    let current = std::fs::File::from(
        openat2(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .context("reopen scheduled executable")?,
    );
    let reopened = current
        .metadata()
        .context("recheck scheduled executable path")?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.len() != after.len()
        || before.dev() != reopened.dev()
        || before.ino() != reopened.ino()
        || before.ctime() != reopened.ctime()
        || before.ctime_nsec() != reopened.ctime_nsec()
        || before.len() != reopened.len()
        || trusted_executable_parents(path)? != parents
    {
        bail!("scheduled executable changed while its identity was inspected");
    }
    let mut identity = Vec::new();
    identity.extend_from_slice(&before.dev().to_be_bytes());
    identity.extend_from_slice(&before.ino().to_be_bytes());
    identity.extend_from_slice(&before.uid().to_be_bytes());
    identity.extend_from_slice(&before.gid().to_be_bytes());
    identity.extend_from_slice(&before.mode().to_be_bytes());
    identity.extend_from_slice(&before.nlink().to_be_bytes());
    identity.extend_from_slice(&before.len().to_be_bytes());
    identity.extend_from_slice(&before.ctime().to_be_bytes());
    identity.extend_from_slice(&before.ctime_nsec().to_be_bytes());
    Ok(identity)
}

/// Compute the durable policy token shared by preview, installation, and execution.
#[cfg(target_os = "linux")]
pub(crate) fn scope_token(
    executable: &Path,
    config_path: &Path,
    location: &Path,
    age: Duration,
) -> anyhow::Result<String> {
    use anyhow::Context;

    validate_age(age)?;
    let executable_identity = executable_identity(executable)?;
    let config_identity = crate::config::scheduled_trash_config_token(config_path)?;
    let (location_identity, _) = crate::trash::scheduled_location_identity(location)?;
    let encoded_location = serde_json::to_vec(&location_identity)
        .context("encode scheduled Trash location identity")?;
    durable_scope_token(
        executable,
        &executable_identity,
        config_path,
        &config_identity,
        location,
        &encoded_location,
        age,
    )
}

#[cfg(target_os = "linux")]
fn durable_scope_token(
    executable: &Path,
    executable_identity: &[u8],
    config_path: &Path,
    config_identity: &str,
    location: &Path,
    encoded_location_identity: &[u8],
    age: Duration,
) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};

    let mut hash = Sha256::new();
    hash.update(b"upkit-scheduled-trash-retention-scope-v1\0");
    for value in [
        executable.as_os_str().as_encoded_bytes(),
        executable_identity,
        config_path.as_os_str().as_encoded_bytes(),
        config_identity.as_bytes(),
        location.as_os_str().as_encoded_bytes(),
        encoded_location_identity,
        age.as_secs().to_be_bytes().as_slice(),
        age.subsec_nanos().to_be_bytes().as_slice(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    Ok(hex::encode(hash.finalize()))
}

fn same_run_location_identity<T: PartialEq>(
    expected_identity: &T,
    expected_mount_id: u64,
    current_identity: &T,
    current_mount_id: u64,
) -> bool {
    expected_identity == current_identity && expected_mount_id == current_mount_id
}

fn cancelled_report(dry_run: bool) -> Report {
    Report {
        outcome: "cancelled",
        eligible: 0,
        removed: 0,
        deferred: 0,
        skipped: 0,
        cancelled: true,
        dry_run,
        items: Vec::new(),
        warnings: Vec::new(),
    }
}

fn redact_item_results(items: Vec<crate::trash::TrashBatchItemResult>) -> Vec<ItemResult> {
    items
        .into_iter()
        .enumerate()
        .map(|(index, item)| ItemResult {
            ordinal: index + 1,
            status: item.status,
            warning: item
                .error
                .as_ref()
                .map(|_| "removal did not complete; inspect the selected Trash location"),
        })
        .collect()
}

fn outcome_with_deferred(outcome: &'static str, deferred: usize) -> &'static str {
    if outcome == "completed" && deferred > 0 {
        "partial"
    } else {
        outcome
    }
}

/// Revalidate the bound policy and schedule, then run at most 32 removals.
/// The current clock is always read here; callers cannot supply a clock snapshot.
#[cfg(target_os = "linux")]
pub(crate) fn run(
    executable: &Path,
    config_path: &Path,
    location: &Path,
    age: Duration,
    expected_scope_token: &str,
    dry_run: bool,
    cancel: &AtomicBool,
) -> anyhow::Result<Report> {
    use anyhow::bail;
    use std::sync::atomic::Ordering;

    validate_age(age)?;
    let expected_scope = scope_token(executable, config_path, location, age)?;
    if expected_scope != expected_scope_token {
        bail!("scheduled Trash policy or scope changed; inspect and reinstall the schedule");
    }

    let (location_identity, mount_id) = crate::trash::scheduled_location_identity(location)?;
    let manager_bus_identity =
        crate::schedule::trash_retention::current_trash_retention_bus_identity()?;
    verify_trash_retention_schedule(
        executable,
        config_path,
        location,
        age,
        expected_scope_token,
        &manager_bus_identity,
    )?;
    if cancel.load(Ordering::Relaxed) {
        return Ok(cancelled_report(dry_run));
    }

    let preview = match crate::trash::scheduled_retention_preview(location, age, cancel) {
        Ok(preview) => preview,
        Err(_) if cancel.load(Ordering::Relaxed) => return Ok(cancelled_report(dry_run)),
        Err(error) => return Err(error),
    };
    if !same_run_location_identity(
        &location_identity,
        mount_id,
        &preview.location_identity,
        preview.mount_id,
    ) {
        bail!("scheduled Trash location or mount changed during inventory");
    }
    #[cfg(all(test, target_os = "linux"))]
    run_test_after_preview_hook()?;
    let snapshot = preview.snapshot_unix_nanos;
    let guard = || -> anyhow::Result<()> {
        validate_age(age)?;
        let token = scope_token(executable, config_path, location, age)?;
        if token != expected_scope_token {
            bail!("scheduled Trash policy or scope changed during removal");
        }
        let now = clock_now()
            .timestamp_nanos_opt()
            .map(i128::from)
            .ok_or_else(|| anyhow::anyhow!("scheduled clock is outside the supported range"))?;
        crate::trash::validate_scheduled_clock(snapshot, now)?;
        let (current_identity, current_mount_id) =
            crate::trash::scheduled_location_identity(location)?;
        if !same_run_location_identity(
            &location_identity,
            mount_id,
            &current_identity,
            current_mount_id,
        ) {
            bail!("scheduled Trash location or mount changed during removal");
        }
        verify_trash_retention_schedule(
            executable,
            config_path,
            location,
            age,
            expected_scope_token,
            &manager_bus_identity,
        )?;
        Ok(())
    };

    guard()?;
    let mut report = Report {
        outcome: outcome_with_deferred("completed", preview.deferred),
        eligible: preview.eligible,
        removed: 0,
        deferred: preview.deferred,
        skipped: preview.skipped,
        cancelled: false,
        dry_run,
        items: Vec::new(),
        warnings: Vec::new(),
    };
    if preview.deferred > 0 {
        report.warnings.push(format!(
            "{} eligible Trash items were deferred by the 32-item run limit.",
            preview.deferred
        ));
    }
    if preview.skipped > 0 {
        report.warnings.push(format!(
            "{} newer, unknown-age, or unsupported Trash items remain untouched.",
            preview.skipped
        ));
    }
    if dry_run {
        return Ok(report);
    }
    let Some(plan) = preview.plan else {
        if cancel.load(Ordering::Relaxed) {
            report.outcome = "cancelled";
            report.cancelled = true;
        }
        return Ok(report);
    };
    if cancel.load(Ordering::Relaxed) {
        report.outcome = "cancelled";
        report.cancelled = true;
        return Ok(report);
    }
    let result = crate::trash::remove_scheduled_batch_with_guard(
        &plan,
        &plan.preview_token,
        cancel,
        &guard,
        |_, _| {},
    )?;
    report.removed = result
        .items
        .iter()
        .filter(|item| item.status == "verified_absent")
        .count();
    report.cancelled = result.outcome == "cancelled";
    report.outcome = outcome_with_deferred(result.outcome, preview.deferred);
    report.items = redact_item_results(result.items);
    Ok(report)
}

#[cfg(target_os = "linux")]
fn verify_trash_retention_schedule(
    executable: &Path,
    config_path: &Path,
    location: &Path,
    age: Duration,
    scope_token: &str,
    bus_identity: &crate::schedule::trash_retention::BusIdentity,
) -> anyhow::Result<()> {
    crate::schedule::trash_retention::verify_trash_retention_schedule(
        executable,
        config_path,
        location,
        age,
        scope_token,
        bus_identity,
    )
}

#[cfg(all(test, target_os = "linux"))]
fn run_test_after_preview_hook() -> anyhow::Result<()> {
    use anyhow::Context;
    use std::{
        fs,
        os::unix::{fs::FileTypeExt, net::UnixListener},
    };

    let Some(fixture) = TEST_BUS_REPLACEMENT.with(|slot| slot.borrow().clone()) else {
        return Ok(());
    };
    let root = test_fixture_root(&fixture.root).context("test fixture root is not private")?;
    let socket = test_fixture_path(&root, &fixture.socket, false)
        .context("test bus socket is outside the private fixture")?;
    if !fs::symlink_metadata(&socket)
        .context("inspect test manager bus socket")?
        .file_type()
        .is_socket()
    {
        anyhow::bail!("test manager bus path is not a socket");
    }
    let backup = test_fixture_path(&root, &fixture.backup, true)
        .context("test bus backup path is outside the private fixture")?;
    if fs::symlink_metadata(&backup).is_ok() {
        anyhow::bail!("test bus backup path already exists");
    }
    let calls = test_fixture_path(&root, &fixture.calls, true)
        .context("test manager call log is outside the private fixture")?;
    let baseline = test_fixture_path(&root, &fixture.baseline, true)
        .context("test manager call baseline is outside the private fixture")?;
    fs::rename(&socket, backup).context("move original test manager socket")?;
    drop(UnixListener::bind(&socket).context("bind replacement test manager socket")?);
    let call_count = fs::read_to_string(calls)
        .map(|text| text.lines().count())
        .unwrap_or_default();
    fs::write(baseline, call_count.to_string()).context("write test manager call baseline")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, net::UnixListener},
        process::Command,
    };

    #[cfg(target_os = "linux")]
    fn secure_directory(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
    }

    #[cfg(target_os = "linux")]
    fn fixture_child_requested(test: &str, mode: &str) -> bool {
        std::env::var("UPKIT_SCHEDULED_TRASH_TEST_CHILD")
            .ok()
            .as_deref()
            == Some(mode)
            && std::env::args().any(|argument| argument == "--exact")
            && std::env::args().any(|argument| argument == test)
    }

    #[cfg(target_os = "linux")]
    struct RunFixture {
        root: tempfile::TempDir,
        data_home: PathBuf,
        unit_directory: PathBuf,
        runtime: PathBuf,
        trash: PathBuf,
        config: PathBuf,
        executable: PathBuf,
        bus: PathBuf,
        _bus_listener: UnixListener,
        bus_backup: PathBuf,
        manager: PathBuf,
        calls: PathBuf,
        baseline: PathBuf,
    }

    #[cfg(target_os = "linux")]
    impl RunFixture {
        fn new() -> Self {
            const TIMER_UNIT: &str = "upkit-trash-retention.timer";
            let root = tempfile::Builder::new()
                .prefix("upkit-scheduled-trash-")
                .tempdir_in("/tmp")
                .unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let home = root.path().join("home");
            secure_directory(&home);
            let config_home = home.join("config");
            secure_directory(&config_home);
            let data_home = home.join("data");
            secure_directory(&data_home);
            let runtime = home.join("runtime");
            secure_directory(&runtime);
            let trash = data_home.join("Trash");
            secure_directory(&trash);
            secure_directory(&trash.join("files"));
            secure_directory(&trash.join("info"));
            let systemd_directory = config_home.join("systemd");
            secure_directory(&systemd_directory);
            let unit_directory = systemd_directory.join("user");
            secure_directory(&unit_directory);

            let config = home.join("upkit.toml");
            fs::write(&config, "version = 1\nscheduled_trash_retention = true\n").unwrap();
            fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
            let binary_directory = home.join("bin");
            secure_directory(&binary_directory);
            let executable = binary_directory.join("upkit");
            fs::write(&executable, "test executable").unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

            let bus = runtime.join("bus");
            let bus_listener = UnixListener::bind(&bus).unwrap();
            let bus_backup = runtime.join("bus-original");
            let state = root.path().join("manager-state");
            fs::write(&state, "inactive\ndisabled\n").unwrap();
            let calls = root.path().join("manager-calls");
            let baseline = root.path().join("manager-calls-before-guard");
            let manager_body = format!(
                "[ \"$1\" = '--user' ] || exit 90\nshift\ncommand=$1\nshift\nprintf 'called\\n' >> {}\ncase \"$command\" in\n  daemon-reload) exit 0 ;;\n  enable) printf 'active\\nenabled\\n' > {} ;;\n  show)\n    unit=$1\n    property=\n    for argument in \"$@\"; do case \"$argument\" in --property=*) property=${{argument#--property=}} ;; esac; done\n    file={}/$unit\n    case \"$property\" in\n      LoadState) if [ -f \"$file\" ]; then printf 'loaded\\n'; else printf 'not-found\\n'; fi ;;\n      FragmentPath) if [ -f \"$file\" ]; then printf '%s\\n' \"$file\"; else printf '\\n'; fi ;;\n      DropInPaths) printf '\\n' ;;\n      NeedDaemonReload) printf 'no\\n' ;;\n      ActiveState) if [ \"$unit\" = '{}' ]; then IFS= read -r value < {}; printf '%s\\n' \"$value\"; else printf 'inactive\\n'; fi ;;\n      UnitFileState) if [ \"$unit\" = '{}' ]; then while IFS= read -r state_value && IFS= read -r file_state; do printf '%s\\n' \"$file_state\"; done < {}; else printf 'static\\n'; fi ;;\n      *) exit 91 ;;\n    esac ;;\n  *) exit 92 ;;\nesac",
                shell_quote(&calls),
                shell_quote(&state),
                shell_quote(&unit_directory),
                TIMER_UNIT,
                shell_quote(&state),
                TIMER_UNIT,
                shell_quote(&state),
            );
            let manager = binary_directory.join("systemctl-fixture");
            fs::write(&manager, format!("#!/bin/sh\n{manager_body}\n")).unwrap();
            fs::set_permissions(&manager, fs::Permissions::from_mode(0o700)).unwrap();

            Self {
                root,
                data_home,
                unit_directory,
                runtime,
                trash,
                config,
                executable,
                bus,
                _bus_listener: bus_listener,
                bus_backup,
                manager,
                calls,
                baseline,
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn fixture_child(test: &str, mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .args(["--exact", test, "--nocapture"])
            .env("PATH", "/usr/bin:/bin")
            .env("UPKIT_SCHEDULED_TRASH_TEST_CHILD", mode);
        command
    }

    #[test]
    fn rejects_an_age_below_the_policy_minimum() {
        let error = validate_age(Duration::from_secs(
            crate::trash::MIN_SCHEDULED_TRASH_RETENTION_SECONDS - 1,
        ))
        .unwrap_err();
        assert!(error.to_string().contains("at least 30 days"));
    }

    #[test]
    fn cancellation_report_has_no_item_details() {
        let report = cancelled_report(false);
        assert_eq!(report.outcome, "cancelled");
        assert!(report.cancelled);
        assert!(report.items.is_empty());
    }

    #[test]
    fn deferred_candidates_keep_successful_run_outcomes_partial() {
        assert_eq!(outcome_with_deferred("completed", 1), "partial");
        assert_eq!(outcome_with_deferred("completed", 0), "completed");
        assert_eq!(outcome_with_deferred("partial", 1), "partial");
        assert_eq!(outcome_with_deferred("cancelled", 1), "cancelled");
    }

    #[test]
    fn scheduled_json_redacts_item_names_locations_and_quarantine_errors() {
        let report = Report {
            outcome: "partial",
            eligible: 1,
            removed: 0,
            deferred: 0,
            skipped: 0,
            cancelled: false,
            dry_run: false,
            items: redact_item_results(vec![crate::trash::TrashBatchItemResult {
                location: std::path::PathBuf::from("/home/alice/.local/share/Trash"),
                name: "private-project.tar".into(),
                status: "failed_or_skipped",
                error: Some(
                    "/tmp/upkit-trash-quarantine/private-project.tar: permission denied".into(),
                ),
            }]),
            warnings: Vec::new(),
        };
        let output = serde_json::to_string(&report).unwrap();
        for sensitive in [
            "/home/alice/.local/share/Trash",
            "private-project.tar",
            "/tmp/upkit-trash-quarantine",
            "permission denied",
        ] {
            assert!(
                !output.contains(sensitive),
                "unexpected {sensitive} in {output}"
            );
        }
        assert!(output.contains("\"ordinal\":1"));
        assert!(output.contains("removal did not complete"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn persistent_scope_ignores_mount_instance_ids_but_run_guard_checks_them() {
        let stable_location: &[u8] = b"stable-trash-directory-and-mount-identity";
        let before_reboot = durable_scope_token(
            Path::new("/usr/bin/upkit"),
            b"executable-identity",
            Path::new("/home/user/.config/upkit/config.toml"),
            "config-identity",
            Path::new("/home/user/.local/share/Trash"),
            stable_location,
            Duration::from_secs(crate::trash::MIN_SCHEDULED_TRASH_RETENTION_SECONDS),
        )
        .unwrap();
        let after_reboot = durable_scope_token(
            Path::new("/usr/bin/upkit"),
            b"executable-identity",
            Path::new("/home/user/.config/upkit/config.toml"),
            "config-identity",
            Path::new("/home/user/.local/share/Trash"),
            stable_location,
            Duration::from_secs(crate::trash::MIN_SCHEDULED_TRASH_RETENTION_SECONDS),
        )
        .unwrap();
        assert_eq!(before_reboot, after_reboot);

        assert!(!same_run_location_identity(
            &stable_location,
            31,
            &stable_location,
            94,
        ));
        let replacement_location: &[u8] = b"replacement-trash-location";
        assert!(!same_run_location_identity(
            &stable_location,
            31,
            &replacement_location,
            31,
        ));
        assert!(same_run_location_identity(
            &stable_location,
            31,
            &stable_location,
            31,
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn executable_identity_rejects_fifo_hardlinks_and_untrusted_permissions() {
        use rustix::fs::{Mode, mkfifoat};
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let executable = dir.path().join("upkit");
        std::fs::write(&executable, "fixture").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let identity = executable_identity(&executable);
        assert!(
            identity.is_ok(),
            "fixture executable was rejected: {identity:?}"
        );

        let hardlink = dir.path().join("upkit-hardlink");
        std::fs::hard_link(&executable, &hardlink).unwrap();
        assert!(executable_identity(&executable).is_err());
        std::fs::remove_file(hardlink).unwrap();

        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(executable_identity(&executable).is_err());

        let untrusted = dir.path().join("untrusted");
        std::fs::create_dir(&untrusted).unwrap();
        std::fs::set_permissions(&untrusted, std::fs::Permissions::from_mode(0o777)).unwrap();
        let nested = untrusted.join("upkit");
        std::fs::write(&nested, "fixture").unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(executable_identity(&nested).is_err());

        let fifo = dir.path().join("fifo");
        mkfifoat(rustix::fs::CWD, &fifo, Mode::RUSR | Mode::WUSR | Mode::XUSR).unwrap();
        assert!(executable_identity(&fifo).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_snapshot_fixture_child() {
        if !fixture_child_requested(
            "scheduled_trash_cleanup::tests::run_snapshot_fixture_child",
            "snapshot",
        ) {
            return;
        }
        let fixture = RunFixture::new();
        let _schedule_context = crate::schedule::trash_retention::TestScheduleContextGuard::install(
            &fixture.manager,
            &fixture.unit_directory,
            &fixture.runtime,
        );
        let _data_directory = crate::trash::TestDataDirectoryGuard::install(&fixture.data_home);
        let executable = &fixture.executable;
        let config = &fixture.config;
        let location = &fixture.trash;
        let age = Duration::from_secs(crate::trash::MIN_SCHEDULED_TRASH_RETENTION_SECONDS);

        let plan = crate::schedule::trash_retention::preview_trash_retention(
            executable, config, location, age,
        )
        .unwrap();
        crate::schedule::trash_retention::install_trash_retention(&plan, &plan.preview_token)
            .unwrap();
        let expected_scope = scope_token(executable, config, location, age).unwrap();
        let _hook = TestBusReplacementGuard::install(
            fixture.root.path(),
            &fixture.bus,
            &fixture.bus_backup,
            &fixture.calls,
            &fixture.baseline,
        );
        let error = run(
            executable,
            config,
            location,
            age,
            &expected_scope,
            true,
            &AtomicBool::new(false),
        )
        .expect_err("the guard must reject the replaced bus snapshot");
        assert!(format!("{error:#}").contains("bus changed"), "{error:#}");

        let baseline = fs::read_to_string(&fixture.baseline)
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert!(
            baseline > 0,
            "initial verification must call the fixture manager"
        );
        assert_eq!(
            fs::read_to_string(&fixture.calls).unwrap().lines().count(),
            baseline
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_success_fixture_child() {
        if !fixture_child_requested(
            "scheduled_trash_cleanup::tests::run_success_fixture_child",
            "success",
        ) {
            return;
        }
        let fixture = RunFixture::new();
        let _schedule_context = crate::schedule::trash_retention::TestScheduleContextGuard::install(
            &fixture.manager,
            &fixture.unit_directory,
            &fixture.runtime,
        );
        let _data_directory = crate::trash::TestDataDirectoryGuard::install(&fixture.data_home);
        let root = fixture.root.path();
        let executable = &fixture.executable;
        let config = &fixture.config;
        let location = &fixture.trash;
        let item = location.join("files/fixture");
        let info = location.join("info/fixture.trashinfo");
        let outside = root.join("outside-sentinel");
        let history_home = root.join("upkit-history-home");
        secure_directory(&history_home);
        fs::write(&item, "scheduled fixture").unwrap();
        fs::set_permissions(&item, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            &info,
            format!(
                "[Trash Info]\nDeletionDate={}\n",
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S")
            ),
        )
        .unwrap();
        fs::set_permissions(&info, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&outside, "leave outside Trash alone").unwrap();
        let age = Duration::from_secs(crate::trash::MIN_SCHEDULED_TRASH_RETENTION_SECONDS);
        let _clock = TestClockGuard::set(chrono::Utc::now() + chrono::TimeDelta::days(34));

        let plan = crate::schedule::trash_retention::preview_trash_retention(
            executable, config, location, age,
        )
        .unwrap();
        crate::schedule::trash_retention::install_trash_retention(&plan, &plan.preview_token)
            .unwrap();
        let expected_scope = scope_token(executable, config, location, age).unwrap();

        let overlapping_history = crate::reports::perform_scheduled_trash_retention(
            &location.join("files"),
            executable,
            config,
            location,
            age,
            &expected_scope,
            &AtomicBool::new(false),
        );
        let error = overlapping_history.result.unwrap_err();
        assert!(error.contains("operation history location overlaps scheduled Trash data"));
        assert!(item.exists());
        assert!(info.exists());
        assert!(!location.join("files/history").exists());

        let performed = crate::reports::perform_scheduled_trash_retention(
            &history_home,
            executable,
            config,
            location,
            age,
            &expected_scope,
            &AtomicBool::new(false),
        );
        assert!(performed.history_warning.is_none());
        let report = performed
            .result
            .unwrap_or_else(|error| panic!("scheduled Trash run failed: {error}"));
        assert_eq!(report.outcome, "completed", "report: {report:?}");
        assert_eq!(report.eligible, 1);
        assert_eq!(report.removed, 1);
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].status, "verified_absent");
        assert!(!item.exists());
        assert!(!info.exists());
        assert_eq!(
            fs::read_to_string(&outside).unwrap(),
            "leave outside Trash alone"
        );

        let history = crate::reports::read(&history_home).unwrap();
        assert!(history.warnings.is_empty());
        assert_eq!(history.records.len(), 1);
        assert_eq!(history.records[0].operation, "scheduled_trash_retention");
        assert_eq!(history.records[0].outcome, "completed");
        assert!(!fs::read_to_string(&fixture.calls).unwrap().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_reuses_one_manager_bus_snapshot_across_inventory_guard() {
        let output = fixture_child(
            "scheduled_trash_cleanup::tests::run_snapshot_fixture_child",
            "snapshot",
        )
        .output()
        .unwrap();
        assert!(
            output.status.success(),
            "snapshot child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_removes_a_fixture_item_and_records_history_with_a_test_clock() {
        let output = fixture_child(
            "scheduled_trash_cleanup::tests::run_success_fixture_child",
            "success",
        )
        .output()
        .unwrap();
        assert!(
            output.status.success(),
            "success child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
