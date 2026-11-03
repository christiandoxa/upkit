//! Manage platform user schedules and verify their read-only scan scopes.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use std::fs;
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};

#[cfg(any(target_os = "windows", test))]
mod windows;

#[cfg(target_os = "linux")]
pub(crate) mod trash_retention;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Frequency {
    Daily,
    Weekly,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanSchedulePreview {
    pub roots: Vec<PathBuf>,
    pub exclusions: Vec<PathBuf>,
    pub frequency: &'static str,
    pub unit_directory: PathBuf,
    pub preview_token: String,
    pub scheduled_scope_token: String,
    pub service_unit: String,
    pub timer_unit: String,
    pub warning: &'static str,
}

/// Whether the reviewed plan runs the opt-in scheduled bytecode cleanup.
pub fn schedules_bytecode_cleanup(plan: &ScanSchedulePreview) -> bool {
    policy_from_token(&plan.scheduled_scope_token)
        .ok()
        .flatten()
        .is_some_and(|policy| policy.scheduled_bytecode_cleanup)
}

/// Whether the reviewed plan explicitly opts into bounded artifact cleanup.
pub fn schedules_artifact_cleanup(plan: &ScanSchedulePreview) -> bool {
    policy_from_token(&plan.scheduled_scope_token)
        .ok()
        .flatten()
        .is_some_and(|policy| policy.scheduled_artifact_cleanup)
}

fn ensure_artifact_schedule_supported(plan: &ScanSchedulePreview) -> Result<()> {
    if schedules_artifact_cleanup(plan) && !cfg!(target_os = "linux") {
        bail!("scheduled artifact cleanup is supported only on Linux");
    }
    Ok(())
}

fn schedules_cleanup(plan: &ScanSchedulePreview) -> bool {
    schedules_bytecode_cleanup(plan) || schedules_artifact_cleanup(plan)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConfiguredSource {
    path: String,
    required: bool,
    profile: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ScheduledScanPolicy {
    version: u8,
    scope_token: String,
    older_than_seconds: Option<u64>,
    enabled_ecosystems: Option<Vec<crate::sweep::Ecosystem>>,
    source: Option<ConfiguredSource>,
    #[serde(default, skip_serializing_if = "is_false")]
    scheduled_bytecode_cleanup: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    scheduled_artifact_cleanup: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

fn scheduled_artifact_ecosystem(ecosystem: crate::sweep::Ecosystem) -> bool {
    matches!(
        ecosystem,
        crate::sweep::Ecosystem::Maven
            | crate::sweep::Ecosystem::Zig
            | crate::sweep::Ecosystem::Dart
            | crate::sweep::Ecosystem::Python
    )
}

fn validate_scheduled_artifact_policy(
    older_than: Option<Duration>,
    enabled: Option<&[crate::sweep::Ecosystem]>,
) -> Result<()> {
    const MIN_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
    if older_than.is_none_or(|age| age < MIN_RETENTION) {
        bail!("scheduled artifact cleanup requires artifact_retention of at least 30 days");
    }
    let Some(enabled) = enabled.filter(|items| !items.is_empty()) else {
        bail!("scheduled artifact cleanup requires an explicit nonempty enabled_ecosystems list");
    };
    if !enabled
        .iter()
        .any(|ecosystem| scheduled_artifact_ecosystem(*ecosystem))
    {
        bail!(
            "scheduled artifact cleanup requires Maven, Zig, Dart, or Python enabled; Cargo is excluded from scheduled cleanup until target-directory safety can be verified"
        );
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn schedule_changes_unsupported() -> anyhow::Error {
    anyhow::anyhow!("user maintenance schedule changes are unsupported on this platform")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConfiguredScanScope {
    roots: Vec<PathBuf>,
    exclusions: Vec<PathBuf>,
    older_than: Option<Duration>,
    enabled_ecosystems: Option<Vec<crate::sweep::Ecosystem>>,
    scheduled_bytecode_cleanup: bool,
    scheduled_artifact_cleanup: bool,
    source: ConfiguredSource,
}

impl ConfiguredScanScope {
    fn policy(&self) -> ScheduledScanPolicy {
        ScheduledScanPolicy {
            version: if self.scheduled_artifact_cleanup {
                4
            } else if self.scheduled_bytecode_cleanup {
                3
            } else {
                2
            },
            scope_token: String::new(),
            older_than_seconds: self.older_than.map(|age| age.as_secs()),
            enabled_ecosystems: self.enabled_ecosystems.clone(),
            source: Some(self.source.clone()),
            scheduled_bytecode_cleanup: self.scheduled_bytecode_cleanup,
            scheduled_artifact_cleanup: self.scheduled_artifact_cleanup,
        }
    }
}

#[cfg(target_os = "linux")]
fn unit_arg(value: &str) -> Result<String> {
    if value.chars().any(char::is_control) {
        bail!("systemd arguments cannot contain control characters");
    }
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}

#[cfg(target_os = "linux")]
fn preview_token(
    executable: &Path,
    roots: &[PathBuf],
    unit_directory: &Path,
    service: &str,
    timer: &str,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    let mut hash = Sha256::new();
    let mut add = |bytes: &[u8]| {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    };
    add(b"upkit-scan-schedule-preview-v1");
    add(&fs::read("/proc/sys/kernel/random/boot_id").context("read boot identity")?);
    add(unit_directory.as_os_str().as_encoded_bytes());
    add(service.as_bytes());
    add(timer.as_bytes());
    for path in std::iter::once(executable).chain(roots.iter().map(PathBuf::as_path)) {
        let metadata = fs::symlink_metadata(path).context("inspect schedule path identity")?;
        if metadata.file_type().is_symlink() {
            bail!("schedule path became a symbolic link");
        }
        add(path.as_os_str().as_encoded_bytes());
        add(&metadata.dev().to_le_bytes());
        add(&metadata.ino().to_le_bytes());
        add(&metadata.ctime().to_le_bytes());
        add(&metadata.ctime_nsec().to_le_bytes());
        add(&metadata.len().to_le_bytes());
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(target_os = "macos")]
fn preview_token(
    executable: &Path,
    roots: &[PathBuf],
    unit_directory: &Path,
    service: &str,
    timer: &str,
) -> Result<String> {
    launchd_preview_token(executable, roots, unit_directory, service, timer)
}

#[cfg(target_os = "macos")]
fn launchd_preview_token(
    executable: &Path,
    roots: &[PathBuf],
    unit_directory: &Path,
    service: &str,
    timer: &str,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;

    let mut hash = Sha256::new();
    let mut add = |bytes: &[u8]| {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    };
    add(b"upkit-launchd-scan-preview-v1");
    add(unit_directory.as_os_str().as_encoded_bytes());
    add(service.as_bytes());
    add(timer.as_bytes());
    for (path, directory) in
        std::iter::once((executable, false)).chain(roots.iter().map(|root| (root.as_path(), true)))
    {
        let metadata = fs::symlink_metadata(path).context("inspect schedule path identity")?;
        if metadata.file_type().is_symlink()
            || metadata.is_dir() != directory
            || metadata.is_file() == directory
        {
            bail!("schedule path changed or has an unexpected file type");
        }
        add(path.as_os_str().as_encoded_bytes());
        add(&metadata.dev().to_le_bytes());
        add(&metadata.ino().to_le_bytes());
        add(&metadata.ctime().to_le_bytes());
        add(&metadata.ctime_nsec().to_le_bytes());
        add(&metadata.len().to_le_bytes());
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(any(target_os = "macos", test))]
fn launchd_xml_text(value: &str) -> Result<String> {
    if value
        .chars()
        .any(|character| character.is_control() || matches!(character, '\u{fffe}' | '\u{ffff}'))
    {
        bail!("launchd arguments cannot contain XML control characters");
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

/// Render a user LaunchAgent that invokes Upkit directly, with no shell parsing.
#[cfg(any(target_os = "macos", test))]
fn launchd_scan_plist(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    scheduled_scope_token: &str,
    frequency: Frequency,
    cleanup: bool,
) -> Result<String> {
    let mut arguments = vec![
        executable
            .to_str()
            .context("launchd executable path must be UTF-8")?
            .to_owned(),
        "--non-interactive".into(),
        "--offline".into(),
    ];
    if cleanup {
        arguments.push("--yes".into());
    }
    arguments.extend([
        "--json".into(),
        "--config".into(),
        "/dev/null".into(),
        "sweep".into(),
    ]);
    if cleanup {
        arguments.extend([
            "scheduled-bytecode-cleanup".into(),
            "--authorize-scheduled-cleanup".into(),
        ]);
    } else {
        arguments.push("scan".into());
    }
    arguments.push(format!("--scope-token={scheduled_scope_token}"));
    arguments.extend(
        exclusions
            .iter()
            .map(|path| {
                Ok(format!(
                    "--exclude={}",
                    path.to_str().context("launchd exclusions must be UTF-8")?
                ))
            })
            .collect::<Result<Vec<_>>>()?,
    );
    arguments.push("--".into());
    arguments.extend(
        roots
            .iter()
            .map(|path| {
                path.to_str()
                    .map(str::to_owned)
                    .context("launchd workspace paths must be UTF-8")
            })
            .collect::<Result<Vec<_>>>()?,
    );

    let mut plist = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n<key>Label</key>\n<string>upkit-scan.timer</string>\n<key>ProgramArguments</key>\n<array>\n",
    );
    for argument in arguments {
        plist.push_str("<string>");
        plist.push_str(&launchd_xml_text(&argument)?);
        plist.push_str("</string>\n");
    }
    plist.push_str("</array>\n<key>StartCalendarInterval</key>\n<dict>\n");
    if matches!(frequency, Frequency::Weekly) {
        // launchd uses 0 for Sunday and 1 through 6 for Monday through Saturday.
        plist.push_str("<key>Weekday</key>\n<integer>0</integer>\n");
    }
    plist.push_str("<key>Hour</key>\n<integer>3</integer>\n<key>Minute</key>\n<integer>0</integer>\n</dict>\n<key>RunAtLoad</key>\n<false/>\n</dict>\n</plist>\n");
    if plist.len() > 65536 {
        bail!("generated launchd property list exceeds the supported size limit");
    }
    Ok(plist)
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct LaunchdScan {
    executable: PathBuf,
    roots: Vec<PathBuf>,
    exclusions: Vec<PathBuf>,
    scope_token: String,
    frequency: Frequency,
}

#[cfg(any(target_os = "macos", test))]
fn launchd_xml_unescape(value: &str) -> Result<String> {
    let mut result = String::with_capacity(value.len());
    let mut rest = value;
    while let Some((before, after)) = rest.split_once('&') {
        result.push_str(before);
        let (entity, tail) = after
            .split_once(';')
            .context("invalid launchd XML entity")?;
        result.push(match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => anyhow::bail!("unsupported launchd XML entity"),
        });
        rest = tail;
    }
    result.push_str(rest);
    if result
        .chars()
        .any(|character| character.is_control() || matches!(character, '\u{fffe}' | '\u{ffff}'))
    {
        bail!("launchd arguments contain XML control characters");
    }
    Ok(result)
}

/// Parse only the exact plist shape Upkit writes; any edit fails closed.
#[cfg(any(target_os = "macos", test))]
fn launchd_parse_scan_plist(plist: &str) -> Result<LaunchdScan> {
    const PREFIX: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n<key>Label</key>\n<string>upkit-scan.timer</string>\n<key>ProgramArguments</key>\n<array>\n";
    const ARRAY_END: &str = "</array>\n<key>StartCalendarInterval</key>\n<dict>\n";
    let body = plist
        .strip_prefix(PREFIX)
        .context("launchd property list is not an Upkit scan")?;
    let (array, schedule) = body
        .split_once(ARRAY_END)
        .context("launchd property list has an invalid argument array")?;
    let arguments = array
        .lines()
        .map(|line| {
            let value = line
                .strip_prefix("<string>")
                .and_then(|value| value.strip_suffix("</string>"))
                .context("launchd argument is not a string")?;
            launchd_xml_unescape(value)
        })
        .collect::<Result<Vec<_>>>()?;
    let (frequency, suffix) = if let Some(suffix) = schedule.strip_prefix(
        "<key>Hour</key>\n<integer>3</integer>\n<key>Minute</key>\n<integer>0</integer>\n</dict>\n<key>RunAtLoad</key>\n<false/>\n</dict>\n</plist>\n",
    ) {
        let _ = suffix;
        (Frequency::Daily, "")
    } else if let Some(suffix) = schedule.strip_prefix(
        "<key>Weekday</key>\n<integer>0</integer>\n<key>Hour</key>\n<integer>3</integer>\n<key>Minute</key>\n<integer>0</integer>\n</dict>\n<key>RunAtLoad</key>\n<false/>\n</dict>\n</plist>\n",
    ) {
        let _ = suffix;
        (Frequency::Weekly, "")
    } else {
        bail!("launchd schedule does not match an Upkit calendar interval");
    };
    if !suffix.is_empty() || arguments.len() < 10 {
        bail!("launchd property list contains unexpected fields");
    }
    let executable = PathBuf::from(&arguments[0]);
    if !executable.is_absolute()
        || arguments[1..8]
            != [
                "--non-interactive",
                "--offline",
                "--json",
                "--config",
                "/dev/null",
                "sweep",
                "scan",
            ]
    {
        bail!("launchd property list does not invoke an Upkit read-only scan");
    }
    let scope_token = arguments[8]
        .strip_prefix("--scope-token=")
        .filter(|token| !token.is_empty())
        .context("launchd property list has no scope token")?
        .to_owned();
    match policy_from_token(&scope_token)? {
        Some(policy)
            if !policy.scheduled_bytecode_cleanup && !policy.scheduled_artifact_cleanup => {}
        Some(_) => bail!("launchd automatic cleanup is unsupported"),
        None if scope_token.len() == 64
            && scope_token.bytes().all(|byte| byte.is_ascii_hexdigit()) => {}
        None => bail!("launchd scope token is invalid"),
    }
    let mut cursor = 9;
    let mut exclusions = Vec::new();
    while let Some(exclusion) = arguments
        .get(cursor)
        .and_then(|arg| arg.strip_prefix("--exclude="))
    {
        exclusions.push(PathBuf::from(exclusion));
        cursor += 1;
    }
    if arguments.get(cursor).map(String::as_str) != Some("--") {
        bail!("launchd property list has no workspace separator");
    }
    let roots = arguments[cursor + 1..]
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if roots.is_empty() || roots.iter().any(|root| !root.is_absolute()) {
        bail!("launchd property list has no absolute workspace roots");
    }
    Ok(LaunchdScan {
        executable,
        roots,
        exclusions,
        scope_token,
        frequency,
    })
}

#[cfg(test)]
mod launchd_plist_tests {
    use super::*;

    #[test]
    fn launchd_preview_uses_xml_escaped_argument_array_and_calendar_frequency() {
        let executable = Path::new("/tmp/upkit & <\"binary>");
        let roots = [PathBuf::from("/tmp/work $HOME; & <\"root>")];
        let exclusions = [PathBuf::from("/tmp/private & <\"dir>")];
        let token = "a".repeat(64);
        let daily = launchd_scan_plist(
            executable,
            &roots,
            &exclusions,
            &token,
            Frequency::Daily,
            false,
        )
        .unwrap();
        assert!(daily.contains("<key>ProgramArguments</key>\n<array>"));
        assert!(daily.contains("<string>/tmp/upkit &amp; &lt;&quot;binary&gt;</string>"));
        assert!(daily.contains("<string>--scope-token="));
        assert!(daily.contains("<string>--exclude=/tmp/private &amp; &lt;&quot;dir&gt;</string>"));
        assert!(daily.contains("<string>/tmp/work $HOME; &amp; &lt;&quot;root&gt;</string>"));
        assert!(daily.contains("<key>Hour</key>\n<integer>3</integer>"));
        assert!(!daily.contains("<key>Weekday</key>"));
        assert!(!daily.contains("/bin/sh"));
        assert!(daily.contains("<key>RunAtLoad</key>\n<false/>"));

        let weekly = launchd_scan_plist(
            executable,
            &roots,
            &exclusions,
            &token,
            Frequency::Weekly,
            false,
        )
        .unwrap();
        assert!(weekly.contains("<key>Weekday</key>\n<integer>0</integer>"));
    }

    #[test]
    fn launchd_preview_rejects_xml_control_characters() {
        assert!(launchd_xml_text("workspace\nroot").is_err());
    }

    #[test]
    fn launchd_plist_round_trips_only_upkit_read_only_scan_arguments() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("workspace & <\"root>");
        fs::create_dir(&root).unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let root = root.canonicalize().unwrap();
        let roots = [root.clone()];
        let exclusions = [PathBuf::from("glob:**/private & <\"dir>")];
        let token = scheduled_scope_token(&executable, &roots, &exclusions).unwrap();
        let plist = launchd_scan_plist(
            &executable,
            &roots,
            &exclusions,
            &token,
            Frequency::Weekly,
            false,
        )
        .unwrap();
        let parsed = launchd_parse_scan_plist(&plist).unwrap();
        assert_eq!(parsed.executable, executable);
        assert_eq!(parsed.roots, roots);
        assert_eq!(parsed.exclusions, exclusions);
        assert_eq!(parsed.scope_token, token);
        assert!(matches!(parsed.frequency, Frequency::Weekly));
        assert_eq!(launchd_validate_plist(&plist).unwrap(), parsed);
        assert!(!plist.contains("/bin/sh"));
        assert!(plist.contains("<string>--</string>"));

        let shell = plist.replace("<string>scan</string>", "<string>sh</string>");
        assert!(launchd_parse_scan_plist(&shell).is_err());
        assert!(launchd_parse_scan_plist(&plist.replace("<false/>", "<true/>")).is_err());
    }

    #[test]
    fn launchd_print_disabled_parser_requires_a_complete_unambiguous_list() {
        assert_eq!(
            launchd_disabled_label(
                b"disabled services = {\n    \"upkit-scan.timer\" => disabled\n}\n",
                LAUNCHD_LABEL
            ),
            Some(true)
        );
        assert_eq!(
            launchd_disabled_label(
                b"disabled services = {\n    \"other\" => enabled\n}\n",
                LAUNCHD_LABEL
            ),
            Some(false)
        );
        assert_eq!(
            launchd_disabled_label(
                b"disabled services = {\n    \"upkit-scan.timer\" => enabled\n    \"upkit-scan.timer\" => disabled\n}\n",
                LAUNCHD_LABEL
            ),
            None
        );
        assert_eq!(
            launchd_disabled_label(b"partial output", LAUNCHD_LABEL),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn launchd_fixture_file_lifecycle_is_create_only_private_and_link_safe() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        let fixture = tempfile::tempdir().unwrap();
        let fixture_root = fixture.path().canonicalize().unwrap();
        let directory_path = fixture_root.join("LaunchAgents");
        let root = fixture_root.join("workspace");
        fs::create_dir(&directory_path).unwrap();
        fs::set_permissions(&directory_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&root).unwrap();
        let (directory, directory_meta) = launchd_directory(&directory_path).unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let root = root.canonicalize().unwrap();
        let roots = [root];
        let token = scheduled_scope_token(&executable, &roots, &[]).unwrap();
        let plist =
            launchd_scan_plist(&executable, &roots, &[], &token, Frequency::Daily, false).unwrap();

        let identity = launchd_create_plist(&directory, &plist).unwrap();
        assert_eq!(identity.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(identity.mode() & 0o777, 0o600);
        assert!(launchd_create_plist(&directory, "overwritten").is_err());
        let (stored, read_identity) = launchd_read_plist(&directory, LAUNCHD_PLIST).unwrap();
        assert_eq!(stored, plist);
        assert!(launchd_same_file(&identity, &read_identity));
        assert!(launchd_same_directory(&directory_path, &directory_meta));
        assert!(launchd_validate_plist(&stored).is_ok());
        assert!(launchd_remove_plist(&directory, "changed", &identity, ".fixture.plist").is_err());
        assert!(directory_path.join(LAUNCHD_PLIST).exists());

        launchd_remove_plist(&directory, &plist, &identity, ".fixture.plist").unwrap();
        assert!(!directory_path.join(LAUNCHD_PLIST).exists());
        assert!(!directory_path.join(".fixture.plist").exists());

        let target = fixture_root.join("outside");
        fs::write(&target, "fixture").unwrap();
        symlink(&target, directory_path.join(LAUNCHD_PLIST)).unwrap();
        assert!(launchd_read_plist(&directory, LAUNCHD_PLIST).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn launchd_manager_lifecycle_uses_only_the_mock_executable() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let fixture = tempfile::tempdir().unwrap();
        let manager = fixture.path().join("launchctl");
        let domain = launchd_domain();
        let target = format!("{domain}/{LAUNCHD_LABEL}");
        let script = format!(
            r##"#!/bin/sh
root="${{0%/*}}"
domain="{domain}"
target="{target}"
case "$1" in
 print-disabled)
  [ "$#" -eq 2 ] && [ "$2" = "$domain" ] || exit 8
  printf 'disabled services = {{\n'
  [ ! -f "$root/disabled" ] || printf '    "%s" => disabled\n' 'upkit-scan.timer'
  printf '}}\n'
  ;;
 enable)
  [ "$#" -eq 2 ] && [ "$2" = "$target" ] || exit 8
  rm -f "$root/disabled"
  ;;
 disable)
  [ "$#" -eq 2 ] && [ "$2" = "$target" ] || exit 8
  : > "$root/disabled"
  ;;
 bootstrap)
  [ "$#" -eq 3 ] && [ "$2" = "$domain" ] && [ -f "$3" ] || exit 8
  : > "$root/loaded"
  ;;
 bootout)
  [ "$#" -eq 2 ] && [ "$2" = "$target" ] && [ -f "$root/loaded" ] || exit 8
  rm -f "$root/loaded"
  ;;
 print)
  [ "$#" -eq 2 ] && [ "$2" = "$target" ] && [ -f "$root/loaded" ] || exit 1
  printf 'gui job = {{\n    path = %s\n    type = LaunchAgent\n}}\n' "$root/upkit-scan.timer.plist"
  ;;
 *) exit 8 ;;
esac
"##
        );
        fs::write(&manager, script).unwrap();
        fs::set_permissions(&manager, fs::Permissions::from_mode(0o755)).unwrap();
        let plist = fixture.path().join("upkit-scan.timer.plist");
        fs::write(&plist, "fixture").unwrap();

        assert!(!launchd_disabled_state_with(&manager, &domain).unwrap());
        launchd_run_with(&manager, &["disable", &target]).unwrap();
        assert!(launchd_disabled_state_with(&manager, &domain).unwrap());
        launchd_run_with(&manager, &["enable", &target]).unwrap();
        assert!(!launchd_disabled_state_with(&manager, &domain).unwrap());
        launchd_run_with(&manager, &["bootstrap", &domain, plist.to_str().unwrap()]).unwrap();
        assert_eq!(
            launchd_loaded_path_with(&manager, &target).unwrap(),
            Some(plist.clone())
        );
        launchd_verify_loaded_path(&manager, &plist).unwrap();
        launchd_run_with(&manager, &["bootout", &target]).unwrap();
        assert_eq!(launchd_loaded_path_with(&manager, &target).unwrap(), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_mutations_reject_stale_tokens_before_touching_manager_or_files() {
        let directory = tempfile::tempdir().unwrap();
        let scan = ScanSchedulePreview {
            roots: vec![],
            exclusions: vec![],
            frequency: "daily",
            unit_directory: directory.path().join("LaunchAgents"),
            preview_token: "preview".into(),
            scheduled_scope_token: "scope".into(),
            service_unit: String::new(),
            timer_unit: String::new(),
            warning: "fixture",
        };
        let error =
            install_scan(Path::new("/ignored"), &scan, "stale", Frequency::Daily).unwrap_err();
        assert!(error.to_string().contains("preview token"));
        let disable = DisableSchedulePreview {
            unit_directory: directory.path().join("LaunchAgents"),
            service_unit: String::new(),
            timer_unit: String::new(),
            active_state: "not_found".into(),
            unit_file_state: Some("disabled".into()),
            preview_token: "preview".into(),
            warning: "fixture",
        };
        assert!(
            disable_scan(&disable, "stale")
                .unwrap_err()
                .to_string()
                .contains("preview token")
        );
        assert!(
            remove_scan(
                &RemoveSchedulePreview {
                    existing: disable,
                    quarantine_paths: vec![],
                    preview_token: "preview".into(),
                    warning: "fixture",
                },
                "stale"
            )
            .unwrap_err()
            .to_string()
            .contains("preview token")
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_scope_token_tracks_workspace_replacement_without_following_links() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let fixture_root = directory.path().canonicalize().unwrap();
        let root = fixture_root.join("workspace");
        fs::create_dir(&root).unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let token = scheduled_scope_token(&executable, std::slice::from_ref(&root), &[]).unwrap();
        assert_eq!(
            token,
            scheduled_scope_token(&executable, std::slice::from_ref(&root), &[]).unwrap()
        );

        let link = fixture_root.join("workspace-link");
        symlink(&root, &link).unwrap();
        assert!(scheduled_scope_token(&executable, &[link], &[]).is_err());

        fs::rename(&root, fixture_root.join("old-workspace")).unwrap();
        fs::create_dir(&root).unwrap();
        assert_ne!(
            token,
            scheduled_scope_token(&executable, &[root], &[]).unwrap()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_preview_rejects_automatic_bytecode_cleanup_policy() {
        let directory = tempfile::tempdir().unwrap();
        let fixture_root = directory.path().canonicalize().unwrap();
        let root = fixture_root.join("workspace");
        let config = fixture_root.join("config.toml");
        fs::create_dir(&root).unwrap();
        let settings = crate::config::Settings {
            workspace_roots: vec![root],
            artifact_retention: Some("7d".into()),
            enabled_ecosystems: Some(vec![crate::sweep::Ecosystem::Python]),
            scheduled_bytecode_cleanup: true,
            ..Default::default()
        };
        fs::write(&config, toml::to_string(&settings).unwrap()).unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let error = preview_configured_install(&executable, Some(&config), None, Frequency::Daily)
            .unwrap_err();
        assert!(error.to_string().contains("automatic scheduled cleanup"));
        assert!(error.to_string().contains("only on Linux"));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }
}

/// Fingerprint the executable and explicit roots without following path links.
/// Root birth time prevents ordinary inode reuse from silently changing scope.
#[cfg(target_os = "linux")]
pub fn scheduled_scope_token(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
) -> Result<String> {
    use rustix::fs::{AtFlags, OFlags, ResolveFlags, StatxFlags};
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    let mut add = |bytes: &[u8]| {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    };
    add(b"upkit-scheduled-scan-scope-v1");
    add(&(roots.len() as u64).to_be_bytes());
    for (path, directory) in
        std::iter::once((executable, false)).chain(roots.iter().map(|root| (root.as_path(), true)))
    {
        if !path.is_absolute() || path.canonicalize().ok().as_deref() != Some(path) {
            bail!("scheduled executable and roots must be canonical absolute paths");
        }
        let flags = OFlags::PATH
            | OFlags::CLOEXEC
            | if directory {
                OFlags::DIRECTORY
            } else {
                OFlags::empty()
            };
        let fd = rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            flags,
            rustix::fs::Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .context("open scheduled path without symbolic links")?;
        let file = fs::File::from(fd);
        let meta = file.metadata()?;
        if (directory && !meta.is_dir()) || (!directory && !meta.is_file()) {
            bail!("scheduled path has an unexpected file type");
        }
        let stats = rustix::fs::statx(
            &file,
            "",
            AtFlags::EMPTY_PATH,
            StatxFlags::BASIC_STATS | StatxFlags::BTIME,
        )
        .context("inspect scheduled path identity")?;
        let required = if directory {
            StatxFlags::BTIME | StatxFlags::INO
        } else {
            StatxFlags::BTIME | StatxFlags::INO | StatxFlags::CTIME | StatxFlags::SIZE
        };
        if stats.stx_mask & required.bits() != required.bits() {
            bail!("scheduled path lacks required stable identity metadata");
        }
        add(path.as_os_str().as_encoded_bytes());
        add(&stats.stx_dev_major.to_le_bytes());
        add(&stats.stx_dev_minor.to_le_bytes());
        add(&stats.stx_ino.to_le_bytes());
        add(&stats.stx_btime.tv_sec.to_le_bytes());
        add(&stats.stx_btime.tv_nsec.to_le_bytes());
        if !directory {
            add(&stats.stx_ctime.tv_sec.to_le_bytes());
            add(&stats.stx_ctime.tv_nsec.to_le_bytes());
            add(&stats.stx_size.to_le_bytes());
        }
    }
    add(&(exclusions.len() as u64).to_be_bytes());
    for exclusion in exclusions {
        add(exclusion.as_os_str().as_encoded_bytes());
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn policy_token(scope_token: String, policy: ScheduledScanPolicy) -> Result<String> {
    use sha2::{Digest, Sha256};
    let artifact_cleanup = policy.scheduled_artifact_cleanup;
    let bytecode_cleanup = policy.scheduled_bytecode_cleanup;
    let payload = serde_json::to_vec(&ScheduledScanPolicy {
        scope_token,
        ..policy
    })?;
    if payload.len() > 12_288 {
        bail!("scheduled scan policy exceeds the supported size limit");
    }
    let mut hash = Sha256::new();
    let (prefix, domain): (&str, &[u8]) = if artifact_cleanup {
        ("v4", b"upkit-scheduled-artifact-policy-v4\0")
    } else if bytecode_cleanup {
        ("v3", b"upkit-scheduled-bytecode-policy-v3\0")
    } else {
        ("v2", b"upkit-scheduled-scan-policy-v2\0")
    };
    hash.update(domain);
    hash.update((payload.len() as u64).to_be_bytes());
    hash.update(&payload);
    Ok(format!(
        "{prefix}.{}.{}",
        hex::encode(&payload),
        hex::encode(hash.finalize())
    ))
}

fn policy_from_token(token: &str) -> Result<Option<ScheduledScanPolicy>> {
    if !token.starts_with("v2.") && !token.starts_with("v3.") && !token.starts_with("v4.") {
        return Ok(None);
    }
    if token.len() > 24_644 {
        bail!("scheduled scan policy token exceeds the supported size limit");
    }
    let mut parts = token.split('.');
    let prefix = parts.next().unwrap_or_default();
    let payload = hex::decode(parts.next().unwrap_or_default())
        .context("decode scheduled scan policy token")?;
    let supplied_hash = parts.next().unwrap_or_default();
    if parts.next().is_some() || payload.len() > 12_288 || supplied_hash.len() != 64 {
        bail!("invalid scheduled scan policy token");
    }
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(match prefix {
        "v4" => &b"upkit-scheduled-artifact-policy-v4\0"[..],
        "v3" => &b"upkit-scheduled-bytecode-policy-v3\0"[..],
        _ => &b"upkit-scheduled-scan-policy-v2\0"[..],
    });
    hash.update((payload.len() as u64).to_be_bytes());
    hash.update(&payload);
    if hex::encode(hash.finalize()) != supplied_hash {
        bail!("scheduled scan policy token is invalid");
    }
    let policy: ScheduledScanPolicy =
        serde_json::from_slice(&payload).context("parse scheduled scan policy token")?;
    if (prefix == "v2"
        && (policy.version != 2
            || policy.scheduled_bytecode_cleanup
            || policy.scheduled_artifact_cleanup))
        || (prefix == "v3"
            && (policy.version != 3
                || !policy.scheduled_bytecode_cleanup
                || policy.scheduled_artifact_cleanup))
        || (prefix == "v4" && (policy.version != 4 || !policy.scheduled_artifact_cleanup))
        || policy.scope_token.len() != 64
        || !policy
            .scope_token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("invalid scheduled scan policy token");
    }
    if policy.scheduled_bytecode_cleanup
        && (policy.source.is_none()
            || policy
                .older_than_seconds
                .is_none_or(|age| age < 7 * 24 * 60 * 60)
            || policy
                .enabled_ecosystems
                .as_ref()
                .is_some_and(|enabled| !enabled.contains(&crate::sweep::Ecosystem::Python)))
    {
        bail!("invalid scheduled bytecode cleanup policy");
    }
    if policy.scheduled_artifact_cleanup {
        if policy.source.is_none() {
            bail!("scheduled artifact cleanup requires a configured scope policy");
        }
        validate_scheduled_artifact_policy(
            policy.older_than_seconds.map(Duration::from_secs),
            policy.enabled_ecosystems.as_deref(),
        )?;
    }
    Ok(Some(policy))
}

#[cfg(target_os = "linux")]
fn schedule_comment_value(value: &str) -> String {
    use std::fmt::Write;
    let mut output = String::new();
    for byte in value.bytes() {
        if (0x20..=0x7e).contains(&byte) && byte != b'%' && byte != b';' && byte != b'=' {
            output.push(char::from(byte));
        } else {
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

#[cfg(target_os = "linux")]
fn schedule_policy_comment(policy: &ScheduledScanPolicy) -> Result<String> {
    let (config_path, config_required, profile_present, profile) = match &policy.source {
        Some(source) => (
            crate::sweep::display_path(&decode_config_path(&source.path)?)
                .replace(';', "%3B")
                .replace('=', "%3D"),
            if source.required { "yes" } else { "no" },
            if source.profile.is_some() {
                "yes"
            } else {
                "no"
            },
            source
                .profile
                .as_deref()
                .map(schedule_comment_value)
                .unwrap_or_else(|| "(none)".into()),
        ),
        None => ("(none)".into(), "n/a", "no", "(none)".into()),
    };
    let enabled_ecosystems = policy.enabled_ecosystems.as_ref().map_or_else(
        || "all".to_owned(),
        |enabled| {
            if enabled.is_empty() {
                "(none)".to_owned()
            } else {
                enabled
                    .iter()
                    .map(|item| item.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            }
        },
    );
    let cleanup = if policy.scheduled_bytecode_cleanup {
        "; scheduled_bytecode_cleanup=yes"
    } else {
        ""
    };
    let artifact_cleanup = if policy.scheduled_artifact_cleanup {
        "; scheduled_artifact_cleanup=yes"
    } else {
        ""
    };
    let kind = if policy.scheduled_bytecode_cleanup || policy.scheduled_artifact_cleanup {
        "Cleanup"
    } else {
        "Scan"
    };
    Ok(format!(
        "# {kind} policy snapshot: older_than_seconds={}; enabled_ecosystems={enabled_ecosystems}; config_path={config_path}; config_required={config_required}; profile_present={profile_present}; profile={profile}{cleanup}{artifact_cleanup}\n",
        policy
            .older_than_seconds
            .map_or_else(|| "all".to_owned(), |age| age.to_string()),
    ))
}

#[cfg(target_os = "macos")]
pub fn scheduled_scope_token(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
) -> Result<String> {
    use rustix::fs::{Mode, OFlags};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;

    let mut hash = Sha256::new();
    let mut add = |bytes: &[u8]| {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    };
    add(b"upkit-scheduled-scan-scope-macos-v1");
    add(&(roots.len() as u64).to_be_bytes());
    for (path, directory) in
        std::iter::once((executable, false)).chain(roots.iter().map(|root| (root.as_path(), true)))
    {
        if !path.is_absolute() || path.canonicalize().ok().as_deref() != Some(path) {
            bail!("scheduled executable and roots must be canonical absolute paths");
        }
        let expected = fs::symlink_metadata(path).context("inspect scheduled path identity")?;
        if expected.file_type().is_symlink() {
            bail!("scheduled path became a symbolic link");
        }
        let flags = OFlags::RDONLY
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW
            | if directory {
                OFlags::DIRECTORY
            } else {
                OFlags::empty()
            };
        let file = fs::File::from(
            rustix::fs::open(path, flags, Mode::empty())
                .context("open scheduled path without following its final link")?,
        );
        let metadata = file.metadata()?;
        if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
            bail!("scheduled path has an unexpected file type");
        }
        if expected.dev() != metadata.dev() || expected.ino() != metadata.ino() {
            bail!("scheduled path changed while its identity was inspected");
        }
        let created = metadata
            .created()
            .context("scheduled path lacks creation-time identity metadata")?
            .duration_since(std::time::UNIX_EPOCH)
            .context("scheduled path creation time predates the Unix epoch")?;
        add(path.as_os_str().as_encoded_bytes());
        add(&metadata.dev().to_le_bytes());
        add(&metadata.ino().to_le_bytes());
        add(&created.as_secs().to_le_bytes());
        add(&created.subsec_nanos().to_le_bytes());
        if !directory {
            add(&metadata.ctime().to_le_bytes());
            add(&metadata.ctime_nsec().to_le_bytes());
            add(&metadata.len().to_le_bytes());
        }
    }
    add(&(exclusions.len() as u64).to_be_bytes());
    for exclusion in exclusions {
        add(exclusion.as_os_str().as_encoded_bytes());
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(target_os = "windows")]
pub fn scheduled_scope_token(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
) -> Result<String> {
    windows::scheduled_scope_token(executable, roots, exclusions)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn scheduled_scope_token(_: &Path, _: &[PathBuf], _: &[PathBuf]) -> Result<String> {
    bail!("scheduled scope verification is unsupported on this platform")
}

/// Verify a scheduled scope immediately before starting its read-only scan.
pub fn run_guarded_scan(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    token: &str,
) -> Result<crate::sweep::ScanReport> {
    let actual = scheduled_scope_token(executable, roots, exclusions)?;
    let (older_than, enabled) = if let Some(policy) = policy_from_token(token)? {
        if policy.scheduled_bytecode_cleanup || policy.scheduled_artifact_cleanup {
            bail!("scheduled cleanup requires its dedicated command");
        }
        if policy.scope_token != actual {
            bail!("scheduled scan scope or executable changed; inspect and create a new schedule");
        }
        verify_configured_source(&policy, roots, exclusions)?;
        (
            policy.older_than_seconds.map(Duration::from_secs),
            policy.enabled_ecosystems,
        )
    } else {
        if token != actual {
            bail!("scheduled scan scope or executable changed; inspect and create a new schedule");
        }
        (None, None)
    };
    crate::sweep::scan_with_policy(
        roots,
        exclusions,
        older_than,
        enabled.as_deref(),
        &std::sync::atomic::AtomicBool::new(false),
        |_| {},
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn verified_bytecode_scope(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    token: &str,
) -> Result<crate::sweep::Scope> {
    let policy = policy_from_token(token)?.context("scheduled cleanup requires a policy token")?;
    if !policy.scheduled_bytecode_cleanup {
        bail!("scheduled cleanup was not approved in this policy");
    }
    if policy.scope_token != scheduled_scope_token(executable, roots, exclusions)? {
        bail!("scheduled cleanup scope or executable changed; inspect and create a new schedule");
    }
    verify_configured_source(&policy, roots, exclusions)?;
    Ok(crate::sweep::Scope {
        roots: roots.to_vec(),
        exclusions: exclusions.to_vec(),
        older_than_seconds: policy.older_than_seconds,
        enabled: policy.enabled_ecosystems,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn verified_artifact_scope(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    token: &str,
) -> Result<crate::sweep::Scope> {
    let policy = policy_from_token(token)?.context("scheduled cleanup requires a policy token")?;
    if !policy.scheduled_artifact_cleanup {
        bail!("scheduled artifact cleanup was not approved in this policy");
    }
    if policy.scope_token != scheduled_scope_token(executable, roots, exclusions)? {
        bail!("scheduled cleanup scope or executable changed; inspect and create a new schedule");
    }
    verify_configured_source(&policy, roots, exclusions)?;
    Ok(crate::sweep::Scope {
        roots: roots.to_vec(),
        exclusions: exclusions.to_vec(),
        older_than_seconds: policy.older_than_seconds,
        enabled: policy.enabled_ecosystems,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn scheduled_cleanup_modes(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    token: &str,
) -> Result<(bool, bool)> {
    let policy = policy_from_token(token)?.context("scheduled cleanup requires a policy token")?;
    if !policy.scheduled_bytecode_cleanup && !policy.scheduled_artifact_cleanup {
        bail!("scheduled cleanup was not approved in this policy");
    }
    if policy.scope_token != scheduled_scope_token(executable, roots, exclusions)? {
        bail!("scheduled cleanup scope or executable changed; inspect and create a new schedule");
    }
    verify_configured_source(&policy, roots, exclusions)?;
    Ok((
        policy.scheduled_bytecode_cleanup,
        policy.scheduled_artifact_cleanup,
    ))
}

/// Render a platform schedule plan without writing it or calling the manager.
pub fn preview_scan(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    frequency: Frequency,
) -> Result<ScanSchedulePreview> {
    preview_scan_with_policy(executable, roots, exclusions, frequency, None)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn preview_scan_with_policy(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    frequency: Frequency,
    policy: Option<ScheduledScanPolicy>,
) -> Result<ScanSchedulePreview> {
    if roots.is_empty() {
        bail!("select at least one workspace root");
    }
    let settings = crate::config::Settings {
        workspace_roots: roots.to_vec(),
        exclusions: exclusions.to_vec(),
        ..Default::default()
    };
    settings.validate()?;
    if !executable.is_absolute() || !fs::metadata(executable).is_ok_and(|meta| meta.is_file()) {
        bail!("executable must be an absolute existing file");
    }
    for root in roots {
        if fs::symlink_metadata(root)
            .context("inspect workspace root")?
            .file_type()
            .is_symlink()
            || !fs::metadata(root)?.is_dir()
            || root.canonicalize()? != *root
        {
            bail!("workspace roots must be existing canonical directories without symbolic links");
        }
    }
    #[cfg(target_os = "linux")]
    let path_arg = |path: &Path| -> Result<String> {
        unit_arg(path.to_str().context("systemd paths must be UTF-8")?)
    };
    #[cfg(target_os = "linux")]
    let args = roots
        .iter()
        .map(|root| path_arg(root))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    #[cfg(target_os = "linux")]
    let systemd_exclusions = exclusions
        .iter()
        .map(|path| {
            unit_arg(&format!(
                "--exclude={}",
                path.to_str().context("systemd exclusions must be UTF-8")?
            ))
        })
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    #[cfg(target_os = "linux")]
    let executable_arg = unit_arg(&format!(
        ":{}",
        executable
            .to_str()
            .context("systemd executable path must be UTF-8")?
    ))?;
    let frequency_label = match frequency {
        Frequency::Daily => "daily",
        Frequency::Weekly => "weekly",
    };
    let unit_directory = if cfg!(target_os = "macos") {
        dirs::home_dir()
            .context("cannot determine user home directory")?
            .join("Library/LaunchAgents")
    } else {
        dirs::config_dir()
            .context("cannot determine user configuration directory")?
            .join("systemd/user")
    };
    if !unit_directory.is_absolute() {
        bail!("user unit directory must be absolute");
    }
    #[cfg(target_os = "linux")]
    unit_arg(
        unit_directory
            .to_str()
            .context("systemd unit directory must be UTF-8")?,
    )?;
    let scope_token = scheduled_scope_token(executable, roots, &settings.exclusions)?;
    let configured = policy.is_some();
    let scheduled_scope_token = if let Some(policy) = policy {
        let token = policy_token(scope_token, policy.clone())?;
        verify_configured_source(&policy, roots, &settings.exclusions)?;
        token
    } else {
        scope_token
    };
    let decoded_policy = policy_from_token(&scheduled_scope_token)?;
    let bytecode_cleanup = decoded_policy
        .as_ref()
        .is_some_and(|policy| policy.scheduled_bytecode_cleanup);
    let artifact_cleanup = decoded_policy
        .as_ref()
        .is_some_and(|policy| policy.scheduled_artifact_cleanup);
    let cleanup = bytecode_cleanup || artifact_cleanup;
    #[cfg(target_os = "macos")]
    if cleanup {
        bail!("automatic scheduled cleanup is supported only on Linux");
    }
    #[cfg(target_os = "linux")]
    let policy_comment = decoded_policy
        .as_ref()
        .map(schedule_policy_comment)
        .transpose()?
        .unwrap_or_default();
    #[cfg(target_os = "linux")]
    let description = if artifact_cleanup {
        "Upkit scheduled workspace artifact cleanup"
    } else if bytecode_cleanup {
        "Upkit scheduled Python bytecode cleanup"
    } else {
        "Upkit workspace artifact scan"
    };
    #[cfg(target_os = "linux")]
    let command = if artifact_cleanup {
        format!(
            "scheduled-cleanup --authorize-scheduled-artifact-cleanup{}",
            if bytecode_cleanup {
                " --authorize-scheduled-cleanup"
            } else {
                ""
            }
        )
    } else if bytecode_cleanup {
        "scheduled-bytecode-cleanup --authorize-scheduled-cleanup".to_owned()
    } else {
        "scan".to_owned()
    };
    #[cfg(target_os = "linux")]
    let authorization = if cleanup { " --yes" } else { "" };
    #[cfg(target_os = "linux")]
    let service_unit = format!(
        "[Unit]\nDescription={description}\n\n[Service]\nType=oneshot\n{policy_comment}ExecStart={executable_arg} --non-interactive --offline{authorization} --json --config /dev/null sweep {command} --scope-token {scheduled_scope_token} {systemd_exclusions} {args}\n"
    );
    #[cfg(target_os = "linux")]
    let timer_unit = format!(
        "[Unit]\nDescription={description} timer\n\n[Timer]\nOnCalendar={frequency_label}\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
    );
    #[cfg(target_os = "macos")]
    let (service_unit, timer_unit) = (
        launchd_scan_plist(
            executable,
            roots,
            &settings.exclusions,
            &scheduled_scope_token,
            frequency,
            false,
        )?,
        String::new(),
    );
    if service_unit.len() > 65536 || timer_unit.len() > 65536 {
        bail!("generated unit exceeds the supported size limit");
    }
    let preview_token = preview_token(
        executable,
        roots,
        &unit_directory,
        &service_unit,
        &timer_unit,
    )?;
    Ok(ScanSchedulePreview {
        roots: roots.to_vec(),
        exclusions: settings.exclusions,
        frequency: frequency_label,
        unit_directory,
        preview_token,
        scheduled_scope_token,
        service_unit,
        timer_unit,
        warning: if cfg!(target_os = "macos") {
            if configured {
                "Preview only; no LaunchAgent is installed. After explicit confirmation, Upkit creates a private user-owned plist and enables it in the current user's GUI launchd domain. RunAtLoad is false; read-only scans run at 03:00 local time daily or Sunday weekly. The token is not authorization. Configured roots, exclusions, retention, ecosystem filters, executable and workspace identities are checked again before each scan; paths can change during traversal."
            } else {
                "Preview only; no LaunchAgent is installed. After explicit confirmation, Upkit creates a private user-owned plist and enables it in the current user's GUI launchd domain. RunAtLoad is false; read-only scans run at 03:00 local time daily or Sunday weekly. The token is not authorization. Only the explicit roots and exclusions apply; configuration profiles, retention and ecosystem filters are not applied. Executable and workspace identities are checked before each scan; paths can change during traversal."
            }
        } else if artifact_cleanup {
            "Preview only; no timer is installed. After explicit authorization, scheduled cleanup can permanently remove at most 8 explicitly scoped rebuildable project artifacts per run after at least 30 days. The profile must list enabled ecosystems; only Maven targets, Zig cache, Dart generated state, and Python pytest/mypy caches qualify. Cargo is excluded from scheduled cleanup until target-directory configuration can be verified safely. A local history attempt is reserved before each removal; interrupted or failed writes may leave incomplete records. No project scripts run."
        } else if cleanup {
            "This timer automatically and permanently removes eligible Python bytecode in the listed workspaces after the configured retention period, at most 32 files per run. It excludes unchecked-hash caches and never removes Trash, shared caches, or artifact directories. Each file is rechecked against project, Git, process, path, source and configuration policy; header validation cannot prove bytecode matches source. The scan and removal results are written to the user journal, and Upkit attempts to record them in local history. Installation requires an existing private user unit directory and may run promptly. Concurrent changes can race the checks; interruption can leave a quarantine file."
        } else if configured {
            "Preview only; no timer is installed. The token is not authorization. This scan writes JSON to the user journal and attempts to record local history; it never cleans files. Configured roots, exclusions, retention and ecosystem filters are rechecked before each scan. Installation requires an existing private user unit directory and may run the scan promptly. Root and executable identity are checked before scanning; paths may still change afterward."
        } else {
            "Preview only; no timer is installed. The token is not authorization. This scan writes JSON to the user journal and attempts to record local history; it never cleans files. Only the explicit roots and exclusions apply; configuration profiles, retention and ecosystem filters are not applied. Installation requires an existing private user unit directory and may run the scan promptly. Root and executable identity are checked before scanning; paths may still change afterward."
        },
    })
}

#[cfg(target_os = "windows")]
fn preview_scan_with_policy(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    frequency: Frequency,
    policy: Option<ScheduledScanPolicy>,
) -> Result<ScanSchedulePreview> {
    windows::preview_scan(executable, roots, exclusions, frequency, policy)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn preview_scan_with_policy(
    _: &Path,
    _: &[PathBuf],
    _: &[PathBuf],
    _: Frequency,
    _: Option<ScheduledScanPolicy>,
) -> Result<ScanSchedulePreview> {
    bail!("user maintenance schedules are unsupported on this platform")
}

/// Inspect the conventional timer name without claiming ownership or changing it.
pub fn status() -> crate::maintenance::TimerStatus {
    #[cfg(target_os = "linux")]
    {
        crate::maintenance::timer_command("upkit-scan.timer", true)
    }
    #[cfg(target_os = "macos")]
    {
        match which::which("launchctl") {
            Ok(launchctl) => launchd_status_with(&launchctl),
            Err(_) => crate::maintenance::TimerStatus {
                state: "unavailable".into(),
                load_state: None,
                unit_file_state: None,
                last_trigger: None,
                next_trigger: None,
                detail: Some("launchctl not found".into()),
            },
        }
    }
    #[cfg(target_os = "windows")]
    {
        windows::status()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        crate::maintenance::TimerStatus {
            state: "unsupported".into(),
            load_state: None,
            unit_file_state: None,
            last_trigger: None,
            next_trigger: None,
            detail: Some("user maintenance schedules are unsupported on this platform".into()),
        }
    }
}

/// Return a schedule snapshot only when manager inspection is allowed.
pub fn status_with_dry_run(dry_run: bool) -> crate::maintenance::TimerStatus {
    if dry_run {
        crate::maintenance::TimerStatus::skipped(
            "dry-run skips the platform scheduler query; schedule state was not inspected",
        )
    } else {
        status()
    }
}

/// Inspect the conventional schedule name while allowing read-only checks to stop early.
pub(crate) fn status_with_cancel(cancel: &AtomicBool) -> crate::maintenance::TimerStatus {
    #[cfg(target_os = "windows")]
    {
        windows::status_with_cancel(cancel)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = cancel;
        status()
    }
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_status_with(executable: &Path) -> crate::maintenance::TimerStatus {
    use std::{
        os::unix::process::CommandExt,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    const LABEL: &str = "upkit-scan.timer";
    const OUTPUT_LIMIT: usize = 65_536;
    let status = |state: &str, load_state: Option<&str>, detail: Option<&str>| {
        crate::maintenance::TimerStatus {
            state: state.into(),
            load_state: load_state.map(str::to_owned),
            unit_file_state: None,
            last_trigger: None,
            next_trigger: None,
            detail: detail.map(str::to_owned),
        }
    };
    let unavailable = |detail| status("unavailable", None, Some(detail));
    let mut command = Command::new(executable);
    command
        .arg("list")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return unavailable("could not start launchctl"),
    };
    let Some(mut stdout) = child.stdout.take() else {
        stop_child_process_group(&mut child);
        return unavailable("launchctl output unavailable");
    };
    if rustix::fs::fcntl_getfl(&stdout)
        .and_then(|flags| rustix::fs::fcntl_setfl(&stdout, flags | rustix::fs::OFlags::NONBLOCK))
        .is_err()
    {
        stop_child_process_group(&mut child);
        return unavailable("could not bound launchctl output reads");
    }

    let mut output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    let result = loop {
        let stdout_eof = match collect_process_output(&mut stdout, &mut output, OUTPUT_LIMIT) {
            Ok(eof) => eof,
            Err(detail) => {
                stop_child_process_group(&mut child);
                return unavailable(detail);
            }
        };
        // Avoid reaping the group leader while its output is still open.
        if stdout_eof {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(_) => return unavailable("launchctl could not be monitored"),
            }
        }
        if Instant::now() >= deadline {
            stop_child_process_group(&mut child);
            return unavailable("launchctl timed out");
        }
        thread::sleep(Duration::from_millis(10));
    };
    if !result.success() {
        return unavailable("launchctl query failed; manager state is unavailable");
    }
    match launchd_list_has_label(&output, LABEL) {
        Some(true) => status(
            "loaded",
            Some("loaded"),
            Some(
                "launchd reports this label loaded; name only, ownership and action are unverified",
            ),
        ),
        Some(false) => status(
            "not_found",
            Some("not-found"),
            Some(
                "label absent from the complete current launchd list; ownership and action are unverified",
            ),
        ),
        None => unavailable("launchctl returned an unverifiable list format"),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", all(test, unix)))]
fn collect_process_output(
    reader: &mut impl std::io::Read,
    output: &mut Vec<u8>,
    limit: usize,
) -> std::result::Result<bool, &'static str> {
    loop {
        let mut buffer = [0; 4096];
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) if output.len() + count <= limit => {
                output.extend_from_slice(&buffer[..count]);
            }
            Ok(_) => return Err("process output exceeded limit"),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("could not read child process output"),
        }
    }
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_list_has_label(output: &[u8], label: &str) -> Option<bool> {
    let output = std::str::from_utf8(output).ok()?;
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    if lines.next()?.split_whitespace().collect::<Vec<_>>() != ["PID", "Status", "Label"] {
        return None;
    }
    let mut found = false;
    for line in lines {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 3
            || (fields[0] != "-" && fields[0].parse::<u32>().is_err())
            || fields[1].parse::<i32>().is_err()
        {
            return None;
        }
        if fields[2] == label {
            if found {
                return None;
            }
            found = true;
        }
    }
    Some(found)
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn stop_child_process_group(child: &mut std::process::Child) {
    use rustix::process::{Pid, Signal, kill_process_group};

    // shortcut: external child reaping can release this ID; use stable process handles if available.
    if let Some(pid) = i32::try_from(child.id()).ok().and_then(Pid::from_raw) {
        let _ = kill_process_group(pid, Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(all(test, unix))]
mod launchd_status_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake_launchctl(directory: &Path, script: &str) -> PathBuf {
        let executable = directory.join("launchctl");
        fs::write(&executable, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        executable
    }

    #[test]
    fn reads_only_a_matching_row_from_the_documented_legacy_list() {
        let dir = tempfile::tempdir().unwrap();
        let manager = fake_launchctl(
            dir.path(),
            "[ \"$#\" -eq 1 ] && [ \"$1\" = list ] || exit 8\nprintf '%s' 'PID Status Label\n- 0 com.example.other\n123 0 upkit-scan.timer\n'",
        );

        let status = launchd_status_with(&manager);
        assert_eq!(status.state, "loaded");
        assert_eq!(status.load_state.as_deref(), Some("loaded"));
        assert!(status.unit_file_state.is_none());
        assert!(status.last_trigger.is_none());
        assert!(status.next_trigger.is_none());
        assert!(
            status
                .detail
                .unwrap()
                .contains("name only, ownership and action are unverified")
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn absent_label_requires_a_complete_valid_list_and_bad_output_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let absent = fake_launchctl(
            dir.path(),
            "[ \"$#\" -eq 1 ] && [ \"$1\" = list ] || exit 8\nprintf '%s' 'PID Status Label\n- 0 com.example.other\n'",
        );
        assert_eq!(launchd_status_with(&absent).state, "not_found");

        let malformed = fake_launchctl(
            dir.path(),
            "[ \"$#\" -eq 1 ] && [ \"$1\" = list ] || exit 8\nprintf '%s' 'PID Status Label\n- running upkit-scan.timer\n'",
        );
        assert_eq!(launchd_status_with(&malformed).state, "unavailable");

        let failed = fake_launchctl(dir.path(), "exit 1");
        assert_eq!(launchd_status_with(&failed).state, "unavailable");
    }

    #[test]
    fn output_limit_stops_an_oversized_fake_manager() {
        let dir = tempfile::tempdir().unwrap();
        let payload = "x".repeat(65_537);
        let manager = fake_launchctl(
            dir.path(),
            &format!("[ \"$#\" -eq 1 ] && [ \"$1\" = list ] || exit 8\nprintf '%s' '{payload}'"),
        );
        let status = launchd_status_with(&manager);
        assert_eq!(status.state, "unavailable");
        assert!(status.detail.unwrap().contains("exceeded limit"));
    }

    #[test]
    fn timeout_kills_a_fake_manager_and_pipe_holding_descendant() {
        let dir = tempfile::tempdir().unwrap();
        let manager = fake_launchctl(
            dir.path(),
            "[ \"$#\" -eq 1 ] && [ \"$1\" = list ] || exit 8\nsleep 30 &\nwait",
        );
        let started = std::time::Instant::now();
        let status = launchd_status_with(&manager);
        assert_eq!(status.state, "unavailable");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn timeout_stops_pipe_holder_after_fake_manager_exits() {
        let dir = tempfile::tempdir().unwrap();
        let manager = fake_launchctl(dir.path(), "( sleep 3; : > \"$0.marker\" ) &\nexit 0");
        let status = launchd_status_with(&manager);
        assert_eq!(status.state, "unavailable");
        assert!(status.detail.unwrap().contains("timed out"));
        std::thread::sleep(std::time::Duration::from_millis(1_200));
        assert!(!manager.with_extension("marker").exists());
    }
}

#[cfg(target_os = "linux")]
fn systemctl(args: &[&str]) -> Result<String> {
    let executable = which::which("systemctl").context("systemctl not found")?;
    systemctl_with(&executable, args, Duration::from_secs(10))
}

#[cfg(target_os = "linux")]
fn systemctl_with(executable: &Path, args: &[&str], timeout: Duration) -> Result<String> {
    use std::{
        process::{Command, Stdio},
        thread,
        time::Instant,
    };
    const OUTPUT_LIMIT: usize = 65_536;
    let mut child = Command::new(executable)
        .arg("--user")
        .args(args)
        .env("SYSTEMD_PAGER", "cat")
        .env("SYSTEMD_COLORS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("start systemctl")?;
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        bail!("capture systemctl output; outcome may be unknown");
    };
    if rustix::fs::fcntl_getfl(&stdout)
        .and_then(|flags| rustix::fs::fcntl_setfl(&stdout, flags | rustix::fs::OFlags::NONBLOCK))
        .is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        bail!("could not bound systemctl output reads; outcome may be unknown");
    }
    let deadline = Instant::now() + timeout;
    let mut data = Vec::new();
    let mut child_status = None;
    let status = loop {
        if child_status.is_none() {
            child_status = child
                .try_wait()
                .context("systemctl could not be monitored; outcome may be unknown")?;
        }
        let stdout_eof = match collect_process_output(&mut stdout, &mut data, OUTPUT_LIMIT) {
            Ok(eof) => eof,
            Err(error) => {
                if child_status.is_none() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                bail!("{error}; systemctl outcome may be unknown");
            }
        };
        if stdout_eof && let Some(status) = child_status.take() {
            break status;
        }
        if Instant::now() >= deadline {
            if child_status.is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
            bail!("systemctl timed out; outcome may be unknown");
        }
        thread::sleep(Duration::from_millis(10));
    };
    if !status.success() {
        bail!("systemctl failed; inspect user manager state before retrying");
    }
    String::from_utf8(data).context("systemctl output is not UTF-8")
}

#[cfg(all(test, target_os = "linux"))]
mod systemctl_tests {
    use super::systemctl_with;
    use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

    #[test]
    fn reads_fake_manager_output() {
        let fixture = tempfile::tempdir().unwrap();
        let manager = fixture.path().join("systemctl");
        fs::write(&manager, "#!/bin/sh\nprintf '%s' \"$1:$2\"\n").unwrap();
        fs::set_permissions(&manager, fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(
            systemctl_with(&manager, &["show"], Duration::from_secs(2)).unwrap(),
            "--user:show"
        );
    }

    #[test]
    fn rejects_oversized_fake_manager_output() {
        let fixture = tempfile::tempdir().unwrap();
        let manager = fixture.path().join("systemctl");
        fs::write(
            &manager,
            "#!/bin/sh\ni=0\nwhile [ \"$i\" -lt 7000 ]; do printf '0123456789'; i=$((i + 1)); done\n",
        )
        .unwrap();
        fs::set_permissions(&manager, fs::Permissions::from_mode(0o700)).unwrap();

        let error = systemctl_with(&manager, &["show"], Duration::from_secs(5)).unwrap_err();
        assert!(error.to_string().contains("output exceeded limit"));
        assert!(error.to_string().contains("outcome may be unknown"));
    }

    #[test]
    fn timeout_returns_when_a_descendant_holds_stdout() {
        let fixture = tempfile::tempdir().unwrap();
        let manager = fixture.path().join("systemctl");
        let marker = fixture.path().join("descendant-ran");
        fs::write(&manager, "#!/bin/sh\n( sleep 1; : > \"$2\" ) &\nexit 0\n").unwrap();
        fs::set_permissions(&manager, fs::Permissions::from_mode(0o700)).unwrap();

        let error = systemctl_with(
            &manager,
            &[marker.to_str().unwrap()],
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(marker.exists());
    }
}

#[cfg(target_os = "linux")]
fn unit_property(name: &str, property: &str) -> Result<String> {
    let argument = format!("--property={property}");
    let output = systemctl(&["show", name, "--no-pager", &argument, "--value"])?;
    let value = output.trim_end_matches(['\n', '\r']);
    if value.chars().any(char::is_control) {
        bail!("invalid systemd unit property");
    }
    Ok(value.to_owned())
}

#[cfg(target_os = "linux")]
fn fragment(name: &str) -> Result<String> {
    unit_property(name, "FragmentPath")
}

#[cfg(any(target_os = "macos", test))]
const LAUNCHD_LABEL: &str = "upkit-scan.timer";
#[cfg(any(target_os = "macos", all(test, unix)))]
const LAUNCHD_PLIST: &str = "upkit-scan.timer.plist";

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_domain() -> String {
    format!("gui/{}", rustix::process::geteuid().as_raw())
}

#[cfg(target_os = "macos")]
fn launchd_agents_directory() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("cannot determine user home directory")?
        .join("Library/LaunchAgents"))
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_directory(path: &Path) -> Result<(fs::File, fs::Metadata)> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() || path.canonicalize().ok().as_deref() != Some(path) {
        bail!("LaunchAgents directory must be an existing canonical path without links");
    }
    let before = fs::symlink_metadata(path).context("inspect LaunchAgents directory")?;
    if before.file_type().is_symlink() || !before.is_dir() {
        bail!("LaunchAgents path is not a real directory");
    }
    let file = fs::File::open(path).context("open LaunchAgents directory")?;
    let metadata = file.metadata()?;
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
        || before.dev() != metadata.dev()
        || before.ino() != metadata.ino()
    {
        bail!(
            "LaunchAgents directory must be owned by the current user and not writable by others"
        );
    }
    Ok((file, metadata))
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_same_directory(path: &Path, expected: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    launchd_directory(path).is_ok_and(|(_, actual)| {
        actual.dev() == expected.dev()
            && actual.ino() == expected.ino()
            && actual.uid() == expected.uid()
            && actual.mode() & 0o022 == 0
    })
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    launchd_same_file_identity(left, right)
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.is_file()
        && right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.nlink() == 1
        && right.nlink() == 1
        && left.mode() & 0o077 == 0
        && right.mode() & 0o077 == 0
        && left.len() == right.len()
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_read_plist(directory: &fs::File, name: &str) -> Result<(String, fs::Metadata)> {
    use rustix::fs::{Mode, OFlags};
    use std::{io::Read, os::unix::fs::MetadataExt};
    let open = || {
        rustix::fs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(fs::File::from)
    };
    let file = open().context("open LaunchAgent without following links")?;
    let metadata = file.metadata()?;
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o600 != 0o600
        || metadata.len() > 65536
    {
        bail!("LaunchAgent is not a private, single-link user-owned regular file");
    }
    let mut bytes = Vec::new();
    (&file).take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        bail!("LaunchAgent exceeds the supported size limit");
    }
    let after = file.metadata()?;
    let reopened = open()
        .context("reopen LaunchAgent after inspection")?
        .metadata()?;
    if !launchd_same_file(&metadata, &after) || !launchd_same_file(&metadata, &reopened) {
        bail!("LaunchAgent changed during inspection");
    }
    Ok((
        String::from_utf8(bytes).context("LaunchAgent is not UTF-8")?,
        metadata,
    ))
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_create_plist(directory: &fs::File, content: &str) -> Result<fs::Metadata> {
    use rustix::fs::{Mode, OFlags};
    use std::{io::Write, os::unix::fs::MetadataExt};
    let fd = rustix::fs::openat(
        directory,
        LAUNCHD_PLIST,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .context("create LaunchAgent; installation may be partial")?;
    let mut file = fs::File::from(fd);
    file.write_all(content.as_bytes())
        .context("write LaunchAgent; installation may be partial")?;
    file.sync_all()
        .context("sync LaunchAgent; installation may be partial")?;
    let identity = file.metadata()?;
    if identity.uid() != rustix::process::geteuid().as_raw()
        || identity.nlink() != 1
        || identity.mode() & 0o077 != 0
        || identity.mode() & 0o600 != 0o600
        || identity.len() != content.len() as u64
    {
        bail!("LaunchAgent identity or permissions changed during creation");
    }
    let (written, observed) = launchd_read_plist(directory, LAUNCHD_PLIST)?;
    if written != content || !launchd_same_file(&identity, &observed) {
        bail!("LaunchAgent changed after creation");
    }
    Ok(identity)
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_remove_plist(
    directory: &fs::File,
    expected: &str,
    identity: &fs::Metadata,
    quarantine: &str,
) -> Result<()> {
    use rustix::fs::{AtFlags, RenameFlags};
    let (current, before) = launchd_read_plist(directory, LAUNCHD_PLIST)?;
    if current != expected || !launchd_same_file(identity, &before) {
        bail!("LaunchAgent changed before removal");
    }
    rustix::fs::renameat_with(
        directory,
        LAUNCHD_PLIST,
        directory,
        quarantine,
        RenameFlags::NOREPLACE,
    )
    .context("quarantine LaunchAgent; it may remain under the shown quarantine path")?;
    let (moved, after) = launchd_read_plist(directory, quarantine)?;
    if moved != expected || !launchd_same_file_identity(identity, &after) {
        bail!("quarantined LaunchAgent identity changed; inspect it before retrying");
    }
    let (check, checked) = launchd_read_plist(directory, quarantine)?;
    if check != expected || !launchd_same_file(&after, &checked) {
        bail!("quarantined LaunchAgent changed before removal");
    }
    rustix::fs::unlinkat(directory, quarantine, AtFlags::empty())
        .context("remove quarantined LaunchAgent; removal may be partial")?;
    directory
        .sync_all()
        .context("sync LaunchAgents directory; removal may be partial")?;
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn launchd_validate_plist(text: &str) -> Result<LaunchdScan> {
    let scan = launchd_parse_scan_plist(text)?;
    let expected = launchd_scan_plist(
        &scan.executable,
        &scan.roots,
        &scan.exclusions,
        &scan.scope_token,
        scan.frequency,
        false,
    )?;
    if expected != text {
        bail!("LaunchAgent differs from an Upkit-generated read-only scan");
    }
    Ok(scan)
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_output_with(
    executable: &Path,
    args: &[&str],
) -> Result<(std::process::ExitStatus, Vec<u8>)> {
    use std::{
        os::unix::process::CommandExt,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    const OUTPUT_LIMIT: usize = 65_536;
    let mut child = Command::new(executable)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .context("could not start launchctl")?;
    let Some(mut stdout) = child.stdout.take() else {
        stop_child_process_group(&mut child);
        bail!("launchctl output unavailable");
    };
    if rustix::fs::fcntl_getfl(&stdout)
        .and_then(|flags| rustix::fs::fcntl_setfl(&stdout, flags | rustix::fs::OFlags::NONBLOCK))
        .is_err()
    {
        stop_child_process_group(&mut child);
        bail!("could not bound launchctl output reads");
    }
    let mut output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let eof = match collect_process_output(&mut stdout, &mut output, OUTPUT_LIMIT) {
            Ok(eof) => eof,
            Err(error) => {
                stop_child_process_group(&mut child);
                bail!("{error}");
            }
        };
        if eof {
            match child.try_wait() {
                Ok(Some(status)) => return Ok((status, output)),
                Ok(None) => {}
                Err(_) => bail!("launchctl could not be monitored"),
            }
        }
        if Instant::now() >= deadline {
            stop_child_process_group(&mut child);
            bail!("launchctl timed out");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_run_with(executable: &Path, args: &[&str]) -> Result<()> {
    use std::{
        os::unix::process::CommandExt,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    let mut child = Command::new(executable)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .context("could not start launchctl")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                stop_child_process_group(&mut child);
                bail!("launchctl timed out; inspect user manager state before retrying");
            }
            Err(_) => bail!(
                "launchctl could not be monitored; inspect user manager state before retrying"
            ),
        }
    };
    if !status.success() {
        bail!("launchctl failed; inspect user manager state before retrying");
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn launchd_disabled_label(output: &[u8], label: &str) -> Option<bool> {
    let output = std::str::from_utf8(output).ok()?;
    let mut lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .peekable();
    if lines.next()? != "disabled services = {" {
        return None;
    }
    let mut found = None;
    let mut closed = false;
    for line in lines.by_ref() {
        if line == "}" {
            closed = true;
            break;
        }
        let (name, state) = line.split_once(" => ")?;
        let name = name.strip_prefix('"')?.strip_suffix('"')?;
        if name.is_empty() || !matches!(state, "enabled" | "disabled") {
            return None;
        }
        if name == label {
            if found.is_some() {
                return None;
            }
            found = Some(state == "disabled");
        }
    }
    if !closed || lines.next().is_some() {
        return None;
    }
    Some(found.unwrap_or(false))
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_disabled_state_with(executable: &Path, domain: &str) -> Result<bool> {
    let (status, output) = launchd_output_with(executable, &["print-disabled", domain])?;
    if !status.success() {
        bail!("launchctl could not query disabled-job state");
    }
    launchd_disabled_label(&output, LAUNCHD_LABEL)
        .context("launchctl returned an unverifiable disabled-job list")
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_loaded_path_with(executable: &Path, target: &str) -> Result<Option<PathBuf>> {
    let (status, output) = launchd_output_with(executable, &["print", target])?;
    if !status.success() {
        return Ok(None);
    }
    let output = std::str::from_utf8(&output).context("launchctl job output is not UTF-8")?;
    let mut path = None;
    let mut agent = false;
    for line in output.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("path = ") {
            if path.replace(PathBuf::from(value)).is_some() {
                bail!("launchctl reported multiple job paths");
            }
        } else if line == "type = LaunchAgent" {
            agent = true;
        }
    }
    if !agent {
        bail!("launchctl did not identify the loaded job as a LaunchAgent");
    }
    Ok(path)
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launchd_verify_loaded_path(executable: &Path, path: &Path) -> Result<()> {
    let target = format!("{}/{}", launchd_domain(), LAUNCHD_LABEL);
    let expected = path.to_str().context("LaunchAgent path must be UTF-8")?;
    if launchd_loaded_path_with(executable, &target)?.as_deref() != Some(Path::new(expected)) {
        bail!("loaded launchd label does not resolve to the verified Upkit LaunchAgent");
    }
    Ok(())
}

/// Install and enable an explicitly authorized, unchanged scan plan.
#[cfg(target_os = "linux")]
pub fn install_scan(
    executable: &Path,
    plan: &ScanSchedulePreview,
    token: &str,
    frequency: Frequency,
) -> Result<&'static str> {
    ensure_artifact_schedule_supported(plan)?;
    install_scan_checked(executable, plan, token, frequency, || Ok(()))
}

#[cfg(target_os = "macos")]
pub fn install_scan(
    executable: &Path,
    plan: &ScanSchedulePreview,
    token: &str,
    frequency: Frequency,
) -> Result<&'static str> {
    ensure_artifact_schedule_supported(plan)?;
    launchd_install_scan_checked(executable, plan, token, frequency, || Ok(()))
}

#[cfg(target_os = "windows")]
pub fn install_scan(
    executable: &Path,
    plan: &ScanSchedulePreview,
    token: &str,
    frequency: Frequency,
) -> Result<&'static str> {
    ensure_artifact_schedule_supported(plan)?;
    windows::install_scan(executable, plan, token, frequency, || Ok(()))
}

#[cfg(target_os = "macos")]
fn launchd_install_scan_checked(
    executable: &Path,
    plan: &ScanSchedulePreview,
    token: &str,
    frequency: Frequency,
    check_scope: impl FnOnce() -> Result<()>,
) -> Result<&'static str> {
    if token != plan.preview_token {
        bail!("schedule preview token does not match");
    }
    let current = preview_from_plan(executable, plan, frequency)?;
    if current.preview_token != token || !current.timer_unit.is_empty() {
        bail!("schedule plan changed since preview; preview again");
    }
    let launchctl = which::which("launchctl").context("launchctl not found")?;
    let manager = launchd_status_with(&launchctl);
    if manager.state == "unavailable" {
        bail!("launchd status is unavailable; refusing to install a schedule");
    }
    if manager.state == "loaded" {
        bail!("launchd already has this label; refusing to create a duplicate schedule");
    }
    let (directory, directory_meta) = launchd_directory(&current.unit_directory)?;
    let file_path = current.unit_directory.join(LAUNCHD_PLIST);
    let path = file_path
        .to_str()
        .context("LaunchAgent path must be UTF-8")?;
    let identity = launchd_create_plist(&directory, &current.service_unit)?;
    if !launchd_same_directory(&current.unit_directory, &directory_meta) {
        bail!("LaunchAgent identity or directory changed; installation may be partial");
    }
    let (installed, installed_identity) = launchd_read_plist(&directory, LAUNCHD_PLIST)
        .context("inspect LaunchAgent; installation may be partial")?;
    launchd_validate_plist(&installed)?;
    if installed != current.service_unit || !launchd_same_file(&identity, &installed_identity) {
        bail!("LaunchAgent changed after creation; installation may be partial");
    }
    check_scope()
        .context("configured scan policy changed; LaunchAgent remains but is not enabled")?;
    let domain = launchd_domain();
    let target = format!("{domain}/{LAUNCHD_LABEL}");
    launchd_run_with(&launchctl, &["enable", &target])
        .context("enable launchd label; LaunchAgent remains and outcome may be partial")?;
    launchd_run_with(&launchctl, &["bootstrap", &domain, path])
        .context("bootstrap LaunchAgent; it may already be loaded")?;
    let observed = preview_disable().context(
        "LaunchAgent may already be loaded; inspect launchd and the plist before retrying",
    )?;
    Ok(
        if observed.active_state == "loaded"
            && observed.unit_file_state.as_deref() == Some("enabled")
            && observed.unit_directory == current.unit_directory
            && observed.service_unit == current.service_unit
        {
            "active_and_enabled"
        } else {
            "unverified"
        },
    )
}

#[cfg(target_os = "linux")]
fn install_scan_checked(
    executable: &Path,
    plan: &ScanSchedulePreview,
    token: &str,
    frequency: Frequency,
    check_scope: impl FnOnce() -> Result<()>,
) -> Result<&'static str> {
    use std::{
        io::{Read, Write},
        os::unix::fs::MetadataExt,
    };
    if token != plan.preview_token {
        bail!("schedule preview token does not match");
    }
    let current = preview_from_plan(executable, plan, frequency)?;
    if current.preview_token != token {
        bail!("schedule plan changed since preview; preview again");
    }
    for unit in ["upkit-scan.service", "upkit-scan.timer"] {
        if unit_property(unit, "LoadState")? != "not-found"
            || !fragment(unit)?.is_empty()
            || !unit_property(unit, "DropInPaths")?.is_empty()
        {
            bail!("a unit or drop-in named {unit} already exists; refusing to overwrite it");
        }
    }
    let directory = rustix::fs::openat2(
        rustix::fs::CWD,
        &current.unit_directory,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
        rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
    )
    .context("open existing user unit directory without links")?;
    let directory = fs::File::from(directory);
    let meta = directory.metadata()?;
    if meta.uid() != rustix::process::geteuid().as_raw() || meta.mode() & 0o022 != 0 {
        bail!("user unit directory must be owned by the current user and not group/other writable");
    }
    let same_directory = || -> bool {
        rustix::fs::openat2(
            rustix::fs::CWD,
            &current.unit_directory,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )
        .ok()
        .map(fs::File::from)
        .and_then(|f| f.metadata().ok())
        .is_some_and(|m| {
            m.dev() == meta.dev()
                && m.ino() == meta.ino()
                && m.uid() == meta.uid()
                && m.mode() & 0o022 == 0
        })
    };
    if !same_directory() {
        bail!("unit directory changed before installation");
    }
    let mut written = Vec::new();
    for (name, contents) in [
        ("upkit-scan.service", &current.service_unit),
        ("upkit-scan.timer", &current.timer_unit),
    ] {
        let fd = rustix::fs::openat2(
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
        let mut file = fs::File::from(fd);
        file.write_all(contents.as_bytes())
            .with_context(|| format!("write {name}; installation may be partial"))?;
        file.sync_all()
            .with_context(|| format!("sync {name}; installation may be partial"))?;
        let identity = file
            .metadata()
            .context("inspect written unit; installation may be partial")?;
        written.push((name, contents, identity.dev(), identity.ino()));
    }
    let same_units = || -> bool {
        written.iter().all(|(name, expected, device, inode)| {
            let Ok(fd) = rustix::fs::openat2(
                &directory,
                *name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::empty(),
                rustix::fs::ResolveFlags::BENEATH
                    | rustix::fs::ResolveFlags::NO_SYMLINKS
                    | rustix::fs::ResolveFlags::NO_XDEV,
            ) else {
                return false;
            };
            let file = fs::File::from(fd);
            let Ok(meta) = file.metadata() else {
                return false;
            };
            if !meta.is_file()
                || meta.dev() != *device
                || meta.ino() != *inode
                || meta.uid() != rustix::process::geteuid().as_raw()
                || meta.nlink() != 1
                || meta.mode() & 0o022 != 0
            {
                return false;
            }
            let mut bytes = Vec::new();
            file.take(65537).read_to_end(&mut bytes).is_ok() && bytes == expected.as_bytes()
        })
    };
    if !same_directory() || !same_units() {
        bail!("unit directory changed; installation may be partial");
    }
    systemctl(&["daemon-reload"]).context("reload user manager; unit files may remain")?;
    for unit in ["upkit-scan.service", "upkit-scan.timer"] {
        let expected = current.unit_directory.join(unit);
        if unit_property(unit, "LoadState")? != "loaded"
            || !unit_property(unit, "DropInPaths")?.is_empty()
            || fragment(unit)? != expected.to_str().context("unit path must be UTF-8")?
        {
            bail!("user manager loaded a different {unit}; files remain but timer was not enabled");
        }
    }
    if !same_directory()
        || !same_units()
        || preview_from_plan(executable, plan, frequency)?.preview_token != token
    {
        bail!("schedule plan or unit files changed; files remain but timer was not enabled");
    }
    check_scope().context("configuration changed; unit files remain but timer was not enabled")?;
    systemctl(&["enable", "--now", "upkit-scan.timer"])
        .context("enable timer; outcome may be partial or unknown")?;
    let timer = status();
    let verified = (|| -> Result<bool> {
        Ok(timer.state == "active"
            && timer.unit_file_state.as_deref() == Some("enabled")
            && same_directory()
            && same_units()
            && unit_property("upkit-scan.timer", "LoadState")? == "loaded"
            && unit_property("upkit-scan.service", "LoadState")? == "loaded"
            && unit_property("upkit-scan.timer", "DropInPaths")?.is_empty()
            && unit_property("upkit-scan.service", "DropInPaths")?.is_empty()
            && fragment("upkit-scan.timer")?
                == current
                    .unit_directory
                    .join("upkit-scan.timer")
                    .to_string_lossy()
            && fragment("upkit-scan.service")?
                == current
                    .unit_directory
                    .join("upkit-scan.service")
                    .to_string_lossy())
    })()
    .context("timer may already be enabled; inspect user manager and unit files before retrying")?;
    Ok(if verified {
        "active_and_enabled"
    } else {
        "unverified"
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn install_scan(
    _: &Path,
    _: &ScanSchedulePreview,
    _: &str,
    _: Frequency,
) -> Result<&'static str> {
    Err(schedule_changes_unsupported())
}

#[derive(Clone, Debug, Serialize)]
pub struct DisableSchedulePreview {
    pub unit_directory: PathBuf,
    pub service_unit: String,
    pub timer_unit: String,
    pub active_state: String,
    pub unit_file_state: Option<String>,
    pub preview_token: String,
    pub warning: &'static str,
}

/// Inspect the exact user timer and its service before asking to disable it.
#[cfg(target_os = "linux")]
pub fn preview_disable() -> Result<DisableSchedulePreview> {
    use sha2::{Digest, Sha256};
    use std::{io::Read, os::unix::fs::MetadataExt};
    let unit_directory = dirs::config_dir()
        .context("cannot determine user configuration directory")?
        .join("systemd/user");
    if !unit_directory.is_absolute() {
        bail!("user unit directory must be absolute");
    }
    let open_directory = || {
        rustix::fs::openat2(
            rustix::fs::CWD,
            &unit_directory,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )
        .map(fs::File::from)
    };
    let directory = open_directory().context("open existing user unit directory without links")?;
    let dir_meta = directory.metadata()?;
    let uid = rustix::process::geteuid().as_raw();
    if dir_meta.uid() != uid || dir_meta.mode() & 0o022 != 0 {
        bail!("user unit directory must be owned by the current user and not group/other writable");
    }
    let mut hash = Sha256::new();
    let mut add = |bytes: &[u8]| {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    };
    add(b"upkit-scan-disable-preview-v1");
    add(&fs::read("/proc/sys/kernel/random/boot_id").context("read boot identity")?);
    add(unit_directory.as_os_str().as_encoded_bytes());
    add(&dir_meta.dev().to_le_bytes());
    add(&dir_meta.ino().to_le_bytes());
    let mut units = Vec::new();
    for name in ["upkit-scan.service", "upkit-scan.timer"] {
        let fd = rustix::fs::openat2(
            &directory,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::BENEATH
                | rustix::fs::ResolveFlags::NO_SYMLINKS
                | rustix::fs::ResolveFlags::NO_XDEV,
        )
        .with_context(|| format!("open {name} without links"))?;
        let mut file = fs::File::from(fd);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
            || metadata.len() > 65536
        {
            bail!("{name} is not a private, single-link regular file within the size limit");
        }
        let mut data = Vec::new();
        (&mut file)
            .take(65537)
            .read_to_end(&mut data)
            .context("read unit file")?;
        if data.len() > 65536 {
            bail!("unit file exceeds size limit");
        }
        let text = String::from_utf8(data).context("unit file is not UTF-8")?;
        if text.chars().any(|c| c.is_control() && c != '\n') {
            bail!("unit file contains control characters");
        }
        if unit_property(name, "LoadState")? != "loaded"
            || unit_property(name, "NeedDaemonReload")? != "no"
            || !unit_property(name, "DropInPaths")?.is_empty()
            || fragment(name)?
                != unit_directory
                    .join(name)
                    .to_str()
                    .context("unit path is not UTF-8")?
        {
            bail!(
                "user manager does not load the expected unmodified {name}; inspect it before disabling"
            );
        }
        let after = file.metadata()?;
        let reopened = rustix::fs::openat2(
            &directory,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::BENEATH
                | rustix::fs::ResolveFlags::NO_SYMLINKS
                | rustix::fs::ResolveFlags::NO_XDEV,
        )
        .map(fs::File::from)
        .context("reopen unit after inspection")?
        .metadata()?;
        for check in [&after, &reopened] {
            if !check.is_file()
                || check.dev() != metadata.dev()
                || check.ino() != metadata.ino()
                || check.uid() != uid
                || check.nlink() != 1
                || check.mode() & 0o022 != 0
                || check.len() != metadata.len()
                || check.ctime() != metadata.ctime()
                || check.ctime_nsec() != metadata.ctime_nsec()
            {
                bail!("{name} changed during inspection");
            }
        }
        add(name.as_bytes());
        add(&metadata.dev().to_le_bytes());
        add(&metadata.ino().to_le_bytes());
        add(&metadata.ctime().to_le_bytes());
        add(&metadata.ctime_nsec().to_le_bytes());
        add(text.as_bytes());
        units.push(text);
    }
    let dir_again = open_directory()?.metadata()?;
    if dir_again.dev() != dir_meta.dev()
        || dir_again.ino() != dir_meta.ino()
        || dir_again.uid() != uid
        || dir_again.mode() & 0o022 != 0
    {
        bail!("unit directory changed during preview");
    }
    let service_lines = units[0].lines().collect::<Vec<_>>();
    let service_command = service_lines
        .last()
        .copied()
        .filter(|line| line.starts_with("ExecStart="))
        .unwrap_or_default();
    let service_token = service_command
        .split_once(" --scope-token ")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .unwrap_or_default();
    let service_policy = policy_from_token(service_token)?;
    let bytecode_cleanup = service_policy
        .as_ref()
        .is_some_and(|policy| policy.scheduled_bytecode_cleanup);
    let artifact_cleanup = service_policy
        .as_ref()
        .is_some_and(|policy| policy.scheduled_artifact_cleanup);
    let cleanup = bytecode_cleanup || artifact_cleanup;
    let description = if cleanup {
        if artifact_cleanup {
            "Upkit scheduled workspace artifact cleanup"
        } else {
            "Upkit scheduled Python bytecode cleanup"
        }
    } else {
        "Upkit workspace artifact scan"
    };
    let service_description = format!("Description={description}");
    let service_prefix = [
        "[Unit]",
        service_description.as_str(),
        "",
        "[Service]",
        "Type=oneshot",
    ];
    let valid_scope_token = service_policy.is_some()
        || (service_token.len() == 64
            && service_token.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let valid_policy_line = match service_policy {
        Some(policy) => {
            service_lines.len() == 7
                && service_lines[5] == schedule_policy_comment(&policy)?.trim_end()
        }
        None => service_lines.len() == 6,
    };
    let cleanup_command = if artifact_cleanup {
        format!(
            "sweep scheduled-cleanup --authorize-scheduled-artifact-cleanup{}",
            if bytecode_cleanup {
                " --authorize-scheduled-cleanup"
            } else {
                ""
            }
        )
    } else if bytecode_cleanup {
        "sweep scheduled-bytecode-cleanup --authorize-scheduled-cleanup".into()
    } else {
        "sweep scan".into()
    };
    if !service_lines.starts_with(&service_prefix)
        || !valid_scope_token
        || !valid_policy_line
        || !service_command.contains(&format!(
            " --non-interactive --offline{} --json --config /dev/null {cleanup_command} ",
            if cleanup { " --yes" } else { "" }
        ))
        || !["daily", "weekly"].iter().any(|frequency| units[1] == format!("[Unit]\nDescription={description} timer\n\n[Timer]\nOnCalendar={frequency}\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n")) {
        bail!("unit content does not match an Upkit-generated timer; refusing to disable it");
    }
    let timer = status();
    if timer.state == "unavailable" || timer.state == "not_found" {
        bail!("timer status is unavailable");
    }
    add(timer.state.as_bytes());
    add(timer.unit_file_state.as_deref().unwrap_or("").as_bytes());
    Ok(DisableSchedulePreview {
        unit_directory,
        service_unit: units.remove(0),
        timer_unit: units.remove(0),
        active_state: timer.state,
        unit_file_state: timer.unit_file_state,
        preview_token: hex::encode(hash.finalize()),
        warning: "Disable and stop this timer only; an already running service, including authorized cleanup, may continue. The unit files remain. Review both unit contents; ownership is not independently proven.",
    })
}

#[cfg(target_os = "macos")]
pub fn preview_disable() -> Result<DisableSchedulePreview> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    let unit_directory = launchd_agents_directory()?;
    let (directory, directory_meta) = launchd_directory(&unit_directory)?;
    let (service_unit, file_meta) = launchd_read_plist(&directory, LAUNCHD_PLIST)?;
    launchd_validate_plist(&service_unit)?;
    if !launchd_same_directory(&unit_directory, &directory_meta) {
        bail!("LaunchAgents directory changed during preview");
    }
    let launchctl = which::which("launchctl").context("launchctl not found")?;
    let timer = launchd_status_with(&launchctl);
    if !matches!(timer.state.as_str(), "loaded" | "not_found") {
        bail!("launchd status is unavailable");
    }
    let disabled = launchd_disabled_state_with(&launchctl, &launchd_domain())?;
    if timer.state == "loaded" && disabled {
        bail!("launchd loaded state conflicts with its disabled-job setting");
    }
    if timer.state == "loaded" {
        launchd_verify_loaded_path(&launchctl, &unit_directory.join(LAUNCHD_PLIST))?;
    }
    let mut hash = Sha256::new();
    let mut add = |bytes: &[u8]| {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    };
    add(b"upkit-launchd-disable-preview-v1");
    add(unit_directory.as_os_str().as_encoded_bytes());
    add(&directory_meta.dev().to_le_bytes());
    add(&directory_meta.ino().to_le_bytes());
    add(&file_meta.dev().to_le_bytes());
    add(&file_meta.ino().to_le_bytes());
    add(&file_meta.ctime().to_le_bytes());
    add(&file_meta.ctime_nsec().to_le_bytes());
    add(service_unit.as_bytes());
    add(timer.state.as_bytes());
    add(if disabled { b"disabled" } else { b"enabled" });
    Ok(DisableSchedulePreview {
        unit_directory,
        service_unit,
        timer_unit: String::new(),
        active_state: timer.state,
        unit_file_state: Some(if disabled { "disabled" } else { "enabled" }.into()),
        preview_token: hex::encode(hash.finalize()),
        warning: "Disables and unloads only the verified Upkit LaunchAgent; a running scan may be stopped. The private user-owned plist remains installed. The preview token expires when the plist, paths, or launchd state changes.",
    })
}

#[cfg(target_os = "windows")]
pub fn preview_disable() -> Result<DisableSchedulePreview> {
    windows::preview_disable()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn preview_disable() -> Result<DisableSchedulePreview> {
    Err(schedule_changes_unsupported())
}

/// Disable an explicitly authorized timer after rechecking its preview.
#[cfg(target_os = "linux")]
pub fn disable_scan(plan: &DisableSchedulePreview, token: &str) -> Result<&'static str> {
    if token != plan.preview_token {
        bail!("schedule preview token does not match");
    }
    let current = preview_disable()?;
    if current.preview_token != token {
        bail!("timer or unit files changed since preview; preview again");
    }
    systemctl(&["disable", "--now", "upkit-scan.timer"])
        .context("disable timer; outcome may be partial or unknown")?;
    let timer = status();
    let verified = (|| -> Result<bool> {
        Ok(timer.state == "inactive"
            && timer.unit_file_state.as_deref() == Some("disabled")
            && unit_property("upkit-scan.timer", "NeedDaemonReload")? == "no"
            && unit_property("upkit-scan.service", "NeedDaemonReload")? == "no"
            && unit_property("upkit-scan.timer", "DropInPaths")?.is_empty()
            && unit_property("upkit-scan.service", "DropInPaths")?.is_empty()
            && fragment("upkit-scan.timer")?
                == current
                    .unit_directory
                    .join("upkit-scan.timer")
                    .to_string_lossy()
            && fragment("upkit-scan.service")?
                == current
                    .unit_directory
                    .join("upkit-scan.service")
                    .to_string_lossy())
    })()
    .context("timer may already be disabled; inspect the user manager before retrying")?;
    Ok(if verified {
        "inactive_and_disabled"
    } else {
        "unverified"
    })
}

#[cfg(target_os = "macos")]
pub fn disable_scan(plan: &DisableSchedulePreview, token: &str) -> Result<&'static str> {
    if token != plan.preview_token {
        bail!("schedule preview token does not match");
    }
    let current = preview_disable()?;
    if current.preview_token != token {
        bail!("LaunchAgent or launchd state changed since preview; preview again");
    }
    let launchctl = which::which("launchctl").context("launchctl not found")?;
    let domain = launchd_domain();
    let target = format!("{domain}/{LAUNCHD_LABEL}");
    launchd_run_with(&launchctl, &["disable", &target])
        .context("disable LaunchAgent; outcome may be partial or unknown")?;
    if current.active_state == "loaded" {
        launchd_run_with(&launchctl, &["bootout", &target])
            .context("disable state was set; LaunchAgent may still be loaded")?;
    }
    let observed = preview_disable()
        .context("LaunchAgent may already be disabled; inspect launchd before retrying")?;
    Ok(
        if observed.active_state == "not_found"
            && observed.unit_file_state.as_deref() == Some("disabled")
            && observed.service_unit == current.service_unit
        {
            "inactive_and_disabled"
        } else {
            "unverified"
        },
    )
}

#[cfg(target_os = "windows")]
pub fn disable_scan(plan: &DisableSchedulePreview, token: &str) -> Result<&'static str> {
    windows::disable_scan(plan, token)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn disable_scan(_: &DisableSchedulePreview, _: &str) -> Result<&'static str> {
    Err(schedule_changes_unsupported())
}

#[derive(Clone, Debug, Serialize)]
pub struct EnableSchedulePreview {
    pub intended: ScanSchedulePreview,
    pub installed: DisableSchedulePreview,
    pub preview_token: String,
    pub warning: &'static str,
}

fn absolute_config_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn encode_config_path(path: &Path) -> Result<String> {
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes()
    };
    #[cfg(not(unix))]
    let bytes = path
        .to_str()
        .context("scheduled configuration path must be UTF-8")?
        .as_bytes();
    Ok(hex::encode(bytes))
}

fn decode_config_path(value: &str) -> Result<PathBuf> {
    let bytes = hex::decode(value).context("decode scheduled configuration path")?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
    }
    #[cfg(not(unix))]
    {
        Ok(PathBuf::from(
            String::from_utf8(bytes).context("scheduled configuration path must be UTF-8")?,
        ))
    }
}

fn configured_scan_scope_at(
    path: &Path,
    required: bool,
    profile: Option<&str>,
) -> Result<ConfiguredScanScope> {
    let settings = crate::config::load(path, required)?;
    let (roots, exclusions, older_than) =
        crate::config::profile_scan_options(&settings, profile, &[], &[], None)?;
    let enabled_ecosystems = crate::config::enabled_ecosystems(&settings, profile)?;
    let scheduled_bytecode_cleanup = crate::config::scheduled_bytecode_cleanup(&settings, profile)?;
    let scheduled_artifact_cleanup = crate::config::scheduled_artifact_cleanup(&settings, profile)?;
    if scheduled_bytecode_cleanup {
        if older_than.is_none_or(|age| age < Duration::from_secs(7 * 24 * 60 * 60)) {
            bail!("scheduled bytecode cleanup requires artifact_retention of at least 7 days");
        }
        if enabled_ecosystems
            .as_ref()
            .is_some_and(|enabled| !enabled.contains(&crate::sweep::Ecosystem::Python))
        {
            bail!("scheduled bytecode cleanup requires the Python ecosystem to be enabled");
        }
    }
    if scheduled_artifact_cleanup {
        validate_scheduled_artifact_policy(older_than, enabled_ecosystems.as_deref())?;
    }
    let path = absolute_config_path(path)?;
    let source = ConfiguredSource {
        path: encode_config_path(&path)?,
        required,
        profile: profile.map(str::to_owned),
    };
    Ok(ConfiguredScanScope {
        roots,
        exclusions,
        older_than,
        enabled_ecosystems,
        scheduled_bytecode_cleanup,
        scheduled_artifact_cleanup,
        source,
    })
}

/// Resolve the effective workspace scope and policies captured by a configured schedule.
fn resolved_configured_scan_scope(
    config: Option<&Path>,
    profile: Option<&str>,
) -> Result<ConfiguredScanScope> {
    let path = crate::config::config_path(config)?;
    configured_scan_scope_at(&path, config.is_some(), profile)
}

/// Resolve the configured roots and exclusions when no scan policy needs to be preserved.
/// Configured schedule operations use the full internal policy resolver instead.
pub fn configured_scan_scope(
    config: Option<&Path>,
    profile: Option<&str>,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let scope = resolved_configured_scan_scope(config, profile)?;
    if scope.older_than.is_some()
        || scope.enabled_ecosystems.is_some()
        || scope.scheduled_bytecode_cleanup
        || scope.scheduled_artifact_cleanup
    {
        bail!(
            "configured scan scope includes retention or ecosystem policies; use a configured schedule preview to preserve them"
        );
    }
    Ok((scope.roots, scope.exclusions))
}

fn verify_configured_source(
    policy: &ScheduledScanPolicy,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
) -> Result<()> {
    let Some(source) = &policy.source else {
        return Ok(());
    };
    let path = decode_config_path(&source.path)?;
    let current = configured_scan_scope_at(&path, source.required, source.profile.as_deref())?;
    if current.roots != roots
        || current.exclusions != exclusions
        || current.older_than.map(|age| age.as_secs()) != policy.older_than_seconds
        || current.enabled_ecosystems != policy.enabled_ecosystems
        || current.scheduled_bytecode_cleanup != policy.scheduled_bytecode_cleanup
        || current.scheduled_artifact_cleanup != policy.scheduled_artifact_cleanup
    {
        bail!(
            "configured workspace scope or scan policy changed; inspect and create a new schedule"
        );
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn policy_from_plan(plan: &ScanSchedulePreview) -> Result<Option<ScheduledScanPolicy>> {
    policy_from_token(&plan.scheduled_scope_token)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn policy_matches_scope(policy: &ScheduledScanPolicy, scope: &ConfiguredScanScope) -> bool {
    policy.version
        == if scope.scheduled_artifact_cleanup {
            4
        } else if scope.scheduled_bytecode_cleanup {
            3
        } else {
            2
        }
        && policy.older_than_seconds == scope.older_than.map(|age| age.as_secs())
        && policy.enabled_ecosystems == scope.enabled_ecosystems
        && policy.scheduled_bytecode_cleanup == scope.scheduled_bytecode_cleanup
        && policy.scheduled_artifact_cleanup == scope.scheduled_artifact_cleanup
        && policy.source.as_ref() == Some(&scope.source)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn preview_from_plan(
    executable: &Path,
    plan: &ScanSchedulePreview,
    frequency: Frequency,
) -> Result<ScanSchedulePreview> {
    preview_scan_with_policy(
        executable,
        &plan.roots,
        &plan.exclusions,
        frequency,
        policy_from_plan(plan)?,
    )
}

pub fn preview_configured_install(
    executable: &Path,
    config: Option<&Path>,
    profile: Option<&str>,
    frequency: Frequency,
) -> Result<ScanSchedulePreview> {
    let scope = resolved_configured_scan_scope(config, profile)?;
    preview_scan_with_policy(
        executable,
        &scope.roots,
        &scope.exclusions,
        frequency,
        Some(scope.policy()),
    )
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn ensure_configured_scope(
    plan: &ScanSchedulePreview,
    config: Option<&Path>,
    profile: Option<&str>,
    allow_legacy: bool,
) -> Result<()> {
    let scope = resolved_configured_scan_scope(config, profile)?;
    let policy = policy_from_plan(plan)?;
    let policy_matches = match policy.as_ref() {
        Some(policy) => policy_matches_scope(policy, &scope),
        None => allow_legacy && scope.older_than.is_none() && scope.enabled_ecosystems.is_none(),
    };
    if scope.roots != plan.roots || scope.exclusions != plan.exclusions || !policy_matches {
        bail!("configured workspace scope or scan policy changed; preview again");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn install_configured_scan(
    executable: &Path,
    plan: &ScanSchedulePreview,
    token: &str,
    frequency: Frequency,
    config: Option<&Path>,
    profile: Option<&str>,
) -> Result<&'static str> {
    ensure_artifact_schedule_supported(plan)?;
    ensure_configured_scope(plan, config, profile, false)?;
    #[cfg(target_os = "linux")]
    return install_scan_checked(executable, plan, token, frequency, || {
        ensure_configured_scope(plan, config, profile, false)
    });
    #[cfg(target_os = "macos")]
    return launchd_install_scan_checked(executable, plan, token, frequency, || {
        ensure_configured_scope(plan, config, profile, false)
    });
    #[cfg(target_os = "windows")]
    return windows::install_scan(executable, plan, token, frequency, || {
        ensure_configured_scope(plan, config, profile, false)
    });
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn install_configured_scan(
    _: &Path,
    _: &ScanSchedulePreview,
    _: &str,
    _: Frequency,
    _: Option<&Path>,
    _: Option<&str>,
) -> Result<&'static str> {
    Err(schedule_changes_unsupported())
}

pub fn preview_configured_enable(
    executable: &Path,
    config: Option<&Path>,
    profile: Option<&str>,
    frequency: Frequency,
) -> Result<EnableSchedulePreview> {
    let scope = resolved_configured_scan_scope(config, profile)?;
    let legacy_intended = if scope.older_than.is_none() && scope.enabled_ecosystems.is_none() {
        Some(preview_scan(
            executable,
            &scope.roots,
            &scope.exclusions,
            frequency,
        )?)
    } else {
        None
    };
    configured_enable_preview_with_installed(
        executable,
        &scope,
        frequency,
        preview_disable()?,
        legacy_intended,
    )
}

/// Review a disabled timer against a freshly generated scan plan.
pub fn preview_enable(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    frequency: Frequency,
) -> Result<EnableSchedulePreview> {
    preview_enable_with_policy(executable, roots, exclusions, frequency, None)
}

fn preview_enable_with_policy(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    frequency: Frequency,
    policy: Option<ScheduledScanPolicy>,
) -> Result<EnableSchedulePreview> {
    let intended = preview_scan_with_policy(executable, roots, exclusions, frequency, policy)?;
    enable_preview_from_installed(intended, preview_disable()?, None)
}

const LEGACY_CONFIGURED_ENABLE_WARNING: &str = "Enabling this timer may start the scan promptly. It reads selected workspaces, writes JSON to the user journal, and attempts to record local history; it does not clean files. This legacy runtime checks executable and embedded roots/exclusions only; it does not reload configuration or recheck retention/ecosystem policy. Config changes will not affect it; keep current policy empty and recreate the schedule after config, profile, or scope changes.";
const LEGACY_CONFIGURED_SCAN_WARNING: &str = "Preview only; no timer is installed. The token is not authorization. This legacy scheduled scan reads selected workspaces, writes JSON to the user journal, and attempts to record local history; it never cleans files. Runtime checks executable and embedded roots/exclusions only; it does not reload configuration or recheck retention/ecosystem policy. Paths may still change after validation.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScheduleBackend {
    Systemd,
    LaunchAgent,
    TaskScheduler,
    Unsupported,
}

impl ScheduleBackend {
    fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Systemd
        } else if cfg!(target_os = "macos") {
            Self::LaunchAgent
        } else if cfg!(target_os = "windows") {
            Self::TaskScheduler
        } else {
            Self::Unsupported
        }
    }
}

fn legacy_configured_enable_warning(backend: ScheduleBackend) -> &'static str {
    match backend {
        ScheduleBackend::Systemd => LEGACY_CONFIGURED_ENABLE_WARNING,
        ScheduleBackend::LaunchAgent => {
            "Enabling this legacy LaunchAgent bootstraps it in the current user's GUI launchd domain. RunAtLoad is false; the read-only scan runs at its next 03:00 local daily or Sunday weekly trigger. It emits JSON to standard output, and Upkit attempts to record each run in local operation history. This legacy runtime checks the executable and embedded roots/exclusions only; it does not reload configuration or recheck retention/ecosystem policy. Config changes will not affect it; keep current policy empty and recreate the schedule after config, profile, or scope changes."
        }
        ScheduleBackend::TaskScheduler => {
            "Enabling this legacy Task Scheduler task schedules its read-only scan for the next 03:00 local daily or Sunday weekly trigger. It emits JSON to standard output, and Upkit attempts to record each run in local operation history. This legacy runtime checks the executable and embedded roots/exclusions only; it does not reload configuration or recheck retention/ecosystem policy. Config changes will not affect it; keep current policy empty and recreate the schedule after config, profile, or scope changes."
        }
        ScheduleBackend::Unsupported => {
            "This legacy scheduled scan checks the executable and embedded roots/exclusions only; it does not reload configuration or recheck retention/ecosystem policy. Config changes will not affect it; keep current policy empty and recreate the schedule after config, profile, or scope changes."
        }
    }
}

fn legacy_configured_scan_warning(backend: ScheduleBackend) -> &'static str {
    match backend {
        ScheduleBackend::Systemd => LEGACY_CONFIGURED_SCAN_WARNING,
        ScheduleBackend::LaunchAgent => {
            "Preview only; no new LaunchAgent is installed. The verified existing LaunchAgent remains unloaded. This legacy scheduled scan emits JSON to standard output, and Upkit attempts to record each run in local operation history; it never cleans files. Runtime checks the executable and embedded roots/exclusions only; it does not reload configuration or recheck retention/ecosystem policy. Paths may still change after validation."
        }
        ScheduleBackend::TaskScheduler => {
            "Preview only; no new Task Scheduler task is registered. The verified existing task remains disabled. This legacy scheduled scan emits JSON to standard output, and Upkit attempts to record each run in local operation history; it never cleans files. Runtime checks the executable and embedded roots/exclusions only; it does not reload configuration or recheck retention/ecosystem policy. Paths may still change after validation."
        }
        ScheduleBackend::Unsupported => {
            "This legacy scheduled scan checks the executable and embedded roots/exclusions only; it does not reload configuration or recheck retention/ecosystem policy. Paths may still change after validation."
        }
    }
}

fn schedule_enable_warning(backend: ScheduleBackend, cleanup: bool) -> &'static str {
    match backend {
        ScheduleBackend::TaskScheduler => {
            "Enabling this Task Scheduler task schedules the read-only scan for its next 03:00 local daily or Sunday weekly trigger. It emits JSON to standard output, and Upkit attempts to record each run in local operation history. Workspace files are not cleaned. Task ownership, access rights, principal, scope, and state are checked again immediately before enabling, but Task Scheduler can change state after that check."
        }
        ScheduleBackend::LaunchAgent => {
            "Enabling this LaunchAgent bootstraps it in the current user's GUI launchd domain. RunAtLoad is false; the read-only scan runs at its next 03:00 local daily or Sunday weekly trigger. It emits JSON to standard output, and Upkit attempts to record each run in local operation history. Workspace files are not cleaned. Paths and executable may change after revalidation."
        }
        ScheduleBackend::Systemd if cleanup => {
            "Enabling this timer may promptly start automatic permanent cleanup under the approved policy. Results are written to the user journal, and Upkit attempts to record each run in local history; paths and executable may change after revalidation."
        }
        ScheduleBackend::Systemd => {
            "Enabling this timer may start the scan promptly. It reads the selected workspaces, writes JSON to the user journal, and Upkit attempts to record each run in local history; it does not clean files. Paths and executable may change after revalidation."
        }
        ScheduleBackend::Unsupported => {
            "Enabling this schedule may run the read-only scan at its next configured trigger. It emits JSON to standard output; Upkit attempts to record each run in local operation history. Workspace files are not cleaned."
        }
    }
}

fn schedule_edit_warning(backend: ScheduleBackend, cleanup: bool) -> &'static str {
    match backend {
        ScheduleBackend::TaskScheduler => {
            "Unregisters the verified disabled Task Scheduler task, then registers the replacement for its next 03:00 local daily or Sunday weekly trigger. The scan emits JSON to standard output, and Upkit attempts to record each run in local operation history. Failure may leave the old task missing or replacement registration partial; no automatic rollback is performed. Workspace files are not cleaned."
        }
        ScheduleBackend::LaunchAgent => {
            "Moves the verified disabled LaunchAgent plist to its shown quarantine path, then installs and bootstraps the replacement for its next 03:00 local daily or Sunday weekly trigger. The scan emits JSON to standard output, and Upkit attempts to record each run in local operation history. Failure may leave the old plist quarantined or the replacement partially installed; no automatic rollback is performed. Workspace files are not cleaned."
        }
        ScheduleBackend::Systemd if cleanup => {
            "Permanently removes the old units, then installs a timer that may promptly start automatic permanent cleanup under the approved policy. Failure may leave old units removed, quarantined, or replacement units partially installed. No automatic rollback is performed."
        }
        ScheduleBackend::Systemd => {
            "Permanently removes the old units, then installs and enables the new timer; the scan may start promptly. Failure may leave old units removed, quarantined, or replacement units partially installed. No automatic rollback is performed. Workspace files are not deleted."
        }
        ScheduleBackend::Unsupported => {
            "Replaces the existing schedule with the reviewed scan plan. Failure may leave the old schedule removed or the replacement partially installed; no automatic rollback is performed."
        }
    }
}

#[cfg(test)]
mod schedule_warning_tests {
    use super::*;

    #[test]
    fn enable_warnings_match_launchd_and_task_scheduler_outputs_and_triggers() {
        let windows = schedule_enable_warning(ScheduleBackend::TaskScheduler, false);
        assert!(windows.contains("Task Scheduler task"));
        assert!(windows.contains("next 03:00 local daily or Sunday weekly trigger"));
        assert!(windows.contains("standard output"));
        assert!(windows.contains("attempts to record each run in local operation history"));
        assert!(!windows.contains("journal"));
        assert!(!windows.contains("promptly"));

        let macos = schedule_enable_warning(ScheduleBackend::LaunchAgent, false);
        assert!(macos.contains("LaunchAgent"));
        assert!(macos.contains("RunAtLoad is false"));
        assert!(macos.contains("next 03:00 local daily or Sunday weekly trigger"));
        assert!(macos.contains("standard output"));
        assert!(macos.contains("attempts to record each run in local operation history"));
        assert!(!macos.contains("journal"));
        assert!(!macos.contains("promptly"));

        let systemd = schedule_enable_warning(ScheduleBackend::Systemd, true);
        assert!(systemd.contains("automatic permanent cleanup"));
        assert!(!systemd.contains("bytecode"));
        assert!(!systemd.contains("does not clean"));
    }

    #[test]
    fn legacy_enable_and_scan_warnings_do_not_claim_cross_platform_journals() {
        for backend in [ScheduleBackend::LaunchAgent, ScheduleBackend::TaskScheduler] {
            let enable = legacy_configured_enable_warning(backend);
            let scan = legacy_configured_scan_warning(backend);
            for warning in [enable, scan] {
                assert!(warning.contains("standard output"));
                assert!(warning.contains("attempts to record each run in local operation history"));
                assert!(!warning.contains("journal"));
                assert!(!warning.contains("timer"));
            }
            assert!(enable.contains("next 03:00 local daily or Sunday weekly trigger"));
        }
        assert!(
            legacy_configured_scan_warning(ScheduleBackend::LaunchAgent)
                .contains("existing LaunchAgent remains unloaded")
        );
        assert!(
            legacy_configured_scan_warning(ScheduleBackend::TaskScheduler)
                .contains("existing task remains disabled")
        );
    }

    #[test]
    fn edit_warnings_describe_platform_specific_partial_outcomes() {
        let windows = schedule_edit_warning(ScheduleBackend::TaskScheduler, false);
        assert!(windows.contains("Unregisters the verified disabled Task Scheduler task"));
        assert!(windows.contains("next 03:00 local daily or Sunday weekly trigger"));
        assert!(windows.contains("old task missing or replacement registration partial"));
        assert!(windows.contains("no automatic rollback"));
        assert!(windows.contains("standard output"));
        assert!(!windows.contains("quarantine"));
        assert!(!windows.contains("journal"));
        assert!(!windows.contains("unit"));

        let macos = schedule_edit_warning(ScheduleBackend::LaunchAgent, false);
        assert!(macos.contains("LaunchAgent plist"));
        assert!(macos.contains("quarantine path"));
        assert!(macos.contains("next 03:00 local daily or Sunday weekly trigger"));
        assert!(macos.contains("replacement partially installed"));
        assert!(macos.contains("standard output"));
        assert!(macos.contains("attempts to record each run in local operation history"));
        assert!(!macos.contains("journal"));

        let systemd = schedule_edit_warning(ScheduleBackend::Systemd, true);
        assert!(systemd.contains("automatic permanent cleanup"));
        assert!(!systemd.contains("bytecode"));
        assert!(!systemd.contains("Workspace files are not deleted"));
    }
}

#[cfg(not(target_os = "windows"))]
fn enable_units_match(intended: &ScanSchedulePreview, installed: &DisableSchedulePreview) -> bool {
    installed.unit_directory == intended.unit_directory
        && installed.service_unit == intended.service_unit
        && installed.timer_unit == intended.timer_unit
}

#[cfg(target_os = "windows")]
fn enable_units_match(intended: &ScanSchedulePreview, installed: &DisableSchedulePreview) -> bool {
    installed.unit_directory == intended.unit_directory
        && installed.timer_unit.is_empty()
        && windows::same_task_except_enabled(&intended.service_unit, &installed.service_unit)
            .is_ok_and(|matches| matches)
}

fn is_disabled_and_idle(installed: &DisableSchedulePreview) -> bool {
    #[cfg(target_os = "windows")]
    let idle = installed.active_state == "disabled";
    #[cfg(not(target_os = "windows"))]
    let idle = matches!(installed.active_state.as_str(), "inactive" | "not_found");
    idle && installed.unit_file_state.as_deref() == Some("disabled")
}

fn enable_preview_from_installed(
    intended: ScanSchedulePreview,
    mut installed: DisableSchedulePreview,
    warning: Option<&'static str>,
) -> Result<EnableSchedulePreview> {
    use sha2::{Digest, Sha256};
    if !is_disabled_and_idle(&installed) {
        bail!("timer must be confirmed inactive and disabled before enabling");
    }
    if !enable_units_match(&intended, &installed) {
        bail!("installed units differ from the selected scan plan; inspect them before enabling");
    }
    installed.warning = if cfg!(target_os = "macos") {
        "The plist matches Upkit's read-only format and a private user-owned LaunchAgents file; launchd's loaded path is checked when present."
    } else if cfg!(target_os = "windows") {
        "The task matches Upkit's read-only XML format, current-user principal, owner and access-control checks."
    } else {
        "The existing units are shown for review; their origin is not independently proven."
    };
    let mut hash = Sha256::new();
    hash.update(b"upkit-scan-enable-preview-v1\0");
    hash.update(intended.preview_token.as_bytes());
    hash.update(installed.preview_token.as_bytes());
    let cleanup = schedules_cleanup(&intended);
    Ok(EnableSchedulePreview {
        intended,
        installed,
        preview_token: hex::encode(hash.finalize()),
        warning: warning
            .unwrap_or_else(|| schedule_enable_warning(ScheduleBackend::current(), cleanup)),
    })
}

fn configured_enable_preview_with_installed(
    executable: &Path,
    scope: &ConfiguredScanScope,
    frequency: Frequency,
    installed: DisableSchedulePreview,
    legacy_intended: Option<ScanSchedulePreview>,
) -> Result<EnableSchedulePreview> {
    if !is_disabled_and_idle(&installed) {
        bail!("timer must be confirmed inactive and disabled before enabling");
    }
    if scope.older_than.is_none()
        && scope.enabled_ecosystems.is_none()
        && let Some(mut intended) = legacy_intended
        && enable_units_match(&intended, &installed)
    {
        intended.warning = legacy_configured_scan_warning(ScheduleBackend::current());
        return enable_preview_from_installed(
            intended,
            installed,
            Some(legacy_configured_enable_warning(ScheduleBackend::current())),
        );
    }
    let intended = preview_scan_with_policy(
        executable,
        &scope.roots,
        &scope.exclusions,
        frequency,
        Some(scope.policy()),
    )?;
    enable_preview_from_installed(intended, installed, None)
}

/// Enable an explicitly authorized and unchanged scan plan.
#[cfg(target_os = "linux")]
pub fn enable_scan(
    executable: &Path,
    plan: &EnableSchedulePreview,
    token: &str,
    frequency: Frequency,
) -> Result<&'static str> {
    ensure_artifact_schedule_supported(&plan.intended)?;
    enable_scan_checked(executable, plan, token, frequency, || Ok(()))
}

#[cfg(target_os = "linux")]
fn enable_scan_checked(
    executable: &Path,
    plan: &EnableSchedulePreview,
    token: &str,
    frequency: Frequency,
    check_scope: impl FnOnce() -> Result<()>,
) -> Result<&'static str> {
    if token != plan.preview_token {
        bail!("schedule preview token does not match");
    }
    let current = preview_enable_with_policy(
        executable,
        &plan.intended.roots,
        &plan.intended.exclusions,
        frequency,
        policy_from_plan(&plan.intended)?,
    )?;
    if current.preview_token != token {
        bail!("timer, unit files, or scan scope changed since preview; preview again");
    }
    check_scope()?;
    systemctl(&["enable", "--now", "upkit-scan.timer"])
        .context("enable timer; outcome may be partial or unknown")?;
    let observed = preview_disable().context(
        "timer may already be enabled; inspect the user manager and unit files before retrying",
    )?;
    if observed.active_state == "active"
        && observed.unit_file_state.as_deref() == Some("enabled")
        && observed.unit_directory == current.intended.unit_directory
        && observed.service_unit == current.intended.service_unit
        && observed.timer_unit == current.intended.timer_unit
    {
        Ok("active_and_enabled")
    } else {
        Ok("unverified")
    }
}

#[cfg(target_os = "macos")]
pub fn enable_scan(
    executable: &Path,
    plan: &EnableSchedulePreview,
    token: &str,
    frequency: Frequency,
) -> Result<&'static str> {
    ensure_artifact_schedule_supported(&plan.intended)?;
    launchd_enable_scan_checked(executable, plan, token, frequency, || Ok(()))
}

#[cfg(target_os = "macos")]
fn launchd_enable_scan_checked(
    executable: &Path,
    plan: &EnableSchedulePreview,
    token: &str,
    frequency: Frequency,
    check_scope: impl Fn() -> Result<()>,
) -> Result<&'static str> {
    if token != plan.preview_token {
        bail!("schedule preview token does not match");
    }
    let current = preview_enable_with_policy(
        executable,
        &plan.intended.roots,
        &plan.intended.exclusions,
        frequency,
        policy_from_plan(&plan.intended)?,
    )?;
    if current.preview_token != token {
        bail!("LaunchAgent, launchd state, or scan scope changed since preview; preview again");
    }
    check_scope()?;
    let launchctl = which::which("launchctl").context("launchctl not found")?;
    let launchctl_status = launchd_status_with(&launchctl);
    if launchctl_status.state != "not_found"
        || !launchd_disabled_state_with(&launchctl, &launchd_domain())?
    {
        bail!("LaunchAgent is no longer confirmed unloaded and disabled");
    }
    let domain = launchd_domain();
    let target = format!("{domain}/{LAUNCHD_LABEL}");
    launchd_run_with(&launchctl, &["enable", &target])
        .context("enable LaunchAgent; bootstrap was not attempted")?;
    if let Err(error) = check_scope() {
        let _ = launchd_run_with(&launchctl, &["disable", &target]);
        return Err(error.context("configuration changed; launchd disabled override was restored"));
    }
    let path = current
        .intended
        .unit_directory
        .join(LAUNCHD_PLIST)
        .to_str()
        .context("LaunchAgent path must be UTF-8")?
        .to_owned();
    launchd_run_with(&launchctl, &["bootstrap", &domain, &path])
        .context("bootstrap LaunchAgent; it may already be loaded")?;
    let observed = preview_disable().context(
        "LaunchAgent may already be loaded; inspect launchd and the plist before retrying",
    )?;
    Ok(
        if observed.active_state == "loaded"
            && observed.unit_file_state.as_deref() == Some("enabled")
            && observed.unit_directory == current.intended.unit_directory
            && observed.service_unit == current.intended.service_unit
        {
            "active_and_enabled"
        } else {
            "unverified"
        },
    )
}

#[cfg(target_os = "windows")]
pub fn enable_scan(
    executable: &Path,
    plan: &EnableSchedulePreview,
    token: &str,
    frequency: Frequency,
) -> Result<&'static str> {
    ensure_artifact_schedule_supported(&plan.intended)?;
    windows::enable_scan(executable, plan, token, frequency, || Ok(()))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn enable_configured_scan(
    executable: &Path,
    plan: &EnableSchedulePreview,
    token: &str,
    frequency: Frequency,
    config: Option<&Path>,
    profile: Option<&str>,
) -> Result<&'static str> {
    ensure_artifact_schedule_supported(&plan.intended)?;
    ensure_configured_scope(&plan.intended, config, profile, true)?;
    #[cfg(target_os = "linux")]
    return enable_scan_checked(executable, plan, token, frequency, || {
        ensure_configured_scope(&plan.intended, config, profile, true)
    });
    #[cfg(target_os = "macos")]
    return launchd_enable_scan_checked(executable, plan, token, frequency, || {
        ensure_configured_scope(&plan.intended, config, profile, true)
    });
    #[cfg(target_os = "windows")]
    return windows::enable_scan(executable, plan, token, frequency, || {
        ensure_configured_scope(&plan.intended, config, profile, true)
    });
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn enable_configured_scan(
    _: &Path,
    _: &EnableSchedulePreview,
    _: &str,
    _: Frequency,
    _: Option<&Path>,
    _: Option<&str>,
) -> Result<&'static str> {
    Err(schedule_changes_unsupported())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn enable_scan(
    _: &Path,
    _: &EnableSchedulePreview,
    _: &str,
    _: Frequency,
) -> Result<&'static str> {
    Err(schedule_changes_unsupported())
}

#[derive(Clone, Debug, Serialize)]
pub struct RemoveSchedulePreview {
    pub existing: DisableSchedulePreview,
    pub quarantine_paths: Vec<PathBuf>,
    pub preview_token: String,
    pub warning: &'static str,
}

/// Inspect an inactive timer and its unit files before removing them.
#[cfg(target_os = "linux")]
pub fn preview_remove() -> Result<RemoveSchedulePreview> {
    use sha2::{Digest, Sha256};
    let existing = preview_disable()?;
    if existing.active_state != "inactive"
        || existing.unit_file_state.as_deref() != Some("disabled")
    {
        bail!("timer must be inactive and disabled before removal");
    }
    if unit_property("upkit-scan.service", "ActiveState")? != "inactive" {
        bail!("service must be inactive before removing its units");
    }
    let mut hash = Sha256::new();
    hash.update(b"upkit-scan-remove-preview-v1\0");
    hash.update(existing.preview_token.as_bytes());
    let preview_token = hex::encode(hash.finalize());
    let quarantine_paths = ["service", "timer"]
        .iter()
        .map(|suffix| {
            existing
                .unit_directory
                .join(format!(".upkit-remove-{}.{suffix}", &preview_token[..24]))
        })
        .collect();
    Ok(RemoveSchedulePreview {
        existing,
        quarantine_paths,
        preview_token,
        warning: "Permanently removes the two shown unit files after checking the timer is disabled and the service is inactive. Changes may be partial; quarantine files may remain. Unit ownership is not independently proven.",
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn preview_remove() -> Result<RemoveSchedulePreview> {
    Err(schedule_changes_unsupported())
}

#[cfg(target_os = "macos")]
pub fn preview_remove() -> Result<RemoveSchedulePreview> {
    use sha2::{Digest, Sha256};
    let existing = preview_disable()?;
    if existing.active_state != "not_found"
        || existing.unit_file_state.as_deref() != Some("disabled")
    {
        bail!("LaunchAgent must be unloaded and disabled before removal");
    }
    let mut hash = Sha256::new();
    hash.update(b"upkit-launchd-remove-preview-v1\0");
    hash.update(existing.preview_token.as_bytes());
    let preview_token = hex::encode(hash.finalize());
    let quarantine_paths = vec![
        existing
            .unit_directory
            .join(format!(".upkit-remove-{}.plist", &preview_token[..24])),
    ];
    Ok(RemoveSchedulePreview {
        existing,
        quarantine_paths,
        preview_token,
        warning: "Permanently removes the verified, disabled LaunchAgent plist after rechecking its identity. The launchd disabled override remains; no other jobs or files are changed.",
    })
}

#[cfg(target_os = "windows")]
pub fn preview_remove() -> Result<RemoveSchedulePreview> {
    windows::preview_remove()
}

/// Remove explicitly approved, unchanged disabled units with create-only quarantine names.
#[cfg(target_os = "linux")]
pub fn remove_scan(plan: &RemoveSchedulePreview, token: &str) -> Result<&'static str> {
    use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags, ResolveFlags};
    use std::{io::Read, os::unix::fs::MetadataExt};
    if token != plan.preview_token {
        bail!("schedule preview token does not match");
    }
    let current = preview_remove()?;
    if current.preview_token != token {
        bail!("timer or units changed since preview; preview again");
    }
    let unit_dir = &current.existing.unit_directory;
    let open_dir = || {
        rustix::fs::openat2(
            rustix::fs::CWD,
            unit_dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map(fs::File::from)
    };
    let directory = open_dir().context("open user unit directory without links")?;
    let metadata = directory.metadata()?;
    let uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        bail!("user unit directory is not private");
    }
    let same_directory = || {
        open_dir()
            .ok()
            .and_then(|file| file.metadata().ok())
            .is_some_and(|m| {
                m.dev() == metadata.dev()
                    && m.ino() == metadata.ino()
                    && m.uid() == uid
                    && m.mode() & 0o022 == 0
            })
    };
    let read_checked = |name: &str, contents: &str| -> Result<(u64, u64)> {
        let fd = rustix::fs::openat2(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?;
        let file = fs::File::from(fd);
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != uid
            || meta.nlink() != 1
            || meta.mode() & 0o022 != 0
            || meta.len() > 65536
        {
            bail!("unit file identity or permissions changed");
        }
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes != contents.as_bytes() {
            bail!("unit file content changed");
        }
        Ok((meta.dev(), meta.ino()))
    };
    let units = [
        ("upkit-scan.service", current.existing.service_unit.as_str()),
        ("upkit-scan.timer", current.existing.timer_unit.as_str()),
    ];
    let names: Vec<_> = current
        .quarantine_paths
        .iter()
        .map(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .context("invalid quarantine name")
        })
        .collect::<Result<_>>()?;
    let identities = units
        .iter()
        .map(|(name, content)| read_checked(name, content))
        .collect::<Result<Vec<_>>>()?;
    if !same_directory()
        || unit_property("upkit-scan.service", "ActiveState")? != "inactive"
        || preview_remove()?.preview_token != token
    {
        bail!("unit directory or timer changed, or service became active");
    }
    for (index, (name, content)) in units.iter().enumerate() {
        if !same_directory()
            || read_checked(name, content)
                .context("inspect unit; files may remain under quarantine names")?
                != identities[index]
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
        .with_context(|| format!("quarantine {name}; files may remain under quarantine names"))?;
        if read_checked(names[index], content)
            .context("inspect quarantined unit; files may remain under quarantine names")?
            != identities[index]
        {
            bail!("quarantined unit identity changed; inspect quarantine files before retrying");
        }
    }
    if !same_directory()
        || unit_property("upkit-scan.service", "ActiveState")
            .context("check service; inspect quarantine files before retrying")?
            != "inactive"
    {
        bail!("directory changed or service started; inspect quarantine files before retrying");
    }
    for (index, (_, content)) in units.iter().enumerate() {
        if !same_directory()
            || read_checked(names[index], content)
                .context("inspect quarantined unit; removal may be partial")?
                != identities[index]
        {
            bail!("quarantined unit changed; removal may be partial");
        }
        rustix::fs::unlinkat(&directory, names[index], AtFlags::empty())
            .context("remove quarantined unit; removal may be partial")?;
    }
    directory
        .sync_all()
        .context("sync unit directory; removal may be partial")?;
    systemctl(&["daemon-reload"])
        .context("reload user manager; unit files may already be removed")?;
    let verified = (|| -> Result<bool> {
        let absent = |name: &str| {
            matches!(
                rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW),
                Err(rustix::io::Errno::NOENT)
            )
        };
        Ok(same_directory()
            && units.iter().all(|(name, _)| absent(name))
            && names.iter().all(|name| absent(name))
            && fragment("upkit-scan.service")?.is_empty()
            && fragment("upkit-scan.timer")?.is_empty()
            && unit_property("upkit-scan.service", "LoadState")? == "not-found"
            && unit_property("upkit-scan.timer", "LoadState")? == "not-found")
    })()
    .context("units may already be removed; inspect user manager before retrying")?;
    Ok(if verified {
        "units_absent"
    } else {
        "unverified"
    })
}

#[cfg(target_os = "macos")]
pub fn remove_scan(plan: &RemoveSchedulePreview, token: &str) -> Result<&'static str> {
    use rustix::fs::AtFlags;
    if token != plan.preview_token {
        bail!("schedule preview token does not match");
    }
    let current = preview_remove()?;
    if current.preview_token != token {
        bail!("LaunchAgent or launchd state changed since preview; preview again");
    }
    let directory_path = &current.existing.unit_directory;
    let (directory, directory_meta) = launchd_directory(directory_path)?;
    let (contents, identity) = launchd_read_plist(&directory, LAUNCHD_PLIST)?;
    let launchctl = which::which("launchctl").context("launchctl not found")?;
    if contents != current.existing.service_unit
        || !launchd_same_directory(directory_path, &directory_meta)
        || launchd_status_with(&launchctl).state != "not_found"
        || !launchd_disabled_state_with(&launchctl, &launchd_domain())?
    {
        bail!("LaunchAgent changed or became active before removal");
    }
    let quarantine = current
        .quarantine_paths
        .first()
        .and_then(|path| path.file_name())
        .context("invalid LaunchAgent quarantine path")?;
    if !launchd_same_directory(directory_path, &directory_meta)
        || launchd_status_with(&launchctl).state != "not_found"
        || !launchd_disabled_state_with(&launchctl, &launchd_domain())?
    {
        bail!("LaunchAgent directory or manager state changed; inspect the quarantine path");
    }
    let quarantine = quarantine
        .to_str()
        .context("quarantine name must be UTF-8")?;
    launchd_remove_plist(&directory, &contents, &identity, quarantine)?;
    let absent = matches!(
        rustix::fs::statat(&directory, LAUNCHD_PLIST, AtFlags::SYMLINK_NOFOLLOW),
        Err(rustix::io::Errno::NOENT)
    ) && matches!(
        rustix::fs::statat(&directory, quarantine, AtFlags::SYMLINK_NOFOLLOW),
        Err(rustix::io::Errno::NOENT)
    );
    if !absent
        || !launchd_same_directory(directory_path, &directory_meta)
        || launchd_status_with(&launchctl).state != "not_found"
    {
        bail!("LaunchAgent removal could not be verified");
    }
    Ok("units_absent")
}

#[cfg(target_os = "windows")]
pub fn remove_scan(plan: &RemoveSchedulePreview, token: &str) -> Result<&'static str> {
    windows::remove_scan(plan, token)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn remove_scan(_: &RemoveSchedulePreview, _: &str) -> Result<&'static str> {
    Err(schedule_changes_unsupported())
}

#[derive(Clone, Debug, Serialize)]
pub struct EditSchedulePreview {
    pub previous: RemoveSchedulePreview,
    pub replacement: ScanSchedulePreview,
    pub preview_token: String,
    pub warning: &'static str,
}

/// Preview replacing an inactive, disabled timer with a new scan plan.
pub fn preview_edit(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    frequency: Frequency,
) -> Result<EditSchedulePreview> {
    preview_edit_with_policy(executable, roots, exclusions, frequency, None)
}

fn preview_edit_with_policy(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    frequency: Frequency,
    policy: Option<ScheduledScanPolicy>,
) -> Result<EditSchedulePreview> {
    use sha2::{Digest, Sha256};
    let previous = preview_remove()?;
    let replacement = preview_scan_with_policy(executable, roots, exclusions, frequency, policy)?;
    if previous.existing.unit_directory != replacement.unit_directory {
        bail!("old and replacement units use different directories");
    }
    #[cfg(target_os = "windows")]
    let unchanged = windows::same_task_except_enabled(
        &previous.existing.service_unit,
        &replacement.service_unit,
    )
    .is_ok_and(|same| same)
        && previous.existing.timer_unit == replacement.timer_unit;
    #[cfg(not(target_os = "windows"))]
    let unchanged = previous.existing.service_unit == replacement.service_unit
        && previous.existing.timer_unit == replacement.timer_unit;
    if unchanged {
        bail!("replacement schedule is unchanged");
    }
    let mut hash = Sha256::new();
    hash.update(b"upkit-scan-edit-preview-v1\0");
    hash.update(previous.preview_token.as_bytes());
    hash.update(replacement.preview_token.as_bytes());
    let cleanup = schedules_cleanup(&replacement);
    Ok(EditSchedulePreview {
        previous,
        replacement,
        preview_token: hex::encode(hash.finalize()),
        warning: schedule_edit_warning(ScheduleBackend::current(), cleanup),
    })
}

pub fn preview_configured_edit(
    executable: &Path,
    config: Option<&Path>,
    profile: Option<&str>,
    frequency: Frequency,
) -> Result<EditSchedulePreview> {
    let scope = resolved_configured_scan_scope(config, profile)?;
    preview_edit_with_policy(
        executable,
        &scope.roots,
        &scope.exclusions,
        frequency,
        Some(scope.policy()),
    )
}

/// Replace explicitly approved, unchanged disabled units; failures may be partial.
#[cfg(target_os = "linux")]
pub fn edit_scan(
    executable: &Path,
    plan: &EditSchedulePreview,
    token: &str,
    frequency: Frequency,
) -> Result<&'static str> {
    ensure_artifact_schedule_supported(&plan.replacement)?;
    edit_scan_checked(executable, plan, token, frequency, || Ok(()))
}

#[cfg(target_os = "macos")]
pub fn edit_scan(
    executable: &Path,
    plan: &EditSchedulePreview,
    token: &str,
    frequency: Frequency,
) -> Result<&'static str> {
    ensure_artifact_schedule_supported(&plan.replacement)?;
    launchd_edit_scan_checked(executable, plan, token, frequency, || Ok(()))
}

#[cfg(target_os = "macos")]
fn launchd_edit_scan_checked(
    executable: &Path,
    plan: &EditSchedulePreview,
    token: &str,
    frequency: Frequency,
    check_scope: impl Fn() -> Result<()>,
) -> Result<&'static str> {
    if token != plan.preview_token {
        bail!("schedule edit preview token does not match");
    }
    let current = preview_edit_with_policy(
        executable,
        &plan.replacement.roots,
        &plan.replacement.exclusions,
        frequency,
        policy_from_plan(&plan.replacement)?,
    )?;
    if current.preview_token != token {
        bail!("old or replacement LaunchAgent changed since preview; preview again");
    }
    check_scope()?;
    let removed = remove_scan(&current.previous, &current.previous.preview_token)
        .context("old LaunchAgent removal failed or was partial; inspect its quarantine path")?;
    if removed != "units_absent" {
        bail!("old LaunchAgent removal could not be verified; replacement was not installed");
    }
    check_scope().context("old LaunchAgent was removed; replacement was not installed")?;
    launchd_install_scan_checked(
        executable,
        &current.replacement,
        &current.replacement.preview_token,
        frequency,
        check_scope,
    )
    .context("old LaunchAgent was removed; replacement installation may be partial or active")
}

#[cfg(target_os = "linux")]
fn edit_scan_checked(
    executable: &Path,
    plan: &EditSchedulePreview,
    token: &str,
    frequency: Frequency,
    check_scope: impl Fn() -> Result<()>,
) -> Result<&'static str> {
    if token != plan.preview_token {
        bail!("schedule edit preview token does not match");
    }
    let current = preview_edit_with_policy(
        executable,
        &plan.replacement.roots,
        &plan.replacement.exclusions,
        frequency,
        policy_from_plan(&plan.replacement)?,
    )?;
    if current.preview_token != token {
        bail!("old or replacement schedule changed since preview; preview again");
    }
    check_scope()?;
    let removed = remove_scan(&current.previous, &current.previous.preview_token)
        .context("old unit removal failed or was partial; inspect units and quarantine paths before retrying")?;
    if removed != "units_absent" {
        bail!("old unit removal could not be verified; replacement was not installed");
    }
    check_scope().context("old units were removed; replacement was not installed")?;
    install_scan_checked(executable, &current.replacement, &current.replacement.preview_token, frequency, check_scope)
        .context("old units were removed; replacement installation may be partial or active, inspect manager and unit directory before retrying")
}

#[cfg(target_os = "windows")]
pub fn edit_scan(
    executable: &Path,
    plan: &EditSchedulePreview,
    token: &str,
    frequency: Frequency,
) -> Result<&'static str> {
    ensure_artifact_schedule_supported(&plan.replacement)?;
    windows::edit_scan(executable, plan, token, frequency, || Ok(()))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn edit_scan(_: &Path, _: &EditSchedulePreview, _: &str, _: Frequency) -> Result<&'static str> {
    Err(schedule_changes_unsupported())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn edit_configured_scan(
    executable: &Path,
    plan: &EditSchedulePreview,
    token: &str,
    frequency: Frequency,
    config: Option<&Path>,
    profile: Option<&str>,
) -> Result<&'static str> {
    ensure_artifact_schedule_supported(&plan.replacement)?;
    ensure_configured_scope(&plan.replacement, config, profile, false)?;
    #[cfg(target_os = "linux")]
    return edit_scan_checked(executable, plan, token, frequency, || {
        ensure_configured_scope(&plan.replacement, config, profile, false)
    });
    #[cfg(target_os = "macos")]
    return launchd_edit_scan_checked(executable, plan, token, frequency, || {
        ensure_configured_scope(&plan.replacement, config, profile, false)
    });
    #[cfg(target_os = "windows")]
    return windows::edit_scan(executable, plan, token, frequency, || {
        ensure_configured_scope(&plan.replacement, config, profile, false)
    });
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn edit_configured_scan(
    _: &Path,
    _: &EditSchedulePreview,
    _: &str,
    _: Frequency,
    _: Option<&Path>,
    _: Option<&str>,
) -> Result<&'static str> {
    Err(schedule_changes_unsupported())
}

#[cfg(all(test, target_os = "linux"))]
mod configured_enable_compat_tests {
    use super::*;
    use std::fs;

    fn fake_disabled_manager(intended: &ScanSchedulePreview) -> DisableSchedulePreview {
        DisableSchedulePreview {
            unit_directory: intended.unit_directory.clone(),
            service_unit: intended.service_unit.clone(),
            timer_unit: intended.timer_unit.clone(),
            active_state: "inactive".into(),
            unit_file_state: Some("disabled".into()),
            preview_token: "fake-manager-preview".into(),
            warning: "fake manager fixture",
        }
    }

    fn scope_with_config(config: &std::path::Path) -> ConfiguredScanScope {
        resolved_configured_scan_scope(Some(config), None).unwrap()
    }

    #[test]
    fn configured_enable_reuses_legacy_unit_only_without_policy() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("workspace");
        let config = dir.path().join("config.toml");
        fs::create_dir(&root).unwrap();
        fs::write(
            &config,
            format!("version = 1\nworkspace_roots = ['{}']\n", root.display()),
        )
        .unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let scope = scope_with_config(&config);
        let legacy = preview_scan(
            &executable,
            &scope.roots,
            &scope.exclusions,
            Frequency::Daily,
        )
        .unwrap();
        let plan = configured_enable_preview_with_installed(
            &executable,
            &scope,
            Frequency::Daily,
            fake_disabled_manager(&legacy),
            Some(legacy.clone()),
        )
        .unwrap();

        assert_eq!(
            plan.intended.scheduled_scope_token,
            legacy.scheduled_scope_token
        );
        assert_eq!(plan.warning, LEGACY_CONFIGURED_ENABLE_WARNING);
        assert_eq!(plan.intended.warning, LEGACY_CONFIGURED_SCAN_WARNING);
        ensure_configured_scope(&plan.intended, Some(&config), None, true).unwrap();
        assert!(ensure_configured_scope(&plan.intended, Some(&config), None, false).is_err());

        let mut active = fake_disabled_manager(&legacy);
        active.active_state = "active".into();
        assert!(
            configured_enable_preview_with_installed(
                &executable,
                &scope,
                Frequency::Daily,
                active,
                Some(legacy),
            )
            .is_err()
        );
    }

    #[test]
    fn configured_enable_never_reuses_legacy_units_when_policy_is_present() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("workspace");
        let config = dir.path().join("config.toml");
        fs::create_dir(&root).unwrap();
        fs::write(
            &config,
            format!(
                "version = 1\nworkspace_roots = ['{}']\nartifact_retention = '30d'\nenabled_ecosystems = ['cargo']\n",
                root.display()
            ),
        )
        .unwrap();
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        let scope = scope_with_config(&config);
        let legacy = preview_scan(
            &executable,
            &scope.roots,
            &scope.exclusions,
            Frequency::Daily,
        )
        .unwrap();
        let err = configured_enable_preview_with_installed(
            &executable,
            &scope,
            Frequency::Daily,
            fake_disabled_manager(&legacy),
            Some(legacy.clone()),
        )
        .unwrap_err();

        assert!(err.to_string().contains("installed units differ"));
        assert!(ensure_configured_scope(&legacy, Some(&config), None, true).is_err());
    }

    #[test]
    fn policy_comment_escapes_profile_controls_on_one_line() {
        let policy = ScheduledScanPolicy {
            version: 2,
            scope_token: "0".repeat(64),
            older_than_seconds: None,
            enabled_ecosystems: None,
            scheduled_bytecode_cleanup: false,
            scheduled_artifact_cleanup: false,
            source: Some(ConfiguredSource {
                path: encode_config_path(std::path::Path::new("/tmp/upkit;config=source")).unwrap(),
                required: true,
                profile: Some("work;profile=spoof\n[Service]".into()),
            }),
        };
        let comment = schedule_policy_comment(&policy).unwrap();
        assert_eq!(comment.lines().count(), 1);
        assert!(comment.contains("config_path=/tmp/upkit%3Bconfig%3Dsource"));
        assert!(
            comment.contains("profile_present=yes; profile=work%3Bprofile%3Dspoof%0A[Service]")
        );
        assert!(!comment.contains(";profile=spoof"));
    }
}
