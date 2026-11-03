#[cfg(target_os = "windows")]
#[test]
fn windows_schedule_preview_only_shows_a_least_privilege_read_only_task() {
    use std::{fs, process::Command};

    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("workspace");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("keep.txt"), "fixture").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args([
            "--json",
            "--non-interactive",
            "schedule",
            "preview",
            "--frequency",
            "weekly",
        ])
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["frequency"], "weekly");
    assert_eq!(plan["unit_directory"], r"\Upkit-Workspace-Scan");
    let xml = plan["service_unit"].as_str().unwrap();
    assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"));
    assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
    assert!(xml.contains("<ScheduleByWeek>"));
    assert!(xml.contains("<Command>"));
    assert!(xml.contains("sweep"));
    assert!(xml.contains("scan"));
    assert!(!xml.contains("scheduled-bytecode-cleanup"));
    assert!(!xml.contains("/f"));
    assert_eq!(
        fs::read_to_string(root.join("keep.txt")).unwrap(),
        "fixture"
    );
    assert_eq!(fs::read_dir(fixture.path()).unwrap().count(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn schedule_preview_is_read_only_and_escapes_systemd_arguments() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("work %n $HOME \"quote\"");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("keep"), "fixture").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args([
            "--json",
            "--non-interactive",
            "schedule",
            "preview",
            "--frequency",
            "daily",
            "--exclude",
            "glob:**/secret",
        ])
        .arg(&root)
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let service = plan["service_unit"].as_str().unwrap();
    assert!(
        plan["warning"]
            .as_str()
            .unwrap()
            .contains("configuration profiles, retention and ecosystem filters are not applied")
    );
    assert!(service.contains("%%n $HOME \\\"quote\\\""));
    assert!(service.contains("ExecStart=\":"));
    assert!(service.contains("--non-interactive --offline --json --config /dev/null sweep scan"));
    assert!(service.contains("--exclude=glob:**/secret"));
    assert!(
        plan["timer_unit"]
            .as_str()
            .unwrap()
            .contains("OnCalendar=daily")
    );
    let scan = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args([
            "--non-interactive",
            "--offline",
            "--json",
            "--config",
            "/dev/null",
            "sweep",
            "scan",
        ])
        .arg(&root)
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(
        scan.status.success(),
        "{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert_eq!(report["roots"][0], root.to_str().unwrap());
    assert_eq!(fs::read_to_string(root.join("keep")).unwrap(), "fixture");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    if Command::new("systemd-analyze")
        .arg("--version")
        .output()
        .is_ok()
    {
        let service_path = dir.path().join("upkit-fixture.service");
        fs::write(&service_path, service).unwrap();
        let verification = Command::new("systemd-analyze")
            .arg("verify")
            .arg(service_path)
            .output()
            .unwrap();
        assert!(
            verification.status.success(),
            "{}",
            String::from_utf8_lossy(&verification.stderr)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn schedule_preview_rejects_linked_or_missing_workspace_roots() {
    use std::{fs, os::unix::fs::symlink};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let link = dir.path().join("link");
    symlink(&root, &link).unwrap();
    let exe = std::env::current_exe().unwrap();
    for candidate in [
        link,
        dir.path().join("missing"),
        dir.path().to_path_buf().join("../"),
    ] {
        assert!(
            upkit::schedule::preview_scan(
                &exe,
                &[candidate],
                &[],
                upkit::schedule::Frequency::Weekly
            )
            .is_err()
        );
    }
    assert!(
        upkit::schedule::preview_scan(&exe, &[], &[], upkit::schedule::Frequency::Daily).is_err()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn launchd_schedule_preview_never_writes_a_launchagent() {
    use std::{fs, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args([
            "--json",
            "--non-interactive",
            "schedule",
            "preview",
            "--frequency",
            "weekly",
        ])
        .arg(&root)
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        plan["unit_directory"],
        dir.path()
            .join("Library/LaunchAgents")
            .to_string_lossy()
            .as_ref()
    );
    assert!(plan["service_unit"].as_str().unwrap().contains("<plist"));
    assert!(
        plan["service_unit"]
            .as_str()
            .unwrap()
            .contains("<key>Weekday</key>")
    );
    assert_eq!(plan["timer_unit"], "");
    assert!(
        plan["warning"]
            .as_str()
            .unwrap()
            .contains("After explicit confirmation, Upkit creates a private user-owned plist")
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn schedule_list_queries_user_timer_without_changing_it() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let systemctl = dir.path().join("systemctl");
    fs::write(&systemctl, r##"#!/bin/sh
[ "$1" = '--user' ] && [ "$2" = 'show' ] && [ "$3" = 'upkit-scan.timer' ] || exit 8
printf 'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\nLastTriggerUSec=Mon 2026-01-01\nNextElapseUSecRealtime=Tue 2026-01-02\n'
"##).unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "schedule", "list"])
        .env("PATH", dir.path())
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["unit"], "upkit-scan.timer");
    assert_eq!(report["status"]["state"], "active");
    assert_eq!(report["status"]["unit_file_state"], "enabled");
    assert_eq!(report["status"]["next_trigger"], "Tue 2026-01-02");
    assert_eq!(report["ownership_verified"], false);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn schedule_list_reports_unavailable_manager() {
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "schedule", "list"])
        .env("PATH", dir.path())
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"]["state"], "unavailable");
    assert_eq!(report["ownership_verified"], false);
}

#[cfg(target_os = "linux")]
#[test]
fn schedule_preview_token_tracks_scope_identity_frequency_and_unit_directory() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let config_a = dir.path().join("config-a");
    let config_b = dir.path().join("config-b");
    let preview = |frequency: &str, config: &std::path::Path| -> serde_json::Value {
        let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args([
                "--json",
                "--non-interactive",
                "schedule",
                "preview",
                "--frequency",
                frequency,
            ])
            .arg(&root)
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", config)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    };
    let first = preview("daily", &config_a);
    assert_eq!(
        first["unit_directory"],
        config_a.join("systemd/user").to_str().unwrap()
    );
    let token = first["preview_token"].as_str().unwrap();
    assert_eq!(token.len(), 64);
    assert_eq!(token, preview("daily", &config_a)["preview_token"]);
    assert_ne!(token, preview("weekly", &config_a)["preview_token"]);
    assert_ne!(token, preview("daily", &config_b)["preview_token"]);
    fs::rename(&root, dir.path().join("old-workspace")).unwrap();
    fs::create_dir(&root).unwrap();
    assert_ne!(token, preview("daily", &config_a)["preview_token"]);
    assert!(!config_a.exists());
    assert!(!config_b.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn schedule_add_requires_authorization_and_installs_only_fixture_units() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    let config = dir.path().join("config");
    let units = config.join("systemd/user");
    let bin = dir.path().join("bin");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&units).unwrap();
    fs::set_permissions(&units, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&bin).unwrap();
    let ctl = bin.join("systemctl");
    fs::write(&ctl, r##"#!/bin/sh
[ "$1" = --user ] || exit 9
case "$2" in
 show)
   case "$5" in
    --property=FragmentPath) [ ! -e "$XDG_CONFIG_HOME/systemd/user/$3" ] || printf '%s\n' "$XDG_CONFIG_HOME/systemd/user/$3" ;;
    --property=LoadState) if [ -e "$XDG_CONFIG_HOME/systemd/user/$3" ]; then printf 'loaded\n'; else printf 'not-found\n'; fi ;;
    --property=DropInPaths) if [ -e "$XDG_CONFIG_HOME/systemd/user/$3" ] && [ -f "$HOME/dropin" ]; then printf '/unexpected.conf\n'; fi ;;
    --property=NeedDaemonReload) if [ -f "$HOME/needs_reload" ]; then printf 'yes\n'; else printf 'no\n'; fi ;;
    --property=ActiveState) if [ -f "$HOME/service_active" ]; then printf 'active\n'; else printf 'inactive\n'; fi ;;
    --property=LoadState,ActiveState,UnitFileState,LastTriggerUSec,NextElapseUSecRealtime) if [ -f "$HOME/timer_inactive" ] && [ -s "$HOME/timer_inactive" ]; then printf 'LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n'; else printf 'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n'; fi ;;
    *) exit 8 ;;
   esac ;;
 daemon-reload) [ ! -f "$HOME/fail_reload" ] || exit 11 ;;
 enable) [ "$3" = --now ] && [ "$4" = upkit-scan.timer ] || exit 7; printf enabled > "$HOME/enabled"; if [ -f "$HOME/disabled" ]; then printf enabled > "$HOME/reenabled"; fi; if [ -f "$HOME/timer_inactive" ]; then : > "$HOME/timer_inactive"; fi ;;
 disable) [ "$3" = --now ] && [ "$4" = upkit-scan.timer ] || exit 7; printf disabled > "$HOME/disabled"; printf inactive > "$HOME/timer_inactive" ;;
 *) exit 6 ;;
esac
"##).unwrap();
    fs::set_permissions(&ctl, fs::Permissions::from_mode(0o755)).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .arg(&root)
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("PATH", &bin)
            .output()
            .unwrap()
    };
    let preview = run(&[
        "--json",
        "--non-interactive",
        "schedule",
        "preview",
        "--frequency",
        "daily",
    ]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let token = plan["preview_token"].as_str().unwrap();
    let rejected = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "add",
        "--frequency",
        "daily",
        "--preview-token",
        token,
    ]);
    assert!(!rejected.status.success());
    assert_eq!(fs::read_dir(&units).unwrap().count(), 0);
    let dry = run(&[
        "--json",
        "--non-interactive",
        "--dry-run",
        "schedule",
        "add",
        "--frequency",
        "daily",
    ]);
    assert!(dry.status.success());
    assert_eq!(fs::read_dir(&units).unwrap().count(), 0);
    let stale = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "add",
        "--frequency",
        "weekly",
        "--authorize-schedule",
        "--preview-token",
        token,
    ]);
    assert!(!stale.status.success());
    assert_eq!(fs::read_dir(&units).unwrap().count(), 0);
    fs::write(dir.path().join("fail_reload"), "fixture").unwrap();
    let partial = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "add",
        "--frequency",
        "daily",
        "--authorize-schedule",
        "--preview-token",
        token,
    ]);
    assert!(!partial.status.success());
    let error: serde_json::Value = serde_json::from_slice(&partial.stdout).unwrap();
    assert!(
        error["error"]
            .as_str()
            .unwrap()
            .contains("unit files may remain")
    );
    assert!(units.join("upkit-scan.service").exists());
    assert!(units.join("upkit-scan.timer").exists());
    assert!(!dir.path().join("enabled").exists());
    fs::remove_file(units.join("upkit-scan.service")).unwrap();
    fs::remove_file(units.join("upkit-scan.timer")).unwrap();
    fs::remove_file(dir.path().join("fail_reload")).unwrap();
    fs::write(dir.path().join("dropin"), "fixture").unwrap();
    let overridden = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "add",
        "--frequency",
        "daily",
        "--authorize-schedule",
        "--preview-token",
        token,
    ]);
    assert!(!overridden.status.success());
    assert!(!dir.path().join("enabled").exists());
    fs::remove_file(units.join("upkit-scan.service")).unwrap();
    fs::remove_file(units.join("upkit-scan.timer")).unwrap();
    fs::remove_file(dir.path().join("dropin")).unwrap();
    std::os::unix::fs::symlink(dir.path().join("outside"), units.join("upkit-scan.service"))
        .unwrap();
    let linked = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "add",
        "--frequency",
        "daily",
        "--authorize-schedule",
        "--preview-token",
        token,
    ]);
    assert!(!linked.status.success());
    assert!(
        fs::symlink_metadata(units.join("upkit-scan.service"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!dir.path().join("outside").exists());
    assert!(!dir.path().join("enabled").exists());
    fs::remove_file(units.join("upkit-scan.service")).unwrap();
    let added = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "add",
        "--frequency",
        "daily",
        "--authorize-schedule",
        "--preview-token",
        token,
    ]);
    assert!(
        added.status.success(),
        "{} {}",
        String::from_utf8_lossy(&added.stdout),
        String::from_utf8_lossy(&added.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&added.stdout).unwrap();
    assert_eq!(result["verification"], "active_and_enabled");
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.service")).unwrap(),
        plan["service_unit"].as_str().unwrap()
    );
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.timer")).unwrap(),
        plan["timer_unit"].as_str().unwrap()
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("enabled")).unwrap(),
        "enabled"
    );
    let duplicate = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "add",
        "--frequency",
        "daily",
        "--authorize-schedule",
        "--preview-token",
        token,
    ]);
    assert!(!duplicate.status.success());
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.service")).unwrap(),
        plan["service_unit"].as_str().unwrap()
    );
    let disable_command = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("PATH", &bin)
            .output()
            .unwrap()
    };
    fs::write(
        units.join("upkit-scan.timer"),
        "[Timer]\nOnCalendar=daily\n",
    )
    .unwrap();
    let unrelated =
        disable_command(&["--json", "--non-interactive", "schedule", "preview-disable"]);
    assert!(!unrelated.status.success());
    fs::write(
        units.join("upkit-scan.timer"),
        plan["timer_unit"].as_str().unwrap(),
    )
    .unwrap();
    fs::write(dir.path().join("dropin"), "fixture").unwrap();
    let overridden =
        disable_command(&["--json", "--non-interactive", "schedule", "preview-disable"]);
    assert!(!overridden.status.success());
    fs::remove_file(dir.path().join("dropin")).unwrap();
    fs::write(dir.path().join("needs_reload"), "fixture").unwrap();
    let stale_manager =
        disable_command(&["--json", "--non-interactive", "schedule", "preview-disable"]);
    assert!(!stale_manager.status.success());
    fs::remove_file(dir.path().join("needs_reload")).unwrap();
    let active = run(&[
        "--json",
        "--non-interactive",
        "schedule",
        "preview-enable",
        "--frequency",
        "daily",
    ]);
    assert!(!active.status.success());
    let preview = disable_command(&["--json", "--non-interactive", "schedule", "preview-disable"]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let disable_plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let previous_token = disable_plan["preview_token"].as_str().unwrap();
    fs::rename(units.join("upkit-scan.timer"), units.join("previous.timer")).unwrap();
    fs::write(
        units.join("upkit-scan.timer"),
        plan["timer_unit"].as_str().unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        units.join("upkit-scan.timer"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let changed = disable_command(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "disable",
        "--authorize-schedule",
        "--preview-token",
        previous_token,
    ]);
    assert!(!changed.status.success());
    assert!(!dir.path().join("disabled").exists());
    let fresh = disable_command(&["--json", "--non-interactive", "schedule", "preview-disable"]);
    assert!(
        fresh.status.success(),
        "{}",
        String::from_utf8_lossy(&fresh.stdout)
    );
    let disable_plan: serde_json::Value = serde_json::from_slice(&fresh.stdout).unwrap();
    let disable_token = disable_plan["preview_token"].as_str().unwrap();
    assert_ne!(disable_token, previous_token);
    assert_eq!(disable_plan["service_unit"], plan["service_unit"]);
    let denied = disable_command(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "disable",
        "--preview-token",
        disable_token,
    ]);
    assert!(!denied.status.success());
    assert!(!dir.path().join("disabled").exists());
    let dry = disable_command(&[
        "--json",
        "--non-interactive",
        "--dry-run",
        "schedule",
        "disable",
    ]);
    assert!(dry.status.success());
    assert!(!dir.path().join("disabled").exists());
    let stale = disable_command(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "disable",
        "--authorize-schedule",
        "--preview-token",
        "wrong",
    ]);
    assert!(!stale.status.success());
    assert!(!dir.path().join("disabled").exists());
    let disabled = disable_command(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "disable",
        "--authorize-schedule",
        "--preview-token",
        disable_token,
    ]);
    assert!(
        disabled.status.success(),
        "{}",
        String::from_utf8_lossy(&disabled.stdout)
    );
    let result: serde_json::Value = serde_json::from_slice(&disabled.stdout).unwrap();
    assert_eq!(result["verification"], "inactive_and_disabled");
    assert_eq!(
        fs::read_to_string(dir.path().join("disabled")).unwrap(),
        "disabled"
    );
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.service")).unwrap(),
        plan["service_unit"].as_str().unwrap()
    );
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.timer")).unwrap(),
        plan["timer_unit"].as_str().unwrap()
    );
    let wrong_scope = run(&[
        "--json",
        "--non-interactive",
        "schedule",
        "preview-enable",
        "--frequency",
        "weekly",
    ]);
    assert!(!wrong_scope.status.success());
    let preview = run(&[
        "--json",
        "--non-interactive",
        "schedule",
        "preview-enable",
        "--frequency",
        "daily",
    ]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let enable_plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let old_enable_token = enable_plan["preview_token"].as_str().unwrap();
    assert_ne!(old_enable_token, disable_token);
    fs::rename(&root, dir.path().join("previous-workspace")).unwrap();
    fs::create_dir(&root).unwrap();
    let changed_root = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "enable",
        "--frequency",
        "daily",
        "--authorize-schedule",
        "--preview-token",
        old_enable_token,
    ]);
    assert!(!changed_root.status.success());
    assert!(!dir.path().join("reenabled").exists());
    fs::remove_dir(&root).unwrap();
    fs::rename(dir.path().join("previous-workspace"), &root).unwrap();
    let refreshed = run(&[
        "--json",
        "--non-interactive",
        "schedule",
        "preview-enable",
        "--frequency",
        "daily",
    ]);
    assert!(refreshed.status.success());
    let enable_plan: serde_json::Value = serde_json::from_slice(&refreshed.stdout).unwrap();
    let enable_token = enable_plan["preview_token"].as_str().unwrap();
    assert_ne!(enable_token, old_enable_token);
    let denied = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "enable",
        "--frequency",
        "daily",
        "--preview-token",
        enable_token,
    ]);
    assert!(!denied.status.success());
    let dry = run(&[
        "--json",
        "--non-interactive",
        "--dry-run",
        "schedule",
        "enable",
        "--frequency",
        "daily",
    ]);
    assert!(dry.status.success());
    assert!(!dir.path().join("reenabled").exists());
    let stale = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "enable",
        "--frequency",
        "daily",
        "--authorize-schedule",
        "--preview-token",
        disable_token,
    ]);
    assert!(!stale.status.success());
    assert!(!dir.path().join("reenabled").exists());
    let enabled = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "enable",
        "--frequency",
        "daily",
        "--authorize-schedule",
        "--preview-token",
        enable_token,
    ]);
    assert!(
        enabled.status.success(),
        "{}",
        String::from_utf8_lossy(&enabled.stdout)
    );
    let enabled: serde_json::Value = serde_json::from_slice(&enabled.stdout).unwrap();
    assert_eq!(enabled["verification"], "active_and_enabled");
    assert_eq!(
        fs::read_to_string(dir.path().join("reenabled")).unwrap(),
        "enabled"
    );
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.service")).unwrap(),
        plan["service_unit"].as_str().unwrap()
    );
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.timer")).unwrap(),
        plan["timer_unit"].as_str().unwrap()
    );
    let history = disable_command(&["--json", "--non-interactive", "report"]);
    assert!(history.status.success());
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["operation"] == "schedule_enable"
                && record["outcome"] == "completed")
    );
    let disable_preview =
        disable_command(&["--json", "--non-interactive", "schedule", "preview-disable"]);
    assert!(disable_preview.status.success());
    let disable_preview: serde_json::Value =
        serde_json::from_slice(&disable_preview.stdout).unwrap();
    let disable_token = disable_preview["preview_token"].as_str().unwrap();
    let disabled_again = disable_command(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "disable",
        "--authorize-schedule",
        "--preview-token",
        disable_token,
    ]);
    assert!(
        disabled_again.status.success(),
        "{}",
        String::from_utf8_lossy(&disabled_again.stdout)
    );
    fs::write(dir.path().join("service_active"), "fixture").unwrap();
    let active = disable_command(&["--json", "--non-interactive", "schedule", "preview-remove"]);
    assert!(!active.status.success());
    fs::remove_file(dir.path().join("service_active")).unwrap();
    let removal = disable_command(&["--json", "--non-interactive", "schedule", "preview-remove"]);
    assert!(
        removal.status.success(),
        "{}",
        String::from_utf8_lossy(&removal.stdout)
    );
    let removal: serde_json::Value = serde_json::from_slice(&removal.stdout).unwrap();
    let removal_token = removal["preview_token"].as_str().unwrap();
    let denied = disable_command(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "remove",
        "--preview-token",
        removal_token,
    ]);
    assert!(!denied.status.success());
    let dry = disable_command(&[
        "--json",
        "--non-interactive",
        "--dry-run",
        "schedule",
        "remove",
    ]);
    assert!(dry.status.success());
    let stale = disable_command(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "remove",
        "--authorize-schedule-removal",
        "--preview-token",
        "wrong",
    ]);
    assert!(!stale.status.success());
    assert!(units.join("upkit-scan.service").exists() && units.join("upkit-scan.timer").exists());
    fs::write(units.join("upkit-scan.service"), "unrelated fixture").unwrap();
    let changed = disable_command(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "remove",
        "--authorize-schedule-removal",
        "--preview-token",
        removal_token,
    ]);
    assert!(!changed.status.success());
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.service")).unwrap(),
        "unrelated fixture"
    );
    fs::write(
        units.join("upkit-scan.service"),
        plan["service_unit"].as_str().unwrap(),
    )
    .unwrap();
    let removal = disable_command(&["--json", "--non-interactive", "schedule", "preview-remove"]);
    assert!(removal.status.success());
    let removal: serde_json::Value = serde_json::from_slice(&removal.stdout).unwrap();
    let removal_token = removal["preview_token"].as_str().unwrap();
    let quarantine = removal["quarantine_paths"].as_array().unwrap();
    let second_quarantine = std::path::PathBuf::from(quarantine[1].as_str().unwrap());
    fs::write(&second_quarantine, "do not replace").unwrap();
    let partial = disable_command(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "remove",
        "--authorize-schedule-removal",
        "--preview-token",
        removal_token,
    ]);
    assert!(!partial.status.success());
    let first_quarantine = std::path::PathBuf::from(quarantine[0].as_str().unwrap());
    assert_eq!(
        fs::read_to_string(&first_quarantine).unwrap(),
        plan["service_unit"].as_str().unwrap()
    );
    assert_eq!(
        fs::read_to_string(&second_quarantine).unwrap(),
        "do not replace"
    );
    assert!(units.join("upkit-scan.timer").exists());
    fs::rename(&first_quarantine, units.join("upkit-scan.service")).unwrap();
    fs::remove_file(&second_quarantine).unwrap();
    let removal = disable_command(&["--json", "--non-interactive", "schedule", "preview-remove"]);
    assert!(removal.status.success());
    let removal: serde_json::Value = serde_json::from_slice(&removal.stdout).unwrap();
    let removal_token = removal["preview_token"].as_str().unwrap();
    let removed = disable_command(&[
        "--json",
        "--non-interactive",
        "--yes",
        "schedule",
        "remove",
        "--authorize-schedule-removal",
        "--preview-token",
        removal_token,
    ]);
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stdout)
    );
    let removed: serde_json::Value = serde_json::from_slice(&removed.stdout).unwrap();
    assert_eq!(removed["verification"], "units_absent");
    assert!(!units.join("upkit-scan.service").exists() && !units.join("upkit-scan.timer").exists());
    let history = disable_command(&["--json", "--non-interactive", "report"]);
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["operation"] == "schedule_remove"
                && record["outcome"] == "completed")
    );
}

#[test]
fn configured_schedule_scope_preserves_profile_exclusions_and_rejects_unrepresentable_policies() {
    use std::fs;
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("settings.toml");
    let root = dir.path().join("workspace");
    let base = format!(
        "exclusions = ['global']\n[profiles.work]\nworkspace_roots = ['{}']\nexclusions = ['glob:**/private']\n",
        root.display(),
    );
    fs::write(&config, format!("version = 1\n{base}")).unwrap();
    let (roots, exclusions) =
        upkit::schedule::configured_scan_scope(Some(&config), Some("work")).unwrap();
    assert_eq!(roots, vec![root]);
    assert_eq!(
        exclusions,
        vec![
            std::path::PathBuf::from("global"),
            std::path::PathBuf::from("glob:**/private")
        ]
    );
    assert!(upkit::schedule::configured_scan_scope(Some(&config), Some("missing")).is_err());

    fs::write(
        &config,
        format!("version = 1\nartifact_retention = '30d'\n{base}"),
    )
    .unwrap();
    assert!(upkit::schedule::configured_scan_scope(Some(&config), Some("work")).is_err());
    fs::write(
        &config,
        format!("version = 1\nenabled_ecosystems = ['cargo']\n{base}"),
    )
    .unwrap();
    assert!(upkit::schedule::configured_scan_scope(Some(&config), Some("work")).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn configured_schedule_policy_reaches_guarded_scan_and_remains_read_only() {
    use std::fs;
    use upkit::schedule::{Frequency, preview_configured_install, run_guarded_scan};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    let config = dir.path().join("settings.toml");
    fs::create_dir_all(root.join("rust/target")).unwrap();
    fs::write(root.join("rust/Cargo.toml"), "[package]").unwrap();
    fs::write(root.join("rust/target/output"), "keep cargo fixture").unwrap();
    fs::create_dir_all(root.join("python/__pycache__")).unwrap();
    fs::write(root.join("python/pyproject.toml"), "[project]").unwrap();
    fs::write(
        root.join("python/__pycache__/keep.pyc"),
        "keep python fixture",
    )
    .unwrap();
    fs::write(
        &config,
        format!(
            "version = 1\nartifact_retention = '90d'\nenabled_ecosystems = ['cargo', 'python']\n[profiles.work]\nworkspace_roots = ['{}']\nartifact_retention = '30d'\nenabled_ecosystems = ['cargo']\n",
            root.display(),
        ),
    )
    .unwrap();

    let executable = std::env::current_exe().unwrap();
    let plan =
        preview_configured_install(&executable, Some(&config), Some("work"), Frequency::Daily)
            .unwrap();
    assert!(plan.scheduled_scope_token.starts_with("v2."));
    assert!(plan.service_unit.contains("older_than_seconds=2592000"));
    assert!(plan.service_unit.contains("enabled_ecosystems=cargo"));
    assert!(plan.service_unit.contains(&format!(
        "config_path={}; config_required=yes; profile_present=yes; profile=work",
        upkit::sweep::display_path(&config)
    )));
    let report = run_guarded_scan(
        &executable,
        &plan.roots,
        &plan.exclusions,
        &plan.scheduled_scope_token,
    )
    .unwrap();
    assert!(report.candidates.is_empty());
    assert_eq!(
        fs::read_to_string(root.join("rust/target/output")).unwrap(),
        "keep cargo fixture"
    );
    assert_eq!(
        fs::read_to_string(root.join("python/__pycache__/keep.pyc")).unwrap(),
        "keep python fixture"
    );

    fs::write(
        &config,
        format!(
            "version = 1\nenabled_ecosystems = ['cargo', 'python']\n[profiles.work]\nworkspace_roots = ['{}']\nartifact_retention = '0h'\nenabled_ecosystems = ['cargo']\n",
            root.display(),
        ),
    )
    .unwrap();
    let plan =
        preview_configured_install(&executable, Some(&config), Some("work"), Frequency::Daily)
            .unwrap();
    let report = run_guarded_scan(
        &executable,
        &plan.roots,
        &plan.exclusions,
        &plan.scheduled_scope_token,
    )
    .unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].ecosystem, "cargo");
    assert_eq!(
        fs::read_to_string(root.join("rust/target/output")).unwrap(),
        "keep cargo fixture"
    );
    assert_eq!(
        fs::read_to_string(root.join("python/__pycache__/keep.pyc")).unwrap(),
        "keep python fixture"
    );

    fs::write(
        &config,
        format!(
            "version = 1\nenabled_ecosystems = ['cargo']\n[profiles.work]\nworkspace_roots = ['{}']\nartifact_retention = '0h'\nenabled_ecosystems = ['python']\n",
            root.display()
        ),
    )
    .unwrap();
    let plan =
        preview_configured_install(&executable, Some(&config), Some("work"), Frequency::Daily)
            .unwrap();
    assert!(plan.service_unit.contains("enabled_ecosystems=(none)"));
    let report = run_guarded_scan(
        &executable,
        &plan.roots,
        &plan.exclusions,
        &plan.scheduled_scope_token,
    )
    .unwrap();
    assert!(report.candidates.is_empty());

    fs::write(
        &config,
        format!(
            "version = 1\nenabled_ecosystems = ['not-an-ecosystem']\n[profiles.work]\nworkspace_roots = ['{}']\nartifact_retention = '0h'\n",
            root.display()
        ),
    )
    .unwrap();
    assert!(
        preview_configured_install(&executable, Some(&config), Some("work"), Frequency::Daily,)
            .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn scheduled_bytecode_policy_is_explicit_profile_scoped_and_age_bounded() {
    use std::fs;
    use upkit::schedule::{Frequency, preview_configured_install, run_guarded_scan};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    let config = dir.path().join("config.toml");
    fs::create_dir(&root).unwrap();
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let write = |global: bool, profile: bool, age: &str, ecosystems: &str| {
        fs::write(&config, format!(
            "version = 1\nworkspace_roots = ['{}']\nartifact_retention = '{age}'\nscheduled_bytecode_cleanup = {global}\n[profiles.work]\nworkspace_roots = ['{}']\nenabled_ecosystems = ['{ecosystems}']\nscheduled_bytecode_cleanup = {profile}\n",
            root.display(), root.display()
        )).unwrap();
    };
    write(true, false, "7d", "python");
    let global =
        preview_configured_install(&executable, Some(&config), None, Frequency::Daily).unwrap();
    assert!(global.scheduled_scope_token.starts_with("v3."));
    assert!(!upkit::schedule::schedules_artifact_cleanup(&global));
    assert!(
        upkit::schedule::install_scan(&executable, &global, "stale", Frequency::Daily)
            .unwrap_err()
            .to_string()
            .contains("preview token")
    );
    assert!(
        global
            .service_unit
            .contains("scheduled-bytecode-cleanup --authorize-scheduled-cleanup")
    );
    assert!(global.warning.contains("automatically and permanently"));
    assert!(
        run_guarded_scan(
            &executable,
            &global.roots,
            &global.exclusions,
            &global.scheduled_scope_token
        )
        .is_err()
    );
    let profile =
        preview_configured_install(&executable, Some(&config), Some("work"), Frequency::Daily)
            .unwrap();
    assert!(profile.scheduled_scope_token.starts_with("v2."));
    assert!(!upkit::schedule::schedules_artifact_cleanup(&profile));
    assert!(
        upkit::schedule::install_scan(&executable, &profile, "stale", Frequency::Daily)
            .unwrap_err()
            .to_string()
            .contains("preview token")
    );
    assert!(profile.service_unit.contains("sweep scan"));
    write(false, true, "1d", "python");
    assert!(
        preview_configured_install(&executable, Some(&config), Some("work"), Frequency::Daily)
            .is_err()
    );
    write(false, true, "7d", "cargo");
    assert!(
        preview_configured_install(&executable, Some(&config), Some("work"), Frequency::Daily)
            .is_err()
    );
    write(false, true, "7d", "python");
    let profile =
        preview_configured_install(&executable, Some(&config), Some("work"), Frequency::Daily)
            .unwrap();
    assert!(profile.scheduled_scope_token.starts_with("v3."));
    assert!(!upkit::schedule::schedules_artifact_cleanup(&profile));
}

#[cfg(target_os = "linux")]
#[test]
fn scheduled_artifact_policy_requires_explicit_ecosystems_and_thirty_days() {
    use std::fs;
    use upkit::schedule::{Frequency, preview_configured_install, schedules_artifact_cleanup};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    let config = dir.path().join("settings.toml");
    fs::create_dir(&root).unwrap();
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let write = |retention: Option<&str>, ecosystems: Option<&str>| {
        let mut text = format!(
            "version = 1\nworkspace_roots = ['{}']\nscheduled_artifact_cleanup = true\n",
            root.display()
        );
        if let Some(retention) = retention {
            text.push_str(&format!("artifact_retention = '{retention}'\n"));
        }
        if let Some(ecosystems) = ecosystems {
            text.push_str(&format!("enabled_ecosystems = {ecosystems}\n"));
        }
        fs::write(&config, text).unwrap();
    };

    write(Some("30d"), Some("['maven', 'zig', 'dart', 'python']"));
    let plan =
        preview_configured_install(&executable, Some(&config), None, Frequency::Daily).unwrap();
    assert!(plan.scheduled_scope_token.starts_with("v4."));
    assert!(schedules_artifact_cleanup(&plan));
    assert!(plan.service_unit.contains("scheduled_artifact_cleanup=yes"));
    assert!(
        plan.service_unit
            .contains("--yes --json --config /dev/null sweep scheduled-cleanup")
    );
    assert!(
        plan.service_unit
            .contains("--authorize-scheduled-artifact-cleanup")
    );
    assert!(
        plan.service_unit
            .contains("Description=Upkit scheduled workspace artifact cleanup")
    );
    assert!(plan.warning.contains("Preview only"));
    assert!(plan.warning.contains("history attempt is reserved"));
    assert!(plan.warning.contains("at most 8"));
    assert!(
        plan.warning
            .contains("Cargo is excluded from scheduled cleanup")
    );

    let error = upkit::schedule::install_scan(&executable, &plan, "wrong-token", Frequency::Daily)
        .unwrap_err();
    assert!(error.to_string().contains("token"));

    let installed = upkit::schedule::DisableSchedulePreview {
        unit_directory: plan.unit_directory.clone(),
        service_unit: plan.service_unit.clone(),
        timer_unit: plan.timer_unit.clone(),
        active_state: "inactive".into(),
        unit_file_state: Some("disabled".into()),
        preview_token: "fixture-disabled".into(),
        warning: "fixture",
    };
    let enable = upkit::schedule::EnableSchedulePreview {
        intended: plan.clone(),
        installed: installed.clone(),
        preview_token: "fixture-enable".into(),
        warning: "fixture",
    };
    let error = upkit::schedule::enable_scan(&executable, &enable, "wrong-token", Frequency::Daily)
        .unwrap_err();
    assert!(error.to_string().contains("token"));

    let edit = upkit::schedule::EditSchedulePreview {
        previous: upkit::schedule::RemoveSchedulePreview {
            existing: installed,
            quarantine_paths: Vec::new(),
            preview_token: "fixture-remove".into(),
            warning: "fixture",
        },
        replacement: plan.clone(),
        preview_token: "fixture-edit".into(),
        warning: "fixture",
    };
    let error = upkit::schedule::edit_scan(&executable, &edit, "wrong-token", Frequency::Daily)
        .unwrap_err();
    assert!(error.to_string().contains("token"));

    for (retention, ecosystems) in [
        (Some("29d"), Some("['cargo']")),
        (None, Some("['cargo']")),
        (Some("30d"), None),
        (Some("30d"), Some("[]")),
        (Some("30d"), Some("['go']")),
    ] {
        write(retention, ecosystems);
        assert!(
            preview_configured_install(&executable, Some(&config), None, Frequency::Daily).is_err(),
            "retention={retention:?}, ecosystems={ecosystems:?}"
        );
    }
    write(Some("30d"), Some("['cargo']"));
    let error =
        preview_configured_install(&executable, Some(&config), None, Frequency::Daily).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Cargo is excluded from scheduled cleanup")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn global_artifact_opt_in_does_not_enable_profiles_or_legacy_v2_v3_scopes() {
    use std::fs;
    use upkit::schedule::{Frequency, preview_configured_install, schedules_artifact_cleanup};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    let config = dir.path().join("settings.toml");
    fs::create_dir(&root).unwrap();
    fs::write(
        &config,
        format!(
            "version = 1\nworkspace_roots = ['{}']\nartifact_retention = '30d'\nenabled_ecosystems = ['python']\nscheduled_artifact_cleanup = true\n[profiles.work]\nworkspace_roots = ['{}']\nartifact_retention = '30d'\nenabled_ecosystems = ['python']\n",
            root.display(),
            root.display(),
        ),
    )
    .unwrap();
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let profile =
        preview_configured_install(&executable, Some(&config), Some("work"), Frequency::Daily)
            .unwrap();
    assert!(profile.scheduled_scope_token.starts_with("v2."));
    assert!(!schedules_artifact_cleanup(&profile));
}

#[cfg(target_os = "linux")]
#[test]
fn configured_schedule_rejects_policy_and_profile_drift_before_activation_and_scan() {
    use std::fs;
    use upkit::schedule::{
        Frequency, install_configured_scan, preview_configured_install, run_guarded_scan,
    };

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    let other = dir.path().join("other");
    let config = dir.path().join("settings.toml");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&other).unwrap();
    let write_config = |workspace: &std::path::Path, age: &str, ecosystem: &str| {
        fs::write(
            &config,
            format!(
                "version = 1\n[profiles.work]\nworkspace_roots = ['{}']\nartifact_retention = '{age}'\nenabled_ecosystems = ['{ecosystem}']\n",
                workspace.display(),
            ),
        )
        .unwrap();
    };
    write_config(&root, "30d", "cargo");
    let executable = std::env::current_exe().unwrap();
    let plan =
        preview_configured_install(&executable, Some(&config), Some("work"), Frequency::Daily)
            .unwrap();

    write_config(&root, "60d", "cargo");
    let scan_error = run_guarded_scan(
        &executable,
        &plan.roots,
        &plan.exclusions,
        &plan.scheduled_scope_token,
    )
    .unwrap_err();
    assert!(
        scan_error
            .to_string()
            .contains("scope or scan policy changed")
    );
    let install_error = install_configured_scan(
        &executable,
        &plan,
        &plan.preview_token,
        Frequency::Daily,
        Some(&config),
        Some("work"),
    )
    .unwrap_err();
    assert!(
        install_error
            .to_string()
            .contains("scope or scan policy changed")
    );

    write_config(&root, "30d", "python");
    assert!(
        run_guarded_scan(
            &executable,
            &plan.roots,
            &plan.exclusions,
            &plan.scheduled_scope_token
        )
        .is_err()
    );
    write_config(&other, "30d", "cargo");
    assert!(
        run_guarded_scan(
            &executable,
            &plan.roots,
            &plan.exclusions,
            &plan.scheduled_scope_token
        )
        .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn scheduled_scan_and_bytecode_cleanup_leave_go_output_directories_untouched() {
    use std::{
        fs::{self, FileTimes},
        time::{Duration, SystemTime},
    };
    use upkit::schedule::{Frequency, preview_configured_install, run_guarded_scan};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    let config = dir.path().join("settings.toml");
    let build = root.join("build");
    let bin = root.join("bin");
    let pycache = root.join("python/__pycache__");
    let old = SystemTime::now() - Duration::from_secs(8 * 24 * 60 * 60);
    fs::create_dir_all(&build).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&pycache).unwrap();
    fs::write(
        root.join("go.mod"),
        "module example.invalid/service\ngo 1.22\n",
    )
    .unwrap();
    fs::write(build.join("keep"), "Go build fixture").unwrap();
    fs::write(bin.join("keep"), "Go bin fixture").unwrap();
    fs::write(root.join("python/pyproject.toml"), "[project]\n").unwrap();
    fs::write(
        pycache.join("fixture.cpython-312.pyc"),
        "Python bytecode fixture",
    )
    .unwrap();
    for path in [
        root.join("go.mod"),
        build.join("keep"),
        build.clone(),
        bin.join("keep"),
        bin.clone(),
        root.join("python/pyproject.toml"),
        pycache.join("fixture.cpython-312.pyc"),
        pycache.clone(),
    ] {
        fs::File::open(path)
            .unwrap()
            .set_times(FileTimes::new().set_modified(old))
            .unwrap();
    }
    fs::write(
        &config,
        format!(
            "version = 1\nworkspace_roots = ['{}']\nartifact_retention = '0h'\nenabled_ecosystems = ['go', 'python']\n",
            root.display()
        ),
    )
    .unwrap();

    let executable = std::env::current_exe().unwrap();
    let plan =
        preview_configured_install(&executable, Some(&config), None, Frequency::Daily).unwrap();
    let report = run_guarded_scan(
        &executable,
        &plan.roots,
        &plan.exclusions,
        &plan.scheduled_scope_token,
    )
    .unwrap();
    assert_eq!(report.candidates.len(), 3);
    assert_eq!(
        report
            .candidates
            .iter()
            .filter(|candidate| candidate.ecosystem == "go" && candidate.classification == "review")
            .count(),
        2
    );

    fs::write(
        &config,
        format!(
            "version = 1\nworkspace_roots = ['{}']\nartifact_retention = '7d'\nenabled_ecosystems = ['go', 'python']\nscheduled_bytecode_cleanup = true\n",
            root.display()
        ),
    )
    .unwrap();
    let cleanup_plan =
        preview_configured_install(&executable, Some(&config), None, Frequency::Daily).unwrap();
    let cleanup = upkit::scheduled_cleanup::run(
        &dir.path().join("upkit-home"),
        &executable,
        &cleanup_plan.roots,
        &cleanup_plan.exclusions,
        &cleanup_plan.scheduled_scope_token,
        true,
        &std::sync::atomic::AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(cleanup.candidates, 1);
    assert_eq!(cleanup.items.len(), 1);
    assert_eq!(cleanup.items[0].status, "skipped_unverified");
    assert_eq!(
        cleanup.items[0].file,
        pycache.join("fixture.cpython-312.pyc")
    );
    assert_eq!(
        fs::read_to_string(build.join("keep")).unwrap(),
        "Go build fixture"
    );
    assert_eq!(
        fs::read_to_string(bin.join("keep")).unwrap(),
        "Go bin fixture"
    );
    assert_eq!(
        fs::read_to_string(pycache.join("fixture.cpython-312.pyc")).unwrap(),
        "Python bytecode fixture"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn configured_schedule_round_trips_a_non_unicode_config_path() {
    use std::{fs, os::unix::ffi::OsStringExt};
    use upkit::schedule::{Frequency, preview_configured_install, run_guarded_scan};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    let config = dir.path().join(std::ffi::OsString::from_vec(
        b"settings;path=\xff.toml".to_vec(),
    ));
    fs::create_dir_all(root.join("rust/target")).unwrap();
    fs::write(root.join("rust/Cargo.toml"), "[package]").unwrap();
    fs::write(root.join("rust/target/keep"), "fixture").unwrap();
    fs::write(
        &config,
        format!(
            "version = 1\nworkspace_roots = ['{}']\nartifact_retention = '0h'\nenabled_ecosystems = ['cargo']\n",
            root.display()
        ),
    )
    .unwrap();

    let executable = std::env::current_exe().unwrap();
    let plan =
        preview_configured_install(&executable, Some(&config), None, Frequency::Daily).unwrap();
    let display_config = upkit::sweep::display_path(&config)
        .replace(';', "%3B")
        .replace('=', "%3D");
    assert!(plan.service_unit.contains(&format!(
        "config_path={display_config}; config_required=yes; profile_present=no; profile=(none)"
    )));
    let report = run_guarded_scan(
        &executable,
        &plan.roots,
        &plan.exclusions,
        &plan.scheduled_scope_token,
    )
    .unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].ecosystem, "cargo");
    assert_eq!(
        fs::read_to_string(root.join("rust/target/keep")).unwrap(),
        "fixture"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn guarded_scan_rejects_malformed_and_oversized_policy_tokens_but_keeps_legacy_tokens() {
    use std::fs;
    use upkit::schedule::{run_guarded_scan, scheduled_scope_token};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("keep"), "fixture").unwrap();
    let executable = std::env::current_exe().unwrap();
    let roots = vec![root.clone()];
    let legacy = scheduled_scope_token(&executable, &roots, &[]).unwrap();
    assert!(run_guarded_scan(&executable, &roots, &[], &legacy).is_ok());
    assert!(run_guarded_scan(&executable, &roots, &[], "v2.not-hex.deadbeef").is_err());
    assert!(
        run_guarded_scan(
            &executable,
            &roots,
            &[],
            &format!("v2.{}", "0".repeat(40_000))
        )
        .is_err()
    );
    assert_eq!(fs::read_to_string(root.join("keep")).unwrap(), "fixture");
}

#[cfg(target_os = "linux")]
#[test]
fn scheduled_scope_rejects_replaced_root_and_changed_exclusions() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .arg(&root)
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .output()
            .unwrap()
    };
    let preview = run(&[
        "--json",
        "--non-interactive",
        "schedule",
        "preview",
        "--frequency",
        "daily",
        "--exclude",
        "private",
    ]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let token = plan["scheduled_scope_token"].as_str().unwrap();
    assert!(
        plan["service_unit"]
            .as_str()
            .unwrap()
            .contains(&format!("--scope-token {token}"))
    );
    fs::write(root.join("new-file"), "fixture").unwrap();
    let dry = run(&[
        "--json",
        "--non-interactive",
        "--offline",
        "--dry-run",
        "--config",
        "/dev/null",
        "sweep",
        "scan",
        "--scope-token",
        token,
        "--exclude",
        "private",
    ]);
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stdout)
    );
    assert!(!dir.path().join("data/upkit/history").exists());
    let verified = run(&[
        "--json",
        "--non-interactive",
        "--offline",
        "--config",
        "/dev/null",
        "sweep",
        "scan",
        "--scope-token",
        token,
        "--exclude",
        "private",
    ]);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stdout)
    );
    let missing_constraints = run(&[
        "--json",
        "--offline",
        "--config",
        "/dev/null",
        "sweep",
        "scan",
        "--scope-token",
        token,
        "--exclude",
        "private",
    ]);
    assert!(!missing_constraints.status.success());
    let changed_config = run(&[
        "--json",
        "--non-interactive",
        "--offline",
        "sweep",
        "scan",
        "--scope-token",
        token,
        "--exclude",
        "private",
    ]);
    assert!(!changed_config.status.success());
    let changed_exclusion = run(&[
        "--json",
        "--non-interactive",
        "--offline",
        "--config",
        "/dev/null",
        "sweep",
        "scan",
        "--scope-token",
        token,
    ]);
    assert!(!changed_exclusion.status.success());
    fs::rename(&root, dir.path().join("previous-workspace")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(root.join("keep"), "untouched").unwrap();
    let changed_root = run(&[
        "--json",
        "--non-interactive",
        "--offline",
        "--config",
        "/dev/null",
        "sweep",
        "scan",
        "--scope-token",
        token,
        "--exclude",
        "private",
    ]);
    assert!(!changed_root.status.success());
    let error: serde_json::Value = serde_json::from_slice(&changed_root.stdout).unwrap();
    assert!(
        error["error"]
            .as_str()
            .unwrap()
            .contains("scope or executable changed")
    );
    assert_eq!(fs::read_to_string(root.join("keep")).unwrap(), "untouched");
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "--non-interactive", "report"])
        .env("HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let history: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let records = history["records"].as_array().unwrap();
    assert!(
        records
            .iter()
            .any(|record| record["operation"] == "scheduled_scan"
                && record["outcome"] == "completed"
                && record["verified_reclaimed_bytes"].is_null())
    );
    assert!(
        records
            .iter()
            .any(|record| record["operation"] == "scheduled_scan"
                && record["outcome"] == "failed_or_unknown")
    );
    let scheduled_records = records
        .iter()
        .filter(|record| record["operation"] == "scheduled_scan")
        .collect::<Vec<_>>();
    assert!(
        scheduled_records
            .iter()
            .all(|record| record["target"] == "configured workspace scan (roots: 1)")
    );
    assert!(!history.to_string().contains(&root.display().to_string()));
}

#[cfg(target_os = "linux")]
#[test]
fn scheduled_scope_rejects_a_replaced_executable() {
    use std::fs;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    let executable = dir.path().join("executable");
    fs::create_dir(&root).unwrap();
    fs::write(&executable, "first").unwrap();
    let roots = vec![root];
    let first = upkit::schedule::scheduled_scope_token(&executable, &roots, &[]).unwrap();
    fs::rename(&executable, dir.path().join("old-executable")).unwrap();
    fs::write(&executable, "second").unwrap();
    let second = upkit::schedule::scheduled_scope_token(&executable, &roots, &[]).unwrap();
    assert_ne!(first, second);
}

#[cfg(target_os = "linux")]
#[test]
fn scheduled_partial_scan_exits_nonzero_and_records_partial_result() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    fs::create_dir_all(root.join("target/private")).unwrap();
    fs::write(root.join("Cargo.toml"), "[workspace]").unwrap();
    fs::write(root.join("target/private/keep"), "fixture").unwrap();
    let run = |args: &[&str], with_root: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        command
            .args(args)
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_DATA_HOME", dir.path().join("data"));
        if with_root {
            command.arg(&root);
        }
        command.output().unwrap()
    };
    let preview = run(
        &[
            "--json",
            "--non-interactive",
            "schedule",
            "preview",
            "--frequency",
            "daily",
            "--exclude",
            "target/private",
        ],
        true,
    );
    assert!(preview.status.success());
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let token = plan["scheduled_scope_token"].as_str().unwrap();
    let scan = run(
        &[
            "--json",
            "--non-interactive",
            "--offline",
            "--config",
            "/dev/null",
            "sweep",
            "scan",
            "--scope-token",
            token,
            "--exclude",
            "target/private",
        ],
        true,
    );
    assert!(!scan.status.success());
    let report: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert!(!report["warnings"].as_array().unwrap().is_empty());
    assert_eq!(report["candidates"][0]["size_complete"], false);
    let history = run(&["--json", "--non-interactive", "report"], false);
    assert!(history.status.success());
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["operation"] == "scheduled_scan"
                && record["outcome"] == "partial"
                && record["verified_reclaimed_bytes"].is_null())
    );
    assert_eq!(
        fs::read_to_string(root.join("target/private/keep")).unwrap(),
        "fixture"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn scheduled_scan_reports_history_write_failure_without_claiming_cleanup() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("keep"), "fixture").unwrap();
    let home = dir.path().join("data/upkit");
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("history"), "not a directory").unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .arg(&root)
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .output()
            .unwrap()
    };
    let preview = run(&[
        "--json",
        "--non-interactive",
        "schedule",
        "preview",
        "--frequency",
        "daily",
    ]);
    assert!(preview.status.success());
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let token = preview["scheduled_scope_token"].as_str().unwrap();
    let scan = run(&[
        "--json",
        "--non-interactive",
        "--offline",
        "--config",
        "/dev/null",
        "sweep",
        "scan",
        "--scope-token",
        token,
    ]);
    assert!(scan.status.success());
    let report: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    assert!(
        report["history_warning"]
            .as_str()
            .unwrap()
            .contains("not recorded")
    );
    assert_eq!(fs::read_to_string(root.join("keep")).unwrap(), "fixture");
    assert_eq!(
        fs::read_to_string(home.join("history")).unwrap(),
        "not a directory"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn launchd_schedule_lifecycle_uses_only_a_mock_manager_and_fixture_home() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    let fixture = tempfile::tempdir().unwrap();
    let fixture_path = fixture.path().canonicalize().unwrap();
    let home = fixture_path.join("home");
    let launch_agents = home.join("Library/LaunchAgents");
    let root = fixture_path.join("workspace");
    let bin = fixture_path.join("bin");
    fs::create_dir_all(&launch_agents).unwrap();
    fs::set_permissions(&launch_agents, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(&root).unwrap();
    fs::create_dir(&bin).unwrap();
    let manager = bin.join("launchctl");
    fs::write(
        &manager,
        r##"#!/bin/sh
root="$FIXTURE"
domain="gui/$FIXTURE_UID"
label="$domain/upkit-scan.timer"
case "$1" in
 list)
  [ "$#" -eq 1 ] || exit 8
  printf 'PID Status Label\n'
  [ ! -f "$root/loaded" ] || printf '%s\n' '- 0 upkit-scan.timer'
  ;;
 print-disabled)
  [ "$#" -eq 2 ] && [ "$2" = "$domain" ] || exit 8
  printf 'disabled services = {\n'
  [ ! -f "$root/disabled" ] || printf '    "%s" => disabled\n' 'upkit-scan.timer'
  printf '}\n'
  ;;
 print)
  [ "$#" -eq 2 ] && [ "$2" = "$label" ] && [ -f "$root/loaded" ] || exit 1
  printf 'gui job = {\n    path = %s\n    type = LaunchAgent\n}\n' "$HOME/Library/LaunchAgents/upkit-scan.timer.plist"
  ;;
 enable)
  [ "$#" -eq 2 ] && [ "$2" = "$label" ] || exit 8
  /bin/rm -f "$root/disabled"
  ;;
 disable)
  [ "$#" -eq 2 ] && [ "$2" = "$label" ] || exit 8
  : > "$root/disabled"
  ;;
 bootstrap)
  [ "$#" -eq 3 ] && [ "$2" = "$domain" ] && [ -f "$3" ] && [ ! -f "$root/loaded" ] || exit 8
  : > "$root/loaded"
  ;;
 bootout)
  [ "$#" -eq 2 ] && [ "$2" = "$label" ] || exit 8
  /bin/rm -f "$root/loaded"
  ;;
 *) exit 8 ;;
esac
"##,
    )
    .unwrap();
    fs::set_permissions(&manager, fs::Permissions::from_mode(0o755)).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(["--json", "--non-interactive"])
            .args(args)
            .env("HOME", &home)
            .env("FIXTURE", &fixture_path)
            .env(
                "FIXTURE_UID",
                rustix::process::geteuid().as_raw().to_string(),
            )
            .env("PATH", &bin)
            .output()
            .unwrap()
    };
    let json = |output: &std::process::Output| {
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let preview = json(&run(&[
        "schedule",
        "preview",
        "--frequency",
        "daily",
        root.to_str().unwrap(),
    ]));
    assert!(preview["warning"].as_str().unwrap().contains("launchd"));
    let token = preview["preview_token"].as_str().unwrap();
    let dry_run = run(&[
        "--dry-run",
        "--yes",
        "schedule",
        "add",
        "--frequency",
        "daily",
        "--authorize-schedule",
        "--preview-token",
        token,
        root.to_str().unwrap(),
    ]);
    assert!(dry_run.status.success());
    assert!(!launch_agents.join("upkit-scan.timer.plist").exists());
    let added = json(&run(&[
        "--yes",
        "schedule",
        "add",
        "--frequency",
        "daily",
        "--authorize-schedule",
        "--preview-token",
        token,
        root.to_str().unwrap(),
    ]));
    assert_eq!(added["verification"], "active_and_enabled");
    let plist = launch_agents.join("upkit-scan.timer.plist");
    assert_eq!(
        fs::metadata(&plist).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(fixture.path().join("loaded").exists());
    assert!(
        !run(&[
            "--yes",
            "schedule",
            "add",
            "--frequency",
            "daily",
            "--authorize-schedule",
            "--preview-token",
            token,
            root.to_str().unwrap(),
        ])
        .status
        .success()
    );

    let disabled = json(&run(&["schedule", "preview-disable"]));
    let disabled_token = disabled["preview_token"].as_str().unwrap();
    let result = json(&run(&[
        "--yes",
        "schedule",
        "disable",
        "--authorize-schedule",
        "--preview-token",
        disabled_token,
    ]));
    assert_eq!(result["verification"], "inactive_and_disabled");
    assert!(!fixture.path().join("loaded").exists());
    assert!(fixture.path().join("disabled").exists());

    let enable = json(&run(&[
        "schedule",
        "preview-enable",
        "--frequency",
        "daily",
        root.to_str().unwrap(),
    ]));
    let enable_token = enable["preview_token"].as_str().unwrap();
    let result = json(&run(&[
        "--yes",
        "schedule",
        "enable",
        "--frequency",
        "daily",
        "--authorize-schedule",
        "--preview-token",
        enable_token,
        root.to_str().unwrap(),
    ]));
    assert_eq!(result["verification"], "active_and_enabled");
    assert!(fixture.path().join("loaded").exists());

    let disabled = json(&run(&["schedule", "preview-disable"]));
    let result = json(&run(&[
        "--yes",
        "schedule",
        "disable",
        "--authorize-schedule",
        "--preview-token",
        disabled["preview_token"].as_str().unwrap(),
    ]));
    assert_eq!(result["verification"], "inactive_and_disabled");
    let removal = json(&run(&["schedule", "preview-remove"]));
    let result = json(&run(&[
        "--yes",
        "schedule",
        "remove",
        "--authorize-schedule-removal",
        "--preview-token",
        removal["preview_token"].as_str().unwrap(),
    ]));
    assert_eq!(result["verification"], "units_absent");
    assert!(!plist.exists());
    assert!(!fixture.path().join("loaded").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn schedule_edit_revalidates_and_reports_partial_replacement() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    let config = dir.path().join("config");
    let units = config.join("systemd/user");
    let bin = dir.path().join("bin");
    fs::create_dir(&root).unwrap();
    fs::create_dir_all(&units).unwrap();
    fs::set_permissions(&units, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&bin).unwrap();
    let ctl = bin.join("systemctl");
    fs::write(&ctl, r##"#!/bin/sh
[ "$1" = --user ] || exit 9
case "$2" in
 show)
  case "$5" in
   --property=FragmentPath) [ ! -e "$XDG_CONFIG_HOME/systemd/user/$3" ] || printf '%s\n' "$XDG_CONFIG_HOME/systemd/user/$3" ;;
   --property=LoadState) if [ -e "$XDG_CONFIG_HOME/systemd/user/$3" ]; then printf 'loaded\n'; else printf 'not-found\n'; fi ;;
   --property=NeedDaemonReload) printf 'no\n' ;;
   --property=DropInPaths) : ;;
   --property=ActiveState) printf 'inactive\n' ;;
   --property=LoadState,ActiveState,UnitFileState,LastTriggerUSec,NextElapseUSecRealtime) if [ -f "$HOME/enabled" ]; then printf 'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n'; else printf 'LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n'; fi ;;
   *) exit 8 ;;
  esac ;;
 daemon-reload) : ;;
 enable) [ "$3" = --now ] && [ "$4" = upkit-scan.timer ] && [ ! -f "$HOME/fail_enable" ] || exit 7; printf enabled > "$HOME/enabled" ;;
 *) exit 6 ;;
esac
"##).unwrap();
    fs::set_permissions(&ctl, fs::Permissions::from_mode(0o755)).unwrap();
    let run = |args: &[&str], with_root: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_upkit"));
        cmd.args(args)
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("PATH", &bin);
        if with_root {
            cmd.arg(&root);
        }
        cmd.output().unwrap()
    };
    let original = run(
        &[
            "--json",
            "--non-interactive",
            "schedule",
            "preview",
            "--frequency",
            "daily",
        ],
        true,
    );
    assert!(original.status.success());
    let original: serde_json::Value = serde_json::from_slice(&original.stdout).unwrap();
    let write_original = || {
        for (name, key) in [
            ("upkit-scan.service", "service_unit"),
            ("upkit-scan.timer", "timer_unit"),
        ] {
            let path = units.join(name);
            fs::write(&path, original[key].as_str().unwrap()).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    };
    write_original();
    let preview_args = [
        "--json",
        "--non-interactive",
        "schedule",
        "preview-edit",
        "--frequency",
        "weekly",
        "--exclude",
        "private",
    ];
    let preview = run(&preview_args, true);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let token = plan["preview_token"].as_str().unwrap();
    assert_eq!(
        plan["previous"]["existing"]["service_unit"],
        original["service_unit"]
    );
    assert!(
        plan["replacement"]["timer_unit"]
            .as_str()
            .unwrap()
            .contains("OnCalendar=weekly")
    );
    let denied = run(
        &[
            "--json",
            "--non-interactive",
            "--yes",
            "schedule",
            "edit",
            "--frequency",
            "weekly",
            "--exclude",
            "private",
            "--preview-token",
            token,
        ],
        true,
    );
    assert!(!denied.status.success());
    let dry = run(
        &[
            "--json",
            "--non-interactive",
            "--dry-run",
            "schedule",
            "edit",
            "--frequency",
            "weekly",
            "--exclude",
            "private",
        ],
        true,
    );
    assert!(dry.status.success());
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.timer")).unwrap(),
        original["timer_unit"].as_str().unwrap()
    );
    let stale = run(
        &[
            "--json",
            "--non-interactive",
            "--yes",
            "schedule",
            "edit",
            "--frequency",
            "weekly",
            "--exclude",
            "private",
            "--authorize-schedule-edit",
            "--preview-token",
            "wrong",
        ],
        true,
    );
    assert!(!stale.status.success());
    assert!(!dir.path().join("enabled").exists());
    fs::write(dir.path().join("fail_enable"), "fixture").unwrap();
    let partial = run(
        &[
            "--json",
            "--non-interactive",
            "--yes",
            "schedule",
            "edit",
            "--frequency",
            "weekly",
            "--exclude",
            "private",
            "--authorize-schedule-edit",
            "--preview-token",
            token,
        ],
        true,
    );
    assert!(!partial.status.success());
    let error: serde_json::Value = serde_json::from_slice(&partial.stdout).unwrap();
    assert!(
        error["error"]
            .as_str()
            .unwrap()
            .contains("old units were removed")
    );
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.timer")).unwrap(),
        plan["replacement"]["timer_unit"].as_str().unwrap()
    );
    assert!(!dir.path().join("enabled").exists());
    fs::remove_file(units.join("upkit-scan.service")).unwrap();
    fs::remove_file(units.join("upkit-scan.timer")).unwrap();
    fs::remove_file(dir.path().join("fail_enable")).unwrap();
    write_original();
    let preview = run(&preview_args, true);
    assert!(preview.status.success());
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let token = plan["preview_token"].as_str().unwrap();
    let edited = run(
        &[
            "--json",
            "--non-interactive",
            "--yes",
            "schedule",
            "edit",
            "--frequency",
            "weekly",
            "--exclude",
            "private",
            "--authorize-schedule-edit",
            "--preview-token",
            token,
        ],
        true,
    );
    assert!(
        edited.status.success(),
        "{}",
        String::from_utf8_lossy(&edited.stdout)
    );
    let edited: serde_json::Value = serde_json::from_slice(&edited.stdout).unwrap();
    assert_eq!(edited["verification"], "active_and_enabled");
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.service")).unwrap(),
        plan["replacement"]["service_unit"].as_str().unwrap()
    );
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.timer")).unwrap(),
        plan["replacement"]["timer_unit"].as_str().unwrap()
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("enabled")).unwrap(),
        "enabled"
    );
    assert!(!units.read_dir().unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".upkit-remove-")
    }));
    let history = run(&["--json", "--non-interactive", "report"], false);
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |record| record["operation"] == "schedule_edit" && record["outcome"] == "completed"
            )
    );
}

#[cfg(target_os = "linux")]
#[test]
fn configured_cli_schedule_lifecycle_rechecks_profile_policy() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workspace");
    let config_home = dir.path().join("config-home");
    let units = config_home.join("systemd/user");
    let bin = dir.path().join("bin");
    let config = dir.path().join("settings.toml");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&units).unwrap();
    fs::set_permissions(&units, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&bin).unwrap();
    let ctl = bin.join("systemctl");
    fs::write(&ctl, r##"#!/bin/sh
[ "$1" = --user ] || exit 9
case "$2" in
 show)
   case "$5" in
    --property=FragmentPath) [ ! -e "$XDG_CONFIG_HOME/systemd/user/$3" ] || printf '%s\n' "$XDG_CONFIG_HOME/systemd/user/$3" ;;
    --property=LoadState) if [ -e "$XDG_CONFIG_HOME/systemd/user/$3" ]; then printf 'loaded\n'; else printf 'not-found\n'; fi ;;
    --property=DropInPaths) : ;;
    --property=NeedDaemonReload) printf 'no\n' ;;
    --property=ActiveState) printf 'inactive\n' ;;
    --property=LoadState,ActiveState,UnitFileState,LastTriggerUSec,NextElapseUSecRealtime) if [ -s "$HOME/inactive" ]; then printf 'LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n'; else printf 'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n'; fi ;;
    *) exit 8 ;;
   esac ;;
 daemon-reload) printf reload >> "$HOME/actions"; if [ -f "$HOME/change_config" ]; then printf 'version = 1\n' > "$TEST_CONFIG"; fi ;;
 enable) [ "$3" = --now ] && [ "$4" = upkit-scan.timer ] || exit 7; printf enable >> "$HOME/actions"; : > "$HOME/inactive" ;;
 disable) [ "$3" = --now ] && [ "$4" = upkit-scan.timer ] || exit 7; printf disable >> "$HOME/actions"; printf inactive > "$HOME/inactive" ;;
 *) exit 6 ;;
esac
"##).unwrap();
    fs::set_permissions(&ctl, fs::Permissions::from_mode(0o755)).unwrap();
    let write_policy = |age: &str| {
        fs::write(&config, format!(
            "version = 1\nexclusions = ['private']\n[profiles.work]\nworkspace_roots = ['{}']\nartifact_retention = '{age}'\nenabled_ecosystems = ['cargo']\n",
            root.display()
        )).unwrap();
    };
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(["--json", "--non-interactive", "--yes", "--config"])
            .arg(&config)
            .args(["--profile", "work"])
            .args(args)
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", &config_home)
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("TEST_CONFIG", &config)
            .env("PATH", &bin)
            .output()
            .unwrap()
    };
    let json = |output: &std::process::Output| {
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    write_policy("30d");
    let preview = json(&run(&["schedule", "preview", "--frequency", "daily"]));
    assert!(
        preview["warning"]
            .as_str()
            .unwrap()
            .contains("rechecked before each scan")
    );
    let token = preview["preview_token"].as_str().unwrap();
    assert!(
        preview["service_unit"]
            .as_str()
            .unwrap()
            .contains("older_than_seconds=2592000")
    );
    assert!(
        preview["service_unit"]
            .as_str()
            .unwrap()
            .contains("enabled_ecosystems=cargo")
    );
    assert!(
        preview["service_unit"]
            .as_str()
            .unwrap()
            .contains("--exclude=private")
    );
    assert!(
        preview["scheduled_scope_token"]
            .as_str()
            .unwrap()
            .starts_with("v2.")
    );
    assert!(
        !run(&[
            "schedule",
            "preview",
            "--frequency",
            "daily",
            "--exclude",
            "other"
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "schedule",
            "add",
            "--frequency",
            "daily",
            "--preview-token",
            token
        ])
        .status
        .success()
    );
    write_policy("60d");
    assert!(
        !run(&[
            "schedule",
            "add",
            "--frequency",
            "daily",
            "--authorize-schedule",
            "--preview-token",
            token
        ])
        .status
        .success()
    );
    assert_eq!(fs::read_dir(&units).unwrap().count(), 0);
    assert!(!dir.path().join("actions").exists());
    write_policy("30d");
    fs::write(dir.path().join("change_config"), "fixture").unwrap();
    assert!(
        !run(&[
            "schedule",
            "add",
            "--frequency",
            "daily",
            "--authorize-schedule",
            "--preview-token",
            token,
        ])
        .status
        .success()
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("actions")).unwrap(),
        "reload"
    );
    assert!(units.join("upkit-scan.service").exists());
    assert!(units.join("upkit-scan.timer").exists());
    fs::remove_file(units.join("upkit-scan.service")).unwrap();
    fs::remove_file(units.join("upkit-scan.timer")).unwrap();
    fs::remove_file(dir.path().join("change_config")).unwrap();
    fs::remove_file(dir.path().join("actions")).unwrap();
    write_policy("30d");
    let added = json(&run(&[
        "schedule",
        "add",
        "--frequency",
        "daily",
        "--authorize-schedule",
        "--preview-token",
        token,
    ]));
    assert_eq!(added["verification"], "active_and_enabled");
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.service")).unwrap(),
        preview["service_unit"].as_str().unwrap()
    );

    let disable = json(&run(&["schedule", "preview-disable"]));
    let disable_token = disable["preview_token"].as_str().unwrap();
    json(&run(&[
        "schedule",
        "disable",
        "--authorize-schedule",
        "--preview-token",
        disable_token,
    ]));
    let enable = json(&run(&[
        "schedule",
        "preview-enable",
        "--frequency",
        "daily",
    ]));
    let enable_token = enable["preview_token"].as_str().unwrap();
    write_policy("60d");
    assert!(
        !run(&[
            "schedule",
            "enable",
            "--frequency",
            "daily",
            "--authorize-schedule",
            "--preview-token",
            enable_token
        ])
        .status
        .success()
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("inactive")).unwrap(),
        "inactive"
    );
    write_policy("30d");
    let enabled = json(&run(&[
        "schedule",
        "enable",
        "--frequency",
        "daily",
        "--authorize-schedule",
        "--preview-token",
        enable_token,
    ]));
    assert_eq!(enabled["verification"], "active_and_enabled");
    let disable = json(&run(&["schedule", "preview-disable"]));
    json(&run(&[
        "schedule",
        "disable",
        "--authorize-schedule",
        "--preview-token",
        disable["preview_token"].as_str().unwrap(),
    ]));
    write_policy("60d");
    let edit = json(&run(&["schedule", "preview-edit", "--frequency", "weekly"]));
    let edit_token = edit["preview_token"].as_str().unwrap();
    write_policy("90d");
    assert!(
        !run(&[
            "schedule",
            "edit",
            "--frequency",
            "weekly",
            "--authorize-schedule-edit",
            "--preview-token",
            edit_token
        ])
        .status
        .success()
    );
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.service")).unwrap(),
        preview["service_unit"].as_str().unwrap()
    );
    write_policy("60d");
    let edited = json(&run(&[
        "schedule",
        "edit",
        "--frequency",
        "weekly",
        "--authorize-schedule-edit",
        "--preview-token",
        edit_token,
    ]));
    assert_eq!(edited["verification"], "active_and_enabled");
    assert_eq!(
        fs::read_to_string(units.join("upkit-scan.service")).unwrap(),
        edit["replacement"]["service_unit"].as_str().unwrap()
    );
    assert!(
        fs::read_to_string(units.join("upkit-scan.service"))
            .unwrap()
            .contains("older_than_seconds=5184000")
    );
    let disable = json(&run(&["schedule", "preview-disable"]));
    json(&run(&[
        "schedule",
        "disable",
        "--authorize-schedule",
        "--preview-token",
        disable["preview_token"].as_str().unwrap(),
    ]));
    fs::write(&config, format!(
        "version = 1\nexclusions = ['private']\n[profiles.work]\nworkspace_roots = ['{}']\nartifact_retention = '60d'\nenabled_ecosystems = ['python']\nscheduled_bytecode_cleanup = true\n",
        root.display(),
    )).unwrap();
    let cleanup_edit = json(&run(&["schedule", "preview-edit", "--frequency", "weekly"]));
    assert!(
        cleanup_edit["warning"]
            .as_str()
            .unwrap()
            .contains("automatic permanent cleanup")
    );
    assert!(
        cleanup_edit["replacement"]["warning"]
            .as_str()
            .unwrap()
            .contains("eligible Python bytecode")
    );
    assert!(
        cleanup_edit["replacement"]["service_unit"]
            .as_str()
            .unwrap()
            .contains("scheduled-bytecode-cleanup --authorize-scheduled-cleanup")
    );
    let edit_token = cleanup_edit["preview_token"].as_str().unwrap();
    let cleanup_edit_result = json(&run(&[
        "schedule",
        "edit",
        "--frequency",
        "weekly",
        "--authorize-schedule-edit",
        "--preview-token",
        edit_token,
    ]));
    assert_eq!(cleanup_edit_result["verification"], "active_and_enabled");
    let cleanup_disable = json(&run(&["schedule", "preview-disable"]));
    assert!(
        cleanup_disable["warning"]
            .as_str()
            .unwrap()
            .contains("cleanup")
    );
    json(&run(&[
        "schedule",
        "disable",
        "--authorize-schedule",
        "--preview-token",
        cleanup_disable["preview_token"].as_str().unwrap(),
    ]));
    let cleanup_enable = json(&run(&[
        "schedule",
        "preview-enable",
        "--frequency",
        "weekly",
    ]));
    assert!(
        cleanup_enable["warning"]
            .as_str()
            .unwrap()
            .contains("automatic permanent cleanup")
    );
    assert!(
        cleanup_enable["intended"]["warning"]
            .as_str()
            .unwrap()
            .contains("eligible Python bytecode")
    );
    let cleanup_enabled = json(&run(&[
        "schedule",
        "enable",
        "--frequency",
        "weekly",
        "--authorize-schedule",
        "--preview-token",
        cleanup_enable["preview_token"].as_str().unwrap(),
    ]));
    assert_eq!(cleanup_enabled["verification"], "active_and_enabled");

    let disable = json(&run(&["schedule", "preview-disable"]));
    json(&run(&[
        "schedule",
        "disable",
        "--authorize-schedule",
        "--preview-token",
        disable["preview_token"].as_str().unwrap(),
    ]));
    let removal = json(&run(&["schedule", "preview-remove"]));
    json(&run(&[
        "schedule",
        "remove",
        "--authorize-schedule-removal",
        "--preview-token",
        removal["preview_token"].as_str().unwrap(),
    ]));
    fs::write(&config, format!(
        "version = 1\nexclusions = ['private']\n[profiles.work]\nworkspace_roots = ['{}']\nartifact_retention = '60d'\nenabled_ecosystems = ['python']\nscheduled_bytecode_cleanup = true\nschedule_frequency = 'weekly'\n",
        root.display(),
    )).unwrap();
    let frequency_preview = json(&run(&["schedule", "preview"]));
    assert_eq!(frequency_preview["frequency"], "weekly");
    let frequency_token = frequency_preview["preview_token"].as_str().unwrap();
    fs::write(&config, format!(
        "version = 1\nexclusions = ['private']\n[profiles.work]\nworkspace_roots = ['{}']\nartifact_retention = '60d'\nenabled_ecosystems = ['python']\nscheduled_bytecode_cleanup = true\nschedule_frequency = 'daily'\n",
        root.display(),
    )).unwrap();
    let stale_frequency_add = run(&[
        "schedule",
        "add",
        "--authorize-schedule",
        "--preview-token",
        frequency_token,
    ]);
    assert!(
        !stale_frequency_add.status.success(),
        "{} {}",
        String::from_utf8_lossy(&stale_frequency_add.stdout),
        String::from_utf8_lossy(&stale_frequency_add.stderr)
    );
    assert!(!units.join("upkit-scan.service").exists());
    assert!(!units.join("upkit-scan.timer").exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cli_schedule_frequency_uses_explicit_profile_global_then_weekly_default() {
    use std::process::Command;
    use upkit::config::{Profile, ScheduleFrequency, Settings, create};

    let dir = tempfile::tempdir().unwrap();
    let global_root = dir.path().join("global");
    let override_root = dir.path().join("override");
    let inherited_root = dir.path().join("inherited");
    for root in [&global_root, &override_root, &inherited_root] {
        std::fs::create_dir(root).unwrap();
    }
    let config = dir.path().join("settings.toml");
    let mut settings = Settings {
        workspace_roots: vec![global_root],
        schedule_frequency: Some(ScheduleFrequency::Daily),
        ..Settings::default()
    };
    settings.profiles.insert(
        "override".into(),
        Profile {
            workspace_roots: vec![override_root],
            schedule_frequency: Some(ScheduleFrequency::Weekly),
            ..Profile::default()
        },
    );
    settings.profiles.insert(
        "inherit".into(),
        Profile {
            workspace_roots: vec![inherited_root],
            ..Profile::default()
        },
    );
    create(&config, &settings, false).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(["--json", "--non-interactive", "--config"])
            .arg(&config)
            .args(args)
            .env("HOME", dir.path())
            .output()
            .unwrap()
    };
    let preview = |args: &[&str]| {
        let output = run(args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };

    assert_eq!(preview(&["schedule", "preview"])["frequency"], "daily");
    assert_eq!(
        preview(&["--profile", "override", "schedule", "preview"])["frequency"],
        "weekly"
    );
    assert_eq!(
        preview(&["--profile", "inherit", "schedule", "preview"])["frequency"],
        "daily"
    );
    assert_eq!(
        preview(&[
            "--profile",
            "override",
            "schedule",
            "preview",
            "--frequency",
            "daily",
        ])["frequency"],
        "daily"
    );

    let default_config = dir.path().join("default.toml");
    create(
        &default_config,
        &Settings {
            workspace_roots: vec![dir.path().join("default-workspace")],
            ..Settings::default()
        },
        false,
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("default-workspace")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "--non-interactive", "--config"])
        .arg(default_config)
        .args(["schedule", "preview"])
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["frequency"], "weekly");
}
