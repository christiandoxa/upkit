use std::process::Command;
#[cfg(unix)]
use tempfile::tempdir;

#[cfg(target_os = "linux")]
#[test]
fn trash_status_reports_fixture_items_and_dates_without_removal() {
    use std::fs;
    let dir = tempdir().unwrap();
    let trash = dir.path().join("Trash");
    fs::create_dir_all(trash.join("files")).unwrap();
    fs::create_dir_all(trash.join("info")).unwrap();
    fs::write(trash.join("files/item"), "fixture").unwrap();
    fs::write(
        trash.join("info/item.trashinfo"),
        "[Trash Info]\nPath=/private\nDeletionDate=2025-01-03T12:30:00\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "trash", "status"])
        .env("HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let home = report["locations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["kind"] == "home")
        .unwrap();
    assert_eq!(home["items"][0]["name"], "item");
    assert_eq!(home["items"][0]["deletion_date"], "2025-01-03T12:30:00");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("/private"));
    assert_eq!(
        fs::read_to_string(trash.join("files/item")).unwrap(),
        "fixture"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn trash_retention_preview_classifies_dates_without_selecting_or_removing() {
    use std::fs;
    let dir = tempdir().unwrap();
    let trash = dir.path().join("Trash");
    fs::create_dir_all(trash.join("files")).unwrap();
    fs::create_dir_all(trash.join("info")).unwrap();
    for (name, date) in [
        ("old", Some("2000-01-01T00:00:00")),
        ("future", Some("2999-01-01T00:00:00")),
        ("unknown", None),
    ] {
        fs::write(trash.join("files").join(name), "fixture").unwrap();
        if let Some(date) = date {
            fs::write(
                trash.join("info").join(format!("{name}.trashinfo")),
                format!("[Trash Info]\nDeletionDate={date}\n"),
            )
            .unwrap();
        }
    }
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "trash", "preview", "--older-than", "30d"])
        .env("HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path())
        .env("TZ", "UTC")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let items = report["items"].as_array().unwrap();
    for (name, expected) in [
        ("old", "older_than_threshold"),
        ("future", "newer_or_future"),
        ("unknown", "unknown_or_ambiguous"),
    ] {
        let item = items.iter().find(|item| item["name"] == name).unwrap();
        assert_eq!(item["age_status"], expected);
        assert_eq!(item["selected"], false);
        assert_eq!(
            fs::read_to_string(trash.join("files").join(name)).unwrap(),
            "fixture"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn trash_retention_treats_ambiguous_local_times_as_unknown() {
    use std::fs;
    if !std::path::Path::new("/usr/share/zoneinfo/America/New_York").exists() {
        return;
    }
    let dir = tempdir().unwrap();
    let trash = dir.path().join("Trash");
    fs::create_dir_all(trash.join("files")).unwrap();
    fs::create_dir_all(trash.join("info")).unwrap();
    fs::write(trash.join("files/item"), "fixture").unwrap();
    fs::write(
        trash.join("info/item.trashinfo"),
        "[Trash Info]\nDeletionDate=2020-11-01T01:30:00\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "trash", "preview", "--older-than", "30d"])
        .env("HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path())
        .env("TZ", "America/New_York")
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let item = report["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "item")
        .unwrap();
    assert_eq!(item["age_status"], "unknown_or_ambiguous");
    assert!(trash.join("files/item").exists());
}

#[cfg(unix)]
#[test]
fn trim_status_uses_read_only_timer_query_and_preserves_home() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let dir = tempdir().unwrap();
    let bin = dir.path().join("bin");
    let home = dir.path().join("home");
    fs::create_dir(&bin).unwrap();
    fs::create_dir(&home).unwrap();
    let systemctl = bin.join("systemctl");
    fs::write(&systemctl, "#!/bin/sh\n[ \"$1\" = show ] || exit 2\nprintf 'LoadState=loaded\\nActiveState=active\\nLastTriggerUSec=last\\nNextElapseUSecRealtime=next\\n'\n").unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
    let fstrim = bin.join("fstrim");
    fs::write(&fstrim, "#!/bin/sh\nexit 99\n").unwrap();
    fs::set_permissions(&fstrim, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "maintenance", "trim", "--status"])
        .env("PATH", &bin)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    if cfg!(target_os = "linux") {
        assert_eq!(report["timer"]["state"], "active");
        assert_eq!(report["timer"]["last_trigger"], "last");
        assert_eq!(report["timer"]["next_trigger"], "next");
        assert_eq!(report["fstrim_available"], true);
        assert!(
            report["capability"]
                .as_str()
                .unwrap()
                .starts_with("unknown")
        );
    } else {
        assert_eq!(report["timer"]["state"], "unavailable");
    }
    assert!(fs::read_dir(home).unwrap().next().is_none());
}

#[test]
fn trim_run_is_not_silently_accepted() {
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["maintenance", "trim", "--run"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[cfg(unix)]
#[test]
fn trim_refuses_missing_explicit_authorization_before_running_program() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let dir = tempdir().unwrap();
    let fstrim = dir.path().join("fstrim");
    fs::write(&fstrim, "#!/bin/sh\ntouch \"$HOME/executed\"\n").unwrap();
    fs::set_permissions(&fstrim, fs::Permissions::from_mode(0o755)).unwrap();
    for args in [
        vec![
            "--non-interactive",
            "--yes",
            "maintenance",
            "trim",
            "--run",
            "--mount",
            "/",
        ],
        vec![
            "--non-interactive",
            "maintenance",
            "trim",
            "--run",
            "--mount",
            "/",
            "--authorize-trim",
            "--preview-token",
            "test",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .env("HOME", dir.path())
            .env("PATH", dir.path())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!dir.path().join("executed").exists());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn unresponsive_systemd_query_fails_gracefully() {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };
    let dir = tempdir().unwrap();
    let systemctl = dir.path().join("systemctl");
    fs::write(&systemctl, "#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
    let start = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "maintenance", "status"])
        .env("PATH", dir.path())
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["timer"]["state"], "unavailable");
    assert!(start.elapsed() < Duration::from_secs(8));
}
