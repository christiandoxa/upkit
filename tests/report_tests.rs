use std::process::Command;
#[cfg(target_os = "linux")]
use std::{fs, path::Path, time::SystemTime};

#[cfg(target_os = "linux")]
fn fixture_record(id: usize, finished_unix: Option<u64>) -> String {
    serde_json::json!({
        "id": id,
        "started_unix": 1,
        "finished_unix": finished_unix,
        "duration_ms": 1,
        "operation": "fixture_operation",
        "target": "fixture_target",
        "outcome": "completed",
        "detail": null,
        "estimated_bytes": null,
        "verified_reclaimed_bytes": null,
        "platform": "fixture"
    })
    .to_string()
}

#[cfg(target_os = "linux")]
fn write_fixture(home: &Path, id: usize, finished_unix: Option<u64>) {
    let history = home.join("history");
    fs::create_dir_all(&history).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = history.join(format!("{id:03}.json"));
    fs::write(&path, fixture_record(id, finished_unix)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[cfg(target_os = "linux")]
fn run_upkit(home: &Path, args: &[String]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "--non-interactive", "--home"])
        .arg(home)
        .args(args)
        .env("HOME", home.parent().unwrap())
        .env("XDG_CONFIG_HOME", home.parent().unwrap())
        .output()
        .unwrap()
}

#[cfg(target_os = "linux")]
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

#[test]
fn empty_reports_are_read_only_in_json_and_dry_run() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("not-created");
    for command in [vec!["report"], vec!["sweep", "report"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(["--json", "--dry-run", "--home"])
            .arg(&home)
            .args(command)
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["records"].as_array().unwrap().len(), 0);
        assert_eq!(report["capacity"], 100);
        assert!(report["known_reclaimed_bytes"].is_null());
        assert_eq!(report["records_without_verified_reclaimed_bytes"], 0);
        assert!(!home.exists());
    }
}

#[cfg(any(target_os = "macos", windows))]
#[test]
fn report_rejects_hard_linked_record() {
    use std::fs;

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("data");
    let history = home.join("history");
    fs::create_dir_all(&history).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let record = |id, target| {
        serde_json::json!({
            "id": id, "started_unix": 1, "finished_unix": 2, "duration_ms": 1,
            "operation": "fixture", "target": target, "outcome": "completed",
            "detail": null, "estimated_bytes": null, "verified_reclaimed_bytes": null,
            "platform": "fixture"
        })
        .to_string()
    };
    let source = dir.path().join("source.json");
    let linked = history.join("000.json");
    let normal = history.join("001.json");
    fs::write(&source, record(0, "private-fixture-marker")).unwrap();
    fs::write(&normal, record(1, "ordinary-fixture")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&source, &normal] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    fs::hard_link(&source, &linked).unwrap();
    let before = fs::read(&source).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "--non-interactive", "--offline", "--home"])
        .arg(&home)
        .arg("report")
        .env("HOME", dir.path())
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-fixture-marker"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["records"].as_array().unwrap().len(), 1);
    assert_eq!(report["records"][0]["target"], "ordinary-fixture");
    assert_eq!(report["warnings"].as_array().unwrap().len(), 1);
    assert_eq!(fs::read(&source).unwrap(), before);
    assert!(linked.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn report_and_purge_preview_escape_bidi_controls_in_history_text() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("upkit-data");
    write_fixture(&home, 0, Some(2));
    let record_path = home.join("history/000.json");
    let mut record: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&record_path).unwrap()).unwrap();
    record["target"] = serde_json::Value::String("fixture_\u{202e}target".into());
    fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();

    let report = run_upkit(&home, &strings(&["report"]));
    assert!(report.status.success());
    let report: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();
    let expected = "fixture_\\u{202e}target";
    assert_eq!(report["records"][0]["target"], expected);
    assert!(
        !report["records"][0]["target"]
            .as_str()
            .unwrap()
            .contains('\u{202e}')
    );

    let preview = run_upkit(
        &home,
        &strings(&["report", "purge", "--older-than", "30d", "--preview"]),
    );
    assert!(preview.status.success());
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(preview["plan"]["candidates"][0]["target"], expected);

    let token = preview["plan"]["preview_token"].as_str().unwrap();
    let token_check = run_upkit(
        &home,
        &[
            "--dry-run".into(),
            "report".into(),
            "purge".into(),
            "--older-than".into(),
            "30d".into(),
            "--run".into(),
            "--preview-token".into(),
            token.into(),
        ],
    );
    assert!(token_check.status.success());
    let token_check: serde_json::Value = serde_json::from_slice(&token_check.stdout).unwrap();
    assert_eq!(token_check["executed"], false);
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(record_path).unwrap()).unwrap();
    assert_eq!(stored["target"], "fixture_\u{202e}target");
}

#[cfg(target_os = "linux")]
#[test]
fn report_does_not_read_private_history_through_a_hard_link() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("upkit-data");
    write_fixture(&home, 0, Some(2));
    let record_path = home.join("history/000.json");
    fs::remove_file(&record_path).unwrap();

    let source = dir.path().join("private-fixture.json");
    let mut fixture: serde_json::Value = serde_json::from_str(&fixture_record(0, Some(2))).unwrap();
    fixture["target"] = serde_json::Value::String("fixture_private_marker".into());
    fs::write(&source, fixture.to_string()).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&source, &record_path).unwrap();
    assert_eq!(fs::metadata(&record_path).unwrap().nlink(), 2);

    let output = run_upkit(&home, &strings(&["report"]));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["records"].as_array().unwrap().is_empty());
    assert_eq!(report["warnings"].as_array().unwrap().len(), 1);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("fixture_private_marker"));
    assert!(source.exists());
    assert!(record_path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn report_reads_history_through_a_symlinked_home_ancestor() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let real_home = dir.path().join("real-home");
    let home_alias = dir.path().join("home-alias");
    write_fixture(&real_home, 0, Some(2));
    symlink(&real_home, &home_alias).unwrap();

    let output = run_upkit(&home_alias, &strings(&["report"]));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["records"].as_array().unwrap().len(), 1);
    assert_eq!(report["records"][0]["operation"], "fixture_operation");
}

#[cfg(target_os = "linux")]
#[test]
fn report_reads_private_read_only_history_files() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("upkit-data");
    write_fixture(&home, 0, Some(2));
    fs::set_permissions(home.join("history"), fs::Permissions::from_mode(0o500)).unwrap();
    fs::set_permissions(
        home.join("history/000.json"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();

    let output = run_upkit(&home, &strings(&["report"]));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["records"].as_array().unwrap().len(), 1);
    assert!(report["warnings"].as_array().unwrap().is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn report_keeps_history_with_finish_before_start_and_warns_about_time_order() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("upkit-data");
    write_fixture(&home, 0, Some(2));
    let record_path = home.join("history/000.json");
    let mut record: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&record_path).unwrap()).unwrap();
    record["started_unix"] = serde_json::Value::from(3);
    fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();

    let output = run_upkit(&home, &strings(&["report"]));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["records"].as_array().unwrap().len(), 1);
    assert_eq!(report["records"][0]["started_unix"], 3);
    assert_eq!(report["records"][0]["finished_unix"], 2);
    assert_eq!(report["warnings"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["warnings"][0],
        "record 000 has a finish timestamp earlier than its start timestamp; the system clock may have changed"
    );

    let purge_preview = run_upkit(
        &home,
        &strings(&["report", "purge", "--older-than", "30d", "--preview"]),
    );
    assert!(!purge_preview.status.success());
    assert!(record_path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn purge_preview_dry_run_authorization_and_token_revalidation_use_fixtures() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("upkit-data");
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    write_fixture(&home, 0, Some(2));
    write_fixture(&home, 1, Some(now));
    write_fixture(&home, 2, None);

    let without_non_interactive = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "--home"])
        .arg(&home)
        .args(["report", "purge", "--older-than", "30d", "--preview"])
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .output()
        .unwrap();
    assert!(!without_non_interactive.status.success());
    assert!(home.join("history/000.json").exists());

    let preview = run_upkit(
        &home,
        &strings(&["report", "purge", "--older-than", "30d", "--preview"]),
    );
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(preview["plan"]["candidates"].as_array().unwrap().len(), 1);
    assert_eq!(preview["plan"]["candidates"][0]["id"], 0);
    assert_eq!(preview["plan"]["candidates"][0]["finished_unix"], 2);
    assert_eq!(preview["plan"]["skipped_unfinished_records"], 1);
    assert!(
        !preview["plan"]["preview_token"]
            .as_str()
            .unwrap()
            .is_empty()
    );
    let mut token = preview["plan"]["preview_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(home.join("history/000.json").exists());

    let dry_run = run_upkit(
        &home,
        &[
            "--dry-run".into(),
            "report".into(),
            "purge".into(),
            "--older-than".into(),
            "30d".into(),
            "--run".into(),
            "--preview-token".into(),
            token.clone(),
        ],
    );
    assert!(
        dry_run.status.success(),
        "{}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let dry_run: serde_json::Value = serde_json::from_slice(&dry_run.stdout).unwrap();
    assert_eq!(dry_run["executed"], false);
    assert!(dry_run["result"].is_null());
    assert!(home.join("history/000.json").exists());
    let still_original: serde_json::Value =
        serde_json::from_slice(&fs::read(home.join("history/000.json")).unwrap()).unwrap();
    assert_eq!(still_original["operation"], "fixture_operation");

    let unauthorized = run_upkit(
        &home,
        &[
            "report".into(),
            "purge".into(),
            "--older-than".into(),
            "30d".into(),
            "--run".into(),
            "--preview-token".into(),
            token.clone(),
        ],
    );
    assert!(!unauthorized.status.success());
    assert!(home.join("history/000.json").exists());

    let stale = run_upkit(
        &home,
        &[
            "--yes".into(),
            "report".into(),
            "purge".into(),
            "--authorize-history-purge".into(),
            "--older-than".into(),
            "31d".into(),
            "--run".into(),
            "--preview-token".into(),
            token.clone(),
        ],
    );
    assert!(!stale.status.success());
    assert!(home.join("history/000.json").exists());

    let recent_path = home.join("history/001.json");
    let mut changed_record: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&recent_path).unwrap()).unwrap();
    changed_record["target"] = serde_json::Value::String("changed_fixture_target".into());
    fs::write(&recent_path, changed_record.to_string()).unwrap();
    let stale_record = run_upkit(
        &home,
        &[
            "--yes".into(),
            "report".into(),
            "purge".into(),
            "--authorize-history-purge".into(),
            "--older-than".into(),
            "30d".into(),
            "--run".into(),
            "--preview-token".into(),
            token.clone(),
        ],
    );
    assert!(!stale_record.status.success());
    assert!(home.join("history/000.json").exists());
    let fresh_preview = run_upkit(
        &home,
        &strings(&["report", "purge", "--older-than", "30d", "--preview"]),
    );
    assert!(fresh_preview.status.success());
    let fresh_preview: serde_json::Value = serde_json::from_slice(&fresh_preview.stdout).unwrap();
    token = fresh_preview["plan"]["preview_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let removed = run_upkit(
        &home,
        &[
            "--yes".into(),
            "report".into(),
            "purge".into(),
            "--authorize-history-purge".into(),
            "--older-than".into(),
            "30d".into(),
            "--run".into(),
            "--preview-token".into(),
            token,
        ],
    );
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
    let removed: serde_json::Value = serde_json::from_slice(&removed.stdout).unwrap();
    assert_eq!(removed["result"]["outcome"], "completed");
    assert_eq!(removed["result"]["items"][0]["status"], "removed");
    assert!(removed["history_warning"].is_null());
    let purge_record: serde_json::Value =
        serde_json::from_slice(&fs::read(home.join("history/000.json")).unwrap()).unwrap();
    assert_eq!(purge_record["operation"], "history_purge");
    assert_eq!(purge_record["outcome"], "completed");
    assert!(
        purge_record["target"]
            .as_str()
            .unwrap()
            .starts_with("history records older than ")
    );
    assert!(
        !purge_record["target"]
            .as_str()
            .unwrap()
            .contains("fixture_target")
    );
    assert!(home.join("history/001.json").exists());
    assert!(home.join("history/002.json").exists());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn purge_reports_unsupported_without_creating_history() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("not-created");
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "--non-interactive", "--home"])
        .arg(&home)
        .args(["report", "purge", "--older-than", "30d", "--preview"])
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("supported on Linux only"));
    assert!(!home.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn purge_preview_fails_closed_on_linked_record_fixture() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("upkit-data");
    write_fixture(&home, 0, Some(2));
    let outside = dir.path().join("keep.json");
    fs::write(&outside, fixture_record(0, Some(2))).unwrap();
    fs::remove_file(home.join("history/000.json")).unwrap();
    symlink(&outside, home.join("history/000.json")).unwrap();

    let output = run_upkit(
        &home,
        &strings(&["report", "purge", "--older-than", "30d", "--preview"]),
    );

    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(outside).unwrap(),
        fixture_record(0, Some(2))
    );
    assert!(
        fs::symlink_metadata(home.join("history/000.json"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}
