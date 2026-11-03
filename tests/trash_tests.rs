#[cfg(target_os = "linux")]
#[test]
fn selected_file_deletion_requires_preview_confirmation_and_unchanged_identity() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let trash = dir.path().join("Trash");
    let files = trash.join("files");
    let info = trash.join("info");
    fs::create_dir_all(&files).unwrap();
    fs::create_dir_all(&info).unwrap();
    for path in [&trash, &files, &info] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let item = files.join("fixture");
    let metadata = info.join("fixture.trashinfo");
    fs::write(&item, "fixture").unwrap();
    fs::write(
        &metadata,
        "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n",
    )
    .unwrap();
    for path in [&item, &metadata] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let location = trash.to_str().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .env_clear()
            .env("HOME", dir.path())
            .env("XDG_DATA_HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("TZ", "UTC")
            .output()
            .unwrap()
    };
    let preview = || {
        let output = run(&[
            "--json",
            "--non-interactive",
            "trash",
            "preview-remove",
            "--location",
            location,
            "--name",
            "fixture",
            "--older-than",
            "30d",
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["plan"]["preview_token"].as_str().unwrap().to_owned()
    };
    let token = preview();
    let remove = |token: &str, authorize: bool| {
        let mut args = vec![
            "--json",
            "--non-interactive",
            "--yes",
            "trash",
            "remove",
            "--location",
            location,
            "--name",
            "fixture",
            "--older-than",
            "30d",
            "--preview-token",
            token,
        ];
        if authorize {
            args.push("--authorize-trash-removal");
        }
        run(&args)
    };
    assert!(!remove(&token, false).status.success());
    assert!(!remove("wrong", true).status.success());
    fs::write(&item, "changed").unwrap();
    assert!(!remove(&token, true).status.success());
    assert_eq!(fs::read_to_string(&item).unwrap(), "changed");
    let token = preview();
    let dry = run(&[
        "--json",
        "--non-interactive",
        "--dry-run",
        "trash",
        "remove",
        "--location",
        location,
        "--name",
        "fixture",
        "--older-than",
        "30d",
    ]);
    assert!(dry.status.success());
    assert!(item.exists());
    let result = remove(&token, true);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["verification"], "verified_absent");
    assert!(!item.exists());
    assert!(!metadata.exists());
    let history = run(&["--json", "report"]);
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["operation"] == "trash_remove"
                && record["outcome"] == "completed"
                && record["verified_reclaimed_bytes"].is_null())
    );
}

#[cfg(target_os = "linux")]
#[test]
fn trash_removal_paths_refuse_history_inside_files_without_mutation() {
    use std::{
        fs, os::unix::fs::PermissionsExt, path::Path, process::Command, sync::atomic::AtomicBool,
        time::Duration,
    };

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let trash = data.join("Trash");
    let files = trash.join("files");
    let info = trash.join("info");
    let home = files.join("upkit");
    let history = home.join("history");
    let marker = history.join("keep");
    let item_info = info.join("upkit.trashinfo");
    fs::create_dir_all(dir.path().join("home")).unwrap();
    fs::create_dir_all(&history).unwrap();
    fs::create_dir_all(&info).unwrap();
    for path in [
        dir.path().join("home"),
        data.clone(),
        trash.clone(),
        files.clone(),
        info.clone(),
        home.clone(),
        history.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(&marker, "keep history").unwrap();
    fs::write(
        &item_info,
        "[Trash Info]\nPath=/tmp/deleted-upkit\nDeletionDate=2000-01-01T00:00:00\n",
    )
    .unwrap();
    for path in [&marker, &item_info] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(["--json", "--non-interactive", "--home"])
            .arg(&home)
            .args(args)
            .env_clear()
            .env("HOME", dir.path().join("home"))
            .env("XDG_DATA_HOME", &data)
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("TZ", "UTC")
            .output()
            .unwrap()
    };
    let age = "30d";
    let single_plan = run(&[
        "trash",
        "preview-remove",
        "--location",
        trash.to_str().unwrap(),
        "--name",
        "upkit",
        "--older-than",
        age,
    ]);
    assert!(
        single_plan.status.success(),
        "{}",
        String::from_utf8_lossy(&single_plan.stdout)
    );
    let single_token: serde_json::Value = serde_json::from_slice(&single_plan.stdout).unwrap();
    let single_token = single_token["plan"]["preview_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let single = run(&[
        "--yes",
        "trash",
        "remove",
        "--location",
        trash.to_str().unwrap(),
        "--name",
        "upkit",
        "--older-than",
        age,
        "--authorize-trash-removal",
        "--preview-token",
        &single_token,
    ]);
    let single_message = String::from_utf8_lossy(&single.stdout);
    assert!(!single.status.success());
    assert!(
        single_message.contains("operation history location"),
        "{single_message}"
    );

    let batch_plan = run(&[
        "trash",
        "preview-batch",
        "--location",
        trash.to_str().unwrap(),
        "--name",
        "upkit",
        "--older-than",
        age,
    ]);
    assert!(
        batch_plan.status.success(),
        "{}",
        String::from_utf8_lossy(&batch_plan.stdout)
    );
    let batch_token: serde_json::Value = serde_json::from_slice(&batch_plan.stdout).unwrap();
    let batch_token = batch_token["plan"]["preview_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let batch = run(&[
        "--yes",
        "trash",
        "remove-batch",
        "--location",
        trash.to_str().unwrap(),
        "--name",
        "upkit",
        "--older-than",
        age,
        "--authorize-trash-removal",
        "--preview-token",
        &batch_token,
    ]);
    let batch_message = String::from_utf8_lossy(&batch.stdout);
    assert!(!batch.status.success());
    assert!(
        batch_message.contains("operation history location"),
        "{batch_message}"
    );

    let scheduled = upkit::reports::perform_scheduled_trash_retention(
        &home,
        Path::new("/unavailable/upkit"),
        Path::new("/unavailable/config.toml"),
        &trash,
        Duration::from_secs(30 * 24 * 60 * 60),
        "fixture",
        &AtomicBool::new(false),
    );
    assert!(
        scheduled
            .result
            .unwrap_err()
            .contains("operation history location")
    );
    assert!(scheduled.history_warning.is_none());
    assert!(home.is_dir());
    assert!(trash.join("files/upkit").is_dir());
    assert_eq!(fs::read_to_string(&marker).unwrap(), "keep history");
    assert!(item_info.is_file());
    assert!(!history.join("000.json").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn batch_cli_deletes_only_explicitly_selected_files() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let trash = dir.path().join("Trash");
    fs::create_dir_all(trash.join("files")).unwrap();
    fs::create_dir_all(trash.join("info")).unwrap();
    for path in [trash.clone(), trash.join("files"), trash.join("info")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    for name in ["a", "b", "keep"] {
        let item = trash.join("files").join(name);
        let info = trash.join("info").join(format!("{name}.trashinfo"));
        fs::write(&item, name).unwrap();
        fs::write(&info, "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n").unwrap();
        for path in [&item, &info] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let location = trash.to_str().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .env_clear()
            .env("HOME", dir.path())
            .env("XDG_DATA_HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("TZ", "UTC")
            .output()
            .unwrap()
    };
    let preview = run(&[
        "--json",
        "--non-interactive",
        "trash",
        "preview-batch",
        "--location",
        location,
        "--name",
        "a",
        "--name",
        "b",
        "--older-than",
        "30d",
    ]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(plan["plan"]["items"].as_array().unwrap().len(), 2);
    let token = plan["plan"]["preview_token"].as_str().unwrap();
    let missing_authorization = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "trash",
        "remove-batch",
        "--location",
        location,
        "--name",
        "a",
        "--name",
        "b",
        "--older-than",
        "30d",
        "--preview-token",
        token,
    ]);
    assert!(!missing_authorization.status.success());
    let changed_selection = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "trash",
        "remove-batch",
        "--location",
        location,
        "--name",
        "a",
        "--older-than",
        "30d",
        "--preview-token",
        token,
        "--authorize-trash-removal",
    ]);
    assert!(!changed_selection.status.success());
    assert!(trash.join("files/a").exists() && trash.join("files/b").exists());
    let output = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "trash",
        "remove-batch",
        "--location",
        location,
        "--name",
        "a",
        "--name",
        "b",
        "--older-than",
        "30d",
        "--preview-token",
        token,
        "--authorize-trash-removal",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["result"]["outcome"], "completed");
    assert_eq!(result["result"]["items"].as_array().unwrap().len(), 2);
    for name in ["a", "b"] {
        assert!(!trash.join("files").join(name).exists());
        assert!(
            !trash
                .join("info")
                .join(format!("{name}.trashinfo"))
                .exists()
        );
    }
    assert_eq!(
        fs::read_to_string(trash.join("files/keep")).unwrap(),
        "keep"
    );
    let history = run(&["--json", "report"]);
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["operation"] == "trash_batch_remove"
                && record["outcome"] == "completed")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn retention_cli_previews_age_scope_and_rejects_changed_selection() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let trash = dir.path().join("Trash");
    fs::create_dir_all(trash.join("files/folder")).unwrap();
    fs::create_dir_all(trash.join("info")).unwrap();
    for path in [trash.clone(), trash.join("files"), trash.join("info")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let create = |name: &str, date: Option<&str>| {
        let item = trash.join("files").join(name);
        if name != "folder" {
            fs::write(&item, name).unwrap();
            fs::set_permissions(&item, fs::Permissions::from_mode(0o600)).unwrap();
        }
        if let Some(date) = date {
            let info = trash.join("info").join(format!("{name}.trashinfo"));
            fs::write(&info, format!("[Trash Info]\nDeletionDate={date}\n")).unwrap();
            fs::set_permissions(info, fs::Permissions::from_mode(0o600)).unwrap();
        }
    };
    for name in ["a", "b", "hard", "folder"] {
        create(name, Some("2000-01-01T00:00:00"));
    }
    create("future", Some("2999-01-01T00:00:00"));
    create("unknown", None);
    fs::hard_link(trash.join("files/hard"), dir.path().join("outside-link")).unwrap();
    // Retention must refuse this directory regardless of the host umask.
    // A writable-by-group item cannot be safely cleared by Upkit.
    fs::set_permissions(
        trash.join("files/folder"),
        fs::Permissions::from_mode(0o770),
    )
    .unwrap();
    let location = trash.to_str().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .env_clear()
            .env("HOME", dir.path())
            .env("XDG_DATA_HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("TZ", "UTC")
            .output()
            .unwrap()
    };
    let preview = || {
        let output = run(&[
            "--json",
            "--non-interactive",
            "trash",
            "preview-retention",
            "--location",
            location,
            "--older-than",
            "30d",
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let value = preview();
    assert_eq!(value["preview"]["selection"]["eligible"], 2);
    assert_eq!(value["preview"]["selection"]["newer_or_unknown"], 2);
    assert_eq!(value["preview"]["selection"]["unsupported"], 2);
    let token = value["preview"]["plan"]["preview_token"].as_str().unwrap();
    let retain = |token: &str, authorized: bool| {
        let mut args = vec![
            "--json",
            "--non-interactive",
            "--yes",
            "trash",
            "retain",
            "--location",
            location,
            "--older-than",
            "30d",
            "--preview-token",
            token,
        ];
        if authorized {
            args.push("--authorize-trash-removal");
        }
        run(&args)
    };
    assert!(!retain(token, false).status.success());
    create("newcomer", Some("2000-01-01T00:00:00"));
    assert!(!retain(token, true).status.success());
    assert!(trash.join("files/a").exists());
    let updated = preview();
    assert_eq!(updated["preview"]["selection"]["eligible"], 3);
    let result = retain(
        updated["preview"]["plan"]["preview_token"]
            .as_str()
            .unwrap(),
        true,
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["result"]["outcome"], "completed");
    for name in ["a", "b", "newcomer"] {
        assert!(!trash.join("files").join(name).exists());
    }
    for name in ["hard", "folder", "future", "unknown"] {
        assert!(trash.join("files").join(name).exists());
    }
    assert!(dir.path().join("outside-link").exists());
    let empty_selection = preview();
    assert_eq!(empty_selection["preview"]["selection"]["eligible"], 0);
    assert!(empty_selection["preview"]["plan"].is_null());
}
#[cfg(target_os = "linux")]
#[test]
fn empty_cli_requires_complete_review_and_handles_unknown_dates() {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
    };
    let dir = tempfile::tempdir().unwrap();
    let trash = dir.path().join("Trash");
    fs::create_dir_all(trash.join("files")).unwrap();
    fs::create_dir_all(trash.join("info")).unwrap();
    for path in [&trash, &trash.join("files"), &trash.join("info")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let add = |name: &str, date: &str| {
        let file = trash.join("files").join(name);
        let info = trash.join("info").join(format!("{name}.trashinfo"));
        fs::write(&file, name).unwrap();
        fs::write(&info, format!("[Trash Info]\nDeletionDate={date}\n")).unwrap();
        for path in [&file, &info] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    };
    add("future", "2999-01-01T00:00:00");
    add("unknown", "not-a-date");
    fs::write(trash.join("info/orphan.trashinfo"), "preserve").unwrap();
    let outside = dir.path().join("outside");
    fs::write(&outside, "keep").unwrap();
    let location = trash.to_str().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .env_clear()
            .env("HOME", dir.path())
            .env("XDG_DATA_HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("TZ", "UTC")
            .output()
            .unwrap()
    };
    let preview = || {
        let output = run(&[
            "--json",
            "--non-interactive",
            "trash",
            "preview-empty",
            "--location",
            location,
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let result = preview();
    let items = result["plan"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(
        items
            .iter()
            .any(|item| item["name"] == "unknown" && item["deletion_date"].is_null())
    );
    let token = result["plan"]["preview_token"].as_str().unwrap().to_owned();
    let execute = |token: &str, authorize: bool| {
        let mut args = vec![
            "--json",
            "--non-interactive",
            "--yes",
            "trash",
            "empty",
            "--location",
            location,
            "--preview-token",
            token,
        ];
        if authorize {
            args.push("--authorize-trash-removal");
        }
        run(&args)
    };
    assert!(!execute(&token, false).status.success());
    assert!(!execute("wrong", true).status.success());
    let dry = run(&[
        "--json",
        "--non-interactive",
        "--dry-run",
        "trash",
        "empty",
        "--location",
        location,
    ]);
    assert!(dry.status.success());
    add("new", "2026-01-01T00:00:00");
    assert!(!execute(&token, true).status.success());
    assert!(trash.join("files/future").exists());
    let directory = trash.join("files/directory");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
    fs::write(
        trash.join("info/directory.trashinfo"),
        "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n",
    )
    .unwrap();
    assert!(
        !run(&[
            "--json",
            "--non-interactive",
            "trash",
            "preview-empty",
            "--location",
            location
        ])
        .status
        .success()
    );
    fs::remove_dir(&directory).unwrap();
    fs::remove_file(trash.join("info/directory.trashinfo")).unwrap();
    symlink(&outside, trash.join("files/link")).unwrap();
    assert!(
        !run(&[
            "--json",
            "--non-interactive",
            "trash",
            "preview-empty",
            "--location",
            location
        ])
        .status
        .success()
    );
    fs::remove_file(trash.join("files/link")).unwrap();
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(directory.join("nested"), "nested data").unwrap();
    fs::set_permissions(directory.join("nested"), fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&outside, directory.join("link")).unwrap();
    let directory_info = trash.join("info/directory.trashinfo");
    fs::write(
        &directory_info,
        "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n",
    )
    .unwrap();
    fs::set_permissions(&directory_info, fs::Permissions::from_mode(0o600)).unwrap();
    let plan = preview();
    let nested = plan["plan"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "directory")
        .unwrap();
    assert_eq!(nested["kind"], "directory");
    assert_eq!(nested["descendant_count"], 2);
    let text_preview = run(&[
        "--non-interactive",
        "trash",
        "preview-remove",
        "--location",
        location,
        "--name",
        "directory",
        "--older-than",
        "30d",
    ]);
    assert!(text_preview.status.success());
    let text = String::from_utf8_lossy(&text_preview.stdout);
    assert!(
        text.contains("kind: directory")
            && text.contains("descendants: 2")
            && text.contains("entire directory")
    );
    let stale = plan["plan"]["preview_token"].as_str().unwrap().to_owned();
    fs::write(directory.join("nested"), "changed nested data").unwrap();
    assert!(!execute(&stale, true).status.success());
    assert!(directory.join("nested").exists());
    let plan = preview();
    let token = plan["plan"]["preview_token"].as_str().unwrap();
    let output = execute(token, true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["result"]["outcome"], "completed");
    assert_eq!(result["result"]["selected_location_files_empty"], true);
    assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 0);
    assert!(!directory_info.exists());
    assert_eq!(
        fs::read_to_string(trash.join("info/orphan.trashinfo")).unwrap(),
        "preserve"
    );
    assert_eq!(fs::read_to_string(outside).unwrap(), "keep");
    for index in 0..101 {
        fs::write(trash.join("files").join(format!("item-{index}")), "keep").unwrap();
    }
    let oversized = run(&[
        "--json",
        "--non-interactive",
        "trash",
        "preview-empty",
        "--location",
        location,
    ]);
    assert!(!oversized.status.success());
    let error: serde_json::Value = serde_json::from_slice(&oversized.stdout).unwrap();
    assert!(error["error"].as_str().unwrap().contains("more than 100"));
    assert_eq!(fs::read_dir(trash.join("files")).unwrap().count(), 101);
}

#[cfg(target_os = "linux")]
#[test]
fn empty_reports_new_items_arriving_during_removal() {
    use std::{
        fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command, sync::atomic::AtomicBool,
    };
    if let Some(root) = std::env::var_os("UPKIT_EMPTY_FIXTURE") {
        let root = PathBuf::from(root);
        let trash = root.join("Trash");
        let cancel = AtomicBool::new(false);
        let plan = upkit::trash::empty_preview(&trash, &cancel)
            .unwrap()
            .unwrap();
        let result = upkit::trash::remove_batch_with_progress(
            &plan,
            &plan.preview_token,
            &cancel,
            |index, _| {
                if index == 1 {
                    let item = trash.join("files/new");
                    let info = trash.join("info/new.trashinfo");
                    fs::write(&item, "new").unwrap();
                    fs::write(&info, "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n").unwrap();
                    for path in [&item, &info] {
                        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
                    }
                }
            },
        )
        .unwrap();
        assert_eq!(result.outcome, "partial");
        assert_eq!(result.selected_location_files_empty, Some(false));
        assert_eq!(fs::read_to_string(trash.join("files/new")).unwrap(), "new");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let trash = dir.path().join("Trash");
    fs::create_dir_all(trash.join("files")).unwrap();
    fs::create_dir_all(trash.join("info")).unwrap();
    for path in [&trash, &trash.join("files"), &trash.join("info")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    for name in ["a", "b"] {
        let item = trash.join("files").join(name);
        let info = trash.join("info").join(format!("{name}.trashinfo"));
        fs::write(&item, name).unwrap();
        fs::write(&info, "[Trash Info]\nDeletionDate=2000-01-01T00:00:00\n").unwrap();
        for path in [&item, &info] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let result = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "empty_reports_new_items_arriving_during_removal",
            "--nocapture",
        ])
        .env("UPKIT_EMPTY_FIXTURE", dir.path())
        .env("HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path())
        .env("TZ", "UTC")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(trash.join("files/new").exists());
}
