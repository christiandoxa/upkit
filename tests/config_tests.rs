use std::fs;
use tempfile::tempdir;
use upkit::config::{Settings, create, load, scan_options};

#[cfg(unix)]
#[test]
fn config_loading_rejects_a_fifo_without_waiting_for_a_writer() {
    use std::{
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    let dir = tempdir().unwrap();
    let fifo = dir.path().join("config.fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--non-interactive", "--json", "--config"])
        .arg(&fifo)
        .args(["config", "show"])
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("configuration FIFO blocked the command");
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert!(!status.success());
    let output = child.wait_with_output().unwrap();
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        diagnostic.contains("configuration must be a regular file"),
        "{diagnostic}"
    );
    let error = load(&fifo, true).unwrap_err();
    assert!(format!("{error:#}").contains("configuration must be a regular file"));
    assert!(fifo.exists());
}

#[cfg(unix)]
#[test]
fn config_loading_preserves_null_device_and_regular_file_symlinks() {
    use std::os::unix::fs::symlink;

    assert!(load(std::path::Path::new("/dev/null"), true).is_ok());
    let dir = tempdir().unwrap();
    let file = dir.path().join("settings.toml");
    let link = dir.path().join("linked.toml");
    fs::write(&file, "version = 1\n").unwrap();
    symlink(&file, &link).unwrap();
    assert_eq!(load(&link, true).unwrap().version, 1);
}

#[test]
fn scheduled_trash_retention_is_separate_and_default_off() {
    let defaults = Settings::default();
    assert!(!upkit::config::scheduled_trash_retention(&defaults).unwrap());
    assert!(
        !toml::to_string(&defaults)
            .unwrap()
            .contains("scheduled_trash_retention")
    );

    let enabled: Settings = toml::from_str(
        "version = 1\nscheduled_bytecode_cleanup = true\nscheduled_trash_retention = true\n",
    )
    .unwrap();
    assert!(upkit::config::scheduled_trash_retention(&enabled).unwrap());
    let bytecode_only: Settings =
        toml::from_str("version = 1\nscheduled_bytecode_cleanup = true\n").unwrap();
    assert!(!upkit::config::scheduled_trash_retention(&bytecode_only).unwrap());
}

#[test]
fn scheduled_artifact_cleanup_is_off_by_default_and_profiles_must_opt_in() {
    let defaults = Settings::default();
    assert!(!upkit::config::scheduled_artifact_cleanup(&defaults, None).unwrap());
    assert!(
        !toml::to_string(&defaults)
            .unwrap()
            .contains("scheduled_artifact_cleanup")
    );

    let enabled: Settings = toml::from_str(
        "version = 1\nscheduled_artifact_cleanup = true\n[profiles.work]\nscheduled_artifact_cleanup = true\n",
    )
    .unwrap();
    assert!(upkit::config::scheduled_artifact_cleanup(&enabled, None).unwrap());
    assert!(upkit::config::scheduled_artifact_cleanup(&enabled, Some("work")).unwrap());

    let profile_default = enabled.profiles.get("work").unwrap().clone();
    let mut settings = enabled;
    settings
        .profiles
        .get_mut("work")
        .unwrap()
        .scheduled_artifact_cleanup = false;
    assert!(!upkit::config::scheduled_artifact_cleanup(&settings, Some("work")).unwrap());
    assert!(profile_default.scheduled_artifact_cleanup);
}

#[test]
fn config_loading_accepts_above_editor_limit_and_rejects_over_one_mib_without_modifying_it() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let large_root = dir.path().join("a".repeat(256 * 1024));
    let settings = Settings {
        workspace_roots: vec![large_root.clone()],
        ..Default::default()
    };
    create(&path, &settings, false).unwrap();
    let size = fs::metadata(&path).unwrap().len();
    assert!(size > 128 * 1024 && size < 1024 * 1024);
    assert_eq!(load(&path, true).unwrap().workspace_roots, vec![large_root]);

    let mut at_limit = b"version = 1\n".to_vec();
    at_limit.resize(1024 * 1024, b' ');
    fs::write(&path, at_limit).unwrap();
    assert_eq!(load(&path, true).unwrap().version, 1);

    let contents = vec![b' '; 1024 * 1024 + 1];
    fs::write(&path, &contents).unwrap();

    let error = load(&path, true).unwrap_err();

    assert!(error.to_string().contains("1 MiB load limit"));
    assert_eq!(fs::read(path).unwrap(), contents);
}

#[test]
fn create_rejects_configuration_that_would_exceed_the_load_limit() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nested/config.toml");
    let oversized_root = dir.path().join("a".repeat(1024 * 1024));
    let settings = Settings {
        workspace_roots: vec![oversized_root],
        ..Default::default()
    };

    let error = create(&path, &settings, false).unwrap_err();

    assert!(error.to_string().contains("1 MiB load limit"));
    assert!(!path.exists());
    assert!(!path.parent().unwrap().exists());
}

#[test]
fn editor_creates_valid_config_without_overwriting_a_new_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("settings/config.toml");
    let snapshot = upkit::config::read_document(&path).unwrap();
    assert!(upkit::config::save_document(&snapshot, "version = 2\n").is_err());
    assert!(!path.exists());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(&path, "version = 1\n# another writer\n").unwrap();
    assert!(upkit::config::save_document(&snapshot, "version = 1\n").is_err());
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "version = 1\n# another writer\n"
    );
    fs::remove_file(&path).unwrap();
    let (saved, backup) =
        upkit::config::save_document(&snapshot, "version = 1\n# saved\n").unwrap();
    assert!(backup.is_none());
    assert_eq!(saved.text, "version = 1\n# saved\n");
    assert_eq!(fs::read_to_string(path).unwrap(), saved.text);
}

#[cfg(target_os = "linux")]
#[test]
fn editor_preserves_a_backup_and_rejects_stale_changes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("config.toml");
    let original = "version = 1\n# original comment\n";
    fs::write(&path, original).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let snapshot = upkit::config::read_document(&path).unwrap();
    let (saved, backup) =
        upkit::config::save_document(&snapshot, "version = 1\n# updated\n").unwrap();
    let backup = backup.unwrap();
    assert_eq!(fs::read_to_string(&backup).unwrap(), original);
    assert_eq!(
        fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), saved.text);
    fs::write(&path, "version = 1\n# external change\n").unwrap();
    assert!(upkit::config::save_document(&saved, "version = 1\n# stale\n").is_err());
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "version = 1\n# external change\n"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn editor_does_not_replace_configuration_with_extended_attributes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, "version = 1\n").unwrap();
    match rustix::fs::setxattr(
        &path,
        "user.upkit-test",
        b"keep",
        rustix::fs::XattrFlags::empty(),
    ) {
        Ok(()) => {}
        Err(rustix::io::Errno::NOTSUP) => return,
        Err(error) => panic!("cannot set fixture attribute: {error}"),
    }
    let snapshot = upkit::config::read_document(&path).unwrap();
    assert!(upkit::config::save_document(&snapshot, "version = 1\n# changed\n").is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), "version = 1\n");
}

#[cfg(target_os = "linux")]
#[test]
fn editor_rejects_a_group_writable_configuration_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o770)).unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, "version = 1\n").unwrap();
    let snapshot = upkit::config::read_document(&path).unwrap();
    assert!(upkit::config::save_document(&snapshot, "version = 1\n# changed\n").is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "version = 1\n");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn editor_rejects_linked_or_hard_linked_configuration() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let original = dir.path().join("original.toml");
    let linked = dir.path().join("linked.toml");
    fs::write(&original, "version = 1\n").unwrap();
    symlink(&original, &linked).unwrap();
    assert!(upkit::config::read_document(&linked).is_err());
    fs::remove_file(&linked).unwrap();
    fs::hard_link(&original, &linked).unwrap();
    assert!(upkit::config::read_document(&original).is_err());
    assert_eq!(fs::read_to_string(&linked).unwrap(), "version = 1\n");
}

#[test]
fn theme_defaults_to_dark_and_rejects_unknown_values() {
    let default: Settings = toml::from_str("version = 1\n").unwrap();
    assert_eq!(default.theme, upkit::config::Theme::Dark);
    let light: Settings = toml::from_str("version = 1\ntheme = 'light'\n").unwrap();
    assert_eq!(light.theme, upkit::config::Theme::Light);
    assert!(toml::from_str::<Settings>("version = 1\ntheme = 'unknown'\n").is_err());
}

#[test]
fn schedule_frequency_uses_profile_then_global_then_weekly_default() {
    use upkit::config::{Profile, ScheduleFrequency, schedule_frequency};

    let default = Settings::default();
    assert_eq!(
        schedule_frequency(&default, None).unwrap(),
        ScheduleFrequency::Weekly
    );

    let mut settings = Settings {
        schedule_frequency: Some(ScheduleFrequency::Daily),
        ..Settings::default()
    };
    settings.profiles.insert(
        "work".into(),
        Profile {
            schedule_frequency: Some(ScheduleFrequency::Weekly),
            ..Profile::default()
        },
    );
    settings
        .profiles
        .insert("inherit".into(), Profile::default());

    assert_eq!(
        schedule_frequency(&settings, None).unwrap(),
        ScheduleFrequency::Daily
    );
    assert_eq!(
        schedule_frequency(&settings, Some("work")).unwrap(),
        ScheduleFrequency::Weekly
    );
    assert_eq!(
        schedule_frequency(&settings, Some("inherit")).unwrap(),
        ScheduleFrequency::Daily
    );
    assert!(schedule_frequency(&settings, Some("missing")).is_err());
    assert!(toml::from_str::<Settings>("version = 1\nschedule_frequency = 'monthly'\n").is_err());
}

#[test]
fn config_init_accepts_a_global_schedule_frequency() {
    use upkit::config::ScheduleFrequency;

    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "--non-interactive", "--config"])
        .arg(&path)
        .args(["config", "init", "--schedule-frequency", "daily"])
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let loaded = load(&path, true).unwrap();
    assert_eq!(loaded.schedule_frequency, Some(ScheduleFrequency::Daily));
}

#[test]
fn config_round_trip_and_no_overwrite() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config/settings.toml");
    let settings = Settings {
        workspace_roots: vec![dir.path().join("workspace")],
        exclusions: vec!["vendor".into()],
        artifact_retention: Some("30d".into()),
        ..Settings::default()
    };
    create(&path, &settings, true).unwrap();
    assert!(!path.exists());
    assert!(!path.parent().unwrap().exists());
    create(&path, &settings, false).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
    let before = fs::read(&path).unwrap();
    let loaded = load(&path, true).unwrap();
    assert_eq!(loaded.workspace_roots, settings.workspace_roots);
    assert_eq!(loaded.exclusions, settings.exclusions);
    assert_eq!(loaded.artifact_retention, settings.artifact_retention);
    assert!(create(&path, &settings, false).is_err());
    assert!(create(&path, &settings, true).is_err());
    assert_eq!(before, fs::read(&path).unwrap());
}

#[test]
fn validates_versions_roots_exclusions_and_retention() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("settings.toml");
    for input in [
        "version = 2",
        "version = 1\nworkspace_roots = ['relative']",
        "version = 1\nexclusions = ['../outside']",
        "version = 1\nexclusions = ['glob:[']",
        "version = 1\nexclusions = ['glob:../outside']",
        "version = 1\nartifact_retention = 'bad'",
        "version = 1\nautomatic_cleanup = true",
    ] {
        fs::write(&path, input).unwrap();
        assert!(load(&path, true).is_err(), "{input}");
    }
    fs::remove_file(&path).unwrap();
    assert!(load(&path, true).is_err());
    assert!(load(&path, false).unwrap().workspace_roots.is_empty());
    assert!(scan_options(&Settings::default(), &[], &[], None).is_err());
}

#[test]
fn cli_uses_configured_roots_exclusions_and_retention() {
    let dir = tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let path = dir.path().join("config.toml");
    fs::create_dir_all(workspace.join("app/target")).unwrap();
    fs::write(workspace.join("app/Cargo.toml"), "[workspace]").unwrap();
    fs::write(workspace.join("app/target/keep"), "fixture").unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
            .arg("--json")
            .arg("--config")
            .arg(&path)
            .args(args)
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("isolated-config"))
            .output()
            .unwrap()
    };
    let init = run(&[
        "config",
        "init",
        "--retention",
        "100000d",
        workspace.to_str().unwrap(),
    ]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let output = run(&["sweep", "scan"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["candidates"].as_array().unwrap().is_empty());
    let output = run(&["sweep", "scan", "--older-than", "0h"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["candidates"].as_array().unwrap().len(), 1);
    let output = run(&["sweep", "scan", "--older-than", "0h", "--exclude", "app"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["candidates"].as_array().unwrap().is_empty());
    assert_eq!(
        fs::read_to_string(workspace.join("app/target/keep")).unwrap(),
        "fixture"
    );
    assert!(!dir.path().join(".bashrc").exists());
}

#[test]
fn explicit_scan_roots_override_configured_roots() {
    let dir = tempdir().unwrap();
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    for root in [&first, &second] {
        fs::create_dir_all(root.join("target")).unwrap();
        fs::write(root.join("Cargo.toml"), "[workspace]").unwrap();
    }
    let config = dir.path().join("config.toml");
    create(
        &config,
        &Settings {
            workspace_roots: vec![first],
            ..Settings::default()
        },
        false,
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "--config"])
        .arg(config)
        .args(["sweep", "scan"])
        .arg(&second)
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["roots"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["roots"][0],
        second.canonicalize().unwrap().to_str().unwrap()
    );
}

#[test]
fn absent_roots_never_trigger_a_default_scan() {
    let dir = tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "sweep", "scan"])
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("APPDATA", dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(response.to_string().contains("workspace roots"));
    assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
}

#[test]
fn workspace_profiles_scope_roots_and_combine_safety_exclusions() {
    use std::time::Duration;
    use upkit::config::{Profile, profile_scan_options};
    let dir = tempdir().unwrap();
    let mut settings = Settings {
        workspace_roots: vec![dir.path().join("default")],
        exclusions: vec!["global-private".into()],
        artifact_retention: Some("90d".into()),
        ..Settings::default()
    };
    settings.profiles.insert(
        "work".into(),
        Profile {
            workspace_roots: vec![dir.path().join("work")],
            exclusions: vec!["team-private".into()],
            artifact_retention: Some("30d".into()),
            ..Profile::default()
        },
    );
    let (roots, exclusions, age) =
        profile_scan_options(&settings, Some("work"), &[], &["cli-private".into()], None).unwrap();
    assert_eq!(roots, vec![dir.path().join("work")]);
    assert_eq!(
        exclusions,
        vec![
            std::path::PathBuf::from("global-private"),
            "team-private".into(),
            "cli-private".into()
        ]
    );
    assert_eq!(age, Some(Duration::from_secs(30 * 86400)));
    let (roots, _, age) = profile_scan_options(
        &settings,
        Some("work"),
        &[dir.path().join("explicit")],
        &[],
        Some(Duration::ZERO),
    )
    .unwrap();
    assert_eq!(roots, vec![dir.path().join("explicit")]);
    assert_eq!(age, Some(Duration::ZERO));
    assert!(profile_scan_options(&settings, Some("missing"), &[], &[], None).is_err());
    settings.profiles.insert("empty".into(), Profile::default());
    assert!(profile_scan_options(&settings, Some("empty"), &[], &[], None).is_err());
    settings
        .profiles
        .get_mut("work")
        .unwrap()
        .artifact_retention = None;
    assert_eq!(
        profile_scan_options(&settings, Some("work"), &[], &[], None)
            .unwrap()
            .2,
        Some(Duration::from_secs(90 * 86400))
    );
}

#[test]
fn profile_config_round_trip_and_rejects_invalid_policy() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let root = dir.path().join("work");
    let mut settings = Settings::default();
    settings.profiles.insert(
        "work".into(),
        upkit::config::Profile {
            workspace_roots: vec![root.clone()],
            exclusions: vec!["private".into()],
            artifact_retention: Some("7d".into()),
            ..Default::default()
        },
    );
    create(&path, &settings, false).unwrap();
    let loaded = load(&path, true).unwrap();
    assert_eq!(loaded.profiles["work"].workspace_roots, vec![root]);
    let bad = [
        "[profiles.work]\nworkspace_roots=['relative']",
        "[profiles.work]\nexclusions=['../source']",
        "[profiles.work]\nartifact_retention='bad'",
        "[profiles.work]\nautomatic_cleanup=true",
        "[profiles.'bad name']\nworkspace_roots=[]",
    ];
    for text in bad {
        fs::write(&path, text).unwrap();
        assert!(load(&path, true).is_err(), "{text}");
    }
}

#[test]
fn cli_profile_scans_only_selected_workspace() {
    use upkit::config::Profile;
    let dir = tempdir().unwrap();
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    for root in [&first, &second] {
        fs::create_dir_all(root.join("target")).unwrap();
        fs::write(root.join("Cargo.toml"), "[workspace]").unwrap();
        fs::write(root.join("target/keep"), "fixture").unwrap();
    }
    let mut settings = Settings {
        workspace_roots: vec![first.clone()],
        ..Settings::default()
    };
    settings.profiles.insert(
        "work".into(),
        Profile {
            workspace_roots: vec![second.clone()],
            ..Profile::default()
        },
    );
    let config = dir.path().join("config.toml");
    create(&config, &settings, false).unwrap();
    let run = |profile: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(["--json", "--config"])
            .arg(&config)
            .args(["--profile", profile, "sweep", "scan"])
            .env("HOME", dir.path())
            .output()
            .unwrap()
    };
    let output = run("work");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["roots"][0],
        second.canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(report["candidates"].as_array().unwrap().len(), 1);
    assert!(!run("missing").status.success());
    assert!(first.join("target/keep").exists());
    assert!(second.join("target/keep").exists());
}

#[test]
fn ecosystem_policies_intersect_and_reject_unknown_names() {
    use upkit::{
        config::{Profile, enabled_ecosystems},
        sweep::Ecosystem,
    };
    let mut settings = Settings {
        enabled_ecosystems: Some(vec![Ecosystem::Cargo, Ecosystem::Python, Ecosystem::Zig]),
        ..Settings::default()
    };
    settings.profiles.insert(
        "work".into(),
        Profile {
            enabled_ecosystems: Some(vec![Ecosystem::Python, Ecosystem::Maven, Ecosystem::Zig]),
            ..Profile::default()
        },
    );
    assert_eq!(
        enabled_ecosystems(&settings, Some("work")).unwrap(),
        Some(vec![Ecosystem::Python, Ecosystem::Zig])
    );
    assert_eq!(
        enabled_ecosystems(&settings, None).unwrap(),
        Some(vec![Ecosystem::Cargo, Ecosystem::Python, Ecosystem::Zig])
    );
    assert!(enabled_ecosystems(&settings, Some("missing")).is_err());
    settings
        .profiles
        .get_mut("work")
        .unwrap()
        .enabled_ecosystems = Some(vec![]);
    assert_eq!(
        enabled_ecosystems(&settings, Some("work")).unwrap(),
        Some(vec![])
    );
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, "enabled_ecosystems = ['unknown']\n").unwrap();
    assert!(load(&path, true).is_err());
    fs::write(&path, "enabled_ecosystems = ['zig']\n").unwrap();
    assert_eq!(
        load(&path, true).unwrap().enabled_ecosystems,
        Some(vec![Ecosystem::Zig])
    );
    fs::write(&path, "enabled_ecosystems = ['sbt']\n").unwrap();
    assert_eq!(
        load(&path, true).unwrap().enabled_ecosystems,
        Some(vec![Ecosystem::Sbt])
    );
    fs::write(&path, "enabled_ecosystems = ['not-an-ecosystem']\n").unwrap();
    assert!(load(&path, true).is_err());
}

#[test]
fn cli_profile_filters_ecosystems_for_scan_and_preview() {
    use upkit::{config::Profile, sweep::Ecosystem};
    let dir = tempdir().unwrap();
    let root = dir.path().join("workspace");
    fs::create_dir_all(root.join("rust/target")).unwrap();
    fs::create_dir_all(root.join("python/__pycache__")).unwrap();
    fs::create_dir_all(root.join("scala/target")).unwrap();
    fs::write(root.join("rust/Cargo.toml"), "[workspace]").unwrap();
    fs::write(root.join("python/pyproject.toml"), "[project]").unwrap();
    fs::write(root.join("scala/build.sbt"), "lazy val root = project\n").unwrap();
    let mut settings = Settings {
        enabled_ecosystems: Some(vec![Ecosystem::Cargo, Ecosystem::Python, Ecosystem::Sbt]),
        ..Settings::default()
    };
    settings.profiles.insert(
        "work".into(),
        Profile {
            workspace_roots: vec![root.clone()],
            enabled_ecosystems: Some(vec![Ecosystem::Python, Ecosystem::Maven, Ecosystem::Sbt]),
            ..Profile::default()
        },
    );
    let config = dir.path().join("config.toml");
    create(&config, &settings, false).unwrap();
    for command in ["scan", "preview"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(["--json", "--config"])
            .arg(&config)
            .args(["--profile", "work", "sweep", command])
            .env("HOME", dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let items = if command == "scan" {
            report["candidates"].as_array().unwrap()
        } else {
            report["items"].as_array().unwrap()
        };
        let mut ecosystems = items
            .iter()
            .map(|item| {
                if command == "scan" {
                    item["ecosystem"].as_str().unwrap()
                } else {
                    item["candidate"]["ecosystem"].as_str().unwrap()
                }
            })
            .collect::<Vec<_>>();
        ecosystems.sort_unstable();
        assert_eq!(ecosystems, ["python", "sbt"]);
        if command == "preview" {
            let sbt = items
                .iter()
                .find(|item| item["candidate"]["ecosystem"] == "sbt")
                .unwrap();
            assert_eq!(sbt["candidate"]["classification"], "review");
            assert_eq!(
                sbt["risk"],
                if cfg!(unix) {
                    "potentially destructive"
                } else {
                    "identity changed or unavailable; do not remove"
                }
            );
            assert_eq!(sbt["execution_ready"], false);
            assert!(
                report["warnings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|warning| {
                        warning
                            .as_str()
                            .is_some_and(|text| text.contains("sbt's target directory"))
                    })
            );
        }
    }
    assert!(root.join("rust/target").exists());
}
#[test]
fn doctor_reports_invalid_configuration_and_unknown_profile_in_json() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let run = |profile: Option<&str>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_upkit"));
        cmd.args(["--json", "--offline", "--dry-run", "--config"])
            .arg(&config);
        if let Some(profile) = profile {
            cmd.args(["--profile", profile]);
        }
        let output = cmd.arg("doctor").env("HOME", dir.path()).output().unwrap();
        assert!(!output.status.success());
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    fs::write(&config, "version = 'private-fixture-value'").unwrap();
    let invalid = run(None);
    assert!(invalid["issues"].as_array().unwrap().iter().any(|issue| {
        issue
            .as_str()
            .unwrap()
            .contains("invalid or unreadable Upkit configuration")
    }));
    assert!(!invalid.to_string().contains("private-fixture-value"));
    fs::write(&config, "version = 1\n").unwrap();
    let unknown = run(Some("missing"));
    assert!(unknown["issues"].as_array().unwrap().iter().any(|issue| {
        issue
            .as_str()
            .unwrap()
            .contains("unknown workspace profile missing")
    }));
    assert_eq!(fs::read_to_string(config).unwrap(), "version = 1\n");
}
