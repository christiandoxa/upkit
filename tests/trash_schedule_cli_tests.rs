#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn write_config(path: &Path, enabled: bool) {
    fs::write(
        path,
        format!("version = 1\nscheduled_trash_retention = {enabled}\n"),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn write_default_config(path: &Path) {
    fs::write(path, "version = 1\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = dir.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let trash = dir.path().join("data/Trash");
    fs::create_dir_all(trash.join("files")).unwrap();
    fs::create_dir_all(trash.join("info")).unwrap();
    dir
}

fn private_binary(home: &Path) -> PathBuf {
    let directory = home.join("bin");
    fs::create_dir_all(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let executable = directory.join("upkit");
    if !executable.exists() {
        fs::copy(env!("CARGO_BIN_EXE_upkit"), &executable).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    }
    executable
}

fn run(home: &Path, config: &Path, args: &[&str]) -> Output {
    Command::new(private_binary(home))
        .arg("--config")
        .arg(config)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_RUNTIME_DIR", home.join("runtime"))
        .output()
        .unwrap()
}

fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn cli_exposes_lifecycle_and_keeps_executor_hidden() {
    let schedule_help = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["schedule", "trash-retention", "--help"])
        .output()
        .unwrap();
    assert!(schedule_help.status.success());
    let help = String::from_utf8_lossy(&schedule_help.stdout);
    for command in [
        "preview", "install", "enable", "disable", "remove", "status",
    ] {
        assert!(help.contains(command), "missing {command} in: {help}");
    }

    let trash_help = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["trash", "--help"])
        .output()
        .unwrap();
    assert!(trash_help.status.success());
    assert!(!String::from_utf8_lossy(&trash_help.stdout).contains("scheduled-retention"));
}

#[test]
fn preview_requires_opt_in_and_at_least_thirty_days_before_manager_access() {
    let dir = fixture();
    let home = dir.path();
    let location = home.join("data/Trash");
    let config = home.join("upkit.toml");
    write_default_config(&config);

    let plain = run(
        home,
        &config,
        &[
            "schedule",
            "trash-retention",
            "preview",
            "--location",
            location.to_str().unwrap(),
            "--older-than",
            "30d",
        ],
    );
    assert!(!plain.status.success());
    assert!(output_text(&plain).contains("--non-interactive or --json"));

    let disabled = run(
        home,
        &config,
        &[
            "--json",
            "--non-interactive",
            "schedule",
            "trash-retention",
            "preview",
            "--location",
            location.to_str().unwrap(),
            "--older-than",
            "30d",
        ],
    );
    assert!(!disabled.status.success());
    let disabled_text = output_text(&disabled);
    assert!(disabled_text.contains("not enabled"), "{disabled_text}");

    write_config(&config, true);
    let too_young = run(
        home,
        &config,
        &[
            "--json",
            "--non-interactive",
            "schedule",
            "trash-retention",
            "preview",
            "--location",
            location.to_str().unwrap(),
            "--older-than",
            "29d",
        ],
    );
    assert!(!too_young.status.success());
    assert!(output_text(&too_young).contains("at least 30"));

    assert!(
        !home
            .join("xdg/systemd/user/upkit-trash-retention.timer")
            .exists()
    );
}

#[test]
fn install_and_hidden_executor_refuse_before_manager_or_trash_access() {
    let dir = fixture();
    let home = dir.path();
    let location = home.join("data/Trash");
    let config = home.join("upkit.toml");
    write_config(&config, true);
    let item = location.join("files/keep");
    fs::write(&item, "fixture data").unwrap();

    let install = run(
        home,
        &config,
        &[
            "--json",
            "--non-interactive",
            "--yes",
            "schedule",
            "trash-retention",
            "install",
            "--location",
            location.to_str().unwrap(),
            "--older-than",
            "30d",
            "--preview-token",
            &"a".repeat(64),
        ],
    );
    assert!(!install.status.success());
    assert!(output_text(&install).contains("--authorize-scheduled-trash-retention"));

    let executor = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args([
            "--json",
            "--non-interactive",
            "--offline",
            "trash",
            "scheduled-retention",
            "--location",
        ])
        .arg(&location)
        .args(["--age-seconds", "2592000", "--scope-token"])
        .arg("a".repeat(64))
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("xdg"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_RUNTIME_DIR", home.join("runtime"))
        .output()
        .unwrap();
    assert!(!executor.status.success());
    assert!(output_text(&executor).contains("explicit --config path"));

    let secret_config = home.join("private-config-path-must-not-leak.toml");
    let invalid_policy = run(
        home,
        &secret_config,
        &[
            "--json",
            "--non-interactive",
            "--offline",
            "trash",
            "scheduled-retention",
            "--location",
            location.to_str().unwrap(),
            "--age-seconds",
            "2592000",
            "--scope-token",
            &"a".repeat(64),
        ],
    );
    assert!(!invalid_policy.status.success());
    assert!(!output_text(&invalid_policy).contains(secret_config.to_str().unwrap()));
    assert_eq!(fs::read_to_string(item).unwrap(), "fixture data");
    assert!(
        !home
            .join("xdg/systemd/user/upkit-trash-retention.timer")
            .exists()
    );
}
