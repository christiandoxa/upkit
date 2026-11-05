//! First-run zero-config CLI and fail-closed cleanup regression tests.
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn run(home: &Path, cwd: &Path, args: &[&str]) -> (Output, Value) {
    let bin = env!("CARGO_BIN_EXE_upkit");
    let output = Command::new(bin)
        .args(["--offline", "--non-interactive", "--json"])
        .args(args)
        .env_clear()
        .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .current_dir(cwd)
        .output()
        .unwrap();
    let data: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("Upkit output was not JSON: exit={:?}", output.status.code()));
    (output, data)
}

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let workspace = root.path().join("project");
    let src = workspace.join("src");
    let target = workspace.join("target");
    fs::create_dir(&home).unwrap();
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(target.join("debug")).unwrap();
    fs::write(
        workspace.join("Cargo.toml"),
        b"[package]\nname='safe-fixture'\nversion='0.1.0'\n",
    )
    .unwrap();
    fs::write(src.join("lib.rs"), b"pub fn fixture() {}\n").unwrap();
    fs::write(
        target.join("debug/build-output"),
        b"only synthetic rebuildable output\n",
    )
    .unwrap();
    (root, home, src, target)
}

#[test]
fn tidy_discovers_nearest_manifest_without_config_and_never_removes_by_default() {
    let (_root, home, src, target) = fixture();
    let (status, data) = run(&home, &src, &["tidy"]);
    assert!(
        status.status.success(),
        "tidy did not report safe inventory"
    );
    let project = src.parent().unwrap().canonicalize().unwrap();
    assert_eq!(data["workspace_roots"], serde_json::json!([project]));
    let artifacts = data["artifacts"].as_array().unwrap();
    assert_eq!(artifacts.len(), 1, "one Cargo output expected");
    assert_eq!(artifacts[0]["kind"], "artifact");
    assert_eq!(artifacts[0]["name"], "cargo");
    assert_eq!(
        artifacts[0]["path"],
        serde_json::json!(target.canonicalize().unwrap())
    );
    assert_eq!(artifacts[0]["status"], "preview_available");
    assert!(data["shared_caches"].is_array());
    assert_eq!(data["executed"], false);
    assert!(target.join("debug/build-output").exists());
}

#[test]
fn tidy_no_manifest_never_scans_home_or_parent_and_still_reports_caches() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let subdir = home.join("nested/no_project");
    fs::create_dir_all(&subdir).unwrap();
    fs::write(
        home.join("Cargo.toml"),
        b"[package]\nname='do-not-scan-home'\nversion='0.1.0'\n",
    )
    .unwrap();
    let (status, data) = run(&home, &subdir, &["tidy"]);
    assert!(status.status.success());
    assert_eq!(data["workspace_roots"], serde_json::json!([]));
    assert_eq!(data["artifacts"], serde_json::json!([]));
    assert!(data["shared_caches"].is_array());
    assert!(
        data["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap_or("").contains("No project detected"))
    );
}

#[test]
fn sweep_scan_defaults_to_cwd_project_but_explicit_config_never_silently_falls_back() {
    let (_root, home, src, target) = fixture();
    let (status, data) = run(&home, &src, &["sweep", "scan"]);
    assert!(status.status.success());
    assert_eq!(
        data["candidates"][0]["target"],
        serde_json::json!(target.canonicalize().unwrap())
    );
    let empty_config = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let (status, data) = run(&home, &src, &["--config", empty_config, "sweep", "scan"]);
    assert!(!status.status.success());
    assert!(data["error"].as_str().unwrap().contains("workspace roots"));
}

#[test]
fn tidy_requires_explicit_selection_and_token_and_never_deletes_on_dry_run() {
    let (_root, home, src, target) = fixture();
    let target_name = target.to_str().unwrap();
    let (status, _data) = run(
        &home,
        &src,
        &["--yes", "tidy", "--run", "--preview-token", "garbage"],
    );
    assert!(
        !status.status.success(),
        "run without a selection must refuse"
    );
    assert!(target.join("debug/build-output").exists());

    let (status, data) = run(&home, &src, &["--dry-run", "tidy", "--select", target_name]);
    assert!(status.status.success());
    assert_eq!(data["executed"], false);
    assert_eq!(data["dry_run"], true);
    assert!(target.join("debug/build-output").exists());

    let (status, _data) = run(
        &home,
        &src,
        &[
            "--yes",
            "tidy",
            "--select",
            target_name,
            "--run",
            "--preview-token",
            "garbage",
        ],
    );
    assert!(!status.status.success());
    assert!(
        target.join("debug/build-output").exists(),
        "invalid token must never delete project files"
    );
}

#[test]
fn cleanup_alias_and_config_show_expose_default_without_persisting_it() {
    let (_root, home, src, _target) = fixture();
    let (status, alias) = run(&home, &src, &["cleanup"]);
    assert!(status.status.success());
    assert_eq!(alias["workspace_roots"].as_array().unwrap().len(), 1);
    assert_eq!(alias["executed"], false);

    let (status, config) = run(&home, &src, &["config", "show"]);
    assert!(status.status.success());
    assert_eq!(config["scan_scope_source"], "current_project");
    assert!(
        config["settings"]["workspace_roots"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        config["effective_workspace_roots"],
        alias["workspace_roots"]
    );
    assert!(
        !home.join("config/upkit/config.toml").exists(),
        "inference must not write settings"
    );
}

#[test]
fn tidy_unique_name_selection_works_without_copying_paths_or_configuring_roots() {
    let (_root, home, src, target) = fixture();
    let (status, data) = run(&home, &src, &["--dry-run", "tidy", "--select", "cargo"]);
    assert!(status.status.success());
    assert_eq!(data["dry_run"], true);
    assert_eq!(data["executed"], false);
    assert_eq!(
        data["target"],
        serde_json::json!(target.canonicalize().unwrap().to_str().unwrap())
    );
    assert!(target.join("debug/build-output").exists());
}

#[test]
fn tidy_never_offers_a_nested_project_as_disposable_artifact() {
    let (_root, home, src, target) = fixture();
    // One nested project marker makes the otherwise rebuildable target unsafe.
    fs::write(
        target.join("Cargo.toml"),
        b"[package]\nname='unexpected-project'\nversion='0.1.0'\n",
    )
    .unwrap();
    let (status, overview) = run(&home, &src, &["tidy"]);
    assert!(status.status.success());
    let artifacts = overview["artifacts"].as_array().unwrap();
    assert!(
        artifacts.is_empty(),
        "nested projects must not be cleanup candidates"
    );
    let (status, detail) = run(&home, &src, &["tidy", "--select", "cargo"]);
    assert!(!status.status.success());
    assert!(
        detail["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unknown tidy selection")
    );
    assert!(target.join("Cargo.toml").exists());
}

#[test]
fn tidy_rejects_unknown_selection_and_never_scans_extra_roots() {
    let (root, home, src, target) = fixture();
    let stranger = root.path().join("stranger");
    fs::create_dir(&stranger).unwrap();
    fs::write(stranger.join("keep"), b"not a recognized target").unwrap();
    let (status, data) = run(
        &home,
        &src,
        &["tidy", "--select", stranger.to_str().unwrap()],
    );
    assert!(!status.status.success());
    assert!(
        data["error"]
            .as_str()
            .unwrap()
            .contains("missing or ambiguous")
    );
    assert!(stranger.join("keep").exists());
    assert!(target.join("debug/build-output").exists());
}
