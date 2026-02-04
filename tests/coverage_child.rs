use clap::Parser;
use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;

use upkit::test_support::{TestPrompt, base_ctx, reset_guard, set_env_var, set_home_dir};
use upkit::{Cli, maybe_path_hint, run};

#[test]
fn spawn_child_non_target_exe() {
    if std::env::var("UPKIT_CHILD").is_ok() {
        return;
    }

    let exe = std::env::current_exe().unwrap();
    let dir = tempdir().unwrap();
    let child = dir.path().join("upkit-tests");
    std::fs::copy(&exe, &child).unwrap();

    let status = Command::new(&child)
        .arg("--exact")
        .arg("child_paths_non_target")
        .arg("--nocapture")
        .env("UPKIT_CHILD", "1")
        .status()
        .unwrap();

    assert!(status.success());
}

#[test]
fn child_paths_non_target() {
    if std::env::var("UPKIT_CHILD").is_err() {
        return;
    }

    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&bindir).unwrap();

    set_env_var("SHELL", Some("bash".to_string()));
    set_env_var("PATH", Some("/usr/bin".to_string()));
    set_home_dir(Some(home.clone()));

    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(home.clone(), bindir.clone(), prompt.clone());
    maybe_path_hint(&ctx);

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = base_ctx(home, bindir, prompt);
    run(&cli, &mut ctx).unwrap();
}
