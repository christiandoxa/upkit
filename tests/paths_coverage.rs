use clap::Parser;
use std::sync::Arc;
use tempfile::tempdir;

use upkit::test_support::{
    TestPrompt, base_ctx, reset_guard, set_env_var, set_home_dir, set_run_output, set_which,
};
use upkit::{Cli, Ctx, Prompt, run};

fn ctx_from_cli(
    cli: &Cli,
    home: std::path::PathBuf,
    bindir: std::path::PathBuf,
    prompt: Arc<dyn Prompt>,
) -> Ctx {
    let mut ctx = base_ctx(home, bindir, prompt);
    ctx.yes = cli.yes;
    ctx.dry_run = cli.dry_run;
    ctx.quiet = cli.quiet;
    ctx.verbose = cli.verbose;
    ctx.no_progress = cli.no_progress;
    ctx.offline = cli.offline;
    ctx.retries = cli.retries;
    ctx.json = cli.json;
    ctx.use_color = !cli.no_color && !cli.json;
    ctx
}

#[test]
fn paths_warn_missing_rc_and_gobin() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    set_env_var("SHELL", Some("bash".to_string()));
    set_env_var("GOBIN", Some("/tmp/gobin".to_string()));
    set_home_dir(None);

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home, bindir, prompt);
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn paths_inserts_label_at_existing_path_line() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    std::fs::create_dir_all(&home).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));

    let rc = home.join(".bashrc");
    std::fs::write(&rc, format!("export PATH=\"{}:$PATH\"\n", bindir.display())).unwrap();

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home, bindir, prompt);
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn paths_label_without_path_line_updates() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    std::fs::create_dir_all(&home).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));

    let rc = home.join(".bashrc");
    std::fs::write(&rc, "# upkit (upkit bin)\n").unwrap();

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home, bindir, prompt);
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn paths_no_rc_uses_first_candidate() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    std::fs::create_dir_all(&home).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home, bindir, prompt);
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn paths_home_relative_patterns_empty_suffix() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = home.clone();
    let prompt = Arc::new(TestPrompt::default());
    std::fs::create_dir_all(&home).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));

    let rc = home.join(".bashrc");
    std::fs::write(&rc, "export PATH=\"$HOME:$PATH\"\n").unwrap();

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home, bindir, prompt);
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn paths_find_existing_path_line_with_home_none() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    std::fs::create_dir_all(&home).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(None);

    let rc = home.join(".bashrc");
    std::fs::write(&rc, "export PATH=\"/opt/bin:$PATH\"\n").unwrap();

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home, bindir, prompt);
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn paths_shell_candidates_variants() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    std::fs::create_dir_all(&home).unwrap();
    set_home_dir(Some(home.clone()));

    for shell in ["zsh", "fish", "bash", "sh"] {
        set_env_var("SHELL", Some(shell.to_string()));
        let cli = Cli::parse_from(["upkit", "paths"]);
        let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
        run(&cli, &mut ctx).unwrap();
    }
}

#[test]
fn paths_npm_global_bin_dir_branches() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    std::fs::create_dir_all(&home).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));
    set_which("npm", Some(std::path::PathBuf::from("/bin/npm")));

    set_run_output(
        "/bin/npm",
        &["bin", "-g"],
        upkit::test_support::output_with_status(0, b"undefined", b""),
    );
    set_run_output(
        "/bin/npm",
        &["config", "get", "prefix"],
        upkit::test_support::output_with_status(0, b"/opt/npm", b""),
    );

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    set_run_output(
        "/bin/npm",
        &["bin", "-g"],
        upkit::test_support::output_with_status(0, b"/opt/npm/bin", b""),
    );

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    set_run_output(
        "/bin/npm",
        &["bin", "-g"],
        upkit::test_support::output_with_status(0, b"", b""),
    );
    set_run_output(
        "/bin/npm",
        &["config", "get", "prefix"],
        upkit::test_support::output_with_status(0, b"", b""),
    );
    set_run_output(
        "/bin/npm",
        &["prefix", "-g"],
        upkit::test_support::output_with_status(0, b"/opt/npm", b""),
    );

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home, bindir, prompt);
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn paths_python_user_base_dir_variants() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    std::fs::create_dir_all(&home).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));

    set_env_var("PYTHONUSERBASE", Some("/opt/pybase".to_string()));
    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    set_env_var("PYTHONUSERBASE", None);
    set_which("python3", Some(std::path::PathBuf::from("/bin/python3")));
    set_run_output(
        "/bin/python3",
        &["-m", "site", "--user-base"],
        upkit::test_support::output_with_status(0, b"/opt/py3", b""),
    );
    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    set_which("python3", None);
    set_which("python", Some(std::path::PathBuf::from("/bin/python")));
    set_run_output(
        "/bin/python",
        &["-m", "site", "--user-base"],
        upkit::test_support::output_with_status(0, b"/opt/py", b""),
    );
    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    set_which("python", None);
    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home, bindir, prompt);
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn paths_npm_program_active_bin() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    std::fs::create_dir_all(&home).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));

    let active_npm = home.join("node").join("active").join("bin");
    std::fs::create_dir_all(&active_npm).unwrap();
    std::fs::write(active_npm.join("npm"), b"").unwrap();

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home, bindir, prompt);
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn paths_go_env_paths_default_and_flutter_bindir() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&bindir).unwrap();
    std::fs::write(bindir.join("flutter"), b"").unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));
    set_env_var("GOBIN", None);
    set_which("go", None);

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home, bindir, prompt);
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn paths_python_user_base_empty_output() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    std::fs::create_dir_all(&home).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));
    set_env_var("PYTHONUSERBASE", None);
    set_which("python3", Some(std::path::PathBuf::from("/bin/python3")));
    set_run_output(
        "/bin/python3",
        &["-m", "site", "--user-base"],
        upkit::test_support::output_with_status(0, b"", b""),
    );

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home, bindir, prompt);
    run(&cli, &mut ctx).unwrap();
}
