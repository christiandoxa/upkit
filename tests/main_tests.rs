use clap::Parser;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;
use upkit::test_support::{
    MockResponse, TestPrompt, base_ctx, output_with_status, reset_guard, set_check_tool,
    set_data_local_dir, set_env_var, set_finish_template, set_home_dir,
    set_http_allow_unknown_error, set_http_plan, set_json_pretty_error, set_make_ctx_error,
    set_prompt_defaults, set_run_output, set_sleep_passthrough, set_spinner_template,
    set_update_tool, set_which, set_write_error, sleep_calls,
};
use upkit::*;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[cfg(target_os = "linux")]
fn reviewed_clean_tool(ctx: &Ctx, tool: ToolKind) -> anyhow::Result<()> {
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let plan = managed_cleanup::preview(ctx, tool, &cancel)?;
    managed_cleanup::remove(ctx, &plan, &cancel)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_fixture_directory(path: &std::path::Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(target_os = "linux")]
fn sealed_tool_root_fixture(
    home: &std::path::Path,
    bindir: &std::path::Path,
    tool: ToolKind,
) -> std::path::PathBuf {
    set_fixture_directory(home);
    set_fixture_directory(bindir);
    let root = home.join(tool.as_str());
    set_fixture_directory(&root);

    let stage = tempfile::Builder::new()
        .prefix("install-")
        .tempdir_in(&root)
        .unwrap();
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let tool_dir = stage.path().join(tool.as_str());
    let bin = tool_dir.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::set_permissions(&tool_dir, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    let fixture_file = tool_dir.join("fixture");
    fs::write(&fixture_file, b"sealed fixture").unwrap();
    fs::set_permissions(&fixture_file, fs::Permissions::from_mode(0o644)).unwrap();
    installation_identity::seal(&root, &stage, tool, "fixture").unwrap();

    let install = stage.keep();
    std::os::unix::fs::symlink(install.join(tool.as_str()), root.join("active")).unwrap();
    root
}

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
fn legacy_clean_tool_refuses_unreviewed_removal_even_with_yes() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("managed");
    let bindir = dir.path().join("bin");
    fs::create_dir_all(home.join("go")).unwrap();
    fs::write(home.join("go/keep"), "fixture").unwrap();
    let mut ctx = base_ctx(home.clone(), bindir, Arc::new(TestPrompt::default()));
    ctx.yes = true;
    assert!(
        clean_tool(&ctx, ToolKind::Go)
            .unwrap_err()
            .to_string()
            .contains("preview")
    );
    assert_eq!(fs::read_to_string(home.join("go/keep")).unwrap(), "fixture");
    ctx.dry_run = true;
    clean_tool(&ctx, ToolKind::Go).unwrap();
    assert!(home.join("go/keep").exists());
}

#[test]
fn version_parse_and_order() {
    let v = Version::parse_loose("v1.2.3-beta").expect("parse");
    assert_eq!(v.to_string(), "1.2.3-beta");
    assert!(Version::parse_loose("go1.2.3").is_some());
    assert!(Version::parse_loose("rustc 1.2.3").is_some());
    let mojo_beta = Version::parse_loose("mojo 1.0.0b2").expect("parse Mojo beta");
    assert!(mojo_beta < Version::parse_loose("1.0.0").unwrap());
    assert!(Version::parse_loose("bad").is_none());

    let a = Version::parse_loose("1.2.3").unwrap();
    let b = Version::parse_loose("1.2.4").unwrap();
    assert!(a < b);
}

#[test]
fn toolkind_helpers() {
    let all = ToolKind::all();
    assert!(all.contains(&ToolKind::Go));
    assert!(all.contains(&ToolKind::Mojo));
    assert_eq!(ToolKind::Python.as_str(), "python");
    assert_eq!(ToolKind::Mojo.as_str(), "mojo");
    assert_eq!(select_kinds(Some(ToolKind::Rust)), vec![ToolKind::Rust]);
    assert_eq!(select_kinds(None).len(), 8);
    assert!(matches!(
        tool_method(ToolKind::Go),
        UpdateMethod::DirectDownload
    ));
    assert!(matches!(tool_method(ToolKind::Mojo), UpdateMethod::BuiltIn));
    assert_eq!(
        tool_bin_names(ToolKind::Go),
        if cfg!(windows) {
            &["go.exe", "gofmt.exe"][..]
        } else {
            &["go", "gofmt"][..]
        }
    );
}

#[test]
fn expand_tilde_variants() {
    let _guard = reset_guard();
    set_home_dir(None);
    assert!(expand_tilde("~/nope").is_none());
    set_home_dir(Some(std::path::PathBuf::from("/tmp")));
    let out = expand_tilde("~/dir").expect("path");
    assert!(out.ends_with("dir"));
    assert_eq!(
        expand_tilde("plain").unwrap(),
        std::path::PathBuf::from("plain")
    );
}

#[test]
fn make_ctx_uses_dirs_overrides() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    set_data_local_dir(Some(dir.path().join("data")));
    set_home_dir(Some(dir.path().join("home")));
    let cli = Cli::parse_from(["upkit"]);
    let ctx = make_ctx(&cli).unwrap();
    assert!(ctx.home.ends_with("upkit"));
    assert!(ctx.bindir.ends_with(".local/bin"));
}

#[test]
fn non_interactive_flag_disables_prompt_input() {
    let cli = Cli::parse_from(["upkit", "--non-interactive", "update"]);
    assert!(cli.non_interactive);
    assert!(!make_ctx(&cli).unwrap().stdin_is_tty);
}

#[test]
fn non_interactive_mutations_require_confirmation_without_prompting() {
    let dir = tempdir().unwrap();
    for command in ["update", "clean", "uninstall"] {
        let cli = Cli::parse_from(["upkit", "--non-interactive", command, "go"]);
        let prompt = Arc::new(TestPrompt::default());
        let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
        let err = run(&cli, &mut ctx).unwrap_err();
        assert!(err.to_string().contains("--yes"));
        assert!(!ctx.home.exists());
    }
}

#[cfg(unix)]
#[test]
fn rejected_non_interactive_command_does_not_change_shell_config() {
    let dir = tempdir().unwrap();
    let rc = dir.path().join(".bashrc");
    fs::write(&rc, "# unchanged\n").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--non-interactive", "update", "go"])
        .env("HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path())
        .env("SHELL", "bash")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--yes"));
    assert_eq!(fs::read_to_string(rc).unwrap(), "# unchanged\n");
    assert!(!dir.path().join("upkit").exists());
}

#[test]
fn dry_run_does_not_create_directories_or_update_shell_config() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("managed");
    let bindir = dir.path().join("bin");
    let rc = dir.path().join(".bashrc");
    fs::write(&rc, "# unchanged\n").unwrap();
    set_home_dir(Some(dir.path().to_path_buf()));
    set_env_var("SHELL", Some("bash".to_owned()));
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(home.clone(), bindir.clone(), prompt);
    ctx.dry_run = true;
    ctx.offline = true;
    let cli = Cli::parse_from(["upkit", "--dry-run", "--offline", "paths"]);
    run(&cli, &mut ctx).unwrap();
    let _ = run_doctor(&ctx, false);
    maybe_path_hint_for_dir(&ctx, &bindir, "test");
    assert!(!home.exists());
    assert!(!bindir.exists());
    assert_eq!(fs::read_to_string(rc).unwrap(), "# unchanged\n");
}

#[test]
fn make_ctx_fallback_dirs() {
    let _guard = reset_guard();
    set_data_local_dir(None);
    set_home_dir(None);
    let cli = Cli::parse_from(["upkit"]);
    let ctx = make_ctx(&cli).unwrap();
    assert!(ctx.home.ends_with("upkit"));
    assert!(ctx.bindir.ends_with(".local/bin"));
}

#[test]
fn make_ctx_uses_ssl_cert_file() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let pem = "\
-----BEGIN CERTIFICATE-----\n\
MIIDCzCCAfOgAwIBAgIUdiczmAOCkgQuwApNRbw/U7NxyhwwDQYJKoZIhvcNAQEL\n\
BQAwFTETMBEGA1UEAwwKdXBraXQtdGVzdDAeFw0yNjAxMTExNDU2NTVaFw0yNjAx\n\
MTIxNDU2NTVaMBUxEzARBgNVBAMMCnVwa2l0LXRlc3QwggEiMA0GCSqGSIb3DQEB\n\
AQUAA4IBDwAwggEKAoIBAQDKiVi1tZPdLAb88tmNAZ2LHldAYMg/YhQ5S0zJxXzW\n\
Y1vy2j2RGVV0E5rM5AlJ+HjjxqvG/4eyS+mcBnTE7lSH9PkMs8e+aqVxqbOGBOrP\n\
hl+9HmbI5jZ+pJP1XuYsyzC8K8t7xj3AzYqBwq8n0z8AmEHoB4YrKA9yi+mHSFwH\n\
6TQAXHdR0xe+SFj0l52sNozI13ei39STDv5UAix3UdFflmniITcTcAaVPa/akfOK\n\
nOO8HuzeTNXbIhSmYsKqLwpj1V2SjSI36tcH9AL6KMGofgP8Z/QW5myFk7i4XyrN\n\
VjiOtB4orcKdKosa/OqiEuPM+Judow7n+h6mCV8HKzvHAgMBAAGjUzBRMB0GA1Ud\n\
DgQWBBT6ZS2JEyXhvF2gdyLllJWProe9ujAfBgNVHSMEGDAWgBT6ZS2JEyXhvF2g\n\
dyLllJWProe9ujAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQC2\n\
CmlDJVgB3JAHd+Fv+EHsijfWBjqlEiVxoS7ZENflFVTK50LoR3Qc+LETn03I7pcl\n\
r1VGPNxQYsa3zkwUtC7/5hi+pAgnNhBW1CLX90aABV6J3N0AGYOJpKBf53O67rcw\n\
FsJgQ0IjZ1JZpDT7ToaQcvjjIevO1fYdPmHrqVAoUm9At65Xt7ypmxqfcTn1RqcN\n\
ABj36fHCz/LEV5gQp1D6hwly00+ntiUSDT9PjFwRnYq+P46ez1onmTQg1ftCJgEh\n\
8vEoW6qhlTKMrFpjenKeYB9lpazBUzqqHf2aEji5FExK9BjmL2C52ePa05Ghy9Ug\n\
6NMx6i4RoEntFk8vyNUd\n\
-----END CERTIFICATE-----\n";
    fs::write(&cert_path, pem).unwrap();
    set_env_var(
        "SSL_CERT_FILE",
        Some(cert_path.to_string_lossy().to_string()),
    );
    let cli = Cli::parse_from(["upkit", "--offline"]);
    let ctx = make_ctx(&cli).unwrap();
    assert!(ctx.timeout > 0);
}

#[test]
fn main_smoke() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    set_data_local_dir(Some(dir.path().join("data")));
    set_home_dir(Some(dir.path().join("home")));
    for tool in ToolKind::all() {
        let report = ToolReport {
            tool,
            installed: None,
            latest: None,
            status: Status::Unknown,
            method: tool_method(tool),
            notes: vec![],
        };
        set_check_tool(tool, Ok(report));
    }
    let _ = main_with(Cli::parse_from(["upkit"]));
}

#[test]
fn debug_and_spinner_template_errors() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.verbose = 1;
    debug(&ctx, "hello");

    set_spinner_template(Some("{:"));
    set_finish_template(Some("{:"));
    let pb = start_spinner(&ctx, "work");
    finish_spinner(pb, "done");
    let pb = start_spinner(&ctx, "work");
    finish_spinner(pb, "done");
    set_spinner_template(None);
    set_finish_template(None);
}

#[test]
fn run_update_with_spinner_template_errors() {
    let _guard = reset_guard();
    set_spinner_template(Some("{:"));
    set_finish_template(Some("{:"));
    set_update_tool(ToolKind::Go, Ok(()));

    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let cli = Cli::parse_from(["upkit", "--yes", "update", "go"]);
    let mut ctx = ctx_from_cli(
        &cli,
        dir.path().join("home"),
        dir.path().join("bin"),
        prompt,
    );
    run(&cli, &mut ctx).unwrap();

    set_spinner_template(None);
    set_finish_template(None);
}

#[test]
fn spinner_branches() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.no_progress = true;
    assert!(start_spinner(&ctx, "skip").is_none());

    ctx.no_progress = false;
    ctx.progress_overwrite = false;
    let pb = start_spinner(&ctx, "static");
    finish_spinner(pb, "failed to run");
}

#[test]
fn reports_json_with_versions() {
    let reports = vec![ToolReport {
        tool: ToolKind::Rust,
        installed: Some(Version {
            major: 1,
            minor: 2,
            patch: 3,
            pre: None,
        }),
        latest: Some(Version {
            major: 1,
            minor: 2,
            patch: 4,
            pre: None,
        }),
        status: Status::Outdated,
        method: UpdateMethod::BuiltIn,
        notes: vec![],
    }];
    let json = reports_to_json(&reports);
    assert!(json.is_array());
}

#[test]
fn run_update_missing_versions_in_labels_and_summary() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    prompt.push_selection(vec![0]);
    prompt.push_confirm(true);

    for tool in ToolKind::all() {
        let status = if tool == ToolKind::Go {
            Status::Unknown
        } else {
            Status::UpToDate
        };
        let report = ToolReport {
            tool,
            installed: None,
            latest: None,
            status,
            method: tool_method(tool),
            notes: vec![],
        };
        set_check_tool(tool, Ok(report));
    }
    set_update_tool(ToolKind::Go, Ok(()));
    set_env_var("PATH", Some(bindir.display().to_string()));
    let cli = Cli::parse_from(["upkit", "update"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt);
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn run_update_installed_versions_in_labels_and_summary() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    prompt.push_selection(vec![0]);
    prompt.push_confirm(true);

    for tool in ToolKind::all() {
        let (installed, status) = if tool == ToolKind::Go {
            (
                Some(Version {
                    major: 1,
                    minor: 0,
                    patch: 0,
                    pre: None,
                }),
                Status::Unknown,
            )
        } else {
            (None, Status::UpToDate)
        };
        let report = ToolReport {
            tool,
            installed,
            latest: None,
            status,
            method: tool_method(tool),
            notes: vec![],
        };
        set_check_tool(tool, Ok(report));
    }
    set_update_tool(ToolKind::Go, Ok(()));
    set_env_var("PATH", Some(bindir.display().to_string()));
    let cli = Cli::parse_from(["upkit", "update"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt);
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn run_output_error_path() {
    let _guard = reset_guard();
    let err = run_output("upkit-nope", &["--version"]).unwrap_err();
    assert!(err.to_string().contains("failed to run"));
}

#[test]
fn ensure_clean_dir_error() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let target = dir.path().join("not_a_dir");
    fs::write(&target, b"nope").unwrap();
    let err = ensure_clean_dir(&target).unwrap_err();
    assert!(err.to_string().contains("refusing to replace"));
    fs::remove_file(&target).unwrap();
}

#[test]
fn link_dir_bins_error() {
    let dir = tempdir().unwrap();
    let bin_dir = dir.path().join("bin_src");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::write(bin_dir.join("go"), b"").unwrap();
    let bindir_file = dir.path().join("bindir_file");
    fs::write(&bindir_file, b"not a dir").unwrap();
    let err = link_dir_bins(&bin_dir, &bindir_file, &["go"]).unwrap_err();
    assert!(err.to_string().contains("symlink"));
}

#[test]
fn print_json_error_fallback() {
    let _guard = reset_guard();
    set_json_pretty_error(true);
    let err = anyhow::anyhow!("boom");
    print_json_error("cmd", &err);
    set_json_pretty_error(false);
}

#[test]
fn http_get_exhausted_retries() {
    let _guard = reset_guard();
    let url = "https://example.com/retry";
    set_http_allow_unknown_error(true);
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.retries = 1;
    let err = http_get_text(&ctx, url).unwrap_err();
    assert!(err.to_string().contains("request failed after"));
    set_http_allow_unknown_error(false);
}

#[test]
fn progress_and_colorize() {
    let prompt = Arc::new(TestPrompt::default());
    let dir = tempdir().unwrap();
    let ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    assert!(!progress_allowed(&Ctx {
        no_progress: true,
        ..ctx.clone()
    }));
    assert!(!progress_allowed(&Ctx {
        json: true,
        ..ctx.clone()
    }));

    let mut color_ctx = ctx.clone();
    color_ctx.use_color = true;
    let colored = colorize_status(&color_ctx, Status::UpToDate, "OK".to_string());
    assert!(colored.contains("OK"));
    let plain = colorize_status(&ctx, Status::UpToDate, "OK".to_string());
    assert_eq!(plain, "OK");
}

#[test]
fn reports_json_and_errors() {
    let reports = vec![ToolReport {
        tool: ToolKind::Go,
        installed: None,
        latest: None,
        status: Status::Unknown,
        method: UpdateMethod::DirectDownload,
        notes: vec!["Check failed: test".into()],
    }];
    let json = reports_to_json(&reports);
    assert!(json.is_array());
    assert!(report_has_error(&reports[0]));

    let err = anyhow::anyhow!("some updates failed: test");
    assert_eq!(map_error_to_exit_code(&err), 2);
    let err = anyhow::anyhow!("some uninstall steps failed: test");
    assert_eq!(map_error_to_exit_code(&err), 2);
    let err = anyhow::anyhow!("non-interactive mode");
    assert_eq!(map_error_to_exit_code(&err), 3);
    let err = anyhow::anyhow!("other");
    assert_eq!(map_error_to_exit_code(&err), 1);
}

#[test]
fn run_output_and_capture_hooks() {
    let _guard = reset_guard();
    set_run_output("echo", &["hi"], output_with_status(0, b"ok", b""));
    let out = run_capture("echo", &["hi"]).unwrap();
    assert_eq!(out, "ok");
    set_run_output("fail", &["now"], output_with_status(1, b"", b"bad"));
    let err = run_capture("fail", &["now"]).unwrap_err();
    assert!(err.to_string().contains("command"));
}

#[test]
fn http_get_with_retry_and_text_json() {
    let _guard = reset_guard();
    let url = "https://example.com/test.json";
    let plan = vec![
        Err("fail".to_string()),
        Ok(MockResponse::new(br#"{"a":1}"#.to_vec(), Some(8))),
    ];
    set_http_plan(url, plan);
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.retries = 1;
    let val: serde_json::Value = http_get_json(&ctx, url).unwrap();
    assert_eq!(val.get("a").unwrap(), 1);
    assert_eq!(sleep_calls().len(), 1);

    let text_url = "https://example.com/text";
    set_http_plan(
        text_url,
        vec![Ok(MockResponse::new(b"hello".to_vec(), Some(5)))],
    );
    let text = http_get_text(&ctx, text_url).unwrap();
    assert_eq!(text, "hello");
}

#[test]
fn download_to_temp_branches() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);

    let url = "https://example.com/a";
    set_http_plan(url, vec![Ok(MockResponse::new(vec![1, 2, 3], Some(3)))]);
    ctx.progress_overwrite = true;
    let tmp = download_to_temp(&ctx, url).unwrap();
    assert_eq!(fs::read(tmp.path()).unwrap(), vec![1, 2, 3]);

    let url = "https://example.com/b";
    set_http_plan(url, vec![Ok(MockResponse::new(vec![4, 5], None))]);
    let tmp = download_to_temp(&ctx, url).unwrap();
    assert_eq!(fs::read(tmp.path()).unwrap(), vec![4, 5]);

    let url = "https://example.com/c";
    set_http_plan(url, vec![Ok(MockResponse::new(vec![6], Some(1)))]);
    ctx.progress_overwrite = false;
    let tmp = download_to_temp(&ctx, url).unwrap();
    assert_eq!(fs::read(tmp.path()).unwrap(), vec![6]);

    let url = "https://example.com/d";
    set_http_plan(url, vec![Ok(MockResponse::new(vec![7, 8], None))]);
    let tmp = download_to_temp(&ctx, url).unwrap();
    assert_eq!(fs::read(tmp.path()).unwrap(), vec![7, 8]);

    let url = "https://example.com/e";
    set_http_plan(url, vec![Ok(MockResponse::new(vec![9], Some(1)))]);
    ctx.no_progress = true;
    let tmp = download_to_temp(&ctx, url).unwrap();
    assert_eq!(fs::read(tmp.path()).unwrap(), vec![9]);
}

#[test]
fn http_get_no_test_response_left() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    let url = "https://example.com/no-response";
    set_http_plan(url, Vec::new());
    let err = match http_get(&ctx, url) {
        Ok(_) => panic!("expected error"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("no test response left"));
}

#[test]
fn http_get_missing_plan_entry() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    set_http_plan(
        "https://example.com/known",
        vec![Ok(MockResponse::new(b"ok".to_vec(), None))],
    );
    let err = match http_get(&ctx, "https://example.com/unknown") {
        Ok(_) => panic!("expected error"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("no test response left"));
}

#[test]
fn filesystem_helpers() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    fs::create_dir_all(&target).unwrap();
    let link = dir.path().join("link");
    atomic_symlink(&target, &link).unwrap();
    let linked = fs::read_link(&link).unwrap();
    assert_eq!(linked, target);

    let clean = dir.path().join("clean");
    fs::create_dir_all(&clean).unwrap();
    fs::write(clean.join("file"), b"data").unwrap();
    assert!(ensure_clean_dir(&clean).is_err());
    assert!(fs::read_dir(&clean).unwrap().next().is_some());
}

#[cfg(unix)]
#[test]
fn symlink_activation_preserves_unrelated_files_and_replaces_existing_link() {
    let dir = tempdir().unwrap();
    let old = dir.path().join("old");
    let new = dir.path().join("new");
    let link = dir.path().join("active");
    let old_tmp = link.with_extension("tmp");
    fs::create_dir(&old).unwrap();
    fs::create_dir(&new).unwrap();
    fs::write(&old_tmp, "keep temporary name").unwrap();
    fs::write(&link, "keep destination").unwrap();
    assert!(atomic_symlink(&new, &link).is_err());
    assert_eq!(fs::read_to_string(&link).unwrap(), "keep destination");
    assert_eq!(fs::read_to_string(&old_tmp).unwrap(), "keep temporary name");
    fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&old, &link).unwrap();
    atomic_symlink(&new, &link).unwrap();
    assert_eq!(fs::read_link(&link).unwrap(), new);
    assert_eq!(fs::read_to_string(&old_tmp).unwrap(), "keep temporary name");
    assert!(!fs::read_dir(dir.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".upkit-link-")
    }));
}

#[cfg(unix)]
#[test]
fn link_dir_bins_preserves_unrelated_existing_symlink() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let src = dir.path().join("source");
    let bin = dir.path().join("bin");
    fs::create_dir(&src).unwrap();
    fs::create_dir(&bin).unwrap();
    fs::write(src.join("go"), "new").unwrap();
    let other = dir.path().join("other");
    fs::write(&other, "keep").unwrap();
    symlink(&other, bin.join("go")).unwrap();
    assert!(link_dir_bins(&src, &bin, &["go"]).is_err());
    assert_eq!(fs::read_link(bin.join("go")).unwrap(), other);
    assert_eq!(fs::read_to_string(&other).unwrap(), "keep");
    fs::remove_file(bin.join("go")).unwrap();
    link_dir_bins(&src, &bin, &["go"]).unwrap();
    link_dir_bins(&src, &bin, &["go"]).unwrap();
    assert_eq!(fs::read_link(bin.join("go")).unwrap(), src.join("go"));
}

#[cfg(unix)]
#[test]
fn binary_link_preflight_checks_all_destinations_before_writing() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("source");
    let bin = dir.path().join("bin");
    fs::create_dir(&src).unwrap();
    fs::create_dir(&bin).unwrap();
    fs::write(src.join("go"), "fixture").unwrap();
    fs::write(src.join("gofmt"), "fixture").unwrap();
    fs::write(bin.join("gofmt"), "user file").unwrap();
    assert!(link_dir_bins(&src, &bin, &["go", "gofmt"]).is_err());
    assert!(!bin.join("go").exists());
    assert_eq!(fs::read_to_string(bin.join("gofmt")).unwrap(), "user file");
}

#[cfg(target_os = "linux")]
#[test]
fn bin_linking_and_clean_tool() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    set_fixture_directory(&home);
    set_fixture_directory(&bindir);
    let bin_dir = dir.path().join("bin_src");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::write(bin_dir.join("go"), b"").unwrap();
    link_dir_bins(&bin_dir, &bindir, &["go", "missing"]).unwrap();
    assert!(bindir.join("go").exists());

    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(home.clone(), bindir.clone(), prompt);
    ctx.dry_run = true;
    clean_tool(&ctx, ToolKind::Go).unwrap();

    ctx.dry_run = false;
    let tool_root = sealed_tool_root_fixture(&home, &bindir, ToolKind::Go);
    let symlink_path = bindir.join("go");
    let target = tool_root.join("active/bin");
    atomic_symlink(&target, &symlink_path).unwrap();
    installation_identity::record_active_link(&tool_root, &bindir, ToolKind::Go).unwrap();
    installation_identity::record_created_links(
        &tool_root,
        &bindir,
        ToolKind::Go,
        &[(symlink_path.clone(), target)],
    )
    .unwrap();
    assert!(clean_tool(&ctx, ToolKind::Go).is_err());
    assert!(tool_root.exists());
    assert!(fs::symlink_metadata(&symlink_path).is_ok());
    reviewed_clean_tool(&ctx, ToolKind::Go).unwrap();
    assert!(!symlink_path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn clean_tool_remove_symlink_error() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(home.clone(), bindir.clone(), prompt);
    let tool_root = sealed_tool_root_fixture(&home, &bindir, ToolKind::Go);
    let symlink_path = bindir.join("go");
    let target = tool_root.join("active/bin");
    atomic_symlink(&target, &symlink_path).unwrap();
    let mut perms = fs::metadata(&bindir).unwrap().permissions();
    perms.set_mode(0o500);
    fs::set_permissions(&bindir, perms).unwrap();
    installation_identity::record_active_link(&tool_root, &bindir, ToolKind::Go).unwrap();
    installation_identity::record_created_links(
        &tool_root,
        &bindir,
        ToolKind::Go,
        &[(symlink_path.clone(), target)],
    )
    .unwrap();
    let err = reviewed_clean_tool(&ctx, ToolKind::Go).unwrap_err();
    let mut perms = fs::metadata(&bindir).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&bindir, perms).unwrap();
    assert!(err.to_string().contains("not owner-writable"));
    assert!(tool_root.exists());
    assert!(fs::symlink_metadata(symlink_path).is_ok());
}

#[test]
fn maybe_path_hint_paths() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let _hook_guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    set_env_var("PATH", Some(bindir.display().to_string()));
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));

    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(home.clone(), bindir.clone(), prompt);
    ctx.quiet = true;
    maybe_path_hint(&ctx);

    ctx.quiet = false;
    maybe_path_hint(&ctx);

    set_env_var("PATH", Some("/usr/bin".to_string()));
    let rc = home.join(".bashrc");
    fs::write(&rc, bindir.display().to_string()).unwrap();
    maybe_path_hint(&ctx);

    fs::remove_file(&rc).unwrap();
    fs::create_dir_all(&rc).unwrap();
    maybe_path_hint(&ctx);

    fs::remove_dir_all(&rc).unwrap();
    maybe_path_hint(&ctx);

    set_home_dir(None);
    maybe_path_hint(&ctx);
    set_home_dir(Some(home.clone()));

    set_env_var("PATH", Some("/usr/bin".to_string()));
    set_write_error(true);
    maybe_path_hint(&ctx);
    set_write_error(false);
}

#[test]
fn run_doctor_variants() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let _hook_guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(home.clone(), bindir.clone(), prompt);
    set_env_var("PATH", Some("/usr/bin".to_string()));
    set_which("go", None);
    set_which("rustc", None);
    set_which("node", None);
    set_which("python3", None);
    set_which("flutter", None);
    set_which("mojo", None);
    set_which("javac", None);
    set_which("dotnet", None);
    set_http_plan("https://example.com", vec![Err("no".to_string())]);
    let err = run_doctor(&ctx, false).unwrap_err();
    assert!(err.to_string().contains("doctor found"));

    ctx.offline = true;
    set_env_var("PATH", Some(bindir.display().to_string()));
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    set_which("go", Some(std::path::PathBuf::from("/bin/go")));
    set_which("rustc", Some(std::path::PathBuf::from("/bin/rustc")));
    set_which("node", Some(std::path::PathBuf::from("/bin/node")));
    set_which("python3", Some(std::path::PathBuf::from("/bin/python3")));
    set_which("flutter", Some(std::path::PathBuf::from("/bin/flutter")));
    set_which("mojo", Some(std::path::PathBuf::from("/bin/mojo")));
    set_which("javac", Some(std::path::PathBuf::from("/bin/javac")));
    set_which("dotnet", Some(std::path::PathBuf::from("/bin/dotnet")));
    run_doctor(&ctx, true).unwrap();
}

#[cfg(unix)]
#[test]
fn run_doctor_unwritable_dirs() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let _hook_guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    let mut perms = fs::metadata(&home).unwrap().permissions();
    perms.set_mode(0o500);
    fs::set_permissions(&home, perms).unwrap();
    let mut perms = fs::metadata(&bindir).unwrap().permissions();
    perms.set_mode(0o500);
    fs::set_permissions(&bindir, perms).unwrap();
    set_env_var("PATH", Some(bindir.display().to_string()));
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(home.clone(), bindir.clone(), prompt);
    ctx.offline = true;
    let err = run_doctor(&ctx, false).unwrap_err();
    assert!(err.to_string().contains("doctor found"));
}

#[test]
fn run_self_update_paths() {
    let _guard = reset_guard();
    set_env_var("UPKIT_INSTALLER", Some("cargo".to_string()));
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(home, bindir, prompt.clone());

    ctx.offline = true;
    assert!(run_self_update(&ctx, false).is_err());

    ctx.offline = false;
    ctx.json = true;
    assert!(run_self_update(&ctx, true).is_err());

    ctx.json = false;
    ctx.stdin_is_tty = false;
    assert!(run_self_update(&ctx, false).is_err());

    ctx.stdin_is_tty = true;
    set_which("cargo", None);
    assert!(run_self_update(&ctx, false).is_err());

    set_which("cargo", Some(std::path::PathBuf::from("/bin/cargo")));
    prompt.push_confirm(false);
    run_self_update(&ctx, false).unwrap();

    ctx.dry_run = true;
    ctx.json = true;
    ctx.yes = true;
    run_self_update(&ctx, true).unwrap();

    ctx.json = false;
    run_self_update(&ctx, false).unwrap();

    ctx.dry_run = false;
    set_run_output(
        "cargo",
        &["install", "--force", "upkit"],
        output_with_status(1, b"", b""),
    );
    assert!(run_self_update(&ctx, false).is_err());

    set_run_output(
        "cargo",
        &["install", "--force", "upkit"],
        output_with_status(0, b"", b""),
    );
    set_run_output(
        "cargo",
        &["install", "--force", "upkit"],
        output_with_status(0, b"", b""),
    );
    run_self_update(&ctx, false).unwrap();
    ctx.json = true;
    run_self_update(&ctx, true).unwrap();

    set_env_var("UPKIT_INSTALLER", Some("npm".to_string()));
    set_env_var(
        "UPKIT_NPM_PACKAGE_NAME",
        Some("@christiandoxa/upkit".to_string()),
    );
    set_which("npm", None);
    assert!(run_self_update(&ctx, true).is_err());

    set_which("npm", Some(std::path::PathBuf::from("/bin/npm")));
    ctx.json = false;
    ctx.dry_run = true;
    run_self_update(&ctx, false).unwrap();

    ctx.dry_run = false;
    set_run_output(
        "npm",
        &["install", "-g", "@christiandoxa/upkit@latest"],
        output_with_status(1, b"", b""),
    );
    assert!(run_self_update(&ctx, false).is_err());

    set_run_output(
        "npm",
        &["install", "-g", "@christiandoxa/upkit@latest"],
        output_with_status(0, b"", b""),
    );
    set_run_output(
        "npm",
        &["install", "-g", "@christiandoxa/upkit@latest"],
        output_with_status(0, b"", b""),
    );
    run_self_update(&ctx, false).unwrap();
    ctx.json = true;
    run_self_update(&ctx, true).unwrap();

    set_env_var("UPKIT_INSTALLER", Some("standalone".to_string()));
    ctx.dry_run = true;
    set_which("sh", None);
    assert!(run_self_update(&ctx, true).is_err());
    set_which("sh", Some(std::path::PathBuf::from("/bin/sh")));
    run_self_update(&ctx, true).unwrap();

    ctx.os = "windows".into();
    set_which("pwsh", Some(std::path::PathBuf::from("pwsh")));
    run_self_update(&ctx, true).unwrap();
    set_which("pwsh", None);
    set_which("powershell", Some(std::path::PathBuf::from("powershell")));
    run_self_update(&ctx, true).unwrap();
    set_which("powershell", None);
    assert!(run_self_update(&ctx, true).is_err());
}

#[test]
fn run_version_and_json_emit() {
    let prompt = Arc::new(TestPrompt::default());
    let dir = tempdir().unwrap();
    let ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    run_version(&ctx, false).unwrap();
    run_version(&ctx, true).unwrap();
    emit_json(&ctx, serde_json::json!({"a": 1})).unwrap();
    assert!(ctx.json_emitted.load(std::sync::atomic::Ordering::Relaxed));
    print_json_error("cmd", &anyhow::anyhow!("err"));
}

#[test]
fn check_tools_parallel_and_spinner() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.offline = true;
    let reports = check_tools_parallel(&ctx, &[ToolKind::Go]);
    assert_eq!(reports.len(), 1);

    let tools = vec![ToolKind::Go, ToolKind::Rust];
    let reports = check_tools_parallel(&ctx, &tools);
    assert_eq!(reports.len(), 2);

    ctx.stderr_is_tty = true;
    let reports = check_tools_with_spinner(&ctx, &tools);
    assert_eq!(reports.len(), 2);
}

#[test]
fn run_command_paths_check_update_clean() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());

    let cli = Cli::parse_from(["upkit", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    let cli = Cli::parse_from(["upkit", "--json", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    let report = ToolReport {
        tool: ToolKind::Go,
        installed: None,
        latest: None,
        status: Status::Unknown,
        method: UpdateMethod::DirectDownload,
        notes: vec![],
    };
    set_check_tool(ToolKind::Go, Ok(report.clone()));
    set_check_tool(ToolKind::Rust, Ok(report.clone()));
    let cli = Cli::parse_from(["upkit", "check"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    let cli = Cli::parse_from(["upkit", "--json", "check"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    let cli = Cli::parse_from(["upkit", "clean"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    ctx.stdin_is_tty = false;
    assert!(run(&cli, &mut ctx).is_err());

    prompt.push_selection(vec![]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    ctx.stdin_is_tty = true;
    ctx.dry_run = true;
    run(&cli, &mut ctx).unwrap();

    prompt.push_selection(vec![0]);
    prompt.push_confirm(false);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    ctx.dry_run = true;
    run(&cli, &mut ctx).unwrap();

    let cli = Cli::parse_from(["upkit", "--json", "-y", "clean", "go"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    let tool_root = home.join("go");
    fs::write(&tool_root, b"not a dir").unwrap();
    assert!(run(&cli, &mut ctx).is_err());

    let cli = Cli::parse_from(["upkit", "-y", "--dry-run", "uninstall", "go"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn run_uninstall_prompts_for_selection() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    prompt.push_selection(vec![0]);
    prompt.push_confirm(true);
    let cli = Cli::parse_from(["upkit", "uninstall"]);
    let mut ctx = ctx_from_cli(&cli, home, bindir, prompt);
    ctx.dry_run = true;
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn run_command_doctor_version_completions_self_update() {
    let _guard = reset_guard();
    set_env_var("UPKIT_INSTALLER", Some("cargo".to_string()));
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());

    let cli = Cli::parse_from(["upkit", "doctor"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    ctx.offline = true;
    run(&cli, &mut ctx).unwrap_err();

    let cli = Cli::parse_from(["upkit", "version"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    let cli = Cli::parse_from(["upkit", "completions", "bash"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    let cli = Cli::parse_from(["upkit", "-y", "--dry-run", "self-update"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    set_which("cargo", Some(std::path::PathBuf::from("/bin/cargo")));
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn run_update_flow_variants() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());

    let cli = Cli::parse_from(["upkit", "update"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    ctx.stdin_is_tty = false;
    assert!(run(&cli, &mut ctx).is_err());

    let cli = Cli::parse_from(["upkit", "install", "go"]);
    if let Some(Commands::Update { tools, .. }) = cli.cmd {
        assert_eq!(tools, vec![ToolKind::Go]);
    } else {
        panic!("install should map to update");
    }

    let cli = Cli::parse_from(["upkit", "--json", "update"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    assert!(run(&cli, &mut ctx).is_err());

    let report = ToolReport {
        tool: ToolKind::Go,
        installed: None,
        latest: None,
        status: Status::UpToDate,
        method: UpdateMethod::DirectDownload,
        notes: vec![],
    };
    set_check_tool(ToolKind::Go, Ok(report.clone()));
    set_check_tool(ToolKind::Rust, Ok(report.clone()));
    set_check_tool(ToolKind::Node, Ok(report.clone()));
    set_check_tool(ToolKind::Python, Ok(report.clone()));
    set_check_tool(ToolKind::Flutter, Ok(report.clone()));
    set_check_tool(ToolKind::Java, Ok(report.clone()));
    set_check_tool(ToolKind::Dotnet, Ok(report.clone()));
    let cli = Cli::parse_from(["upkit", "update"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    let report = ToolReport {
        tool: ToolKind::Go,
        installed: None,
        latest: Some(Version {
            major: 1,
            minor: 0,
            patch: 0,
            pre: None,
        }),
        status: Status::Outdated,
        method: tool_method(ToolKind::Go),
        notes: vec![],
    };
    set_check_tool(ToolKind::Go, Ok(report.clone()));
    prompt.push_selection(vec![]);
    let cli = Cli::parse_from(["upkit", "update"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    prompt.push_selection(vec![0]);
    prompt.push_confirm(false);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    set_update_tool(ToolKind::Rust, Ok(()));
    set_update_tool(ToolKind::Node, Err("nope".into()));
    let cli = Cli::parse_from(["upkit", "--json", "-y", "update", "rust", "node"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    assert!(run(&cli, &mut ctx).is_err());

    set_update_tool(ToolKind::Rust, Ok(()));
    let cli = Cli::parse_from(["upkit", "--json", "-y", "update", "rust"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn report_printing_and_spinners() {
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    let reports = vec![ToolReport {
        tool: ToolKind::Go,
        installed: Some(Version {
            major: 1,
            minor: 0,
            patch: 0,
            pre: None,
        }),
        latest: Some(Version {
            major: 1,
            minor: 1,
            patch: 0,
            pre: None,
        }),
        status: Status::Outdated,
        method: UpdateMethod::DirectDownload,
        notes: vec!["note".into()],
    }];
    print_reports(&ctx, &reports);
    ctx.quiet = true;
    print_reports(&ctx, &reports);

    ctx.quiet = false;
    ctx.no_progress = true;
    assert!(start_spinner(&ctx, "x").is_none());
    ctx.no_progress = false;
    ctx.progress_overwrite = false;
    let pb = start_spinner(&ctx, "x");
    finish_spinner(pb, "failed");
    ctx.progress_overwrite = true;
    let pb = start_spinner(&ctx, "x");
    finish_spinner(pb, "ok");
}

#[test]
fn dialoguer_prompt_defaults() {
    let _guard = reset_guard();
    set_prompt_defaults(true);
    let prompt = DialoguerPrompt;
    assert!(prompt.confirm("ok?", true).unwrap());
    let picked = prompt.multi_select("pick", &[String::from("a")]).unwrap();
    assert!(picked.is_empty());
    set_prompt_defaults(false);
}

#[test]
fn main_with_make_ctx_error_paths() {
    let _guard = reset_guard();
    set_make_ctx_error(Some("boom".into()));
    let code = main_with(Cli::parse_from(["upkit", "paths"]));
    assert_eq!(code, std::process::ExitCode::from(1));

    set_make_ctx_error(Some("boom".into()));
    let code = main_with(Cli::parse_from(["upkit", "--json", "paths"]));
    assert_eq!(code, std::process::ExitCode::from(1));
    set_make_ctx_error(None);
}

#[test]
fn main_with_run_error_paths() {
    let _guard = reset_guard();
    set_env_var("UPKIT_INSTALLER", Some("cargo".to_string()));
    set_which("cargo", None);
    let code = main_with(Cli::parse_from(["upkit", "-y", "self-update"]));
    assert_eq!(code, std::process::ExitCode::from(1));

    let code = main_with(Cli::parse_from(["upkit", "--json", "self-update"]));
    assert_eq!(code, std::process::ExitCode::from(1));
}

#[test]
fn main_with_offline_warning() {
    let _guard = reset_guard();
    let code = main_with(Cli::parse_from(["upkit", "--offline", "paths"]));
    assert_eq!(code, std::process::ExitCode::SUCCESS);
}

#[test]
fn log_helpers_and_sleep_passthrough() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    debug(
        &Ctx {
            verbose: 1,
            ..ctx.clone()
        },
        "debug",
    );
    warn(&ctx, "warn");
    error("err");

    set_sleep_passthrough(true);
    sleep_for(std::time::Duration::from_millis(1));
    set_sleep_passthrough(false);
}

#[test]
fn tool_routing_and_safe_errors() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.offline = true;
    set_which("go", None);
    set_which("rustc", None);
    set_which("node", None);
    set_which("python3", None);
    set_which("python", None);
    set_which("flutter", None);
    set_which("mojo", None);
    set_which("javac", None);
    set_which("dotnet", None);

    for tool in ToolKind::all() {
        let _ = check_tool(&ctx, tool);
    }

    for tool in ToolKind::all() {
        assert!(update_tool(&ctx, tool).is_err());
    }

    set_check_tool(ToolKind::Go, Err("boom".into()));
    let report = check_tool_safe(&ctx, ToolKind::Go);
    assert!(report.notes[0].contains("Check failed"));
}

#[test]
fn colorize_and_tool_bins_variants() {
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.use_color = true;
    let text = colorize_status(&ctx, Status::Outdated, "OLD".to_string());
    assert!(text.contains("OLD"));
    let text = colorize_status(&ctx, Status::NotInstalled, "MISS".to_string());
    assert!(text.contains("MISS"));
    assert_eq!(
        tool_bin_names(ToolKind::Node),
        &["node", "npm", "npx", "corepack"]
    );
    let python_bins: &[&str] = if cfg!(windows) {
        &["python.exe"]
    } else {
        &["python", "python3", "pip", "pip3"]
    };
    assert_eq!(tool_bin_names(ToolKind::Python), python_bins);
    assert!(tool_bin_names(ToolKind::Rust).is_empty());
    assert_eq!(
        tool_bin_names(ToolKind::Flutter),
        &["flutter", "dart", "pub"]
    );
    assert_eq!(tool_bin_names(ToolKind::Mojo), &["mojo"]);
}

#[test]
fn maybe_path_hint_shell_variants_and_write_errors() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let _hook_guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    set_home_dir(Some(home.clone()));
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(home.clone(), bindir.clone(), prompt);

    set_env_var("PATH", Some("/usr/bin".to_string()));
    set_env_var("SHELL", Some("zsh".to_string()));
    maybe_path_hint(&ctx);
    assert!(home.join(".zshrc").exists());

    set_env_var("SHELL", Some("fish".to_string()));
    fs::create_dir_all(home.join(".config/fish")).unwrap();
    maybe_path_hint(&ctx);
    let fish_rc = home.join(".config/fish/config.fish");
    let content = fs::read_to_string(&fish_rc).unwrap();
    assert!(content.contains("set -gx PATH"));

    set_env_var("SHELL", Some("ksh".to_string()));
    maybe_path_hint(&ctx);
    assert!(home.join(".profile").exists());

    set_env_var("SHELL", Some("bash".to_string()));
    set_write_error(true);
    maybe_path_hint(&ctx);
    set_write_error(false);

    let mut buf = Vec::new();
    set_write_error(true);
    assert!(write_all_checked(&mut buf, b"nope").is_err());
    set_write_error(false);
}

#[test]
fn download_to_temp_partial_progress() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.progress_overwrite = false;
    let url = "https://example.com/partial";
    set_http_plan(url, vec![Ok(MockResponse::new(vec![1, 2], Some(5)))]);
    let err = download_to_temp(&ctx, url).unwrap_err();
    assert!(err.to_string().contains("download incomplete"));
}

#[cfg(target_os = "linux")]
#[test]
fn clean_tool_symlink_paths() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(home.clone(), bindir.clone(), prompt);

    let tool_root = sealed_tool_root_fixture(&home, &bindir, ToolKind::Go);
    fs::write(bindir.join("go"), b"not a symlink").unwrap();
    let outside = dir.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    atomic_symlink(&outside, &bindir.join("gofmt")).unwrap();
    let install = fs::read_link(tool_root.join("active"))
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    installation_identity::record_active_link(&tool_root, &bindir, ToolKind::Go).unwrap();
    reviewed_clean_tool(&ctx, ToolKind::Go).unwrap();
    assert!(bindir.join("go").exists());
    assert!(bindir.join("gofmt").exists());
    assert!(!tool_root.join("active").exists());
    assert!(!install.exists());

    let tool_root = sealed_tool_root_fixture(&home, &bindir, ToolKind::Go);
    let home_link = bindir.join("gofmt");
    let target = tool_root.join("active/bin");
    atomic_symlink(&target, &home_link).unwrap();
    installation_identity::record_active_link(&tool_root, &bindir, ToolKind::Go).unwrap();
    installation_identity::record_created_links(
        &tool_root,
        &bindir,
        ToolKind::Go,
        &[(home_link.clone(), target)],
    )
    .unwrap();
    reviewed_clean_tool(&ctx, ToolKind::Go).unwrap();
    assert!(!home_link.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn managed_cleanup_preserves_links_to_other_tools_and_parent_traversals() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bin = dir.path().join("bin");
    let go_root = sealed_tool_root_fixture(&home, &bin, ToolKind::Go);
    set_fixture_directory(&home.join("node/bin"));
    fs::write(home.join("node/bin/node"), "keep").unwrap();
    let other = home.join("node/bin/node");
    let traversal = go_root.join("../node/bin/node");
    symlink(&other, bin.join("go")).unwrap();
    symlink(&traversal, bin.join("gofmt")).unwrap();
    let ctx = base_ctx(home.clone(), bin.clone(), Arc::new(TestPrompt::default()));
    installation_identity::record_active_link(&go_root, &bin, ToolKind::Go).unwrap();
    reviewed_clean_tool(&ctx, ToolKind::Go).unwrap();
    assert_eq!(fs::read_link(bin.join("go")).unwrap(), other);
    assert_eq!(fs::read_link(bin.join("gofmt")).unwrap(), traversal);
    assert_eq!(
        fs::read_to_string(home.join("node/bin/node")).unwrap(),
        "keep"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn clean_rejects_linked_tool_root_and_user_home_scope() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("managed");
    let outside = dir.path().join("source");
    let bindir = dir.path().join("bin");
    set_fixture_directory(&home);
    fs::create_dir_all(&outside).unwrap();
    set_fixture_directory(&bindir);
    fs::write(outside.join("keep"), "source").unwrap();
    std::os::unix::fs::symlink(&outside, home.join("go")).unwrap();
    let ctx = base_ctx(home.clone(), bindir, Arc::new(TestPrompt::default()));
    assert!(reviewed_clean_tool(&ctx, ToolKind::Go).is_err());
    assert!(outside.join("keep").exists());
    fs::remove_file(home.join("go")).unwrap();
    let tool_root = sealed_tool_root_fixture(&home, &ctx.bindir, ToolKind::Go);
    std::os::unix::fs::symlink(&outside, home.join("go/link")).unwrap();
    installation_identity::record_active_link(&tool_root, &ctx.bindir, ToolKind::Go).unwrap();
    reviewed_clean_tool(&ctx, ToolKind::Go).unwrap();
    assert!(outside.join("keep").exists());
    assert!(fs::symlink_metadata(home.join("go/link")).is_ok());
    fs::remove_dir_all(&tool_root).unwrap();
    fs::create_dir(&tool_root).unwrap();
    fs::write(home.join("go/keep"), "source").unwrap();
    let mut root_ctx = ctx.clone();
    root_ctx.home = std::path::PathBuf::from("/");
    assert!(reviewed_clean_tool(&root_ctx, ToolKind::Go).is_err());
    assert!(home.join("go/keep").exists());
}

#[test]
fn run_doctor_no_issues_and_errors() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let _hook_guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(home.clone(), bindir.clone(), prompt);
    set_env_var("PATH", Some(bindir.display().to_string()));
    set_which("go", Some(std::path::PathBuf::from("/bin/go")));
    set_which("rustc", Some(std::path::PathBuf::from("/bin/rustc")));
    set_which("node", Some(std::path::PathBuf::from("/bin/node")));
    set_which("python3", Some(std::path::PathBuf::from("/bin/python3")));
    set_which("flutter", Some(std::path::PathBuf::from("/bin/flutter")));
    set_which("mojo", Some(std::path::PathBuf::from("/bin/mojo")));
    set_which("javac", Some(std::path::PathBuf::from("/bin/javac")));
    set_which("dotnet", Some(std::path::PathBuf::from("/bin/dotnet")));
    ctx.offline = true;
    run_doctor(&ctx, false).unwrap();

    let bad_home = dir.path().join("bad_home");
    let bad_bin = dir.path().join("bad_bin");
    fs::write(&bad_home, b"file").unwrap();
    fs::write(&bad_bin, b"file").unwrap();
    let mut bad_ctx = base_ctx(
        bad_home.clone(),
        bad_bin.clone(),
        Arc::new(TestPrompt::default()),
    );
    bad_ctx.offline = true;
    set_env_var("PATH", Some("/usr/bin".to_string()));
    set_which("go", None);
    set_which("rustc", None);
    set_which("node", None);
    set_which("python3", None);
    set_which("flutter", None);
    set_which("mojo", None);
    set_which("javac", None);
    set_which("dotnet", None);
    assert!(run_doctor(&bad_ctx, false).is_err());
}

#[test]
fn doctor_reports_unavailable_space_without_creating_home() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("missing-home");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "--offline", "--dry-run", "doctor", "--home"])
        .arg(&home)
        .arg("--bindir")
        .arg(dir.path())
        .env("HOME", dir.path())
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report.get("home_available_bytes").unwrap().is_null());
    assert!(!home.exists());
}

#[cfg(unix)]
#[test]
fn doctor_reports_broken_tool_links_without_changing_them() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bin = dir.path().join("bin");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&bin).unwrap();
    let target = home.join("missing");
    symlink(&target, bin.join("go")).unwrap();
    let node = home.join("node/active/bin/node");
    fs::create_dir_all(node.parent().unwrap()).unwrap();
    fs::write(&node, "fixture").unwrap();
    fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&node, bin.join("node")).unwrap();
    fs::write(home.join("python"), "fixture").unwrap();
    fs::set_permissions(home.join("python"), fs::Permissions::from_mode(0o600)).unwrap();
    symlink(home.join("python"), bin.join("python")).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "--offline", "--dry-run", "doctor", "--home"])
        .arg(&home)
        .arg("--bindir")
        .arg(&bin)
        .env("HOME", dir.path())
        .env("PATH", &bin)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(report["home_available_bytes"].as_u64().is_some());
    let issues = report["issues"].as_array().unwrap();
    assert!(
        issues
            .iter()
            .any(|issue| issue.as_str().unwrap().contains("cannot resolve tool link"))
    );
    assert!(
        issues
            .iter()
            .any(|issue| issue.as_str().unwrap().contains("non-executable file"))
    );
    assert!(
        !issues
            .iter()
            .any(|issue| issue.as_str().unwrap().contains("tool link")
                && issue.as_str().unwrap().contains("node"))
    );
    assert_eq!(fs::read_link(bin.join("go")).unwrap(), target);
    assert_eq!(fs::read_to_string(node).unwrap(), "fixture");
}

#[cfg(unix)]
#[test]
fn doctor_reports_managed_tool_link_outside_installation_without_changing_it() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bin = dir.path().join("bin");
    let outside = dir.path().join("external/node");
    let managed = home.join("node/active/bin/node");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(managed.parent().unwrap()).unwrap();
    fs::create_dir_all(outside.parent().unwrap()).unwrap();
    fs::write(&managed, "managed fixture").unwrap();
    fs::write(&outside, "external fixture").unwrap();
    fs::set_permissions(&managed, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&outside, bin.join("node")).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "--offline", "--dry-run", "doctor", "--home"])
        .arg(&home)
        .arg("--bindir")
        .arg(&bin)
        .env("HOME", dir.path())
        .env("PATH", &bin)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["issues"].as_array().unwrap().iter().any(|issue| {
        issue
            .as_str()
            .unwrap()
            .contains("does not resolve inside the managed node installation")
    }));
    assert_eq!(fs::read_link(bin.join("node")).unwrap(), outside);
    assert_eq!(fs::read_to_string(managed).unwrap(), "managed fixture");
    assert_eq!(fs::read_to_string(outside).unwrap(), "external fixture");
}

#[cfg(unix)]
#[test]
fn doctor_checks_only_selected_workspace_roots_without_changes() {
    use std::{os::unix::fs::symlink, process::Command};
    let dir = tempdir().unwrap();
    let valid = dir.path().join("valid");
    let missing = dir.path().join("missing");
    let linked = dir.path().join("linked");
    let file = dir.path().join("file");
    fs::create_dir(&valid).unwrap();
    fs::write(&file, "fixture").unwrap();
    symlink(&valid, &linked).unwrap();
    let mut settings = upkit::config::Settings {
        workspace_roots: vec![valid.clone()],
        ..Default::default()
    };
    settings.profiles.insert(
        "broken".into(),
        upkit::config::Profile {
            workspace_roots: vec![missing.clone(), linked.clone(), file.clone()],
            ..Default::default()
        },
    );
    let config = dir.path().join("config.toml");
    fs::write(&config, toml::to_string(&settings).unwrap()).unwrap();
    let run = |profile: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        command
            .args(["--json", "--offline", "--dry-run", "--config"])
            .arg(&config);
        if let Some(profile) = profile {
            command.args(["--profile", profile]);
        }
        command.arg("doctor").env("HOME", dir.path());
        let output = command.output().unwrap();
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let default = run(None);
    assert!(
        !default["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue.as_str().unwrap().contains("workspace root"))
    );
    let selected = run(Some("broken"));
    let issues = selected["issues"].as_array().unwrap();
    for problem in [
        "cannot be inspected",
        "is a symbolic link",
        "is not a directory",
    ] {
        assert!(
            issues
                .iter()
                .any(|issue| issue.as_str().unwrap().contains(problem))
        );
    }
    assert!(!missing.exists());
    assert_eq!(fs::read_link(linked).unwrap(), valid);
    assert_eq!(fs::read_to_string(file).unwrap(), "fixture");
}

#[test]
fn run_update_and_clean_json_paths() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());

    set_update_tool(ToolKind::Rust, Err("nope".into()));
    let cli = Cli::parse_from(["upkit", "-y", "update", "rust"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    ctx.quiet = true;
    set_env_var("PATH", Some(bindir.display().to_string()));
    assert!(run(&cli, &mut ctx).is_err());

    set_update_tool(ToolKind::Rust, Err("nope".into()));
    let cli = Cli::parse_from(["upkit", "--json", "-y", "update", "rust"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    assert!(run(&cli, &mut ctx).is_err());

    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    let cli = Cli::parse_from(["upkit", "--json", "--dry-run", "-y", "clean", "go"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    let cli = Cli::parse_from(["upkit", "-y", "clean", "go"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    let tool_root = home.join("go");
    fs::write(&tool_root, b"file").unwrap();
    assert!(run(&cli, &mut ctx).is_err());

    let cli = Cli::parse_from(["upkit", "--json", "-y", "clean", "go"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    fs::write(&tool_root, b"file").unwrap();
    assert!(run(&cli, &mut ctx).is_err());
}

#[test]
fn managed_cleanup_json_dry_run_is_one_report_and_changes_nothing() {
    use std::process::Command;
    let dir = tempdir().unwrap();
    let home = dir.path().join("managed");
    let bin = dir.path().join("bin");
    fs::create_dir_all(home.join("go")).unwrap();
    fs::write(home.join("go/fixture"), "keep").unwrap();
    for command in ["clean", "uninstall"] {
        let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args([
                "--json",
                "--dry-run",
                "--non-interactive",
                "--yes",
                "--home",
            ])
            .arg(&home)
            .arg("--bindir")
            .arg(&bin)
            .args([command, "go"])
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
        assert_eq!(report["command"], command);
        assert_eq!(report["dry_run"], true);
        assert_eq!(report["results"][0]["executed"], false);
        assert_eq!(fs::read_to_string(home.join("go/fixture")).unwrap(), "keep");
        assert!(!bin.exists());
    }
}

#[test]
fn run_doctor_and_self_update_with_spinners() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let _guard = reset_guard();
    set_env_var("UPKIT_INSTALLER", Some("cargo".to_string()));
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());

    let cli = Cli::parse_from(["upkit", "doctor"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    ctx.offline = true;
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    set_env_var("PATH", Some(bindir.display().to_string()));
    set_which("go", Some(std::path::PathBuf::from("/bin/go")));
    set_which("rustc", Some(std::path::PathBuf::from("/bin/rustc")));
    set_which("node", Some(std::path::PathBuf::from("/bin/node")));
    set_which("python3", Some(std::path::PathBuf::from("/bin/python3")));
    set_which("flutter", Some(std::path::PathBuf::from("/bin/flutter")));
    set_which("mojo", Some(std::path::PathBuf::from("/bin/mojo")));
    set_which("javac", Some(std::path::PathBuf::from("/bin/javac")));
    set_which("dotnet", Some(std::path::PathBuf::from("/bin/dotnet")));
    run(&cli, &mut ctx).unwrap();

    let cli = Cli::parse_from(["upkit", "-y", "self-update"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    set_which("cargo", Some(std::path::PathBuf::from("/bin/cargo")));
    set_run_output(
        "cargo",
        &["install", "--force", "upkit"],
        output_with_status(0, b"", b""),
    );
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn hooks_lock_poison_recovery() {
    test_support::poison_hooks_lock();
    let _guard = reset_guard();
}

#[test]
fn run_update_and_clean_selection_paths() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());

    for tool in ToolKind::all() {
        let report = ToolReport {
            tool,
            installed: None,
            latest: None,
            status: Status::UpToDate,
            method: tool_method(tool),
            notes: vec![],
        };
        set_check_tool(tool, Ok(report));
    }
    let cli = Cli::parse_from(["upkit", "update"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    let report = ToolReport {
        tool: ToolKind::Go,
        installed: None,
        latest: Some(Version {
            major: 1,
            minor: 0,
            patch: 0,
            pre: None,
        }),
        status: Status::Outdated,
        method: UpdateMethod::DirectDownload,
        notes: vec![],
    };
    set_check_tool(ToolKind::Go, Ok(report));
    set_update_tool(ToolKind::Go, Ok(()));
    let cli = Cli::parse_from(["upkit", "-y", "update"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    ctx.quiet = true;
    set_env_var("PATH", Some(bindir.display().to_string()));
    run(&cli, &mut ctx).unwrap();

    for tool in ToolKind::all() {
        set_update_tool(tool, Ok(()));
    }
    let cli = Cli::parse_from(["upkit", "-y", "--dry-run", "clean"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    let cli = Cli::parse_from(["upkit", "-y", "--dry-run", "update", "--all"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    ctx.quiet = true;
    set_env_var("PATH", Some(bindir.display().to_string()));
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn run_update_and_clean_cancel_paths() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");

    let prompt = Arc::new(TestPrompt::default());
    for tool in ToolKind::all() {
        let report = ToolReport {
            tool,
            installed: None,
            latest: None,
            status: Status::UpToDate,
            method: tool_method(tool),
            notes: vec![],
        };
        set_check_tool(tool, Ok(report));
    }
    let report = ToolReport {
        tool: ToolKind::Go,
        installed: None,
        latest: Some(Version {
            major: 1,
            minor: 0,
            patch: 0,
            pre: None,
        }),
        status: Status::Outdated,
        method: tool_method(ToolKind::Go),
        notes: vec![],
    };
    set_check_tool(ToolKind::Go, Ok(report));
    prompt.push_selection(vec![0]);
    prompt.push_confirm(false);
    let cli = Cli::parse_from(["upkit", "update"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    let prompt = Arc::new(TestPrompt::default());
    let report = ToolReport {
        tool: ToolKind::Go,
        installed: None,
        latest: Some(Version {
            major: 1,
            minor: 0,
            patch: 0,
            pre: None,
        }),
        status: Status::Outdated,
        method: tool_method(ToolKind::Go),
        notes: vec![],
    };
    set_check_tool(ToolKind::Go, Ok(report));
    set_update_tool(ToolKind::Go, Ok(()));
    prompt.push_selection(vec![0]);
    prompt.push_confirm(true);
    let cli = Cli::parse_from(["upkit", "update"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    ctx.quiet = true;
    set_env_var("PATH", Some(bindir.display().to_string()));
    run(&cli, &mut ctx).unwrap();

    let prompt = Arc::new(TestPrompt::default());
    prompt.push_selection(vec![0]);
    prompt.push_confirm(false);
    let cli = Cli::parse_from(["upkit", "clean"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    ctx.dry_run = true;
    run(&cli, &mut ctx).unwrap();

    let prompt = Arc::new(TestPrompt::default());
    prompt.push_selection(vec![0]);
    prompt.push_confirm(true);
    let cli = Cli::parse_from(["upkit", "--dry-run", "clean"]);
    let mut ctx = ctx_from_cli(&cli, home.clone(), bindir.clone(), prompt.clone());
    run(&cli, &mut ctx).unwrap();

    let cli = Cli::parse_from(["upkit", "--json", "clean"]);
    let mut ctx = ctx_from_cli(
        &cli,
        home.clone(),
        bindir.clone(),
        Arc::new(TestPrompt::default()),
    );
    assert!(run(&cli, &mut ctx).is_err());

    let cli = Cli::parse_from(["upkit", "-y", "--dry-run", "clean", "--all"]);
    let mut ctx = ctx_from_cli(
        &cli,
        home.clone(),
        bindir.clone(),
        Arc::new(TestPrompt::default()),
    );
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn run_self_update_confirm_true() {
    let _guard = reset_guard();
    set_env_var("UPKIT_INSTALLER", Some("cargo".to_string()));
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    prompt.push_confirm(true);
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    set_which("cargo", Some(std::path::PathBuf::from("/bin/cargo")));
    ctx.offline = false;
    ctx.dry_run = true;
    ctx.stdin_is_tty = true;
    run_self_update(&ctx, false).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn clean_tool_empty_bins_and_symlink_skip() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(home.clone(), bindir.clone(), prompt);

    let tool_root = sealed_tool_root_fixture(&home, &bindir, ToolKind::Go);
    let active_target = fs::read_link(tool_root.join("active")).unwrap();
    assert_eq!(fs::read_dir(active_target.join("bin")).unwrap().count(), 0);
    installation_identity::record_active_link(&tool_root, &bindir, ToolKind::Go).unwrap();
    reviewed_clean_tool(&ctx, ToolKind::Go).unwrap();
    assert!(!tool_root.join("active").exists());
    assert!(!active_target.exists());

    let outside = dir.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let link_path = bindir.join("go");
    atomic_symlink(&outside, &link_path).unwrap();
    assert!(reviewed_clean_tool(&ctx, ToolKind::Go).is_err());
    assert!(link_path.exists());
}

#[test]
fn run_doctor_metadata_ok() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    set_env_var("PATH", Some(bindir.display().to_string()));
    set_which("go", Some(std::path::PathBuf::from("/bin/go")));
    set_which("rustc", Some(std::path::PathBuf::from("/bin/rustc")));
    set_which("node", Some(std::path::PathBuf::from("/bin/node")));
    set_which("python3", Some(std::path::PathBuf::from("/bin/python3")));
    set_which("flutter", Some(std::path::PathBuf::from("/bin/flutter")));
    set_which("mojo", Some(std::path::PathBuf::from("/bin/mojo")));
    set_which("javac", Some(std::path::PathBuf::from("/bin/javac")));
    set_which("dotnet", Some(std::path::PathBuf::from("/bin/dotnet")));
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(home, bindir, prompt);
    ctx.offline = true;
    run_doctor(&ctx, false).unwrap();
}

#[test]
fn download_to_temp_progress_overwrite() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.progress_overwrite = true;
    let url = "https://example.com/progress";
    set_http_plan(url, vec![Ok(MockResponse::new(vec![1, 2, 3], Some(3)))]);
    let tmp = download_to_temp(&ctx, url).unwrap();
    assert_eq!(fs::read(tmp.path()).unwrap(), vec![1, 2, 3]);
}

#[test]
fn main_with_completions_sets_quiet_paths() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));
    set_data_local_dir(Some(home));
    let code = main_with(Cli::parse_from(["upkit", "completions", "bash"]));
    assert_eq!(code, std::process::ExitCode::SUCCESS);
}

#[test]
fn run_paths_warns_missing_status() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));
    let cli = Cli::parse_from(["upkit", "--dry-run", "paths"]);
    let mut ctx = ctx_from_cli(&cli, home, bindir, prompt);
    run(&cli, &mut ctx).unwrap();
}

#[test]
fn run_doctor_writable_paths_coverage() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&home).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&home, perms).unwrap();

        let mut perms = fs::metadata(&bindir).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&bindir, perms).unwrap();
    }
    set_env_var("PATH", Some(bindir.display().to_string()));
    set_which("go", Some(std::path::PathBuf::from("/bin/go")));
    set_which("rustc", Some(std::path::PathBuf::from("/bin/rustc")));
    set_which("node", Some(std::path::PathBuf::from("/bin/node")));
    set_which("python3", Some(std::path::PathBuf::from("/bin/python3")));
    set_which("flutter", Some(std::path::PathBuf::from("/bin/flutter")));
    set_which("mojo", Some(std::path::PathBuf::from("/bin/mojo")));
    set_which("javac", Some(std::path::PathBuf::from("/bin/javac")));
    set_which("dotnet", Some(std::path::PathBuf::from("/bin/dotnet")));
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(home, bindir, prompt);
    ctx.offline = true;
    run_doctor(&ctx, false).unwrap();
}
