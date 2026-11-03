use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tempfile::tempdir;
use upkit::test_support::{
    MockResponse, TestPrompt, base_ctx, output_with_status, reset_guard, set_http_plan,
    set_run_output, set_which,
};
use upkit::tools::rust::{check_rust, rust_latest_stable, update_rust};
use upkit::{Ctx, Status};

fn ctx_with_dirs() -> (Ctx, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    (ctx, dir)
}

fn rustup_proxy(dir: &tempfile::TempDir) -> (PathBuf, PathBuf) {
    let bin = dir.path().join("rustup-fixture");
    fs::create_dir_all(&bin).unwrap();
    let extension = if cfg!(windows) { ".exe" } else { "" };
    let rustup = bin.join(format!("rustup{extension}"));
    let rustc = bin.join(format!("rustc{extension}"));
    fs::write(&rustup, b"rustup fixture").unwrap();
    fs::hard_link(&rustup, &rustc).unwrap();
    (rustc, rustup)
}

fn rustup_show_active(rustup: &Path, toolchain: &str) {
    set_run_output(
        rustup.to_string_lossy().as_ref(),
        &["show", "active-toolchain"],
        output_with_status(
            0,
            format!("{toolchain} (fixture override)\n").as_bytes(),
            b"",
        ),
    );
}

fn rustup_targets(rustup: &Path, toolchain: &str, targets: &[&str]) {
    set_run_output(
        rustup.to_string_lossy().as_ref(),
        &["target", "list", "--toolchain", toolchain],
        output_with_status(0, format!("{}\n", targets.join("\n")).as_bytes(), b""),
    );
}

fn write_rustup_fixture(dir: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf) {
    let bin = dir.path().join("rust-fixture-bin");
    fs::create_dir_all(&bin).unwrap();
    let extension = if cfg!(windows) { ".exe" } else { "" };
    let rustup = bin.join(format!("rustup{extension}"));
    let rustc = bin.join(format!("rustc{extension}"));
    let managed_rustc = bin.join(format!("managed-rustc{extension}"));
    fs::write(&rustup, b"rustup fixture").unwrap();
    fs::write(&rustc, b"distribution rustc fixture").unwrap();
    fs::write(&managed_rustc, b"rustup-managed rustc fixture").unwrap();
    (rustc, rustup, managed_rustc)
}

fn pinned_toolchain_update_error(
    toolchain: &str,
    installed: &str,
    channel: &str,
    latest: &str,
) -> String {
    let _guard = reset_guard();
    let (mut ctx, dir) = ctx_with_dirs();
    ctx.force = true;
    let (rustc, rustup) = rustup_proxy(&dir);
    set_which("rustc", Some(rustc));
    set_which("rustup", Some(rustup.clone()));
    set_run_output(
        "rustc",
        &["--version"],
        output_with_status(0, format!("rustc {installed}").as_bytes(), b""),
    );
    set_http_plan(
        &format!("https://static.rust-lang.org/dist/channel-rust-{channel}.toml"),
        vec![Ok(MockResponse::new(
            format!("[pkg.rustc]\nversion = \"{latest}\"").into_bytes(),
            None,
        ))],
    );
    rustup_show_active(&rustup, toolchain);
    rustup_targets(&rustup, toolchain, &["x86_64-unknown-linux-gnu"]);

    update_rust(&ctx).unwrap_err().to_string()
}

#[test]
fn rust_latest_and_check() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
    let toml = r#"
        [pkg.rustc]
        version = "1.77.1 (abc 2024-01-01)"
    "#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(toml.as_bytes().to_vec(), None))],
    );
    let v = rust_latest_stable(&ctx).unwrap();
    assert_eq!(v.to_string(), "1.77.1");

    set_http_plan(
        url,
        vec![Ok(MockResponse::new(toml.as_bytes().to_vec(), None))],
    );
    set_which("rustc", Some(PathBuf::from("/bin/rustc")));
    set_run_output(
        "rustc",
        &["--version"],
        output_with_status(0, b"rustc 1.77.1 (abc 2024-01-01)", b""),
    );
    let report = check_rust(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));
}

#[test]
fn rust_latest_manifest_errors() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
    set_http_plan(url, vec![Err("no".to_string())]);
    let err = rust_latest_stable(&ctx).unwrap_err();
    assert!(err.to_string().contains("request failed"));

    let toml = "[nope]";
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(toml.as_bytes().to_vec(), None))],
    );
    let err = rust_latest_stable(&ctx).unwrap_err();
    assert!(err.to_string().contains("pkg.rustc.version"));
}

#[test]
fn rust_check_outdated() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
    let toml = r#"
        [pkg.rustc]
        version = "1.77.1 (abc 2024-01-01)"
    "#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(toml.as_bytes().to_vec(), None))],
    );
    set_which("rustc", Some(PathBuf::from("/bin/rustc")));
    set_run_output(
        "rustc",
        &["--version"],
        output_with_status(0, b"rustc 1.77.0 (abc 2024-01-01)", b""),
    );
    let report = check_rust(&ctx).unwrap();
    assert!(matches!(report.status, Status::Outdated));
}

#[test]
fn rust_nightly_check_does_not_compare_semver_freshness() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_http_plan(
        "https://static.rust-lang.org/dist/channel-rust-nightly.toml",
        vec![Ok(MockResponse::new(
            b"[pkg.rustc]\nversion = \"1.90.0-nightly (abc 2025-10-15)\"".to_vec(),
            None,
        ))],
    );
    set_which("rustc", Some(PathBuf::from("/fixture/rustc")));
    set_run_output(
        "rustc",
        &["--version"],
        output_with_status(0, b"rustc 1.90.0-nightly (abc 2025-10-14)", b""),
    );

    let report = check_rust(&ctx).unwrap();
    assert!(matches!(report.status, Status::Unknown));
    assert_eq!(report.latest.unwrap().to_string(), "1.90.0-nightly");
}

#[test]
fn rust_check_not_installed() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
    let toml = r#"
        [pkg.rustc]
        version = "1.77.1 (abc 2024-01-01)"
    "#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(toml.as_bytes().to_vec(), None))],
    );
    set_which("rustc", None);
    let report = check_rust(&ctx).unwrap();
    assert!(matches!(report.status, Status::NotInstalled));
}

#[test]
fn rust_check_offline_distinguishes_missing_executable_from_unknown_version() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.offline = true;
    set_which("rustc", None);
    let missing = check_rust(&ctx).unwrap();
    assert!(matches!(missing.status, Status::NotInstalled));
    assert!(missing.notes.iter().any(|note| note.contains("on PATH")));

    set_which("rustc", Some(PathBuf::from("/fixture/rustc")));
    let unverified = check_rust(&ctx).unwrap();
    assert!(matches!(unverified.status, Status::Unknown));
    assert!(unverified.installed.is_none());
}

#[test]
fn rust_check_failed_probe_is_unknown_not_missing() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("rustc", Some(PathBuf::from("/fixture/rustc")));
    set_run_output(
        "rustc",
        &["--version"],
        output_with_status(1, b"", b"unavailable"),
    );
    let report = check_rust(&ctx).unwrap();
    assert!(matches!(report.status, Status::Unknown));
    assert!(report.latest.is_none());
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("could not be verified"))
    );
}

#[test]
fn update_rust_paths() {
    let _guard = reset_guard();
    let (mut ctx, dir) = ctx_with_dirs();
    ctx.offline = true;
    assert!(update_rust(&ctx).is_err());

    ctx.offline = false;
    ctx.force = true;
    let url = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
    let toml = r#"
        [pkg.rustc]
        version = "1.77.1 (abc 2024-01-01)"
    "#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(toml.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(toml.as_bytes().to_vec(), None)),
        ],
    );
    let (rustc, rustup) = rustup_proxy(&dir);
    set_which("rustc", Some(rustc));
    set_run_output(
        "rustc",
        &["--version"],
        output_with_status(0, b"rustc 1.77.0 (abc 2024-01-01)", b""),
    );

    let rustup_program = rustup.to_string_lossy().to_string();
    set_which("rustup", Some(rustup.clone()));
    rustup_show_active(&rustup, "stable-x86_64-unknown-linux-gnu");
    rustup_show_active(&rustup, "stable-x86_64-unknown-linux-gnu");
    rustup_targets(
        &rustup,
        "stable-x86_64-unknown-linux-gnu",
        &["x86_64-unknown-linux-gnu"],
    );
    rustup_targets(
        &rustup,
        "stable-x86_64-unknown-linux-gnu",
        &["x86_64-unknown-linux-gnu"],
    );
    set_run_output(
        &rustup_program,
        &["update", "stable-x86_64-unknown-linux-gnu"],
        output_with_status(1, b"", b""),
    );
    assert!(update_rust(&ctx).is_err());

    set_run_output(
        &rustup_program,
        &["update", "stable-x86_64-unknown-linux-gnu"],
        output_with_status(0, b"", b""),
    );
    update_rust(&ctx).unwrap();
}

#[test]
fn update_rust_missing_rustup() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
    let toml = r#"
        [pkg.rustc]
        version = "1.77.1 (abc 2024-01-01)"
    "#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(toml.as_bytes().to_vec(), None))],
    );
    set_which("rustc", Some(PathBuf::from("/bin/rustc")));
    set_run_output(
        "rustc",
        &["--version"],
        output_with_status(0, b"rustc 1.77.0 (abc 2024-01-01)", b""),
    );
    set_which("rustup", None);
    let err = update_rust(&ctx).unwrap_err();
    assert!(err.to_string().contains("rustup not found"));
}

#[cfg(unix)]
#[test]
fn update_rust_dry_run_does_not_run_rustc_or_rustup_and_reports_unknown() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = reset_guard();
    let (mut ctx, dir) = ctx_with_dirs();
    ctx.dry_run = true;

    let rustc = dir.path().join("rustc");
    let rustup = dir.path().join("rustup");
    fs::write(&rustc, b"rustc fixture").unwrap();
    fs::write(
        &rustup,
        "#!/bin/sh\nprintf x >> \"$0.ran\"\ncase \"$1:$2\" in\n  which:rustc) printf '%s\\n' \"${0%/*}/rustc\" ;;\n  show:active-toolchain) printf '%s\\n' 'stable-x86_64-unknown-linux-gnu (fixture override)' ;;\n  target:list) printf '%s\\n' 'x86_64-unknown-linux-gnu' ;;\nesac\n",
    )
    .unwrap();
    fs::set_permissions(&rustup, fs::Permissions::from_mode(0o700)).unwrap();
    let rustup_sentinel = dir.path().join("rustup.ran");

    set_which("rustc", Some(rustc));
    set_which("rustup", Some(rustup));
    for _ in 0..2 {
        set_run_output(
            "rustc",
            &["--version"],
            output_with_status(0, b"rustc 1.90.0-custom", b""),
        );
    }

    let report = check_rust(&ctx).unwrap();
    assert!(report.installed.is_none());
    assert!(report.latest.is_none());
    assert!(matches!(report.status, Status::Unknown));
    assert!(
        report
            .notes
            .iter()
            .any(|note| note == "Rust version and channel were not inspected in dry-run mode.")
    );

    update_rust(&ctx).unwrap();
    assert!(!rustup_sentinel.exists());

    let args = vec!["--version".to_string()];
    assert!(upkit::test_support::take_run_output("rustc", &args).is_some());
    assert!(upkit::test_support::take_run_output("rustc", &args).is_some());
    assert!(upkit::test_support::take_run_output("rustc", &args).is_none());
}

#[test]
fn update_rust_refuses_distribution_rustc_even_when_rustup_is_also_installed() {
    let _guard = reset_guard();
    let (mut ctx, dir) = ctx_with_dirs();
    ctx.force = true;
    let (rustc, rustup, managed_rustc) = write_rustup_fixture(&dir);
    let rustup_program = rustup.to_string_lossy().to_string();
    set_which("rustc", Some(rustc));
    set_which("rustup", Some(rustup));
    set_run_output(
        "rustc",
        &["--version"],
        output_with_status(0, b"rustc 1.77.0 (abc 2024-01-01)", b""),
    );
    set_http_plan(
        "https://static.rust-lang.org/dist/channel-rust-stable.toml",
        vec![Ok(MockResponse::new(
            b"[pkg.rustc]\nversion = \"1.77.1 (abc 2024-01-02)\"".to_vec(),
            None,
        ))],
    );
    set_run_output(
        &rustup_program,
        &["which", "rustc"],
        output_with_status(0, format!("{}\n", managed_rustc.display()).as_bytes(), b""),
    );

    let error = update_rust(&ctx).unwrap_err();
    assert!(error.to_string().contains("not managed by the rustup"));
}

#[test]
fn update_rust_accepts_a_toolchain_binary_reported_by_rustup() {
    let _guard = reset_guard();
    let (mut ctx, dir) = ctx_with_dirs();
    ctx.force = true;
    let (_distribution_rustc, rustup, managed_rustc) = write_rustup_fixture(&dir);
    let rustup_program = rustup.to_string_lossy().to_string();
    let toolchain_rustc = managed_rustc.to_string_lossy().to_string();
    set_which("rustc", Some(managed_rustc));
    set_which("rustup", Some(rustup.clone()));
    set_run_output(
        "rustc",
        &["--version"],
        output_with_status(0, b"rustc 1.77.0 (abc 2024-01-01)", b""),
    );
    set_http_plan(
        "https://static.rust-lang.org/dist/channel-rust-stable.toml",
        vec![Ok(MockResponse::new(
            b"[pkg.rustc]\nversion = \"1.77.1 (abc 2024-01-02)\"".to_vec(),
            None,
        ))],
    );
    set_run_output(
        &rustup_program,
        &["which", "rustc"],
        output_with_status(0, format!("{toolchain_rustc}\n").as_bytes(), b""),
    );
    rustup_show_active(&rustup, "stable-x86_64-unknown-linux-gnu");
    rustup_targets(
        &rustup,
        "stable-x86_64-unknown-linux-gnu",
        &["x86_64-unknown-linux-gnu"],
    );
    set_run_output(
        &rustup_program,
        &["update", "stable-x86_64-unknown-linux-gnu"],
        output_with_status(0, b"", b""),
    );

    update_rust(&ctx).unwrap();
}

#[test]
fn update_rust_refuses_to_update_a_pinned_nightly_toolchain() {
    let error = pinned_toolchain_update_error(
        "nightly-2025-10-15-x86_64-unknown-linux-gnu",
        "1.90.0-nightly (abc 2025-10-14)",
        "nightly",
        "1.90.0-nightly (abc 2025-10-15)",
    );
    assert!(error.contains("is pinned"));
}

#[test]
fn update_rust_refuses_to_update_a_version_pinned_toolchain() {
    let error = pinned_toolchain_update_error(
        "1.77.0-x86_64-unknown-linux-gnu",
        "1.77.0 (abc 2024-01-01)",
        "stable",
        "1.77.1 (abc 2024-01-02)",
    );
    assert!(error.contains("is pinned"));
}

#[test]
fn update_rust_refuses_channel_prefixed_custom_toolchains() {
    for (toolchain, installed, channel, latest) in [
        (
            "stable-custom",
            "1.77.0 (abc 2024-01-01)",
            "stable",
            "1.77.1 (abc 2024-01-02)",
        ),
        (
            "nightly-custom",
            "1.90.0-nightly (abc 2025-10-14)",
            "nightly",
            "1.90.0-nightly (abc 2025-10-15)",
        ),
        (
            "stable-foo-bar-baz",
            "1.77.0 (abc 2024-01-01)",
            "stable",
            "1.77.1 (abc 2024-01-02)",
        ),
    ] {
        let error = pinned_toolchain_update_error(toolchain, installed, channel, latest);
        assert!(error.contains("is pinned"), "{toolchain}: {error}");
    }
}

#[test]
fn update_rust_up_to_date() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
    let toml = r#"
        [pkg.rustc]
        version = "1.77.1 (abc 2024-01-01)"
    "#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(toml.as_bytes().to_vec(), None))],
    );
    set_which("rustc", Some(PathBuf::from("/bin/rustc")));
    set_run_output(
        "rustc",
        &["--version"],
        output_with_status(0, b"rustc 1.77.1 (abc 2024-01-01)", b""),
    );
    set_which("rustup", Some(PathBuf::from("/fixture/rustup")));
    update_rust(&ctx).unwrap();
}
