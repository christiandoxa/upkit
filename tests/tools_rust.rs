use std::path::PathBuf;
use std::sync::Arc;
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
fn update_rust_paths() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
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
    set_which("rustc", Some(PathBuf::from("/bin/rustc")));
    set_run_output(
        "rustc",
        &["--version"],
        output_with_status(0, b"rustc 1.77.0 (abc 2024-01-01)", b""),
    );

    set_which("rustup", Some(PathBuf::from("/bin/rustup")));
    set_run_output(
        "rustup",
        &["update", "stable"],
        output_with_status(1, b"", b""),
    );
    assert!(update_rust(&ctx).is_err());

    set_run_output(
        "rustup",
        &["update", "stable"],
        output_with_status(0, b"", b""),
    );
    update_rust(&ctx).unwrap();
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
    update_rust(&ctx).unwrap();
}
