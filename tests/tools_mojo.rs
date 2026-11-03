use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use upkit::test_support::{
    MockResponse, TestPrompt, base_ctx, output_with_status, reset_guard, set_http_plan,
    set_run_output, set_which,
};
use upkit::tools::mojo::{check_mojo, mojo_latest, update_mojo};
use upkit::{Ctx, Status};

const RELEASES_URL: &str = "https://mojolang.org/releases/";

fn ctx_with_dirs() -> (Ctx, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    (ctx, dir)
}

fn releases_page(version: &str) -> String {
    format!("<span>Latest release: {version}</span>")
}

#[test]
fn mojo_latest_and_check() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let page = releases_page("1.0.0");
    set_http_plan(
        RELEASES_URL,
        vec![Ok(MockResponse::new(page.as_bytes().to_vec(), None))],
    );
    assert_eq!(mojo_latest(&ctx).unwrap().to_string(), "1.0.0");

    set_which("mojo", Some(PathBuf::from("/bin/mojo")));
    set_run_output(
        "mojo",
        &["--version"],
        output_with_status(0, b"mojo 1.0.0b2", b""),
    );
    set_http_plan(
        RELEASES_URL,
        vec![Ok(MockResponse::new(page.into_bytes(), None))],
    );
    let report = check_mojo(&ctx).unwrap();
    assert_eq!(report.installed.unwrap().to_string(), "1.0.0-b2");
    assert!(matches!(report.status, Status::Outdated));
}

#[test]
fn mojo_check_not_installed() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("mojo", None);
    let page = releases_page("1.0.0");
    set_http_plan(
        RELEASES_URL,
        vec![Ok(MockResponse::new(page.into_bytes(), None))],
    );
    let report = check_mojo(&ctx).unwrap();
    assert!(matches!(report.status, Status::NotInstalled));
}

#[test]
fn mojo_found_but_unverifiable_is_unknown_not_not_installed() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("mojo", Some(PathBuf::from("/fixture/mojo")));
    set_run_output(
        "mojo",
        &["--version"],
        output_with_status(1, b"", b"fixture failure"),
    );
    let page = releases_page("1.0.0");
    set_http_plan(
        RELEASES_URL,
        vec![Ok(MockResponse::new(page.into_bytes(), None))],
    );

    let report = check_mojo(&ctx).unwrap();

    assert!(report.installed.is_none());
    assert_eq!(report.status, Status::Unknown);
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("could not be verified"))
    );
}

#[test]
fn dry_run_does_not_execute_a_mojo_wrapper() {
    use upkit::test_support::take_run_output;

    let _guard = reset_guard();
    let (mut ctx, dir) = ctx_with_dirs();
    ctx.dry_run = true;
    ctx.quiet = true;
    set_which("mojo", Some(dir.path().join("mojo")));
    set_which("pixi", None);
    set_which("uv", Some(dir.path().join("uv")));
    let page = releases_page("1.0.0");
    set_http_plan(
        RELEASES_URL,
        vec![
            Ok(MockResponse::new(page.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(page.into_bytes(), None)),
        ],
    );
    let args = vec!["--version".to_owned()];
    set_run_output(
        "mojo",
        &["--version"],
        output_with_status(0, b"mojo 1.0.0", b""),
    );
    let report = check_mojo(&ctx).unwrap();
    assert_eq!(report.status, Status::Unknown);
    assert!(report.installed.is_none());
    assert!(take_run_output("mojo", &args).is_some());
    set_run_output(
        "mojo",
        &["--version"],
        output_with_status(0, b"mojo 1.0.0", b""),
    );
    update_mojo(&ctx).unwrap();
    assert!(take_run_output("mojo", &args).is_some());
    assert!(!ctx.home.exists() && !ctx.bindir.exists());
}

#[test]
fn update_mojo_skips_pixi_outside_project() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("mojo", Some(PathBuf::from("/bin/mojo")));
    set_run_output(
        "mojo",
        &["--version"],
        output_with_status(0, b"mojo 0.26.2", b""),
    );
    set_which("pixi", Some(PathBuf::from("/bin/pixi")));
    set_which("uv", Some(PathBuf::from("/bin/uv")));
    set_which("python3", None);
    set_which("python", None);
    set_run_output(
        "uv",
        &["pip", "install", "--system", "--upgrade", "mojo"],
        output_with_status(0, b"", b""),
    );
    let page = releases_page("1.0.0");
    set_http_plan(
        RELEASES_URL,
        vec![Ok(MockResponse::new(page.into_bytes(), None))],
    );
    update_mojo(&ctx).unwrap();
}

#[test]
fn update_mojo_falls_back_to_uv() {
    let _guard = reset_guard();
    let (ctx, dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let python_bin = dir.path().join("python-bin");
    fs::create_dir_all(&python_bin).unwrap();
    fs::write(python_bin.join("python3"), b"").unwrap();
    fs::write(python_bin.join("mojo"), b"").unwrap();
    set_which("python3", Some(python_bin.join("python3")));
    set_which("mojo", Some(PathBuf::from("/bin/mojo")));
    set_run_output(
        "mojo",
        &["--version"],
        output_with_status(0, b"mojo 0.26.2", b""),
    );
    set_which("pixi", None);
    set_which("uv", Some(PathBuf::from("/bin/uv")));
    set_run_output(
        "uv",
        &["pip", "install", "--system", "--upgrade", "mojo"],
        output_with_status(0, b"", b""),
    );
    let page = releases_page("1.0.0");
    set_http_plan(
        RELEASES_URL,
        vec![Ok(MockResponse::new(page.into_bytes(), None))],
    );
    update_mojo(&ctx).unwrap();
    assert!(ctx.bindir.join("mojo").exists());
}
