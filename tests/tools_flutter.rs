use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use upkit::test_support::{
    MockResponse, TestPrompt, base_ctx, output_with_status, reset_guard, set_http_plan,
    set_run_output, set_which,
};
use upkit::tools::flutter::{
    check_flutter, flutter_installed_version, flutter_latest_stable, flutter_releases_url,
    update_flutter,
};
use upkit::{Ctx, Status};

fn ctx_with_dirs() -> (Ctx, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    (ctx, dir)
}

fn make_flutter_tar_xz() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let enc = xz2::write::XzEncoder::new(&mut bytes, 6);
        let mut tar = tar::Builder::new(enc);
        for path in ["flutter/bin/flutter", "flutter/bin/dart", "flutter/bin/pub"] {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_cksum();
            tar.append_data(&mut header, path, std::io::empty())
                .unwrap();
        }
        tar.finish().unwrap();
    }
    bytes
}

#[test]
fn flutter_releases_url_and_latest() {
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    assert!(flutter_releases_url(&ctx).unwrap().contains("linux"));
    ctx.os = "macos".into();
    assert!(flutter_releases_url(&ctx).unwrap().contains("macos"));
    ctx.os = "windows".into();
    assert!(flutter_releases_url(&ctx).unwrap().contains("windows"));
    ctx.os = "other".into();
    assert!(flutter_releases_url(&ctx).is_err());

    let _guard = reset_guard();
    ctx.os = "linux".into();
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let json = r#"{"releases":[{"channel":"stable","version":"3.10.0","archive":"stable/linux/flutter_linux_3.10.0-stable.tar.xz","hash":"abc"},{"channel":"stable","version":"3.9.0","archive":"stable/linux/flutter_linux_3.9.0-stable.tar.xz","hash":"def"},{"channel":"beta","version":"4.0.0","archive":"beta/linux/flutter_linux_4.0.0-beta.tar.xz","hash":"ghi"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let v = flutter_latest_stable(&ctx).unwrap();
    assert_eq!(v.to_string(), "3.10.0");
}

#[test]
fn flutter_latest_no_stable() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let json = r#"{"releases":[{"channel":"beta","version":"4.0.0","archive":"beta/linux/flutter_linux_4.0.0-beta.tar.xz","hash":"abc"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let err = flutter_latest_stable(&ctx).unwrap_err();
    assert!(err.to_string().contains("flutter latest stable"));
}

#[test]
fn flutter_installed_and_check() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("flutter", Some(PathBuf::from("/bin/flutter")));
    set_run_output(
        "flutter",
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"3.1.0"}"#, b""),
    );
    set_run_output(
        "flutter",
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"3.1.0"}"#, b""),
    );
    let v = flutter_installed_version(None).unwrap();
    assert_eq!(v.to_string(), "3.1.0");

    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let json = r#"{"releases":[{"channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.xz","hash":"abc"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let report = check_flutter(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));

    set_http_plan(
        url,
        vec![Ok(MockResponse::new(
            br#"{"releases":[{"channel":"stable","version":"3.2.0","archive":"stable/linux/flutter_linux_3.2.0-stable.tar.xz","hash":"abc"}]}"#
                .to_vec(),
            None,
        ))],
    );
    set_run_output(
        "flutter",
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"3.1.0"}"#, b""),
    );
    let report = check_flutter(&ctx).unwrap();
    assert!(matches!(report.status, Status::Outdated));
}

#[test]
fn flutter_check_not_installed() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("flutter", None);
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let json = r#"{"releases":[{"channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.xz","hash":"abc"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let report = check_flutter(&ctx).unwrap();
    assert!(matches!(report.status, Status::NotInstalled));
}

#[test]
fn flutter_check_uses_bindir() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let bindir_flutter = ctx.bindir.join("flutter");
    std::fs::create_dir_all(&ctx.bindir).unwrap();
    std::fs::write(&bindir_flutter, b"").unwrap();
    set_which("flutter", None);
    set_run_output(
        bindir_flutter.to_string_lossy().as_ref(),
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"3.1.0"}"#, b""),
    );
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let json = r#"{"releases":[{"channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.xz","hash":"abc"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let report = check_flutter(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));
}

#[test]
fn update_flutter_paths() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.offline = true;
    assert!(update_flutter(&ctx).is_err());

    ctx.offline = false;
    set_which("flutter", None);
    std::fs::create_dir_all(&ctx.bindir).unwrap();
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let archive = make_flutter_tar_xz();
    let hash = format!("{:x}", Sha256::digest(&archive));
    let json = format!(
        r#"{{"releases":[{{"channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.xz","hash":"{}"}}]}}"#,
        hash
    );
    let download_url = "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_3.1.0-stable.tar.xz";
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    set_http_plan(download_url, vec![Ok(MockResponse::new(archive, None))]);
    update_flutter(&ctx).unwrap();
    assert!(ctx.bindir.join("flutter").exists());
    std::fs::remove_file(ctx.bindir.join("flutter")).unwrap();

    set_which("flutter", Some(PathBuf::from("/bin/flutter")));
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_run_output(
        "flutter",
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"3.0.0"}"#, b""),
    );
    ctx.dry_run = true;
    update_flutter(&ctx).unwrap();

    ctx.dry_run = false;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_run_output(
        "flutter",
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"3.0.0"}"#, b""),
    );
    set_run_output("flutter", &["upgrade"], output_with_status(1, b"", b""));
    assert!(update_flutter(&ctx).is_err());

    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_run_output(
        "flutter",
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"3.0.0"}"#, b""),
    );
    set_run_output("flutter", &["upgrade"], output_with_status(0, b"", b""));
    update_flutter(&ctx).unwrap();

    ctx.force = false;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_run_output(
        "flutter",
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"3.1.0"}"#, b""),
    );
    set_which("flutter", Some(PathBuf::from("/bin/flutter")));
    update_flutter(&ctx).unwrap();
}
