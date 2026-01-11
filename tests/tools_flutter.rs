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

fn make_flutter_tar_gz() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
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

fn make_flutter_tar_gz_missing_root() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut tar = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_cksum();
        tar.append_data(&mut header, "other/bin/flutter", std::io::empty())
            .unwrap();
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
fn flutter_installed_version_fallback_to_root() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let root = dir.path().join("flutter");
    let bin_dir = root.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let bin = bin_dir.join("flutter");
    std::fs::write(&bin, b"").unwrap();
    std::fs::write(root.join("version"), "3.2.1\n").unwrap();
    set_run_output(
        bin.to_string_lossy().as_ref(),
        &["--version", "--machine"],
        output_with_status(1, b"", b""),
    );
    let v = flutter_installed_version(&bin).unwrap();
    assert_eq!(v.to_string(), "3.2.1");
}

#[test]
fn flutter_installed_version_parses_json() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let root = dir.path().join("flutter");
    let bin_dir = root.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let bin = bin_dir.join("flutter");
    std::fs::write(&bin, b"").unwrap();
    set_run_output(
        bin.to_string_lossy().as_ref(),
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"3.5.0"}"#, b""),
    );
    let v = flutter_installed_version(&bin).unwrap();
    assert_eq!(v.to_string(), "3.5.0");
}

#[test]
fn flutter_installed_and_check() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("flutter", Some(PathBuf::from("/bin/flutter")));
    set_run_output(
        "/bin/flutter",
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"3.1.0"}"#, b""),
    );
    set_run_output(
        "/bin/flutter",
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"3.1.0"}"#, b""),
    );
    let v = flutter_installed_version(std::path::Path::new("/bin/flutter")).unwrap();
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
        "/bin/flutter",
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
fn update_flutter_install_dry_run() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.dry_run = true;
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
    update_flutter(&ctx).unwrap();
}

#[test]
fn update_flutter_install_tar_gz() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.quiet = true;
    std::fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("flutter", None);
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let json = r#"{"releases":[{"channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.gz","hash":"abc"}]}"#;
    let download_url = "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_3.1.0-stable.tar.gz";
    let archive = make_flutter_tar_gz();
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    set_http_plan(download_url, vec![Ok(MockResponse::new(archive, None))]);
    update_flutter(&ctx).unwrap();
}

#[test]
fn update_flutter_install_missing_layout() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.quiet = true;
    std::fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("flutter", None);
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let json = r#"{"releases":[{"channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.gz","hash":"abc"}]}"#;
    let download_url = "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_3.1.0-stable.tar.gz";
    let archive = make_flutter_tar_gz_missing_root();
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    set_http_plan(download_url, vec![Ok(MockResponse::new(archive, None))]);
    let err = update_flutter(&ctx).unwrap_err();
    assert!(err.to_string().contains("missing flutter/"));
}

#[test]
fn update_flutter_install_unsupported_archive() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.quiet = true;
    set_which("flutter", None);
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let json = r#"{"releases":[{"channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.zip","hash":"abc"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let download_url = "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_3.1.0-stable.zip";
    set_http_plan(
        download_url,
        vec![Ok(MockResponse::new(vec![1, 2], Some(2)))],
    );
    let err = update_flutter(&ctx).unwrap_err();
    assert!(
        err.to_string()
            .contains("unsupported flutter archive format")
    );
}

#[test]
fn update_flutter_active_link_error() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    std::fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("flutter", None);
    let tool_root = ctx.home.join("flutter");
    std::fs::create_dir_all(tool_root.join("active.tmp")).unwrap();
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let archive = make_flutter_tar_xz();
    let json = r#"{"releases":[{"channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.xz","hash":"abc"}]}"#;
    let download_url = "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_3.1.0-stable.tar.xz";
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    set_http_plan(download_url, vec![Ok(MockResponse::new(archive, None))]);
    let err = update_flutter(&ctx).unwrap_err();
    assert!(err.to_string().contains("link flutter active"));
}

#[test]
fn update_flutter_prune_warn() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    std::fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("flutter", None);
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let archive = make_flutter_tar_xz();
    let json = r#"{"releases":[{"channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.xz","hash":"abc"}]}"#;
    let download_url = "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_3.1.0-stable.tar.xz";
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    set_http_plan(download_url, vec![Ok(MockResponse::new(archive, None))]);
    upkit::test_support::set_prune_tool_versions_error(Some("prune".to_string()));
    update_flutter(&ctx).unwrap();
    upkit::test_support::set_prune_tool_versions_error(None);
}

#[test]
fn update_flutter_upgrade_uses_bindir() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    std::fs::create_dir_all(&ctx.bindir).unwrap();
    let bindir_flutter = ctx.bindir.join("flutter");
    std::fs::write(&bindir_flutter, b"").unwrap();
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let json = r#"{"releases":[{"channel":"stable","version":"3.2.0","archive":"stable/linux/flutter_linux_3.2.0-stable.tar.xz","hash":"abc"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_run_output(
        bindir_flutter.to_string_lossy().as_ref(),
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"3.0.0"}"#, b""),
    );
    set_run_output(
        bindir_flutter.to_string_lossy().as_ref(),
        &["upgrade"],
        output_with_status(0, b"", b""),
    );
    update_flutter(&ctx).unwrap();
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
    let hash = "dummy-hash";
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
        "/bin/flutter",
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
        "/bin/flutter",
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
        "/bin/flutter",
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
        "/bin/flutter",
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"3.1.0"}"#, b""),
    );
    set_which("flutter", Some(PathBuf::from("/bin/flutter")));
    update_flutter(&ctx).unwrap();
}
