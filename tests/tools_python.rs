use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use upkit::test_support::{
    MockResponse, TestPrompt, base_ctx, output_with_status, reset_guard, set_http_plan,
    set_prune_tool_versions_error, set_run_output, set_which,
};
use upkit::tools::python::{
    check_python, python_latest, python_pick_asset, python_target, update_python,
};
use upkit::{Ctx, Status, Version};

fn ctx_with_dirs() -> (Ctx, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    (ctx, dir)
}

#[test]
fn python_target_and_latest() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();
    assert_eq!(python_target(&ctx).unwrap(), "x86_64-unknown-linux-gnu");

    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = python_latest(&ctx).unwrap();
    assert_eq!(v.to_string(), "3.11.9");
}

#[test]
fn python_latest_picks_highest_matching_asset() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.8-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python-3.11.8.tar.zst"},{"name":"cpython-3.11.9-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python-3.11.9.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = python_latest(&ctx).unwrap();
    assert_eq!(v.to_string(), "3.11.9");
}

#[test]
fn python_target_variants() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "aarch64".into();
    assert_eq!(python_target(&ctx).unwrap(), "aarch64-unknown-linux-gnu");

    ctx.os = "macos".into();
    ctx.arch = "x86_64".into();
    assert_eq!(python_target(&ctx).unwrap(), "x86_64-apple-darwin");

    ctx.arch = "aarch64".into();
    assert_eq!(python_target(&ctx).unwrap(), "aarch64-apple-darwin");

    ctx.os = "windows".into();
    ctx.arch = "x86_64".into();
    assert!(python_target(&ctx).is_err());
}

#[test]
fn python_latest_no_match() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.zip","browser_download_url":"https://example.com/python.zip"},{"name":"cpython-3.11.9+20240224-aarch64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let err = python_latest(&ctx).unwrap_err();
    assert!(
        err.to_string()
            .contains("could not determine latest python version")
    );
}

#[test]
fn python_pick_asset_and_check() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();

    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = Version {
        major: 3,
        minor: 11,
        patch: 9,
        pre: None,
    };
    let asset = python_pick_asset(&ctx, &v).unwrap();
    assert!(asset.name.contains("x86_64-unknown-linux-gnu"));

    set_which("python3", None);
    set_which("python", None);
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let report = check_python(&ctx).unwrap();
    assert!(matches!(report.status, Status::NotInstalled));
}

#[test]
fn python_pick_asset_install_only() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();

    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"},{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu-install_only.tar.zst","browser_download_url":"https://example.com/python-install.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = Version {
        major: 3,
        minor: 11,
        patch: 9,
        pre: None,
    };
    let asset = python_pick_asset(&ctx, &v).unwrap();
    assert!(asset.name.contains("install_only"));
}

#[test]
fn python_check_fallback_binary() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("python3", None);
    set_which("python", Some(PathBuf::from("/bin/python")));
    set_run_output(
        "python",
        &["--version"],
        output_with_status(0, b"Python 3.11.9", b""),
    );
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let report = check_python(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));
}

#[test]
fn python_check_uses_bindir() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let bindir_python = ctx.bindir.join("python3");
    fs::write(&bindir_python, b"").unwrap();
    set_which("python3", None);
    set_which("python", None);
    set_run_output(
        bindir_python.to_string_lossy().as_ref(),
        &["--version"],
        output_with_status(0, b"Python 3.11.9", b""),
    );
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let report = check_python(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));
}

#[test]
fn python_check_uses_python_bindir() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let bindir_python = ctx.bindir.join("python");
    fs::write(&bindir_python, b"").unwrap();
    set_which("python3", None);
    set_which("python", None);
    set_run_output(
        bindir_python.to_string_lossy().as_ref(),
        &["--version"],
        output_with_status(0, b"Python 3.11.9", b""),
    );
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let report = check_python(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));
}

#[test]
fn python_pick_asset_missing() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();

    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-aarch64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = Version {
        major: 3,
        minor: 11,
        patch: 9,
        pre: None,
    };
    assert!(python_pick_asset(&ctx, &v).is_err());
}

#[test]
fn update_python_prune_warn() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("python3", None);
    set_which("python", None);
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tgz"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let tar = {
        let mut bytes = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_cksum();
            tar.append_data(&mut header, "python/install/bin/python", std::io::empty())
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_cksum();
            tar.append_data(&mut header, "python/install/bin/python3", std::io::empty())
                .unwrap();
            tar.finish().unwrap();
        }
        zstd::stream::encode_all(&bytes[..], 0).unwrap()
    };
    set_http_plan(
        "https://example.com/python.tgz",
        vec![Ok(MockResponse::new(tar.clone(), Some(tar.len() as u64)))],
    );
    set_prune_tool_versions_error(Some("prune".to_string()));
    update_python(&ctx).unwrap();
    set_prune_tool_versions_error(None);
}

#[test]
fn python_check_outdated_and_latest_error() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("python3", Some(PathBuf::from("/bin/python3")));
    set_run_output(
        "python3",
        &["--version"],
        output_with_status(0, b"Python 3.11.1", b""),
    );
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let report = check_python(&ctx).unwrap();
    assert!(matches!(report.status, Status::Outdated));

    set_http_plan(url, vec![Err("no".to_string())]);
    let report = check_python(&ctx).unwrap();
    assert!(matches!(report.status, Status::Unknown));
}

#[test]
fn update_python_offline_and_dry_run() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.offline = true;
    assert!(update_python(&ctx).is_err());

    ctx.offline = false;
    ctx.dry_run = true;
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    set_which("python3", None);
    update_python(&ctx).unwrap();
}

#[test]
fn update_python_dry_run_logs() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.dry_run = true;
    set_which("python3", None);
    set_which("python", None);
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tgz"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    update_python(&ctx).unwrap();
}

#[test]
fn update_python_up_to_date() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("python3", Some(PathBuf::from("/bin/python3")));
    set_run_output(
        "python3",
        &["--version"],
        output_with_status(0, b"Python 3.11.9", b""),
    );
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    update_python(&ctx).unwrap();
}

#[test]
fn update_python_success_and_layout_error() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("python3", None);
    set_which("python", None);
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tgz"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let tar = b"not a tar".to_vec();
    set_http_plan(
        "https://example.com/python.tgz",
        vec![Ok(MockResponse::new(tar, Some(8)))],
    );
    let err = update_python(&ctx).unwrap_err();
    assert!(err.to_string().contains("archive"));

    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tgz"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let tar = {
        let mut bytes = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_cksum();
            tar.append_data(&mut header, "python/bin/python", std::io::empty())
                .unwrap();
            tar.finish().unwrap();
        }
        zstd::stream::encode_all(&bytes[..], 0).unwrap()
    };
    set_http_plan(
        "https://example.com/python.tgz",
        vec![Ok(MockResponse::new(tar.clone(), Some(tar.len() as u64)))],
    );
    update_python(&ctx).unwrap();
}

#[test]
fn update_python_layout_missing() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("python3", None);
    set_which("python", None);
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tgz"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let tar = {
        let mut bytes = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_cksum();
            tar.append_data(&mut header, "other/bin/python", std::io::empty())
                .unwrap();
            tar.finish().unwrap();
        }
        zstd::stream::encode_all(&bytes[..], 0).unwrap()
    };
    set_http_plan(
        "https://example.com/python.tgz",
        vec![Ok(MockResponse::new(tar.clone(), Some(tar.len() as u64)))],
    );
    let err = update_python(&ctx).unwrap_err();
    assert!(
        err.to_string()
            .contains("unexpected python-build-standalone layout")
    );
}

#[test]
fn update_python_install_layout() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("python3", None);
    set_which("python", None);
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tgz"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let tar = {
        let mut bytes = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_cksum();
            tar.append_data(&mut header, "python/install/bin/python", std::io::empty())
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_cksum();
            tar.append_data(&mut header, "python/install/bin/python3", std::io::empty())
                .unwrap();
            tar.finish().unwrap();
        }
        zstd::stream::encode_all(&bytes[..], 0).unwrap()
    };
    set_http_plan(
        "https://example.com/python.tgz",
        vec![Ok(MockResponse::new(tar.clone(), Some(tar.len() as u64)))],
    );
    update_python(&ctx).unwrap();
    let python = fs::read_link(ctx.bindir.join("python")).unwrap();
    assert!(python.to_string_lossy().contains("install/bin/python"));
}

#[test]
fn update_python_latest_unknown() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    set_http_plan(url, vec![Err("no".to_string())]);
    let err = update_python(&ctx).unwrap_err();
    assert!(err.to_string().contains("latest unknown"));
}
