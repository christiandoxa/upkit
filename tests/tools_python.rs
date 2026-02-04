use anyhow::anyhow;
use jmpln::patch;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use upkit::test_support::{
    MockResponse, TestPrompt, base_ctx, output_with_status, reset_guard, set_http_plan,
    set_prune_tool_versions_error, set_run_output, set_which,
};
use upkit::tools::python::{
    check_python, pip_global_packages, python_latest, python_pick_asset, python_target,
    restore_pip_globals, update_python,
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
fn python_latest_matches_simple_asset() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.12.1","assets":[{"name":"cpython-3.12.1-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python-3.12.1.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = python_latest(&ctx).unwrap();
    assert_eq!(v.to_string(), "3.12.1");
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

#[test]
fn python_latest_updates_best_in_loop() {
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
fn pip_global_packages_empty_stdout() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let active = dir.path().join("active");
    let python = active.join("install").join("bin").join("python3");
    fs::create_dir_all(python.parent().unwrap()).unwrap();
    fs::write(&python, b"").unwrap();
    set_run_output(
        python.to_string_lossy().as_ref(),
        &["-m", "pip", "list", "--format=json"],
        output_with_status(0, b"", b""),
    );
    assert!(pip_global_packages(&active).unwrap().is_empty());
}

#[test]
fn pip_global_packages_non_array_and_missing_name() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let active = dir.path().join("active");
    let python = active.join("install").join("bin").join("python3");
    fs::create_dir_all(python.parent().unwrap()).unwrap();
    fs::write(&python, b"").unwrap();
    set_run_output(
        python.to_string_lossy().as_ref(),
        &["-m", "pip", "list", "--format=json"],
        output_with_status(0, br#"{"nope":true}"#, b""),
    );
    assert!(pip_global_packages(&active).unwrap().is_empty());

    let list_json = br#"[{"version":"1.0.0"},{"name":"foo","version":""}]"#;
    set_run_output(
        python.to_string_lossy().as_ref(),
        &["-m", "pip", "list", "--format=json"],
        output_with_status(0, list_json, b""),
    );
    let packages = pip_global_packages(&active).unwrap();
    assert!(packages.contains(&"foo".to_string()));
}

#[test]
fn restore_pip_globals_missing_python() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let active = dir.path().join("active");
    restore_pip_globals(&active, &["foo==1.0.0".to_string()]).unwrap();
}

#[test]
fn update_python_warns_on_pip_globals_error() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.dry_run = true;
    fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("python3", None);
    set_which("python", None);

    let tool_root = ctx.home.join("python");
    let old_dir = tool_root.join("old");
    let python = old_dir.join("install").join("bin").join("python3");
    fs::create_dir_all(python.parent().unwrap()).unwrap();
    fs::write(&python, b"").unwrap();
    #[cfg(unix)]
    {
        symlink(&old_dir, tool_root.join("active")).unwrap();
    }
    set_run_output(
        python.to_string_lossy().as_ref(),
        &["-m", "pip", "list", "--format=json"],
        output_with_status(1, b"", b""),
    );

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
fn update_python_warns_on_restore_pip_globals() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("python3", None);
    set_which("python", None);

    fn fake_pip_global_packages(_active: &std::path::Path) -> anyhow::Result<Vec<String>> {
        Ok(vec!["foo==1.0.0".to_string()])
    }
    fn fake_restore_pip_globals(
        _active: &std::path::Path,
        _packages: &[String],
    ) -> anyhow::Result<()> {
        Err(anyhow!("boom"))
    }
    let _patch_list = patch!(pip_global_packages => fake_pip_global_packages).unwrap();
    let _patch_restore = patch!(restore_pip_globals => fake_restore_pip_globals).unwrap();

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
}

#[test]
fn update_python_warns_on_restore_pip_globals_run_output() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("python3", None);
    set_which("python", None);

    let tool_root = ctx.home.join("python");
    let old_dir = tool_root.join("old");
    let old_python = old_dir.join("install").join("bin").join("python3");
    fs::create_dir_all(old_python.parent().unwrap()).unwrap();
    fs::write(&old_python, b"").unwrap();
    #[cfg(unix)]
    {
        symlink(&old_dir, tool_root.join("active")).unwrap();
    }
    set_run_output(
        old_python.to_string_lossy().as_ref(),
        &["-m", "pip", "list", "--format=json"],
        output_with_status(0, br#"[{"name":"foo","version":"1.0.0"}]"#, b""),
    );

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

    let new_python = tool_root
        .join("3.11.9")
        .join("python")
        .join("install")
        .join("bin")
        .join("python3");
    set_run_output(
        new_python.to_string_lossy().as_ref(),
        &["-m", "pip", "install", "foo==1.0.0"],
        output_with_status(1, b"", b""),
    );

    update_python(&ctx).unwrap();
}

#[test]
fn pip_globals_filters_and_versions() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let active = dir.path().join("active");
    let python = active.join("install").join("bin").join("python3");
    fs::create_dir_all(python.parent().unwrap()).unwrap();
    fs::write(&python, b"").unwrap();

    let json = r#"[{"name":"pip","version":"23.2"},{"name":"setuptools","version":"65.5"},{"name":"wheel","version":"0.41"},{"name":"requests","version":"2.31.0"},{"name":"black","version":"23.7"}]"#;
    set_run_output(
        python.to_string_lossy().as_ref(),
        &["-m", "pip", "list", "--format=json"],
        output_with_status(0, json.as_bytes(), b""),
    );
    let packages = pip_global_packages(&active).unwrap();
    assert_eq!(
        packages,
        vec!["black==23.7".to_string(), "requests==2.31.0".to_string()]
    );
}

#[test]
fn pip_globals_errors_on_failed_list() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let active = dir.path().join("active");
    let python = active.join("bin").join("python3");
    fs::create_dir_all(python.parent().unwrap()).unwrap();
    fs::write(&python, b"").unwrap();

    set_run_output(
        python.to_string_lossy().as_ref(),
        &["-m", "pip", "list", "--format=json"],
        output_with_status(1, b"", b"boom"),
    );
    let err = pip_global_packages(&active).unwrap_err();
    assert!(err.to_string().contains("pip list failed"));
}

#[test]
fn restore_pip_globals_runs_install() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let active = dir.path().join("active");
    let python = active.join("bin").join("python3");
    fs::create_dir_all(python.parent().unwrap()).unwrap();
    fs::write(&python, b"").unwrap();

    set_run_output(
        python.to_string_lossy().as_ref(),
        &["-m", "pip", "install", "requests==2.31.0", "black==23.7"],
        output_with_status(0, b"", b""),
    );
    let packages = vec!["requests==2.31.0".to_string(), "black==23.7".to_string()];
    restore_pip_globals(&active, &packages).unwrap();
}
