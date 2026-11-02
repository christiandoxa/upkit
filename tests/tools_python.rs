use sha2::{Digest, Sha256};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use upkit::test_support::{
    MockResponse, TestPrompt, base_ctx, output_with_status, reset_guard, set_http_plan,
    set_prune_tool_versions_error, set_run_output, set_which, take_run_output,
};
use upkit::tools::python::{
    check_python, pip_global_packages, python_latest, python_pick_asset, python_target,
    restore_pip_globals, update_python,
};
use upkit::{Ctx, Status, Version};

fn ctx_with_dirs() -> (Ctx, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.quiet = true;
    (ctx, dir)
}

fn python_tar(entries: &[&str]) -> Vec<u8> {
    let entries = entries
        .iter()
        .map(|entry| (*entry, b"fixture".as_slice(), 0o755))
        .collect::<Vec<_>>();
    python_tar_with_files(&entries)
}

fn python_tar_with_files(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut bytes);
        for (entry, contents, mode) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(*mode);
            header.set_cksum();
            tar.append_data(&mut header, entry, *contents).unwrap();
        }
        tar.finish().unwrap();
    }
    zstd::stream::encode_all(&bytes[..], 0).unwrap()
}

fn set_verified_release(url: &str, metadata: &str, archive: &[u8]) {
    let mut release: serde_json::Value = serde_json::from_str(metadata).unwrap();
    release["assets"][0]["digest"] =
        format!("sha256:{}", hex::encode(Sha256::digest(archive))).into();
    let bytes = serde_json::to_vec(&release).unwrap();
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(bytes.clone(), None)),
            Ok(MockResponse::new(bytes, None)),
        ],
    );
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
fn python_latest_falls_back_to_expanded_assets_html() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();

    let api_url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    set_http_plan(api_url, vec![Err("rate limited".to_string())]);
    set_http_plan(
        "https://github.com/astral-sh/python-build-standalone/releases/latest",
        vec![Ok(MockResponse::new(
            br#"<include-fragment src="/astral-sh/python-build-standalone/releases/expanded_assets/20260510"></include-fragment>"#.to_vec(),
            None,
        ))],
    );
    let assets_html = r#"
        <a href="/astral-sh/python-build-standalone/releases/download/20260510/cpython-3.14.5+20260510-x86_64-unknown-linux-gnu-pgo+lto-full.tar.zst">asset</a>
        <a href="/astral-sh/python-build-standalone/releases/download/20260510/cpython-3.15.0b1+20260510-x86_64-unknown-linux-gnu-pgo+lto-full.tar.zst">asset</a>
    "#;
    set_http_plan(
        "https://github.com/astral-sh/python-build-standalone/releases/expanded_assets/20260510",
        vec![Ok(MockResponse::new(assets_html.as_bytes().to_vec(), None))],
    );

    let v = python_latest(&ctx).unwrap();
    assert_eq!(v.to_string(), "3.14.5");
}

#[test]
fn python_latest_prefers_stable_over_prerelease() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.15.0","assets":[{"name":"cpython-3.15.0rc1+20260801-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python-rc.tar.zst"},{"name":"cpython-3.15.0+20260815-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = python_latest(&ctx).unwrap();
    assert_eq!(v.to_string(), "3.15.0");
}

#[test]
fn python_selects_stable_asset_with_exact_target() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let metadata = r#"{"tag_name":"fixture","assets":[{"name":"cpython-3.15.0rc1+20260801-x86_64-unknown-linux-gnu-install_only.tar.zst","browser_download_url":"https://example.com/rc"},{"name":"cpython-3.14.9+20260801-x86_64-unknown-linux-gnuX-install_only.tar.zst","browser_download_url":"https://example.com/wrong"},{"name":"cpython-3.14.0rc1+20260801-x86_64-unknown-linux-gnu-install_only.tar.zst","browser_download_url":"https://example.com/same-rc"},{"name":"cpython-3.14.0+20260801-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/stable"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(metadata.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(metadata.as_bytes().to_vec(), None)),
        ],
    );
    let latest = python_latest(&ctx).unwrap();
    assert_eq!(latest.to_string(), "3.14.0");
    assert_eq!(
        python_pick_asset(&ctx, &latest)
            .unwrap()
            .browser_download_url,
        "https://example.com/stable"
    );
}

#[test]
fn python_pick_asset_falls_back_to_expanded_assets_html() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();

    let api_url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    set_http_plan(api_url, vec![Err("rate limited".to_string())]);
    set_http_plan(
        "https://github.com/astral-sh/python-build-standalone/releases/latest",
        vec![Ok(MockResponse::new(
            br#"<include-fragment src="/astral-sh/python-build-standalone/releases/expanded_assets/20260510"></include-fragment>"#.to_vec(),
            None,
        ))],
    );
    let assets_html = r#"
        <a href="/astral-sh/python-build-standalone/releases/download/20260510/cpython-3.15.0b1+20260510-x86_64-unknown-linux-gnu-debug-full.tar.zst">asset</a>
        <a href="/astral-sh/python-build-standalone/releases/download/20260510/cpython-3.15.0b1+20260510-x86_64-unknown-linux-gnu-pgo+lto-full.tar.zst">asset</a>
    "#;
    set_http_plan(
        "https://github.com/astral-sh/python-build-standalone/releases/expanded_assets/20260510",
        vec![Ok(MockResponse::new(assets_html.as_bytes().to_vec(), None))],
    );

    let want = Version {
        major: 3,
        minor: 15,
        patch: 0,
        pre: Some("b1".to_string()),
    };
    let asset = python_pick_asset(&ctx, &want).unwrap();
    assert!(asset.name.starts_with("cpython-3.15.0b1+20260510"));
    assert!(asset.name.contains("pgo+lto-full"));
    assert!(!asset.name.contains("debug"));
    assert!(asset.browser_download_url.contains("/download/20260510/"));
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
    assert_eq!(python_target(&ctx).unwrap(), "x86_64-pc-windows-msvc");
    ctx.arch = "aarch64".into();
    assert_eq!(python_target(&ctx).unwrap(), "aarch64-pc-windows-msvc");
    ctx.arch = "x86".into();
    assert!(python_target(&ctx).is_err());
}

#[test]
fn python_selects_official_windows_architecture_assets() {
    for (arch, target) in [
        ("x86_64", "x86_64-pc-windows-msvc"),
        ("aarch64", "aarch64-pc-windows-msvc"),
    ] {
        let _guard = reset_guard();
        let (mut ctx, _dir) = ctx_with_dirs();
        ctx.os = "windows".into();
        ctx.arch = arch.into();
        let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
        let json = format!(
            r#"{{"tag_name":"20261026","assets":[{{"name":"cpython-3.15.2+20261026-{target}-pgo-full.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}}]}}"#
        );
        set_http_plan(
            url,
            vec![
                Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
                Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            ],
        );

        let latest = python_latest(&ctx).unwrap();
        assert_eq!(latest.to_string(), "3.15.2");
        assert_eq!(
            python_pick_asset(&ctx, &latest).unwrap().name,
            format!("cpython-3.15.2+20261026-{target}-pgo-full.tar.zst")
        );
    }
}

#[test]
fn python_check_uses_windows_executable() {
    let _guard = reset_guard();
    let (mut ctx, dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    ctx.arch = "aarch64".into();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let python = ctx.bindir.join("python.exe");
    fs::write(&python, b"fixture").unwrap();
    set_which("python.exe", None);
    set_which("python", None);
    set_run_output(
        python.to_string_lossy().as_ref(),
        &["--version"],
        output_with_status(0, b"Python 3.15.2", b""),
    );
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"20261026","assets":[{"name":"cpython-3.15.2+20261026-aarch64-pc-windows-msvc-pgo-full.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let report = check_python(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));
    assert_eq!(report.installed.unwrap().to_string(), "3.15.2");
    drop(dir);
}

#[test]
fn update_python_installs_windows_python_exe_layout() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    ctx.arch = "aarch64".into();
    fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("python.exe", None);
    set_which("python", None);
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"20261026","assets":[{"name":"cpython-3.15.2+20261026-aarch64-pc-windows-msvc-pgo-full.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    let archive = python_tar(&["python/install/python.exe"]);
    set_verified_release(url, json, &archive);
    set_http_plan(
        "https://example.com/python.tar.zst",
        vec![Ok(MockResponse::new(
            archive.clone(),
            Some(archive.len() as u64),
        ))],
    );

    update_python(&ctx).unwrap();

    let active_python = ctx.home.join("python/active/install/python.exe");
    assert!(active_python.is_file());
    assert_eq!(
        fs::read_link(ctx.bindir.join("python.exe")).unwrap(),
        active_python
    );
    assert!(!ctx.bindir.join("python3").exists());
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

#[cfg(unix)]
#[test]
fn python_dry_run_skips_version_probe_for_detected_executable() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();
    ctx.dry_run = true;
    fs::create_dir_all(&ctx.bindir).unwrap();
    let executable = ctx.bindir.join("python3");
    fs::write(&executable, b"#!/bin/sh\n: > \"$0.called\"\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let sentinel = ctx.bindir.join("python3.called");
    let api_url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    set_http_plan(
        api_url,
        (0..3)
            .map(|_| Ok(MockResponse::new(json.as_bytes().to_vec(), None)))
            .collect(),
    );

    let report = check_python(&ctx).unwrap();
    assert!(report.installed.is_none());
    assert!(matches!(report.status, Status::Unknown));
    assert_eq!(report.latest.unwrap().to_string(), "3.11.9");
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("version was not checked"))
    );
    assert!(
        !sentinel.exists(),
        "dry-run executed the detected Python binary"
    );

    update_python(&ctx).unwrap();
    assert!(
        !sentinel.exists(),
        "dry-run update executed the detected Python binary"
    );
    assert!(
        !ctx.home.join("python").exists(),
        "dry-run created the managed Python install"
    );
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
    let tar = python_tar(&["python/install/bin/python", "python/install/bin/python3"]);
    set_verified_release(url, json, &tar);
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
    set_verified_release(url, json, &tar);
    set_http_plan(
        "https://example.com/python.tgz",
        vec![Ok(MockResponse::new(tar, Some(8)))],
    );
    let err = update_python(&ctx).unwrap_err();
    assert!(err.to_string().contains("archive"));
    let tool_root = ctx.home.join("python");
    assert!(!fs::read_dir(&tool_root).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("install-")
    }));
    let existing = tool_root.join("3.11.9");
    fs::create_dir(&existing).unwrap();
    fs::write(existing.join("keep"), "fixture").unwrap();

    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tgz"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let tar = python_tar(&["python/bin/python", "python/bin/python3"]);
    set_verified_release(url, json, &tar);
    set_http_plan(
        "https://example.com/python.tgz",
        vec![Ok(MockResponse::new(tar.clone(), Some(tar.len() as u64)))],
    );
    update_python(&ctx).unwrap();
    assert_eq!(
        fs::read_to_string(existing.join("keep")).unwrap(),
        "fixture"
    );
}

#[test]
fn update_python_rejects_archive_links_escaping_the_install_root() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("python3", None);
    set_which("python", None);
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let metadata = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tar.zst"}]}"#;
    let archive = {
        let mut bytes = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut bytes);
            let mut executable = tar::Header::new_gnu();
            executable.set_size(0);
            executable.set_cksum();
            tar.append_data(&mut executable, "python/bin/python3", std::io::empty())
                .unwrap();

            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_size(0);
            link.set_link_name("/upkit-do-not-create").unwrap();
            link.set_cksum();
            tar.append_data(&mut link, "python/bin/python", std::io::empty())
                .unwrap();
            tar.finish().unwrap();
        }
        zstd::stream::encode_all(&bytes[..], 0).unwrap()
    };
    set_verified_release(url, metadata, &archive);
    set_http_plan(
        "https://example.com/python.tar.zst",
        vec![Ok(MockResponse::new(
            archive.clone(),
            Some(archive.len() as u64),
        ))],
    );

    let error = update_python(&ctx).unwrap_err();
    assert!(
        error
            .chain()
            .any(|cause| cause.to_string().contains("unsafe symbolic link"))
    );
    let tool_root = ctx.home.join("python");
    assert!(!tool_root.join("active").exists());
    assert_eq!(fs::read_dir(tool_root).unwrap().count(), 0);
}

#[test]
fn python_install_rejects_missing_malformed_and_mismatched_digests() {
    let _guard = reset_guard();
    for case in ["missing", "malformed", "mismatch"] {
        let (ctx, _dir) = ctx_with_dirs();
        set_which("python3", None);
        set_which("python", None);
        let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
        let mut release = serde_json::json!({"tag_name":"v3.11.9", "assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst", "browser_download_url":"https://example.com/python.tgz"}]});
        if case == "malformed" {
            release["assets"][0]["digest"] = "sha256:invalid".into();
        }
        if case == "mismatch" {
            release["assets"][0]["digest"] = format!("sha256:{}", "0".repeat(64)).into();
        }
        let bytes = serde_json::to_vec(&release).unwrap();
        set_http_plan(
            url,
            vec![
                Ok(MockResponse::new(bytes.clone(), None)),
                Ok(MockResponse::new(bytes, None)),
            ],
        );
        if case == "mismatch" {
            let archive = python_tar(&["python/bin/python"]);
            set_http_plan(
                "https://example.com/python.tgz",
                vec![Ok(MockResponse::new(archive, None))],
            );
        }
        let err = update_python(&ctx).unwrap_err().to_string();
        assert!(err.contains(if case == "mismatch" {
            "mismatch"
        } else {
            "lacks a valid"
        }));
        assert!(!ctx.home.exists());
        assert!(!ctx.bindir.exists());
    }
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
    set_verified_release(url, json, &tar);
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

#[cfg(unix)]
#[test]
fn update_python_checks_binary_conflicts_before_activation() {
    use std::os::unix::fs::symlink;
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    fs::write(ctx.bindir.join("python"), "user file").unwrap();
    let tool_root = ctx.home.join("python");
    let old = tool_root.join("old");
    fs::create_dir_all(&old).unwrap();
    symlink(&old, tool_root.join("active")).unwrap();
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
    let archive = python_tar(&["python/bin/python", "python/bin/python3"]);
    set_verified_release(url, json, &archive);
    set_http_plan(
        "https://example.com/python.tgz",
        vec![Ok(MockResponse::new(
            archive.clone(),
            Some(archive.len() as u64),
        ))],
    );
    assert!(update_python(&ctx).is_err());
    assert_eq!(fs::read_link(tool_root.join("active")).unwrap(), old);
    assert_eq!(
        fs::read_to_string(ctx.bindir.join("python")).unwrap(),
        "user file"
    );
    assert!(!fs::read_dir(&tool_root).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("install-")
    }));
}

#[cfg(unix)]
#[test]
fn update_python_rejects_unusable_python3_before_activation() {
    let _guard = reset_guard();
    for (case, entries) in [
        (
            "missing",
            vec![("python/bin/not-python3", b"fixture".as_slice(), 0o755)],
        ),
        ("empty", vec![("python/bin/python3", b"".as_slice(), 0o755)]),
        (
            "non-executable",
            vec![("python/bin/python3", b"fixture".as_slice(), 0o644)],
        ),
    ] {
        let (ctx, _dir) = ctx_with_dirs();
        fs::create_dir_all(&ctx.bindir).unwrap();
        let tool_root = ctx.home.join("python");
        let old = tool_root.join("old");
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("keep"), "fixture").unwrap();
        symlink(&old, tool_root.join("active")).unwrap();
        set_which("python3", None);
        set_which("python", None);

        let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
        let metadata = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tgz"}]}"#;
        let archive = python_tar_with_files(&entries);
        set_verified_release(url, metadata, &archive);
        set_http_plan(
            "https://example.com/python.tgz",
            vec![Ok(MockResponse::new(archive.clone(), None))],
        );

        assert!(update_python(&ctx).is_err(), "accepted {case} python3");
        assert_eq!(fs::read_link(tool_root.join("active")).unwrap(), old);
        assert_eq!(fs::read_to_string(old.join("keep")).unwrap(), "fixture");
        assert!(!fs::read_dir(&tool_root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("install-")
        }));
    }
}

#[cfg(unix)]
#[test]
fn update_python_refuses_external_active_install() {
    use std::os::unix::fs::symlink;
    let _guard = reset_guard();
    let (ctx, dir) = ctx_with_dirs();
    let external = dir.path().join("external");
    let root = ctx.home.join("python");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir(&external).unwrap();
    fs::write(external.join("keep"), "fixture").unwrap();
    symlink(&external, root.join("active")).unwrap();
    set_which("python3", None);
    set_which("python", None);
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tgz"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    assert!(
        update_python(&ctx)
            .unwrap_err()
            .to_string()
            .contains("outside the tool root")
    );
    assert_eq!(fs::read_link(root.join("active")).unwrap(), external);
    assert_eq!(
        fs::read_to_string(external.join("keep")).unwrap(),
        "fixture"
    );
    assert_eq!(fs::read_dir(root).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn update_python_refuses_linked_tool_root_before_extraction() {
    use std::os::unix::fs::symlink;
    let _guard = reset_guard();
    let (ctx, dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.home).unwrap();
    let external = dir.path().join("external");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("keep"), "fixture").unwrap();
    symlink(&external, ctx.home.join("python")).unwrap();
    set_which("python3", None);
    set_which("python", None);
    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tgz"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    assert!(
        update_python(&ctx)
            .unwrap_err()
            .to_string()
            .contains("linked")
    );
    assert_eq!(
        fs::read_to_string(external.join("keep")).unwrap(),
        "fixture"
    );
    assert_eq!(fs::read_dir(external).unwrap().count(), 1);
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
    let tar = python_tar(&["python/install/bin/python", "python/install/bin/python3"]);
    set_verified_release(url, json, &tar);
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

    let tool_root = ctx.home.join("python");
    fs::create_dir_all(&tool_root).unwrap();
    let snapshot = tool_root.join("pip-globals.txt");
    fs::write(&snapshot, "foo==1.0.0\n").unwrap();
    let python = tool_root.join("active/install/bin/python3");
    set_run_output(
        python.to_string_lossy().as_ref(),
        &["-m", "pip", "install", "foo==1.0.0"],
        output_with_status(1, b"", b"fixture failure"),
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
    let tar = python_tar(&["python/install/bin/python3"]);
    set_verified_release(url, json, &tar);
    set_http_plan(
        "https://example.com/python.tgz",
        vec![Ok(MockResponse::new(tar.clone(), Some(tar.len() as u64)))],
    );

    update_python(&ctx).unwrap();
    assert!(
        take_run_output(
            python.to_string_lossy().as_ref(),
            &[
                "-m".into(),
                "pip".into(),
                "install".into(),
                "foo==1.0.0".into()
            ],
        )
        .is_none(),
        "pip package restore was not attempted"
    );
    assert_eq!(fs::read_to_string(snapshot).unwrap(), "foo==1.0.0\n");
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
    let tar = python_tar(&["python/install/bin/python3"]);
    set_verified_release(url, json, &tar);
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
fn update_python_writes_pip_globals_snapshot() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("python3", None);
    set_which("python", None);

    let tool_root = ctx.home.join("python");
    let old_dir = tool_root.join("old");
    let old_python = old_dir.join("install").join("bin").join("python3");
    let active_python = tool_root
        .join("active")
        .join("install")
        .join("bin")
        .join("python3");
    fs::create_dir_all(old_python.parent().unwrap()).unwrap();
    fs::write(&old_python, b"").unwrap();
    #[cfg(unix)]
    {
        symlink(&old_dir, tool_root.join("active")).unwrap();
    }
    set_run_output(
        active_python.to_string_lossy().as_ref(),
        &["-m", "pip", "list", "--format=json"],
        output_with_status(
            0,
            br#"[{"name":"requests","version":"2.31.0"},{"name":"black","version":"23.7"}]"#,
            b"",
        ),
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
    let tar = python_tar(&["python/install/bin/python3"]);
    set_verified_release(url, json, &tar);
    set_http_plan(
        "https://example.com/python.tgz",
        vec![Ok(MockResponse::new(tar.clone(), Some(tar.len() as u64)))],
    );

    set_run_output(
        active_python.to_string_lossy().as_ref(),
        &["-m", "pip", "install", "black==23.7", "requests==2.31.0"],
        output_with_status(0, b"", b""),
    );

    update_python(&ctx).unwrap();

    let snapshot = fs::read_to_string(tool_root.join("pip-globals.txt")).unwrap();
    assert_eq!(snapshot, "black==23.7\nrequests==2.31.0\n");
}

#[test]
fn update_python_restores_pip_globals_from_snapshot_when_active_missing() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("python3", None);
    set_which("python", None);

    let tool_root = ctx.home.join("python");
    fs::create_dir_all(&tool_root).unwrap();
    let active_python = tool_root
        .join("active")
        .join("install")
        .join("bin")
        .join("python3");
    fs::write(
        tool_root.join("pip-globals.txt"),
        "# saved pip globals\nrequests==2.31.0\nblack==23.7\nrequests==2.31.0\n",
    )
    .unwrap();

    let url = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest";
    let json = r#"{"tag_name":"v3.11.9","assets":[{"name":"cpython-3.11.9+20240224-x86_64-unknown-linux-gnu.tar.zst","browser_download_url":"https://example.com/python.tgz"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let tar = python_tar(&["python/install/bin/python3"]);
    set_verified_release(url, json, &tar);
    set_http_plan(
        "https://example.com/python.tgz",
        vec![Ok(MockResponse::new(tar.clone(), Some(tar.len() as u64)))],
    );

    set_run_output(
        active_python.to_string_lossy().as_ref(),
        &["-m", "pip", "install", "black==23.7", "requests==2.31.0"],
        output_with_status(0, b"", b""),
    );

    update_python(&ctx).unwrap();

    let snapshot = fs::read_to_string(tool_root.join("pip-globals.txt")).unwrap();
    assert_eq!(snapshot, "black==23.7\nrequests==2.31.0\n");
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
