use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use upkit::test_support::{
    MockResponse, TestPrompt, base_ctx, output_with_status, reset_guard, set_http_plan,
    set_prune_tool_versions_error, set_run_output, set_which,
};
use upkit::tools::node::{
    check_node, ensure_npm_prefix, node_artifact_name, node_latest_lts, node_os_arch, node_shasums,
    update_node,
};
use upkit::{Ctx, Status, Version};

#[cfg(unix)]
use upkit::test_support::take_run_output;

#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

fn ctx_with_dirs() -> (Ctx, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.quiet = true;
    (ctx, dir)
}

fn make_node_tar_xz() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let enc = xz2::write::XzEncoder::new(&mut bytes, 6);
        let mut tar = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o755);
        header.set_size(0);
        header.set_cksum();
        tar.append_data(
            &mut header,
            "node-v1.2.3-linux-x64/bin/node",
            std::io::empty(),
        )
        .unwrap();
        tar.finish().unwrap();
    }
    bytes
}

fn make_node_tar_xz_flat() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let enc = xz2::write::XzEncoder::new(&mut bytes, 6);
        let mut tar = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_cksum();
        tar.append_data(&mut header, "node", std::io::empty())
            .unwrap();
        tar.finish().unwrap();
    }
    bytes
}

fn make_node_tar_xz_with_npm() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let enc = xz2::write::XzEncoder::new(&mut bytes, 6);
        let mut tar = tar::Builder::new(enc);
        for path in [
            "node-v1.2.3-linux-x64/bin/node",
            "node-v1.2.3-linux-x64/bin/npm",
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o755);
            header.set_size(0);
            header.set_cksum();
            tar.append_data(&mut header, path, std::io::empty())
                .unwrap();
        }
        tar.finish().unwrap();
    }
    bytes
}

#[cfg(unix)]
fn node_layout_fixture(case: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let encoder = xz2::write::XzEncoder::new(&mut bytes, 6);
        let mut tar = tar::Builder::new(encoder);
        let root = if case == "wrong-root" {
            "other"
        } else {
            "node-v1.2.3-linux-x64"
        };
        if case != "missing-node" {
            let mut header = tar::Header::new_gnu();
            header.set_mode(if case == "non-executable" {
                0o644
            } else {
                0o755
            });
            header.set_size(7);
            header.set_cksum();
            tar.append_data(&mut header, format!("{root}/bin/node"), &b"fixture"[..])
                .unwrap();
        } else {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o755);
            header.set_size(0);
            header.set_cksum();
            tar.append_data(&mut header, format!("{root}/bin/npm"), std::io::empty())
                .unwrap();
        }
        if case == "extra-root" {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(0);
            header.set_cksum();
            tar.append_data(&mut header, "other/file", std::io::empty())
                .unwrap();
        }
        if case == "escaping-link" || case == "internal-link" {
            if case == "internal-link" {
                let mut header = tar::Header::new_gnu();
                header.set_mode(0o755);
                header.set_size(7);
                header.set_cksum();
                tar.append_data(&mut header, format!("{root}/lib/npm.js"), &b"fixture"[..])
                    .unwrap();
            }
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_mode(0o777);
            header.set_size(0);
            header
                .set_link_name(if case == "escaping-link" {
                    "../../outside"
                } else {
                    "../lib/npm.js"
                })
                .unwrap();
            header.set_cksum();
            tar.append_data(&mut header, format!("{root}/bin/npm"), std::io::empty())
                .unwrap();
        }
        tar.finish().unwrap();
    }
    bytes
}

#[cfg(unix)]
#[test]
fn node_update_rejects_invalid_layout_before_switching_active() {
    let _guard = reset_guard();
    for case in [
        "wrong-root",
        "extra-root",
        "missing-node",
        "non-executable",
        "escaping-link",
        "internal-link",
    ] {
        let (ctx, _dir) = ctx_with_dirs();
        fs::create_dir_all(&ctx.bindir).unwrap();
        let old = ctx.home.join("node/old");
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("keep"), "keep").unwrap();
        symlink(&old, ctx.home.join("node/active")).unwrap();
        set_which("node", None);
        set_http_plan(
            "https://nodejs.org/dist/index.json",
            vec![Ok(MockResponse::new(
                br#"[{"version":"v1.2.3","lts":true}]"#.to_vec(),
                None,
            ))],
        );
        let bytes = node_layout_fixture(case);
        let hash = hex::encode(Sha256::digest(&bytes));
        set_http_plan(
            "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt",
            vec![Ok(MockResponse::new(
                format!("{hash}  node-v1.2.3-linux-x64.tar.xz\n").into_bytes(),
                None,
            ))],
        );
        set_http_plan(
            "https://nodejs.org/dist/v1.2.3/node-v1.2.3-linux-x64.tar.xz",
            vec![Ok(MockResponse::new(bytes, None))],
        );
        let result = update_node(&ctx);
        if case == "internal-link" {
            result.unwrap();
            assert_eq!(fs::read(ctx.bindir.join("npm")).unwrap(), b"fixture");
        } else {
            assert!(result.is_err(), "{case} must be rejected");
            assert_eq!(fs::read_link(ctx.home.join("node/active")).unwrap(), old);
            assert!(!ctx.bindir.join("node").exists());
        }
        assert_eq!(fs::read_to_string(old.join("keep")).unwrap(), "keep");
    }
}

#[test]
fn node_os_arch_maps() {
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();
    assert_eq!(node_os_arch(&ctx), ("linux".into(), "x64".into()));
    ctx.os = "macos".into();
    ctx.arch = "aarch64".into();
    assert_eq!(node_os_arch(&ctx), ("darwin".into(), "arm64".into()));
}

#[test]
fn node_os_arch_other() {
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "plan9".into();
    ctx.arch = "mips".into();
    assert_eq!(node_os_arch(&ctx), ("plan9".into(), "mips".into()));
}

#[test]
fn node_os_arch_windows() {
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    ctx.arch = "x86_64".into();
    assert_eq!(node_os_arch(&ctx), ("win".into(), "x64".into()));
}

#[test]
fn node_latest_and_shasums() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true},{"version":"v1.2.2","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = node_latest_lts(&ctx).unwrap();
    assert_eq!(v.to_string(), "1.2.3");

    let json = r#"[{"version":"v1.2.3","lts":false}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    assert!(node_latest_lts(&ctx).is_err());

    let sums_url = "https://nodejs.org/dist/v2.0.0/SHASUMS256.txt";
    let sums = format!("{}  node-v2.0.0-linux-x64.tar.xz\n", "a".repeat(64));
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.as_bytes().to_vec(), None))],
    );
    let map = node_shasums(&ctx, "v2.0.0").unwrap();
    assert_eq!(
        map.get("node-v2.0.0-linux-x64.tar.xz").unwrap(),
        &"a".repeat(64)
    );
}

#[test]
fn node_shasums_rejects_duplicate_and_malformed_rows() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://nodejs.org/dist/v2.0.0/SHASUMS256.txt";
    let artifact = "node-v2.0.0-linux-x64.tar.xz";
    let hash = "a".repeat(64);
    for (manifest, expected) in [
        (
            format!("{hash}  {artifact}\n{}  {artifact}\n", "b".repeat(64)),
            "duplicate checksum",
        ),
        (format!("abc  {artifact}\n"), "malformed SHA-256"),
        (
            format!("{}  {artifact}\n", "g".repeat(64)),
            "malformed SHA-256",
        ),
        (format!("{hash}  {artifact} extra\n"), "malformed SHA-256"),
    ] {
        set_http_plan(
            url,
            vec![Ok(MockResponse::new(manifest.into_bytes(), None))],
        );
        let error = node_shasums(&ctx, "v2.0.0").unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
    }
}

#[test]
fn update_node_rejects_duplicate_asset_checksum_before_archive_download() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let index_url = "https://nodejs.org/dist/index.json";
    let sums_url = "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt";
    let archive_url = "https://nodejs.org/dist/v1.2.3/node-v1.2.3-linux-x64.tar.xz";
    let artifact = "node-v1.2.3-linux-x64.tar.xz";
    set_http_plan(
        index_url,
        vec![Ok(MockResponse::new(
            br#"[{"version":"v1.2.3","lts":true}]"#.to_vec(),
            None,
        ))],
    );
    set_which("node", None);
    set_which("npm", None);
    let sums = format!(
        "{}  {artifact}\n{}  {artifact}\n",
        "a".repeat(64),
        "b".repeat(64)
    );
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.into_bytes(), None))],
    );
    set_http_plan(
        archive_url,
        vec![Err("archive download should not be reached".into())],
    );

    let error = update_node(&ctx).unwrap_err();
    assert!(error.to_string().contains("duplicate checksum"));
    assert!(!ctx.home.join("node").exists());
}

#[test]
fn node_latest_lts_multiple_entries() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true},{"version":"v1.2.10","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = node_latest_lts(&ctx).unwrap();
    assert_eq!(v.to_string(), "1.2.10");
}

#[test]
fn node_latest_lts_string_flag() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v20.10.0","lts":"hydrogen"},{"version":"v22.0.0","lts":false}]"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = node_latest_lts(&ctx).unwrap();
    assert_eq!(v.to_string(), "20.10.0");
}

#[test]
fn node_latest_lts_unknown_flag() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v20.10.0","lts":null},{"version":"v20.9.0","lts":"hydrogen"}]"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = node_latest_lts(&ctx).unwrap();
    assert_eq!(v.to_string(), "20.9.0");
}

#[test]
fn node_artifact_windows_zip() {
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    let v = Version {
        major: 1,
        minor: 2,
        patch: 3,
        pre: None,
    };
    ctx.arch = "x86_64".into();
    assert_eq!(
        node_artifact_name(&ctx, &v).unwrap(),
        "node-v1.2.3-win-x64.zip"
    );
    ctx.arch = "aarch64".into();
    assert_eq!(
        node_artifact_name(&ctx, &v).unwrap(),
        "node-v1.2.3-win-arm64.zip"
    );
    ctx.arch = "mips".into();
    assert!(node_artifact_name(&ctx, &v).is_err());
}

#[test]
fn node_check_statuses() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", None);
    let report = check_node(&ctx).unwrap();
    assert!(matches!(report.status, Status::NotInstalled));

    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", Some(PathBuf::from("/bin/node")));
    set_run_output(
        "node",
        &["--version"],
        output_with_status(0, b"v1.2.3", b""),
    );
    let report = check_node(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));
}

#[test]
fn node_found_but_unverifiable_is_unknown_not_not_installed() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("node", Some(PathBuf::from("/fixture/node")));
    set_run_output(
        "node",
        &["--version"],
        output_with_status(1, b"", b"fixture failure"),
    );
    set_http_plan(
        "https://nodejs.org/dist/index.json",
        vec![Ok(MockResponse::new(
            br#"[{"version":"v1.2.3","lts":true}]"#.to_vec(),
            None,
        ))],
    );

    let report = check_node(&ctx).unwrap();

    assert!(report.installed.is_none());
    assert_eq!(report.status, Status::Unknown);
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("could not be verified"))
    );
}

#[cfg(unix)]
#[test]
fn node_dry_run_skips_version_probe_for_detected_executable() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();
    ctx.dry_run = true;
    fs::create_dir_all(&ctx.bindir).unwrap();
    let executable = ctx.bindir.join("node");
    fs::write(&executable, b"#!/bin/sh\n: > \"$0.called\"\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let sentinel = ctx.bindir.join("node.called");
    let index_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        index_url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );

    let report = check_node(&ctx).unwrap();
    assert!(report.installed.is_none());
    assert!(matches!(report.status, Status::Unknown));
    assert_eq!(report.latest.unwrap().to_string(), "1.2.3");
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("version was not checked"))
    );
    assert!(
        !sentinel.exists(),
        "dry-run executed the detected Node binary"
    );

    update_node(&ctx).unwrap();
    assert!(
        !sentinel.exists(),
        "dry-run update executed the detected Node binary"
    );
    assert!(
        !ctx.home.join("node").exists(),
        "dry-run created the managed Node install"
    );
}

#[test]
fn node_check_uses_bindir() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let bindir_node = ctx.bindir.join("node");
    fs::write(&bindir_node, b"").unwrap();
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", None);
    set_run_output(
        bindir_node.to_string_lossy().as_ref(),
        &["--version"],
        output_with_status(0, b"v1.2.3", b""),
    );
    let report = check_node(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));
}

#[test]
fn node_check_windows_uses_exe_and_reports_path_requirement() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let binary = ctx.bindir.join("node.exe");
    fs::write(&binary, b"").unwrap();
    set_which("node", None);
    set_http_plan(
        "https://nodejs.org/dist/index.json",
        vec![Ok(MockResponse::new(
            br#"[{"version":"v1.2.3","lts":true}]"#.to_vec(),
            None,
        ))],
    );
    set_run_output(
        binary.to_string_lossy().as_ref(),
        &["--version"],
        output_with_status(0, b"v1.2.3", b""),
    );
    let report = check_node(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));
    assert!(
        report
            .notes
            .iter()
            .any(|note| note == "Windows: put node/active first on PATH.")
    );
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.starts_with("Windows Node PATH: "))
    );
}

#[cfg(any(unix, windows))]
fn windows_node_zip(arch: &str, case: &str) -> Vec<u8> {
    use std::io::{Cursor, Write};
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    let root = format!("node-v1.2.3-win-{arch}");
    for name in [
        "node.exe",
        "npm.cmd",
        "npx.cmd",
        "node_modules/npm/bin/npm-cli.js",
        "node_modules/npm/bin/npx-cli.js",
        "node_modules/npm/bin/npm-prefix.js",
    ] {
        if case == name {
            continue;
        }
        zip.start_file(format!("{root}/{name}"), options).unwrap();
        if case != "empty-node" || name != "node.exe" {
            zip.write_all(b"fixture").unwrap();
        }
    }
    if case == "extra-root" {
        zip.start_file("other/file", options).unwrap();
        zip.write_all(b"fixture").unwrap();
    }
    if case == "link" {
        zip.add_symlink(format!("{root}/link"), "../../outside", options)
            .unwrap();
    }
    zip.finish().unwrap().into_inner()
}

#[cfg(any(unix, windows))]
fn plan_windows_node(arch: &str, bytes: &[u8], bad_hash: bool) {
    let name = format!("node-v1.2.3-win-{arch}.zip");
    let hash = if bad_hash {
        "0".repeat(64)
    } else {
        hex::encode(Sha256::digest(bytes))
    };
    set_http_plan(
        "https://nodejs.org/dist/index.json",
        vec![Ok(MockResponse::new(
            br#"[{"version":"v1.2.3","lts":true}]"#.to_vec(),
            None,
        ))],
    );
    set_http_plan(
        "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt",
        vec![Ok(MockResponse::new(
            format!("{hash}  {name}\n").into_bytes(),
            None,
        ))],
    );
    set_http_plan(
        &format!("https://nodejs.org/dist/v1.2.3/{name}"),
        vec![Ok(MockResponse::new(bytes.to_vec(), None))],
    );
}

#[cfg(any(unix, windows))]
#[test]
fn windows_node_zip_preserves_layout_and_prior_installation() {
    #[cfg(windows)]
    if !windows_symlinks::available() {
        return;
    }
    let _guard = reset_guard();
    for (arch, case) in [
        ("x64", "node.exe"),
        ("x64", "npm.cmd"),
        ("x64", "npx.cmd"),
        ("x64", "node_modules/npm/bin/npm-cli.js"),
        ("x64", "node_modules/npm/bin/npx-cli.js"),
        ("x64", "node_modules/npm/bin/npm-prefix.js"),
        ("x64", "empty-node"),
        ("x64", "extra-root"),
        ("x64", "link"),
        ("x64", "malformed"),
        ("x64", "bad-hash"),
        ("x64", "valid"),
        ("arm64", "valid"),
    ] {
        let (mut ctx, _dir) = ctx_with_dirs();
        ctx.os = "windows".into();
        ctx.arch = if arch == "x64" { "x86_64" } else { "aarch64" }.into();
        fs::create_dir_all(&ctx.bindir).unwrap();
        fs::write(ctx.bindir.join("npm.cmd"), b"unrelated").unwrap();
        let root = ctx.home.join("node");
        let old = root.join("old");
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("node.exe"), b"old").unwrap();
        fs::write(old.join("keep"), b"keep").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&old, root.join("active")).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&old, root.join("active")).unwrap();
        set_run_output(
            root.join("active/node.exe").to_string_lossy().as_ref(),
            &["--version"],
            output_with_status(0, b"v0.0.1", b""),
        );
        set_which("node", None);
        let bytes = if case == "malformed" {
            b"not a zip archive".to_vec()
        } else {
            windows_node_zip(arch, case)
        };
        plan_windows_node(arch, &bytes, case == "bad-hash");
        let result = update_node(&ctx);
        if case == "valid" {
            result.unwrap();
            for name in [
                "node.exe",
                "npm.cmd",
                "npx.cmd",
                "node_modules/npm/bin/npm-cli.js",
            ] {
                assert_eq!(
                    fs::read(root.join("active").join(name)).unwrap(),
                    b"fixture"
                );
            }
            assert_ne!(
                fs::canonicalize(root.join("active")).unwrap(),
                fs::canonicalize(&old).unwrap()
            );
            set_run_output(
                root.join("active/node.exe").to_string_lossy().as_ref(),
                &["--version"],
                output_with_status(0, b"v1.2.3", b""),
            );
            set_http_plan(
                "https://nodejs.org/dist/index.json",
                vec![Ok(MockResponse::new(
                    br#"[{"version":"v1.2.3","lts":true}]"#.to_vec(),
                    None,
                ))],
            );
            assert_eq!(
                check_node(&ctx).unwrap().installed.unwrap().to_string(),
                "1.2.3"
            );
        } else {
            assert!(result.is_err(), "{arch} {case}");
            assert_eq!(
                fs::canonicalize(root.join("active")).unwrap(),
                fs::canonicalize(&old).unwrap()
            );
        }
        assert_eq!(fs::read(old.join("keep")).unwrap(), b"keep");
        assert_eq!(fs::read(ctx.bindir.join("npm.cmd")).unwrap(), b"unrelated");
    }
}

#[cfg(any(unix, windows))]
#[test]
fn windows_node_zip_dry_run_and_active_conflict_are_safe() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    ctx.arch = "x86_64".into();
    set_which("node", None);
    let bytes = windows_node_zip("x64", "valid");
    plan_windows_node("x64", &bytes, false);
    ctx.dry_run = true;
    update_node(&ctx).unwrap();
    assert!(!ctx.home.join("node").exists());
    ctx.dry_run = false;
    fs::create_dir_all(ctx.home.join("node/active")).unwrap();
    fs::write(ctx.home.join("node/active/keep"), b"keep").unwrap();
    plan_windows_node("x64", &bytes, false);
    assert!(update_node(&ctx).is_err());
    assert_eq!(
        fs::read(ctx.home.join("node/active/keep")).unwrap(),
        b"keep"
    );
}

#[cfg(any(unix, windows))]
#[test]
fn windows_node_check_rejects_active_link_outside_tool_root() {
    #[cfg(windows)]
    if !windows_symlinks::available() {
        return;
    }
    let _guard = reset_guard();
    let (mut ctx, dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    let outside = dir.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("node.exe"), b"fixture").unwrap();
    let root = ctx.home.join("node");
    fs::create_dir_all(&root).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, root.join("active")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&outside, root.join("active")).unwrap();
    set_which("node", None);
    set_run_output(
        root.join("active/node.exe").to_string_lossy().as_ref(),
        &["--version"],
        output_with_status(0, b"v1.2.3", b""),
    );
    set_http_plan(
        "https://nodejs.org/dist/index.json",
        vec![Ok(MockResponse::new(
            br#"[{"version":"v1.2.3","lts":true}]"#.to_vec(),
            None,
        ))],
    );
    assert!(check_node(&ctx).unwrap().installed.is_none());
}

#[cfg(unix)]
#[test]
#[ignore = "requires a checksum-verified Node.js Windows ZIP in UPKIT_NODE_ARCHIVE"]
fn windows_node_official_archive_fixture() {
    let _guard = reset_guard();
    let archive = PathBuf::from(std::env::var_os("UPKIT_NODE_ARCHIVE").unwrap());
    let name = archive.file_name().unwrap().to_str().unwrap();
    let stem = name
        .strip_prefix("node-v")
        .unwrap()
        .strip_suffix(".zip")
        .unwrap();
    let (version, arch) = stem.split_once("-win-").unwrap();
    let bytes = fs::read(&archive).unwrap();
    let digest = hex::encode(Sha256::digest(&bytes));
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    ctx.arch = match arch {
        "x64" => "x86_64",
        "arm64" => "aarch64",
        _ => panic!("unknown architecture"),
    }
    .into();
    set_which("node", None);
    set_http_plan(
        "https://nodejs.org/dist/index.json",
        vec![Ok(MockResponse::new(
            format!(r#"[{{"version":"v{version}","lts":true}}]"#).into_bytes(),
            None,
        ))],
    );
    set_http_plan(
        &format!("https://nodejs.org/dist/v{version}/SHASUMS256.txt"),
        vec![Ok(MockResponse::new(
            format!("{digest}  {name}\n").into_bytes(),
            None,
        ))],
    );
    set_http_plan(
        &format!("https://nodejs.org/dist/v{version}/{name}"),
        vec![Ok(MockResponse::new(bytes, None))],
    );
    update_node(&ctx).unwrap();
    for name in [
        "node.exe",
        "npm.cmd",
        "npx.cmd",
        "node_modules/npm/bin/npm-cli.js",
        "node_modules/npm/bin/npx-cli.js",
        "node_modules/npm/bin/npm-prefix.js",
    ] {
        assert!(ctx.home.join("node/active").join(name).is_file());
    }
}

#[test]
fn node_check_outdated() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", Some(PathBuf::from("/bin/node")));
    set_run_output(
        "node",
        &["--version"],
        output_with_status(0, b"v1.2.2", b""),
    );
    let report = check_node(&ctx).unwrap();
    assert!(matches!(report.status, Status::Outdated));
}

#[test]
fn update_node_offline_and_dry_run() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.offline = true;
    assert!(update_node(&ctx).is_err());

    ctx.offline = false;
    ctx.dry_run = true;
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", None);
    update_node(&ctx).unwrap();
}

#[test]
fn update_node_sha_mismatch_and_success() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", None);

    let tar_bytes = make_node_tar_xz();
    let mut hasher = Sha256::new();
    hasher.update(&tar_bytes);
    let good_sha = hex::encode(hasher.finalize());

    let sums = format!("{}  node-v1.2.3-linux-x64.tar.xz\n", "0".repeat(64));
    let sums_url = "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt";
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.as_bytes().to_vec(), None))],
    );

    let dl = "https://nodejs.org/dist/v1.2.3/node-v1.2.3-linux-x64.tar.xz";
    set_http_plan(
        dl,
        vec![Ok(MockResponse::new(
            tar_bytes.clone(),
            Some(tar_bytes.len() as u64),
        ))],
    );
    let err = update_node(&ctx).unwrap_err();
    assert!(err.to_string().contains("sha256 mismatch"));

    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let sums = format!("{good_sha}  node-v1.2.3-linux-x64.tar.xz\n");
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.as_bytes().to_vec(), None))],
    );
    set_http_plan(
        dl,
        vec![Ok(MockResponse::new(
            tar_bytes.clone(),
            Some(tar_bytes.len() as u64),
        ))],
    );
    update_node(&ctx).unwrap();
    assert!(ctx.home.join("node").exists());
}

#[test]
fn update_node_missing_checksum_entry() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", None);
    let sums = format!("{}  other.tar.xz\n", "a".repeat(64));
    let sums_url = "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt";
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.into_bytes(), None))],
    );
    let err = update_node(&ctx).unwrap_err();
    assert!(err.to_string().contains("could not find checksum"));
}

#[test]
fn update_node_warns_on_prefix_and_prune() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", None);

    let tar_bytes = make_node_tar_xz_with_npm();
    let mut hasher = Sha256::new();
    hasher.update(&tar_bytes);
    let good_sha = hex::encode(hasher.finalize());
    let sums = format!("{good_sha}  node-v1.2.3-linux-x64.tar.xz\n");
    let sums_url = "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt";
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.as_bytes().to_vec(), None))],
    );

    let dl = "https://nodejs.org/dist/v1.2.3/node-v1.2.3-linux-x64.tar.xz";
    set_http_plan(
        dl,
        vec![Ok(MockResponse::new(
            tar_bytes.clone(),
            Some(tar_bytes.len() as u64),
        ))],
    );

    let npm = ctx.home.join("node").join("active").join("bin").join("npm");
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &["config", "get", "prefix"],
        output_with_status(0, b"/tmp/old", b""),
    );
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &[
            "config",
            "set",
            "prefix",
            ctx.home.join("node/active").to_string_lossy().as_ref(),
        ],
        output_with_status(1, b"", b""),
    );

    set_prune_tool_versions_error(Some("prune".to_string()));
    update_node(&ctx).unwrap();
    set_prune_tool_versions_error(None);
}

#[cfg(unix)]
#[test]
fn update_node_restores_npm_globals() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", None);

    let tar_bytes = make_node_tar_xz_with_npm();
    let mut hasher = Sha256::new();
    hasher.update(&tar_bytes);
    let good_sha = hex::encode(hasher.finalize());
    let sums = format!("{good_sha}  node-v1.2.3-linux-x64.tar.xz\n");
    let sums_url = "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt";
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.as_bytes().to_vec(), None))],
    );

    let dl = "https://nodejs.org/dist/v1.2.3/node-v1.2.3-linux-x64.tar.xz";
    set_http_plan(
        dl,
        vec![Ok(MockResponse::new(
            tar_bytes.clone(),
            Some(tar_bytes.len() as u64),
        ))],
    );

    let tool_root = ctx.home.join("node");
    let old_dir = tool_root.join("old");
    fs::create_dir_all(old_dir.join("bin")).unwrap();
    fs::write(old_dir.join("bin/npm"), b"").unwrap();
    symlink(&old_dir, tool_root.join("active")).unwrap();

    let npm = ctx.home.join("node").join("active").join("bin").join("npm");
    let list_json = r#"{"dependencies":{"npm":{"version":"10.0.0"},"corepack":{"version":"0.0.0"},"eslint":{"version":"9.0.0"},"@scope/pkg":{"version":"1.0.0"}}}"#;
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &["ls", "-g", "--depth=0", "--json"],
        output_with_status(0, list_json.as_bytes(), b""),
    );
    let desired = ctx.home.join("node/active").to_string_lossy().to_string();
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &["config", "get", "prefix"],
        output_with_status(0, desired.as_bytes(), b""),
    );
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &["install", "-g", "@scope/pkg", "eslint"],
        output_with_status(0, b"", b""),
    );

    update_node(&ctx).unwrap();

    let args = vec![
        "install".to_string(),
        "-g".to_string(),
        "@scope/pkg".to_string(),
        "eslint".to_string(),
    ];
    assert!(take_run_output(npm.to_string_lossy().as_ref(), &args).is_none());
}

#[test]
fn update_node_latest_unknown() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":false}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let err = update_node(&ctx).unwrap_err();
    assert!(err.to_string().contains("latest unknown"));
}

#[test]
fn update_node_bad_archive_layout() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", None);

    let tar_bytes = make_node_tar_xz_flat();
    let mut hasher = Sha256::new();
    hasher.update(&tar_bytes);
    let good_sha = hex::encode(hasher.finalize());

    let sums = format!("{good_sha}  node-v1.2.3-linux-x64.tar.xz\n");
    let sums_url = "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt";
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.as_bytes().to_vec(), None))],
    );

    let dl = "https://nodejs.org/dist/v1.2.3/node-v1.2.3-linux-x64.tar.xz";
    set_http_plan(
        dl,
        vec![Ok(MockResponse::new(
            tar_bytes.clone(),
            Some(tar_bytes.len() as u64),
        ))],
    );
    let err = update_node(&ctx).unwrap_err();
    assert!(err.to_string().contains("archive layout"));
}

#[test]
fn update_node_up_to_date() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", Some(PathBuf::from("/bin/node")));
    set_run_output(
        "node",
        &["--version"],
        output_with_status(0, b"v1.2.3", b""),
    );
    update_node(&ctx).unwrap();
}

#[test]
fn update_node_warns_on_globals_error() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let old_active = ctx.home.join("node").join("old");
    let active_bin = old_active.join("bin");
    fs::create_dir_all(&active_bin).unwrap();
    fs::write(active_bin.join("npm"), b"").unwrap();
    #[cfg(unix)]
    {
        symlink(&old_active, ctx.home.join("node").join("active")).unwrap();
    }
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", None);

    let tar_bytes = make_node_tar_xz_with_npm();
    let mut hasher = Sha256::new();
    hasher.update(&tar_bytes);
    let good_sha = hex::encode(hasher.finalize());
    let sums = format!("{good_sha}  node-v1.2.3-linux-x64.tar.xz\n");
    let sums_url = "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt";
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.as_bytes().to_vec(), None))],
    );

    let dl = "https://nodejs.org/dist/v1.2.3/node-v1.2.3-linux-x64.tar.xz";
    set_http_plan(
        dl,
        vec![Ok(MockResponse::new(
            tar_bytes.clone(),
            Some(tar_bytes.len() as u64),
        ))],
    );

    let npm = active_bin.join("npm");
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &["ls", "-g", "--depth=0", "--json"],
        output_with_status(0, b"not-json", b""),
    );

    update_node(&ctx).unwrap();
}

#[test]
fn update_node_warns_on_restore_globals() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let old_active = ctx.home.join("node").join("old");
    let active_bin = old_active.join("bin");
    fs::create_dir_all(&active_bin).unwrap();
    fs::write(active_bin.join("npm"), b"").unwrap();
    #[cfg(unix)]
    {
        symlink(&old_active, ctx.home.join("node").join("active")).unwrap();
    }
    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", None);

    let tar_bytes = make_node_tar_xz_with_npm();
    let mut hasher = Sha256::new();
    hasher.update(&tar_bytes);
    let good_sha = hex::encode(hasher.finalize());
    let sums = format!("{good_sha}  node-v1.2.3-linux-x64.tar.xz\n");
    let sums_url = "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt";
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.as_bytes().to_vec(), None))],
    );

    let dl = "https://nodejs.org/dist/v1.2.3/node-v1.2.3-linux-x64.tar.xz";
    set_http_plan(
        dl,
        vec![Ok(MockResponse::new(
            tar_bytes.clone(),
            Some(tar_bytes.len() as u64),
        ))],
    );

    let npm = active_bin.join("npm");
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &["ls", "-g", "--depth=0", "--json"],
        output_with_status(
            0,
            br#"{"dependencies":{"eslint":{"version":"9.0.0"}}}"#,
            b"",
        ),
    );
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &["install", "-g", "eslint@9.0.0"],
        output_with_status(1, b"", b""),
    );

    update_node(&ctx).unwrap();
}

#[test]
fn update_node_globals_empty_output() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let old_active = ctx.home.join("node").join("old");
    let active_bin = old_active.join("bin");
    fs::create_dir_all(&active_bin).unwrap();
    fs::write(active_bin.join("npm"), b"").unwrap();
    #[cfg(unix)]
    {
        symlink(&old_active, ctx.home.join("node").join("active")).unwrap();
    }

    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", None);

    let tar_bytes = make_node_tar_xz_with_npm();
    let mut hasher = Sha256::new();
    hasher.update(&tar_bytes);
    let good_sha = hex::encode(hasher.finalize());
    let sums = format!("{good_sha}  node-v1.2.3-linux-x64.tar.xz\n");
    let sums_url = "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt";
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.as_bytes().to_vec(), None))],
    );

    let dl = "https://nodejs.org/dist/v1.2.3/node-v1.2.3-linux-x64.tar.xz";
    set_http_plan(
        dl,
        vec![Ok(MockResponse::new(
            tar_bytes.clone(),
            Some(tar_bytes.len() as u64),
        ))],
    );

    let npm = active_bin.join("npm");
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &["ls", "-g", "--depth=0", "--json"],
        output_with_status(0, b"", b""),
    );

    update_node(&ctx).unwrap();
}

#[test]
fn update_node_globals_missing_deps() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let old_active = ctx.home.join("node").join("old");
    let active_bin = old_active.join("bin");
    fs::create_dir_all(&active_bin).unwrap();
    fs::write(active_bin.join("npm"), b"").unwrap();
    #[cfg(unix)]
    {
        symlink(&old_active, ctx.home.join("node").join("active")).unwrap();
    }

    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", None);

    let tar_bytes = make_node_tar_xz_with_npm();
    let mut hasher = Sha256::new();
    hasher.update(&tar_bytes);
    let good_sha = hex::encode(hasher.finalize());
    let sums = format!("{good_sha}  node-v1.2.3-linux-x64.tar.xz\n");
    let sums_url = "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt";
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.as_bytes().to_vec(), None))],
    );

    let dl = "https://nodejs.org/dist/v1.2.3/node-v1.2.3-linux-x64.tar.xz";
    set_http_plan(
        dl,
        vec![Ok(MockResponse::new(
            tar_bytes.clone(),
            Some(tar_bytes.len() as u64),
        ))],
    );

    let npm = active_bin.join("npm");
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &["ls", "-g", "--depth=0", "--json"],
        output_with_status(0, br#"{}"#, b""),
    );

    update_node(&ctx).unwrap();
}

#[test]
fn update_node_restore_globals_npm_missing() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let old_active = ctx.home.join("node").join("old");
    let active_bin = old_active.join("bin");
    fs::create_dir_all(&active_bin).unwrap();
    fs::write(active_bin.join("npm"), b"").unwrap();
    #[cfg(unix)]
    {
        symlink(&old_active, ctx.home.join("node").join("active")).unwrap();
    }

    let idx_url = "https://nodejs.org/dist/index.json";
    let json = r#"[{"version":"v1.2.3","lts":true}]"#;
    set_http_plan(
        idx_url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("node", None);

    let tar_bytes = make_node_tar_xz();
    let mut hasher = Sha256::new();
    hasher.update(&tar_bytes);
    let good_sha = hex::encode(hasher.finalize());
    let sums = format!("{good_sha}  node-v1.2.3-linux-x64.tar.xz\n");
    let sums_url = "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt";
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.as_bytes().to_vec(), None))],
    );

    let dl = "https://nodejs.org/dist/v1.2.3/node-v1.2.3-linux-x64.tar.xz";
    set_http_plan(
        dl,
        vec![Ok(MockResponse::new(
            tar_bytes.clone(),
            Some(tar_bytes.len() as u64),
        ))],
    );

    let npm = active_bin.join("npm");
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &["ls", "-g", "--depth=0", "--json"],
        output_with_status(
            0,
            br#"{"dependencies":{"eslint":{"version":"9.0.0"}}}"#,
            b"",
        ),
    );

    update_node(&ctx).unwrap();
}

#[test]
fn ensure_npm_prefix_no_npm() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let active = dir.path().join("active");
    fs::create_dir_all(&active).unwrap();
    ensure_npm_prefix(&active).unwrap();
}

#[test]
fn ensure_npm_prefix_no_change() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let active = dir.path().join("active");
    let npm = active.join("bin").join("npm");
    fs::create_dir_all(npm.parent().unwrap()).unwrap();
    fs::write(&npm, b"").unwrap();
    let desired = active.to_string_lossy().to_string();
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &["config", "get", "prefix"],
        output_with_status(0, desired.as_bytes(), b""),
    );
    ensure_npm_prefix(&active).unwrap();
}

#[test]
fn ensure_npm_prefix_set() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let active = dir.path().join("active");
    let npm = active.join("bin").join("npm");
    fs::create_dir_all(npm.parent().unwrap()).unwrap();
    fs::write(&npm, b"").unwrap();
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &["config", "get", "prefix"],
        output_with_status(0, b"/tmp/old", b""),
    );
    set_run_output(
        npm.to_string_lossy().as_ref(),
        &["config", "set", "prefix", active.to_string_lossy().as_ref()],
        output_with_status(0, b"", b""),
    );
    ensure_npm_prefix(&active).unwrap();
}
#[cfg(windows)]
#[path = "support/windows_symlinks.rs"]
mod windows_symlinks;
