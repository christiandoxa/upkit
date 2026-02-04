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
use std::os::unix::fs::symlink;

fn ctx_with_dirs() -> (Ctx, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    (ctx, dir)
}

fn make_node_tar_xz() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let enc = xz2::write::XzEncoder::new(&mut bytes, 6);
        let mut tar = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
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
    let sums = b"abc  node-v2.0.0-linux-x64.tar.xz\n";
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.to_vec(), Some(34)))],
    );
    let map = node_shasums(&ctx, "v2.0.0").unwrap();
    assert_eq!(map.get("node-v2.0.0-linux-x64.tar.xz").unwrap(), "abc");
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
fn node_artifact_windows_error() {
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    let v = Version {
        major: 1,
        minor: 2,
        patch: 3,
        pre: None,
    };
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

    let sums = format!("bad  node-v1.2.3-linux-x64.tar.xz\n");
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
    let sums = "abc  other.tar.xz\n";
    let sums_url = "https://nodejs.org/dist/v1.2.3/SHASUMS256.txt";
    set_http_plan(
        sums_url,
        vec![Ok(MockResponse::new(sums.as_bytes().to_vec(), None))],
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
