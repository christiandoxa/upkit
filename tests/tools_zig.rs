use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use upkit::test_support::{
    MockResponse, TestPrompt, base_ctx, output_with_status, reset_guard, set_http_plan,
    set_prune_tool_versions_error, set_run_output, set_which,
};
use upkit::tools::zig::{check_zig, update_zig, zig_latest, zig_pick_asset, zig_target};
use upkit::{Ctx, Status, Version};

fn ctx_with_dirs() -> (Ctx, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    (ctx, dir)
}

fn zig_index(version: &str, shasum: &str) -> String {
    format!(
        r#"{{
  "master": {{
    "version": "0.16.0-dev.1+abc",
    "x86_64-linux": {{
      "tarball": "https://ziglang.org/builds/zig-x86_64-linux-0.16.0-dev.1+abc.tar.xz",
      "shasum": "dev",
      "size": "1"
    }}
  }},
  "0.15.9": {{
    "version": "0.15.9",
    "x86_64-linux": {{
      "tarball": "https://ziglang.org/download/0.15.9/zig-x86_64-linux-0.15.9.tar.xz",
      "shasum": "old",
      "size": "1"
    }}
  }},
  "{version}": {{
    "version": "{version}",
    "x86_64-linux": {{
      "tarball": "https://ziglang.org/download/{version}/zig-x86_64-linux-{version}.tar.xz",
      "shasum": "{shasum}",
      "size": "123"
    }},
    "aarch64-macos": {{
      "tarball": "https://ziglang.org/download/{version}/zig-aarch64-macos-{version}.tar.xz",
      "shasum": "{shasum}",
      "size": "123"
    }}
  }}
}}"#
    )
}

fn make_zig_tar_xz(version: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let enc = xz2::write::XzEncoder::new(&mut bytes, 6);
        let mut tar = tar::Builder::new(enc);
        let root = format!("zig-x86_64-linux-{version}");
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, format!("{root}/zig"), std::io::empty())
            .unwrap();
        tar.finish().unwrap();
    }
    bytes
}

#[test]
fn zig_target_and_latest() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();
    assert_eq!(zig_target(&ctx).unwrap(), "x86_64-linux");

    ctx.os = "macos".into();
    ctx.arch = "aarch64".into();
    assert_eq!(zig_target(&ctx).unwrap(), "aarch64-macos");

    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();
    let url = "https://ziglang.org/download/index.json";
    let json = zig_index("0.16.0", "abc");
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = zig_latest(&ctx).unwrap();
    assert_eq!(v.to_string(), "0.16.0");
}

#[test]
fn zig_target_windows_unsupported() {
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    ctx.arch = "x86_64".into();
    assert!(zig_target(&ctx).is_err());
}

#[test]
fn zig_pick_asset_and_check() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://ziglang.org/download/index.json";
    let json = zig_index("0.16.0", "abc");
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let want = Version {
        major: 0,
        minor: 16,
        patch: 0,
        pre: None,
    };
    let asset = zig_pick_asset(&ctx, &want).unwrap();
    assert!(asset.tarball.ends_with(".tar.xz"));

    set_which("zig", None);
    let report = check_zig(&ctx).unwrap();
    assert!(matches!(report.status, Status::NotInstalled));
}

#[test]
fn zig_check_uses_bindir() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let bindir_zig = ctx.bindir.join("zig");
    fs::write(&bindir_zig, b"").unwrap();
    set_which("zig", None);
    set_run_output(
        bindir_zig.to_string_lossy().as_ref(),
        &["version"],
        output_with_status(0, b"0.16.0", b""),
    );
    let url = "https://ziglang.org/download/index.json";
    let json = zig_index("0.16.0", "abc");
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let report = check_zig(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));
}

#[test]
fn update_zig_installs_and_prunes() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let url = "https://ziglang.org/download/index.json";
    let archive = make_zig_tar_xz("0.16.0");
    let mut hasher = Sha256::new();
    hasher.update(&archive);
    let shasum = hex::encode(hasher.finalize());
    let json = zig_index("0.16.0", &shasum);
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let download_url = "https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz";
    set_http_plan(
        download_url,
        vec![Ok(MockResponse::new(
            archive.clone(),
            Some(archive.len() as u64),
        ))],
    );

    set_prune_tool_versions_error(Some("prune".to_string()));
    update_zig(&ctx).unwrap();
    set_prune_tool_versions_error(None);

    assert!(ctx.bindir.join("zig").exists());
    assert!(ctx.home.join("zig").join("active").exists());
}

#[test]
fn update_zig_sha_mismatch() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let url = "https://ziglang.org/download/index.json";
    let archive = make_zig_tar_xz("0.16.0");
    let json = zig_index("0.16.0", "bad");
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let download_url = "https://ziglang.org/download/0.16.0/zig-x86_64-linux-0.16.0.tar.xz";
    set_http_plan(
        download_url,
        vec![Ok(MockResponse::new(
            archive.clone(),
            Some(archive.len() as u64),
        ))],
    );

    let err = update_zig(&ctx).unwrap_err();
    assert!(err.to_string().contains("Zig sha256 mismatch"));
}

#[test]
fn zig_check_from_path() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("zig", Some(PathBuf::from("/bin/zig")));
    set_run_output("zig", &["version"], output_with_status(0, b"0.16.0", b""));
    let url = "https://ziglang.org/download/index.json";
    let json = zig_index("0.16.0", "abc");
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let report = check_zig(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));
}
