use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use upkit::test_support::{
    MockResponse, TestPrompt, base_ctx, output_with_status, reset_guard, set_env_var, set_home_dir,
    set_http_plan, set_prune_tool_versions_error, set_run_output, set_which,
};
use upkit::tools::go::{
    GoToolSpec, check_go, go_global_bin_dirs, go_global_tools, go_latest, go_os_arch, go_pick_file,
    go_tool_spec_from_binary, parse_go_version_metadata, restore_go_globals, update_go,
};
use upkit::{Ctx, Status, Version};

fn ctx_with_dirs() -> (Ctx, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    (ctx, dir)
}

fn go_json(version: &str, sha: &str) -> String {
    format!(
        r#"[{{"version":"{version}","stable":true,"files":[{{"filename":"go1.2.3.linux-amd64.tar.gz","os":"linux","arch":"amd64","kind":"archive","sha256":"{sha}"}}]}}]"#
    )
}

fn make_go_tar_gz() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut tar = tar::Builder::new(enc);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_cksum();
        tar.append_data(&mut header, "go/bin/go", std::io::empty())
            .unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_cksum();
        tar.append_data(&mut header, "go/bin/gofmt", std::io::empty())
            .unwrap();
        tar.finish().unwrap();
    }
    bytes
}

#[test]
fn go_os_arch_maps() {
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();
    assert_eq!(go_os_arch(&ctx), ("linux".into(), "amd64".into()));
    ctx.os = "macos".into();
    ctx.arch = "aarch64".into();
    assert_eq!(go_os_arch(&ctx), ("darwin".into(), "arm64".into()));
}

#[test]
fn go_os_arch_windows_other() {
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    ctx.arch = "mips".into();
    assert_eq!(go_os_arch(&ctx), ("windows".into(), "mips".into()));
    ctx.os = "plan9".into();
    ctx.arch = "sparc".into();
    assert_eq!(go_os_arch(&ctx), ("plan9".into(), "sparc".into()));
}

#[test]
fn go_latest_and_pick_file() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://go.dev/dl/?mode=json";
    let json = r#"[{"version":"go1.2.3","stable":true,"files":[]},{"version":"go1.2.4","stable":true,"files":[]}]"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = go_latest(&ctx).unwrap();
    assert_eq!(v.to_string(), "1.2.4");

    let json = r#"[{"version":"go1.2.3","stable":true,"files":[{"filename":"go1.2.3.linux-amd64.tar.gz","os":"linux","arch":"amd64","kind":"archive","sha256":"abc"}]}]"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = Version {
        major: 1,
        minor: 2,
        patch: 3,
        pre: None,
    };
    let (dl, sha) = go_pick_file(&ctx, &v).unwrap();
    assert!(dl.ends_with(".tar.gz"));
    assert_eq!(sha, "abc");
}

#[test]
fn go_latest_no_stable() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://go.dev/dl/?mode=json";
    let json = r#"[{"version":"go1.2.3","stable":false,"files":[]}]"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let err = go_latest(&ctx).unwrap_err();
    assert!(err.to_string().contains("latest Go"));
}

#[test]
fn go_latest_fallback_url() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let primary = "https://go.dev/dl/?mode=json";
    let fallback = "https://golang.org/dl/?mode=json";
    let json = r#"[{"version":"go1.2.3","stable":true,"files":[]}]"#;
    set_http_plan(primary, vec![Err("no".to_string())]);
    set_http_plan(
        fallback,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = go_latest(&ctx).unwrap();
    assert_eq!(v.to_string(), "1.2.3");
}

#[test]
fn update_go_latest_unknown() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://go.dev/dl/?mode=json";
    let json = r#"[{"version":"go1.2.3","stable":false,"files":[]}]"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("go", None);
    let err = update_go(&ctx).unwrap_err();
    assert!(err.to_string().contains("latest unknown"));
}

#[test]
fn update_go_existing_wrappers_and_prune_warn() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let tool_root = ctx.home.join("go");
    let active = tool_root.join("active");
    fs::create_dir_all(&tool_root).unwrap();
    let old_active = tool_root.join("old");
    fs::create_dir_all(&old_active).unwrap();
    upkit::atomic_symlink(&old_active, &active).unwrap();
    set_which("go", None);
    let url = "https://go.dev/dl/?mode=json";

    let tar_bytes = make_go_tar_gz();
    let mut hasher = Sha256::new();
    hasher.update(&tar_bytes);
    let good_sha = hex::encode(hasher.finalize());
    let json = go_json("go1.2.3", &good_sha);
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );

    let dl = "https://go.dev/dl/go1.2.3.linux-amd64.tar.gz";
    set_http_plan(
        dl,
        vec![Ok(MockResponse::new(
            tar_bytes.clone(),
            Some(tar_bytes.len() as u64),
        ))],
    );

    set_prune_tool_versions_error(Some("prune".to_string()));
    update_go(&ctx).unwrap();
    set_prune_tool_versions_error(None);
}

#[test]
fn go_pick_file_missing() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://go.dev/dl/?mode=json";
    let json = r#"[{"version":"go9.9.9","stable":true,"files":[]}]"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = Version {
        major: 9,
        minor: 9,
        patch: 9,
        pre: None,
    };
    assert!(go_pick_file(&ctx, &v).is_err());
}

#[test]
fn go_pick_file_version_mismatch() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://go.dev/dl/?mode=json";
    let json = r#"[{"version":"go1.2.4","stable":true,"files":[]}]"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    let v = Version {
        major: 1,
        minor: 2,
        patch: 3,
        pre: None,
    };
    assert!(go_pick_file(&ctx, &v).is_err());
}

#[test]
fn go_check_statuses() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://go.dev/dl/?mode=json";
    let json = r#"[{"version":"go1.2.3","stable":true,"files":[]}]"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("go", None);
    let report = check_go(&ctx).unwrap();
    assert!(matches!(report.status, Status::NotInstalled));

    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("go", Some(PathBuf::from("/bin/go")));
    set_run_output(
        "go",
        &["version"],
        output_with_status(0, b"go version go1.2.3 linux/amd64", b""),
    );
    let report = check_go(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));
}

#[test]
fn go_check_uses_bindir() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let bindir_go = ctx.bindir.join("go");
    fs::create_dir_all(&ctx.bindir).unwrap();
    fs::write(&bindir_go, b"").unwrap();
    let url = "https://go.dev/dl/?mode=json";
    let json = r#"[{"version":"go1.2.3","stable":true,"files":[]}]"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("go", None);
    set_run_output(
        bindir_go.to_string_lossy().as_ref(),
        &["version"],
        output_with_status(0, b"go version go1.2.3 linux/amd64", b""),
    );
    let report = check_go(&ctx).unwrap();
    assert!(matches!(report.status, Status::UpToDate));
}

#[test]
fn go_check_outdated_and_unknown() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://go.dev/dl/?mode=json";
    let json = r#"[{"version":"go1.2.3","stable":true,"files":[]}]"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("go", Some(PathBuf::from("/bin/go")));
    set_run_output(
        "go",
        &["version"],
        output_with_status(0, b"go version go1.2.2 linux/amd64", b""),
    );
    let report = check_go(&ctx).unwrap();
    assert!(matches!(report.status, Status::Outdated));

    let url = "https://go.dev/dl/?mode=json";
    set_http_plan(url, vec![Err("no".to_string())]);
    let report = check_go(&ctx).unwrap();
    assert!(matches!(report.status, Status::Unknown));
}

#[test]
fn update_go_offline_and_dry_run() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.offline = true;
    assert!(update_go(&ctx).is_err());

    ctx.offline = false;
    ctx.dry_run = true;
    let url = "https://go.dev/dl/?mode=json";
    let json = r#"[{"version":"go1.2.3","stable":true,"files":[{"filename":"go1.2.3.linux-amd64.tar.gz","os":"linux","arch":"amd64","kind":"archive","sha256":"abc"}]}]"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    set_which("go", None);
    update_go(&ctx).unwrap();
}

#[test]
fn update_go_up_to_date() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://go.dev/dl/?mode=json";
    let json = r#"[{"version":"go1.2.3","stable":true,"files":[]}]"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    set_which("go", Some(PathBuf::from("/bin/go")));
    set_run_output(
        "go",
        &["version"],
        output_with_status(0, b"go version go1.2.3 linux/amd64", b""),
    );
    update_go(&ctx).unwrap();
}

#[test]
fn update_go_sha_mismatch_and_success() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let url = "https://go.dev/dl/?mode=json";
    let archive = make_go_tar_gz();
    let sha = hex::encode(Sha256::digest(&archive));
    let json = go_json("go1.2.3", "badsum");
    set_which("go", None);
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    let dl = "https://go.dev/dl/go1.2.3.linux-amd64.tar.gz";
    set_http_plan(
        dl,
        vec![Ok(MockResponse::new(
            archive.clone(),
            Some(archive.len() as u64),
        ))],
    );
    let err = update_go(&ctx).unwrap_err();
    assert!(err.to_string().contains("sha256 mismatch"));

    let json = go_json("go1.2.3", &sha);
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    set_http_plan(
        dl,
        vec![Ok(MockResponse::new(
            archive.clone(),
            Some(archive.len() as u64),
        ))],
    );
    update_go(&ctx).unwrap();
    assert!(ctx.home.join("go").exists());
}

#[test]
fn go_env_value_uses_env() {
    let _guard = reset_guard();
    set_env_var("GOBIN", Some(" /tmp/gobin ".to_string()));
    let value = upkit::tools::go::go_env_value(None, "GOBIN");
    assert_eq!(value.as_deref(), Some("/tmp/gobin"));
}

#[test]
fn go_env_value_runs_go_env() {
    let _guard = reset_guard();
    set_env_var("GOPATH", None);
    set_run_output(
        "go",
        &["env", "GOPATH"],
        output_with_status(0, b"/opt/go\n", b""),
    );
    let value = upkit::tools::go::go_env_value(None, "GOPATH");
    assert_eq!(value.as_deref(), Some("/opt/go"));
}

#[test]
fn go_env_value_uses_env_for_gopath() {
    let _guard = reset_guard();
    set_env_var("GOPATH", Some(" /tmp/gopath ".to_string()));
    let value = upkit::tools::go::go_env_value(None, "GOPATH");
    assert_eq!(value.as_deref(), Some("/tmp/gopath"));
}

#[test]
fn go_env_paths_from_env_and_default() {
    let _guard = reset_guard();
    set_env_var("GOPATH", Some("/a:/b".to_string()));
    let paths = upkit::tools::go::go_env_paths(None, "GOPATH");
    assert_eq!(paths.len(), 2);

    set_env_var("GOPATH", None);
    set_run_output("go", &["env", "GOPATH"], output_with_status(0, b"\n", b""));
    set_home_dir(Some(std::path::PathBuf::from("/tmp")));
    let paths = upkit::tools::go::go_env_paths(None, "GOPATH");
    assert_eq!(paths, vec![std::path::PathBuf::from("/tmp/go")]);
}

#[test]
fn go_env_paths_empty_for_unknown_key() {
    let _guard = reset_guard();
    set_env_var("GOROOT", None);
    set_run_output("go", &["env", "GOROOT"], output_with_status(0, b"\n", b""));
    let paths = upkit::tools::go::go_env_paths(None, "GOROOT");
    assert!(paths.is_empty());
}

#[test]
fn ensure_go_wrappers_hints_from_gobin() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(home.clone(), bindir.clone(), prompt);
    ctx.quiet = true;
    fs::create_dir_all(&bindir).unwrap();
    let tool_root = home.join("go");
    let active = tool_root.join("active");
    fs::create_dir_all(&active).unwrap();
    set_env_var("GOBIN", Some("/tmp/gobin".to_string()));
    upkit::tools::go::ensure_go_wrappers(&ctx, &tool_root, &active).unwrap();
}

#[test]
fn parse_go_version_metadata_skips_devel() {
    let output = "example\nmod example.com/tool (devel)\n";
    assert!(parse_go_version_metadata(output).is_none());
}

#[test]
fn parse_go_version_metadata_extracts_mod() {
    let output = "example\nmod example.com/tool v1.2.3\n";
    let spec = parse_go_version_metadata(output).unwrap();
    assert_eq!(spec.module, "example.com/tool");
    assert_eq!(spec.version, "v1.2.3");
}

#[test]
fn go_global_bin_dirs_prefers_gobin() {
    let _guard = reset_guard();
    set_env_var("GOBIN", Some("/tmp/gobin".to_string()));
    set_env_var("GOPATH", Some("/tmp/gopath".to_string()));
    let dirs = go_global_bin_dirs(None);
    assert_eq!(dirs, vec![std::path::PathBuf::from("/tmp/gobin")]);
}

#[test]
fn go_tool_spec_from_binary_uses_version_output() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let binary = dir.path().join("tool");
    fs::write(&binary, b"").unwrap();
    set_run_output(
        "go",
        &["version", "-m", binary.to_string_lossy().as_ref()],
        output_with_status(0, b"example\nmod example.com/tool v1.2.3\n", b""),
    );
    let spec = go_tool_spec_from_binary(None, &binary).unwrap();
    assert_eq!(spec.module, "example.com/tool");
    assert_eq!(spec.version, "v1.2.3");
}

#[test]
fn restore_go_globals_runs_install() {
    let _guard = reset_guard();
    set_run_output(
        "go",
        &["install", "example.com/tool@v1.2.3"],
        output_with_status(0, b"", b""),
    );
    let tools = vec![GoToolSpec {
        module: "example.com/tool".to_string(),
        version: "v1.2.3".to_string(),
    }];
    restore_go_globals(None, &tools).unwrap();
}

#[test]
fn go_global_tools_reads_gobin_dir() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let gobin = dir.path().join("bin");
    fs::create_dir_all(&gobin).unwrap();
    let binary = gobin.join("tool");
    fs::write(&binary, b"").unwrap();
    set_env_var("GOBIN", Some(gobin.to_string_lossy().to_string()));
    set_run_output(
        "go",
        &["version", "-m", binary.to_string_lossy().as_ref()],
        output_with_status(0, b"example\nmod example.com/tool v1.2.3\n", b""),
    );
    let tools = go_global_tools(None).unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].module, "example.com/tool");
}
