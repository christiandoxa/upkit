#[cfg(windows)]
#[path = "support/windows_symlinks.rs"]
mod windows_symlinks;

#[cfg(any(unix, windows))]
use sha2::{Digest, Sha512};
use std::{fs, sync::Arc};
use upkit::{
    Status, ToolKind,
    test_support::{MockResponse, TestPrompt, base_ctx, reset_guard, set_http_plan, set_which},
    tools::dotnet::{check_dotnet, update_dotnet},
};

const INDEX: &str =
    "https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json";
const RELEASES: &str =
    "https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json";
const DOWNLOAD: &str =
    "https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.403/dotnet-sdk-linux-x64.tar.gz";

fn index() -> Vec<u8> {
    br#"{"releases-index":[{"channel-version":"11.0","latest-sdk":"11.0.100-preview.1","release-type":"sts","support-phase":"go-live"},{"channel-version":"8.0","latest-sdk":"8.0.426","release-type":"lts","support-phase":"maintenance"},{"channel-version":"10.0","latest-sdk":"10.0.403","release-type":"lts","support-phase":"active"}]}"#.to_vec()
}

fn metadata(hash: &str) -> Vec<u8> {
    metadata_with_url(hash, DOWNLOAD)
}

fn metadata_with_url(hash: &str, url: &str) -> Vec<u8> {
    format!(r#"{{"releases":[{{"sdks":[{{"version":"10.0.403","files":[{{"name":"dotnet-sdk-linux-x64.tar.gz","rid":"linux-x64","url":"{url}","hash":"{hash}"}}]}}]}}]}}"#).into_bytes()
}

fn plan(hash: &str) {
    plan_with_url(hash, DOWNLOAD);
}

fn plan_with_url(hash: &str, url: &str) {
    set_http_plan(INDEX, vec![Ok(MockResponse::new(index(), None))]);
    set_http_plan(
        RELEASES,
        vec![Ok(MockResponse::new(metadata_with_url(hash, url), None))],
    );
}

fn plan_windows(hash: &str) {
    let mut value: serde_json::Value = serde_json::from_slice(&metadata(hash)).unwrap();
    let asset = &mut value["releases"][0]["sdks"][0]["files"][0];
    asset["name"] = "dotnet-sdk-win-arm64.zip".into();
    asset["rid"] = "win-arm64".into();
    set_http_plan(INDEX, vec![Ok(MockResponse::new(index(), None))]);
    set_http_plan(
        RELEASES,
        vec![Ok(MockResponse::new(
            serde_json::to_vec(&value).unwrap(),
            None,
        ))],
    );
}

#[cfg(any(unix, windows))]
fn windows_archive(include_runtime: bool) -> Vec<u8> {
    use std::io::{Cursor, Write};
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let mut names = vec![
        "dotnet.exe",
        "sdk/10.0.403/dotnet.dll",
        "host/fxr/10/hostfxr.dll",
    ];
    if include_runtime {
        names.push("shared/Microsoft.NETCore.App/10/coreclr.dll");
    }
    for name in names {
        zip.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
        zip.write_all(b"fixture").unwrap();
    }
    zip.finish().unwrap().into_inner()
}

#[cfg(unix)]
fn archive() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        for name in [
            "sdk",
            "sdk/10.0.403",
            "host",
            "host/fxr",
            "host/fxr/10",
            "shared",
            "shared/Microsoft.NETCore.App",
            "shared/Microsoft.NETCore.App/10",
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_mode(0o755);
            header.set_size(0);
            header.set_cksum();
            tar.append_data(&mut header, name, std::io::empty())
                .unwrap();
        }
        for name in [
            "dotnet",
            "sdk/10.0.403/dotnet.dll",
            "host/fxr/10/libhostfxr.so",
            "shared/Microsoft.NETCore.App/10/libcoreclr.so",
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o755);
            header.set_size(7);
            header.set_cksum();
            tar.append_data(&mut header, name, &b"fixture"[..]).unwrap();
        }
        tar.finish().unwrap();
    }
    bytes
}

fn fixture() -> (upkit::Ctx, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut ctx = base_ctx(
        dir.path().join("managed"),
        dir.path().join("bin"),
        Arc::new(TestPrompt::default()),
    );
    ctx.quiet = true;
    set_which("dotnet", None);
    (ctx, dir)
}

#[test]
fn detects_only_complete_stable_sdk_without_running_dotnet_and_selects_supported_lts() {
    let _guard = reset_guard();
    let (ctx, dir) = fixture();
    let host = dir.path().join("dotnet");
    fs::write(&host, "not executed").unwrap();
    let sdk = dir.path().join("sdk/10.0.100");
    fs::create_dir_all(&sdk).unwrap();
    fs::write(sdk.join("dotnet.dll"), b"fixture SDK").unwrap();
    fs::create_dir_all(dir.path().join("sdk/99.0.0")).unwrap();
    fs::create_dir_all(dir.path().join("sdk/11.0.100-preview.1")).unwrap();
    set_which("dotnet", Some(host));
    plan(&"a".repeat(128));
    let report = check_dotnet(&ctx).unwrap();
    assert_eq!(report.tool, ToolKind::Dotnet);
    assert_eq!(report.installed.unwrap().to_string(), "10.0.100");
    assert_eq!(report.latest.unwrap().to_string(), "10.0.403");
    assert_eq!(report.status, Status::Outdated);
}

#[test]
fn incomplete_sdk_layout_reports_unknown_instead_of_not_installed() {
    let _guard = reset_guard();
    let (ctx, dir) = fixture();
    let host = dir.path().join("dotnet");
    fs::write(&host, "not executed").unwrap();
    fs::create_dir_all(dir.path().join("sdk/10.0.100")).unwrap();
    set_which("dotnet", Some(host));
    plan(&"a".repeat(128));

    let report = check_dotnet(&ctx).unwrap();
    assert!(report.installed.is_none());
    assert_eq!(report.status, Status::Unknown);
    assert!(report.notes.iter().any(|note| note.contains("incomplete")));
}

#[test]
fn host_wrapper_with_sdk_elsewhere_reports_unknown_without_running_it() {
    let _guard = reset_guard();
    let (ctx, dir) = fixture();
    let host = dir.path().join("usr/bin/dotnet");
    fs::create_dir_all(host.parent().unwrap()).unwrap();
    fs::write(&host, "not executed").unwrap();
    let sdk = dir.path().join("usr/lib/dotnet/sdk/10.0.100");
    fs::create_dir_all(&sdk).unwrap();
    fs::write(sdk.join("dotnet.dll"), b"fixture SDK").unwrap();
    set_which("dotnet", Some(host));
    plan(&"a".repeat(128));

    let report = check_dotnet(&ctx).unwrap();
    assert!(report.installed.is_none());
    assert_eq!(report.status, Status::Unknown);
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("stored elsewhere"))
    );
}

#[test]
fn empty_sdk_directory_reports_unknown() {
    let _guard = reset_guard();
    let (ctx, dir) = fixture();
    let host = dir.path().join("dotnet");
    fs::write(&host, "not executed").unwrap();
    fs::create_dir_all(dir.path().join("sdk")).unwrap();
    set_which("dotnet", Some(host));
    plan(&"a".repeat(128));

    let report = check_dotnet(&ctx).unwrap();

    assert!(report.installed.is_none());
    assert_eq!(report.status, Status::Unknown);
}

#[test]
fn sdk_directory_with_only_prerelease_sdk_reports_unknown() {
    let _guard = reset_guard();
    let (ctx, dir) = fixture();
    let host = dir.path().join("dotnet");
    fs::write(&host, "not executed").unwrap();
    let preview = dir.path().join("sdk/10.0.403-preview.1");
    fs::create_dir_all(&preview).unwrap();
    fs::write(preview.join("dotnet.dll"), b"fixture SDK").unwrap();
    set_which("dotnet", Some(host));
    plan(&"a".repeat(128));

    let report = check_dotnet(&ctx).unwrap();

    assert!(report.installed.is_none());
    assert_eq!(report.status, Status::Unknown);
    assert!(report.notes.iter().any(|note| note.contains("prerelease")));
}

#[test]
fn sdk_directory_with_only_nonversion_entries_reports_unknown() {
    let _guard = reset_guard();
    let (ctx, dir) = fixture();
    let host = dir.path().join("dotnet");
    fs::write(&host, "not executed").unwrap();
    let sdk = dir.path().join("sdk");
    fs::create_dir_all(&sdk).unwrap();
    fs::write(sdk.join("sentinel"), b"fixture").unwrap();
    set_which("dotnet", Some(host));
    plan(&"a".repeat(128));

    let report = check_dotnet(&ctx).unwrap();

    assert!(report.installed.is_none());
    assert_eq!(report.status, Status::Unknown);
}

#[test]
fn rejects_untrusted_dotnet_archive_host_before_download() {
    let _guard = reset_guard();
    let (ctx, _dir) = fixture();
    plan_with_url(
        &"a".repeat(128),
        "https://attacker.invalid/dotnet-sdk-linux-x64.tar.gz",
    );

    let error = update_dotnet(&ctx).unwrap_err();

    assert!(error.to_string().contains("official HTTPS archive URL"));
    assert!(!ctx.home.exists());
}

#[test]
fn accepts_legacy_official_dotnet_archive_cdns() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = fixture();
    ctx.dry_run = true;
    for url in [
        "https://download.visualstudio.microsoft.com/download/pr/fixture/dotnet-sdk-linux-x64.tar.gz",
        "https://dotnetcli.azureedge.net/dotnet/Sdk/10.0.403/dotnet-sdk-linux-x64.tar.gz",
    ] {
        plan_with_url(&"a".repeat(128), url);
        update_dotnet(&ctx).unwrap();
    }

    assert!(!ctx.home.exists());
}

#[cfg(unix)]
#[test]
fn detects_sdk_dll_symlink_within_sdk_version_directory() {
    use std::os::unix::fs::symlink;
    let _guard = reset_guard();
    let (ctx, dir) = fixture();
    let host = dir.path().join("dotnet");
    fs::write(&host, "not executed").unwrap();
    let sdk = dir.path().join("sdk/10.0.100");
    fs::create_dir_all(sdk.join("lib")).unwrap();
    fs::write(sdk.join("lib/dotnet.dll"), b"fixture SDK").unwrap();
    symlink("lib/dotnet.dll", sdk.join("dotnet.dll")).unwrap();
    set_which("dotnet", Some(host));
    plan(&"a".repeat(128));

    let report = check_dotnet(&ctx).unwrap();
    assert_eq!(report.installed.unwrap().to_string(), "10.0.100");
}

#[cfg(unix)]
#[test]
fn ignores_sdk_dll_symlink_to_another_version_inside_install_root() {
    use std::os::unix::fs::symlink;
    let _guard = reset_guard();
    let (ctx, dir) = fixture();
    let host = dir.path().join("dotnet");
    fs::write(&host, "not executed").unwrap();
    let old_sdk = dir.path().join("sdk/10.0.100");
    fs::create_dir_all(&old_sdk).unwrap();
    fs::write(old_sdk.join("dotnet.dll"), b"fixture SDK").unwrap();
    let latest_sdk = dir.path().join("sdk/10.0.403");
    fs::create_dir_all(&latest_sdk).unwrap();
    symlink("../10.0.100/dotnet.dll", latest_sdk.join("dotnet.dll")).unwrap();
    set_which("dotnet", Some(host));
    plan(&"a".repeat(128));

    let report = check_dotnet(&ctx).unwrap();

    assert_eq!(report.installed.unwrap().to_string(), "10.0.100");
    assert_eq!(report.status, Status::Outdated);
}

#[cfg(unix)]
#[test]
fn ignores_sdk_version_directory_symlink_when_detecting_installed_sdk() {
    use std::os::unix::fs::symlink;
    let _guard = reset_guard();
    let (ctx, dir) = fixture();
    let host = dir.path().join("dotnet");
    fs::write(&host, "not executed").unwrap();
    let sdk = dir.path().join("sdk/10.0.100");
    fs::create_dir_all(&sdk).unwrap();
    fs::write(sdk.join("dotnet.dll"), b"fixture SDK").unwrap();
    symlink("10.0.100", dir.path().join("sdk/99.0.0")).unwrap();
    set_which("dotnet", Some(host));
    plan(&"a".repeat(128));

    let report = check_dotnet(&ctx).unwrap();

    assert_eq!(report.installed.unwrap().to_string(), "10.0.100");
    assert_eq!(report.status, Status::Outdated);
}

#[cfg(unix)]
#[test]
fn installs_verified_sdk_and_preserves_existing_versions() {
    let _guard = reset_guard();
    let (ctx, _dir) = fixture();
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(&ctx.home).unwrap();
    fs::set_permissions(&ctx.home, fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir_all(&ctx.bindir).unwrap();
    fs::set_permissions(&ctx.bindir, fs::Permissions::from_mode(0o755)).unwrap();
    let tool_root = ctx.home.join("dotnet");
    fs::create_dir_all(tool_root.join("old")).unwrap();
    fs::set_permissions(&tool_root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(tool_root.join("old"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(ctx.home.join("dotnet/old/keep"), "keep").unwrap();
    fs::set_permissions(
        tool_root.join("old/keep"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let bytes = archive();
    plan(&hex::encode(Sha512::digest(&bytes)));
    set_http_plan(
        DOWNLOAD,
        vec![Ok(MockResponse::new(
            bytes.clone(),
            Some(bytes.len() as u64),
        ))],
    );
    update_dotnet(&ctx).unwrap();
    assert_eq!(fs::read(ctx.bindir.join("dotnet")).unwrap(), b"fixture");
    assert_eq!(
        fs::read_to_string(ctx.home.join("dotnet/old/keep")).unwrap(),
        "keep"
    );
    #[cfg(target_os = "linux")]
    {
        let preview = upkit::managed_cleanup::preview(
            &ctx,
            ToolKind::Dotnet,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(preview.root, ctx.home.join("dotnet"));
        assert!(preview.links.contains(&ctx.bindir.join("dotnet")));
    }
}

#[cfg(unix)]
#[test]
fn rejects_bad_hash_and_binary_conflict_without_replacing_files() {
    let _guard = reset_guard();
    let (ctx, _dir) = fixture();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let bytes = archive();
    plan(&"0".repeat(128));
    set_http_plan(
        DOWNLOAD,
        vec![Ok(MockResponse::new(
            bytes.clone(),
            Some(bytes.len() as u64),
        ))],
    );
    assert!(
        update_dotnet(&ctx)
            .unwrap_err()
            .to_string()
            .contains("SHA-512")
    );
    assert!(!ctx.home.join("dotnet/active").exists());
    fs::write(ctx.bindir.join("dotnet"), "unrelated").unwrap();
    plan(&hex::encode(Sha512::digest(&bytes)));
    set_http_plan(
        DOWNLOAD,
        vec![Ok(MockResponse::new(
            bytes.clone(),
            Some(bytes.len() as u64),
        ))],
    );
    assert!(update_dotnet(&ctx).is_err());
    assert_eq!(
        fs::read_to_string(ctx.bindir.join("dotnet")).unwrap(),
        "unrelated"
    );
    assert!(!ctx.home.join("dotnet/active").exists());
}

#[test]
fn dry_run_and_offline_do_not_modify_files() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = fixture();
    ctx.dry_run = true;
    plan(&"a".repeat(128));
    update_dotnet(&ctx).unwrap();
    assert!(!ctx.home.exists() && !ctx.bindir.exists());
    ctx.offline = true;
    assert!(update_dotnet(&ctx).is_err());
    ctx.offline = false;
    ctx.os = "windows".into();
    ctx.arch = "aarch64".into();
    plan_windows(&"a".repeat(128));
    update_dotnet(&ctx).unwrap();
    assert!(!ctx.home.exists() && !ctx.bindir.exists());
}

#[cfg(any(unix, windows))]
#[test]
fn installs_windows_arm64_sdk_with_exe_link_and_rejects_missing_runtime() {
    #[cfg(windows)]
    if !windows_symlinks::available() {
        return;
    }
    let _guard = reset_guard();
    let (mut ctx, _dir) = fixture();
    ctx.os = "windows".into();
    ctx.arch = "aarch64".into();
    fs::create_dir_all(&ctx.bindir).unwrap();
    fs::create_dir_all(ctx.home.join("dotnet/old")).unwrap();
    fs::write(ctx.home.join("dotnet/old/keep"), "keep").unwrap();
    let bad = windows_archive(false);
    plan_windows(&hex::encode(Sha512::digest(&bad)));
    set_http_plan(DOWNLOAD, vec![Ok(MockResponse::new(bad, None))]);
    assert!(update_dotnet(&ctx).is_err());
    assert!(!ctx.home.join("dotnet/active").exists());
    let good = windows_archive(true);
    let hash = hex::encode(Sha512::digest(&good));
    plan_windows(&hash);
    let report = check_dotnet(&ctx).unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("permission to create symbolic links"))
    );
    fs::write(ctx.bindir.join("dotnet.exe"), "unrelated").unwrap();
    plan_windows(&hash);
    set_http_plan(DOWNLOAD, vec![Ok(MockResponse::new(good.clone(), None))]);
    assert!(update_dotnet(&ctx).is_err());
    assert_eq!(
        fs::read_to_string(ctx.bindir.join("dotnet.exe")).unwrap(),
        "unrelated"
    );
    assert!(!ctx.home.join("dotnet/active").exists());
    fs::remove_file(ctx.bindir.join("dotnet.exe")).unwrap();
    plan_windows(&hash);
    set_http_plan(DOWNLOAD, vec![Ok(MockResponse::new(good, None))]);
    update_dotnet(&ctx).unwrap();
    assert_eq!(fs::read(ctx.bindir.join("dotnet.exe")).unwrap(), b"fixture");
    assert!(!ctx.bindir.join("dotnet").exists());
    assert_eq!(
        fs::read_to_string(ctx.home.join("dotnet/old/keep")).unwrap(),
        "keep"
    );
}

#[test]
fn rejects_untrusted_or_duplicate_sdk_assets() {
    let _guard = reset_guard();
    let (ctx, _dir) = fixture();
    let valid: serde_json::Value = serde_json::from_slice(&metadata(&"a".repeat(128))).unwrap();
    let mut bad_rid = valid.clone();
    bad_rid["releases"][0]["sdks"][0]["files"][0]["rid"] = "linux-arm64".into();
    let mut bad_url = valid.clone();
    bad_url["releases"][0]["sdks"][0]["files"][0]["url"] =
        "http://example.invalid/sdk.tar.gz".into();
    let mut duplicate = valid.clone();
    let file = duplicate["releases"][0]["sdks"][0]["files"][0].clone();
    duplicate["releases"][0]["sdks"][0]["files"]
        .as_array_mut()
        .unwrap()
        .push(file);
    for metadata in [bad_rid, bad_url, duplicate] {
        set_http_plan(INDEX, vec![Ok(MockResponse::new(index(), None))]);
        set_http_plan(
            RELEASES,
            vec![Ok(MockResponse::new(
                serde_json::to_vec(&metadata).unwrap(),
                None,
            ))],
        );
        assert!(update_dotnet(&ctx).is_err());
        assert!(!ctx.home.exists());
    }
}

#[cfg(unix)]
#[test]
fn offline_cli_infers_sdk_without_executing_dotnet() {
    use std::{os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("fake-bin");
    fs::create_dir(&bin).unwrap();
    let host = bin.join("dotnet");
    fs::write(&host, "#!/bin/sh\nprintf invoked > \"$HOME/invoked\"\n").unwrap();
    fs::set_permissions(&host, fs::Permissions::from_mode(0o755)).unwrap();
    let sdk = bin.join("sdk/10.0.100");
    fs::create_dir_all(&sdk).unwrap();
    fs::write(sdk.join("dotnet.dll"), b"fixture SDK").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args([
            "--offline",
            "--non-interactive",
            "--json",
            "--only",
            "dotnet",
            "check",
        ])
        .env("HOME", dir.path())
        .env("PATH", &bin)
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report[0]["tool"], "dotnet");
    assert_eq!(report[0]["installed"], "10.0.100");
    assert!(report[0]["latest"].is_null());
    assert!(!dir.path().join("invoked").exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}
