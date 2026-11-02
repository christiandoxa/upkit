#[cfg(windows)]
#[path = "support/windows_symlinks.rs"]
mod windows_symlinks;

#[cfg(any(unix, windows))]
use sha2::{Digest, Sha256};
#[cfg(any(unix, windows))]
use std::fs;
use std::{path::PathBuf, sync::Arc};
use upkit::{
    Status, ToolKind,
    test_support::{
        MockResponse, TestPrompt, base_ctx, output_with_status, reset_guard, set_http_plan,
        set_run_output, set_which,
    },
    tools::java::{check_java, update_java},
};

const AVAILABLE: &str = "https://api.adoptium.net/v3/info/available_releases";
const ASSETS: &str = "https://api.adoptium.net/v3/assets/latest/25/hotspot?architecture=x64&heap_size=normal&image_type=jdk&os=linux&vendor=eclipse";
const DOWNLOAD: &str = "https://example.invalid/temurin.tar.gz";

fn metadata(checksum: &str) -> String {
    format!(
        r#"[{{"vendor":"eclipse","binary":{{"architecture":"x64","os":"linux","image_type":"jdk","jvm_impl":"hotspot","heap_size":"normal","package":{{"name":"jdk.tar.gz","link":"{DOWNLOAD}","checksum":"{checksum}"}}}},"version":{{"major":25,"minor":0,"security":5}}}}]"#
    )
}

fn plan_metadata(checksum: &str) {
    set_http_plan(
        AVAILABLE,
        vec![Ok(MockResponse::new(
            br#"{"most_recent_lts":25}"#.to_vec(),
            None,
        ))],
    );
    set_http_plan(
        ASSETS,
        vec![Ok(MockResponse::new(metadata(checksum).into_bytes(), None))],
    );
}

fn plan_windows_metadata(checksum: &str) {
    let mut asset: serde_json::Value = serde_json::from_str(&metadata(checksum)).unwrap();
    asset[0]["binary"]["os"] = "windows".into();
    asset[0]["binary"]["package"]["name"] = "jdk.zip".into();
    set_http_plan(
        AVAILABLE,
        vec![Ok(MockResponse::new(
            br#"{"most_recent_lts":25}"#.to_vec(),
            None,
        ))],
    );
    set_http_plan(
        "https://api.adoptium.net/v3/assets/latest/25/hotspot?architecture=x64&heap_size=normal&image_type=jdk&os=windows&vendor=eclipse",
        vec![Ok(MockResponse::new(
            serde_json::to_vec(&asset).unwrap(),
            None,
        ))],
    );
}

#[cfg(any(unix, windows))]
fn windows_archive(include_compiler: bool) -> Vec<u8> {
    use std::io::{Cursor, Write};
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let names = if include_compiler {
        vec!["jdk/bin/java.exe", "jdk/bin/javac.exe", "jdk/bin/jar.exe"]
    } else {
        vec!["jdk/bin/java.exe"]
    };
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
        for name in ["jdk", "jdk/bin"] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_mode(0o755);
            header.set_size(0);
            header.set_cksum();
            tar.append_data(&mut header, name, std::io::empty())
                .unwrap();
        }
        for name in ["jdk/bin/java", "jdk/bin/javac"] {
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
    set_which("javac", None);
    (ctx, dir)
}

fn existing_java_install(ctx: &upkit::Ctx) {
    fs::create_dir_all(&ctx.home).unwrap();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let root = ctx.home.join("java");
    fs::create_dir_all(root.join("old")).unwrap();
    #[cfg(unix)]
    let old = root.join("old");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for directory in [&ctx.home, &ctx.bindir, &root, &old] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    fs::write(root.join("old/keep"), "keep").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.join("old/keep"), fs::Permissions::from_mode(0o644)).unwrap();
    }
}

#[test]
fn checks_lts_and_detects_installed_jdk_version() {
    let _guard = reset_guard();
    let (ctx, _dir) = fixture();
    set_which("javac", Some(PathBuf::from("/fixture/javac")));
    set_run_output(
        "/fixture/javac",
        &["-version"],
        output_with_status(0, b"", b"javac 25.0.4+7\n"),
    );
    plan_metadata(&"a".repeat(64));
    let report = check_java(&ctx).unwrap();
    assert_eq!(report.tool, ToolKind::Java);
    assert_eq!(report.installed.unwrap().to_string(), "25.0.4");
    assert_eq!(report.latest.unwrap().to_string(), "25.0.5");
    assert_eq!(report.status, Status::Outdated);
}

#[test]
fn supports_legacy_javac_versions_and_offline_checks() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = fixture();
    ctx.offline = true;
    set_which("javac", Some(PathBuf::from("/fixture/javac")));
    set_run_output(
        "/fixture/javac",
        &["-version"],
        output_with_status(0, b"javac 1.8.0_452\n", b""),
    );
    let report = check_java(&ctx).unwrap();
    assert_eq!(report.installed.unwrap().to_string(), "8.0.452");
    assert!(report.latest.is_none());
    assert!(update_java(&ctx).is_err());
    assert!(!ctx.home.exists());
}

#[test]
fn macos_does_not_run_the_javac_installation_shim_without_a_jdk() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = fixture();
    ctx.os = "macos".into();
    ctx.offline = true;
    set_which("javac", Some(PathBuf::from("/usr/bin/javac")));
    set_run_output(
        "/usr/libexec/java_home",
        &["--failfast"],
        output_with_status(1, b"", b"Unable to find a Java Runtime"),
    );
    // This successful mock would be returned if the Apple shim were invoked.
    set_run_output(
        "/usr/bin/javac",
        &["-version"],
        output_with_status(0, b"", b"javac 25.0.4+7\n"),
    );

    let report = check_java(&ctx).unwrap();

    assert!(report.installed.is_none());
}

#[test]
fn macos_resolves_a_registered_jdk_before_running_javac() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = fixture();
    ctx.os = "macos".into();
    ctx.offline = true;
    set_which("javac", Some(PathBuf::from("/usr/bin/javac")));
    set_run_output(
        "/usr/libexec/java_home",
        &["--failfast"],
        output_with_status(
            0,
            b"/Library/Java/JavaVirtualMachines/temurin.jdk/Contents/Home\n",
            b"",
        ),
    );
    set_run_output(
        "/Library/Java/JavaVirtualMachines/temurin.jdk/Contents/Home/bin/javac",
        &["-version"],
        output_with_status(0, b"", b"javac 25.0.4+7\n"),
    );

    let report = check_java(&ctx).unwrap();

    assert_eq!(report.installed.unwrap().to_string(), "25.0.4");
}

#[cfg(unix)]
#[test]
fn installs_verified_archive_and_preserves_existing_data() {
    let _guard = reset_guard();
    let (ctx, _dir) = fixture();
    existing_java_install(&ctx);
    let bytes = archive();
    plan_metadata(&hex::encode(Sha256::digest(&bytes)));
    set_http_plan(
        DOWNLOAD,
        vec![Ok(MockResponse::new(
            bytes.clone(),
            Some(bytes.len() as u64),
        ))],
    );
    update_java(&ctx).unwrap();
    assert_eq!(fs::read(ctx.bindir.join("java")).unwrap(), b"fixture");
    assert_eq!(fs::read(ctx.bindir.join("javac")).unwrap(), b"fixture");
    assert_eq!(
        fs::read_to_string(ctx.home.join("java/old/keep")).unwrap(),
        "keep"
    );
    #[cfg(target_os = "linux")]
    {
        let plan = upkit::managed_cleanup::preview(
            &ctx,
            ToolKind::Java,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(plan.root, ctx.home.join("java"));
        assert!(plan.links.contains(&ctx.bindir.join("java")));
        assert!(plan.links.contains(&ctx.bindir.join("javac")));
    }
}

#[cfg(unix)]
#[test]
fn rejects_bad_checksum_and_conflicting_binary_without_replacement() {
    let _guard = reset_guard();
    let (ctx, _dir) = fixture();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let bytes = archive();
    plan_metadata(&"0".repeat(64));
    set_http_plan(
        DOWNLOAD,
        vec![Ok(MockResponse::new(
            bytes.clone(),
            Some(bytes.len() as u64),
        ))],
    );
    assert!(
        update_java(&ctx)
            .unwrap_err()
            .to_string()
            .contains("SHA-256")
    );
    assert!(!ctx.home.join("java/active").exists());

    fs::write(ctx.bindir.join("java"), "unrelated").unwrap();
    plan_metadata(&hex::encode(Sha256::digest(&bytes)));
    set_http_plan(
        DOWNLOAD,
        vec![Ok(MockResponse::new(
            bytes.clone(),
            Some(bytes.len() as u64),
        ))],
    );
    assert!(update_java(&ctx).is_err());
    assert_eq!(
        fs::read_to_string(ctx.bindir.join("java")).unwrap(),
        "unrelated"
    );
    assert!(!ctx.home.join("java/active").exists());
}

#[test]
fn dry_run_for_unix_and_windows_does_not_modify_files() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = fixture();
    ctx.dry_run = true;
    plan_metadata(&"a".repeat(64));
    update_java(&ctx).unwrap();
    assert!(!ctx.home.exists() && !ctx.bindir.exists());
    ctx.os = "windows".into();
    plan_windows_metadata(&"a".repeat(64));
    update_java(&ctx).unwrap();
    assert!(!ctx.home.exists() && !ctx.bindir.exists());
}

#[cfg(unix)]
#[test]
fn dry_run_does_not_execute_a_javac_wrapper() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = reset_guard();
    let (mut ctx, dir) = fixture();
    ctx.dry_run = true;
    let javac = dir.path().join("javac");
    fs::write(&javac, "#!/bin/sh\nprintf ran > \"$0.ran\"\n").unwrap();
    fs::set_permissions(&javac, fs::Permissions::from_mode(0o700)).unwrap();
    set_which("javac", Some(javac));

    plan_metadata(&"a".repeat(64));
    let report = check_java(&ctx).unwrap();
    assert_eq!(report.status, Status::Unknown);
    assert!(report.installed.is_none());
    plan_metadata(&"a".repeat(64));
    update_java(&ctx).unwrap();
    assert!(!dir.path().join("javac.ran").exists());
    assert!(!ctx.home.exists() && !ctx.bindir.exists());
}

#[cfg(any(unix, windows))]
#[test]
fn installs_windows_jdk_archive_with_exe_links_and_rejects_missing_compiler() {
    #[cfg(windows)]
    if !windows_symlinks::available() {
        return;
    }
    let _guard = reset_guard();
    let (mut ctx, _dir) = fixture();
    ctx.os = "windows".into();
    existing_java_install(&ctx);
    let bad = windows_archive(false);
    plan_windows_metadata(&hex::encode(Sha256::digest(&bad)));
    set_http_plan(DOWNLOAD, vec![Ok(MockResponse::new(bad, None))]);
    assert!(update_java(&ctx).is_err());
    assert!(!ctx.home.join("java/active").exists());
    let good = windows_archive(true);
    let hash = hex::encode(Sha256::digest(&good));
    plan_windows_metadata(&hash);
    let report = check_java(&ctx).unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("permission to create symbolic links"))
    );
    fs::write(ctx.bindir.join("java.exe"), "unrelated").unwrap();
    plan_windows_metadata(&hash);
    set_http_plan(DOWNLOAD, vec![Ok(MockResponse::new(good.clone(), None))]);
    assert!(update_java(&ctx).is_err());
    assert_eq!(
        fs::read_to_string(ctx.bindir.join("java.exe")).unwrap(),
        "unrelated"
    );
    assert!(!ctx.home.join("java/active").exists());
    fs::remove_file(ctx.bindir.join("java.exe")).unwrap();
    plan_windows_metadata(&hash);
    set_http_plan(DOWNLOAD, vec![Ok(MockResponse::new(good, None))]);
    update_java(&ctx).unwrap();
    for name in ["java.exe", "javac.exe", "jar.exe"] {
        assert_eq!(fs::read(ctx.bindir.join(name)).unwrap(), b"fixture");
    }
    assert!(!ctx.bindir.join("java").exists());
    assert_eq!(
        fs::read_to_string(ctx.home.join("java/old/keep")).unwrap(),
        "keep"
    );
}

#[test]
fn rejects_ambiguous_or_untrusted_release_metadata() {
    let _guard = reset_guard();
    let (ctx, _dir) = fixture();
    let valid: serde_json::Value = serde_json::from_str(&metadata(&"a".repeat(64))).unwrap();
    let mut wrong_arch = valid.clone();
    wrong_arch[0]["binary"]["architecture"] = "aarch64".into();
    let mut insecure_url = valid.clone();
    insecure_url[0]["binary"]["package"]["link"] = "http://example.invalid/jdk.tar.gz".into();
    let duplicate = serde_json::json!([valid[0].clone(), valid[0].clone()]);
    for assets in [wrong_arch, insecure_url, duplicate] {
        set_http_plan(
            AVAILABLE,
            vec![Ok(MockResponse::new(
                br#"{"most_recent_lts":25}"#.to_vec(),
                None,
            ))],
        );
        set_http_plan(
            ASSETS,
            vec![Ok(MockResponse::new(
                serde_json::to_vec(&assets).unwrap(),
                None,
            ))],
        );
        assert!(update_java(&ctx).is_err());
        assert!(!ctx.home.exists());
    }
}

#[cfg(unix)]
#[test]
fn rejects_archive_binary_linked_outside_the_jdk() {
    let _guard = reset_guard();
    let (ctx, dir) = fixture();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let outside = dir.path().join("outside");
    fs::write(&outside, "keep").unwrap();
    let mut bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_mode(0o777);
        link.set_size(0);
        link.set_link_name(&outside).unwrap();
        link.set_cksum();
        tar.append_data(&mut link, "jdk/bin/java", std::io::empty())
            .unwrap();
        let mut file = tar::Header::new_gnu();
        file.set_mode(0o755);
        file.set_size(7);
        file.set_cksum();
        tar.append_data(&mut file, "jdk/bin/javac", &b"fixture"[..])
            .unwrap();
        tar.finish().unwrap();
    }
    plan_metadata(&hex::encode(Sha256::digest(&bytes)));
    set_http_plan(
        DOWNLOAD,
        vec![Ok(MockResponse::new(
            bytes.clone(),
            Some(bytes.len() as u64),
        ))],
    );
    assert!(update_java(&ctx).is_err());
    assert_eq!(fs::read_to_string(outside).unwrap(), "keep");
    assert!(!ctx.home.join("java/active").exists());
    assert!(!ctx.bindir.join("java").exists());
}

#[cfg(unix)]
#[test]
fn accepts_internal_jdk_links_and_rejects_oversized_archives() {
    use std::io::Write;
    let _guard = reset_guard();
    let (ctx, _dir) = fixture();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let mut bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        for name in ["jdk/lib/java", "jdk/bin/javac"] {
            let mut file = tar::Header::new_gnu();
            file.set_mode(0o755);
            file.set_size(7);
            file.set_cksum();
            tar.append_data(&mut file, name, &b"fixture"[..]).unwrap();
        }
        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_mode(0o777);
        link.set_size(0);
        link.set_link_name("../lib/java").unwrap();
        link.set_cksum();
        tar.append_data(&mut link, "jdk/bin/java", std::io::empty())
            .unwrap();
        tar.finish().unwrap();
    }
    plan_metadata(&hex::encode(Sha256::digest(&bytes)));
    set_http_plan(
        DOWNLOAD,
        vec![Ok(MockResponse::new(
            bytes.clone(),
            Some(bytes.len() as u64),
        ))],
    );
    update_java(&ctx).unwrap();
    assert_eq!(fs::read(ctx.bindir.join("java")).unwrap(), b"fixture");

    let (mut ctx, _dir) = fixture();
    ctx.force = true;
    fs::create_dir_all(&ctx.bindir).unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_path("jdk/bin/java").unwrap();
    header.set_mode(0o755);
    header.set_size(3 * 1024 * 1024 * 1024 + 1);
    header.set_cksum();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(header.as_bytes()).unwrap();
    let oversized = encoder.finish().unwrap();
    plan_metadata(&hex::encode(Sha256::digest(&oversized)));
    set_http_plan(
        DOWNLOAD,
        vec![Ok(MockResponse::new(
            oversized.clone(),
            Some(oversized.len() as u64),
        ))],
    );
    assert!(
        update_java(&ctx)
            .unwrap_err()
            .to_string()
            .contains("extraction limits")
    );
    assert!(!ctx.home.join("java/active").exists());
}

#[cfg(unix)]
#[test]
fn installs_a_mac_layout_from_a_matching_archive_fixture() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = fixture();
    ctx.os = "macos".into();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let mut bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        for name in ["jdk/Contents/Home/bin/java", "jdk/Contents/Home/bin/javac"] {
            let mut file = tar::Header::new_gnu();
            file.set_mode(0o755);
            file.set_size(7);
            file.set_cksum();
            tar.append_data(&mut file, name, &b"fixture"[..]).unwrap();
        }
        tar.finish().unwrap();
    }
    let mut assets: serde_json::Value =
        serde_json::from_str(&metadata(&hex::encode(Sha256::digest(&bytes)))).unwrap();
    assets[0]["binary"]["os"] = "mac".into();
    set_http_plan(
        AVAILABLE,
        vec![Ok(MockResponse::new(
            br#"{"most_recent_lts":25}"#.to_vec(),
            None,
        ))],
    );
    set_http_plan(
        "https://api.adoptium.net/v3/assets/latest/25/hotspot?architecture=x64&heap_size=normal&image_type=jdk&os=mac&vendor=eclipse",
        vec![Ok(MockResponse::new(
            serde_json::to_vec(&assets).unwrap(),
            None,
        ))],
    );
    set_http_plan(
        DOWNLOAD,
        vec![Ok(MockResponse::new(
            bytes.clone(),
            Some(bytes.len() as u64),
        ))],
    );
    update_java(&ctx).unwrap();
    assert_eq!(fs::read(ctx.bindir.join("javac")).unwrap(), b"fixture");
}

#[cfg(unix)]
#[test]
fn offline_cli_reports_java_from_a_fake_javac_without_writes() {
    use std::{os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("fake-bin");
    fs::create_dir(&bin).unwrap();
    let javac = bin.join("javac");
    fs::write(&javac, "#!/bin/sh\nprintf 'javac 25.0.4+7\\n'\n").unwrap();
    fs::set_permissions(&javac, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args([
            "--offline",
            "--non-interactive",
            "--json",
            "--only",
            "java",
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
    assert_eq!(report[0]["tool"], "java");
    assert_eq!(report[0]["installed"], "25.0.4");
    assert!(report[0]["latest"].is_null());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}
