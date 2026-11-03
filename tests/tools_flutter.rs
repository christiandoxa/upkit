use sha2::{Digest, Sha256};
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
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.quiet = true;
    (ctx, dir)
}

fn release_json(archive: &str, bytes: &[u8]) -> String {
    serde_json::json!({"releases": [{"dart_sdk_arch":"x64","channel":"stable", "version":"3.1.0", "archive":archive, "hash":"revision", "sha256":hex::encode(Sha256::digest(bytes))}]}).to_string()
}

fn make_flutter_tar_xz() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let enc = xz2::write::XzEncoder::new(&mut bytes, 6);
        let mut tar = tar::Builder::new(enc);
        for path in [
            "flutter/bin/flutter",
            "flutter/bin/dart",
            "flutter/bin/internal/shared.sh",
            "flutter/packages/flutter_tools/pubspec.yaml",
            "flutter/bin/cache/dart-sdk/bin/dart",
            "flutter/bin/cache/flutter_tools.snapshot",
            "flutter/bin/cache/engine.stamp",
            "flutter/bin/cache/flutter.version.json",
            "flutter/.git/HEAD",
            "flutter/.git/config",
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o755);
            let content: &[u8] = if path.ends_with("flutter.version.json") {
                br#"{"frameworkVersion":"3.1.0"}"#
            } else {
                b"fixture"
            };
            header.set_size(content.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, path, content).unwrap();
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
        for path in [
            "flutter/bin/flutter",
            "flutter/bin/dart",
            "flutter/bin/internal/shared.sh",
            "flutter/packages/flutter_tools/pubspec.yaml",
            "flutter/bin/cache/dart-sdk/bin/dart",
            "flutter/bin/cache/flutter_tools.snapshot",
            "flutter/bin/cache/engine.stamp",
            "flutter/bin/cache/flutter.version.json",
            "flutter/.git/HEAD",
            "flutter/.git/config",
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o755);
            let content: &[u8] = if path.ends_with("flutter.version.json") {
                br#"{"frameworkVersion":"3.1.0"}"#
            } else {
                b"fixture"
            };
            header.set_size(content.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, path, content).unwrap();
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

#[cfg(unix)]
fn flutter_macos_zip(missing_component: bool, escaping_link: bool) -> Vec<u8> {
    use std::io::{Cursor, Write};
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
    let paths = [
        "flutter/bin/flutter",
        "flutter/bin/dart",
        "flutter/bin/internal/shared.sh",
        "flutter/packages/flutter_tools/pubspec.yaml",
        "flutter/bin/cache/dart-sdk/bin/dart",
        "flutter/bin/cache/flutter_tools.snapshot",
        "flutter/bin/cache/engine.stamp",
        "flutter/bin/cache/flutter.version.json",
        "flutter/.git/HEAD",
        "flutter/.git/config",
        "flutter/framework/Versions/A/asset",
    ];
    for path in paths {
        if missing_component && path.ends_with("bin/cache/dart-sdk/bin/dart") {
            continue;
        }
        zip.start_file(path, options).unwrap();
        zip.write_all(if path.ends_with("flutter.version.json") {
            br#"{"frameworkVersion":"3.1.0"}"#
        } else {
            b"fixture"
        })
        .unwrap();
    }
    zip.add_symlink("flutter/framework/Versions/Current", "A", options)
        .unwrap();
    zip.add_symlink(
        "flutter/framework/link",
        if escaping_link {
            "../../outside"
        } else {
            "Versions/Current/asset"
        },
        options,
    )
    .unwrap();
    zip.finish().unwrap().into_inner()
}

#[cfg(unix)]
fn invalid_flutter_tar(case: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let encoder = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        for path in [
            "flutter/bin/flutter",
            "flutter/bin/dart",
            "flutter/bin/internal/shared.sh",
            "flutter/packages/flutter_tools/pubspec.yaml",
            "flutter/bin/cache/dart-sdk/bin/dart",
            "flutter/bin/cache/flutter_tools.snapshot",
            "flutter/bin/cache/engine.stamp",
            "flutter/bin/cache/flutter.version.json",
            "flutter/.git/HEAD",
            "flutter/.git/config",
        ] {
            if case == "missing" && path == "flutter/bin/dart" {
                continue;
            }
            let mut header = tar::Header::new_gnu();
            if matches!(case, "escaping-link" | "dangling-link") && path == "flutter/bin/dart" {
                header.set_entry_type(tar::EntryType::Symlink);
                header
                    .set_link_name(if case == "dangling-link" {
                        "missing"
                    } else {
                        "../../outside"
                    })
                    .unwrap();
                header.set_size(0);
                header.set_mode(0o777);
                header.set_cksum();
                tar.append_data(&mut header, path, std::io::empty())
                    .unwrap();
                continue;
            }
            header.set_mode(
                if case == "non-executable" && path == "flutter/bin/flutter" {
                    0o644
                } else {
                    0o755
                },
            );
            let content: &[u8] = if case == "empty" && path == "flutter/bin/flutter" {
                b""
            } else if path.ends_with("flutter.version.json") {
                if case == "wrong-version" {
                    br#"{"frameworkVersion":"9.9.9"}"#
                } else {
                    br#"{"frameworkVersion":"3.1.0"}"#
                }
            } else {
                b"fixture"
            };
            header.set_size(content.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, path, content).unwrap();
        }
        if case == "chain-escape" {
            let mut header = tar::Header::new_gnu();
            header.set_size(1);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "flutter/a/b/file", &b"x"[..])
                .unwrap();
            for (path, target) in [
                ("flutter/a/b/x", "../.."),
                ("flutter/a/b/y", "x/../../outside"),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_link_name(target).unwrap();
                header.set_size(0);
                header.set_mode(0o777);
                header.set_cksum();
                tar.append_data(&mut header, path, std::io::empty())
                    .unwrap();
            }
        }
        if case == "extra-root" {
            let mut header = tar::Header::new_gnu();
            header.set_size(1);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "other/file", &b"x"[..])
                .unwrap();
        }
        if case == "special" {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Fifo);
            header.set_size(0);
            header.set_mode(0o600);
            header.set_cksum();
            tar.append_data(&mut header, "flutter/pipe", std::io::empty())
                .unwrap();
        }
        tar.finish().unwrap();
    }
    bytes
}

#[cfg(unix)]
#[test]
fn flutter_tar_rejects_unsafe_and_incomplete_archives_before_activation() {
    use std::os::unix::fs::symlink;
    let _guard = reset_guard();
    for case in [
        "missing",
        "empty",
        "non-executable",
        "extra-root",
        "escaping-link",
        "dangling-link",
        "chain-escape",
        "wrong-version",
        "special",
    ] {
        let (ctx, _dir) = ctx_with_dirs();
        std::fs::create_dir_all(&ctx.bindir).unwrap();
        let old = ctx.home.join("flutter/old");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("keep"), "keep").unwrap();
        std::fs::write(ctx.home.join("flutter/outside"), "untouched").unwrap();
        symlink(&old, ctx.home.join("flutter/active")).unwrap();
        set_which("flutter", None);
        let bytes = invalid_flutter_tar(case);
        let archive = "stable/linux/flutter_linux_3.1.0-stable.tar.gz";
        let json = release_json(archive, &bytes);
        let url =
            "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
        set_http_plan(
            url,
            vec![
                Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
                Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            ],
        );
        set_http_plan(
            &format!("https://storage.googleapis.com/flutter_infra_release/releases/{archive}"),
            vec![Ok(MockResponse::new(bytes, None))],
        );
        let error = update_flutter(&ctx).unwrap_err();
        if case == "chain-escape" {
            assert!(
                error
                    .chain()
                    .any(|cause| cause.to_string().contains("symbolic link resolves outside")),
                "{error:#}"
            );
        }
        assert_eq!(
            std::fs::read_link(ctx.home.join("flutter/active")).unwrap(),
            old
        );
        assert_eq!(std::fs::read_to_string(old.join("keep")).unwrap(), "keep");
        assert_eq!(
            std::fs::read_to_string(ctx.home.join("flutter/outside")).unwrap(),
            "untouched"
        );
        assert!(!ctx.bindir.join("flutter").exists());
    }
}

#[cfg(unix)]
#[test]
fn flutter_macos_zip_installs_and_refuses_incomplete_or_escaping_archives() {
    let _guard = reset_guard();
    for case in ["missing", "escaping", "valid"] {
        let (mut ctx, _dir) = ctx_with_dirs();
        ctx.os = "macos".into();
        ctx.arch = "aarch64".into();
        std::fs::create_dir_all(&ctx.bindir).unwrap();
        let old = ctx.home.join("flutter/old");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("keep"), "keep").unwrap();
        std::os::unix::fs::symlink(&old, ctx.home.join("flutter/active")).unwrap();
        set_which("flutter", None);
        let bytes = flutter_macos_zip(case == "missing", case == "escaping");
        let archive = "stable/macos/flutter_macos_arm64_3.1.0-stable.zip";
        let json = serde_json::json!({"releases":[{"channel":"stable","version":"3.1.0","dart_sdk_arch":"arm64","archive":archive,"sha256":hex::encode(Sha256::digest(&bytes))}]}).to_string();
        let url =
            "https://storage.googleapis.com/flutter_infra_release/releases/releases_macos.json";
        set_http_plan(
            url,
            vec![
                Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
                Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            ],
        );
        set_http_plan(
            &format!("https://storage.googleapis.com/flutter_infra_release/releases/{archive}"),
            vec![Ok(MockResponse::new(bytes, None))],
        );
        let result = update_flutter(&ctx);
        if case == "valid" {
            result.unwrap();
            assert_eq!(
                std::fs::read(ctx.bindir.join("flutter")).unwrap(),
                b"fixture"
            );
            assert_eq!(
                std::fs::read(ctx.home.join("flutter/active/framework/link")).unwrap(),
                b"fixture"
            );
        } else {
            assert!(result.is_err(), "{case}");
            assert_eq!(
                std::fs::read_link(ctx.home.join("flutter/active")).unwrap(),
                old
            );
        }
        assert_eq!(std::fs::read_to_string(old.join("keep")).unwrap(), "keep");
    }
}

#[cfg(any(unix, windows))]
fn flutter_windows_zip(case: &str) -> Vec<u8> {
    use std::io::{Cursor, Write};
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    for name in [
        "flutter/bin/flutter.bat",
        "flutter/bin/dart.bat",
        "flutter/bin/internal/shared.bat",
        "flutter/packages/flutter_tools/pubspec.yaml",
        "flutter/bin/cache/dart-sdk/bin/dart.exe",
        "flutter/bin/cache/flutter_tools.snapshot",
        "flutter/bin/cache/engine.stamp",
        "flutter/bin/cache/flutter.version.json",
        "flutter/.git/HEAD",
        "flutter/.git/config",
    ] {
        if case == "missing" && name.ends_with("dart.exe") {
            continue;
        }
        zip.start_file(name, options).unwrap();
        let content: &[u8] = if case == "empty" && name.ends_with("flutter.bat") {
            b""
        } else if name.ends_with("flutter.version.json") && case == "wrong-version" {
            br#"{"frameworkVersion":"9.9.9"}"#
        } else if name.ends_with("flutter.version.json") {
            br#"{"frameworkVersion":"3.1.0"}"#
        } else {
            b"fixture"
        };
        zip.write_all(content).unwrap();
    }
    if case == "extra-root" {
        zip.start_file("other/file", options).unwrap();
        zip.write_all(b"fixture").unwrap();
    }
    if case == "link" {
        zip.add_symlink("flutter/link", "../../outside", options)
            .unwrap();
    }
    zip.finish().unwrap().into_inner()
}

#[cfg(any(unix, windows))]
fn plan_windows_flutter(bytes: &[u8], bad_hash: bool) {
    let archive = "stable/windows/flutter_windows_3.1.0-stable.zip";
    let digest = if bad_hash {
        "0".repeat(64)
    } else {
        hex::encode(Sha256::digest(bytes))
    };
    let json = serde_json::json!({"releases":[{"channel":"stable","version":"3.1.0","dart_sdk_arch":"x64","archive":archive,"sha256":digest}]}).to_string();
    set_http_plan(
        "https://storage.googleapis.com/flutter_infra_release/releases/releases_windows.json",
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.into_bytes(), None)),
        ],
    );
    set_http_plan(
        &format!("https://storage.googleapis.com/flutter_infra_release/releases/{archive}"),
        vec![Ok(MockResponse::new(bytes.to_vec(), None))],
    );
}

#[cfg(any(unix, windows))]
#[test]
fn flutter_windows_zip_preserves_layout_and_previous_installation() {
    #[cfg(windows)]
    if !windows_symlinks::available() {
        return;
    }
    let _guard = reset_guard();
    for case in [
        "missing",
        "empty",
        "wrong-version",
        "extra-root",
        "link",
        "bad-hash",
        "malformed",
        "valid",
    ] {
        let (mut ctx, _dir) = ctx_with_dirs();
        ctx.os = "windows".into();
        ctx.arch = "x86_64".into();
        let old = ctx.home.join("flutter/old");
        std::fs::create_dir_all(old.join("bin/cache")).unwrap();
        std::fs::write(old.join("bin/flutter.bat"), b"old").unwrap();
        std::fs::write(
            old.join("bin/cache/flutter.version.json"),
            br#"{"frameworkVersion":"3.0.0"}"#,
        )
        .unwrap();
        std::fs::write(old.join("keep"), b"keep").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&old, ctx.home.join("flutter/active")).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&old, ctx.home.join("flutter/active")).unwrap();
        set_which("flutter", None);
        let bytes = if case == "malformed" {
            b"not a zip".to_vec()
        } else {
            flutter_windows_zip(case)
        };
        plan_windows_flutter(&bytes, case == "bad-hash");
        let result = update_flutter(&ctx);
        if case == "valid" {
            result.unwrap();
            for name in [
                "bin/flutter.bat",
                "bin/dart.bat",
                "bin/internal/shared.bat",
                "bin/cache/dart-sdk/bin/dart.exe",
            ] {
                assert_eq!(
                    std::fs::read(ctx.home.join("flutter/active").join(name)).unwrap(),
                    b"fixture"
                );
            }
            assert_ne!(
                std::fs::canonicalize(ctx.home.join("flutter/active")).unwrap(),
                std::fs::canonicalize(&old).unwrap()
            );
            set_http_plan(
                "https://storage.googleapis.com/flutter_infra_release/releases/releases_windows.json",
                vec![Ok(MockResponse::new(
                    release_json("stable/windows/flutter.zip", b"fixture").into_bytes(),
                    None,
                ))],
            );
            let report = check_flutter(&ctx).unwrap();
            assert_eq!(report.installed.unwrap().to_string(), "3.1.0");
        } else {
            assert!(result.is_err(), "{case}");
            assert_eq!(
                std::fs::canonicalize(ctx.home.join("flutter/active")).unwrap(),
                std::fs::canonicalize(&old).unwrap()
            );
        }
        assert_eq!(std::fs::read(old.join("keep")).unwrap(), b"keep");
        assert!(!ctx.bindir.join("flutter.bat").exists());
    }
}

#[cfg(any(unix, windows))]
#[test]
fn flutter_windows_zip_dry_run_and_active_conflict_are_safe() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    ctx.arch = "x86_64".into();
    set_which("flutter", None);
    let bytes = flutter_windows_zip("valid");
    plan_windows_flutter(&bytes, false);
    ctx.dry_run = true;
    update_flutter(&ctx).unwrap();
    assert!(!ctx.home.join("flutter").exists());
    ctx.dry_run = false;
    std::fs::create_dir_all(ctx.home.join("flutter/active")).unwrap();
    std::fs::write(ctx.home.join("flutter/active/keep"), b"keep").unwrap();
    plan_windows_flutter(&bytes, false);
    assert!(update_flutter(&ctx).is_err());
    assert_eq!(
        std::fs::read(ctx.home.join("flutter/active/keep")).unwrap(),
        b"keep"
    );
}

#[cfg(any(unix, windows))]
#[test]
fn flutter_windows_zip_new_install_and_repeat_check() {
    #[cfg(windows)]
    if !windows_symlinks::available() {
        return;
    }
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    ctx.arch = "x86_64".into();
    set_which("flutter", None);
    let bytes = flutter_windows_zip("valid");
    plan_windows_flutter(&bytes, false);
    update_flutter(&ctx).unwrap();
    let active = ctx.home.join("flutter/active");
    let installed = std::fs::canonicalize(&active).unwrap();
    assert_eq!(
        std::fs::read(active.join("bin/flutter.bat")).unwrap(),
        b"fixture"
    );
    set_http_plan(
        "https://storage.googleapis.com/flutter_infra_release/releases/releases_windows.json",
        vec![Ok(MockResponse::new(
            release_json("stable/windows/flutter.zip", b"fixture").into_bytes(),
            None,
        ))],
    );
    update_flutter(&ctx).unwrap();
    assert_eq!(std::fs::canonicalize(active).unwrap(), installed);
}

#[cfg(any(unix, windows))]
#[test]
fn flutter_windows_rejects_active_link_outside_tool_root() {
    #[cfg(windows)]
    if !windows_symlinks::available() {
        return;
    }
    let _guard = reset_guard();
    let (mut ctx, dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    ctx.arch = "x86_64".into();
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(outside.join("bin/cache")).unwrap();
    std::fs::write(outside.join("bin/flutter.bat"), b"fixture").unwrap();
    std::fs::write(
        outside.join("bin/cache/flutter.version.json"),
        br#"{"frameworkVersion":"3.1.0"}"#,
    )
    .unwrap();
    let root = ctx.home.join("flutter");
    std::fs::create_dir_all(&root).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, root.join("active")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&outside, root.join("active")).unwrap();
    set_which("flutter", None);
    let bytes = flutter_windows_zip("valid");
    plan_windows_flutter(&bytes, false);
    assert!(update_flutter(&ctx).is_err());
    assert_eq!(
        std::fs::canonicalize(root.join("active")).unwrap(),
        std::fs::canonicalize(&outside).unwrap()
    );
    assert_eq!(
        std::fs::read(outside.join("bin/flutter.bat")).unwrap(),
        b"fixture"
    );
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
    let json = r#"{"releases":[{"dart_sdk_arch":"x64","channel":"stable","version":"3.10.0","archive":"stable/linux/flutter_linux_3.10.0-stable.tar.xz","hash":"abc"},{"dart_sdk_arch":"x64","channel":"stable","version":"3.9.0","archive":"stable/linux/flutter_linux_3.9.0-stable.tar.xz","hash":"def"},{"channel":"beta","version":"4.0.0","archive":"beta/linux/flutter_linux_4.0.0-beta.tar.xz","hash":"ghi"}]}"#;
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
fn flutter_selects_matching_architecture_and_refuses_older_only_match() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "macos".into();
    ctx.arch = "aarch64".into();
    std::fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("flutter", None);
    let archive = make_flutter_tar_xz();
    let checksum = hex::encode(Sha256::digest(&archive));
    let metadata = serde_json::json!({"releases": [
        {"channel":"stable", "version":"3.1.0", "dart_sdk_arch":"x64", "archive":"stable/macos/intel.tar.xz", "sha256":checksum},
        {"channel":"stable", "version":"3.1.0", "dart_sdk_arch":"arm64", "archive":"stable/macos/arm.tar.xz", "sha256":checksum}
    ]}).to_string();
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_macos.json";
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(metadata.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(metadata.as_bytes().to_vec(), None)),
        ],
    );
    set_http_plan(
        "https://storage.googleapis.com/flutter_infra_release/releases/stable/macos/arm.tar.xz",
        vec![Ok(MockResponse::new(archive, None))],
    );
    update_flutter(&ctx).unwrap();
    assert!(ctx.bindir.join("flutter").exists());

    let metadata = r#"{"releases":[{"channel":"stable","version":"3.2.0","dart_sdk_arch":"x64","archive":"intel.tar.xz"},{"channel":"stable","version":"3.1.0","dart_sdk_arch":"arm64","archive":"arm.tar.xz"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(metadata.as_bytes().to_vec(), None))],
    );
    assert!(
        flutter_latest_stable(&ctx)
            .unwrap_err()
            .to_string()
            .contains("no archive")
    );
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(metadata.as_bytes().to_vec(), None))],
    );
    assert!(
        check_flutter(&ctx)
            .unwrap()
            .notes
            .iter()
            .any(|note| note.contains("no archive"))
    );
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
    let json = r#"{"releases":[{"dart_sdk_arch":"x64","channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.xz","hash":"abc"}]}"#;
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
            br#"{"releases":[{"dart_sdk_arch":"x64","channel":"stable","version":"3.2.0","archive":"stable/linux/flutter_linux_3.2.0-stable.tar.xz","hash":"abc"}]}"#
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
fn flutter_windows_check_reports_path_requirements() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    set_which("flutter", None);
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_windows.json";
    let metadata = r#"{"releases":[{"dart_sdk_arch":"x64","channel":"stable","version":"3.1.0","archive":"stable/windows/flutter.zip"}]}"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(metadata.as_bytes().to_vec(), None))],
    );
    let report = check_flutter(&ctx).unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|note| note == "Windows: put flutter/active/bin first on PATH.")
    );
}

#[test]
fn flutter_check_not_installed() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("flutter", None);
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let json = r#"{"releases":[{"dart_sdk_arch":"x64","channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.xz","hash":"abc"}]}"#;
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
    let json = r#"{"releases":[{"dart_sdk_arch":"x64","channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.xz","hash":"abc"}]}"#;
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
fn flutter_found_but_unverifiable_is_unknown_not_not_installed() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();
    let flutter = PathBuf::from("/fixture/flutter");
    set_which("flutter", Some(flutter.clone()));
    set_run_output(
        flutter.to_string_lossy().as_ref(),
        &["--version", "--machine"],
        output_with_status(1, b"", b"fixture failure"),
    );
    set_http_plan(
        "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json",
        vec![Ok(MockResponse::new(
            br#"{"releases":[{"dart_sdk_arch":"x64","channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.xz","hash":"abc"}]}"#.to_vec(),
            None,
        ))],
    );

    let report = check_flutter(&ctx).unwrap();

    assert!(report.installed.is_none());
    assert_eq!(report.status, Status::Unknown);
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("could not be verified"))
    );
}

#[test]
fn update_flutter_install_dry_run() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.dry_run = true;
    set_which("flutter", None);
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let json = r#"{"releases":[{"dart_sdk_arch":"x64","channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.xz","hash":"abc"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    update_flutter(&ctx).unwrap();
}

#[cfg(unix)]
#[test]
fn flutter_dry_run_does_not_run_installed_binary_or_claim_its_version() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = reset_guard();
    let (mut ctx, dir) = ctx_with_dirs();
    ctx.os = "linux".into();
    ctx.arch = "x86_64".into();
    ctx.dry_run = true;

    let flutter = dir.path().join("flutter");
    std::fs::write(
        &flutter,
        "#!/bin/sh\nprintf 'ran' > \"$0.ran\"\nprintf '{\\\"frameworkVersion\\\":\\\"99.0.0\\\"}\\n'\n",
    )
    .unwrap();
    std::fs::set_permissions(&flutter, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sentinel = dir.path().join("flutter.ran");
    set_which("flutter", Some(flutter));

    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let json = r#"{"releases":[{"dart_sdk_arch":"x64","channel":"stable","version":"3.1.0","archive":"stable/linux/flutter_linux_3.1.0-stable.tar.xz","hash":"abc"}]}"#;
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );

    let report = check_flutter(&ctx).unwrap();
    assert_eq!(report.installed, None);
    assert_eq!(report.status, Status::Unknown);
    assert!(matches!(report.method, upkit::UpdateMethod::BuiltIn));
    assert!(
        report
            .notes
            .iter()
            .any(|note| note == "Installed Flutter version was not verified.")
    );

    update_flutter(&ctx).unwrap();
    assert!(!sentinel.exists());
}

#[test]
fn update_flutter_install_tar_gz() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.quiet = true;
    std::fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("flutter", None);
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let download_url = "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_3.1.0-stable.tar.gz";
    let archive = make_flutter_tar_gz();
    let json = release_json("stable/linux/flutter_linux_3.1.0-stable.tar.gz", &archive);
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
fn flutter_install_rejects_missing_or_mismatched_checksum_before_extraction() {
    let _guard = reset_guard();
    for case in ["missing", "malformed", "mismatch"] {
        let (ctx, dir) = ctx_with_dirs();
        set_which("flutter", None);
        let archive = make_flutter_tar_gz();
        let archive_path = "stable/linux/flutter_linux_3.1.0-stable.tar.gz";
        let json = match case {
            "mismatch" => release_json(archive_path, b"different archive"),
            "malformed" => serde_json::json!({"releases":[{"dart_sdk_arch":"x64","channel":"stable","version":"3.1.0","archive":archive_path,"sha256":"invalid"}]}).to_string(),
            _ => serde_json::json!({"releases":[{"dart_sdk_arch":"x64","channel":"stable","version":"3.1.0","archive":archive_path}]}).to_string(),
        };
        let url =
            "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
        set_http_plan(
            url,
            vec![
                Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
                Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            ],
        );
        if case == "mismatch" {
            let download_url = "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_3.1.0-stable.tar.gz";
            set_http_plan(download_url, vec![Ok(MockResponse::new(archive, None))]);
        }
        let err = update_flutter(&ctx).unwrap_err().to_string();
        assert!(err.contains(if case == "mismatch" {
            "mismatch"
        } else {
            "lacks a valid"
        }));
        assert!(!ctx.home.join("flutter").exists());
        assert!(!ctx.bindir.exists());
        assert!(!dir.path().join(".bashrc").exists());
    }
}

#[test]
fn update_flutter_install_missing_layout() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.quiet = true;
    std::fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("flutter", None);
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let download_url = "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_3.1.0-stable.tar.gz";
    let archive = make_flutter_tar_gz_missing_root();
    let json = release_json("stable/linux/flutter_linux_3.1.0-stable.tar.gz", &archive);
    set_http_plan(
        url,
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
        ],
    );
    set_http_plan(download_url, vec![Ok(MockResponse::new(archive, None))]);
    let err = update_flutter(&ctx).unwrap_err();
    assert!(err.to_string().contains("expected only flutter/"));
}

#[test]
fn update_flutter_install_unsupported_archive() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.quiet = true;
    set_which("flutter", None);
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let json = release_json("stable/linux/flutter_linux_3.1.0-stable.zip", &[1, 2]);
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
    std::fs::create_dir_all(&tool_root).unwrap();
    std::fs::write(tool_root.join("active"), "keep").unwrap();
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let archive = make_flutter_tar_xz();
    let json = release_json("stable/linux/flutter_linux_3.1.0-stable.tar.xz", &archive);
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
    assert!(err.to_string().contains("non-symlink active"));
    assert_eq!(
        std::fs::read_to_string(tool_root.join("active")).unwrap(),
        "keep"
    );
}

#[test]
fn update_flutter_prune_warn() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    std::fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("flutter", None);
    let url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json";
    let archive = make_flutter_tar_xz();
    let json = release_json("stable/linux/flutter_linux_3.1.0-stable.tar.xz", &archive);
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
    let json = r#"{"releases":[{"dart_sdk_arch":"x64","channel":"stable","version":"3.2.0","archive":"stable/linux/flutter_linux_3.2.0-stable.tar.xz","hash":"abc"}]}"#;
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
fn flutter_installed_version_from_machine_output() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let bin = dir.path().join("flutter");
    let json = r#"{"frameworkVersion":"3.2.1"}"#;
    set_run_output(
        bin.to_string_lossy().as_ref(),
        &["--version", "--machine"],
        output_with_status(0, json.as_bytes(), b""),
    );
    let v = flutter_installed_version(&bin).unwrap();
    assert_eq!(v.to_string(), "3.2.1");
}

#[test]
fn flutter_installed_version_machine_output_invalid_version() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let root = dir.path().join("flutter");
    let bin_dir = root.join("bin");
    let bin = bin_dir.join("flutter");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::write(&bin, b"").unwrap();
    std::fs::write(root.join("version"), b"3.2.1").unwrap();
    set_run_output(
        bin.to_string_lossy().as_ref(),
        &["--version", "--machine"],
        output_with_status(0, br#"{"frameworkVersion":"invalid"}"#, b""),
    );
    let v = flutter_installed_version(&bin).unwrap();
    assert_eq!(v.to_string(), "3.2.1");
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
    let json = release_json("stable/linux/flutter_linux_3.1.0-stable.tar.xz", &archive);
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
#[cfg(windows)]
#[path = "support/windows_symlinks.rs"]
mod windows_symlinks;
