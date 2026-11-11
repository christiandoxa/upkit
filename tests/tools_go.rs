#[cfg(windows)]
#[path = "support/windows_symlinks.rs"]
mod windows_symlinks;

use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use upkit::test_support::{
    MockResponse, TestPrompt, base_ctx, output_with_status, reset_guard, set_env_var, set_home_dir,
    set_http_plan, set_prune_tool_versions_error, set_run_output, set_which, take_run_output,
};
use upkit::tools::go::{
    GoToolSpec, check_go, go_env_value, go_global_bin_dirs, go_global_tools, go_latest, go_os_arch,
    go_pick_file, go_tool_spec_from_binary, parse_go_version_metadata, restore_go_globals,
    update_go,
};
use upkit::{Ctx, Status, Version};

fn ctx_with_dirs() -> (Ctx, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.quiet = true;
    (ctx, dir)
}

fn secure_fixture_dir(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
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
        for (name, contents, mode) in [
            ("go/bin/go", &b"fixture"[..], 0o755),
            ("go/bin/gofmt", &b"fixture"[..], 0o755),
            ("go/pkg/tool/linux_amd64/compile", &b"fixture"[..], 0o755),
            ("go/pkg/tool/linux_amd64/link", &b"fixture"[..], 0o755),
            ("go/src/runtime/proc.go", &b"fixture"[..], 0o644),
            ("go/VERSION", &b"go1.2.3\n"[..], 0o644),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(mode);
            header.set_size(contents.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, name, contents).unwrap();
        }
        tar.finish().unwrap();
    }
    bytes
}

#[cfg(any(unix, windows))]
fn go_windows_zip(arch: &str, case: &str) -> Vec<u8> {
    use std::io::{Cursor, Write};
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let files = [
        ("go/bin/go.exe".to_string(), b"fixture".as_slice()),
        ("go/bin/gofmt.exe".to_string(), b"fixture".as_slice()),
        (
            format!("go/pkg/tool/windows_{arch}/compile.exe"),
            b"fixture".as_slice(),
        ),
        (
            format!("go/pkg/tool/windows_{arch}/link.exe"),
            b"fixture".as_slice(),
        ),
        ("go/src/runtime/proc.go".to_string(), b"fixture".as_slice()),
        (
            "go/VERSION".to_string(),
            if case == "wrong-version" {
                b"go1.2.4\n".as_slice()
            } else {
                b"go1.2.3\n".as_slice()
            },
        ),
    ];
    for (name, bytes) in files {
        if (case == "missing-go" && name == "go/bin/go.exe")
            || (case == "missing-gofmt" && name == "go/bin/gofmt.exe")
            || (case == "missing-compiler" && name.ends_with("/compile.exe"))
            || (case == "missing-linker" && name.ends_with("/link.exe"))
            || (case == "missing-runtime" && name.ends_with("/proc.go"))
        {
            continue;
        }
        let empty = (case == "empty-go" && name == "go/bin/go.exe")
            || (case == "empty-compiler" && name.ends_with("/compile.exe"));
        zip.start_file(name, options).unwrap();
        zip.write_all(if empty { b"" } else { bytes }).unwrap();
    }
    if case == "extra-root" {
        zip.start_file("other/file", options).unwrap();
        zip.write_all(b"fixture").unwrap();
    }
    if case == "escaping-link" {
        zip.add_symlink("go/escape", "../../outside", options)
            .unwrap();
    }
    zip.finish().unwrap().into_inner()
}

#[cfg(any(unix, windows))]
fn plan_go_windows(arch: &str, bytes: &[u8], corrupt: bool) {
    let name = format!("go1.2.3.windows-{arch}.zip");
    let digest = if corrupt {
        "0".repeat(64)
    } else {
        hex::encode(Sha256::digest(bytes))
    };
    let json = format!(
        r#"[{{"version":"go1.2.3","stable":true,"files":[{{"filename":"{name}","os":"windows","arch":"{arch}","kind":"archive","sha256":"{digest}"}}]}}]"#
    );
    set_http_plan(
        "https://go.dev/dl/?mode=json",
        vec![
            Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(json.into_bytes(), None)),
        ],
    );
    set_http_plan(
        &format!("https://go.dev/dl/{name}"),
        vec![Ok(MockResponse::new(bytes.to_vec(), None))],
    );
}

#[cfg(unix)]
fn go_archive_variant(case: &str) -> Vec<u8> {
    if case == "oversized" {
        use std::io::Write;
        let mut header = tar::Header::new_gnu();
        header.set_path("go/bin/go").unwrap();
        header.set_mode(0o755);
        header.set_size(3 * 1024 * 1024 * 1024 + 1);
        header.set_cksum();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(header.as_bytes()).unwrap();
        return encoder.finish().unwrap();
    }
    let mut bytes = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut bytes, flate2::Compression::default());
        let mut tar = tar::Builder::new(enc);
        let platform = if case == "macos" {
            "darwin_arm64"
        } else {
            "linux_amd64"
        };
        let files = [
            ("go/bin/go".to_owned(), b"fixture".as_slice(), 0o755),
            ("go/bin/gofmt".to_owned(), b"fixture".as_slice(), 0o755),
            (
                format!("go/pkg/tool/{platform}/compile"),
                b"fixture".as_slice(),
                0o755,
            ),
            (
                format!("go/pkg/tool/{platform}/link"),
                b"fixture".as_slice(),
                0o755,
            ),
            (
                "go/src/runtime/proc.go".to_owned(),
                b"fixture".as_slice(),
                0o644,
            ),
            (
                "go/VERSION".to_owned(),
                if case == "wrong-version" {
                    b"go1.2.4\n".as_slice()
                } else if case == "binary-build-info" {
                    b"go1.2.3\ntime \xff\xfe\n".as_slice()
                } else {
                    b"go1.2.3\n".as_slice()
                },
                0o644,
            ),
        ];
        for (name, data, mode) in files {
            if (case == "missing-go" && name == "go/bin/go")
                || (case == "missing-gofmt" && name == "go/bin/gofmt")
                || (case == "missing-compiler" && name.ends_with("/compile"))
                || (case == "missing-runtime" && name.ends_with("proc.go"))
                || (case == "escaping-link" && name == "go/bin/go")
            {
                continue;
            }
            let mut header = tar::Header::new_gnu();
            header.set_mode(if case == "non-executable" && name == "go/bin/go" {
                0o644
            } else {
                mode
            });
            header.set_size(data.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, name, data).unwrap();
        }
        if case == "escaping-link" {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_mode(0o777);
            header.set_size(0);
            header.set_link_name("../../outside").unwrap();
            header.set_cksum();
            tar.append_data(&mut header, "go/bin/go", std::io::empty())
                .unwrap();
        }
        if case == "extra-root" || case == "special" {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(0);
            if case == "special" {
                header.set_entry_type(tar::EntryType::Fifo);
            }
            header.set_cksum();
            tar.append_data(
                &mut header,
                if case == "special" {
                    "go/special"
                } else {
                    "other/file"
                },
                std::io::empty(),
            )
            .unwrap();
        }
        tar.finish().unwrap();
    }
    bytes
}

#[cfg(unix)]
#[test]
fn go_update_validates_archive_before_switching_active() {
    use std::os::unix::fs::symlink;
    let _guard = reset_guard();
    for case in [
        "missing-go",
        "missing-gofmt",
        "missing-compiler",
        "missing-runtime",
        "wrong-version",
        "non-executable",
        "escaping-link",
        "extra-root",
        "special",
        "oversized",
        "macos",
        "binary-build-info",
    ] {
        let (mut ctx, dir) = ctx_with_dirs();
        let root = ctx.home.join("go");
        let old = root.join("old");
        fs::create_dir_all(&old).unwrap();
        secure_fixture_dir(&root);
        fs::write(old.join("keep"), "keep").unwrap();
        symlink(&old, root.join("active")).unwrap();
        fs::create_dir_all(&ctx.bindir).unwrap();
        set_which("go", None);
        let bytes = go_archive_variant(case);
        let hash = hex::encode(Sha256::digest(&bytes));
        let (os, arch, name) = if case == "macos" {
            ctx.os = "macos".into();
            ctx.arch = "aarch64".into();
            ("darwin", "arm64", "go1.2.3.darwin-arm64.tar.gz")
        } else {
            ("linux", "amd64", "go1.2.3.linux-amd64.tar.gz")
        };
        let json = format!(
            r#"[{{"version":"go1.2.3","stable":true,"files":[{{"filename":"{name}","os":"{os}","arch":"{arch}","kind":"archive","sha256":"{hash}"}}]}}]"#
        );
        set_http_plan(
            "https://go.dev/dl/?mode=json",
            vec![
                Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
                Ok(MockResponse::new(json.into_bytes(), None)),
            ],
        );
        set_http_plan(
            &format!("https://go.dev/dl/{name}"),
            vec![Ok(MockResponse::new(bytes, None))],
        );
        let result = update_go(&ctx);
        if matches!(case, "macos" | "binary-build-info") {
            result.unwrap();
        } else {
            let expected = match case {
                "missing-go" => "inspect staged Go component bin/go",
                "missing-gofmt" => "inspect staged Go component bin/gofmt",
                "missing-compiler" => "inspect staged Go component pkg/tool/linux_amd64/compile",
                "missing-runtime" => "inspect staged Go component src/runtime/proc.go",
                "wrong-version" => "VERSION does not match",
                "non-executable" => "not executable",
                "escaping-link" => "unsafe symbolic link",
                "extra-root" => "unexpected Go archive layout",
                "special" => "special file",
                "oversized" => "extraction limits",
                _ => unreachable!(),
            };
            assert!(
                format!("{:#}", result.unwrap_err()).contains(expected),
                "{case}"
            );
            assert_eq!(fs::read_link(root.join("active")).unwrap(), old, "{case}");
        }
        assert_eq!(fs::read_to_string(old.join("keep")).unwrap(), "keep");
        assert!(!dir.path().join("outside").exists());
    }
}

#[cfg(any(unix, windows))]
#[test]
fn windows_go_zip_installs_exe_links_and_rejects_invalid_archives() {
    #[cfg(windows)]
    if !windows_symlinks::available() {
        return;
    }
    let _guard = reset_guard();
    for (arch, case) in [
        ("amd64", "missing-go"),
        ("amd64", "missing-gofmt"),
        ("amd64", "missing-compiler"),
        ("amd64", "missing-linker"),
        ("amd64", "missing-runtime"),
        ("amd64", "empty-go"),
        ("amd64", "empty-compiler"),
        ("amd64", "wrong-version"),
        ("amd64", "extra-root"),
        ("amd64", "escaping-link"),
        ("amd64", "bad-hash"),
        ("amd64", "valid"),
        ("arm64", "valid"),
    ] {
        let (mut ctx, dir) = ctx_with_dirs();
        ctx.os = "windows".into();
        ctx.arch = if arch == "amd64" { "x86_64" } else { "aarch64" }.into();
        fs::create_dir_all(&ctx.bindir).unwrap();
        let root = ctx.home.join("go");
        let old = root.join("old");
        fs::create_dir_all(old.join("bin")).unwrap();
        fs::write(old.join("bin/go.exe"), b"old-go").unwrap();
        fs::write(old.join("bin/gofmt.exe"), b"old-fmt").unwrap();
        fs::write(old.join("keep"), "keep").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&old, root.join("active")).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&old, root.join("active")).unwrap();
        set_which("go", None);
        set_env_var(
            "GOBIN",
            Some(
                dir.path()
                    .join("unused-gobin")
                    .to_string_lossy()
                    .into_owned(),
            ),
        );
        let bytes = go_windows_zip(arch, case);
        plan_go_windows(arch, &bytes, case == "bad-hash");
        let result = update_go(&ctx);
        if case == "valid" {
            result.unwrap();
            assert_eq!(fs::read(ctx.bindir.join("go.exe")).unwrap(), b"fixture");
            assert_eq!(fs::read(ctx.bindir.join("gofmt.exe")).unwrap(), b"fixture");
            assert!(!root.join("wrappers").exists());
            assert_ne!(
                fs::canonicalize(root.join("active")).unwrap(),
                fs::canonicalize(&old).unwrap()
            );
            let go_path = ctx.bindir.join("go.exe");
            set_run_output(
                go_path.to_string_lossy().as_ref(),
                &["version"],
                output_with_status(0, b"go version go1.2.3 windows/amd64", b""),
            );
            let json = format!(
                r#"[{{"version":"go1.2.3","stable":true,"files":[{{"filename":"go1.2.3.windows-{arch}.zip","os":"windows","arch":"{arch}","kind":"archive","sha256":"{}"}}]}}]"#,
                "a".repeat(64)
            );
            set_http_plan(
                "https://go.dev/dl/?mode=json",
                vec![Ok(MockResponse::new(json.into_bytes(), None))],
            );
            let report = check_go(&ctx).unwrap();
            assert_eq!(report.installed.unwrap().to_string(), "1.2.3");
            assert!(
                report
                    .notes
                    .iter()
                    .any(|note| note.contains("GOROOT settings"))
            );
        } else {
            assert!(result.is_err(), "{arch} {case}");
            assert_eq!(
                fs::canonicalize(root.join("active")).unwrap(),
                fs::canonicalize(&old).unwrap()
            );
            assert_eq!(fs::read(ctx.bindir.join("go.exe")).unwrap(), b"old-go");
        }
        assert_eq!(fs::read_to_string(old.join("keep")).unwrap(), "keep");
        assert!(!dir.path().join("outside").exists());
    }
}

#[cfg(any(unix, windows))]
#[test]
fn windows_go_zip_refuses_existing_binary_and_dry_run_does_not_link() {
    #[cfg(windows)]
    if !windows_symlinks::available() {
        return;
    }
    let _guard = reset_guard();
    let (mut ctx, dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    ctx.arch = "x86_64".into();
    fs::create_dir_all(&ctx.bindir).unwrap();
    fs::write(ctx.bindir.join("go.exe"), "unrelated").unwrap();
    set_which("go", None);
    set_env_var(
        "GOBIN",
        Some(
            dir.path()
                .join("unused-gobin")
                .to_string_lossy()
                .into_owned(),
        ),
    );
    let bytes = go_windows_zip("amd64", "valid");
    plan_go_windows("amd64", &bytes, false);
    ctx.dry_run = true;
    update_go(&ctx).unwrap();
    assert!(!ctx.home.join("go").exists());
    assert_eq!(
        fs::read_to_string(ctx.bindir.join("go.exe")).unwrap(),
        "unrelated"
    );
    ctx.dry_run = false;
    plan_go_windows("amd64", &bytes, false);
    assert!(update_go(&ctx).is_err());
    assert!(!ctx.home.join("go/active").exists());
    assert_eq!(
        fs::read_to_string(ctx.bindir.join("go.exe")).unwrap(),
        "unrelated"
    );
    assert!(!ctx.bindir.join("gofmt.exe").exists());
}

#[cfg(any(unix, windows))]
#[test]
fn windows_go_link_repair_rejects_external_executable_and_dry_run_is_read_only() {
    #[cfg(windows)]
    if !windows_symlinks::available() {
        return;
    }
    let _guard = reset_guard();
    let (mut ctx, dir) = ctx_with_dirs();
    ctx.os = "windows".into();
    ctx.arch = "x86_64".into();
    fs::create_dir_all(&ctx.bindir).unwrap();
    let root = ctx.home.join("go");
    let old = root.join("old");
    fs::create_dir_all(old.join("bin")).unwrap();
    fs::write(old.join("bin/gofmt.exe"), b"old-fmt").unwrap();
    let outside = dir.path().join("outside.exe");
    fs::write(&outside, b"untouched").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&old, root.join("active")).unwrap();
        std::os::unix::fs::symlink(&outside, old.join("bin/go.exe")).unwrap();
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(&old, root.join("active")).unwrap();
        std::os::windows::fs::symlink_file(&outside, old.join("bin/go.exe")).unwrap();
    }
    let active = root.join("active");
    assert!(upkit::tools::go::ensure_go_wrappers(&ctx, &root, &active).is_err());
    assert!(!ctx.bindir.join("go.exe").exists());
    assert_eq!(fs::read(&outside).unwrap(), b"untouched");
    ctx.dry_run = true;
    set_which("go", None);
    let bytes = go_windows_zip("amd64", "valid");
    plan_go_windows("amd64", &bytes, false);
    update_go(&ctx).unwrap();
    assert!(!ctx.bindir.join("go.exe").exists());
    assert!(!ctx.bindir.join("gofmt.exe").exists());
    assert_eq!(fs::read(&outside).unwrap(), b"untouched");
    assert_eq!(
        fs::canonicalize(active).unwrap(),
        fs::canonicalize(old).unwrap()
    );
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
fn go_archive_selection_requires_exact_version() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let url = "https://go.dev/dl/?mode=json";
    let metadata = r#"[{"version":"go1.2.30","stable":true,"files":[{"filename":"go1.2.30.linux-amd64.tar.gz","os":"linux","arch":"amd64","kind":"archive","sha256":"wrong"}]},{"version":"go1.2.3","stable":true,"files":[{"filename":"go1.2.3.linux-amd64.tar.gz","os":"linux","arch":"amd64","kind":"archive","sha256":"right"}]}]"#;
    set_http_plan(
        url,
        vec![Ok(MockResponse::new(metadata.as_bytes().to_vec(), None))],
    );
    let want = Version {
        major: 1,
        minor: 2,
        patch: 3,
        pre: None,
    };
    let (download, digest) = go_pick_file(&ctx, &want).unwrap();
    assert!(download.ends_with("go1.2.3.linux-amd64.tar.gz"));
    assert_eq!(digest, "right");
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
    secure_fixture_dir(&tool_root);
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
fn go_found_but_unverifiable_is_unknown_not_not_installed() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    set_which("go", Some(PathBuf::from("/fixture/go")));
    set_run_output(
        "go",
        &["version"],
        output_with_status(1, b"", b"fixture failure"),
    );
    set_http_plan(
        "https://go.dev/dl/?mode=json",
        vec![Ok(MockResponse::new(
            br#"[{"version":"go1.2.3","stable":true,"files":[]}]"#.to_vec(),
            None,
        ))],
    );

    let report = check_go(&ctx).unwrap();

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

#[cfg(unix)]
#[test]
fn dry_run_skips_go_executable_and_preserves_update_plan_state() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let _guard = reset_guard();
    let (mut ctx, dir) = ctx_with_dirs();
    ctx.dry_run = true;
    fs::create_dir_all(&ctx.bindir).unwrap();
    let sentinel = dir.path().join("go-was-run");
    let fake_go = ctx.bindir.join("go");
    fs::write(
        &fake_go,
        format!(
            "#!/bin/sh\n: > '{}'\nprintf 'go version go1.2.3 linux/amd64\\n'\n",
            sentinel.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_go, fs::Permissions::from_mode(0o755)).unwrap();

    let url = "https://go.dev/dl/?mode=json";
    let (os, arch) = go_os_arch(&ctx);
    let extension = if os == "windows" { "zip" } else { "tar.gz" };
    let json = format!(
        r#"[{{"version":"go1.2.3","stable":true,"files":[{{"filename":"go1.2.3.{os}-{arch}.{extension}","os":"{os}","arch":"{arch}","kind":"archive","sha256":"abc"}}]}}]"#
    );
    set_http_plan(
        url,
        (0..3)
            .map(|_| Ok(MockResponse::new(json.as_bytes().to_vec(), None)))
            .collect(),
    );

    let report = check_go(&ctx).unwrap();
    assert_eq!(report.status, Status::Unknown);
    assert!(report.installed.is_none());
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("skipped running Go"))
    );
    assert!(!sentinel.exists());

    let tool_root = ctx.home.join("go");
    let old = tool_root.join("old");
    let wrappers = tool_root.join("wrappers");
    fs::create_dir_all(&old).unwrap();
    fs::create_dir_all(&wrappers).unwrap();
    secure_fixture_dir(&tool_root);
    secure_fixture_dir(&wrappers);
    fs::write(wrappers.join("go"), "existing wrapper").unwrap();
    symlink(&old, tool_root.join("active")).unwrap();

    update_go(&ctx).unwrap();

    assert!(!sentinel.exists());
    assert_eq!(fs::read_link(tool_root.join("active")).unwrap(), old);
    assert_eq!(
        fs::read_to_string(wrappers.join("go")).unwrap(),
        "existing wrapper"
    );
    assert!(!wrappers.join("gofmt").exists());
    assert!(!tool_root.join("1.2.3").exists());
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
fn dry_run_does_not_rewrite_existing_go_wrappers() {
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    ctx.dry_run = true;
    let tool_root = ctx.home.join("go");
    fs::create_dir_all(tool_root.join("active")).unwrap();
    fs::create_dir_all(tool_root.join("wrappers")).unwrap();
    fs::write(tool_root.join("wrappers/go"), "unchanged").unwrap();
    set_which("go", Some(PathBuf::from("/bin/go")));
    set_run_output(
        "go",
        &["version"],
        output_with_status(0, b"go version go1.2.3 linux/amd64", b""),
    );
    let json = r#"[{"version":"go1.2.3","stable":true,"files":[]}]"#;
    set_http_plan(
        "https://go.dev/dl/?mode=json",
        vec![Ok(MockResponse::new(json.as_bytes().to_vec(), None))],
    );
    assert!(
        update_go(&ctx)
            .unwrap_err()
            .to_string()
            .contains("non-symlink active")
    );
    assert_eq!(
        fs::read_to_string(tool_root.join("wrappers/go")).unwrap(),
        "unchanged"
    );
    assert!(!tool_root.join("wrappers/gofmt").exists());
    assert!(!ctx.bindir.exists());
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
fn update_go_continues_when_global_tools_directory_cannot_be_read() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("go", None);
    let tool_root = ctx.home.join("go");
    let old = tool_root.join("old");
    fs::create_dir_all(old.join("bin")).unwrap();
    secure_fixture_dir(&tool_root);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&old, tool_root.join("active")).unwrap();
    let invalid_gobin = ctx.home.join("not-a-directory");
    fs::write(&invalid_gobin, "fixture").unwrap();
    set_env_var("GOBIN", Some(invalid_gobin.to_string_lossy().into_owned()));
    assert!(go_global_tools(None).is_err());

    let tar_bytes = make_go_tar_gz();
    let mut hasher = Sha256::new();
    hasher.update(&tar_bytes);
    let good_sha = hex::encode(hasher.finalize());
    let json = go_json("go1.2.3", &good_sha);
    let url = "https://go.dev/dl/?mode=json";
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

    update_go(&ctx).unwrap();
}

#[test]
fn update_go_warns_on_restore_globals_run_output() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    fs::create_dir_all(&ctx.bindir).unwrap();
    set_which("go", None);

    let tool_root = ctx.home.join("go");
    let old_active = tool_root.join("old");
    let active_bin = old_active.join("bin");
    fs::create_dir_all(&active_bin).unwrap();
    secure_fixture_dir(&tool_root);
    fs::write(active_bin.join("go"), b"").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&old_active, tool_root.join("active")).unwrap();
    }

    let gobin = ctx.home.join("gobin");
    fs::create_dir_all(&gobin).unwrap();
    let tool_bin = gobin.join("tool");
    fs::write(&tool_bin, b"").unwrap();
    set_env_var("GOBIN", Some(gobin.to_string_lossy().to_string()));

    let tool_bin_str = tool_bin.to_string_lossy().to_string();
    let go_program = tool_root.join("wrappers").join("go");
    set_run_output(
        go_program.to_string_lossy().as_ref(),
        &["version", "-m", tool_bin_str.as_str()],
        output_with_status(0, b"mod example.com/tool v1.2.3\n", b""),
    );
    set_run_output(
        go_program.to_string_lossy().as_ref(),
        &["install", "example.com/tool@v1.2.3"],
        output_with_status(1, b"", b""),
    );

    let tar_bytes = make_go_tar_gz();
    let mut hasher = Sha256::new();
    hasher.update(&tar_bytes);
    let good_sha = hex::encode(hasher.finalize());
    let json = go_json("go1.2.3", &good_sha);
    let url = "https://go.dev/dl/?mode=json";
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

    update_go(&ctx).unwrap();
    assert!(
        take_run_output(
            go_program.to_string_lossy().as_ref(),
            &["install".into(), "example.com/tool@v1.2.3".into()],
        )
        .is_none(),
        "Go package restore was not attempted"
    );
}

#[test]
fn go_env_value_reads_env_var() {
    let _guard = reset_guard();
    set_env_var("GOBIN", Some("/tmp/gobin".to_string()));
    assert_eq!(go_env_value(None, "GOBIN"), Some("/tmp/gobin".to_string()));
}

#[test]
fn go_global_tools_edge_cases() {
    let _guard = reset_guard();
    set_env_var("GOBIN", None);
    set_run_output("go", &["env", "GOBIN"], output_with_status(0, b"", b""));
    set_run_output("go", &["env", "GOPATH"], output_with_status(0, b"", b""));
    set_home_dir(None);
    assert!(go_global_tools(None).unwrap().is_empty());

    let dir = tempdir().unwrap();
    let gobin = dir.path().join("gobin");
    set_env_var("GOBIN", Some(gobin.to_string_lossy().to_string()));
    assert!(go_global_tools(None).unwrap().is_empty());

    fs::create_dir_all(&gobin).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("missing", gobin.join("broken")).unwrap();
    }
    let subdir = gobin.join("dir");
    fs::create_dir_all(&subdir).unwrap();
    assert!(go_global_tools(None).unwrap().is_empty());
}

#[test]
fn parse_go_version_metadata_without_mod() {
    assert!(parse_go_version_metadata("go version go1.2.3").is_none());
}

#[test]
fn restore_go_globals_uses_explicit_bin() {
    let _guard = reset_guard();
    let tool = GoToolSpec {
        module: "example.com/tool".to_string(),
        version: "v1.2.3".to_string(),
    };
    set_run_output(
        "/tmp/go",
        &["install", "example.com/tool@v1.2.3"],
        output_with_status(0, b"", b""),
    );
    restore_go_globals(Some(std::path::Path::new("/tmp/go")), &[tool]).unwrap();
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn update_go_secures_legacy_group_writable_directories() {
    use std::os::unix::fs::PermissionsExt;
    let _guard = reset_guard();
    let (mut ctx, _dir) = ctx_with_dirs();
    let root = ctx.home.join("go");
    let wrappers = root.join("wrappers");
    let old = root.join("old");
    fs::create_dir_all(&ctx.bindir).unwrap();
    fs::create_dir_all(&old).unwrap();
    std::os::unix::fs::symlink(&old, root.join("active")).unwrap();
    fs::create_dir(&wrappers).unwrap();
    for name in ["go", "gofmt"] {
        let wrapper = wrappers.join(name);
        fs::write(
            &wrapper,
            format!(
                "#!/usr/bin/env sh\nexport GOROOT=\"{}\"\nexec \"{}/bin/{name}\" \"$@\"\n",
                root.join("active").display(),
                root.join("active").display()
            ),
        )
        .unwrap();
        fs::set_permissions(wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::set_permissions(&root, fs::Permissions::from_mode(0o775)).unwrap();
    fs::set_permissions(&wrappers, fs::Permissions::from_mode(0o775)).unwrap();
    set_which("go", None);
    let archive = make_go_tar_gz();
    let json = go_json("go1.2.3", &hex::encode(Sha256::digest(&archive)));
    let plan = || {
        set_http_plan(
            "https://go.dev/dl/?mode=json",
            vec![
                Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
                Ok(MockResponse::new(json.as_bytes().to_vec(), None)),
            ],
        );
        set_http_plan(
            "https://go.dev/dl/go1.2.3.linux-amd64.tar.gz",
            vec![Ok(MockResponse::new(archive.clone(), None))],
        );
    };
    ctx.dry_run = true;
    plan();
    update_go(&ctx).unwrap();
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o775
    );
    ctx.dry_run = false;
    plan();
    update_go(&ctx).unwrap();
    assert_eq!(fs::metadata(&root).unwrap().permissions().mode() & 0o022, 0);
    assert_eq!(
        fs::metadata(&wrappers).unwrap().permissions().mode() & 0o022,
        0
    );
    assert!(ctx.bindir.join("go").exists());
    assert!(
        fs::read_to_string(wrappers.join("go"))
            .unwrap()
            .contains("GOROOT=\"")
    );
    let wrapper = wrappers.join("gofmt");
    let tampered = fs::read_to_string(&wrapper)
        .unwrap()
        .replace("gofmt\"", "gofmx\"");
    fs::write(&wrapper, &tampered).unwrap();
    assert!(upkit::tools::go::ensure_go_wrappers(&ctx, &root, &root.join("active")).is_err());
    assert_eq!(fs::read_to_string(wrapper).unwrap(), tampered);
}

#[cfg(unix)]
#[test]
fn legacy_go_wrapper_with_shell_expansion_is_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("tool$(touch INJECTED)");
    let root = home.join("go");
    let active = root.join("active");
    let wrappers = root.join("wrappers");
    let bindir = dir.path().join("bin");
    let ctx = base_ctx(home, bindir.clone(), Arc::new(TestPrompt::default()));
    fs::create_dir_all(&wrappers).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    secure_fixture_dir(&root);
    secure_fixture_dir(&wrappers);
    let wrapper = wrappers.join("go");
    let legacy = format!(
        "#!/usr/bin/env sh\nexport GOROOT=\"{}\"\nexec \"{}/bin/go\" \"$@\"\n",
        active.display(),
        active.display()
    );
    fs::write(&wrapper, &legacy).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(upkit::tools::go::ensure_go_wrappers(&ctx, &root, &active).is_err());
    assert_eq!(fs::read_to_string(wrapper).unwrap(), legacy);
    assert!(!dir.path().join("INJECTED").exists());
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
    secure_fixture_dir(&tool_root);
    set_env_var("GOBIN", Some("/tmp/gobin".to_string()));
    upkit::tools::go::ensure_go_wrappers(&ctx, &tool_root, &active).unwrap();
}

#[test]
fn go_wrappers_refuse_unrelated_files_without_partial_creation() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let root = ctx.home.join("go");
    let wrappers = root.join("wrappers");
    fs::create_dir_all(&wrappers).unwrap();
    secure_fixture_dir(&root);
    secure_fixture_dir(&wrappers);
    fs::create_dir_all(&ctx.bindir).unwrap();
    fs::write(wrappers.join("gofmt"), "keep unrelated data").unwrap();
    assert!(upkit::tools::go::ensure_go_wrappers(&ctx, &root, &root.join("active")).is_err());
    assert_eq!(
        fs::read_to_string(wrappers.join("gofmt")).unwrap(),
        "keep unrelated data"
    );
    assert!(!wrappers.join("go").exists());
    assert!(fs::read_dir(&ctx.bindir).unwrap().next().is_none());
}

#[test]
fn go_update_refuses_wrapper_conflict_before_activation() {
    let _guard = reset_guard();
    let (ctx, _dir) = ctx_with_dirs();
    let wrappers = ctx.home.join("go/wrappers");
    fs::create_dir_all(&wrappers).unwrap();
    secure_fixture_dir(&ctx.home.join("go"));
    secure_fixture_dir(&wrappers);
    fs::create_dir_all(&ctx.bindir).unwrap();
    fs::write(wrappers.join("gofmt"), "keep unrelated data").unwrap();
    set_which("go", None);
    let archive = make_go_tar_gz();
    let digest = hex::encode(Sha256::digest(&archive));
    let metadata = go_json("go1.2.3", &digest);
    set_http_plan(
        "https://go.dev/dl/?mode=json",
        vec![
            Ok(MockResponse::new(metadata.as_bytes().to_vec(), None)),
            Ok(MockResponse::new(metadata.into_bytes(), None)),
        ],
    );
    set_http_plan(
        "https://go.dev/dl/go1.2.3.linux-amd64.tar.gz",
        vec![Ok(MockResponse::new(archive, None))],
    );
    assert!(update_go(&ctx).is_err());
    assert!(!ctx.home.join("go/active").exists());
    assert!(!wrappers.join("go").exists());
    assert_eq!(
        fs::read_to_string(wrappers.join("gofmt")).unwrap(),
        "keep unrelated data"
    );
}

#[cfg(unix)]
#[test]
fn go_wrappers_reject_links_and_reuse_only_unchanged_generated_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let _guard = reset_guard();
    let (ctx, dir) = ctx_with_dirs();
    let root = ctx.home.join("go");
    let wrappers = root.join("wrappers");
    let active = root.join("active");
    fs::create_dir_all(&root).unwrap();
    secure_fixture_dir(&root);
    fs::create_dir_all(&ctx.bindir).unwrap();
    let outside = dir.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("go"), "keep").unwrap();
    symlink(&outside, &wrappers).unwrap();
    assert!(upkit::tools::go::ensure_go_wrappers(&ctx, &root, &active).is_err());
    assert_eq!(fs::read_to_string(outside.join("go")).unwrap(), "keep");
    fs::remove_file(&wrappers).unwrap();
    fs::create_dir(&wrappers).unwrap();
    secure_fixture_dir(&wrappers);
    symlink(outside.join("go"), wrappers.join("go")).unwrap();
    assert!(upkit::tools::go::ensure_go_wrappers(&ctx, &root, &active).is_err());
    assert_eq!(fs::read_to_string(outside.join("go")).unwrap(), "keep");
    fs::remove_file(wrappers.join("go")).unwrap();
    upkit::tools::go::ensure_go_wrappers(&ctx, &root, &active).unwrap();
    let original = fs::read(wrappers.join("go")).unwrap();
    upkit::tools::go::ensure_go_wrappers(&ctx, &root, &active).unwrap();
    assert_eq!(fs::read(wrappers.join("go")).unwrap(), original);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(upkit::tools::go::ensure_go_wrappers(&ctx, &root, &active).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::hard_link(wrappers.join("go"), outside.join("hardlink")).unwrap();
    assert!(upkit::tools::go::ensure_go_wrappers(&ctx, &root, &active).is_err());
    assert_eq!(fs::read(outside.join("hardlink")).unwrap(), original);
    fs::remove_file(outside.join("hardlink")).unwrap();
    fs::set_permissions(&wrappers, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(upkit::tools::go::ensure_go_wrappers(&ctx, &root, &active).is_err());
    fs::set_permissions(&wrappers, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(wrappers.join("gofmt"), "changed").unwrap();
    assert!(upkit::tools::go::ensure_go_wrappers(&ctx, &root, &active).is_err());
    assert_eq!(
        fs::read_to_string(wrappers.join("gofmt")).unwrap(),
        "changed"
    );
    assert_eq!(fs::read(wrappers.join("go")).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn go_wrapper_treats_special_path_characters_as_literal() {
    use std::os::unix::fs::PermissionsExt;
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("tool$(touch INJECTED)'home");
    let bindir = dir.path().join("bin");
    let mut ctx = base_ctx(
        home.clone(),
        bindir.clone(),
        Arc::new(TestPrompt::default()),
    );
    ctx.quiet = true;
    fs::create_dir_all(&bindir).unwrap();
    let tool_root = home.join("go");
    let active = tool_root.join("active");
    fs::create_dir_all(active.join("bin")).unwrap();
    secure_fixture_dir(&tool_root);
    let binary = active.join("bin/go");
    fs::write(&binary, "#!/bin/sh\nprintf safe\n").unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    upkit::tools::go::ensure_go_wrappers(&ctx, &tool_root, &active).unwrap();
    let output = std::process::Command::new(tool_root.join("wrappers/go"))
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"safe");
    assert!(!dir.path().join("INJECTED").exists());
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
