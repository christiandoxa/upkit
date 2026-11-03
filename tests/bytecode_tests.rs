#![cfg(target_os = "linux")]

#[path = "support/git.rs"]
mod git_support;

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Fixture {
    _dir: tempfile::TempDir,
    _git_dir: tempfile::TempDir,
    repo: PathBuf,
    source: PathBuf,
    file: PathBuf,
    bin: PathBuf,
    home: PathBuf,
    git: PathBuf,
}

impl Fixture {
    fn new() -> Option<Self> {
        let git = git_support::elf_git()?;
        if std::env::var_os("UPKIT_TEST_IN_NAMESPACE").is_none() && !namespace_available() {
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let repo = dir.path().join("project");
        let cache = repo.join("__pycache__");
        fs::create_dir_all(&cache).unwrap();
        for path in [&repo, &cache] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(repo.join("pyproject.toml"), "[project]\nname='fixture'\n").unwrap();
        fs::set_permissions(
            repo.join("pyproject.toml"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let source = repo.join("example.py");
        fs::write(&source, "value = 1\n").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = fs::metadata(&source).unwrap();
        let file = cache.join("example.cpython-311.pyc");
        let mut bytes = Vec::from(3495u16.to_le_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(metadata.mtime() as u32).to_le_bytes());
        bytes.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
        bytes.push(0);
        fs::write(&file, bytes).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let run_git = |args: &[&str]| {
            let output = Command::new(&git)
                .env("HOME", dir.path())
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .arg("-C")
                .arg(&repo)
                .args([
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgSign=false",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run_git(&["init", "-q"]);
        run_git(&["add", "pyproject.toml", "example.py"]);
        run_git(&["commit", "-qm", "fixture"]);
        let git_dir = tempfile::tempdir().unwrap();
        fs::set_permissions(git_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let bin = git_dir.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
        let wrapper = bin.join("git");
        fs::copy(&git, &wrapper).unwrap();
        let home = dir.path().join("home");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        Some(Self {
            _dir: dir,
            _git_dir: git_dir,
            repo,
            source,
            file,
            bin,
            home,
            git,
        })
    }

    fn run<T: AsRef<std::ffi::OsStr>>(&self, args: &[T]) -> Output {
        let in_namespace = std::env::var_os("UPKIT_TEST_IN_NAMESPACE").is_some();
        let mut command = if in_namespace {
            Command::new(env!("CARGO_BIN_EXE_upkit"))
        } else {
            let mut command = Command::new("unshare");
            command.args([
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--mount-proc",
                env!("CARGO_BIN_EXE_upkit"),
            ]);
            command
        };
        command
            .current_dir(self._git_dir.path())
            .args(["--non-interactive", "--json"])
            .args(args)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env(
                "PATH",
                std::env::join_paths([Path::new("bin"), Path::new("/usr/bin"), Path::new("/bin")])
                    .unwrap(),
            )
            .output()
            .unwrap()
    }
    fn run_with_sentinel_git<T: AsRef<std::ffi::OsStr>>(
        &self,
        args: &[T],
        sentinel: &Path,
    ) -> Output {
        Command::new("unshare")
            .current_dir(self._git_dir.path())
            .args([
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--mount-proc",
                env!("CARGO_BIN_EXE_upkit"),
            ])
            .args(["--non-interactive", "--json"])
            .args(args)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env(
                "PATH",
                std::env::join_paths([
                    Path::new("sentinel-bin"),
                    Path::new("bin"),
                    Path::new("/usr/bin"),
                    Path::new("/bin"),
                ])
                .unwrap(),
            )
            .env("UPKIT_TEST_GIT_SENTINEL", sentinel)
            .env(
                "UPKIT_TEST_GIT_GRAFT_PATH",
                self.repo.join(".git/info/grafts"),
            )
            .output()
            .unwrap()
    }
    fn preview(&self) -> String {
        let output = self.run(&[
            "sweep",
            "bytecode",
            self.file.to_str().unwrap(),
            "--root",
            self.repo.to_str().unwrap(),
        ]);
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        value["plan"]["preview_token"].as_str().unwrap().to_owned()
    }

    fn add_file(&self, name: &str) -> PathBuf {
        let source = self.repo.join(format!("{name}.py"));
        fs::write(&source, format!("{name} = 1\n")).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = fs::metadata(&source).unwrap();
        let file = self
            .repo
            .join("__pycache__")
            .join(format!("{name}.cpython-311.pyc"));
        let mut bytes = Vec::from(3495u16.to_le_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(metadata.mtime() as u32).to_le_bytes());
        bytes.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
        bytes.push(0);
        fs::write(&file, bytes).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        file
    }
}

fn namespace_available() -> bool {
    Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--pid",
            "--fork",
            "--mount-proc",
            "/bin/true",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn run_fixture_namespace_worker(scenario: &str) {
    if git_support::elf_git().is_none() || !namespace_available() {
        eprintln!("SKIP: Git or an isolated user/PID namespace is unavailable");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let done = temp.path().join("worker-ran");
    let output = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--pid",
            "--fork",
            "--mount-proc",
        ])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "bytecode_fixture_namespace_worker",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("UPKIT_TEST_IN_NAMESPACE", "1")
        .env("UPKIT_TEST_NAMESPACE_SCENARIO", scenario)
        .env("UPKIT_TEST_NAMESPACE_DONE", &done)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        done.is_file(),
        "namespace worker did not execute the scenario"
    );
}

#[test]
#[ignore = "invoked by CLI preview/removal tests inside one mount namespace"]
fn bytecode_fixture_namespace_worker() {
    let Some(fixture) = Fixture::new() else {
        panic!("Git fixture could not be created in the isolated namespace");
    };
    match std::env::var("UPKIT_TEST_NAMESPACE_SCENARIO").as_deref() {
        Ok("cli_batch_previews_rechecks_and_removes_only_selected_files") => {
            cli_batch_previews_rechecks_and_removes_only_selected_files_in_namespace(&fixture);
        }
        Ok("non_unicode_project_bytecode_batch_preview_token_and_removal") => {
            non_unicode_project_bytecode_batch_preview_token_and_removal_in_namespace(fixture);
        }
        Ok("cli_batch_can_remove_files_from_different_caches") => {
            cli_batch_can_remove_files_from_different_caches_in_namespace(&fixture);
        }
        Ok("cli_accepts_real_supported_cpython_timestamp_bytecode") => {
            cli_accepts_real_supported_cpython_timestamp_bytecode_in_namespace(&fixture);
        }
        Ok("cli_removes_bytecode_with_non_identifier_source_stems") => {
            cli_removes_bytecode_with_non_identifier_source_stems_in_namespace(&fixture);
        }
        Ok("cli_verifies_and_removes_real_hash_based_cpython_bytecode") => {
            cli_verifies_and_removes_real_hash_based_cpython_bytecode_in_namespace();
        }
        Ok("cli_requires_authorization_and_an_unchanged_preview") => {
            cli_requires_authorization_and_an_unchanged_preview_in_namespace(&fixture);
        }
        Ok("cli_rejects_new_partial_clone_configuration_without_removing_bytecode") => {
            cli_rejects_new_partial_clone_configuration_without_removing_bytecode_in_namespace(
                &fixture,
            );
        }
        Ok("cli_rejects_a_bytecode_changed_after_preview_and_excluded_cache") => {
            cli_rejects_a_bytecode_changed_after_preview_and_excluded_cache_in_namespace(&fixture);
        }
        Ok("cli_rejects_a_manifest_changed_after_preview") => {
            cli_rejects_a_manifest_changed_after_preview_in_namespace(&fixture);
        }
        Ok("cli_rejects_go_workspace_marker_in_bytecode_cache") => {
            cli_rejects_go_workspace_marker_in_bytecode_cache_in_namespace(&fixture);
        }
        scenario => panic!("unknown bytecode namespace scenario: {scenario:?}"),
    }
    fs::write(
        std::env::var_os("UPKIT_TEST_NAMESPACE_DONE").unwrap(),
        "executed",
    )
    .unwrap();
}

#[test]
fn bytecode_dry_run_skips_a_trusted_sentinel_git_for_single_and_batch() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let (_bin, sentinel) = git_support::sentinel_elf_git(f._git_dir.path());
    let file = f.file.to_str().unwrap();
    let root = f.repo.to_str().unwrap();

    let normal = f.run_with_sentinel_git(&["sweep", "bytecode", file, "--root", root], &sentinel);
    assert!(
        normal.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&normal.stdout),
        String::from_utf8_lossy(&normal.stderr)
    );
    assert!(
        sentinel.exists(),
        "normal preview did not run the trusted fixture Git"
    );
    fs::remove_file(&sentinel).unwrap();

    let dry_preview = f.run_with_sentinel_git(
        &["--dry-run", "sweep", "bytecode", file, "--root", root],
        &sentinel,
    );
    assert!(dry_preview.status.success());
    let dry_preview: serde_json::Value = serde_json::from_slice(&dry_preview.stdout).unwrap();
    assert_eq!(dry_preview["status"], "skipped_unverified");
    assert!(dry_preview.get("plan").is_none());
    assert!(dry_preview.get("preview_token").is_none());
    assert!(
        !sentinel.exists(),
        "single bytecode preview invoked fixture Git"
    );

    let dry_single = f.run_with_sentinel_git(
        &[
            "--dry-run",
            "sweep",
            "bytecode",
            file,
            "--root",
            root,
            "--run",
        ],
        &sentinel,
    );
    assert!(dry_single.status.success());
    let dry_single: serde_json::Value = serde_json::from_slice(&dry_single.stdout).unwrap();
    assert_eq!(dry_single["status"], "skipped_unverified");
    assert_eq!(dry_single["validated_selections"], 1);
    assert!(dry_single.get("plan").is_none());
    assert!(dry_single.get("preview_token").is_none());
    assert!(
        !sentinel.exists(),
        "single bytecode dry-run invoked fixture Git"
    );

    let second = f.add_file("second");
    let dry_batch_preview = f.run_with_sentinel_git(
        &[
            "--dry-run",
            "sweep",
            "bytecode-batch",
            file,
            second.to_str().unwrap(),
            "--root",
            root,
        ],
        &sentinel,
    );
    assert!(dry_batch_preview.status.success());
    let dry_batch_preview: serde_json::Value =
        serde_json::from_slice(&dry_batch_preview.stdout).unwrap();
    assert_eq!(dry_batch_preview["status"], "skipped_unverified");
    assert_eq!(dry_batch_preview["validated_selections"], 2);
    assert!(dry_batch_preview.get("plan").is_none());
    assert!(dry_batch_preview.get("preview_token").is_none());
    assert!(
        !sentinel.exists(),
        "bytecode batch preview invoked fixture Git"
    );

    let dry_batch = f.run_with_sentinel_git(
        &[
            "--dry-run",
            "sweep",
            "bytecode-batch",
            file,
            second.to_str().unwrap(),
            "--root",
            root,
            "--run",
        ],
        &sentinel,
    );
    assert!(dry_batch.status.success());
    let dry_batch: serde_json::Value = serde_json::from_slice(&dry_batch.stdout).unwrap();
    assert_eq!(dry_batch["status"], "skipped_unverified");
    assert_eq!(dry_batch["validated_selections"], 2);
    assert!(dry_batch.get("plan").is_none());
    assert!(dry_batch.get("preview_token").is_none());
    assert!(
        !sentinel.exists(),
        "bytecode batch dry-run invoked fixture Git"
    );
    assert!(f.file.exists() && second.exists());
}

#[test]
fn bytecode_dry_run_rejects_non_files_named_like_bytecode() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let fake_dir = f.file.parent().unwrap().join("fake.cpython-311.pyc");
    fs::create_dir(&fake_dir).unwrap();
    let fake_link = f.file.parent().unwrap().join("link.cpython-311.pyc");
    std::os::unix::fs::symlink(&f.file, &fake_link).unwrap();
    let root = f.repo.to_str().unwrap();

    for selection in [&fake_dir, &fake_link] {
        let output = f.run(&[
            "--dry-run",
            "sweep",
            "bytecode",
            selection.to_str().unwrap(),
            "--root",
            root,
            "--run",
        ]);
        let message = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{message}");
        assert!(message.contains("not a regular file"), "{message}");
    }
    assert!(f.file.is_file());
    assert!(fake_dir.is_dir());
}

#[test]
fn scheduled_bytecode_cleanup_requires_opt_in_and_rechecks_policy() {
    use std::{
        hash::Hasher,
        time::{Duration, SystemTime},
    };

    let Some(f) = Fixture::new() else {
        eprintln!("SKIP: Git or an isolated user/PID namespace is unavailable");
        return;
    };
    let second = f.add_file("second");
    let unchecked_source = f.repo.join("a_unchecked.py");
    fs::write(&unchecked_source, "value = 1\n").unwrap();
    fs::set_permissions(&unchecked_source, fs::Permissions::from_mode(0o600)).unwrap();
    let unchecked = f.repo.join("__pycache__/a_unchecked.cpython-311.pyc");
    let mut bytes = Vec::from(3495u16.to_le_bytes());
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(&1u32.to_le_bytes());
    let key = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64;
    let mut hash = siphasher::sip::SipHasher13::new_with_keys(key, 0);
    hash.write(b"value = 1\n");
    bytes.extend_from_slice(&hash.finish().to_le_bytes());
    bytes.push(0);
    fs::write(&unchecked, bytes).unwrap();
    fs::set_permissions(&unchecked, fs::Permissions::from_mode(0o600)).unwrap();
    let old = SystemTime::now() - Duration::from_secs(30 * 24 * 60 * 60);
    for path in [&f.file, &second, &unchecked, &f.repo.join("__pycache__")] {
        fs::File::open(path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(old))
            .unwrap();
    }
    let config = f.home.join("settings.toml");
    let write_config = |age: &str, opt_in: bool| {
        fs::write(&config, format!(
            "version = 1\n[profiles.work]\nworkspace_roots = ['{}']\nartifact_retention = '{age}'\nenabled_ecosystems = ['python']\nscheduled_bytecode_cleanup = {opt_in}\n",
            f.repo.display()
        )).unwrap();
    };
    write_config("1d", true);
    let preview = || {
        f.run(&[
            "--config",
            config.to_str().unwrap(),
            "--profile",
            "work",
            "schedule",
            "preview",
            "--frequency",
            "daily",
        ])
    };
    assert!(!preview().status.success());
    write_config("7d", true);
    let preview = preview();
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let token = preview["scheduled_scope_token"].as_str().unwrap();
    assert!(token.starts_with("v3."));
    assert!(
        preview["warning"]
            .as_str()
            .unwrap()
            .contains("automatically and permanently")
    );
    assert!(
        preview["service_unit"]
            .as_str()
            .unwrap()
            .contains("scheduled-bytecode-cleanup --authorize-scheduled-cleanup")
    );
    let root = f.repo.to_str().unwrap();
    let missing_authorization = f.run(&[
        "--offline",
        "--yes",
        "--config",
        "/dev/null",
        "sweep",
        "scheduled-bytecode-cleanup",
        "--scope-token",
        token,
        root,
    ]);
    assert!(!missing_authorization.status.success());
    let scan_with_cleanup_token = f.run(&[
        "--offline",
        "--dry-run",
        "--config",
        "/dev/null",
        "sweep",
        "scan",
        "--scope-token",
        token,
        root,
    ]);
    assert!(!scan_with_cleanup_token.status.success());
    let run_cleanup = |extra: &[&str], token: &str| {
        let mut args = vec!["--offline", "--yes", "--config", "/dev/null"];
        args.extend_from_slice(extra);
        args.extend_from_slice(&[
            "sweep",
            "scheduled-bytecode-cleanup",
            "--authorize-scheduled-cleanup",
            "--scope-token",
            token,
            root,
        ]);
        f.run(&args)
    };
    assert!(!run_cleanup(&["--dry-run"], "invalid").status.success());
    let (_bin, sentinel) = git_support::sentinel_elf_git(f._git_dir.path());
    let dry = f.run_with_sentinel_git(
        &[
            "--offline",
            "--yes",
            "--config",
            "/dev/null",
            "--dry-run",
            "sweep",
            "scheduled-bytecode-cleanup",
            "--authorize-scheduled-cleanup",
            "--scope-token",
            token,
            root,
        ],
        &sentinel,
    );
    assert!(
        !dry.status.success(),
        "unverified scheduled dry-run should fail closed"
    );
    let dry: serde_json::Value = serde_json::from_slice(&dry.stdout).unwrap();
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["complete"], false);
    assert!(dry["items"].as_array().unwrap().iter().all(|item| {
        item["status"] == "skipped_unverified"
            && item.get("file").is_none()
            && item.get("detail").is_none()
    }));
    assert!(!dry.to_string().contains(root));
    assert!(dry["warnings"].as_array().unwrap().iter().any(|warning| {
        warning
            .as_str()
            .unwrap()
            .contains("inspected counts only filenames")
    }));
    assert!(
        !sentinel.exists(),
        "scheduled dry-run invoked the trusted fixture Git"
    );
    assert!(f.file.exists() && second.exists() && unchecked.exists());
    assert!(!f.home.join("data/upkit/history").exists());
    let history = f.home.join("data/upkit/history");
    fs::create_dir_all(&history).unwrap();
    fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
    for id in 0..99 {
        fs::write(history.join(format!("{id:03}.json")), "occupied fixture").unwrap();
    }
    let full = run_cleanup(&[], token);
    assert!(!full.status.success());
    let full: serde_json::Value = serde_json::from_slice(&full.stdout).unwrap();
    assert!(full["items"].as_array().unwrap().iter().any(|item| {
        item["status"] == "failed"
            && item.get("file").is_none()
            && item.get("detail").is_none()
            && item.get("history_warning").is_none()
    }));
    assert!(!full.to_string().contains(root));
    assert!(f.file.exists() && second.exists() && unchecked.exists());
    fs::remove_dir_all(&history).unwrap();
    fs::remove_file(&config).unwrap();
    for args in [&["--dry-run"][..], &[][..]] {
        let output = run_cleanup(args, token);
        assert!(!output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for text in [&stdout, &stderr] {
            assert!(!text.contains(config.to_str().unwrap()));
            assert!(!text.contains(root));
        }
        assert!(stdout.contains("details are redacted") || stderr.contains("details are redacted"));
        assert!(f.file.exists() && second.exists() && unchecked.exists());
    }
    if history.exists() {
        fs::remove_dir_all(&history).unwrap();
    }
    write_config("7d", false);
    assert!(!run_cleanup(&[], token).status.success());
    assert!(f.file.exists() && second.exists() && unchecked.exists());
    write_config("7d", true);
    let result = run_cleanup(&[], token);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(
        result["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["status"] == "verified_absent")
    );
    assert!(!f.file.exists());
    assert!(second.exists() && unchecked.exists() && f.source.exists());
}

#[test]
fn scheduled_cleanup_is_complete_when_the_last_file_uses_the_inspection_limit() {
    use std::{
        hash::Hasher,
        time::{Duration, SystemTime},
    };

    let Some(f) = Fixture::new() else {
        eprintln!("SKIP: Git or an isolated user/PID namespace is unavailable");
        return;
    };
    let old = SystemTime::now() - Duration::from_secs(30 * 24 * 60 * 60);
    let cache = f.file.parent().unwrap();
    for index in 0..31 {
        let name = format!("a{index:02}");
        let source = f.repo.join(format!("{name}.py"));
        let source_text = format!("{name} = 1\n");
        fs::write(&source, &source_text).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();

        let mut bytes = Vec::from(3495u16.to_le_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let key = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64;
        let mut hash = siphasher::sip::SipHasher13::new_with_keys(key, 0);
        hash.write(source_text.as_bytes());
        bytes.extend_from_slice(&hash.finish().to_le_bytes());
        bytes.push(0);

        let file = cache.join(format!("{name}.cpython-311.pyc"));
        fs::write(&file, bytes).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::File::open(file)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(old))
            .unwrap();
    }
    fs::File::open(cache)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old))
        .unwrap();
    fs::File::open(&f.file)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old))
        .unwrap();

    let config = f.home.join("settings.toml");
    fs::write(
        &config,
        format!(
            "version = 1\n[profiles.work]\nworkspace_roots = ['{}']\nartifact_retention = '7d'\nenabled_ecosystems = ['python']\nscheduled_bytecode_cleanup = true\n",
            f.repo.display()
        ),
    )
    .unwrap();
    let preview = f.run(&[
        "--config",
        config.to_str().unwrap(),
        "--profile",
        "work",
        "schedule",
        "preview",
        "--frequency",
        "daily",
    ]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let root = f.repo.to_str().unwrap();
    let cleanup = f.run(&[
        "--offline",
        "--dry-run",
        "--yes",
        "--config",
        "/dev/null",
        "sweep",
        "scheduled-bytecode-cleanup",
        "--authorize-scheduled-cleanup",
        "--scope-token",
        preview["scheduled_scope_token"].as_str().unwrap(),
        root,
    ]);
    assert!(
        !cleanup.status.success(),
        "unverified scheduled dry-run should not report a completed preview: {}",
        String::from_utf8_lossy(&cleanup.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&cleanup.stdout).unwrap();
    assert_eq!(report["inspected"], 32);
    assert_eq!(report["complete"], false);
    assert_eq!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|warning| warning
                .as_str()
                .unwrap()
                .contains("inspected counts only filenames"))
            .count(),
        1
    );
    assert!(report["items"].as_array().unwrap().iter().all(|item| {
        item["status"] == "skipped_unverified"
            && item.get("file").is_none()
            && item.get("detail").is_none()
    }));
    assert!(!report.to_string().contains(root));
    assert!(f.file.exists());
    assert_eq!(fs::read_dir(cache).unwrap().count(), 32);
}

#[test]
fn scheduled_cleanup_rotates_a_bounded_file_window_without_mutating_dry_run() {
    use std::{
        hash::Hasher,
        time::{Duration, SystemTime},
    };

    let Some(f) = Fixture::new() else {
        eprintln!("SKIP: Git or an isolated user/PID namespace is unavailable");
        return;
    };
    let cache = f.file.parent().unwrap();
    fs::remove_file(&f.file).unwrap();
    let old = SystemTime::now() - Duration::from_secs(30 * 24 * 60 * 60);
    for index in 0..33 {
        let name = format!("a{index:02}");
        let source_text = format!("{name} = 1\n");
        let source = f.repo.join(format!("{name}.py"));
        fs::write(&source, &source_text).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let mut bytes = Vec::from(3495u16.to_le_bytes());
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let key = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64;
        let mut hash = siphasher::sip::SipHasher13::new_with_keys(key, 0);
        hash.write(source_text.as_bytes());
        bytes.extend_from_slice(&hash.finish().to_le_bytes());
        bytes.push(0);
        let path = cache.join(format!("{name}.cpython-311.pyc"));
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::File::open(path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(old))
            .unwrap();
    }
    fs::File::open(cache)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(old))
        .unwrap();
    let config = f.home.join("settings.toml");
    fs::write(&config, format!(
        "version = 1\n[profiles.work]\nworkspace_roots = ['{}']\nartifact_retention = '7d'\nenabled_ecosystems = ['python']\nscheduled_bytecode_cleanup = true\n",
        f.repo.display()
    )).unwrap();
    let preview = f.run(&[
        "--config",
        config.to_str().unwrap(),
        "--profile",
        "work",
        "schedule",
        "preview",
        "--frequency",
        "daily",
    ]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let output = f.run(&[
        "--offline",
        "--dry-run",
        "--yes",
        "--config",
        "/dev/null",
        "sweep",
        "scheduled-bytecode-cleanup",
        "--authorize-scheduled-cleanup",
        "--scope-token",
        plan["scheduled_scope_token"].as_str().unwrap(),
        f.repo.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["inspected"], 32);
    assert_eq!(report["complete"], false);
    let items = report["items"].as_array().unwrap();
    assert_eq!(items.len(), 32);
    assert!(
        items
            .iter()
            .all(|item| item["status"] == "skipped_unverified"
                && item.get("file").is_none()
                && item.get("detail").is_none())
    );
    assert!(!report.to_string().contains(f.repo.to_str().unwrap()));
    assert_eq!(fs::read_dir(cache).unwrap().count(), 33);
    assert!(!f.home.join("data/upkit/history").exists());
}

#[test]
fn non_unicode_project_bytecode_batch_preview_token_and_removal() {
    run_fixture_namespace_worker("non_unicode_project_bytecode_batch_preview_token_and_removal");
}

fn non_unicode_project_bytecode_batch_preview_token_and_removal_in_namespace(mut f: Fixture) {
    use std::{ffi::OsStr, os::unix::ffi::OsStringExt};
    let renamed = f
        ._dir
        .path()
        .join(std::ffi::OsString::from_vec(b"project-\xff%".to_vec()));
    fs::rename(&f.repo, &renamed).unwrap();
    f.repo = renamed;
    f.source = f.repo.join("example.py");
    f.file = f.repo.join("__pycache__/example.cpython-311.pyc");
    let second = f.add_file("second");
    let untouched = f.add_file("untouched");
    let args = [
        OsStr::new("sweep"),
        OsStr::new("bytecode-batch"),
        f.file.as_os_str(),
        second.as_os_str(),
        OsStr::new("--root"),
        f.repo.as_os_str(),
    ];
    let output = f.run(&args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["plan"]["files"][0]["file"]["encoding"],
        "unix-percent-bytes"
    );
    assert!(
        value["plan"]["files"][0]["file"]["value"]
            .as_str()
            .unwrap()
            .contains("/project-%FF%25/")
    );
    assert_eq!(
        value["plan"]["scope"]["roots"][0]["encoding"],
        "unix-percent-bytes"
    );
    let token = value["plan"]["preview_token"].as_str().unwrap();
    let run = |token: &str| {
        f.run(&[
            OsStr::new("--yes"),
            OsStr::new("sweep"),
            OsStr::new("bytecode-batch"),
            f.file.as_os_str(),
            second.as_os_str(),
            OsStr::new("--root"),
            f.repo.as_os_str(),
            OsStr::new("--run"),
            OsStr::new("--authorize-bytecode-removal"),
            OsStr::new("--preview-token"),
            OsStr::new(token),
        ])
    };
    assert!(!run("wrong").status.success());
    assert!(f.file.exists() && second.exists());
    let result = run(token);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["result"]["complete"], true);
    assert_eq!(
        result["result"]["items"][0]["file"]["encoding"],
        "unix-percent-bytes"
    );
    assert!(!f.file.exists() && !second.exists() && untouched.exists());
    assert!(f.source.exists());
}

#[test]
fn cli_batch_previews_rechecks_and_removes_only_selected_files() {
    run_fixture_namespace_worker("cli_batch_previews_rechecks_and_removes_only_selected_files");
}

fn cli_batch_previews_rechecks_and_removes_only_selected_files_in_namespace(fixture: &Fixture) {
    let second = fixture.add_file("second");
    let untouched = fixture.add_file("untouched");
    let first = fixture.file.to_str().unwrap();
    let second_arg = second.to_str().unwrap();
    let root = fixture.repo.to_str().unwrap();
    let preview = || {
        let output = fixture.run(&["sweep", "bytecode-batch", first, second_arg, "--root", root]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["plan"]["files"].as_array().unwrap().len(), 2);
        value["plan"]["preview_token"].as_str().unwrap().to_owned()
    };
    let token = preview();
    let missing = fixture.run(&[
        "--yes",
        "sweep",
        "bytecode-batch",
        first,
        second_arg,
        "--root",
        root,
        "--run",
        "--preview-token",
        &token,
    ]);
    assert!(!missing.status.success());
    let wrong = fixture.run(&[
        "--yes",
        "sweep",
        "bytecode-batch",
        first,
        second_arg,
        "--root",
        root,
        "--run",
        "--authorize-bytecode-removal",
        "--preview-token",
        "wrong",
    ]);
    assert!(!wrong.status.success());
    let duplicate = fixture.run(&["sweep", "bytecode-batch", first, first, "--root", root]);
    assert!(!duplicate.status.success());
    let dry_run = fixture.run(&[
        "--dry-run",
        "sweep",
        "bytecode-batch",
        first,
        second_arg,
        "--root",
        root,
        "--run",
    ]);
    assert!(dry_run.status.success());
    let dry_run: serde_json::Value = serde_json::from_slice(&dry_run.stdout).unwrap();
    assert_eq!(dry_run["status"], "skipped_unverified");
    assert_eq!(dry_run["validated_selections"], 2);
    assert!(dry_run.get("plan").is_none());
    assert!(dry_run.get("preview_token").is_none());
    let mut bytes = fs::read(&second).unwrap();
    bytes.push(1);
    fs::write(&second, bytes).unwrap();
    let stale = fixture.run(&[
        "--yes",
        "sweep",
        "bytecode-batch",
        first,
        second_arg,
        "--root",
        root,
        "--run",
        "--authorize-bytecode-removal",
        "--preview-token",
        &token,
    ]);
    assert!(!stale.status.success());
    assert!(fixture.file.exists() && second.exists() && untouched.exists());
    let token = preview();
    let output = fixture.run(&[
        "--yes",
        "sweep",
        "bytecode-batch",
        first,
        second_arg,
        "--root",
        root,
        "--run",
        "--authorize-bytecode-removal",
        "--preview-token",
        &token,
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["result"]["complete"], true);
    for item in value["result"]["items"].as_array().unwrap() {
        assert_eq!(item["status"], "verified_absent");
    }
    assert!(!fixture.file.exists() && !second.exists());
    assert!(untouched.exists());
    assert!(fixture.repo.join("second.py").exists());
    let history = fixture.run(&["report"]);
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert_eq!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|record| record["operation"] == "bytecode_removal")
            .count(),
        2
    );
}

#[test]
fn cli_batch_can_remove_files_from_different_caches() {
    run_fixture_namespace_worker("cli_batch_can_remove_files_from_different_caches");
}

fn cli_batch_can_remove_files_from_different_caches_in_namespace(fixture: &Fixture) {
    let old_file = fixture.add_file("second");
    let package = fixture.repo.join("package");
    let cache = package.join("__pycache__");
    fs::create_dir_all(&cache).unwrap();
    fs::set_permissions(&package, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(fixture.repo.join("second.py"), package.join("second.py")).unwrap();
    let second = cache.join("second.cpython-311.pyc");
    fs::rename(old_file, &second).unwrap();
    let first = fixture.file.to_str().unwrap();
    let second_arg = second.to_str().unwrap();
    let root = fixture.repo.to_str().unwrap();
    let preview = fixture.run(&["sweep", "bytecode-batch", first, second_arg, "--root", root]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let token = value["plan"]["preview_token"].as_str().unwrap();
    let result = fixture.run(&[
        "--yes",
        "sweep",
        "bytecode-batch",
        first,
        second_arg,
        "--root",
        root,
        "--run",
        "--authorize-bytecode-removal",
        "--preview-token",
        token,
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert!(!fixture.file.exists() && !second.exists());
    assert!(fixture.source.exists() && package.join("second.py").exists());
}

#[test]
fn cli_accepts_real_supported_cpython_timestamp_bytecode() {
    run_fixture_namespace_worker("cli_accepts_real_supported_cpython_timestamp_bytecode");
}

#[test]
fn cli_removes_bytecode_with_non_identifier_source_stems() {
    run_fixture_namespace_worker("cli_removes_bytecode_with_non_identifier_source_stems");
}

fn cli_removes_bytecode_with_non_identifier_source_stems_in_namespace(fixture: &Fixture) {
    let names = ["non-module-name", "package.module"];
    let files = names
        .iter()
        .map(|name| fixture.add_file(name))
        .collect::<Vec<_>>();
    let root = fixture.repo.to_str().unwrap();
    let mut preview_args = vec!["sweep", "bytecode-batch"];
    preview_args.extend(files.iter().map(|file| file.to_str().unwrap()));
    preview_args.extend(["--root", root]);
    let preview = fixture.run(&preview_args);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(plan["plan"]["files"].as_array().unwrap().len(), files.len());
    for name in names {
        assert!(
            plan["plan"]["files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|file| file["source"]
                    == fixture.repo.join(format!("{name}.py")).to_str().unwrap()),
            "preview omitted source {name:?}: {plan}"
        );
    }
    let token = plan["plan"]["preview_token"].as_str().unwrap();
    let mut remove_args = vec!["--yes", "sweep", "bytecode-batch"];
    remove_args.extend(files.iter().map(|file| file.to_str().unwrap()));
    remove_args.extend([
        "--root",
        root,
        "--run",
        "--authorize-bytecode-removal",
        "--preview-token",
        token,
    ]);
    let result = fixture.run(&remove_args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["result"]["complete"], true);
    assert!(files.iter().all(|file| !file.exists()));
    assert!(
        names
            .iter()
            .all(|name| fixture.repo.join(format!("{name}.py")).is_file())
    );
}

fn cli_accepts_real_supported_cpython_timestamp_bytecode_in_namespace(fixture: &Fixture) {
    let Ok(python) = which::which("python3") else {
        return;
    };
    let source = fixture.repo.join("real_fixture.py");
    fs::write(&source, "value = 42\n").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
    let output = Command::new(python)
        .args(["-I", "-B", "-c", "import importlib.util,json,py_compile,sys; print(json.dumps([sys.implementation.cache_tag, int.from_bytes(importlib.util.MAGIC_NUMBER[:2], 'little'), py_compile.compile(sys.argv[1], doraise=True)]))"])
        .arg(&source)
        .env("HOME", &fixture.home)
        .output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let supported = [
        ("cpython-310", 3439),
        ("cpython-311", 3495),
        ("cpython-312", 3531),
        ("cpython-313", 3571),
        ("cpython-314", 3627),
        ("cpython-315", 3666),
        ("cpython-316", 3706),
    ];
    if !supported
        .iter()
        .any(|(tag, magic)| info[0] == *tag && info[1] == *magic)
    {
        return;
    }
    let file = PathBuf::from(info[2].as_str().unwrap());
    let file_arg = file.to_str().unwrap();
    let root = fixture.repo.to_str().unwrap();
    let preview = fixture.run(&["sweep", "bytecode", file_arg, "--root", root]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let token = value["plan"]["preview_token"].as_str().unwrap();
    let removal = fixture.run(&[
        "--yes",
        "sweep",
        "bytecode",
        file_arg,
        "--root",
        root,
        "--run",
        "--authorize-bytecode-removal",
        "--preview-token",
        token,
    ]);
    assert!(
        removal.status.success(),
        "{}",
        String::from_utf8_lossy(&removal.stdout)
    );
    assert!(!file.exists());
    assert_eq!(fs::read_to_string(source).unwrap(), "value = 42\n");
}

#[test]
fn cli_verifies_and_removes_real_hash_based_cpython_bytecode() {
    run_fixture_namespace_worker("cli_verifies_and_removes_real_hash_based_cpython_bytecode");
}

fn cli_verifies_and_removes_real_hash_based_cpython_bytecode_in_namespace() {
    for interpreter in ["python3", "python3.12"] {
        let Ok(python) = which::which(interpreter) else {
            continue;
        };
        verify_real_hash_bytecode(&python);
    }
}

fn verify_real_hash_bytecode(python: &Path) {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    for (name, mode, invalidation) in [
        ("checked_fixture", "CHECKED_HASH", "hash-checked"),
        ("unchecked_fixture", "UNCHECKED_HASH", "hash-unchecked"),
    ] {
        let source = fixture.repo.join(format!("{name}.py"));
        fs::write(&source, "value = 42\n").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let output = Command::new(python)
            .args(["-I", "-B", "-c", "import importlib.util,json,py_compile,sys; print(json.dumps([sys.implementation.cache_tag, int.from_bytes(importlib.util.MAGIC_NUMBER[:2], 'little'), py_compile.compile(sys.argv[1], doraise=True, invalidation_mode=getattr(py_compile.PycInvalidationMode,sys.argv[2]))]))"])
            .arg(&source).arg(mode).env("HOME", &fixture.home).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if ![
            ("cpython-310", 3439),
            ("cpython-311", 3495),
            ("cpython-312", 3531),
            ("cpython-313", 3571),
            ("cpython-314", 3627),
            ("cpython-315", 3666),
            ("cpython-316", 3706),
        ]
        .iter()
        .any(|(tag, magic)| info[0] == *tag && info[1] == *magic)
        {
            return;
        }
        let file = PathBuf::from(info[2].as_str().unwrap());
        let file_arg = file.to_str().unwrap();
        let root = fixture.repo.to_str().unwrap();
        let preview = || fixture.run(&["sweep", "bytecode", file_arg, "--root", root]);
        let result = preview();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
        let plan: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(plan["plan"]["invalidation"], invalidation);
        let old_token = plan["plan"]["preview_token"].as_str().unwrap();
        fs::write(&source, "value = 43\n").unwrap();
        assert!(!preview().status.success());
        assert!(file.exists());
        fs::write(&source, "value = 42\n").unwrap();
        let result = preview();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
        let plan: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        let token = plan["plan"]["preview_token"].as_str().unwrap();
        assert_ne!(token, old_token);
        let stale = fixture.run(&[
            "--yes",
            "sweep",
            "bytecode",
            file_arg,
            "--root",
            root,
            "--run",
            "--authorize-bytecode-removal",
            "--preview-token",
            old_token,
        ]);
        assert!(!stale.status.success());
        assert!(file.exists());
        let removal = fixture.run(&[
            "--yes",
            "sweep",
            "bytecode",
            file_arg,
            "--root",
            root,
            "--run",
            "--authorize-bytecode-removal",
            "--preview-token",
            token,
        ]);
        assert!(
            removal.status.success(),
            "{}",
            String::from_utf8_lossy(&removal.stdout)
        );
        assert!(!file.exists());
        assert_eq!(fs::read_to_string(&source).unwrap(), "value = 42\n");
    }
}

#[test]
fn batch_stops_and_preserves_remaining_files() {
    use std::sync::atomic::{AtomicBool, Ordering};
    if let Ok(mode) = std::env::var("UPKIT_BATCH_FIXTURE_MODE") {
        let project = PathBuf::from(std::env::var_os("UPKIT_BATCH_FIXTURE_PROJECT").unwrap());
        let home = PathBuf::from(std::env::var_os("UPKIT_BATCH_FIXTURE_HOME").unwrap());
        let git = PathBuf::from(std::env::var_os("UPKIT_BATCH_FIXTURE_GIT").unwrap());
        let files = ["example", "second", "third"].map(|name| {
            project
                .join("__pycache__")
                .join(format!("{name}.cpython-311.pyc"))
        });
        let scope = upkit::bytecode::Scope {
            roots: vec![project.clone()],
            exclusions: vec![],
            older_than_seconds: None,
            enabled: None,
        };
        let cancel = AtomicBool::new(false);
        let plan = upkit::bytecode::preview_batch(&scope, &files, &cancel).unwrap();
        let result = upkit::reports::perform_bytecode_batch_with_progress(
            &home,
            &plan,
            &plan.preview_token,
            &cancel,
            |done, _| {
                if done == 1 {
                    if mode == "cancel" {
                        cancel.store(true, Ordering::Relaxed);
                    } else if mode == "git-change" {
                        let replacement = git.with_extension("replacement");
                        fs::copy(&git, &replacement).unwrap();
                        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755))
                            .unwrap();
                        fs::rename(replacement, &git).unwrap();
                        assert!(
                            Command::new(&git)
                                .arg("--version")
                                .status()
                                .unwrap()
                                .success()
                        );
                    } else {
                        fs::write(project.join("second.py"), "changed after preview\n").unwrap();
                    }
                }
            },
        )
        .unwrap();
        assert!(!result.complete);
        assert_eq!(result.items[0].status, "verified_absent");
        assert_eq!(
            result.items[1].status,
            if mode == "cancel" {
                "cancelled"
            } else {
                "failed"
            }
        );
        if mode == "git-change" {
            assert_eq!(
                result.items[1].error.as_deref(),
                Some("bytecode or project changed after batch preview")
            );
        }
        assert!(!result.items[1].attempted);
        assert_eq!(result.items[2].status, "skipped");
        assert!(!files[0].exists() && files[1].exists() && files[2].exists());
        assert_eq!(upkit::reports::read(&home).unwrap().records.len(), 1);
        return;
    }
    for mode in ["change", "cancel", "git-change"] {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let second = fixture.add_file("second");
        let third = fixture.add_file("third");
        let output = Command::new("unshare")
            .current_dir(fixture._git_dir.path())
            .args([
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--mount-proc",
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "batch_stops_and_preserves_remaining_files",
                "--nocapture",
            ])
            .env("UPKIT_BATCH_FIXTURE_MODE", mode)
            .env("UPKIT_BATCH_FIXTURE_PROJECT", &fixture.repo)
            .env("UPKIT_BATCH_FIXTURE_HOME", &fixture.home)
            .env("UPKIT_BATCH_FIXTURE_GIT", fixture.bin.join("git"))
            .env("HOME", &fixture.home)
            .env("XDG_CONFIG_HOME", fixture.home.join("config"))
            .env("XDG_DATA_HOME", fixture.home.join("data"))
            .env(
                "PATH",
                std::env::join_paths([Path::new("bin"), Path::new("/usr/bin"), Path::new("/bin")])
                    .unwrap(),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!fixture.file.exists() && second.exists() && third.exists());
    }
}

#[test]
fn cli_requires_authorization_and_an_unchanged_preview() {
    run_fixture_namespace_worker("cli_requires_authorization_and_an_unchanged_preview");
}

fn cli_requires_authorization_and_an_unchanged_preview_in_namespace(fixture: &Fixture) {
    let token = fixture.preview();
    assert_eq!(
        fixture.preview(),
        token,
        "preview token changes without a dry-run"
    );
    let file = fixture.file.to_str().unwrap();
    let root = fixture.repo.to_str().unwrap();
    let missing_authorization = fixture.run(&[
        "--yes",
        "sweep",
        "bytecode",
        file,
        "--root",
        root,
        "--run",
        "--preview-token",
        &token,
    ]);
    assert!(!missing_authorization.status.success());
    let wrong_token = fixture.run(&[
        "--yes",
        "sweep",
        "bytecode",
        file,
        "--root",
        root,
        "--run",
        "--authorize-bytecode-removal",
        "--preview-token",
        "wrong",
    ]);
    assert!(!wrong_token.status.success());
    assert!(fixture.file.exists());
    assert_eq!(
        fixture.preview(),
        token,
        "wrong token changed the preview token"
    );
    let dry_run = fixture.run(&[
        "--dry-run",
        "sweep",
        "bytecode",
        file,
        "--root",
        root,
        "--run",
    ]);
    assert!(
        dry_run.status.success(),
        "{}",
        String::from_utf8_lossy(&dry_run.stdout)
    );
    let dry_run: serde_json::Value = serde_json::from_slice(&dry_run.stdout).unwrap();
    assert_eq!(dry_run["status"], "skipped_unverified");
    assert!(dry_run.get("plan").is_none());
    assert!(dry_run.get("preview_token").is_none());
    assert!(fixture.file.exists());
    assert_eq!(
        fixture.preview(),
        token,
        "dry-run changed the preview token"
    );
    let success = fixture.run(&[
        "--yes",
        "sweep",
        "bytecode",
        file,
        "--root",
        root,
        "--run",
        "--authorize-bytecode-removal",
        "--preview-token",
        &token,
    ]);
    assert!(
        success.status.success(),
        "{}",
        String::from_utf8_lossy(&success.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(value["verification"], "verified_absent");
    assert!(!fixture.file.exists());
    assert_eq!(fs::read_to_string(&fixture.source).unwrap(), "value = 1\n");
    let history = fixture.run(&["report"]);
    assert!(String::from_utf8_lossy(&history.stdout).contains("bytecode_removal"));
}

#[test]
fn cli_rejects_new_partial_clone_configuration_without_removing_bytecode() {
    run_fixture_namespace_worker(
        "cli_rejects_new_partial_clone_configuration_without_removing_bytecode",
    );
}

fn cli_rejects_new_partial_clone_configuration_without_removing_bytecode_in_namespace(
    fixture: &Fixture,
) {
    let version = Command::new(fixture.bin.join("git"))
        .arg("--version")
        .output()
        .unwrap();
    let version = String::from_utf8_lossy(&version.stdout);
    let minor = version
        .trim()
        .strip_prefix("git version 2.")
        .and_then(|rest| rest.split('.').next())
        .and_then(|part| part.parse::<u32>().ok());
    if !minor.is_some_and(|minor| (36..45).contains(&minor)) {
        return;
    }
    let token = fixture.preview();
    let result = Command::new(fixture.bin.join("git"))
        .env("HOME", &fixture.home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .arg("-C")
        .arg(&fixture.repo)
        .args(["config", "remote.origin.promisor", "true"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let file = fixture.file.to_str().unwrap();
    let root = fixture.repo.to_str().unwrap();
    let output = fixture.run(&[
        "--yes",
        "sweep",
        "bytecode",
        file,
        "--root",
        root,
        "--run",
        "--authorize-bytecode-removal",
        "--preview-token",
        &token,
    ]);
    assert!(!output.status.success());
    assert!(fixture.file.exists());
    assert_eq!(fs::read_to_string(&fixture.source).unwrap(), "value = 1\n");
}

#[test]
fn cli_rejects_a_bytecode_changed_after_preview_and_excluded_cache() {
    run_fixture_namespace_worker("cli_rejects_a_bytecode_changed_after_preview_and_excluded_cache");
}

fn cli_rejects_a_bytecode_changed_after_preview_and_excluded_cache_in_namespace(fixture: &Fixture) {
    let token = fixture.preview();
    let mut bytes = fs::read(&fixture.file).unwrap();
    bytes.push(1);
    fs::write(&fixture.file, &bytes).unwrap();
    let file = fixture.file.to_str().unwrap();
    let root = fixture.repo.to_str().unwrap();
    let stale = fixture.run(&[
        "--yes",
        "sweep",
        "bytecode",
        file,
        "--root",
        root,
        "--run",
        "--authorize-bytecode-removal",
        "--preview-token",
        &token,
    ]);
    assert!(!stale.status.success());
    let excluded = fixture.run(&[
        "sweep",
        "bytecode",
        file,
        "--root",
        root,
        "--exclude",
        "__pycache__",
    ]);
    assert!(!excluded.status.success());
    assert_eq!(fs::read(&fixture.file).unwrap(), bytes);
}

#[test]
fn cli_rejects_bytecode_in_the_index_and_reachable_history() {
    let Some(fixture) = Fixture::new() else {
        return;
    };
    let git = fixture.git.clone();
    let git_command = |args: &[&str]| {
        let output = Command::new(&git)
            .env("HOME", &fixture.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .arg("-C")
            .arg(&fixture.repo)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgSign=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git_command(&["add", "-f", "__pycache__/example.cpython-311.pyc"]);
    let args = [
        "sweep",
        "bytecode",
        fixture.file.to_str().unwrap(),
        "--root",
        fixture.repo.to_str().unwrap(),
    ];
    assert!(!fixture.run(&args).status.success());
    git_command(&["commit", "-qm", "track cache"]);
    git_command(&[
        "rm",
        "--cached",
        "-q",
        "__pycache__/example.cpython-311.pyc",
    ]);
    git_command(&["commit", "-qm", "untrack cache"]);
    assert!(!fixture.run(&args).status.success());
    assert!(fixture.file.exists());
}

#[test]
fn cli_rejects_a_manifest_changed_after_preview() {
    run_fixture_namespace_worker("cli_rejects_a_manifest_changed_after_preview");
}

#[test]
fn cli_rejects_go_workspace_marker_in_bytecode_cache() {
    run_fixture_namespace_worker("cli_rejects_go_workspace_marker_in_bytecode_cache");
}

fn cli_rejects_a_manifest_changed_after_preview_in_namespace(fixture: &Fixture) {
    let token = fixture.preview();
    fs::write(
        fixture.repo.join("pyproject.toml"),
        "[project]\nname='changed'\n",
    )
    .unwrap();
    let output = fixture.run(&[
        "--yes",
        "sweep",
        "bytecode",
        fixture.file.to_str().unwrap(),
        "--root",
        fixture.repo.to_str().unwrap(),
        "--run",
        "--authorize-bytecode-removal",
        "--preview-token",
        &token,
    ]);
    assert!(!output.status.success());
    assert!(fixture.file.exists());
}

fn cli_rejects_go_workspace_marker_in_bytecode_cache_in_namespace(fixture: &Fixture) {
    let marker = fixture.file.parent().unwrap().join("go.work");
    fs::write(&marker, "go 1.24\n").unwrap();
    let output = fixture.run(&[
        "sweep",
        "bytecode",
        fixture.file.to_str().unwrap(),
        "--root",
        fixture.repo.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    let output_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output_text.contains("selected target was not found in the scan"),
        "{output_text}"
    );
    assert!(fixture.file.is_file());
    assert!(marker.is_file());
}
