#![cfg(target_os = "linux")]

#[path = "support/git.rs"]
mod git_support;
use std::{
    fs,
    os::unix::{
        ffi::OsStringExt,
        fs::{PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Fixture {
    _dir: tempfile::TempDir,
    _git_dir: tempfile::TempDir,
    project: PathBuf,
    target: PathBuf,
    home: PathBuf,
    git: PathBuf,
}
impl Fixture {
    fn new() -> Option<Self> {
        let git = git_support::elf_git()?;
        if std::env::var_os("UPKIT_TEST_IN_NAMESPACE").is_none()
            && !Command::new("unshare")
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
                .is_ok_and(|s| s.success())
        {
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let project = dir.path().join("project");
        let target = project.join("target");
        fs::create_dir_all(target.join("debug")).unwrap();
        for path in [&project, &target, &target.join("debug")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let manifest = project.join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname='fixture'\nversion='0.1.0'\n[workspace]\n",
        )
        .unwrap();
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
        let file = target.join("debug/output");
        fs::write(&file, "artifact").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let home = dir.path().join("home");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        let git_dir = tempfile::tempdir().unwrap();
        fs::set_permissions(git_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let bin = git_dir.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
        fs::copy(&git, bin.join("git")).unwrap();
        let result = Self {
            _dir: dir,
            _git_dir: git_dir,
            project,
            target,
            home,
            git,
        };
        result.git(&["init", "-q"]);
        result.git(&["add", "Cargo.toml"]);
        result.git(&["commit", "-qm", "fixture"]);
        Some(result)
    }
    fn git(&self, args: &[&str]) {
        let result = Command::new(&self.git)
            .env("HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .arg("-C")
            .arg(&self.project)
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
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    fn run<T: AsRef<std::ffi::OsStr>>(&self, args: &[T]) -> Output {
        self.run_with_json(args, true)
    }
    fn run_text<T: AsRef<std::ffi::OsStr>>(&self, args: &[T]) -> Output {
        self.run_with_json(args, false)
    }
    fn run_with_json<T: AsRef<std::ffi::OsStr>>(&self, args: &[T], json: bool) -> Output {
        let home = self.home.join("upkit");
        self.run_with_home_and_json(&home, args, json)
    }
    fn run_with_home<T: AsRef<std::ffi::OsStr>>(&self, home: &Path, args: &[T]) -> Output {
        self.run_with_home_and_json(home, args, true)
    }
    fn run_with_home_and_json<T: AsRef<std::ffi::OsStr>>(
        &self,
        home: &Path,
        args: &[T],
        json: bool,
    ) -> Output {
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
            .args(["--non-interactive"]);
        if json {
            command.arg("--json");
        }
        command
            .arg("--home")
            .arg(home)
            .args(args)
            .env("HOME", &self.home)
            .env_remove("CARGO_HOME")
            .env_remove("CARGO_TARGET_DIR")
            .env_remove("CARGO_BUILD_TARGET_DIR")
            .env_remove("CARGO_BUILD_BUILD_DIR")
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
            .args(["--non-interactive", "--json", "--home"])
            .arg(self.home.join("upkit"))
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
                self.project.join(".git/info/grafts"),
            )
            .output()
            .unwrap()
    }
    fn preview(&self) -> serde_json::Value {
        let result = self.run(&[
            "sweep",
            "run",
            "--scope",
            "artifacts",
            "--select",
            self.target.to_str().unwrap(),
            "--root",
            self.project.to_str().unwrap(),
            "--preview",
        ]);
        assert!(
            result.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice(&result.stdout).unwrap()
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
            "artifact_fixture_namespace_worker",
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
fn artifact_fixture_namespace_worker() {
    let Some(mut fixture) = Fixture::new() else {
        panic!("Git fixture could not be created in the isolated namespace");
    };
    match std::env::var("UPKIT_TEST_NAMESPACE_SCENARIO").as_deref() {
        Ok("artifact_batch_cli_previews_dry_runs_authorizes_and_records_each_item") => {
            artifact_batch_cli_previews_dry_runs_authorizes_and_records_each_item_in_namespace(
                &fixture,
            );
        }
        Ok("non_unicode_project_artifact_preview_token_and_removal") => {
            non_unicode_project_artifact_preview_token_and_removal_in_namespace(&mut fixture);
        }
        Ok("reviewed_artifact_cleanup_requires_authorization_and_revalidates_tree") => {
            reviewed_artifact_cleanup_requires_authorization_and_revalidates_tree_in_namespace(
                &fixture,
            );
        }
        Ok("standalone_cargo_cleanup_revalidates_parent_workspaces") => {
            standalone_cargo_cleanup_revalidates_parent_workspaces_in_namespace(&fixture);
        }
        Ok("artifact_removal_rejects_changed_scope_age_and_manifest") => {
            artifact_removal_rejects_changed_scope_age_and_manifest_in_namespace(&fixture);
        }
        Ok("artifact_removal_refuses_history_inside_selected_target_without_mutation") => {
            artifact_removal_refuses_history_inside_selected_target_without_mutation_in_namespace(
                &fixture,
            );
        }
        Ok("go_project_outputs_are_inspection_only_and_cannot_be_removed") => {
            go_project_outputs_are_inspection_only_and_cannot_be_removed_in_namespace(&fixture);
        }
        scenario => panic!("unknown artifact namespace scenario: {scenario:?}"),
    }
    fs::write(
        std::env::var_os("UPKIT_TEST_NAMESPACE_DONE").unwrap(),
        "executed",
    )
    .unwrap();
}

#[test]
fn dry_run_git_backed_previews_skip_a_trusted_sentinel_git() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let (_bin, sentinel) = git_support::sentinel_elf_git(f._git_dir.path());
    let root = f.project.to_str().unwrap();
    let target = f.target.to_str().unwrap();

    let normal =
        f.run_with_sentinel_git(&["sweep", "preview", root, "--select", target], &sentinel);
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

    let dry_sweep = f.run_with_sentinel_git(
        &["--dry-run", "sweep", "preview", root, "--select", target],
        &sentinel,
    );
    assert!(dry_sweep.status.success());
    let dry_sweep: serde_json::Value = serde_json::from_slice(&dry_sweep.stdout).unwrap();
    assert_eq!(dry_sweep["status"], "skipped_unverified");
    assert_eq!(dry_sweep["validated_selections"], 1);
    assert!(dry_sweep.get("plan").is_none());
    assert!(dry_sweep.get("preview_token").is_none());
    assert!(
        !sentinel.exists(),
        "dry-run invoked the trusted fixture Git"
    );

    let dry_artifact = f.run_with_sentinel_git(
        &[
            "--dry-run",
            "sweep",
            "run",
            "--scope",
            "artifacts",
            "--select",
            target,
            "--root",
            root,
        ],
        &sentinel,
    );
    assert!(dry_artifact.status.success());
    let dry_artifact: serde_json::Value = serde_json::from_slice(&dry_artifact.stdout).unwrap();
    assert_eq!(dry_artifact["status"], "skipped_unverified");
    assert!(dry_artifact.get("plan").is_none());
    assert!(dry_artifact.get("preview_token").is_none());
    assert!(
        !sentinel.exists(),
        "artifact dry-run invoked the trusted fixture Git"
    );
    assert!(f.target.exists());

    let python_manifest = f.project.join("pyproject.toml");
    fs::write(&python_manifest, "[project]\nname = 'fixture'\n").unwrap();
    fs::set_permissions(&python_manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let pytest_cache = f.project.join(".pytest_cache");
    fs::create_dir(&pytest_cache).unwrap();
    fs::set_permissions(&pytest_cache, fs::Permissions::from_mode(0o700)).unwrap();
    let data = pytest_cache.join("state");
    fs::write(&data, "fixture").unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o600)).unwrap();
    let dry_artifact_batch = f.run_with_sentinel_git(
        &[
            "--dry-run",
            "sweep",
            "run",
            "--scope",
            "artifacts",
            "--select",
            target,
            "--select",
            pytest_cache.to_str().unwrap(),
            "--root",
            root,
            "--preview",
        ],
        &sentinel,
    );
    assert!(dry_artifact_batch.status.success());
    let dry_artifact_batch: serde_json::Value =
        serde_json::from_slice(&dry_artifact_batch.stdout).unwrap();
    assert_eq!(dry_artifact_batch["status"], "skipped_unverified");
    assert_eq!(dry_artifact_batch["validated_selections"], 2);
    assert!(dry_artifact_batch.get("plan").is_none());
    assert!(dry_artifact_batch.get("preview_token").is_none());
    assert!(
        !sentinel.exists(),
        "artifact batch dry-run invoked fixture Git"
    );
    assert!(f.target.exists() && pytest_cache.exists());
}

#[test]
fn non_unicode_project_artifact_preview_token_and_removal() {
    run_fixture_namespace_worker("non_unicode_project_artifact_preview_token_and_removal");
}

fn non_unicode_project_artifact_preview_token_and_removal_in_namespace(f: &mut Fixture) {
    use std::ffi::OsStr;
    let renamed = f
        ._dir
        .path()
        .join(std::ffi::OsString::from_vec(b"project-\xff%".to_vec()));
    fs::rename(&f.project, &renamed).unwrap();
    f.project = renamed;
    f.target = f.project.join("target");
    let literal = f._dir.path().join("project-%FF%");
    fs::create_dir(&literal).unwrap();
    fs::write(literal.join("keep"), "untouched").unwrap();
    let args = [
        OsStr::new("sweep"),
        OsStr::new("run"),
        OsStr::new("--scope"),
        OsStr::new("artifacts"),
        OsStr::new("--select"),
        f.target.as_os_str(),
        OsStr::new("--root"),
        f.project.as_os_str(),
        OsStr::new("--preview"),
    ];
    let output = f.run(&args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["plan"]["target"]["encoding"], "unix-percent-bytes");
    assert!(
        value["plan"]["target"]["value"]
            .as_str()
            .unwrap()
            .ends_with("/project-%FF%25/target")
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
            OsStr::new("run"),
            OsStr::new("--scope"),
            OsStr::new("artifacts"),
            OsStr::new("--select"),
            f.target.as_os_str(),
            OsStr::new("--root"),
            f.project.as_os_str(),
            OsStr::new("--authorize-artifact-removal"),
            OsStr::new("--preview-token"),
            OsStr::new(token),
        ])
    };
    assert!(!run("wrong").status.success());
    assert!(f.target.exists());
    let result = run(token);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["verification"], "verified_absent");
    assert!(!f.target.exists());
    assert_eq!(
        fs::read_to_string(literal.join("keep")).unwrap(),
        "untouched"
    );
}

#[test]
fn selected_artifact_batch_removes_only_reviewed_targets() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let python_manifest = f.project.join("pyproject.toml");
    fs::write(&python_manifest, "[project]\nname = 'fixture'\n").unwrap();
    fs::set_permissions(&python_manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let pytest_cache = f.project.join(".pytest_cache");
    let mypy_cache = f.project.join(".mypy_cache");
    fs::create_dir_all(&pytest_cache).unwrap();
    fs::create_dir_all(&mypy_cache).unwrap();
    for path in [&pytest_cache, &mypy_cache] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(pytest_cache.join("state"), "selected cache").unwrap();
    fs::write(mypy_cache.join("state"), "leave untouched").unwrap();
    for path in [pytest_cache.join("state"), mypy_cache.join("state")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let result = Command::new("unshare")
        .current_dir(f._git_dir.path())
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
            "artifact_batch_worker",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("UPKIT_BATCH_PROJECT", &f.project)
        .env("UPKIT_BATCH_TARGET", &f.target)
        .env("UPKIT_BATCH_PYTEST_CACHE", &pytest_cache)
        .env("UPKIT_BATCH_MYPY_CACHE", &mypy_cache)
        .env("HOME", &f.home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env(
            "PATH",
            std::env::join_paths([Path::new("bin"), Path::new("/usr/bin"), Path::new("/bin")])
                .unwrap(),
        )
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!f.target.exists());
    assert!(!pytest_cache.exists());
    assert!(mypy_cache.join("state").is_file());
    assert!(f.project.join("Cargo.toml").is_file());
    assert!(python_manifest.is_file());
}

#[test]
fn zig_artifact_preview_uses_build_manifest_and_marks_zig_out_for_review() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let manifest = f.project.join("build.zig");
    fs::write(&manifest, "// fixture; never executed by scan or preview\n").unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let cache = f.project.join(".zig-cache");
    let output = f.project.join("zig-out");
    fs::create_dir(&cache).unwrap();
    fs::create_dir(&output).unwrap();
    for path in [&cache, &output] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        let file = path.join("user-file");
        fs::write(&file, "keep unless explicitly confirmed").unwrap();
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let cache_arg = cache.to_str().unwrap();
    let output_arg = output.to_str().unwrap();
    let root_arg = f.project.to_str().unwrap();
    let preview = f.run(&[
        "sweep",
        "run",
        "--scope",
        "artifacts",
        "--select",
        cache_arg,
        "--select",
        output_arg,
        "--root",
        root_arg,
        "--preview",
    ]);
    assert!(
        preview.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&preview.stdout),
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let items = preview["plan"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let cache_plan = items
        .iter()
        .find(|item| item["target"] == cache_arg)
        .unwrap();
    assert_eq!(cache_plan["ecosystem"], "zig");
    assert_eq!(cache_plan["manifest"], manifest.to_str().unwrap());
    assert_eq!(cache_plan["classification"], "rebuildable");
    let output_plan = items
        .iter()
        .find(|item| item["target"] == output_arg)
        .unwrap();
    assert_eq!(output_plan["ecosystem"], "zig");
    assert_eq!(output_plan["manifest"], manifest.to_str().unwrap());
    assert_eq!(output_plan["classification"], "review");
    assert!(
        output_plan["warning"]
            .as_str()
            .unwrap()
            .contains("including any user data")
    );
    assert!(
        output_plan["reproduction_warning"]
            .as_str()
            .is_some_and(|warning| warning.contains("can contain user data"))
    );
    assert!(cache.join("user-file").is_file());
    assert!(output.join("user-file").is_file());

    let outside = f.project.parent().unwrap().join("outside");
    fs::write(&outside, "preserve").unwrap();
    symlink(&outside, cache.join("external-link")).unwrap();
    let rejected = f.run(&[
        "sweep",
        "run",
        "--scope",
        "artifacts",
        "--select",
        cache_arg,
        "--root",
        root_arg,
        "--preview",
    ]);
    assert!(!rejected.status.success());
    assert_eq!(fs::read_to_string(outside).unwrap(), "preserve");
}

#[test]
fn go_project_outputs_are_inspection_only_and_cannot_be_removed() {
    run_fixture_namespace_worker("go_project_outputs_are_inspection_only_and_cannot_be_removed");
}

fn go_project_outputs_are_inspection_only_and_cannot_be_removed_in_namespace(f: &Fixture) {
    let manifest = f.project.join("go.mod");
    fs::write(&manifest, "module example.invalid/service\ngo 1.22\n").unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let build = f.project.join("build");
    let bin = f.project.join("bin");
    for target in [&build, &bin] {
        fs::create_dir(target).unwrap();
        fs::set_permissions(target, fs::Permissions::from_mode(0o700)).unwrap();
        let file = target.join("user-data");
        fs::write(&file, "keep Go project data").unwrap();
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let root = f.project.to_str().unwrap();
    let build_arg = build.to_str().unwrap();
    let bin_arg = bin.to_str().unwrap();
    let generic_preview = f.run(&[
        "sweep", "preview", root, "--select", build_arg, "--select", bin_arg,
    ]);
    assert!(
        generic_preview.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&generic_preview.stdout),
        String::from_utf8_lossy(&generic_preview.stderr)
    );
    let generic_preview: serde_json::Value =
        serde_json::from_slice(&generic_preview.stdout).unwrap();
    let items = generic_preview["items"].as_array().unwrap();
    let selected_items = items
        .iter()
        .filter(|item| item["selected"] == true)
        .collect::<Vec<_>>();
    assert_eq!(selected_items.len(), 2);
    assert!(selected_items.iter().all(|item| {
        item["candidate"]["ecosystem"] == "go"
            && item["candidate"]["classification"] == "review"
            && item["risk"] == "potentially destructive"
            && item["execution_ready"] == false
    }));
    assert!(generic_preview.get("preview_token").is_none());

    let scope = upkit::sweep::Scope {
        roots: vec![f.project.clone()],
        exclusions: Vec::new(),
        older_than_seconds: None,
        enabled: None,
    };
    let cancel = std::sync::atomic::AtomicBool::new(false);
    for target in [&build, &bin] {
        let error = upkit::artifact_cleanup::preview(&scope, target, &cancel).unwrap_err();
        assert!(format!("{error:#}").contains("inspection-only"));
    }
    let targets = vec![build.clone(), bin.clone()];
    let error = upkit::artifact_cleanup::preview_batch(&scope, &targets, &cancel).unwrap_err();
    assert!(format!("{error:#}").contains("inspection-only"));
    assert!(upkit::artifact_cleanup::remove(&scope, &build, "forged", &cancel).is_err());
    assert!(upkit::artifact_cleanup::remove_batch(&scope, &targets, "forged", &cancel).is_err());

    for (selection, preview) in [
        (vec![build_arg], true),
        (vec![build_arg, bin_arg], true),
        (vec![build_arg], false),
        (vec![build_arg, bin_arg], false),
    ] {
        let mut args = if preview {
            vec!["sweep", "run", "--scope", "artifacts"]
        } else {
            vec!["--yes", "sweep", "run", "--scope", "artifacts"]
        };
        for target in &selection {
            args.extend(["--select", target]);
        }
        args.extend(["--root", root]);
        if preview {
            args.push("--preview");
        } else {
            args.extend(["--authorize-artifact-removal", "--preview-token", "forged"]);
        }
        let output = f.run(&args);
        assert!(!output.status.success());
        let detail = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(detail.contains("inspection-only"), "{detail}");
    }

    assert_eq!(
        fs::read_to_string(build.join("user-data")).unwrap(),
        "keep Go project data"
    );
    assert_eq!(
        fs::read_to_string(bin.join("user-data")).unwrap(),
        "keep Go project data"
    );
    assert!(!f.home.join("upkit/history").exists());
}

#[test]
#[ignore = "runs only inside the selected-batch fixture namespace"]
fn artifact_batch_worker() {
    let project = PathBuf::from(std::env::var_os("UPKIT_BATCH_PROJECT").unwrap());
    let target = PathBuf::from(std::env::var_os("UPKIT_BATCH_TARGET").unwrap());
    let pytest_cache = PathBuf::from(std::env::var_os("UPKIT_BATCH_PYTEST_CACHE").unwrap());
    let mypy_cache = PathBuf::from(std::env::var_os("UPKIT_BATCH_MYPY_CACHE").unwrap());
    let scope = upkit::sweep::Scope {
        roots: vec![project.clone()],
        exclusions: Vec::new(),
        older_than_seconds: None,
        enabled: None,
    };
    let targets = vec![target.clone(), pytest_cache.clone()];
    let cancel = std::sync::atomic::AtomicBool::new(false);

    let oversized = vec![target.clone(); upkit::artifact_cleanup::MAX_BATCH_ARTIFACTS + 1];
    assert!(upkit::artifact_cleanup::preview_batch(&scope, &oversized, &cancel).is_err());
    assert!(
        upkit::artifact_cleanup::preview_batch(&scope, &[target.clone(), target.clone()], &cancel)
            .is_err()
    );
    assert!(
        upkit::artifact_cleanup::preview_batch(&scope, &[project.clone(), target.clone()], &cancel)
            .is_err()
    );

    let plan = upkit::artifact_cleanup::preview_batch(&scope, &targets, &cancel).unwrap();
    assert_eq!(plan.items.len(), 2);
    assert!(plan.items.iter().any(|item| item.target == target));
    assert!(plan.items.iter().any(|item| item.target == pytest_cache));
    assert!(upkit::artifact_cleanup::remove_batch(&scope, &targets, "wrong", &cancel).is_err());
    assert!(target.exists());
    assert!(pytest_cache.exists());

    let result =
        upkit::artifact_cleanup::remove_batch(&scope, &targets, &plan.preview_token, &cancel)
            .unwrap();
    assert_eq!(result.outcomes.len(), 2);
    assert!(
        result
            .outcomes
            .iter()
            .all(|item| item.status == "verified_absent")
    );
    assert!(!result.cancelled);
    assert!(!target.exists());
    assert!(!pytest_cache.exists());
    assert!(mypy_cache.join("state").is_file());
    assert!(project.join("Cargo.toml").is_file());
    assert!(project.join("pyproject.toml").is_file());
    serde_json::to_value(result).unwrap();
}

#[test]
fn artifact_batch_cli_previews_dry_runs_authorizes_and_records_each_item() {
    run_fixture_namespace_worker(
        "artifact_batch_cli_previews_dry_runs_authorizes_and_records_each_item",
    );
}

fn artifact_batch_cli_previews_dry_runs_authorizes_and_records_each_item_in_namespace(f: &Fixture) {
    let python_manifest = f.project.join("pyproject.toml");
    fs::write(&python_manifest, "[project]\nname = 'fixture'\n").unwrap();
    fs::set_permissions(&python_manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let pytest_cache = f.project.join(".pytest_cache");
    let mypy_cache = f.project.join(".mypy_cache");
    fs::create_dir_all(&pytest_cache).unwrap();
    fs::create_dir_all(&mypy_cache).unwrap();
    for path in [&pytest_cache, &mypy_cache] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(pytest_cache.join("state"), "selected cache").unwrap();
    fs::write(mypy_cache.join("state"), "leave untouched").unwrap();
    for path in [pytest_cache.join("state"), mypy_cache.join("state")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let target = f.target.to_str().unwrap();
    let pytest = pytest_cache.to_str().unwrap();
    let root = f.project.to_str().unwrap();
    let base = vec![
        "sweep",
        "run",
        "--scope",
        "artifacts",
        "--select",
        target,
        "--select",
        pytest,
        "--root",
        root,
    ];

    let mut args = base.clone();
    args.push("--preview");
    let preview = f.run(&args);
    assert!(
        preview.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&preview.stdout),
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(preview["plan"]["items"].as_array().unwrap().len(), 2);
    assert!(preview["result"].is_null());
    let token = preview["plan"]["preview_token"].as_str().unwrap();

    let mut args = vec!["--dry-run"];
    args.extend(base.iter().copied());
    args.extend(["--preview-token", token, "--authorize-artifact-removal"]);
    let dry_run = f.run(&args);
    assert!(dry_run.status.success());
    let dry_run: serde_json::Value = serde_json::from_slice(&dry_run.stdout).unwrap();
    assert_eq!(dry_run["dry_run"], true);
    assert_eq!(dry_run["status"], "skipped_unverified");
    assert_eq!(dry_run["validated_selections"], 2);
    assert!(dry_run.get("plan").is_none());
    assert!(dry_run.get("preview_token").is_none());
    assert!(f.target.exists() && pytest_cache.exists());
    assert!(!f.home.join("upkit/history").exists());

    let mut args = vec!["--yes"];
    args.extend(base.iter().copied());
    args.extend(["--preview-token", "wrong", "--authorize-artifact-removal"]);
    let rejected = f.run(&args);
    assert!(!rejected.status.success());
    let rejected: serde_json::Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(rejected["result"]["complete"], false);
    assert!(
        rejected["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["status"] == "not_attempted" && item["attempted"] == false)
    );
    assert!(f.target.exists() && pytest_cache.exists());

    let mut args = vec!["--yes"];
    args.extend(base.iter().copied());
    args.extend(["--preview-token", token, "--authorize-artifact-removal"]);
    let removed = f.run(&args);
    assert!(
        removed.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&removed.stdout),
        String::from_utf8_lossy(&removed.stderr)
    );
    let removed: serde_json::Value = serde_json::from_slice(&removed.stdout).unwrap();
    assert_eq!(removed["result"]["complete"], true);
    assert_eq!(removed["result"]["items"].as_array().unwrap().len(), 2);
    assert!(
        removed["result"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["status"] == "verified_absent" && item["attempted"] == true)
    );
    assert!(!f.target.exists() && !pytest_cache.exists());
    assert!(mypy_cache.join("state").is_file());
    assert!(f.project.join("Cargo.toml").is_file() && python_manifest.is_file());

    let history = f.run(&["report"]);
    assert!(history.status.success());
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    let artifact_records = history["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["operation"] == "artifact_removal")
        .collect::<Vec<_>>();
    assert_eq!(artifact_records.len(), 4);
    assert_eq!(
        artifact_records
            .iter()
            .filter(|record| record["outcome"] == "completed")
            .count(),
        2
    );
    assert_eq!(
        artifact_records
            .iter()
            .filter(|record| record["outcome"] == "not_attempted")
            .count(),
        2
    );
    assert_eq!(
        artifact_records
            .iter()
            .filter(|record| record["outcome"] == "failed_or_unknown")
            .count(),
        0
    );
}

#[test]
fn reviewed_artifact_cleanup_requires_authorization_and_revalidates_tree() {
    run_fixture_namespace_worker(
        "reviewed_artifact_cleanup_requires_authorization_and_revalidates_tree",
    );
}

fn reviewed_artifact_cleanup_requires_authorization_and_revalidates_tree_in_namespace(f: &Fixture) {
    let strange = f
        .target
        .join("debug")
        .join(std::ffi::OsString::from_vec(b"source-\xff.rs".to_vec()));
    fs::write(&strange, "source fixture").unwrap();
    fs::set_permissions(&strange, fs::Permissions::from_mode(0o600)).unwrap();
    let plan = f.preview();
    assert_eq!(plan["plan"]["ecosystem"], "cargo");
    assert!(
        plan["plan"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"] == "debug/source-%FF.rs")
    );
    let token = plan["plan"]["preview_token"].as_str().unwrap().to_owned();
    let target = f.target.to_str().unwrap();
    let root = f.project.to_str().unwrap();
    let run = |token: &str, authorized: bool| {
        let mut args = vec![
            "--yes",
            "sweep",
            "run",
            "--scope",
            "artifacts",
            "--select",
            target,
            "--root",
            root,
            "--preview-token",
            token,
        ];
        if authorized {
            args.push("--authorize-artifact-removal");
        }
        f.run(&args)
    };
    assert!(!run(&token, false).status.success());
    assert!(!run("wrong", true).status.success());
    let dry = f.run(&[
        "--dry-run",
        "sweep",
        "run",
        "--scope",
        "artifacts",
        "--select",
        target,
        "--root",
        root,
    ]);
    assert!(dry.status.success());
    let dry: serde_json::Value = serde_json::from_slice(&dry.stdout).unwrap();
    assert_eq!(dry["status"], "skipped_unverified");
    assert!(dry.get("plan").is_none());
    assert!(dry.get("preview_token").is_none());
    fs::write(f.target.join("debug/output"), "changed").unwrap();
    assert!(!run(&token, true).status.success());
    assert!(f.target.join("debug/output").exists());
    let plan = f.preview();
    let token = plan["plan"]["preview_token"].as_str().unwrap();
    let result = run(token, true);
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["verification"], "verified_absent");
    assert!(!f.target.exists());
    assert!(f.project.join("Cargo.toml").exists());
    let history = f.run(&["report"]);
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["operation"] == "artifact_removal"
                && record["outcome"] == "completed")
    );
}

#[test]
fn standalone_cargo_cleanup_revalidates_parent_workspaces() {
    run_fixture_namespace_worker("standalone_cargo_cleanup_revalidates_parent_workspaces");
}

fn standalone_cargo_cleanup_revalidates_parent_workspaces_in_namespace(f: &Fixture) {
    let manifest = f.project.join("Cargo.toml");
    fs::write(
        &manifest,
        "[package]\nname = 'fixture'\nversion = '0.1.0'\n",
    )
    .unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    f.git(&["add", "Cargo.toml"]);
    f.git(&["commit", "-qm", "make fixture standalone"]);
    let root = f.project.to_str().unwrap();
    let target = f.target.to_str().unwrap();

    let scan = f.run(&["sweep", "scan", root]);
    assert!(scan.status.success());
    let scan: serde_json::Value = serde_json::from_slice(&scan.stdout).unwrap();
    let cargo = scan["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["target"] == target)
        .unwrap();
    assert_eq!(cargo["classification"], "rebuildable");
    assert_eq!(cargo["cargo_workspace"]["status"], "standalone_package");

    let preview = f.preview();
    let token = preview["plan"]["preview_token"].as_str().unwrap();
    let parent_manifest = f.project.parent().unwrap().join("Cargo.toml");
    fs::write(&parent_manifest, "[workspace]\nmembers = ['project']\n").unwrap();
    let changed = f.run(&[
        "--yes",
        "sweep",
        "run",
        "--scope",
        "artifacts",
        "--select",
        target,
        "--root",
        root,
        "--authorize-artifact-removal",
        "--preview-token",
        token,
    ]);
    assert!(!changed.status.success());
    assert!(f.target.join("debug/output").exists());

    fs::remove_file(parent_manifest).unwrap();
    let preview = f.preview();
    let token = preview["plan"]["preview_token"].as_str().unwrap();
    let removed = f.run(&[
        "--yes",
        "sweep",
        "run",
        "--scope",
        "artifacts",
        "--select",
        target,
        "--root",
        root,
        "--authorize-artifact-removal",
        "--preview-token",
        token,
    ]);
    assert!(
        removed.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&removed.stdout),
        String::from_utf8_lossy(&removed.stderr)
    );
    assert!(!f.target.exists());
}

#[test]
fn parcel_cache_removal_plan_discloses_unverified_contents() {
    let Some(mut f) = Fixture::new() else {
        return;
    };
    let manifest = f.project.join("package.json");
    fs::write(&manifest, "{}\n").unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let target = f.project.join(".parcel-cache");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let data = target.join("data");
    fs::write(&data, b"fixture").unwrap();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o600)).unwrap();
    f.target = target;

    let plan = f.preview();
    assert_eq!(plan["plan"]["ecosystem"], "javascript");
    assert_eq!(plan["plan"]["classification"], "review");
    let warning = plan["plan"]["reproduction_warning"].as_str().unwrap();
    assert!(warning.contains("do not prove") && warning.contains("inspect"));
    assert!(data.is_file());
}

#[test]
fn javascript_coverage_report_enters_the_reviewed_artifact_plan() {
    let Some(mut f) = Fixture::new() else {
        return;
    };
    let manifest = f.project.join("package.json");
    fs::write(&manifest, "{}\n").unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let target = f.project.join("coverage");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let report = target.join("lcov.info");
    fs::write(&report, "TN:\nSF:src/app.ts\n").unwrap();
    fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).unwrap();
    f.target = target;

    let plan = f.preview();
    assert_eq!(plan["plan"]["ecosystem"], "javascript");
    assert_eq!(plan["plan"]["classification"], "review");
    assert!(
        plan["plan"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"] == "lcov.info")
    );
    assert!(
        plan["plan"]["reproduction_warning"]
            .as_str()
            .unwrap()
            .contains("coverage report filename")
    );
    assert!(report.is_file());
}

#[test]
fn gradle_local_state_removal_plan_warns_state_may_not_be_rebuildable() {
    let Some(mut f) = Fixture::new() else {
        return;
    };
    let manifest = f.project.join("build.gradle.kts");
    fs::write(&manifest, "plugins {}\n").unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let target = f.project.join(".gradle");
    let version = target.join("8.10");
    let checksums = version.join("checksums");
    fs::create_dir_all(&checksums).unwrap();
    for path in [&target, &version, &checksums] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let state = checksums.join("state.bin");
    fs::write(&state, b"project state").unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    f.target = target;

    let plan = f.preview();
    assert_eq!(plan["plan"]["ecosystem"], "gradle");
    assert_eq!(plan["plan"]["classification"], "review");
    let warning = plan["plan"]["reproduction_warning"].as_str().unwrap();
    assert!(warning.contains("stores project state"));
    assert!(warning.contains("do not prove every entry can be regenerated"));
    assert!(warning.contains("Inspect its contents before removal"));
    assert!(state.is_file());
}

#[test]
fn hypothesis_removal_plan_warns_that_reproduction_examples_will_be_lost() {
    let Some(mut f) = Fixture::new() else {
        return;
    };
    let manifest = f.project.join("pyproject.toml");
    fs::write(&manifest, "[project]\n").unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let target = f.project.join(".hypothesis");
    fs::create_dir_all(target.join("examples")).unwrap();
    for path in [&target, &target.join("examples")] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let example = target.join("examples/failing-case");
    fs::write(&example, b"reproducible failure").unwrap();
    fs::set_permissions(&example, fs::Permissions::from_mode(0o600)).unwrap();
    f.target = target;

    let plan = f.preview();
    assert_eq!(plan["plan"]["ecosystem"], "python");
    assert_eq!(
        plan["plan"]["reproduction_warning"],
        "Deleting this Hypothesis database removes saved failure examples used to reproduce test failures."
    );
    assert!(
        plan["plan"]["warning"]
            .as_str()
            .unwrap()
            .contains("including any user data")
    );
    let output = f.run_text(&[
        "sweep",
        "run",
        "--scope",
        "artifacts",
        "--select",
        f.target.to_str().unwrap(),
        "--root",
        f.project.to_str().unwrap(),
        "--preview",
    ]);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8_lossy(&output.stdout);
    assert!(output.contains("saved failure examples"));
    assert!(output.contains("including any user data"));
    assert!(example.is_file());
}

#[test]
fn pytype_removal_plan_warns_about_generated_stubs_in_cli_preview() {
    let Some(mut f) = Fixture::new() else {
        return;
    };
    let manifest = f.project.join("pyproject.toml");
    fs::write(&manifest, "[project]\n").unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let target = f.project.join(".pytype");
    let pyi = target.join("pyi");
    fs::create_dir_all(&pyi).unwrap();
    for path in [&target, &pyi] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let stub = pyi.join("module.pyi");
    fs::write(&stub, b"def inferred() -> int: ...\n").unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o600)).unwrap();
    f.target = target;

    let plan = f.preview();
    assert_eq!(plan["plan"]["ecosystem"], "python");
    assert_eq!(plan["plan"]["classification"], "review");
    assert_eq!(
        plan["plan"]["reproduction_warning"],
        "The default pytype output directory can contain generated .pyi stubs; inspect them before removal."
    );
    let output = f.run_text(&[
        "sweep",
        "run",
        "--scope",
        "artifacts",
        "--select",
        f.target.to_str().unwrap(),
        "--root",
        f.project.to_str().unwrap(),
        "--preview",
    ]);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("generated .pyi stubs"));
    assert!(stub.is_file());
}

#[test]
fn nested_bind_mount_makes_artifact_inventory_incomplete_and_refuses_removal() {
    let Some(f) = Fixture::new() else {
        return;
    };
    if !Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--fork",
            "/bin/true",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        eprintln!("SKIP: an isolated user/mount namespace is unavailable");
        return;
    }
    let outside = f._dir.path().join("outside");
    let mounted = f.target.join("debug/mounted");
    fs::create_dir(&outside).unwrap();
    fs::create_dir(&mounted).unwrap();
    fs::write(outside.join("keep"), "fixture").unwrap();

    let output = Command::new("unshare")
        .current_dir(f._git_dir.path())
        .args([
            "--user", "--map-root-user", "--mount", "--pid", "--fork", "--mount-proc",
            "/bin/sh", "-c",
            "mount --bind \"$1\" \"$2\" || exit 77; \"$3\" --non-interactive --json --config /dev/null --home \"$4\" sweep scan \"$5\" || exit 78; \"$3\" --non-interactive --json --config /dev/null --home \"$4\" sweep run --scope artifacts --select \"$6\" --root \"$5\" --preview; code=$?; [ \"$code\" -ne 0 ] || exit 79",
            "fixture",
        ])
        .arg(&outside)
        .arg(&mounted)
        .arg(env!("CARGO_BIN_EXE_upkit"))
        .arg(f.home.join("upkit"))
        .arg(&f.project)
        .arg(&f.target)
        .env_clear()
            .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
        .env("HOME", &f.home)
        .env("XDG_CONFIG_HOME", f.home.join("config"))
        .env("XDG_DATA_HOME", f.home.join("data"))
        .env("PATH", std::env::join_paths([Path::new("bin"), Path::new("/usr/bin"), Path::new("/bin")]).unwrap())
        .output()
        .unwrap();
    if output.status.code() == Some(77) {
        eprintln!("SKIP: bind mounts are unavailable in an isolated user/mount namespace");
        return;
    }
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8(output.stdout).unwrap();
    let mut reports = serde_json::Deserializer::from_str(&lines).into_iter::<serde_json::Value>();
    let scan = reports.next().unwrap().unwrap();
    assert!(scan["warnings"].as_array().unwrap().iter().any(|warning| {
        warning
            .as_str()
            .is_some_and(|text| text.contains("skipped mount point"))
    }));
    assert!(
        scan["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| candidate["size_complete"] == false)
    );
    let preview = reports.next().unwrap().unwrap();
    assert_eq!(preview["ok"], false);
    assert!(reports.next().is_none());
    assert_eq!(fs::read_to_string(outside.join("keep")).unwrap(), "fixture");
    assert_eq!(
        fs::read_to_string(f.target.join("debug/output")).unwrap(),
        "artifact"
    );
}

#[test]
fn artifact_preview_rejects_tracked_files_exclusions_and_active_processes() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let target = f.target.to_str().unwrap();
    let root = f.project.to_str().unwrap();
    let excluded = f.run(&[
        "sweep",
        "run",
        "--scope",
        "artifacts",
        "--select",
        target,
        "--root",
        root,
        "--exclude",
        "target",
        "--preview",
    ]);
    assert!(!excluded.status.success());
    let active = Command::new("unshare").current_dir(f._git_dir.path()).args(["--user", "--map-root-user", "--pid", "--fork", "--mount-proc", "/bin/sh", "-c", "cd \"$1\" || exit 1; /bin/sleep 30 & child=$!; cd \"$5\" || exit 1; \"$3\" --non-interactive --json --home \"$4\" sweep run --scope artifacts --select \"$1\" --root \"$2\" --preview; code=$?; kill \"$child\"; wait \"$child\" 2>/dev/null; exit \"$code\"", "fixture"])
        .arg(&f.target).arg(&f.project).arg(env!("CARGO_BIN_EXE_upkit")).arg(f.home.join("upkit"))
        .arg(f._git_dir.path())
        .env("HOME", &f.home).env("XDG_CONFIG_HOME", f.home.join("config"))
        .env("PATH", std::env::join_paths([Path::new("bin"), Path::new("/usr/bin"), Path::new("/bin")]).unwrap()).output().unwrap();
    assert!(!active.status.success());
    assert!(String::from_utf8_lossy(&active.stdout).contains("process activity"));
    f.git(&["add", "-f", "target/debug/output"]);
    assert!(
        !f.run(&[
            "sweep",
            "run",
            "--scope",
            "artifacts",
            "--select",
            target,
            "--root",
            root,
            "--preview"
        ])
        .status
        .success()
    );
    assert_eq!(
        fs::read_to_string(f.target.join("debug/output")).unwrap(),
        "artifact"
    );
}

#[test]
fn artifact_removal_rejects_changed_scope_age_and_manifest() {
    run_fixture_namespace_worker("artifact_removal_rejects_changed_scope_age_and_manifest");
}

fn artifact_removal_rejects_changed_scope_age_and_manifest_in_namespace(f: &Fixture) {
    let token = f.preview()["plan"]["preview_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let target = f.target.to_str().unwrap();
    let root = f.project.to_str().unwrap();
    let parent = f._dir.path().to_str().unwrap();
    let removal = |root: &str, extra: &[&str]| {
        let mut args = vec![
            "--yes",
            "sweep",
            "run",
            "--scope",
            "artifacts",
            "--select",
            target,
            "--root",
            root,
            "--authorize-artifact-removal",
            "--preview-token",
            &token,
        ];
        args.extend_from_slice(extra);
        f.run(&args)
    };
    let changed_scope = removal(parent, &[]);
    assert!(!changed_scope.status.success());
    assert!(String::from_utf8_lossy(&changed_scope.stdout).contains("artifact preview changed"));
    let too_young = removal(root, &["--older-than", "1d"]);
    assert!(!too_young.status.success());
    assert!(String::from_utf8_lossy(&too_young.stdout).contains("selected target was not found"));
    fs::write(
        f.project.join("Cargo.toml"),
        "[package]\nname='changed'\nversion='0.1.0'\n[workspace]\n",
    )
    .unwrap();
    let changed_manifest = removal(root, &[]);
    assert!(!changed_manifest.status.success());
    assert!(String::from_utf8_lossy(&changed_manifest.stdout).contains("artifact preview changed"));
    assert_eq!(
        fs::read_to_string(f.target.join("debug/output")).unwrap(),
        "artifact"
    );
}

#[test]
fn artifact_removal_refuses_history_inside_selected_target_without_mutation() {
    run_fixture_namespace_worker(
        "artifact_removal_refuses_history_inside_selected_target_without_mutation",
    );
}

fn artifact_removal_refuses_history_inside_selected_target_without_mutation_in_namespace(
    f: &Fixture,
) {
    let overlap_home = f.target.join("upkit");
    let history = overlap_home.join("history");
    fs::create_dir_all(&history).unwrap();
    fs::set_permissions(&overlap_home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
    let record = history.join("existing.json");
    fs::write(&record, "keep history").unwrap();
    fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();

    let token = f.preview()["plan"]["preview_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let result = f.run_with_home(
        &overlap_home,
        &[
            "--yes",
            "sweep",
            "run",
            "--scope",
            "artifacts",
            "--select",
            f.target.to_str().unwrap(),
            "--root",
            f.project.to_str().unwrap(),
            "--authorize-artifact-removal",
            "--preview-token",
            &token,
        ],
    );

    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("operation history location"));
    assert!(f.target.join("debug/output").is_file());
    assert_eq!(fs::read_to_string(&record).unwrap(), "keep history");
    assert_eq!(fs::read_dir(&history).unwrap().count(), 1);
}
