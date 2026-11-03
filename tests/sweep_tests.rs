use std::fs;
use tempfile::tempdir;
use upkit::sweep::scan;

#[cfg(unix)]
fn system_git_path() -> Option<std::path::PathBuf> {
    use std::{io::Read, os::unix::fs::MetadataExt, path::PathBuf};

    #[cfg(target_os = "linux")]
    let mut candidates = ["/usr/bin/git", "/bin/git"].into_iter().map(PathBuf::from);
    #[cfg(not(target_os = "linux"))]
    let candidates = which::which("git").ok().into_iter();
    candidates.find_map(|candidate| {
        let path = candidate.canonicalize().ok()?;
        let metadata = fs::metadata(&path).ok()?;
        if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
            return None;
        }
        let mut header = [0; 4];
        fs::File::open(&path).ok()?.read_exact(&mut header).ok()?;
        (cfg!(not(target_os = "linux")) || header == *b"\x7fELF").then_some(path)
    })
}

#[cfg(target_os = "linux")]
#[test]
fn preview_and_cache_inventory_observe_a_fixture_process_working_directory() {
    use std::process::{Command, Stdio};
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let target = project.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]\n").unwrap();
    let mut child = Command::new("/bin/sleep")
        .arg("60")
        .current_dir(&target)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        command
            .env("HOME", dir.path())
            .env("XDG_CACHE_HOME", dir.path().join("cache"))
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("GOCACHE", &target);
        command
    };
    let preview = command()
        .args(["--json", "sweep", "preview"])
        .arg(&project)
        .output()
        .unwrap();
    let cache = command()
        .args(["--json", "cache", "status"])
        .output()
        .unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(preview.status.success());
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(
        plan["items"][0]["activity_status"],
        "open_handles_or_cwd_observed"
    );
    assert!(
        plan["items"][0]["risk"]
            .as_str()
            .unwrap()
            .contains("do not remove")
    );
    assert_eq!(plan["items"][0]["execution_ready"], false);
    assert!(cache.status.success());
    let cache: serde_json::Value = serde_json::from_slice(&cache.stdout).unwrap();
    let entry = cache["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "Go build")
        .unwrap();
    assert_eq!(entry["activity_status"], "open_handles_or_cwd_observed");
}

#[cfg(target_os = "linux")]
#[test]
fn preview_observes_an_executable_without_a_handle_or_cwd_in_the_artifact() {
    use std::{
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let target = project.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]\n").unwrap();
    let executable = target.join("fixture-sleep");
    fs::copy("/bin/sleep", &executable).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = Command::new(&executable)
        .arg("60")
        .current_dir(&project)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let process = format!("/proc/{}", child.id());
    let cwd = fs::read_link(format!("{process}/cwd")).unwrap();
    let has_handle = fs::read_dir(format!("{process}/fd"))
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_link(entry.path()).ok())
        .any(|path| path.starts_with(&target));
    let preview = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "sweep", "preview"])
        .arg(&project)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .output()
        .unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(!cwd.starts_with(&target));
    assert!(!has_handle);
    assert!(preview.status.success());
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(plan["items"][0]["activity_status"], "executable_observed");
    assert!(
        plan["items"][0]["risk"]
            .as_str()
            .unwrap()
            .contains("do not remove")
    );
}

#[test]
fn discovers_manifest_backed_artifacts_and_deduplicates_roots() {
    let dir = tempdir().unwrap();
    let rust = dir.path().join("rust");
    let python = dir.path().join("python");
    let unrelated = dir.path().join("unrelated/target");
    fs::create_dir_all(rust.join("target/debug")).unwrap();
    fs::write(rust.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(rust.join("target/debug/output"), b"12345").unwrap();
    fs::create_dir_all(python.join("pkg/__pycache__")).unwrap();
    fs::write(python.join("pyproject.toml"), "[project]\n").unwrap();
    fs::write(python.join("pkg/__pycache__/cached"), b"abc").unwrap();
    fs::create_dir_all(&unrelated).unwrap();
    let report = scan(&[dir.path().to_owned(), rust.clone()]).unwrap();
    assert_eq!(report.candidates.len(), 2);
    let cargo = report
        .candidates
        .iter()
        .find(|c| c.ecosystem == "cargo")
        .unwrap();
    assert_eq!(cargo.logical_bytes, 5);
    assert!(cargo.size_complete);
    assert_eq!(cargo.project_root, rust);
    let python = report
        .candidates
        .iter()
        .find(|c| c.ecosystem == "python")
        .unwrap();
    assert_eq!(python.logical_bytes, 3);
    assert!(report.warnings.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn custom_cargo_target_dir_is_review_only_and_excluded_from_cleanup_adapters() {
    use std::{
        fs::FileTimes,
        sync::atomic::AtomicBool,
        time::{Duration, SystemTime},
    };
    use upkit::schedule::{Frequency, preview_configured_install};

    let dir = tempdir().unwrap();
    let root = dir.path().join("workspace");
    let custom_project = root.join("custom");
    let default_project = root.join("default");
    let custom_target = custom_project.join("generated/target");
    let default_target = default_project.join("target");
    for path in [&custom_target, &default_target] {
        fs::create_dir_all(path).unwrap();
    }
    fs::create_dir(custom_project.join(".cargo")).unwrap();
    fs::write(custom_project.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(
        custom_project.join(".cargo/config.toml"),
        "[build]\ntarget-dir = 'generated/target'\n",
    )
    .unwrap();
    fs::write(custom_target.join("custom-output"), b"custom fixture").unwrap();
    fs::write(default_project.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(default_target.join("default-output"), b"default fixture").unwrap();

    let old = SystemTime::now() - Duration::from_secs(31 * 24 * 60 * 60);
    for path in [
        custom_project.join("Cargo.toml"),
        custom_target.join("custom-output"),
        custom_target.clone(),
        default_project.join("Cargo.toml"),
        default_target.join("default-output"),
        default_target.clone(),
    ] {
        fs::File::open(path)
            .unwrap()
            .set_times(FileTimes::new().set_modified(old))
            .unwrap();
    }

    let stale_report = scan(std::slice::from_ref(&root)).unwrap();
    let report = scan(std::slice::from_ref(&root)).unwrap();
    let custom = report
        .candidates
        .iter()
        .find(|candidate| candidate.target == custom_target)
        .unwrap();
    let default = report
        .candidates
        .iter()
        .find(|candidate| candidate.target == default_target)
        .unwrap();
    assert_eq!(custom.ecosystem, "cargo");
    assert_eq!(custom.classification, "review");
    assert_eq!(custom.operation, "inspection only");
    assert!(
        custom
            .reproduction_warning
            .unwrap()
            .contains("custom directory")
    );
    assert_eq!(default.classification, "rebuildable");

    let plan = upkit::sweep::preview(report, std::slice::from_ref(&custom_target)).unwrap();
    let custom_item = plan
        .items
        .iter()
        .find(|item| item.candidate.target == custom_target)
        .unwrap();
    assert_eq!(custom_item.identity_status, "metadata_match");
    assert!(!custom_item.execution_ready);

    let scope = upkit::sweep::Scope {
        roots: vec![root.clone()],
        exclusions: Vec::new(),
        older_than_seconds: None,
        enabled: None,
    };
    let error = upkit::artifact_cleanup::preview(&scope, &custom_target, &AtomicBool::new(false))
        .unwrap_err();
    assert!(
        format!("{error:#}")
            .contains("custom or unresolved Cargo target directories are inspection-only")
    );

    let settings = dir.path().join("settings.toml");
    fs::write(
        &settings,
        format!(
            "version = 1\nworkspace_roots = ['{}']\nartifact_retention = '30d'\nenabled_ecosystems = ['cargo', 'maven']\nscheduled_artifact_cleanup = true\n",
            root.display(),
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&settings, fs::Permissions::from_mode(0o600)).unwrap();
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let schedule =
        preview_configured_install(&executable, Some(&settings), None, Frequency::Daily).unwrap();
    let scheduled = upkit::scheduled_cleanup::run_artifact_cleanup(
        &dir.path().join("upkit-home"),
        &executable,
        &schedule.roots,
        &schedule.exclusions,
        &schedule.scheduled_scope_token,
        true,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(scheduled.candidates, 0);
    assert_eq!(scheduled.selected, 0);
    assert!(custom_target.exists());
    assert!(default_target.exists());

    fs::write(
        custom_project.join(".cargo/config.toml"),
        "[build]\ntarget-dir = 'generated/target'\n# changed after the scan\n",
    )
    .unwrap();
    let stale_plan = upkit::sweep::preview(stale_report, &[]).unwrap();
    let stale_item = stale_plan
        .items
        .iter()
        .find(|item| item.candidate.target == custom_target)
        .unwrap();
    assert_eq!(stale_item.identity_status, "changed_or_unavailable");
}

#[test]
fn cargo_custom_target_dir_requires_unambiguous_in_scope_config() {
    let dir = tempdir().unwrap();
    let outside = dir.path().join("shared");
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir(outside.join("target")).unwrap();
    let project = dir.path().join("outside-project");
    fs::create_dir_all(project.join(".cargo")).unwrap();
    fs::create_dir(project.join("target")).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(project.join("target/keep"), b"fixture").unwrap();
    fs::write(
        project.join(".cargo/config.toml"),
        "[build]\ntarget-dir = '../shared/target'\n",
    )
    .unwrap();
    let outside_report = scan(std::slice::from_ref(&project)).unwrap();
    assert_eq!(outside_report.candidates.len(), 1);
    assert_eq!(outside_report.candidates[0].target, project.join("target"));
    assert_eq!(outside_report.candidates[0].classification, "review");
    assert!(
        outside_report.candidates[0]
            .reproduction_warning
            .unwrap()
            .contains("could not be resolved safely")
    );
    assert!(outside_report.warnings.iter().any(|warning| {
        warning.contains(
            "Cargo target-dir configuration or a known environment override is unresolved",
        )
    }));
    let plan = upkit::sweep::preview(outside_report, &[project.join("target")]).unwrap();
    assert_eq!(plan.items[0].identity_status, "unavailable");
    assert!(!plan.items[0].execution_ready);
    #[cfg(target_os = "linux")]
    {
        let scope = upkit::sweep::Scope {
            roots: vec![project.clone()],
            exclusions: Vec::new(),
            older_than_seconds: None,
            enabled: None,
        };
        let error = upkit::artifact_cleanup::preview(
            &scope,
            &project.join("target"),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("artifact cleanup requires a complete scan of the approved roots")
        );
    }

    let no_config = dir.path().join("no-config");
    fs::create_dir_all(no_config.join(".cargo")).unwrap();
    fs::create_dir_all(no_config.join("target")).unwrap();
    fs::write(no_config.join("Cargo.toml"), "[workspace]\n").unwrap();
    let report = scan(std::slice::from_ref(&no_config)).unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].target, no_config.join("target"));
    assert_eq!(report.candidates[0].classification, "rebuildable");

    let explicit_default = dir.path().join("explicit-default");
    fs::create_dir_all(explicit_default.join(".cargo")).unwrap();
    fs::create_dir_all(explicit_default.join("target")).unwrap();
    fs::write(explicit_default.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(
        explicit_default.join(".cargo/config.toml"),
        "[build]\ntarget-dir = 'target'\n",
    )
    .unwrap();
    let report = scan(std::slice::from_ref(&explicit_default)).unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].classification, "rebuildable");
    assert!(report.candidates[0].reproduction_warning.is_none());

    let ambiguous = dir.path().join("ambiguous");
    fs::create_dir_all(ambiguous.join(".cargo")).unwrap();
    fs::create_dir(ambiguous.join("build")).unwrap();
    fs::write(ambiguous.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(ambiguous.join("pyproject.toml"), "[project]\n").unwrap();
    fs::write(
        ambiguous.join(".cargo/config.toml"),
        "[build]\ntarget-dir = 'build'\n",
    )
    .unwrap();
    let report = scan(std::slice::from_ref(&ambiguous)).unwrap();
    assert!(report.candidates.is_empty());
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("ambiguous artifact match"))
    );

    let conflicting = dir.path().join("conflicting");
    fs::create_dir_all(conflicting.join(".cargo")).unwrap();
    fs::create_dir(conflicting.join("generated")).unwrap();
    fs::create_dir(conflicting.join("target")).unwrap();
    fs::write(conflicting.join("Cargo.toml"), "[workspace]\n").unwrap();
    for name in ["config.toml", "config"] {
        fs::write(
            conflicting.join(".cargo").join(name),
            "[build]\ntarget-dir = 'generated'\n",
        )
        .unwrap();
    }
    let report = scan(std::slice::from_ref(&conflicting)).unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].target, conflicting.join("target"));
    assert_eq!(report.candidates[0].classification, "review");
    assert!(report.warnings.iter().any(|warning| {
        warning.contains(
            "Cargo target-dir configuration or a known environment override is unresolved",
        )
    }));
}

#[cfg(unix)]
#[test]
fn cargo_target_dir_scanning_does_not_follow_a_cargo_config_symlink() {
    let dir = tempdir().unwrap();
    let outside = dir.path().join("outside/.cargo");
    fs::create_dir_all(outside.join("generated/target")).unwrap();
    fs::write(
        outside.join("config.toml"),
        "[build]\ntarget-dir = 'generated/target'\n",
    )
    .unwrap();
    let project = dir.path().join("project");
    fs::create_dir(&project).unwrap();
    fs::create_dir(project.join("target")).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(project.join("target/keep"), b"fixture").unwrap();
    std::os::unix::fs::symlink(&outside, project.join(".cargo")).unwrap();

    let report = scan(std::slice::from_ref(&project)).unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].target, project.join("target"));
    assert_eq!(report.candidates[0].classification, "review");
    assert!(report.warnings.iter().any(|warning| {
        warning.contains(
            "Cargo target-dir configuration or a known environment override is unresolved",
        )
    }));
    assert!(outside.join("generated/target").is_dir());
}

#[test]
fn discovers_only_python_root_tox_and_nox_directories_for_review() {
    use std::process::Command;

    let fixture = tempdir().unwrap();
    let home = fixture.path().join("home");
    let workspace = fixture.path().join("workspace");
    let project = workspace.join("mixed-project");
    let nested = project.join("nested-python");
    let tox = project.join(".tox/env/keep");
    let nox = project.join(".nox/session/keep");
    let nested_tox = nested.join(".tox/env/keep");
    let nested_nox = nested.join(".nox/session/keep");

    fs::create_dir_all(&home).unwrap();
    for path in [&tox, &nox, &nested_tox, &nested_nox] {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"fixture environment state").unwrap();
    }
    fs::write(project.join("pyproject.toml"), "[project]\n").unwrap();
    fs::write(project.join("pubspec.yaml"), "name: mixed_fixture\n").unwrap();
    fs::write(nested.join("setup.cfg"), "[metadata]\n").unwrap();
    fs::create_dir_all(project.join("package/.tox/env")).unwrap();
    fs::create_dir_all(workspace.join("unrelated/.tox/env")).unwrap();
    fs::create_dir_all(workspace.join("unrelated/.nox/session")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--non-interactive", "--json", "sweep", "scan"])
        .arg(&workspace)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_DATA_HOME", home.join("data"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let candidates = report["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 4);

    for (target, root) in [
        (project.join(".tox"), project.clone()),
        (project.join(".nox"), project.clone()),
        (nested.join(".tox"), nested.clone()),
        (nested.join(".nox"), nested.clone()),
    ] {
        let candidate = candidates
            .iter()
            .find(|candidate| candidate["target"] == target.to_str().unwrap())
            .expect("expected project-root Python environment candidate");
        assert_eq!(candidate["ecosystem"], "python");
        assert_eq!(candidate["project_root"], root.to_str().unwrap());
        assert_eq!(candidate["classification"], "review");
        assert!(
            candidate["reproduction_warning"]
                .as_str()
                .unwrap()
                .contains("may include user data")
        );
        assert!(target.is_dir());
    }
    assert!(project.join("package/.tox/env").is_dir());
    assert!(workspace.join("unrelated/.tox/env").is_dir());
    assert!(workspace.join("unrelated/.nox/session").is_dir());
}

#[test]
fn discovers_hypothesis_database_only_inside_a_python_project() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let cache = project.join(".hypothesis/examples");
    fs::create_dir_all(&cache).unwrap();
    fs::write(project.join("pyproject.toml"), "[project]\n").unwrap();
    fs::write(cache.join("example"), b"case").unwrap();
    fs::create_dir_all(dir.path().join("unrelated/.hypothesis")).unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert_eq!(report.candidates.len(), 1);
    let candidate = &report.candidates[0];
    assert_eq!(candidate.ecosystem, "python");
    assert_eq!(candidate.project_root, project);
    assert_eq!(candidate.target, candidate.project_root.join(".hypothesis"));
    assert_eq!(candidate.logical_bytes, 4);
    assert_eq!(candidate.classification, "review");
    let target = candidate.target.clone();
    let plan = upkit::sweep::preview(report, std::slice::from_ref(&target)).unwrap();
    assert_eq!(plan.items[0].risk, "potentially destructive");
    assert!(!plan.items[0].execution_ready);
    assert!(plan.warnings.iter().any(|warning| {
        warning.contains(".hypothesis") && warning.contains("saved failure examples")
    }));
    assert!(
        plan.warnings
            .iter()
            .any(|warning| { warning.contains("Process activity is a bounded snapshot") })
    );
    assert!(target.join("examples/example").is_file());
}

#[test]
fn discovers_pytype_output_as_review_only_with_generated_stub_warning() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let output = project.join(".pytype/pyi");
    fs::create_dir_all(&output).unwrap();
    fs::write(project.join("pyproject.toml"), "[project]\n").unwrap();
    let stub = b"def inferred() -> int: ...\n";
    fs::write(output.join("module.pyi"), stub).unwrap();

    let report = scan(std::slice::from_ref(&project)).unwrap();
    assert_eq!(report.candidates.len(), 1);
    let candidate = &report.candidates[0];
    assert_eq!(candidate.ecosystem, "python");
    assert_eq!(candidate.project_root, project);
    assert_eq!(candidate.target, project.join(".pytype"));
    assert_eq!(candidate.classification, "review");
    assert_eq!(candidate.logical_bytes, stub.len() as u64);

    let target = candidate.target.clone();
    let plan = upkit::sweep::preview(report, std::slice::from_ref(&target)).unwrap();
    assert_eq!(plan.items[0].risk, "potentially destructive");
    assert!(!plan.items[0].execution_ready);
    assert!(plan.warnings.iter().any(|warning| {
        warning.contains("generated .pyi stubs") && warning.contains("inspect them")
    }));
    assert!(target.join("pyi/module.pyi").is_file());
}

#[test]
fn discovers_python_build_and_dist_as_review_only_and_skips_ambiguous_builds() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("workspace");
    let project = root.join("python-project");
    let build = project.join("build");
    let dist = project.join("dist");
    fs::create_dir_all(build.join("lib")).unwrap();
    fs::create_dir_all(&dist).unwrap();
    fs::write(project.join("pyproject.toml"), "[project]\n").unwrap();
    fs::write(build.join("lib/output.py"), b"generated output").unwrap();
    fs::write(dist.join("package.whl"), b"release artifact").unwrap();

    let unrelated = root.join("unrelated");
    fs::create_dir_all(unrelated.join("build")).unwrap();
    fs::create_dir_all(unrelated.join("dist")).unwrap();
    let mixed = root.join("python-flutter");
    fs::create_dir_all(mixed.join("build")).unwrap();
    fs::write(mixed.join("pyproject.toml"), "[project]\n").unwrap();
    fs::write(mixed.join("pubspec.yaml"), "name: fixture\n").unwrap();

    let report = scan(std::slice::from_ref(&root)).unwrap();
    assert_eq!(report.candidates.len(), 2);
    for (target, bytes) in [
        (&build, b"generated output".as_slice()),
        (&dist, b"release artifact".as_slice()),
    ] {
        let candidate = report
            .candidates
            .iter()
            .find(|candidate| candidate.target == *target)
            .unwrap();
        assert_eq!(candidate.ecosystem, "python");
        assert_eq!(candidate.project_root, project);
        assert_eq!(candidate.classification, "review");
        assert_eq!(candidate.logical_bytes, bytes.len() as u64);
        assert!(candidate.size_complete);
        assert!(
            candidate
                .reproduction_warning
                .unwrap()
                .contains("release artifacts")
        );
        assert!(target.is_dir());
    }
    let warning = report
        .warnings
        .iter()
        .find(|warning| warning.contains(&mixed.join("build").display().to_string()))
        .expect("ambiguous Flutter/Python build warning");
    assert!(warning.contains("ambiguous"));
    assert!(warning.contains("flutter"));
    assert!(warning.contains("python"));
    assert!(!report.candidates.iter().any(|candidate| {
        candidate.target == unrelated.join("build") || candidate.target == unrelated.join("dist")
    }));
    assert!(dist.join("package.whl").is_file());
    assert!(build.join("lib/output.py").is_file());
}

#[test]
fn discovers_python_egg_info_metadata_only_at_a_project_root_for_review() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("workspace");
    let project = root.join("python-project");
    let metadata = project.join("demo.egg-info");
    let nested_metadata = project.join("nested/demo.egg-info");
    fs::create_dir_all(&metadata).unwrap();
    fs::create_dir_all(&nested_metadata).unwrap();
    fs::write(project.join("pyproject.toml"), "[project]\n").unwrap();
    let package_info = b"Name: demo\nVersion: 1.0\n";
    fs::write(metadata.join("PKG-INFO"), package_info).unwrap();
    fs::write(nested_metadata.join("PKG-INFO"), b"nested metadata").unwrap();
    fs::create_dir_all(root.join("unrelated/demo.egg-info")).unwrap();

    let report = scan(std::slice::from_ref(&root)).unwrap();
    assert_eq!(report.candidates.len(), 1);
    let candidate = &report.candidates[0];
    assert_eq!(candidate.ecosystem, "python");
    assert_eq!(candidate.project_root, project);
    assert_eq!(candidate.target, metadata);
    assert_eq!(candidate.classification, "review");
    assert_eq!(candidate.logical_bytes, package_info.len() as u64);
    assert!(candidate.size_complete);
    let warning = candidate.reproduction_warning.unwrap();
    assert!(warning.contains("package metadata") && warning.contains("inspect every entry"));

    let target = candidate.target.clone();
    let preview = upkit::sweep::preview(report, std::slice::from_ref(&target)).unwrap();
    assert_eq!(preview.items[0].risk, "potentially destructive");
    assert!(!preview.items[0].execution_ready);
    assert!(
        preview
            .warnings
            .iter()
            .any(|message| message.contains(warning))
    );
    assert!(metadata.join("PKG-INFO").is_file());
    assert!(nested_metadata.join("PKG-INFO").is_file());
}

#[test]
fn discovers_ruff_cache_as_review_only_inside_python_projects() {
    use std::sync::atomic::AtomicBool;

    let dir = tempdir().unwrap();
    let root = dir.path().join("workspace");
    let project = root.join("project");
    let cache = project.join(".ruff_cache");
    let nested_project = project.join("nested");
    let nested_cache = nested_project.join(".ruff_cache");
    let unrelated_cache = root.join("unrelated/.ruff_cache");
    fs::create_dir_all(&cache).unwrap();
    fs::create_dir_all(&nested_cache).unwrap();
    fs::create_dir_all(&unrelated_cache).unwrap();
    fs::write(project.join("pyproject.toml"), "[project]\n").unwrap();
    fs::write(nested_project.join("setup.cfg"), "[metadata]\n").unwrap();
    fs::write(cache.join("entry"), b"root cache").unwrap();
    fs::write(nested_cache.join("entry"), b"nested cache").unwrap();
    fs::write(unrelated_cache.join("entry"), b"unrelated").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let linked_project = root.join("linked");
        let external_cache = dir.path().join("outside/.ruff_cache");
        fs::create_dir_all(&linked_project).unwrap();
        fs::create_dir_all(&external_cache).unwrap();
        fs::write(linked_project.join("pyproject.toml"), "[project]\n").unwrap();
        fs::write(external_cache.join("entry"), b"external").unwrap();
        symlink(&external_cache, linked_project.join(".ruff_cache")).unwrap();
    }

    let report = scan(std::slice::from_ref(&root)).unwrap();
    assert_eq!(report.candidates.len(), 2);
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.target == cache)
        .unwrap();
    assert_eq!(candidate.ecosystem, "python");
    assert_eq!(candidate.project_root, project);
    assert_eq!(candidate.classification, "review");
    assert_eq!(candidate.logical_bytes, b"root cache".len() as u64);
    let warning = "Ruff's .ruff_cache directory is local lint state, but the scanner cannot verify every entry is disposable; inspect its contents before removal.";
    assert_eq!(candidate.reproduction_warning, Some(warning));

    let plan = upkit::sweep::preview(report, std::slice::from_ref(&cache)).unwrap();
    let item = plan
        .items
        .iter()
        .find(|item| item.candidate.target == cache)
        .unwrap();
    assert_eq!(item.risk, "potentially destructive");
    assert!(!item.execution_ready);
    assert!(plan.warnings.iter().any(|item| item.contains(warning)));
    assert!(cache.join("entry").is_file());

    let excluded = upkit::sweep::scan_with_policy(
        std::slice::from_ref(&root),
        &[std::path::PathBuf::from("project/.ruff_cache")],
        None,
        None,
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(excluded.candidates.len(), 1);
    assert_eq!(excluded.candidates[0].target, nested_cache);
    assert!(nested_cache.join("entry").is_file());
}

#[test]
fn discovers_parcel_cache_only_at_a_javascript_project_root_for_review() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let cache = project.join(".parcel-cache");
    fs::create_dir_all(&cache).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{"devDependencies":{"@parcel/core":"^2.0.0"}}"#,
    )
    .unwrap();
    fs::write(cache.join("data"), b"fixture").unwrap();
    fs::create_dir_all(project.join("nested/.parcel-cache")).unwrap();
    fs::create_dir_all(dir.path().join("unrelated/.parcel-cache")).unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert_eq!(report.candidates.len(), 1);
    let candidate = &report.candidates[0];
    assert_eq!(candidate.ecosystem, "javascript");
    assert_eq!(candidate.classification, "review");
    assert_eq!(candidate.target, cache);
    assert_eq!(candidate.logical_bytes, 7);
    let plan = upkit::sweep::preview(report, std::slice::from_ref(&cache)).unwrap();
    assert_eq!(plan.items[0].risk, "potentially destructive");
    assert!(!plan.items[0].execution_ready);
    assert!(
        plan.warnings
            .iter()
            .any(|warning| { warning.contains("Parcel") && warning.contains("do not prove") })
    );
    assert!(cache.join("data").is_file());
}

#[test]
fn javascript_framework_output_names_are_review_only_not_proof_of_generated_contents() {
    let dir = tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let next = workspace.join("next-app");
    let nuxt = workspace.join("nuxt-app");
    let unrelated = workspace.join("unrelated-js");
    let unmanifested = workspace.join("unmanifested");
    for (project, manifest, target) in [
        (&next, r#"{"dependencies":{"next":"^15.0.0"}}"#, ".next"),
        (&nuxt, r#"{"devDependencies":{"nuxt":"^3.0.0"}}"#, ".nuxt"),
    ] {
        fs::create_dir_all(project.join(target)).unwrap();
        fs::write(project.join("package.json"), manifest).unwrap();
        fs::write(project.join(target).join("fixture"), b"output").unwrap();
    }

    let unrelated_cache = [".next", ".nuxt", ".parcel-cache"].map(|name| {
        let path = unrelated.join(name);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("keep"), b"user data").unwrap();
        path
    });
    fs::write(unrelated.join("package.json"), "{}\n").unwrap();
    fs::create_dir_all(unmanifested.join(".next")).unwrap();
    fs::write(unmanifested.join(".next/keep"), b"user data").unwrap();

    let report = scan(std::slice::from_ref(&workspace)).unwrap();
    assert_eq!(report.candidates.len(), 5);
    for (project, target_name, framework) in [(&next, ".next", "Next.js"), (&nuxt, ".nuxt", "Nuxt")]
    {
        let target = project.join(target_name);
        let candidate = report
            .candidates
            .iter()
            .find(|candidate| candidate.target == target)
            .unwrap();
        assert_eq!(&candidate.project_root, project);
        assert_eq!(candidate.classification, "review");
        assert!(candidate.reproduction_warning.is_some_and(|warning| {
            warning.contains(framework)
                && warning.contains("configurable")
                && warning.contains("do not prove its contents are generated")
        }));
    }
    assert!(report.candidates.iter().all(|candidate| {
        candidate.classification == "review"
            && candidate
                .reproduction_warning
                .is_some_and(|warning| warning.contains("do not prove its contents are generated"))
    }));
    assert!(report.candidates.iter().all(|candidate| {
        candidate.project_root != unmanifested && candidate.target != unmanifested.join(".next")
    }));
    for path in unrelated_cache {
        assert!(path.join("keep").is_file());
    }
    assert!(unmanifested.join(".next/keep").is_file());
}

#[test]
fn discovers_root_javascript_coverage_reports_only_with_known_file_markers() {
    let dir = tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let project = workspace.join("covered-app");
    let coverage = project.join("coverage");
    fs::create_dir_all(&coverage).unwrap();
    fs::write(project.join("package.json"), "{}\n").unwrap();
    fs::write(coverage.join("lcov.info"), "TN:\nSF:src/app.ts\n").unwrap();
    fs::write(coverage.join("index.html"), b"report").unwrap();

    let unverified = workspace.join("unverified");
    fs::create_dir_all(unverified.join("coverage")).unwrap();
    fs::write(unverified.join("package.json"), "{}\n").unwrap();
    fs::write(unverified.join("coverage/README.md"), b"user files").unwrap();

    let unmanifested = workspace.join("unmanifested");
    fs::create_dir_all(unmanifested.join("coverage")).unwrap();
    fs::write(unmanifested.join("coverage/lcov.info"), b"outside project").unwrap();

    fs::create_dir_all(project.join("packages/nested/coverage")).unwrap();
    fs::write(
        project.join("packages/nested/coverage/lcov.info"),
        b"nested",
    )
    .unwrap();

    let report = scan(std::slice::from_ref(&workspace)).unwrap();
    assert_eq!(report.candidates.len(), 1);
    let candidate = &report.candidates[0];
    assert_eq!(candidate.ecosystem, "javascript");
    assert_eq!(candidate.project_root, project);
    assert_eq!(candidate.target, coverage);
    assert_eq!(candidate.classification, "review");
    assert_eq!(
        candidate.logical_bytes,
        b"TN:\nSF:src/app.ts\n".len() as u64 + b"report".len() as u64
    );
    assert!(candidate.size_complete);
    assert!(candidate.reproduction_warning.is_some_and(|warning| {
        warning.contains("known coverage report filename")
            && warning.contains("does not prove every entry is disposable")
    }));
    #[cfg(unix)]
    {
        let plan = upkit::sweep::preview(report, std::slice::from_ref(&coverage)).unwrap();
        assert_eq!(plan.items[0].risk, "potentially destructive");
        assert!(!plan.items[0].execution_ready);
        assert!(plan.warnings.iter().any(|warning| {
            warning.contains("known coverage report filename")
                && warning.contains("inspect all entries before removal")
        }));
    }
    assert!(unverified.join("coverage/README.md").is_file());
    assert!(unmanifested.join("coverage/lcov.info").is_file());
    assert!(project.join("packages/nested/coverage/lcov.info").is_file());
}

#[test]
fn discovers_only_angular_workspace_cli_cache_for_review() {
    let dir = tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let project = workspace.join("angular-app");
    let cache = project.join(".angular/cache");
    fs::create_dir_all(cache.join("18.0.0")).unwrap();
    fs::write(project.join("package.json"), "{}\n").unwrap();
    fs::write(
        project.join("angular.json"),
        r#"{"version":1,"projects":{"app":{"projectType":"application"}}}"#,
    )
    .unwrap();
    fs::write(cache.join("18.0.0/build"), b"generated cache").unwrap();
    fs::create_dir_all(project.join("user/cache")).unwrap();

    let unrelated = workspace.join("unrelated");
    let unrelated_cache = unrelated.join(".angular/cache");
    fs::create_dir_all(&unrelated_cache).unwrap();
    fs::write(unrelated.join("package.json"), "{}\n").unwrap();
    fs::write(unrelated_cache.join("keep"), b"not identified").unwrap();

    let invalid = workspace.join("invalid-angular-config");
    let invalid_cache = invalid.join(".angular/cache");
    fs::create_dir_all(&invalid_cache).unwrap();
    fs::write(invalid.join("package.json"), "{}\n").unwrap();
    fs::write(invalid.join("angular.json"), r#"{"projects":[]}"#).unwrap();
    fs::write(invalid_cache.join("keep"), b"not identified").unwrap();

    let report = scan(std::slice::from_ref(&workspace)).unwrap();
    let safe_manifest_open_available = {
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
            openat2(
                rustix::fs::CWD,
                project.join("angular.json"),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .is_ok()
        }
        #[cfg(any(target_os = "macos", windows))]
        {
            true
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            false
        }
    };
    if safe_manifest_open_available {
        assert_eq!(report.candidates.len(), 1);
        let candidate = &report.candidates[0];
        assert_eq!(candidate.ecosystem, "javascript");
        assert_eq!(candidate.project_root, project);
        assert_eq!(candidate.target, cache);
        assert_eq!(candidate.classification, "review");
        assert_eq!(candidate.logical_bytes, b"generated cache".len() as u64);
        assert!(candidate.reproduction_warning.is_some_and(|warning| {
            warning.contains("cache path is configurable in angular.json")
        }));
    } else {
        assert!(report.candidates.is_empty());
    }
    assert!(unrelated_cache.join("keep").is_file());
    assert!(invalid_cache.join("keep").is_file());
    assert!(project.join("user/cache").is_dir());
}

#[test]
fn discovers_sveltekit_default_output_only_with_manifest_evidence_and_never_plans_removal() {
    let dir = tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let project = workspace.join("app");
    let nested = project.join("packages/widget");
    let generic = workspace.join("generic");
    let oversized = workspace.join("oversized");
    let cache = project.join(".svelte-kit");
    let nested_cache = nested.join(".svelte-kit");
    let generic_named_output = generic.join(".svelte-kit");
    let oversized_named_output = oversized.join(".svelte-kit");

    for (root, output) in [(&project, &cache), (&nested, &nested_cache)] {
        fs::create_dir_all(output.join("types")).unwrap();
        fs::write(
            root.join("package.json"),
            r#"{"devDependencies":{"@sveltejs/kit":"^3.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            root.join("vite.config.js"),
            "import { sveltekit } from '@sveltejs/kit/vite';\n",
        )
        .unwrap();
        fs::write(output.join("types/generated.d.ts"), b"generated fixture").unwrap();
    }
    fs::create_dir_all(&generic_named_output).unwrap();
    fs::write(
        generic.join("package.json"),
        r#"{"dependencies":{"vite":"^8"}}"#,
    )
    .unwrap();
    fs::write(generic_named_output.join("keep"), b"user data").unwrap();
    fs::create_dir_all(&oversized_named_output).unwrap();
    fs::write(oversized.join("package.json"), vec![b' '; 1024 * 1024 + 1]).unwrap();
    fs::write(oversized_named_output.join("keep"), b"user data").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let linked = workspace.join("linked");
        let linked_output = linked.join(".svelte-kit");
        let external_manifest = dir.path().join("external-package.json");
        fs::create_dir_all(&linked_output).unwrap();
        fs::write(
            &external_manifest,
            r#"{"devDependencies":{"@sveltejs/kit":"^3.0.0"}}"#,
        )
        .unwrap();
        symlink(&external_manifest, linked.join("package.json")).unwrap();
        fs::write(linked_output.join("keep"), b"user data").unwrap();
    }

    let report = scan(std::slice::from_ref(&workspace)).unwrap();
    let safe_manifest_open_available = {
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
            openat2(
                rustix::fs::CWD,
                project.join("package.json"),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
            )
            .is_ok()
        }
        #[cfg(any(target_os = "macos", windows))]
        {
            true
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            false
        }
    };
    if safe_manifest_open_available {
        assert_eq!(report.candidates.len(), 2);
        for (target, root) in [(&cache, &project), (&nested_cache, &nested)] {
            let candidate = report
                .candidates
                .iter()
                .find(|candidate| &candidate.target == target)
                .unwrap();
            assert_eq!(candidate.ecosystem, "javascript");
            assert_eq!(&candidate.project_root, root);
            assert_eq!(candidate.classification, "review");
            assert_eq!(candidate.operation, "inspection only");
            assert!(candidate.reproduction_warning.is_some_and(|warning| {
                warning.contains("configurable outDir")
                    && warning.contains("cannot verify every entry is disposable")
            }));
        }
    } else {
        assert!(report.candidates.is_empty());
    }
    assert!(report.candidates.iter().all(|candidate| {
        candidate.target != generic_named_output && candidate.target != oversized_named_output
    }));
    assert!(generic_named_output.join("keep").is_file());
    assert!(oversized_named_output.join("keep").is_file());

    #[cfg(target_os = "linux")]
    {
        if report
            .candidates
            .iter()
            .any(|candidate| candidate.target == cache)
        {
            let scope = upkit::sweep::Scope {
                roots: vec![workspace],
                exclusions: Vec::new(),
                older_than_seconds: None,
                enabled: None,
            };
            let error = upkit::artifact_cleanup::preview(
                &scope,
                &cache,
                &std::sync::atomic::AtomicBool::new(false),
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("SvelteKit output is inspection-only"));
            assert!(cache.join("types/generated.d.ts").is_file());
        }
    }
}

#[test]
fn discovers_only_vites_default_cache_as_review_only() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let cache = project.join("node_modules/.vite");
    fs::create_dir_all(cache.join("deps")).unwrap();
    fs::write(project.join("package.json"), "{}\n").unwrap();
    fs::write(cache.join("deps/chunk"), b"fixture").unwrap();
    fs::create_dir_all(dir.path().join("unrelated/node_modules/.vite")).unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert_eq!(report.candidates.len(), 1);
    let candidate = &report.candidates[0];
    assert_eq!(candidate.ecosystem, "javascript");
    assert_eq!(candidate.project_root, project);
    assert_eq!(candidate.target, cache);
    assert_eq!(candidate.logical_bytes, 7);
    assert_eq!(candidate.classification, "review");
    let target = candidate.target.clone();
    let plan = upkit::sweep::preview(report, std::slice::from_ref(&target)).unwrap();
    assert_eq!(plan.items[0].risk, "potentially destructive");
    assert!(!plan.items[0].execution_ready);
    assert!(plan.warnings.iter().any(|warning| {
        warning.contains("Vite's default cache location")
            && warning.contains("contents are not verified as generated")
    }));
    assert!(target.join("deps/chunk").is_file());

    let disabled = upkit::sweep::scan_with_policy(
        &[dir.path().to_owned()],
        &[],
        None,
        Some(&[upkit::sweep::Ecosystem::Cargo]),
        &std::sync::atomic::AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert!(disabled.candidates.is_empty());

    let excluded = upkit::sweep::scan_with_policy(
        &[dir.path().to_owned()],
        &[std::path::PathBuf::from("project/node_modules")],
        None,
        None,
        &std::sync::atomic::AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert!(excluded.candidates.is_empty());
}

#[test]
fn does_not_classify_a_vite_named_nested_project_as_cache() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let vite_cache = project.join("node_modules/.vite");
    fs::create_dir_all(&vite_cache).unwrap();
    fs::write(project.join("package.json"), "{}\n").unwrap();
    fs::write(vite_cache.join("package.json"), "{}\n").unwrap();
    fs::write(vite_cache.join("index.js"), b"source").unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert!(report.candidates.is_empty());
    assert!(vite_cache.join("index.js").is_file());
}

#[test]
fn does_not_scan_vite_cache_across_a_node_modules_project_boundary() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let modules = project.join("node_modules");
    let cache = modules.join(".vite");
    fs::create_dir_all(&cache).unwrap();
    fs::write(project.join("package.json"), "{}\n").unwrap();
    fs::write(modules.join("package.json"), "{}\n").unwrap();
    fs::write(cache.join("fixture"), b"keep").unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert!(report.candidates.is_empty());
    assert_eq!(fs::read(cache.join("fixture")).unwrap(), b"keep");
}

#[cfg(unix)]
#[test]
fn vite_cache_scan_does_not_follow_node_modules_or_cache_symlinks() {
    use std::os::unix::fs::symlink;

    let dir = tempdir().unwrap();
    let external_cache = dir.path().join("external/node_modules/.vite");
    fs::create_dir_all(&external_cache).unwrap();
    fs::write(external_cache.join("fixture"), b"keep").unwrap();

    let linked_modules = dir.path().join("linked-modules");
    fs::create_dir_all(&linked_modules).unwrap();
    fs::write(linked_modules.join("package.json"), "{}\n").unwrap();
    symlink(
        external_cache.parent().unwrap(),
        linked_modules.join("node_modules"),
    )
    .unwrap();

    let linked_cache = dir.path().join("linked-cache");
    fs::create_dir_all(linked_cache.join("node_modules")).unwrap();
    fs::write(linked_cache.join("package.json"), "{}\n").unwrap();
    symlink(&external_cache, linked_cache.join("node_modules/.vite")).unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert!(report.candidates.is_empty());
    assert!(!report.is_complete());
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("linked-modules/node_modules")
                && warning.contains("linked or reparse directory"))
    );
    assert!(report.warnings.iter().any(
        |warning| warning.contains("linked-cache/node_modules/.vite")
            && warning.contains("linked or reparse directory")
    ));
    assert_eq!(fs::read(external_cache.join("fixture")).unwrap(), b"keep");
}

#[cfg(windows)]
#[test]
fn vite_cache_scan_does_not_follow_reparse_directories() {
    use std::os::windows::fs::symlink_dir;

    let dir = tempdir().unwrap();
    let external_cache = dir.path().join("external/node_modules/.vite");
    fs::create_dir_all(&external_cache).unwrap();
    fs::write(external_cache.join("fixture"), b"keep").unwrap();

    let linked_modules = dir.path().join("linked-modules");
    fs::create_dir_all(&linked_modules).unwrap();
    fs::write(linked_modules.join("package.json"), "{}\n").unwrap();
    if let Err(error) = symlink_dir(
        external_cache.parent().unwrap(),
        linked_modules.join("node_modules"),
    ) {
        eprintln!("SKIP: Windows reparse fixture unavailable: {error}");
        return;
    }

    let linked_cache = dir.path().join("linked-cache");
    fs::create_dir_all(linked_cache.join("node_modules")).unwrap();
    fs::write(linked_cache.join("package.json"), "{}\n").unwrap();
    if let Err(error) = symlink_dir(&external_cache, linked_cache.join("node_modules/.vite")) {
        eprintln!("SKIP: Windows reparse fixture unavailable: {error}");
        return;
    }

    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert!(report.candidates.is_empty());
    assert!(!report.is_complete());
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("linked-modules")
                && warning.contains("node_modules")
                && warning.contains("linked or reparse directory"))
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("linked-cache")
                && warning.contains(".vite")
                && warning.contains("linked or reparse directory"))
    );
    assert_eq!(fs::read(external_cache.join("fixture")).unwrap(), b"keep");
}

#[cfg(target_os = "linux")]
#[test]
fn cargo_workspace_evidence_respects_members_excludes_overrides_and_scan_scope() {
    let dir = tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    fs::create_dir_all(workspace.join("target")).unwrap();
    fs::write(
        workspace.join("Cargo.toml"),
        "[workspace]\nmembers = ['crates/*']\nexclude = ['crates/excluded']\n",
    )
    .unwrap();
    for (name, manifest) in [
        (
            "crates/member",
            "[package]\nname='member'\nversion='0.1.0'\n",
        ),
        (
            "crates/excluded",
            "[package]\nname='excluded'\nversion='0.1.0'\n",
        ),
        (
            "vendor/implicit",
            "[package]\nname='implicit'\nversion='0.1.0'\n",
        ),
        (
            "crates/override",
            "[package]\nname='override'\nversion='0.1.0'\nworkspace='../../elsewhere'\n",
        ),
        ("crates/invalid", "[package\n"),
    ] {
        let project = workspace.join(name);
        fs::create_dir_all(project.join("target")).unwrap();
        fs::write(project.join("Cargo.toml"), manifest).unwrap();
        fs::write(project.join("target/fixture"), name).unwrap();
    }
    let report = scan(&[workspace.clone(), workspace.join("crates/member")]).unwrap();
    let status = |project: &std::path::Path| {
        let candidate = report
            .candidates
            .iter()
            .find(|candidate| candidate.project_root == project)
            .unwrap();
        let workspace = candidate.cargo_workspace.as_ref().unwrap();
        (workspace.status, workspace.workspace_root.clone())
    };
    assert_eq!(
        status(&workspace),
        ("workspace_manifest", Some(workspace.clone()))
    );
    assert_eq!(
        status(&workspace.join("crates/member")),
        ("member_pattern_match", Some(workspace.clone()))
    );
    assert_eq!(
        status(&workspace.join("crates/excluded")),
        ("exclude_pattern_match", Some(workspace.clone()))
    );
    assert_eq!(
        status(&workspace.join("vendor/implicit")),
        ("membership_unresolved", Some(workspace.clone()))
    );
    assert_eq!(
        status(&workspace.join("crates/override")),
        ("workspace_override_unresolved", None)
    );
    assert_eq!(
        status(&workspace.join("crates/invalid")),
        ("manifest_unavailable", None)
    );
    let member = workspace.join("crates/member");
    let isolated = scan(std::slice::from_ref(&member)).unwrap();
    let isolated_candidate = isolated
        .candidates
        .iter()
        .find(|candidate| candidate.target == member.join("target"))
        .unwrap();
    assert_eq!(
        isolated_candidate.cargo_workspace.as_ref().unwrap().status,
        "member_pattern_match"
    );
    assert_eq!(isolated_candidate.classification, "review");
    let value = serde_json::to_value(&report).unwrap();
    let json_member = value["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["project_root"] == member.to_str().unwrap())
        .unwrap();
    assert_eq!(
        json_member["cargo_workspace"]["status"],
        "member_pattern_match"
    );
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--non-interactive", "sweep", "scan"])
        .arg(&workspace)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Cargo workspace: member_pattern_match")
    );
    fs::write(
        workspace.join("Cargo.toml"),
        "[workspace]\nmembers = ['crates/*', '[invalid']\n",
    )
    .unwrap();
    let invalid_patterns = scan(std::slice::from_ref(&workspace)).unwrap();
    let member_evidence = invalid_patterns
        .candidates
        .iter()
        .find(|candidate| candidate.project_root == member)
        .unwrap()
        .cargo_workspace
        .as_ref()
        .unwrap();
    assert_eq!(member_evidence.status, "membership_unresolved");
    assert!(workspace.join("crates/member/target/fixture").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn cargo_workspace_evidence_never_follows_or_reads_excluded_manifests() {
    use std::{os::unix::fs::symlink, sync::atomic::AtomicBool};
    let dir = tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let project = workspace.join("member");
    fs::create_dir_all(project.join("target")).unwrap();
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname='member'\nversion='0.1.0'\n",
    )
    .unwrap();
    let outside = dir.path().join("outside");
    fs::write(&outside, "[workspace]\nmembers=['member']\n").unwrap();
    symlink(&outside, workspace.join("Cargo.toml")).unwrap();
    let report = scan(std::slice::from_ref(&workspace)).unwrap();
    assert_eq!(
        report.candidates[0]
            .cargo_workspace
            .as_ref()
            .unwrap()
            .status,
        "manifest_unavailable"
    );
    fs::remove_file(workspace.join("Cargo.toml")).unwrap();
    fs::write(
        workspace.join("Cargo.toml"),
        "[workspace]\nmembers=['member']\n",
    )
    .unwrap();
    let report = upkit::sweep::scan_with_policy(
        std::slice::from_ref(&workspace),
        &[workspace.join("Cargo.toml")],
        None,
        None,
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(
        report.candidates[0]
            .cargo_workspace
            .as_ref()
            .unwrap()
            .status,
        "manifest_unavailable"
    );
    fs::write(workspace.join("Cargo.toml"), vec![b' '; 1_048_577]).unwrap();
    let report = scan(std::slice::from_ref(&workspace)).unwrap();
    assert_eq!(
        report.candidates[0]
            .cargo_workspace
            .as_ref()
            .unwrap()
            .status,
        "manifest_unavailable"
    );
    assert_eq!(
        fs::read_to_string(outside).unwrap(),
        "[workspace]\nmembers=['member']\n"
    );
}

#[cfg(unix)]
#[test]
fn skips_symlinks_and_does_not_scan_linked_roots() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let root = dir.path().join("workspace");
    let outside = dir.path().join("outside");
    fs::create_dir_all(root.join("target")).unwrap();
    fs::write(root.join("Cargo.toml"), "[workspace]").unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret"), b"outside").unwrap();
    symlink(&outside, root.join("target/link")).unwrap();
    symlink(&outside, root.join("external")).unwrap();
    fs::create_dir_all(root.join("fake/target")).unwrap();
    symlink(root.join("Cargo.toml"), root.join("fake/Cargo.toml")).unwrap();
    let report = scan(std::slice::from_ref(&root)).unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].logical_bytes, 0);
    assert!(scan(&[root.join("external")]).is_err());
    assert!(outside.join("secret").exists());
}

#[test]
fn refuses_missing_and_filesystem_roots() {
    assert!(scan(&[]).is_err());
    #[cfg(unix)]
    assert!(scan(&[std::path::PathBuf::from("/")]).is_err());
}

#[test]
fn recognizes_project_specific_artifact_signatures() {
    let dir = tempdir().unwrap();
    for (name, manifest, target) in [
        ("maven", "pom.xml", "target"),
        ("gradle", "build.gradle.kts", "build"),
        ("dotnet", "app.csproj", "obj"),
        ("flutter", "pubspec.yaml", ".dart_tool"),
        ("js", "package.json", ".next"),
        ("cmake", "CMakeLists.txt", "build"),
        ("meson", "meson.build", "build"),
    ] {
        let root = dir.path().join(name);
        fs::create_dir_all(root.join(target)).unwrap();
        fs::write(
            root.join(manifest),
            if name == "js" {
                r#"{"dependencies":{"next":"^15"}}"#
            } else {
                ""
            },
        )
        .unwrap();
        if name == "cmake" {
            fs::write(root.join("build/CMakeCache.txt"), "").unwrap();
        }
        if name == "meson" {
            fs::create_dir_all(root.join("build/meson-private")).unwrap();
            fs::write(root.join("build/meson-private/coredata.dat"), "").unwrap();
        }
    }
    fs::create_dir_all(dir.path().join("ambiguous/build")).unwrap();
    fs::write(dir.path().join("ambiguous/CMakeLists.txt"), "").unwrap();
    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert_eq!(report.candidates.len(), 7);
    for ecosystem in [
        "maven",
        "gradle",
        "dotnet",
        "dart",
        "javascript",
        "cmake",
        "meson",
    ] {
        assert!(
            report.candidates.iter().any(|c| c.ecosystem == ecosystem),
            "{ecosystem}"
        );
    }
}

#[test]
fn skips_shared_cargo_maven_target_for_all_and_selected_policies() {
    use upkit::sweep::{Ecosystem, scan_with_policy};

    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let target = project.join("target");
    fs::create_dir_all(target.join("nested-project/target")).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(project.join("pom.xml"), "<project/>\n").unwrap();
    fs::write(project.join("build.sbt"), "lazy val root = project\n").unwrap();
    fs::write(target.join("nested-project/Cargo.toml"), "[workspace]\n").unwrap();

    let policies = [
        None,
        Some(vec![Ecosystem::Cargo]),
        Some(vec![Ecosystem::Maven]),
        Some(vec![Ecosystem::Cargo, Ecosystem::Maven]),
    ];
    for enabled in policies {
        let report = scan_with_policy(
            std::slice::from_ref(&project),
            &[],
            None,
            enabled.as_deref(),
            &std::sync::atomic::AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        assert!(report.candidates.is_empty());
        assert!(!report.is_complete());
        let warning = report
            .warnings
            .iter()
            .find(|warning| warning.contains(&target.display().to_string()))
            .expect("shared target warning");
        assert!(warning.contains("ambiguous"));
        assert!(warning.contains("cargo"));
        assert!(warning.contains("maven"));
        assert!(warning.contains("sbt"));
    }

    let report = scan(&[project]).unwrap();
    assert!(upkit::sweep::preview(report, &[target]).is_err());
}

#[test]
fn nested_sbt_project_marker_blocks_cargo_target_cleanup() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let target = project.join("target");
    let nested_project = target.join("nested-scala");
    fs::create_dir_all(nested_project.join("target")).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(
        nested_project.join("build.sbt"),
        "lazy val nested = project\n",
    )
    .unwrap();
    fs::write(nested_project.join("target/classes.bin"), b"classes").unwrap();

    let report = scan(std::slice::from_ref(&project)).unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].ecosystem, "cargo");
    assert_eq!(
        report.candidates[0].nested_project_marker.as_deref(),
        Some(nested_project.join("build.sbt").as_path())
    );

    let plan = upkit::sweep::preview(report, std::slice::from_ref(&target)).unwrap();
    assert_eq!(
        plan.items[0].risk,
        "nested project or version-control marker; do not remove"
    );
    assert!(!plan.items[0].execution_ready);
    assert!(nested_project.join("target/classes.bin").is_file());
}

#[test]
fn skips_shared_flutter_gradle_build_when_both_are_enabled() {
    use upkit::sweep::{Ecosystem, scan_with_policy};

    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let build = project.join("build");
    fs::create_dir_all(&build).unwrap();
    fs::write(project.join("pubspec.yaml"), "name: fixture\n").unwrap();
    fs::write(project.join("build.gradle"), "plugins {}\n").unwrap();

    let report = scan_with_policy(
        std::slice::from_ref(&project),
        &[],
        None,
        Some(&[Ecosystem::Flutter, Ecosystem::Gradle]),
        &std::sync::atomic::AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert!(report.candidates.is_empty());
    assert!(!report.is_complete());
    let warning = report
        .warnings
        .iter()
        .find(|warning| warning.contains(&build.display().to_string()))
        .expect("shared build warning");
    assert!(warning.contains("ambiguous"));
    assert!(warning.contains("flutter"));
    assert!(warning.contains("gradle"));
}

#[test]
fn skips_build_with_both_cmake_and_meson_signatures() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let build = project.join("build");
    fs::create_dir_all(build.join("meson-private")).unwrap();
    fs::write(project.join("CMakeLists.txt"), "").unwrap();
    fs::write(project.join("meson.build"), "").unwrap();
    fs::write(build.join("CMakeCache.txt"), "").unwrap();
    fs::write(build.join("meson-private/coredata.dat"), "").unwrap();

    let report = scan(&[project]).unwrap();
    assert!(report.candidates.is_empty());
    assert!(!report.is_complete());
    let warning = report
        .warnings
        .iter()
        .find(|warning| warning.contains(&build.display().to_string()))
        .expect("shared build warning");
    assert!(warning.contains("ambiguous"));
    assert!(warning.contains("cmake"));
    assert!(warning.contains("meson"));
}

#[test]
fn discovers_only_project_local_gradle_state_as_review_only() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let cache = project.join(".gradle");
    fs::create_dir_all(cache.join("8.10/checksums")).unwrap();
    fs::write(project.join("build.gradle.kts"), "plugins {}\n").unwrap();
    fs::write(cache.join("8.10/checksums/state.bin"), b"cache").unwrap();
    fs::create_dir_all(project.join("nested/.gradle")).unwrap();
    fs::create_dir_all(dir.path().join("unrelated/.gradle")).unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert_eq!(report.candidates.len(), 1);
    let candidate = &report.candidates[0];
    assert_eq!(candidate.ecosystem, "gradle");
    assert_eq!(candidate.target, cache);
    assert_eq!(candidate.classification, "review");
    assert_eq!(candidate.logical_bytes, b"cache".len() as u64);
    let warning = "Gradle stores project state in this local .gradle directory; the directory name and build.gradle manifest do not prove every entry can be regenerated. Inspect its contents before removal.";
    assert_eq!(candidate.reproduction_warning, Some(warning));
    let scan_json = serde_json::to_value(&report).unwrap();
    assert_eq!(scan_json["candidates"][0]["reproduction_warning"], warning);

    let target = candidate.target.clone();
    let plan = upkit::sweep::preview(report, std::slice::from_ref(&target)).unwrap();
    assert_eq!(plan.items[0].identity_status, "metadata_match");
    assert_eq!(plan.items[0].risk, "potentially destructive");
    assert!(!plan.items[0].execution_ready);
    assert_eq!(plan.items[0].candidate.reproduction_warning, Some(warning));
    assert!(plan.warnings.iter().any(|item| item.contains(warning)));
    assert!(target.join("8.10/checksums/state.bin").is_file());
}

#[test]
fn discovers_sbt_target_as_review_only_and_respects_ecosystem_filter() {
    use upkit::sweep::{Ecosystem, scan_with_policy};

    let dir = tempdir().unwrap();
    let project = dir.path().join("scala-project");
    let target = project.join("target");
    let root = dir.path().to_owned();
    fs::create_dir_all(&target).unwrap();
    fs::write(project.join("build.sbt"), "lazy val root = project\n").unwrap();
    fs::write(target.join("classes.bin"), b"compiled classes").unwrap();

    let scan = |enabled: Option<&[Ecosystem]>| {
        scan_with_policy(
            std::slice::from_ref(&root),
            &[],
            None,
            enabled,
            &std::sync::atomic::AtomicBool::new(false),
            |_| {},
        )
        .unwrap()
    };
    let report = scan(None);
    assert_eq!(report.candidates.len(), 1);
    let candidate = &report.candidates[0];
    assert_eq!(candidate.ecosystem, "sbt");
    assert_eq!(candidate.project_root, project);
    assert_eq!(candidate.target, target);
    assert_eq!(candidate.classification, "review");
    let warning = "sbt's target directory contains generated build outputs and local state; inspect every entry before removal.";
    assert_eq!(candidate.reproduction_warning, Some(warning));

    let plan = upkit::sweep::preview(report, std::slice::from_ref(&target)).unwrap();
    assert_eq!(plan.items[0].candidate.classification, "review");
    assert_eq!(plan.items[0].risk, "potentially destructive");
    assert!(!plan.items[0].execution_ready);
    assert!(plan.warnings.iter().any(|item| item.contains(warning)));

    let enabled = scan(Some(&[Ecosystem::Sbt]));
    assert_eq!(enabled.candidates.len(), 1);
    let disabled = scan(Some(&[Ecosystem::Cargo]));
    assert!(disabled.candidates.is_empty());
    assert!(!disabled.is_complete());
    assert!(
        disabled
            .warnings
            .iter()
            .any(|warning| warning.contains("sbt"))
    );
    assert!(target.join("classes.bin").is_file());
}

#[test]
fn go_build_and_bin_are_review_only_and_vendor_is_not_an_artifact() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("service");
    let vendor = project.join("vendor");
    fs::create_dir_all(project.join("build")).unwrap();
    fs::create_dir_all(project.join("bin")).unwrap();
    fs::create_dir_all(vendor.join("example.com/dependency")).unwrap();
    fs::write(
        project.join("go.mod"),
        "module example.com/service\ngo 1.22\n",
    )
    .unwrap();
    fs::write(
        vendor.join("modules.txt"),
        "# example.com/dependency v1.2.3\n## explicit; go 1.22\nexample.com/dependency\n",
    )
    .unwrap();
    fs::write(
        vendor.join("example.com/dependency/dependency.go"),
        "package dependency\n",
    )
    .unwrap();
    fs::write(project.join("build/service"), b"custom output").unwrap();
    fs::write(project.join("bin/tool"), b"custom output").unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert_eq!(report.candidates.len(), 2);
    for target in [&project.join("build"), &project.join("bin")] {
        let candidate = report
            .candidates
            .iter()
            .find(|candidate| &candidate.target == target)
            .unwrap();
        assert_eq!(candidate.ecosystem, "go");
        assert_eq!(candidate.classification, "review");
        assert_eq!(candidate.operation, "inspection only");
        assert!(candidate.reproduction_warning.is_some_and(|warning| {
            warning.contains("may contain tracked or user-authored files")
                && warning.contains("removal is unsupported")
        }));
    }
    assert!(
        vendor
            .join("example.com/dependency/dependency.go")
            .is_file()
    );
    assert!(project.join("build/service").is_file());
    assert!(project.join("bin/tool").is_file());
}

#[cfg(unix)]
#[test]
fn go_output_scan_respects_exclusions_nested_projects_and_symlinks() {
    use std::{os::unix::fs::symlink, path::PathBuf};
    use upkit::sweep::scan_with_policy;

    let dir = tempdir().unwrap();
    let project = dir.path().join("service");
    let build = project.join("build");
    let nested = build.join("nested");
    let bin = project.join("bin");
    let outside = dir.path().join("outside");
    fs::create_dir_all(&nested).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(
        project.join("go.mod"),
        "module example.com/service\ngo 1.22\n",
    )
    .unwrap();
    fs::write(
        nested.join("go.mod"),
        "module example.com/nested\ngo 1.22\n",
    )
    .unwrap();
    fs::write(build.join("output"), b"fixture output").unwrap();
    fs::write(bin.join("tool"), b"fixture output").unwrap();
    fs::write(outside.join("secret"), b"outside").unwrap();
    symlink(&outside, bin.join("linked")).unwrap();

    let report = scan(std::slice::from_ref(&project)).unwrap();
    assert_eq!(report.candidates.len(), 2);
    let build_candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.target == build)
        .unwrap();
    assert_eq!(
        build_candidate.nested_project_marker.as_deref(),
        Some(nested.join("go.mod").as_path())
    );
    let bin_candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.target == bin)
        .unwrap();
    assert_eq!(bin_candidate.logical_bytes, b"fixture output".len() as u64);
    assert_eq!(
        bin_candidate.symlink_marker.as_deref(),
        Some(bin.join("linked").as_path())
    );

    let excluded = scan_with_policy(
        std::slice::from_ref(&project),
        &[PathBuf::from("build")],
        None,
        None,
        &std::sync::atomic::AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(excluded.candidates.len(), 1);
    assert_eq!(excluded.candidates[0].target, bin);
    assert!(outside.join("secret").is_file());
}

#[test]
fn go_and_dotnet_bin_collision_fails_closed_as_ambiguous() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("service");
    let bin = project.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::write(
        project.join("go.mod"),
        "module example.com/service\ngo 1.22\n",
    )
    .unwrap();
    fs::write(project.join("app.csproj"), "<Project />\n").unwrap();
    fs::write(bin.join("keep"), b"user data").unwrap();

    let report = scan(&[project]).unwrap();
    assert!(report.candidates.is_empty());
    assert!(report.warnings.iter().any(|warning| {
        warning.contains("ambiguous artifact match (go, dotnet)")
            && warning.contains("target and its subtree were skipped")
    }));
    assert_eq!(fs::read(bin.join("keep")).unwrap(), b"user data");
}

#[test]
fn dotnet_project_extensions_ignore_case_for_discovery_and_nested_safety() {
    let dir = tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let dotnet = workspace.join("dotnet");
    let bin = dotnet.join("bin");
    let rust = workspace.join("rust");
    let target = rust.join("target");
    let nested_manifest = target.join("source/Nested.FSPROJ");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(nested_manifest.parent().unwrap()).unwrap();
    fs::write(dotnet.join("App.CSPROJ"), "<Project />\n").unwrap();
    fs::write(bin.join("fixture.dll"), b"generated output").unwrap();
    fs::write(rust.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(&nested_manifest, "<Project />\n").unwrap();

    let report = scan(std::slice::from_ref(&workspace)).unwrap();
    assert_eq!(report.candidates.len(), 2);
    let dotnet_candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.target == bin)
        .unwrap();
    assert_eq!(dotnet_candidate.ecosystem, "dotnet");
    assert_eq!(dotnet_candidate.project_root, dotnet);
    assert_eq!(
        dotnet_candidate.logical_bytes,
        b"generated output".len() as u64
    );

    let rust_candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.target == target)
        .unwrap();
    assert_eq!(
        rust_candidate.nested_project_marker.as_deref(),
        Some(nested_manifest.as_path())
    );

    #[cfg(unix)]
    {
        let plan = upkit::sweep::preview(report, &[]).unwrap();
        let item = plan
            .items
            .iter()
            .find(|item| item.candidate.target == bin)
            .unwrap();
        assert_eq!(item.identity_status, "metadata_match");
        assert!(!item.execution_ready);
        let nested_item = plan
            .items
            .iter()
            .find(|item| item.candidate.target == target)
            .unwrap();
        assert_eq!(
            nested_item.risk,
            "nested project or version-control marker; do not remove"
        );
        assert!(!nested_item.execution_ready);
        assert!(target.join("source/Nested.FSPROJ").is_file());
    }
}

#[test]
fn go_work_workspace_outputs_remain_review_only_and_fail_closed() {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    let dir = tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let build = workspace.join("build");
    let nested = build.join("nested");
    let module = workspace.join("modules/service");
    let bin = workspace.join("bin");
    let outside = dir.path().join("outside");
    fs::create_dir_all(&nested).unwrap();
    fs::create_dir_all(&module).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(
        workspace.join("go.work"),
        "go 1.22\n\nuse ./modules/service\n",
    )
    .unwrap();
    fs::write(
        module.join("go.mod"),
        "module example.com/service\ngo 1.22\n",
    )
    .unwrap();
    fs::write(workspace.join("app.csproj"), "<Project />\n").unwrap();
    fs::write(
        nested.join("go.mod"),
        "module example.com/nested\ngo 1.22\n",
    )
    .unwrap();
    fs::write(build.join("output"), b"fixture output").unwrap();
    fs::write(bin.join("keep"), b"user data").unwrap();
    fs::write(outside.join("secret"), vec![0u8; 4096]).unwrap();
    #[cfg(unix)]
    symlink(&outside, build.join("linked")).unwrap();

    let report = scan(std::slice::from_ref(&workspace)).unwrap();
    assert_eq!(report.candidates.len(), 1);
    let candidate = &report.candidates[0];
    assert_eq!(candidate.ecosystem, "go");
    assert_eq!(candidate.project_root, workspace);
    assert_eq!(candidate.target, build);
    assert_eq!(candidate.classification, "review");
    assert_eq!(candidate.operation, "inspection only");
    assert!(candidate.reproduction_warning.is_some_and(|warning| {
        warning.contains("may contain tracked or user-authored files")
            && warning.contains("removal is unsupported")
    }));
    assert!(candidate.logical_bytes < fs::metadata(outside.join("secret")).unwrap().len());
    assert_eq!(
        candidate.nested_project_marker.as_deref(),
        Some(nested.join("go.mod").as_path())
    );
    #[cfg(unix)]
    assert_eq!(
        candidate.symlink_marker.as_deref(),
        Some(build.join("linked").as_path())
    );
    assert!(report.warnings.iter().any(|warning| {
        warning.contains("ambiguous artifact match (go, dotnet)")
            && warning.contains("target and its subtree were skipped")
    }));

    let plan = upkit::sweep::preview(report, std::slice::from_ref(&build)).unwrap();
    #[cfg(unix)]
    assert_eq!(plan.items[0].identity_status, "metadata_match");
    #[cfg(not(unix))]
    assert_eq!(plan.items[0].identity_status, "unavailable");
    assert!(!plan.items[0].execution_ready);
    assert_eq!(
        plan.items[0].risk,
        "nested project or version-control marker; do not remove"
    );
    assert!(bin.join("keep").is_file());
    assert!(outside.join("secret").is_file());
}

#[test]
fn scans_zig_build_outputs_only_for_manifest_backed_projects() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("zig-project");
    let cache = project.join(".zig-cache");
    let output = project.join("zig-out");
    fs::create_dir_all(&cache).unwrap();
    fs::create_dir_all(&output).unwrap();
    fs::write(project.join("build.zig"), "fixture").unwrap();
    fs::write(project.join("build.zig.zon"), ".{ .name = .fixture }\n").unwrap();
    fs::write(cache.join("keep"), "cache").unwrap();
    fs::write(output.join("keep"), "user data").unwrap();

    let unrelated = dir.path().join("unrelated");
    fs::create_dir_all(unrelated.join(".zig-cache")).unwrap();
    fs::create_dir_all(unrelated.join("zig-out")).unwrap();
    fs::write(unrelated.join(".zig-cache/keep"), "not a project").unwrap();
    fs::write(unrelated.join("zig-out/keep"), "not a project").unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert_eq!(report.candidates.len(), 2);
    let cache_candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.target == cache)
        .unwrap();
    assert_eq!(cache_candidate.ecosystem, "zig");
    assert_eq!(cache_candidate.classification, "rebuildable");
    assert_eq!(cache_candidate.logical_bytes, 5);
    let output_candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.target == output)
        .unwrap();
    assert_eq!(output_candidate.ecosystem, "zig");
    assert_eq!(output_candidate.classification, "review");
    assert_eq!(output_candidate.logical_bytes, 9);
    assert!(
        output_candidate
            .reproduction_warning
            .is_some_and(|warning| warning.contains("can contain user data"))
    );

    let plan = upkit::sweep::preview(report, &[cache.clone(), output.clone()]).unwrap();
    let cache_item = plan
        .items
        .iter()
        .find(|item| item.candidate.target == cache)
        .unwrap();
    let output_item = plan
        .items
        .iter()
        .find(|item| item.candidate.target == output)
        .unwrap();
    assert!(!cache_item.execution_ready && !output_item.execution_ready);
    assert_eq!(output_item.risk, "potentially destructive");
    assert!(plan.warnings.iter().any(|warning| {
        warning.contains("zig-out") && warning.contains("can contain user data")
    }));
    assert!(unrelated.join(".zig-cache/keep").is_file());
    assert!(unrelated.join("zig-out/keep").is_file());
}

#[test]
fn artifact_named_nested_project_is_not_misclassified_as_parent_output() {
    let dir = tempdir().unwrap();
    let nested = dir.path().join("target");
    fs::create_dir_all(nested.join("target")).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    fs::write(nested.join("Cargo.toml"), "[package]").unwrap();
    fs::write(nested.join("source.rs"), "source").unwrap();
    fs::write(nested.join("target/output"), "artifact").unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].project_root, nested);
    assert_eq!(report.candidates[0].target, nested.join("target"));
    assert!(nested.join("source.rs").exists());
}

#[test]
fn nested_project_is_discovered_when_parent_ecosystem_is_disabled() {
    use std::sync::atomic::AtomicBool;
    use upkit::sweep::{Ecosystem, scan_with_policy};
    let dir = tempdir().unwrap();
    let nested = dir.path().join("target");
    fs::create_dir_all(nested.join("__pycache__")).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    fs::write(nested.join("pyproject.toml"), "[project]").unwrap();
    let report = scan_with_policy(
        &[dir.path().to_owned()],
        &[],
        None,
        Some(&[Ecosystem::Python]),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].project_root, nested);
    assert_eq!(report.candidates[0].ecosystem, "python");
}

#[test]
fn disabled_artifact_subtrees_warn_that_nested_projects_may_be_missed() {
    use std::sync::atomic::AtomicBool;
    use upkit::sweep::{Ecosystem, scan_with_policy};

    let dir = tempdir().unwrap();
    let root = dir.path();
    let target = root.join("target");
    let nested = target.join("nested");
    fs::create_dir_all(nested.join("__pycache__")).unwrap();
    fs::write(root.join("Cargo.toml"), "[workspace]").unwrap();
    fs::write(nested.join("pyproject.toml"), "[project]").unwrap();
    let cache = nested.join("__pycache__/fixture.pyc");
    fs::write(&cache, b"bytecode").unwrap();

    let report = scan_with_policy(
        &[root.to_owned()],
        &[],
        None,
        Some(&[Ecosystem::Python]),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();

    assert!(report.candidates.is_empty());
    assert!(!report.is_complete());
    assert!(report.warnings.iter().any(|warning| {
        warning.contains(&target.display().to_string())
            && warning.contains("nested projects may not be detected")
    }));
    assert!(nested.join("pyproject.toml").is_file());
    assert_eq!(fs::read(&cache).unwrap(), b"bytecode");
}

#[test]
fn nested_other_ecosystem_preserves_enclosing_python_context() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let javascript = root.join("frontend");
    let nested_python = javascript.join("service");
    fs::create_dir_all(javascript.join("src/__pycache__")).unwrap();
    fs::create_dir_all(nested_python.join("__pycache__")).unwrap();
    fs::write(root.join("pyproject.toml"), "[project]").unwrap();
    fs::write(javascript.join("package.json"), "{}").unwrap();
    fs::write(nested_python.join("pyproject.toml"), "[project]").unwrap();
    let report = scan(&[root.to_owned()]).unwrap();
    assert_eq!(report.candidates.len(), 2);
    let outer = report
        .candidates
        .iter()
        .find(|candidate| candidate.target == javascript.join("src/__pycache__"))
        .unwrap();
    assert_eq!(outer.project_root, root);
    let inner = report
        .candidates
        .iter()
        .find(|candidate| candidate.target == nested_python.join("__pycache__"))
        .unwrap();
    assert_eq!(inner.project_root, nested_python);
}

#[cfg(unix)]
#[test]
fn preview_flags_candidate_that_became_a_project() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    let report = scan(&[dir.path().to_owned()]).unwrap();
    fs::write(target.join("Cargo.toml"), "[package]").unwrap();
    let plan = upkit::sweep::preview(report, &[]).unwrap();
    assert_eq!(plan.items[0].identity_status, "changed_or_unavailable");
    assert!(!plan.items[0].execution_ready);
}

#[test]
fn scan_and_preview_flag_nested_project_and_repository_markers() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    fs::create_dir_all(target.join("nested/.git")).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    fs::write(target.join("nested/package.json"), "{}").unwrap();
    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(
        report.candidates[0].nested_project_marker.as_deref(),
        Some(target.join("nested/package.json").as_path())
    );
    assert_eq!(
        report.candidates[0].nested_vcs_marker.as_deref(),
        Some(target.join("nested/.git").as_path())
    );
    let json = serde_json::to_value(&report).unwrap();
    assert!(
        std::path::Path::new(
            json["candidates"][0]["nested_project_marker"]
                .as_str()
                .unwrap()
        )
        .ends_with(std::path::Path::new("nested").join("package.json"))
    );
    let plan = upkit::sweep::preview(report, &[]).unwrap();
    assert!(plan.items[0].risk.contains("do not remove"));
    assert!(!plan.items[0].execution_ready);
    assert!(target.join("nested/package.json").exists());
}

#[test]
fn go_workspace_marker_blocks_artifact_preview() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    let workspace = target.join("nested/go.work");
    fs::create_dir_all(workspace.parent().unwrap()).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    fs::write(&workspace, "go 1.24\n").unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(
        report.candidates[0].nested_project_marker.as_deref(),
        Some(workspace.as_path())
    );
    let plan = upkit::sweep::preview(report, &[]).unwrap();
    assert!(plan.items[0].risk.contains("do not remove"));
    assert!(!plan.items[0].execution_ready);
    assert!(workspace.is_file());
}

#[cfg(unix)]
#[test]
fn preview_reports_hard_links_without_touching_external_file() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    let original = dir.path().join("source.txt");
    let linked = target.join("linked");
    fs::write(&original, b"source data").unwrap();
    fs::hard_link(&original, &linked).unwrap();
    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert_eq!(
        report.candidates[0].hard_link_marker.as_deref(),
        Some(linked.as_path())
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json["candidates"][0]["hard_link_marker"],
        linked.to_str().unwrap()
    );
    let plan = upkit::sweep::preview(report, &[]).unwrap();
    assert!(plan.items[0].risk.contains("hard-linked"));
    assert!(!plan.items[0].execution_ready);
    assert_eq!(fs::read(&original).unwrap(), b"source data");
}

#[cfg(windows)]
#[test]
fn windows_scan_reports_fixture_hard_links_without_claiming_allocated_space() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    let original = dir.path().join("source.txt");
    let linked = target.join("linked");
    fs::write(&original, b"source data").unwrap();
    fs::hard_link(&original, &linked).unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    let candidate = &report.candidates[0];
    assert_eq!(
        candidate.hard_link_marker.as_deref(),
        Some(linked.as_path())
    );
    assert_eq!(candidate.logical_bytes, b"source data".len() as u64);
    assert!(candidate.allocated_bytes.is_none());
    assert!(candidate.size_complete);
    assert_eq!(fs::read(&original).unwrap(), b"source data");
}

#[cfg(unix)]
#[test]
fn preview_flags_symlink_without_following_or_modifying_target() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    let external = dir.path().join("external");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("source"), b"keep").unwrap();
    let link = target.join("link");
    symlink(&external, &link).unwrap();
    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert_eq!(
        report.candidates[0].symlink_marker.as_deref(),
        Some(link.as_path())
    );
    assert_eq!(report.candidates[0].logical_bytes, 0);
    let plan = upkit::sweep::preview(report, &[]).unwrap();
    assert!(plan.items[0].risk.contains("symbolic link"));
    assert!(!plan.items[0].execution_ready);
    assert_eq!(fs::read(external.join("source")).unwrap(), b"keep");
}

#[test]
fn json_scan_is_read_only() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    fs::create_dir_all(project.join("target")).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
    fs::write(project.join("target/keep"), "data").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "sweep", "scan"])
        .arg(&project)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("isolated-config"))
        .env("APPDATA", dir.path().join("isolated-config"))
        .env("XDG_DATA_HOME", dir.path())
        .env("SHELL", "bash")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["candidates"][0]["ecosystem"], "cargo");
    assert_eq!(report["candidates"][0]["logical_bytes"], 4);
    #[cfg(target_os = "linux")]
    assert_eq!(report["complete"], true);
    assert_eq!(
        fs::read_to_string(project.join("target/keep")).unwrap(),
        "data"
    );
    assert!(!dir.path().join(".bashrc").exists());
    assert!(!dir.path().join("upkit").exists());
}

#[test]
fn json_scan_reports_incomplete_when_a_target_is_ambiguous() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    fs::create_dir_all(project.join("target")).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]\n").unwrap();
    fs::write(project.join("pom.xml"), "<project/>\n").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--offline", "--json", "sweep", "scan"])
        .arg(&project)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("APPDATA", dir.path().join("config"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["complete"], false);
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                warning
                    .as_str()
                    .is_some_and(|text| text.contains("ambiguous"))
            })
    );
    assert!(project.join("target").is_dir());
}

#[test]
fn exclusions_apply_to_discovery_and_size_estimates() {
    use std::sync::atomic::AtomicBool;
    use upkit::sweep::scan_with;
    let dir = tempdir().unwrap();
    let root = dir.path().join("workspace");
    fs::create_dir_all(root.join("app/target/private")).unwrap();
    fs::write(root.join("app/Cargo.toml"), "[workspace]").unwrap();
    fs::write(root.join("app/target/public"), b"123").unwrap();
    fs::write(root.join("app/target/private/secret"), b"12345").unwrap();
    fs::create_dir_all(root.join("skip/target")).unwrap();
    fs::write(root.join("skip/Cargo.toml"), "[workspace]").unwrap();
    let report = scan_with(
        &[root.clone(), root.join("skip")],
        &["skip".into(), "app/target/private".into()],
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].logical_bytes, 3);
    assert!(!report.candidates[0].size_complete);
    assert!(!report.cancelled);
    let plan = upkit::sweep::preview(report, &[]).unwrap();
    assert!(plan.items[0].risk.contains("incomplete artifact inventory"));
    assert!(
        scan_with(
            &[root],
            &["../outside".into()],
            &AtomicBool::new(false),
            |_| {}
        )
        .is_err()
    );
}

#[test]
fn glob_exclusions_skip_projects_and_mark_partial_sizes() {
    use std::sync::atomic::AtomicBool;
    let dir = tempdir().unwrap();
    let root = dir.path();
    for project in ["keep", "skip-one"] {
        fs::create_dir_all(root.join(project).join("target/private")).unwrap();
        fs::write(root.join(project).join("Cargo.toml"), "[workspace]").unwrap();
        fs::write(root.join(project).join("target/public"), b"123").unwrap();
        fs::write(root.join(project).join("target/private/secret"), b"secret").unwrap();
    }
    let report = upkit::sweep::scan_with(
        &[root.to_owned()],
        &["glob:skip-*".into(), "glob:**/target/private".into()],
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].logical_bytes, 3);
    assert!(!report.candidates[0].size_complete);
    assert!(root.join("skip-one/target/private/secret").exists());
    for pattern in ["glob:", "glob:../outside", "glob:["] {
        assert!(
            upkit::sweep::scan_with(
                &[root.to_owned()],
                &[pattern.into()],
                &AtomicBool::new(false),
                |_| {}
            )
            .is_err()
        );
    }
}

#[test]
fn discovers_ninja_build_state_for_inspection_only() {
    use std::sync::atomic::AtomicBool;
    use upkit::sweep::{Ecosystem, scan_with_policy};

    assert_eq!(
        serde_json::from_str::<Ecosystem>("\"ninja\"").unwrap(),
        Ecosystem::Ninja
    );
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let target = project.join("build");
    let unrelated = dir.path().join("unrelated/build");
    let unmarked = dir.path().join("unmarked");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&unrelated).unwrap();
    fs::create_dir_all(unmarked.join("build")).unwrap();
    fs::write(project.join("build.ninja"), "build fixture: phony\n").unwrap();
    fs::write(target.join(".ninja_log"), "# ninja log v5\n").unwrap();
    fs::write(target.join("source.cpp"), "user source").unwrap();
    fs::write(unrelated.join(".ninja_log"), "# ninja log v5\n").unwrap();
    fs::write(unmarked.join("build.ninja"), "build fixture: phony\n").unwrap();
    #[cfg(unix)]
    {
        let linked_project = dir.path().join("linked");
        fs::create_dir_all(linked_project.join("build")).unwrap();
        std::os::unix::fs::symlink(
            project.join("build.ninja"),
            linked_project.join("build.ninja"),
        )
        .unwrap();
        fs::write(linked_project.join("build/.ninja_log"), "# ninja log v5\n").unwrap();
        std::os::unix::fs::symlink(target.join(".ninja_log"), unmarked.join("build/.ninja_log"))
            .unwrap();
    }
    let roots = vec![dir.path().to_owned()];
    let scan = |enabled: Option<&[Ecosystem]>| {
        scan_with_policy(&roots, &[], None, enabled, &AtomicBool::new(false), |_| {}).unwrap()
    };
    let report = scan(Some(&[Ecosystem::Ninja]));
    assert_eq!(report.candidates.len(), 1);
    let candidate = &report.candidates[0];
    assert_eq!(candidate.target, target);
    assert_eq!(candidate.ecosystem, "ninja");
    assert_eq!(candidate.classification, "review");
    assert_eq!(candidate.operation, "inspection only");
    assert!(
        candidate
            .reproduction_warning
            .unwrap()
            .contains("user files")
    );
    let plan = upkit::sweep::preview(report, std::slice::from_ref(&target)).unwrap();
    assert!(!plan.items[0].execution_ready);
    assert!(scan(Some(&[Ecosystem::Cargo])).candidates.is_empty());
    let stale = scan(None);
    fs::remove_file(target.join(".ninja_log")).unwrap();
    let plan = upkit::sweep::preview(stale, std::slice::from_ref(&target)).unwrap();
    assert_eq!(plan.items[0].identity_status, "changed_or_unavailable");
    fs::write(target.join(".ninja_log"), "# ninja log v5\n").unwrap();

    #[cfg(target_os = "linux")]
    {
        let scope = upkit::sweep::Scope {
            roots,
            exclusions: vec![],
            older_than_seconds: None,
            enabled: None,
        };
        let error =
            upkit::artifact_cleanup::preview(&scope, &target, &AtomicBool::new(false)).unwrap_err();
        assert!(format!("{error:#}").contains("inspection-only"));
    }
    assert_eq!(fs::read(target.join("source.cpp")).unwrap(), b"user source");
}

#[test]
fn discovers_custom_cmake_and_meson_build_directories_with_metadata() {
    use std::sync::atomic::AtomicBool;
    let dir = tempdir().unwrap();
    let cmake = dir.path().join("cmake");
    let meson = dir.path().join("meson");
    fs::create_dir_all(cmake.join("out-debug")).unwrap();
    fs::create_dir_all(cmake.join("source")).unwrap();
    fs::create_dir_all(meson.join("out-release/meson-private")).unwrap();
    fs::write(cmake.join("CMakeLists.txt"), "project(fixture)").unwrap();
    fs::write(cmake.join("out-debug/CMakeCache.txt"), "fixture").unwrap();
    fs::write(cmake.join("out-debug/build.ninja"), "generated fixture").unwrap();
    fs::write(cmake.join("source/source.cpp"), "source").unwrap();
    fs::write(meson.join("meson.build"), "project('fixture')").unwrap();
    fs::write(
        meson.join("out-release/meson-private/coredata.dat"),
        "fixture",
    )
    .unwrap();
    let report = upkit::sweep::scan_with(
        &[dir.path().to_owned()],
        &[],
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(report.candidates.len(), 2);
    for (target, ecosystem) in [
        (cmake.join("out-debug"), "cmake"),
        (meson.join("out-release"), "meson"),
    ] {
        let candidate = report
            .candidates
            .iter()
            .find(|candidate| candidate.target == target)
            .unwrap();
        assert_eq!(candidate.ecosystem, ecosystem);
        assert_eq!(candidate.classification, "review");
    }
    assert!(cmake.join("source/source.cpp").exists());
    assert!(
        meson
            .join("out-release/meson-private/coredata.dat")
            .exists()
    );
}

#[test]
fn discovers_nested_c_family_build_metadata_for_review_without_crossing_projects() {
    let dir = tempdir().unwrap();
    let cmake = dir.path().join("cmake");
    let cmake_output = cmake.join("apps/api/generated-output");
    let nested_cmake = cmake.join("subproject");
    let go = cmake.join("tools/go-service");
    let meson = dir.path().join("meson");
    let meson_output = meson.join("components/core/generated-output");
    fs::create_dir_all(&cmake_output).unwrap();
    fs::create_dir_all(nested_cmake.join("out")).unwrap();
    fs::create_dir_all(go.join("build")).unwrap();
    fs::create_dir_all(meson_output.join("meson-private")).unwrap();
    fs::write(cmake.join("CMakeLists.txt"), "project(fixture)").unwrap();
    fs::write(cmake_output.join("CMakeCache.txt"), "fixture").unwrap();
    fs::write(cmake_output.join("source.cpp"), "user source").unwrap();
    fs::write(nested_cmake.join("CMakeLists.txt"), "project(subproject)").unwrap();
    fs::write(nested_cmake.join("out/CMakeCache.txt"), "fixture").unwrap();
    fs::write(go.join("go.mod"), "module example.invalid/service\n").unwrap();
    fs::write(go.join("build/CMakeCache.txt"), "not its parent's output").unwrap();
    fs::write(meson.join("meson.build"), "project('fixture')").unwrap();
    fs::write(meson_output.join("meson-private/coredata.dat"), "fixture").unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    assert_eq!(report.candidates.len(), 4);
    for (target, project_root, ecosystem) in [
        (cmake_output.clone(), cmake.clone(), "cmake"),
        (nested_cmake.join("out"), nested_cmake, "cmake"),
        (meson_output.clone(), meson.clone(), "meson"),
    ] {
        let candidate = report
            .candidates
            .iter()
            .find(|candidate| candidate.target == target)
            .unwrap();
        assert_eq!(candidate.project_root, project_root);
        assert_eq!(candidate.ecosystem, ecosystem);
        assert_eq!(candidate.classification, "review");
        assert!(
            candidate
                .reproduction_warning
                .unwrap()
                .contains("user files")
        );
    }
    let go_build = report
        .candidates
        .iter()
        .find(|candidate| candidate.target == go.join("build"))
        .unwrap();
    assert_eq!(go_build.project_root, go);
    assert_eq!(go_build.ecosystem, "go");
    assert_eq!(go_build.classification, "review");
    assert!(
        go_build
            .reproduction_warning
            .is_some_and(|warning| { warning.contains("removal is unsupported") })
    );
    #[cfg(target_os = "linux")]
    {
        let scope = upkit::sweep::Scope {
            roots: vec![dir.path().to_owned()],
            exclusions: Vec::new(),
            older_than_seconds: None,
            enabled: None,
        };
        let error = upkit::artifact_cleanup::preview(
            &scope,
            &go_build.target,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("inspection-only"));
    }

    let plan = upkit::sweep::preview(report, std::slice::from_ref(&cmake_output)).unwrap();
    let item = plan
        .items
        .iter()
        .find(|item| item.candidate.target == cmake_output)
        .unwrap();
    assert_eq!(item.identity_status, "metadata_match");
    assert_eq!(item.risk, "potentially destructive");
    assert!(!item.execution_ready);
    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("user files"))
    );
    assert_eq!(
        fs::read_to_string(cmake_output.join("source.cpp")).unwrap(),
        "user source"
    );
}

#[test]
fn cancellation_stops_scanning_and_is_reported() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use upkit::sweep::scan_with;
    let dir = tempdir().unwrap();
    fs::create_dir_all(dir.path().join("project/target")).unwrap();
    fs::write(dir.path().join("project/Cargo.toml"), "[workspace]").unwrap();
    let cancelled = AtomicBool::new(false);
    let mut visits = 0;
    let report = scan_with(&[dir.path().to_owned()], &[], &cancelled, |_| {
        visits += 1;
        cancelled.store(true, Ordering::Relaxed);
    })
    .unwrap();
    assert_eq!(visits, 1);
    assert!(report.cancelled);
    assert!(report.candidates.is_empty());
}

#[test]
fn cancellation_during_size_estimation_marks_partial_candidate_incomplete() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use upkit::sweep::scan_with;

    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let target = project.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
    fs::write(target.join("artifact"), b"fixture artifact").unwrap();

    let cancelled = AtomicBool::new(false);
    let mut target_visits = 0;
    let report = scan_with(&[dir.path().to_owned()], &[], &cancelled, |path| {
        if path == target {
            target_visits += 1;
            if target_visits == 2 {
                cancelled.store(true, Ordering::Relaxed);
            }
        }
    })
    .unwrap();

    assert!(report.cancelled);
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.target == target)
        .expect("partially measured target remains in the report");
    assert!(!candidate.size_complete);
    assert_eq!(candidate.logical_bytes, 0);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| { warning.contains("scan cancelled during size estimation") })
    );
    assert!(target.join("artifact").is_file());
}

#[cfg(windows)]
#[test]
fn scan_stays_on_the_verified_root_volume_for_descendant_directories() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let target = project.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]\n").unwrap();

    let report = scan(&[dir.path().to_owned()]).unwrap();
    // Scan roots are canonicalized, including the extended-length Windows
    // prefix (\\?\C:\). The fixture's original path spelling need
    // not compare equal to a discovered canonical candidate.
    let canonical_target = target.canonicalize().unwrap();
    let warning_kinds: Vec<_> = report
        .warnings
        .iter()
        .map(|warning| {
            if warning.contains("volume differs or could not be verified") {
                "volume_guard"
            } else if warning.contains("filesystem boundary") {
                "filesystem_boundary"
            } else if warning.contains("Cargo target-dir configuration") {
                "cargo_configuration_unresolved"
            } else {
                "other"
            }
        })
        .collect();
    assert!(
        report
            .candidates
            .iter()
            .any(|candidate| candidate.target == canonical_target),
        "canonical target missing; candidates={}, warning kinds={warning_kinds:?}",
        report.candidates.len()
    );
    assert!(
        !warning_kinds.contains(&"volume_guard"),
        "same-volume fixture was rejected: {warning_kinds:?}"
    );
}

#[test]
fn cli_exclude_filters_json_results() {
    let dir = tempdir().unwrap();
    fs::create_dir_all(dir.path().join("skip/target")).unwrap();
    fs::write(dir.path().join("skip/Cargo.toml"), "[workspace]").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "sweep", "scan", "--exclude", "skip"])
        .arg(dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("isolated-config"))
        .env("APPDATA", dir.path().join("isolated-config"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["candidates"].as_array().unwrap().is_empty());
    assert_eq!(report["cancelled"], false);
}

#[cfg(unix)]
#[test]
fn text_report_escapes_control_characters_in_paths() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project\u{1b}[2J");
    fs::create_dir_all(project.join("target")).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--non-interactive", "sweep", "scan"])
        .arg(&project)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("isolated-config"))
        .env("APPDATA", dir.path().join("isolated-config"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!output.stdout.contains(&0x1b));
    assert!(String::from_utf8_lossy(&output.stdout).contains("%1B"));
}

#[cfg(unix)]
#[test]
fn text_report_distinguishes_non_utf8_and_literal_escape_paths() {
    use std::os::unix::ffi::OsStringExt;
    let dir = tempdir().unwrap();
    for name in [
        b"project-\xff".as_slice(),
        b"project-%FF",
        "project-�".as_bytes(),
    ] {
        let project = dir.path().join(std::ffi::OsString::from_vec(name.to_vec()));
        fs::create_dir_all(project.join("target")).unwrap();
        fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--non-interactive", "sweep", "scan"])
        .arg(dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("isolated-config"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "project-%FF/target",
        "project-%25FF/target",
        "project-%EF%BF%BD/target",
    ] {
        assert!(text.contains(expected), "missing {expected} in {text}");
    }
}

#[cfg(windows)]
#[test]
fn display_path_distinguishes_unpaired_surrogates_and_literal_escapes() {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf};
    let unpaired = PathBuf::from(OsString::from_wide(&[b'a' as u16, 0xd800]));
    let literal = PathBuf::from("a%uD800");
    assert_eq!(upkit::sweep::display_path(&unpaired), "a%uD800");
    assert_eq!(upkit::sweep::display_path(&literal), "a%u0025uD800");
}

#[cfg(unix)]
#[test]
fn scan_and_preview_json_preserve_non_unicode_paths() {
    use std::os::unix::{ffi::OsStringExt, fs::symlink};
    let dir = tempdir().unwrap();
    let root = dir
        .path()
        .join(std::ffi::OsString::from_vec(b"workspace-\xff%".to_vec()));
    let project = root.join("member");
    let target = project.join("target");
    let unicode_project = dir.path().join("unicode-%FF");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(unicode_project.join("target")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = ['member']\n",
    )
    .unwrap();
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname='member'\nversion='0.1.0'\n",
    )
    .unwrap();
    fs::write(unicode_project.join("Cargo.toml"), "[workspace]\n").unwrap();
    let link = target.join(std::ffi::OsString::from_vec(b"link-\xfe%".to_vec()));
    symlink("missing", &link).unwrap();
    let decode = |value: &serde_json::Value| {
        assert_eq!(value["encoding"], "unix-percent-bytes");
        let text = value["value"].as_str().unwrap().as_bytes();
        let mut bytes = Vec::new();
        let mut i = 0;
        while i < text.len() {
            if text[i] == b'%' {
                let digits = std::str::from_utf8(&text[i + 1..i + 3]).unwrap();
                bytes.push(u8::from_str_radix(digits, 16).unwrap());
                i += 3;
            } else {
                bytes.push(text[i]);
                i += 1;
            }
        }
        std::path::PathBuf::from(std::ffi::OsString::from_vec(bytes))
    };
    let run = |preview: bool| {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"));
        cmd.args([
            "--non-interactive",
            "--json",
            "sweep",
            if preview { "preview" } else { "scan" },
        ])
        .arg(&root)
        .arg(&unicode_project)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("isolated-config"));
        if preview {
            cmd.arg("--select").arg(&target);
        }
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let scan = run(false);
    assert!(
        scan["roots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.is_object() && decode(v) == root)
    );
    let candidates = scan["candidates"].as_array().unwrap();
    let item = candidates
        .iter()
        .find(|v| v["target"].is_object() && decode(&v["target"]) == target)
        .unwrap();
    assert_eq!(decode(&item["project_root"]), project);
    assert_eq!(decode(&item["symlink_marker"]), link);
    #[cfg(target_os = "linux")]
    assert_eq!(decode(&item["cargo_workspace"]["workspace_root"]), root);
    assert!(
        candidates
            .iter()
            .any(|v| v["target"] == unicode_project.join("target").to_str().unwrap())
    );
    let preview = run(true);
    assert!(
        preview["roots"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.is_object() && decode(v) == root)
    );
    let selected = preview["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["selected"] == true)
        .unwrap();
    assert_eq!(decode(&selected["candidate"]["target"]), target);
    assert!(link.is_symlink());
}

#[cfg(windows)]
#[test]
fn scan_report_json_preserves_unpaired_surrogates() {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf};
    let root = PathBuf::from(OsString::from_wide(&[b'a' as u16, 0xd800]));
    let report = upkit::sweep::ScanReport {
        roots: vec![root, PathBuf::from("a%uD800")],
        candidates: vec![],
        warnings: vec![],
        cancelled: false,
    };
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(value["roots"][0]["encoding"], "windows-percent-utf16");
    assert_eq!(value["roots"][0]["value"], "a%uD800");
    assert_eq!(value["roots"][1], "a%uD800");
}

#[test]
fn age_parser_rejects_bad_inputs_without_panicking() {
    use std::time::Duration;
    use upkit::sweep::parse_age;
    assert_eq!(parse_age("30d").unwrap(), Duration::from_secs(30 * 86400));
    assert_eq!(parse_age("2h").unwrap(), Duration::from_secs(7200));
    for bad in ["", "é", "3", "-1d", "1y", "18446744073709551615w"] {
        assert!(parse_age(bad).is_err(), "{bad}");
    }
}

#[cfg(unix)]
#[test]
fn age_filter_uses_newest_descendant_and_deduplicates_allocated_hardlinks() {
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, SystemTime};
    use upkit::sweep::scan_with_age;
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    let file = target.join("one");
    fs::write(&file, b"hello").unwrap();
    fs::hard_link(&file, target.join("two")).unwrap();
    let old = SystemTime::now() - Duration::from_secs(40 * 86400);
    let times = fs::FileTimes::new().set_modified(old);
    fs::File::open(&file).unwrap().set_times(times).unwrap();
    fs::File::open(&target).unwrap().set_times(times).unwrap();
    let age = Some(Duration::from_secs(30 * 86400));
    let report = scan_with_age(
        &[dir.path().to_owned()],
        &[],
        age,
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(report.candidates.len(), 1);
    let candidate = &report.candidates[0];
    assert_eq!(candidate.logical_bytes, 10);
    assert_eq!(
        candidate.allocated_bytes,
        Some(fs::metadata(&file).unwrap().blocks() * 512)
    );
    assert!(candidate.modified_unix.is_some());
    fs::write(target.join("new"), b"new").unwrap();
    let report = scan_with_age(
        &[dir.path().to_owned()],
        &[],
        age,
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert!(report.candidates.is_empty());
}

#[test]
fn age_filter_keeps_normal_artifacts_when_cache_estimates_are_platform_limited() {
    use std::{sync::atomic::AtomicBool, time::Duration};
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    fs::write(target.join("output"), b"fixture").unwrap();

    let report = upkit::sweep::scan_with_age(
        &[dir.path().to_owned()],
        &[],
        Some(Duration::ZERO),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();

    assert_eq!(report.candidates.len(), 1);
    assert!(report.candidates[0].modified_unix.is_some());
    assert!(report.candidates[0].size_complete);
}

#[cfg(unix)]
#[test]
fn special_files_make_measurement_and_age_incomplete() {
    use std::{os::unix::net::UnixListener, sync::atomic::AtomicBool, time::Duration};
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    let socket_path = target.join("socket");
    let _socket = UnixListener::bind(&socket_path).unwrap();
    let report = upkit::sweep::scan_with_age(
        &[dir.path().to_owned()],
        &[],
        None,
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert!(!report.candidates[0].size_complete);
    assert!(report.candidates[0].modified_unix.is_none());
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("special file skipped"))
    );
    let filtered = upkit::sweep::scan_with_age(
        &[dir.path().to_owned()],
        &[],
        Some(Duration::ZERO),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert!(filtered.candidates.is_empty());
    assert!(
        filtered
            .warnings
            .iter()
            .any(|warning| warning.contains("age could not be verified"))
    );
    assert!(socket_path.exists());
}

#[test]
fn age_filter_does_not_treat_excluded_contents_as_old() {
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;
    use upkit::sweep::scan_with_age;
    let dir = tempdir().unwrap();
    fs::create_dir_all(dir.path().join("target/private")).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    let report = scan_with_age(
        &[dir.path().to_owned()],
        &["target/private".into()],
        Some(Duration::ZERO),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    assert!(report.candidates.is_empty());
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("age could not be verified"))
    );
}

#[test]
fn cli_age_filter_and_invalid_age() {
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join("target")).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    let run = |age: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(["--json", "sweep", "scan", "--older-than", age])
            .arg(dir.path())
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("isolated-config"))
            .env("APPDATA", dir.path().join("isolated-config"))
            .output()
            .unwrap()
    };
    let output = run("100000d");
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["candidates"].as_array().unwrap().is_empty());
    assert!(!run("é").status.success());
}

#[test]
fn parallel_scan_reports_all_candidates_with_bounded_workers() {
    use std::collections::HashSet;
    use std::sync::atomic::AtomicBool;
    use upkit::sweep::scan_with;
    let dir = tempdir().unwrap();
    for index in 0..80 {
        let project = dir.path().join(format!("project-{index}"));
        fs::create_dir_all(project.join("target")).unwrap();
        fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
        fs::write(project.join("target/file"), b"fixture").unwrap();
    }
    let mut workers = HashSet::new();
    let report = scan_with(
        &[dir.path().to_owned()],
        &[],
        &AtomicBool::new(false),
        |_| {
            workers.insert(std::thread::current().id());
        },
    )
    .unwrap();
    assert_eq!(report.candidates.len(), 80);
    assert!(
        report
            .candidates
            .iter()
            .all(|candidate| candidate.logical_bytes == 7)
    );
    assert!(!workers.is_empty() && workers.len() <= 4);
    assert!(
        report
            .candidates
            .windows(2)
            .all(|pair| pair[0].target < pair[1].target)
    );
}

#[test]
fn progress_callback_panic_does_not_deadlock_workers() {
    use std::sync::atomic::AtomicBool;
    use upkit::sweep::scan_with;
    let dir = tempdir().unwrap();
    for index in 0..8 {
        fs::create_dir(dir.path().join(format!("p{index}"))).unwrap();
    }
    let result = scan_with(
        &[dir.path().to_owned()],
        &[],
        &AtomicBool::new(false),
        |_| panic!("fixture panic"),
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("scan worker panicked")
    );
}

#[test]
fn parallel_cancellation_preserves_partial_report_and_files() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use upkit::sweep::scan_with;
    let dir = tempdir().unwrap();
    for index in 0..40 {
        let project = dir.path().join(format!("p{index}"));
        fs::create_dir_all(project.join("target")).unwrap();
        fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
        fs::write(project.join("target/keep"), "fixture").unwrap();
    }
    let cancel = AtomicBool::new(false);
    let mut visits = 0;
    let report = scan_with(&[dir.path().to_owned()], &[], &cancel, |_| {
        visits += 1;
        if visits >= 8 {
            cancel.store(true, Ordering::Relaxed);
        }
    })
    .unwrap();
    assert!(report.cancelled);
    assert!(visits >= 8);
    assert!(report.candidates.len() < 40);
    assert_eq!(
        fs::read_to_string(dir.path().join("p0/target/keep")).unwrap(),
        "fixture"
    );
}

#[test]
fn preview_requires_explicit_discovered_targets_and_never_deletes() {
    use upkit::sweep::preview;
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let target = project.join("target");
    let outside = dir.path().join("outside");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
    fs::write(target.join("keep"), "fixture").unwrap();
    let plan = preview(scan(std::slice::from_ref(&project)).unwrap(), &[]).unwrap();
    assert_eq!(plan.items.len(), 1);
    assert!(!plan.items[0].selected);
    assert_eq!(plan.items[0].git_history_status, "not_checked");
    assert!(!plan.items[0].execution_ready);
    assert!(
        plan.items[0]
            .safeguards_required
            .iter()
            .any(|s| s.contains("active build"))
    );
    let plan = preview(
        scan(std::slice::from_ref(&project)).unwrap(),
        std::slice::from_ref(&target),
    )
    .unwrap();
    assert!(plan.items[0].selected);
    assert_ne!(plan.items[0].git_history_status, "not_checked");
    assert_eq!(plan.items[0].candidate.logical_bytes, 7);
    assert!(preview(scan(std::slice::from_ref(&project)).unwrap(), &[outside]).is_err());
    let mut cancelled = scan(std::slice::from_ref(&project)).unwrap();
    cancelled.cancelled = true;
    assert!(preview(cancelled, &[]).is_err());
    let report = scan(std::slice::from_ref(&project)).unwrap();
    let cancel = std::sync::atomic::AtomicBool::new(true);
    assert!(upkit::sweep::preview_with_cancel(report, &[], &cancel).is_err());
    assert_eq!(fs::read_to_string(target.join("keep")).unwrap(), "fixture");
}

#[cfg(unix)]
#[test]
fn preview_rejects_a_replaced_target_symlink() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let target = project.join("target");
    let outside = dir.path().join("outside");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
    fs::write(outside.join("keep"), "fixture").unwrap();
    let report = scan(&[project]).unwrap();
    fs::remove_dir(&target).unwrap();
    symlink(&outside, &target).unwrap();
    assert!(upkit::sweep::preview(report, &[target]).is_err());
    assert_eq!(fs::read_to_string(outside.join("keep")).unwrap(), "fixture");
}

#[test]
fn cli_preview_json_selects_only_the_requested_candidate() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let target = project.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
    fs::write(target.join("keep"), "fixture").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "sweep", "preview", "--select"])
        .arg(&target)
        .arg(&project)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("APPDATA", dir.path().join("config"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["items"][0]["selected"], true);
    assert_eq!(plan["items"][0]["execution_ready"], false);
    assert_eq!(plan["items"][0]["candidate"]["ecosystem"], "cargo");
    #[cfg(unix)]
    assert_eq!(plan["items"][0]["identity_status"], "metadata_match");
    #[cfg(not(unix))]
    assert_eq!(plan["items"][0]["identity_status"], "unavailable");
    assert_eq!(fs::read_to_string(target.join("keep")).unwrap(), "fixture");
}

#[cfg(unix)]
#[test]
fn preview_detects_changed_manifest_and_replaced_directory() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("Cargo.toml");
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(&manifest, "[workspace]\n").unwrap();
    let report = scan(&[dir.path().to_owned()]).unwrap();
    let plan = upkit::sweep::preview(report, &[]).unwrap();
    assert_eq!(plan.items[0].identity_status, "metadata_match");
    assert!(!plan.items[0].execution_ready);

    let report = scan(&[dir.path().to_owned()]).unwrap();
    fs::write(
        &manifest,
        "[package]\nname = 'changed'\nversion = '0.1.0'\n",
    )
    .unwrap();
    let plan = upkit::sweep::preview(report, &[]).unwrap();
    assert_eq!(plan.items[0].identity_status, "changed_or_unavailable");
    assert!(plan.items[0].risk.contains("identity changed"));

    let report = scan(&[dir.path().to_owned()]).unwrap();
    fs::rename(&target, dir.path().join("old-target")).unwrap();
    fs::create_dir(&target).unwrap();
    let plan = upkit::sweep::preview(report, std::slice::from_ref(&target)).unwrap();
    assert_eq!(plan.items[0].identity_status, "changed_or_unavailable");
    assert!(plan.items[0].selected);
    assert!(!plan.items[0].execution_ready);
    assert!(target.exists());
}

#[cfg(not(unix))]
#[test]
fn preview_reports_unavailable_platform_identity() {
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join("target")).unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[workspace]").unwrap();
    let plan = upkit::sweep::preview(scan(&[dir.path().to_owned()]).unwrap(), &[]).unwrap();
    assert_eq!(plan.items[0].identity_status, "unavailable");
    assert!(!plan.items[0].execution_ready);
}

#[test]
fn preview_does_not_claim_identity_for_ambiguous_dotnet_projects() {
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join("obj")).unwrap();
    fs::write(dir.path().join("first.csproj"), "<Project />").unwrap();
    fs::write(dir.path().join("second.csproj"), "<Project />").unwrap();
    let plan = upkit::sweep::preview(scan(&[dir.path().to_owned()]).unwrap(), &[]).unwrap();
    assert_eq!(plan.items.len(), 1);
    assert_eq!(plan.items[0].identity_status, "unavailable");
    assert!(!plan.items[0].execution_ready);
}

#[cfg(unix)]
#[test]
fn preview_checks_git_index_without_running_fsmonitor_hooks() {
    use std::{os::unix::fs::PermissionsExt, process::Command};
    let Some(git) = system_git_path().filter(|_| which::which("git").is_ok()) else {
        return;
    };
    let version = Command::new(&git).arg("--version").output().unwrap();
    let text = String::from_utf8_lossy(&version.stdout);
    let parts = text
        .trim()
        .strip_prefix("git version ")
        .unwrap_or("")
        .split('.')
        .take(2)
        .map(|v| v.parse::<u32>().unwrap_or(0))
        .collect::<Vec<_>>();
    if parts.len() != 2 || parts[0] != 2 || parts[1] < 36 {
        return;
    }
    let system_path = std::env::join_paths([
        git.parent().unwrap(),
        std::path::Path::new("/usr/bin"),
        std::path::Path::new("/bin"),
    ])
    .unwrap();
    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let repo = dir.path().join("repo");
    let tracked = repo.join("tracked");
    let untracked = repo.join("untracked");
    fs::create_dir_all(tracked.join("Target")).unwrap();
    fs::create_dir_all(untracked.join("target")).unwrap();
    for project in [&tracked, &untracked] {
        fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
    }
    fs::write(tracked.join("Target/keep"), "fixture").unwrap();
    fs::write(untracked.join("target/keep"), "fixture").unwrap();
    let git_command = |args: &[&std::ffi::OsStr]| {
        Command::new(&git)
            .env_clear()
            .env("PATH", &system_path)
            .env("HOME", dir.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .args(args)
            .output()
            .unwrap()
    };
    let output = git_command(&["init".as_ref(), "-q".as_ref(), repo.as_os_str()]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = git_command(&[
        "-C".as_ref(),
        repo.as_os_str(),
        "add".as_ref(),
        "-f".as_ref(),
        "--".as_ref(),
        "tracked/Target/keep".as_ref(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::rename(tracked.join("Target"), tracked.join("target")).unwrap();
    let hook = repo.join(".git/hooks/monitor");
    let marker = dir.path().join("hook-ran");
    fs::write(&hook, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    let output = git_command(&[
        "-C".as_ref(),
        repo.as_os_str(),
        "config".as_ref(),
        "core.fsmonitor".as_ref(),
        hook.as_os_str(),
    ]);
    assert!(output.status.success());
    let trace = dir.path().join("git-trace");
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "sweep", "preview"])
        .arg(&repo)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("PATH", &system_path)
        .env("GIT_TRACE", &trace)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let items = plan["items"].as_array().unwrap();
    let tracked_canonical = tracked.canonicalize().unwrap();
    let untracked_canonical = untracked.canonicalize().unwrap();
    let tracked_item = items
        .iter()
        .find(|item| item["candidate"]["project_root"] == tracked_canonical.to_str().unwrap())
        .unwrap();
    let untracked_item = items
        .iter()
        .find(|item| item["candidate"]["project_root"] == untracked_canonical.to_str().unwrap())
        .unwrap();
    assert_eq!(tracked_item["git_index_status"], "tracked_in_index");
    assert!(
        tracked_item["risk"]
            .as_str()
            .unwrap()
            .contains("do not remove")
    );
    assert_eq!(
        untracked_item["git_index_status"],
        "no_matching_entries_in_git_index"
    );
    assert_eq!(untracked_item["git_head_status"], "unavailable");
    assert_eq!(tracked_item["execution_ready"], false);
    assert!(!marker.exists(), "preview executed a project hook");
    assert!(!trace.exists(), "preview passed GIT_TRACE to Git");
    assert_eq!(
        fs::read_to_string(tracked.join("target/keep")).unwrap(),
        "fixture"
    );
}

#[cfg(unix)]
#[test]
fn preview_does_not_execute_git_from_workspace() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let project = dir.path().join("workspace");
    let bin = project.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir(project.join("target")).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
    let marker = dir.path().join("executed");
    let fake_git = bin.join("git");
    fs::write(
        &fake_git,
        format!(
            "#!/bin/sh\nprintf x > '{}'\nprintf 'git version 2.43.0\\n'\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o755)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "sweep", "preview"])
        .arg(&project)
        .env("PATH", &bin)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["items"][0]["git_index_status"], "unavailable");
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn preview_does_not_query_old_git_versions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let project = dir.path().join("workspace");
    let bin = dir.path().join("mock-bin");
    fs::create_dir_all(project.join("target")).unwrap();
    fs::create_dir(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
    let marker = dir.path().join("queried");
    let fake_git = bin.join("git");
    fs::write(&fake_git, format!("#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'git version 2.35.9\\n'; else printf x > '{}'; fi\n", marker.display())).unwrap();
    fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o755)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "sweep", "preview"])
        .arg(&project)
        .env("PATH", &bin)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["items"][0]["git_index_status"], "unavailable");
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn preview_head_detects_staged_deletion_without_fetching_or_deleting_files() {
    use std::{ffi::OsStr, os::unix::fs::PermissionsExt, process::Command};
    let Some(git) = system_git_path() else {
        return;
    };
    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let system_path = std::env::join_paths([
        git.parent().unwrap(),
        std::path::Path::new("/usr/bin"),
        std::path::Path::new("/bin"),
    ])
    .unwrap();
    let repo = dir.path().join("repo");
    let tracked = repo.join("tracked");
    let untracked = repo.join("untracked");
    for project in [&tracked, &untracked] {
        fs::create_dir_all(project.join("target")).unwrap();
        fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
        fs::write(project.join("target/keep"), "fixture").unwrap();
    }
    let git_command = |args: &[&OsStr]| {
        Command::new(&git)
            .env_clear()
            .env("PATH", &system_path)
            .env("HOME", dir.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("user.name=Fixture")
            .arg("-c")
            .arg("user.email=fixture@example.invalid")
            .arg("-c")
            .arg("commit.gpgSign=false")
            .args(args)
            .output()
            .unwrap()
    };
    for args in [
        vec![OsStr::new("init"), OsStr::new("-q"), repo.as_os_str()],
        vec![
            OsStr::new("-C"),
            repo.as_os_str(),
            OsStr::new("add"),
            OsStr::new("-f"),
            OsStr::new("tracked/Cargo.toml"),
            OsStr::new("tracked/target/keep"),
            OsStr::new("untracked/Cargo.toml"),
        ],
        vec![
            OsStr::new("-C"),
            repo.as_os_str(),
            OsStr::new("commit"),
            OsStr::new("-qm"),
            OsStr::new("fixture"),
        ],
        vec![
            OsStr::new("-C"),
            repo.as_os_str(),
            OsStr::new("update-index"),
            OsStr::new("--force-remove"),
            OsStr::new("--"),
            OsStr::new("tracked/target/keep"),
        ],
    ] {
        let output = git_command(&args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let index_before = fs::read(repo.join(".git/index")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "sweep", "preview"])
        .arg(&repo)
        .env("PATH", &system_path)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let items = plan["items"].as_array().unwrap();
    let tracked_root = tracked.canonicalize().unwrap();
    let untracked_root = untracked.canonicalize().unwrap();
    let tracked_item = items
        .iter()
        .find(|item| item["candidate"]["project_root"] == tracked_root.to_str().unwrap())
        .unwrap();
    let untracked_item = items
        .iter()
        .find(|item| item["candidate"]["project_root"] == untracked_root.to_str().unwrap())
        .unwrap();
    assert_eq!(
        tracked_item["git_index_status"],
        "no_matching_entries_in_git_index"
    );
    assert_eq!(
        tracked_item["git_head_status"],
        "matching_entry_in_head_or_index"
    );
    assert!(
        tracked_item["risk"]
            .as_str()
            .unwrap()
            .contains("do not remove")
    );
    assert_eq!(
        untracked_item["git_head_status"],
        "no_matching_entries_in_head_or_index"
    );
    assert_eq!(
        fs::read_to_string(tracked.join("target/keep")).unwrap(),
        "fixture"
    );
    assert_eq!(
        fs::read_to_string(untracked.join("target/keep")).unwrap(),
        "fixture"
    );
    assert_eq!(fs::read(repo.join(".git/index")).unwrap(), index_before);
    let unborn = dir.path().join("unborn");
    fs::create_dir_all(unborn.join("target")).unwrap();
    fs::write(unborn.join("Cargo.toml"), "[workspace]").unwrap();
    assert!(
        git_command(&[OsStr::new("init"), OsStr::new("-q"), unborn.as_os_str()])
            .status
            .success()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "sweep", "preview"])
        .arg(&unborn)
        .env("PATH", &system_path)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["items"][0]["git_head_status"], "unavailable");
}

#[cfg(target_os = "linux")]
#[test]
fn preview_refuses_legacy_shell_git_without_execution() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let project = dir.path().join("workspace");
    let bin = dir.path().join("mock-bin");
    fs::create_dir_all(project.join("target")).unwrap();
    fs::create_dir(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(project.join("Cargo.toml"), "[workspace]").unwrap();
    let marker = dir.path().join("head-queried");
    let fake_git = bin.join("git");
    fs::write(
        &fake_git,
        format!("#!/bin/sh\nprintf x > '{}'\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o755)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "sweep", "preview"])
        .arg(&project)
        .env("PATH", &bin)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["items"][0]["git_index_status"], "unavailable");
    assert_eq!(plan["items"][0]["git_head_status"], "unavailable");
    assert!(
        !marker.exists(),
        "Linux must refuse a PATH shell script as Git"
    );
}

#[test]
fn disabled_ecosystem_is_not_inventoried_or_descended() {
    use std::sync::atomic::AtomicBool;
    use upkit::sweep::{Ecosystem, scan_with_policy};
    let dir = tempdir().unwrap();
    fs::create_dir_all(dir.path().join("rust/target/nested")).unwrap();
    fs::write(dir.path().join("rust/Cargo.toml"), "[workspace]").unwrap();
    fs::write(dir.path().join("rust/target/nested/keep"), "fixture").unwrap();
    fs::create_dir_all(dir.path().join("py/__pycache__")).unwrap();
    fs::write(dir.path().join("py/pyproject.toml"), "[project]").unwrap();
    let mut visited = Vec::new();
    let report = scan_with_policy(
        &[dir.path().to_owned()],
        &[],
        None,
        Some(&[Ecosystem::Python]),
        &AtomicBool::new(false),
        |path| visited.push(path.to_owned()),
    )
    .unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidates[0].ecosystem, "python");
    assert!(!visited.iter().any(|path| path.ends_with("target/nested")));
    assert_eq!(
        fs::read_to_string(dir.path().join("rust/target/nested/keep")).unwrap(),
        "fixture"
    );
}

#[test]
fn cargo_workspace_roots_are_rebuildable_and_members_or_exclusions_are_review_only() {
    let dir = tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let member = workspace.join("member");
    let excluded = workspace.join("excluded");
    for target in [
        workspace.join("target"),
        member.join("target"),
        excluded.join("target"),
    ] {
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("output"), b"fixture").unwrap();
    }
    fs::write(
        workspace.join("Cargo.toml"),
        "[workspace]\nmembers = ['member']\nexclude = ['excluded']\n",
    )
    .unwrap();
    fs::write(
        member.join("Cargo.toml"),
        "[package]\nname = 'member'\nversion = '0.1.0'\n",
    )
    .unwrap();
    fs::write(
        excluded.join("Cargo.toml"),
        "[package]\nname = 'excluded'\nversion = '0.1.0'\n",
    )
    .unwrap();

    let report = scan(std::slice::from_ref(&workspace)).unwrap();
    let candidate = |target: &std::path::Path| {
        report
            .candidates
            .iter()
            .find(|candidate| candidate.target == target)
            .unwrap()
    };
    let root = candidate(&workspace.join("target"));
    assert_eq!(root.classification, "rebuildable");
    assert_eq!(
        root.cargo_workspace.as_ref().unwrap().status,
        "workspace_manifest"
    );

    let member = candidate(&member.join("target"));
    assert_eq!(member.classification, "review");
    assert_eq!(
        member.cargo_workspace.as_ref().unwrap().status,
        "member_pattern_match"
    );
    assert!(
        member
            .reproduction_warning
            .unwrap()
            .contains("workspace root")
    );

    let excluded = candidate(&excluded.join("target"));
    assert_eq!(excluded.classification, "review");
    assert_eq!(
        excluded.cargo_workspace.as_ref().unwrap().status,
        "exclude_pattern_match"
    );
    assert!(excluded.reproduction_warning.unwrap().contains("exclusion"));
}

#[test]
fn standalone_cargo_package_is_rebuildable_after_full_ancestor_inspection() {
    let dir = tempdir().unwrap();
    let project = dir.path().join("project");
    let target = project.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("output"), b"fixture").unwrap();
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = 'project'\nversion = '0.1.0'\n",
    )
    .unwrap();

    let report = scan(std::slice::from_ref(&project)).unwrap();
    let candidate = report
        .candidates
        .iter()
        .find(|item| item.target == target)
        .unwrap();
    assert_eq!(candidate.classification, "rebuildable");
    assert_eq!(
        candidate.cargo_workspace.as_ref().unwrap().status,
        "standalone_package"
    );
    assert!(candidate.reproduction_warning.is_none());

    fs::write(project.join("Cargo.toml"), "[package]\n").unwrap();
    let invalid_package = scan(std::slice::from_ref(&project)).unwrap();
    let invalid_package = invalid_package
        .candidates
        .iter()
        .find(|item| item.target == target)
        .unwrap();
    assert_eq!(invalid_package.classification, "review");
    assert_eq!(
        invalid_package.cargo_workspace.as_ref().unwrap().status,
        "manifest_unavailable"
    );

    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = 'project'\nversion = '0.1.0'\nworkspace = '../external-workspace'\n",
    )
    .unwrap();
    let overridden = scan(std::slice::from_ref(&project)).unwrap();
    let overridden = overridden
        .candidates
        .iter()
        .find(|item| item.target == target)
        .unwrap();
    assert_eq!(overridden.classification, "review");
    assert_eq!(
        overridden.cargo_workspace.as_ref().unwrap().status,
        "workspace_override_unresolved"
    );
}

#[test]
fn cargo_local_config_include_and_build_dir_make_default_target_review_only() {
    let dir = tempdir().unwrap();
    for (name, config) in [
        ("include", "include = ['extra.toml']\n"),
        ("build-dir", "[build]\nbuild-dir = 'generated'\n"),
    ] {
        let project = dir.path().join(name);
        let cargo = project.join(".cargo");
        let target = project.join("target");
        fs::create_dir_all(&cargo).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("output"), b"fixture").unwrap();
        fs::write(project.join("Cargo.toml"), "[workspace]\n").unwrap();
        fs::write(cargo.join("config.toml"), config).unwrap();

        let report = scan(std::slice::from_ref(&project)).unwrap();
        let candidate = report
            .candidates
            .iter()
            .find(|item| item.target == target)
            .unwrap();
        assert_eq!(candidate.classification, "review");
        assert!(report.warnings.iter().any(|warning| {
            warning.contains(
                "Cargo target-dir configuration or a known environment override is unresolved",
            )
        }));
    }
}
