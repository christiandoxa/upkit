#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{fs, process::Command};

#[cfg(unix)]
#[test]
fn dry_run_status_and_manager_previews_never_execute_path_scheduler_wrappers() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = tempfile::tempdir().unwrap();
    let bin = fixture.path().join("bin");
    let home = fixture.path().join("home");
    let managed = fixture.path().join("managed");
    let config = fixture.path().join("config");
    let data = fixture.path().join("data");
    let sentinel = fixture.path().join("scheduler-was-run");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&managed).unwrap();
    fs::create_dir_all(&config).unwrap();
    fs::create_dir_all(&data).unwrap();

    let manager_name = if cfg!(target_os = "macos") {
        "launchctl"
    } else {
        "systemctl"
    };
    let wrapper = "#!/bin/sh\nprintf called >> \"$UPKIT_SCHEDULER_SENTINEL\"\nprintf 'LoadState=not-found\\nActiveState=inactive\\nUnitFileState=disabled\\n'\n";
    for name in [
        manager_name,
        "fstrim",
        "docker",
        "podman",
        "go",
        "rustc",
        "node",
        "python3",
        "flutter",
        "mojo",
        "javac",
        "dotnet",
    ] {
        let path = bin.join(name);
        fs::write(&path, wrapper).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
            .arg("--home")
            .arg(&managed)
            .arg("--bindir")
            .arg(&bin)
            .args(args)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_DATA_HOME", &data)
            .env("XDG_CACHE_HOME", fixture.path().join("cache"))
            .env("PATH", &bin)
            .env("UPKIT_SCHEDULER_SENTINEL", &sentinel)
            .output()
            .unwrap();
        if !args.contains(&"doctor") {
            assert!(
                output.status.success(),
                "args={args:?}\nstdout={}\nstderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };

    let maintenance = run(&[
        "--json",
        "--non-interactive",
        "--dry-run",
        "maintenance",
        "status",
    ]);
    assert_eq!(
        maintenance["timer"]["state"],
        if cfg!(target_os = "linux") {
            "skipped"
        } else {
            "unavailable"
        }
    );

    let doctor = run(&["--json", "--non-interactive", "--dry-run", "doctor"]);
    assert_eq!(doctor["capabilities"]["fstrim_timer"]["state"], "skipped");
    assert_eq!(doctor["capabilities"]["scan_timer"]["state"], "skipped");

    let schedule = run(&[
        "--json",
        "--non-interactive",
        "--dry-run",
        "schedule",
        "list",
    ]);
    assert_eq!(schedule["status"]["state"], "skipped");

    for command in [
        "preview-disable",
        "preview-remove",
        "preview-enable",
        "preview-edit",
        "disable",
        "remove",
        "enable",
        "edit",
    ] {
        let report = run(&[
            "--json",
            "--non-interactive",
            "--dry-run",
            "schedule",
            command,
        ]);
        assert!(report["skipped"].as_bool().unwrap(), "command={command}");
        assert_eq!(
            report["manager_state"], "not_inspected",
            "command={command}"
        );
        assert!(report["plan"].is_null(), "command={command}");
        assert!(report["preview_token"].is_null(), "command={command}");
    }

    let root = fixture.path().join("workspace");
    fs::create_dir(&root).unwrap();
    let plan = run(&[
        "--json",
        "--non-interactive",
        "--dry-run",
        "schedule",
        "preview",
        "--frequency",
        "daily",
        root.to_str().unwrap(),
    ]);
    assert_eq!(plan["frequency"], "daily");
    assert!(
        plan["preview_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );

    assert!(!sentinel.exists(), "a scheduler executable was launched");
}
