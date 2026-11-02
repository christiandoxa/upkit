#[cfg(target_os = "linux")]
#[test]
fn doctor_reports_capabilities_without_running_maintenance_or_container_engines() {
    use std::{fs, os::unix::fs::PermissionsExt, os::unix::net::UnixListener, process::Command};
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let docker_socket = root.join("docker.sock");
    let listener = UnixListener::bind(&docker_socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let missing_socket = root.join("missing-podman.sock");
    let systemctl = bin.join("systemctl");
    fs::write(
        &systemctl,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$HOME/systemctl-calls\"\nprintf 'LoadState=loaded\\nActiveState=active\\nUnitFileState=enabled\\n'\n",
    ).unwrap();
    for name in ["fstrim", "docker", "podman"] {
        let path = bin.join(name);
        fs::write(
            &path,
            "#!/bin/sh\nprintf invoked > \"$HOME/unexpected-invocation\"\n",
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::set_permissions(systemctl, fs::Permissions::from_mode(0o755)).unwrap();
    let run = |offline, dry_run| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        command
            .args([
                "--timeout",
                "1",
                "--retries",
                "0",
                "--non-interactive",
                "--json",
            ])
            .env("HOME", root)
            .env("PATH", &bin)
            .env("DOCKER_HOST", format!("unix://{}", docker_socket.display()))
            .env(
                "CONTAINER_HOST",
                format!("unix://{}", missing_socket.display()),
            )
            .env_remove("DOCKER_CONTEXT")
            .env_remove("CONTAINER_CONNECTION")
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("XDG_DATA_HOME", root.join("data"));
        if dry_run {
            command.arg("--dry-run");
        }
        command.arg("doctor");
        if offline {
            command.arg("--offline");
        } else {
            for name in [
                "HTTPS_PROXY",
                "https_proxy",
                "HTTP_PROXY",
                "http_proxy",
                "ALL_PROXY",
                "all_proxy",
            ] {
                command.env(name, "http://127.0.0.1:1");
            }
            command.env_remove("NO_PROXY").env_remove("no_proxy");
        }
        command.output().unwrap()
    };
    let offline = run(true, true);
    let offline_report: serde_json::Value = serde_json::from_slice(&offline.stdout).unwrap();
    let integrity = &offline_report["capabilities"]["installation_integrity"];
    assert_eq!(integrity["supported"], true);
    assert_eq!(integrity["complete"], true);
    assert_eq!(integrity["roots_inspected"], 0);
    assert_eq!(integrity["verified_seals"], 0);
    assert!(integrity.get("path").is_none());
    assert_eq!(
        offline_report["capabilities"]["fstrim_timer"]["state"],
        "skipped"
    );
    assert_eq!(
        offline_report["capabilities"]["scan_timer"]["state"],
        "skipped"
    );
    assert!(!root.join("systemctl-calls").exists());
    let output = run(false, false);
    let output_text = String::from_utf8_lossy(&output.stdout);
    assert!(!output_text.contains(&docker_socket.to_string_lossy().to_string()));
    assert!(!output_text.contains(&missing_socket.to_string_lossy().to_string()));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let capabilities = &report["capabilities"];
    assert_eq!(capabilities["fstrim_available"], true);
    assert_eq!(capabilities["fstrim_timer"]["state"], "active");
    assert_eq!(capabilities["scan_timer"]["state"], "active");
    let actions = capabilities["actionable_diagnostics"].as_array().unwrap();
    assert!(
        actions
            .iter()
            .any(|action| action.as_str().unwrap().contains("OS schedule"))
    );
    assert!(
        actions
            .iter()
            .any(|action| action.as_str().unwrap().contains("upkit schedule list"))
    );
    assert!(actions.iter().any(|action| {
        action
            .as_str()
            .unwrap()
            .contains("engine connection was not tested")
    }));
    assert!(actions.iter().all(|action| {
        let action = action.as_str().unwrap();
        !action.contains(&docker_socket.to_string_lossy().to_string())
            && !action.contains(&missing_socket.to_string_lossy().to_string())
    }));
    assert!(
        capabilities["cache_removal_probe"]
            .as_str()
            .unwrap()
            .starts_with("openat2_")
    );
    for engine in capabilities["containers"].as_array().unwrap() {
        assert_eq!(engine["executable_found"], true);
        assert_eq!(
            engine["endpoint"],
            if engine["engine"] == "docker" {
                "unix_socket_present_unverified"
            } else {
                "unix_socket_missing"
            }
        );
        assert_eq!(engine["connection"], "not_checked");
    }
    let calls = fs::read_to_string(root.join("systemctl-calls")).unwrap();
    let calls: Vec<_> = calls.lines().collect();
    assert_eq!(calls.len(), 2);
    assert!(
        calls
            .iter()
            .any(|line| line.starts_with("show fstrim.timer "))
    );
    assert!(
        calls
            .iter()
            .any(|line| line.starts_with("--user show upkit-scan.timer "))
    );
    assert!(!root.join("unexpected-invocation").exists());
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[test]
fn doctor_reports_non_directory_home_and_bindir_without_writing_them() {
    use std::{fs, process::Command};

    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    let home = root.join("home-file");
    let bindir = root.join("bin-file");
    let path = root.join("path");
    fs::write(&home, "home fixture").unwrap();
    fs::write(&bindir, "bin fixture").unwrap();
    fs::create_dir(&path).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args([
            "--json",
            "--offline",
            "--dry-run",
            "--non-interactive",
            "--home",
        ])
        .arg(&home)
        .arg("--bindir")
        .arg(&bindir)
        .arg("doctor")
        .current_dir(root)
        .env("HOME", root)
        .env("PATH", &path)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .env_remove("CONTAINER_HOST")
        .env_remove("CONTAINER_CONNECTION")
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let issues = report["issues"].as_array().unwrap();
    assert!(issues.iter().any(|issue| {
        issue
            .as_str()
            .unwrap()
            .contains("home path is not a directory")
    }));
    assert!(issues.iter().any(|issue| {
        issue
            .as_str()
            .unwrap()
            .contains("bindir path is not a directory")
    }));
    assert_eq!(fs::read_to_string(&home).unwrap(), "home fixture");
    assert_eq!(fs::read_to_string(&bindir).unwrap(), "bin fixture");
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_distinguishes_unreadable_paths_from_missing_ones() {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
    };

    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    let blocked = root.join("blocked");
    let home = blocked.join("home");
    fs::create_dir_all(&home).unwrap();
    let path = root.join("path");
    fs::create_dir(&path).unwrap();
    let loop_path = root.join("loop");
    symlink(&loop_path, &loop_path).unwrap();
    let bindir = loop_path.join("bin");
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();

    let permission_denied = match fs::metadata(&home) {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => true,
        Ok(_) => false,
        Err(error) => panic!("unexpected home metadata error: {error}"),
    };
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args([
            "--json",
            "--offline",
            "--dry-run",
            "--non-interactive",
            "--home",
        ])
        .arg(&home)
        .arg("--bindir")
        .arg(&bindir)
        .arg("doctor")
        .current_dir(root)
        .env("HOME", root)
        .env("PATH", &path)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .env_remove("CONTAINER_HOST")
        .env_remove("CONTAINER_CONNECTION")
        .output()
        .unwrap();
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700)).unwrap();

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let issues = report["issues"].as_array().unwrap();
    if permission_denied {
        assert!(issues.iter().any(|issue| {
            issue
                .as_str()
                .unwrap()
                .contains("home directory cannot be inspected")
        }));
        assert!(!issues.iter().any(|issue| {
            issue
                .as_str()
                .unwrap()
                .contains("home directory does not exist")
        }));
    } else {
        eprintln!("SKIP: permission checks were bypassed; symlink-loop case still runs");
    }
    assert!(issues.iter().any(|issue| {
        issue
            .as_str()
            .unwrap()
            .contains("bindir cannot be inspected")
    }));
    assert!(
        !issues
            .iter()
            .any(|issue| { issue.as_str().unwrap().contains("bindir does not exist") })
    );
}
