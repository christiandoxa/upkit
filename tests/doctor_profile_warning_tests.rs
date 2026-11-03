#[cfg(target_os = "linux")]
#[test]
fn doctor_reports_empty_profile_roots_as_a_nonfatal_scan_recommendation() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    use tempfile::tempdir;
    use upkit::config::{Profile, Settings, create};

    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    let config = dir.path().join("config.toml");
    let workspace = dir.path().join("global-workspace");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&bindir).unwrap();
    fs::create_dir(&workspace).unwrap();
    for name in [
        "go", "rustc", "node", "python3", "flutter", "mojo", "javac", "dotnet",
    ] {
        let tool = bindir.join(name);
        fs::write(&tool, "fixture").unwrap();
        fs::set_permissions(tool, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let systemctl = bindir.join("systemctl");
    fs::write(
        &systemctl,
        "#!/bin/sh\n: > \"$HOME/systemctl-called\"\nexit 99\n",
    )
    .unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();

    let mut settings = Settings {
        workspace_roots: vec![workspace],
        ..Default::default()
    };
    settings.profiles.insert("empty".into(), Profile::default());
    create(&config, &settings, false).unwrap();
    let config_before = fs::read(&config).unwrap();

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
        .arg("--config")
        .arg(&config)
        .args(["--profile", "empty", "doctor"])
        .env("HOME", &home)
        .env("PATH", &bindir)
        .env("XDG_CONFIG_HOME", dir.path().join("xdg-config"))
        .env("XDG_DATA_HOME", dir.path().join("xdg-data"))
        .env("XDG_CACHE_HOME", dir.path().join("xdg-cache"))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["issues"].as_array().unwrap().is_empty());
    assert_eq!(report["capabilities"]["fstrim_timer"]["state"], "skipped");
    assert_eq!(report["capabilities"]["scan_timer"]["state"], "skipped");
    assert!(
        report["capabilities"]["actionable_diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                warning
                    .as_str()
                    .unwrap()
                    .contains("workspace profile empty has no configured roots")
                    && warning
                        .as_str()
                        .unwrap()
                        .contains("pass paths explicitly to `sweep scan`")
            })
    );
    assert_eq!(fs::read(config).unwrap(), config_before);
    assert!(!home.join("systemctl-called").exists());
}
