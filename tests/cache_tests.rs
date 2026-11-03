#[cfg(target_os = "linux")]
fn user_mount_namespace_available(source: &std::path::Path) -> bool {
    use std::process::{Command, Stdio};

    Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--pid",
            "--fork",
            "--mount-proc",
            "/bin/sh",
            "-c",
            "/usr/bin/mount --make-rprivate / && /usr/bin/mount --bind \"$1\" /etc/opt",
            "sh",
        ])
        .arg(source)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "linux")]
fn isolated_machine_config_dir(root: &std::path::Path) -> Option<std::path::PathBuf> {
    use std::fs;

    let has_real_etc_opt = fs::symlink_metadata("/etc/opt")
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink());
    if !has_real_etc_opt {
        eprintln!("SKIP: cache CLI fixture; /etc/opt is not an existing real directory");
        return None;
    }
    let source = root.join("isolated-opt");
    fs::create_dir_all(source.join("NuGet/Config")).unwrap();
    if !user_mount_namespace_available(&source) {
        eprintln!("SKIP: cache CLI fixture; user/mount namespace unavailable");
        return None;
    }
    Some(source)
}

#[cfg(target_os = "linux")]
fn isolated_upkit_command(source: &std::path::Path) -> std::process::Command {
    let mut command = std::process::Command::new("unshare");
    command
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--pid",
            "--fork",
            "--mount-proc",
            "/bin/sh",
            "-c",
            "/usr/bin/mount --make-rprivate / && /usr/bin/mount --bind \"$1\" /etc/opt && shift && if [ \"${UPKIT_TEST_SKIP_NPM_GLOBALCONFIG:-}\" = 1 ]; then unset NPM_CONFIG_GLOBALCONFIG; elif [ \"${NPM_CONFIG_GLOBALCONFIG+x}\" != x ]; then export NPM_CONFIG_GLOBALCONFIG=\"$HOME/upkit-cache-test-global.npmrc\"; fi && unset UPKIT_TEST_SKIP_NPM_GLOBALCONFIG && exec \"$@\"",
            "sh",
        ])
        .arg(source)
        .arg(env!("CARGO_BIN_EXE_upkit"));
    command.current_dir(source.parent().unwrap());
    command
}

#[cfg(target_os = "linux")]
#[test]
fn cache_preview_fails_closed_without_npm_global_config_location() {
    let dir = tempfile::tempdir().unwrap();
    let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) else {
        return;
    };
    let home = dir.path().join("home");
    let target = home.join(".cargo/registry");
    let prefix = home.join("npm-prefix");
    let possible_npm_cache = home.join("npm-cache");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::create_dir_all(prefix.join("etc")).unwrap();
    std::fs::create_dir_all(possible_npm_cache.join("_cacache")).unwrap();
    std::fs::write(
        prefix.join("etc/npmrc"),
        format!("cache={}\n", possible_npm_cache.display()),
    )
    .unwrap();

    let status = isolated_upkit_command(&isolated_opt)
        .args(["--json", "cache", "status"])
        .current_dir(dir.path())
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("NPM_CONFIG_PREFIX", &prefix)
        .env("UPKIT_TEST_SKIP_NPM_GLOBALCONFIG", "1")
        .output()
        .unwrap();
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    let possible_cache_path = possible_npm_cache.join("_cacache");
    assert!(status["entries"].as_array().unwrap().iter().any(|entry| {
        entry["name"] == "npm configured cache (possible)"
            && entry["path"] == possible_cache_path.to_str().unwrap()
    }));

    let output = isolated_upkit_command(&isolated_opt)
        .args(["--json", "sweep", "run", "--scope", "cache", "--select"])
        .arg(&target)
        .arg("--preview")
        .current_dir(dir.path())
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("NPM_CONFIG_PREFIX", &prefix)
        .env("UPKIT_TEST_SKIP_NPM_GLOBALCONFIG", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.contains("npm global config location is unverified"));
}

#[cfg(target_os = "linux")]
#[test]
fn nuget_dotnet_home_and_defaults_are_protected_in_isolated_mount_namespace() {
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    let dir = tempfile::tempdir().unwrap();
    let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) else {
        return;
    };

    let home = dir.path().join("home");
    let dotnet_home = dir.path().join("dotnet-home");
    let xdg_config = dir.path().join("xdg-config");
    let xdg_data = dir.path().join("safe-xdg-data");
    let cargo_registry = home.join(".cargo/registry");
    let machine_common = dir.path().join("machine-common");
    let machine_override_config = machine_common.join("NuGet/Config");
    let home_packages = dir.path().join("home-packages");
    let home_xdg_packages = dir.path().join("home-xdg-packages");
    let xdg_packages = dir.path().join("xdg-packages");
    let dotnet_packages = dir.path().join("dotnet-packages");
    let override_packages = dir.path().join("override-packages");
    let home_feed = dir.path().join("home-feed");
    let home_xdg_feed = dir.path().join("home-xdg-feed");
    let xdg_feed = dir.path().join("xdg-feed");
    let dotnet_feed = dir.path().join("dotnet-feed");
    let home_defaults_feed = dir.path().join("home-defaults-feed");
    let dotnet_defaults_feed = dir.path().join("dotnet-defaults-feed");
    let xdg_defaults_feed = dir.path().join("xdg-defaults-feed");
    for path in [
        &home,
        &dotnet_home,
        &cargo_registry,
        &machine_override_config,
        &home_packages,
        &home_xdg_packages,
        &xdg_packages,
        &dotnet_packages,
        &override_packages,
        &home_feed,
        &home_xdg_feed,
        &xdg_feed,
        &dotnet_feed,
        &home_defaults_feed,
        &dotnet_defaults_feed,
        &xdg_defaults_feed,
    ] {
        fs::create_dir_all(path).unwrap();
    }
    for path in [
        home.as_path(),
        cargo_registry.parent().unwrap(),
        cargo_registry.as_path(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(cargo_registry.join("fixture"), b"keep cargo cache").unwrap();
    fs::set_permissions(
        cargo_registry.join("fixture"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let write_user_config = |path: &Path, packages: &Path, source: &Path| {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            format!(
                "<configuration><config><add key=\"globalPackagesFolder\" value=\"{}\"/></config><packageSources><add key=\"local\" value=\"{}\"/></packageSources></configuration>",
                packages.display(),
                source.display()
            ),
        )
        .unwrap();
    };
    let write_defaults_config = |path: &Path, source: &Path| {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            format!(
                "<configuration><packageSources><add key=\"local\" value=\"{}\"/></packageSources></configuration>",
                source.display()
            ),
        )
        .unwrap();
    };
    write_user_config(
        &home.join(".nuget/NuGet/NuGet.Config"),
        &home_packages,
        &home_feed,
    );
    write_user_config(
        &home.join(".config/NuGet/NuGet.Config"),
        &home_xdg_packages,
        &home_xdg_feed,
    );
    write_user_config(
        &xdg_config.join("NuGet/NuGet.Config"),
        &xdg_packages,
        &xdg_feed,
    );
    write_user_config(
        &dotnet_home.join(".nuget/NuGet/NuGet.Config"),
        &dotnet_packages,
        &dotnet_feed,
    );
    write_defaults_config(
        &home.join(".local/share/NuGetDefaults.Config"),
        &home_defaults_feed,
    );
    write_defaults_config(
        &dotnet_home.join(".local/share/NuGetDefaults.Config"),
        &dotnet_defaults_feed,
    );
    write_defaults_config(&xdg_data.join("NuGetDefaults.Config"), &xdg_defaults_feed);
    let go_env = xdg_config.join("go/env");
    fs::create_dir_all(go_env.parent().unwrap()).unwrap();
    fs::write(
        go_env,
        format!(
            "GOPATH={}\nGOMODCACHE={}\nGOCACHE={}\nGOCACHEPROG=\n",
            home.join("go").display(),
            home.join("go/pkg/mod").display(),
            home.join(".cache/go-build").display()
        ),
    )
    .unwrap();

    let app_home = dir.path().join("upkit-home");
    let run = |active_dotnet_home: &Path, target: Option<&Path>| {
        let mut command = isolated_upkit_command(&isolated_opt);
        command
            .args(["--non-interactive", "--json", "--home"])
            .arg(&app_home);
        if let Some(target) = target {
            command
                .args(["sweep", "run", "--scope", "cache", "--select"])
                .arg(target)
                .arg("--preview");
        } else {
            command.args(["cache", "status"]);
        }
        command
            .current_dir(dir.path())
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("DOTNET_CLI_HOME", active_dotnet_home)
            .env("NUGET_PACKAGES", &override_packages)
            .env("NUGET_COMMON_APPLICATION_DATA", &machine_common)
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_CONFIG_HOME", &xdg_config)
            .env("XDG_DATA_HOME", &xdg_data)
            .output()
            .unwrap()
    };

    let safe_preview = run(&dotnet_home, Some(&cargo_registry));
    assert!(
        safe_preview.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&safe_preview.stdout),
        String::from_utf8_lossy(&safe_preview.stderr)
    );
    let report_output = run(&dotnet_home, None);
    assert!(
        report_output.status.success(),
        "{}",
        String::from_utf8_lossy(&report_output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&report_output.stdout).unwrap();
    let entries = report["entries"].as_array().unwrap();
    for packages in [
        &home_packages,
        &home_xdg_packages,
        &xdg_packages,
        &dotnet_packages,
    ] {
        assert!(entries.iter().any(|entry| {
            entry["name"] == "NuGet global packages" && entry["path"] == packages.to_str().unwrap()
        }));
    }
    for feed in [
        &home_feed,
        &home_xdg_feed,
        &xdg_feed,
        &dotnet_feed,
        &home_defaults_feed,
        &dotnet_defaults_feed,
        &xdg_defaults_feed,
    ] {
        assert!(entries.iter().any(|entry| {
            entry["name"] == "NuGet local package source" && entry["path"] == feed.to_str().unwrap()
        }));
    }
    for packages in [
        &home_packages,
        &home_xdg_packages,
        &xdg_packages,
        &dotnet_packages,
    ] {
        let protected = run(&dotnet_home, Some(packages));
        assert!(!protected.status.success());
        assert!(
            String::from_utf8_lossy(&protected.stdout)
                .contains("Upkit inventories NuGet package folders but does not remove them")
        );
    }

    let default_machine_config = isolated_opt.join("NuGet/Config/machine.config");
    fs::write(&default_machine_config, "<configuration />").unwrap();
    let default_machine_block = run(&dotnet_home, Some(&cargo_registry));
    assert!(!default_machine_block.status.success());
    let output_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&default_machine_block.stdout),
        String::from_utf8_lossy(&default_machine_block.stderr)
    );
    assert!(output_text.contains("machine-level NuGet config may change package locations"));
    fs::remove_file(default_machine_config).unwrap();

    let override_machine_config = machine_override_config.join("machine.config");
    fs::write(&override_machine_config, "<configuration />").unwrap();
    let override_machine_block = run(&dotnet_home, Some(&cargo_registry));
    assert!(!override_machine_block.status.success());
    let output_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&override_machine_block.stdout),
        String::from_utf8_lossy(&override_machine_block.stderr)
    );
    assert!(output_text.contains("machine-level NuGet config may change package locations"));
    fs::remove_file(override_machine_config).unwrap();

    let alternative_home = cargo_registry.join("alternative-dotnet-home");
    let defaults_feed = cargo_registry.join("alternative-defaults-feed");
    fs::create_dir_all(&defaults_feed).unwrap();
    write_defaults_config(
        &alternative_home.join(".local/share/NuGetDefaults.Config"),
        &defaults_feed,
    );
    let alternative_report = run(&alternative_home, None);
    assert!(
        alternative_report.status.success(),
        "{}",
        String::from_utf8_lossy(&alternative_report.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&alternative_report.stdout).unwrap();
    assert!(report["entries"].as_array().unwrap().iter().any(|entry| {
        entry["name"] == "NuGet local package source"
            && entry["path"] == defaults_feed.to_str().unwrap()
    }));
    let overlap = run(&alternative_home, Some(&cargo_registry));
    assert!(!overlap.status.success());
    assert!(
        String::from_utf8_lossy(&overlap.stdout)
            .contains("selected cache overlaps another discovered cache location")
    );
    assert_eq!(
        fs::read(cargo_registry.join("fixture")).unwrap(),
        b"keep cargo cache"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn cache_status_reports_fixture_sizes_without_mutating_files() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let registry = home.join(".cargo/registry");
    let modules = home.join("go/pkg/mod");
    let config = home.join("config");
    fs::create_dir_all(&registry).unwrap();
    fs::create_dir_all(&modules).unwrap();
    fs::create_dir_all(config.join("go")).unwrap();
    fs::write(
        config.join("go/env"),
        format!(
            "GOPATH={}\nGOMODCACHE=\nGOCACHEPROG=\n",
            home.join("go").display()
        ),
    )
    .unwrap();
    fs::write(registry.join("fixture"), b"cargo").unwrap();
    fs::write(modules.join("fixture"), b"modules").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "cache", "status"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = report["entries"].as_array().unwrap();
    let cargo = entries
        .iter()
        .find(|entry| entry["name"] == "Cargo registry")
        .unwrap();
    let go = entries
        .iter()
        .find(|entry| entry["name"] == "Go modules")
        .unwrap();
    assert_eq!(cargo["logical_bytes"], 5);
    assert_eq!(go["logical_bytes"], 7);
    assert_eq!(cargo["classification"], "shared dependencies");
    assert_eq!(cargo["status"], "inventory only");
    assert_eq!(cargo["directory_owner_status"], "current_user");
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("persistent environment"))
    );
    assert_eq!(fs::read(registry.join("fixture")).unwrap(), b"cargo");
    assert_eq!(fs::read(modules.join("fixture")).unwrap(), b"modules");
    assert!(!home.join(".bashrc").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn cache_status_warns_when_cache_estimates_overlap() {
    use std::fs;

    let dir = tempfile::tempdir().unwrap();
    let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) else {
        return;
    };
    let home = dir.path().join("home");
    let registry = home.join(".cargo/registry");
    let pip = registry.join("pip");
    let go_build = pip.join("go-build");
    let cargo_git = home.join(".cargo/git");
    fs::create_dir_all(&go_build).unwrap();
    fs::create_dir_all(&cargo_git).unwrap();
    fs::write(registry.join("registry-fixture"), b"registry").unwrap();
    fs::write(pip.join("pip-fixture"), b"pip").unwrap();
    fs::write(go_build.join("go-fixture"), b"go").unwrap();
    fs::write(cargo_git.join("git-fixture"), b"git").unwrap();

    let output = isolated_upkit_command(&isolated_opt)
        .args(["--json", "cache", "status"])
        .current_dir(dir.path())
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("GOENV", "off")
        .env("GOCACHE", &go_build)
        .env("GOMODCACHE", home.join("go-mod"))
        .env("XDG_CACHE_HOME", &registry)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = report["entries"].as_array().unwrap();
    let warnings = |name| {
        entries.iter().find(|entry| entry["name"] == name).unwrap()["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                warning
                    .as_str()
                    .unwrap()
                    .contains("size estimates may overlap")
            })
    };
    assert!(warnings("Cargo registry"));
    assert!(warnings("pip"));
    assert!(warnings("Go build"));
    assert!(!warnings("Cargo git"));
    assert_eq!(
        fs::read(registry.join("registry-fixture")).unwrap(),
        b"registry"
    );
    assert_eq!(fs::read(pip.join("pip-fixture")).unwrap(), b"pip");
    assert_eq!(fs::read(go_build.join("go-fixture")).unwrap(), b"go");
    assert_eq!(fs::read(cargo_git.join("git-fixture")).unwrap(), b"git");
}

#[test]
fn cargo_build_outputs_are_inventory_only_with_unknown_scope() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let target = home.join("cargo-target");
    let build = dir.path().join("cargo-build");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&build).unwrap();
    fs::write(target.join("fixture"), b"target output").unwrap();
    fs::write(build.join("fixture"), b"intermediate output").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "cache", "status"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("CARGO_TARGET_DIR", &target)
        .env("CARGO_BUILD_BUILD_DIR", &build)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = report["entries"].as_array().unwrap();
    for path in [&target, &build] {
        let entry = entries
            .iter()
            .find(|entry| {
                entry["name"] == "Cargo build output (possible)"
                    && entry["path"] == path.to_str().unwrap()
            })
            .unwrap();
        assert_eq!(entry["ownership"], "configured Cargo output; scope unknown");
        assert_eq!(entry["classification"], "configured output; scope unknown");
        assert_eq!(entry["status"], "inventory only");
        assert!(
            entry["consequence"]
                .as_str()
                .unwrap()
                .contains("other user data")
        );
    }
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                warning.as_str().unwrap().contains(
                    "Cargo --target-dir/--config overrides and config files outside that search are not inspected",
                )
            })
    );
    assert_eq!(fs::read(target.join("fixture")).unwrap(), b"target output");
    assert_eq!(
        fs::read(build.join("fixture")).unwrap(),
        b"intermediate output"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn nuget_global_packages_inventory_uses_default_and_absolute_override() {
    use std::fs;
    let dir = tempfile::tempdir().unwrap();
    let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) else {
        return;
    };
    let home = dir.path().join("home");
    let default = home.join(".nuget/packages");
    let custom = dir.path().join("custom-nuget-packages");
    let environment_override = dir.path().join("environment-nuget-packages");
    let fallback = dir.path().join("fallback-nuget-packages");
    let config = home.join("config");
    fs::create_dir_all(&default).unwrap();
    fs::create_dir_all(&custom).unwrap();
    fs::create_dir_all(&environment_override).unwrap();
    fs::create_dir_all(&fallback).unwrap();
    fs::create_dir_all(config.join("go")).unwrap();
    fs::write(
        config.join("go/env"),
        format!(
            "GOPATH={}\nGOMODCACHE=\nGOCACHEPROG=\n",
            home.join("go").display()
        ),
    )
    .unwrap();
    fs::write(default.join("default.nupkg"), b"default").unwrap();
    fs::write(custom.join("custom.nupkg"), b"custom").unwrap();
    fs::write(
        environment_override.join("environment.nupkg"),
        b"environment",
    )
    .unwrap();
    fs::write(fallback.join("fallback.nupkg"), b"fallback").unwrap();
    let run = |override_path: Option<&std::path::Path>| {
        let mut command = isolated_upkit_command(&isolated_opt);
        command
            .args(["--json", "cache", "status"])
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env(
                "NUGET_COMMON_APPLICATION_DATA",
                dir.path().join("machine-common"),
            )
            .env("NUGET_FALLBACK_PACKAGES", &fallback);
        if let Some(path) = override_path {
            command.env("NUGET_PACKAGES", path);
        }
        command.output().unwrap()
    };

    let output = run(None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                warning.as_str().is_some_and(|value| {
                    value.contains("project-file restore properties are not inspected")
                })
            })
    );
    let entry = report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "NuGet global packages")
        .unwrap();
    assert_eq!(entry["path"], default.to_str().unwrap());
    assert_eq!(entry["logical_bytes"], 7);
    assert_eq!(entry["status"], "inventory only");
    assert!(
        entry["warnings"][0]
            .as_str()
            .unwrap()
            .contains("NuGet.Config")
    );
    assert!(report["entries"].as_array().unwrap().iter().any(|entry| {
        entry["name"] == "NuGet fallback packages" && entry["path"] == fallback.to_str().unwrap()
    }));

    let user_config = home.join(".nuget/NuGet/NuGet.Config");
    fs::create_dir_all(user_config.parent().unwrap()).unwrap();
    fs::write(
        &user_config,
        format!(
            "<configuration><config><add key=\"GlobalPackagesFolder\" value=\"{}\" /></config></configuration>",
            custom.display()
        ),
    )
    .unwrap();
    let output = run(None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entry = report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "NuGet global packages")
        .unwrap();
    assert_eq!(entry["path"], custom.to_str().unwrap());

    let output = run(Some(&environment_override));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = report["entries"].as_array().unwrap();
    let entry = entries
        .iter()
        .find(|entry| {
            entry["name"] == "NuGet global packages"
                && entry["path"] == environment_override.to_str().unwrap()
        })
        .unwrap();
    assert_eq!(entry["path"], environment_override.to_str().unwrap());
    assert!(entries.iter().any(|entry| {
        entry["name"] == "NuGet global packages" && entry["path"] == default.to_str().unwrap()
    }));
    assert!(entries.iter().any(|entry| {
        entry["name"] == "NuGet global packages" && entry["path"] == custom.to_str().unwrap()
    }));
    assert_eq!(fs::read(default.join("default.nupkg")).unwrap(), b"default");
    assert_eq!(fs::read(custom.join("custom.nupkg")).unwrap(), b"custom");
    assert_eq!(
        fs::read(fallback.join("fallback.nupkg")).unwrap(),
        b"fallback"
    );
    assert_eq!(
        fs::read(environment_override.join("environment.nupkg")).unwrap(),
        b"environment"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn nuget_cache_is_not_removable_and_blocks_overlap_or_unknown_override() {
    use std::fs;
    let dir = tempfile::tempdir().unwrap();
    let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) else {
        return;
    };
    let home = dir.path().join("home");
    let cargo_registry = home.join(".cargo/registry");
    let nuget_packages = home.join(".nuget/custom-packages");
    let overlapping_nuget_packages = cargo_registry.join("nuget-packages");
    let fallback_packages = cargo_registry.join("fallback-packages");
    let config = home.join(".config");
    fs::create_dir_all(&nuget_packages).unwrap();
    fs::create_dir_all(&overlapping_nuget_packages).unwrap();
    fs::create_dir_all(&fallback_packages).unwrap();
    fs::create_dir_all(config.join("go")).unwrap();
    fs::write(
        config.join("go/env"),
        format!(
            "GOPATH={}\nGOMODCACHE={}\nGOCACHE={}\nGOCACHEPROG=\n",
            home.join("go").display(),
            home.join("go/pkg/mod").display(),
            home.join(".cache/go-build").display()
        ),
    )
    .unwrap();
    fs::write(cargo_registry.join("fixture"), b"cargo").unwrap();
    fs::write(nuget_packages.join("fixture"), b"nuget").unwrap();
    fs::write(overlapping_nuget_packages.join("fixture"), b"nested").unwrap();
    fs::write(fallback_packages.join("fixture"), b"fallback").unwrap();
    let preview = |target: &std::path::Path,
                   nuget_override: &std::ffi::OsStr,
                   fallback_override: &std::ffi::OsStr| {
        isolated_upkit_command(&isolated_opt)
            .args([
                "--offline",
                "--json",
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
            ])
            .arg(target)
            .arg("--preview")
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env(
                "NUGET_COMMON_APPLICATION_DATA",
                dir.path().join("machine-common"),
            )
            .env("NUGET_PACKAGES", nuget_override)
            .env("NUGET_FALLBACK_PACKAGES", fallback_override)
            .output()
            .unwrap()
    };

    let output = preview(
        &nuget_packages,
        nuget_packages.as_os_str(),
        fallback_packages.as_os_str(),
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("Upkit inventories NuGet package folders but does not remove them")
    );

    let output = preview(
        &cargo_registry,
        overlapping_nuget_packages.as_os_str(),
        fallback_packages.as_os_str(),
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("overlaps another discovered cache location")
    );

    let output = preview(
        &cargo_registry,
        std::ffi::OsStr::new("relative/packages"),
        fallback_packages.as_os_str(),
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("NuGet global package location is unknown")
    );
    assert_eq!(fs::read(cargo_registry.join("fixture")).unwrap(), b"cargo");
    assert_eq!(fs::read(nuget_packages.join("fixture")).unwrap(), b"nuget");
    assert_eq!(
        fs::read(overlapping_nuget_packages.join("fixture")).unwrap(),
        b"nested"
    );
    let output = preview(
        &fallback_packages,
        nuget_packages.as_os_str(),
        fallback_packages.as_os_str(),
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("Upkit inventories NuGet package folders but does not remove them")
    );
    assert_eq!(
        fs::read(fallback_packages.join("fixture")).unwrap(),
        b"fallback"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn nuget_user_repository_and_default_push_paths_are_protected() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) else {
        return;
    };
    let home = dir.path().join("home");
    let config = home.join(".config");
    let cargo_registry = home.join(".cargo/registry");
    let repository = dir.path().join("packages-config-repository");
    let local_feed = dir.path().join("default-push-feed");
    fs::create_dir_all(&cargo_registry).unwrap();
    fs::create_dir_all(&repository).unwrap();
    fs::create_dir_all(&local_feed).unwrap();
    fs::create_dir_all(config.join("go")).unwrap();
    let cargo_parent = cargo_registry.parent().unwrap();
    for path in [
        &home,
        cargo_parent,
        &cargo_registry,
        &repository,
        &local_feed,
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(cargo_registry.join("fixture"), b"keep cargo cache").unwrap();
    fs::write(local_feed.join("fixture.nupkg"), b"keep local feed").unwrap();
    fs::set_permissions(
        cargo_registry.join("fixture"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(
        local_feed.join("fixture.nupkg"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(
        config.join("go/env"),
        format!(
            "GOPATH={}\nGOMODCACHE={}\nGOCACHE={}\nGOCACHEPROG=\n",
            home.join("go").display(),
            home.join("go/pkg/mod").display(),
            home.join(".cache/go-build").display()
        ),
    )
    .unwrap();
    let user_config = home.join(".nuget/NuGet/NuGet.Config");
    fs::create_dir_all(user_config.parent().unwrap()).unwrap();
    let write_user_config = |repository_path: &std::path::Path, push_source: &std::path::Path| {
        fs::write(
            &user_config,
            format!(
                "<configuration><config><add key=\"RepositoryPath\" value=\"{}\"/><add key=\"defaultPushSource\" value=\"{}\"/></config></configuration>",
                repository_path.display(),
                push_source.display()
            ),
        )
        .unwrap();
    };
    let run = |target: &std::path::Path| {
        isolated_upkit_command(&isolated_opt)
            .args([
                "--non-interactive",
                "--json",
                "--home",
                home.join("upkit").to_str().unwrap(),
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
            ])
            .arg(target)
            .arg("--preview")
            .current_dir(dir.path())
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env(
                "NUGET_COMMON_APPLICATION_DATA",
                dir.path().join("machine-common"),
            )
            .output()
            .unwrap()
    };

    write_user_config(&repository, &local_feed);
    let output = run(&cargo_registry);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["plan"]["name"], "Cargo registry");
    assert_eq!(plan["plan"]["target"], cargo_registry.to_str().unwrap());

    let direct_feed = run(&local_feed);
    assert!(!direct_feed.status.success());
    assert!(String::from_utf8_lossy(&direct_feed.stdout).contains("local NuGet package sources"));

    let overlapping_repository = cargo_registry.join("nuget-packages");
    fs::create_dir(&overlapping_repository).unwrap();
    fs::set_permissions(&overlapping_repository, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(overlapping_repository.join("fixture"), b"keep repository").unwrap();
    fs::set_permissions(
        overlapping_repository.join("fixture"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    write_user_config(&overlapping_repository, &local_feed);
    let output = run(&cargo_registry);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("selected cache overlaps another discovered cache location")
    );

    let overlapping_push_source = cargo_registry.join("local-push-feed");
    fs::create_dir(&overlapping_push_source).unwrap();
    fs::set_permissions(&overlapping_push_source, fs::Permissions::from_mode(0o700)).unwrap();
    write_user_config(&repository, &overlapping_push_source);
    let output = run(&cargo_registry);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("selected cache overlaps another discovered cache location")
    );
    assert_eq!(
        fs::read(cargo_registry.join("fixture")).unwrap(),
        b"keep cargo cache"
    );
    assert_eq!(
        fs::read(local_feed.join("fixture.nupkg")).unwrap(),
        b"keep local feed"
    );
    assert_eq!(
        fs::read(overlapping_repository.join("fixture")).unwrap(),
        b"keep repository"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn nuget_fallback_config_blocks_cache_removal_even_with_nuget_packages_override() {
    use std::fs;
    let dir = tempfile::tempdir().unwrap();
    let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) else {
        return;
    };
    let home = dir.path().join("home");
    let config = home.join(".config");
    let cargo_registry = home.join(".cargo/registry");
    let fallback = cargo_registry.join("offline-nuget");
    let active_global = dir.path().join("active-nuget");
    let active_fallback = dir.path().join("active-fallback");
    fs::create_dir_all(&fallback).unwrap();
    fs::create_dir_all(&active_global).unwrap();
    fs::create_dir_all(&active_fallback).unwrap();
    fs::create_dir_all(config.join("go")).unwrap();
    fs::write(
        config.join("go/env"),
        format!(
            "GOPATH={}\nGOMODCACHE={}\nGOCACHE={}\nGOCACHEPROG=\n",
            home.join("go").display(),
            home.join("go/pkg/mod").display(),
            home.join(".cache/go-build").display()
        ),
    )
    .unwrap();
    fs::write(fallback.join("fixture"), b"keep fallback data").unwrap();
    let user_config = home.join(".nuget/NuGet/NuGet.Config");
    fs::create_dir_all(user_config.parent().unwrap()).unwrap();
    fs::write(
        user_config,
        format!(
            "<configuration><fallbackPackageFolders><add key=\"offline\" value=\"{}\" /></fallbackPackageFolders></configuration>",
            fallback.display()
        ),
    )
    .unwrap();

    let output = isolated_upkit_command(&isolated_opt)
        .args([
            "--offline",
            "--json",
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
        ])
        .arg(&cargo_registry)
        .arg("--preview")
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("NUGET_PACKAGES", &active_global)
        .env("NUGET_FALLBACK_PACKAGES", &active_fallback)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env(
            "NUGET_COMMON_APPLICATION_DATA",
            dir.path().join("machine-common"),
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    let output_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output_text.contains("selected cache overlaps another discovered cache location"));
    assert_eq!(
        fs::read(fallback.join("fixture")).unwrap(),
        b"keep fallback data"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn nuget_fallback_config_is_inventoried_when_unambiguous() {
    use std::fs;
    let dir = tempfile::tempdir().unwrap();
    let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) else {
        return;
    };
    let home = dir.path().join("home");
    let fallback = dir.path().join("fallback-packages");
    let config = home.join(".nuget/NuGet/NuGet.Config");
    fs::create_dir_all(&fallback).unwrap();
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(fallback.join("fixture"), b"keep fallback").unwrap();
    fs::write(
        config,
        format!(
            "<configuration><fallbackPackageFolders><add key=\"offline\" value=\"{}\"/></fallbackPackageFolders></configuration>",
            fallback.display()
        ),
    )
    .unwrap();

    let output = isolated_upkit_command(&isolated_opt)
        .args(["--json", "cache", "status"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env(
            "NUGET_COMMON_APPLICATION_DATA",
            dir.path().join("machine-common"),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entry = report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "NuGet fallback packages")
        .unwrap();
    assert_eq!(entry["path"], fallback.to_str().unwrap());
    assert_eq!(entry["status"], "inventory only");
    assert_eq!(
        fs::read(fallback.join("fixture")).unwrap(),
        b"keep fallback"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn nuget_msbuild_environment_paths_are_protected_or_fail_closed() {
    use std::{ffi::OsStr, fs, os::unix::fs::PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) else {
        return;
    };
    let home = dir.path().join("home");
    let project = dir.path().join("project");
    let config = home.join(".config");
    let cargo_registry = home.join(".cargo/registry");
    let restore_packages = cargo_registry.join("restore-packages");
    let restore_fallback = cargo_registry.join("restore-fallback");
    let source_feed = dir.path().join("msbuild-feed");
    let custom_config = dir.path().join("custom/NuGet.Config");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&restore_packages).unwrap();
    fs::create_dir_all(&restore_fallback).unwrap();
    fs::create_dir_all(&source_feed).unwrap();
    fs::create_dir_all(custom_config.parent().unwrap()).unwrap();
    for path in [
        &home,
        &cargo_registry.parent().unwrap().to_path_buf(),
        &cargo_registry,
        &source_feed,
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::create_dir_all(config.join("go")).unwrap();
    fs::write(
        config.join("go/env"),
        format!(
            "GOPATH={}\nGOMODCACHE={}\nGOCACHE={}\nGOCACHEPROG=\n",
            home.join("go").display(),
            home.join("go/pkg/mod").display(),
            home.join(".cache/go-build").display()
        ),
    )
    .unwrap();
    fs::create_dir_all(config.join("go")).unwrap();
    fs::write(
        config.join("go/env"),
        format!(
            "GOPATH={}\nGOMODCACHE={}\nGOCACHE={}\nGOCACHEPROG=\n",
            home.join("go").display(),
            home.join("go/pkg/mod").display(),
            home.join(".cache/go-build").display()
        ),
    )
    .unwrap();
    fs::write(restore_packages.join("fixture"), b"keep msbuild packages").unwrap();
    fs::write(restore_fallback.join("fixture"), b"keep msbuild fallback").unwrap();
    for path in [&restore_packages, &restore_fallback] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(path.join("fixture"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(
        &custom_config,
        "<configuration><config><add key=\"globalPackagesFolder\" value=\"/tmp/unknown-nuget\"/></config></configuration>",
    )
    .unwrap();
    let run = |variable: &str, value: &OsStr, target: &std::path::Path| {
        isolated_upkit_command(&isolated_opt)
            .args([
                "--non-interactive",
                "--json",
                "--home",
                home.join("upkit").to_str().unwrap(),
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
            ])
            .arg(target)
            .arg("--preview")
            .current_dir(&project)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env(
                "NUGET_COMMON_APPLICATION_DATA",
                dir.path().join("machine-common"),
            )
            .env(variable, value)
            .output()
            .unwrap()
    };

    for (variable, path) in [
        ("restorepackagespath", &restore_packages),
        ("RestoreRepositoryPath", &restore_packages),
        ("RestoreFallbackFolders", &restore_fallback),
        ("RestoreAdditionalProjectFallbackFolders", &restore_fallback),
    ] {
        let output = run(variable, path.as_os_str(), &cargo_registry);
        assert!(!output.status.success(), "{variable}");
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("selected cache overlaps another discovered cache location"),
            "{variable}"
        );
    }
    let output = run(
        "RestoreConfigFile",
        custom_config.as_os_str(),
        &cargo_registry,
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("NuGet package locations are unverified")
    );
    let args = format!("/p:RestorePackagesPath={}", restore_packages.display());
    let output = run(
        "NUGET_RESTORE_MSBUILD_ARGS",
        OsStr::new(&args),
        &cargo_registry,
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("NuGet package locations are unverified")
    );
    assert_eq!(
        fs::read(restore_packages.join("fixture")).unwrap(),
        b"keep msbuild packages"
    );
    assert_eq!(
        fs::read(restore_fallback.join("fixture")).unwrap(),
        b"keep msbuild fallback"
    );

    let sources = format!(
        "{};https://synthetic-user:synthetic-token@example.test/v3/index.json",
        source_feed.display()
    );
    for variable in ["RestoreSources", "RestoreAdditionalProjectSources"] {
        let output = run(variable, OsStr::new(&sources), &cargo_registry);
        assert!(
            output.status.success(),
            "{variable}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let output_text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output_text.contains("synthetic-token"));
        let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(plan["plan"]["name"], "Cargo registry");
        assert_eq!(plan["plan"]["target"], cargo_registry.to_str().unwrap());
        let output = run(variable, source_feed.as_os_str(), &source_feed);
        assert!(!output.status.success());
        let output_text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output_text.contains("local NuGet package sources"));
        assert!(!output_text.contains("synthetic-token"));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn nuget_ancestor_config_allows_safe_preview_and_protects_local_feeds() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) else {
        return;
    };
    let home = dir.path().join("home");
    let solution = dir.path().join("solution");
    let project = solution.join("member");
    let config = home.join(".config");
    let cargo_registry = home.join(".cargo/registry");
    let package_location = dir.path().join("project-packages");
    let local_feed = dir.path().join("local-feed");
    let global_override = dir.path().join("global-override");
    let fallback_override = dir.path().join("fallback-override");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&cargo_registry).unwrap();
    fs::create_dir_all(&package_location).unwrap();
    fs::create_dir_all(&local_feed).unwrap();
    fs::create_dir_all(&global_override).unwrap();
    fs::create_dir_all(&fallback_override).unwrap();
    fs::create_dir_all(config.join("go")).unwrap();
    for path in [
        &home,
        &cargo_registry.parent().unwrap().to_path_buf(),
        &cargo_registry,
        &local_feed,
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(cargo_registry.join("fixture"), b"keep cargo cache").unwrap();
    fs::write(local_feed.join("fixture.nupkg"), b"keep local feed").unwrap();
    fs::set_permissions(
        cargo_registry.join("fixture"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(
        local_feed.join("fixture.nupkg"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(
        config.join("go/env"),
        format!(
            "GOPATH={}\nGOMODCACHE={}\nGOCACHE={}\nGOCACHEPROG=\n",
            home.join("go").display(),
            home.join("go/pkg/mod").display(),
            home.join(".cache/go-build").display()
        ),
    )
    .unwrap();
    fs::write(package_location.join("fixture"), b"keep project packages").unwrap();
    fs::write(
        solution.join("NuGet.config"),
        format!(
            "<configuration><config><add key=\"globalPackagesFolder\" value=\"{}\" /></config><fallbackPackageFolders><add key=\"solution-fallback\" value=\"{}\" /></fallbackPackageFolders><packageSources><add key=\"local\" value=\"{}\" /><add key=\"private\" value=\"https://synthetic-user:synthetic-token@example.test/v3/index.json\" protocolVersion=\"3\" /></packageSources></configuration>",
            package_location.display(),
            dir.path().join("solution-fallback").display(),
            local_feed.display()
        ),
    )
    .unwrap();

    let run = |target: &std::path::Path| {
        isolated_upkit_command(&isolated_opt)
            .args([
                "--non-interactive",
                "--json",
                "--home",
                home.join("upkit").to_str().unwrap(),
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
            ])
            .arg(target)
            .arg("--preview")
            .current_dir(&project)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("NUGET_PACKAGES", &global_override)
            .env("NUGET_FALLBACK_PACKAGES", &fallback_override)
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env(
                "NUGET_COMMON_APPLICATION_DATA",
                dir.path().join("machine-common"),
            )
            .output()
            .unwrap()
    };

    let output = run(&cargo_registry);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output_text.contains("synthetic-token"));
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["plan"]["name"], "Cargo registry");
    assert_eq!(plan["plan"]["target"], cargo_registry.to_str().unwrap());
    let local_feed_output = run(&local_feed);
    assert!(!local_feed_output.status.success());
    let local_feed_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&local_feed_output.stdout),
        String::from_utf8_lossy(&local_feed_output.stderr)
    );
    assert!(local_feed_text.contains("local NuGet package sources"));
    assert!(!local_feed_text.contains("synthetic-token"));
    let nested_feed = cargo_registry.join("nested-feed");
    fs::create_dir(&nested_feed).unwrap();
    fs::write(nested_feed.join("keep"), b"keep nested feed").unwrap();
    fs::write(
        solution.join("NuGet.config"),
        format!(
            "<configuration><packageSources><add key=\"local\" value=\"{}\" /></packageSources></configuration>",
            nested_feed.display()
        ),
    )
    .unwrap();
    let overlap = run(&cargo_registry);
    assert!(!overlap.status.success());
    assert!(
        String::from_utf8_lossy(&overlap.stdout)
            .contains("selected cache overlaps another discovered cache location")
    );
    assert_eq!(
        fs::read(nested_feed.join("keep")).unwrap(),
        b"keep nested feed"
    );
    assert_eq!(
        fs::read(package_location.join("fixture")).unwrap(),
        b"keep project packages"
    );
    assert_eq!(
        fs::read(local_feed.join("fixture.nupkg")).unwrap(),
        b"keep local feed"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn maven_cache_inventory_uses_user_settings_repository_without_mutating_files() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let custom = home.join("maven-cache");
    let default = home.join(".m2/repository");
    fs::create_dir_all(&custom).unwrap();
    fs::create_dir_all(&default).unwrap();
    fs::write(custom.join("keep.jar"), b"custom").unwrap();
    fs::write(default.join("keep.jar"), b"default").unwrap();
    fs::write(
        home.join(".m2/settings.xml"),
        "<settings xmlns=\"http://maven.apache.org/SETTINGS/1.2.0\"><localRepository>${user.home}/maven-cache</localRepository></settings>",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "cache", "status"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("GOENV", "off")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entries = report["entries"].as_array().unwrap();
    let maven = entries
        .iter()
        .find(|entry| entry["name"] == "Maven")
        .unwrap();
    assert_eq!(maven["path"], custom.to_str().unwrap());
    assert!(
        !entries
            .iter()
            .any(|entry| entry["path"] == default.to_str().unwrap())
    );
    assert_eq!(fs::read(custom.join("keep.jar")).unwrap(), b"custom");
    assert_eq!(fs::read(default.join("keep.jar")).unwrap(), b"default");
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                warning
                    .as_str()
                    .unwrap()
                    .contains("Maven global settings, command-line overrides")
            })
    );
}

#[cfg(target_os = "linux")]
#[test]
fn unresolved_maven_user_settings_are_reported_and_not_inventoried() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let repository = home.join(".m2/repository");
    fs::create_dir_all(&repository).unwrap();
    fs::write(repository.join("keep.jar"), b"fixture").unwrap();
    fs::write(
        home.join(".m2/settings.xml"),
        "<settings><localRepository>relative/fixture-secret</localRepository></settings>",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "cache", "status"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("GOENV", "off")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("fixture-secret"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Maven")
    );
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                warning
                    .as_str()
                    .unwrap()
                    .contains("Maven localRepository must be a safe absolute path")
            })
    );
    assert_eq!(fs::read(repository.join("keep.jar")).unwrap(), b"fixture");
}

#[cfg(target_os = "linux")]
#[test]
fn cache_json_preserves_non_unicode_paths_in_inventory_and_go_preview() {
    use std::{
        ffi::OsString,
        fs,
        os::unix::{ffi::OsStringExt, fs::PermissionsExt},
        process::Command,
    };
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let config = home.join("config");
    let cargo_home = dir.path().join(OsString::from_vec(b"cargo-\xff".to_vec()));
    let registry = cargo_home.join("registry");
    let go_cache = dir.path().join(OsString::from_vec(b"go-\xfe".to_vec()));
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&registry).unwrap();
    fs::create_dir_all(config.join("go")).unwrap();
    fs::create_dir(&go_cache).unwrap();
    fs::write(
        config.join("go/env"),
        format!(
            "GOCACHE=\nGOPATH={}\nGOMODCACHE=\nGOCACHEPROG=\n",
            home.join("go").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&cargo_home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&go_cache, fs::Permissions::from_mode(0o700)).unwrap();
    let cargo_fixture = registry.join("keep");
    fs::write(&cargo_fixture, b"fixture").unwrap();
    fs::set_permissions(&cargo_fixture, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(go_cache.join("testexpire.txt"), b"42\n").unwrap();
    fs::set_permissions(
        go_cache.join("testexpire.txt"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "--offline", "cache", "status"])
        .env_clear()
        .env("HOME", &home)
        .env("CARGO_HOME", &cargo_home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let path = &report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "Cargo registry")
        .unwrap()["path"];
    assert_eq!(path["encoding"], "unix-percent-bytes");
    assert!(
        path["value"]
            .as_str()
            .unwrap()
            .contains("cargo-%FF/registry")
    );
    let preview = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "--non-interactive", "--home"])
        .arg(&home)
        .args(["cache", "go-test", "--path"])
        .arg(&go_cache)
        .arg("--preview")
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .output()
        .unwrap();
    assert!(
        preview.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&preview.stdout),
        String::from_utf8_lossy(&preview.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    for key in ["cache_path", "marker_path"] {
        assert_eq!(preview["plan"][key]["encoding"], "unix-percent-bytes");
        assert!(
            preview["plan"][key]["value"]
                .as_str()
                .unwrap()
                .contains("go-%FE")
        );
    }
    assert!(preview["plan"]["preview_token"].as_str().is_some());

    if let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) {
        let preview = isolated_upkit_command(&isolated_opt)
            .args(["--json", "--non-interactive", "--home"])
            .arg(home.join("upkit"))
            .args(["sweep", "run", "--scope", "cache", "--select"])
            .arg(&registry)
            .arg("--preview")
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("CARGO_HOME", &cargo_home)
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .output()
            .unwrap();
        assert!(
            preview.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&preview.stdout),
            String::from_utf8_lossy(&preview.stderr)
        );
        let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
        assert_eq!(preview["plan"]["target"]["encoding"], "unix-percent-bytes");
        assert!(
            preview["plan"]["target"]["value"]
                .as_str()
                .unwrap()
                .contains("cargo-%FF/registry")
        );
    }
    assert_eq!(fs::read(registry.join("keep")).unwrap(), b"fixture");
    assert_eq!(fs::read(go_cache.join("testexpire.txt")).unwrap(), b"42\n");
}

#[cfg(target_os = "linux")]
#[test]
fn configured_yarn_and_compiler_caches_are_inventoried_without_mutation() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let yarn = dir.path().join("yarn-cache");
    let ccache = dir.path().join("ccache");
    let sccache = dir.path().join("sccache");
    let pnpm_store = dir.path().join("pnpm-home/store");
    for path in [&home, &yarn, &ccache, &sccache, &pnpm_store] {
        fs::create_dir_all(path).unwrap();
    }
    for (path, contents) in [
        (&yarn, b"yarn".as_slice()),
        (&ccache, b"ccache".as_slice()),
        (&sccache, b"sccache".as_slice()),
        (&pnpm_store, b"pnpm".as_slice()),
    ] {
        fs::write(path.join("fixture"), contents).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "cache", "status"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("GOENV", "off")
        .env("YARN_CACHE_FOLDER", &yarn)
        .env("CCACHE_DIR", &ccache)
        .env("SCCACHE_DIR", &sccache)
        .env("PNPM_HOME", pnpm_store.parent().unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for (name, path, expected) in [
        ("Yarn classic", yarn, b"yarn".as_slice()),
        ("ccache", ccache, b"ccache".as_slice()),
        ("sccache", sccache, b"sccache".as_slice()),
        ("pnpm", pnpm_store, b"pnpm".as_slice()),
    ] {
        let entry = report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap();
        assert_eq!(entry["path"], path.to_str().unwrap());
        assert_eq!(entry["logical_bytes"], expected.len());
        assert_eq!(entry["status"], "inventory only");
        assert_eq!(fs::read(path.join("fixture")).unwrap(), expected);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn pnpm_inferred_store_can_be_inspected_but_not_removed() {
    let dir = tempfile::tempdir().unwrap();
    let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) else {
        return;
    };
    let home = dir.path().join("home");
    let store = home.join(".local/share/pnpm/store");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::create_dir_all(home.join(".config/go")).unwrap();
    std::fs::write(
        home.join(".config/go/env"),
        format!(
            "GOCACHE=\nGOPATH={}\nGOMODCACHE=\nGOCACHEPROG=\n",
            home.join("go").display()
        ),
    )
    .unwrap();
    std::fs::write(store.join("fixture"), b"keep").unwrap();
    let output = isolated_upkit_command(&isolated_opt)
        .args(["--json", "--non-interactive", "--home"])
        .arg(home.join("upkit-data"))
        .args(["sweep", "run", "--scope", "cache", "--select"])
        .arg(&store)
        .arg("--preview")
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("configured per workspace or filesystem"),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(store.join("fixture")).unwrap(), b"keep");
}

#[cfg(target_os = "linux")]
#[test]
fn unresolved_pnpm_store_blocks_removal_of_other_shared_caches() {
    let dir = tempfile::tempdir().unwrap();
    let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) else {
        return;
    };
    let home = dir.path().join("home");
    let registry = home.join(".cargo/registry");
    std::fs::create_dir_all(&registry).unwrap();
    std::fs::create_dir_all(home.join(".config/go")).unwrap();
    std::fs::write(
        home.join(".config/go/env"),
        format!(
            "GOCACHE=\nGOPATH={}\nGOMODCACHE=\nGOCACHEPROG=\n",
            home.join("go").display()
        ),
    )
    .unwrap();
    std::fs::write(registry.join("fixture"), b"keep").unwrap();
    let output = isolated_upkit_command(&isolated_opt)
        .args(["--json", "--non-interactive", "--home"])
        .arg(home.join("upkit-data"))
        .args(["sweep", "run", "--scope", "cache", "--select"])
        .arg(&registry)
        .arg("--preview")
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("PNPM_CONFIG_STORE_DIR", "relative/store")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("pnpm store configuration is not absolute"),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(registry.join("fixture")).unwrap(), b"keep");
}

#[cfg(target_os = "linux")]
#[test]
fn uv_cache_inventory_is_read_only_and_respects_absolute_overrides() {
    use std::{fs, os::unix::fs::symlink, path::Path, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let xdg = home.join("cache");
    let default_cache = xdg.join("uv");
    let override_cache = dir.path().join("custom-uv-cache");
    fs::create_dir_all(&default_cache).unwrap();
    fs::create_dir_all(&override_cache).unwrap();
    fs::write(default_cache.join("fixture"), b"default uv").unwrap();
    fs::write(override_cache.join("fixture"), b"custom uv").unwrap();

    let run = |home: &Path, xdg: &Path, override_dir: Option<&Path>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        command
            .current_dir(dir.path())
            .args(["--json", "cache", "status"])
            .env_clear()
            .env("HOME", home)
            .env("PATH", "")
            .env("XDG_CACHE_HOME", xdg)
            .env("XDG_DATA_HOME", home.join("data"))
            .env("GOENV", "off");
        if let Some(path) = override_dir {
            command.env("UV_CACHE_DIR", path);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let uv_entry = |report: &serde_json::Value| {
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "uv")
            .cloned()
    };

    let report = run(&home, &xdg, None);
    let entry = uv_entry(&report).unwrap();
    assert_eq!(entry["path"], default_cache.to_str().unwrap());
    assert_eq!(entry["logical_bytes"], 10);
    assert_eq!(entry["classification"], "shared package cache");
    assert_eq!(entry["status"], "inventory only");
    assert_eq!(
        fs::read(default_cache.join("fixture")).unwrap(),
        b"default uv"
    );
    assert_eq!(
        fs::read(override_cache.join("fixture")).unwrap(),
        b"custom uv"
    );

    let report = run(&home, &xdg, Some(&override_cache));
    let entry = uv_entry(&report).unwrap();
    assert_eq!(entry["path"], override_cache.to_str().unwrap());
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"] == default_cache.to_str().unwrap())
    );
    assert_eq!(
        fs::read(default_cache.join("fixture")).unwrap(),
        b"default uv"
    );
    assert_eq!(
        fs::read(override_cache.join("fixture")).unwrap(),
        b"custom uv"
    );

    let report = run(&home, &xdg, Some(Path::new("relative-uv-cache")));
    assert!(uv_entry(&report).is_none());
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning == "uv: UV_CACHE_DIR is not absolute; cache location skipped")
    );

    let missing_home = dir.path().join("missing-home");
    let missing_xdg = missing_home.join("cache");
    fs::create_dir_all(&missing_home).unwrap();
    let report = run(&missing_home, &missing_xdg, None);
    assert!(uv_entry(&report).is_none());

    let outside = dir.path().join("outside-uv-cache");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("fixture"), b"keep").unwrap();
    let linked_cache = dir.path().join("linked-uv-cache");
    symlink(&outside, &linked_cache).unwrap();
    let report = run(&home, &xdg, Some(&linked_cache));
    assert!(uv_entry(&report).is_none());
    assert_eq!(fs::read(outside.join("fixture")).unwrap(), b"keep");
}

#[cfg(target_os = "linux")]
#[test]
fn go_module_cache_uses_first_gopath_entry() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let config = dir.path().join("config");
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    let modules = first.join("pkg/mod");
    fs::create_dir_all(config.join("go")).unwrap();
    fs::write(
        config.join("go/env"),
        b"GOCACHE=\nGOPATH=\nGOMODCACHE=\nGOCACHEPROG=\n",
    )
    .unwrap();
    fs::create_dir_all(&modules).unwrap();
    fs::write(modules.join("fixture"), b"modules").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "cache", "status"])
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("GOPATH", std::env::join_paths([&first, &second]).unwrap())
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entry = report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "Go modules")
        .unwrap();
    assert_eq!(entry["path"], modules.to_str().unwrap());
    assert_eq!(entry["logical_bytes"], 7);
    assert!(modules.join("fixture").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn go_cache_inventory_respects_persistent_environment_and_process_overrides() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let config = home.join("config");
    let persistent_cache = home.join("persistent-build");
    let override_cache = home.join("override-build");
    let modules = home.join("persistent-modules");
    for path in [
        &persistent_cache,
        &override_cache,
        &modules,
        &config.join("go"),
    ] {
        fs::create_dir_all(path).unwrap();
    }
    fs::write(persistent_cache.join("artifact"), "persistent").unwrap();
    fs::write(override_cache.join("artifact"), "override").unwrap();
    fs::write(modules.join("module"), "module").unwrap();
    let env_file = config.join("go/env");
    fs::write(
        &env_file,
        format!(
            "GOCACHE=/ignored\nGOCACHE={}\nGOMODCACHE={}\nGOCACHEPROG=/not/executed\n",
            persistent_cache.display(),
            modules.display()
        ),
    )
    .unwrap();
    let fake_bin = home.join("bin");
    fs::create_dir(&fake_bin).unwrap();
    let fake_go = fake_bin.join("go");
    fs::write(
        &fake_go,
        format!(
            "#!/bin/sh\nprintf invoked > '{}'\n",
            home.join("go-invoked").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_go, fs::Permissions::from_mode(0o755)).unwrap();
    let run = |overrides: &[(&str, &std::ffi::OsStr)]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        command
            .current_dir(dir.path())
            .args(["--json", "cache", "status"])
            .env_clear()
            .env("HOME", &home)
            .env("PATH", &fake_bin)
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("XDG_DATA_HOME", home.join("data"));
        for (key, value) in overrides {
            command.env(key, value);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let path = |report: &serde_json::Value, name: &str| {
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap()["path"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let report = run(&[("GOCACHE", std::ffi::OsStr::new(""))]);
    assert_eq!(
        path(&report, "Go build"),
        persistent_cache.to_str().unwrap()
    );
    assert_eq!(path(&report, "Go modules"), modules.to_str().unwrap());
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning
                .as_str()
                .unwrap()
                .contains("external Go build-cache program"))
    );
    let report = run(&[("GOCACHE", override_cache.as_os_str())]);
    assert_eq!(path(&report, "Go build"), override_cache.to_str().unwrap());
    assert_eq!(path(&report, "Go modules"), modules.to_str().unwrap());
    let report = run(&[
        ("GOENV", std::ffi::OsStr::new("off")),
        ("GOCACHE", override_cache.as_os_str()),
    ]);
    assert_eq!(path(&report, "Go build"), override_cache.to_str().unwrap());
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go modules")
    );
    assert!(
        !report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning
                .as_str()
                .unwrap()
                .contains("external Go build-cache program"))
    );
    assert!(!home.join("go-invoked").exists());
    assert!(persistent_cache.join("artifact").exists() && modules.join("module").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn go_user_empty_settings_shield_unknown_goroot_defaults() {
    use std::{fs, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let config = dir.path().join("config");
    let cache = dir.path().join("cache");
    let goroot = dir.path().join("unverified-goroot");
    let user_env = config.join("go/env");
    let build = cache.join("go-build");
    let modules = home.join("go/pkg/mod");
    let root_build = dir.path().join("goroot-build");
    let root_gopath = dir.path().join("goroot-gopath");
    let root_modules = dir.path().join("goroot-modules");
    fs::create_dir_all(user_env.parent().unwrap()).unwrap();
    fs::create_dir_all(goroot.join("go")).unwrap();
    for path in [&build, &modules, &root_build, &root_gopath, &root_modules] {
        fs::create_dir_all(path).unwrap();
    }
    fs::write(&user_env, b"GOCACHE=\nGOPATH=\nGOMODCACHE=\nGOCACHEPROG=\n").unwrap();
    fs::write(
        goroot.join("go.env"),
        format!(
            "GOCACHE={}\nGOPATH={}\nGOMODCACHE={}\nGOCACHEPROG=C:\\private\\untrusted-go-cache.exe\n",
            root_build.display(),
            root_gopath.display(),
            root_modules.display(),
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "cache", "status"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "")
        .env("GOROOT", &goroot)
        .env("GOTOOLCHAIN", "auto")
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_DATA_HOME", home.join("data"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let path = |name: &str| {
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap()["path"]
            .as_str()
            .unwrap()
    };
    assert_eq!(path("Go build"), build.to_str().unwrap());
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go modules")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("goroot-build"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("goroot-modules"));
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                let warning = warning.as_str().unwrap();
                warning.contains("Go:") && warning.contains("unknown or unresolved")
            })
    );
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|warning| !warning
                .as_str()
                .unwrap()
                .contains("external Go build-cache program"))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn goenv_off_and_missing_user_keys_do_not_claim_unknown_goroot_defaults() {
    use std::{fs, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let config = dir.path().join("config");
    let goroot = dir.path().join("unverified-goroot");
    let user_build = dir.path().join("user-build");
    let user_modules = dir.path().join("user-modules");
    let root_build = dir.path().join("goroot-build");
    let root_modules = dir.path().join("goroot-modules");
    let process_build = dir.path().join("process-build");
    fs::create_dir_all(config.join("go")).unwrap();
    fs::create_dir_all(goroot.join("go")).unwrap();
    for path in [
        &user_build,
        &user_modules,
        &root_build,
        &root_modules,
        &process_build,
    ] {
        fs::create_dir_all(path).unwrap();
    }
    fs::write(
        config.join("go/env"),
        format!(
            "GOCACHE={}\nGOMODCACHE={}\nGOCACHEPROG=\n",
            user_build.display(),
            user_modules.display()
        ),
    )
    .unwrap();
    fs::write(
        goroot.join("go.env"),
        format!(
            "GOCACHE={}\nGOMODCACHE={}\nGOCACHEPROG=C:\\private\\untrusted-go-cache.exe\n",
            root_build.display(),
            root_modules.display()
        ),
    )
    .unwrap();

    let run = |goenv: Option<&std::ffi::OsStr>, gocache: Option<&std::path::Path>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        command
            .current_dir(dir.path())
            .args(["--json", "cache", "status"])
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "")
            .env("GOROOT", &goroot)
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("XDG_DATA_HOME", home.join("data"));
        if let Some(goenv) = goenv {
            command.env("GOENV", goenv);
        }
        if let Some(gocache) = gocache {
            command.env("GOCACHE", gocache);
        }
        command.output().unwrap()
    };
    let report = |output: &std::process::Output| {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let go_entries = |report: &serde_json::Value| {
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| matches!(entry["name"].as_str(), Some("Go build" | "Go modules")))
            .cloned()
            .collect::<Vec<_>>()
    };

    let configured = report(&run(None, None));
    assert_eq!(go_entries(&configured).len(), 2);
    assert!(
        configured["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go build"
                && entry["path"] == user_build.to_str().unwrap())
    );
    assert!(
        configured["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go modules"
                && entry["path"] == user_modules.to_str().unwrap())
    );

    let disabled = report(&run(Some(std::ffi::OsStr::new("off")), None));
    assert!(go_entries(&disabled).is_empty());
    assert!(
        disabled["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                let warning = warning.as_str().unwrap();
                warning.contains("Go:") && warning.contains("unknown or unresolved")
            })
    );
    let process = report(&run(
        Some(std::ffi::OsStr::new("off")),
        Some(&process_build),
    ));
    assert!(process["entries"].as_array().unwrap().iter().any(
        |entry| entry["name"] == "Go build" && entry["path"] == process_build.to_str().unwrap()
    ));
    assert!(
        !process["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go modules")
    );

    let missing_home = dir.path().join("missing-home");
    let missing = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "cache", "status"])
        .env_clear()
        .env("HOME", &missing_home)
        .env("PATH", "")
        .env("GOROOT", &goroot)
        .env("XDG_CONFIG_HOME", dir.path().join("missing-config"))
        .env("XDG_CACHE_HOME", missing_home.join("cache"))
        .env("XDG_DATA_HOME", missing_home.join("data"))
        .output()
        .unwrap();
    let missing = report(&missing);
    assert!(go_entries(&missing).is_empty());
    assert!(
        !serde_json::to_string(&missing)
            .unwrap()
            .contains("goroot-build")
    );
    assert!(
        !serde_json::to_string(&missing)
            .unwrap()
            .contains("goroot-modules")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn go_persistent_environment_gopath_and_unsafe_file_are_reported() {
    use std::{
        fs,
        os::unix::{fs::symlink, net::UnixListener},
        process::Command,
    };
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let first = home.join("first");
    let second = home.join("second");
    fs::create_dir_all(first.join("pkg/mod")).unwrap();
    fs::create_dir_all(&second).unwrap();
    let env_file = home.join("custom-go-env");
    fs::write(
        &env_file,
        format!(
            "GOCACHE=\nGOPATH={}\nGOMODCACHE=\nGOCACHEPROG=\n",
            std::env::join_paths([&first, &second])
                .unwrap()
                .to_string_lossy()
        ),
    )
    .unwrap();
    let run = |selected: &std::path::Path| {
        let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
            .current_dir(dir.path())
            .args(["--json", "cache", "status"])
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("GOENV", selected)
            .output()
            .unwrap();
        assert!(output.status.success());
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let report = run(&env_file);
    assert_eq!(
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "Go modules")
            .unwrap()["path"],
        first.join("pkg/mod").to_str().unwrap()
    );
    let link = home.join("linked-go-env");
    symlink(&env_file, &link).unwrap();
    let report = run(&link);
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go build" || entry["name"] == "Go modules")
    );
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("persistent environment"))
    );
    assert!(env_file.exists());
    let oversized = home.join("oversized-go-env");
    fs::write(&oversized, vec![b'x'; 256 * 1024 + 1]).unwrap();
    let report = run(&oversized);
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go build" || entry["name"] == "Go modules")
    );
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("too large"))
    );
    let socket = home.join("socket-go-env");
    let _listener = UnixListener::bind(&socket).unwrap();
    let report = run(&socket);
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go build" || entry["name"] == "Go modules")
    );
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning.as_str().unwrap().contains("persistent environment"))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn relative_xdg_directories_do_not_select_wrong_go_defaults() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let wrong_cache = home.join(".cache/go-build");
    let configured = home.join("configured-cache");
    fs::create_dir_all(&wrong_cache).unwrap();
    fs::create_dir_all(&configured).unwrap();
    fs::create_dir_all(home.join(".config/go")).unwrap();
    let env_file = home.join(".config/go/env");
    fs::write(
        &env_file,
        format!(
            "GOCACHE={}\nGOPATH={}\nGOMODCACHE=\nGOCACHEPROG=\n",
            configured.display(),
            home.join("go").display()
        ),
    )
    .unwrap();
    let run = |goenv: Option<&std::path::Path>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        command
            .current_dir(dir.path())
            .args(["--json", "cache", "status"])
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", "relative-config")
            .env("XDG_CACHE_HOME", "relative-cache")
            .env("XDG_DATA_HOME", home.join("data"));
        if let Some(path) = goenv {
            command.env("GOENV", path);
        }
        let output = command.output().unwrap();
        assert!(output.status.success());
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let report = run(None);
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go build")
    );
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning
                .as_str()
                .unwrap()
                .contains("XDG_CONFIG_HOME is relative"))
    );
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                let warning = warning.as_str().unwrap();
                warning.contains("Go:") && warning.contains("unknown or unresolved")
            })
    );
    let report = run(Some(&env_file));
    let build = report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "Go build")
        .unwrap();
    assert_eq!(build["path"], configured.to_str().unwrap());
    assert!(wrong_cache.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn go_test_cache_marker_is_visible_without_mutation() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("go-build");
    fs::create_dir(&cache).unwrap();
    fs::write(cache.join("testexpire.txt"), "123456789\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "cache", "status"])
        .env_clear()
        .env("HOME", dir.path())
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .env("GOCACHE", &cache)
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let entry = report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "Go build")
        .unwrap();
    assert_eq!(entry["go_test_cache"]["status"], "expiration_marker");
    assert_eq!(
        entry["go_test_cache"]["expired_before_unix_nanos"],
        123456789_u64
    );
    assert_eq!(
        fs::read_to_string(cache.join("testexpire.txt")).unwrap(),
        "123456789\n"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn go_test_preview_binds_identity_and_rejects_links() {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache");
    fs::create_dir(&cache).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    let marker = cache.join("testexpire.txt");
    let empty = upkit::cache::go_test_expiration_preview(&cache).unwrap();
    assert_eq!(empty.current_expiration_unix_nanos, None);
    fs::write(&marker, "123\n").unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    let first = upkit::cache::go_test_expiration_preview(&cache).unwrap();
    assert_eq!(first.current_expiration_unix_nanos, Some(123));
    assert_ne!(first.preview_token, empty.preview_token);
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&marker)
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    assert!(upkit::cache::go_test_expiration_preview(&cache).is_err());
    drop(lock);
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(upkit::cache::go_test_expiration_preview(&cache).is_err());
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&marker, "456\n").unwrap();
    let changed = upkit::cache::go_test_expiration_preview(&cache).unwrap();
    assert_ne!(first.preview_token, changed.preview_token);
    let outside = dir.path().join("outside");
    fs::write(&outside, "789\n").unwrap();
    fs::remove_file(&marker).unwrap();
    fs::hard_link(&outside, &marker).unwrap();
    assert!(upkit::cache::go_test_expiration_preview(&cache).is_err());
    fs::remove_file(&marker).unwrap();
    symlink(&outside, &marker).unwrap();
    assert!(upkit::cache::go_test_expiration_preview(&cache).is_err());
    assert_eq!(fs::read_to_string(&outside).unwrap(), "789\n");
}

#[cfg(target_os = "linux")]
#[test]
fn go_test_expiration_requires_matching_preview_and_verifies_fixture() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache");
    fs::create_dir(&cache).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(cache.join("artifact"), "keep").unwrap();
    let plan = upkit::cache::go_test_expiration_preview(&cache).unwrap();
    assert!(upkit::cache::expire_go_test_cache(&plan, "wrong").is_err());
    assert!(!cache.join("testexpire.txt").exists());
    let result = upkit::cache::expire_go_test_cache(&plan, &plan.preview_token).unwrap();
    assert!(result.changed);
    assert_eq!(result.verification, "marker_matches");
    assert_eq!(
        fs::read_to_string(cache.join("testexpire.txt"))
            .unwrap()
            .trim()
            .parse::<u64>()
            .unwrap(),
        result.expired_before_unix_nanos
    );
    assert_eq!(fs::read_to_string(cache.join("artifact")).unwrap(), "keep");
    assert!(upkit::cache::expire_go_test_cache(&plan, &plan.preview_token).is_err());
    let next = upkit::cache::go_test_expiration_preview(&cache).unwrap();
    fs::write(cache.join("testexpire.txt"), "42\n").unwrap();
    assert!(upkit::cache::expire_go_test_cache(&next, &next.preview_token).is_err());
    assert_eq!(
        fs::read_to_string(cache.join("testexpire.txt")).unwrap(),
        "42\n"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn go_test_cli_requires_explicit_authorization_and_records_fixture_result() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache");
    let home = dir.path().join("upkit-data");
    fs::create_dir(&cache).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(cache.join("keep"), "fixture").unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .current_dir(dir.path())
            .args(["--json", "--non-interactive", "--home"])
            .arg(&home)
            .args(args)
            .env_clear()
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path())
            .output()
            .unwrap()
    };
    let path = cache.to_str().unwrap();
    let preview = run(&["cache", "go-test", "--path", path, "--preview"]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let token = plan["plan"]["preview_token"].as_str().unwrap();
    assert!(!cache.join("testexpire.txt").exists());
    assert!(
        !run(&[
            "--yes",
            "cache",
            "go-test",
            "--path",
            path,
            "--run",
            "--preview-token",
            token
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "--yes",
            "cache",
            "go-test",
            "--path",
            path,
            "--run",
            "--preview-token",
            "wrong",
            "--authorize-shared-cache"
        ])
        .status
        .success()
    );
    assert!(!cache.join("testexpire.txt").exists());
    let dry = run(&["--dry-run", "cache", "go-test", "--path", path, "--run"]);
    assert!(dry.status.success());
    assert!(!cache.join("testexpire.txt").exists());
    let result = run(&[
        "--yes",
        "cache",
        "go-test",
        "--path",
        path,
        "--run",
        "--preview-token",
        token,
        "--authorize-shared-cache",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["result"]["verification"], "marker_matches");
    assert_eq!(fs::read_to_string(cache.join("keep")).unwrap(), "fixture");
    let history = run(&["report"]);
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["operation"] == "go_test_cache_expiration"
                && record["outcome"] == "completed")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn zig_global_cache_inventory_uses_override_and_xdg_default_without_mutating_files() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let xdg_cache = home.join("cache");
    let default = xdg_cache.join("zig");
    let custom = dir.path().join("custom-zig-cache");
    for (cache, value) in [(&default, "default"), (&custom, "custom")] {
        fs::create_dir_all(cache).unwrap();
        fs::write(cache.join("keep"), value).unwrap();
    }
    let run = |override_path: Option<&std::path::Path>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        command
            .current_dir(dir.path())
            .args(["--json", "cache", "status"])
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CACHE_HOME", &xdg_cache)
            .env("XDG_DATA_HOME", home.join("data"))
            .env("PATH", "/usr/bin:/bin");
        if let Some(path) = override_path {
            command.env("ZIG_GLOBAL_CACHE_DIR", path);
        }
        command.output().unwrap()
    };
    for (output, expected, marker) in [
        (run(None), default.as_path(), "default"),
        (run(Some(&custom)), custom.as_path(), "custom"),
    ] {
        assert!(output.status.success());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let zig = report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "Zig")
            .unwrap();
        assert_eq!(zig["path"], expected.to_str().unwrap());
        assert_eq!(zig["classification"], "shared build cache");
        assert_eq!(zig["status"], "inventory only");
        assert_eq!(fs::read_to_string(expected.join("keep")).unwrap(), marker);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn relative_zig_global_cache_is_reported_and_not_inventoried() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let default = home.join("cache/zig");
    fs::create_dir_all(&default).unwrap();
    fs::write(default.join("keep"), "fixture").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .current_dir(dir.path())
        .args(["--json", "cache", "status"])
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("ZIG_GLOBAL_CACHE_DIR", "relative/zig")
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Zig")
    );
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                warning
                    .as_str()
                    .unwrap()
                    .contains("ZIG_GLOBAL_CACHE_DIR must be an absolute path")
            })
    );
    assert_eq!(fs::read_to_string(default.join("keep")).unwrap(), "fixture");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_go_environment_uses_go_config_dir_without_exposing_other_values() {
    use std::{fs, os::unix::fs::symlink, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let home = root.join("home");
    let config = home.join("Library/Application Support/go");
    let build = root.join("configured-build");
    let modules = root.join("configured-modules");
    let override_config = root.join("selected-go-env");
    let selected_build = root.join("selected-build");
    let selected_modules = root.join("selected-modules");
    let process_build = root.join("process-build");
    for path in [
        &config,
        &build,
        &modules,
        &selected_build,
        &selected_modules,
        &process_build,
    ] {
        fs::create_dir_all(path).unwrap();
    }
    fs::write(build.join("keep"), b"build").unwrap();
    fs::write(modules.join("keep"), b"modules").unwrap();
    fs::write(selected_build.join("keep"), b"selected build").unwrap();
    fs::write(selected_modules.join("keep"), b"selected modules").unwrap();
    fs::write(process_build.join("keep"), b"process build").unwrap();
    fs::write(
        config.join("env"),
        format!(
            "GOCACHE={}\nGOMODCACHE={}\nGOCACHEPROG=/private/go-config-secret\n",
            build.display(),
            modules.display()
        ),
    )
    .unwrap();
    fs::write(
        &override_config,
        format!(
            "GOCACHE={}\nGOMODCACHE={}\nGOCACHEPROG=/private/selected-go-secret\n",
            selected_build.display(),
            selected_modules.display()
        ),
    )
    .unwrap();

    let run = |goenv: Option<&std::path::Path>, gocache: Option<&std::path::Path>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        command
            .current_dir(dir.path())
            .args(["--json", "cache", "status"])
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", root.join("wrong-xdg-config"))
            .env("XDG_CACHE_HOME", root.join("cache"))
            .env("XDG_DATA_HOME", root.join("data"));
        if let Some(goenv) = goenv {
            command.env("GOENV", goenv);
        }
        if let Some(gocache) = gocache {
            command.env("GOCACHE", gocache);
        }
        command.output().unwrap()
    };
    let path = |report: &serde_json::Value, name: &str| {
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap()["path"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    for (output, expected_build, expected_modules) in [
        (run(None, None), &build, &modules),
        (
            run(Some(&override_config), Some(&process_build)),
            &process_build,
            &selected_modules,
        ),
    ] {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.contains("go-config-secret"));
        assert!(!stdout.contains("selected-go-secret"));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(path(&report, "Go build"), expected_build.to_str().unwrap());
        assert_eq!(
            path(&report, "Go modules"),
            expected_modules.to_str().unwrap()
        );
    }

    let linked_env = root.join("linked-go-env");
    symlink(&override_config, &linked_env).unwrap();
    let output = run(Some(&linked_env), None);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go build" || entry["name"] == "Go modules")
    );
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| { warning.as_str().unwrap().contains("persistent environment") })
    );
    let oversized_env = root.join("oversized-go-env");
    fs::write(&oversized_env, vec![b'x'; 256 * 1024 + 1]).unwrap();
    let output = run(Some(&oversized_env), None);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| { warning.as_str().unwrap().contains("too large") })
    );
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go build" || entry["name"] == "Go modules")
    );
    assert_eq!(fs::read(build.join("keep")).unwrap(), b"build");
    assert_eq!(fs::read(modules.join("keep")).unwrap(), b"modules");
    assert_eq!(
        fs::read(selected_build.join("keep")).unwrap(),
        b"selected build"
    );
    assert_eq!(
        fs::read(selected_modules.join("keep")).unwrap(),
        b"selected modules"
    );
    assert_eq!(
        fs::read(process_build.join("keep")).unwrap(),
        b"process build"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_go_environment_reads_default_and_override_with_process_precedence() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let app_data = root.join("appdata");
    let home = root.join("home");
    let local = root.join("local");
    let default_env = app_data.join("go/env");
    let override_env = root.join("custom-go-env");
    let default_build = root.join("configured-default-build");
    let default_modules = root.join("configured-default-modules");
    let override_build = root.join("configured-override-build");
    let override_modules = root.join("configured-override-modules");
    let process_build = root.join("process-build");
    let paths = [
        default_env.parent().unwrap().to_path_buf(),
        home.clone(),
        local.clone(),
        default_build.clone(),
        default_modules.clone(),
        override_build.clone(),
        override_modules.clone(),
        process_build.clone(),
    ];
    for path in paths {
        fs::create_dir_all(path).unwrap();
    }
    fs::write(
        &default_env,
        format!(
            "GOCACHE={}\nGOMODCACHE={}\nGOCACHEPROG=C:\\private\\go-config-secret.exe\n",
            default_build.display(),
            default_modules.display()
        ),
    )
    .unwrap();
    fs::write(
        &override_env,
        format!(
            "GOCACHE={}\nGOMODCACHE={}\nGOCACHEPROG=C:\\private\\selected-go-secret.exe\n",
            override_build.display(),
            override_modules.display()
        ),
    )
    .unwrap();

    let run = |goenv: Option<&std::ffi::OsStr>, gocache: Option<&std::ffi::OsStr>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        command
            .current_dir(&root)
            .args(["--json", "cache", "status"])
            .env_clear()
            .env("APPDATA", &app_data)
            .env("USERPROFILE", &home)
            .env("LOCALAPPDATA", &local);
        if let Some(goenv) = goenv {
            command.env("GOENV", goenv);
        }
        if let Some(gocache) = gocache {
            command.env("GOCACHE", gocache);
        }
        command.output().unwrap()
    };
    let report = |output: &std::process::Output| {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let path = |report: &serde_json::Value, name: &str| {
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap_or_else(|| {
                // Log only classification labels, never paths or values from
                // the user's environment. This fixture uses synthetic paths.
                let reasons: Vec<_> = report["warnings"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|warning| warning.as_str())
                    .filter(|warning| warning.contains("Go"))
                    .map(|warning| {
                        if warning.contains("location is unsafe or unavailable") {
                            "goenv_location_unsafe"
                        } else if warning.contains("is unreadable, unsafe") {
                            "goenv_read_unverified"
                        } else if warning.contains("contains unsupported values") {
                            "goenv_parse_unverified"
                        } else if warning.contains("cache configuration is incomplete") {
                            "cache_scope_unverified"
                        } else if warning.contains("default build cache is unavailable") {
                            "build_cache_unavailable"
                        } else {
                            "other_go_warning"
                        }
                    })
                    .collect();
                panic!("fixture expected {name} inventory, but it is absent; Go diagnostics: {reasons:?}")
            })["path"]
            .as_str()
            .unwrap()
            .to_owned()
    };

    let default_report = report(&run(None, None));
    assert_eq!(
        path(&default_report, "Go build"),
        default_build.to_str().unwrap()
    );
    assert_eq!(
        path(&default_report, "Go modules"),
        default_modules.to_str().unwrap()
    );
    assert!(
        !serde_json::to_string(&default_report)
            .unwrap()
            .contains("go-config-secret")
    );

    let override_report = report(&run(
        Some(override_env.as_os_str()),
        Some(process_build.as_os_str()),
    ));
    assert_eq!(
        path(&override_report, "Go build"),
        process_build.to_str().unwrap()
    );
    assert_eq!(
        path(&override_report, "Go modules"),
        override_modules.to_str().unwrap()
    );
    assert!(
        !serde_json::to_string(&override_report)
            .unwrap()
            .contains("selected-go-secret")
    );

    let unsafe_report = report(&run(Some(std::ffi::OsStr::new("relative-go-env")), None));
    assert!(
        !unsafe_report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go build" || entry["name"] == "Go modules")
    );
    assert!(
        unsafe_report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning
                .as_str()
                .unwrap()
                .contains("location is unsafe or unavailable on Windows"))
    );
    let unsafe_with_process_cache = report(&run(
        Some(std::ffi::OsStr::new("relative-go-env")),
        Some(process_build.as_os_str()),
    ));
    assert_eq!(
        path(&unsafe_with_process_cache, "Go build"),
        process_build.to_str().unwrap()
    );
    assert!(
        !unsafe_with_process_cache["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go modules")
    );

    let disabled_report = report(&run(Some(std::ffi::OsStr::new("off")), None));
    assert!(
        !disabled_report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go build" || entry["name"] == "Go modules")
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_go_environment_requires_known_gopath_and_follows_localappdata() {
    use std::{fs, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("go-home");
    let local = dir.path().join("go-local");
    let default_gopath = home.join("go");
    let default_modules = default_gopath.join("pkg/mod");
    let default_build = local.join("go-build");
    let override_gopath = dir.path().join("override-gopath");
    let override_modules = override_gopath.join("pkg/mod");
    let override_build = dir.path().join("override-build");
    let go_env = dir.path().join("fixture-go-env");
    for path in [
        &default_modules,
        &default_build,
        &override_modules,
        &override_build,
    ] {
        fs::create_dir_all(path).unwrap();
    }
    for (path, content) in [
        (&default_modules, b"default modules".as_slice()),
        (&default_build, b"default build".as_slice()),
        (&override_modules, b"override modules".as_slice()),
        (&override_build, b"override build".as_slice()),
    ] {
        fs::write(path.join("keep"), content).unwrap();
    }
    fs::write(&go_env, b"GOCACHE=\nGOPATH=\nGOMODCACHE=\nGOCACHEPROG=\n").unwrap();

    let run = |userprofile: Option<&std::ffi::OsStr>,
               localappdata: Option<&std::ffi::OsStr>,
               gopath: Option<&std::ffi::OsStr>,
               gocache: Option<&std::ffi::OsStr>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        command
            .current_dir(dir.path())
            .args(["--json", "cache", "status"])
            .env_clear()
            .env("GOENV", &go_env);
        for (key, value) in [
            ("USERPROFILE", userprofile),
            ("LOCALAPPDATA", localappdata),
            ("GOPATH", gopath),
            ("GOCACHE", gocache),
        ] {
            if let Some(value) = value {
                command.env(key, value);
            }
        }
        command.output().unwrap()
    };
    let parse_report = |output: &std::process::Output| {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let path = |report: &serde_json::Value, name: &str| {
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap_or_else(|| {
                // Log only classification labels, never paths or values from
                // the user's environment. This fixture uses synthetic paths.
                let reasons: Vec<_> = report["warnings"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|warning| warning.as_str())
                    .filter(|warning| warning.contains("Go"))
                    .map(|warning| {
                        if warning.contains("location is unsafe or unavailable") {
                            "goenv_location_unsafe"
                        } else if warning.contains("is unreadable, unsafe") {
                            "goenv_read_unverified"
                        } else if warning.contains("contains unsupported values") {
                            "goenv_parse_unverified"
                        } else if warning.contains("cache configuration is incomplete") {
                            "cache_scope_unverified"
                        } else if warning.contains("default build cache is unavailable") {
                            "build_cache_unavailable"
                        } else {
                            "other_go_warning"
                        }
                    })
                    .collect();
                panic!("fixture expected {name} inventory, but it is absent; Go diagnostics: {reasons:?}")
            })["path"]
            .as_str()
            .unwrap()
            .to_owned()
    };

    let report = parse_report(&run(
        Some(home.as_os_str()),
        Some(local.as_os_str()),
        None,
        None,
    ));
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go modules")
    );
    assert_eq!(path(&report, "Go build"), default_build.to_str().unwrap());
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                let warning = warning.as_str().unwrap();
                warning.contains("Go:") && warning.contains("unknown or unresolved")
            })
    );
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|warning| {
                !warning
                    .as_str()
                    .unwrap()
                    .contains("Go's default build cache is unavailable")
            })
    );

    let report = parse_report(&run(
        Some(home.as_os_str()),
        Some(local.as_os_str()),
        Some(override_gopath.as_os_str()),
        Some(override_build.as_os_str()),
    ));
    assert_eq!(
        path(&report, "Go modules"),
        override_modules.to_str().unwrap()
    );
    assert_eq!(path(&report, "Go build"), override_build.to_str().unwrap());

    for (profile, local_app) in [
        (None, None),
        (
            Some(std::ffi::OsStr::new("relative-profile")),
            Some(std::ffi::OsStr::new("relative-local")),
        ),
    ] {
        let report = parse_report(&run(profile, local_app, None, None));
        assert!(
            !report["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| matches!(entry["name"].as_str(), Some("Go build" | "Go modules")))
        );
        let warnings = report["warnings"].as_array().unwrap();
        assert!(warnings.iter().any(|warning| {
            warning
                .as_str()
                .unwrap()
                .contains("LOCALAPPDATA is unset or relative")
        }));
        assert!(warnings.iter().any(|warning| {
            warning
                .as_str()
                .unwrap()
                .contains("USERPROFILE is unset or relative")
        }));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn bun_cache_inventory_uses_documented_default_and_override_precedence() {
    use std::{ffi::OsStr, fs, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let default = home.join(".bun/install/cache");
    let install_root = home.join("custom-bun");
    let install_cache = install_root.join("install/cache");
    let override_cache = home.join("bun-cache-override");
    for path in [&default, &install_cache, &override_cache] {
        fs::create_dir_all(path).unwrap();
        fs::write(path.join("fixture"), b"keep").unwrap();
    }
    let run_status = |cache_dir: Option<&OsStr>, install: Option<&OsStr>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        command
            .current_dir(dir.path())
            .args(["--offline", "--json", "cache", "status"])
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("GOENV", "off")
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("ZIG_GLOBAL_CACHE_DIR", home.join(".cache/zig"));
        if let Some(cache_dir) = cache_dir {
            command.env("BUN_INSTALL_CACHE_DIR", cache_dir);
        }
        if let Some(install) = install {
            command.env("BUN_INSTALL", install);
        }
        command.output().unwrap()
    };

    for (cache_dir, install, expected, expected_command_target) in [
        (None, None, &default, None),
        (
            None,
            Some(install_root.as_os_str()),
            &default,
            Some(&install_cache),
        ),
        (
            Some(override_cache.as_os_str()),
            Some(install_root.as_os_str()),
            &override_cache,
            None,
        ),
    ] {
        let output = run_status(cache_dir, install);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let bun = report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "Bun")
            .unwrap();
        assert_eq!(bun["path"], expected.to_str().unwrap());
        assert_eq!(bun["status"], "inventory only");
        assert_eq!(fs::read(expected.join("fixture")).unwrap(), b"keep");
        let command_target = report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "Bun cache command target");
        if let Some(expected_command_target) = expected_command_target {
            assert_eq!(
                command_target.unwrap()["path"],
                expected_command_target.to_str().unwrap()
            );
        } else {
            assert!(command_target.is_none());
        }
    }

    let output = run_status(Some(OsStr::new("relative/cache")), None);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Bun")
    );
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                warning
                    .as_str()
                    .unwrap()
                    .contains("BUN_INSTALL_CACHE_DIR is not safely resolvable")
            })
    );

    let output = run_status(None, Some(OsStr::new("relative/bun")));
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Bun" && entry["path"] == default.to_str().unwrap())
    );
    assert!(
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                warning
                    .as_str()
                    .unwrap()
                    .contains("BUN_INSTALL is not safely resolvable")
            })
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bun_cache_inventory_blocks_upkit_removal_and_overlap_with_other_caches() {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    let dir = tempfile::tempdir().unwrap();
    let Some(isolated_opt) = isolated_machine_config_dir(dir.path()) else {
        return;
    };
    let home = dir.path().join("home");
    let bun_cache = home.join(".bun/install/cache");
    let cargo_registry = home.join(".cargo/registry");
    let workspace = home.join("workspace");
    let linked_parent = cargo_registry.join("nested");
    let config = home.join(".config");
    fs::create_dir_all(config.join("go")).unwrap();
    fs::write(
        config.join("go/env"),
        format!(
            "GOCACHE={}\nGOMODCACHE={}\nGOPATH={}\nGOCACHEPROG=\n",
            home.join(".cache/go-build").display(),
            home.join("go/pkg/mod").display(),
            home.join("go").display()
        ),
    )
    .unwrap();
    fs::create_dir_all(&bun_cache).unwrap();
    fs::create_dir_all(&cargo_registry).unwrap();
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&linked_parent).unwrap();
    symlink(&linked_parent, workspace.join("cache-link")).unwrap();
    fs::write(bun_cache.join("fixture"), b"bun").unwrap();
    fs::write(cargo_registry.join("fixture"), b"cargo").unwrap();
    let preview = |target: &std::path::Path,
                   bun_cache_dir: Option<&std::ffi::OsStr>,
                   bun_install: Option<&std::ffi::OsStr>,
                   cargo_home: Option<&std::path::Path>| {
        let mut command = isolated_upkit_command(&isolated_opt);
        command
            .current_dir(&workspace)
            .args([
                "--offline",
                "--json",
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
            ])
            .arg(target)
            .arg("--preview")
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("ZIG_GLOBAL_CACHE_DIR", home.join(".cache/zig"));
        if let Some(bun_cache_dir) = bun_cache_dir {
            command.env("BUN_INSTALL_CACHE_DIR", bun_cache_dir);
        }
        if let Some(bun_install) = bun_install {
            command.env("BUN_INSTALL", bun_install);
        }
        if let Some(cargo_home) = cargo_home {
            command.env("CARGO_HOME", cargo_home);
        }
        command.output().unwrap()
    };

    let output = preview(&bun_cache, Some(bun_cache.as_os_str()), None, None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("Upkit inventories the Bun cache but does not remove it"),
    );
    assert_eq!(fs::read(bun_cache.join("fixture")).unwrap(), b"bun");

    let output = preview(
        &cargo_registry,
        Some(home.join(".cargo").as_os_str()),
        None,
        None,
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("overlaps another discovered cache location")
    );
    assert_eq!(fs::read(cargo_registry.join("fixture")).unwrap(), b"cargo");

    fs::write(
        workspace.join("bunfig.toml"),
        "[install.cache]\ndir = \"cache-link/../bun-cache\"\n",
    )
    .unwrap();
    let bun_config_cache = cargo_registry.join("bun-cache");
    fs::create_dir_all(&bun_config_cache).unwrap();
    fs::write(bun_config_cache.join("fixture"), b"bun-config").unwrap();
    let output = preview(&cargo_registry, None, None, None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("overlaps another discovered cache location")
    );
    assert_eq!(fs::read(cargo_registry.join("fixture")).unwrap(), b"cargo");
    assert_eq!(
        fs::read(bun_config_cache.join("fixture")).unwrap(),
        b"bun-config"
    );
    let output = preview(&bun_config_cache, None, None, None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("Upkit inventories the Bun cache but does not remove it")
    );
    assert_eq!(
        fs::read(bun_config_cache.join("fixture")).unwrap(),
        b"bun-config"
    );

    fs::write(workspace.join("bunfig.toml"), "[install.cache\n").unwrap();
    let output = preview(&cargo_registry, None, None, None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Bun cache configuration is unverified")
    );
    assert_eq!(fs::read(cargo_registry.join("fixture")).unwrap(), b"cargo");

    let external_bunfig = workspace.join("real-bunfig.toml");
    fs::write(
        &external_bunfig,
        "[install.cache]\ndir = \"/tmp/private\"\n",
    )
    .unwrap();
    fs::remove_file(workspace.join("bunfig.toml")).unwrap();
    symlink(&external_bunfig, workspace.join("bunfig.toml")).unwrap();
    let output = preview(&cargo_registry, None, None, None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Bun cache configuration is unverified")
    );
    assert_eq!(fs::read(cargo_registry.join("fixture")).unwrap(), b"cargo");

    fs::remove_file(workspace.join("bunfig.toml")).unwrap();
    fs::write(
        workspace.join(".npmrc"),
        format!("cache={}\n", home.join(".cargo").display()),
    )
    .unwrap();
    let output = preview(&cargo_registry, None, None, None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("overlaps another discovered cache location")
    );
    assert_eq!(fs::read(cargo_registry.join("fixture")).unwrap(), b"cargo");

    fs::remove_file(workspace.join(".npmrc")).unwrap();
    fs::write(
        config.join(".npmrc"),
        format!("cache={}\n", home.join(".cargo").display()),
    )
    .unwrap();
    let output = preview(&cargo_registry, None, None, None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("overlaps another discovered cache location")
    );
    assert_eq!(fs::read(cargo_registry.join("fixture")).unwrap(), b"cargo");
    let separate_bun_cache = home.join("separate-bun-cache");
    fs::create_dir(&separate_bun_cache).unwrap();
    for path in [
        home.join(".cargo"),
        cargo_registry.clone(),
        linked_parent.clone(),
        bun_config_cache.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    for path in [
        cargo_registry.join("fixture"),
        bun_config_cache.join("fixture"),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(
        config.join(".npmrc"),
        format!("cache={}\n", separate_bun_cache.display()),
    )
    .unwrap();
    let output = preview(&cargo_registry, None, None, None);
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(cargo_registry.join("fixture")).unwrap(), b"cargo");
    fs::remove_file(config.join(".npmrc")).unwrap();
    let external_npmrc = workspace.join("external-npmrc");
    fs::write(&external_npmrc, "cache=/fixture/private\n").unwrap();
    symlink(&external_npmrc, config.join(".npmrc")).unwrap();
    let output = preview(&cargo_registry, None, None, None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("npm XDG config file could not be read safely")
    );
    assert_eq!(fs::read(cargo_registry.join("fixture")).unwrap(), b"cargo");
    fs::remove_file(config.join(".npmrc")).unwrap();

    let output = preview(
        &cargo_registry,
        Some(std::ffi::OsStr::new("relative/cache")),
        None,
        None,
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Bun cache configuration is unverified")
    );
    assert_eq!(fs::read(cargo_registry.join("fixture")).unwrap(), b"cargo");

    let install_cache = home.join("custom-bun/install/cache");
    let cargo_in_install_cache = install_cache.join("registry");
    fs::create_dir_all(&cargo_in_install_cache).unwrap();
    fs::write(cargo_in_install_cache.join("fixture"), b"cargo").unwrap();
    let output = preview(
        &cargo_in_install_cache,
        None,
        Some(home.join("custom-bun").as_os_str()),
        Some(&install_cache),
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("overlaps another discovered cache location")
    );
    assert_eq!(
        fs::read(cargo_in_install_cache.join("fixture")).unwrap(),
        b"cargo"
    );

    let output = preview(
        &cargo_registry,
        None,
        Some(std::ffi::OsStr::new("relative/bun")),
        None,
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Bun cache command path is unverified")
    );
    assert_eq!(fs::read(cargo_registry.join("fixture")).unwrap(), b"cargo");
}
