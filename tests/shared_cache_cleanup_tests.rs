#![cfg(target_os = "linux")]
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    cache: PathBuf,
    machine_opt: PathBuf,
}

fn private_etc_opt_namespace(machine_opt: &Path) -> Command {
    let mut command = Command::new("unshare");
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
            "/usr/bin/mount --make-rprivate / && /usr/bin/mount --bind \"$1\" /etc/opt && shift && export NPM_CONFIG_GLOBALCONFIG=\"${NPM_CONFIG_GLOBALCONFIG:-$HOME/upkit-test-global.npmrc}\" && exec \"$@\"",
            "sh",
        ])
        .arg(machine_opt);
    command
}

impl Fixture {
    fn new() -> Option<Self> {
        if !fs::symlink_metadata("/etc/opt")
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        {
            eprintln!("SKIP: shared-cache fixture; /etc/opt is not an existing real directory");
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let machine_opt = dir.path().join("machine-opt");
        fs::create_dir_all(machine_opt.join("NuGet/Config")).unwrap();
        if !private_etc_opt_namespace(&machine_opt)
            .arg("/bin/true")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            eprintln!("SKIP: shared-cache fixture; private mount namespace unavailable");
            return None;
        }
        let home = dir.path().join("home");
        let parent = home.join("cache");
        let cache = parent.join("go-build");
        let config = home.join("config");
        fs::create_dir_all(config.join("go")).unwrap();
        fs::write(
            config.join("go/env"),
            format!(
                "GOPATH={}\nGOMODCACHE=\nGOCACHEPROG=\n",
                home.join("go").display()
            ),
        )
        .unwrap();
        fs::create_dir_all(cache.join("bucket")).unwrap();
        for path in [&home, &parent, &cache, &cache.join("bucket")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(cache.join("bucket/item"), "fixture").unwrap();
        fs::set_permissions(cache.join("bucket/item"), fs::Permissions::from_mode(0o600)).unwrap();
        Some(Self {
            _dir: dir,
            home,
            cache,
            machine_opt,
        })
    }
    fn command(&self) -> Command {
        let mut command = private_etc_opt_namespace(&self.machine_opt);
        command.current_dir(&self.home);
        command
    }
    fn run(&self, args: &[&str], cache: &Path) -> Output {
        self.run_with_environment(args, cache, None)
    }
    fn run_with_environment(
        &self,
        args: &[&str],
        cache: &Path,
        extra: Option<(&str, &std::ffi::OsStr)>,
    ) -> Output {
        let mut command = self.command();
        command
            .arg(env!("CARGO_BIN_EXE_upkit"))
            .args(["--non-interactive", "--json", "--home"])
            .arg(self.home.join("upkit"))
            .args(args)
            .env_clear()
            .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("XDG_CACHE_HOME", self.home.join("cache"))
            .env("GOCACHE", cache);
        if let Some((name, value)) = extra {
            command.env(name, value);
        }
        command.output().unwrap()
    }
    fn run_with_zig_cache(&self, args: &[&str], zig_cache: &Path) -> Output {
        self.command()
            .arg(env!("CARGO_BIN_EXE_upkit"))
            .args(["--non-interactive", "--json", "--home"])
            .arg(self.home.join("upkit"))
            .args(args)
            .env_clear()
            .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("XDG_CACHE_HOME", self.home.join("cache"))
            .env("GOCACHE", &self.cache)
            .env("ZIG_GLOBAL_CACHE_DIR", zig_cache)
            .output()
            .unwrap()
    }
    fn preview_with_cargo_targets(
        &self,
        selected: &Path,
        target_dir: Option<&std::ffi::OsStr>,
        build_target_dir: Option<&std::ffi::OsStr>,
        cargo_home: Option<&Path>,
    ) -> Output {
        let mut command = self.command();
        command
            .arg(env!("CARGO_BIN_EXE_upkit"))
            .args([
                "--non-interactive",
                "--json",
                "--home",
                self.home.join("upkit").to_str().unwrap(),
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
            ])
            .arg(selected)
            .arg("--preview")
            .current_dir(&self.home)
            .env_clear()
            .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("XDG_CACHE_HOME", self.home.join("cache"))
            .env("GOCACHE", &self.cache);
        if let Some(path) = target_dir {
            command.env("CARGO_TARGET_DIR", path);
        }
        if let Some(path) = build_target_dir {
            command.env("CARGO_BUILD_TARGET_DIR", path);
        }
        if let Some(path) = cargo_home {
            command.env("CARGO_HOME", path);
        }
        command.output().unwrap()
    }
    fn preview(&self) -> serde_json::Value {
        self.preview_cache(&self.cache)
    }
    fn preview_cache(&self, cache: &Path) -> serde_json::Value {
        let out = self.run(
            &[
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
                cache.to_str().unwrap(),
                "--preview",
            ],
            cache,
        );
        assert!(
            out.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
}

#[test]
fn cargo_build_outputs_are_inventory_only_and_block_overlapping_cache_removal() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let target = f.home.join("cargo-target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(target.join("keep"), "fixture").unwrap();
    fs::set_permissions(target.join("keep"), fs::Permissions::from_mode(0o600)).unwrap();

    let output = f.preview_with_cargo_targets(&target, Some(target.as_os_str()), None, None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Cargo build output is inventory-only")
    );
    assert_eq!(fs::read_to_string(target.join("keep")).unwrap(), "fixture");

    let overlapping_output = f.preview_with_cargo_targets(
        &f.cache,
        Some(f.cache.join("bucket").as_os_str()),
        None,
        None,
    );
    assert!(!overlapping_output.status.success());
    assert!(
        String::from_utf8_lossy(&overlapping_output.stdout)
            .contains("selected cache overlaps another discovered cache location")
    );
    assert_eq!(
        fs::read_to_string(f.cache.join("bucket/item")).unwrap(),
        "fixture"
    );

    let conflicting_output = f.preview_with_cargo_targets(
        &f.cache,
        Some(target.as_os_str()),
        Some(f.cache.join("bucket").as_os_str()),
        None,
    );
    assert!(!conflicting_output.status.success());
    assert!(
        String::from_utf8_lossy(&conflicting_output.stdout)
            .contains("cache directory environment setting is unresolved")
    );
    assert_eq!(
        fs::read_to_string(f.cache.join("bucket/item")).unwrap(),
        "fixture"
    );
}

#[test]
fn cargo_config_output_paths_follow_scope_and_environment_precedence() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let cargo_home = f.home.join("cargo-home");
    let cargo_target = f.home.join("cargo-target");
    let project_config_dir = f.home.join(".cargo");
    fs::create_dir_all(&cargo_home).unwrap();
    fs::create_dir_all(&cargo_target).unwrap();
    fs::create_dir(&project_config_dir).unwrap();
    fs::set_permissions(&cargo_target, fs::Permissions::from_mode(0o700)).unwrap();
    let cargo_home_config = cargo_home.join("config.toml");
    let project_config = project_config_dir.join("config.toml");
    let path_value = |path: &Path| serde_json::to_string(path.to_str().unwrap()).unwrap();
    fs::write(
        &cargo_home_config,
        "[build]\ntarget-dir = \"cargo-target\"\n",
    )
    .unwrap();
    let relative_output =
        f.preview_with_cargo_targets(&cargo_target, None, None, Some(&cargo_home));
    assert!(!relative_output.status.success());
    assert!(
        String::from_utf8_lossy(&relative_output.stdout)
            .contains("Cargo build output is inventory-only")
    );
    fs::write(
        &cargo_home_config,
        format!("[build]\ntarget-dir = {}\n", path_value(&cargo_target)),
    )
    .unwrap();
    fs::write(
        &project_config,
        format!(
            "[build]\ntarget-dir = {}\n",
            path_value(&f.cache.join("bucket/cargo-target"))
        ),
    )
    .unwrap();

    let project_overlap = f.preview_with_cargo_targets(&f.cache, None, None, Some(&cargo_home));
    assert!(!project_overlap.status.success());
    assert!(
        String::from_utf8_lossy(&project_overlap.stdout)
            .contains("selected cache overlaps another discovered cache location")
    );

    fs::write(
        &project_config,
        format!("[build]\ntarget-dir = {}\n", path_value(&cargo_target)),
    )
    .unwrap();
    let overridden_global = f.preview_with_cargo_targets(&f.cache, None, None, Some(&cargo_home));
    assert!(
        overridden_global.status.success(),
        "{}{}",
        String::from_utf8_lossy(&overridden_global.stdout),
        String::from_utf8_lossy(&overridden_global.stderr)
    );

    fs::remove_file(&project_config).unwrap();
    fs::write(
        project_config_dir.join("config"),
        format!("[build]\ntarget-dir = {}\n", path_value(&cargo_target)),
    )
    .unwrap();
    fs::write(
        &project_config,
        format!(
            "[build]\ntarget-dir = {}\n",
            path_value(&f.cache.join("bucket/ignored-modern-config"))
        ),
    )
    .unwrap();
    let legacy_wins = f.preview_with_cargo_targets(&f.cache, None, None, Some(&cargo_home));
    assert!(
        legacy_wins.status.success(),
        "{}{}",
        String::from_utf8_lossy(&legacy_wins.stdout),
        String::from_utf8_lossy(&legacy_wins.stderr)
    );

    fs::write(
        project_config_dir.join("config"),
        format!(
            "[build]\nbuild-dir = {}\n",
            path_value(&f.cache.join("bucket/cargo-build"))
        ),
    )
    .unwrap();
    let build_dir_overlap = f.preview_with_cargo_targets(&f.cache, None, None, Some(&cargo_home));
    assert!(!build_dir_overlap.status.success());
    assert!(
        String::from_utf8_lossy(&build_dir_overlap.stdout)
            .contains("selected cache overlaps another discovered cache location")
    );

    fs::write(
        project_config_dir.join("config"),
        format!(
            "[build]\ntarget-dir = {}\n",
            path_value(&f.cache.join("bucket/cargo-target"))
        ),
    )
    .unwrap();
    let env_target = f.home.join("env-cargo-target");
    fs::create_dir(&env_target).unwrap();
    fs::set_permissions(&env_target, fs::Permissions::from_mode(0o700)).unwrap();
    let env_override = f.preview_with_cargo_targets(
        &f.cache,
        Some(env_target.as_os_str()),
        None,
        Some(&cargo_home),
    );
    assert!(
        env_override.status.success(),
        "{}{}",
        String::from_utf8_lossy(&env_override.stdout),
        String::from_utf8_lossy(&env_override.stderr)
    );

    let env_cache_alias = f.home.join("env-cache-alias");
    symlink(&f.cache, &env_cache_alias).unwrap();
    let env_alias_target = env_cache_alias.join("not-created/target");
    let env_alias_overlap = f.preview_with_cargo_targets(
        &f.cache,
        Some(env_alias_target.as_os_str()),
        None,
        Some(&cargo_home),
    );
    assert!(!env_alias_overlap.status.success());
    assert!(
        String::from_utf8_lossy(&env_alias_overlap.stdout)
            .contains("selected cache overlaps another discovered cache location")
    );
    fs::remove_file(&env_cache_alias).unwrap();

    fs::write(
        project_config_dir.join("config"),
        "[build]\ntarget-dir = \"cache/../cache/go-build/not-created/target\"\n",
    )
    .unwrap();
    let parent_component = f.preview_with_cargo_targets(&f.cache, None, None, Some(&cargo_home));
    assert!(!parent_component.status.success());
    assert!(
        String::from_utf8_lossy(&parent_component.stdout)
            .contains("selected cache overlaps another discovered cache location")
    );

    let cache_alias = f.home.join("cargo-cache-alias");
    symlink(&f.cache, &cache_alias).unwrap();
    fs::write(
        project_config_dir.join("config"),
        format!(
            "[build]\ntarget-dir = {}\n",
            path_value(&cache_alias.join("not-created/target"))
        ),
    )
    .unwrap();
    let symlink_prefix = f.preview_with_cargo_targets(&f.cache, None, None, Some(&cargo_home));
    assert!(!symlink_prefix.status.success());
    assert!(
        String::from_utf8_lossy(&symlink_prefix.stdout)
            .contains("selected cache overlaps another discovered cache location")
    );
    fs::remove_file(&cache_alias).unwrap();

    fs::write(
        project_config_dir.join("config"),
        "[build]\ntarget-dir = 7\n",
    )
    .unwrap();
    let ambiguous = f.preview_with_cargo_targets(&f.cache, None, None, Some(&cargo_home));
    assert!(!ambiguous.status.success());
    assert!(
        String::from_utf8_lossy(&ambiguous.stdout)
            .contains("Cargo output configuration is unverified")
    );

    fs::remove_file(project_config_dir.join("config")).unwrap();
    fs::remove_file(&project_config).unwrap();
    let linked_config = project_config_dir.join("config.toml");
    fs::write(
        f.home.join("unreadable-cargo-config"),
        format!("[build]\ntarget-dir = {}\n", path_value(&f.cache)),
    )
    .unwrap();
    symlink(f.home.join("unreadable-cargo-config"), &linked_config).unwrap();
    let unreadable = f.preview_with_cargo_targets(&f.cache, None, None, Some(&cargo_home));
    assert!(!unreadable.status.success());
    assert!(
        String::from_utf8_lossy(&unreadable.stdout)
            .contains("Cargo output configuration is unverified")
    );
}

#[test]
fn cache_preview_rejects_uv_overlap_and_relative_uv_configuration() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let uv = f.cache.join("uv");
    fs::create_dir(&uv).unwrap();
    fs::write(uv.join("keep"), "fixture").unwrap();
    for (selected, override_dir, error) in [
        (
            f.cache.as_path(),
            uv.as_path(),
            "overlaps another discovered cache",
        ),
        (uv.as_path(), uv.as_path(), "not a discovered shared cache"),
        (
            f.cache.as_path(),
            Path::new("relative"),
            "uv cache configuration is relative",
        ),
    ] {
        let out = f
            .command()
            .arg(env!("CARGO_BIN_EXE_upkit"))
            .args([
                "--non-interactive",
                "--json",
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
            ])
            .arg(selected)
            .arg("--preview")
            .env_clear()
            .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
            .env("HOME", &f.home)
            .env("XDG_CACHE_HOME", f.home.join("cache"))
            .env("XDG_DATA_HOME", f.home.join("data"))
            .env("XDG_CONFIG_HOME", f.home.join("config"))
            .env("GOCACHE", &f.cache)
            .env("UV_CACHE_DIR", override_dir)
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains(error));
        assert_eq!(fs::read(uv.join("keep")).unwrap(), b"fixture");
    }
}

#[test]
fn zig_global_cache_overlap_blocks_shared_cache_preview() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let zig = f.cache.join("zig-global");
    fs::create_dir(&zig).unwrap();
    fs::write(zig.join("keep"), "fixture").unwrap();
    let target = f.cache.to_str().unwrap();
    let output = f
        .command()
        .arg(env!("CARGO_BIN_EXE_upkit"))
        .args([
            "--non-interactive",
            "--json",
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            target,
            "--preview",
        ])
        .env_clear()
        .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
        .env("HOME", &f.home)
        .env("XDG_CACHE_HOME", f.home.join("cache"))
        .env("XDG_DATA_HOME", f.home.join("data"))
        .env("XDG_CONFIG_HOME", f.home.join("config"))
        .env("GOCACHE", &f.cache)
        .env("ZIG_GLOBAL_CACHE_DIR", &zig)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(message.contains("overlaps another discovered cache location"));
    assert_eq!(fs::read(zig.join("keep")).unwrap(), b"fixture");
    assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
}

#[test]
fn relative_zig_global_cache_blocks_shared_cache_preview() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let target = f.cache.to_str().unwrap();
    let output = f
        .command()
        .arg(env!("CARGO_BIN_EXE_upkit"))
        .args([
            "--non-interactive",
            "--json",
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            target,
            "--preview",
        ])
        .env_clear()
        .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
        .env("HOME", &f.home)
        .env("XDG_CACHE_HOME", f.home.join("cache"))
        .env("XDG_DATA_HOME", f.home.join("data"))
        .env("XDG_CONFIG_HOME", f.home.join("config"))
        .env("GOCACHE", &f.cache)
        .env("ZIG_GLOBAL_CACHE_DIR", "relative/zig")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(message.contains("ZIG_GLOBAL_CACHE_DIR must be an absolute path"));
    assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
}

#[test]
fn npm_user_config_protects_cache_and_logs_without_exposing_credentials() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let original_plan = f.preview();
    let original_token = original_plan["plan"]["preview_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let npm_root = f.cache.join("npm-fixture");
    let npm_cache = npm_root.join("_cacache");
    let npm_logs = f.cache.join("npm-log-fixture");
    fs::create_dir_all(&npm_cache).unwrap();
    fs::create_dir_all(&npm_logs).unwrap();
    fs::write(npm_cache.join("keep"), b"cache fixture").unwrap();
    fs::write(npm_logs.join("keep"), b"log fixture").unwrap();
    let secret = "synthetic-secret-marker";
    fs::write(
        f.home.join(".npmrc"),
        format!(
            "//registry.example.invalid/:_authToken={secret}\ncache=${{HOME}}/cache/go-build/npm-fixture\nlogs-dir=${{HOME}}/cache/go-build/npm-log-fixture\n"
        ),
    )
    .unwrap();

    let status = f.run(&["cache", "status"], &f.cache);
    assert!(status.status.success());
    let output = String::from_utf8(status.stdout).unwrap();
    assert!(!output.contains(secret));
    let report: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(report["entries"].as_array().unwrap().iter().any(|entry| {
        entry["name"] == "npm configured cache (possible)"
            && entry["path"] == npm_cache.to_str().unwrap()
    }));

    let preview = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            f.cache.to_str().unwrap(),
            "--preview",
        ],
        &f.cache,
    );
    assert!(!preview.status.success());
    let output = String::from_utf8_lossy(&preview.stdout);
    assert!(output.contains("overlaps another discovered cache location"));
    assert!(!output.contains(secret));
    let run = f.run(
        &[
            "--yes",
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            f.cache.to_str().unwrap(),
            "--preview-token",
            &original_token,
            "--authorize-shared-cache",
        ],
        &f.cache,
    );
    assert!(!run.status.success());
    assert!(!String::from_utf8_lossy(&run.stdout).contains(secret));
    let possible_cache = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            npm_cache.to_str().unwrap(),
            "--preview",
        ],
        &f.cache,
    );
    assert!(!possible_cache.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&possible_cache.stdout),
        String::from_utf8_lossy(&possible_cache.stderr)
    );
    assert!(message.contains("this possible cache is inspection-only"));
    let default_cache = f.home.join(".npm/_cacache");
    fs::create_dir_all(&default_cache).unwrap();
    let default_preview = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            default_cache.to_str().unwrap(),
            "--preview",
        ],
        &f.cache,
    );
    assert!(!default_preview.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&default_preview.stdout),
        String::from_utf8_lossy(&default_preview.stderr)
    );
    assert!(message.contains("npm configuration may override the default cache"));
    assert_eq!(fs::read(npm_cache.join("keep")).unwrap(), b"cache fixture");
    assert_eq!(fs::read(npm_logs.join("keep")).unwrap(), b"log fixture");
    assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
}

#[test]
fn npm_project_and_explicit_global_config_locations_are_inspected_read_only() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let project = f.home.join("npm-project");
    fs::create_dir_all(&project).unwrap();
    fs::write(project.join("package.json"), b"{}").unwrap();

    let redirected_user = f.home.join("redirected-user.npmrc");
    let redirected_global = f.home.join("redirected-global.npmrc");
    let explicit_global = f.home.join("explicit-global.npmrc");
    let project_cache = f.home.join("project-npm-cache");
    let user_cache = f.home.join("redirected-user-cache");
    let redirected_global_cache = f.home.join("redirected-global-cache");
    let explicit_global_cache = f.home.join("explicit-global-cache");
    let project_logs = f.home.join("project-npm-logs");
    let global_logs = f.home.join("explicit-global-logs");
    for root in [
        &project_cache,
        &user_cache,
        &redirected_global_cache,
        &explicit_global_cache,
    ] {
        fs::create_dir_all(root.join("_cacache")).unwrap();
    }
    fs::create_dir_all(&project_logs).unwrap();
    fs::create_dir_all(&global_logs).unwrap();
    fs::write(
        project.join(".npmrc"),
        format!(
            "userconfig={}\ncache={}\nlogs-dir={}\n//registry.example.invalid/:_authToken=synthetic-project-secret\n",
            redirected_user.display(),
            project_cache.display(),
            project_logs.display(),
        ),
    )
    .unwrap();
    fs::write(
        &redirected_user,
        format!(
            "cache={}\nglobalconfig={}\n",
            user_cache.display(),
            redirected_global.display(),
        ),
    )
    .unwrap();
    fs::write(
        &redirected_global,
        format!("cache={}\n", redirected_global_cache.display()),
    )
    .unwrap();
    fs::write(
        &explicit_global,
        format!(
            "cache={}\nlogs-dir={}\n//registry.example.invalid/:_authToken=synthetic-global-secret\n",
            explicit_global_cache.display(),
            global_logs.display(),
        ),
    )
    .unwrap();

    let run = |args: &[&str]| {
        f.command()
            .arg(env!("CARGO_BIN_EXE_upkit"))
            .args(["--non-interactive", "--json", "--home"])
            .arg(f.home.join("upkit"))
            .args(args)
            .env_clear()
            .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
            .env("HOME", &f.home)
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_CONFIG_HOME", f.home.join("config"))
            .env("XDG_DATA_HOME", f.home.join("data"))
            .env("XDG_CACHE_HOME", f.home.join("cache"))
            .env("GOCACHE", &f.cache)
            .env("NPM_CONFIG_GLOBALCONFIG", &explicit_global)
            .current_dir(&project)
            .output()
            .unwrap()
    };
    let status = run(&["cache", "status"]);
    assert!(status.status.success());
    let output = String::from_utf8(status.stdout).unwrap();
    assert!(!output.contains("synthetic-project-secret"));
    assert!(!output.contains("synthetic-global-secret"));
    let report: serde_json::Value = serde_json::from_str(&output).unwrap();
    for root in [
        &project_cache,
        &user_cache,
        &redirected_global_cache,
        &explicit_global_cache,
    ] {
        let target = root.join("_cacache");
        assert!(report["entries"].as_array().unwrap().iter().any(|entry| {
            entry["name"] == "npm configured cache (possible)"
                && entry["path"] == target.to_str().unwrap()
        }));
    }
    for logs in [&project_logs, &global_logs] {
        assert!(report["entries"].as_array().unwrap().iter().any(|entry| {
            entry["name"] == "npm logs" && entry["path"] == logs.to_str().unwrap()
        }));
    }

    let possible_cache = project_cache.join("_cacache");
    let preview = run(&[
        "sweep",
        "run",
        "--scope",
        "cache",
        "--select",
        possible_cache.to_str().unwrap(),
        "--preview",
    ]);
    assert!(!preview.status.success());
    assert!(
        String::from_utf8_lossy(&preview.stdout).contains("this possible cache is inspection-only")
    );

    let log_preview = run(&[
        "sweep",
        "run",
        "--scope",
        "cache",
        "--select",
        global_logs.to_str().unwrap(),
        "--preview",
    ]);
    assert!(!log_preview.status.success());
    assert!(
        String::from_utf8_lossy(&log_preview.stdout).contains("npm log directories are protected")
    );
    assert!(project_cache.join("_cacache").is_dir());
    assert!(user_cache.join("_cacache").is_dir());
    assert!(redirected_global_cache.join("_cacache").is_dir());
    assert!(explicit_global_cache.join("_cacache").is_dir());
}

#[test]
fn unresolved_or_linked_npm_user_config_blocks_cache_removal() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let config = f.home.join(".npmrc");
    fs::write(&config, "cache=${UNRESOLVED}/synthetic-private-value\n").unwrap();
    let status = f.run(&["cache", "status"], &f.cache);
    assert!(status.status.success());
    let output = String::from_utf8(status.stdout).unwrap();
    assert!(output.contains("npm cache configuration is unverified"));
    assert!(!output.contains("synthetic-private-value"));
    let preview = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            f.cache.to_str().unwrap(),
            "--preview",
        ],
        &f.cache,
    );
    assert!(!preview.status.success());
    assert!(!String::from_utf8_lossy(&preview.stdout).contains("synthetic-private-value"));
    fs::remove_file(&config).unwrap();
    let outside = f.home.join("external-settings");
    fs::write(&outside, "cache=/synthetic-fixture\n").unwrap();
    symlink(&outside, &config).unwrap();
    let preview = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            f.cache.to_str().unwrap(),
            "--preview",
        ],
        &f.cache,
    );
    assert!(!preview.status.success());
    assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
}

#[test]
fn npm_user_config_override_contributes_cache_and_protected_logs() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let config = f.home.join("alternate-npmrc");
    let npm_cache = f.home.join("alternate-npm/_cacache");
    let logs = f.cache.join("alternate-logs");
    fs::create_dir_all(&npm_cache).unwrap();
    fs::create_dir_all(&logs).unwrap();
    fs::write(logs.join("keep"), "fixture").unwrap();
    fs::write(
        &config,
        format!(
            "cache={}\nlogs-dir={}\n",
            npm_cache.parent().unwrap().display(),
            logs.display()
        ),
    )
    .unwrap();
    let run = |args: &[&str], user_config: &str| {
        f.command()
            .arg(env!("CARGO_BIN_EXE_upkit"))
            .args(["--non-interactive", "--json", "--home"])
            .arg(f.home.join("upkit"))
            .args(args)
            .env_clear()
            .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
            .env("HOME", &f.home)
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_CONFIG_HOME", f.home.join("config"))
            .env("XDG_DATA_HOME", f.home.join("data"))
            .env("XDG_CACHE_HOME", f.home.join("cache"))
            .env("GOCACHE", &f.cache)
            .env("NPM_CONFIG_USERCONFIG", user_config)
            .output()
            .unwrap()
    };
    let user_config = format!(" {} ", config.display());
    let output = run(&["cache", "status"], &user_config);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["entries"].as_array().unwrap().iter().any(|entry| {
        entry["name"] == "npm configured cache (possible)"
            && entry["path"] == npm_cache.to_str().unwrap()
    }));
    let preview = run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            f.cache.to_str().unwrap(),
            "--preview",
        ],
        &user_config,
    );
    assert!(!preview.status.success());
    assert!(
        String::from_utf8_lossy(&preview.stdout)
            .contains("overlaps another discovered cache location")
    );
    let dynamic = format!("{}/${{SYNTHETIC_VARIABLE}}/npmrc", f.home.display());
    let unresolved = run(&["cache", "status"], &dynamic);
    assert!(unresolved.status.success());
    let output = String::from_utf8(unresolved.stdout).unwrap();
    assert!(output.contains("npm cache configuration is unverified"));
    assert!(!output.contains("SYNTHETIC_VARIABLE"));
    assert_eq!(fs::read_to_string(logs.join("keep")).unwrap(), "fixture");
}

#[test]
fn unresolved_cache_directory_overrides_block_removal_without_exposing_values_or_running_tools() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let fake_bin = f.home.join("fake-bin");
    fs::create_dir(&fake_bin).unwrap();
    let sentinel = f.home.join("executor-ran");
    for name in [
        "cargo", "npm", "yarn", "pip", "gradle", "ccache", "sccache", "dart",
    ] {
        let executable = fake_bin.join(name);
        fs::write(&executable, "#!/bin/sh\n: > \"$UPKIT_EXECUTOR_SENTINEL\"\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let run_with_overrides = |args: &[&str], cache_overrides: &[(&str, &str)]| {
        let mut command = f.command();
        command.arg("/usr/bin/env");
        for &(name, value) in cache_overrides {
            command.arg(format!("{name}={value}"));
        }
        command
            .arg(env!("CARGO_BIN_EXE_upkit"))
            .args(["--non-interactive", "--json", "--home"])
            .arg(f.home.join("upkit"))
            .args(args)
            .env_clear()
            .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
            .env("HOME", &f.home)
            .env("PATH", format!("{}:/usr/bin:/bin", fake_bin.display()))
            .env("UPKIT_EXECUTOR_SENTINEL", &sentinel)
            .env("XDG_CONFIG_HOME", f.home.join("config"))
            .env("XDG_DATA_HOME", f.home.join("data"))
            .env("XDG_CACHE_HOME", f.home.join("cache"))
            .env("ZIG_GLOBAL_CACHE_DIR", f.home.join("zig-cache"))
            .env("GOCACHE", &f.cache);
        command.output().unwrap()
    };
    let run = |args: &[&str], cache_override: Option<(&str, &str)>| {
        run_with_overrides(args, &cache_override.into_iter().collect::<Vec<_>>())
    };

    let status = run(
        &["cache", "status"],
        Some(("CARGO_HOME", "relative-private-cache")),
    );
    assert!(status.status.success());
    let status_json: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert!(status_json["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning == "a cache directory environment setting is unresolved; shared-cache removal is blocked"));
    assert!(!String::from_utf8_lossy(&status.stdout).contains("relative-private-cache"));

    let plan = f.preview();
    let token = plan["plan"]["preview_token"].as_str().unwrap();
    let target = f.cache.to_str().unwrap();
    let removal_args = [
        "--yes",
        "sweep",
        "run",
        "--scope",
        "cache",
        "--select",
        target,
        "--preview-token",
        token,
        "--authorize-shared-cache",
    ];
    for name in [
        "CARGO_HOME",
        "npm_config_cache",
        "YARN_CACHE_FOLDER",
        "PIP_CACHE_DIR",
        "GRADLE_USER_HOME",
        "CCACHE_DIR",
        "SCCACHE_DIR",
        "PUB_CACHE",
    ] {
        let removal = run(&removal_args, Some((name, "relative-private-cache")));
        assert!(!removal.status.success(), "{name} must block removal");
        assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
        assert!(!sentinel.exists());
    }
    let off_override = run(&removal_args, Some(("CARGO_HOME", "off")));
    assert!(!off_override.status.success());
    assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
    assert!(!sentinel.exists());

    let relative_xdg_status = run(
        &["cache", "status"],
        Some(("XDG_CACHE_HOME", "relative-private-cache")),
    );
    assert!(relative_xdg_status.status.success());
    let xdg_json: serde_json::Value = serde_json::from_slice(&relative_xdg_status.stdout).unwrap();
    assert!(xdg_json["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning == "a cache directory environment setting is unresolved; shared-cache removal is blocked"));
    assert!(
        !String::from_utf8_lossy(&relative_xdg_status.stdout).contains("relative-private-cache")
    );
    let relative_xdg_removal = run(
        &removal_args,
        Some(("XDG_CACHE_HOME", "relative-private-cache")),
    );
    assert!(!relative_xdg_removal.status.success());
    assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
    assert!(!sentinel.exists());

    let npm_cache = f.home.join("npm-cache");
    fs::create_dir_all(npm_cache.join("_cacache")).unwrap();
    let lowercase_npm = run(
        &["cache", "status"],
        Some(("npm_config_cache", npm_cache.to_str().unwrap())),
    );
    assert!(lowercase_npm.status.success());
    let lowercase_json: serde_json::Value = serde_json::from_slice(&lowercase_npm.stdout).unwrap();
    assert!(!lowercase_json["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning == "a cache directory environment setting is unresolved; shared-cache removal is blocked"));
    assert!(
        lowercase_json["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "npm"
                && entry["path"] == npm_cache.join("_cacache").to_str().unwrap())
    );

    for name in ["NPM_CONFIG_CACHE", "Npm_Config_Cache"] {
        let alias_npm_cache = f.home.join(format!("alias-{name}"));
        let alias_npm_target = alias_npm_cache.join("_cacache");
        fs::create_dir_all(&alias_npm_target).unwrap();
        for path in [&alias_npm_cache, &alias_npm_target] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let npm_fixture = alias_npm_target.join("fixture");
        fs::write(&npm_fixture, "keep").unwrap();
        fs::set_permissions(npm_fixture, fs::Permissions::from_mode(0o600)).unwrap();
        let alias_npm_value = alias_npm_cache.to_str().unwrap();
        let status = run(&["cache", "status"], Some((name, alias_npm_value)));
        assert!(status.status.success());
        let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
        assert!(!report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning == "a cache directory environment setting is unresolved; shared-cache removal is blocked"));
        assert!(
            report["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["name"] == "npm"
                    && entry["path"] == alias_npm_cache.join("_cacache").to_str().unwrap())
        );
        let preview = run(
            &[
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
                alias_npm_target.to_str().unwrap(),
                "--preview",
            ],
            Some((name, alias_npm_value)),
        );
        assert!(
            preview.status.success(),
            "{name}: {}{}",
            String::from_utf8_lossy(&preview.stdout),
            String::from_utf8_lossy(&preview.stderr)
        );
        let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
        let token = preview["plan"]["preview_token"].as_str().unwrap();
        let remove = [
            "--yes",
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            alias_npm_target.to_str().unwrap(),
            "--preview-token",
            token,
            "--authorize-shared-cache",
        ];
        let removal = run(&remove, Some((name, alias_npm_value)));
        assert!(
            removal.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&removal.stderr)
        );
        assert!(!alias_npm_target.exists());
        assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
        assert!(!sentinel.exists());
    }

    let conflicting_npm_cache = f.home.join("conflicting-npm-cache");
    let nested_npm_cache = conflicting_npm_cache.join("_cacache");
    let second_npm_target = nested_npm_cache.join("_cacache");
    fs::create_dir_all(&second_npm_target).unwrap();
    let first_npm_value = conflicting_npm_cache.to_str().unwrap();
    let second_npm_value = nested_npm_cache.to_str().unwrap();
    let conflicts = [
        ("npm_config_cache", first_npm_value),
        ("NPM_CONFIG_CACHE", second_npm_value),
    ];
    let status = run_with_overrides(&["cache", "status"], &conflicts);
    assert!(status.status.success());
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert!(report["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning == "npm: conflicting case-insensitive cache or logs environment values are treated as possible locations for removal checks; Upkit does not infer which values npm uses."));
    for target in [&nested_npm_cache, &second_npm_target] {
        assert!(
            report["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["name"] == "npm" && entry["path"] == target.to_str().unwrap())
        );
    }
    let overlap = run_with_overrides(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            nested_npm_cache.to_str().unwrap(),
            "--preview",
        ],
        &conflicts,
    );
    assert!(!overlap.status.success());
    let overlap_message = format!(
        "{}{}",
        String::from_utf8_lossy(&overlap.stdout),
        String::from_utf8_lossy(&overlap.stderr)
    );
    assert!(overlap_message.contains("conflicting npm cache environment values"));

    let independent_npm_cache = f.home.join("independent-npm-cache");
    fs::create_dir_all(independent_npm_cache.join("_cacache")).unwrap();
    let independent_value = independent_npm_cache.to_str().unwrap();
    let independent_conflicts = [
        ("npm_config_cache", first_npm_value),
        ("NPM_CONFIG_CACHE", independent_value),
    ];
    for target in [&nested_npm_cache, &independent_npm_cache.join("_cacache")] {
        let result = run_with_overrides(
            &[
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
                target.to_str().unwrap(),
                "--preview",
            ],
            &independent_conflicts,
        );
        assert!(!result.status.success());
        let message = format!(
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(message.contains("conflicting npm cache environment values"));
    }

    let npm_logs = f.home.join("npm-log-protected/_logs");
    let other_cache = npm_logs.join("go-build");
    fs::create_dir_all(&other_cache).unwrap();
    for path in [
        f.home.join("npm-log-protected"),
        npm_logs.clone(),
        other_cache.clone(),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let npm_log_root = f.home.join("npm-log-protected");
    let overrides = [
        ("npm_config_cache", npm_log_root.to_str().unwrap()),
        ("GOCACHE", other_cache.to_str().unwrap()),
    ];
    let preview = run_with_overrides(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            other_cache.to_str().unwrap(),
            "--preview",
        ],
        &overrides,
    );
    assert!(!preview.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&preview.stdout),
        String::from_utf8_lossy(&preview.stderr)
    );
    assert!(message.contains("selected cache overlaps another discovered cache location"));
    assert!(other_cache.is_dir());

    let custom_npm_root = f.home.join("npm-custom-cache");
    let custom_npm_cache = custom_npm_root.join("_cacache");
    let custom_npm_logs = f.home.join("npm-custom-logs");
    fs::create_dir_all(&custom_npm_cache).unwrap();
    fs::create_dir(&custom_npm_logs).unwrap();
    for path in [&custom_npm_root, &custom_npm_cache, &custom_npm_logs] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let custom_npm_cache_value = custom_npm_root.to_str().unwrap();
    let custom_npm_logs_value = custom_npm_logs.to_str().unwrap();
    let custom_npm_overrides = [
        ("npm_config_cache", custom_npm_cache_value),
        ("npm_config_logs_dir", custom_npm_logs_value),
    ];
    let status = run_with_overrides(&["cache", "status"], &custom_npm_overrides);
    assert!(status.status.success());
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert!(
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "npm"
                && entry["path"] == custom_npm_cache.to_str().unwrap())
    );
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "npm logs")
    );
    let preview = run_with_overrides(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            custom_npm_cache.to_str().unwrap(),
            "--preview",
        ],
        &custom_npm_overrides,
    );
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );

    let npm_root_logs = custom_npm_root.join("_logs");
    let logs_preview = run_with_overrides(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            npm_root_logs.to_str().unwrap(),
            "--preview",
        ],
        &custom_npm_overrides,
    );
    assert!(!logs_preview.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&logs_preview.stdout),
        String::from_utf8_lossy(&logs_preview.stderr)
    );
    assert!(message.contains("npm log directories are protected"));

    let default_npm_logs = f.home.join(".npm/_logs");
    let other_cache = default_npm_logs.join("go-build");
    fs::create_dir_all(&other_cache).unwrap();
    for path in [f.home.join(".npm"), default_npm_logs, other_cache.clone()] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut overrides = custom_npm_overrides.to_vec();
    overrides.push(("GOCACHE", other_cache.to_str().unwrap()));
    let preview = run_with_overrides(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            other_cache.to_str().unwrap(),
            "--preview",
        ],
        &overrides,
    );
    assert!(!preview.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&preview.stdout),
        String::from_utf8_lossy(&preview.stderr)
    );
    assert!(message.contains("selected cache overlaps another discovered cache location"));
    assert!(other_cache.is_dir());

    let log_conflict_a = f.home.join("npm-log-conflict-a");
    let log_conflict_b = f.home.join("npm-log-conflict-b");
    let other_cache = log_conflict_b.join("go-build");
    fs::create_dir_all(&log_conflict_a).unwrap();
    fs::create_dir_all(&other_cache).unwrap();
    for path in [&log_conflict_a, &log_conflict_b, &other_cache] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let log_overrides = [
        ("npm_config_logs_dir", log_conflict_a.to_str().unwrap()),
        ("NPM_CONFIG_LOGS-DIR", log_conflict_b.to_str().unwrap()),
        ("GOCACHE", other_cache.to_str().unwrap()),
    ];
    let preview = run_with_overrides(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            other_cache.to_str().unwrap(),
            "--preview",
        ],
        &log_overrides,
    );
    assert!(!preview.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&preview.stdout),
        String::from_utf8_lossy(&preview.stderr)
    );
    assert!(message.contains("selected cache overlaps another discovered cache location"));
    assert!(other_cache.is_dir());

    let dynamic = format!("{}/${{SYNTHETIC_VARIABLE}}/cache", f.home.display());
    for name in ["NPM_CONFIG_CACHE", "npm_config_logs-dir"] {
        let status = run(&["cache", "status"], Some((name, &dynamic)));
        assert!(status.status.success());
        let output = String::from_utf8(status.stdout).unwrap();
        assert!(output.contains("a cache directory environment setting is unresolved"));
        assert!(!output.contains("SYNTHETIC_VARIABLE"));
        let removal = run(&removal_args, Some((name, &dynamic)));
        assert!(!removal.status.success());
        assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
        assert!(!sentinel.exists());
    }

    for name in ["NPM_CONFIG_CACHE", "Npm_Config_Cache"] {
        let status = run(&["cache", "status"], Some((name, "relative-private-cache")));
        assert!(status.status.success());
        let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
        assert!(report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning == "a cache directory environment setting is unresolved; shared-cache removal is blocked"));
        assert!(!String::from_utf8_lossy(&status.stdout).contains("relative-private-cache"));
        let removal = run(&removal_args, Some((name, "relative-private-cache")));
        assert!(!removal.status.success(), "{name} must block removal");
        assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
        assert!(!sentinel.exists());
    }

    for name in [
        "CARGO_HOME",
        "npm_config_cache",
        "npm_config_logs_dir",
        "YARN_CACHE_FOLDER",
        "PIP_CACHE_DIR",
        "GRADLE_USER_HOME",
        "CCACHE_DIR",
        "SCCACHE_DIR",
        "PUB_CACHE",
        "XDG_CACHE_HOME",
    ] {
        let status = run(&["cache", "status"], Some((name, "")));
        assert!(status.status.success());
        let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
        assert!(report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning == "a cache directory environment setting is unresolved; shared-cache removal is blocked"),
            "{name} must warn when explicitly empty");

        let removal = run(&removal_args, Some((name, "")));
        assert!(!removal.status.success(), "{name} must block removal");
        assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
        assert!(!sentinel.exists());
    }
    for name in [
        "NPM_CONFIG_CACHE",
        "Npm_Config_Cache",
        "NPM_CONFIG_LOGS_DIR",
        "Npm_Config_Logs_Dir",
    ] {
        let status = run(&["cache", "status"], Some((name, "")));
        assert!(status.status.success());
        let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
        assert!(report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| warning == "a cache directory environment setting is unresolved; shared-cache removal is blocked"),
            "{name} must warn when explicitly empty");
        let removal = run(&removal_args, Some((name, "")));
        assert!(!removal.status.success(), "{name} must block removal");
        assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
        assert!(!sentinel.exists());
    }

    let unset_removal = run(&removal_args, None);
    assert!(unset_removal.status.success());
    assert!(!f.cache.join("bucket/item").exists());
    assert!(!sentinel.exists());
}

#[test]
fn zig_global_cache_preview_is_read_only_and_yes_alone_does_not_remove_it() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let zig = f.home.join("zig-global");
    let packages = zig.join("packages");
    let dependency = packages.join("fixture-dependency");
    fs::create_dir_all(&dependency).unwrap();
    for path in [&zig, &packages, &dependency] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let file = dependency.join("source.zig");
    fs::write(&file, "fixture dependency").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();

    let target = zig.to_str().unwrap();
    let run = |args: &[&str]| {
        f.command()
            .arg(env!("CARGO_BIN_EXE_upkit"))
            .args(["--non-interactive", "--json", "--home"])
            .arg(f.home.join("upkit"))
            .args(args)
            .env_clear()
            .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
            .env("HOME", &f.home)
            .env("PATH", "/usr/bin:/bin")
            .env("GOCACHE", &f.cache)
            .env("XDG_CONFIG_HOME", f.home.join("config"))
            .env("XDG_DATA_HOME", f.home.join("data"))
            .env("XDG_CACHE_HOME", f.home.join("cache"))
            .env("ZIG_GLOBAL_CACHE_DIR", &zig)
            .output()
            .unwrap()
    };

    let preview = run(&[
        "sweep",
        "run",
        "--scope",
        "cache",
        "--select",
        target,
        "--preview",
    ]);
    assert!(
        preview.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&preview.stdout),
        String::from_utf8_lossy(&preview.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(plan["plan"]["name"], "Zig");
    assert_eq!(plan["plan"]["target"], target);
    assert_eq!(plan["plan"]["classification"], "shared build cache");
    assert!(
        plan["plan"]["consequence"]
            .as_str()
            .unwrap()
            .contains("packages may need to be downloaded again")
    );
    assert!(
        plan["plan"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"] == "packages/fixture-dependency/source.zig")
    );
    assert!(zig.is_dir());
    assert_eq!(fs::read_to_string(&file).unwrap(), "fixture dependency");

    let yes_only = run(&[
        "--yes", "sweep", "run", "--scope", "cache", "--select", target,
    ]);
    assert!(!yes_only.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&yes_only.stdout),
        String::from_utf8_lossy(&yes_only.stderr)
    );
    assert!(message.contains("--authorize-shared-cache"));
    assert!(zig.is_dir());
    assert_eq!(fs::read_to_string(&file).unwrap(), "fixture dependency");
}

#[test]
fn zig_global_cache_cannot_be_a_non_git_source_project_root() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let project = f.home.join("zig-project");
    fs::create_dir(&project).unwrap();
    fs::set_permissions(&project, fs::Permissions::from_mode(0o700)).unwrap();
    let manifest = project.join("build.zig");
    let source = project.join("main.zig");
    fs::write(&manifest, "pub fn build(_: *std.Build) void {}\n").unwrap();
    fs::write(&source, "pub fn main() void {}\n").unwrap();
    for file in [&manifest, &source] {
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let output = f.run_with_zig_cache(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            project.to_str().unwrap(),
            "--preview",
        ],
        &project,
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("cache root contains a project manifest")
    );
    assert_eq!(
        fs::read_to_string(&source).unwrap(),
        "pub fn main() void {}\n"
    );
}

#[test]
fn dependency_manifest_nested_in_cargo_cache_is_previewed_with_source_warning() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let registry = f.home.join(".cargo/registry");
    let package = registry.join("src/index/package-0.1.0");
    fs::create_dir_all(&package).unwrap();
    for dir in [
        f.home.join(".cargo"),
        registry.clone(),
        registry.join("src"),
        registry.join("src/index"),
        package.clone(),
    ] {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let manifest = package.join("Cargo.toml");
    fs::write(&manifest, "[package]\nname='fixture'\nversion='0.1.0'\n").unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();

    let output = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            registry.to_str().unwrap(),
            "--preview",
        ],
        &f.cache,
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        plan["plan"]["warning"]
            .as_str()
            .unwrap()
            .contains("cannot distinguish dependency source from your own source")
    );
    assert!(
        plan["plan"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"] == "src/index/package-0.1.0/Cargo.toml")
    );
    assert!(manifest.is_file());
}

#[test]
fn unresolved_maven_settings_block_shared_cache_preview() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let settings = f.home.join(".m2/settings.xml");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        "<settings><localRepository>relative/repository</localRepository></settings>",
    )
    .unwrap();
    let target = f.cache.to_str().unwrap();
    let output = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            target,
            "--preview",
        ],
        &f.cache,
    );
    assert!(!output.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(message.contains("Maven cache configuration is unverified"));
    assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
}

#[test]
fn maven_project_config_files_block_shared_cache_preview() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let config_dir = f.home.join(".mvn");
    fs::create_dir_all(&config_dir).unwrap();
    let names = [
        "jvm.config",
        "maven.config",
        "maven-system.properties",
        "maven-user.properties",
        "settings.xml",
        "extensions.xml",
    ];
    for name in names {
        fs::write(
            config_dir.join(name),
            "-Dmaven.repo.local=/synthetic/fixture-repository\n",
        )
        .unwrap();
    }

    let status = f.run(&["cache", "status"], &f.cache);
    assert!(status.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert!(
        status["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|warning| {
                warning
                    .as_str()
                    .unwrap()
                    .contains("Maven local repository is unverified")
            })
    );

    let target = f.cache.to_str().unwrap();
    let output = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            target,
            "--preview",
        ],
        &f.cache,
    );
    assert!(!output.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(message.contains("Maven local repository may be overridden"));
    assert!(!message.contains("fixture-repository"));
    assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
}

#[test]
fn safe_maven_project_and_installation_configs_allow_shared_cache_preview() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let project_config = f.home.join(".mvn");
    fs::create_dir_all(&project_config).unwrap();
    fs::write(project_config.join("jvm.config"), "-Xmx2g\n-Xms512m\n").unwrap();
    fs::write(project_config.join("maven.config"), "--batch-mode -T 2\n").unwrap();
    fs::write(
        project_config.join("settings.xml"),
        "<settings><offline>false</offline></settings>",
    )
    .unwrap();

    let maven_home = f.home.join("maven-install");
    fs::create_dir_all(maven_home.join("conf")).unwrap();
    fs::write(
        maven_home.join("conf/settings.xml"),
        "<settings xmlns=\"http://maven.apache.org/SETTINGS/1.2.0\"><mirrors/></settings>",
    )
    .unwrap();

    let target = f.cache.to_str().unwrap();
    let output = f.run_with_environment(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            target,
            "--preview",
        ],
        &f.cache,
        Some(("MAVEN_HOME", maven_home.as_os_str())),
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
}

#[test]
fn linked_maven_options_file_blocks_shared_cache_preview() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let project_config = f.home.join(".mvn");
    fs::create_dir_all(&project_config).unwrap();
    let safe_options = f.home.join("safe-jvm.config");
    fs::write(&safe_options, "-Xmx2g\n").unwrap();
    symlink(safe_options, project_config.join("jvm.config")).unwrap();

    let output = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            f.cache.to_str().unwrap(),
            "--preview",
        ],
        &f.cache,
    );
    assert!(!output.status.success());
    assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
}

#[test]
fn maven_environment_overrides_block_but_heap_options_do_not() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let target = f.cache.to_str().unwrap();
    let args = [
        "sweep",
        "run",
        "--scope",
        "cache",
        "--select",
        target,
        "--preview",
    ];
    let assert_blocked = |output: Output| {
        assert!(!output.status.success());
        let message = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(message.contains("Maven local repository"));
        assert!(!message.contains("synthetic"));
        assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
    };

    for (name, value) in [
        ("MAVEN_OPTS", "-Duser.home=/synthetic/maven-home"),
        ("JAVA_TOOL_OPTIONS", "-Duser.home=/synthetic/maven-home"),
        (
            "JAVA_TOOL_OPTIONS",
            "-Djava.system.class.loader=example.Loader",
        ),
        (
            "JDK_JAVA_OPTIONS",
            "-Djava.class.path=/synthetic/loader.jar",
        ),
        ("JDK_JAVA_OPTIONS", "-Dmaven.repo.local=/synthetic/cache"),
        ("MAVEN_OPTS", "-Dcustom.property=value"),
        ("_JAVA_OPTIONS", "-Dmaven.repo.local=/synthetic/cache"),
        (
            "MAVEN_ARGS",
            "-Dmaven.repo.local.head=/synthetic/maven-head",
        ),
        (
            "MAVEN_ARGS",
            "-Dmaven.repo.local.tail=/synthetic/maven-tail",
        ),
        (
            "MAVEN_ARGS",
            "-Dmaven.project.settings=/synthetic/project-settings.xml",
        ),
        ("MAVEN_ARGS", "-s /synthetic/settings.xml"),
        ("MAVEN_ARGS", "--global-settings=/synthetic/global.xml"),
        ("MAVEN_ARGS", "-f /synthetic/other/pom.xml"),
    ] {
        assert_blocked(f.run_with_environment(
            &args,
            &f.cache,
            Some((name, std::ffi::OsStr::new(value))),
        ));
    }

    let maven_home = f.home.join("maven-install");
    fs::create_dir_all(maven_home.join("conf")).unwrap();
    fs::write(
        maven_home.join("conf/settings.xml"),
        "<settings><localRepository>/synthetic/global-repository</localRepository></settings>",
    )
    .unwrap();
    assert_blocked(f.run_with_environment(
        &args,
        &f.cache,
        Some(("MAVEN_HOME", maven_home.as_os_str())),
    ));
    fs::write(
        maven_home.join("conf/settings.xml"),
        "<settings><offline>false</offline></settings>",
    )
    .unwrap();
    let linked_maven_home = f.home.join("maven-install-link");
    symlink(&maven_home, &linked_maven_home).unwrap();
    let linked_home_output = f.run_with_environment(
        &args,
        &f.cache,
        Some(("MAVEN_HOME", linked_maven_home.as_os_str())),
    );
    assert!(!linked_home_output.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&linked_home_output.stdout),
        String::from_utf8_lossy(&linked_home_output.stderr)
    );
    assert!(message.contains("Maven installation home"), "{message}");
    assert!(!message.contains("synthetic"));
    assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");

    let maven_user_config = f.home.join(".m2");
    fs::create_dir_all(&maven_user_config).unwrap();
    for name in ["maven-system.properties", "maven-user.properties"] {
        fs::write(
            maven_user_config.join(name),
            "maven.repo.local=/synthetic/user-repository\n",
        )
        .unwrap();
        assert_blocked(f.run(&args, &f.cache));
        fs::remove_file(maven_user_config.join(name)).unwrap();
    }

    let heap_options = f.run_with_environment(
        &args,
        &f.cache,
        Some(("MAVEN_OPTS", std::ffi::OsStr::new("-Xmx2g"))),
    );
    assert!(
        heap_options.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&heap_options.stdout),
        String::from_utf8_lossy(&heap_options.stderr)
    );
    assert_eq!(fs::read(f.cache.join("bucket/item")).unwrap(), b"fixture");
}

#[test]
fn shared_cache_requires_explicit_authorization_and_revalidates() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let plan = f.preview();
    assert_eq!(plan["plan"]["name"], "Go build");
    assert!(
        plan["plan"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["path"] == "bucket/item")
    );
    assert!(
        plan["plan"]["warning"]
            .as_str()
            .unwrap()
            .contains("user data")
    );
    let token = plan["plan"]["preview_token"].as_str().unwrap();
    let target = f.cache.to_str().unwrap();
    let run = |token: &str, auth: bool, cache: &Path| {
        let mut args = vec![
            "--yes",
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            target,
            "--preview-token",
            token,
        ];
        if auth {
            args.push("--authorize-shared-cache");
        }
        f.run(&args, cache)
    };
    assert!(!run(token, false, &f.cache).status.success());
    assert!(!run("wrong", true, &f.cache).status.success());
    assert!(
        !f.run(
            &[
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
                target,
                "--preview-token",
                token,
                "--authorize-shared-cache"
            ],
            &f.cache
        )
        .status
        .success()
    );
    assert!(
        !f.run(
            &[
                "--yes",
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
                target,
                "--authorize-shared-cache"
            ],
            &f.cache
        )
        .status
        .success()
    );
    assert!(
        !run(token, true, &f.home.join("other-cache"))
            .status
            .success()
    );
    assert!(
        !f.run(
            &[
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
                target,
                "--root",
                f.home.to_str().unwrap(),
                "--preview"
            ],
            &f.cache
        )
        .status
        .success()
    );
    let dry = f.run(
        &[
            "--dry-run",
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            target,
        ],
        &f.cache,
    );
    assert!(dry.status.success());
    fs::write(f.cache.join("bucket/item"), "changed").unwrap();
    assert!(!run(token, true, &f.cache).status.success());
    assert_eq!(
        fs::read_to_string(f.cache.join("bucket/item")).unwrap(),
        "changed"
    );
    let plan = f.preview();
    let token = plan["plan"]["preview_token"].as_str().unwrap();
    let out = run(token, true, &f.cache);
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["verification"], "verified_absent");
    assert!(!f.cache.exists());
    let history = f.run(&["report"], &f.cache);
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["operation"] == "shared_cache_removal"
                && record["outcome"] == "completed")
    );
}

#[test]
fn shared_cache_rejects_links_vcs_and_unrelated_paths() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let target = f.cache.to_str().unwrap();
    let preview = |path: &str| {
        f.run(
            &[
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
                path,
                "--preview",
            ],
            &f.cache,
        )
    };
    assert!(!preview(f.home.to_str().unwrap()).status.success());
    let link = f.cache.join("bucket/link");
    symlink(f.home.join("outside"), &link).unwrap();
    assert!(!preview(target).status.success());
    fs::remove_file(link).unwrap();
    let hard = f.home.join("hard-link");
    fs::hard_link(f.cache.join("bucket/item"), &hard).unwrap();
    assert!(!preview(target).status.success());
    fs::remove_file(hard).unwrap();
    fs::create_dir(f.cache.join("bucket/.git")).unwrap();
    assert!(!preview(target).status.success());
    assert_eq!(
        fs::read_to_string(f.cache.join("bucket/item")).unwrap(),
        "fixture"
    );
}

#[test]
fn shared_cache_rejects_active_process_and_removes_only_selected_dependency_cache() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let active = f.command()
        .args(["/bin/sh", "-c", "cd \"$1\" || exit 1; /bin/sleep 30 & child=$!; cd \"$2\" || exit 1; \"$3\" --non-interactive --json --home \"$4\" sweep run --scope cache --select \"$1\" --preview; code=$?; kill \"$child\"; wait \"$child\" 2>/dev/null; exit \"$code\"", "fixture"])
        .arg(&f.cache).arg(&f.home).arg(env!("CARGO_BIN_EXE_upkit")).arg(f.home.join("upkit"))
        .env_clear()
            .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE")).env("HOME", &f.home).env("PATH", "/usr/bin:/bin")
        .env("GOCACHE", &f.cache).env("XDG_DATA_HOME", f.home.join("data"))
        .env("XDG_CONFIG_HOME", f.home.join("config")).env("XDG_CACHE_HOME", f.home.join("cache"))
        .output().unwrap();
    assert!(!active.status.success());
    assert!(String::from_utf8_lossy(&active.stdout).contains("process activity"));
    let cargo = f.home.join(".cargo/registry");
    fs::create_dir_all(cargo.join("src/package")).unwrap();
    for dir in [
        f.home.join(".cargo"),
        cargo.clone(),
        cargo.join("src"),
        cargo.join("src/package"),
    ] {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(
        cargo.join("src/package/Cargo.toml"),
        "[package]\nname='fixture'\n",
    )
    .unwrap();
    fs::set_permissions(
        cargo.join("src/package/Cargo.toml"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let target = cargo.to_str().unwrap();
    let overlap = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            target,
            "--preview",
        ],
        &cargo.join("nested-go-cache"),
    );
    assert!(!overlap.status.success());
    assert!(String::from_utf8_lossy(&overlap.stdout).contains("overlaps another"));
    let preview = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            target,
            "--preview",
        ],
        &f.cache,
    );
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(plan["plan"]["name"], "Cargo registry");
    assert!(
        plan["plan"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["path"] == "src/package/Cargo.toml")
    );
    let token = plan["plan"]["preview_token"].as_str().unwrap();
    let result = f.run(
        &[
            "--yes",
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            target,
            "--preview-token",
            token,
            "--authorize-shared-cache",
        ],
        &f.cache,
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert!(!cargo.exists());
    assert_eq!(
        fs::read_to_string(f.cache.join("bucket/item")).unwrap(),
        "fixture"
    );
}

#[test]
fn shared_cache_removal_refuses_unknown_gopath_after_preview() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let cargo = f.home.join(".cargo/registry");
    fs::create_dir_all(cargo.join("src/package")).unwrap();
    for dir in [
        f.home.join(".cargo"),
        cargo.clone(),
        cargo.join("src"),
        cargo.join("src/package"),
    ] {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(
        cargo.join("src/package/Cargo.toml"),
        "[package]\nname='fixture'\n",
    )
    .unwrap();
    fs::set_permissions(
        cargo.join("src/package/Cargo.toml"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let target = cargo.to_str().unwrap();
    let preview_output = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            target,
            "--preview",
        ],
        &f.cache,
    );
    assert!(
        preview_output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&preview_output.stdout),
        String::from_utf8_lossy(&preview_output.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&preview_output.stdout).unwrap();
    assert_eq!(preview["plan"]["name"], "Cargo registry");
    let token = preview["plan"]["preview_token"].as_str().unwrap();
    let goroot = f.home.join("go");
    let root_modules = goroot.join("pkg/mod");
    fs::create_dir_all(goroot.join("pkg/tool")).unwrap();
    fs::create_dir_all(&root_modules).unwrap();
    fs::write(root_modules.join("root-module"), "fixture").unwrap();
    fs::write(
        goroot.join("go.env"),
        format!(
            "GOPATH={}\nGOMODCACHE={}\nGOCACHEPROG=/private/untrusted-cache\n",
            goroot.join("gopath").display(),
            root_modules.display()
        ),
    )
    .unwrap();
    fs::write(
        f.home.join("config/go/env"),
        b"GOPATH=\nGOMODCACHE=\nGOCACHEPROG=\n",
    )
    .unwrap();
    let status = f
        .command()
        .arg(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "cache", "status"])
        .env_clear()
        .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
        .env("HOME", &f.home)
        .env("PATH", "/usr/bin:/bin")
        .env("GOROOT", &goroot)
        .env("GOTOOLCHAIN", "auto")
        .env("GOCACHE", &f.cache)
        .env("XDG_CONFIG_HOME", f.home.join("config"))
        .env("XDG_DATA_HOME", f.home.join("data"))
        .env("XDG_CACHE_HOME", f.home.join("cache"))
        .output()
        .unwrap();
    assert!(status.status.success());
    let report: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert!(
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go build" && entry["path"] == f.cache.to_str().unwrap())
    );
    assert!(
        !report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "Go modules")
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
    let output = f
        .command()
        .arg(env!("CARGO_BIN_EXE_upkit"))
        .args(["--non-interactive", "--json", "--home"])
        .arg(f.home.join("upkit"))
        .args(["--yes", "sweep", "run", "--scope", "cache", "--select"])
        .arg(&cargo)
        .args(["--authorize-shared-cache", "--preview-token", token])
        .env_clear()
        .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
        .env("HOME", &f.home)
        .env("PATH", "/usr/bin:/bin")
        .env("GOROOT", &goroot)
        .env("GOTOOLCHAIN", "auto")
        .env("GOCACHE", &f.cache)
        .env("XDG_CONFIG_HOME", f.home.join("config"))
        .env("XDG_DATA_HOME", f.home.join("data"))
        .env("XDG_CACHE_HOME", f.home.join("cache"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        message.contains("Go cache locations are unknown"),
        "{message}"
    );
    assert_eq!(
        fs::read_to_string(cargo.join("src/package/Cargo.toml")).unwrap(),
        "[package]\nname='fixture'\n"
    );
}

#[test]
fn shared_cache_removal_refuses_external_go_cache_program_without_running_it() {
    use std::os::unix::fs::PermissionsExt;

    let Some(f) = Fixture::new() else {
        return;
    };
    let cargo = f.home.join(".cargo/registry");
    fs::create_dir_all(cargo.join("src/package")).unwrap();
    for dir in [
        f.home.join(".cargo"),
        cargo.clone(),
        cargo.join("src"),
        cargo.join("src/package"),
    ] {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let manifest = cargo.join("src/package/Cargo.toml");
    fs::write(&manifest, "[package]\nname='fixture'\n").unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    let target = cargo.to_str().unwrap();
    let preview = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            target,
            "--preview",
        ],
        &f.cache,
    );
    assert!(
        preview.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&preview.stdout),
        String::from_utf8_lossy(&preview.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let token = plan["plan"]["preview_token"].as_str().unwrap();

    let bin = f.home.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let go_ran = f.home.join("go-command-ran");
    let fake_go = bin.join("go");
    fs::write(
        &fake_go,
        format!("#!/bin/sh\nprintf invoked > '{}'\n", go_ran.display()),
    )
    .unwrap();
    fs::set_permissions(&fake_go, fs::Permissions::from_mode(0o700)).unwrap();
    let cache_program_ran = f.home.join("cache-program-ran");
    let cache_program = bin.join("cache-program");
    fs::write(
        &cache_program,
        format!(
            "#!/bin/sh\nprintf invoked > '{}'\n",
            cache_program_ran.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&cache_program, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        f.home.join("config/go/env"),
        format!(
            "GOPATH={}\nGOMODCACHE=\nGOCACHEPROG={}\n",
            f.home.join("go").display(),
            cache_program.display()
        ),
    )
    .unwrap();

    let output = f
        .command()
        .arg(env!("CARGO_BIN_EXE_upkit"))
        .args(["--non-interactive", "--json", "--home"])
        .arg(f.home.join("upkit"))
        .args(["--yes", "sweep", "run", "--scope", "cache", "--select"])
        .arg(&cargo)
        .args(["--authorize-shared-cache", "--preview-token", token])
        .env_clear()
        .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
        .env("HOME", &f.home)
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("GOCACHE", &f.cache)
        .env("XDG_CONFIG_HOME", f.home.join("config"))
        .env("XDG_DATA_HOME", f.home.join("data"))
        .env("XDG_CACHE_HOME", f.home.join("cache"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        message.contains("external cache program is configured"),
        "{message}"
    );
    assert!(!go_ran.exists());
    assert!(!cache_program_ran.exists());
    assert_eq!(
        fs::read_to_string(&manifest).unwrap(),
        "[package]\nname='fixture'\n"
    );
}

#[test]
fn history_inside_selected_cache_is_rejected_before_removal() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("cache");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("keep"), "fixture").unwrap();
    let plan = upkit::shared_cache_cleanup::CacheRemovalPlan {
        name: "Go build",
        target: target.clone(),
        classification: "shared build cache",
        consequence: "rebuild",
        logical_bytes: 7,
        entries: vec![],
        preview_token: "fixture".into(),
        warning: "fixture",
    };
    let result = upkit::reports::perform_shared_cache_removal(
        &target.join("history-home"),
        &plan,
        "fixture",
        &std::sync::atomic::AtomicBool::new(false),
    );
    assert!(result.result.unwrap_err().contains("history location"));
    assert_eq!(fs::read_to_string(target.join("keep")).unwrap(), "fixture");
    assert!(!target.join("history-home").exists());
    let alias = dir.path().join("alias");
    symlink(&target, &alias).unwrap();
    let result = upkit::reports::perform_shared_cache_removal(
        &alias.join("history-home"),
        &plan,
        "fixture",
        &std::sync::atomic::AtomicBool::new(false),
    );
    assert!(result.result.unwrap_err().contains("history location"));
    assert!(!target.join("history-home").exists());

    let inverse_target = dir.path().join("inverse-cache");
    let outside = dir.path().join("outside");
    fs::create_dir(&inverse_target).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(inverse_target.join("keep"), "fixture").unwrap();
    symlink(&outside, inverse_target.join("home")).unwrap();
    let inverse_plan = upkit::shared_cache_cleanup::CacheRemovalPlan {
        name: "Go build",
        target: inverse_target.clone(),
        classification: "shared build cache",
        consequence: "rebuild",
        logical_bytes: 7,
        entries: vec![],
        preview_token: "fixture".into(),
        warning: "fixture",
    };
    let inverse = upkit::reports::perform_shared_cache_removal(
        &inverse_target.join("home"),
        &inverse_plan,
        "fixture",
        &std::sync::atomic::AtomicBool::new(false),
    );
    assert!(inverse.result.unwrap_err().contains("history location"));
    assert_eq!(
        fs::read_to_string(inverse_target.join("keep")).unwrap(),
        "fixture"
    );
    assert!(!outside.join("history").exists());
}

#[test]
fn shared_cache_removal_rejects_history_target_and_descendant_without_mutation() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let history = f.home.join("upkit/history");
    fs::create_dir_all(&history).unwrap();
    fs::set_permissions(f.home.join("upkit"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
    let history_marker = history.join("history-marker");
    fs::write(&history_marker, "keep history").unwrap();
    fs::set_permissions(&history_marker, fs::Permissions::from_mode(0o600)).unwrap();

    for target in [history.clone(), history.join("go-build")] {
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let cache_marker = target.join("cache-marker");
        fs::write(&cache_marker, "keep cache").unwrap();
        fs::set_permissions(&cache_marker, fs::Permissions::from_mode(0o600)).unwrap();

        let plan = f.preview_cache(&target);
        let token = plan["plan"]["preview_token"].as_str().unwrap().to_owned();
        let output = f.run(
            &[
                "--yes",
                "sweep",
                "run",
                "--scope",
                "cache",
                "--select",
                target.to_str().unwrap(),
                "--authorize-shared-cache",
                "--preview-token",
                &token,
            ],
            &target,
        );
        let message = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{message}");
        assert!(message.contains("operation history location"), "{message}");
        assert!(target.is_dir());
        assert_eq!(fs::read_to_string(&cache_marker).unwrap(), "keep cache");
        assert_eq!(fs::read_to_string(&history_marker).unwrap(), "keep history");
        assert!(!history.join("000.json").exists());
    }
}

#[test]
fn shared_cache_preview_and_removal_support_non_utf8_paths() {
    use std::os::unix::ffi::OsStringExt;
    let Some(f) = Fixture::new() else {
        return;
    };
    let target = f
        .home
        .join("cache")
        .join(std::ffi::OsString::from_vec(b"cache-\xff%".to_vec()));
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let file = target.join(std::ffi::OsString::from_vec(b"file-\xfe%".to_vec()));
    fs::write(&file, "fixture").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let run = |token: Option<&str>| {
        let mut command = f.command();
        command
            .arg(env!("CARGO_BIN_EXE_upkit"))
            .args(["--non-interactive", "--json", "--home"])
            .arg(f.home.join("upkit"));
        if token.is_some() {
            command.arg("--yes");
        }
        command
            .args(["sweep", "run", "--scope", "cache", "--select"])
            .arg(&target);
        match token {
            Some(token) => {
                command.args(["--authorize-shared-cache", "--preview-token", token]);
            }
            None => {
                command.arg("--preview");
            }
        }
        command
            .env_clear()
            .envs(std::env::vars_os().filter(|(key, _)| key == "LLVM_PROFILE_FILE"))
            .env("HOME", &f.home)
            .env("PATH", "/usr/bin:/bin")
            .env("GOCACHE", &target)
            .env("XDG_DATA_HOME", f.home.join("data"))
            .env("XDG_CONFIG_HOME", f.home.join("config"))
            .env("XDG_CACHE_HOME", f.home.join("cache"))
            .output()
            .unwrap()
    };
    let output = run(None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["plan"]["target"]["encoding"], "unix-percent-bytes");
    assert!(
        plan["plan"]["target"]["value"]
            .as_str()
            .unwrap()
            .ends_with("/cache-%FF%25")
    );
    assert_eq!(plan["plan"]["entries"][0]["path"], "file-%FE%25");
    let output = run(plan["plan"]["preview_token"].as_str());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!target.exists());
    assert!(f.cache.exists());
}

#[test]
fn shared_cache_preview_keeps_unicode_target_as_text() {
    let Some(f) = Fixture::new() else {
        return;
    };
    let target = f.home.join("cache/go-é%cache");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let file = target.join("fixture");
    fs::write(&file, "keep").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let target_arg = target.to_str().unwrap();
    let output = f.run(
        &[
            "sweep",
            "run",
            "--scope",
            "cache",
            "--select",
            target_arg,
            "--preview",
        ],
        &target,
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let preview: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(preview["plan"]["target"], target_arg);
    assert_eq!(fs::read_to_string(target.join("fixture")).unwrap(), "keep");
}
