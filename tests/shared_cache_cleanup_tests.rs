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
            "/usr/bin/mount --make-rprivate / && /usr/bin/mount --bind \"$1\" /etc/opt && shift && exec \"$@\"",
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
        private_etc_opt_namespace(&self.machine_opt)
    }
    fn run(&self, args: &[&str], cache: &Path) -> Output {
        self.command()
            .arg(env!("CARGO_BIN_EXE_upkit"))
            .args(["--non-interactive", "--json", "--home"])
            .arg(self.home.join("upkit"))
            .args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("XDG_CACHE_HOME", self.home.join("cache"))
            .env("GOCACHE", cache)
            .output()
            .unwrap()
    }
    fn run_with_zig_cache(&self, args: &[&str], zig_cache: &Path) -> Output {
        self.command()
            .arg(env!("CARGO_BIN_EXE_upkit"))
            .args(["--non-interactive", "--json", "--home"])
            .arg(self.home.join("upkit"))
            .args(args)
            .env_clear()
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
        .env_clear().env("HOME", &f.home).env("PATH", "/usr/bin:/bin")
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
