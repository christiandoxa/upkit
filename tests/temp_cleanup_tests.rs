#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::{Path, PathBuf},
        process::{Command, Output},
        time::{Duration, UNIX_EPOCH},
    };

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("upkit-home");
        let bindir = root.path().join("upkit-bin");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&bindir).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&bindir, fs::Permissions::from_mode(0o700)).unwrap();
        let user_home = root.path().join("user-home");
        fs::create_dir(&user_home).unwrap();
        fs::set_permissions(&user_home, fs::Permissions::from_mode(0o700)).unwrap();
        (root, home, bindir, user_home)
    }

    fn stale_link(parent: &Path, home: &Path) -> PathBuf {
        let staging = tempfile::Builder::new()
            .prefix(".upkit-link-")
            .tempdir_in(parent)
            .unwrap();
        symlink(
            home.join("go/versions/1.2.3/bin/go"),
            staging.path().join("link"),
        )
        .unwrap();
        fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let old = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        fs::File::open(staging.path())
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(old))
            .unwrap();
        let destination = parent.join(".upkit-link-cli-fixture");
        fs::rename(staging.keep(), &destination).unwrap();
        destination
    }

    fn run(
        home: &Path,
        bindir: &Path,
        user_home: &Path,
        global: &[&str],
        operation: &[&str],
        select: Option<&Path>,
    ) -> Output {
        run_in_namespace(home, bindir, user_home, global, operation, select, false)
    }

    fn run_in_namespace(
        home: &Path,
        bindir: &Path,
        user_home: &Path,
        global: &[&str],
        operation: &[&str],
        select: Option<&Path>,
        isolated: bool,
    ) -> Output {
        let mut command = if isolated {
            let mut command = Command::new("unshare");
            command
                .args([
                    "--user",
                    "--map-root-user",
                    "--pid",
                    "--fork",
                    "--mount-proc",
                ])
                .arg(env!("CARGO_BIN_EXE_upkit"));
            command
        } else {
            Command::new(env!("CARGO_BIN_EXE_upkit"))
        };
        command
            .args(["--json", "--non-interactive", "--home"])
            .arg(home)
            .arg("--bindir")
            .arg(bindir)
            .args(global)
            .args(["maintenance", "temp"])
            .args(operation);
        if let Some(path) = select {
            command.arg("--select").arg(path);
        }
        command
            .env("HOME", user_home)
            .env("XDG_CONFIG_HOME", user_home.join("config"))
            .env("XDG_DATA_HOME", user_home.join("data"))
            .output()
            .unwrap()
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

    #[test]
    fn json_preview_and_dry_run_leave_fixture_staging_untouched() {
        let (_root, home, bindir, user_home) = fixture();
        let candidate = stale_link(&bindir, &home);

        let preview = run(&home, &bindir, &user_home, &[], &["--preview"], None);
        assert!(
            preview.status.success(),
            "{}",
            String::from_utf8_lossy(&preview.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
        assert_eq!(report["plan"]["supported"], true);
        assert_eq!(report["plan"]["candidates"].as_array().unwrap().len(), 1);
        assert!(
            report["plan"]["candidates"][0]["path"]
                .as_str()
                .unwrap()
                .ends_with(".upkit-link-cli-fixture")
        );
        assert!(candidate.join("link").is_symlink());

        let dry_run = run(&home, &bindir, &user_home, &["--dry-run"], &["--run"], None);
        assert!(
            dry_run.status.success(),
            "{}",
            String::from_utf8_lossy(&dry_run.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&dry_run.stdout).unwrap();
        assert_eq!(report["executed"], false);
        assert!(candidate.join("link").is_symlink());
        assert!(!home.join("history").exists());
    }

    #[test]
    fn cli_requires_explicit_authorization_before_planning_mutation() {
        let (_root, home, bindir, user_home) = fixture();
        let candidate = stale_link(&bindir, &home);
        let output = run(
            &home,
            &bindir,
            &user_home,
            &[],
            &["--run"],
            Some(&candidate),
        );
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("--yes, --authorize-temp-cleanup, and a token from a prior --preview"),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(candidate.join("link").is_symlink());
        assert!(!home.join("history").exists());
    }

    #[test]
    fn namespaced_cli_rejects_wrong_token_then_records_each_selected_result() {
        if !namespace_available() {
            eprintln!("SKIP: an isolated user/PID namespace is unavailable");
            return;
        }
        let (_root, home, bindir, user_home) = fixture();
        let candidate = stale_link(&bindir, &home);
        let selected = Some(candidate.as_path());
        let preview = run_in_namespace(
            &home,
            &bindir,
            &user_home,
            &[],
            &["--preview"],
            selected,
            true,
        );
        assert!(
            preview.status.success(),
            "{}",
            String::from_utf8_lossy(&preview.stderr)
        );
        let preview: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
        let token = preview["plan"]["preview_token"]
            .as_str()
            .unwrap()
            .to_owned();

        let wrong_token = run_in_namespace(
            &home,
            &bindir,
            &user_home,
            &["--yes"],
            &[
                "--run",
                "--authorize-temp-cleanup",
                "--preview-token",
                "wrong",
            ],
            selected,
            true,
        );
        assert!(!wrong_token.status.success());
        assert!(candidate.join("link").is_symlink());

        let supplied_token = [
            "--run",
            "--authorize-temp-cleanup",
            "--preview-token",
            &token,
        ];
        let removed = run_in_namespace(
            &home,
            &bindir,
            &user_home,
            &["--yes"],
            &supplied_token,
            selected,
            true,
        );
        assert!(
            removed.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&removed.stdout),
            String::from_utf8_lossy(&removed.stderr)
        );
        let removed: serde_json::Value = serde_json::from_slice(&removed.stdout).unwrap();
        assert_eq!(removed["cleanup"]["items"][0]["status"], "removed");
        assert!(!candidate.exists());

        let mut records = fs::read_dir(home.join("history"))
            .unwrap()
            .map(|entry| {
                serde_json::from_slice::<serde_json::Value>(
                    &fs::read(entry.unwrap().path()).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|record| record["id"].as_u64().unwrap());
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["target"], candidate.display().to_string());
        assert_eq!(records[0]["outcome"], "failed_or_unknown");
        assert!(
            records[0]["detail"]
                .as_str()
                .unwrap()
                .contains("preview changed")
        );
        assert_eq!(records[1]["target"], candidate.display().to_string());
        assert_eq!(records[1]["outcome"], "completed");
        assert_eq!(records[1]["detail"], "removed");
    }
}
