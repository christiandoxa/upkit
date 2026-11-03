#[cfg(unix)]
#[test]
fn container_status_uses_read_only_engine_queries() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let home = dir.path().join("home");
    fs::create_dir(&bin).unwrap();
    fs::create_dir(&home).unwrap();
    let docker = bin.join("docker");
    fs::write(&docker, "#!/bin/sh\n[ \"$1 $2 $3 $4\" = 'system df --format json' ] || exit 2\nprintf '%s\\n' '{\"Type\":\"Images\",\"Size\":\"12MB\"}' '{\"Type\":\"Local Volumes\",\"Size\":\"4MB\"}'\n").unwrap();
    fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "containers", "status"])
        .env("PATH", &bin)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report[0]["state"], "available");
    assert_eq!(report[0]["usage"][0]["Type"], "Images");
    assert_eq!(report[0]["usage"][1]["Type"], "Local Volumes");
    let networks = report[0]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|list| list["kind"] == "unattached custom networks (snapshot)")
        .unwrap();
    assert!(networks["error"].is_string());
    let build_cache = report[0]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|list| list["kind"] == "build cache (selected Buildx builder; snapshot)")
        .unwrap();
    assert!(build_cache["error"].is_string());
    assert_eq!(report[1]["state"], "unavailable");
    assert!(fs::read_dir(home).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn build_cache_removal_requires_unchanged_preview_and_exact_filter() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let docker = dir.path().join("docker");
    let id = "a".repeat(25);
    fs::write(&docker, r##"#!/bin/sh
case "$*" in
 'info --format json') printf '{"ID":"fixture-engine"}\n' ;;
 'buildx inspect fixture --timeout=2s')
   if [ -f "$HOME/multi" ]; then extra='Name: node1'; else extra=''; fi
   if [ -f "$HOME/changed-builder" ]; then endpoint='other'; else endpoint='fixture-endpoint'; fi
   printf 'Name: fixture\nDriver: docker-container\n\nNodes:\nName: node0\nEndpoint: %s\nStatus: running\n%s\n' "$endpoint" "$extra" ;;
 'buildx --builder fixture du --timeout=2s --format=json')
   if [ -f "$HOME/removed" ]; then printf '[]\n'; else
     if [ -f "$HOME/shared" ]; then shared=true; else shared=false; fi
     if [ -f "$HOME/mutable" ]; then mutable=true; else mutable=false; fi
     if [ -f "$HOME/inuse" ]; then reclaimable=false; else reclaimable=true; fi
     if [ -f "$HOME/decimal-string" ]; then size='"123"'; elif [ -f "$HOME/human-size" ]; then size='"1MB"'; else size=123; fi
     printf '{"ID":"%s","Size":%s,"Type":"regular","CreatedAt":"2025-01-01T00:00:00Z","Mutable":%s,"Shared":%s,"Reclaimable":%s}\n' "$CACHE_ID" "$size" "$mutable" "$shared" "$reclaimable"
   fi ;;
 "buildx --builder fixture prune --timeout=2s --force --filter id=^${CACHE_ID}$ --filter immutable=\"\" --filter private=\"\"")
   if [ -f "$HOME/fail-prune" ]; then exit 7; else printf removed > "$HOME/removed"; fi ;;
 *) exit 7 ;;
esac
"##).unwrap();
    fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .env("PATH", dir.path())
            .env("HOME", dir.path())
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("CACHE_ID", &id)
            .output()
            .unwrap()
    };
    let preview = || {
        run(&[
            "--non-interactive",
            "--json",
            "containers",
            "preview-build-cache",
            "--builder",
            "fixture",
            "--id",
            &id,
        ])
    };
    let output = preview();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let token = value["plan"]["preview_token"].as_str().unwrap();
    let remove = |token: &str, authorized: bool| {
        let mut args = vec![
            "--non-interactive",
            "--json",
            "--yes",
            "containers",
            "remove-build-cache",
            "--builder",
            "fixture",
            "--id",
            &id,
            "--preview-token",
            token,
        ];
        if authorized {
            args.push("--authorize-build-cache-removal");
        }
        run(&args)
    };
    assert!(!remove(token, false).status.success());
    assert!(!remove("wrong", true).status.success());
    for marker in ["shared", "mutable", "inuse", "changed-builder", "multi"] {
        fs::write(dir.path().join(marker), "fixture").unwrap();
        assert!(!remove(token, true).status.success(), "{marker}");
        fs::remove_file(dir.path().join(marker)).unwrap();
    }
    for flag in ["--dry-run", "--offline"] {
        assert!(
            !run(&[
                flag,
                "--non-interactive",
                "--json",
                "containers",
                "preview-build-cache",
                "--builder",
                "fixture",
                "--id",
                &id
            ])
            .status
            .success()
        );
    }
    assert!(!dir.path().join("removed").exists());
    let output = remove(token, true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["verification"], "verified_absent");
    assert!(dir.path().join("removed").exists());
    let history = run(&["--json", "report"]);
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["operation"] == "build_cache_remove"
                && record["estimated_bytes"] == 123
                && record["verified_reclaimed_bytes"].is_null())
    );
    fs::remove_file(dir.path().join("removed")).unwrap();
    fs::write(dir.path().join("decimal-string"), "fixture").unwrap();
    let output = preview();
    assert!(output.status.success());
    let token = serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["plan"]["preview_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let output = remove(&token, true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let history = run(&["--json", "report"]);
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["operation"] == "build_cache_remove"
                && record["outcome"] == "completed"
                && record["estimated_bytes"] == 123
                && record["verified_reclaimed_bytes"].is_null())
    );
    fs::remove_file(dir.path().join("removed")).unwrap();
    fs::remove_file(dir.path().join("decimal-string")).unwrap();
    fs::write(dir.path().join("human-size"), "fixture").unwrap();
    fs::write(dir.path().join("fail-prune"), "fixture").unwrap();
    let output = preview();
    assert!(output.status.success());
    let token = serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["plan"]["preview_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let output = remove(&token, true);
    assert!(!output.status.success());
    let history = run(&["--json", "report"]);
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["operation"] == "build_cache_remove"
                && record["outcome"] == "failed_or_unknown"
                && record["estimated_bytes"].is_null()
                && record["verified_reclaimed_bytes"].is_null())
    );
}

#[cfg(unix)]
#[test]
fn dry_run_skips_container_engine_queries() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    for engine in ["docker", "podman"] {
        let executable = dir.path().join(engine);
        let script = format!(
            "#!/bin/sh\nprintf '{engine} %s\\n' \"$*\" >> \"$HOME/engine-calls\"\ncase \"$*\" in\n'buildx inspect --timeout=2s') printf invoked > \"$HOME/buildx-invoked\" ;;\nesac\nprintf '[]\\n'\n"
        );
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let run = |dry_run: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_upkit"));
        if dry_run {
            command.arg("--dry-run");
        }
        command
            .args(["--json", "containers", "status"])
            .env("HOME", dir.path())
            .env("PATH", dir.path())
            .output()
            .unwrap()
    };
    let output = run(true);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for engine in [0, 1] {
        assert_eq!(report[engine]["state"], "skipped");
        assert!(
            report[engine]["detail"]
                .as_str()
                .unwrap()
                .contains("Dry-run")
        );
        assert!(report[engine]["resources"].as_array().unwrap().is_empty());
    }
    assert!(!dir.path().join("engine-calls").exists());
    assert!(!dir.path().join("buildx-invoked").exists());
    let normal = run(false);
    assert!(normal.status.success());
    let calls = fs::read_to_string(dir.path().join("engine-calls")).unwrap();
    assert!(calls.lines().any(|line| line.starts_with("docker ")));
    assert!(calls.lines().any(|line| line.starts_with("podman ")));
    assert!(dir.path().join("buildx-invoked").exists());
}

#[cfg(unix)]
#[test]
fn dry_run_container_and_network_previews_skip_both_engines() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let id = "a".repeat(64);
    for engine in ["docker", "podman"] {
        let executable = dir.path().join(engine);
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\nprintf '{engine} %s\\n' \"$*\" >> \"$HOME/engine-calls\"\nexit 99\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .env("PATH", dir.path())
            .env("HOME", dir.path())
            .output()
            .unwrap()
    };
    let assert_skipped = |output: std::process::Output, operation: &str| {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["operation"], operation);
        assert!(value["plan"].is_null());
        assert_eq!(value["dry_run"], true);
        assert_eq!(value["executed"], false);
        assert_eq!(value["verification"], "not_run");
        assert!(value["detail"].as_str().unwrap().contains("no "));
        assert!(value["detail"].as_str().unwrap().contains("verified"));
    };

    for engine in ["docker", "podman"] {
        assert_skipped(
            run(&[
                "--dry-run",
                "--json",
                "containers",
                "preview-remove",
                "--engine",
                engine,
                "--id",
                &id,
            ]),
            "container removal",
        );
        assert_skipped(
            run(&[
                "--dry-run",
                "--non-interactive",
                "--json",
                "containers",
                "remove",
                "--engine",
                engine,
                "--id",
                &id,
            ]),
            "container removal",
        );
        assert_skipped(
            run(&[
                "--dry-run",
                "--json",
                "containers",
                "preview-network",
                "--engine",
                engine,
                "--id",
                &id,
            ]),
            "network removal",
        );
        assert_skipped(
            run(&[
                "--dry-run",
                "--non-interactive",
                "--json",
                "containers",
                "remove-network",
                "--engine",
                engine,
                "--id",
                &id,
            ]),
            "network removal",
        );
    }
    assert!(!dir.path().join("engine-calls").exists());

    for engine in ["docker", "podman"] {
        for command in ["preview-remove", "preview-network"] {
            let output = run(&[
                "--dry-run",
                "--json",
                "containers",
                command,
                "--engine",
                engine,
                "--id",
                "short",
            ]);
            assert!(!output.status.success());
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(diagnostic.contains("complete 64-character lowercase hexadecimal"));
        }
    }
    assert!(!dir.path().join("engine-calls").exists());
}

#[cfg(unix)]
#[test]
fn image_preview_and_removal_are_unsupported_without_engine_calls() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let id = "a".repeat(64);
    let script = r##"#!/bin/sh
printf '%s\n' "$*" >> "$HOME/engine-calls"
if [ "$1 $2" = 'image rm' ]; then printf attempted > "$HOME/image-rm-called"; fi
exit 99
"##;
    for engine in ["docker", "podman"] {
        let executable = dir.path().join(engine);
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .env("PATH", dir.path())
            .env("HOME", dir.path())
            .env("IMAGE_ID", &id)
            .output()
            .unwrap()
    };
    for engine in ["docker", "podman"] {
        let preview = run(&[
            "--json",
            "containers",
            "preview-image",
            "--engine",
            engine,
            "--id",
            &id,
        ]);
        assert!(!preview.status.success());
        assert!(String::from_utf8_lossy(&preview.stdout).contains("unsupported"));

        let removal = run(&[
            "--json",
            "--non-interactive",
            "--yes",
            "containers",
            "remove-image",
            "--engine",
            engine,
            "--id",
            &id,
            "--preview-token",
            "prior-token",
            "--authorize-image-removal",
        ]);
        assert!(!removal.status.success());
        assert!(String::from_utf8_lossy(&removal.stdout).contains("unsupported"));
        assert!(!dir.path().join("engine-calls").exists());
        assert!(!dir.path().join("image-rm-called").exists());
    }
}

#[cfg(unix)]
#[test]
fn unused_network_removal_requires_preview_and_revalidates() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let id = "b".repeat(64);
    let script = r##"#!/bin/sh
case "$1 $2" in
  'info --format') printf '%s\n' '{"ID":"fixture-server","store":{"graphRoot":"/fixture"},"host":{"hostname":"fixture"}}' ;;
  'network inspect')
    if [ -f "$HOME/changed" ]; then name=changed; elif [ -f "$HOME/default" ]; then name=podman; else name=fixture; fi
    case "$0" in *podman) printf '[{"id":"%s","name":"%s","driver":"bridge"}]\n' "$NETWORK_ID" "$name" ;; *) printf '[{"Id":"%s","Name":"%s","Driver":"bridge","Scope":"local","Containers":{}}]\n' "$NETWORK_ID" "$name" ;; esac ;;
  'network ls')
    case "$*" in *'--no-trunc --format json') ;; *) exit 6 ;; esac
    case "$*" in *dangling=true*) case "$0" in *docker) case "$*" in *'--filter type=custom'*) ;; *) exit 7 ;; esac ;; esac ;; esac
    if [ -f "$HOME/attached" ] || [ -f "$HOME/removed" ]; then printf '[]\n'; else printf '[{"ID":"%s"}]\n' "$NETWORK_ID"; fi ;;
  'network rm') [ "$3" = -- ] && [ "$4" = "$NETWORK_ID" ] && [ "$#" = 4 ] || exit 4; printf removed > "$HOME/removed" ;;
  *) exit 5 ;;
esac
"##;
    for engine in ["docker", "podman"] {
        let executable = dir.path().join(engine);
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .env("PATH", dir.path())
            .env("HOME", dir.path())
            .env("NETWORK_ID", &id)
            .output()
            .unwrap()
    };
    for engine in ["docker", "podman"] {
        let preview = run(&[
            "--json",
            "containers",
            "preview-network",
            "--engine",
            engine,
            "--id",
            &id,
        ]);
        assert!(
            preview.status.success(),
            "{}",
            String::from_utf8_lossy(&preview.stdout)
        );
        let value: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
        let token = value["plan"]["preview_token"].as_str().unwrap();
        let remove = |token: &str, authorized: bool| {
            let mut args = vec![
                "--json",
                "--non-interactive",
                "--yes",
                "containers",
                "remove-network",
                "--engine",
                engine,
                "--id",
                &id,
                "--preview-token",
                token,
            ];
            if authorized {
                args.push("--authorize-network-removal");
            }
            run(&args)
        };
        assert!(!remove(token, false).status.success());
        assert!(!remove("wrong", true).status.success());
        for file in ["changed", "default", "attached"] {
            fs::write(dir.path().join(file), "fixture").unwrap();
            assert!(!remove(token, true).status.success(), "{file}");
            fs::remove_file(dir.path().join(file)).unwrap();
        }
        assert!(!dir.path().join("removed").exists());
        let output = remove(token, true);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["verification"], "verified_absent");
        fs::remove_file(dir.path().join("removed")).unwrap();
    }
    let history = run(&["--json", "report"]);
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(
        history["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["operation"] == "container_network_remove"
                && record["outcome"] == "completed")
    );
}

#[cfg(unix)]
#[test]
fn offline_container_status_does_not_run_engines() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let docker = dir.path().join("docker");
    fs::write(&docker, "#!/bin/sh\ntouch \"$HOME/executed\"\n").unwrap();
    fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--offline", "--json", "containers", "status"])
        .env("PATH", dir.path())
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report[0]["state"], "skipped");
    assert!(!dir.path().join("executed").exists());
}

#[cfg(unix)]
#[test]
fn podman_json_array_is_supported() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let podman = dir.path().join("podman");
    fs::write(
        &podman,
        "#!/bin/sh\nprintf '[\\n{\"Type\":\"Containers\",\"Total\":2}\\n]\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "containers", "status"])
        .env("PATH", dir.path())
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report[1]["state"], "available");
    assert_eq!(report[1]["usage"][0]["Total"], 2);
}

#[cfg(unix)]
#[test]
fn podman_filtered_inventory_reports_items_and_failures() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let podman = dir.path().join("podman");
    fs::write(
        &podman,
        r##"#!/bin/sh
case "$*" in
 'system df --format json') printf '[]\n' ;;
 'container ls --all --size --no-trunc --format json') printf '{"id":"pod-id","state":"exited","size":"8MB"}\n' ;;
 'network ls --filter dangling=true --no-trunc --format json') printf '[{"name":"unused"}]\n' ;;
 'image ls --all --filter dangling=true --no-trunc --format json') exit 2 ;;
 *) printf '[]\n' ;;
esac
"##,
    )
    .unwrap();
    fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "containers", "status"])
        .env("PATH", dir.path())
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let lists = report[1]["resources"].as_array().unwrap();
    assert_eq!(lists[0]["items"][0]["size"], "8MB");
    assert!(
        lists
            .iter()
            .find(|list| list["kind"] == "build cache")
            .unwrap()["error"]
            .is_string()
    );
    assert!(
        lists
            .iter()
            .find(|list| list["kind"] == "dangling images")
            .unwrap()["error"]
            .is_string()
    );
    assert_eq!(
        lists
            .iter()
            .find(|list| list["kind"] == "unattached networks")
            .unwrap()["items"][0]["name"],
        "unused"
    );
}

#[cfg(unix)]
#[test]
fn podman_unused_image_inventory_uses_documented_counts_and_fails_closed() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let podman = dir.path().join("podman");
    let unused_id = "a".repeat(64);
    let active_id = "b".repeat(64);
    let script = r##"#!/bin/sh
case "$*" in
  'system df --format json') printf '[]\n' ;;
  'image ls --all --format json'|'image ls --all --no-trunc --format json')
    printf '[{"id":"%s","names":["example:one","example:two"],"size":1048576,"Labels":"private"},{"id":"%s","names":["active:latest"],"size":2097152}]\n' "$UNUSED_ID" "$ACTIVE_ID" ;;
  'image ls --all --no-trunc --format {{.Id}} {{.Containers}}')
    if [ -f "$HOME/partial" ]; then printf '%s 0\n' "$UNUSED_ID";
    elif [ -f "$HOME/invalid" ]; then printf 'short 0\n';
    else printf '%s 0\n%s 1\n' "$UNUSED_ID" "$ACTIVE_ID"; fi ;;
  *) printf '[]\n' ;;
esac
"##;
    fs::write(&podman, script).unwrap();
    fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(["--json", "containers", "status"])
            .env("PATH", dir.path())
            .env("HOME", dir.path())
            .env("UNUSED_ID", &unused_id)
            .env("ACTIVE_ID", &active_id)
            .output()
            .unwrap()
    };
    let unused_images = |output: &std::process::Output| {
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        report[1]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|list| list["kind"] == "unused images (snapshot)")
            .unwrap()
            .clone()
    };

    let output = run();
    assert!(output.status.success());
    let list = unused_images(&output);
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert_eq!(list["items"][0]["ID"], unused_id);
    assert_eq!(list["items"][0]["Containers"], 0);
    assert_eq!(
        list["items"][0]["References"],
        serde_json::json!(["example:one", "example:two"])
    );
    assert_eq!(list["items"][0]["Size"], 1048576);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private"));

    fs::write(dir.path().join("partial"), "fixture").unwrap();
    let output = run();
    assert!(output.status.success());
    let list = unused_images(&output);
    assert!(list["items"].as_array().unwrap().is_empty());
    assert!(
        list["error"]
            .as_str()
            .unwrap()
            .contains("omit listed images")
    );

    fs::remove_file(dir.path().join("partial")).unwrap();
    fs::write(dir.path().join("invalid"), "fixture").unwrap();
    let output = run();
    assert!(output.status.success());
    let list = unused_images(&output);
    assert!(list["items"].as_array().unwrap().is_empty());
    assert!(list["error"].as_str().unwrap().contains("invalid ID"));
}

#[cfg(unix)]
#[test]
fn inventory_lists_each_resource_and_reports_partial_failures() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let docker = dir.path().join("docker");
    fs::write(&docker, r##"#!/bin/sh
case "$*" in
  'system df --format json') printf '%s\n' '{"Type":"Images","Size":"12MB"}' ;;
  'container ls --all --size --no-trunc --format json') printf '%s\n' '{"ID":"abc","State":"exited","Size":"12kB (virtual 42MB)","Command":"secret command","Labels":"secret"}' ;;
  'image ls --all --format json') printf '[{"id":"img","names":["example"],"size":123}]\n' ;;
  'volume ls --format json') exit 2 ;;
  'volume ls --filter dangling=true --format json') printf '%s\n' '{"Name":"unused-volume","Driver":"local","Mountpoint":"/fixture/private","Labels":"secret volume"}' ;;
  'network ls --format json') printf '%s\n' '{"ID":"net","Name":"bridge"}' ;;
  'image ls --all --filter dangling=true --no-trunc --format json') printf '%s\n' '{"ID":"dangling","Repository":"<none>"}' ;;
  'network ls --filter dangling=true --filter type=custom --no-trunc --format json') printf '%s\n' '{"ID":"unused","Name":"example","Labels":"secret"}' ;;
  'buildx inspect --timeout=2s') printf 'Name: fixture\nNodes:\n' ;;
  'buildx --builder fixture du --timeout=2s --format=json') printf '%s\n' '{"ID":"cache-id","Size":"123","Reclaimable":true,"Shared":true,"Mutable":false,"Description":"secret build command","Parents":["secret-parent"],"LastUsedAt":"2025-01-01T00:00:00Z"}' ;;
  *) exit 3 ;;
esac
"##).unwrap();
    fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--json", "containers", "status"])
        .env("PATH", dir.path())
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let lists = report[0]["resources"].as_array().unwrap();
    assert_eq!(lists.len(), 9);
    assert_eq!(lists[0]["items"][0]["State"], "exited");
    assert_eq!(lists[0]["items"][0]["Size"], "12kB (virtual 42MB)");
    assert!(lists[0]["items"][0].get("Command").is_none());
    assert!(lists[0]["items"][0].get("Labels").is_none());
    assert_eq!(lists[1]["items"][0]["id"], "img");
    assert_eq!(lists[1]["items"][0]["names"][0], "example");
    assert!(lists[2]["error"].is_string());
    assert_eq!(lists[3]["items"][0]["Name"], "bridge");
    assert_eq!(lists[4]["kind"], "dangling images");
    assert_eq!(lists[4]["items"][0]["ID"], "dangling");
    assert_eq!(lists[5]["kind"], "unattached custom networks (snapshot)");
    assert_eq!(lists[5]["items"][0]["ID"], "unused");
    assert!(lists[5]["items"][0].get("Labels").is_none());
    assert_eq!(lists[6]["kind"], "unattached volumes (snapshot)");
    assert_eq!(lists[6]["items"][0]["Name"], "unused-volume");
    assert_eq!(lists[6]["items"][0]["Driver"], "local");
    assert!(lists[6]["items"][0].get("Mountpoint").is_none());
    assert!(lists[6]["items"][0].get("Labels").is_none());
    assert_eq!(
        lists[7]["kind"],
        "build cache (selected Buildx builder; snapshot)"
    );
    assert_eq!(lists[7]["items"][0]["ID"], "cache-id");
    assert_eq!(lists[7]["items"][0]["Builder"], "fixture");
    assert_eq!(lists[7]["items"][0]["Reclaimable"], true);
    assert_eq!(lists[7]["items"][0]["Shared"], true);
    assert!(lists[7]["items"][0].get("Description").is_none());
    assert!(lists[7]["items"][0].get("Parents").is_none());
    assert_eq!(lists[8]["kind"], "unused images (snapshot)");
    assert!(lists[8]["error"].is_string());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret"));
}

#[cfg(unix)]
#[test]
fn docker_unused_image_inventory_matches_complete_ids_and_collapses_tags() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let docker = dir.path().join("docker");
    let unused_id = "a".repeat(64);
    let active_id = "b".repeat(64);
    let script = r##"#!/bin/sh
case "$*" in
  'system df --format json') printf '[]\n' ;;
  'system df --verbose')
    if [ -f "$HOME/ambiguous" ]; then
      printf 'Images space usage:\nREPOSITORY TAG IMAGE ID CREATED SIZE SHARED SIZE UNIQUE SIZE CONTAINERS\nexample one %s 5 minutes ago 10MB 0B 10MB 0\nother latest %s 5 minutes ago 10MB 0B 10MB 0\nactive latest %s 5 minutes ago 20MB 0B 20MB 1\nContainers space usage:\nCONTAINER ID IMAGE COMMAND LOCAL VOLUMES SIZE CREATED STATUS NAMES\nfixture example "secret command" 0 1B now Exited secret-name\n' "$SHORT_ID" "$SHORT_ID" "$ACTIVE_PREFIX"
    elif [ -f "$HOME/partial" ]; then
      printf 'Images space usage:\nREPOSITORY TAG IMAGE ID CREATED SIZE SHARED SIZE UNIQUE SIZE CONTAINERS\nexample one abc 5 minutes ago 10MB 0B 10MB 0\nContainers space usage:\nCONTAINER ID IMAGE COMMAND LOCAL VOLUMES SIZE CREATED STATUS NAMES\nfixture example "secret command" 0 1B now Exited secret-name\n'
    elif [ -f "$HOME/truncated" ]; then
      printf 'Images space usage:\nREPOSITORY TAG IMAGE ID CREATED SIZE SHARED SIZE UNIQUE SIZE CONTAINERS\nexample one %s 5 minutes ago 10MB 0B 10MB 0\nexample two %s 5 minutes ago 10MB 0B 10MB 0\nactive latest %s 5 minutes ago 20MB 0B 20MB 1\n' "$UNUSED_PREFIX" "$UNUSED_PREFIX" "$ACTIVE_PREFIX"
    else
      printf 'Images space usage:\nREPOSITORY TAG IMAGE ID CREATED SIZE SHARED SIZE UNIQUE SIZE CONTAINERS\nexample one %s 5 minutes ago 10MB 0B 10MB 0\nexample two %s 5 minutes ago 10MB 0B 10MB 0\nactive latest %s 5 minutes ago 20MB 0B 20MB 1\nContainers space usage:\nCONTAINER ID IMAGE COMMAND LOCAL VOLUMES SIZE CREATED STATUS NAMES\nfixture example "secret command" 0 1B now Exited secret-name\n' "$UNUSED_PREFIX" "$UNUSED_PREFIX" "$ACTIVE_PREFIX"
    fi ;;
  'image ls --all --no-trunc --format json')
    if [ -f "$HOME/ambiguous" ]; then
      printf '[{"ID":"%s","Repository":"example","Tag":"one","Size":"10MB","Labels":"secret"},{"ID":"%s","Repository":"example","Tag":"two","Size":"10MB"},{"ID":"%s","Repository":"other","Tag":"latest","Size":"10MB"},{"ID":"%s","Repository":"active","Tag":"latest","Size":"20MB"}]\n' "$UNUSED_ID" "$UNUSED_ID" "$AMBIGUOUS_ID" "$ACTIVE_ID"
    else
      printf '[{"ID":"%s","Repository":"example","Tag":"one","Size":"10MB","Labels":"secret"},{"ID":"%s","Repository":"example","Tag":"two","Size":"10MB"},{"ID":"%s","Repository":"active","Tag":"latest","Size":"20MB"}]\n' "$UNUSED_ID" "$UNUSED_ID" "$ACTIVE_ID"
    fi ;;
  'buildx inspect --timeout=2s') exit 2 ;;
  *) printf '[]\n' ;;
esac
"##;
    fs::write(&docker, script).unwrap();
    fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(["--json", "containers", "status"])
            .env("PATH", dir.path())
            .env("HOME", dir.path())
            .env("UNUSED_ID", &unused_id)
            .env("ACTIVE_ID", &active_id)
            .env("UNUSED_PREFIX", &unused_id[..12])
            .env("ACTIVE_PREFIX", &active_id[..12])
            .env("SHORT_ID", &unused_id[..12])
            .env(
                "AMBIGUOUS_ID",
                format!("{}{}", &unused_id[..12], "c".repeat(52)),
            )
            .output()
            .unwrap()
    };

    let output = run();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let images = report[0]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|list| list["kind"] == "unused images (snapshot)")
        .unwrap();
    let items = images["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["ID"], unused_id);
    assert_eq!(items[0]["Containers"], 0);
    assert_eq!(
        items[0]["References"],
        serde_json::json!(["example:one", "example:two"])
    );
    assert_eq!(items[0]["Size"], "10MB");
    assert!(items[0].get("Labels").is_none());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-name"));

    fs::write(dir.path().join("ambiguous"), "fixture").unwrap();
    let output = run();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let images = report[0]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|list| list["kind"] == "unused images (snapshot)")
        .unwrap();
    assert!(images["items"].as_array().unwrap().is_empty());
    assert!(images["error"].as_str().unwrap().contains("ambiguous"));

    fs::remove_file(dir.path().join("ambiguous")).unwrap();
    fs::write(dir.path().join("partial"), "fixture").unwrap();
    let output = run();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let images = report[0]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|list| list["kind"] == "unused images (snapshot)")
        .unwrap();
    assert!(images["items"].as_array().unwrap().is_empty());
    assert!(
        images["error"]
            .as_str()
            .unwrap()
            .contains("invalid image ID")
    );

    fs::remove_file(dir.path().join("partial")).unwrap();
    fs::write(dir.path().join("truncated"), "fixture").unwrap();
    let output = run();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let images = report[0]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|list| list["kind"] == "unused images (snapshot)")
        .unwrap();
    assert!(images["items"].as_array().unwrap().is_empty());
    assert!(images["error"].as_str().unwrap().contains("truncated"));
}

#[cfg(unix)]
#[test]
fn stopped_container_removal_requires_preview_and_revalidates_state() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let engine = dir.path().join("docker");
    let id = "a".repeat(64);
    let state = dir.path().join("state");
    fs::write(&state, "exited").unwrap();
    fs::write(dir.path().join("daemon"), "fixture-daemon").unwrap();
    fs::write(&engine, r##"#!/bin/sh
case "$1 $2" in
  'info --format') daemon=$(/bin/cat "$HOME/daemon"); printf '{"ID":"%s"}\n' "$daemon" ;;
  'container inspect') state=$(/bin/cat "$HOME/state"); printf '[{"Id":"%s","Name":"fixture","RestartCount":0,"SizeRw":123,"State":{"Status":"%s","Running":false,"Restarting":false,"StartedAt":"a","FinishedAt":"b"},"Secrets":"never-output"}]\n' "$4" "$state" ;;
  'container rm') [ "$3" = -- ] && [ "$4" = "$EXPECTED_ID" ] && [ "$#" = 4 ] || exit 4; printf removed > "$HOME/removed" ;;
  'container ls') [ ! -f "$HOME/verify_fail" ] || exit 6; [ -f "$HOME/removed" ] || exit 5; printf '[]\n' ;;
  *) exit 3 ;;
esac
"##).unwrap();
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o755)).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path())
            .env("XDG_DATA_HOME", dir.path())
            .env("PATH", dir.path())
            .env("EXPECTED_ID", &id)
            .output()
            .unwrap()
    };
    let preview = run(&[
        "--json",
        "containers",
        "preview-remove",
        "--engine",
        "docker",
        "--id",
        &id,
    ]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    let token = plan["plan"]["preview_token"].as_str().unwrap();
    assert_eq!(plan["plan"]["writable_bytes"], 123);
    assert!(!String::from_utf8_lossy(&preview.stdout).contains("never-output"));
    let incomplete = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "containers",
        "remove",
        "--engine",
        "docker",
        "--id",
        &id,
        "--preview-token",
        token,
    ]);
    assert!(!incomplete.status.success());
    assert!(!dir.path().join("removed").exists());
    fs::write(&state, "running").unwrap();
    let changed = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "containers",
        "remove",
        "--engine",
        "docker",
        "--id",
        &id,
        "--preview-token",
        token,
        "--authorize-container-removal",
    ]);
    assert!(!changed.status.success());
    assert!(!dir.path().join("removed").exists());
    fs::write(&state, "exited").unwrap();
    fs::write(dir.path().join("daemon"), "different-daemon").unwrap();
    let changed_daemon = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "containers",
        "remove",
        "--engine",
        "docker",
        "--id",
        &id,
        "--preview-token",
        token,
        "--authorize-container-removal",
    ]);
    assert!(!changed_daemon.status.success());
    assert!(!dir.path().join("removed").exists());
    fs::write(dir.path().join("daemon"), "fixture-daemon").unwrap();
    let dry = run(&[
        "--json",
        "--non-interactive",
        "--dry-run",
        "containers",
        "remove",
        "--engine",
        "docker",
        "--id",
        &id,
    ]);
    assert!(dry.status.success());
    assert!(!dir.path().join("removed").exists());
    let removed = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "containers",
        "remove",
        "--engine",
        "docker",
        "--id",
        &id,
        "--preview-token",
        token,
        "--authorize-container-removal",
    ]);
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stdout)
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("removed")).unwrap(),
        "removed"
    );
    fs::write(dir.path().join("verify_fail"), "fixture").unwrap();
    let unverified = run(&[
        "--json",
        "--non-interactive",
        "--yes",
        "containers",
        "remove",
        "--engine",
        "docker",
        "--id",
        &id,
        "--preview-token",
        token,
        "--authorize-container-removal",
    ]);
    assert!(!unverified.status.success());
    let result: serde_json::Value = serde_json::from_slice(&unverified.stdout).unwrap();
    assert_eq!(result["executed"], true);
    assert_eq!(result["verification"], "unverified_listing");
    let report = run(&["--json", "report"]);
    assert!(report.status.success());
    let history: serde_json::Value = serde_json::from_slice(&report.stdout).unwrap();
    let records = history["records"].as_array().unwrap();
    assert!(
        records
            .iter()
            .any(|record| record["operation"] == "container_remove"
                && record["outcome"] == "completed"
                && record["verified_reclaimed_bytes"].is_null())
    );
    assert!(
        records
            .iter()
            .any(|record| record["outcome"] == "unverified")
    );
}

#[cfg(unix)]
#[test]
fn podman_removal_preview_uses_host_and_store_identity() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("podman");
    let id = "b".repeat(64);
    fs::write(&executable, r##"#!/bin/sh
case "$1 $2" in
 'info --format') printf '%s\n' '{"host":{"hostname":"test-host"},"store":{"graphRoot":"/fixture/store"}}' ;;
 'container inspect') printf '[{"Id":"%s","Name":"pod","RestartCount":0,"State":{"Status":"exited","Running":false,"Restarting":false,"StartedAt":"a","FinishedAt":"b"}}]\n' "$4" ;;
 *) exit 7 ;;
esac
"##).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(args)
            .env("HOME", dir.path())
            .env("PATH", dir.path())
            .output()
            .unwrap()
    };
    let output = run(&[
        "--json",
        "containers",
        "preview-remove",
        "--engine",
        "podman",
        "--id",
        &id,
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["plan"]["engine_identity"],
        "Podman host test-host storage /fixture/store"
    );
    assert!(
        !run(&[
            "--json",
            "--offline",
            "containers",
            "preview-remove",
            "--engine",
            "podman",
            "--id",
            &id
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "--json",
            "containers",
            "preview-remove",
            "--engine",
            "podman",
            "--id",
            "short"
        ])
        .status
        .success()
    );
}

#[cfg(unix)]
#[test]
fn malformed_engine_inventory_rows_fail_only_their_resource_list() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("podman");
    let id = "a".repeat(64);
    fs::write(
        &executable,
        r##"#!/bin/sh
case "$*" in
  'system df --format json') printf '%s\n' '{"Type":"Images","Size":"12MB"}' ;;
  'container ls --all --size --no-trunc --format json') printf '[null]\n' ;;
  'image ls --all --format json'|'image ls --all --no-trunc --format json')
    printf '{"ID":"%s","Names":["fixture:latest"]}\n{"ID":"%s","Names":["fixture:old"]}\n' "$IMAGE_ID" "$IMAGE_ID" ;;
  'image ls --all --no-trunc --format {{.Id}} {{.Containers}}')
    printf '%s 0\n%s 0\n' "$IMAGE_ID" "$IMAGE_ID" ;;
  *) printf '[]\n' ;;
esac
"##,
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--non-interactive", "--json", "containers", "status"])
        .env("PATH", dir.path())
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path())
        .env("IMAGE_ID", id)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let podman = &report[1];
    assert_eq!(podman["state"], "available");
    assert_eq!(podman["usage"][0]["Size"], "12MB");

    let resources = podman["resources"].as_array().unwrap();
    let list = |kind: &str| {
        resources
            .iter()
            .find(|list| list["kind"] == kind)
            .unwrap_or_else(|| panic!("missing resource list: {kind}"))
    };
    let containers = list("containers");
    assert_eq!(
        containers["error"],
        "Engine returned a non-object inventory row."
    );
    assert_eq!(containers["items"], serde_json::json!([]));

    let images = list("images");
    assert!(images["error"].is_null());
    assert_eq!(images["items"].as_array().unwrap().len(), 2);
    let unused_images = list("unused images (snapshot)");
    assert!(unused_images["error"].is_null());
    assert_eq!(unused_images["items"].as_array().unwrap().len(), 1);
    assert!(list("volumes")["error"].is_null());
    assert!(list("networks")["error"].is_null());
}
