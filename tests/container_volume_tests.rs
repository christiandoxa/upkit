#[cfg(unix)]
#[test]
fn container_status_lists_unattached_volumes_without_host_metadata() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let home = dir.path().join("home");
    fs::create_dir(&bin).unwrap();
    fs::create_dir(&home).unwrap();
    let engine = r##"#!/bin/sh
case "$*" in
  'system df --format json') printf '[]\n' ;;
  'container ls --all --size --no-trunc --format json'|'image ls --all --format json'|'volume ls --format json'|'network ls --format json'|'image ls --all --filter dangling=true --no-trunc --format json'|'network ls --filter dangling=true --filter type=custom --no-trunc --format json'|'network ls --filter dangling=true --no-trunc --format json'|'image ls --all --no-trunc --format json'|'image ls --all --no-trunc --format {{.Id}} {{.Containers}}') printf '[]\n' ;;
  'volume ls --filter dangling=true --format json') printf '{"Name":"unused-fixture","Driver":"local","Scope":"local","Mountpoint":"/fixture/private","Labels":"secret=fixture"}\n' ;;
  'buildx inspect --timeout=2s') printf 'Name: fixture\nDriver: docker-container\nNodes:\n' ;;
  'buildx --builder fixture du --timeout=2s --format=json') printf '[]\n' ;;
  'system df --verbose') printf 'Images space usage:\nREPOSITORY TAG IMAGE ID CREATED SIZE SHARED SIZE UNIQUE SIZE CONTAINERS\nContainers space usage:\n' ;;
  *) printf '%s\n' "$*" >> "$HOME/unexpected-command"; exit 2 ;;
esac
"##;

    for name in ["docker", "podman"] {
        let path = bin.join(name);
        fs::write(&path, engine).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

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
    for engine in report.as_array().unwrap() {
        let list = engine["resources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|list| list["kind"] == "unattached volumes (snapshot)")
            .unwrap();
        assert!(list["error"].is_null());
        assert_eq!(list["items"][0]["Name"], "unused-fixture");
        assert_eq!(list["items"][0]["Driver"], "local");
        assert!(list["items"][0].get("Mountpoint").is_none());
        assert!(list["items"][0].get("Labels").is_none());
    }
    assert!(!dir.path().join("home/unexpected-command").exists());
}
