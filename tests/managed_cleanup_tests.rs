#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};
use upkit::{
    Ctx, ToolKind, managed_cleanup,
    test_support::{TestPrompt, base_ctx},
};

fn fixture() -> (tempfile::TempDir, Ctx, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("managed");
    let bindir = dir.path().join("bin");
    let root = home.join("go");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&bindir, fs::Permissions::from_mode(0o755)).unwrap();
    let stage = tempfile::Builder::new()
        .prefix("install-")
        .tempdir_in(&root)
        .unwrap();
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o700)).unwrap();
    use std::os::unix::fs::MetadataExt;
    let stage_meta = fs::symlink_metadata(stage.path()).unwrap();
    assert_eq!(stage_meta.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(stage_meta.mode() & 0o077, 0);
    fs::create_dir_all(stage.path().join("go/bin")).unwrap();
    fs::set_permissions(stage.path().join("go"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(
        stage.path().join("go/bin"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::write(stage.path().join("go/bin/go"), "fixture binary").unwrap();
    fs::write(stage.path().join("go/keep"), "fixture data").unwrap();
    fs::set_permissions(
        stage.path().join("go/bin/go"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    fs::set_permissions(
        stage.path().join("go/keep"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    fs::copy("/bin/sleep", stage.path().join("go/bin/sleep")).unwrap();
    fs::set_permissions(
        stage.path().join("go/bin/sleep"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    upkit::installation_identity::seal(&root, &stage, ToolKind::Go, "fixture").unwrap();
    let install = stage.keep();
    symlink(install.join("go"), root.join("active")).unwrap();
    upkit::installation_identity::record_active_link(&root, &bindir, ToolKind::Go).unwrap();
    let link = bindir.join("go");
    let target = root.join("active/bin/go");
    symlink(&target, &link).unwrap();
    upkit::installation_identity::record_created_links(
        &root,
        &bindir,
        ToolKind::Go,
        &[(link, target)],
    )
    .unwrap();
    let ctx = base_ctx(home, bindir, Arc::new(TestPrompt::default()));
    (dir, ctx, root)
}

fn install_path(root: &std::path::Path) -> PathBuf {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("install-"))
        })
        .unwrap()
}

#[test]
#[ignore = "fixture worker invoked by the isolated managed-clean PTY test"]
fn tui_pty_managed_install_fixture_worker() {
    use std::{fs::OpenOptions, io::Write, os::unix::fs::MetadataExt};

    let fixture_root = PathBuf::from(
        std::env::var_os("UPKIT_PTY_FIXTURE_ROOT").expect("fixture root is required"),
    );
    let bindir = PathBuf::from(
        std::env::var_os("UPKIT_PTY_FIXTURE_BINDIR").expect("fixture bin directory is required"),
    );
    let tools = std::env::var("UPKIT_PTY_FIXTURE_TOOLS")
        .expect("fixture tools are required")
        .split(',')
        .map(|tool| match tool {
            "go" => ToolKind::Go,
            "node" => ToolKind::Node,
            _ => panic!("fixture tool must be go or node"),
        })
        .collect::<Vec<_>>();
    assert!(!tools.is_empty());
    assert!(
        tools
            .iter()
            .enumerate()
            .all(|(index, tool)| !tools[..index].contains(tool))
    );
    assert!(fixture_root.is_absolute());
    assert_eq!(fixture_root.canonicalize().unwrap(), fixture_root);
    let root_meta = fs::symlink_metadata(&fixture_root).unwrap();
    assert!(root_meta.is_dir() && !root_meta.file_type().is_symlink());
    assert_eq!(root_meta.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(root_meta.mode() & 0o077, 0);
    assert_eq!(bindir, fixture_root.join("bin"));
    assert!(bindir.is_absolute());
    assert!(!fixture_root.join("managed").exists());

    let marker = fixture_root.join(".upkit-managed-fixture");
    let mut marker_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
        .expect("refuse to reuse a fixture directory");
    marker_file
        .write_all(b"upkit managed cleanup PTY fixture\n")
        .unwrap();

    let home = fixture_root.join("managed");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&bindir).unwrap();
    fs::set_permissions(&bindir, fs::Permissions::from_mode(0o755)).unwrap();

    for tool in tools {
        let root = home.join(tool.as_str());
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();

        let stage = tempfile::Builder::new()
            .prefix("install-")
            .tempdir_in(&root)
            .unwrap();
        fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let tool_dir = stage.path().join(tool.as_str());
        let bin = tool_dir.join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::set_permissions(&tool_dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let executable = bin.join(tool.as_str());
        fs::write(&executable, b"sealed fixture executable").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o644)).unwrap();
        upkit::installation_identity::seal(&root, &stage, tool, "fixture").unwrap();

        let install = stage.keep();
        symlink(install.join(tool.as_str()), root.join("active")).unwrap();
        upkit::installation_identity::record_active_link(&root, &bindir, tool).unwrap();
        let link = bindir.join(tool.as_str());
        let target = root.join("active/bin").join(tool.as_str());
        symlink(&target, &link).unwrap();
        upkit::installation_identity::record_created_links(&root, &bindir, tool, &[(link, target)])
            .unwrap();
    }
}

#[test]
fn cli_json_keeps_unicode_managed_cleanup_paths_as_strings() {
    use std::process::Command;
    let (dir, ctx, _) = fixture();
    let shell_home = dir.path().join("shell-home");
    fs::create_dir(&shell_home).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .env("HOME", &shell_home)
        .env("XDG_CONFIG_HOME", shell_home.join("config"))
        .env("XDG_DATA_HOME", shell_home.join("data"))
        .args(["--non-interactive", "--json", "--home"])
        .arg(&ctx.home)
        .arg("--bindir")
        .arg(&ctx.bindir)
        .args(["managed-clean", "go"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let plan = &value["plan"];
    assert!(plan["root"].is_string());
    assert!(plan["entries"].as_array().unwrap()[0].is_string());
    assert!(plan["links"].as_array().unwrap()[0].is_string());
    assert_eq!(plan["preview_token"].as_str().unwrap().len(), 64);
}

#[test]
fn cli_json_encodes_non_unicode_managed_cleanup_paths_and_token_inputs() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let home = dir
        .path()
        .join(OsString::from_vec(b"managed-\xff%".to_vec()));
    let bindir = dir.path().join(OsString::from_vec(b"bin-\xfe%".to_vec()));
    let shell_home = dir.path().join("shell-home");
    let root = home.join("go");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    fs::create_dir(&shell_home).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&bindir, fs::Permissions::from_mode(0o755)).unwrap();
    let stage = tempfile::Builder::new()
        .prefix("install-")
        .tempdir_in(&root)
        .unwrap();
    fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let entry_name = OsString::from_vec(b"payload-\xfd%".to_vec());
    let entry = stage.path().join(&entry_name);
    fs::write(&entry, "fixture").unwrap();
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o644)).unwrap();
    upkit::installation_identity::seal(&root, &stage, ToolKind::Go, "fixture").unwrap();
    let install = stage.keep();
    symlink(&install, root.join("active")).unwrap();
    upkit::installation_identity::record_active_link(&root, &bindir, ToolKind::Go).unwrap();
    let link = bindir.join("go");
    let target = root.join("active").join(&entry_name);
    symlink(&target, &link).unwrap();
    upkit::installation_identity::record_created_links(
        &root,
        &bindir,
        ToolKind::Go,
        &[(link, target)],
    )
    .unwrap();
    let ctx = base_ctx(
        home.clone(),
        bindir.clone(),
        Arc::new(TestPrompt::default()),
    );
    let plan = managed_cleanup::preview(&ctx, ToolKind::Go, &AtomicBool::new(false)).unwrap();
    serde_json::to_value(plan).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .env("HOME", &shell_home)
        .env("XDG_CONFIG_HOME", shell_home.join("config"))
        .env("XDG_DATA_HOME", shell_home.join("data"))
        .args(["--non-interactive", "--json", "--home"])
        .arg(&home)
        .arg("--bindir")
        .arg(&bindir)
        .args(["managed-clean", "go"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let plan = &value["plan"];
    assert_eq!(plan["root"]["encoding"], "unix-percent-bytes");
    assert_eq!(plan["root"]["value"], upkit::sweep::display_path(&root));
    assert_eq!(
        plan["selected_entries"][0]["encoding"],
        "unix-percent-bytes"
    );
    assert_eq!(
        plan["selected_entries"][0]["value"],
        upkit::sweep::display_path(&install)
    );
    assert_eq!(plan["links"][0]["encoding"], "unix-percent-bytes");
    assert_eq!(
        plan["links"][0]["value"],
        upkit::sweep::display_path(&bindir.join("go"))
    );
    assert_eq!(plan["preview_token"].as_str().unwrap().len(), 64);
}

#[test]
fn preview_is_read_only_and_rejects_a_changed_nested_file() {
    let (_dir, ctx, root) = fixture();
    let cancel = AtomicBool::new(false);
    let plan = managed_cleanup::preview(&ctx, ToolKind::Go, &cancel).unwrap();
    assert_eq!(plan.root, root);
    assert_eq!(plan.installation_status, "sealed_installations_verified");
    assert_eq!(plan.links, vec![ctx.bindir.join("go"), root.join("active")]);
    assert!(plan.entries.contains(&root.join("active")));
    fs::write(
        plan.selected_entries[0].join("go/keep"),
        "changed after preview",
    )
    .unwrap();
    assert!(managed_cleanup::remove(&ctx, &plan, &cancel).is_err());
    assert_eq!(
        fs::read_to_string(plan.selected_entries[0].join("go/keep")).unwrap(),
        "changed after preview"
    );
    assert!(fs::symlink_metadata(ctx.bindir.join("go")).is_ok());
}

#[test]
fn content_mismatch_is_preserved_as_unverified_data() {
    let (_dir, ctx, root) = fixture();
    let install = install_path(&root);
    fs::write(install.join("go/keep"), "changed before preview").unwrap();

    let plan = managed_cleanup::preview(&ctx, ToolKind::Go, &AtomicBool::new(false)).unwrap();
    assert_eq!(plan.installation_status, "unverified_data_preserved");
    assert!(plan.selected_entries.is_empty());
    assert!(plan.preserved_entries.contains(&install));
    assert!(plan.links.is_empty());
    assert!(plan.preserved_links.contains(&ctx.bindir.join("go")));
    assert!(managed_cleanup::remove(&ctx, &plan, &AtomicBool::new(false)).is_err());
    assert_eq!(
        fs::read_to_string(install.join("go/keep")).unwrap(),
        "changed before preview"
    );
}

#[test]
fn unrecorded_binary_link_into_a_sealed_install_blocks_preview() {
    let (_dir, ctx, root) = fixture();
    let install = install_path(&root);
    let link = ctx.bindir.join("go");
    fs::remove_file(&link).unwrap();
    symlink(install.join("go/bin/go"), &link).unwrap();

    let result = managed_cleanup::preview(&ctx, ToolKind::Go, &AtomicBool::new(false));
    assert!(result.unwrap_err().to_string().contains("unrecorded link"));
    assert!(install.join("go/bin/go").exists());
    assert!(fs::read_link(link).unwrap().starts_with(&install));
}

#[test]
fn missing_receipts_and_changed_bindir_block_sealed_install_cleanup() {
    let (_dir, mut ctx, root) = fixture();
    let install = install_path(&root);
    let old_bindir_link = ctx.bindir.join("go");
    let new_bindir = root.parent().unwrap().join("new-bin");
    fs::create_dir(&new_bindir).unwrap();
    fs::remove_file(root.join("active")).unwrap();
    fs::remove_dir_all(root.join(".upkit-managed-links")).unwrap();
    ctx.bindir = new_bindir;

    assert!(managed_cleanup::preview(&ctx, ToolKind::Go, &AtomicBool::new(false)).is_err());
    assert!(install.exists());
    assert!(fs::symlink_metadata(old_bindir_link).is_ok());
}

#[test]
fn removal_rejects_changed_links_and_dry_run() {
    let (dir, mut ctx, root) = fixture();
    let cancel = AtomicBool::new(false);
    let plan = managed_cleanup::preview(&ctx, ToolKind::Go, &cancel).unwrap();
    ctx.dry_run = true;
    assert!(managed_cleanup::remove(&ctx, &plan, &cancel).is_err());
    ctx.dry_run = false;
    let outside = dir.path().join("outside");
    fs::write(&outside, "keep").unwrap();
    fs::remove_file(ctx.bindir.join("go")).unwrap();
    symlink(&outside, ctx.bindir.join("go")).unwrap();
    assert!(managed_cleanup::remove(&ctx, &plan, &cancel).is_err());
    assert!(root.exists());
    assert_eq!(fs::read_to_string(outside).unwrap(), "keep");
}

#[test]
fn removal_deletes_only_the_selected_root_and_matching_links() {
    let (dir, ctx, root) = fixture();
    let outside = dir.path().join("outside");
    fs::write(&outside, "keep").unwrap();
    symlink(&outside, root.join("external-link")).unwrap();
    symlink(&outside, ctx.bindir.join("gofmt")).unwrap();
    fs::write(root.join("user-data"), "keep me").unwrap();
    let cancel = AtomicBool::new(false);
    let plan = managed_cleanup::preview(&ctx, ToolKind::Go, &cancel).unwrap();
    assert!(plan.preserved_entries.contains(&root.join("user-data")));
    assert!(plan.preserved_entries.contains(&root.join("external-link")));
    assert!(plan.preserved_links.contains(&ctx.bindir.join("gofmt")));
    assert_eq!(
        managed_cleanup::remove(&ctx, &plan, &cancel).unwrap(),
        "verified_selected_absent"
    );
    assert!(root.exists());
    assert_eq!(
        fs::read_to_string(root.join("user-data")).unwrap(),
        "keep me"
    );
    assert!(root.join("external-link").exists());
    assert!(root.join(".upkit-managed-links").exists());
    assert!(fs::symlink_metadata(ctx.bindir.join("go")).is_err());
    assert_eq!(fs::read_to_string(&outside).unwrap(), "keep");
    assert!(fs::symlink_metadata(ctx.bindir.join("gofmt")).is_ok());
}

#[test]
fn cleanup_removes_recorded_go_wrapper_links_but_preserves_wrapper_files() {
    let (_dir, ctx, root) = fixture();
    let install = install_path(&root);
    fs::remove_file(ctx.bindir.join("go")).unwrap();
    upkit::tools::go::ensure_go_wrappers(&ctx, &root, &root.join("active")).unwrap();
    let cancel = AtomicBool::new(false);
    let plan = managed_cleanup::preview(&ctx, ToolKind::Go, &cancel).unwrap();
    for name in ["go", "gofmt"] {
        assert!(plan.links.contains(&ctx.bindir.join(name)));
    }
    assert!(plan.preserved_entries.contains(&root.join("wrappers")));
    assert_eq!(
        managed_cleanup::remove(&ctx, &plan, &cancel).unwrap(),
        "verified_selected_absent"
    );
    assert!(!install.exists());
    for name in ["go", "gofmt"] {
        assert!(fs::symlink_metadata(ctx.bindir.join(name)).is_err());
        assert!(root.join("wrappers").join(name).is_file());
    }
}

#[test]
fn unrecorded_go_wrapper_link_blocks_removal_of_active_installation() {
    let (_dir, ctx, root) = fixture();
    let install = install_path(&root);
    let link = ctx.bindir.join("go");
    fs::remove_file(&link).unwrap();
    upkit::tools::go::ensure_go_wrappers(&ctx, &root, &root.join("active")).unwrap();
    fs::remove_file(&link).unwrap();
    symlink(root.join("wrappers/go"), &link).unwrap();

    let error = managed_cleanup::preview(&ctx, ToolKind::Go, &AtomicBool::new(false)).unwrap_err();
    assert!(error.to_string().contains("unrecorded link"));
    assert!(install.join("go/bin/go").exists());
    assert_eq!(fs::read_link(link).unwrap(), root.join("wrappers/go"));
}

#[test]
fn cross_named_unrecorded_go_wrapper_blocks_removal() {
    let (_dir, ctx, root) = fixture();
    let install = install_path(&root);
    let link = ctx.bindir.join("go");
    fs::remove_file(&link).unwrap();
    upkit::tools::go::ensure_go_wrappers(&ctx, &root, &root.join("active")).unwrap();
    fs::remove_file(&link).unwrap();
    symlink(root.join("wrappers/gofmt"), &link).unwrap();

    let error = managed_cleanup::preview(&ctx, ToolKind::Go, &AtomicBool::new(false)).unwrap_err();
    assert!(error.to_string().contains("unrecorded link"));
    assert!(install.join("go/bin/go").exists());
    assert_eq!(fs::read_link(link).unwrap(), root.join("wrappers/gofmt"));
}

#[test]
fn recorded_dangling_go_wrapper_link_can_be_removed() {
    let (_dir, ctx, root) = fixture();
    let install = install_path(&root);
    fs::remove_file(ctx.bindir.join("go")).unwrap();
    upkit::tools::go::ensure_go_wrappers(&ctx, &root, &root.join("active")).unwrap();
    fs::remove_file(root.join("wrappers/go")).unwrap();
    let cancel = AtomicBool::new(false);
    let plan = managed_cleanup::preview(&ctx, ToolKind::Go, &cancel).unwrap();
    assert!(plan.links.contains(&ctx.bindir.join("go")));
    assert_eq!(
        managed_cleanup::remove(&ctx, &plan, &cancel).unwrap(),
        "verified_selected_absent"
    );
    assert!(!install.exists());
    assert!(fs::symlink_metadata(ctx.bindir.join("go")).is_err());
}

#[test]
fn preview_rejects_linked_roots_special_files_and_cancelled_work() {
    use std::os::unix::net::UnixListener;
    let (_dir, ctx, root) = fixture();
    let listener = UnixListener::bind(root.join("socket")).unwrap();
    let plan = managed_cleanup::preview(&ctx, ToolKind::Go, &AtomicBool::new(false)).unwrap();
    assert!(plan.preserved_entries.contains(&root.join("socket")));
    drop(listener);
    fs::remove_file(root.join("socket")).unwrap();
    assert!(managed_cleanup::preview(&ctx, ToolKind::Go, &AtomicBool::new(true)).is_err());
    fs::rename(&root, ctx.home.join("old-go")).unwrap();
    symlink(ctx.home.join("old-go"), &root).unwrap();
    assert!(managed_cleanup::preview(&ctx, ToolKind::Go, &AtomicBool::new(false)).is_err());
}

#[test]
fn cli_refuses_to_clean_directly_under_user_home() {
    use std::process::Command;
    let (_dir, ctx, root) = fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .env("HOME", &ctx.home)
        .env("XDG_CONFIG_HOME", ctx.home.join("config"))
        .args(["--non-interactive", "--json", "--home"])
        .arg(&ctx.home)
        .arg("--bindir")
        .arg(&ctx.bindir)
        .args(["clean", "go", "--preview"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["error"].as_str().unwrap().contains("user home"));
    assert!(install_path(&root).join("go/keep").exists());
    assert!(fs::symlink_metadata(ctx.bindir.join("go")).is_ok());
}

#[test]
fn a_running_tool_executable_blocks_removal() {
    use std::process::{Command, Stdio};
    let (_dir, ctx, root) = fixture();
    let executable = install_path(&root).join("go/bin/sleep");
    let mut child = Command::new(&executable)
        .arg("60")
        .current_dir(&ctx.home)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let cancel = AtomicBool::new(false);
    let plan = managed_cleanup::preview(&ctx, ToolKind::Go, &cancel).unwrap();
    let result = managed_cleanup::remove(&ctx, &plan, &cancel);
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(plan.activity_status, "executable_observed");
    assert!(result.is_err());
    assert!(root.exists());
}

#[test]
fn clean_and_uninstall_require_a_reviewed_batch_and_stop_on_stale_scope() {
    use std::process::Command;
    for verb in ["clean", "uninstall"] {
        let (dir, ctx, root) = fixture();
        let go_install = install_path(&root);
        let node = ctx.home.join("node");
        fs::create_dir(&node).unwrap();
        fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
        let node_stage = tempfile::Builder::new()
            .prefix("install-")
            .tempdir_in(&node)
            .unwrap();
        fs::set_permissions(node_stage.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(node_stage.path().join("node/bin")).unwrap();
        fs::set_permissions(
            node_stage.path().join("node"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::set_permissions(
            node_stage.path().join("node/bin"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(node_stage.path().join("node/bin/node"), "node fixture").unwrap();
        fs::write(node_stage.path().join("node/fixture"), "node data").unwrap();
        fs::set_permissions(
            node_stage.path().join("node/bin/node"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        fs::set_permissions(
            node_stage.path().join("node/fixture"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        upkit::installation_identity::seal(&node, &node_stage, ToolKind::Node, "fixture").unwrap();
        let node_install = node_stage.keep();
        symlink(node_install.join("node"), node.join("active")).unwrap();
        upkit::installation_identity::record_active_link(&node, &ctx.bindir, ToolKind::Node)
            .unwrap();
        let node_link = ctx.bindir.join("node");
        let node_target = node.join("active/bin/node");
        symlink(&node_target, &node_link).unwrap();
        upkit::installation_identity::record_created_links(
            &node,
            &ctx.bindir,
            ToolKind::Node,
            &[(node_link.clone(), node_target.clone())],
        )
        .unwrap();
        let shell_home = dir.path().join("shell-home");
        fs::create_dir(&shell_home).unwrap();
        fs::write(shell_home.join(".bashrc"), "unchanged\n").unwrap();
        let run = |args: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_upkit"))
                .env("HOME", &shell_home)
                .env("XDG_CONFIG_HOME", shell_home.join("config"))
                .args(["--non-interactive", "--json", "--home"])
                .arg(&ctx.home)
                .arg("--bindir")
                .arg(&ctx.bindir)
                .args(args)
                .output()
                .unwrap()
        };
        let preview = || {
            let output = run(&[verb, "go", "node", "--preview"]);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["plans"].as_array().unwrap().len(), 2);
            value["preview_token"].as_str().unwrap().to_owned()
        };
        let token = preview();
        assert!(!run(&["--yes", verb, "go", "node"]).status.success());
        let other_verb = if verb == "clean" {
            "uninstall"
        } else {
            "clean"
        };
        assert!(
            !run(&[
                "--yes",
                other_verb,
                "go",
                "node",
                "--authorize-managed-cleanup",
                "--preview-token",
                &token
            ])
            .status
            .success()
        );
        assert!(
            !run(&["--yes", verb, "go", "node", "--preview-token", &token])
                .status
                .success()
        );
        assert!(
            !run(&[
                "--yes",
                verb,
                "go",
                "node",
                "--authorize-managed-cleanup",
                "--preview-token",
                "invalid"
            ])
            .status
            .success()
        );
        fs::write(node.join("user-data"), "changed").unwrap();
        assert!(
            !run(&[
                "--yes",
                verb,
                "go",
                "node",
                "--authorize-managed-cleanup",
                "--preview-token",
                &token
            ])
            .status
            .success()
        );
        assert!(root.exists() && node.exists());
        let token = preview();
        fs::remove_file(&node_link).unwrap();
        symlink(&node_target, &node_link).unwrap();
        assert!(
            !run(&[
                "--yes",
                verb,
                "go",
                "node",
                "--authorize-managed-cleanup",
                "--preview-token",
                &token
            ])
            .status
            .success()
        );
        assert!(root.exists() && node.exists());
        fs::remove_file(&node_link).unwrap();
        symlink(&node_target, &node_link).unwrap();
        upkit::installation_identity::record_created_links(
            &node,
            &ctx.bindir,
            ToolKind::Node,
            &[(node_link.clone(), node_target.clone())],
        )
        .unwrap();
        let token = preview();
        let output = run(&[
            "--yes",
            verb,
            "go",
            "node",
            "--authorize-managed-cleanup",
            "--preview-token",
            &token,
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            result["results"][0]["verification"],
            "verified_selected_absent"
        );
        assert_eq!(
            result["results"][1]["verification"],
            "verified_selected_absent"
        );
        assert!(root.exists() && node.exists());
        assert!(!go_install.exists() && !node_install.exists());
        assert_eq!(
            fs::read_to_string(shell_home.join(".bashrc")).unwrap(),
            "unchanged\n"
        );
        assert_eq!(upkit::reports::read(&ctx.home).unwrap().records.len(), 2);
    }
}

#[test]
fn clean_all_reviews_every_tool_and_stops_after_a_blocked_tool() {
    use std::process::{Child, Command, Stdio};
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let (dir, ctx, root) = fixture();
    let node = ctx.home.join("node");
    fs::create_dir(&node).unwrap();
    fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
    let node_stage = tempfile::Builder::new()
        .prefix("install-")
        .tempdir_in(&node)
        .unwrap();
    fs::set_permissions(node_stage.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(node_stage.path().join("node/bin")).unwrap();
    fs::set_permissions(
        node_stage.path().join("node"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(
        node_stage.path().join("node/bin"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let executable = node_stage.path().join("node/bin/sleep");
    fs::copy("/bin/sleep", &executable).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    upkit::installation_identity::seal(&node, &node_stage, ToolKind::Node, "fixture").unwrap();
    let node_install = node_stage.keep();
    symlink(node_install.join("node"), node.join("active")).unwrap();
    upkit::installation_identity::record_active_link(&node, &ctx.bindir, ToolKind::Node).unwrap();
    let executable = node_install.join("node/bin/sleep");
    let child = ChildGuard(
        Command::new(&executable)
            .arg("60")
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .args(["--non-interactive", "--json", "--home"])
            .arg(&ctx.home)
            .arg("--bindir")
            .arg(&ctx.bindir)
            .args(args)
            .output()
            .unwrap()
    };
    let output = run(&["clean", "--all", "--preview"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let preview: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        preview["plans"].as_array().unwrap().len(),
        ToolKind::all().len()
    );
    let token = preview["preview_token"].as_str().unwrap();
    let output = run(&[
        "--yes",
        "clean",
        "--all",
        "--authorize-managed-cleanup",
        "--preview-token",
        token,
    ]);
    drop(child);
    assert!(!output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let results = result["results"].as_array().unwrap();
    assert_eq!(results[0]["verification"], "verified_selected_absent");
    assert_eq!(results[1]["verification"], "no_verified_targets");
    assert_eq!(results[2]["tool"], "node");
    assert_eq!(results[2]["ok"], false);
    assert_eq!(results[3]["executed"], false);
    assert!(root.exists());
    assert!(node.exists());
}

#[test]
fn cli_requires_a_current_preview_and_explicit_authorization() {
    use std::process::{Command, Output};
    let (dir, ctx, root) = fixture();
    let shell_home = dir.path().join("shell-home");
    fs::create_dir(&shell_home).unwrap();
    fs::write(shell_home.join(".bashrc"), "untouched\n").unwrap();
    let run = |args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_upkit"))
            .env("HOME", &shell_home)
            .env("XDG_CONFIG_HOME", shell_home.join("config"))
            .env("XDG_DATA_HOME", shell_home.join("data"))
            .args(["--non-interactive", "--json", "--home"])
            .arg(&ctx.home)
            .arg("--bindir")
            .arg(&ctx.bindir)
            .args(args)
            .output()
            .unwrap()
    };
    let preview = || {
        let output = run(&["managed-clean", "go"]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["plan"]["preview_token"]
            .as_str().unwrap().to_owned()
    };
    let token = preview();
    assert!(
        !run(&[
            "--yes",
            "managed-clean",
            "go",
            "--run",
            "--preview-token",
            &token
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "--yes",
            "managed-clean",
            "go",
            "--run",
            "--authorize-managed-cleanup",
            "--preview-token",
            "incorrect"
        ])
        .status
        .success()
    );
    let dry = run(&["--dry-run", "managed-clean", "go", "--run"]);
    assert!(dry.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&dry.stdout).unwrap()["dry_run"],
        true
    );
    assert!(root.exists());
    fs::write(root.join("user-data"), "changed").unwrap();
    assert!(
        !run(&[
            "--yes",
            "managed-clean",
            "go",
            "--run",
            "--authorize-managed-cleanup",
            "--preview-token",
            &token
        ])
        .status
        .success()
    );
    let token = preview();
    fs::remove_file(ctx.bindir.join("go")).unwrap();
    symlink(install_path(&root).join("go/bin/go"), ctx.bindir.join("go")).unwrap();
    assert!(
        !run(&[
            "--yes",
            "managed-clean",
            "go",
            "--run",
            "--authorize-managed-cleanup",
            "--preview-token",
            &token
        ])
        .status
        .success()
    );
    let link = ctx.bindir.join("go");
    let target = install_path(&root).join("go/bin/go");
    upkit::installation_identity::record_created_links(
        &root,
        &ctx.bindir,
        ToolKind::Go,
        &[(link, target)],
    )
    .unwrap();
    let token = preview();
    let output = run(&[
        "--yes",
        "managed-clean",
        "go",
        "--run",
        "--authorize-managed-cleanup",
        "--preview-token",
        &token,
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["verification"],
        "verified_selected_absent"
    );
    assert!(root.exists());
    assert_eq!(
        fs::read_to_string(shell_home.join(".bashrc")).unwrap(),
        "untouched\n"
    );
    assert!(
        upkit::reports::read(&ctx.home)
            .unwrap()
            .records
            .iter()
            .any(|r| r.operation == "managed_tool_cleanup")
    );
}
