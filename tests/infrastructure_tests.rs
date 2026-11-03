use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tempfile::tempdir;
use upkit::Prompt;
use upkit::ToolKind;
#[cfg(coverage)]
use upkit::infrastructure::http_get_text;
use upkit::infrastructure::{
    DialoguerPrompt, MockAttempt, code_to_index, download_to_temp, finish_spinner, index_to_code,
    maybe_path_hint_for_dir, mock_http_attempt, prune_tool_versions, remove_path_hint_for_label,
    start_spinner, tool_path_hint_labels,
};
#[cfg(target_os = "linux")]
use upkit::test_support::set_write_error;
use upkit::test_support::{
    MockResponse, TestPrompt, base_ctx, reset_guard, set_env_var, set_home_dir, set_http_plan,
    set_prompt_confirm, set_prompt_input,
};

#[cfg(target_os = "linux")]
fn set_private_path_directory(path: &std::path::Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn index_code_roundtrip() {
    let _guard = reset_guard();
    assert_eq!(index_to_code(0), "a");
    assert_eq!(index_to_code(25), "z");
    assert_eq!(index_to_code(26), "aa");
    assert_eq!(index_to_code(27), "ab");
    assert_eq!(code_to_index("a").unwrap(), 0);
    assert_eq!(code_to_index("z").unwrap(), 25);
    assert_eq!(code_to_index("aa").unwrap(), 26);
    assert_eq!(code_to_index("ab").unwrap(), 27);
}

#[test]
fn code_to_index_errors() {
    let _guard = reset_guard();
    assert!(code_to_index("").is_err());
    assert!(code_to_index("A").is_err());
    assert!(code_to_index("a1").is_err());
}

#[test]
fn dialoguer_confirm_override() {
    let _guard = reset_guard();
    set_prompt_confirm(true);
    let prompt = DialoguerPrompt;
    let ok = prompt.confirm("Proceed?", false).unwrap();
    assert!(ok);
}

#[test]
fn dialoguer_confirm_default_in_coverage() {
    let _guard = reset_guard();
    let prompt = DialoguerPrompt;
    #[cfg(coverage)]
    {
        let ok = prompt.confirm("Proceed?", true).unwrap();
        assert!(ok);
    }
    #[cfg(not(coverage))]
    {
        set_prompt_confirm(true);
        let ok = prompt.confirm("Proceed?", false).unwrap();
        assert!(ok);
    }
}

#[test]
fn dialoguer_multi_select_parses_input() {
    let _guard = reset_guard();
    set_prompt_input("a,c");
    let prompt = DialoguerPrompt;
    let items = vec!["one".to_string(), "two".to_string(), "three".to_string()];
    let chosen = prompt.multi_select("Pick items", &items).unwrap();
    assert_eq!(chosen, vec![0, 2]);
}

#[test]
fn dialoguer_multi_select_empty_items() {
    let _guard = reset_guard();
    let prompt = DialoguerPrompt;
    let chosen = prompt.multi_select("Pick items", &[]).unwrap();
    assert!(chosen.is_empty());
}

#[test]
fn dialoguer_multi_select_empty_input() {
    let _guard = reset_guard();
    set_prompt_input("   ");
    let prompt = DialoguerPrompt;
    let items = vec!["one".to_string()];
    let chosen = prompt.multi_select("Pick items", &items).unwrap();
    assert!(chosen.is_empty());
}

#[test]
fn dialoguer_multi_select_empty_token() {
    let _guard = reset_guard();
    set_prompt_input("a,,b");
    let prompt = DialoguerPrompt;
    let items = vec!["one".to_string(), "two".to_string()];
    let chosen = prompt.multi_select("Pick items", &items).unwrap();
    assert_eq!(chosen, vec![0, 1]);
}

#[test]
fn dialoguer_multi_select_invalid_token() {
    let _guard = reset_guard();
    set_prompt_input("a,1");
    let prompt = DialoguerPrompt;
    let items = vec!["one".to_string(), "two".to_string()];
    let err = prompt.multi_select("Pick items", &items).unwrap_err();
    assert!(err.to_string().contains("invalid selection"));
}

#[test]
fn dialoguer_multi_select_coverage_default() {
    let _guard = reset_guard();
    let prompt = DialoguerPrompt;
    let items = vec!["one".to_string(), "two".to_string()];
    #[cfg(coverage)]
    {
        let chosen = prompt.multi_select("Pick items", &items).unwrap();
        assert!(chosen.is_empty());
    }
    #[cfg(not(coverage))]
    {
        set_prompt_input("a");
        let chosen = prompt.multi_select("Pick items", &items).unwrap();
        assert_eq!(chosen, vec![0]);
    }
}

#[test]
fn dialoguer_multi_select_out_of_range() {
    let _guard = reset_guard();
    set_prompt_input("c");
    let prompt = DialoguerPrompt;
    let items = vec!["one".to_string(), "two".to_string()];
    let err = prompt.multi_select("Pick items", &items).unwrap_err();
    assert!(err.to_string().contains("selection out of range"));
}

#[test]
fn prune_tool_versions_preserves_unverified_old_dirs() {
    let dir = tempdir().unwrap();
    let tool_root = dir.path().join("tool");
    let keep_dir = tool_root.join("1.2.3");
    let old_dir = tool_root.join("0.9.0");
    let wrappers = tool_root.join("wrappers");
    let cache_file = tool_root.join("cache.txt");

    fs::create_dir_all(&keep_dir).unwrap();
    fs::create_dir_all(&old_dir).unwrap();
    fs::write(old_dir.join("source.txt"), "keep").unwrap();
    fs::create_dir_all(&wrappers).unwrap();
    fs::write(&cache_file, b"cache").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let active = tool_root.join("active");
        symlink(&keep_dir, &active).unwrap();
    }

    assert!(prune_tool_versions(&tool_root, &keep_dir, &["active", "wrappers"]).is_err());

    assert!(keep_dir.exists());
    assert!(old_dir.exists());
    assert_eq!(
        fs::read_to_string(old_dir.join("source.txt")).unwrap(),
        "keep"
    );
    assert!(wrappers.exists());
    assert!(cache_file.exists());
}

#[cfg(unix)]
#[test]
fn pruning_review_does_not_mistake_link_receipts_for_an_old_version() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let keep = dir.path().join("installed");
    let receipts = dir.path().join(".upkit-managed-links");
    fs::create_dir(&keep).unwrap();
    fs::create_dir(&receipts).unwrap();
    fs::write(receipts.join("fixture"), b"keep").unwrap();
    prune_tool_versions(dir.path(), &keep, &[]).unwrap();
    assert_eq!(fs::read(receipts.join("fixture")).unwrap(), b"keep");
}

#[test]
fn maybe_path_hint_updates_missing_path_line() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    #[cfg(target_os = "linux")]
    set_private_path_directory(&home);
    fs::create_dir_all(&bindir).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_env_var("PATH", Some("/usr/bin".to_string()));
    set_home_dir(Some(home.clone()));
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(home.clone(), bindir.clone(), prompt);
    let rc = home.join(".bashrc");
    fs::write(&rc, "# upkit (upkit bin)\n").unwrap();
    maybe_path_hint_for_dir(&ctx, &bindir, "upkit bin");
    let updated = fs::read_to_string(&rc).unwrap();
    assert!(updated.contains("export PATH="));
}

#[test]
fn path_hint_respects_explicit_no_path_update() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir(&home).unwrap();
    let rc = home.join(".bashrc");
    fs::write(&rc, "# existing configuration\n").unwrap();
    set_env_var("SHELL", Some("bash".into()));
    set_env_var("PATH", Some("/usr/bin".into()));
    set_env_var("UPKIT_NO_PATH_UPDATE", Some("1".into()));
    set_home_dir(Some(home.clone()));
    let ctx = base_ctx(
        home,
        dir.path().join("bin"),
        Arc::new(TestPrompt::default()),
    );
    maybe_path_hint_for_dir(&ctx, &ctx.bindir, "upkit bin");
    assert_eq!(
        fs::read_to_string(rc).unwrap(),
        "# existing configuration\n"
    );
}

#[test]
fn path_hint_preserves_unrecognized_line_after_label() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir(&home).unwrap();
    #[cfg(target_os = "linux")]
    set_private_path_directory(&home);
    let rc = home.join(".bashrc");
    let original = "# upkit (upkit bin)\nalias fixture='keep this'\n";
    fs::write(&rc, original).unwrap();
    set_env_var("SHELL", Some("bash".into()));
    set_env_var("PATH", Some("/usr/bin".into()));
    set_home_dir(Some(home.clone()));
    let ctx = base_ctx(
        home,
        dir.path().join("bin"),
        Arc::new(TestPrompt::default()),
    );
    maybe_path_hint_for_dir(&ctx, &ctx.bindir, "upkit bin");
    let updated = fs::read_to_string(&rc).unwrap();
    assert!(updated.contains("alias fixture='keep this'\n"));
    assert!(updated.contains("export PATH="));
    maybe_path_hint_for_dir(&ctx, &ctx.bindir, "upkit bin");
    assert_eq!(fs::read_to_string(rc).unwrap(), updated);
}

#[cfg(unix)]
#[test]
fn path_hint_does_not_write_a_lossy_non_unicode_path() {
    use std::os::unix::ffi::OsStringExt;

    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir(&home).unwrap();
    #[cfg(target_os = "linux")]
    set_private_path_directory(&home);
    let rc = home.join(".bashrc");
    fs::write(&rc, "# preserve\n").unwrap();
    set_env_var("SHELL", Some("bash".into()));
    set_env_var("PATH", Some("/usr/bin".into()));
    set_home_dir(Some(home.clone()));
    let bindir = dir
        .path()
        .join(std::ffi::OsString::from_vec(b"bin-\xff".to_vec()));
    let ctx = base_ctx(home, bindir, Arc::new(TestPrompt::default()));
    maybe_path_hint_for_dir(&ctx, &ctx.bindir, "upkit bin");
    assert_eq!(fs::read_to_string(rc).unwrap(), "# preserve\n");
}

#[cfg(target_os = "linux")]
#[test]
fn path_hint_preserves_existing_file_on_write_failure_or_invalid_text() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir(&home).unwrap();
    set_private_path_directory(&home);
    let rc = home.join(".bashrc");
    set_env_var("SHELL", Some("bash".into()));
    set_env_var("PATH", Some("/usr/bin".into()));
    set_home_dir(Some(home.clone()));
    let ctx = base_ctx(
        home,
        dir.path().join("bin"),
        Arc::new(TestPrompt::default()),
    );

    fs::write(&rc, b"# preserve\n").unwrap();
    set_write_error(true);
    maybe_path_hint_for_dir(&ctx, &ctx.bindir, "upkit bin");
    set_write_error(false);
    assert_eq!(fs::read(&rc).unwrap(), b"# preserve\n");

    fs::write(&rc, b"\xff\xfe").unwrap();
    maybe_path_hint_for_dir(&ctx, &ctx.bindir, "upkit bin");
    assert_eq!(fs::read(rc).unwrap(), b"\xff\xfe");
}

#[cfg(target_os = "linux")]
#[test]
fn path_hint_refuses_symlink_and_preserves_existing_permissions() {
    use std::os::unix::fs::symlink;

    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir(&home).unwrap();
    set_private_path_directory(&home);
    let rc = home.join(".bashrc");
    let target = dir.path().join("target");
    fs::write(&target, b"# preserve\n").unwrap();
    symlink(&target, &rc).unwrap();
    set_env_var("SHELL", Some("bash".into()));
    set_env_var("PATH", Some("/usr/bin".into()));
    set_home_dir(Some(home.clone()));
    let ctx = base_ctx(
        home,
        dir.path().join("bin"),
        Arc::new(TestPrompt::default()),
    );
    maybe_path_hint_for_dir(&ctx, &ctx.bindir, "upkit bin");
    assert!(fs::symlink_metadata(&rc).unwrap().file_type().is_symlink());
    assert_eq!(fs::read(&target).unwrap(), b"# preserve\n");

    fs::remove_file(&rc).unwrap();
    fs::hard_link(&target, &rc).unwrap();
    maybe_path_hint_for_dir(&ctx, &ctx.bindir, "upkit bin");
    assert_eq!(fs::read(&target).unwrap(), b"# preserve\n");
    assert_eq!(fs::read(&rc).unwrap(), b"# preserve\n");

    fs::remove_file(&rc).unwrap();
    fs::write(&rc, b"# preserve\n").unwrap();
    fs::set_permissions(&rc, fs::Permissions::from_mode(0o640)).unwrap();
    if rustix::fs::setxattr(
        &rc,
        "user.upkit_fixture",
        b"fixture",
        rustix::fs::XattrFlags::empty(),
    )
    .is_ok()
    {
        maybe_path_hint_for_dir(&ctx, &ctx.bindir, "upkit bin");
        assert_eq!(fs::read(&rc).unwrap(), b"# preserve\n");
        rustix::fs::removexattr(&rc, "user.upkit_fixture").unwrap();
    }
    maybe_path_hint_for_dir(&ctx, &ctx.bindir, "upkit bin");
    assert_eq!(
        fs::metadata(&rc).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert!(fs::read_to_string(rc).unwrap().contains("export PATH="));
}

#[cfg(target_os = "linux")]
#[test]
fn path_hint_rejects_group_writable_profile_parent_without_changing_profile() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o775)).unwrap();
    let rc = home.join(".bashrc");
    let original = b"# preserve this profile\n";
    fs::write(&rc, original).unwrap();
    set_env_var("SHELL", Some("bash".into()));
    set_env_var("PATH", Some("/usr/bin".into()));
    set_home_dir(Some(home.clone()));
    let ctx = base_ctx(
        home,
        dir.path().join("bin"),
        Arc::new(TestPrompt::default()),
    );

    maybe_path_hint_for_dir(&ctx, &ctx.bindir, "upkit bin");

    assert_eq!(fs::read(&rc).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn path_hint_does_not_execute_path_contents() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(&home).unwrap();
    #[cfg(target_os = "linux")]
    set_private_path_directory(&home);
    let bindir = dir.path().join("bin$(touch INJECTED)\"'\\path");
    set_env_var("SHELL", Some("bash".to_owned()));
    set_env_var("PATH", Some("/usr/bin:/bin".to_owned()));
    set_home_dir(Some(home.clone()));
    let ctx = base_ctx(
        home.clone(),
        bindir.clone(),
        Arc::new(TestPrompt::default()),
    );
    maybe_path_hint_for_dir(&ctx, &bindir, "upkit bin");
    let output = std::process::Command::new("/bin/sh")
        .args(["-c", ". \"$1\"; printf '%s' \"$PATH\"", "sh"])
        .arg(home.join(".bashrc"))
        .env("PATH", "/usr/bin:/bin")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{}:/usr/bin:/bin", bindir.display())
    );
    assert!(!dir.path().join("INJECTED").exists());
}

#[test]
fn maybe_path_hint_adds_blank_line_when_existing_content() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    #[cfg(target_os = "linux")]
    set_private_path_directory(&home);
    fs::create_dir_all(&bindir).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_env_var("PATH", Some("/usr/bin".to_string()));
    set_home_dir(Some(home.clone()));
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(home.clone(), bindir.clone(), prompt);
    let rc = home.join(".bashrc");
    fs::write(&rc, "export PATH=\"/opt/bin:$PATH\"\n").unwrap();
    maybe_path_hint_for_dir(&ctx, &bindir, "upkit bin");
    let updated = fs::read_to_string(&rc).unwrap();
    assert!(updated.contains("# upkit (upkit bin)"));
}

#[test]
fn remove_path_hint_quiet_and_missing_rc() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bindir).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(home.clone(), bindir, prompt);
    ctx.quiet = true;
    remove_path_hint_for_label(&ctx, "upkit bin");
    ctx.quiet = false;
    remove_path_hint_for_label(&ctx, "upkit bin");
}

#[test]
fn remove_path_hint_handles_unresolvable_and_removes_path_line() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    #[cfg(target_os = "linux")]
    set_private_path_directory(&home);
    fs::create_dir_all(&bindir).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(None);
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(home.clone(), bindir.clone(), prompt);
    remove_path_hint_for_label(&ctx, "upkit bin");

    set_home_dir(Some(home.clone()));
    let rc = home.join(".bashrc");
    fs::write(
        &rc,
        "# upkit (upkit bin)\nexport PATH=\"/tmp:$PATH\"\nother\n",
    )
    .unwrap();
    remove_path_hint_for_label(&ctx, "upkit bin");
    let updated = fs::read_to_string(&rc).unwrap();
    assert!(!updated.contains("upkit"));
}

#[test]
fn remove_path_hint_skips_non_path_line() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let bindir = dir.path().join("bin");
    fs::create_dir_all(&home).unwrap();
    #[cfg(target_os = "linux")]
    set_private_path_directory(&home);
    fs::create_dir_all(&bindir).unwrap();
    set_env_var("SHELL", Some("bash".to_string()));
    set_home_dir(Some(home.clone()));
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(home.clone(), bindir, prompt);
    let rc = home.join(".bashrc");
    fs::write(&rc, "# keep\r\n# upkit (upkit bin)\r\nnot a path").unwrap();
    remove_path_hint_for_label(&ctx, "upkit bin");
    let updated = fs::read_to_string(&rc).unwrap();
    assert_eq!(updated, "# keep\r\nnot a path");
}

#[test]
fn download_to_temp_with_active_spinner() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.progress_overwrite = true;
    let url = "https://example.com/spinner";
    set_http_plan(url, vec![Ok(MockResponse::new(vec![1], Some(1)))]);
    let pb = start_spinner(&ctx, "Downloading");
    let tmp = download_to_temp(&ctx, url).unwrap();
    finish_spinner(pb, "done");
    assert_eq!(fs::read(tmp.path()).unwrap(), vec![1]);
}

#[cfg(coverage)]
#[test]
fn http_get_requires_mocking_under_coverage() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    let err = http_get_text(&ctx, "https://example.com/unmocked").unwrap_err();
    assert!(err.to_string().contains("http mocking disabled"));
}

#[test]
fn mock_http_attempt_requires_mocking() {
    let _guard = reset_guard();
    let mut last_err: Option<anyhow::Error> = None;
    let attempt = mock_http_attempt("https://example.com", &mut last_err, true);
    assert!(matches!(attempt, MockAttempt::Handled(None)));
    assert!(last_err.is_some());
}

#[test]
fn mock_http_attempt_skipped_when_not_required() {
    let _guard = reset_guard();
    let mut last_err: Option<anyhow::Error> = None;
    let attempt = mock_http_attempt("https://example.com", &mut last_err, false);
    assert!(matches!(attempt, MockAttempt::Skipped));
    assert!(last_err.is_none());
}

#[test]
fn prune_tool_versions_no_root_and_keep_names() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let tool_root = dir.path().join("tool");
    let keep_dir = tool_root.join("1.0.0");
    prune_tool_versions(&tool_root, &keep_dir, &["active"]).unwrap();

    fs::create_dir_all(&keep_dir).unwrap();
    fs::create_dir_all(tool_root.join("active")).unwrap();
    prune_tool_versions(&tool_root, &keep_dir, &["active"]).unwrap();
    assert!(tool_root.join("active").exists());
}

#[test]
fn prune_tool_versions_skips_non_dir_entries() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let tool_root = dir.path().join("tool");
    let keep_dir = tool_root.join("1.0.0");
    fs::create_dir_all(&keep_dir).unwrap();
    fs::write(tool_root.join("note.txt"), b"note").unwrap();
    prune_tool_versions(&tool_root, &keep_dir, &[]).unwrap();
    assert!(tool_root.join("note.txt").exists());
}

#[test]
fn prune_tool_versions_coverage_name_branch() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let tool_root = dir.path().join("tool");
    let keep_dir = tool_root.join("1.0.0");
    let extra_dir = tool_root.join("extra");
    fs::create_dir_all(&keep_dir).unwrap();
    fs::create_dir_all(&extra_dir).unwrap();
    assert!(prune_tool_versions(&tool_root, &keep_dir, &[]).is_err());
    assert!(extra_dir.exists());
}

#[test]
fn download_to_temp_progress_overwrite_with_total() {
    let _guard = reset_guard();
    let dir = tempdir().unwrap();
    let prompt = Arc::new(TestPrompt::default());
    let mut ctx = base_ctx(dir.path().join("home"), dir.path().join("bin"), prompt);
    ctx.progress_overwrite = true;
    let url = "https://example.com/with-total";
    set_http_plan(url, vec![Ok(MockResponse::new(vec![1, 2], Some(2)))]);
    let tmp = download_to_temp(&ctx, url).unwrap();
    assert_eq!(fs::read(tmp.path()).unwrap(), vec![1, 2]);
}

#[test]
fn tool_path_hint_labels_variants() {
    assert_eq!(tool_path_hint_labels(ToolKind::Node), &["npm global bin"]);
    assert_eq!(
        tool_path_hint_labels(ToolKind::Python),
        &["python user base bin"]
    );
    assert_eq!(
        tool_path_hint_labels(ToolKind::Flutter),
        &["flutter bin", "pub cache bin"]
    );
    assert!(tool_path_hint_labels(ToolKind::Mojo).is_empty());
}
