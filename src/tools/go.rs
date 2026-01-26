use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{env, ffi::OsStr, fs, path::PathBuf};

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, atomic_symlink, download_to_temp,
    ensure_clean_dir, get_env_var, home_dir, http_get_json, info, keep_latest_version,
    link_dir_bins, maybe_path_hint_for_dir, prune_tool_versions, run_capture, run_output,
    sha256_file, warn, which_or_none,
};

#[derive(Debug, Deserialize)]
struct GoRelease {
    version: String, // "go1.22.5"
    stable: bool,
    files: Vec<GoFile>,
}

#[derive(Debug, Deserialize)]
struct GoFile {
    filename: String,
    os: String,
    arch: String,
    kind: String, // "archive", "installer", ...
    sha256: String,
}

pub fn go_os_arch(ctx: &Ctx) -> (String, String) {
    let os = match ctx.os.as_str() {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        other => other,
    }
    .to_string();

    let arch = match ctx.arch.as_str() {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
    .to_string();

    (os, arch)
}

pub fn check_go(ctx: &Ctx) -> Result<ToolReport> {
    let installed = if let Some(bin) = go_bin_in_bindir(ctx) {
        let args = [OsStr::new("version")];
        run_capture(bin.as_os_str(), &args).ok()
    } else {
        which_or_none("go").and_then(|_| run_capture("go", &["version"]).ok())
    }
    .and_then(|out| Version::parse_loose(&out));

    let latest = go_latest(ctx).ok();
    let status = Status::from_versions(installed.as_ref(), latest.as_ref());

    let mut notes = vec!["Installs into upkit home and symlinks binaries into bindir.".into()];
    if latest.is_none() {
        notes.push("Could not fetch the latest Go release; status may be unknown.".into());
    }

    Ok(ToolReport {
        tool: ToolKind::Go,
        installed,
        latest,
        status,
        method: UpdateMethod::DirectDownload,
        notes,
    })
}

pub fn go_latest(ctx: &Ctx) -> Result<Version> {
    let releases = go_releases(ctx)?;
    let stable = releases
        .into_iter()
        .filter(|r| r.stable)
        .collect::<Vec<_>>();
    let mut best: Option<Version> = None;
    for r in stable {
        if let Some(v) = Version::parse_loose(&r.version) {
            keep_latest_version(&mut best, v);
        }
    }
    best.ok_or_else(|| anyhow!("could not determine latest Go version"))
}

pub fn go_pick_file(ctx: &Ctx, want_version: &Version) -> Result<(String, String)> {
    // returns (download_url, sha256)
    let releases = go_releases(ctx)?;
    let (os, arch) = go_os_arch(ctx);
    let want_prefix = format!(
        "go{}.{}.{}",
        want_version.major, want_version.minor, want_version.patch
    );

    for r in releases.into_iter().filter(|r| r.stable) {
        if !r.version.starts_with(&want_prefix) {
            continue;
        }
        let file = r.files.iter().find(|f| {
            f.kind == "archive" && f.os == os && f.arch == arch && f.filename.ends_with(".tar.gz")
        });
        if let Some(f) = file {
            let dl = format!("https://go.dev/dl/{}", f.filename);
            return Ok((dl, f.sha256.clone()));
        }
    }

    bail!("no Go archive found for this OS/arch")
}

pub fn update_go(ctx: &Ctx) -> Result<()> {
    if ctx.offline {
        bail!("offline mode enabled; Go update requires network access");
    }
    let report = check_go(ctx)?;
    let latest = report
        .latest
        .clone()
        .ok_or_else(|| anyhow!("latest unknown"))?;
    let tool_root = ctx.home.join("go");
    let active = tool_root.join("active");
    if tool_root.exists() && active.exists() {
        ensure_go_wrappers(ctx, &tool_root, &active)?;
    }

    if matches!(report.status, Status::UpToDate) && !ctx.force {
        info(ctx, format!("go is up-to-date ({})", latest.to_string()));
        return Ok(());
    }

    let prior_globals = if active.exists() {
        match go_global_tools(go_executable(&tool_root, &active).as_deref()) {
            Ok(list) => list,
            Err(err) => {
                warn(ctx, format!("Failed to list go global tools: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    info(ctx, format!("Updating go -> {}", latest.to_string()));
    let (dl, expected_sha) = go_pick_file(ctx, &latest)?;
    if ctx.dry_run {
        info(ctx, format!("[dry-run] would download {dl} and install"));
        return Ok(());
    }

    let tmp = download_to_temp(ctx, &dl)?;
    let got = sha256_file(tmp.path())?;
    if !got.eq_ignore_ascii_case(&expected_sha) {
        bail!("Go sha256 mismatch: expected {expected_sha}, got {got}");
    }

    fs::create_dir_all(&tool_root)?;
    let ver_dir = tool_root.join(latest.to_string());
    ensure_clean_dir(&ver_dir)?;

    // extract tar.gz into ver_dir; tar contains top-level "go/"
    {
        let f = fs::File::open(tmp.path())?;
        let gz = flate2::read::GzDecoder::new(f);
        let mut ar = tar::Archive::new(gz);
        ar.unpack(&ver_dir)?;
    }

    // Active directory points to ver_dir/go
    let extracted_go_dir = ver_dir.join("go");
    atomic_symlink(&extracted_go_dir, &active)?;

    ensure_go_wrappers(ctx, &tool_root, &active)?;
    if let Err(err) = restore_go_globals(
        go_executable(&tool_root, &active).as_deref(),
        &prior_globals,
    ) {
        warn(ctx, format!("Failed to restore go global tools: {err}"));
    }

    if let Err(err) = prune_tool_versions(&tool_root, &ver_dir, &["active", "wrappers"]) {
        warn(ctx, format!("Failed to remove old go versions: {err}"));
    }

    info(ctx, format!("go updated to {}", latest.to_string()));
    Ok(())
}

fn ensure_go_wrappers(
    ctx: &Ctx,
    tool_root: &std::path::Path,
    active: &std::path::Path,
) -> Result<()> {
    let wrapper_dir = tool_root.join("wrappers");
    fs::create_dir_all(&wrapper_dir)?;
    write_go_wrapper(&wrapper_dir.join("go"), active)?;
    write_go_wrapper(&wrapper_dir.join("gofmt"), active)?;
    link_dir_bins(&wrapper_dir, &ctx.bindir, &["go", "gofmt"])?;
    maybe_hint_go_bins(ctx, Some(&wrapper_dir.join("go")));
    Ok(())
}

fn write_go_wrapper(wrapper_path: &std::path::Path, active: &std::path::Path) -> Result<()> {
    let target = active.join("bin").join(
        wrapper_path
            .file_name()
            .ok_or_else(|| anyhow!("invalid wrapper path"))?,
    );
    let script = format!(
        "#!/usr/bin/env sh\nexport GOROOT=\"{}\"\nexec \"{}\" \"$@\"\n",
        active.display(),
        target.display()
    );
    fs::write(wrapper_path, script)?;
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(wrapper_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(wrapper_path, perms)?;
    }
    Ok(())
}

fn maybe_hint_go_bins(ctx: &Ctx, go_bin: Option<&std::path::Path>) {
    let gobin = go_env_value(go_bin, "GOBIN");
    if let Some(dir) = gobin {
        maybe_path_hint_for_dir(ctx, std::path::Path::new(&dir), "go GOBIN");
        return;
    }
    for gopath in go_env_paths(go_bin, "GOPATH") {
        maybe_path_hint_for_dir(ctx, &gopath.join("bin"), "go GOPATH/bin");
    }
}

fn go_env_value(go_bin: Option<&std::path::Path>, key: &str) -> Option<String> {
    if let Some(value) = get_env_var(key) {
        let value = value.trim().to_string();
        if !value.is_empty() {
            return Some(value);
        }
    }
    match go_bin {
        Some(bin) => {
            let args = [OsStr::new("env"), OsStr::new(key)];
            run_capture(bin.as_os_str(), &args).ok()
        }
        None => run_capture("go", &["env", key]).ok(),
    }
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty())
}

fn go_env_paths(go_bin: Option<&std::path::Path>, key: &str) -> Vec<std::path::PathBuf> {
    if let Some(value) = go_env_value(go_bin, key) {
        return env::split_paths(&value).collect();
    }
    if key == "GOPATH" {
        return default_gopath().into_iter().collect();
    }
    Vec::new()
}

fn default_gopath() -> Option<std::path::PathBuf> {
    home_dir().map(|home| home.join("go"))
}

fn go_bin_in_bindir(ctx: &Ctx) -> Option<std::path::PathBuf> {
    let candidate = ctx.bindir.join("go");
    if candidate.exists() {
        return Some(candidate);
    }
    None
}

fn go_releases(ctx: &Ctx) -> Result<Vec<GoRelease>> {
    const URLS: [&str; 2] = [
        "https://go.dev/dl/?mode=json",
        "https://golang.org/dl/?mode=json",
    ];
    let mut last_err: Option<anyhow::Error> = None;
    for url in URLS {
        match http_get_json::<Vec<GoRelease>>(ctx, url) {
            Ok(releases) => return Ok(releases),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("could not fetch Go releases")))
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct GoToolSpec {
    module: String,
    version: String,
}

fn go_executable(tool_root: &std::path::Path, active: &std::path::Path) -> Option<PathBuf> {
    let wrapper = tool_root.join("wrappers").join("go");
    if wrapper.exists() {
        return Some(wrapper);
    }
    let bin = active.join("bin").join("go");
    if bin.exists() {
        return Some(bin);
    }
    None
}

fn go_global_tools(go_bin: Option<&std::path::Path>) -> Result<Vec<GoToolSpec>> {
    let bin_dirs = go_global_bin_dirs(go_bin);
    if bin_dirs.is_empty() {
        return Ok(Vec::new());
    }
    let mut specs = Vec::new();
    for dir in bin_dirs {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            if !meta.is_file() {
                continue;
            }
            if let Some(spec) = go_tool_spec_from_binary(go_bin, &path) {
                specs.push(spec);
            }
        }
    }
    specs.sort();
    specs.dedup();
    Ok(specs)
}

fn go_global_bin_dirs(go_bin: Option<&std::path::Path>) -> Vec<PathBuf> {
    if let Some(gobin) = go_env_value(go_bin, "GOBIN") {
        return vec![PathBuf::from(gobin)];
    }
    let mut dirs = Vec::new();
    for gopath in go_env_paths(go_bin, "GOPATH") {
        dirs.push(gopath.join("bin"));
    }
    dirs
}

fn go_tool_spec_from_binary(
    go_bin: Option<&std::path::Path>,
    binary: &std::path::Path,
) -> Option<GoToolSpec> {
    let program = match go_bin {
        Some(path) => path.to_string_lossy().to_string(),
        None => "go".to_string(),
    };
    let args = [
        "version".to_string(),
        "-m".to_string(),
        binary.to_string_lossy().to_string(),
    ];
    let output = run_output(program, &args).ok()?;
    if !output.status.success() {
        return None;
    }
    parse_go_version_metadata(&String::from_utf8_lossy(&output.stdout))
}

fn parse_go_version_metadata(output: &str) -> Option<GoToolSpec> {
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let key = parts.next()?;
        if key == "mod" {
            let module = parts.next()?.to_string();
            let version = parts.next()?.to_string();
            if version == "(devel)" {
                return None;
            }
            return Some(GoToolSpec { module, version });
        }
    }
    None
}

fn restore_go_globals(go_bin: Option<&std::path::Path>, tools: &[GoToolSpec]) -> Result<()> {
    if tools.is_empty() {
        return Ok(());
    }
    let program = match go_bin {
        Some(path) => path.to_string_lossy().to_string(),
        None => "go".to_string(),
    };
    for tool in tools {
        let target = format!("{}@{}", tool.module, tool.version);
        let args = vec!["install".to_string(), target];
        run_capture(program.clone(), &args)?;
    }
    Ok(())
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::test_support::{
        TestPrompt, base_ctx, output_with_status, reset_guard, set_env_var, set_home_dir,
        set_run_output,
    };
    use std::fs;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn go_env_value_uses_env() {
        let _guard = reset_guard();
        set_env_var("GOBIN", Some(" /tmp/gobin ".to_string()));
        let value = go_env_value(None, "GOBIN");
        assert_eq!(value.as_deref(), Some("/tmp/gobin"));
    }

    #[test]
    fn go_env_value_runs_go_env() {
        let _guard = reset_guard();
        set_env_var("GOPATH", None);
        set_run_output(
            "go",
            &["env", "GOPATH"],
            output_with_status(0, b"/opt/go\n", b""),
        );
        let value = go_env_value(None, "GOPATH");
        assert_eq!(value.as_deref(), Some("/opt/go"));
    }

    #[test]
    fn go_env_value_uses_env_for_gopath() {
        let _guard = reset_guard();
        set_env_var("GOPATH", Some(" /tmp/gopath ".to_string()));
        let value = go_env_value(None, "GOPATH");
        assert_eq!(value.as_deref(), Some("/tmp/gopath"));
    }

    #[test]
    fn go_env_paths_from_env_and_default() {
        let _guard = reset_guard();
        set_env_var("GOPATH", Some("/a:/b".to_string()));
        let paths = go_env_paths(None, "GOPATH");
        assert_eq!(paths.len(), 2);

        set_env_var("GOPATH", None);
        set_run_output("go", &["env", "GOPATH"], output_with_status(0, b"\n", b""));
        set_home_dir(Some(std::path::PathBuf::from("/tmp")));
        let paths = go_env_paths(None, "GOPATH");
        assert_eq!(paths, vec![std::path::PathBuf::from("/tmp/go")]);
    }

    #[test]
    fn go_env_paths_empty_for_unknown_key() {
        let _guard = reset_guard();
        set_env_var("GOROOT", None);
        set_run_output("go", &["env", "GOROOT"], output_with_status(0, b"\n", b""));
        let paths = go_env_paths(None, "GOROOT");
        assert!(paths.is_empty());
    }

    #[test]
    fn ensure_go_wrappers_hints_from_gobin() {
        let _guard = reset_guard();
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let bindir = dir.path().join("bin");
        let prompt = Arc::new(TestPrompt::default());
        let mut ctx = base_ctx(home.clone(), bindir.clone(), prompt);
        ctx.quiet = true;
        fs::create_dir_all(&bindir).unwrap();
        let tool_root = home.join("go");
        let active = tool_root.join("active");
        fs::create_dir_all(&active).unwrap();
        set_env_var("GOBIN", Some("/tmp/gobin".to_string()));
        ensure_go_wrappers(&ctx, &tool_root, &active).unwrap();
    }

    #[test]
    fn parse_go_version_metadata_skips_devel() {
        let output = "example\nmod example.com/tool (devel)\n";
        assert!(parse_go_version_metadata(output).is_none());
    }

    #[test]
    fn parse_go_version_metadata_extracts_mod() {
        let output = "example\nmod example.com/tool v1.2.3\n";
        let spec = parse_go_version_metadata(output).unwrap();
        assert_eq!(spec.module, "example.com/tool");
        assert_eq!(spec.version, "v1.2.3");
    }

    #[test]
    fn go_global_bin_dirs_prefers_gobin() {
        let _guard = reset_guard();
        set_env_var("GOBIN", Some("/tmp/gobin".to_string()));
        set_env_var("GOPATH", Some("/tmp/gopath".to_string()));
        let dirs = go_global_bin_dirs(None);
        assert_eq!(dirs, vec![std::path::PathBuf::from("/tmp/gobin")]);
    }

    #[test]
    fn go_tool_spec_from_binary_uses_version_output() {
        let _guard = reset_guard();
        let dir = tempdir().unwrap();
        let binary = dir.path().join("tool");
        fs::write(&binary, b"").unwrap();
        set_run_output(
            "go",
            &["version", "-m", binary.to_string_lossy().as_ref()],
            output_with_status(0, b"example\nmod example.com/tool v1.2.3\n", b""),
        );
        let spec = go_tool_spec_from_binary(None, &binary).unwrap();
        assert_eq!(spec.module, "example.com/tool");
        assert_eq!(spec.version, "v1.2.3");
    }

    #[test]
    fn restore_go_globals_runs_install() {
        let _guard = reset_guard();
        set_run_output(
            "go",
            &["install", "example.com/tool@v1.2.3"],
            output_with_status(0, b"", b""),
        );
        let tools = vec![GoToolSpec {
            module: "example.com/tool".to_string(),
            version: "v1.2.3".to_string(),
        }];
        restore_go_globals(None, &tools).unwrap();
    }

    #[test]
    fn go_global_tools_reads_gobin_dir() {
        let _guard = reset_guard();
        let dir = tempdir().unwrap();
        let gobin = dir.path().join("bin");
        fs::create_dir_all(&gobin).unwrap();
        let binary = gobin.join("tool");
        fs::write(&binary, b"").unwrap();
        set_env_var("GOBIN", Some(gobin.to_string_lossy().to_string()));
        set_run_output(
            "go",
            &["version", "-m", binary.to_string_lossy().as_ref()],
            output_with_status(0, b"example\nmod example.com/tool v1.2.3\n", b""),
        );
        let tools = go_global_tools(None).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].module, "example.com/tool");
    }
}
