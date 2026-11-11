use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    env,
    ffi::OsStr,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    Ctx, Status, ToolKind, ToolReport, UpdateMethod, Version, download_to_temp, get_env_var,
    home_dir, http_get_json, info, keep_latest_version, link_managed_tool_bins,
    maybe_path_hint_for_dir, prune_tool_versions, run_capture, run_output, sha256_file, warn,
    which_or_none,
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
    let managed_bin = go_bin_in_bindir(ctx);
    let path_bin = if managed_bin.is_none() {
        which_or_none("go")
    } else {
        None
    };
    let executable_found =
        managed_bin.as_ref().is_some_and(|bin| bin.is_file()) || path_bin.is_some();
    let skip_execution = ctx.dry_run || ctx.offline;
    let installed = if skip_execution {
        None
    } else if let Some(bin) = managed_bin {
        let args = [OsStr::new("version")];
        run_capture(bin.as_os_str(), &args).ok()
    } else if path_bin.is_some() {
        run_capture("go", &["version"]).ok()
    } else {
        None
    }
    .and_then(|out| Version::parse_loose(&out));

    let latest = go_latest(ctx).ok();
    let version_unverified = executable_found && installed.is_none();
    let status = if version_unverified {
        Status::Unknown
    } else {
        Status::from_versions(installed.as_ref(), latest.as_ref())
    };

    let mut notes = vec!["Installs into upkit home and symlinks binaries into bindir.".into()];
    if skip_execution && executable_found {
        notes.push(format!(
            "{} skipped running Go; the installed version is unknown.",
            if ctx.dry_run {
                "Dry-run"
            } else {
                "Offline mode"
            }
        ));
    } else if version_unverified {
        notes.push("A Go executable was found, but its version could not be verified.".into());
    }
    if ctx.os == "windows" {
        notes.push("Windows installation requires permission to create symbolic links.".into());
        notes.push("Existing GOROOT settings can override the managed Go installation.".into());
    }
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
    for r in releases.into_iter().filter(|r| r.stable) {
        if Version::parse_loose(&r.version).as_ref() != Some(want_version) {
            continue;
        }
        let extension = if os == "windows" { ".zip" } else { ".tar.gz" };
        let file = r.files.iter().find(|f| {
            f.kind == "archive" && f.os == os && f.arch == arch && f.filename.ends_with(extension)
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
    crate::infrastructure::validate_active_install(&tool_root)?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if !ctx.dry_run && ctx.os != "windows" && tool_root.exists() {
        secure_go_directories(ctx, &tool_root)?;
    }
    if tool_root.exists() && active.exists() {
        ensure_go_wrappers(ctx, &tool_root, &active)?;
    }

    if matches!(report.status, Status::UpToDate) && !ctx.force {
        info(ctx, format!("go is up-to-date ({})", latest));
        return Ok(());
    }

    let prior_globals = if !ctx.dry_run && active.exists() {
        match go_global_tools(go_executable(ctx, &tool_root, &active).as_deref()) {
            Ok(list) => list,
            Err(err) => {
                warn(ctx, format!("Failed to list go global tools: {err}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    info(ctx, format!("Updating go -> {}", latest));
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

    crate::infrastructure::ensure_tool_root(&tool_root)?;
    crate::infrastructure::validate_active_install(&tool_root)?;
    let stage = crate::infrastructure::new_install_stage(&tool_root)?;

    if ctx.os == "windows" {
        super::archive::unpack_windows_zip(tmp.path(), stage.path())?;
    } else {
        super::archive::unpack_tar_gz(tmp.path(), stage.path(), 1)?;
    }
    validate_go_archive(ctx, stage.path(), &latest)?;
    if ctx.os == "windows" {
        let names = crate::infrastructure::tool_bin_names_for_os(ToolKind::Go, &ctx.os);
        crate::infrastructure::preflight_bin_links(
            Some(&stage.path().join("go/bin")),
            &active.join("bin"),
            &ctx.bindir,
            names,
        )?;
    } else {
        check_go_wrappers(&tool_root, &active)?;
        crate::infrastructure::preflight_bin_links(
            None,
            &tool_root.join("wrappers"),
            &ctx.bindir,
            &["go", "gofmt"],
        )?;
    }
    crate::infrastructure::seal_managed_install(
        ctx,
        &tool_root,
        &stage,
        ToolKind::Go,
        &latest.to_string(),
    );
    let ver_dir = stage.keep();

    // Active directory points to ver_dir/go
    let extracted_go_dir = ver_dir.join("go");
    crate::infrastructure::activate_managed_install(
        ctx,
        &tool_root,
        &extracted_go_dir,
        ToolKind::Go,
    )?;

    ensure_go_wrappers(ctx, &tool_root, &active)?;
    if let Err(err) = restore_go_globals(
        go_executable(ctx, &tool_root, &active).as_deref(),
        &prior_globals,
    ) {
        warn(ctx, format!("Failed to restore go global tools: {err}"));
    }

    if let Err(err) = prune_tool_versions(&tool_root, &ver_dir, &["active", "wrappers"]) {
        warn(ctx, format!("Failed to remove old go versions: {err}"));
    }

    info(ctx, format!("go updated to {}", latest));
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn secure_go_directories(ctx: &Ctx, tool_root: &Path) -> Result<()> {
    use rustix::fs::{Mode, OFlags, fchmod, fstat, open, openat};
    use rustix::io::Errno;

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let root = open(tool_root, flags, Mode::empty()).context("open Go tool root")?;
    let secure = |fd: &rustix::fd::OwnedFd, path: &Path| -> Result<()> {
        let stat = fstat(fd)?;
        if stat.st_uid != rustix::process::geteuid().as_raw() {
            bail!(
                "Go directory must be owned by the current user: {}",
                path.display()
            );
        }
        if stat.st_mode & 0o022 != 0 {
            fchmod(fd, Mode::from_raw_mode(stat.st_mode & !0o022))?;
            warn(
                ctx,
                format!(
                    "Removed group/other write permission from {}",
                    path.display()
                ),
            );
        }
        Ok(())
    };
    secure(&root, tool_root)?;
    match openat(&root, "wrappers", flags, Mode::empty()) {
        Ok(wrappers) => secure(&wrappers, &tool_root.join("wrappers"))?,
        Err(Errno::NOENT) => {}
        Err(err) => return Err(err).context("open Go wrapper directory"),
    }
    Ok(())
}

fn validate_go_archive(ctx: &Ctx, stage: &Path, version: &Version) -> Result<()> {
    let mut entries = fs::read_dir(stage)?;
    let entry = entries.next().context("empty Go archive")??;
    if entry.file_name() != "go"
        || !entry.file_type()?.is_dir()
        || entries.next().transpose()?.is_some()
    {
        bail!("unexpected Go archive layout");
    }
    let root = entry
        .path()
        .canonicalize()
        .context("resolve staged Go directory")?;
    let (os, arch) = go_os_arch(ctx);
    let suffix = if os == "windows" { ".exe" } else { "" };
    for (relative, executable) in [
        (format!("bin/go{suffix}"), true),
        (format!("bin/gofmt{suffix}"), true),
        (format!("pkg/tool/{os}_{arch}/compile{suffix}"), true),
        (format!("pkg/tool/{os}_{arch}/link{suffix}"), true),
        ("src/runtime/proc.go".to_owned(), false),
        ("VERSION".to_owned(), false),
    ] {
        let file = root
            .join(&relative)
            .canonicalize()
            .with_context(|| format!("inspect staged Go component {relative}"))?;
        if !file.starts_with(&root) || !file.is_file() {
            bail!("staged Go component is not a file inside the installation: {relative}");
        }
        let metadata = file.metadata()?;
        if metadata.len() == 0 {
            bail!("staged Go component is empty: {relative}");
        }
        #[cfg(unix)]
        if os != "windows" && executable && metadata.permissions().mode() & 0o111 == 0 {
            bail!("staged Go component is not executable: {relative}");
        }
        #[cfg(not(unix))]
        let _ = executable;
        if relative == "VERSION" {
            if metadata.len() > 1024 {
                bail!("staged Go VERSION is oversized");
            }
            let expected = format!("go{version}");
            let mut bytes = Vec::new();
            fs::File::open(file)?.take(1025).read_to_end(&mut bytes)?;
            let first = bytes
                .split(|byte| *byte == b'\n')
                .next()
                .unwrap_or_default();
            if first.strip_suffix(b"\r").unwrap_or(first) != expected.as_bytes() {
                bail!("staged Go VERSION does not match the selected release");
            }
        }
    }
    Ok(())
}

pub fn ensure_go_wrappers(
    ctx: &Ctx,
    tool_root: &std::path::Path,
    active: &std::path::Path,
) -> Result<()> {
    if ctx.dry_run {
        return Ok(());
    }
    if ctx.os == "windows" {
        if active != tool_root.join("active") {
            bail!("Go active path must be inside the tool root");
        }
        crate::infrastructure::validate_active_install(tool_root)?;
        let bin = active.join("bin");
        let root = active
            .canonicalize()
            .context("resolve active Go installation")?;
        let names = crate::infrastructure::tool_bin_names_for_os(ToolKind::Go, &ctx.os);
        for name in names {
            let resolved = bin
                .join(name)
                .canonicalize()
                .with_context(|| format!("inspect managed {name}"))?;
            if !resolved.starts_with(&root)
                || !resolved.is_file()
                || resolved.metadata()?.len() == 0
            {
                bail!("managed Go executable is missing or outside its installation: {name}");
            }
        }
        link_managed_tool_bins(ctx, tool_root, ToolKind::Go, &bin, &ctx.bindir, names)?;
        maybe_hint_go_bins(ctx, Some(&bin.join("go.exe")));
        return Ok(());
    }
    let wrapper_dir = tool_root.join("wrappers");
    check_go_wrappers(tool_root, active)?;
    crate::infrastructure::preflight_bin_links(None, &wrapper_dir, &ctx.bindir, &["go", "gofmt"])?;
    #[cfg(unix)]
    let mut wrapper_builder = fs::DirBuilder::new();
    #[cfg(not(unix))]
    let wrapper_builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        wrapper_builder.mode(0o755);
    }
    match wrapper_builder.create(&wrapper_dir) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err).context("create Go wrapper directory"),
    }
    check_go_wrappers(tool_root, active)?;
    for name in ["go", "gofmt"] {
        write_go_wrapper(&wrapper_dir.join(name), active, name)?;
    }
    link_managed_tool_bins(
        ctx,
        tool_root,
        ToolKind::Go,
        &wrapper_dir,
        &ctx.bindir,
        &["go", "gofmt"],
    )?;
    maybe_hint_go_bins(ctx, Some(&wrapper_dir.join("go")));
    Ok(())
}

fn go_wrapper_script(active: &Path, name: &str) -> Result<String> {
    let target = active.join("bin").join(name);
    let quote = |path: &std::path::Path| -> Result<String> {
        let value = path
            .to_str()
            .ok_or_else(|| anyhow!("Go wrapper path is not valid UTF-8"))?;
        Ok(format!("'{}'", value.replace('\'', "'\\''")))
    };
    Ok(format!(
        "#!/usr/bin/env sh\nexport GOROOT={}\nexec {} \"$@\"\n",
        quote(active)?,
        quote(&target)?
    ))
}

fn legacy_go_wrapper_script(active: &Path, name: &str) -> Option<String> {
    let active = active.to_str()?;
    if active
        .chars()
        .any(|c| c.is_control() || matches!(c, '"' | '$' | '`' | '\\'))
    {
        return None;
    }
    Some(format!(
        "#!/usr/bin/env sh\nexport GOROOT=\"{active}\"\nexec \"{active}/bin/{name}\" \"$@\"\n"
    ))
}

fn check_go_wrappers(tool_root: &Path, active: &Path) -> Result<()> {
    let root = fs::symlink_metadata(tool_root).context("inspect Go tool root")?;
    if !root.is_dir() || root.file_type().is_symlink() {
        bail!("refusing linked or non-directory Go tool root");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if root.mode() & 0o022 != 0 {
            bail!("Go tool root must not be writable by group or others");
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if root.uid() != rustix::process::geteuid().as_raw() {
            bail!("Go tool root must be owned by the current user");
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if root.file_attributes() & 0x400 != 0 {
            bail!("refusing reparse-point Go tool root");
        }
    }
    let dir = tool_root.join("wrappers");
    let metadata = match fs::symlink_metadata(&dir) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).context("inspect Go wrapper directory"),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("refusing linked or non-directory Go wrapper directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 {
            bail!("Go wrapper directory must not be writable by group or others");
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            bail!("Go wrapper directory must be owned by the current user");
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            bail!("refusing reparse-point Go wrapper directory");
        }
    }
    for name in ["go", "gofmt"] {
        let path = dir.join(name);
        let script = go_wrapper_script(active, name)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => verify_go_wrapper(
                &path,
                &script,
                legacy_go_wrapper_script(active, name).as_deref(),
            )?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).context("inspect Go wrapper"),
        }
    }
    Ok(())
}

fn verify_go_wrapper(path: &Path, expected: &str, legacy: Option<&str>) -> Result<()> {
    let before = fs::symlink_metadata(path).context("inspect Go wrapper")?;
    let valid_len =
        |len| len == expected.len() as u64 || legacy.is_some_and(|s| len == s.len() as u64);
    if !before.is_file() || before.file_type().is_symlink() || !valid_len(before.len()) {
        bail!(
            "refusing to replace an unrelated Go wrapper: {}",
            path.display()
        );
    }
    #[cfg(target_os = "linux")]
    let mut file = fs::File::from(rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    #[cfg(not(target_os = "linux"))]
    let mut file = fs::File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || !valid_len(opened.len()) {
        bail!("Go wrapper changed during inspection");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || opened.nlink() != 1
            || opened.mode() & 0o022 != 0
            || opened.mode() & 0o111 == 0
        {
            bail!("Go wrapper has unsafe identity or permissions");
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.uid() != rustix::process::geteuid().as_raw() {
            bail!("Go wrapper must be owned by the current user");
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if before.file_attributes() & 0x400 != 0 || opened.file_attributes() & 0x400 != 0 {
            bail!("refusing reparse-point Go wrapper");
        }
    }
    let mut contents = Vec::new();
    (&mut file)
        .take(expected.len().max(legacy.map_or(0, str::len)) as u64 + 1)
        .read_to_end(&mut contents)?;
    if contents != expected.as_bytes() && !legacy.is_some_and(|s| contents == s.as_bytes()) {
        bail!(
            "refusing to replace an unrelated Go wrapper: {}",
            path.display()
        );
    }
    Ok(())
}

fn write_go_wrapper(wrapper_path: &Path, active: &Path, name: &str) -> Result<()> {
    let script = go_wrapper_script(active, name)?;
    match fs::symlink_metadata(wrapper_path) {
        Ok(_) => {
            return verify_go_wrapper(
                wrapper_path,
                &script,
                legacy_go_wrapper_script(active, name).as_deref(),
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("inspect Go wrapper"),
    }
    let mut temp = tempfile::NamedTempFile::new_in(
        wrapper_path.parent().context("Go wrapper has no parent")?,
    )?;
    temp.write_all(script.as_bytes())?;
    #[cfg(unix)]
    {
        let mut perms = temp.as_file().metadata()?.permissions();
        perms.set_mode(0o755);
        temp.as_file().set_permissions(perms)?;
    }
    temp.persist_noclobber(wrapper_path)
        .context("install Go wrapper without replacing an existing path")?;
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

pub fn go_env_value(go_bin: Option<&std::path::Path>, key: &str) -> Option<String> {
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

pub fn go_env_paths(go_bin: Option<&std::path::Path>, key: &str) -> Vec<std::path::PathBuf> {
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
    let candidate = ctx
        .bindir
        .join(if ctx.os == "windows" { "go.exe" } else { "go" });
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
pub struct GoToolSpec {
    pub module: String,
    pub version: String,
}

fn go_executable(
    ctx: &Ctx,
    tool_root: &std::path::Path,
    active: &std::path::Path,
) -> Option<PathBuf> {
    if ctx.os == "windows" {
        let bin = active.join("bin/go.exe");
        return bin.exists().then_some(bin);
    }
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

pub fn go_global_tools(go_bin: Option<&std::path::Path>) -> Result<Vec<GoToolSpec>> {
    let bin_dirs = go_global_bin_dirs(go_bin);
    if bin_dirs.is_empty() {
        return Ok(Vec::new());
    }
    let mut specs = Vec::new();
    for dir in bin_dirs {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("read {}", dir.display())),
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("read an entry in {}", dir.display()))?;
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| format!("inspect {}", path.display()));
                }
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

pub fn go_global_bin_dirs(go_bin: Option<&std::path::Path>) -> Vec<PathBuf> {
    if let Some(gobin) = go_env_value(go_bin, "GOBIN") {
        return vec![PathBuf::from(gobin)];
    }
    let mut dirs = Vec::new();
    for gopath in go_env_paths(go_bin, "GOPATH") {
        dirs.push(gopath.join("bin"));
    }
    dirs
}

pub fn go_tool_spec_from_binary(
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

pub fn parse_go_version_metadata(output: &str) -> Option<GoToolSpec> {
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

pub fn restore_go_globals(go_bin: Option<&std::path::Path>, tools: &[GoToolSpec]) -> Result<()> {
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
