use anyhow::{Context, Result, anyhow, bail};
#[cfg(not(coverage))]
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
use indicatif::ProgressDrawTarget;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::blocking::Client;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    env,
    ffi::OsStr,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering as AtomicOrdering},
    },
    time::Duration,
};
use tempfile::NamedTempFile;

use crate::domain::{Status, ToolKind, ToolReport, UpdateMethod};
use crate::test_support;

#[derive(Clone)]
pub struct Ctx {
    #[cfg_attr(any(test, coverage), allow(dead_code))]
    pub http: Client,
    pub home: PathBuf,
    pub bindir: PathBuf,
    pub os: String,
    pub arch: String,
    pub stdin_is_tty: bool,
    pub stderr_is_tty: bool,
    pub progress_overwrite: bool,
    pub yes: bool,
    pub dry_run: bool,
    pub quiet: bool,
    pub verbose: u8,
    pub no_progress: bool,
    pub offline: bool,
    pub retries: u8,
    pub timeout: u64,
    pub force: bool,
    pub json: bool,
    pub use_color: bool,
    pub json_emitted: Arc<AtomicBool>,
    pub prompt: Arc<dyn Prompt>,
}

pub trait Prompt: Send + Sync {
    fn confirm(&self, prompt: &str, default: bool) -> Result<bool>;
    fn multi_select(&self, prompt: &str, items: &[String]) -> Result<Vec<usize>>;
}

#[derive(Clone, Debug)]
pub struct DialoguerPrompt;

impl Prompt for DialoguerPrompt {
    fn confirm(&self, prompt: &str, default: bool) -> Result<bool> {
        if test_support::prompt_defaults_override() {
            let _ = prompt;
            return Ok(default);
        }
        if let Some(value) = test_support::next_prompt_confirm() {
            let _ = prompt;
            return Ok(value);
        }
        #[cfg(coverage)]
        {
            let _ = prompt;
            return Ok(default);
        }
        #[cfg(not(coverage))]
        Ok(Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .default(default)
            .interact()?)
    }

    fn multi_select(&self, prompt: &str, items: &[String]) -> Result<Vec<usize>> {
        if test_support::prompt_defaults_override() {
            let _ = prompt;
            let _ = items;
            return Ok(Vec::new());
        }
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let codes = (0..items.len()).map(index_to_code).collect::<Vec<_>>();
        for (code, item) in codes.iter().zip(items.iter()) {
            eprintln!("  {code}) {item}");
        }
        let prompt = format!("{prompt} [type letters, comma-separated; example: a,c,f]");
        let input = if let Some(value) = test_support::next_prompt_input() {
            value
        } else {
            #[cfg(coverage)]
            {
                let _ = prompt;
                return Ok(Vec::new());
            }
            #[cfg(not(coverage))]
            {
                Input::with_theme(&ColorfulTheme::default())
                    .with_prompt(prompt)
                    .allow_empty(true)
                    .interact_text()?
            }
        };
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }
        let mut chosen = Vec::new();
        let mut seen = HashSet::new();
        for raw in trimmed.split([',', ' ', ';', '\t']) {
            let token = raw.trim().to_lowercase();
            if token.is_empty() {
                continue;
            }
            if !token.chars().all(|c| c.is_ascii_lowercase()) {
                bail!("invalid selection: {token}");
            }
            let idx = code_to_index(&token)?;
            if idx >= items.len() {
                bail!("selection out of range: {token}");
            }
            if seen.insert(idx) {
                chosen.push(idx);
            }
        }
        Ok(chosen)
    }
}

pub fn index_to_code(mut idx: usize) -> String {
    let mut out = Vec::new();
    loop {
        let rem = (idx % 26) as u8;
        out.push((b'a' + rem) as char);
        if idx < 26 {
            break;
        }
        idx = idx / 26 - 1;
    }
    out.into_iter().rev().collect()
}

pub fn code_to_index(code: &str) -> Result<usize> {
    if code.is_empty() {
        bail!("empty selection");
    }
    let mut acc = 0usize;
    for ch in code.chars() {
        if !ch.is_ascii_lowercase() {
            bail!("invalid selection: {code}");
        }
        let val = (ch as u8 - b'a') as usize;
        acc = acc * 26 + val + 1;
    }
    Ok(acc - 1)
}

pub fn info<S: AsRef<str>>(ctx: &Ctx, msg: S) {
    if !ctx.quiet && !ctx.json {
        println!("{}", msg.as_ref());
    }
}

pub fn warn<S: AsRef<str>>(ctx: &Ctx, msg: S) {
    if !ctx.quiet && !ctx.json {
        eprintln!("warning: {}", msg.as_ref());
    }
}

pub fn debug<S: AsRef<str>>(ctx: &Ctx, msg: S) {
    if !ctx.quiet && !ctx.json && ctx.verbose > 0 {
        eprintln!("debug: {}", msg.as_ref());
    }
}

pub fn error<S: AsRef<str>>(msg: S) {
    eprintln!("error: {}", msg.as_ref());
}

pub fn print_reports(ctx: &Ctx, reports: &[ToolReport]) {
    if ctx.quiet {
        return;
    }
    for r in reports {
        let installed = r
            .installed
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into());
        let latest = r
            .latest
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "?".into());
        let status = format!("{:?}", r.status);
        let status = colorize_status(ctx, r.status, status);
        println!(
            "{:7}  installed={:12}  latest={:12}  status={}",
            r.tool.as_str(),
            installed,
            latest,
            status
        );
        for n in &r.notes {
            println!("         note: {n}");
        }
    }
}

pub fn maybe_path_hint(ctx: &Ctx) {
    maybe_path_hint_for_dir(ctx, &ctx.bindir, "upkit bin");
    if upkit_installed_via_npm() {
        if let Some(dir) = npm_global_bin_dir(ctx) {
            maybe_path_hint_for_dir(ctx, &dir, "npm global bin");
        }
        return;
    }
    if let Some(dir) = upkit_exe_dir() {
        let upkit_dir = if is_dev_exe_dir(&dir) {
            ctx.bindir.clone()
        } else {
            dir
        };
        if upkit_dir != ctx.bindir {
            maybe_path_hint_for_dir(ctx, &upkit_dir, "upkit exe");
        }
    }
}

pub fn maybe_path_hint_for_dir(ctx: &Ctx, dir: &Path, label: &str) {
    if ctx.quiet || ctx.dry_run || get_env_var("UPKIT_NO_PATH_UPDATE").as_deref() == Some("1") {
        return;
    }
    let shell = get_env_var("SHELL").unwrap_or_default();
    let rc = shell_rc_path(&shell);
    let rc_path = match expand_tilde(rc) {
        Some(p) => p,
        None => {
            warn(ctx, "Could not resolve shell rc file to update PATH.");
            return;
        }
    };

    let label_line = format!("# upkit ({label})");
    let Some(path_line) = path_hint_line(&shell, dir) else {
        warn(
            ctx,
            "Cannot write a non-Unicode path to shell configuration; add it manually.",
        );
        return;
    };
    let dir_string = dir.to_string_lossy().to_string();
    let existing = match fs::read_to_string(&rc_path) {
        Ok(content) => Some(content),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => {
            warn(ctx, format!("Failed to read shell configuration: {err}"));
            return;
        }
    };
    let (mut output, found_label, mut updated) = insert_path_after_labels(
        existing.as_deref().unwrap_or_default(),
        &label_line,
        &path_line,
    );

    if !found_label {
        let path = get_env_var("PATH").unwrap_or_default();
        if env::split_paths(&path).any(|p| p == dir) {
            return;
        }
        let already_configured = existing
            .as_ref()
            .map(|content| content.contains(&dir_string))
            .unwrap_or(false);
        if already_configured {
            return;
        }
        append_path_hint(&mut output, &label_line, &path_line);
        updated = true;
    }

    if !updated {
        return;
    }

    write_path_hint(ctx, &rc_path, output, existing.as_deref());
}

#[derive(Clone, Debug)]
pub(crate) struct PathCheckEntry {
    pub(crate) label: String,
    pub(crate) dir: PathBuf,
    pub(crate) configured: bool,
    pub(crate) updated: bool,
}

struct PathTarget {
    label: &'static str,
    dir: PathBuf,
}

pub(crate) fn ensure_required_paths(ctx: &Ctx) -> Vec<PathCheckEntry> {
    let shell = get_env_var("SHELL").unwrap_or_default();
    let rc_paths = resolve_shell_rc_paths(&shell);
    let primary_rc = primary_shell_rc_path(&rc_paths);
    let home = home_dir();
    let can_update = !ctx.dry_run && get_env_var("UPKIT_NO_PATH_UPDATE").as_deref() != Some("1");
    if let Some(dir) = upkit_exe_dir()
        && is_dev_exe_dir(&dir)
        && can_update
    {
        if let Some(rc_path) = primary_rc.as_ref() {
            update_path_hint_in_rc(ctx, rc_path, &shell, &ctx.bindir, "upkit bin");
        } else {
            warn(ctx, "Could not resolve shell rc file to update PATH.");
        }
    }
    let mut warned_missing_rc = false;
    let mut report = Vec::new();

    for target in required_path_targets(ctx) {
        let configured = dir_configured_in_rc(&target.dir, &rc_paths, home.as_deref());
        let labeled = label_configured_in_rc(target.label, &rc_paths);
        let mut updated = false;
        if (!configured || !labeled) && can_update {
            if let Some(rc_path) = primary_rc.as_ref() {
                updated = update_path_hint_in_rc(ctx, rc_path, &shell, &target.dir, target.label);
            } else if !warned_missing_rc {
                warn(ctx, "Could not resolve shell rc file to update PATH.");
                warned_missing_rc = true;
            }
        }
        report.push(PathCheckEntry {
            label: target.label.to_string(),
            dir: target.dir,
            configured,
            updated,
        });
    }

    report
}

pub fn remove_path_hint_for_label(ctx: &Ctx, label: &str) {
    if ctx.quiet {
        return;
    }
    let shell = get_env_var("SHELL").unwrap_or_default();
    let rc = shell_rc_path(&shell);
    let rc_path = match expand_tilde(rc) {
        Some(p) => p,
        None => {
            warn(ctx, "Could not resolve shell rc file to update PATH.");
            return;
        }
    };
    let content = match fs::read_to_string(&rc_path) {
        Ok(content) => content,
        Err(_) => return,
    };

    let label_line = format!("# upkit ({label})");
    let mut changed = false;
    let mut output = String::with_capacity(content.len());
    let mut iter = content.split_inclusive('\n').peekable();
    while let Some(line) = iter.next() {
        if line.trim_end() == label_line {
            changed = true;
            if let Some(next_line) = iter.peek() {
                let trimmed = next_line.trim_start();
                if trimmed.starts_with("export PATH=") || trimmed.starts_with("set -gx PATH") {
                    iter.next();
                }
            }
            #[cfg(coverage)]
            {
                let _ = line;
            }
            continue;
        }
        output.push_str(line);
    }

    if !changed {
        return;
    }
    write_path_hint(ctx, &rc_path, output, Some(&content));
}

fn path_hint_line(shell: &str, dir: &Path) -> Option<String> {
    let path = dir.to_str()?;
    if shell.ends_with("fish") {
        let escaped = path.replace('\\', "\\\\").replace('\'', "\\'");
        Some(format!("set -gx PATH '{escaped}' $PATH"))
    } else {
        let escaped = path
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$")
            .replace('`', "\\`");
        Some(format!("export PATH=\"{escaped}:$PATH\""))
    }
}

fn required_path_targets(ctx: &Ctx) -> Vec<PathTarget> {
    let mut targets: Vec<PathTarget> = Vec::new();
    let cargo_dir = cargo_bin_dir();
    fn push_target(targets: &mut Vec<PathTarget>, label: &'static str, dir: PathBuf) {
        if !targets.iter().any(|target| target.dir == dir) {
            targets.push(PathTarget { label, dir });
        }
    }
    targets.push(PathTarget {
        label: "upkit bin",
        dir: ctx.bindir.clone(),
    });
    if !upkit_installed_via_npm()
        && let Some(dir) = upkit_exe_dir()
    {
        let matches_cargo = cargo_dir.as_ref() == Some(&dir);
        let upkit_dir = if is_dev_exe_dir(&dir) {
            ctx.bindir.clone()
        } else {
            dir
        };
        if !matches_cargo
            && !path_contains_dir(&upkit_dir)
            && !targets.iter().any(|target| target.dir == upkit_dir)
        {
            push_target(&mut targets, "upkit exe", upkit_dir);
        }
    }
    if let Some(dir) = cargo_dir {
        push_target(&mut targets, "cargo bin", dir);
    }
    if let Some(dir) = npm_global_bin_dir(ctx) {
        push_target(&mut targets, "npm global bin", dir);
    }
    if let Some(home) = home_dir() {
        push_target(&mut targets, "local bin", home.join(".local").join("bin"));
    }
    if let Some(base) = python_user_base_dir() {
        let (label, child) = if ctx.os == "windows" {
            ("python user base scripts", "Scripts")
        } else {
            ("python user base bin", "bin")
        };
        push_target(&mut targets, label, base.join(child));
    }
    if let Some(dir) = flutter_bin_dir(ctx) {
        push_target(&mut targets, "flutter bin", dir);
    }
    if let Some(pub_cache) = pub_cache_dir() {
        push_target(&mut targets, "pub cache bin", pub_cache.join("bin"));
    }
    if let Some(gobin) = go_env_value("GOBIN") {
        push_target(&mut targets, "go GOBIN", PathBuf::from(gobin));
    } else {
        for gopath in go_env_paths("GOPATH") {
            push_target(&mut targets, "go GOPATH/bin", gopath.join("bin"));
        }
    }
    targets
}

fn upkit_installed_via_npm() -> bool {
    matches!(get_env_var("UPKIT_INSTALLER").as_deref(), Some("npm"))
}

fn is_dev_exe_dir(dir: &Path) -> bool {
    dir.components()
        .any(|component| component.as_os_str() == "target")
}

fn shell_rc_path(shell: &str) -> &'static str {
    if shell.ends_with("zsh") {
        "~/.zshrc"
    } else if shell.ends_with("fish") {
        "~/.config/fish/config.fish"
    } else if shell.ends_with("bash") {
        "~/.bashrc"
    } else {
        "~/.profile"
    }
}

fn upkit_exe_dir() -> Option<PathBuf> {
    let exe = env::current_exe().ok()?;
    exe.parent().map(|parent| parent.to_path_buf())
}

fn path_contains_dir(dir: &Path) -> bool {
    let path = get_env_var("PATH").unwrap_or_default();
    env::split_paths(&path).any(|p| p == dir)
}

fn shell_rc_candidates(shell: &str) -> Vec<&'static str> {
    if shell.ends_with("zsh") {
        vec!["~/.zshrc", "~/.zprofile"]
    } else if shell.ends_with("fish") {
        vec!["~/.config/fish/config.fish"]
    } else if shell.ends_with("bash") {
        vec!["~/.bashrc", "~/.bash_profile", "~/.profile"]
    } else {
        vec!["~/.profile"]
    }
}

fn resolve_shell_rc_paths(shell: &str) -> Vec<PathBuf> {
    shell_rc_candidates(shell)
        .into_iter()
        .filter_map(expand_tilde)
        .collect()
}

fn primary_shell_rc_path(rc_paths: &[PathBuf]) -> Option<PathBuf> {
    for path in rc_paths {
        if path.exists() {
            return Some(path.clone());
        }
    }
    rc_paths.first().cloned()
}

fn dir_configured_in_rc(dir: &Path, rc_paths: &[PathBuf], home: Option<&Path>) -> bool {
    if dir.to_str().is_none() {
        return false;
    }
    for rc_path in rc_paths {
        let Ok(content) = fs::read_to_string(rc_path) else {
            continue;
        };
        if rc_contains_dir(&content, dir, home) {
            return true;
        }
    }
    false
}

fn label_configured_in_rc(label: &str, rc_paths: &[PathBuf]) -> bool {
    let label_line = format!("# upkit ({label})");
    for rc_path in rc_paths {
        let Ok(content) = fs::read_to_string(rc_path) else {
            continue;
        };
        if content.lines().any(|line| line.trim_end() == label_line) {
            return true;
        }
    }
    false
}

fn rc_contains_dir(content: &str, dir: &Path, home: Option<&Path>) -> bool {
    let dir_str = dir.to_string_lossy();
    if content.contains(dir_str.as_ref()) {
        return true;
    }
    let Some(home) = home else {
        return false;
    };
    let Some((tilde, home_env, home_env_braced)) = home_relative_patterns(home, dir) else {
        return false;
    };
    content.contains(&tilde) || content.contains(&home_env) || content.contains(&home_env_braced)
}

fn home_relative_patterns(home: &Path, dir: &Path) -> Option<(String, String, String)> {
    let rel = dir.strip_prefix(home).ok()?;
    let rel_str = rel.to_string_lossy();
    let suffix = if rel_str.is_empty() {
        "".to_string()
    } else {
        format!("/{}", rel_str)
    };
    Some((
        format!("~{suffix}"),
        format!("$HOME{suffix}"),
        format!("${{HOME}}{suffix}"),
    ))
}

fn line_contains_dir(line: &str, dir: &Path, home: Option<&Path>) -> bool {
    if dir.to_str().is_none() {
        return false;
    }
    let dir_str = dir.to_string_lossy();
    if line.contains(dir_str.as_ref()) {
        return true;
    }
    let Some(home) = home else {
        return false;
    };
    let Some((tilde, home_env, home_env_braced)) = home_relative_patterns(home, dir) else {
        return false;
    };
    line.contains(&tilde) || line.contains(&home_env) || line.contains(&home_env_braced)
}

fn find_existing_path_line(lines: &[String], dir: &Path, home: Option<&Path>) -> Option<usize> {
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if (trimmed.starts_with("export PATH=") || trimmed.starts_with("set -gx PATH"))
            && line_contains_dir(trimmed, dir, home)
        {
            return Some(index);
        }
    }
    None
}

fn insert_path_after_labels(content: &str, label: &str, path: &str) -> (String, bool, bool) {
    let mut output = String::with_capacity(content.len() + label.len() + path.len() + 4);
    let mut lines = content.split_inclusive('\n').peekable();
    let mut found = false;
    let mut changed = false;
    while let Some(line) = lines.next() {
        output.push_str(line);
        if line.trim_end() != label {
            continue;
        }
        found = true;
        if lines.peek().is_some_and(|next| next.trim_end() == path) {
            output.push_str(lines.next().unwrap());
            continue;
        }
        let newline = if line.ends_with("\r\n") { "\r\n" } else { "\n" };
        if !line.ends_with('\n') {
            output.push_str(newline);
        }
        output.push_str(path);
        output.push_str(newline);
        changed = true;
    }
    (output, found, changed)
}

fn append_path_hint(content: &mut String, label: &str, path: &str) {
    let newline = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    if !content.is_empty() {
        if !content.ends_with('\n') {
            content.push_str(newline);
        }
        content.push_str(newline);
    }
    content.push_str(label);
    content.push_str(newline);
    content.push_str(path);
    content.push_str(newline);
}

fn update_path_hint_in_rc(ctx: &Ctx, rc_path: &Path, shell: &str, dir: &Path, label: &str) -> bool {
    let label_line = format!("# upkit ({label})");
    let Some(path_line) = path_hint_line(shell, dir) else {
        warn(
            ctx,
            "Cannot write a non-Unicode path to shell configuration; add it manually.",
        );
        return false;
    };
    let existing = match fs::read_to_string(rc_path) {
        Ok(content) => Some(content),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => {
            warn(ctx, format!("Failed to read shell configuration: {err}"));
            return false;
        }
    };
    let (mut output, found_label, mut updated) = insert_path_after_labels(
        existing.as_deref().unwrap_or_default(),
        &label_line,
        &path_line,
    );

    if !found_label {
        let home = home_dir();
        let lines = output
            .split_inclusive('\n')
            .map(str::to_string)
            .collect::<Vec<_>>();
        if let Some(index) = find_existing_path_line(&lines, dir, home.as_deref()) {
            let offset = lines[..index].iter().map(String::len).sum();
            let newline = if lines[index].ends_with("\r\n") {
                "\r\n"
            } else {
                "\n"
            };
            output.insert_str(offset, &format!("{label_line}{newline}"));
            updated = true;
        } else {
            append_path_hint(&mut output, &label_line, &path_line);
            updated = true;
        }
    }

    if !updated {
        return false;
    }

    write_path_hint(ctx, rc_path, output, existing.as_deref())
}

#[cfg(target_os = "linux")]
fn write_path_hint(ctx: &Ctx, rc_path: &Path, output: String, expected: Option<&str>) -> bool {
    use std::os::unix::fs::MetadataExt;

    let no_xattrs = |file: &fs::File| -> io::Result<bool> {
        let mut buffer = [0u8; 1];
        rustix::fs::flistxattr(file, &mut buffer[..])
            .map(|names| names == 0)
            .map_err(io::Error::from)
    };
    let result = (|| -> io::Result<()> {
        let previous = match fs::symlink_metadata(rc_path) {
            Ok(meta) => {
                if !meta.is_file()
                    || meta.file_type().is_symlink()
                    || meta.nlink() != 1
                    || meta.uid() != rustix::process::geteuid().as_raw()
                {
                    return Err(io::Error::other(
                        "shell configuration is linked, non-regular, or owned by another user",
                    ));
                }
                let opened = fs::File::open(rc_path)?;
                let opened_meta = opened.metadata()?;
                if opened_meta.dev() != meta.dev()
                    || opened_meta.ino() != meta.ino()
                    || !no_xattrs(&opened)?
                {
                    return Err(io::Error::other(
                        "shell configuration metadata cannot be preserved",
                    ));
                }
                Some((meta, opened))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
        let parent = rc_path
            .parent()
            .ok_or_else(|| io::Error::other("missing parent directory"))?;
        let parent_meta = fs::symlink_metadata(parent)?;
        if !parent_meta.is_dir()
            || parent_meta.file_type().is_symlink()
            || parent_meta.uid() != rustix::process::geteuid().as_raw()
            || parent_meta.mode() & 0o022 != 0
        {
            return Err(io::Error::other(
                "shell configuration directory is linked, not user-owned, or writable by others",
            ));
        }
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        write_all_checked(temp.as_file_mut(), output.as_bytes())?;
        if let Some((meta, _)) = &previous {
            if temp.as_file().metadata()?.gid() != meta.gid() || !no_xattrs(temp.as_file())? {
                return Err(io::Error::other(
                    "shell configuration metadata cannot be preserved",
                ));
            }
            temp.as_file().set_permissions(meta.permissions())?;
        }
        match expected {
            Some(expected) => {
                let current = fs::symlink_metadata(rc_path)?;
                if !current.is_file()
                    || current.file_type().is_symlink()
                    || previous.as_ref().is_none_or(|(meta, _)| {
                        current.dev() != meta.dev()
                            || current.ino() != meta.ino()
                            || current.mode() != meta.mode()
                            || current.uid() != meta.uid()
                            || current.gid() != meta.gid()
                            || current.nlink() != meta.nlink()
                    })
                    || fs::read(rc_path)? != expected.as_bytes()
                {
                    return Err(io::Error::other(
                        "shell configuration changed during update",
                    ));
                }
                if let Some((_, opened)) = &previous
                    && !no_xattrs(opened)?
                {
                    return Err(io::Error::other(
                        "shell configuration metadata changed during update",
                    ));
                }
            }
            None => match fs::symlink_metadata(rc_path) {
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
                Ok(_) => {
                    return Err(io::Error::other(
                        "shell configuration appeared during update",
                    ));
                }
            },
        }
        persist_path_hint(temp, rc_path, expected.is_some())?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            info(
                ctx,
                format!(
                    "PATH updated in {} (restart shell to apply).",
                    rc_path.display()
                ),
            );
            true
        }
        Err(err) => {
            warn(
                ctx,
                format!("Failed to update PATH in {}: {err}", rc_path.display()),
            );
            false
        }
    }
}

#[cfg(target_os = "linux")]
fn persist_path_hint(temp: tempfile::NamedTempFile, path: &Path, existed: bool) -> io::Result<()> {
    if existed {
        temp.persist(path).map_err(|err| err.error)?;
    } else {
        temp.persist_noclobber(path).map_err(|err| err.error)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn write_path_hint(ctx: &Ctx, rc_path: &Path, output: String, _expected: Option<&str>) -> bool {
    let result = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(rc_path)
        .and_then(|mut file| write_all_checked(&mut file, output.as_bytes()));
    match result {
        Ok(()) => {
            info(
                ctx,
                format!(
                    "PATH updated in {} (restart shell to apply).",
                    rc_path.display()
                ),
            );
            true
        }
        Err(err) => {
            warn(
                ctx,
                format!("Failed to update PATH in {}: {err}", rc_path.display()),
            );
            false
        }
    }
}

fn cargo_bin_dir() -> Option<PathBuf> {
    let cargo_home = get_env_var("CARGO_HOME")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".cargo")))?;
    Some(cargo_home.join("bin"))
}

fn npm_global_bin_dir(ctx: &Ctx) -> Option<PathBuf> {
    let program = npm_program_for_paths(ctx)?;
    let program = program.to_string_lossy().to_string();
    let bin_output = run_capture(program.clone(), &["bin".to_string(), "-g".to_string()]).ok();
    if let Some(path) = normalize_path_output(bin_output) {
        return Some(PathBuf::from(path));
    }
    let prefix_output = run_capture(
        program.clone(),
        &[
            "config".to_string(),
            "get".to_string(),
            "prefix".to_string(),
        ],
    )
    .ok();
    if let Some(prefix) = normalize_path_output(prefix_output) {
        return Some(PathBuf::from(prefix).join("bin"));
    }
    let prefix_output = run_capture(program, &["prefix".to_string(), "-g".to_string()]).ok();
    normalize_path_output(prefix_output).map(|prefix| PathBuf::from(prefix).join("bin"))
}

fn normalize_path_output(output: Option<String>) -> Option<String> {
    let trimmed = output?.trim().to_string();
    if trimmed.is_empty() || trimmed == "undefined" || trimmed == "null" {
        return None;
    }
    Some(trimmed)
}

fn npm_program_for_paths(ctx: &Ctx) -> Option<PathBuf> {
    let bindir_npm = ctx.bindir.join("npm");
    if bindir_npm.exists() {
        return Some(bindir_npm);
    }
    let active_npm = ctx.home.join("node").join("active").join("bin").join("npm");
    if active_npm.exists() {
        return Some(active_npm);
    }
    which_or_none("npm")
}

fn python_user_base_dir() -> Option<PathBuf> {
    if let Some(base) = get_env_var("PYTHONUSERBASE").filter(|value| !value.trim().is_empty()) {
        return Some(PathBuf::from(base));
    }
    if which_or_none("python3").is_some()
        && let Some(base) = python_user_base_from("python3")
    {
        return Some(base);
    }
    if which_or_none("python").is_some()
        && let Some(base) = python_user_base_from("python")
    {
        return Some(base);
    }
    home_dir().map(|home| home.join(".local"))
}

fn python_user_base_from(program: &str) -> Option<PathBuf> {
    let output = run_capture(program, &["-m", "site", "--user-base"]).ok()?;
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(PathBuf::from(trimmed))
}

fn go_env_value(key: &str) -> Option<String> {
    if let Some(value) = get_env_var(key) {
        let value = value.trim().to_string();
        if !value.is_empty() {
            return Some(value);
        }
    }
    which_or_none("go")?;
    run_capture("go", &["env", key])
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn go_env_paths(key: &str) -> Vec<PathBuf> {
    if let Some(value) = go_env_value(key) {
        return env::split_paths(&value).collect();
    }
    if key == "GOPATH" {
        return default_gopath().into_iter().collect();
    }
    Vec::new()
}

fn default_gopath() -> Option<PathBuf> {
    home_dir().map(|home| home.join("go"))
}

fn flutter_bin_dir(ctx: &Ctx) -> Option<PathBuf> {
    let active_bin = ctx.home.join("flutter").join("active").join("bin");
    if active_bin.exists() {
        return Some(active_bin);
    }
    let bindir_flutter = ctx.bindir.join("flutter");
    if bindir_flutter.exists() {
        return Some(ctx.bindir.clone());
    }
    let flutter = which_or_none("flutter")?;
    flutter.parent().map(|parent| parent.to_path_buf())
}

fn pub_cache_dir() -> Option<PathBuf> {
    get_env_var("PUB_CACHE")
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".pub-cache")))
}

pub fn write_all_checked(writer: &mut dyn Write, bytes: &[u8]) -> io::Result<()> {
    if test_support::force_write_error() {
        return Err(io::Error::other("forced write error"));
    }
    writer.write_all(bytes)
}

pub fn colorize_status(ctx: &Ctx, status: Status, text: String) -> String {
    if !ctx.use_color {
        return text;
    }
    let code = match status {
        Status::UpToDate => 32,
        Status::Outdated => 33,
        Status::NotInstalled => 31,
        Status::Unknown => 90,
    };
    format!("\x1b[{}m{}\x1b[0m", code, text)
}

pub fn expand_tilde(path: &str) -> Option<PathBuf> {
    if let Some(stripped) = path.strip_prefix("~/") {
        let home = home_dir()?;
        return Some(home.join(stripped));
    }
    Some(PathBuf::from(path))
}

pub fn home_dir() -> Option<PathBuf> {
    if let Some(result) = test_support::home_dir_override() {
        return result;
    }
    dirs::home_dir()
}

pub fn data_local_dir() -> Option<PathBuf> {
    if let Some(result) = test_support::data_local_dir_override() {
        return result;
    }
    dirs::data_local_dir()
}

pub fn get_env_var(key: &str) -> Option<String> {
    if let Some(result) = test_support::env_var_override(key) {
        return result;
    }
    env::var(key).ok()
}

#[derive(Debug)]
pub enum ProgressHandle {
    Spinner(ProgressBar),
    Static,
}

static ACTIVE_SPINNER: OnceLock<Mutex<Option<ProgressBar>>> = OnceLock::new();

fn active_spinner() -> &'static Mutex<Option<ProgressBar>> {
    ACTIVE_SPINNER.get_or_init(|| Mutex::new(None))
}

fn register_active_spinner(pb: &ProgressBar) {
    *active_spinner().lock().unwrap() = Some(pb.clone());
}

fn clear_active_spinner() {
    if let Ok(mut guard) = active_spinner().lock() {
        *guard = None;
    }
}

fn with_spinner_suspended<F, T>(action: F) -> T
where
    F: FnOnce() -> T,
{
    let spinner = active_spinner().lock().unwrap().clone();
    match spinner {
        Some(pb) => pb.suspend(action),
        None => action(),
    }
}

fn spinner_template() -> String {
    if let Some(template) = test_support::spinner_template_override() {
        return template;
    }
    "{spinner} {msg}".to_string()
}

fn finish_template() -> String {
    if let Some(template) = test_support::finish_template_override() {
        return template;
    }
    "{spinner} {msg}".to_string()
}

#[cfg_attr(coverage, inline(never))]
pub fn start_spinner(ctx: &Ctx, msg: &str) -> Option<ProgressHandle> {
    if !progress_allowed(ctx) {
        return None;
    }
    if !progress_overwrite_allowed(ctx) {
        let output = format!("{msg}...");
        if !ctx.quiet && !ctx.json {
            eprintln!("{output}");
        }
        return Some(ProgressHandle::Static);
    }
    let pb = ProgressBar::new_spinner();
    pb.set_draw_target(ProgressDrawTarget::stderr());
    let template = spinner_template();
    let style = ProgressStyle::with_template(&template)
        .unwrap_or_else(|_| ProgressStyle::default_spinner());
    pb.set_style(style.tick_strings(&["-", "\\", "|", "/"]));
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    register_active_spinner(&pb);
    Some(ProgressHandle::Spinner(pb))
}

#[cfg_attr(coverage, inline(never))]
pub fn finish_spinner(pb: Option<ProgressHandle>, msg: &str) {
    if let Some(pb) = pb {
        let msg = if msg.to_lowercase().contains("failed") {
            format!("❌ {msg}")
        } else {
            format!("✅ {msg}")
        };
        match pb {
            ProgressHandle::Spinner(pb) => {
                let template = finish_template();
                let style = ProgressStyle::with_template(&template)
                    .unwrap_or_else(|_| ProgressStyle::default_spinner());
                pb.set_style(style);
                pb.finish_with_message(msg);
                clear_active_spinner();
            }
            ProgressHandle::Static => {}
        }
    }
}

pub fn progress_allowed(ctx: &Ctx) -> bool {
    !ctx.no_progress && !ctx.quiet && !ctx.json && ctx.stderr_is_tty
}

pub fn progress_overwrite_allowed(ctx: &Ctx) -> bool {
    progress_allowed(ctx) && ctx.progress_overwrite
}

pub fn reports_to_json(reports: &[ToolReport]) -> serde_json::Value {
    use serde_json::json;
    json!(
        reports
            .iter()
            .map(|r| {
                json!({
                    "tool": r.tool.as_str(),
                    "installed": r.installed.as_ref().map(|v| v.to_string()),
                    "latest": r.latest.as_ref().map(|v| v.to_string()),
                    "status": format!("{:?}", r.status),
                    "method": match &r.method {
                        UpdateMethod::BuiltIn => "built-in",
                        UpdateMethod::DirectDownload => "direct-download",
                    },
                    "notes": r.notes,
                })
            })
            .collect::<Vec<_>>()
    )
}

pub fn run_output<S: AsRef<OsStr>>(program: S, args: &[S]) -> Result<std::process::Output> {
    {
        let program_str = program.as_ref().to_string_lossy().to_string();
        let args_vec = args
            .iter()
            .map(|s| s.as_ref().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        if let Some(out) = test_support::take_run_output(&program_str, &args_vec) {
            return Ok(out);
        }
    }

    Command::new(&program)
        .args(args.iter().map(|s| s.as_ref()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("failed to run {:?}", program.as_ref()))
}

pub fn run_status<S: AsRef<OsStr>>(program: S, args: &[S]) -> Result<std::process::ExitStatus> {
    Ok(run_output(program, args)?.status)
}

pub fn run_capture<S: AsRef<OsStr> + Clone>(program: S, args: &[S]) -> Result<String> {
    let out = run_output(program.clone(), args)?;
    if !out.status.success() {
        bail!(
            "command {:?} failed: {}",
            program.as_ref(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub fn sleep_for(duration: Duration) {
    if test_support::record_sleep(duration) {
        return;
    }
    std::thread::sleep(duration);
}

pub fn which_or_none(bin: &str) -> Option<PathBuf> {
    if let Some(result) = test_support::which_override(bin) {
        return result;
    }
    which::which(bin).ok()
}

pub trait HttpResponse: Read {
    fn content_length(&self) -> Option<u64>;
}

pub enum MockAttempt {
    Handled(Option<Box<dyn HttpResponse>>),
    Skipped,
}

pub fn mock_http_attempt(
    url: &str,
    last_err: &mut Option<anyhow::Error>,
    require_mocking: bool,
) -> MockAttempt {
    if test_support::http_mocking_enabled() || test_support::http_allow_unknown_error() {
        if let Some(resp) = test_support::next_http_response(url) {
            match resp {
                Ok(r) => return MockAttempt::Handled(Some(r)),
                Err(err) => *last_err = Some(err),
            }
        } else if !test_support::http_allow_unknown_error() {
            *last_err = Some(anyhow!("no test response left"));
        }
        return MockAttempt::Handled(None);
    }
    if require_mocking {
        *last_err = Some(anyhow!(
            "http mocking disabled under coverage; set test responses"
        ));
        return MockAttempt::Handled(None);
    }
    MockAttempt::Skipped
}

#[cfg(not(coverage))]
struct ReqwestResponse {
    inner: reqwest::blocking::Response,
}

#[cfg(not(coverage))]
impl Read for ReqwestResponse {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

#[cfg(not(coverage))]
impl HttpResponse for ReqwestResponse {
    fn content_length(&self) -> Option<u64> {
        self.inner.content_length()
    }
}

#[cfg(not(coverage))]
fn handle_reqwest_response(
    resp: Result<reqwest::blocking::Response, reqwest::Error>,
    last_err: &mut Option<anyhow::Error>,
) -> Option<Box<dyn HttpResponse>> {
    match resp {
        Ok(r) => match r.error_for_status() {
            Ok(r) => Some(Box::new(ReqwestResponse { inner: r })),
            Err(err) => {
                *last_err = Some(err.into());
                None
            }
        },
        Err(err) => {
            *last_err = Some(err.into());
            None
        }
    }
}

#[cfg(coverage)]
pub fn http_get(ctx: &Ctx, url: &str) -> Result<Box<dyn HttpResponse>> {
    if ctx.offline {
        bail!("offline mode enabled");
    }
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..=ctx.retries {
        if let MockAttempt::Handled(Some(resp)) = mock_http_attempt(url, &mut last_err, true) {
            return Ok(resp);
        }
        if attempt < ctx.retries {
            let backoff = 250u64.saturating_mul(2u64.pow(attempt as u32));
            sleep_for(Duration::from_millis(backoff));
        }
    }
    Err(anyhow!(
        "request failed after {} attempt(s): {}",
        ctx.retries + 1,
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown".into())
    ))
}

#[cfg(not(coverage))]
pub fn http_get(ctx: &Ctx, url: &str) -> Result<Box<dyn HttpResponse>> {
    if ctx.offline {
        bail!("offline mode enabled");
    }
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..=ctx.retries {
        match mock_http_attempt(url, &mut last_err, false) {
            MockAttempt::Handled(Some(resp)) => return Ok(resp),
            MockAttempt::Handled(None) => {}
            MockAttempt::Skipped => {
                let resp = ctx.http.get(url).send();
                if let Some(resp) = handle_reqwest_response(resp, &mut last_err) {
                    return Ok(resp);
                }
            }
        }
        if attempt < ctx.retries {
            let backoff = 250u64.saturating_mul(2u64.pow(attempt as u32));
            sleep_for(Duration::from_millis(backoff));
        }
    }
    Err(anyhow!(
        "request failed after {} attempt(s): {}",
        ctx.retries + 1,
        last_err.unwrap_or_else(|| anyhow!("unknown error"))
    ))
}

#[cfg(coverage)]
pub fn http_get_no_timeout(ctx: &Ctx, url: &str) -> Result<Box<dyn HttpResponse>> {
    http_get(ctx, url)
}

#[cfg(not(coverage))]
pub fn http_get_no_timeout(ctx: &Ctx, url: &str) -> Result<Box<dyn HttpResponse>> {
    if ctx.offline {
        bail!("offline mode enabled");
    }
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..=ctx.retries {
        match mock_http_attempt(url, &mut last_err, false) {
            MockAttempt::Handled(Some(resp)) => return Ok(resp),
            MockAttempt::Handled(None) => {}
            MockAttempt::Skipped => {
                let long_timeout = ctx.timeout.saturating_mul(10).max(600);
                let resp = ctx
                    .http
                    .get(url)
                    .timeout(Duration::from_secs(long_timeout))
                    .send();
                if let Some(resp) = handle_reqwest_response(resp, &mut last_err) {
                    return Ok(resp);
                }
            }
        }
        if attempt < ctx.retries {
            let backoff = 250u64.saturating_mul(2u64.pow(attempt as u32));
            sleep_for(Duration::from_millis(backoff));
        }
    }
    Err(anyhow!(
        "request failed after {} attempt(s): {}",
        ctx.retries + 1,
        last_err.unwrap_or_else(|| anyhow!("unknown error"))
    ))
}

const MAX_METADATA_BYTES: u64 = 32 * 1024 * 1024;

fn http_get_metadata(ctx: &Ctx, url: &str, limit: u64) -> Result<Vec<u8>> {
    let resp = http_get(ctx, url)?;
    if resp.content_length().is_some_and(|length| length > limit) {
        bail!("metadata response exceeds the {limit}-byte limit");
    }
    let mut buf = Vec::new();
    resp.take(limit + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > limit {
        bail!("metadata response exceeds the {limit}-byte limit");
    }
    Ok(buf)
}

pub fn http_get_json<T: DeserializeOwned>(ctx: &Ctx, url: &str) -> Result<T> {
    let buf = http_get_metadata(ctx, url, MAX_METADATA_BYTES)?;
    Ok(serde_json::from_slice(&buf)?)
}

pub fn http_get_text(ctx: &Ctx, url: &str) -> Result<String> {
    let buf = http_get_metadata(ctx, url, MAX_METADATA_BYTES)?;
    Ok(String::from_utf8(buf)?)
}

pub(crate) fn sha256_file(path: &Path) -> Result<String> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 64];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

// shortcut: archives over 8 GiB are rejected; revisit if supported releases exceed this limit.
const MAX_TOOL_ARCHIVE_DOWNLOAD_BYTES: u64 = 8 * 1024 * 1024 * 1024;

fn copy_download_body(
    reader: &mut impl Read,
    writer: &mut impl Write,
    limit: u64,
    mut progress: impl FnMut(u64),
) -> Result<u64> {
    let mut downloaded = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let remaining = limit - downloaded;
        let read_limit = usize::try_from(remaining.saturating_add(1))
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let count = reader.read(&mut buffer[..read_limit])?;
        if count == 0 {
            return Ok(downloaded);
        }
        if count as u64 > remaining {
            bail!("download exceeds the {limit}-byte limit");
        }
        writer.write_all(&buffer[..count])?;
        downloaded += count as u64;
        progress(downloaded);
    }
}

pub fn download_to_temp(ctx: &Ctx, url: &str) -> Result<NamedTempFile> {
    download_to_temp_with_limit(ctx, url, MAX_TOOL_ARCHIVE_DOWNLOAD_BYTES)
}

fn download_to_temp_with_limit(ctx: &Ctx, url: &str, limit: u64) -> Result<NamedTempFile> {
    with_spinner_suspended(|| {
        let show_progress = progress_allowed(ctx);
        let mut resp = http_get_no_timeout(ctx, url)?;
        let total = resp.content_length();
        if total.is_some_and(|total| total > limit) {
            bail!("download exceeds the {limit}-byte limit");
        }
        let mut tmp = NamedTempFile::new()?;
        let downloaded_total = if show_progress && progress_overwrite_allowed(ctx) {
            if let Some(total) = total {
                let pb = ProgressBar::with_draw_target(
                    Some(total),
                    ProgressDrawTarget::stderr_with_hz(10),
                );
                pb.set_length(total);
                let style = ProgressStyle::with_template(
                    "[{bar:40.cyan/blue}] {percent:>3}% {bytes}/{total_bytes} {msg}",
                )?
                .progress_chars("=>-");
                #[cfg(coverage)]
                {
                    let _ = &style;
                }
                pb.set_style(style);
                pb.set_message(format!("Downloading {url}"));
                let downloaded =
                    copy_download_body(&mut resp, &mut tmp, limit, |bytes| pb.set_position(bytes))?;
                pb.finish_with_message("Downloaded");
                Some(downloaded)
            } else {
                let pb =
                    ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr_with_hz(10));
                pb.set_style(
                    ProgressStyle::with_template("{spinner} {msg}")?
                        .tick_strings(&["-", "\\", "|", "/"]),
                );
                pb.set_message(format!("Downloading {url}"));
                pb.enable_steady_tick(Duration::from_millis(80));
                let downloaded = copy_download_body(&mut resp, &mut tmp, limit, |_| {})?;
                pb.finish_with_message("Downloaded");
                Some(downloaded)
            }
        } else if show_progress {
            if let Some(total) = total {
                info(ctx, format!("Downloading {url} [0%]"));
                let downloaded = copy_download_body(&mut resp, &mut tmp, limit, |_| {})?;
                if downloaded >= total {
                    info(ctx, format!("Downloading {url} [100%]"));
                } else {
                    let pct = (downloaded.saturating_mul(100) / total).min(100);
                    info(ctx, format!("Downloading {url} [{pct}%]"));
                }
                Some(downloaded)
            } else {
                info(ctx, format!("Downloading {url}"));
                Some(copy_download_body(&mut resp, &mut tmp, limit, |_| {})?)
            }
        } else {
            Some(copy_download_body(&mut resp, &mut tmp, limit, |_| {})?)
        };

        if let (Some(total), Some(downloaded)) = (total, downloaded_total)
            && downloaded < total
        {
            bail!("download incomplete for {url}: expected {total} bytes, got {downloaded}");
        }
        Ok(tmp)
    })
}

#[cfg(test)]
mod download_limit_tests {
    use super::*;
    use crate::test_support::{
        MockResponse, TestPrompt, base_ctx, reset_guard, set_env_var, set_home_dir, set_http_plan,
    };

    #[test]
    fn metadata_limits_reported_and_actual_body_lengths() {
        let _guard = reset_guard();
        let dir = tempfile::tempdir().unwrap();
        let ctx = base_ctx(
            dir.path().join("home"),
            dir.path().join("bin"),
            Arc::new(TestPrompt::default()),
        );
        let url = "https://example.invalid/metadata";
        for header in [Some(9), Some(8), None] {
            set_http_plan(url, vec![Ok(MockResponse::new(vec![b'x'; 9], header))]);
            assert!(
                http_get_metadata(&ctx, url, 8)
                    .unwrap_err()
                    .to_string()
                    .contains("8-byte limit")
            );
        }
        set_http_plan(url, vec![Ok(MockResponse::new(b"12345678".to_vec(), None))]);
        assert_eq!(http_get_metadata(&ctx, url, 8).unwrap(), b"12345678");

        for json in [true, false] {
            set_http_plan(
                url,
                vec![Ok(MockResponse::new(
                    Vec::new(),
                    Some(MAX_METADATA_BYTES + 1),
                ))],
            );
            let result = if json {
                http_get_json::<serde_json::Value>(&ctx, url).map(|_| ())
            } else {
                http_get_text(&ctx, url).map(|_| ())
            };
            assert!(result.unwrap_err().to_string().contains("byte limit"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn path_fix_never_uses_a_lossy_non_unicode_directory() {
        use std::os::unix::ffi::OsStringExt;

        let _guard = reset_guard();
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join("profile");
        fs::write(&rc, "# preserve\n").unwrap();
        let bin = dir
            .path()
            .join(std::ffi::OsString::from_vec(b"bin-\xff".to_vec()));
        let ctx = base_ctx(
            dir.path().join("home"),
            bin.clone(),
            Arc::new(TestPrompt::default()),
        );
        assert!(!update_path_hint_in_rc(&ctx, &rc, "bash", &bin, "fixture"));
        assert_eq!(fs::read_to_string(&rc).unwrap(), "# preserve\n");
        fs::write(
            &rc,
            format!("export PATH=\"{}:$PATH\"\n", bin.to_string_lossy()),
        )
        .unwrap();
        assert!(!dir_configured_in_rc(&bin, &[rc], None));
    }

    #[test]
    fn path_hint_insertions_preserve_existing_line_endings_and_unterminated_text() {
        let original = "# keep\r\n# upkit (fixture)\r\nalias x='keep'\nlast line";
        let label = "# upkit (fixture)";
        let entry = "export PATH=\"/fixture:$PATH\"";
        let (updated, found, changed) = insert_path_after_labels(original, label, entry);
        assert!(found && changed);
        assert_eq!(
            updated,
            "# keep\r\n# upkit (fixture)\r\nexport PATH=\"/fixture:$PATH\"\r\nalias x='keep'\nlast line"
        );
        let (again, found, changed) = insert_path_after_labels(&updated, label, entry);
        assert!(found && !changed);
        assert_eq!(again, updated);

        let mut appended = "line with no newline".to_string();
        append_path_hint(&mut appended, label, entry);
        assert!(appended.starts_with("line with no newline\n\n"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn path_hint_label_insertion_preserves_existing_profile_bytes() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = reset_guard();
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let rc = dir.path().join("profile");
        let ctx = base_ctx(
            dir.path().join("home"),
            dir.path().join("bin"),
            Arc::new(TestPrompt::default()),
        );
        let original = "# keep\r\nexport PATH=\"/fixture/bin:$PATH\"\r\nlast line";
        fs::write(&rc, original).unwrap();
        assert!(update_path_hint_in_rc(
            &ctx,
            &rc,
            "bash",
            Path::new("/fixture/bin"),
            "fixture"
        ));
        assert_eq!(
            fs::read_to_string(rc).unwrap(),
            "# keep\r\n# upkit (fixture)\r\nexport PATH=\"/fixture/bin:$PATH\"\r\nlast line"
        );
    }

    #[test]
    fn required_path_inspection_respects_no_path_update() {
        let _guard = reset_guard();
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".bashrc");
        fs::write(&rc, "# existing configuration\n").unwrap();
        set_home_dir(Some(dir.path().to_path_buf()));
        set_env_var("SHELL", Some("bash".into()));
        set_env_var("PATH", Some("/usr/bin".into()));
        set_env_var("UPKIT_NO_PATH_UPDATE", Some("1".into()));
        let ctx = base_ctx(
            dir.path().join("upkit"),
            dir.path().join("bin"),
            Arc::new(TestPrompt::default()),
        );
        let entries = ensure_required_paths(&ctx);
        assert!(entries.iter().all(|entry| !entry.updated));
        assert_eq!(
            fs::read_to_string(rc).unwrap(),
            "# existing configuration\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn path_update_refuses_stale_or_newly_created_configuration() {
        let _guard = reset_guard();
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join("profile");
        let ctx = base_ctx(
            dir.path().join("home"),
            dir.path().join("bin"),
            Arc::new(TestPrompt::default()),
        );
        fs::write(&rc, "newer content\n").unwrap();
        assert!(!write_path_hint(
            &ctx,
            &rc,
            "replacement\n".into(),
            Some("older content\n")
        ));
        assert_eq!(fs::read_to_string(&rc).unwrap(), "newer content\n");
        assert!(!write_path_hint(&ctx, &rc, "replacement\n".into(), None));
        assert_eq!(fs::read_to_string(&rc).unwrap(), "newer content\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn path_update_does_not_replace_a_file_created_during_staging() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join("profile");
        let mut temp = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        writeln!(temp, "new PATH entry").unwrap();
        fs::write(&rc, "concurrent contents\n").unwrap();
        assert_eq!(
            persist_path_hint(temp, &rc, false).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read_to_string(rc).unwrap(), "concurrent contents\n");
    }

    #[test]
    fn bounded_download_rejects_oversized_bodies_with_and_without_lengths() {
        let _guard = reset_guard();
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = base_ctx(
            dir.path().join("home"),
            dir.path().join("bin"),
            Arc::new(TestPrompt::default()),
        );
        let url = "https://example.invalid/archive";
        for (overwrite, progress, header) in [
            (true, true, Some(9)),
            (true, true, Some(8)),
            (true, true, None),
            (false, true, Some(8)),
            (false, true, None),
            (false, false, None),
        ] {
            ctx.progress_overwrite = overwrite;
            ctx.no_progress = !progress;
            set_http_plan(url, vec![Ok(MockResponse::new(vec![1; 9], header))]);
            let error = download_to_temp_with_limit(&ctx, url, 8).unwrap_err();
            assert!(error.to_string().contains("8-byte limit"));
        }
        set_http_plan(url, vec![Ok(MockResponse::new(vec![2; 8], None))]);
        let file = download_to_temp_with_limit(&ctx, url, 8).unwrap();
        assert_eq!(fs::read(file.path()).unwrap(), vec![2; 8]);

        struct Chunks<'a>(&'a [u8]);
        impl Read for Chunks<'_> {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                let count = output.len().min(self.0.len()).min(3);
                output[..count].copy_from_slice(&self.0[..count]);
                self.0 = &self.0[count..];
                Ok(count)
            }
        }
        let mut output = Vec::new();
        let error =
            copy_download_body(&mut Chunks(b"123456789"), &mut output, 8, |_| {}).unwrap_err();
        assert!(error.to_string().contains("8-byte limit"));
        assert_eq!(output, b"123456");
    }
}

pub fn ensure_clean_dir(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(_) => bail!(
            "refusing to replace existing installation path: {}",
            dir.display()
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("inspect {}", dir.display())),
    }
    fs::create_dir(dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(())
}

pub(crate) fn ensure_directory_tree(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // New Upkit roots must not be writable by the group or other users; the umask still applies.
        builder.mode(0o755);
    }
    builder
        .create(dir)
        .with_context(|| format!("create directory tree {}", dir.display()))
}

pub(crate) fn ensure_tool_root(tool_root: &Path) -> Result<()> {
    ensure_directory_tree(tool_root)
        .with_context(|| format!("create tool root {}", tool_root.display()))
}

#[cfg(all(test, unix))]
mod tool_root_tests {
    use super::{ensure_directory_tree, ensure_tool_root};
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn new_tool_root_is_not_group_writable_and_existing_mode_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("new/tool");
        ensure_tool_root(&root).unwrap();
        assert_eq!(fs::metadata(&root).unwrap().permissions().mode() & 0o022, 0);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o775)).unwrap();
        ensure_tool_root(&root).unwrap();
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o775
        );
    }

    #[test]
    fn new_directory_tree_is_not_group_writable_and_existing_modes_are_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let existing_parent = dir.path().join("existing");
        fs::create_dir(&existing_parent).unwrap();
        fs::set_permissions(&existing_parent, fs::Permissions::from_mode(0o775)).unwrap();
        let requested = existing_parent.join("new/nested/bin");

        ensure_directory_tree(&requested).unwrap();

        assert_eq!(
            fs::metadata(&existing_parent).unwrap().permissions().mode() & 0o777,
            0o775
        );
        for path in [
            existing_parent.join("new"),
            existing_parent.join("new/nested"),
            requested,
        ] {
            assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o022, 0);
        }

        ensure_directory_tree(&existing_parent).unwrap();
        assert_eq!(
            fs::metadata(existing_parent).unwrap().permissions().mode() & 0o777,
            0o775
        );
    }
}

pub(crate) fn new_install_stage(tool_root: &Path) -> Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("install-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    Ok(builder.tempdir_in(tool_root)?)
}

pub fn prune_tool_versions(tool_root: &Path, keep_dir: &Path, keep_names: &[&str]) -> Result<()> {
    if let Some(err) = test_support::prune_tool_versions_error() {
        bail!(err);
    }
    if !tool_root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(tool_root)? {
        let entry = entry?;
        let path = entry.path();
        if path == keep_dir {
            continue;
        }
        #[cfg(unix)]
        if path.file_name()
            == Some(std::ffi::OsStr::new(
                crate::installation_identity::LINK_RECEIPTS,
            ))
        {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            if keep_names.iter().any(|keep| keep == &name) {
                continue;
            }
            #[cfg(coverage)]
            {
                let _ = name;
            }
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        // shortcut: old versions lack verified identity, restore pruning after safe migration and confirmation.
        bail!(
            "automatic removal of old directories is unavailable until installation identity and cleanup safeguards are verified: {}",
            path.display()
        );
    }
    Ok(())
}

pub fn atomic_symlink(target: &Path, link: &Path) -> Result<()> {
    let replacing = match fs::symlink_metadata(link) {
        Ok(meta) if !meta.file_type().is_symlink() => {
            bail!("refusing to replace non-symlink path: {}", link.display());
        }
        Ok(_) => true,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => return Err(err).with_context(|| format!("inspect {}", link.display())),
    };
    let parent = link
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temp = tempfile::Builder::new()
        .prefix(".upkit-link-")
        .tempdir_in(parent)?;
    let tmp_link = temp.path().join("link");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(target, &tmp_link)?;
        install_link(&tmp_link, link, replacing)?;
        Ok(())
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::{symlink_dir, symlink_file};
        let metadata = fs::metadata(target)
            .with_context(|| format!("inspect symlink target {}", target.display()))?;
        if metadata.is_dir() {
            symlink_dir(target, &tmp_link).context("create temporary directory symlink")?;
        } else if metadata.is_file() {
            symlink_file(target, &tmp_link).context("create temporary file symlink")?;
        } else {
            bail!(
                "symlink target is not a regular file or directory: {}",
                target.display()
            );
        }
        install_link(&tmp_link, link, replacing).context("install Windows symlink")?;
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod windows_link_tests {
    use super::*;

    #[test]
    fn windows_links_preserve_file_and_directory_types() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tool.exe");
        let folder = dir.path().join("tool");
        let file_link = dir.path().join("tool-link.exe");
        let folder_link = dir.path().join("tool-link");
        fs::write(&file, b"fixture").unwrap();
        fs::create_dir(&folder).unwrap();
        if let Err(err) = atomic_symlink(&file, &file_link) {
            if err.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.raw_os_error() == Some(1314))
            }) {
                eprintln!("symlink privilege unavailable; Windows link test skipped");
                return;
            }
            panic!("create file symlink: {err:#}");
        }
        atomic_symlink(&folder, &folder_link).unwrap();
        assert!(fs::metadata(&file_link).unwrap().is_file());
        assert_eq!(fs::read(&file_link).unwrap(), b"fixture");
        assert!(fs::metadata(&folder_link).unwrap().is_dir());
        assert_eq!(fs::read_link(&file_link).unwrap(), file);
        assert_eq!(fs::read_link(&folder_link).unwrap(), folder);
    }
}

fn install_link(source: &Path, destination: &Path, replacing: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    if !replacing {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            source,
            rustix::fs::CWD,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .context("install new link without replacing an existing path")?;
        return Ok(());
    }
    #[cfg(not(target_os = "linux"))]
    let _ = replacing;
    fs::rename(source, destination)?;
    Ok(())
}

pub(crate) fn validate_active_install(tool_root: &Path) -> Result<()> {
    match fs::symlink_metadata(tool_root) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("inspect {}", tool_root.display())),
        Ok(meta) => {
            if !meta.is_dir() || meta.file_type().is_symlink() {
                bail!(
                    "refusing linked or non-directory tool root: {}",
                    tool_root.display()
                );
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if meta.file_attributes() & 0x400 != 0 {
                    bail!("refusing reparse-point tool root: {}", tool_root.display());
                }
            }
        }
    }
    let active = tool_root.join("active");
    match fs::symlink_metadata(&active) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("inspect {}", active.display())),
        Ok(meta) if !meta.file_type().is_symlink() => bail!(
            "refusing to replace non-symlink active path: {}",
            active.display()
        ),
        Ok(_) => {}
    }
    let root = tool_root.canonicalize().context("resolve tool root")?;
    let resolved = active
        .canonicalize()
        .context("resolve existing active installation")?;
    if resolved == root || !resolved.starts_with(&root) || !resolved.is_dir() {
        bail!(
            "refusing to replace active link outside the tool root: {}",
            active.display()
        );
    }
    Ok(())
}

pub(crate) fn activate_install(tool_root: &Path, target: &Path) -> Result<()> {
    validate_active_install(tool_root)?;
    let root = tool_root.canonicalize().context("resolve tool root")?;
    let target = target
        .canonicalize()
        .context("resolve staged installation")?;
    if target == root || !target.starts_with(&root) || !target.is_dir() {
        bail!("staged installation is outside the tool root");
    }
    atomic_symlink(&target, &tool_root.join("active"))
}

pub(crate) fn activate_managed_install(
    ctx: &Ctx,
    tool_root: &Path,
    target: &Path,
    tool: ToolKind,
) -> Result<()> {
    activate_install(tool_root, target)?;
    #[cfg(unix)]
    {
        // A receipt failure must not turn a successful activation into a failed update.
        if let Err(err) =
            crate::installation_identity::record_active_link(tool_root, &ctx.bindir, tool)
        {
            warn(
                ctx,
                format!(
                    "Managed cleanup will preserve the active {} link because its identity could not be recorded: {err}",
                    tool.as_str()
                ),
            );
        }
    }
    #[cfg(not(unix))]
    let _ = (ctx, tool);
    Ok(())
}

pub(crate) fn seal_managed_install(
    ctx: &Ctx,
    tool_root: &Path,
    stage: &tempfile::TempDir,
    tool: ToolKind,
    version: &str,
) {
    #[cfg(unix)]
    if let Err(err) = crate::installation_identity::seal(tool_root, stage, tool, version) {
        warn(
            ctx,
            format!(
                "This {} install is not eligible for managed cleanup: {err}",
                tool.as_str()
            ),
        );
    }
    #[cfg(not(unix))]
    let _ = (ctx, tool_root, stage, tool, version);
}

pub(crate) fn preflight_bin_links(
    source: Option<&Path>,
    target: &Path,
    bindir: &Path,
    names: &[&str],
) -> Result<()> {
    if !fs::metadata(bindir).is_ok_and(|meta| meta.is_dir()) {
        bail!(
            "symlink destination is not an accessible directory: {}",
            bindir.display()
        );
    }
    for &name in names {
        if source.is_some_and(|source| !source.join(name).exists()) {
            continue;
        }
        let dst = bindir.join(name);
        match fs::symlink_metadata(&dst) {
            Ok(meta)
                if meta.file_type().is_symlink()
                    && fs::read_link(&dst).is_ok_and(|existing| existing == target.join(name)) => {}
            Ok(_) => bail!(
                "refusing to replace an unrelated binary path: {}",
                dst.display()
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).with_context(|| format!("inspect {}", dst.display())),
        }
    }
    Ok(())
}

pub fn link_dir_bins(bin_dir: &Path, bindir: &Path, names: &[&str]) -> Result<()> {
    link_dir_bins_created(bin_dir, bindir, names).map(|_| ())
}

pub(crate) fn link_managed_tool_bins(
    ctx: &Ctx,
    tool_root: &Path,
    tool: ToolKind,
    bin_dir: &Path,
    bindir: &Path,
    names: &[&str],
) -> Result<()> {
    let created = link_dir_bins_created(bin_dir, bindir, names)?;
    #[cfg(unix)]
    {
        // Matching pre-existing symlinks are not recorded or adopted.
        if let Err(err) =
            crate::installation_identity::record_created_links(tool_root, bindir, tool, &created)
        {
            warn(
                ctx,
                format!(
                    "Managed cleanup will preserve unrecorded {} binary links: {err}",
                    tool.as_str()
                ),
            );
        }
    }
    #[cfg(not(unix))]
    let _ = (ctx, tool_root, tool, created);
    Ok(())
}

fn link_dir_bins_created(
    bin_dir: &Path,
    bindir: &Path,
    names: &[&str],
) -> Result<Vec<(PathBuf, PathBuf)>> {
    preflight_bin_links(Some(bin_dir), bin_dir, bindir, names)?;
    let mut created = Vec::new();
    for &name in names {
        let src = bin_dir.join(name);
        if !src.exists() {
            continue;
        }
        let dst = bindir.join(name);
        if fs::read_link(&dst).is_ok_and(|existing| existing == src) {
            continue;
        }
        atomic_symlink(&src, &dst)
            .with_context(|| format!("symlink {} -> {}", dst.display(), src.display()))?;
        created.push((dst, src));
    }
    Ok(created)
}

pub fn tool_bin_names(tool: ToolKind) -> &'static [&'static str] {
    tool_bin_names_for_os(tool, std::env::consts::OS)
}

pub(crate) fn tool_bin_names_for_os(tool: ToolKind, os: &str) -> &'static [&'static str] {
    match tool {
        ToolKind::Go if os == "windows" => &["go.exe", "gofmt.exe"],
        ToolKind::Go => &["go", "gofmt"],
        ToolKind::Node => &["node", "npm", "npx", "corepack"],
        ToolKind::Python if os == "windows" => &["python.exe"],
        ToolKind::Python => &["python", "python3", "pip", "pip3"],
        ToolKind::Flutter => &["flutter", "dart", "pub"],
        ToolKind::Rust => &[],
        ToolKind::Mojo => &["mojo"],
        ToolKind::Java if os == "windows" => &[
            "java.exe",
            "javac.exe",
            "jar.exe",
            "javadoc.exe",
            "javap.exe",
            "jlink.exe",
            "jmod.exe",
            "jpackage.exe",
            "jshell.exe",
            "keytool.exe",
        ],
        ToolKind::Java => &[
            "java", "javac", "jar", "javadoc", "javap", "jlink", "jmod", "jpackage", "jshell",
            "keytool",
        ],
        ToolKind::Dotnet if os == "windows" => &["dotnet.exe"],
        ToolKind::Dotnet => &["dotnet"],
    }
}

pub fn tool_path_hint_labels(tool: ToolKind) -> &'static [&'static str] {
    match tool {
        ToolKind::Go => &["go GOBIN", "go GOPATH/bin"],
        ToolKind::Node => &["npm global bin"],
        ToolKind::Python => &["python user base bin"],
        ToolKind::Flutter => &["flutter bin", "pub cache bin"],
        ToolKind::Rust => &["cargo bin"],
        ToolKind::Mojo => &[],
        ToolKind::Java => &[],
        ToolKind::Dotnet => &[],
    }
}

pub fn emit_json(ctx: &Ctx, value: serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    ctx.json_emitted.store(true, AtomicOrdering::Relaxed);
    Ok(())
}

fn json_to_string_pretty(value: &serde_json::Value) -> Result<String, serde_json::Error> {
    if let Some(result) = test_support::json_pretty_override(value) {
        return result;
    }
    serde_json::to_string_pretty(value)
}

pub fn print_json_error(command: &str, err: &anyhow::Error) {
    let payload = serde_json::json!({
        "command": command,
        "ok": false,
        "error": err.to_string(),
    });
    println!(
        "{}",
        json_to_string_pretty(&payload).unwrap_or_else(|_| "{}".into())
    );
}

#[cfg(all(test, unix))]
mod activation_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[cfg(target_os = "linux")]
    #[test]
    fn new_link_does_not_replace_path_created_after_inspection() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("staged-link");
        let destination = dir.path().join("destination");
        symlink("target", &source).unwrap();
        fs::write(&destination, "keep").unwrap();
        assert!(install_link(&source, &destination, false).is_err());
        assert_eq!(fs::read_to_string(&destination).unwrap(), "keep");
        assert_eq!(fs::read_link(&source).unwrap(), Path::new("target"));
    }

    #[test]
    fn activation_rejects_external_targets_and_accepts_managed_relative_link() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tool");
        let old = root.join("old");
        let new = root.join("new");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&old).unwrap();
        fs::create_dir(&new).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink("old", root.join("active")).unwrap();
        assert!(activate_install(&root, &outside).is_err());
        assert_eq!(
            fs::read_link(root.join("active")).unwrap(),
            Path::new("old")
        );
        activate_install(&root, &new).unwrap();
        assert_eq!(
            fs::read_link(root.join("active")).unwrap(),
            new.canonicalize().unwrap()
        );
    }

    #[test]
    fn linked_tool_root_is_rejected_even_without_active_link() {
        let dir = tempfile::tempdir().unwrap();
        let external = dir.path().join("external");
        let root = dir.path().join("tool");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("keep"), "fixture").unwrap();
        symlink(&external, &root).unwrap();
        assert!(
            validate_active_install(&root)
                .unwrap_err()
                .to_string()
                .contains("linked")
        );
        assert!(activate_install(&root, &external).is_err());
        assert_eq!(
            fs::read_to_string(external.join("keep")).unwrap(),
            "fixture"
        );
        assert!(!external.join("active").exists());
    }
}
