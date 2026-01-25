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
        for raw in trimmed.split(|c: char| c == ',' || c == ' ' || c == ';' || c == '\t') {
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

fn index_to_code(mut idx: usize) -> String {
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

fn code_to_index(code: &str) -> Result<usize> {
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
    maybe_path_hint_for_dir(ctx, &ctx.bindir, "upkit");
}

pub fn maybe_path_hint_for_dir(ctx: &Ctx, dir: &Path, label: &str) {
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

    let label_line = format!("# upkit ({label})");
    let path_line = path_hint_line(&shell, dir);
    let dir_string = dir.to_string_lossy().to_string();
    let existing = fs::read_to_string(&rc_path).ok();
    let mut found_label = false;
    let mut updated = false;
    let mut lines = Vec::new();

    if let Some(content) = &existing {
        let mut iter = content.lines().peekable();
        while let Some(line) = iter.next() {
            if line.trim_end() == label_line {
                found_label = true;
                lines.push(label_line.clone());
                if let Some(next_line) = iter.peek().map(|next| next.trim_end()) {
                    if next_line != path_line {
                        updated = true;
                    }
                    iter.next();
                } else {
                    updated = true;
                }
                lines.push(path_line.clone());
                continue;
            }
            lines.push(line.to_string());
        }
    }

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
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push(label_line);
        lines.push(path_line);
        updated = true;
    }

    if !updated {
        return;
    }

    let mut output = lines.join("\n");
    output.push('\n');
    write_path_hint(ctx, &rc_path, output);
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
    let mut warned_missing_rc = false;
    let mut report = Vec::new();

    for target in required_path_targets(ctx) {
        let configured = dir_configured_in_rc(&target.dir, &rc_paths, home.as_deref());
        let mut updated = false;
        if !configured && !ctx.dry_run {
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
    let mut lines = Vec::new();
    let mut iter = content.lines().peekable();
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
        lines.push(line.to_string());
    }

    if !changed {
        return;
    }
    let mut output = lines.join("\n");
    output.push('\n');
    write_path_hint(ctx, &rc_path, output);
}

fn path_hint_line(shell: &str, dir: &Path) -> String {
    if shell.ends_with("fish") {
        format!("set -gx PATH {} $PATH", dir.display())
    } else {
        format!("export PATH=\"{}:$PATH\"", dir.display())
    }
}

fn required_path_targets(ctx: &Ctx) -> Vec<PathTarget> {
    let mut targets = Vec::new();
    targets.push(PathTarget {
        label: "upkit",
        dir: ctx.bindir.clone(),
    });
    if let Some(dir) = cargo_bin_dir() {
        targets.push(PathTarget {
            label: "cargo bin",
            dir,
        });
    }
    if let Some(dir) = npm_global_bin_dir(ctx) {
        targets.push(PathTarget {
            label: "npm global bin",
            dir,
        });
    }
    if let Some(base) = python_user_base_dir() {
        targets.push(PathTarget {
            label: "python user base bin",
            dir: base.join("bin"),
        });
    }
    if let Some(dir) = flutter_bin_dir(ctx) {
        targets.push(PathTarget {
            label: "flutter bin",
            dir,
        });
    }
    if let Some(pub_cache) = pub_cache_dir() {
        targets.push(PathTarget {
            label: "pub cache bin",
            dir: pub_cache.join("bin"),
        });
    }
    if let Some(gobin) = go_env_value("GOBIN") {
        targets.push(PathTarget {
            label: "go GOBIN",
            dir: PathBuf::from(gobin),
        });
    } else {
        for gopath in go_env_paths("GOPATH") {
            targets.push(PathTarget {
                label: "go GOPATH/bin",
                dir: gopath.join("bin"),
            });
        }
    }
    targets
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

fn update_path_hint_in_rc(ctx: &Ctx, rc_path: &Path, shell: &str, dir: &Path, label: &str) -> bool {
    let label_line = format!("# upkit ({label})");
    let path_line = path_hint_line(shell, dir);
    let existing = fs::read_to_string(rc_path).ok();
    let mut found_label = false;
    let mut updated = false;
    let mut lines = Vec::new();

    if let Some(content) = &existing {
        let mut iter = content.lines().peekable();
        while let Some(line) = iter.next() {
            if line.trim_end() == label_line {
                found_label = true;
                lines.push(label_line.clone());
                if let Some(next_line) = iter.peek().map(|next| next.trim_end()) {
                    if next_line != path_line {
                        updated = true;
                    }
                    iter.next();
                } else {
                    updated = true;
                }
                lines.push(path_line.clone());
                continue;
            }
            lines.push(line.to_string());
        }
    }

    if !found_label {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push(label_line);
        lines.push(path_line);
        updated = true;
    }

    if !updated {
        return false;
    }

    let mut output = lines.join("\n");
    output.push('\n');
    write_path_hint(ctx, rc_path, output);
    true
}

fn write_path_hint(ctx: &Ctx, rc_path: &Path, output: String) {
    match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(rc_path)
    {
        Ok(mut f) => {
            if let Err(err) = write_all_checked(&mut f, output.as_bytes()) {
                warn(
                    ctx,
                    format!("Failed to update PATH in {}: {err}", rc_path.display()),
                );
            } else {
                info(
                    ctx,
                    format!(
                        "PATH updated in {} (restart shell to apply).",
                        rc_path.display()
                    ),
                );
            }
        }
        Err(err) => {
            warn(
                ctx,
                format!("Failed to open {} to update PATH: {err}", rc_path.display()),
            );
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
    let args = vec!["bin".to_string(), "-g".to_string()];
    let output = run_capture(program, &args).ok()?;
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(PathBuf::from(trimmed))
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
    if which_or_none("python3").is_some() {
        if let Some(base) = python_user_base_from("python3") {
            return Some(base);
        }
    }
    if which_or_none("python").is_some() {
        if let Some(base) = python_user_base_from("python") {
            return Some(base);
        }
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
    if which_or_none("go").is_none() {
        return None;
    }
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
        return Err(io::Error::new(io::ErrorKind::Other, "forced write error"));
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

    Ok(Command::new(&program)
        .args(args.iter().map(|s| s.as_ref()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("failed to run {:?}", program.as_ref()))?)
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

enum MockAttempt {
    Handled(Option<Box<dyn HttpResponse>>),
    Skipped,
}

fn mock_http_attempt(
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

pub fn http_get_json<T: DeserializeOwned>(ctx: &Ctx, url: &str) -> Result<T> {
    let mut resp = http_get(ctx, url)?;
    let mut buf = Vec::new();
    resp.read_to_end(&mut buf)?;
    Ok(serde_json::from_slice(&buf)?)
}

pub fn http_get_text(ctx: &Ctx, url: &str) -> Result<String> {
    let mut resp = http_get(ctx, url)?;
    let mut buf = Vec::new();
    resp.read_to_end(&mut buf)?;
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

pub fn download_to_temp(ctx: &Ctx, url: &str) -> Result<NamedTempFile> {
    with_spinner_suspended(|| {
        let show_progress = progress_allowed(ctx);
        let mut resp = http_get_no_timeout(ctx, url)?;
        let mut tmp = NamedTempFile::new()?;
        let total = resp.content_length();
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
                let mut buf = [0u8; 1024 * 64];
                let mut downloaded = 0u64;
                loop {
                    let n = resp.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    tmp.write_all(&buf[..n])?;
                    downloaded += n as u64;
                    pb.set_position(downloaded);
                }
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
                let downloaded = io::copy(&mut resp, &mut tmp)?;
                pb.finish_with_message("Downloaded");
                Some(downloaded)
            }
        } else if show_progress {
            if let Some(total) = total {
                info(ctx, format!("Downloading {url} [0%]"));
                let mut buf = [0u8; 1024 * 64];
                let mut downloaded = 0u64;
                loop {
                    let n = resp.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    tmp.write_all(&buf[..n])?;
                    downloaded += n as u64;
                }
                if downloaded >= total {
                    info(ctx, format!("Downloading {url} [100%]"));
                } else {
                    let pct = (downloaded.saturating_mul(100) / total).min(100);
                    info(ctx, format!("Downloading {url} [{pct}%]"));
                }
                Some(downloaded)
            } else {
                info(ctx, format!("Downloading {url}"));
                Some(io::copy(&mut resp, &mut tmp)?)
            }
        } else {
            Some(io::copy(&mut resp, &mut tmp)?)
        };

        if let (Some(total), Some(downloaded)) = (total, downloaded_total) {
            if downloaded < total {
                bail!("download incomplete for {url}: expected {total} bytes, got {downloaded}");
            }
        }
        Ok(tmp)
    })
}

pub fn ensure_clean_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        fs::remove_dir_all(dir).with_context(|| format!("remove {}", dir.display()))?;
    }
    fs::create_dir_all(dir)?;
    Ok(())
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
        fs::remove_dir_all(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

pub fn atomic_symlink(target: &Path, link: &Path) -> Result<()> {
    // Create tmp symlink then rename (best-effort, cross-platform-ish).
    // On Windows this will likely require privileges; we keep Linux/macOS as primary.
    let tmp_link = link.with_extension("tmp");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let _ = fs::remove_file(&tmp_link);
        symlink(target, &tmp_link)?;
        fs::rename(&tmp_link, link)?;
        return Ok(());
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::symlink_dir;
        let _ = fs::remove_file(&tmp_link);
        // If target is a file, you may want symlink_file. Here we only symlink dirs.
        symlink_dir(target, &tmp_link)?;
        fs::rename(&tmp_link, link)?;
        return Ok(());
    }
}

pub fn link_dir_bins(bin_dir: &Path, bindir: &Path, names: &[&str]) -> Result<()> {
    for &name in names {
        let src = bin_dir.join(name);
        if !src.exists() {
            continue; // best effort
        }
        let dst = bindir.join(name);
        atomic_symlink(&src, &dst)
            .with_context(|| format!("symlink {} -> {}", dst.display(), src.display()))?;
    }
    Ok(())
}

pub fn tool_bin_names(tool: ToolKind) -> &'static [&'static str] {
    match tool {
        ToolKind::Go => &["go", "gofmt"],
        ToolKind::Node => &["node", "npm", "npx", "corepack"],
        ToolKind::Python => &["python", "python3", "pip", "pip3"],
        ToolKind::Flutter => &["flutter", "dart", "pub"],
        ToolKind::Rust => &[],
    }
}

pub fn tool_path_hint_labels(tool: ToolKind) -> &'static [&'static str] {
    match tool {
        ToolKind::Go => &["go GOBIN", "go GOPATH/bin"],
        ToolKind::Node => &["npm global bin"],
        ToolKind::Python => &["python user base bin"],
        ToolKind::Flutter => &["flutter bin", "pub cache bin"],
        ToolKind::Rust => &["cargo bin"],
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

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::test_support::{
        MockResponse, TestPrompt, base_ctx, reset_guard, set_env_var, set_home_dir, set_http_plan,
    };
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn index_code_roundtrip() {
        let _guard = test_support::reset_guard();
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
        let _guard = test_support::reset_guard();
        assert!(code_to_index("").is_err());
        assert!(code_to_index("A").is_err());
        assert!(code_to_index("a1").is_err());
    }

    #[test]
    fn dialoguer_confirm_override() {
        let _guard = test_support::reset_guard();
        test_support::set_prompt_confirm(true);
        let prompt = DialoguerPrompt;
        let ok = prompt.confirm("Proceed?", false).unwrap();
        assert!(ok);
    }

    #[test]
    fn dialoguer_confirm_default_in_coverage() {
        let _guard = test_support::reset_guard();
        let prompt = DialoguerPrompt;
        #[cfg(coverage)]
        {
            let ok = prompt.confirm("Proceed?", true).unwrap();
            assert!(ok);
        }
        #[cfg(not(coverage))]
        {
            test_support::set_prompt_confirm(true);
            let ok = prompt.confirm("Proceed?", false).unwrap();
            assert!(ok);
        }
    }

    #[test]
    fn dialoguer_multi_select_parses_input() {
        let _guard = test_support::reset_guard();
        test_support::set_prompt_input("a,c");
        let prompt = DialoguerPrompt;
        let items = vec!["one".to_string(), "two".to_string(), "three".to_string()];
        let chosen = prompt.multi_select("Pick items", &items).unwrap();
        assert_eq!(chosen, vec![0, 2]);
    }

    #[test]
    fn dialoguer_multi_select_empty_items() {
        let _guard = test_support::reset_guard();
        let prompt = DialoguerPrompt;
        let chosen = prompt.multi_select("Pick items", &[]).unwrap();
        assert!(chosen.is_empty());
    }

    #[test]
    fn dialoguer_multi_select_empty_input() {
        let _guard = test_support::reset_guard();
        test_support::set_prompt_input("   ");
        let prompt = DialoguerPrompt;
        let items = vec!["one".to_string()];
        let chosen = prompt.multi_select("Pick items", &items).unwrap();
        assert!(chosen.is_empty());
    }

    #[test]
    fn dialoguer_multi_select_empty_token() {
        let _guard = test_support::reset_guard();
        test_support::set_prompt_input("a,,b");
        let prompt = DialoguerPrompt;
        let items = vec!["one".to_string(), "two".to_string()];
        let chosen = prompt.multi_select("Pick items", &items).unwrap();
        assert_eq!(chosen, vec![0, 1]);
    }

    #[test]
    fn dialoguer_multi_select_invalid_token() {
        let _guard = test_support::reset_guard();
        test_support::set_prompt_input("a,1");
        let prompt = DialoguerPrompt;
        let items = vec!["one".to_string(), "two".to_string()];
        let err = prompt.multi_select("Pick items", &items).unwrap_err();
        assert!(err.to_string().contains("invalid selection"));
    }

    #[test]
    fn dialoguer_multi_select_coverage_default() {
        let _guard = test_support::reset_guard();
        let prompt = DialoguerPrompt;
        let items = vec!["one".to_string(), "two".to_string()];
        #[cfg(coverage)]
        {
            let chosen = prompt.multi_select("Pick items", &items).unwrap();
            assert!(chosen.is_empty());
        }
        #[cfg(not(coverage))]
        {
            test_support::set_prompt_input("a");
            let chosen = prompt.multi_select("Pick items", &items).unwrap();
            assert_eq!(chosen, vec![0]);
        }
    }

    #[test]
    fn dialoguer_multi_select_out_of_range() {
        let _guard = test_support::reset_guard();
        test_support::set_prompt_input("c");
        let prompt = DialoguerPrompt;
        let items = vec!["one".to_string(), "two".to_string()];
        let err = prompt.multi_select("Pick items", &items).unwrap_err();
        assert!(err.to_string().contains("selection out of range"));
    }

    #[test]
    fn prune_tool_versions_removes_old_dirs() {
        let dir = tempdir().unwrap();
        let tool_root = dir.path().join("tool");
        let keep_dir = tool_root.join("1.2.3");
        let old_dir = tool_root.join("0.9.0");
        let wrappers = tool_root.join("wrappers");
        let cache_file = tool_root.join("cache.txt");

        fs::create_dir_all(&keep_dir).unwrap();
        fs::create_dir_all(&old_dir).unwrap();
        fs::create_dir_all(&wrappers).unwrap();
        fs::write(&cache_file, b"cache").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let active = tool_root.join("active");
            symlink(&keep_dir, &active).unwrap();
        }

        prune_tool_versions(&tool_root, &keep_dir, &["active", "wrappers"]).unwrap();

        assert!(keep_dir.exists());
        assert!(!old_dir.exists());
        assert!(wrappers.exists());
        assert!(cache_file.exists());
    }

    #[test]
    fn maybe_path_hint_updates_missing_path_line() {
        let _guard = reset_guard();
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let bindir = dir.path().join("bin");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&bindir).unwrap();
        set_env_var("SHELL", Some("bash".to_string()));
        set_env_var("PATH", Some("/usr/bin".to_string()));
        set_home_dir(Some(home.clone()));
        let prompt = Arc::new(TestPrompt::default());
        let ctx = base_ctx(home.clone(), bindir.clone(), prompt);
        let rc = home.join(".bashrc");
        fs::write(&rc, "# upkit (upkit)\n").unwrap();
        maybe_path_hint_for_dir(&ctx, &bindir, "upkit");
        let updated = fs::read_to_string(&rc).unwrap();
        assert!(updated.contains("export PATH="));
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
        remove_path_hint_for_label(&ctx, "upkit");
        ctx.quiet = false;
        remove_path_hint_for_label(&ctx, "upkit");
    }

    #[test]
    fn remove_path_hint_handles_unresolvable_and_removes_path_line() {
        let _guard = reset_guard();
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let bindir = dir.path().join("bin");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&bindir).unwrap();
        set_env_var("SHELL", Some("bash".to_string()));
        set_home_dir(None);
        let prompt = Arc::new(TestPrompt::default());
        let ctx = base_ctx(home.clone(), bindir.clone(), prompt);
        remove_path_hint_for_label(&ctx, "upkit");

        set_home_dir(Some(home.clone()));
        let rc = home.join(".bashrc");
        fs::write(&rc, "# upkit (upkit)\nexport PATH=\"/tmp:$PATH\"\nother\n").unwrap();
        remove_path_hint_for_label(&ctx, "upkit");
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
        fs::create_dir_all(&bindir).unwrap();
        set_env_var("SHELL", Some("bash".to_string()));
        set_home_dir(Some(home.clone()));
        let prompt = Arc::new(TestPrompt::default());
        let ctx = base_ctx(home.clone(), bindir, prompt);
        let rc = home.join(".bashrc");
        fs::write(&rc, "# upkit (upkit)\nnot a path\n").unwrap();
        remove_path_hint_for_label(&ctx, "upkit");
        let updated = fs::read_to_string(&rc).unwrap();
        assert!(!updated.contains("upkit"));
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
    }
}
