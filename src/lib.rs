#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
#[cfg(not(coverage))]
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
use indicatif::ProgressDrawTarget;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use reqwest::{Certificate, blocking::Client};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::process::ExitCode;
use std::{
    cmp::Ordering,
    collections::HashSet,
    env,
    ffi::OsStr,
    fs,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering as AtomicOrdering},
    },
    time::Duration,
};
use tempfile::NamedTempFile;

pub mod tools;

/// upkit: check & update dev toolchains (hybrid built-in + direct download).
#[derive(Parser, Debug)]
#[command(name = "upkit")]
#[command(version)]
#[command(about = "Check and update Go/Rust/Node/Python/Flutter", long_about = None)]
pub struct Cli {
    /// Print JSON instead of pretty text
    #[arg(long, global = true)]
    pub json: bool,

    /// Assume "yes" for prompts (non-interactive)
    #[arg(short = 'y', long, global = true)]
    pub yes: bool,

    /// Increase verbosity (-v, -vv)
    #[arg(short = 'v', long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress non-error output
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,

    /// Disable ANSI colors
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Don't perform actions; only show what would happen
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Disable progress indicators
    #[arg(long, global = true)]
    pub no_progress: bool,

    /// Disable network access (skip latest checks and downloads)
    #[arg(long, global = true)]
    pub offline: bool,

    /// Network timeout in seconds
    #[arg(long, default_value_t = 60, global = true)]
    pub timeout: u64,

    /// Retry failed network requests this many times
    #[arg(long, default_value_t = 2, global = true)]
    pub retries: u8,

    /// Limit which tools to operate on
    #[arg(long, value_enum, global = true)]
    pub only: Option<ToolKind>,

    /// Where upkit stores tool installs (default: ~/.local/share/upkit)
    #[arg(long, global = true)]
    pub home: Option<PathBuf>,

    /// Where upkit places symlinks (default: ~/.local/bin)
    #[arg(long, global = true)]
    pub bindir: Option<PathBuf>,

    #[command(subcommand)]
    pub cmd: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Show installed version + latest version + status
    Check,
    /// Update tools (interactive by default)
    Update {
        /// Tools to update (skips interactive selection)
        tools: Vec<ToolKind>,
        /// Update all tools (skip interactive selection)
        #[arg(long)]
        all: bool,
        /// Update even if already up-to-date
        #[arg(long)]
        force: bool,
    },
    /// Remove managed tool installs and symlinks
    Clean {
        /// Tools to clean (skips interactive selection)
        tools: Vec<ToolKind>,
        /// Clean all tools (skip interactive selection)
        #[arg(long)]
        all: bool,
    },
    /// Uninstall managed tool installs and symlinks
    Uninstall {
        /// Tools to uninstall (skips interactive selection)
        tools: Vec<ToolKind>,
        /// Uninstall all tools (skip interactive selection)
        #[arg(long)]
        all: bool,
    },
    /// Diagnose common setup problems and provide fixes
    Doctor,
    /// Print version details
    Version,
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Update upkit itself
    SelfUpdate,
    /// Print where upkit stores installs and symlinks
    Paths,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq, Hash)]
pub enum ToolKind {
    Go,
    Rust,
    Node,
    Python,
    Flutter,
}

impl ToolKind {
    pub fn all() -> Vec<ToolKind> {
        vec![
            ToolKind::Go,
            ToolKind::Rust,
            ToolKind::Node,
            ToolKind::Python,
            ToolKind::Flutter,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ToolKind::Go => "go",
            ToolKind::Rust => "rust",
            ToolKind::Node => "node",
            ToolKind::Python => "python",
            ToolKind::Flutter => "flutter",
        }
    }
}

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

#[derive(Clone, Debug)]
pub enum UpdateMethod {
    BuiltIn,
    DirectDownload,
}

#[derive(Clone, Debug)]
pub struct ToolReport {
    pub tool: ToolKind,
    pub installed: Option<Version>,
    pub latest: Option<Version>,
    pub status: Status,
    pub method: UpdateMethod,
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    UpToDate,
    Outdated,
    NotInstalled,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Option<String>, // keep simple
}

impl Version {
    pub fn parse_loose(s: &str) -> Option<Self> {
        // Accept: "1.2.3", "v1.2.3", "go1.22.5", "rustc 1.85.0", "3.22.1-foo"
        let re =
            Regex::new(r"(?i)(?:go|v|rustc\s+)?(\d+)\.(\d+)\.(\d+)(?:[-+~._]([0-9A-Za-z.-]+))?")
                .ok()?;
        let caps = re.captures(s)?;
        let major = caps.get(1)?.as_str().parse().ok()?;
        let minor = caps.get(2)?.as_str().parse().ok()?;
        let patch = caps.get(3)?.as_str().parse().ok()?;
        let pre = caps.get(4).map(|m| m.as_str().to_string());
        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }

    pub fn to_string(&self) -> String {
        match &self.pre {
            Some(p) => format!("{}.{}.{}-{}", self.major, self.minor, self.patch, p),
            None => format!("{}.{}.{}", self.major, self.minor, self.patch),
        }
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch, &self.pre).cmp(&(
            other.major,
            other.minor,
            other.patch,
            &other.pre,
        ))
    }
}
impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn main_entry() -> ExitCode {
    main_with(Cli::parse())
}

pub fn main_with(cli: Cli) -> ExitCode {
    let mut ctx = match make_ctx(&cli) {
        Ok(ctx) => ctx,
        Err(err) => {
            if cli.json {
                print_json_error("init", &err);
            } else {
                error(err.to_string());
            }
            return ExitCode::from(map_error_to_exit_code(&err));
        }
    };
    debug(
        &ctx,
        format!(
            "os={} arch={} home={} bindir={} timeout={}s retries={} offline={} dry_run={}",
            ctx.os,
            ctx.arch,
            ctx.home.display(),
            ctx.bindir.display(),
            cli.timeout,
            ctx.retries,
            ctx.offline,
            ctx.dry_run
        ),
    );
    if ctx.offline {
        warn(
            &ctx,
            "Offline mode enabled; latest checks and downloads are disabled.",
        );
    }

    let result = run(&cli, &mut ctx);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            if cli.json && !ctx.json_emitted.load(AtomicOrdering::Relaxed) {
                print_json_error("run", &err);
            }
            if !cli.json {
                error(err.to_string());
            }
            ExitCode::from(map_error_to_exit_code(&err))
        }
    }
}

pub fn run(cli: &Cli, ctx: &mut Ctx) -> Result<()> {
    match cli.cmd.clone().unwrap_or(Commands::Check) {
        Commands::Paths => {
            ensure_dirs(ctx)?;
            if cli.json {
                let payload = serde_json::json!({
                    "home": ctx.home.display().to_string(),
                    "bindir": ctx.bindir.display().to_string(),
                });
                emit_json(ctx, payload)?;
            } else {
                info(ctx, format!("upkit home : {}", ctx.home.display()));
                info(ctx, format!("upkit bindir: {}", ctx.bindir.display()));
                info(ctx, "(created directories if missing)");
            }
        }
        Commands::Check => {
            ensure_dirs(ctx)?;
            let tools = select_kinds(cli.only);
            let use_spinner = progress_allowed(ctx) && !cli.json;
            let reports = if use_spinner {
                check_tools_with_spinner(ctx, &tools)
            } else {
                if !cli.json {
                    for t in &tools {
                        info(ctx, format!("Checking {}...", t.as_str()));
                    }
                }
                check_tools_parallel(ctx, &tools)
            };
            if cli.json {
                emit_json(ctx, reports_to_json(&reports))?;
            } else {
                if !use_spinner {
                    for r in &reports {
                        let emoji = if report_has_error(r) { "❌" } else { "✅" };
                        info(ctx, format!("{emoji} Checked {}", r.tool.as_str()));
                    }
                }
                print_reports(ctx, &reports);
                maybe_path_hint(ctx);
            }
        }
        Commands::Update { tools, all, force } => {
            ensure_dirs(ctx)?;
            ctx.force = force;
            let mut overall_pb = start_spinner(ctx, "Preparing update plan...");
            let targets = if !tools.is_empty() {
                tools
            } else if all {
                select_kinds(cli.only)
            } else {
                // interactive selection (default: only outdated + not-installed + unknown)
                if !ctx.stdin_is_tty && !ctx.yes {
                    return Err(anyhow!(
                        "non-interactive mode: pass tool names, or use --all/--yes to accept defaults"
                    ));
                }
                if cli.json && !ctx.yes {
                    return Err(anyhow!(
                        "JSON mode requires --yes or explicit tool selection"
                    ));
                }
                let tools = select_kinds(cli.only);
                let reports = check_tools_parallel(ctx, &tools);

                let mut labels = Vec::new();
                let mut pick = Vec::new();
                for r in &reports {
                    let want = force
                        || matches!(
                            r.status,
                            Status::Outdated | Status::NotInstalled | Status::Unknown
                        );
                    if want {
                        labels.push(format!(
                            "{}  installed={}  latest={}  ({:?})",
                            r.tool.as_str(),
                            r.installed
                                .as_ref()
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "-".into()),
                            r.latest
                                .as_ref()
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "?".into()),
                            r.status
                        ));
                        pick.push(r.tool);
                    }
                }

                if pick.is_empty() {
                    finish_spinner(overall_pb, "Update plan ready");
                    info(ctx, "All selected tools are up-to-date.");
                    return Ok(());
                }

                let chosen_idx = if ctx.yes {
                    (0..pick.len()).collect::<Vec<_>>()
                } else {
                    finish_spinner(overall_pb.take(), "Update plan ready");
                    ctx.prompt.multi_select("Update which tools?", &labels)?
                };
                chosen_idx.into_iter().map(|i| pick[i]).collect()
            };
            finish_spinner(overall_pb, "Update plan ready");

            if targets.is_empty() {
                info(ctx, "Nothing selected.");
                return Ok(());
            }

            // Confirm overall plan
            if !ctx.yes {
                let mut summary = String::new();
                let reports = check_tools_parallel(ctx, &targets);
                for (t, r) in targets.iter().zip(reports.iter()) {
                    summary.push_str(&format!(
                        "- {}: {} -> {}\n",
                        t.as_str(),
                        r.installed
                            .as_ref()
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "-".into()),
                        r.latest
                            .as_ref()
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "?".into()),
                    ));
                }
                info(ctx, format!("Plan:\n{summary}"));
                let ok = ctx.prompt.confirm("Proceed?", false)?;
                if !ok {
                    info(ctx, "Canceled.");
                    return Ok(());
                }
            }

            let mut failures = Vec::new();
            let mut results = Vec::new();
            for t in targets {
                let pb = start_spinner(ctx, &format!("Updating {}", t.as_str()));
                let result = update_tool(ctx, t).with_context(|| format!("update {}", t.as_str()));
                if let Err(err) = result {
                    finish_spinner(pb, &format!("Failed to update {}", t.as_str()));
                    if !cli.json {
                        error(format!("Failed to update {}: {err}", t.as_str()));
                    }
                    failures.push(format!("- {}: {err}", t.as_str()));
                    results.push(serde_json::json!({
                        "tool": t.as_str(),
                        "ok": false,
                        "error": err.to_string(),
                    }));
                } else {
                    finish_spinner(pb, &format!("Updated {}", t.as_str()));
                    results.push(serde_json::json!({
                        "tool": t.as_str(),
                        "ok": true,
                    }));
                }
            }
            if !failures.is_empty() {
                if cli.json {
                    let payload = serde_json::json!({
                        "command": "update",
                        "ok": false,
                        "results": results,
                    });
                    emit_json(ctx, payload)?;
                }
                return Err(anyhow!("some updates failed:\n{}", failures.join("\n")));
            }
            if cli.json {
                let payload = serde_json::json!({
                    "command": "update",
                    "ok": true,
                    "results": results,
                });
                emit_json(ctx, payload)?;
            }
            maybe_path_hint(ctx);
        }
        Commands::Clean { tools, all } => {
            run_clean_command(ctx, cli, tools, all, CleanAction::Clean)?;
        }
        Commands::Uninstall { tools, all } => {
            run_clean_command(ctx, cli, tools, all, CleanAction::Uninstall)?;
        }
        Commands::Doctor => {
            ensure_dirs(ctx)?;
            let pb = start_spinner(ctx, "Running doctor checks...");
            run_doctor(ctx, cli.json)?;
            finish_spinner(pb, "Doctor completed");
        }
        Commands::Version => {
            run_version(ctx, cli.json)?;
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "upkit", &mut io::stdout());
        }
        Commands::SelfUpdate => {
            ensure_dirs(ctx)?;
            let pb = if ctx.dry_run {
                None
            } else {
                start_spinner(ctx, "Updating upkit...")
            };
            run_self_update(ctx, cli.json)?;
            finish_spinner(pb, "Self-update completed");
        }
    }

    Ok(())
}

#[derive(Copy, Clone, Debug)]
enum CleanAction {
    Clean,
    Uninstall,
}

impl CleanAction {
    fn verb(self) -> &'static str {
        match self {
            CleanAction::Clean => "clean",
            CleanAction::Uninstall => "uninstall",
        }
    }

    fn title(self) -> &'static str {
        match self {
            CleanAction::Clean => "Clean",
            CleanAction::Uninstall => "Uninstall",
        }
    }

    fn prompt(self) -> &'static str {
        match self {
            CleanAction::Clean => "Remove which tool installs?",
            CleanAction::Uninstall => "Uninstall which tool installs?",
        }
    }
}

fn run_clean_command(
    ctx: &Ctx,
    cli: &Cli,
    tools: Vec<ToolKind>,
    all: bool,
    action: CleanAction,
) -> Result<()> {
    ensure_dirs(ctx)?;
    let mut overall_pb = start_spinner(ctx, &format!("Preparing {} plan...", action.verb()));
    let targets = if !tools.is_empty() {
        tools
    } else if all {
        select_kinds(cli.only)
    } else {
        if !ctx.stdin_is_tty && !ctx.yes {
            return Err(anyhow!(
                "non-interactive mode: pass tool names, or use --all/--yes to accept defaults"
            ));
        }
        if cli.json && !ctx.yes {
            return Err(anyhow!(
                "JSON mode requires --yes or explicit tool selection"
            ));
        }
        let tools = select_kinds(cli.only);
        let labels = tools
            .iter()
            .map(|t| t.as_str().to_string())
            .collect::<Vec<_>>();
        let chosen_idx = if ctx.yes {
            (0..tools.len()).collect::<Vec<_>>()
        } else {
            finish_spinner(overall_pb.take(), &format!("{} plan ready", action.title()));
            ctx.prompt.multi_select(action.prompt(), &labels)?
        };
        chosen_idx.into_iter().map(|i| tools[i]).collect()
    };
    finish_spinner(overall_pb, &format!("{} plan ready", action.title()));

    if targets.is_empty() {
        info(ctx, "Nothing selected.");
        return Ok(());
    }

    if !ctx.yes {
        let mut summary = String::new();
        for t in &targets {
            summary.push_str(&format!("- {}\n", t.as_str()));
        }
        info(ctx, format!("{} plan:\n{summary}", action.title()));
        let ok = ctx.prompt.confirm("Proceed?", false)?;
        if !ok {
            info(ctx, "Canceled.");
            return Ok(());
        }
    }

    let mut failures = Vec::new();
    let mut results = Vec::new();
    for t in targets {
        let pb = start_spinner(ctx, &format!("{} {}", action.title(), t.as_str()));
        let result = clean_tool(ctx, t);
        if let Err(err) = result {
            finish_spinner(pb, &format!("Failed to {} {}", action.verb(), t.as_str()));
            if !cli.json {
                error(format!("Failed to {} {}: {err}", action.verb(), t.as_str()));
            }
            failures.push(format!("- {}: {err}", t.as_str()));
            results.push(serde_json::json!({
                "tool": t.as_str(),
                "ok": false,
                "error": err.to_string(),
            }));
        } else {
            finish_spinner(pb, &format!("{}ed {}", action.title(), t.as_str()));
            results.push(serde_json::json!({
                "tool": t.as_str(),
                "ok": true,
            }));
        }
    }
    if !failures.is_empty() {
        if cli.json {
            let payload = serde_json::json!({
                "command": action.verb(),
                "ok": false,
                "results": results,
            });
            emit_json(ctx, payload)?;
        }
        return Err(anyhow!(
            "some {} steps failed:\n{}",
            action.verb(),
            failures.join("\n")
        ));
    }
    if cli.json {
        let payload = serde_json::json!({
            "command": action.verb(),
            "ok": true,
            "results": results,
        });
        emit_json(ctx, payload)?;
    }
    Ok(())
}

pub fn make_ctx(cli: &Cli) -> Result<Ctx> {
    if let Some(err) = test_support::make_ctx_error() {
        bail!(err);
    }
    let mut http_builder = Client::builder()
        .user_agent("upkit/0.1 (github.com/christiandoxa/upkit)")
        .timeout(Duration::from_secs(cli.timeout));
    if let Some(cert_path) = get_env_var("SSL_CERT_FILE") {
        let pem =
            fs::read(&cert_path).with_context(|| format!("read SSL_CERT_FILE {}", cert_path))?;
        let cert = Certificate::from_pem(&pem)
            .with_context(|| format!("parse SSL_CERT_FILE {}", cert_path))?;
        http_builder = http_builder.add_root_certificate(cert);
    }
    let http = http_builder.build()?;

    let home = cli.home.clone().unwrap_or_else(|| {
        data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("upkit")
    });

    let bindir = cli.bindir.clone().unwrap_or_else(|| {
        home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".local")
            .join("bin")
    });

    let os = env::consts::OS.to_string();
    let arch = env::consts::ARCH.to_string();
    let stdin_is_tty = io::stdin().is_terminal();
    let stderr_is_tty = io::stderr().is_terminal();
    let use_color = !cli.no_color && io::stdout().is_terminal() && !cli.json;
    let json_emitted = Arc::new(AtomicBool::new(false));

    Ok(Ctx {
        http,
        home,
        bindir,
        os,
        arch,
        stdin_is_tty,
        stderr_is_tty,
        progress_overwrite: stderr_is_tty,
        yes: cli.yes,
        dry_run: cli.dry_run,
        quiet: cli.quiet,
        verbose: cli.verbose,
        no_progress: cli.no_progress,
        offline: cli.offline,
        retries: cli.retries,
        timeout: cli.timeout,
        force: false,
        json: cli.json,
        use_color,
        json_emitted,
        prompt: Arc::new(DialoguerPrompt),
    })
}

pub fn ensure_dirs(ctx: &Ctx) -> Result<()> {
    fs::create_dir_all(&ctx.home)?;
    fs::create_dir_all(&ctx.bindir)?;
    Ok(())
}

pub fn select_kinds(only: Option<ToolKind>) -> Vec<ToolKind> {
    match only {
        Some(t) => vec![t],
        None => ToolKind::all(),
    }
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
    let rc = if shell.ends_with("zsh") {
        "~/.zshrc"
    } else if shell.ends_with("fish") {
        "~/.config/fish/config.fish"
    } else if shell.ends_with("bash") {
        "~/.bashrc"
    } else {
        "~/.profile"
    };
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
    match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&rc_path)
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

pub fn remove_path_hint_for_label(ctx: &Ctx, label: &str) {
    if ctx.quiet {
        return;
    }
    let shell = get_env_var("SHELL").unwrap_or_default();
    let rc = if shell.ends_with("zsh") {
        "~/.zshrc"
    } else if shell.ends_with("fish") {
        "~/.config/fish/config.fish"
    } else if shell.ends_with("bash") {
        "~/.bashrc"
    } else {
        "~/.profile"
    };
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
            continue;
        }
        lines.push(line.to_string());
    }

    if !changed {
        return;
    }
    let mut output = lines.join("\n");
    output.push('\n');
    match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&rc_path)
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

fn path_hint_line(shell: &str, dir: &Path) -> String {
    if shell.ends_with("fish") {
        format!("set -gx PATH {} $PATH", dir.display())
    } else {
        format!("export PATH=\"{}:$PATH\"", dir.display())
    }
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
        Status::UpToDate => "32",
        Status::Outdated => "33",
        Status::NotInstalled => "31",
        Status::Unknown => "90",
    };
    format!("\u{1b}[{}m{}\u{1b}[0m", code, text)
}

pub fn expand_tilde(path: &str) -> Option<PathBuf> {
    if !path.starts_with("~/") {
        return Some(PathBuf::from(path));
    }
    home_dir().map(|home| home.join(&path[2..]))
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

pub enum ProgressHandle {
    Spinner(ProgressBar),
    Static,
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
    "{msg}".to_string()
}

#[cfg_attr(coverage, inline(never))]
pub fn start_spinner(ctx: &Ctx, msg: &str) -> Option<ProgressHandle> {
    if !progress_allowed(ctx) {
        return None;
    }
    if !progress_overwrite_allowed(ctx) {
        info(ctx, msg);
        return Some(ProgressHandle::Static);
    }
    let pb = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr_with_hz(10));
    let template = spinner_template();
    let style = ProgressStyle::with_template(&template)
        .unwrap_or_else(|_| ProgressStyle::default_spinner());
    pb.set_style(style.tick_strings(&["-", "\\", "|", "/"]));
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
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

/* -------------------------- tool routing -------------------------- */

pub fn check_tool(ctx: &Ctx, tool: ToolKind) -> Result<ToolReport> {
    if let Some(result) = test_support::check_tool_override(tool) {
        return result;
    }
    match tool {
        ToolKind::Go => tools::go::check_go(ctx),
        ToolKind::Node => tools::node::check_node(ctx),
        ToolKind::Python => tools::python::check_python(ctx),
        ToolKind::Rust => tools::rust::check_rust(ctx),
        ToolKind::Flutter => tools::flutter::check_flutter(ctx),
    }
}

pub fn update_tool(ctx: &Ctx, tool: ToolKind) -> Result<()> {
    if let Some(result) = test_support::update_tool_override(tool) {
        return result;
    }
    match tool {
        ToolKind::Go => tools::go::update_go(ctx),
        ToolKind::Node => tools::node::update_node(ctx),
        ToolKind::Python => tools::python::update_python(ctx),
        ToolKind::Rust => tools::rust::update_rust(ctx),
        ToolKind::Flutter => tools::flutter::update_flutter(ctx),
    }
}

pub fn tool_method(tool: ToolKind) -> UpdateMethod {
    match tool {
        ToolKind::Go | ToolKind::Node | ToolKind::Python => UpdateMethod::DirectDownload,
        ToolKind::Rust | ToolKind::Flutter => UpdateMethod::BuiltIn,
    }
}

pub fn check_tool_safe(ctx: &Ctx, tool: ToolKind) -> ToolReport {
    match check_tool(ctx, tool) {
        Ok(r) => r,
        Err(err) => ToolReport {
            tool,
            installed: None,
            latest: None,
            status: Status::Unknown,
            method: tool_method(tool),
            notes: vec![format!("Check failed: {err}")],
        },
    }
}

/* -------------------------- shared helpers -------------------------- */

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

#[cfg(coverage)]
pub fn http_get(ctx: &Ctx, url: &str) -> Result<Box<dyn HttpResponse>> {
    if ctx.offline {
        bail!("offline mode enabled");
    }
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..=ctx.retries {
        if test_support::http_mocking_enabled() || test_support::http_allow_unknown_error() {
            if let Some(resp) = test_support::next_http_response(url) {
                match resp {
                    Ok(r) => return Ok(r),
                    Err(err) => last_err = Some(err),
                }
            } else if !test_support::http_allow_unknown_error() {
                last_err = Some(anyhow!("no test response left"));
            }
        } else {
            last_err = Some(anyhow!(
                "http mocking disabled under coverage; set test responses"
            ));
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
        if test_support::http_mocking_enabled() || test_support::http_allow_unknown_error() {
            if let Some(resp) = test_support::next_http_response(url) {
                match resp {
                    Ok(r) => return Ok(r),
                    Err(err) => last_err = Some(err),
                }
            } else if !test_support::http_allow_unknown_error() {
                last_err = Some(anyhow!("no test response left"));
            }
        } else {
            let resp = ctx.http.get(url).send();
            match resp {
                Ok(r) => match r.error_for_status() {
                    Ok(r) => return Ok(Box::new(ReqwestResponse { inner: r })),
                    Err(err) => last_err = Some(err.into()),
                },
                Err(err) => last_err = Some(err.into()),
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
        if test_support::http_mocking_enabled() || test_support::http_allow_unknown_error() {
            if let Some(resp) = test_support::next_http_response(url) {
                match resp {
                    Ok(r) => return Ok(r),
                    Err(err) => last_err = Some(err),
                }
            } else if !test_support::http_allow_unknown_error() {
                last_err = Some(anyhow!("no test response left"));
            }
        } else {
            let long_timeout = ctx.timeout.saturating_mul(10).max(600);
            let resp = ctx
                .http
                .get(url)
                .timeout(Duration::from_secs(long_timeout))
                .send();
            match resp {
                Ok(r) => match r.error_for_status() {
                    Ok(r) => return Ok(Box::new(ReqwestResponse { inner: r })),
                    Err(err) => last_err = Some(err.into()),
                },
                Err(err) => last_err = Some(err.into()),
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

fn sha256_file(path: &Path) -> Result<String> {
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
    let show_progress = progress_allowed(ctx);
    let mut resp = http_get_no_timeout(ctx, url)?;
    let mut tmp = NamedTempFile::new()?;
    let total = resp.content_length();
    if show_progress && progress_overwrite_allowed(ctx) {
        if let Some(total) = total {
            let pb =
                ProgressBar::with_draw_target(Some(total), ProgressDrawTarget::stderr_with_hz(10));
            pb.set_length(total);
            let style = ProgressStyle::with_template(
                "[{bar:40.cyan/blue}] {percent:>3}% {bytes}/{total_bytes} {msg}",
            )?
            .progress_chars("=>-");
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
        } else {
            let pb = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr_with_hz(10));
            pb.set_style(
                ProgressStyle::with_template("{spinner} {msg}")?
                    .tick_strings(&["-", "\\", "|", "/"]),
            );
            pb.set_message(format!("Downloading {url}"));
            pb.enable_steady_tick(Duration::from_millis(80));
            io::copy(&mut resp, &mut tmp)?;
            pb.finish_with_message("Downloaded");
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
        } else {
            info(ctx, format!("Downloading {url}"));
            io::copy(&mut resp, &mut tmp)?;
        }
    } else {
        io::copy(&mut resp, &mut tmp)?;
    }
    Ok(tmp)
}

pub fn ensure_clean_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        fs::remove_dir_all(dir).with_context(|| format!("remove {}", dir.display()))?;
    }
    fs::create_dir_all(dir)?;
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
/* -------------------------- bin linking helpers -------------------------- */

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

pub fn clean_tool(ctx: &Ctx, tool: ToolKind) -> Result<()> {
    let tool_root = ctx.home.join(tool.as_str());
    if ctx.dry_run {
        println!(
            "[dry-run] would remove {} and related symlinks",
            tool_root.display()
        );
        return Ok(());
    }

    if tool_root.exists() {
        fs::remove_dir_all(&tool_root)
            .with_context(|| format!("remove {}", tool_root.display()))?;
    }

    let bindir_readonly = fs::metadata(&ctx.bindir)
        .map(|meta| meta.permissions().readonly())
        .unwrap_or(false);
    for &name in tool_bin_names(tool) {
        let dst = ctx.bindir.join(name);
        let meta = match fs::symlink_metadata(&dst) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if !meta.file_type().is_symlink() {
            continue;
        }
        if matches!(fs::read_link(&dst), Ok(target) if target.starts_with(&ctx.home)) {
            if bindir_readonly {
                bail!("remove {} failed: bindir is not writable", dst.display());
            }
            fs::remove_file(&dst).with_context(|| format!("remove {}", dst.display()))?;
        }
    }

    for &label in tool_path_hint_labels(tool) {
        remove_path_hint_for_label(ctx, label);
    }

    info(ctx, format!("cleaned {}", tool.as_str()));
    Ok(())
}

pub fn run_doctor(ctx: &Ctx, json: bool) -> Result<()> {
    let mut issues: Vec<String> = Vec::new();
    let interactive = ctx.stdin_is_tty;

    if !ctx.home.exists() {
        issues.push(format!(
            "home directory does not exist: {}",
            ctx.home.display()
        ));
    }
    if !ctx.bindir.exists() {
        issues.push(format!("bindir does not exist: {}", ctx.bindir.display()));
    }

    if let Err(err) = fs::create_dir_all(&ctx.home) {
        issues.push(format!("cannot create home dir: {err}"));
    }
    if let Err(err) = fs::create_dir_all(&ctx.bindir) {
        issues.push(format!("cannot create bindir: {err}"));
    }

    if fs::metadata(&ctx.home).is_ok() {
        if let Err(err) = tempfile::Builder::new()
            .prefix("upkit")
            .tempfile_in(&ctx.home)
        {
            issues.push(format!("home dir not writable: {err}"));
        }
    }
    if fs::metadata(&ctx.bindir).is_ok() {
        if let Err(err) = tempfile::Builder::new()
            .prefix("upkit")
            .tempfile_in(&ctx.bindir)
        {
            issues.push(format!("bindir not writable: {err}"));
        }
    }

    let path = get_env_var("PATH").unwrap_or_default();
    if !path.split(':').any(|p| p == ctx.bindir.to_string_lossy()) {
        issues.push(format!(
            "bindir is not on PATH; add: export PATH=\"{}:$PATH\"",
            ctx.bindir.display()
        ));
    }

    let mut missing = Vec::new();
    for tool in ToolKind::all() {
        let bin = match tool {
            ToolKind::Go => "go",
            ToolKind::Rust => "rustc",
            ToolKind::Node => "node",
            ToolKind::Python => "python3",
            ToolKind::Flutter => "flutter",
        };
        if which_or_none(bin).is_none() {
            missing.push(bin);
        }
    }
    if !missing.is_empty() {
        issues.push(format!("missing tools in PATH: {}", missing.join(", ")));
    }

    if !ctx.offline {
        if let Err(err) = http_get_text(ctx, "https://example.com") {
            issues.push(format!("network check failed: {err}"));
        }
    }

    if json {
        let report = serde_json::json!({
            "os": ctx.os,
            "arch": ctx.arch,
            "interactive": interactive,
            "offline": ctx.offline,
            "home": ctx.home.display().to_string(),
            "bindir": ctx.bindir.display().to_string(),
            "issues": issues,
        });
        emit_json(ctx, report)?;
    } else {
        info(ctx, "Doctor report:");
        info(
            ctx,
            format!(
                "- os={} arch={} interactive={} offline={}",
                ctx.os, ctx.arch, interactive, ctx.offline
            ),
        );
        info(
            ctx,
            format!(
                "- home={} bindir={}",
                ctx.home.display(),
                ctx.bindir.display()
            ),
        );
        if issues.is_empty() {
            info(ctx, "No issues found.");
            return Ok(());
        }
        warn(ctx, "Issues detected:");
        for issue in &issues {
            warn(ctx, format!("- {issue}"));
        }
    }

    if issues.is_empty() {
        return Ok(());
    }

    Err(anyhow!("doctor found {} issue(s)", issues.len()))
}

pub fn run_self_update(ctx: &Ctx, json: bool) -> Result<()> {
    if ctx.offline {
        bail!("offline mode enabled; self-update requires network access");
    }
    if json && !ctx.yes {
        bail!("JSON mode requires --yes for self-update");
    }
    if !ctx.stdin_is_tty && !ctx.yes {
        return Err(anyhow!("non-interactive mode: use --yes to proceed"));
    }
    if which_or_none("cargo").is_none() {
        bail!("cargo not found in PATH; reinstall manually");
    }
    if !ctx.yes {
        let ok = ctx
            .prompt
            .confirm("Update upkit via cargo install --force upkit?", false)?;
        if !ok {
            info(ctx, "Canceled.");
            return Ok(());
        }
    }
    if ctx.dry_run {
        if json {
            let payload = serde_json::json!({
                "command": "self-update",
                "ok": true,
                "dry_run": true,
            });
            emit_json(ctx, payload)?;
        } else {
            info(ctx, "[dry-run] would run: cargo install --force upkit");
        }
        return Ok(());
    }
    let status = run_status("cargo", &["install", "--force", "upkit"])
        .context("failed to run cargo install")?;
    if !status.success() {
        bail!("self-update failed");
    }
    if json {
        let payload = serde_json::json!({
            "command": "self-update",
            "ok": true,
        });
        emit_json(ctx, payload)?;
    } else {
        info(ctx, "upkit updated");
    }
    Ok(())
}

pub fn run_version(ctx: &Ctx, json: bool) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let git = option_env!("UPKIT_GIT_HASH").unwrap_or("unknown");
    let date = option_env!("UPKIT_BUILD_DATE").unwrap_or("unknown");
    let payload = serde_json::json!({
        "version": version,
        "git": git,
        "build_date": date,
    });
    if json {
        emit_json(ctx, payload)?;
    } else {
        info(ctx, format!("upkit {}", version));
        info(ctx, format!("commit: {git}"));
        info(ctx, format!("build date: {date}"));
    }
    Ok(())
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

pub fn check_tools_parallel(ctx: &Ctx, tools: &[ToolKind]) -> Vec<ToolReport> {
    if tools.len() <= 1 {
        let tool = tools[0];
        let report = check_tool_safe(ctx, tool);
        return vec![report];
    }
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|s| {
        for (idx, tool) in tools.iter().enumerate() {
            let tx = tx.clone();
            let ctx = ctx.clone();
            s.spawn(move || {
                let report = check_tool_safe(&ctx, *tool);
                let _ = tx.send((idx, report));
            });
        }
    });
    drop(tx);
    let mut out: Vec<Option<ToolReport>> = vec![None; tools.len()];
    for (idx, report) in rx {
        out[idx] = Some(report);
    }
    out.into_iter().map(|r| r.unwrap()).collect()
}

pub fn check_tools_with_spinner(ctx: &Ctx, tools: &[ToolKind]) -> Vec<ToolReport> {
    let mut out = Vec::new();
    for tool in tools {
        let pb = start_spinner(ctx, &format!("Checking {}", tool.as_str()));
        let report = check_tool_safe(ctx, *tool);
        finish_spinner(pb, &format!("Checked {}", tool.as_str()));
        out.push(report);
    }
    out
}

pub fn report_has_error(report: &ToolReport) -> bool {
    report
        .notes
        .iter()
        .any(|n| n.to_lowercase().starts_with("check failed:"))
}

pub fn map_error_to_exit_code(err: &anyhow::Error) -> u8 {
    let msg = err.to_string();
    if msg.starts_with("some updates failed")
        || msg.starts_with("some clean steps failed")
        || msg.starts_with("some uninstall steps failed")
        || msg.starts_with("doctor found")
    {
        2
    } else if msg.starts_with("non-interactive mode") {
        3
    } else {
        1
    }
}

#[cfg_attr(coverage, allow(dead_code))]
pub mod test_support {
    use super::*;
    use std::collections::{HashMap, VecDeque};
    use std::io::Cursor;
    use std::process::Output;
    use std::sync::{Mutex, OnceLock};

    #[derive(Clone, Debug, Hash, PartialEq, Eq)]
    struct CommandKey {
        program: String,
        args: Vec<String>,
    }

    #[derive(Default)]
    pub struct Hooks {
        run_output: HashMap<CommandKey, VecDeque<Output>>,
        which: HashMap<String, Option<PathBuf>>,
        http: HashMap<String, VecDeque<Result<MockResponse, String>>>,
        check_tool: HashMap<ToolKind, Result<ToolReport, String>>,
        update_tool: HashMap<ToolKind, Result<(), String>>,
        home_dir: Option<Option<PathBuf>>,
        data_local_dir: Option<Option<PathBuf>>,
        env_vars: HashMap<String, Option<String>>,
        write_error: bool,
        sleep: Vec<Duration>,
        make_ctx_error: Option<String>,
        sleep_passthrough: bool,
        spinner_template: Option<String>,
        finish_template: Option<String>,
        json_pretty_error: bool,
        http_allow_unknown_error: bool,
        http_mocking_enabled: bool,
        prompt_defaults: bool,
        prompt_inputs: VecDeque<String>,
        prompt_confirms: VecDeque<bool>,
    }

    static HOOKS: OnceLock<Mutex<Hooks>> = OnceLock::new();
    static HOOKS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn hooks() -> &'static Mutex<Hooks> {
        HOOKS.get_or_init(|| Mutex::new(Hooks::default()))
    }

    fn hooks_lock_init() -> Mutex<()> {
        Mutex::new(())
    }

    fn command_key(program: &str, args: &[String]) -> CommandKey {
        CommandKey {
            program: program.to_string(),
            args: args.to_vec(),
        }
    }

    pub fn reset_hooks() {
        *hooks().lock().unwrap() = Hooks::default();
    }

    pub fn reset_guard() -> std::sync::MutexGuard<'static, ()> {
        let lock = HOOKS_LOCK.get_or_init(hooks_lock_init);
        let guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        reset_hooks();
        guard
    }

    pub fn poison_hooks_lock() {
        let _ = hooks_lock_init();
        let lock = HOOKS_LOCK.get_or_init(hooks_lock_init);
        let _ = std::panic::catch_unwind(|| {
            let _guard = lock.lock().unwrap();
            panic!("poison");
        });
    }

    pub fn set_run_output(program: &str, args: &[&str], output: Output) {
        let args_vec = args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut hooks = hooks().lock().unwrap();
        hooks
            .run_output
            .entry(command_key(program, &args_vec))
            .or_default()
            .push_back(output);
    }

    pub fn take_run_output(program: &str, args: &[String]) -> Option<Output> {
        let mut hooks = hooks().lock().unwrap();
        let key = command_key(program, args);
        hooks.run_output.get_mut(&key).and_then(|q| q.pop_front())
    }

    pub fn set_which(bin: &str, path: Option<PathBuf>) {
        hooks().lock().unwrap().which.insert(bin.to_string(), path);
    }

    pub fn which_override(bin: &str) -> Option<Option<PathBuf>> {
        hooks().lock().unwrap().which.get(bin).cloned()
    }

    pub fn set_http_plan(url: &str, plan: Vec<Result<MockResponse, String>>) {
        let mut hooks = hooks().lock().unwrap();
        hooks.http_mocking_enabled = true;
        hooks.http.insert(url.to_string(), plan.into());
    }

    pub fn set_http_allow_unknown_error(enabled: bool) {
        hooks().lock().unwrap().http_allow_unknown_error = enabled;
    }

    pub fn http_allow_unknown_error() -> bool {
        hooks().lock().unwrap().http_allow_unknown_error
    }

    pub fn http_mocking_enabled() -> bool {
        hooks().lock().unwrap().http_mocking_enabled
    }

    pub fn set_spinner_template(template: Option<&str>) {
        hooks().lock().unwrap().spinner_template = template.map(str::to_string);
    }

    pub fn set_finish_template(template: Option<&str>) {
        hooks().lock().unwrap().finish_template = template.map(str::to_string);
    }

    pub fn set_prompt_defaults(enabled: bool) {
        hooks().lock().unwrap().prompt_defaults = enabled;
    }

    pub fn prompt_defaults_override() -> bool {
        hooks().lock().unwrap().prompt_defaults
    }

    pub fn set_prompt_input(value: &str) {
        hooks()
            .lock()
            .unwrap()
            .prompt_inputs
            .push_back(value.to_string());
    }

    pub fn next_prompt_input() -> Option<String> {
        hooks().lock().unwrap().prompt_inputs.pop_front()
    }

    pub fn set_prompt_confirm(value: bool) {
        hooks().lock().unwrap().prompt_confirms.push_back(value);
    }

    pub fn next_prompt_confirm() -> Option<bool> {
        hooks().lock().unwrap().prompt_confirms.pop_front()
    }

    pub fn spinner_template_override() -> Option<String> {
        hooks().lock().unwrap().spinner_template.clone()
    }

    pub fn finish_template_override() -> Option<String> {
        hooks().lock().unwrap().finish_template.clone()
    }

    pub fn set_json_pretty_error(enabled: bool) {
        hooks().lock().unwrap().json_pretty_error = enabled;
    }

    pub fn set_check_tool(tool: ToolKind, result: Result<ToolReport, String>) {
        hooks().lock().unwrap().check_tool.insert(tool, result);
    }

    pub fn check_tool_override(tool: ToolKind) -> Option<Result<ToolReport>> {
        hooks()
            .lock()
            .unwrap()
            .check_tool
            .get(&tool)
            .cloned()
            .map(|r| r.map_err(anyhow::Error::msg))
    }

    pub fn set_update_tool(tool: ToolKind, result: Result<(), String>) {
        hooks().lock().unwrap().update_tool.insert(tool, result);
    }

    pub fn update_tool_override(tool: ToolKind) -> Option<Result<()>> {
        hooks()
            .lock()
            .unwrap()
            .update_tool
            .get(&tool)
            .cloned()
            .map(|r| r.map_err(anyhow::Error::msg))
    }

    pub fn next_http_response(url: &str) -> Option<Result<Box<dyn HttpResponse>>> {
        let mut hooks = hooks().lock().unwrap();
        let plan = hooks.http.get_mut(url)?;
        let next = plan
            .pop_front()
            .unwrap_or_else(|| Err("no test response left".into()));
        Some(
            next.map(|resp| Box::new(resp) as Box<dyn HttpResponse>)
                .map_err(anyhow::Error::msg),
        )
    }

    pub fn json_pretty_override(
        value: &serde_json::Value,
    ) -> Option<Result<String, serde_json::Error>> {
        let hooks = hooks().lock().unwrap();
        if hooks.json_pretty_error {
            let err = io::Error::new(io::ErrorKind::Other, "forced json error");
            return Some(Err(serde_json::Error::io(err)));
        }
        let _ = value;
        None
    }

    pub fn set_home_dir(path: Option<PathBuf>) {
        hooks().lock().unwrap().home_dir = Some(path);
    }

    pub fn set_data_local_dir(path: Option<PathBuf>) {
        hooks().lock().unwrap().data_local_dir = Some(path);
    }

    pub fn home_dir_override() -> Option<Option<PathBuf>> {
        hooks().lock().unwrap().home_dir.clone()
    }

    pub fn data_local_dir_override() -> Option<Option<PathBuf>> {
        hooks().lock().unwrap().data_local_dir.clone()
    }

    pub fn set_env_var(key: &str, value: Option<String>) {
        hooks()
            .lock()
            .unwrap()
            .env_vars
            .insert(key.to_string(), value);
    }

    pub fn env_var_override(key: &str) -> Option<Option<String>> {
        hooks().lock().unwrap().env_vars.get(key).cloned()
    }

    pub fn record_sleep(duration: Duration) -> bool {
        let mut hooks = hooks().lock().unwrap();
        if hooks.sleep_passthrough {
            return false;
        }
        hooks.sleep.push(duration);
        true
    }

    pub fn sleep_calls() -> Vec<Duration> {
        hooks().lock().unwrap().sleep.clone()
    }

    pub fn set_write_error(enabled: bool) {
        hooks().lock().unwrap().write_error = enabled;
    }

    pub fn force_write_error() -> bool {
        hooks().lock().unwrap().write_error
    }

    pub fn set_make_ctx_error(err: Option<String>) {
        hooks().lock().unwrap().make_ctx_error = err;
    }

    pub fn make_ctx_error() -> Option<String> {
        hooks().lock().unwrap().make_ctx_error.clone()
    }

    pub fn set_sleep_passthrough(enabled: bool) {
        hooks().lock().unwrap().sleep_passthrough = enabled;
    }

    pub struct MockResponse {
        cursor: Cursor<Vec<u8>>,
        len: Option<u64>,
    }

    impl MockResponse {
        pub fn new(bytes: Vec<u8>, len: Option<u64>) -> Self {
            Self {
                cursor: Cursor::new(bytes),
                len,
            }
        }
    }

    impl Read for MockResponse {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.cursor.read(buf)
        }
    }

    impl HttpResponse for MockResponse {
        fn content_length(&self) -> Option<u64> {
            self.len
        }
    }

    pub fn output_with_status(code: i32, stdout: &[u8], stderr: &[u8]) -> Output {
        Output {
            status: exit_status(code),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[cfg(unix)]
    fn exit_status(code: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code << 8)
    }

    #[cfg(windows)]
    fn exit_status(code: i32) -> std::process::ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code as u32)
    }

    #[derive(Clone, Debug, Default)]
    pub struct TestPrompt {
        confirms: Arc<Mutex<VecDeque<bool>>>,
        selections: Arc<Mutex<VecDeque<Vec<usize>>>>,
    }

    impl TestPrompt {
        pub fn push_confirm(&self, value: bool) {
            self.confirms.lock().unwrap().push_back(value);
        }

        pub fn push_selection(&self, value: Vec<usize>) {
            self.selections.lock().unwrap().push_back(value);
        }
    }

    impl Prompt for TestPrompt {
        fn confirm(&self, _prompt: &str, _default: bool) -> Result<bool> {
            Ok(self
                .confirms
                .lock()
                .map_err(|_| anyhow!("prompt confirms lock poisoned"))?
                .pop_front()
                .unwrap_or(false))
        }

        fn multi_select(&self, _prompt: &str, _items: &[String]) -> Result<Vec<usize>> {
            Ok(self
                .selections
                .lock()
                .map_err(|_| anyhow!("prompt selections lock poisoned"))?
                .pop_front()
                .unwrap_or_default())
        }
    }

    pub fn base_ctx(home: PathBuf, bindir: PathBuf, prompt: Arc<dyn Prompt>) -> Ctx {
        let http = Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .expect("build http client");
        Ctx {
            http,
            home,
            bindir,
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            stdin_is_tty: true,
            stderr_is_tty: true,
            progress_overwrite: true,
            yes: false,
            dry_run: false,
            quiet: false,
            verbose: 0,
            no_progress: false,
            offline: false,
            retries: 0,
            timeout: 1,
            force: false,
            json: false,
            use_color: false,
            json_emitted: Arc::new(AtomicBool::new(false)),
            prompt,
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

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
}
