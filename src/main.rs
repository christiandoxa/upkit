#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use dialoguer::{Confirm, MultiSelect, theme::ColorfulTheme};
use indicatif::ProgressDrawTarget;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use reqwest::blocking::Client;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::process::ExitCode;
use std::{
    cmp::Ordering,
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

mod tools;

/// upkit: check & update dev toolchains (hybrid built-in + direct download).
#[derive(Parser, Debug)]
#[command(name = "upkit")]
#[command(version)]
#[command(about = "Check and update Go/Rust/Node/Python/Flutter", long_about = None)]
struct Cli {
    /// Print JSON instead of pretty text
    #[arg(long)]
    json: bool,

    /// Assume "yes" for prompts (non-interactive)
    #[arg(short = 'y', long)]
    yes: bool,

    /// Increase verbosity (-v, -vv)
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Suppress non-error output
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Disable ANSI colors
    #[arg(long)]
    no_color: bool,

    /// Don't perform actions; only show what would happen
    #[arg(long)]
    dry_run: bool,

    /// Disable progress indicators
    #[arg(long)]
    no_progress: bool,

    /// Disable network access (skip latest checks and downloads)
    #[arg(long)]
    offline: bool,

    /// Network timeout in seconds
    #[arg(long, default_value_t = 60)]
    timeout: u64,

    /// Retry failed network requests this many times
    #[arg(long, default_value_t = 2)]
    retries: u8,

    /// Limit which tools to operate on
    #[arg(long, value_enum)]
    only: Option<ToolKind>,

    /// Where upkit stores tool installs (default: ~/.local/share/upkit)
    #[arg(long)]
    home: Option<PathBuf>,

    /// Where upkit places symlinks (default: ~/.local/bin)
    #[arg(long)]
    bindir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
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
enum ToolKind {
    Go,
    Rust,
    Node,
    Python,
    Flutter,
}

impl ToolKind {
    fn all() -> Vec<ToolKind> {
        vec![
            ToolKind::Go,
            ToolKind::Rust,
            ToolKind::Node,
            ToolKind::Python,
            ToolKind::Flutter,
        ]
    }

    fn as_str(&self) -> &'static str {
        match self {
            ToolKind::Go => "go",
            ToolKind::Rust => "rust",
            ToolKind::Node => "node",
            ToolKind::Python => "python",
            ToolKind::Flutter => "flutter",
        }
    }
}

#[derive(Clone, Debug)]
struct Ctx {
    http: Client,
    home: PathBuf,
    bindir: PathBuf,
    os: String,
    arch: String,
    yes: bool,
    dry_run: bool,
    quiet: bool,
    verbose: u8,
    no_progress: bool,
    offline: bool,
    retries: u8,
    force: bool,
    json: bool,
    use_color: bool,
    json_emitted: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
enum UpdateMethod {
    BuiltIn,
    DirectDownload,
}

#[derive(Clone, Debug)]
struct ToolReport {
    tool: ToolKind,
    installed: Option<Version>,
    latest: Option<Version>,
    status: Status,
    method: UpdateMethod,
    notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    UpToDate,
    Outdated,
    NotInstalled,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<String>, // keep simple
}

impl Version {
    fn parse_loose(s: &str) -> Option<Self> {
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

    fn to_string(&self) -> String {
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

fn main() -> ExitCode {
    let cli = Cli::parse();
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
            } else if !cli.json {
                error(err.to_string());
            }
            ExitCode::from(map_error_to_exit_code(&err))
        }
    }
}

fn run(cli: &Cli, ctx: &mut Ctx) -> Result<()> {
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
            let overall_pb = start_spinner(ctx, "Preparing update plan...");
            let targets = if !tools.is_empty() {
                tools
            } else if all {
                select_kinds(cli.only)
            } else {
                // interactive selection (default: only outdated + not-installed + unknown)
                if !is_interactive() && !ctx.yes {
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
                    info(ctx, "All selected tools are up-to-date.");
                    return Ok(());
                }

                let theme = ColorfulTheme::default();
                let chosen_idx = if ctx.yes {
                    (0..pick.len()).collect::<Vec<_>>()
                } else {
                    MultiSelect::with_theme(&theme)
                        .with_prompt("Update which tools?")
                        .items(&labels)
                        .interact()?
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
                let ok = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Proceed?")
                    .default(false)
                    .interact()?;
                if !ok {
                    info(ctx, "Canceled.");
                    return Ok(());
                }
            }

            let mut failures = Vec::new();
            let mut results = Vec::new();
            for t in targets {
                let pb = start_spinner(ctx, format!("Updating {}", t.as_str()));
                let result = update_tool(ctx, t).with_context(|| format!("update {}", t.as_str()));
                if let Err(err) = result {
                    finish_spinner(pb, format!("Failed to update {}", t.as_str()));
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
                    finish_spinner(pb, format!("Updated {}", t.as_str()));
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
            ensure_dirs(ctx)?;
            let overall_pb = start_spinner(ctx, "Preparing clean plan...");
            let targets = if !tools.is_empty() {
                tools
            } else if all {
                select_kinds(cli.only)
            } else {
                if !is_interactive() && !ctx.yes {
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
                let labels = tools.iter().map(|t| t.as_str()).collect::<Vec<_>>();
                let chosen_idx = if ctx.yes {
                    (0..tools.len()).collect::<Vec<_>>()
                } else {
                    MultiSelect::with_theme(&ColorfulTheme::default())
                        .with_prompt("Remove which tool installs?")
                        .items(&labels)
                        .interact()?
                };
                chosen_idx.into_iter().map(|i| tools[i]).collect()
            };
            finish_spinner(overall_pb, "Clean plan ready");

            if targets.is_empty() {
                info(ctx, "Nothing selected.");
                return Ok(());
            }

            if !ctx.yes {
                let mut summary = String::new();
                for t in &targets {
                    summary.push_str(&format!("- {}\n", t.as_str()));
                }
                info(ctx, format!("Clean plan:\n{summary}"));
                let ok = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Proceed?")
                    .default(false)
                    .interact()?;
                if !ok {
                    info(ctx, "Canceled.");
                    return Ok(());
                }
            }

            let mut failures = Vec::new();
            let mut results = Vec::new();
            for t in targets {
                let pb = start_spinner(ctx, format!("Cleaning {}", t.as_str()));
                let result = clean_tool(ctx, t);
                if let Err(err) = result {
                    finish_spinner(pb, format!("Failed to clean {}", t.as_str()));
                    if !cli.json {
                        error(format!("Failed to clean {}: {err}", t.as_str()));
                    }
                    failures.push(format!("- {}: {err}", t.as_str()));
                    results.push(serde_json::json!({
                        "tool": t.as_str(),
                        "ok": false,
                        "error": err.to_string(),
                    }));
                } else {
                    finish_spinner(pb, format!("Cleaned {}", t.as_str()));
                    results.push(serde_json::json!({
                        "tool": t.as_str(),
                        "ok": true,
                    }));
                }
            }
            if !failures.is_empty() {
                if cli.json {
                    let payload = serde_json::json!({
                        "command": "clean",
                        "ok": false,
                        "results": results,
                    });
                    emit_json(ctx, payload)?;
                }
                return Err(anyhow!("some clean steps failed:\n{}", failures.join("\n")));
            }
            if cli.json {
                let payload = serde_json::json!({
                    "command": "clean",
                    "ok": true,
                    "results": results,
                });
                emit_json(ctx, payload)?;
            }
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

fn make_ctx(cli: &Cli) -> Result<Ctx> {
    let http = Client::builder()
        .user_agent("upkit/0.1 (github.com/christiandoxa/upkit)")
        .timeout(Duration::from_secs(cli.timeout))
        .build()?;

    let home = cli.home.clone().unwrap_or_else(|| {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("upkit")
    });

    let bindir = cli.bindir.clone().unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".local")
            .join("bin")
    });

    let os = env::consts::OS.to_string();
    let arch = env::consts::ARCH.to_string();
    let use_color = !cli.no_color && io::stdout().is_terminal() && !cli.json;
    let json_emitted = Arc::new(AtomicBool::new(false));

    Ok(Ctx {
        http,
        home,
        bindir,
        os,
        arch,
        yes: cli.yes,
        dry_run: cli.dry_run,
        quiet: cli.quiet,
        verbose: cli.verbose,
        no_progress: cli.no_progress,
        offline: cli.offline,
        retries: cli.retries,
        force: false,
        json: cli.json,
        use_color,
        json_emitted,
    })
}

fn ensure_dirs(ctx: &Ctx) -> Result<()> {
    fs::create_dir_all(&ctx.home)?;
    fs::create_dir_all(&ctx.bindir)?;
    Ok(())
}

fn select_kinds(only: Option<ToolKind>) -> Vec<ToolKind> {
    match only {
        Some(t) => vec![t],
        None => ToolKind::all(),
    }
}

fn is_interactive() -> bool {
    io::stdin().is_terminal()
}

pub(crate) fn info<S: AsRef<str>>(ctx: &Ctx, msg: S) {
    if !ctx.quiet && !ctx.json {
        println!("{}", msg.as_ref());
    }
}

pub(crate) fn warn<S: AsRef<str>>(ctx: &Ctx, msg: S) {
    if !ctx.quiet && !ctx.json {
        eprintln!("warning: {}", msg.as_ref());
    }
}

pub(crate) fn debug<S: AsRef<str>>(ctx: &Ctx, msg: S) {
    if !ctx.quiet && !ctx.json && ctx.verbose > 0 {
        eprintln!("debug: {}", msg.as_ref());
    }
}

fn error<S: AsRef<str>>(msg: S) {
    eprintln!("error: {}", msg.as_ref());
}

fn print_reports(ctx: &Ctx, reports: &[ToolReport]) {
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

fn maybe_path_hint(ctx: &Ctx) {
    if ctx.quiet {
        return;
    }
    let path = env::var("PATH").unwrap_or_default();
    if path.split(':').any(|p| p == ctx.bindir.to_string_lossy()) {
        return;
    }
    let shell = env::var("SHELL").unwrap_or_default();
    let rc = if shell.ends_with("zsh") {
        "~/.zshrc"
    } else if shell.ends_with("fish") {
        "~/.config/fish/config.fish"
    } else if shell.ends_with("bash") {
        "~/.bashrc"
    } else {
        "~/.profile"
    };
    let rc_path = expand_tilde(rc);
    let bindir_str = ctx.bindir.to_string_lossy().to_string();
    let already_configured = rc_path
        .as_ref()
        .and_then(|p| fs::read_to_string(p).ok())
        .map(|content| content.contains(&bindir_str))
        .unwrap_or(false);
    if already_configured {
        return;
    }
    let rc_path = match rc_path {
        Some(p) => p,
        None => {
            warn(ctx, "Could not resolve shell rc file to update PATH.");
            return;
        }
    };
    let line = if shell.ends_with("fish") {
        format!("\n# upkit\nset -gx PATH {} $PATH\n", ctx.bindir.display())
    } else {
        format!(
            "\n# upkit\nexport PATH=\"{}:$PATH\"\n",
            ctx.bindir.display()
        )
    };
    match fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rc_path)
    {
        Ok(mut f) => {
            if let Err(err) = f.write_all(line.as_bytes()) {
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

fn colorize_status(ctx: &Ctx, status: Status, text: String) -> String {
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

fn expand_tilde(path: &str) -> Option<PathBuf> {
    if !path.starts_with("~/") {
        return Some(PathBuf::from(path));
    }
    dirs::home_dir().map(|home| home.join(&path[2..]))
}

enum ProgressHandle {
    Spinner(ProgressBar),
    Static,
}

fn start_spinner<S: AsRef<str>>(ctx: &Ctx, msg: S) -> Option<ProgressHandle> {
    if !progress_allowed(ctx) {
        return None;
    }
    if !progress_overwrite_allowed(ctx) {
        info(ctx, msg.as_ref());
        return Some(ProgressHandle::Static);
    }
    let pb = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr_with_hz(10));
    pb.set_style(
        ProgressStyle::with_template("{spinner} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner())
            .tick_strings(&["-", "\\", "|", "/"]),
    );
    pb.set_message(msg.as_ref().to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    Some(ProgressHandle::Spinner(pb))
}

fn finish_spinner<S: AsRef<str>>(pb: Option<ProgressHandle>, msg: S) {
    if let Some(pb) = pb {
        let msg = msg.as_ref();
        let msg = if msg.to_lowercase().contains("failed") {
            format!("❌ {msg}")
        } else {
            format!("✅ {msg}")
        };
        match pb {
            ProgressHandle::Spinner(pb) => {
                pb.set_style(
                    ProgressStyle::with_template("{msg}")
                        .unwrap_or_else(|_| ProgressStyle::default_spinner()),
                );
                pb.finish_with_message(msg);
            }
            ProgressHandle::Static => {}
        }
    }
}

fn progress_allowed(ctx: &Ctx) -> bool {
    !ctx.no_progress && !ctx.quiet && !ctx.json && io::stderr().is_terminal()
}

fn progress_overwrite_allowed(ctx: &Ctx) -> bool {
    progress_allowed(ctx) && io::stderr().is_terminal()
}

fn reports_to_json(reports: &[ToolReport]) -> serde_json::Value {
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

fn check_tool(ctx: &Ctx, tool: ToolKind) -> Result<ToolReport> {
    match tool {
        ToolKind::Go => tools::go::check_go(ctx),
        ToolKind::Node => tools::node::check_node(ctx),
        ToolKind::Python => tools::python::check_python(ctx),
        ToolKind::Rust => tools::rust::check_rust(ctx),
        ToolKind::Flutter => tools::flutter::check_flutter(ctx),
    }
}

fn update_tool(ctx: &Ctx, tool: ToolKind) -> Result<()> {
    match tool {
        ToolKind::Go => tools::go::update_go(ctx),
        ToolKind::Node => tools::node::update_node(ctx),
        ToolKind::Python => tools::python::update_python(ctx),
        ToolKind::Rust => tools::rust::update_rust(ctx),
        ToolKind::Flutter => tools::flutter::update_flutter(ctx),
    }
}

fn tool_method(tool: ToolKind) -> UpdateMethod {
    match tool {
        ToolKind::Go | ToolKind::Node | ToolKind::Python => UpdateMethod::DirectDownload,
        ToolKind::Rust | ToolKind::Flutter => UpdateMethod::BuiltIn,
    }
}

fn check_tool_safe(ctx: &Ctx, tool: ToolKind) -> ToolReport {
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

fn run_capture<S: AsRef<OsStr>>(program: S, args: &[S]) -> Result<String> {
    let out = Command::new(&program)
        .args(args.iter().map(|s| s.as_ref()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("failed to run {:?}", program.as_ref()))?;

    if !out.status.success() {
        bail!(
            "command {:?} failed: {}",
            program.as_ref(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn which_or_none(bin: &str) -> Option<PathBuf> {
    which::which(bin).ok()
}

pub(crate) fn http_get(ctx: &Ctx, url: &str) -> Result<reqwest::blocking::Response> {
    if ctx.offline {
        bail!("offline mode enabled");
    }
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..=ctx.retries {
        let resp = ctx.http.get(url).send();
        match resp {
            Ok(r) => match r.error_for_status() {
                Ok(r) => return Ok(r),
                Err(err) => last_err = Some(err.into()),
            },
            Err(err) => last_err = Some(err.into()),
        }
        if attempt < ctx.retries {
            let backoff = 250u64.saturating_mul(2u64.pow(attempt as u32));
            std::thread::sleep(Duration::from_millis(backoff));
        }
    }
    Err(anyhow!(
        "request failed after {} attempt(s): {}",
        ctx.retries + 1,
        last_err.unwrap_or_else(|| anyhow!("unknown error"))
    ))
}

pub(crate) fn http_get_json<T: DeserializeOwned>(ctx: &Ctx, url: &str) -> Result<T> {
    Ok(http_get(ctx, url)?.json()?)
}

pub(crate) fn http_get_text(ctx: &Ctx, url: &str) -> Result<String> {
    Ok(http_get(ctx, url)?.text()?)
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

fn download_to_temp(ctx: &Ctx, url: &str) -> Result<NamedTempFile> {
    let show_progress = progress_allowed(ctx);
    let mut resp = http_get(ctx, url)?;
    let mut tmp = NamedTempFile::new()?;
    let total = resp.content_length();
    if show_progress && progress_overwrite_allowed(ctx) {
        if let Some(total) = total {
            let pb =
                ProgressBar::with_draw_target(Some(total), ProgressDrawTarget::stderr_with_hz(10));
            pb.set_length(total);
            pb.set_style(
                ProgressStyle::with_template(
                    "[{bar:40.cyan/blue}] {percent:>3}% {bytes}/{total_bytes} {msg}",
                )?
                .progress_chars("=>-"),
            );
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

fn ensure_clean_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        fs::remove_dir_all(dir).with_context(|| format!("remove {}", dir.display()))?;
    }
    fs::create_dir_all(dir)?;
    Ok(())
}

fn atomic_symlink(target: &Path, link: &Path) -> Result<()> {
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

fn link_dir_bins(bin_dir: &Path, bindir: &Path, names: &[&str]) -> Result<()> {
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

fn tool_bin_names(tool: ToolKind) -> &'static [&'static str] {
    match tool {
        ToolKind::Go => &["go", "gofmt"],
        ToolKind::Node => &["node", "npm", "npx", "corepack"],
        ToolKind::Python => &["python", "python3", "pip", "pip3"],
        ToolKind::Rust | ToolKind::Flutter => &[],
    }
}

fn clean_tool(ctx: &Ctx, tool: ToolKind) -> Result<()> {
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

    for &name in tool_bin_names(tool) {
        let dst = ctx.bindir.join(name);
        let meta = match fs::symlink_metadata(&dst) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if !meta.file_type().is_symlink() {
            continue;
        }
        if let Ok(target) = fs::read_link(&dst) {
            if target.starts_with(&ctx.home) {
                fs::remove_file(&dst).with_context(|| format!("remove {}", dst.display()))?;
            }
        }
    }

    info(ctx, format!("cleaned {}", tool.as_str()));
    Ok(())
}

fn run_doctor(ctx: &Ctx, json: bool) -> Result<()> {
    let mut issues: Vec<String> = Vec::new();
    let interactive = is_interactive();

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

    let path = env::var("PATH").unwrap_or_default();
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

fn run_self_update(ctx: &Ctx, json: bool) -> Result<()> {
    if ctx.offline {
        bail!("offline mode enabled; self-update requires network access");
    }
    if json && !ctx.yes {
        bail!("JSON mode requires --yes for self-update");
    }
    if !is_interactive() && !ctx.yes {
        return Err(anyhow!("non-interactive mode: use --yes to proceed"));
    }
    if which_or_none("cargo").is_none() {
        bail!("cargo not found in PATH; reinstall manually");
    }
    if !ctx.yes {
        let ok = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Update upkit via cargo install --force upkit?")
            .default(false)
            .interact()?;
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
    let status = Command::new("cargo")
        .args(["install", "--force", "upkit"])
        .status()
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

fn run_version(ctx: &Ctx, json: bool) -> Result<()> {
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

fn emit_json(ctx: &Ctx, value: serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    ctx.json_emitted.store(true, AtomicOrdering::Relaxed);
    Ok(())
}

fn print_json_error(command: &str, err: &anyhow::Error) {
    let payload = serde_json::json!({
        "command": command,
        "ok": false,
        "error": err.to_string(),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".into())
    );
}

fn check_tools_parallel(ctx: &Ctx, tools: &[ToolKind]) -> Vec<ToolReport> {
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

fn check_tools_with_spinner(ctx: &Ctx, tools: &[ToolKind]) -> Vec<ToolReport> {
    let mut out = Vec::new();
    for tool in tools {
        let pb = start_spinner(ctx, format!("Checking {}", tool.as_str()));
        let report = check_tool_safe(ctx, *tool);
        finish_spinner(pb, format!("Checked {}", tool.as_str()));
        out.push(report);
    }
    out
}

fn report_has_error(report: &ToolReport) -> bool {
    report
        .notes
        .iter()
        .any(|n| n.to_lowercase().starts_with("check failed:"))
}

fn map_error_to_exit_code(err: &anyhow::Error) -> u8 {
    let msg = err.to_string();
    if msg.starts_with("some updates failed")
        || msg.starts_with("some clean steps failed")
        || msg.starts_with("doctor found")
    {
        2
    } else if msg.starts_with("non-interactive mode") {
        3
    } else {
        1
    }
}
