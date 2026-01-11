use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser, Subcommand};
use reqwest::{Certificate, blocking::Client};
use std::process::ExitCode;
use std::{
    env,
    fs,
    io,
    io::IsTerminal,
    path::PathBuf,
    sync::mpsc,
    sync::{Arc, atomic::Ordering as AtomicOrdering},
    time::Duration,
};

use crate::domain::{Status, ToolKind, ToolReport, UpdateMethod};
use crate::infrastructure::{
    Ctx, DialoguerPrompt, data_local_dir, debug, emit_json, error, finish_spinner, get_env_var,
    home_dir, http_get_text, info, maybe_path_hint, print_json_error, print_reports,
    progress_allowed, remove_path_hint_for_label, reports_to_json, run_status, start_spinner,
    tool_bin_names, tool_path_hint_labels, warn, which_or_none,
};
use crate::{test_support, tools};

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
    #[command(visible_alias = "install")]
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
                        error(format!("Failed to update {}: {err:#}", t.as_str()));
                    }
                    failures.push(format!("- {}: {err:#}", t.as_str()));
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
    let json_emitted = Arc::new(std::sync::atomic::AtomicBool::new(false));

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
    let pb = start_spinner(ctx, "Checking toolchains...");
    let mut out = Vec::new();
    for tool in tools {
        if let Some(crate::infrastructure::ProgressHandle::Spinner(inner)) = pb.as_ref() {
            inner.set_message(format!("Checking {}", tool.as_str()));
        }
        let report = check_tool_safe(ctx, *tool);
        out.push(report);
    }
    finish_spinner(pb, "Checked toolchains");
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
