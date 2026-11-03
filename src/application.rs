use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser, Subcommand};
use reqwest::{Certificate, blocking::Client};
use std::process::ExitCode;
use std::{
    env,
    ffi::OsString,
    fs, io,
    io::IsTerminal,
    path::PathBuf,
    sync::mpsc,
    sync::{Arc, atomic::Ordering as AtomicOrdering},
    time::Duration,
};

use crate::domain::{Status, ToolKind, ToolReport, UpdateMethod};
use crate::infrastructure::{
    Ctx, DialoguerPrompt, data_local_dir, debug, emit_json, ensure_required_paths, error,
    finish_spinner, get_env_var, home_dir, http_get_text, info, maybe_path_hint, print_json_error,
    print_reports, progress_allowed, reports_to_json, run_capture, run_status, start_spinner,
    tool_bin_names, warn, which_or_none,
};
use crate::{test_support, tools};

fn schedule_isolated_config(path: Option<&std::path::Path>, windows: bool) -> bool {
    path == Some(if windows {
        std::path::Path::new("NUL")
    } else {
        std::path::Path::new("/dev/null")
    })
}

fn require_scheduled_artifact_cleanup_support(is_linux: bool) -> Result<()> {
    if !is_linux {
        bail!("scheduled artifact cleanup is supported only on Linux");
    }
    Ok(())
}

#[cfg(test)]
mod scheduled_artifact_platform_tests {
    use super::require_scheduled_artifact_cleanup_support;

    #[test]
    fn scheduled_artifact_cleanup_fails_closed_off_linux() {
        let error = require_scheduled_artifact_cleanup_support(false).unwrap_err();
        assert!(error.to_string().contains("supported only on Linux"));
        assert!(require_scheduled_artifact_cleanup_support(true).is_ok());
    }
}

/// Manage developer toolchains, workspace artifacts, and maintenance.
#[derive(Parser, Debug)]
#[command(name = "upkit")]
#[command(version)]
#[command(about = "Manage developer toolchains, workspace artifacts, and maintenance", long_about = None)]
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

    /// Skip Upkit network checks and downloads (external programs may use network)
    #[arg(long, global = true)]
    pub offline: bool,

    /// Never open the interactive dashboard or prompt for input
    #[arg(long, global = true)]
    pub non_interactive: bool,

    /// Read scan settings from this TOML file
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Use a named workspace profile for artifact scans
    #[arg(long, global = true)]
    pub profile: Option<String>,

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
    /// Open the interactive dashboard
    Tui,
    /// Show or safely prune local maintenance operation history
    Report {
        #[command(subcommand)]
        command: Option<ReportCommand>,
    },
    /// Inspect container storage without removing resources
    Containers {
        #[command(subcommand)]
        command: ContainerCommand,
    },
    /// Preview workspace scan schedules
    Schedule {
        #[command(subcommand)]
        command: ScheduleCommand,
    },
    /// Inspect and manage Trash
    Trash {
        #[command(subcommand)]
        command: TrashCommand,
    },
    /// Inspect shared developer caches
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
    /// Inspect system maintenance capabilities
    Maintenance {
        #[command(subcommand)]
        command: MaintenanceCommand,
    },
    /// Inspect or initialize workspace scan settings
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Inspect developer artifacts in explicitly selected workspaces
    Sweep {
        #[command(subcommand)]
        command: SweepCommand,
    },
    /// Preview or safely remove one managed tool root and matching binary links
    ManagedClean {
        /// Explicitly selected managed tool
        tool: ToolKind,
        /// Execute the previously reviewed cleanup
        #[arg(long)]
        run: bool,
        /// Token from a previous managed-clean preview
        #[arg(long)]
        preview_token: Option<String>,
        /// Explicitly authorize permanent removal of this managed tool root
        #[arg(long)]
        authorize_managed_cleanup: bool,
    },
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
        #[command(flatten)]
        safety: CleanSafety,
    },
    /// Uninstall managed tool installs and symlinks
    Uninstall {
        /// Tools to uninstall (skips interactive selection)
        tools: Vec<ToolKind>,
        /// Uninstall all tools (skip interactive selection)
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        safety: CleanSafety,
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

#[derive(clap::Args, Debug, Clone)]
pub struct CleanSafety {
    /// Review the selected tool roots without removing them
    #[arg(long)]
    preview: bool,
    /// Token returned by a previous preview of this selection
    #[arg(long)]
    preview_token: Option<String>,
    /// Authorize permanent removal of the selected managed tool roots
    #[arg(long)]
    authorize_managed_cleanup: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ReportCommand {
    /// Preview or permanently remove old history records
    Purge {
        /// Remove only records whose finish time is older than this age
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: std::time::Duration,
        /// Inspect the selected history records without removing them
        #[arg(long, conflicts_with_all = ["run", "preview_token", "authorize_history_purge"])]
        preview: bool,
        /// Execute the reviewed removal
        #[arg(long, requires = "preview_token", conflicts_with = "preview")]
        run: bool,
        /// Token from a preview with the same age threshold
        #[arg(long, requires = "run")]
        preview_token: Option<String>,
        /// Explicitly authorize permanent removal of the selected history records
        #[arg(long, requires = "run")]
        authorize_history_purge: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum SweepCommand {
    /// Show local maintenance operation history
    Report,
    /// Preview or permanently remove explicitly selected artifacts or one shared cache
    Run {
        #[arg(long, value_enum)]
        scope: SweepRunScope,
        /// Absolute path of an exact discovered artifact; repeat to select a batch
        #[arg(long, required = true)]
        select: Vec<PathBuf>,
        /// Workspace roots to scan; repeat as needed
        #[arg(long)]
        root: Vec<PathBuf>,
        /// Exclude a path or glob from scanning
        #[arg(long)]
        exclude: Vec<PathBuf>,
        /// Only include artifacts older than this age
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Option<Duration>,
        /// Inspect the complete removal plan without removing anything
        #[arg(long, conflicts_with_all = ["preview_token", "authorize_artifact_removal", "authorize_shared_cache"])]
        preview: bool,
        /// Token from a prior preview of the same scope
        #[arg(long)]
        preview_token: Option<String>,
        /// Explicitly authorize permanent artifact directory removal
        #[arg(long)]
        authorize_artifact_removal: bool,
        /// Explicitly authorize permanent removal of the selected shared cache
        #[arg(long)]
        authorize_shared_cache: bool,
    },
    /// Preview or remove one explicitly selected CPython bytecode file
    Bytecode {
        /// Absolute path to a CPython bytecode file inside __pycache__
        file: PathBuf,
        /// Workspace root to inspect; repeat as needed (defaults to configured roots)
        #[arg(long)]
        root: Vec<PathBuf>,
        /// Exclude a path from the scan
        #[arg(long)]
        exclude: Vec<PathBuf>,
        /// Only include caches older than this age
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Option<Duration>,
        /// Remove the reviewed file
        #[arg(long)]
        run: bool,
        /// Token returned by a previous preview
        #[arg(long)]
        preview_token: Option<String>,
        /// Explicitly authorize permanent removal of the selected bytecode
        #[arg(long)]
        authorize_bytecode_removal: bool,
    },
    /// Preview or remove explicitly selected CPython bytecode files
    BytecodeBatch {
        /// Absolute bytecode paths inside discovered __pycache__ directories
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Workspace root to inspect; repeat as needed
        #[arg(long)]
        root: Vec<PathBuf>,
        /// Exclude a path from the scan
        #[arg(long)]
        exclude: Vec<PathBuf>,
        /// Only include caches older than this age
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Option<Duration>,
        /// Remove the reviewed files
        #[arg(long)]
        run: bool,
        /// Token from the complete batch preview
        #[arg(long)]
        preview_token: Option<String>,
        /// Explicitly authorize permanent removal of the selected files
        #[arg(long)]
        authorize_bytecode_removal: bool,
    },
    /// Discover project artifacts without deleting anything
    Scan {
        /// Workspace roots to inspect
        paths: Vec<PathBuf>,
        /// Exclude a path (absolute or relative to each root); repeat as needed
        #[arg(long)]
        exclude: Vec<PathBuf>,
        /// Only report artifacts whose newest modification is older than this age (e.g. 30d)
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Option<Duration>,
        /// Verify the scheduled scan scope before reading workspaces
        #[arg(long, hide = true)]
        scope_token: Option<String>,
    },
    /// Run an explicitly approved scheduled bytecode cleanup policy
    #[command(hide = true)]
    ScheduledBytecodeCleanup {
        #[arg(long)]
        scope_token: String,
        #[arg(long)]
        authorize_scheduled_cleanup: bool,
        #[arg(long)]
        exclude: Vec<PathBuf>,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Run an explicitly approved scheduled artifact cleanup policy
    #[command(hide = true)]
    ScheduledCleanup {
        #[arg(long)]
        scope_token: String,
        #[arg(long)]
        authorize_scheduled_cleanup: bool,
        #[arg(long)]
        authorize_scheduled_artifact_cleanup: bool,
        #[arg(long)]
        exclude: Vec<PathBuf>,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Preview artifact removal targets without executing cleanup
    Preview {
        /// Workspace roots to inspect (defaults to configured roots)
        paths: Vec<PathBuf>,
        /// Exclude a path (absolute or relative to each root)
        #[arg(long)]
        exclude: Vec<PathBuf>,
        /// Only include artifacts older than this age
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Option<Duration>,
        /// Select an exact discovered target; repeat to select more
        #[arg(long)]
        select: Vec<PathBuf>,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SweepRunScope {
    Artifacts,
    Cache,
}

#[derive(Subcommand, Debug, Clone)]
pub enum MaintenanceCommand {
    /// Show TRIM and system timer status
    Status,
    /// Review or remove abandoned Upkit link-staging directories
    Temp {
        /// Preview exact selected staging directories without removal
        #[arg(long, conflicts_with = "run")]
        preview: bool,
        /// Remove staging directories from a prior explicit preview
        #[arg(long, conflicts_with = "preview")]
        run: bool,
        /// Select an exact candidate path; repeat to select more
        #[arg(long)]
        select: Vec<PathBuf>,
        /// Token returned by a prior preview of this selection
        #[arg(long, requires = "run")]
        preview_token: Option<String>,
        /// Explicitly authorize permanent removal of the staging directories
        #[arg(long, requires = "run")]
        authorize_temp_cleanup: bool,
    },
    /// Inspect TRIM status
    Trim {
        /// Show status without changing storage or schedules
        #[arg(long, conflicts_with_all = ["preview", "run"])]
        status: bool,
        /// Preview TRIM for an explicitly selected mounted filesystem
        #[arg(long, conflicts_with = "run", requires = "mount")]
        preview: bool,
        /// Run a previously previewed TRIM operation
        #[arg(long, requires = "mount")]
        run: bool,
        /// Absolute, canonical mount point to inspect or trim
        #[arg(long)]
        mount: Option<PathBuf>,
        /// Token returned by a prior preview
        #[arg(long, requires = "run")]
        preview_token: Option<String>,
        /// Explicitly authorize a manual TRIM operation
        #[arg(long, requires = "run")]
        authorize_trim: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum CacheCommand {
    /// Estimate sizes of recognized shared caches without removing them
    Status,
    /// Preview or expire test results in one explicitly selected Go cache
    GoTest {
        /// Absolute canonical Go cache directory
        #[arg(long)]
        path: PathBuf,
        /// Inspect the selected cache without modifying it
        #[arg(long, conflicts_with = "run")]
        preview: bool,
        /// Expire test results after a prior preview
        #[arg(long, conflicts_with = "preview")]
        run: bool,
        /// Token from a prior preview of this path
        #[arg(long, requires = "run")]
        preview_token: Option<String>,
        /// Explicitly authorize changing the shared Go test cache
        #[arg(long, requires = "run")]
        authorize_shared_cache: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ContainerCommand {
    /// Report Docker and Podman storage usage
    Status,
    /// Preview removal of one stopped container
    PreviewRemove {
        #[arg(long)]
        engine: String,
        #[arg(long)]
        id: String,
    },
    /// Remove one explicitly selected stopped container after preview
    Remove {
        #[arg(long)]
        engine: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_container_removal: bool,
    },
    /// Explain why dangling-image preview is disabled (no engine is contacted)
    PreviewImage {
        #[arg(long)]
        engine: String,
        #[arg(long)]
        id: String,
    },
    /// Attempt dangling-image removal (currently unsupported; no engine is contacted)
    RemoveImage {
        #[arg(long)]
        engine: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_image_removal: bool,
    },
    /// Preview removal of one unused bridge network by its full ID
    PreviewNetwork {
        #[arg(long)]
        engine: String,
        #[arg(long)]
        id: String,
    },
    /// Remove one explicitly selected unused bridge network after preview
    RemoveNetwork {
        #[arg(long)]
        engine: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_network_removal: bool,
    },
    /// Preview one private, unused Buildx cache record
    PreviewBuildCache {
        #[arg(long)]
        builder: String,
        #[arg(long)]
        id: String,
    },
    /// Remove one reviewed Buildx cache record
    RemoveBuildCache {
        #[arg(long)]
        builder: String,
        #[arg(long)]
        id: String,
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_build_cache_removal: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ScheduleCommand {
    /// Inspect the Upkit scan schedule without changing it
    List,
    /// Preview replacing an inactive schedule with a new scope or frequency
    PreviewEdit {
        #[arg(long, value_enum)]
        frequency: Option<crate::schedule::Frequency>,
        #[arg(long, requires = "paths")]
        exclude: Vec<PathBuf>,
        paths: Vec<PathBuf>,
    },
    /// Replace a previewed inactive schedule and enable the new schedule
    Edit {
        #[arg(long, value_enum)]
        frequency: Option<crate::schedule::Frequency>,
        #[arg(long, requires = "paths")]
        exclude: Vec<PathBuf>,
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_schedule_edit: bool,
        paths: Vec<PathBuf>,
    },
    /// Preview removal of an inactive, disabled scan schedule
    PreviewRemove,
    /// Remove a previously previewed inactive scan schedule
    Remove {
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_schedule_removal: bool,
    },
    /// Preview re-enabling a disabled schedule for the specified scan scope
    PreviewEnable {
        #[arg(long, value_enum)]
        frequency: Option<crate::schedule::Frequency>,
        #[arg(long, requires = "paths")]
        exclude: Vec<PathBuf>,
        paths: Vec<PathBuf>,
    },
    /// Re-enable a previously previewed scan schedule
    Enable {
        #[arg(long, value_enum)]
        frequency: Option<crate::schedule::Frequency>,
        #[arg(long, requires = "paths")]
        exclude: Vec<PathBuf>,
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_schedule: bool,
        paths: Vec<PathBuf>,
    },
    /// Preview disabling the existing Upkit scan schedule
    PreviewDisable,
    /// Disable a previously previewed scan schedule
    Disable {
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_schedule: bool,
    },
    /// Install and enable one previewed scan schedule
    Add {
        #[arg(long, value_enum)]
        frequency: Option<crate::schedule::Frequency>,
        #[arg(long, requires = "paths")]
        exclude: Vec<PathBuf>,
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_schedule: bool,
        paths: Vec<PathBuf>,
    },
    /// Preview a scan schedule for explicit roots or configured policy
    Preview {
        #[arg(long, value_enum)]
        frequency: Option<crate::schedule::Frequency>,
        #[arg(long, requires = "paths")]
        exclude: Vec<PathBuf>,
        paths: Vec<PathBuf>,
    },
    /// Manage the Linux user Trash retention timer
    #[command(name = "trash-retention")]
    TrashRetention {
        #[command(subcommand)]
        command: TrashRetentionScheduleCommand,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum TrashRetentionScheduleCommand {
    /// Preview a daily schedule for one exact Trash location and age threshold
    Preview {
        #[arg(long)]
        location: PathBuf,
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Duration,
    },
    /// Install and enable one previously previewed Trash retention schedule
    Install {
        #[arg(long)]
        location: PathBuf,
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Duration,
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_scheduled_trash_retention: bool,
    },
    /// Preview re-enabling a disabled Trash retention schedule
    PreviewEnable,
    /// Re-enable a previously previewed Trash retention schedule
    Enable {
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_scheduled_trash_retention: bool,
    },
    /// Preview disabling the Trash retention schedule
    PreviewDisable,
    /// Disable a previously previewed Trash retention schedule
    Disable {
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_scheduled_trash_retention: bool,
    },
    /// Preview removal of an inactive, disabled Trash retention schedule
    PreviewRemove,
    /// Remove a previously previewed Trash retention schedule
    Remove {
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_scheduled_trash_retention: bool,
    },
    /// Show Trash retention timer state
    Status,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TrashCommand {
    /// Show accessible Trash locations and estimated sizes
    Status,
    /// Preview emptying one location containing supported files and directories
    PreviewEmpty {
        #[arg(long)]
        location: PathBuf,
    },
    /// Empty one previously previewed Trash location
    Empty {
        #[arg(long)]
        location: PathBuf,
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_trash_removal: bool,
    },
    /// Preview age-based Trash retention without removing anything
    Preview {
        /// Age threshold, for example 30d
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Duration,
    },
    /// Preview permanent deletion of one old file or directory
    PreviewRemove {
        #[arg(long)]
        location: PathBuf,
        /// Reversible item name printed by Trash preview
        #[arg(long)]
        name: String,
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Duration,
    },
    /// Permanently delete one previously previewed item
    Remove {
        #[arg(long)]
        location: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Duration,
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_trash_removal: bool,
    },
    /// Preview permanent deletion of selected old items from one location
    PreviewBatch {
        #[arg(long)]
        location: PathBuf,
        /// Repeat for each escaped item name
        #[arg(long, required = true)]
        name: Vec<String>,
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Duration,
    },
    /// Permanently delete previously previewed items from one location
    RemoveBatch {
        #[arg(long)]
        location: PathBuf,
        #[arg(long, required = true)]
        name: Vec<String>,
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Duration,
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_trash_removal: bool,
    },
    /// Preview old eligible items in one selected Trash location
    PreviewRetention {
        #[arg(long)]
        location: PathBuf,
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Duration,
    },
    /// Permanently remove a previously previewed set of old eligible items
    Retain {
        #[arg(long)]
        location: PathBuf,
        #[arg(long, value_parser = crate::sweep::parse_age)]
        older_than: Duration,
        #[arg(long)]
        preview_token: Option<String>,
        #[arg(long)]
        authorize_trash_removal: bool,
    },
    /// Run the installed, guarded Trash retention policy
    #[command(hide = true)]
    ScheduledRetention {
        #[arg(long)]
        location: PathBuf,
        #[arg(long)]
        age_seconds: u64,
        #[arg(long)]
        scope_token: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConfigCommand {
    /// Print the effective configuration
    Show,
    /// Create a new configuration without overwriting an existing file
    Init {
        /// Absolute workspace roots to scan
        paths: Vec<PathBuf>,
        /// Exclude a path relative to each root or an absolute path
        #[arg(long)]
        exclude: Vec<PathBuf>,
        /// Only report artifacts older than this age, for example 30d
        #[arg(long)]
        retention: Option<String>,
        /// Default maintenance schedule frequency
        #[arg(long, value_enum)]
        schedule_frequency: Option<crate::config::ScheduleFrequency>,
    },
}

fn resolve_scan(
    cli: &Cli,
    paths: &[PathBuf],
    exclude: &[PathBuf],
    age: Option<Duration>,
) -> Result<crate::config::ResolvedScan> {
    resolve_scan_config(
        cli.config.as_deref(),
        cli.profile.as_deref(),
        paths,
        exclude,
        age,
    )
}

fn report_git_preview_skipped(
    ctx: &Ctx,
    operation: &str,
    validated_selections: usize,
) -> Result<()> {
    let reason = "Git evidence was not collected during --dry-run; targets remain unverified and no preview plan or token was created.";
    if ctx.json {
        emit_json(
            ctx,
            serde_json::json!({
                "dry_run": true,
                "status": "skipped_unverified",
                "operation": operation,
                "validated_selections": validated_selections,
                "reason": reason,
            }),
        )?;
    } else {
        info(
            ctx,
            format!(
                "Dry-run: {operation} preview skipped; {validated_selections} selection(s) passed non-Git validation. Targets remain unverified; no plan or preview token was created."
            ),
        );
    }
    Ok(())
}

pub(crate) fn resolve_scan_config(
    config: Option<&std::path::Path>,
    profile: Option<&str>,
    paths: &[PathBuf],
    exclude: &[PathBuf],
    age: Option<Duration>,
) -> Result<crate::config::ResolvedScan> {
    let config_path = crate::config::config_path(config)?;
    let settings = crate::config::load(&config_path, config.is_some())?;
    let (paths, exclusions, age) =
        crate::config::profile_scan_options(&settings, profile, paths, exclude, age)?;
    let enabled = crate::config::enabled_ecosystems(&settings, profile)?;
    Ok((paths, exclusions, age, enabled))
}

pub fn main_entry() -> ExitCode {
    main_with(Cli::parse())
}

pub(crate) fn schedule_uses_config(paths: &[PathBuf], exclusions: &[PathBuf]) -> Result<bool> {
    if paths.is_empty() && !exclusions.is_empty() {
        bail!("explicit schedule exclusions require explicit workspace roots");
    }
    Ok(paths.is_empty())
}

pub(crate) fn resolve_schedule_frequency_for(
    config: Option<&std::path::Path>,
    profile: Option<&str>,
    frequency: Option<crate::schedule::Frequency>,
) -> Result<crate::schedule::Frequency> {
    if let Some(frequency) = frequency {
        return Ok(frequency);
    }
    let path = crate::config::config_path(config)?;
    let settings = crate::config::load(&path, config.is_some())?;
    Ok(
        match crate::config::schedule_frequency(&settings, profile)? {
            crate::config::ScheduleFrequency::Daily => crate::schedule::Frequency::Daily,
            crate::config::ScheduleFrequency::Weekly => crate::schedule::Frequency::Weekly,
        },
    )
}

fn resolve_schedule_frequency(
    cli: &Cli,
    frequency: Option<crate::schedule::Frequency>,
) -> Result<crate::schedule::Frequency> {
    resolve_schedule_frequency_for(cli.config.as_deref(), cli.profile.as_deref(), frequency)
}

#[cfg(target_os = "linux")]
fn require_trash_retention_authorization(
    cli: &Cli,
    ctx: &Ctx,
    preview_token: Option<&str>,
    authorized: bool,
) -> Result<()> {
    if !ctx.dry_run && !cli.non_interactive && !cli.json {
        bail!("scheduled Trash retention lifecycle changes require --non-interactive or --json");
    }
    if !ctx.dry_run && (!cli.yes || !authorized || preview_token.is_none()) {
        bail!(
            "scheduled Trash retention changes require --yes, --authorize-scheduled-trash-retention, and a token from a prior preview"
        );
    }
    Ok(())
}

fn run_trash_retention_schedule(
    cli: &Cli,
    ctx: &mut Ctx,
    command: TrashRetentionScheduleCommand,
) -> Result<()> {
    if !cli.non_interactive && !cli.json {
        bail!(
            "scheduled Trash retention CLI commands require --non-interactive or --json; use the Automation screen for an interactive review"
        );
    }
    #[cfg(target_os = "linux")]
    {
        run_linux_trash_retention_schedule(cli, ctx, command)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cli, ctx, command);
        bail!("scheduled Trash retention is supported only on Linux")
    }
}

fn run_scheduled_trash_retention(
    cli: &Cli,
    ctx: &mut Ctx,
    location: PathBuf,
    age_seconds: u64,
    scope_token: String,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !cli.non_interactive || !cli.offline || cli.config.is_none() || cli.profile.is_some() {
            bail!(
                "scheduled Trash retention requires --non-interactive, --offline, an explicit --config path, and no profile"
            );
        }
        let config_path = crate::config::config_path(cli.config.as_deref())?;
        let executable = env::current_exe()?.canonicalize()?;
        let age = Duration::from_secs(age_seconds);
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let (report, history_warning) = if ctx.dry_run {
            (
                crate::scheduled_trash_cleanup::run(
                    &executable,
                    &config_path,
                    &location,
                    age,
                    &scope_token,
                    true,
                    &cancel,
                )
                .map_err(|_| {
                    anyhow!("scheduled Trash retention failed; inspect its redacted report")
                })?,
                None,
            )
        } else {
            let performed = crate::reports::perform_scheduled_trash_retention(
                &ctx.home,
                &executable,
                &config_path,
                &location,
                age,
                &scope_token,
                &cancel,
            );
            let history_warning = performed
                .history_warning
                .is_some()
                .then_some("Local operation history may be incomplete; details are redacted.");
            let report = performed.result.map_err(|_| {
                anyhow!(if history_warning.is_some() {
                    "scheduled Trash retention failed; local operation history may be incomplete (details are redacted)"
                } else {
                    "scheduled Trash retention failed; inspect its redacted report and local history"
                })
            })?;
            (report, history_warning)
        };
        if cli.json {
            let mut output = serde_json::to_value(&report)?;
            if let Some(warning) = &history_warning {
                output["history_warning"] = serde_json::json!(warning);
            }
            emit_json(ctx, output)?;
        } else {
            info(ctx, serde_json::to_string_pretty(&report)?);
            if let Some(warning) = &history_warning {
                warn(ctx, warning);
            }
        }
        if report.outcome != "completed" {
            bail!("scheduled Trash retention was incomplete; inspect the report and history");
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cli, ctx, location, age_seconds, scope_token);
        bail!("scheduled Trash retention is supported only on Linux")
    }
}

#[cfg(target_os = "linux")]
fn run_linux_trash_retention_schedule(
    cli: &Cli,
    ctx: &mut Ctx,
    command: TrashRetentionScheduleCommand,
) -> Result<()> {
    use crate::schedule::trash_retention as retention;

    if ctx.dry_run {
        return match command {
            TrashRetentionScheduleCommand::Status => {
                let status = crate::maintenance::TimerStatus::skipped(
                    "dry-run skips the systemd query; Trash retention schedule state was not inspected",
                );
                if cli.json {
                    emit_json(
                        ctx,
                        serde_json::json!({
                            "unit": "upkit-trash-retention.timer",
                            "dry_run": true,
                            "status": status,
                        }),
                    )
                } else {
                    info(ctx, serde_json::to_string_pretty(&status)?);
                    Ok(())
                }
            }
            TrashRetentionScheduleCommand::Preview { .. }
            | TrashRetentionScheduleCommand::Install { .. }
            | TrashRetentionScheduleCommand::PreviewEnable
            | TrashRetentionScheduleCommand::Enable { .. }
            | TrashRetentionScheduleCommand::PreviewDisable
            | TrashRetentionScheduleCommand::Disable { .. }
            | TrashRetentionScheduleCommand::PreviewRemove
            | TrashRetentionScheduleCommand::Remove { .. } => {
                report_manager_preview_skipped(ctx, cli.json, "trash-retention schedule")
            }
        };
    }

    let executable = || -> Result<PathBuf> { Ok(env::current_exe()?.canonicalize()?) };
    let config_path = || crate::config::config_path(cli.config.as_deref());
    let print_current_preview = |preview: &retention::TrashRetentionCurrentPreview| {
        info(
            ctx,
            format!(
                "Current eligible={}  deferred={}  skipped={}",
                preview.eligible, preview.deferred, preview.skipped
            ),
        );
        for item in &preview.next_run_items {
            info(
                ctx,
                format!(
                    "  {}  kind={}  deleted={}  descendants={}  logical bytes={}",
                    item.name,
                    item.kind,
                    item.deletion_date.as_deref().unwrap_or("unknown"),
                    item.descendant_count,
                    item.logical_bytes
                ),
            );
        }
    };
    let print_schedule_preview = |plan: &retention::TrashRetentionSchedulePreview| -> Result<()> {
        let warning = "Future Trash items at this exact location that exceed this age threshold will be permanently deleted each day while the schedule is enabled.";
        if cli.json {
            emit_json(
                ctx,
                serde_json::json!({
                    "plan": {
                        "location": plan.location,
                        "age_seconds": plan.age_seconds,
                        "current_preview": plan.current_preview,
                        "unit_directory": plan.unit_directory,
                        "service_unit": plan.service_unit,
                        "timer_unit": plan.timer_unit,
                        "preview_token": plan.preview_token,
                        "warning": plan.warning,
                    },
                    "executed": false,
                    "permanent_deletion_warning": warning,
                }),
            )?;
        } else {
            info(
                ctx,
                format!(
                    "Location: {}  age threshold: {} seconds  frequency: daily",
                    crate::sweep::display_path(&plan.location),
                    plan.age_seconds
                ),
            );
            info(ctx, &plan.service_unit);
            info(ctx, &plan.timer_unit);
            print_current_preview(&plan.current_preview);
            info(ctx, plan.warning);
            info(ctx, warning);
            info(ctx, format!("Preview token: {}", plan.preview_token));
        }
        Ok(())
    };
    let print_action = |plan: &retention::TrashRetentionActionPreview,
                        verification: Option<&str>,
                        history_warning: Option<&str>|
     -> Result<()> {
        let permanent_deletion_warning = (plan.action == "enable").then_some({
            "Enabling this schedule will permanently delete future Trash items at the exact location above once they exceed the age threshold above."
        });
        if cli.json {
            emit_json(
                ctx,
                serde_json::json!({
                    "plan": {
                        "action": plan.action,
                        "location": plan.location,
                        "age_seconds": plan.age_seconds,
                        "current_preview": plan.current_preview,
                        "unit_directory": plan.unit_directory,
                        "service_unit": plan.service_unit,
                        "timer_unit": plan.timer_unit,
                        "active_state": plan.active_state,
                        "unit_file_state": plan.unit_file_state,
                        "quarantine_paths": plan.quarantine_paths,
                        "preview_token": plan.preview_token,
                        "warning": plan.warning,
                    },
                    "dry_run": ctx.dry_run,
                    "verification": verification,
                    "history_warning": history_warning,
                    "permanent_deletion_warning": permanent_deletion_warning,
                }),
            )?;
        } else {
            info(
                ctx,
                format!(
                    "Location: {}  age threshold: {} seconds",
                    crate::sweep::display_path(&plan.location),
                    plan.age_seconds
                ),
            );
            info(ctx, plan.action);
            info(ctx, &plan.service_unit);
            info(ctx, &plan.timer_unit);
            if let Some(preview) = &plan.current_preview {
                print_current_preview(preview);
            }
            info(ctx, plan.warning);
            if let Some(warning) = permanent_deletion_warning {
                info(ctx, warning);
            }
            info(ctx, format!("Preview token: {}", plan.preview_token));
            if let Some(warning) = history_warning {
                warn(ctx, warning);
            }
            info(
                ctx,
                verification.map_or("Dry run: no schedule change made.".into(), |value| {
                    format!("Schedule verification: {value}.")
                }),
            );
        }
        if verification == Some("unverified") {
            bail!(
                "Trash retention schedule change could not be verified; inspect the user scheduler before retrying"
            );
        }
        Ok(())
    };
    let perform_action = |plan: &retention::TrashRetentionActionPreview,
                          operation: fn(
        &std::path::Path,
        &retention::TrashRetentionActionPreview,
        &str,
    ) -> crate::reports::Performed<&'static str>,
                          token: &str|
     -> Result<()> {
        let mut history_warning = None;
        let verification = if ctx.dry_run {
            None
        } else {
            let performed = operation(&ctx.home, plan, token);
            history_warning = performed.history_warning;
            Some(performed.result.map_err(|error| {
                anyhow!(
                    "{error}{}",
                    history_warning
                        .as_ref()
                        .map_or(String::new(), |warning| format!("; {warning}"))
                )
            })?)
        };
        print_action(plan, verification, history_warning.as_deref())
    };

    match command {
        TrashRetentionScheduleCommand::Preview {
            location,
            older_than,
        } => {
            let plan = retention::preview_trash_retention(
                &executable()?,
                &config_path()?,
                &location,
                older_than,
            )?;
            print_schedule_preview(&plan)
        }
        TrashRetentionScheduleCommand::Install {
            location,
            older_than,
            preview_token,
            authorize_scheduled_trash_retention,
        } => {
            require_trash_retention_authorization(
                cli,
                ctx,
                preview_token.as_deref(),
                authorize_scheduled_trash_retention,
            )?;
            let plan = retention::preview_trash_retention(
                &executable()?,
                &config_path()?,
                &location,
                older_than,
            )?;
            let mut history_warning = None;
            let verification = if ctx.dry_run {
                None
            } else {
                let performed = crate::reports::perform_trash_retention_install(
                    &ctx.home,
                    &plan,
                    preview_token.as_deref().unwrap_or_default(),
                );
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({
                        "plan": {
                            "location": plan.location,
                            "age_seconds": plan.age_seconds,
                            "current_preview": plan.current_preview,
                            "unit_directory": plan.unit_directory,
                            "service_unit": plan.service_unit,
                            "timer_unit": plan.timer_unit,
                            "preview_token": plan.preview_token,
                            "warning": plan.warning,
                        },
                        "dry_run": ctx.dry_run,
                        "verification": verification,
                        "history_warning": history_warning,
                        "permanent_deletion_warning": "Future Trash items at this exact location that exceed this age threshold will be permanently deleted each day while the schedule is enabled.",
                    }),
                )?;
            } else {
                info(
                    ctx,
                    format!(
                        "Location: {}  age threshold: {} seconds  frequency: daily",
                        crate::sweep::display_path(&plan.location),
                        plan.age_seconds
                    ),
                );
                info(ctx, &plan.service_unit);
                info(ctx, &plan.timer_unit);
                print_current_preview(&plan.current_preview);
                info(ctx, plan.warning);
                info(
                    ctx,
                    "Future matching Trash items will be permanently deleted each day while enabled.",
                );
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    verification.map_or("Dry run: schedule was not installed.".into(), |value| {
                        format!("Schedule installation verification: {value}.")
                    }),
                );
            }
            if verification == Some("unverified") {
                bail!(
                    "Trash retention schedule installation could not be verified; inspect the user scheduler before retrying"
                );
            }
            Ok(())
        }
        TrashRetentionScheduleCommand::PreviewEnable => {
            print_action(&retention::preview_trash_retention_enable()?, None, None)
        }
        TrashRetentionScheduleCommand::Enable {
            preview_token,
            authorize_scheduled_trash_retention,
        } => {
            require_trash_retention_authorization(
                cli,
                ctx,
                preview_token.as_deref(),
                authorize_scheduled_trash_retention,
            )?;
            let plan = retention::preview_trash_retention_enable()?;
            perform_action(
                &plan,
                crate::reports::perform_trash_retention_enable,
                preview_token.as_deref().unwrap_or_default(),
            )
        }
        TrashRetentionScheduleCommand::PreviewDisable => {
            print_action(&retention::preview_trash_retention_disable()?, None, None)
        }
        TrashRetentionScheduleCommand::Disable {
            preview_token,
            authorize_scheduled_trash_retention,
        } => {
            require_trash_retention_authorization(
                cli,
                ctx,
                preview_token.as_deref(),
                authorize_scheduled_trash_retention,
            )?;
            let plan = retention::preview_trash_retention_disable()?;
            perform_action(
                &plan,
                crate::reports::perform_trash_retention_disable,
                preview_token.as_deref().unwrap_or_default(),
            )
        }
        TrashRetentionScheduleCommand::PreviewRemove => {
            print_action(&retention::preview_trash_retention_remove()?, None, None)
        }
        TrashRetentionScheduleCommand::Remove {
            preview_token,
            authorize_scheduled_trash_retention,
        } => {
            require_trash_retention_authorization(
                cli,
                ctx,
                preview_token.as_deref(),
                authorize_scheduled_trash_retention,
            )?;
            let plan = retention::preview_trash_retention_remove()?;
            perform_action(
                &plan,
                crate::reports::perform_trash_retention_remove,
                preview_token.as_deref().unwrap_or_default(),
            )
        }
        TrashRetentionScheduleCommand::Status => {
            let status = retention::trash_retention_status()?;
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({
                        "unit": "upkit-trash-retention.timer",
                        "status": status,
                    }),
                )?;
            } else {
                info(ctx, serde_json::to_string_pretty(&status)?);
            }
            Ok(())
        }
    }
}

fn schedule_tui_request(command: &ScheduleCommand) -> bool {
    match command {
        ScheduleCommand::Preview { .. }
        | ScheduleCommand::PreviewEdit { .. }
        | ScheduleCommand::PreviewEnable { .. }
        | ScheduleCommand::PreviewRemove
        | ScheduleCommand::PreviewDisable => true,
        ScheduleCommand::Add {
            preview_token,
            authorize_schedule,
            ..
        }
        | ScheduleCommand::Enable {
            preview_token,
            authorize_schedule,
            ..
        }
        | ScheduleCommand::Disable {
            preview_token,
            authorize_schedule,
        } => preview_token.is_none() && !authorize_schedule,
        ScheduleCommand::Edit {
            preview_token,
            authorize_schedule_edit,
            ..
        } => preview_token.is_none() && !authorize_schedule_edit,
        ScheduleCommand::Remove {
            preview_token,
            authorize_schedule_removal,
        } => preview_token.is_none() && !authorize_schedule_removal,
        ScheduleCommand::List => false,
        #[cfg(target_os = "linux")]
        ScheduleCommand::TrashRetention { command } => match command {
            TrashRetentionScheduleCommand::Preview { .. }
            | TrashRetentionScheduleCommand::PreviewEnable
            | TrashRetentionScheduleCommand::PreviewDisable
            | TrashRetentionScheduleCommand::PreviewRemove => true,
            TrashRetentionScheduleCommand::Install {
                preview_token,
                authorize_scheduled_trash_retention,
                ..
            }
            | TrashRetentionScheduleCommand::Enable {
                preview_token,
                authorize_scheduled_trash_retention,
            }
            | TrashRetentionScheduleCommand::Disable {
                preview_token,
                authorize_scheduled_trash_retention,
            }
            | TrashRetentionScheduleCommand::Remove {
                preview_token,
                authorize_scheduled_trash_retention,
            } => preview_token.is_none() && !authorize_scheduled_trash_retention,
            TrashRetentionScheduleCommand::Status => true,
        },
        #[cfg(not(target_os = "linux"))]
        ScheduleCommand::TrashRetention { .. } => false,
    }
}

fn report_manager_preview_skipped(ctx: &Ctx, json: bool, operation: &str) -> Result<()> {
    if json {
        emit_json(
            ctx,
            serde_json::json!({
                "operation": operation,
                "dry_run": true,
                "skipped": true,
                "manager_state": "not_inspected",
                "plan": null,
                "preview_token": null,
            }),
        )
    } else {
        info(
            ctx,
            format!(
                "Dry-run: {operation} preview skipped; scheduler state was not inspected and no preview token was created. Run the preview without --dry-run to review a complete plan."
            ),
        );
        Ok(())
    }
}

fn temp_cleanup_tui_request(command: &MaintenanceCommand, interactive: bool) -> bool {
    interactive
        && matches!(
            command,
            MaintenanceCommand::Temp {
                preview: true,
                run: false,
                select,
                preview_token: None,
                authorize_temp_cleanup: false,
            } if select.is_empty()
        )
}

fn trim_tui_target(command: &MaintenanceCommand, interactive: bool) -> Option<PathBuf> {
    if !interactive {
        return None;
    }
    match command {
        MaintenanceCommand::Trim {
            preview: true,
            run: false,
            mount: Some(mount),
            preview_token: None,
            authorize_trim: false,
            ..
        } => Some(mount.clone()),
        _ => None,
    }
}

fn cache_go_test_tui_target(command: &CacheCommand, interactive: bool) -> Option<PathBuf> {
    if !interactive {
        return None;
    }
    match command {
        CacheCommand::GoTest {
            path,
            preview: true,
            run: false,
            preview_token: None,
            authorize_shared_cache: false,
        } => Some(path.clone()),
        _ => None,
    }
}

fn cache_tui_request(command: &CacheCommand, interactive: bool) -> bool {
    (interactive && matches!(command, CacheCommand::Status))
        || cache_go_test_tui_target(command, interactive).is_some()
}

fn report_purge_tui_age(command: &ReportCommand, interactive: bool) -> Option<Duration> {
    if !interactive {
        return None;
    }
    match command {
        ReportCommand::Purge {
            older_than,
            preview: true,
            run: false,
            ..
        } => Some(*older_than),
        _ => None,
    }
}

#[cfg(test)]
mod schedule_route_tests {
    use super::*;

    #[test]
    fn schedule_interactive_routing_does_not_ignore_automation_flags() {
        let command = ScheduleCommand::Add {
            frequency: Some(crate::schedule::Frequency::Weekly),
            paths: vec!["/workspace".into()],
            exclude: vec!["private".into()],
            preview_token: None,
            authorize_schedule: false,
        };
        assert!(schedule_tui_request(&command));
        let ScheduleCommand::Add {
            frequency,
            paths,
            exclude,
            ..
        } = command
        else {
            unreachable!()
        };
        assert!(!schedule_tui_request(&ScheduleCommand::Add {
            frequency,
            paths: paths.clone(),
            exclude: exclude.clone(),
            preview_token: Some("token".into()),
            authorize_schedule: false
        }));
        assert!(!schedule_tui_request(&ScheduleCommand::Add {
            frequency,
            paths,
            exclude,
            preview_token: None,
            authorize_schedule: true
        }));
        assert!(schedule_tui_request(&ScheduleCommand::PreviewDisable));
        assert!(!schedule_tui_request(&ScheduleCommand::Disable {
            preview_token: None,
            authorize_schedule: true
        }));
    }
}

#[cfg(test)]
mod temp_cleanup_route_tests {
    use super::*;

    #[test]
    fn temp_cleanup_interactive_route_only_opens_unselected_preview() {
        let preview = MaintenanceCommand::Temp {
            preview: true,
            run: false,
            select: Vec::new(),
            preview_token: None,
            authorize_temp_cleanup: false,
        };
        assert!(temp_cleanup_tui_request(&preview, true));
        assert!(!temp_cleanup_tui_request(&preview, false));

        for command in [
            MaintenanceCommand::Temp {
                preview: true,
                run: false,
                select: vec![PathBuf::from("fixture")],
                preview_token: None,
                authorize_temp_cleanup: false,
            },
            MaintenanceCommand::Temp {
                preview: false,
                run: true,
                select: Vec::new(),
                preview_token: Some("fixture-token".into()),
                authorize_temp_cleanup: true,
            },
        ] {
            assert!(!temp_cleanup_tui_request(&command, true));
        }
    }
}

#[cfg(test)]
mod trim_route_tests {
    use super::*;

    #[test]
    fn trim_preview_routes_only_interactive_explicit_preview_to_tui() {
        let mount = PathBuf::from("/fixture/mount");
        let preview = MaintenanceCommand::Trim {
            status: false,
            preview: true,
            run: false,
            mount: Some(mount.clone()),
            preview_token: None,
            authorize_trim: false,
        };
        assert_eq!(trim_tui_target(&preview, true), Some(mount.clone()));
        assert_eq!(trim_tui_target(&preview, false), None);

        for command in [
            MaintenanceCommand::Trim {
                status: false,
                preview: false,
                run: true,
                mount: Some(mount.clone()),
                preview_token: Some("fixture-token".into()),
                authorize_trim: true,
            },
            MaintenanceCommand::Trim {
                status: true,
                preview: false,
                run: false,
                mount: None,
                preview_token: None,
                authorize_trim: false,
            },
        ] {
            assert_eq!(trim_tui_target(&command, true), None);
        }
    }
}

#[cfg(test)]
mod cache_route_tests {
    use super::*;

    #[test]
    fn go_test_preview_routes_to_cache_screen_only_for_interactive_preview() {
        let path = PathBuf::from("/workspace/cache with spaces");
        let preview = CacheCommand::GoTest {
            path: path.clone(),
            preview: true,
            run: false,
            preview_token: None,
            authorize_shared_cache: false,
        };
        assert!(cache_tui_request(&preview, true));
        assert_eq!(cache_go_test_tui_target(&preview, true), Some(path.clone()));
        assert!(!cache_tui_request(&preview, false));
        assert_eq!(cache_go_test_tui_target(&preview, false), None);

        let authorized_run = CacheCommand::GoTest {
            path,
            preview: false,
            run: true,
            preview_token: Some("fixture-token".into()),
            authorize_shared_cache: true,
        };
        assert!(!cache_tui_request(&authorized_run, true));
        assert_eq!(cache_go_test_tui_target(&authorized_run, true), None);
    }
}

#[cfg(test)]
mod report_route_tests {
    use super::*;

    #[test]
    fn interactive_history_preview_routes_to_reports_with_requested_age() {
        let age = Duration::from_secs(30 * 86_400);
        let preview = ReportCommand::Purge {
            older_than: age,
            preview: true,
            run: false,
            preview_token: None,
            authorize_history_purge: false,
        };
        assert_eq!(report_purge_tui_age(&preview, true), Some(age));
        assert_eq!(report_purge_tui_age(&preview, false), None);

        let run = ReportCommand::Purge {
            older_than: age,
            preview: false,
            run: true,
            preview_token: Some("fixture-token".into()),
            authorize_history_purge: true,
        };
        assert_eq!(report_purge_tui_age(&run, true), None);
    }
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
    let interactive = !cli.non_interactive
        && !cli.json
        && !cli.yes
        && !cli.dry_run
        && !cli.offline
        && !cli.quiet
        && io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && env::var_os("CI").is_none();
    let temp_cleanup_tui = match &cli.cmd {
        Some(Commands::Maintenance { command }) => temp_cleanup_tui_request(command, interactive),
        _ => false,
    };
    let trim_tui_mount = match &cli.cmd {
        Some(Commands::Maintenance { command }) => trim_tui_target(command, interactive),
        _ => None,
    };
    let go_test_tui_target = match &cli.cmd {
        Some(Commands::Cache { command }) => cache_go_test_tui_target(command, interactive),
        _ => None,
    };
    let history_purge_preview = match &cli.cmd {
        Some(Commands::Report {
            command: Some(command),
        }) => report_purge_tui_age(command, interactive),
        _ => None,
    };
    let managed_scope = match &cli.cmd {
        Some(Commands::Clean { tools, .. } | Commands::Uninstall { tools, .. }) => {
            let mut selected = Vec::new();
            for tool in if tools.is_empty() {
                select_kinds(cli.only)
            } else {
                tools.clone()
            } {
                if !selected.contains(&tool) {
                    selected.push(tool);
                }
            }
            Some(selected)
        }
        Some(Commands::ManagedClean {
            tool,
            run: false,
            preview_token: None,
            authorize_managed_cleanup: false,
        }) => Some(vec![*tool]),
        _ => None,
    };
    let start = match &cli.cmd {
        None if interactive => Some((crate::tui::Start::Dashboard, None)),
        Some(Commands::Check) if interactive => Some((crate::tui::Start::Toolchains, None)),
        Some(Commands::Doctor) if interactive => Some((crate::tui::Start::Doctor, None)),
        Some(Commands::Config {
            command: ConfigCommand::Show,
        }) if interactive => Some((crate::tui::Start::Settings, None)),
        Some(Commands::Report { command: None }) if interactive => {
            Some((crate::tui::Start::Reports, None))
        }
        Some(Commands::Report {
            command: Some(ReportCommand::Purge { .. }),
        }) if history_purge_preview.is_some() => Some((crate::tui::Start::Reports, None)),
        Some(Commands::Schedule {
            command: ScheduleCommand::List,
        }) if interactive => Some((crate::tui::Start::Automation, None)),
        Some(Commands::Schedule { command }) if interactive && schedule_tui_request(command) => {
            Some((crate::tui::Start::Automation, None))
        }
        Some(Commands::Maintenance {
            command:
                MaintenanceCommand::Temp {
                    preview: true,
                    run: false,
                    preview_token: None,
                    authorize_temp_cleanup: false,
                    ..
                },
        }) if temp_cleanup_tui => Some((crate::tui::Start::Maintenance, None)),
        Some(Commands::Maintenance {
            command: MaintenanceCommand::Trim { .. },
        }) if trim_tui_mount.is_some() => Some((crate::tui::Start::Maintenance, None)),
        Some(Commands::Maintenance {
            command:
                MaintenanceCommand::Status
                | MaintenanceCommand::Trim {
                    preview: false,
                    run: false,
                    mount: None,
                    ..
                },
        }) if interactive => Some((crate::tui::Start::Maintenance, None)),
        Some(Commands::Cache { command }) if cache_tui_request(command, interactive) => {
            Some((crate::tui::Start::Cache, None))
        }
        Some(Commands::Trash { .. }) if interactive => Some((crate::tui::Start::Trash, None)),
        Some(Commands::Containers {
            command:
                ContainerCommand::RemoveBuildCache {
                    preview_token: Some(_),
                    ..
                }
                | ContainerCommand::RemoveBuildCache {
                    authorize_build_cache_removal: true,
                    ..
                },
        }) if interactive => None,
        Some(Commands::Containers {
            command: ContainerCommand::PreviewImage { .. } | ContainerCommand::RemoveImage { .. },
        }) => None,
        Some(Commands::Containers { .. }) if interactive => {
            Some((crate::tui::Start::Containers, None))
        }
        Some(Commands::Sweep {
            command: SweepCommand::Report,
        }) if interactive => Some((crate::tui::Start::Reports, None)),
        Some(Commands::Sweep {
            command:
                SweepCommand::Run {
                    scope: SweepRunScope::Artifacts,
                    select,
                    preview: false,
                    preview_token: None,
                    authorize_artifact_removal: false,
                    authorize_shared_cache: false,
                    ..
                },
        }) if interactive && select.len() <= 1 => Some((crate::tui::Start::Artifacts, None)),
        Some(Commands::Sweep {
            command:
                SweepCommand::Run {
                    scope: SweepRunScope::Cache,
                    select,
                    root,
                    exclude,
                    older_than: None,
                    preview: false,
                    preview_token: None,
                    authorize_artifact_removal: false,
                    authorize_shared_cache: false,
                    ..
                },
        }) if interactive
            && select.len() == 1
            && root.is_empty()
            && exclude.is_empty()
            && cli.config.is_none()
            && cli.profile.is_none() =>
        {
            Some((crate::tui::Start::Cache, None))
        }
        Some(Commands::Sweep {
            command: SweepCommand::Run { .. },
        }) => None,
        Some(Commands::Sweep {
            command:
                SweepCommand::Bytecode {
                    run: false,
                    preview_token: None,
                    authorize_bytecode_removal: false,
                    ..
                },
        }) if interactive => Some((crate::tui::Start::Artifacts, None)),
        Some(Commands::Sweep {
            command: SweepCommand::Bytecode { .. } | SweepCommand::BytecodeBatch { .. },
        }) => None,
        Some(Commands::Sweep {
            command:
                SweepCommand::Scan {
                    scope_token: Some(_),
                    ..
                },
        }) if interactive => None,
        Some(Commands::Sweep {
            command:
                SweepCommand::ScheduledBytecodeCleanup { .. } | SweepCommand::ScheduledCleanup { .. },
        }) => None,
        Some(Commands::Trash {
            command: TrashCommand::ScheduledRetention { .. },
        }) => None,
        Some(Commands::Sweep { .. }) if interactive => Some((crate::tui::Start::Artifacts, None)),
        Some(Commands::Clean { safety, .. } | Commands::Uninstall { safety, .. })
            if interactive
                && !safety.preview
                && safety.preview_token.is_none()
                && !safety.authorize_managed_cleanup =>
        {
            Some((crate::tui::Start::Toolchains, managed_scope.clone()))
        }
        Some(Commands::ManagedClean {
            run: false,
            preview_token: None,
            authorize_managed_cleanup: false,
            ..
        }) if interactive => Some((crate::tui::Start::Toolchains, managed_scope.clone())),
        Some(Commands::Update { tools, all, force }) if interactive => {
            ctx.force = *force;
            let selected = if !tools.is_empty() {
                Some(tools.clone())
            } else if *all {
                Some(select_kinds(cli.only))
            } else {
                None
            };
            Some((crate::tui::Start::Toolchains, selected))
        }
        Some(Commands::SelfUpdate) if interactive => Some((crate::tui::Start::Toolchains, None)),
        Some(Commands::Tui) if interactive => Some((crate::tui::Start::Dashboard, None)),
        _ => None,
    };
    if let Some((start, selected)) = start {
        let scan = match &cli.cmd {
            Some(Commands::Sweep {
                command:
                    SweepCommand::Scan {
                        paths,
                        exclude,
                        older_than,
                        scope_token: _,
                    },
            }) => match resolve_scan(&cli, paths, exclude, *older_than) {
                Ok((paths, exclude, older_than, enabled)) => {
                    Some((paths, exclude, older_than, enabled, None))
                }
                Err(err) => {
                    error(format!("{err:#}"));
                    return ExitCode::from(map_error_to_exit_code(&err));
                }
            },
            Some(Commands::Sweep {
                command:
                    SweepCommand::Preview {
                        paths,
                        exclude,
                        older_than,
                        select,
                    },
            }) => match resolve_scan(&cli, paths, exclude, *older_than) {
                Ok((paths, exclude, older_than, enabled)) => {
                    Some((paths, exclude, older_than, enabled, Some(select.clone())))
                }
                Err(err) => {
                    error(format!("{err:#}"));
                    return ExitCode::from(map_error_to_exit_code(&err));
                }
            },
            _ => None,
        };
        return match crate::tui::run_with_config(
            &ctx,
            start,
            cli.only,
            selected,
            scan,
            crate::tui::LaunchOptions {
                config: cli.config.clone(),
                profile: cli.profile.clone(),
                temp_cleanup_requested: temp_cleanup_tui,
                trim_preview_target: trim_tui_mount.clone(),
                schedule_request: match &cli.cmd {
                    Some(Commands::Schedule { command }) if schedule_tui_request(command) => {
                        Some(command.clone())
                    }
                    _ => None,
                },
                trash_age: match &cli.cmd {
                    Some(Commands::Trash {
                        command:
                            TrashCommand::Preview { older_than }
                            | TrashCommand::PreviewRemove { older_than, .. }
                            | TrashCommand::Remove { older_than, .. }
                            | TrashCommand::PreviewBatch { older_than, .. }
                            | TrashCommand::RemoveBatch { older_than, .. }
                            | TrashCommand::PreviewRetention { older_than, .. }
                            | TrashCommand::Retain { older_than, .. },
                    }) => Some(*older_than),
                    _ => None,
                },
                trash_target: match &cli.cmd {
                    Some(Commands::Trash {
                        command:
                            TrashCommand::PreviewRemove {
                                location,
                                name,
                                older_than,
                            }
                            | TrashCommand::Remove {
                                location,
                                name,
                                older_than,
                                ..
                            },
                    }) => Some((location.clone(), vec![name.clone()], *older_than)),
                    Some(Commands::Trash {
                        command:
                            TrashCommand::PreviewBatch {
                                location,
                                name,
                                older_than,
                            }
                            | TrashCommand::RemoveBatch {
                                location,
                                name,
                                older_than,
                                ..
                            },
                    }) => Some((location.clone(), name.clone(), *older_than)),
                    _ => None,
                },
                trash_retention_target: match &cli.cmd {
                    Some(Commands::Trash {
                        command:
                            TrashCommand::PreviewRetention {
                                location,
                                older_than,
                            }
                            | TrashCommand::Retain {
                                location,
                                older_than,
                                ..
                            },
                    }) => Some((location.clone(), *older_than)),
                    _ => None,
                },
                trash_empty_target: match &cli.cmd {
                    Some(Commands::Trash {
                        command:
                            TrashCommand::PreviewEmpty { location }
                            | TrashCommand::Empty { location, .. },
                    }) => Some(location.clone()),
                    _ => None,
                },
                container_target: match &cli.cmd {
                    Some(Commands::Containers {
                        command:
                            ContainerCommand::PreviewRemove { engine, id }
                            | ContainerCommand::Remove { engine, id, .. },
                    }) => Some((engine.clone(), id.clone())),
                    _ => None,
                },
                network_target: match &cli.cmd {
                    Some(Commands::Containers {
                        command:
                            ContainerCommand::PreviewNetwork { engine, id }
                            | ContainerCommand::RemoveNetwork { engine, id, .. },
                    }) => Some((engine.clone(), id.clone())),
                    _ => None,
                },
                build_cache_target: match &cli.cmd {
                    Some(Commands::Containers {
                        command: ContainerCommand::PreviewBuildCache { builder, id },
                    }) => Some((builder.clone(), id.clone(), true)),
                    Some(Commands::Containers {
                        command: ContainerCommand::RemoveBuildCache { builder, id, .. },
                    }) => Some((builder.clone(), id.clone(), false)),
                    _ => None,
                },
                bytecode_target: match &cli.cmd {
                    Some(Commands::Sweep {
                        command:
                            SweepCommand::Bytecode {
                                file,
                                root,
                                exclude,
                                older_than,
                                ..
                            },
                    }) => Some(crate::tui::BytecodeRequest {
                        file: file.clone(),
                        roots: root.clone(),
                        exclusions: exclude.clone(),
                        age: *older_than,
                    }),
                    _ => None,
                },
                artifact_target: match &cli.cmd {
                    Some(Commands::Sweep {
                        command:
                            SweepCommand::Run {
                                scope: SweepRunScope::Artifacts,
                                select,
                                root,
                                exclude,
                                older_than,
                                ..
                            },
                    }) => select.first().map(|file| crate::tui::BytecodeRequest {
                        file: file.clone(),
                        roots: root.clone(),
                        exclusions: exclude.clone(),
                        age: *older_than,
                    }),
                    _ => None,
                },
                shared_cache_target: match &cli.cmd {
                    Some(Commands::Sweep {
                        command:
                            SweepCommand::Run {
                                scope: SweepRunScope::Cache,
                                select,
                                ..
                            },
                    }) => select.first().cloned(),
                    _ => None,
                },
                go_test_target: go_test_tui_target.clone(),
                history_purge_preview,
                artifact_scope: match &cli.cmd {
                    Some(Commands::Sweep {
                        command:
                            SweepCommand::Scan {
                                paths,
                                exclude,
                                older_than,
                                ..
                            }
                            | SweepCommand::Preview {
                                paths,
                                exclude,
                                older_than,
                                ..
                            },
                    }) => Some((paths.clone(), exclude.clone(), *older_than)),
                    Some(Commands::Sweep {
                        command:
                            SweepCommand::Run {
                                root,
                                exclude,
                                older_than,
                                ..
                            },
                    }) => Some((root.clone(), exclude.clone(), *older_than)),
                    _ => None,
                },
                managed_scope: managed_scope.clone(),
                self_update_requested: matches!(&cli.cmd, Some(Commands::SelfUpdate)),
            },
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                error(err.to_string());
                ExitCode::FAILURE
            }
        };
    }
    let command = cli.cmd.clone().unwrap_or(Commands::Check);
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
    if result.is_ok() && matches!(command, Commands::Update { .. } | Commands::SelfUpdate) {
        let _ = ensure_required_paths(&ctx);
    }
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

fn report_container_dry_run_skip(
    cli: &Cli,
    ctx: &mut Ctx,
    engine: &str,
    id: &str,
    resource: &str,
    operation: &str,
) -> Result<()> {
    if ctx.offline {
        bail!("container operations are unavailable in offline mode");
    }
    crate::containers::validate_engine(engine)?;
    crate::containers::validate_full_id(id, resource)?;
    let detail = format!(
        "Dry-run skipped {engine} engine inspection; no {operation} plan was generated or verified."
    );
    if cli.json {
        emit_json(
            ctx,
            serde_json::json!({
                "engine": engine,
                "operation": operation,
                "plan": null,
                "dry_run": true,
                "executed": false,
                "verification": "not_run",
                "detail": detail,
            }),
        )?;
    } else {
        info(ctx, detail);
        info(ctx, "No engine command or resource change was performed.");
    }
    Ok(())
}

pub fn run(cli: &Cli, ctx: &mut Ctx) -> Result<()> {
    if cli.non_interactive
        && !ctx.yes
        && matches!(
            cli.cmd,
            Some(Commands::Update { .. } | Commands::SelfUpdate)
        )
    {
        bail!("non-interactive mode: use --yes to confirm this operation");
    }
    match cli.cmd.clone().unwrap_or(Commands::Check) {
        Commands::Schedule {
            command: ScheduleCommand::TrashRetention { command },
        } => run_trash_retention_schedule(cli, ctx, command)?,
        Commands::ManagedClean {
            tool,
            run,
            preview_token,
            authorize_managed_cleanup,
        } => {
            if !cli.non_interactive {
                bail!(
                    "managed cleanup preview and removal require --non-interactive outside the dashboard"
                );
            }
            if run
                && !ctx.dry_run
                && (!ctx.yes || !authorize_managed_cleanup || preview_token.is_none())
            {
                bail!(
                    "managed cleanup requires --yes, --authorize-managed-cleanup, and a token from a prior preview"
                );
            }
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let plan = crate::managed_cleanup::preview(ctx, tool, &cancel)?;
            let mut history_warning = None;
            let verification = if run && !ctx.dry_run {
                if preview_token.as_deref() != Some(plan.preview_token.as_str()) {
                    bail!(
                        "managed cleanup preview changed or token does not match; review it again"
                    );
                }
                let performed = crate::reports::perform_managed_cleanup(ctx, &plan, &cancel);
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            } else {
                None
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({"plan": plan, "dry_run": ctx.dry_run, "verification": verification, "history_warning": history_warning}),
                )?;
            } else {
                info(ctx, serde_json::to_string_pretty(&plan)?);
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    verification.map_or("Preview only; no tool was removed.".into(), |status| {
                        format!("Removal verification: {status}.")
                    }),
                );
            }
            if verification == Some("unverified_replacement") {
                bail!(
                    "cleanup completed but an original path is occupied; inspect it before retrying"
                );
            }
        }
        Commands::Schedule {
            command:
                ScheduleCommand::PreviewEdit {
                    frequency,
                    exclude,
                    paths,
                },
        } => {
            if ctx.dry_run {
                report_manager_preview_skipped(ctx, cli.json, "schedule edit preview")?;
                return Ok(());
            }
            let frequency = resolve_schedule_frequency(cli, frequency)?;
            let executable = env::current_exe()?.canonicalize()?;
            let plan = if schedule_uses_config(&paths, &exclude)? {
                crate::schedule::preview_configured_edit(
                    &executable,
                    cli.config.as_deref(),
                    cli.profile.as_deref(),
                    frequency,
                )?
            } else {
                crate::schedule::preview_edit(&executable, &paths, &exclude, frequency)?
            };
            if cli.json {
                emit_json(ctx, serde_json::to_value(&plan)?)?;
            } else {
                info(ctx, "Existing schedule definition:");
                info(ctx, &plan.previous.existing.service_unit);
                info(ctx, &plan.previous.existing.timer_unit);
                for path in &plan.previous.quarantine_paths {
                    info(
                        ctx,
                        format!("Quarantine: {}", crate::sweep::display_path(path)),
                    );
                }
                info(ctx, "Replacement schedule definition:");
                info(ctx, &plan.replacement.service_unit);
                info(ctx, &plan.replacement.timer_unit);
                info(ctx, plan.replacement.warning);
                info(ctx, plan.warning);
                info(ctx, format!("Preview token: {}", plan.preview_token));
            }
        }
        Commands::Schedule {
            command:
                ScheduleCommand::Edit {
                    frequency,
                    exclude,
                    paths,
                    preview_token,
                    authorize_schedule_edit,
                },
        } => {
            if ctx.dry_run {
                report_manager_preview_skipped(ctx, cli.json, "schedule edit")?;
                return Ok(());
            }
            let frequency = resolve_schedule_frequency(cli, frequency)?;
            if !cli.non_interactive && !ctx.dry_run {
                bail!("schedule edit with authorization flags requires --non-interactive");
            }
            if !ctx.dry_run && (!ctx.yes || !authorize_schedule_edit || preview_token.is_none()) {
                bail!(
                    "schedule edit requires --yes, --authorize-schedule-edit, and a token from a prior edit preview"
                );
            }
            let executable = env::current_exe()?.canonicalize()?;
            let configured = schedule_uses_config(&paths, &exclude)?;
            let plan = if configured {
                crate::schedule::preview_configured_edit(
                    &executable,
                    cli.config.as_deref(),
                    cli.profile.as_deref(),
                    frequency,
                )?
            } else {
                crate::schedule::preview_edit(&executable, &paths, &exclude, frequency)?
            };
            let mut history_warning = None;
            let verification = if ctx.dry_run {
                None
            } else {
                let performed = if configured {
                    crate::reports::perform_configured_schedule_edit(
                        &ctx.home,
                        &executable,
                        &plan,
                        preview_token.as_deref().unwrap_or_default(),
                        frequency,
                        cli.config.as_deref(),
                        cli.profile.as_deref(),
                    )
                } else {
                    crate::reports::perform_schedule_edit(
                        &ctx.home,
                        &executable,
                        &plan,
                        preview_token.as_deref().unwrap_or_default(),
                        frequency,
                    )
                };
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({ "plan": plan, "dry_run": ctx.dry_run, "verification": verification, "history_warning": history_warning }),
                )?;
            } else {
                info(ctx, &plan.previous.existing.service_unit);
                info(ctx, &plan.previous.existing.timer_unit);
                for path in &plan.previous.quarantine_paths {
                    info(
                        ctx,
                        format!("Quarantine: {}", crate::sweep::display_path(path)),
                    );
                }
                info(ctx, &plan.replacement.service_unit);
                info(ctx, &plan.replacement.timer_unit);
                info(ctx, plan.replacement.warning);
                info(ctx, plan.warning);
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    verification.map_or("Dry run: schedule was not changed.".into(), |status| {
                        format!("Schedule edit verification: {status}.")
                    }),
                );
            }
            if verification == Some("unverified") {
                bail!(
                    "replacement schedule could not be verified; inspect the platform scheduler before retrying"
                );
            }
        }
        Commands::Schedule {
            command: ScheduleCommand::PreviewRemove,
        } => {
            if ctx.dry_run {
                report_manager_preview_skipped(ctx, cli.json, "schedule removal preview")?;
                return Ok(());
            }
            let plan = crate::schedule::preview_remove()?;
            if cli.json {
                emit_json(ctx, serde_json::to_value(&plan)?)?;
            } else {
                info(
                    ctx,
                    format!(
                        "Schedule location: {}",
                        crate::sweep::display_path(&plan.existing.unit_directory)
                    ),
                );
                info(ctx, &plan.existing.service_unit);
                info(ctx, &plan.existing.timer_unit);
                for path in &plan.quarantine_paths {
                    info(
                        ctx,
                        format!("Quarantine: {}", crate::sweep::display_path(path)),
                    );
                }
                info(ctx, plan.warning);
                info(ctx, format!("Preview token: {}", plan.preview_token));
            }
        }
        Commands::Schedule {
            command:
                ScheduleCommand::Remove {
                    preview_token,
                    authorize_schedule_removal,
                },
        } => {
            if ctx.dry_run {
                report_manager_preview_skipped(ctx, cli.json, "schedule removal")?;
                return Ok(());
            }
            if !cli.non_interactive && !ctx.dry_run {
                bail!("schedule removal with authorization flags requires --non-interactive");
            }
            if !ctx.dry_run && (!ctx.yes || !authorize_schedule_removal || preview_token.is_none())
            {
                bail!(
                    "schedule removal requires --yes, --authorize-schedule-removal, and a token from a prior removal preview"
                );
            }
            let plan = crate::schedule::preview_remove()?;
            let mut history_warning = None;
            let verification = if ctx.dry_run {
                None
            } else {
                let performed = crate::reports::perform_schedule_removal(
                    &ctx.home,
                    &plan,
                    preview_token.as_deref().unwrap_or_default(),
                );
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({ "plan": plan, "dry_run": ctx.dry_run, "verification": verification, "history_warning": history_warning }),
                )?;
            } else {
                info(ctx, &plan.existing.service_unit);
                info(ctx, &plan.existing.timer_unit);
                for path in &plan.quarantine_paths {
                    info(
                        ctx,
                        format!("Quarantine: {}", crate::sweep::display_path(path)),
                    );
                }
                info(ctx, plan.warning);
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    verification.map_or(
                        "Dry run: schedule definitions were not removed.".into(),
                        |status| format!("Schedule removal verification: {status}."),
                    ),
                );
            }
            if verification == Some("unverified") {
                bail!(
                    "schedule removal could not be verified; inspect the platform scheduler before retrying"
                );
            }
        }
        Commands::Schedule {
            command:
                ScheduleCommand::PreviewEnable {
                    frequency,
                    exclude,
                    paths,
                },
        } => {
            if ctx.dry_run {
                report_manager_preview_skipped(ctx, cli.json, "schedule enable preview")?;
                return Ok(());
            }
            let frequency = resolve_schedule_frequency(cli, frequency)?;
            let executable = env::current_exe()?.canonicalize()?;
            let plan = if schedule_uses_config(&paths, &exclude)? {
                crate::schedule::preview_configured_enable(
                    &executable,
                    cli.config.as_deref(),
                    cli.profile.as_deref(),
                    frequency,
                )?
            } else {
                crate::schedule::preview_enable(&executable, &paths, &exclude, frequency)?
            };
            if cli.json {
                emit_json(ctx, serde_json::to_value(&plan)?)?;
            } else {
                info(
                    ctx,
                    format!(
                        "Schedule location: {}",
                        crate::sweep::display_path(&plan.intended.unit_directory)
                    ),
                );
                info(ctx, &plan.installed.service_unit);
                info(ctx, &plan.installed.timer_unit);
                info(ctx, plan.intended.warning);
                info(ctx, plan.warning);
                info(ctx, format!("Preview token: {}", plan.preview_token));
            }
        }
        Commands::Schedule {
            command:
                ScheduleCommand::Enable {
                    frequency,
                    exclude,
                    paths,
                    preview_token,
                    authorize_schedule,
                },
        } => {
            if ctx.dry_run {
                report_manager_preview_skipped(ctx, cli.json, "schedule enable")?;
                return Ok(());
            }
            let frequency = resolve_schedule_frequency(cli, frequency)?;
            if !cli.non_interactive && !ctx.dry_run {
                bail!("schedule enable with authorization flags requires --non-interactive");
            }
            if !ctx.dry_run && (!ctx.yes || !authorize_schedule || preview_token.is_none()) {
                bail!(
                    "schedule enable requires --yes, --authorize-schedule, and a token from a prior enable preview"
                );
            }
            let executable = env::current_exe()?.canonicalize()?;
            let configured = schedule_uses_config(&paths, &exclude)?;
            let plan = if configured {
                crate::schedule::preview_configured_enable(
                    &executable,
                    cli.config.as_deref(),
                    cli.profile.as_deref(),
                    frequency,
                )?
            } else {
                crate::schedule::preview_enable(&executable, &paths, &exclude, frequency)?
            };
            let mut history_warning = None;
            let verification = if ctx.dry_run {
                None
            } else {
                let performed = if configured {
                    crate::reports::perform_configured_schedule_enable(
                        &ctx.home,
                        &executable,
                        &plan,
                        preview_token.as_deref().unwrap_or_default(),
                        frequency,
                        cli.config.as_deref(),
                        cli.profile.as_deref(),
                    )
                } else {
                    crate::reports::perform_schedule_enable(
                        &ctx.home,
                        &executable,
                        &plan,
                        preview_token.as_deref().unwrap_or_default(),
                        frequency,
                    )
                };
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({ "plan": plan, "dry_run": ctx.dry_run, "verification": verification, "history_warning": history_warning }),
                )?;
            } else {
                info(ctx, &plan.installed.service_unit);
                info(ctx, &plan.installed.timer_unit);
                info(ctx, plan.intended.warning);
                info(ctx, plan.warning);
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    verification.map_or("Dry run: schedule was not enabled.".into(), |status| {
                        format!("Schedule enable verification: {status}.")
                    }),
                );
            }
            if verification == Some("unverified") {
                bail!(
                    "schedule enable could not be verified; inspect the platform scheduler before retrying"
                );
            }
        }
        Commands::Schedule {
            command: ScheduleCommand::PreviewDisable,
        } => {
            if ctx.dry_run {
                report_manager_preview_skipped(ctx, cli.json, "schedule disable preview")?;
                return Ok(());
            }
            let plan = crate::schedule::preview_disable()?;
            if cli.json {
                emit_json(ctx, serde_json::to_value(&plan)?)?;
            } else {
                info(
                    ctx,
                    format!(
                        "Schedule location: {}",
                        crate::sweep::display_path(&plan.unit_directory)
                    ),
                );
                info(
                    ctx,
                    format!(
                        "State: {}  enabled: {}",
                        plan.active_state,
                        plan.unit_file_state.as_deref().unwrap_or("unknown")
                    ),
                );
                info(ctx, &plan.service_unit);
                info(ctx, &plan.timer_unit);
                info(ctx, plan.warning);
                info(ctx, format!("Preview token: {}", plan.preview_token));
            }
        }
        Commands::Schedule {
            command:
                ScheduleCommand::Disable {
                    preview_token,
                    authorize_schedule,
                },
        } => {
            if ctx.dry_run {
                report_manager_preview_skipped(ctx, cli.json, "schedule disable")?;
                return Ok(());
            }
            if !cli.non_interactive && !ctx.dry_run {
                bail!("schedule disable with authorization flags requires --non-interactive");
            }
            if !ctx.dry_run && (!ctx.yes || !authorize_schedule || preview_token.is_none()) {
                bail!(
                    "schedule disable requires --yes, --authorize-schedule, and a token from a prior disable preview"
                );
            }
            let plan = crate::schedule::preview_disable()?;
            let mut history_warning = None;
            let verification = if ctx.dry_run {
                None
            } else {
                let performed = crate::reports::perform_schedule_disable(
                    &ctx.home,
                    &plan,
                    preview_token.as_deref().unwrap_or_default(),
                );
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({ "plan": plan, "dry_run": ctx.dry_run, "verification": verification, "history_warning": history_warning }),
                )?;
            } else {
                info(ctx, &plan.service_unit);
                info(ctx, &plan.timer_unit);
                info(ctx, plan.warning);
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    verification.map_or("Dry run: schedule was not disabled.".into(), |status| {
                        format!("Schedule disable verification: {status}.")
                    }),
                );
            }
            if verification == Some("unverified") {
                bail!(
                    "schedule disable could not be verified; inspect the platform scheduler before retrying"
                );
            }
        }
        Commands::Schedule {
            command:
                ScheduleCommand::Add {
                    frequency,
                    exclude,
                    preview_token,
                    authorize_schedule,
                    paths,
                },
        } => {
            let frequency = resolve_schedule_frequency(cli, frequency)?;
            if !cli.non_interactive && !ctx.dry_run {
                bail!("schedule add with authorization flags requires --non-interactive");
            }
            if !ctx.dry_run && (!ctx.yes || !authorize_schedule || preview_token.is_none()) {
                bail!(
                    "schedule installation requires --yes, --authorize-schedule, and a token from a prior preview"
                );
            }
            let executable = env::current_exe()?.canonicalize()?;
            let configured = schedule_uses_config(&paths, &exclude)?;
            let plan = if configured {
                crate::schedule::preview_configured_install(
                    &executable,
                    cli.config.as_deref(),
                    cli.profile.as_deref(),
                    frequency,
                )?
            } else {
                crate::schedule::preview_scan(&executable, &paths, &exclude, frequency)?
            };
            let mut history_warning = None;
            let verification = if ctx.dry_run {
                None
            } else {
                let performed = if configured {
                    crate::reports::perform_configured_schedule_install(
                        &ctx.home,
                        &executable,
                        &plan,
                        preview_token.as_deref().unwrap_or_default(),
                        frequency,
                        cli.config.as_deref(),
                        cli.profile.as_deref(),
                    )
                } else {
                    crate::reports::perform_schedule_install(
                        &ctx.home,
                        &executable,
                        &plan,
                        preview_token.as_deref().unwrap_or_default(),
                        frequency,
                    )
                };
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({ "plan": plan, "dry_run": ctx.dry_run, "verification": verification, "history_warning": history_warning }),
                )?;
            } else {
                info(ctx, &plan.service_unit);
                info(ctx, &plan.timer_unit);
                info(ctx, plan.warning);
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    verification.map_or("Dry run: no schedule installed.".into(), |status| {
                        format!("Schedule installation verification: {status}.")
                    }),
                );
            }
            if verification == Some("unverified") {
                bail!(
                    "schedule installation could not be verified; inspect the platform scheduler before retrying"
                );
            }
        }
        Commands::Schedule {
            command: ScheduleCommand::List,
        } => {
            let status = crate::schedule::status_with_dry_run(ctx.dry_run);
            let schedule_name = if cfg!(target_os = "windows") {
                r"\Upkit-Workspace-Scan"
            } else {
                "upkit-scan.timer"
            };
            let ownership_verified =
                cfg!(target_os = "windows") && status.load_state.as_deref() == Some("registered");
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({ "unit": schedule_name, "status": status, "ownership_verified": ownership_verified }),
                )?;
            } else {
                if cfg!(target_os = "windows") {
                    info(
                        ctx,
                        format!(
                            "{schedule_name}: state={}  enabled={}  last={}  next={}",
                            status.state,
                            status.unit_file_state.as_deref().unwrap_or("unknown"),
                            status.last_trigger.as_deref().unwrap_or("unknown"),
                            status.next_trigger.as_deref().unwrap_or("unknown")
                        ),
                    );
                } else {
                    info(
                        ctx,
                        format!(
                            "{schedule_name}: {}  unit-file={}  last={}  next={}",
                            status.state,
                            status.unit_file_state.as_deref().unwrap_or("unknown"),
                            status.last_trigger.as_deref().unwrap_or("unknown"),
                            status.next_trigger.as_deref().unwrap_or("unknown")
                        ),
                    );
                }
                if let Some(detail) = status.detail {
                    info(ctx, detail);
                }
                if !cfg!(target_os = "windows") {
                    info(
                        ctx,
                        "Timer name only; ownership and configured action are not verified.",
                    );
                }
            }
        }
        Commands::Schedule {
            command:
                ScheduleCommand::Preview {
                    frequency,
                    paths,
                    exclude,
                },
        } => {
            let frequency = resolve_schedule_frequency(cli, frequency)?;
            let executable = env::current_exe()?.canonicalize()?;
            let plan = if schedule_uses_config(&paths, &exclude)? {
                crate::schedule::preview_configured_install(
                    &executable,
                    cli.config.as_deref(),
                    cli.profile.as_deref(),
                    frequency,
                )?
            } else {
                crate::schedule::preview_scan(&executable, &paths, &exclude, frequency)?
            };
            if cli.json {
                emit_json(ctx, serde_json::to_value(&plan)?)?;
            } else {
                info(
                    ctx,
                    format!(
                        "Schedule location: {}",
                        crate::sweep::display_path(&plan.unit_directory)
                    ),
                );
                info(ctx, format!("Preview token: {}", plan.preview_token));
                info(ctx, &plan.service_unit);
                info(ctx, &plan.timer_unit);
                info(ctx, plan.warning);
            }
        }
        Commands::Report { command: None }
        | Commands::Sweep {
            command: SweepCommand::Report,
        } => {
            let history = crate::reports::read(&ctx.home)?;
            if cli.json {
                emit_json(ctx, serde_json::to_value(&history)?)?;
            } else {
                for record in &history.records {
                    info(
                        ctx,
                        format!(
                            "started={}  finished={}  {}  {}  {}  target={}  duration={}ms",
                            crate::reports::format_timestamp(record.started_unix),
                            record
                                .finished_unix
                                .map(crate::reports::format_timestamp)
                                .unwrap_or_else(|| "unfinished".into()),
                            record.id,
                            record.operation,
                            record.outcome,
                            record.target,
                            record.duration_ms
                        ),
                    );
                    if let Some(detail) = &record.detail {
                        info(ctx, format!("  {detail}"));
                    }
                    info(
                        ctx,
                        format!(
                            "  estimated bytes: {}; verified reclaimed bytes: {}",
                            record
                                .estimated_bytes
                                .map_or("unknown".into(), |v| v.to_string()),
                            record
                                .verified_reclaimed_bytes
                                .map_or("unknown".into(), |v| v.to_string())
                        ),
                    );
                }
                for warning in &history.warnings {
                    warn(ctx, warning);
                }
                if history.records.is_empty() {
                    info(ctx, "No maintenance operation records.");
                }
                info(
                    ctx,
                    format!(
                        "Verified reclaimed-byte subtotal: {}; records without a measurement: {}. Subtotal covers readable records only.",
                        history
                            .known_reclaimed_bytes
                            .map_or("unknown".into(), |v| v.to_string()),
                        history.records_without_verified_reclaimed_bytes
                    ),
                );
                info(
                    ctx,
                    format!(
                        "{} of {} history slots used by valid records.",
                        history.records.len(),
                        history.capacity
                    ),
                );
            }
        }
        Commands::Report {
            command:
                Some(ReportCommand::Purge {
                    older_than,
                    preview,
                    run,
                    preview_token,
                    authorize_history_purge,
                }),
        } => {
            if !cli.non_interactive {
                bail!(
                    "history purge requires --non-interactive; use the Reports screen for interactive review"
                );
            }
            if preview == run {
                bail!("choose exactly one of --preview or --run");
            }
            if run && !ctx.dry_run && (!ctx.yes || !authorize_history_purge) {
                bail!(
                    "history purge requires --yes, --authorize-history-purge, and a token from a prior preview"
                );
            }
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let plan = crate::reports::preview_history_purge(&ctx.home, older_than, &cancel)?;
            if run && ctx.dry_run && preview_token.as_deref() != Some(plan.preview_token.as_str()) {
                bail!("history changed or parameters differ from the preview; review it again");
            }
            let mut history_warning = None;
            let result = if run && !ctx.dry_run {
                let performed = crate::reports::perform_history_purge(
                    &ctx.home,
                    &plan,
                    preview_token
                        .as_deref()
                        .context("preview token is required")?,
                    &cancel,
                    |_, _| {},
                );
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            } else {
                None
            };
            let failed = result
                .as_ref()
                .is_some_and(|result| result.outcome != "completed");
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({
                        "plan": plan,
                        "dry_run": ctx.dry_run,
                        "executed": result.is_some(),
                        "result": result,
                        "history_warning": history_warning,
                    }),
                )?;
            } else {
                info(ctx, serde_json::to_string_pretty(&plan)?);
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                if let Some(result) = &result {
                    info(ctx, format!("Purge result: {}.", result.outcome));
                    for item in &result.items {
                        info(
                            ctx,
                            format!(
                                "Record {}: {}{}",
                                item.id,
                                item.status,
                                item.error
                                    .as_ref()
                                    .map_or(String::new(), |error| { format!(" ({error})") })
                            ),
                        );
                    }
                } else if ctx.dry_run {
                    info(ctx, "Dry run only; no history records were removed.");
                } else {
                    info(ctx, "Preview only; no history records were removed.");
                }
            }
            if failed {
                bail!("history purge was partial or failed; inspect the result and review again");
            }
        }
        Commands::Containers {
            command: ContainerCommand::PreviewBuildCache { builder, id },
        } => {
            if ctx.dry_run {
                bail!(
                    "Buildx inspection is skipped in dry-run because it may change Buildx configuration"
                );
            }
            let plan = crate::containers::build_cache_preview(&builder, &id, ctx.offline)?;
            if cli.json {
                emit_json(ctx, serde_json::json!({"plan": plan, "executed": false}))?;
            } else {
                info(ctx, serde_json::to_string_pretty(&plan)?);
            }
        }
        Commands::Containers {
            command:
                ContainerCommand::RemoveBuildCache {
                    builder,
                    id,
                    preview_token,
                    authorize_build_cache_removal,
                },
        } => {
            if !cli.non_interactive {
                bail!("build cache removal requires --non-interactive in this context");
            }
            if ctx.dry_run {
                bail!(
                    "Buildx inspection is skipped in dry-run because it may change Buildx configuration"
                );
            }
            if !ctx.yes || !authorize_build_cache_removal || preview_token.is_none() {
                bail!(
                    "build cache removal requires --yes, --authorize-build-cache-removal, and a token from a prior preview"
                );
            }
            let plan = crate::containers::build_cache_preview(&builder, &id, ctx.offline)?;
            let performed = crate::reports::perform_build_cache_removal(
                &ctx.home,
                &plan,
                preview_token.as_deref().unwrap_or_default(),
            );
            let history_warning = performed.history_warning;
            let verification = performed.result.map_err(|error| {
                anyhow!(
                    "{error}{}",
                    history_warning
                        .as_ref()
                        .map_or(String::new(), |warning| format!("; {warning}"))
                )
            })?;
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({"plan": plan, "executed": true, "verification": verification, "history_warning": history_warning}),
                )?;
            } else {
                info(
                    ctx,
                    format!("Build cache removal verification: {verification}."),
                );
                if let Some(warning) = history_warning {
                    warn(ctx, warning);
                }
            }
            if verification != "verified_absent" {
                bail!(
                    "build cache removal could not be verified; inspect builder state before retrying"
                );
            }
        }
        Commands::Containers {
            command: ContainerCommand::PreviewNetwork { engine, id },
        } => {
            if ctx.dry_run {
                report_container_dry_run_skip(
                    cli,
                    ctx,
                    &engine,
                    &id,
                    "network",
                    "network removal",
                )?;
                return Ok(());
            }
            let plan = crate::containers::network_removal_preview(&engine, &id, ctx.offline)?;
            if cli.json {
                emit_json(ctx, serde_json::json!({ "plan": plan, "executed": false }))?;
            } else {
                info(
                    ctx,
                    format!(
                        "{}  {}  id={}  name={}",
                        plan.engine, plan.engine_identity, plan.network_id, plan.name
                    ),
                );
                info(ctx, plan.warning);
                info(ctx, format!("Preview token: {}", plan.preview_token));
                info(ctx, "Preview only; no network removed.");
            }
        }
        Commands::Containers {
            command:
                ContainerCommand::RemoveNetwork {
                    engine,
                    id,
                    preview_token,
                    authorize_network_removal,
                },
        } => {
            if !cli.non_interactive {
                bail!("network removal requires --non-interactive in this context");
            }
            if !ctx.dry_run && (!ctx.yes || !authorize_network_removal || preview_token.is_none()) {
                bail!(
                    "network removal requires --yes, --authorize-network-removal, and a token from a prior preview"
                );
            }
            if ctx.dry_run {
                report_container_dry_run_skip(
                    cli,
                    ctx,
                    &engine,
                    &id,
                    "network",
                    "network removal",
                )?;
                return Ok(());
            }
            let plan = crate::containers::network_removal_preview(&engine, &id, ctx.offline)?;
            let mut history_warning = None;
            let verification = if ctx.dry_run {
                None
            } else {
                let performed = crate::reports::perform_network_removal(
                    &ctx.home,
                    &plan,
                    preview_token.as_deref().unwrap_or_default(),
                );
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({ "plan": plan, "executed": !ctx.dry_run, "dry_run": ctx.dry_run, "verification": verification, "history_warning": history_warning }),
                )?;
            } else {
                info(
                    ctx,
                    format!(
                        "{}  {}  id={}  name={}",
                        plan.engine, plan.engine_identity, plan.network_id, plan.name
                    ),
                );
                info(ctx, plan.warning);
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    verification.map_or("Preview only; no network removed.".into(), |status| {
                        format!("Network removal verification: {status}.")
                    }),
                );
            }
            if verification.is_some_and(|status| status != "verified_absent") {
                bail!(
                    "network removal could not be verified; inspect engine state before retrying"
                );
            }
        }
        Commands::Containers {
            command: ContainerCommand::PreviewImage { engine, id },
        } => {
            let _ = (engine, id);
            bail!(
                "dangling image preview and removal are unsupported because Docker and Podman cannot conditionally delete an image while preserving tags added after inspection; use `containers status` for the read-only inventory"
            );
        }
        Commands::Containers {
            command: ContainerCommand::RemoveImage { .. },
        } => bail!(
            "dangling image removal is unsupported until the engine can conditionally delete the reviewed image without removing tags added after preview"
        ),
        Commands::Containers {
            command: ContainerCommand::PreviewRemove { engine, id },
        } => {
            if ctx.stdin_is_tty && !cli.non_interactive && !cli.json && !ctx.dry_run {
                bail!(
                    "container removal preview requires --non-interactive or --json in this context"
                );
            }
            if ctx.dry_run {
                report_container_dry_run_skip(
                    cli,
                    ctx,
                    &engine,
                    &id,
                    "container",
                    "container removal",
                )?;
                return Ok(());
            }
            let plan = crate::containers::removal_preview(&engine, &id, ctx.offline)?;
            if cli.json {
                emit_json(ctx, serde_json::json!({ "plan": plan, "executed": false }))?;
            } else {
                info(
                    ctx,
                    format!(
                        "{}  {}  id={}  name={}  writable bytes={}",
                        plan.engine,
                        plan.engine_identity,
                        plan.container_id,
                        plan.name,
                        plan.writable_bytes
                            .map_or("unknown".into(), |v| v.to_string())
                    ),
                );
                info(ctx, plan.warning);
                info(ctx, format!("Preview token: {}", plan.preview_token));
                info(ctx, "Preview only; no container removed.");
            }
        }
        Commands::Containers {
            command:
                ContainerCommand::Remove {
                    engine,
                    id,
                    preview_token,
                    authorize_container_removal,
                },
        } => {
            if !cli.non_interactive {
                bail!("container removal requires --non-interactive in this context");
            }
            if !ctx.dry_run && (!ctx.yes || !authorize_container_removal || preview_token.is_none())
            {
                bail!(
                    "container removal requires --yes, --authorize-container-removal, and a token from a prior preview"
                );
            }
            if ctx.dry_run {
                report_container_dry_run_skip(
                    cli,
                    ctx,
                    &engine,
                    &id,
                    "container",
                    "container removal",
                )?;
                return Ok(());
            }
            let plan = crate::containers::removal_preview(&engine, &id, ctx.offline)?;
            let mut history_warning = None;
            let verification = if !ctx.dry_run {
                let performed = crate::reports::perform_container_removal(
                    &ctx.home,
                    &plan,
                    preview_token.as_deref().unwrap_or_default(),
                );
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            } else {
                None
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({ "plan": plan, "executed": !ctx.dry_run, "dry_run": ctx.dry_run, "verification": verification, "history_warning": history_warning }),
                )?;
            } else {
                info(
                    ctx,
                    format!(
                        "{}  {}  id={}  name={}",
                        plan.engine, plan.engine_identity, plan.container_id, plan.name
                    ),
                );
                info(ctx, plan.warning);
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    verification.map_or("Preview only; no container removed.".into(), |status| {
                        format!("Removal command completed; verification: {status}.")
                    }),
                );
            }
            if verification.is_some_and(|status| status != "verified_absent") {
                bail!(
                    "container removal could not be verified; inspect engine state before retrying"
                );
            }
        }
        Commands::Containers {
            command: ContainerCommand::Status,
        } => {
            let report = crate::containers::status_with_dry_run(ctx.offline, ctx.dry_run);
            if cli.json {
                emit_json(ctx, serde_json::to_value(&report)?)?;
            } else {
                for engine in report {
                    info(ctx, format!("{}: {}", engine.engine, engine.state));
                    for row in engine.usage {
                        info(ctx, format!("  {row}"));
                    }
                    for list in engine.resources {
                        info(ctx, format!("  {}:", list.kind));
                        if let Some(error) = list.error {
                            warn(ctx, format!("    {error}"));
                        }
                        for item in list.items {
                            info(ctx, format!("    {item}"));
                        }
                    }
                    if let Some(detail) = engine.detail {
                        warn(ctx, detail);
                    }
                }
                info(
                    ctx,
                    "Storage figures are engine estimates; no resources were removed.",
                );
            }
        }
        Commands::Trash {
            command: TrashCommand::PreviewEmpty { location },
        } => {
            let plan =
                crate::trash::empty_preview(&location, &std::sync::atomic::AtomicBool::new(false))?;
            if cli.json {
                emit_json(ctx, serde_json::json!({"plan": plan, "executed": false}))?;
            } else if let Some(plan) = plan {
                info(ctx, serde_json::to_string_pretty(&plan)?);
            } else {
                info(
                    ctx,
                    "No files in the selected Trash location; metadata may remain.",
                );
            }
        }
        Commands::Trash {
            command:
                TrashCommand::Empty {
                    location,
                    preview_token,
                    authorize_trash_removal,
                },
        } => {
            if !cli.non_interactive {
                bail!("Trash empty requires --non-interactive in this context");
            }
            if !ctx.dry_run && (!ctx.yes || !authorize_trash_removal || preview_token.is_none()) {
                bail!(
                    "Trash empty requires --yes, --authorize-trash-removal, and a token from a prior empty preview"
                );
            }
            let plan =
                crate::trash::empty_preview(&location, &std::sync::atomic::AtomicBool::new(false))?
                    .context("no files in the selected Trash location")?;
            let mut history_warning = None;
            let outcome = if ctx.dry_run {
                None
            } else {
                let performed = crate::reports::perform_trash_batch(
                    &ctx.home,
                    &plan,
                    preview_token.as_deref().unwrap_or_default(),
                );
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({"plan": plan, "executed": !ctx.dry_run, "dry_run": ctx.dry_run, "result": outcome, "history_warning": history_warning}),
                )?;
            } else {
                info(
                    ctx,
                    serde_json::to_string_pretty(
                        &serde_json::json!({"plan": plan, "result": outcome, "history_warning": history_warning}),
                    )?,
                );
            }
            if outcome
                .as_ref()
                .is_some_and(|result| result.outcome != "completed")
            {
                bail!("Trash empty did not complete; inspect individual results before retrying");
            }
        }
        Commands::Trash {
            command:
                TrashCommand::PreviewRetention {
                    location,
                    older_than,
                },
        } => {
            let preview = crate::trash::retention_batch_preview(
                &location,
                older_than,
                &std::sync::atomic::AtomicBool::new(false),
            )?;
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({"preview": preview, "executed": false}),
                )?;
            } else {
                info(
                    ctx,
                    format!(
                        "{}: {} eligible, {} newer/unknown, {} unsupported",
                        crate::sweep::display_path(&preview.selection.location),
                        preview.selection.eligible,
                        preview.selection.newer_or_unknown,
                        preview.selection.unsupported
                    ),
                );
                if let Some(plan) = &preview.plan {
                    for item in &plan.items {
                        info(
                            ctx,
                            format!(
                                "  {}  kind={}  descendants={}  deleted={}  logical bytes={}",
                                item.name,
                                item.kind,
                                item.descendant_count,
                                item.deletion_date.as_deref().unwrap_or("unknown"),
                                item.logical_bytes
                            ),
                        );
                    }
                    info(ctx, plan.warning);
                    info(ctx, format!("Preview token: {}", plan.preview_token));
                } else {
                    info(ctx, "No eligible items; nothing selected.");
                }
                for warning in &preview.warnings {
                    warn(ctx, warning);
                }
            }
        }
        Commands::Trash {
            command:
                TrashCommand::Retain {
                    location,
                    older_than,
                    preview_token,
                    authorize_trash_removal,
                },
        } => {
            if !cli.non_interactive {
                bail!("Trash retention requires --non-interactive in this context");
            }
            if !ctx.dry_run && (!ctx.yes || !authorize_trash_removal || preview_token.is_none()) {
                bail!(
                    "Trash retention requires --yes, --authorize-trash-removal, and a token from a prior retention preview"
                );
            }
            let preview = crate::trash::retention_batch_preview(
                &location,
                older_than,
                &std::sync::atomic::AtomicBool::new(false),
            )?;
            let plan = preview
                .plan
                .as_ref()
                .context("no eligible items in the selected location")?;
            let mut history_warning = None;
            let outcome = if ctx.dry_run {
                None
            } else {
                let performed = crate::reports::perform_trash_batch(
                    &ctx.home,
                    plan,
                    preview_token.as_deref().unwrap_or_default(),
                );
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({"preview": preview, "executed": !ctx.dry_run, "dry_run": ctx.dry_run, "result": outcome, "history_warning": history_warning}),
                )?;
            } else {
                if let Some(result) = &outcome {
                    for item in &result.items {
                        info(
                            ctx,
                            format!(
                                "{} / {}: {}{}",
                                crate::sweep::display_path(&item.location),
                                item.name,
                                item.status,
                                item.error
                                    .as_ref()
                                    .map_or(String::new(), |error| format!(" ({error})"))
                            ),
                        );
                    }
                    info(ctx, format!("Trash retention outcome: {}", result.outcome));
                } else {
                    info(ctx, "Dry run: no items removed.");
                }
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
            }
            if outcome
                .as_ref()
                .is_some_and(|result| result.outcome != "completed")
            {
                bail!("Trash retention did not complete; inspect item results before retrying");
            }
        }
        Commands::Trash {
            command:
                TrashCommand::PreviewBatch {
                    location,
                    name,
                    older_than,
                },
        } => {
            let plan = crate::trash::named_batch_preview(
                &location,
                &name,
                older_than,
                &std::sync::atomic::AtomicBool::new(false),
            )?;
            if cli.json {
                emit_json(ctx, serde_json::json!({"plan": plan, "executed": false}))?;
            } else {
                for item in &plan.items {
                    info(
                        ctx,
                        format!(
                            "Trash: {}  item: {}  kind: {}  descendants: {}  deleted: {}  logical bytes: {}",
                            crate::sweep::display_path(&item.location),
                            item.name,
                            item.kind,
                            item.descendant_count,
                            item.deletion_date.as_deref().unwrap_or("unknown"),
                            item.logical_bytes
                        ),
                    );
                }
                info(ctx, plan.warning);
                info(ctx, format!("Preview token: {}", plan.preview_token));
            }
        }
        Commands::Trash {
            command:
                TrashCommand::RemoveBatch {
                    location,
                    name,
                    older_than,
                    preview_token,
                    authorize_trash_removal,
                },
        } => {
            if !cli.non_interactive {
                bail!("Trash deletion requires --non-interactive in this context");
            }
            if !ctx.dry_run && (!ctx.yes || !authorize_trash_removal || preview_token.is_none()) {
                bail!(
                    "Trash deletion requires --yes, --authorize-trash-removal, and a token from a prior batch preview"
                );
            }
            let plan = crate::trash::named_batch_preview(
                &location,
                &name,
                older_than,
                &std::sync::atomic::AtomicBool::new(false),
            )?;
            let mut history_warning = None;
            let outcome = if ctx.dry_run {
                None
            } else {
                let performed = crate::reports::perform_trash_batch(
                    &ctx.home,
                    &plan,
                    preview_token.as_deref().unwrap_or_default(),
                );
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({"plan": plan, "executed": !ctx.dry_run, "dry_run": ctx.dry_run, "result": outcome, "history_warning": history_warning}),
                )?;
            } else {
                if let Some(result) = &outcome {
                    for item in &result.items {
                        info(
                            ctx,
                            format!(
                                "{} / {}: {}{}",
                                crate::sweep::display_path(&item.location),
                                item.name,
                                item.status,
                                item.error
                                    .as_ref()
                                    .map_or(String::new(), |error| format!(" ({error})"))
                            ),
                        );
                    }
                    info(ctx, format!("Trash batch outcome: {}", result.outcome));
                } else {
                    info(ctx, "Dry run: no items removed.");
                }
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
            }
            if outcome
                .as_ref()
                .is_some_and(|result| result.outcome != "completed")
            {
                bail!("Trash batch did not complete; inspect item results before retrying");
            }
        }
        Commands::Trash {
            command:
                TrashCommand::PreviewRemove {
                    location,
                    name,
                    older_than,
                },
        } => {
            let plan = crate::trash::named_removal_preview(
                &location,
                &name,
                older_than,
                &std::sync::atomic::AtomicBool::new(false),
            )?;
            if cli.json {
                emit_json(ctx, serde_json::json!({"plan": plan, "executed": false}))?;
            } else {
                info(
                    ctx,
                    format!(
                        "Trash: {}  item: {}  kind: {}  descendants: {}  logical bytes: {}",
                        crate::sweep::display_path(&plan.location),
                        plan.name,
                        plan.kind,
                        plan.descendant_count,
                        plan.logical_bytes
                    ),
                );
                info(ctx, plan.warning);
                info(ctx, format!("Preview token: {}", plan.preview_token));
            }
        }
        Commands::Trash {
            command:
                TrashCommand::Remove {
                    location,
                    name,
                    older_than,
                    preview_token,
                    authorize_trash_removal,
                },
        } => {
            if !cli.non_interactive {
                bail!("Trash deletion requires --non-interactive in this context");
            }
            if !ctx.dry_run && (!ctx.yes || !authorize_trash_removal || preview_token.is_none()) {
                bail!(
                    "Trash deletion requires --yes, --authorize-trash-removal, and a token from a prior preview"
                );
            }
            let plan = crate::trash::named_removal_preview(
                &location,
                &name,
                older_than,
                &std::sync::atomic::AtomicBool::new(false),
            )?;
            let mut history_warning = None;
            let verification = if ctx.dry_run {
                None
            } else {
                let performed = crate::reports::perform_trash_removal(
                    &ctx.home,
                    &plan,
                    preview_token.as_deref().unwrap_or_default(),
                );
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({"plan": plan, "executed": !ctx.dry_run, "dry_run": ctx.dry_run, "verification": verification, "history_warning": history_warning}),
                )?;
            } else {
                info(
                    ctx,
                    format!(
                        "Trash: {}  item: {}",
                        crate::sweep::display_path(&plan.location),
                        plan.name
                    ),
                );
                info(ctx, plan.warning);
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    verification.map_or("Dry run: no item removed.".into(), |status| {
                        format!("Trash removal verification: {status}.")
                    }),
                );
            }
            if verification.is_some_and(|status| status != "verified_absent") {
                bail!("Trash removal could not be verified; inspect Trash before retrying");
            }
        }
        Commands::Trash {
            command: TrashCommand::Preview { older_than },
        } => {
            if ctx.stdin_is_tty && !cli.non_interactive && !cli.json && !ctx.dry_run {
                bail!(
                    "Trash retention preview currently requires --non-interactive or --json; dashboard preview is not yet available"
                );
            }
            let report = crate::trash::status(&std::sync::atomic::AtomicBool::new(false));
            let preview = crate::trash::retention_preview(report, older_than)?;
            if cli.json {
                emit_json(ctx, serde_json::to_value(&preview)?)?;
            } else {
                for item in &preview.items {
                    info(
                        ctx,
                        format!(
                            "{}  {}  deleted={}  location={}",
                            item.age_status,
                            item.name,
                            item.deletion_date.as_deref().unwrap_or("unknown"),
                            crate::sweep::display_path(&item.location)
                        ),
                    );
                }
                for warning in &preview.warnings {
                    warn(ctx, warning);
                }
                info(ctx, "Preview only; no items selected or removed.");
            }
        }
        Commands::Trash {
            command: TrashCommand::Status,
        } => {
            let report = crate::trash::status(&std::sync::atomic::AtomicBool::new(false));
            if cli.json {
                emit_json(ctx, serde_json::to_value(&report)?)?;
            } else {
                for location in &report.locations {
                    let (label, path) = if location.path.as_os_str().is_empty() {
                        (
                            location.kind.to_owned(),
                            "(virtual; no filesystem path)".to_owned(),
                        )
                    } else {
                        (
                            format!("{} Trash", location.kind),
                            crate::sweep::display_path(&location.path),
                        )
                    };
                    info(
                        ctx,
                        format!(
                            "{label}: {path}  items={}  logical={} bytes{}",
                            location
                                .item_count
                                .map_or("unknown".into(), |v| v.to_string()),
                            location
                                .logical_bytes
                                .map_or("unknown".into(), |v| v.to_string()),
                            if location.size_complete {
                                ""
                            } else {
                                " (incomplete)"
                            }
                        ),
                    );
                    for item in &location.items {
                        info(
                            ctx,
                            format!(
                                "  {}  deleted={}",
                                item.name,
                                item.deletion_date.as_deref().unwrap_or("unknown")
                            ),
                        );
                    }
                    for warning in &location.warnings {
                        warn(ctx, warning);
                    }
                }
                for warning in &report.warnings {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    match report.platform {
                        "linux" => {
                            "Counts include orphaned entries; sizes are estimates. The dashboard can preview permanent deletion of selected files and directories."
                        }
                        "macos" => {
                            "Names are a read-only snapshot; deletion dates and item actions are unavailable."
                        }
                        "windows" => {
                            "Recycle Bin sizes are estimates; item-level actions are unsupported."
                        }
                        _ => "Item-level Trash actions are unsupported on this platform.",
                    },
                );
            }
        }
        Commands::Trash {
            command:
                TrashCommand::ScheduledRetention {
                    location,
                    age_seconds,
                    scope_token,
                },
        } => run_scheduled_trash_retention(cli, ctx, location, age_seconds, scope_token)?,
        Commands::Cache {
            command:
                CacheCommand::GoTest {
                    path,
                    preview,
                    run,
                    preview_token,
                    authorize_shared_cache,
                },
        } => {
            if !cli.non_interactive {
                bail!("Go test-cache preview and expiration currently require --non-interactive");
            }
            if !preview && !run {
                bail!("specify --preview or --run");
            }
            if run
                && !ctx.dry_run
                && (!ctx.yes || !authorize_shared_cache || preview_token.is_none())
            {
                bail!(
                    "Go test-cache expiration requires --yes, --authorize-shared-cache, and a token from a prior --preview"
                );
            }
            let plan = crate::cache::go_test_expiration_preview(&path)?;
            let mut history_warning = None;
            let mut outcome = None;
            if run && !ctx.dry_run {
                let performed = crate::reports::perform_go_test_expiration(
                    &ctx.home,
                    &plan,
                    preview_token.as_deref().unwrap_or_default(),
                );
                history_warning = performed.history_warning;
                outcome = Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?);
            }
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({"plan": plan, "executed": outcome.is_some(), "dry_run": ctx.dry_run, "result": outcome, "history_warning": history_warning}),
                )?;
            } else {
                info(
                    ctx,
                    format!(
                        "Go test cache: {}",
                        crate::sweep::display_path(&plan.cache_path)
                    ),
                );
                info(
                    ctx,
                    format!("Marker: {}", crate::sweep::display_path(&plan.marker_path)),
                );
                info(
                    ctx,
                    format!(
                        "Existing expiration (Unix nanoseconds): {}",
                        plan.current_expiration_unix_nanos
                            .map_or("none".into(), |value| value.to_string())
                    ),
                );
                info(ctx, plan.warning);
                info(ctx, format!("Preview token: {}", plan.preview_token));
                if let Some(result) = &outcome {
                    info(
                        ctx,
                        format!(
                            "Result: {} (changed={})",
                            result.verification, result.changed
                        ),
                    );
                }
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
            }
            if outcome
                .as_ref()
                .is_some_and(|result| result.verification != "marker_matches")
            {
                bail!(
                    "Go test-cache expiration could not be verified; inspect the selected cache before retrying"
                );
            }
        }
        Commands::Cache {
            command: CacheCommand::Status,
        } => {
            let report = crate::cache::inventory(&std::sync::atomic::AtomicBool::new(false));
            if cli.json {
                emit_json(ctx, serde_json::to_value(&report)?)?;
            } else {
                for entry in &report.entries {
                    info(
                        ctx,
                        format!(
                            "{}  {}  logical={}  allocated={}{}  {}",
                            entry.name,
                            entry.classification,
                            entry
                                .logical_bytes
                                .map_or("unknown".into(), |v| v.to_string()),
                            entry
                                .allocated_bytes
                                .map_or("unknown".into(), |v| v.to_string()),
                            if entry.size_complete {
                                ""
                            } else {
                                " (incomplete)"
                            },
                            crate::sweep::display_path(&entry.path)
                        ),
                    );
                    info(ctx, format!("  Consequence: {}", entry.consequence));
                    info(
                        ctx,
                        format!(
                            "  Directory owner (snapshot): {}",
                            entry.directory_owner_status
                        ),
                    );
                    info(
                        ctx,
                        format!("  Process activity: {}", entry.activity_status),
                    );
                    if let Some(test_cache) = &entry.go_test_cache {
                        info(
                            ctx,
                            format!(
                                "  Go test cache marker: {}; expiration (Unix nanoseconds): {}",
                                test_cache.status,
                                test_cache
                                    .expired_before_unix_nanos
                                    .map_or("unknown".into(), |value| value.to_string())
                            ),
                        );
                    }
                    for warning in &entry.warnings {
                        warn(ctx, warning);
                    }
                }
                for warning in &report.warnings {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    "Shared caches are not selected for removal. Sizes are estimates, not guaranteed reclaimed space.",
                );
            }
        }
        Commands::Maintenance {
            command:
                MaintenanceCommand::Temp {
                    preview,
                    run,
                    select,
                    preview_token,
                    authorize_temp_cleanup,
                },
        } => {
            if !cli.non_interactive {
                bail!("temporary staging cleanup currently requires --non-interactive");
            }
            if !preview && !run {
                bail!("specify --preview or --run");
            }
            if run
                && !ctx.dry_run
                && (!ctx.yes || !authorize_temp_cleanup || preview_token.is_none())
            {
                bail!(
                    "temporary staging cleanup requires --yes, --authorize-temp-cleanup, and a token from a prior --preview"
                );
            }
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let plan = crate::temp_cleanup::preview(&ctx.home, &ctx.bindir, &select, &cancel)?;
            #[cfg(not(target_os = "linux"))]
            {
                if cli.json {
                    emit_json(ctx, serde_json::json!({"plan": plan, "executed": false}))?;
                } else {
                    info(ctx, plan.warning);
                }
                if run {
                    bail!("{}", plan.warning);
                }
                return Ok(());
            }
            #[cfg(target_os = "linux")]
            {
                let mut cleanup = None;
                let mut history_warning = None;
                let mut operation_error = None;
                if run && !ctx.dry_run {
                    let performed = crate::reports::perform_temp_cleanup(
                        &ctx.home,
                        &plan,
                        preview_token.as_deref().unwrap_or_default(),
                        &cancel,
                    );
                    history_warning = performed.history_warning;
                    match performed.result {
                        Ok(result) => cleanup = Some(result),
                        Err(error) => operation_error = Some(error),
                    }
                }
                if cli.json {
                    emit_json(
                        ctx,
                        serde_json::json!({
                            "plan": plan,
                            "cleanup": cleanup,
                            "executed": run && !ctx.dry_run,
                            "dry_run": ctx.dry_run,
                            "history_warning": history_warning,
                            "error": operation_error,
                        }),
                    )?;
                } else {
                    info(ctx, serde_json::to_string_pretty(&plan)?);
                    if let Some(result) = &cleanup {
                        info(ctx, serde_json::to_string_pretty(result)?);
                    }
                    if let Some(warning) = &history_warning {
                        warn(ctx, warning);
                    }
                }
                if let Some(error) = operation_error {
                    bail!("{error}");
                }
                if cleanup
                    .as_ref()
                    .is_some_and(|result| result.outcome != "completed")
                {
                    bail!(
                        "temporary cleanup had a partial or failed result; inspect the reported item statuses"
                    );
                }
            }
        }
        Commands::Maintenance {
            command:
                MaintenanceCommand::Trim {
                    preview,
                    run,
                    mount,
                    preview_token,
                    authorize_trim,
                    ..
                },
        } if preview || run || mount.is_some() => {
            if !cli.non_interactive {
                bail!(
                    "TRIM preview and execution currently require --non-interactive; dashboard execution is not yet available"
                );
            }
            if !preview && !run {
                bail!("specify --preview or --run with --mount");
            }
            let mount = mount.context("an explicit --mount is required")?;
            if run && !ctx.dry_run && (!ctx.yes || !authorize_trim || preview_token.is_none()) {
                bail!("TRIM requires --yes, --authorize-trim, and a token from a prior --preview");
            }
            let plan = crate::maintenance::trim_plan(&mount)?;
            let mut history_warning = None;
            if run && !ctx.dry_run {
                let performed = crate::reports::perform_trim(
                    &ctx.home,
                    &plan,
                    preview_token.as_deref().unwrap_or_default(),
                );
                history_warning = performed.history_warning;
                performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?;
            }
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({"plan": plan, "executed": run && !ctx.dry_run, "dry_run": ctx.dry_run, "history_warning": history_warning}),
                )?;
            } else {
                info(
                    ctx,
                    format!(
                        "Mount: {}  filesystem={}  device={}",
                        crate::sweep::display_path(&plan.mount),
                        plan.filesystem,
                        plan.device
                    ),
                );
                info(ctx, plan.warning);
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                info(ctx, format!("Preview token: {}", plan.preview_token));
                info(
                    ctx,
                    if run && !ctx.dry_run {
                        "TRIM completed."
                    } else {
                        "Preview only; no TRIM was performed."
                    },
                );
            }
        }
        Commands::Maintenance { command: _ } => {
            let report = crate::maintenance::trim_status_with_dry_run(ctx.dry_run);
            if cli.json {
                emit_json(ctx, serde_json::to_value(&report)?)?;
            } else {
                info(ctx, format!("TRIM capability: {}", report.capability));
                info(
                    ctx,
                    format!("fstrim available: {}", report.fstrim_available),
                );
                info(ctx, format!("fstrim.timer: {}", report.timer.state));
                for mount in &report.mounts {
                    info(
                        ctx,
                        format!(
                            "Mount {} ({}, {}): device discard {}, limit {} bytes; available {} bytes; filesystem TRIM {}; online discard option {}; fstab TRIM exclusion {}",
                            crate::maintenance::display_mount_path(&mount.mount_path),
                            mount.filesystem,
                            mount.device,
                            mount.device_discard,
                            mount
                                .discard_max_bytes
                                .map_or("unknown".into(), |value| value.to_string()),
                            mount
                                .available_bytes
                                .map_or("unknown".into(), |value| value.to_string()),
                            mount.filesystem_trim,
                            mount.online_discard_option,
                            mount.fstab_trim_exclusion
                        ),
                    );
                }
                if let Some(warning) = &report.mounts_warning {
                    warn(ctx, warning);
                }
                if let Some(last) = report.timer.last_trigger {
                    info(ctx, format!("Last trigger: {last}"));
                }
                if let Some(next) = report.timer.next_trigger {
                    info(ctx, format!("Next trigger: {next}"));
                }
                if let Some(detail) = report.timer.detail {
                    warn(ctx, detail);
                }
                info(ctx, report.guidance);
            }
        }
        Commands::Sweep {
            command:
                SweepCommand::Run {
                    scope: SweepRunScope::Cache,
                    select,
                    root,
                    exclude,
                    older_than,
                    preview,
                    preview_token,
                    authorize_artifact_removal,
                    authorize_shared_cache,
                },
        } => {
            if select.len() != 1 {
                bail!("shared cache removal requires exactly one --select path");
            }
            if !root.is_empty()
                || !exclude.is_empty()
                || older_than.is_some()
                || cli.config.is_some()
                || cli.profile.is_some()
                || authorize_artifact_removal
            {
                bail!(
                    "workspace roots, exclusions, age, profiles, and artifact authorization do not apply to shared cache removal"
                );
            }
            if !preview && !cli.non_interactive && !cli.json && !ctx.dry_run {
                bail!("shared cache removal requires --non-interactive outside the dashboard");
            }
            if !preview
                && !ctx.dry_run
                && (!ctx.yes || !authorize_shared_cache || preview_token.is_none())
            {
                bail!(
                    "shared cache removal requires --yes, --authorize-shared-cache, and a token from a prior --preview"
                );
            }
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let select = &select[0];
            let plan = crate::shared_cache_cleanup::preview(select, &cancel)?;
            let mut history_warning = None;
            let verification = if preview || ctx.dry_run {
                None
            } else {
                let performed = crate::reports::perform_shared_cache_removal(
                    &ctx.home,
                    &plan,
                    preview_token.as_deref().unwrap_or_default(),
                    &cancel,
                );
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({"plan": plan, "dry_run": ctx.dry_run, "verification": verification, "history_warning": history_warning}),
                )?;
            } else {
                info(ctx, serde_json::to_string_pretty(&plan)?);
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    verification.map_or("Preview only; no cache was removed.".into(), |status| {
                        format!("Shared cache removal verification: {status}.")
                    }),
                );
            }
            if verification.is_some_and(|status| status != "verified_absent") {
                bail!("cache removal could not be verified; inspect the target before retrying");
            }
        }
        Commands::Sweep {
            command:
                SweepCommand::Run {
                    scope: SweepRunScope::Artifacts,
                    select,
                    root,
                    exclude,
                    older_than,
                    preview,
                    preview_token,
                    authorize_artifact_removal,
                    authorize_shared_cache,
                },
        } => {
            if authorize_shared_cache {
                bail!("shared-cache authorization does not apply to artifacts");
            }
            if select.len() > 1 && !cli.non_interactive && !cli.json && !ctx.dry_run {
                bail!("artifact batch commands require --non-interactive outside the dashboard");
            }
            if !preview && !cli.non_interactive && !cli.json && !ctx.dry_run {
                bail!(
                    "artifact preview and removal require --non-interactive outside the dashboard"
                );
            }
            if !preview
                && !ctx.dry_run
                && (!ctx.yes || !authorize_artifact_removal || preview_token.is_none())
            {
                bail!(
                    "artifact removal requires --yes, --authorize-artifact-removal, and a token from a prior --preview"
                );
            }
            let (roots, exclusions, older_than, enabled) =
                resolve_scan(cli, &root, &exclude, older_than)?;
            let scan_scope = crate::sweep::Scope {
                roots,
                exclusions,
                older_than_seconds: older_than.map(|age| age.as_secs()),
                enabled,
            };
            let cancel = std::sync::atomic::AtomicBool::new(false);
            if ctx.dry_run {
                let validated = crate::artifact_cleanup::validate_dry_run_selection(
                    &scan_scope,
                    &select,
                    &cancel,
                )?;
                report_git_preview_skipped(ctx, "artifact", validated)?;
                return Ok(());
            }
            if select.len() == 1 {
                let plan = crate::artifact_cleanup::preview(&scan_scope, &select[0], &cancel)?;
                let mut history_warning = None;
                let verification = if preview || ctx.dry_run {
                    None
                } else {
                    let performed = crate::reports::perform_artifact_removal(
                        &ctx.home,
                        &plan,
                        preview_token.as_deref().unwrap_or_default(),
                        &cancel,
                    );
                    history_warning = performed.history_warning;
                    Some(performed.result.map_err(|error| {
                        anyhow!(
                            "{error}{}",
                            history_warning
                                .as_ref()
                                .map_or(String::new(), |warning| format!("; {warning}"))
                        )
                    })?)
                };
                if cli.json {
                    emit_json(
                        ctx,
                        serde_json::json!({"plan": plan, "dry_run": ctx.dry_run, "verification": verification, "history_warning": history_warning}),
                    )?;
                } else {
                    info(ctx, serde_json::to_string_pretty(&plan)?);
                    if let Some(warning) = plan.reproduction_warning {
                        warn(ctx, warning);
                    }
                    if let Some(warning) = &history_warning {
                        warn(ctx, warning);
                    }
                    info(
                        ctx,
                        verification
                            .map_or("Preview only; no artifact was removed.".into(), |status| {
                                format!("Artifact removal verification: {status}.")
                            }),
                    );
                }
                if verification.is_some_and(|status| status != "verified_absent") {
                    bail!(
                        "artifact removal could not be verified; inspect the target before retrying"
                    );
                }
            } else {
                let plan = crate::artifact_cleanup::preview_batch(&scan_scope, &select, &cancel)?;
                let result = if preview || ctx.dry_run {
                    None
                } else {
                    Some(crate::reports::perform_artifact_batch(
                        &ctx.home,
                        &plan,
                        preview_token.as_deref().unwrap_or_default(),
                        &cancel,
                    ))
                };
                let complete = result.as_ref().is_none_or(|result| result.complete);
                let output =
                    serde_json::json!({"plan": plan, "dry_run": ctx.dry_run, "result": result});
                if cli.json {
                    emit_json(ctx, output)?;
                } else {
                    info(ctx, serde_json::to_string_pretty(&output)?);
                }
                if !complete {
                    bail!(
                        "artifact batch did not verify every removal; inspect individual results and any quarantine paths"
                    );
                }
            }
        }
        Commands::Sweep {
            command:
                SweepCommand::BytecodeBatch {
                    files,
                    root,
                    exclude,
                    older_than,
                    run,
                    preview_token,
                    authorize_bytecode_removal,
                },
        } => {
            if !cli.non_interactive {
                bail!(
                    "bytecode batch preview and removal require --non-interactive; use the Artifacts screen for interactive selection"
                );
            }
            if run
                && !ctx.dry_run
                && (!ctx.yes || !authorize_bytecode_removal || preview_token.is_none())
            {
                bail!(
                    "bytecode batch removal requires --yes, --authorize-bytecode-removal, and a token from a prior batch preview"
                );
            }
            let (roots, exclusions, older_than, enabled) =
                resolve_scan(cli, &root, &exclude, older_than)?;
            let scope = crate::bytecode::Scope {
                roots,
                exclusions,
                older_than_seconds: older_than.map(|age| age.as_secs()),
                enabled,
            };
            let cancel = std::sync::atomic::AtomicBool::new(false);
            if ctx.dry_run {
                let validated =
                    crate::bytecode::validate_dry_run_selection(&scope, &files, &cancel)?;
                report_git_preview_skipped(ctx, "bytecode batch", validated)?;
                return Ok(());
            }
            let plan = crate::bytecode::preview_batch(&scope, &files, &cancel)?;
            let result = if run && !ctx.dry_run {
                Some(crate::reports::perform_bytecode_batch(
                    &ctx.home,
                    &plan,
                    preview_token.as_deref().unwrap_or_default(),
                    &cancel,
                )?)
            } else {
                None
            };
            let complete = result.as_ref().is_none_or(|result| result.complete);
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({"plan": plan, "dry_run": ctx.dry_run, "result": result}),
                )?;
            } else {
                info(
                    ctx,
                    serde_json::to_string_pretty(
                        &serde_json::json!({"plan": plan, "dry_run": ctx.dry_run, "result": result}),
                    )?,
                );
            }
            if !complete {
                bail!(
                    "bytecode batch stopped before all files were verified removed; inspect individual results"
                );
            }
        }
        Commands::Sweep {
            command:
                SweepCommand::Bytecode {
                    file,
                    root,
                    exclude,
                    older_than,
                    run,
                    preview_token,
                    authorize_bytecode_removal,
                },
        } => {
            if !cli.non_interactive {
                bail!("bytecode preview and removal currently require --non-interactive");
            }
            if run
                && !ctx.dry_run
                && (!ctx.yes || !authorize_bytecode_removal || preview_token.is_none())
            {
                bail!(
                    "bytecode removal requires --yes, --authorize-bytecode-removal, and a token from a prior preview"
                );
            }
            let (roots, exclusions, older_than, enabled) =
                resolve_scan(cli, &root, &exclude, older_than)?;
            let scope = crate::bytecode::Scope {
                roots,
                exclusions,
                older_than_seconds: older_than.map(|age| age.as_secs()),
                enabled,
            };
            let cancel = std::sync::atomic::AtomicBool::new(false);
            if ctx.dry_run {
                let validated = crate::bytecode::validate_dry_run_selection(
                    &scope,
                    std::slice::from_ref(&file),
                    &cancel,
                )?;
                report_git_preview_skipped(ctx, "bytecode", validated)?;
                return Ok(());
            }
            let plan = crate::bytecode::preview(&scope, &file, &cancel)?;
            let mut history_warning = None;
            let verification = if run && !ctx.dry_run {
                let performed = crate::reports::perform_bytecode_removal(
                    &ctx.home,
                    &plan,
                    preview_token.as_deref().unwrap_or_default(),
                    &cancel,
                );
                history_warning = performed.history_warning;
                Some(performed.result.map_err(|error| {
                    anyhow!(
                        "{error}{}",
                        history_warning
                            .as_ref()
                            .map_or(String::new(), |warning| format!("; {warning}"))
                    )
                })?)
            } else {
                None
            };
            if cli.json {
                emit_json(
                    ctx,
                    serde_json::json!({"plan": plan, "dry_run": ctx.dry_run, "verification": verification, "history_warning": history_warning}),
                )?;
            } else {
                info(
                    ctx,
                    format!(
                        "Project: {}\nManifest: {}\nSource: {}\nBytecode: {}\nCPython: {}\nInvalidation: {}\nLogical bytes: {}\nPreview token: {}\n{}",
                        crate::sweep::display_path(&plan.project),
                        crate::sweep::display_path(&plan.manifest),
                        crate::sweep::display_path(&plan.source),
                        crate::sweep::display_path(&plan.file),
                        plan.python,
                        plan.invalidation,
                        plan.logical_bytes,
                        plan.preview_token,
                        plan.warning
                    ),
                );
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    verification
                        .map_or("Preview only; no bytecode was removed.".into(), |status| {
                            format!("Removal verification: {status}.")
                        }),
                );
            }
            if verification == Some("unverified_replacement") {
                bail!(
                    "bytecode was removed but the original path is occupied; inspect it before retrying"
                );
            }
        }
        Commands::Sweep {
            command:
                SweepCommand::Preview {
                    paths,
                    exclude,
                    older_than,
                    select,
                },
        } => {
            let (paths, exclude, older_than, enabled) =
                resolve_scan(cli, &paths, &exclude, older_than)?;
            let report = crate::sweep::scan_with_policy(
                &paths,
                &exclude,
                older_than,
                enabled.as_deref(),
                &std::sync::atomic::AtomicBool::new(false),
                |_| {},
            )?;
            if ctx.dry_run {
                let validated = crate::sweep::validate_preview_selection(
                    &report,
                    &select,
                    &std::sync::atomic::AtomicBool::new(false),
                )?;
                report_git_preview_skipped(ctx, "sweep", validated.len())?;
                return Ok(());
            }
            let plan = crate::sweep::preview(report, &select)?;
            if cli.json {
                emit_json(ctx, serde_json::to_value(&plan)?)?;
            } else {
                for item in &plan.items {
                    info(
                        ctx,
                        format!(
                            "[{}] {}  risk={}  identity={}  git_index={}  git_head={}  git_history={}  activity={}  logical={} bytes{}  allocated={}  project={}  target={}  proposed={}",
                            if item.selected { "x" } else { " " },
                            item.candidate.ecosystem,
                            item.risk,
                            item.identity_status,
                            item.git_index_status,
                            item.git_head_status,
                            item.git_history_status,
                            item.activity_status,
                            item.candidate.logical_bytes,
                            if item.candidate.size_complete {
                                ""
                            } else {
                                " (incomplete)"
                            },
                            item.candidate
                                .allocated_bytes
                                .map_or("unavailable".into(), |value| format!("{value} bytes")),
                            crate::sweep::display_path(&item.candidate.project_root),
                            crate::sweep::display_path(&item.candidate.target),
                            item.proposed_operation
                        ),
                    );
                    if let Some(workspace) = &item.candidate.cargo_workspace {
                        info(ctx, format!("Cargo workspace: {}", workspace.description()));
                    }
                    for marker in [
                        &item.candidate.nested_project_marker,
                        &item.candidate.nested_vcs_marker,
                        &item.candidate.hard_link_marker,
                        &item.candidate.symlink_marker,
                    ]
                    .into_iter()
                    .flatten()
                    {
                        warn(
                            ctx,
                            format!(
                                "Project, VCS, hard-link, or symlink marker found during scan: {}",
                                crate::sweep::display_path(marker)
                            ),
                        );
                    }
                }
                for warning in &plan.warnings {
                    warn(ctx, warning);
                }
                info(
                    ctx,
                    "Preview only: directory cleanup is unavailable. Project identity, tracked files, active builds, paths, mounts, and permissions require verification before removal.",
                );
            }
        }
        Commands::Config { command } => {
            let path = crate::config::config_path(cli.config.as_deref())?;
            match command {
                ConfigCommand::Show => {
                    let settings = crate::config::load(&path, cli.config.is_some())?;
                    if cli.json {
                        emit_json(
                            ctx,
                            serde_json::json!({ "path": path, "settings": settings }),
                        )?;
                    } else {
                        info(
                            ctx,
                            format!(
                                "Configuration: {}\n{}",
                                crate::sweep::display_path(&path),
                                toml::to_string_pretty(&settings)?
                            ),
                        );
                    }
                }
                ConfigCommand::Init {
                    paths,
                    exclude,
                    retention,
                    schedule_frequency,
                } => {
                    let settings = crate::config::Settings {
                        version: 1,
                        workspace_roots: paths,
                        exclusions: exclude,
                        artifact_retention: retention,
                        schedule_frequency,
                        ..Default::default()
                    };
                    crate::config::create(&path, &settings, ctx.dry_run)?;
                    if cli.json {
                        emit_json(
                            ctx,
                            serde_json::json!({ "path": path, "created": !ctx.dry_run, "dry_run": ctx.dry_run, "settings": settings }),
                        )?;
                    } else {
                        info(
                            ctx,
                            format!(
                                "{} configuration: {}",
                                if ctx.dry_run {
                                    "Would create"
                                } else {
                                    "Created"
                                },
                                crate::sweep::display_path(&path)
                            ),
                        );
                    }
                }
            }
        }
        Commands::Sweep {
            command:
                SweepCommand::ScheduledBytecodeCleanup {
                    paths,
                    exclude,
                    scope_token,
                    authorize_scheduled_cleanup,
                },
        } => {
            if !cli.non_interactive
                || !cli.offline
                || !ctx.yes
                || !authorize_scheduled_cleanup
                || cli.config.as_deref() != Some(std::path::Path::new("/dev/null"))
                || cli.profile.is_some()
            {
                bail!(
                    "scheduled cleanup requires --non-interactive, --offline, --yes, --config /dev/null, and explicit authorization"
                );
            }
            let executable = env::current_exe()?.canonicalize()?;
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let mut history_warning = None;
            let report = if ctx.dry_run {
                crate::scheduled_cleanup::run(
                    &ctx.home,
                    &executable,
                    &paths,
                    &exclude,
                    &scope_token,
                    true,
                    &cancel,
                )
                .map_err(|_| anyhow!("scheduled bytecode cleanup failed; details are redacted"))?
            } else {
                let performed = crate::reports::perform_scheduled_cleanup(
                    &ctx.home,
                    &executable,
                    &paths,
                    &exclude,
                    &scope_token,
                    &cancel,
                );
                history_warning = performed
                    .history_warning
                    .map(|_| "Local operation history may be incomplete; details are redacted.");
                performed.result.map_err(|_| {
                    anyhow!("scheduled bytecode cleanup failed; details are redacted")
                })?
            };
            if cli.json {
                let mut output = serde_json::to_value(&report)?;
                if let Some(warning) = &history_warning {
                    output["history_warning"] = serde_json::json!(warning);
                }
                emit_json(ctx, output)?;
            } else {
                info(ctx, serde_json::to_string_pretty(&report)?);
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
            }
            if !report.complete {
                bail!("scheduled cleanup was incomplete; inspect the report and history");
            }
        }
        Commands::Sweep {
            command:
                SweepCommand::ScheduledCleanup {
                    paths,
                    exclude,
                    scope_token,
                    authorize_scheduled_cleanup,
                    authorize_scheduled_artifact_cleanup,
                },
        } => {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (
                    paths,
                    exclude,
                    scope_token,
                    authorize_scheduled_cleanup,
                    authorize_scheduled_artifact_cleanup,
                );
                return require_scheduled_artifact_cleanup_support(false);
            }
            #[cfg(target_os = "linux")]
            {
                require_scheduled_artifact_cleanup_support(true)?;
                if !cli.non_interactive
                    || !cli.offline
                    || !ctx.yes
                    || cli.config.as_deref() != Some(std::path::Path::new("/dev/null"))
                    || cli.profile.is_some()
                {
                    bail!(
                        "scheduled cleanup requires --non-interactive, --offline, --yes, --config /dev/null, and explicit authorization"
                    );
                }
                let executable = env::current_exe()?.canonicalize()?;
                let (bytecode, artifacts) = crate::schedule::scheduled_cleanup_modes(
                    &executable,
                    &paths,
                    &exclude,
                    &scope_token,
                )?;
                if !artifacts
                    || bytecode != authorize_scheduled_cleanup
                    || artifacts != authorize_scheduled_artifact_cleanup
                {
                    bail!("scheduled cleanup authorization does not match its policy token");
                }
                let cancel = std::sync::atomic::AtomicBool::new(false);
                let mut artifact_report = if ctx.dry_run {
                    crate::scheduled_cleanup::run_artifact_cleanup(
                        &ctx.home,
                        &executable,
                        &paths,
                        &exclude,
                        &scope_token,
                        true,
                        &cancel,
                    )?
                } else {
                    let performed = crate::reports::perform_scheduled_artifact_cleanup(
                        &ctx.home,
                        &executable,
                        &paths,
                        &exclude,
                        &scope_token,
                        &cancel,
                    );
                    performed.result.map_err(|_| {
                        anyhow!("scheduled artifact cleanup failed; inspect the report and history")
                    })?
                };
                let mut bytecode_report = None;
                let mut bytecode_complete = true;
                if artifact_report.continue_with_bytecode && bytecode {
                    let report = if ctx.dry_run {
                        crate::scheduled_cleanup::run(
                            &ctx.home,
                            &executable,
                            &paths,
                            &exclude,
                            &scope_token,
                            true,
                            &cancel,
                        )?
                    } else {
                        let performed = crate::reports::perform_scheduled_cleanup(
                            &ctx.home,
                            &executable,
                            &paths,
                            &exclude,
                            &scope_token,
                            &cancel,
                        );
                        performed.result.map_err(|_| {
                            anyhow!(
                                "scheduled bytecode cleanup failed; inspect the report and history"
                            )
                        })?
                    };
                    bytecode_complete = report.complete;
                    bytecode_report =
                        Some(crate::scheduled_cleanup::redacted_bytecode_report(&report));
                }
                let complete = artifact_report.complete && bytecode_complete;
                if !artifact_report.continue_with_bytecode && bytecode {
                    artifact_report.warnings.push(
                        "Bytecode cleanup was not attempted because an artifact safety, history, or cancellation check did not complete.".into(),
                    );
                }
                let output = serde_json::json!({
                    "artifact_cleanup": artifact_report,
                    "bytecode_cleanup": bytecode_report,
                    "complete": complete,
                    "dry_run": ctx.dry_run,
                });
                if cli.json {
                    emit_json(ctx, output)?;
                } else {
                    info(ctx, serde_json::to_string_pretty(&output)?);
                }
                if !complete {
                    bail!("scheduled cleanup was incomplete; inspect the report and history");
                }
            }
        }
        Commands::Sweep {
            command:
                SweepCommand::Scan {
                    paths,
                    exclude,
                    older_than,
                    scope_token,
                },
        } => {
            if scope_token.is_some()
                && (!cli.non_interactive
                    || !cli.offline
                    || !schedule_isolated_config(cli.config.as_deref(), cfg!(windows))
                    || cli.profile.is_some()
                    || older_than.is_some()
                    || paths.is_empty())
            {
                bail!(
                    "scheduled scope verification requires explicit roots, --non-interactive, --offline, --config /dev/null, and no profile or age filter"
                );
            }
            let (paths, exclude, older_than, enabled) =
                resolve_scan(cli, &paths, &exclude, older_than)?;
            let scheduled = scope_token.is_some();
            let mut history_warning = None;
            let report = if let Some(token) = scope_token {
                let executable = env::current_exe()?.canonicalize()?;
                if ctx.dry_run {
                    crate::schedule::run_guarded_scan(&executable, &paths, &exclude, &token)?
                } else {
                    let performed = crate::reports::perform_scheduled_scan(
                        &ctx.home,
                        &executable,
                        &paths,
                        &exclude,
                        &token,
                    );
                    history_warning = performed.history_warning;
                    performed.result.map_err(|error| {
                        anyhow!(
                            "{error}{}",
                            history_warning
                                .as_ref()
                                .map_or(String::new(), |warning| format!("; {warning}"))
                        )
                    })?
                }
            } else {
                crate::sweep::scan_with_policy(
                    &paths,
                    &exclude,
                    older_than,
                    enabled.as_deref(),
                    &std::sync::atomic::AtomicBool::new(false),
                    |_| {},
                )?
            };
            if cli.json {
                let mut output = serde_json::to_value(&report)?;
                output["complete"] = serde_json::json!(report.is_complete());
                if let Some(warning) = &history_warning {
                    output["history_warning"] = serde_json::json!(warning);
                }
                emit_json(ctx, output)?;
            } else {
                if let Some(warning) = &history_warning {
                    warn(ctx, warning);
                }
                for candidate in &report.candidates {
                    info(
                        ctx,
                        format!(
                            "{}  logical={} bytes  allocated={}{}  modified={}  {}  {}",
                            candidate.ecosystem,
                            candidate.logical_bytes,
                            candidate
                                .allocated_bytes
                                .map_or("unavailable".into(), |value| format!("{value} bytes")),
                            if candidate.size_complete {
                                ""
                            } else {
                                " (incomplete)"
                            },
                            candidate
                                .modified_unix
                                .map_or("unknown".into(), |value| value.to_string()),
                            candidate.classification,
                            crate::sweep::display_path(&candidate.target)
                        ),
                    );
                    if let Some(workspace) = &candidate.cargo_workspace {
                        info(ctx, format!("Cargo workspace: {}", workspace.description()));
                    }
                    for marker in [
                        &candidate.nested_project_marker,
                        &candidate.nested_vcs_marker,
                        &candidate.hard_link_marker,
                        &candidate.symlink_marker,
                    ]
                    .into_iter()
                    .flatten()
                    {
                        warn(
                            ctx,
                            format!(
                                "Project, VCS, hard-link, or symlink marker found during scan: {}",
                                crate::sweep::display_path(marker)
                            ),
                        );
                    }
                }
                info(
                    ctx,
                    "Logical sizes are estimates, not guaranteed reclaimed space; no cleanup was performed.",
                );
                for warning in &report.warnings {
                    warn(ctx, warning);
                }
            }
            if scheduled && !report.is_complete() {
                bail!("scheduled scan was incomplete; inspect the report and warnings");
            }
        }
        Commands::Tui => {
            if cli.json
                || !io::stdin().is_terminal()
                || !io::stdout().is_terminal()
                || env::var_os("CI").is_some()
            {
                bail!("the dashboard requires an interactive terminal");
            }
            if cli.non_interactive || cli.dry_run || cli.offline || cli.yes || cli.quiet {
                bail!("the dashboard cannot be combined with non-interactive flags");
            }
            crate::tui::run_with_config(
                ctx,
                crate::tui::Start::Dashboard,
                cli.only,
                None,
                None,
                crate::tui::LaunchOptions {
                    config: cli.config.clone(),
                    profile: cli.profile.clone(),
                    ..Default::default()
                },
            )?;
        }
        Commands::Paths => {
            ensure_dirs(ctx)?;
            let report = ensure_required_paths(ctx);
            if cli.json {
                let paths = report
                    .iter()
                    .map(|entry| {
                        serde_json::json!({
                            "label": entry.label,
                            "dir": crate::sweep::JsonPath(&entry.dir),
                            "configured": entry.configured,
                            "updated": entry.updated,
                        })
                    })
                    .collect::<Vec<_>>();
                let payload = serde_json::json!({
                    "home": crate::sweep::JsonPath(&ctx.home),
                    "bindir": crate::sweep::JsonPath(&ctx.bindir),
                    "paths": paths,
                });
                emit_json(ctx, payload)?;
            } else {
                info(
                    ctx,
                    format!("upkit home : {}", crate::sweep::display_path(&ctx.home)),
                );
                info(
                    ctx,
                    format!("upkit bindir: {}", crate::sweep::display_path(&ctx.bindir)),
                );
                if !ctx.dry_run {
                    info(ctx, "(created directories if missing)");
                }
                if report.is_empty() {
                    info(ctx, "No path targets detected.");
                } else {
                    info(ctx, "Path checks:");
                    for entry in &report {
                        let status = if entry.updated {
                            "added"
                        } else if entry.configured {
                            "ok"
                        } else {
                            "missing"
                        };
                        let line = format!(
                            "- {status}: {} ({})",
                            entry.label,
                            crate::sweep::display_path(&entry.dir)
                        );
                        if entry.updated || entry.configured {
                            info(ctx, line);
                        } else {
                            warn(ctx, line);
                        }
                    }
                }
            }
        }
        Commands::Check => {
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
        Commands::Clean { tools, all, safety } => {
            run_clean_command(ctx, cli, tools, all, CleanAction::Clean, safety)?;
        }
        Commands::Uninstall { tools, all, safety } => {
            run_clean_command(ctx, cli, tools, all, CleanAction::Uninstall, safety)?;
        }
        Commands::Doctor => {
            let pb = start_spinner(ctx, "Running doctor checks...");
            run_doctor_with_config(ctx, cli.json, cli.config.as_deref(), cli.profile.as_deref())?;
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

fn run_guarded_clean(
    ctx: &Ctx,
    cli: &Cli,
    tools: Vec<ToolKind>,
    all: bool,
    action: CleanAction,
    safety: CleanSafety,
) -> Result<()> {
    use sha2::{Digest, Sha256};
    if !safety.preview
        && (!ctx.yes || !safety.authorize_managed_cleanup || safety.preview_token.is_none())
    {
        bail!(
            "{} requires a prior --preview, --yes, --authorize-managed-cleanup, and --preview-token",
            action.verb()
        );
    }
    if safety.preview && (safety.preview_token.is_some() || safety.authorize_managed_cleanup) {
        bail!("preview cannot be combined with cleanup authorization or a token");
    }
    if tools.is_empty() && !all && cli.only.is_none() {
        bail!("select tool names, --only, or --all for managed cleanup");
    }
    let mut targets = Vec::new();
    for tool in if tools.is_empty() {
        select_kinds(cli.only)
    } else {
        tools
    } {
        if !targets.contains(&tool) {
            targets.push(tool);
        }
    }
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let plans = targets
        .iter()
        .map(|tool| crate::managed_cleanup::preview_including_absent(ctx, *tool, &cancel))
        .collect::<Result<Vec<_>>>()?;
    let mut hash = Sha256::new();
    hash.update(b"upkit-managed-clean-batch-v1");
    hash.update(action.verb().as_bytes());
    for plan in &plans {
        hash.update(plan.tool.as_bytes());
        hash.update(plan.preview_token.as_bytes());
    }
    let token = hex::encode(hash.finalize());
    if !safety.preview && safety.preview_token.as_deref() != Some(token.as_str()) {
        bail!(
            "managed cleanup preview changed or token does not match; review the complete selection again"
        );
    }
    if !safety.preview {
        preflight_managed_cleanup_batch(ctx, &targets, &plans, &cancel)?;
    }
    let mut results = Vec::new();
    let mut failed = false;
    if !safety.preview {
        for (tool, plan) in targets.iter().zip(&plans) {
            if failed {
                results.push(serde_json::json!({"tool": plan.tool, "ok": false, "executed": false, "error": "skipped after earlier failure"}));
                continue;
            }
            if plan.selected_entries.is_empty() && plan.links.is_empty() {
                if let Err(error) = revalidate_managed_absence(ctx, *tool, plan, &cancel) {
                    failed = true;
                    results.push(serde_json::json!({"tool": plan.tool, "ok": false, "executed": false, "error": format!("{error:#}")}));
                    continue;
                }
                results.push(serde_json::json!({"tool": plan.tool, "ok": true, "executed": false, "verification": "no_verified_targets", "preserved_entries": plan.preserved_entries, "preserved_links": plan.preserved_links, "detail": "No sealed installation or recorded link was eligible; unverified data was preserved."}));
                continue;
            }
            let performed = crate::reports::perform_managed_cleanup(ctx, plan, &cancel);
            let (ok, verification, error) = match performed.result {
                Ok("verified_selected_absent") => (true, Some("verified_selected_absent"), None),
                Ok(status) => (
                    false,
                    Some(status),
                    Some("cleanup outcome is unverified; inspect the original paths".to_string()),
                ),
                Err(error) => (false, None, Some(error)),
            };
            failed = !ok;
            results.push(serde_json::json!({"tool": plan.tool, "ok": ok, "executed": true, "verification": verification, "error": error, "history_warning": performed.history_warning}));
        }
    }
    if cli.json {
        emit_json(
            ctx,
            serde_json::json!({"command": action.verb(), "ok": !failed, "dry_run": ctx.dry_run, "preview": safety.preview, "preview_token": token, "plans": plans, "results": results}),
        )?;
    } else {
        info(
            ctx,
            serde_json::to_string_pretty(
                &serde_json::json!({"preview_token": token, "plans": plans, "results": results}),
            )?,
        );
    }
    if failed {
        bail!(
            "{} stopped after a failed or unverified operation; inspect results and quarantine paths",
            action.verb()
        );
    }
    Ok(())
}

fn preflight_managed_cleanup_batch(
    ctx: &Ctx,
    targets: &[ToolKind],
    plans: &[crate::managed_cleanup::CleanupPlan],
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    for (tool, plan) in targets.iter().zip(plans) {
        let fresh = crate::managed_cleanup::preview_including_absent(ctx, *tool, cancel)?;
        crate::managed_cleanup::validate_removal_plan(&fresh)?;
        if fresh.preview_token != plan.preview_token {
            bail!("managed paths changed after review; no cleanup was started");
        }
    }
    Ok(())
}

fn revalidate_managed_absence(
    ctx: &Ctx,
    tool: ToolKind,
    plan: &crate::managed_cleanup::CleanupPlan,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    let current = crate::managed_cleanup::preview_including_absent(ctx, tool, cancel)?;
    if current.preview_token != plan.preview_token
        || !current.selected_entries.is_empty()
        || !current.links.is_empty()
    {
        bail!("managed cleanup target changed after preview; review the complete selection again");
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod managed_absence_revalidation_tests {
    use super::*;
    use crate::test_support::{TestPrompt, base_ctx};
    use std::{fs, os::unix::fs::PermissionsExt, sync::Arc, sync::atomic::AtomicBool};

    #[test]
    fn absent_target_is_rejected_if_it_appears_after_preview() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("managed");
        let bindir = dir.path().join("bin");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&bindir).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&bindir, fs::Permissions::from_mode(0o755)).unwrap();
        let ctx = base_ctx(home, bindir, Arc::new(TestPrompt::default()));
        let cancel = AtomicBool::new(false);
        let plan =
            crate::managed_cleanup::preview_including_absent(&ctx, ToolKind::Go, &cancel).unwrap();

        revalidate_managed_absence(&ctx, ToolKind::Go, &plan, &cancel).unwrap();
        let root = ctx.home.join(ToolKind::Go.as_str());
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::write(root.join("appeared-after-preview"), "keep").unwrap();

        let error = revalidate_managed_absence(&ctx, ToolKind::Go, &plan, &cancel).unwrap_err();
        assert!(error.to_string().contains("changed after preview"));
        assert_eq!(
            fs::read_to_string(root.join("appeared-after-preview")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn preflight_allows_a_shared_writable_target_with_no_eligible_paths() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("managed");
        let bindir = dir.path().join("bin");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&bindir).unwrap();
        fs::set_permissions(&bindir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o775)).unwrap();
        let ctx = base_ctx(home, bindir, Arc::new(TestPrompt::default()));
        let cancel = AtomicBool::new(false);
        let plan =
            crate::managed_cleanup::preview_including_absent(&ctx, ToolKind::Go, &cancel).unwrap();
        assert!(plan.writable_by_others);
        assert!(plan.selected_entries.is_empty() && plan.links.is_empty());

        preflight_managed_cleanup_batch(&ctx, &[ToolKind::Go], &[plan], &cancel).unwrap();
    }
}

fn run_clean_command(
    ctx: &Ctx,
    cli: &Cli,
    tools: Vec<ToolKind>,
    all: bool,
    action: CleanAction,
    safety: CleanSafety,
) -> Result<()> {
    if safety.preview || !ctx.dry_run {
        return run_guarded_clean(ctx, cli, tools, all, action, safety);
    }
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
                "executed": if ctx.dry_run { Some(false) } else { None },
                "error": err.to_string(),
            }));
        } else {
            finish_spinner(pb, &format!("{}ed {}", action.title(), t.as_str()));
            results.push(serde_json::json!({
                "tool": t.as_str(),
                "ok": true,
                "executed": !ctx.dry_run,
            }));
        }
    }
    if !failures.is_empty() {
        if cli.json {
            let payload = serde_json::json!({
                "command": action.verb(),
                "ok": false,
                "dry_run": ctx.dry_run,
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
            "dry_run": ctx.dry_run,
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
        #[cfg(coverage)]
        {
            let _ = cert_path.as_str();
            let _ = &http_builder;
        }
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
    let stdin_is_tty = io::stdin().is_terminal() && !cli.non_interactive;
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
    if ctx.dry_run {
        return Ok(());
    }
    crate::infrastructure::ensure_directory_tree(&ctx.home)?;
    crate::infrastructure::ensure_directory_tree(&ctx.bindir)?;
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
        ToolKind::Mojo => tools::mojo::check_mojo(ctx),
        ToolKind::Java => tools::java::check_java(ctx),
        ToolKind::Dotnet => tools::dotnet::check_dotnet(ctx),
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
        ToolKind::Mojo => tools::mojo::update_mojo(ctx),
        ToolKind::Java => tools::java::update_java(ctx),
        ToolKind::Dotnet => tools::dotnet::update_dotnet(ctx),
    }
}

pub fn tool_method(tool: ToolKind) -> UpdateMethod {
    match tool {
        ToolKind::Go | ToolKind::Node | ToolKind::Python | ToolKind::Java | ToolKind::Dotnet => {
            UpdateMethod::DirectDownload
        }
        ToolKind::Rust | ToolKind::Flutter | ToolKind::Mojo => UpdateMethod::BuiltIn,
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

/// Report the legacy dry-run only; use `managed_cleanup::preview` and `remove` for cleanup.
pub fn clean_tool(ctx: &Ctx, tool: ToolKind) -> Result<()> {
    if !ctx.dry_run {
        bail!(
            "direct cleanup is unavailable; review a managed_cleanup::preview plan and use managed_cleanup::remove"
        );
    }
    info(
        ctx,
        format!(
            "[dry-run] would remove {} and related symlinks",
            ctx.home.join(tool.as_str()).display()
        ),
    );
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
fn mount_inside(mounts: &[u8], root: &std::path::Path) -> Result<bool> {
    Ok(mount_points(mounts)?
        .iter()
        .any(|path| path.starts_with(root)))
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(field: &[u8]) -> Result<PathBuf> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let mut decoded = Vec::with_capacity(field.len());
    let mut index = 0;
    while index < field.len() {
        if field[index] != b'\\' {
            decoded.push(field[index]);
            index += 1;
            continue;
        }
        let escape = field
            .get(index + 1..index + 4)
            .ok_or_else(|| anyhow!("invalid mount table path escape"))?;
        decoded.push(match escape {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => bail!("invalid mount table path escape"),
        });
        index += 4;
    }
    if !decoded.starts_with(b"/") || decoded.contains(&0) {
        bail!("mount table path is not absolute");
    }
    Ok(PathBuf::from(OsString::from_vec(decoded)))
}

#[cfg(target_os = "linux")]
fn mountinfo_decimal(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().all(|byte| byte.is_ascii_digit())
        && std::str::from_utf8(value).is_ok_and(|value| value.parse::<u64>().is_ok())
}

#[cfg(target_os = "linux")]
fn mountinfo_device(value: &[u8]) -> bool {
    let Some(separator) = value.iter().position(|byte| *byte == b':') else {
        return false;
    };
    let (major, suffix) = value.split_at(separator);
    let minor = &suffix[1..];
    mountinfo_decimal(major) && mountinfo_decimal(minor) && !minor.contains(&b':')
}

#[cfg(target_os = "linux")]
fn mountinfo_options(value: &[u8]) -> bool {
    let mut options = value.split(|byte| *byte == b',');
    let access = options.next().unwrap_or_default();
    (access == b"ro" || access == b"rw") && options.all(|option| !option.is_empty())
}

#[cfg(target_os = "linux")]
pub(crate) fn mount_points(mounts: &[u8]) -> Result<Vec<PathBuf>> {
    let lines = mounts.strip_suffix(b"\n").unwrap_or(mounts);
    if lines.is_empty() {
        bail!("mount table is empty");
    }
    let mut points = Vec::new();
    for line in lines.split(|byte| *byte == b'\n') {
        if line.is_empty() || line.contains(&b'\t') {
            bail!("invalid mount table entry");
        }
        let fields = line.split(|byte| *byte == b' ').collect::<Vec<_>>();
        if fields.iter().any(|field| field.is_empty()) || fields.len() < 10 {
            bail!("invalid mount table entry");
        }
        let separator = fields
            .iter()
            .enumerate()
            .skip(6)
            .find_map(|(index, field)| (*field == b"-").then_some(index))
            .ok_or_else(|| anyhow!("invalid mount table entry"))?;
        if separator + 4 != fields.len()
            || !mountinfo_decimal(fields[0])
            || !mountinfo_decimal(fields[1])
            || !mountinfo_device(fields[2])
            || !mountinfo_options(fields[5])
            || fields[separator + 1].is_empty()
            || fields[separator + 2].is_empty()
            || !mountinfo_options(fields[separator + 3])
        {
            bail!("invalid mount table entry");
        }
        let _root = decode_mountinfo_path(fields[3])?;
        points.push(decode_mountinfo_path(fields[4])?);
    }
    if points.is_empty() {
        bail!("mount table contains no entries");
    }
    Ok(points)
}

#[cfg(all(test, target_os = "linux"))]
mod mount_tests {
    use super::mount_inside;
    use std::path::Path;

    #[test]
    fn low_storage_warning_does_not_assume_unavailable_is_healthy() {
        assert!(
            super::low_storage_warning(Some(1024))
                .unwrap()
                .contains("below 1 GiB")
        );
        assert!(super::low_storage_warning(Some(1024 * 1024 * 1024)).is_none());
        assert!(super::low_storage_warning(None).is_none());
    }

    #[test]
    fn recognizes_nested_and_escaped_mounts() {
        let mounts = b"1 0 0:1 / / rw - tmpfs tmpfs rw\n2 1 0:1 / /tmp/tool\\040home/go/cache rw shared:1 future:tag - tmpfs tmpfs rw\n";
        assert!(mount_inside(mounts, Path::new("/tmp/tool home/go")).unwrap());
        assert!(!mount_inside(mounts, Path::new("/tmp/tool home/node")).unwrap());
        assert!(mount_inside(b"broken", Path::new("/tmp")).is_err());
    }

    #[test]
    fn mount_parser_preserves_non_unicode_path_bytes_and_linux_escapes() {
        use std::os::unix::ffi::OsStrExt;

        let mounts = b"36 35 98:0 /root-\xff /mnt/non-\xfe\\040space\\011tab\\012line\\134040 rw,noatime master:1 future:field - ext3 /dev/root rw,errors=continue\n";
        let points = super::mount_points(mounts).unwrap();
        assert_eq!(
            points[0].as_os_str().as_bytes(),
            b"/mnt/non-\xfe space\ttab\nline\\040"
        );
    }

    #[test]
    fn mount_parser_rejects_empty_or_malformed_tables() {
        for mounts in [
            b"".as_slice(),
            b"\n",
            b"1 0 0:1 / / rw tmpfs tmpfs rw\n",
            b"1 0 0:1 / / rw - tmpfs tmpfs\n",
            b"+1 0 0:1 / / rw - tmpfs tmpfs rw\n",
            b"1 0 0:1 relative / rw - tmpfs tmpfs rw\n",
            br"1 0 0:1 / /\777 rw - tmpfs tmpfs rw\n",
            b"1 0 0:1 / /\\04 rw - tmpfs tmpfs rw\n",
            b"1 0 0:1 / / rw - tmpfs tmpfs rw extra\n",
        ] {
            assert!(super::mount_points(mounts).is_err(), "{mounts:?}");
        }
    }

    #[test]
    fn mount_parser_reads_the_current_mount_table_without_lossy_paths() {
        let mounts = std::fs::read("/proc/self/mountinfo").unwrap();
        let points = super::mount_points(&mounts).unwrap();
        assert!(points.iter().any(|path| path == Path::new("/")));
    }
}

pub fn run_doctor(ctx: &Ctx, json: bool) -> Result<()> {
    run_doctor_with_config(ctx, json, None, None)
}

fn run_doctor_with_config(
    ctx: &Ctx,
    json: bool,
    config: Option<&std::path::Path>,
    profile: Option<&str>,
) -> Result<()> {
    let diagnostics = diagnose_with_config(ctx, config, profile);
    let mut issues = diagnostics.issues;
    let available_bytes = crate::maintenance::available_space(&ctx.home);
    let doctor_cancel = std::sync::atomic::AtomicBool::new(false);
    let mut capabilities = crate::doctor::capabilities_with_dry_run(
        &ctx.home,
        ctx.offline,
        ctx.dry_run,
        &doctor_cancel,
    );
    capabilities
        .actionable_diagnostics
        .extend(diagnostics.warnings);
    if let Some(diagnostic) = capabilities.installation_diagnostic() {
        issues.push(diagnostic);
    }
    let interactive = ctx.stdin_is_tty;

    if json {
        let report = serde_json::json!({
            "os": ctx.os,
            "arch": ctx.arch,
            "interactive": interactive,
            "offline": ctx.offline,
            "home": ctx.home.display().to_string(),
            "bindir": ctx.bindir.display().to_string(),
            "home_available_bytes": available_bytes,
            "capabilities": capabilities,
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
        info(
            ctx,
            format!(
                "- home filesystem available bytes: {} (snapshot)",
                available_bytes.map_or("unavailable".into(), |bytes| bytes.to_string())
            ),
        );
        for line in capabilities.lines() {
            info(ctx, format!("- {line}"));
        }
        if issues.is_empty() {
            info(
                ctx,
                "No issues found by diagnostic checks; see capability status above.",
            );
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

fn low_storage_warning(available: Option<u64>) -> Option<String> {
    available.filter(|bytes| *bytes < 1024 * 1024 * 1024).map(|bytes| format!(
        "Upkit home filesystem has {bytes} available bytes (below 1 GiB); review storage and free space before installing or updating tools"
    ))
}

fn path_component_matches(left: &std::ffi::OsStr, right: &std::ffi::OsStr, windows: bool) -> bool {
    left == right
        || (windows
            && left
                .to_str()
                .zip(right.to_str())
                .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right)))
}

fn path_is_within(path: &std::path::Path, directory: &std::path::Path, windows: bool) -> bool {
    let mut path = path.components();
    directory.components().all(|directory| {
        path.next().is_some_and(|component| {
            path_component_matches(component.as_os_str(), directory.as_os_str(), windows)
        })
    })
}

fn managed_tool_root(ctx: &Ctx, tool: ToolKind) -> Option<PathBuf> {
    match tool {
        ToolKind::Go
        | ToolKind::Node
        | ToolKind::Python
        | ToolKind::Flutter
        | ToolKind::Java
        | ToolKind::Dotnet => Some(ctx.home.join(tool.as_str())),
        ToolKind::Rust | ToolKind::Mojo => None,
    }
}

fn paths_match(left: &std::path::Path, right: &std::path::Path, windows: bool) -> bool {
    let mut left = left.components();
    let mut right = right.components();
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (Some(left), Some(right))
                if path_component_matches(left.as_os_str(), right.as_os_str(), windows) => {}
            _ => return false,
        }
    }
}

fn paths_are_equivalent(left: &std::path::Path, right: &std::path::Path, windows: bool) -> bool {
    paths_match(left, right, windows)
        || matches!(
            (left.canonicalize(), right.canonicalize()),
            (Ok(left), Ok(right)) if paths_match(&left, &right, windows)
        )
}

fn path_entry_index(
    directory: &std::path::Path,
    path_entries: &[PathBuf],
    windows: bool,
) -> Option<usize> {
    path_entries
        .iter()
        .position(|entry| paths_are_equivalent(directory, entry, windows))
}

fn path_is_on_path(directory: &std::path::Path, path_entries: &[PathBuf], windows: bool) -> bool {
    path_entry_index(directory, path_entries, windows).is_some()
}

fn windows_command_in_directory(
    directory: &std::path::Path,
    command: &str,
    extensions: &[&str],
) -> Option<PathBuf> {
    extensions.iter().find_map(|extension| {
        let candidate = directory.join(format!("{command}{extension}"));
        fs::metadata(&candidate)
            .is_ok_and(|metadata| metadata.is_file())
            .then_some(candidate)
    })
}

fn managed_windows_command(
    directory: &std::path::Path,
    command: &str,
    extensions: &[&str],
) -> Option<PathBuf> {
    let active_dir = directory.canonicalize().ok()?;
    let candidate = windows_command_in_directory(directory, command, extensions)?;
    let resolved = candidate.canonicalize().ok()?;
    let metadata = fs::metadata(&resolved).ok()?;
    (metadata.is_file()
        && metadata.len() > 0
        && resolved
            .parent()
            .is_some_and(|parent| paths_are_equivalent(parent, &active_dir, true)))
    .then_some(resolved)
}

fn windows_path_shadow_warnings(
    tool: &str,
    commands: &[&str],
    managed_path: &std::path::Path,
    path_entries: &[PathBuf],
    managed_index: usize,
    pathext: &str,
) -> Vec<String> {
    let extensions: Vec<_> = pathext
        .split(';')
        .filter(|extension| {
            extension.starts_with('.')
                && extension.len() > 1
                && extension[1..]
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric())
        })
        .collect();
    commands
        .iter()
        .filter_map(|command| {
            let managed = managed_windows_command(managed_path, command, &extensions)?;
            let shadow = path_entries[..managed_index]
                .iter()
                .filter(|entry| !entry.as_os_str().is_empty())
                .find_map(|entry| windows_command_in_directory(entry, command, &extensions))?;
            (!paths_are_equivalent(&shadow, &managed, true)).then(|| {
                format!(
                    "Windows PATH/PATHEXT search finds {command} at {} before managed {tool} at {}; it may take precedence, so move the managed directory earlier in PATH if unintended",
                    crate::sweep::display_path(&shadow),
                    crate::sweep::display_path(managed_path)
                )
            })
        })
        .collect()
}

fn managed_windows_node_path(ctx: &Ctx) -> Option<PathBuf> {
    if ctx.os != "windows" {
        return None;
    }

    let root = ctx.home.join("node");
    if crate::infrastructure::validate_active_install(&root).is_err() {
        return None;
    }

    let active = root.join("active");
    let active_dir = active.canonicalize().ok()?;
    let binary = active.join("node.exe").canonicalize().ok()?;
    let metadata = fs::metadata(&binary).ok()?;
    (metadata.is_file()
        && metadata.len() > 0
        && binary
            .parent()
            .is_some_and(|parent| paths_are_equivalent(parent, &active_dir, true)))
    .then_some(active)
}

fn managed_windows_flutter_bin(ctx: &Ctx) -> Option<PathBuf> {
    if ctx.os != "windows" {
        return None;
    }

    let root = ctx.home.join("flutter");
    crate::infrastructure::validate_active_install(&root).ok()?;
    let active_link = root.join("active");
    let active = active_link.canonicalize().ok()?;
    let bin_link = active_link.join("bin");
    let bin = bin_link.canonicalize().ok()?;
    if !active.is_dir() || !bin.is_dir() || !path_is_within(&bin, &active, true) {
        return None;
    }

    for launcher in ["flutter.bat", "dart.bat"] {
        let launcher = bin_link.join(launcher).canonicalize().ok()?;
        let metadata = fs::metadata(&launcher).ok()?;
        if !metadata.is_file() || metadata.len() == 0 || !path_is_within(&launcher, &bin, true) {
            return None;
        }
    }

    Some(bin_link)
}

pub(crate) struct DoctorDiagnostics {
    pub issues: Vec<String>,
    pub warnings: Vec<String>,
}

pub(crate) fn diagnose_with_config(
    ctx: &Ctx,
    config: Option<&std::path::Path>,
    profile: Option<&str>,
) -> DoctorDiagnostics {
    let mut issues: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    if let Some(warning) = crate::doctor::artifact_growth_warning(&ctx.home) {
        issues.push(warning);
    }
    if let Some(warning) = low_storage_warning(crate::maintenance::available_space(&ctx.home)) {
        issues.push(warning);
    }

    let settings = crate::config::config_path(config)
        .and_then(|path| crate::config::load(&path, config.is_some()));
    match settings {
        Ok(settings) => {
            if let Some(name) = profile && !settings.profiles.contains_key(name) {
                issues.push(format!("unknown workspace profile {}; configure it or remove --profile", name.escape_default()));
            }
            let roots = match profile {
                Some(name) => settings.profiles.get(name).map(|profile| &profile.workspace_roots),
                None => Some(&settings.workspace_roots),
            };
            if let Some(roots) = roots {
                if roots.is_empty() && let Some(name) = profile {
                    warnings.push(format!(
                        "workspace profile {} has no configured roots; add workspace_roots or pass paths explicitly to `sweep scan`",
                        name.escape_default()
                    ));
                }
                for root in roots {
                    let problem = match fs::symlink_metadata(root) {
                        Ok(meta) if meta.file_type().is_symlink() => Some("is a symbolic link".to_owned()),
                        Ok(meta) if !meta.is_dir() => Some("is not a directory".to_owned()),
                        Ok(_) => fs::read_dir(root).err().map(|err| format!("cannot be read: {err}")),
                        Err(err) => Some(format!("cannot be inspected: {err}")),
                    };
                    if let Some(problem) = problem {
                        issues.push(format!("workspace root {} {problem}; correct the configured root before scanning", crate::sweep::display_path(root)));
                    }
                }
            }
        }
        Err(err) => issues.push(format!("invalid or unreadable Upkit configuration: {err}; inspect or repair the configuration file")),
    }

    match fs::metadata(&ctx.home) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => issues.push(format!(
            "home directory does not exist: {}",
            crate::sweep::display_path(&ctx.home)
        )),
        Err(err) => issues.push(format!(
            "home directory cannot be inspected: {}: {err}",
            crate::sweep::display_path(&ctx.home)
        )),
        Ok(metadata) if !metadata.is_dir() => issues.push(format!(
            "home path is not a directory: {}",
            crate::sweep::display_path(&ctx.home)
        )),
        Ok(_) => {}
    }
    match fs::metadata(&ctx.bindir) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => issues.push(format!(
            "bindir does not exist: {}",
            crate::sweep::display_path(&ctx.bindir)
        )),
        Err(err) => issues.push(format!(
            "bindir cannot be inspected: {}: {err}",
            crate::sweep::display_path(&ctx.bindir)
        )),
        Ok(metadata) if !metadata.is_dir() => issues.push(format!(
            "bindir path is not a directory: {}",
            crate::sweep::display_path(&ctx.bindir)
        )),
        Ok(_) => {}
    }

    if !ctx.dry_run && fs::metadata(&ctx.home).is_ok() {
        if let Err(err) = tempfile::Builder::new()
            .prefix("upkit")
            .tempfile_in(&ctx.home)
        {
            issues.push(format!("home dir not writable: {err}"));
            #[cfg(coverage)]
            {
                let _ = &err;
            }
        }
        #[cfg(coverage)]
        {
            let _ = &ctx.home;
        }
    }
    if !ctx.dry_run && fs::metadata(&ctx.bindir).is_ok() {
        if let Err(err) = tempfile::Builder::new()
            .prefix("upkit")
            .tempfile_in(&ctx.bindir)
        {
            issues.push(format!("bindir not writable: {err}"));
            #[cfg(coverage)]
            {
                let _ = &err;
            }
        }
        #[cfg(coverage)]
        {
            let _ = &ctx.bindir;
        }
    }

    let path = get_env_var("PATH").unwrap_or_default();
    let path_entries: Vec<_> = env::split_paths(&path).collect();
    let windows = ctx.os == "windows";
    if !path_is_on_path(&ctx.bindir, &path_entries, windows) {
        issues.push(format!(
            "bindir is not on PATH; add {} to PATH",
            ctx.bindir.display()
        ));
    }
    if let Some(node_path) = managed_windows_node_path(ctx) {
        if let Some(managed_index) = path_entry_index(&node_path, &path_entries, windows) {
            if windows {
                issues.extend(windows_path_shadow_warnings(
                    "Node",
                    &["node", "npm", "npx"],
                    &node_path,
                    &path_entries,
                    managed_index,
                    &get_env_var("PATHEXT").unwrap_or_default(),
                ));
            }
        } else {
            issues.push(format!(
                "managed Windows Node install is not on PATH; add {} to PATH to make node, npm, and npx available",
                crate::sweep::display_path(&node_path)
            ));
        }
    }
    if let Some(flutter_bin) = managed_windows_flutter_bin(ctx) {
        if let Some(managed_index) = path_entry_index(&flutter_bin, &path_entries, windows) {
            if windows {
                issues.extend(windows_path_shadow_warnings(
                    "Flutter",
                    &["flutter", "dart"],
                    &flutter_bin,
                    &path_entries,
                    managed_index,
                    &get_env_var("PATHEXT").unwrap_or_default(),
                ));
            }
        } else {
            issues.push(format!(
                "managed Windows Flutter install is not on PATH; add {} to PATH to make Flutter and Dart available",
                crate::sweep::display_path(&flutter_bin)
            ));
        }
    }

    for tool in ToolKind::all() {
        for name in tool_bin_names(tool) {
            let link = ctx.bindir.join(name);
            if fs::symlink_metadata(&link).is_ok_and(|meta| meta.file_type().is_symlink()) {
                match fs::metadata(&link) {
                    Ok(meta) if meta.is_file() => {
                        if let Some(root) = managed_tool_root(ctx, tool) {
                            let resolved_inside_root = link
                                .canonicalize()
                                .ok()
                                .zip(root.canonicalize().ok())
                                .is_some_and(|(target, root)| {
                                    path_is_within(&target, &root, windows)
                                        && !paths_match(&target, &root, windows)
                                });
                            if !resolved_inside_root {
                                issues.push(format!(
                                    "tool link {} does not resolve inside the managed {} installation; inspect or reinstall {}",
                                    crate::sweep::display_path(&link),
                                    tool.as_str(),
                                    tool.as_str()
                                ));
                            }
                        }
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if meta.permissions().mode() & 0o111 == 0 {
                                issues.push(format!(
                                    "tool link {} resolves to a non-executable file; inspect permissions or reinstall {}",
                                    crate::sweep::display_path(&link), tool.as_str()
                                ));
                            }
                        }
                    }
                    Ok(_) => issues.push(format!(
                        "tool link {} does not resolve to a file; inspect or reinstall {}",
                        crate::sweep::display_path(&link),
                        tool.as_str()
                    )),
                    Err(err) => issues.push(format!(
                        "cannot resolve tool link {}: {err}; inspect or reinstall {}",
                        crate::sweep::display_path(&link),
                        tool.as_str()
                    )),
                }
            }
        }
    }

    let mut missing = Vec::new();
    for tool in ToolKind::all() {
        let bin = match tool {
            ToolKind::Go => "go",
            ToolKind::Rust => "rustc",
            ToolKind::Node => "node",
            ToolKind::Python if ctx.os == "windows" => "python.exe",
            ToolKind::Python => "python3",
            ToolKind::Flutter => "flutter",
            ToolKind::Mojo => "mojo",
            ToolKind::Java => "javac",
            ToolKind::Dotnet => "dotnet",
        };
        if which_or_none(bin).is_none() {
            missing.push(bin);
        }
    }
    if !missing.is_empty() {
        issues.push(format!("missing tools in PATH: {}", missing.join(", ")));
    }

    if !ctx.offline
        && let Err(err) = http_get_text(ctx, "https://example.com")
    {
        issues.push(format!("network check failed: {err}"));
    }

    DoctorDiagnostics { issues, warnings }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelfUpdatePlan {
    pub(crate) program: String,
    pub(crate) program_path: PathBuf,
    pub(crate) args: Vec<String>,
    pub(crate) destination: PathBuf,
    pub(crate) prompt: String,
    pub(crate) description: String,
    pub(crate) via: &'static str,
    pub(crate) release_source: Option<OsString>,
}

pub(crate) fn self_update_plan(ctx: &Ctx) -> Result<SelfUpdatePlan> {
    if ctx.offline {
        bail!("offline mode enabled; self-update requires network access");
    }
    let install_via_npm = matches!(get_env_var("UPKIT_INSTALLER").as_deref(), Some("npm"));
    let exe = env::current_exe().context("locate the running upkit binary")?;
    let exe_dir = exe.parent().context("locate the upkit install directory")?;
    let cargo_home = get_env_var("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".cargo")));
    let install_via_cargo = matches!(get_env_var("UPKIT_INSTALLER").as_deref(), Some("cargo"))
        || cargo_home
            .and_then(|home| home.join("bin").canonicalize().ok())
            .is_some_and(|bin| exe_dir.canonicalize().is_ok_and(|dir| dir == bin));
    let package_name = get_env_var("UPKIT_NPM_PACKAGE_NAME")
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "@christiandoxa/upkit".to_string());
    let (program, args, prompt_text, dry_run_text, via) = if install_via_npm {
        if which_or_none("npm").is_none() {
            bail!("npm not found in PATH; reinstall manually");
        }
        let command = format!("npm install -g {package_name}@latest");
        (
            "npm".to_string(),
            vec![
                "install".to_string(),
                "-g".to_string(),
                format!("{package_name}@latest"),
            ],
            format!("Update upkit via {command}?"),
            command,
            "npm",
        )
    } else if install_via_cargo {
        if which_or_none("cargo").is_none() {
            bail!("cargo not found in PATH; reinstall manually");
        }
        (
            "cargo".to_string(),
            vec![
                "install".to_string(),
                "--force".to_string(),
                "upkit".to_string(),
            ],
            "Update upkit via cargo install --force upkit?".to_string(),
            "cargo install --force upkit".to_string(),
            "cargo",
        )
    } else {
        let program = if ctx.os == "windows" {
            if which_or_none("pwsh").is_some() {
                "pwsh"
            } else {
                "powershell"
            }
        } else {
            "sh"
        };
        if which_or_none(program).is_none() {
            bail!("{program} not found in PATH; reinstall manually");
        }
        (
            program.to_string(),
            Vec::new(),
            "Update upkit from GitHub Releases?".to_string(),
            format!("install latest GitHub release into {}", exe_dir.display()),
            "github",
        )
    };
    let program_path = which_or_none(&program)
        .with_context(|| format!("{program} not found in PATH; reinstall manually"))?;
    let release_source = if via == "github" {
        env::var_os("UPKIT_RELEASE_BASE_URL").filter(|value| {
            if ctx.os == "windows" {
                !value.to_string_lossy().trim().is_empty()
            } else {
                !value.is_empty()
            }
        })
    } else {
        None
    };
    Ok(SelfUpdatePlan {
        program,
        program_path,
        args,
        destination: exe_dir.to_path_buf(),
        prompt: prompt_text,
        description: dry_run_text,
        via,
        release_source,
    })
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
    let plan = self_update_plan(ctx)?;
    if !ctx.yes {
        let ok = ctx.prompt.confirm(&plan.prompt, false)?;
        if !ok {
            info(ctx, "Canceled.");
            return Ok(());
        }
    }
    execute_self_update(ctx, &plan, json, false)
}

pub(crate) fn run_approved_self_update(ctx: &Ctx, plan: &SelfUpdatePlan) -> Result<()> {
    if &self_update_plan(ctx)? != plan {
        bail!("self-update plan changed; review it again");
    }
    execute_self_update(ctx, plan, false, true)
}

fn execute_self_update(
    ctx: &Ctx,
    plan: &SelfUpdatePlan,
    json: bool,
    use_reviewed_program: bool,
) -> Result<()> {
    let SelfUpdatePlan {
        program,
        args,
        destination,
        description,
        via,
        ..
    } = plan;
    if ctx.dry_run {
        if json {
            let payload = serde_json::json!({
                "command": "self-update",
                "ok": true,
                "dry_run": true,
                "via": via,
            });
            emit_json(ctx, payload)?;
        } else {
            info(ctx, format!("[dry-run] would run: {description}"));
        }
        return Ok(());
    }
    if *via == "github" {
        let windows = ctx.os == "windows";
        let installer = tempfile::tempdir()?;
        let installer_path =
            installer
                .path()
                .join(if windows { "install.ps1" } else { "install.sh" });
        fs::write(
            &installer_path,
            if windows {
                include_str!("../install.ps1")
            } else {
                include_str!("../install.sh")
            },
        )?;
        let mut args: Vec<OsString> = if windows {
            ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]
                .map(OsString::from)
                .to_vec()
        } else {
            Vec::new()
        };
        args.push(installer_path.into_os_string());
        args.push(
            if windows {
                "-InstallDir"
            } else {
                "--install-dir"
            }
            .into(),
        );
        args.push(destination.as_os_str().to_owned());
        args.push(if windows { "-Release" } else { "--release" }.into());
        args.push("latest".into());
        if use_reviewed_program {
            let mut command = std::process::Command::new(&plan.program_path);
            command.args(&args);
            if let Some(source) = &plan.release_source {
                command.env("UPKIT_RELEASE_BASE_URL", source);
            } else {
                command.env_remove("UPKIT_RELEASE_BASE_URL");
            }
            if windows {
                command.env("UPKIT_NO_PATH_UPDATE", "1");
            }
            let output = command.output().context("start reviewed installer")?;
            if !output.status.success() {
                bail!(
                    "GitHub self-update failed: installer exited with {}",
                    output.status
                );
            }
        } else {
            run_capture(OsString::from(program), &args)
                .map_err(|err| anyhow!("GitHub self-update failed: {err:#}"))?;
        }
    } else {
        let status = if use_reviewed_program {
            let args = args.iter().map(OsString::from).collect::<Vec<_>>();
            run_status(plan.program_path.as_os_str().to_owned(), &args)
        } else {
            run_status(program.clone(), args)
        }
        .context("failed to run self-update command")?;
        if !status.success() {
            bail!("self-update failed");
        }
    }
    if json {
        let payload = serde_json::json!({
            "command": "self-update",
            "ok": true,
            "via": via,
        });
        emit_json(ctx, payload)?;
    } else {
        info(ctx, "upkit updated");
    }
    Ok(())
}

#[cfg(test)]
mod self_update_review_tests {
    use super::*;
    use crate::test_support::{TestPrompt, base_ctx, reset_guard, set_env_var, set_which};
    use std::sync::Arc;

    #[test]
    fn changed_self_update_plan_is_rejected_before_execution() {
        let _guard = reset_guard();
        let directory = tempfile::tempdir().unwrap();
        let ctx = base_ctx(
            directory.path().join("home"),
            directory.path().join("bin"),
            Arc::new(TestPrompt::default()),
        );
        set_env_var("UPKIT_INSTALLER", Some("npm".into()));
        set_env_var("UPKIT_NPM_PACKAGE_NAME", Some("fixture-package".into()));
        set_which("npm", Some(PathBuf::from("/fixture/bin/npm")));
        let plan = self_update_plan(&ctx).unwrap();
        set_env_var("UPKIT_NPM_PACKAGE_NAME", Some("other-package".into()));
        let error = run_approved_self_update(&ctx, &plan).unwrap_err();
        assert!(error.to_string().contains("plan changed"));
        set_env_var("UPKIT_NPM_PACKAGE_NAME", Some("fixture-package".into()));
        set_which("npm", Some(PathBuf::from("/fixture/other/npm")));
        let error = run_approved_self_update(&ctx, &plan).unwrap_err();
        assert!(error.to_string().contains("plan changed"));
    }

    #[test]
    fn changed_release_source_invalidates_a_reviewed_plan() {
        let _guard = reset_guard();
        let directory = tempfile::tempdir().unwrap();
        let mut ctx = base_ctx(
            directory.path().join("home"),
            directory.path().join("bin"),
            Arc::new(TestPrompt::default()),
        );
        ctx.os = "linux".into();
        set_env_var("UPKIT_INSTALLER", Some("standalone".into()));
        set_which("sh", Some(PathBuf::from("/fixture/bin/sh")));
        let mut plan = self_update_plan(&ctx).unwrap();
        plan.release_source = if plan.release_source.is_some() {
            None
        } else {
            Some("/fixture/other-release".into())
        };
        let error = run_approved_self_update(&ctx, &plan).unwrap_err();
        assert!(error.to_string().contains("plan changed"));
    }
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

#[cfg(all(test, any(unix, windows)))]
mod windows_node_doctor_tests {
    use super::{diagnose_with_config, managed_windows_flutter_bin, windows_path_shadow_warnings};
    use crate::infrastructure::Ctx;
    use crate::test_support::{TestPrompt, base_ctx, reset_guard, set_env_var};
    #[cfg(unix)]
    use std::os::unix::fs::symlink as symlink_dir;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_dir;
    use std::{env, fs, io, path::Path, sync::Arc};
    use tempfile::tempdir;

    fn fixture_ctx(root: &Path) -> (Ctx, std::path::PathBuf) {
        let home = root.join("home");
        let bindir = root.join("bin");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&bindir).unwrap();
        let config = root.join("config.toml");
        fs::write(&config, "").unwrap();
        let mut ctx = base_ctx(home, bindir, Arc::new(TestPrompt::default()));
        ctx.os = "windows".into();
        ctx.offline = true;
        ctx.dry_run = true;
        (ctx, config)
    }

    #[cfg(unix)]
    fn remove_dir_symlink(path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    #[cfg(windows)]
    fn remove_dir_symlink(path: &Path) -> io::Result<()> {
        fs::remove_dir(path)
    }

    fn ensure_symlink_permission(root: &Path) -> bool {
        let target = root.join("symlink-probe-target");
        let link = root.join("symlink-probe");
        fs::create_dir_all(&target).unwrap();
        match symlink_dir(&target, &link) {
            Ok(()) => {
                remove_dir_symlink(&link).unwrap();
                true
            }
            Err(err) if cfg!(windows) && err.raw_os_error() == Some(1314) => {
                eprintln!(
                    "SKIP: Windows directory-symlink permission unavailable; skipping Doctor fixture ({err})"
                );
                false
            }
            Err(err) => panic!("probe directory-symlink support: {err}"),
        }
    }

    fn set_path(paths: &[std::path::PathBuf]) {
        let path = env::join_paths(paths.iter().map(|path| path.as_os_str())).unwrap();
        set_env_var("PATH", Some(path.to_string_lossy().into_owned()));
    }

    fn diagnose(ctx: &Ctx, config: &Path) -> Vec<String> {
        diagnose_with_config(ctx, Some(config), None).issues
    }

    #[test]
    fn selected_empty_profile_roots_are_a_nonfatal_scan_warning() {
        let _guard = reset_guard();
        let dir = tempdir().unwrap();
        let (ctx, config) = fixture_ctx(dir.path());
        let global_root = dir.path().join("global-workspace");
        fs::create_dir(&global_root).unwrap();
        let mut settings = crate::config::Settings {
            workspace_roots: vec![global_root],
            ..Default::default()
        };
        settings
            .profiles
            .insert("empty".into(), crate::config::Profile::default());
        fs::write(&config, toml::to_string_pretty(&settings).unwrap()).unwrap();
        set_path(std::slice::from_ref(&ctx.bindir));

        let diagnostics = diagnose_with_config(&ctx, Some(&config), Some("empty"));

        assert!(
            diagnostics.issues.iter().all(|issue| {
                !issue.contains("workspace profile empty has no configured roots")
            })
        );
        assert!(diagnostics.warnings.iter().any(|warning| {
            warning.contains("workspace profile empty has no configured roots")
                && warning.contains("pass paths explicitly to `sweep scan`")
        }));
    }

    fn install_node_fixture(ctx: &Ctx) -> std::path::PathBuf {
        let node_root = ctx.home.join("node");
        let version = node_root.join("v20.0.0");
        fs::create_dir_all(&version).unwrap();
        fs::write(version.join("node.exe"), b"fixture executable").unwrap();
        fs::write(version.join("npm.cmd"), b"fixture command").unwrap();
        fs::write(version.join("npx.cmd"), b"fixture command").unwrap();
        symlink_dir(&version, node_root.join("active")).unwrap();
        node_root.join("active")
    }

    fn install_flutter_fixture(ctx: &Ctx) -> std::path::PathBuf {
        let flutter_root = ctx.home.join("flutter");
        let version = flutter_root.join("v3.36.0/flutter");
        let bin = version.join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("flutter.bat"), b"fixture launcher").unwrap();
        fs::write(bin.join("dart.bat"), b"fixture launcher").unwrap();
        symlink_dir(&version, flutter_root.join("active")).unwrap();
        flutter_root.join("active/bin")
    }

    #[test]
    fn doctor_reports_missing_path_for_a_managed_windows_node_install() {
        let _guard = reset_guard();
        let dir = tempdir().unwrap();
        if !ensure_symlink_permission(dir.path()) {
            return;
        }
        let (ctx, config) = fixture_ctx(dir.path());
        let active = install_node_fixture(&ctx);
        set_path(std::slice::from_ref(&ctx.bindir));

        let issues = diagnose(&ctx, &config);
        let issue = issues
            .iter()
            .find(|issue| issue.contains("managed Windows Node install is not on PATH"))
            .expect("managed Node PATH issue");
        assert!(issue.contains(&active.display().to_string()));
        assert!(issue.contains("node, npm, and npx"));
    }

    #[test]
    fn doctor_accepts_equivalent_windows_node_path_entries() {
        let _guard = reset_guard();
        let dir = tempdir().unwrap();
        if !ensure_symlink_permission(dir.path()) {
            return;
        }
        let (ctx, config) = fixture_ctx(dir.path());
        let active = install_node_fixture(&ctx);
        let alias = active.join("..").join("active");
        let case_alias = active.with_file_name("ACTIVE");
        set_path(&[ctx.bindir.clone(), alias, case_alias]);

        let issues = diagnose(&ctx, &config);
        assert!(
            !issues
                .iter()
                .any(|issue| issue.contains("managed Windows Node install is not on PATH"))
        );
    }

    #[test]
    fn doctor_ignores_lookalike_or_outside_node_paths() {
        let _guard = reset_guard();
        let dir = tempdir().unwrap();
        if !ensure_symlink_permission(dir.path()) {
            return;
        }
        let (ctx, config) = fixture_ctx(dir.path());
        let active = ctx.home.join("node/active");
        fs::create_dir_all(&active).unwrap();
        fs::write(active.join("node.exe"), b"fixture executable").unwrap();
        set_path(std::slice::from_ref(&ctx.bindir));

        assert!(
            !diagnose(&ctx, &config)
                .iter()
                .any(|issue| issue.contains("managed Windows Node install is not on PATH"))
        );

        fs::remove_dir_all(&active).unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("node.exe"), b"fixture executable").unwrap();
        symlink_dir(&outside, &active).unwrap();
        assert!(
            !diagnose(&ctx, &config)
                .iter()
                .any(|issue| issue.contains("managed Windows Node install is not on PATH"))
        );
    }

    #[test]
    fn doctor_detects_node_and_npm_shadowing_in_path_and_pathext_order() {
        let dir = tempdir().unwrap();
        if !ensure_symlink_permission(dir.path()) {
            return;
        }
        let (ctx, _) = fixture_ctx(dir.path());
        let active = install_node_fixture(&ctx);
        for name in ["node.EXE", "npm.CMD", "npx.CMD"] {
            fs::write(active.join(name), b"fixture command").unwrap();
        }

        let earlier = dir.path().join("earlier-bin");
        fs::create_dir(&earlier).unwrap();
        fs::write(earlier.join("node.EXE"), b"").unwrap();
        for name in ["npm.EXE", "npm.CMD"] {
            fs::write(earlier.join(name), b"fixture command").unwrap();
        }

        let warnings = windows_path_shadow_warnings(
            "Node",
            &["node", "npm", "npx"],
            &active,
            &[earlier.clone(), active.clone()],
            1,
            ".EXE;.CMD",
        );
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("node"));
        assert!(warnings[0].contains(&earlier.join("node.EXE").display().to_string()));
        assert!(warnings[1].contains("npm"));
        assert!(warnings[1].contains(&earlier.join("npm.EXE").display().to_string()));
        assert!(!warnings.iter().any(|warning| warning.contains("npx")));
    }

    #[test]
    fn doctor_respects_node_path_order_case_and_pathext() {
        let dir = tempdir().unwrap();
        if !ensure_symlink_permission(dir.path()) {
            return;
        }
        let (ctx, _) = fixture_ctx(dir.path());
        let active = install_node_fixture(&ctx);
        for name in ["node.EXE", "npm.CMD", "npx.CMD"] {
            fs::write(active.join(name), b"fixture command").unwrap();
        }

        let other = dir.path().join("other-bin");
        fs::create_dir(&other).unwrap();
        fs::write(other.join("node.EXE"), b"fixture command").unwrap();

        assert!(
            windows_path_shadow_warnings(
                "Node",
                &["node", "npm", "npx"],
                &active,
                &[active.clone(), other.clone()],
                0,
                ".EXE;.CMD"
            )
            .is_empty()
        );
        let alias = dir.path().join("active-alias");
        symlink_dir(active.canonicalize().unwrap(), &alias).unwrap();
        assert!(
            windows_path_shadow_warnings(
                "Node",
                &["node", "npm", "npx"],
                &active,
                &[alias, active.clone()],
                0,
                ".EXE;.CMD"
            )
            .is_empty()
        );
        assert!(
            windows_path_shadow_warnings(
                "Node",
                &["node", "npm", "npx"],
                &active,
                &[other.clone(), active.with_file_name("ACTIVE")],
                1,
                ".EXE;.CMD"
            )
            .iter()
            .any(|warning| warning.contains("node"))
        );
        assert!(
            windows_path_shadow_warnings(
                "Node",
                &["node", "npm", "npx"],
                &active,
                &[other, active.clone()],
                1,
                ".BAT"
            )
            .is_empty()
        );
    }

    #[test]
    fn doctor_reports_windows_flutter_path_and_rejects_uncontained_links() {
        let _guard = reset_guard();
        let dir = tempdir().unwrap();
        if !ensure_symlink_permission(dir.path()) {
            return;
        }
        let (ctx, config) = fixture_ctx(dir.path());
        let flutter_bin = install_flutter_fixture(&ctx);
        set_path(std::slice::from_ref(&ctx.bindir));
        set_env_var("PATHEXT", Some(".EXE;.BAT".into()));

        let issues = diagnose(&ctx, &config);
        let issue = issues
            .iter()
            .find(|issue| issue.contains("managed Windows Flutter install is not on PATH"))
            .expect("managed Flutter PATH issue");
        assert!(issue.contains(&flutter_bin.display().to_string()));

        set_path(&[ctx.bindir.clone(), flutter_bin.clone()]);
        let issues = diagnose(&ctx, &config);
        assert!(
            !issues
                .iter()
                .any(|issue| issue.contains("managed Windows Flutter install is not on PATH"))
        );

        let active_link = ctx.home.join("flutter/active");
        let active = active_link.canonicalize().unwrap();
        let bin = active.join("bin");
        fs::remove_dir_all(&bin).unwrap();
        let outside_bin = dir.path().join("outside-bin");
        fs::create_dir(&outside_bin).unwrap();
        fs::write(outside_bin.join("flutter.bat"), b"fixture launcher").unwrap();
        fs::write(outside_bin.join("dart.bat"), b"fixture launcher").unwrap();
        symlink_dir(&outside_bin, &bin).unwrap();
        assert!(managed_windows_flutter_bin(&ctx).is_none());

        remove_dir_symlink(&active_link).unwrap();
        let outside_sdk = dir.path().join("outside-sdk");
        fs::create_dir_all(outside_sdk.join("bin")).unwrap();
        fs::write(outside_sdk.join("bin/flutter.bat"), b"fixture launcher").unwrap();
        fs::write(outside_sdk.join("bin/dart.bat"), b"fixture launcher").unwrap();
        symlink_dir(&outside_sdk, &active_link).unwrap();
        assert!(managed_windows_flutter_bin(&ctx).is_none());
    }
}

#[cfg(test)]
mod schedule_null_config_tests {
    #[test]
    fn scheduled_scan_requires_the_platform_null_device() {
        use std::path::Path;
        assert!(super::schedule_isolated_config(
            Some(Path::new("NUL")),
            true
        ));
        assert!(!super::schedule_isolated_config(
            Some(Path::new("/dev/null")),
            true
        ));
        assert!(super::schedule_isolated_config(
            Some(Path::new("/dev/null")),
            false
        ));
        assert!(!super::schedule_isolated_config(
            Some(Path::new("NUL")),
            false
        ));
        assert!(!super::schedule_isolated_config(None, true));
    }
}
