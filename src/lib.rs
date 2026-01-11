#![forbid(unsafe_code)]

pub mod application;
pub mod domain;
pub mod infrastructure;
pub mod test_support;
pub mod tools;

pub use application::{
    Cli, Commands, check_tool, check_tool_safe, check_tools_parallel, check_tools_with_spinner,
    clean_tool, ensure_dirs, main_entry, main_with, make_ctx, map_error_to_exit_code,
    report_has_error, run, run_doctor, run_self_update, run_version, select_kinds, tool_method,
    update_tool,
};
pub use domain::{Status, ToolKind, ToolReport, UpdateMethod, Version};
pub use infrastructure::{
    Ctx, DialoguerPrompt, HttpResponse, ProgressHandle, Prompt, atomic_symlink, colorize_status,
    data_local_dir, debug, download_to_temp, emit_json, ensure_clean_dir, error, expand_tilde,
    finish_spinner, get_env_var, home_dir, http_get, http_get_json, http_get_no_timeout,
    http_get_text, info, link_dir_bins, maybe_path_hint, maybe_path_hint_for_dir, print_json_error,
    print_reports, progress_allowed, progress_overwrite_allowed, prune_tool_versions,
    remove_path_hint_for_label, reports_to_json, run_capture, run_output, run_status, sleep_for,
    start_spinner, tool_bin_names, tool_path_hint_labels, warn, which_or_none, write_all_checked,
};

pub(crate) use infrastructure::sha256_file;
