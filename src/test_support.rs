use crate::domain::{ToolKind, ToolReport};
use crate::infrastructure::{Ctx, HttpResponse, Prompt};
use anyhow::{Result, anyhow};
use reqwest::blocking::Client;
use std::collections::{HashMap, VecDeque};
use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::process::Output;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

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
        let err = std::io::Error::new(std::io::ErrorKind::Other, "forced json error");
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
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
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
        json_emitted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        prompt,
    }
}
