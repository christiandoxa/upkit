//! Windows Task Scheduler XML and user-task orchestration.
use super::Frequency;
#[cfg(any(target_os = "windows", test))]
use super::{DisableSchedulePreview, RemoveSchedulePreview};
#[cfg(target_os = "windows")]
use super::{EditSchedulePreview, EnableSchedulePreview, ScanSchedulePreview, ScheduledScanPolicy};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
#[cfg(target_os = "windows")]
use std::path::Path;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};

const TASK_PATH: &str = "\\Upkit-Workspace-Scan";
const TASK_URI: &str = "urn:upkit:maintenance:workspace-scan:v1";
const TASK_DESCRIPTION: &str = "Read-only Upkit workspace scan";
const TASK_NAMESPACE: &str = "http://schemas.microsoft.com/windows/2004/02/mit/task";
const TASK_XML_LIMIT: usize = 65_536;
const TASK_ARGUMENT_LIMIT: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq)]
struct TaskDefinition {
    sid: String,
    frequency: Frequency,
    enabled: bool,
    command: String,
    arguments: String,
}

#[derive(Debug)]
struct XmlNode {
    name: String,
    attributes: BTreeMap<String, String>,
    text: String,
    children: Vec<XmlNode>,
}

fn xml_escape(value: &str) -> Result<String> {
    if value.chars().any(|c| {
        !(c == '\t'
            || c == '\n'
            || c == '\r'
            || ('\u{20}'..='\u{d7ff}').contains(&c)
            || ('\u{e000}'..='\u{fffd}').contains(&c)
            || ('\u{10000}'..='\u{10ffff}').contains(&c))
    }) {
        bail!("Task Scheduler XML value contains an invalid XML character");
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

fn quote_windows_argument(value: &str) -> Result<String> {
    if value.chars().any(char::is_control) {
        bail!("scheduled arguments cannot contain control characters");
    }
    let mut result = String::from("\"");
    let mut slashes = 0;
    for character in value.chars() {
        match character {
            '\\' => slashes += 1,
            '"' => {
                result.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
                result.push('"');
                slashes = 0;
            }
            _ => {
                result.extend(std::iter::repeat_n('\\', slashes));
                slashes = 0;
                result.push(character);
            }
        }
    }
    result.extend(std::iter::repeat_n('\\', slashes * 2));
    result.push('"');
    Ok(result)
}

fn windows_arguments(arguments: &[String]) -> Result<String> {
    let joined = arguments
        .iter()
        .map(|argument| quote_windows_argument(argument))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    if joined.len() > TASK_ARGUMENT_LIMIT {
        bail!("scheduled command arguments exceed the supported size limit");
    }
    Ok(joined)
}

fn parse_windows_arguments(arguments: &str) -> Result<Vec<String>> {
    let characters = arguments.chars().collect::<Vec<_>>();
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < characters.len() {
        while characters
            .get(offset)
            .is_some_and(|character| character.is_whitespace())
        {
            offset += 1;
        }
        if offset == characters.len() {
            break;
        }
        let mut value = String::new();
        let mut quoted = false;
        let mut started = false;
        loop {
            let mut slashes = 0;
            while characters.get(offset) == Some(&'\\') {
                slashes += 1;
                offset += 1;
            }
            if characters.get(offset) == Some(&'"') {
                value.extend(std::iter::repeat_n('\\', slashes / 2));
                if slashes % 2 == 1 {
                    value.push('"');
                } else {
                    quoted = !quoted;
                }
                offset += 1;
                started = true;
                continue;
            }
            value.extend(std::iter::repeat_n('\\', slashes));
            let Some(character) = characters.get(offset).copied() else {
                break;
            };
            if !quoted && character.is_whitespace() {
                break;
            }
            value.push(character);
            offset += 1;
            started = true;
        }
        if quoted || !started {
            bail!("scheduled Task Scheduler arguments are malformed");
        }
        result.push(value);
        while characters
            .get(offset)
            .is_some_and(|character| character.is_whitespace())
        {
            offset += 1;
        }
    }
    if windows_arguments(&result)? != arguments {
        bail!("scheduled Task Scheduler arguments are not canonically quoted");
    }
    Ok(result)
}

fn valid_sid(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    parts.len() >= 4
        && parts.len() <= 18
        && parts[0] == "S"
        && parts[1] == "1"
        && parts[2]
            .parse::<u64>()
            .is_ok_and(|authority| authority <= 0x0000_ffff_ffff_ffff)
        && parts[3..]
            .iter()
            .all(|part| part.parse::<u64>().is_ok_and(|id| id <= u32::MAX.into()))
        && value.len() <= 184
}

fn task_xml(
    command: &str,
    arguments: &str,
    sid: &str,
    frequency: Frequency,
    enabled: bool,
) -> Result<String> {
    if !valid_sid(sid) || command.is_empty() {
        bail!("Task Scheduler identity or executable path is invalid");
    }
    let boundary = if matches!(frequency, Frequency::Weekly) {
        "2000-01-02T03:00:00"
    } else {
        "2000-01-01T03:00:00"
    };
    let recurrence: &str = match frequency {
        Frequency::Daily => "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>",
        Frequency::Weekly => {
            "<ScheduleByWeek><WeeksInterval>1</WeeksInterval><DaysOfWeek><Sunday/></DaysOfWeek></ScheduleByWeek>"
        }
    };
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Task version=\"1.2\" xmlns=\"{TASK_NAMESPACE}\"><RegistrationInfo><Author>Upkit</Author><URI>{TASK_URI}</URI><Description>{TASK_DESCRIPTION}</Description></RegistrationInfo><Triggers><CalendarTrigger><StartBoundary>{boundary}</StartBoundary><Enabled>true</Enabled>{recurrence}</CalendarTrigger></Triggers><Principals><Principal id=\"UpkitUser\"><UserId>{}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><StartWhenAvailable>false</StartWhenAvailable><Enabled>{}</Enabled><ExecutionTimeLimit>PT2H</ExecutionTimeLimit></Settings><Actions Context=\"UpkitUser\"><Exec><Command>{}</Command><Arguments>{}</Arguments></Exec></Actions></Task>\n",
        xml_escape(sid)?,
        enabled,
        xml_escape(command)?,
        xml_escape(arguments)?,
    );
    if xml.len() > TASK_XML_LIMIT {
        bail!("generated Task Scheduler XML exceeds the supported size limit");
    }
    Ok(xml)
}

fn scan_arguments(
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    scope_token: &str,
) -> Result<Vec<String>> {
    let mut arguments = vec![
        "--non-interactive".into(),
        "--offline".into(),
        "--json".into(),
        "--config".into(),
        "NUL".into(),
        "sweep".into(),
        "scan".into(),
        format!("--scope-token={scope_token}"),
    ];
    for path in exclusions {
        arguments.push(format!(
            "--exclude={}",
            path.to_str()
                .context("scheduled exclusion path must be UTF-8")?
        ));
    }
    arguments.push("--".into());
    for path in roots {
        arguments.push(
            path.to_str()
                .context("scheduled workspace path must be UTF-8")?
                .to_owned(),
        );
    }
    if arguments.iter().any(String::is_empty) {
        bail!("scheduled arguments contain a non-UTF-8 or empty path");
    }
    Ok(arguments)
}

#[cfg(target_os = "windows")]
fn scan_task_xml(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    scope_token: &str,
    sid: &str,
    frequency: Frequency,
    enabled: bool,
) -> Result<String> {
    let command = executable
        .to_str()
        .context("scheduled executable path must be UTF-8")?;
    let arguments = windows_arguments(&scan_arguments(roots, exclusions, scope_token)?)?;
    task_xml(command, &arguments, sid, frequency, enabled)
}

fn decode_task_xml(bytes: &[u8]) -> Result<String> {
    if bytes.len() > TASK_XML_LIMIT + 4 {
        bail!("Task Scheduler XML exceeds the supported size limit");
    }
    if let Some(bytes) = bytes.strip_prefix(&[0xff, 0xfe]) {
        let (pairs, remainder) = bytes.as_chunks::<2>();
        if !remainder.is_empty() {
            bail!("Task Scheduler returned truncated UTF-16 XML");
        }
        let units = pairs
            .iter()
            .map(|[low, high]| u16::from_le_bytes([*low, *high]))
            .collect::<Vec<_>>();
        return String::from_utf16(&units).context("decode Task Scheduler UTF-16 XML");
    }
    if let Some(bytes) = bytes.strip_prefix(&[0xfe, 0xff]) {
        let (pairs, remainder) = bytes.as_chunks::<2>();
        if !remainder.is_empty() {
            bail!("Task Scheduler returned truncated UTF-16 XML");
        }
        let units = pairs
            .iter()
            .map(|[high, low]| u16::from_be_bytes([*high, *low]))
            .collect::<Vec<_>>();
        return String::from_utf16(&units).context("decode Task Scheduler UTF-16 XML");
    }
    if bytes.len() >= 2
        && bytes
            .iter()
            .skip(1)
            .step_by(2)
            .filter(|byte| **byte == 0)
            .count()
            > bytes.len() / 4
    {
        let (pairs, remainder) = bytes.as_chunks::<2>();
        if !remainder.is_empty() {
            bail!("Task Scheduler returned truncated UTF-16 XML");
        }
        let units = pairs
            .iter()
            .map(|[low, high]| u16::from_le_bytes([*low, *high]))
            .collect::<Vec<_>>();
        return String::from_utf16(&units).context("decode Task Scheduler UTF-16 XML");
    }
    String::from_utf8(
        bytes
            .strip_prefix(&[0xef, 0xbb, 0xbf])
            .unwrap_or(bytes)
            .to_vec(),
    )
    .context("Task Scheduler XML is not UTF-8 or UTF-16")
}

fn node(name: &str, attributes: BTreeMap<String, String>) -> XmlNode {
    XmlNode {
        name: name.to_owned(),
        attributes,
        text: String::new(),
        children: Vec::new(),
    }
}

fn append_node(root: &mut Option<XmlNode>, stack: &mut [XmlNode], child: XmlNode) -> Result<()> {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(child);
    } else if root.replace(child).is_some() {
        bail!("Task Scheduler XML contains multiple root elements");
    }
    Ok(())
}

fn parse_xml(xml: &str) -> Result<XmlNode> {
    if xml.len() > TASK_XML_LIMIT {
        bail!("Task Scheduler XML exceeds the supported size limit");
    }
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut stack = Vec::<XmlNode>::new();
    let mut root = None;
    let mut declaration_seen = false;
    loop {
        match reader.read_event().context("parse Task Scheduler XML")? {
            quick_xml::events::Event::Decl(_) if !declaration_seen && root.is_none() => {
                declaration_seen = true;
            }
            quick_xml::events::Event::Start(element) => {
                let mut attributes = BTreeMap::new();
                for attribute in element.attributes().with_checks(true) {
                    let attribute = attribute.context("parse Task Scheduler XML attribute")?;
                    let name = attribute.key.as_ref().to_owned();
                    let value = attribute
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .context("decode Task Scheduler XML attribute")?
                        .into_owned();
                    if attributes.insert(name, value).is_some() {
                        bail!("Task Scheduler XML has a duplicate attribute");
                    }
                }
                stack.push(node(element.name().as_ref(), attributes));
                if stack.len() > 16 {
                    bail!("Task Scheduler XML nesting exceeds the supported depth");
                }
            }
            quick_xml::events::Event::Empty(element) => {
                let mut attributes = BTreeMap::new();
                for attribute in element.attributes().with_checks(true) {
                    let attribute = attribute.context("parse Task Scheduler XML attribute")?;
                    let name = attribute.key.as_ref().to_owned();
                    let value = attribute
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .context("decode Task Scheduler XML attribute")?
                        .into_owned();
                    if attributes.insert(name, value).is_some() {
                        bail!("Task Scheduler XML has a duplicate attribute");
                    }
                }
                append_node(
                    &mut root,
                    &mut stack,
                    node(element.name().as_ref(), attributes),
                )?;
            }
            quick_xml::events::Event::Text(text) => {
                let decoded = text.into_inner();
                if let Some(parent) = stack.last_mut() {
                    parent.text.push_str(&decoded);
                    if parent.text.len() > TASK_XML_LIMIT {
                        bail!("Task Scheduler XML text exceeds the supported size limit");
                    }
                } else if !decoded.trim().is_empty() {
                    bail!("unexpected text outside the Task Scheduler XML root");
                }
            }
            quick_xml::events::Event::End(end) => {
                let child = stack
                    .pop()
                    .context("unbalanced Task Scheduler XML element")?;
                if child.name.as_str() != end.name().as_ref() {
                    bail!("mismatched Task Scheduler XML element");
                }
                append_node(&mut root, &mut stack, child)?;
            }
            quick_xml::events::Event::Eof => break,
            quick_xml::events::Event::Comment(_)
            | quick_xml::events::Event::DocType(_)
            | quick_xml::events::Event::CData(_)
            | quick_xml::events::Event::PI(_) => {
                bail!("Task Scheduler XML contains an unsupported construct");
            }
            quick_xml::events::Event::GeneralRef(reference) => {
                let value = if let Some(character) = reference
                    .resolve_char_ref()
                    .context("decode Task Scheduler XML character reference")?
                {
                    character
                } else {
                    match reference.as_ref() {
                        "amp" => '&',
                        "lt" => '<',
                        "gt" => '>',
                        "quot" => '"',
                        "apos" => '\'',
                        _ => bail!("Task Scheduler XML has an unknown entity"),
                    }
                };
                let parent = stack
                    .last_mut()
                    .context("unexpected entity outside the Task Scheduler XML root")?;
                parent.text.push(value);
            }
            _ => bail!("Task Scheduler XML contains an unsupported construct"),
        }
    }
    if !stack.is_empty() {
        bail!("unclosed Task Scheduler XML element");
    }
    root.context("Task Scheduler XML has no root element")
}

fn exact_attributes(node: &XmlNode, expected: &[(&str, &str)]) -> Result<()> {
    if node.attributes.len() != expected.len()
        || expected
            .iter()
            .any(|(name, value)| node.attributes.get(*name).map(String::as_str) != Some(*value))
    {
        bail!("Task Scheduler XML attributes do not match Upkit's task format");
    }
    Ok(())
}

fn children_are(node: &XmlNode, expected: &[&str]) -> Result<()> {
    if node.children.len() != expected.len()
        || expected.iter().any(|name| {
            node.children
                .iter()
                .filter(|child| child.name == **name)
                .count()
                != 1
        })
    {
        bail!("Task Scheduler XML contains an unknown or duplicate element");
    }
    Ok(())
}

fn child<'a>(node: &'a XmlNode, name: &str) -> Result<&'a XmlNode> {
    let mut matches = node.children.iter().filter(|child| child.name == name);
    let found = matches
        .next()
        .with_context(|| format!("Task Scheduler XML is missing {name}"))?;
    if matches.next().is_some() {
        bail!("Task Scheduler XML contains duplicate {name}");
    }
    Ok(found)
}

fn text(node: &XmlNode, name: &str) -> Result<String> {
    let item = child(node, name)?;
    if !item.children.is_empty() || !item.attributes.is_empty() {
        bail!("Task Scheduler XML {name} is not a plain text value");
    }
    Ok(item.text.clone())
}

fn parse_task_xml(xml: &str) -> Result<TaskDefinition> {
    let root = parse_xml(xml)?;
    if root.name != "Task" {
        bail!("Task Scheduler returned a non-task XML root");
    }
    exact_attributes(&root, &[("version", "1.2"), ("xmlns", TASK_NAMESPACE)])?;
    children_are(
        &root,
        &[
            "RegistrationInfo",
            "Triggers",
            "Principals",
            "Settings",
            "Actions",
        ],
    )?;

    let registration = child(&root, "RegistrationInfo")?;
    if !registration.attributes.is_empty() {
        bail!("Task Scheduler registration attributes are unsupported");
    }
    if registration.children.iter().any(|item| {
        !matches!(
            item.name.as_str(),
            "Author" | "URI" | "Description" | "Date"
        )
    }) || !["Author", "URI", "Description"]
        .iter()
        .all(|name| registration.children.iter().any(|item| item.name == *name))
    {
        bail!("Task Scheduler registration metadata is not an Upkit task");
    }
    if text(registration, "Author")? != "Upkit"
        || text(registration, "URI")? != TASK_URI
        || text(registration, "Description")? != TASK_DESCRIPTION
    {
        bail!("Task Scheduler registration metadata is not an Upkit task");
    }
    if registration.children.iter().any(|item| item.name == "Date") {
        let date = text(registration, "Date")?;
        if date.len() > 64 || !date.contains('T') || date.chars().any(char::is_control) {
            bail!("Task Scheduler registration date is invalid");
        }
    }

    let triggers = child(&root, "Triggers")?;
    exact_attributes(triggers, &[])?;
    children_are(triggers, &["CalendarTrigger"])?;
    let trigger = child(triggers, "CalendarTrigger")?;
    exact_attributes(trigger, &[])?;
    let start = text(trigger, "StartBoundary")?;
    if text(trigger, "Enabled")? != "true" {
        bail!("Upkit schedule trigger must be enabled");
    }
    let schedule_by_day = trigger
        .children
        .iter()
        .any(|item| item.name == "ScheduleByDay");
    let schedule_by_week = trigger
        .children
        .iter()
        .any(|item| item.name == "ScheduleByWeek");
    let frequency = match (schedule_by_day, schedule_by_week, start.as_str()) {
        (true, false, "2000-01-01T03:00:00") => {
            children_are(trigger, &["StartBoundary", "Enabled", "ScheduleByDay"])?;
            let daily = child(trigger, "ScheduleByDay")?;
            exact_attributes(daily, &[])?;
            children_are(daily, &["DaysInterval"])?;
            if text(daily, "DaysInterval")? != "1" {
                bail!("Upkit daily schedule interval changed");
            }
            Frequency::Daily
        }
        (false, true, "2000-01-02T03:00:00") => {
            children_are(trigger, &["StartBoundary", "Enabled", "ScheduleByWeek"])?;
            let weekly = child(trigger, "ScheduleByWeek")?;
            exact_attributes(weekly, &[])?;
            children_are(weekly, &["WeeksInterval", "DaysOfWeek"])?;
            if text(weekly, "WeeksInterval")? != "1" {
                bail!("Upkit weekly schedule interval changed");
            }
            let days = child(weekly, "DaysOfWeek")?;
            exact_attributes(days, &[])?;
            children_are(days, &["Sunday"])?;
            exact_attributes(child(days, "Sunday")?, &[])?;
            Frequency::Weekly
        }
        _ => bail!("Task Scheduler trigger does not match an Upkit schedule"),
    };

    let principals = child(&root, "Principals")?;
    exact_attributes(principals, &[])?;
    children_are(principals, &["Principal"])?;
    let principal = child(principals, "Principal")?;
    exact_attributes(principal, &[("id", "UpkitUser")])?;
    children_are(principal, &["UserId", "LogonType", "RunLevel"])?;
    let sid = text(principal, "UserId")?;
    if !valid_sid(&sid)
        || text(principal, "LogonType")? != "InteractiveToken"
        || text(principal, "RunLevel")? != "LeastPrivilege"
    {
        bail!("Task Scheduler principal is not the current least-privilege interactive user");
    }

    let settings = child(&root, "Settings")?;
    exact_attributes(settings, &[])?;
    children_are(
        settings,
        &[
            "MultipleInstancesPolicy",
            "StartWhenAvailable",
            "Enabled",
            "ExecutionTimeLimit",
        ],
    )?;
    if text(settings, "MultipleInstancesPolicy")? != "IgnoreNew"
        || text(settings, "StartWhenAvailable")? != "false"
        || text(settings, "ExecutionTimeLimit")? != "PT2H"
    {
        bail!("Task Scheduler settings differ from Upkit's safe scan settings");
    }
    let enabled = match text(settings, "Enabled")?.as_str() {
        "true" => true,
        "false" => false,
        _ => bail!("Task Scheduler enabled state is invalid"),
    };

    let actions = child(&root, "Actions")?;
    exact_attributes(actions, &[("Context", "UpkitUser")])?;
    children_are(actions, &["Exec"])?;
    let exec = child(actions, "Exec")?;
    exact_attributes(exec, &[])?;
    if exec
        .children
        .iter()
        .any(|item| !matches!(item.name.as_str(), "Command" | "Arguments"))
    {
        bail!("Task Scheduler action contains unsupported elements");
    }
    children_are(exec, &["Command", "Arguments"])?;
    let command = text(exec, "Command")?;
    let arguments = text(exec, "Arguments")?;
    if command.is_empty() || arguments.is_empty() || arguments.len() > TASK_ARGUMENT_LIMIT {
        bail!("Task Scheduler scan action is invalid");
    }
    Ok(TaskDefinition {
        sid,
        frequency,
        enabled,
        command,
        arguments,
    })
}

#[cfg(target_os = "windows")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    volume: u32,
    index: u64,
    created: u64,
    modified: u64,
    size: u64,
}

#[cfg(target_os = "windows")]
fn handle_identity(file: &std::fs::File, directory: bool) -> Result<FileIdentity> {
    use std::os::windows::fs::MetadataExt;
    const REPARSE: u32 = 0x400;

    let metadata = file.metadata()?;
    if metadata.file_attributes() & REPARSE != 0
        || metadata.is_dir() != directory
        || metadata.is_file() == directory
    {
        bail!("scheduled path has an unexpected type or is a reparse point");
    }
    let information = winapi_util::file::information(file)?;
    let created = information
        .creation_time()
        .context("scheduled path lacks creation identity")?;
    let modified = if directory {
        0
    } else {
        information
            .last_write_time()
            .context("scheduled file lacks modification identity")?
    };
    Ok(FileIdentity {
        volume: u32::try_from(information.volume_serial_number())
            .context("scheduled path volume identity is invalid")?,
        index: information.file_index(),
        created,
        modified,
        size: if directory {
            0
        } else {
            information.file_size()
        },
    })
}

#[cfg(target_os = "windows")]
fn reject_reparse_components(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    const REPARSE: u32 = 0x400;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component);
        if let Ok(metadata) = std::fs::symlink_metadata(&current)
            && metadata.file_attributes() & REPARSE != 0
        {
            bail!("scheduled paths cannot contain Windows reparse points");
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn normalized_path(path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("canonicalize scheduled path {}", path.display()))?;
    let value = canonical.to_string_lossy();
    let value = if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(drive) = value.strip_prefix(r"\\?\") {
        drive.to_owned()
    } else {
        value.into_owned()
    };
    Ok(PathBuf::from(value))
}

#[cfg(target_os = "windows")]
fn comparable_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

#[cfg(target_os = "windows")]
fn file_identity(path: &Path, directory: bool) -> Result<FileIdentity> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const REPARSE: u32 = 0x400;
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const SHARE_ALL: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;

    if !path.is_absolute() || comparable_path(&normalized_path(path)?) != comparable_path(path) {
        bail!("scheduled paths must be canonical absolute Windows paths");
    }
    reject_reparse_components(path)?;
    let expected = std::fs::symlink_metadata(path).context("inspect scheduled path")?;
    if expected.file_attributes() & REPARSE != 0
        || expected.is_dir() != directory
        || expected.is_file() == directory
    {
        bail!("scheduled path has an unexpected type or is a reparse point");
    }
    let open = || {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .share_mode(SHARE_ALL)
            .custom_flags(OPEN_REPARSE_POINT | if directory { BACKUP_SEMANTICS } else { 0 });
        options.open(path)
    };
    let file = open().context("open scheduled path without following links")?;
    let identity = handle_identity(&file, directory)?;
    let rechecked = open().context("reopen scheduled path to verify its identity")?;
    if rechecked.metadata()?.file_attributes() & REPARSE != 0
        || handle_identity(&rechecked, directory)? != identity
    {
        bail!("scheduled path changed while its identity was inspected");
    }
    Ok(identity)
}

#[cfg(target_os = "windows")]
pub(super) fn scheduled_scope_token(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    let mut add = |bytes: &[u8]| {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    };
    add(b"upkit-scheduled-scan-scope-windows-v1\0");
    add(&(roots.len() as u64).to_be_bytes());
    for (path, directory) in
        std::iter::once((executable, false)).chain(roots.iter().map(|root| (root.as_path(), true)))
    {
        if !path.is_absolute() {
            bail!("scheduled executable and roots must be absolute paths");
        }
        let identity = file_identity(path, directory)?;
        add(path.as_os_str().as_encoded_bytes());
        add(&identity.volume.to_le_bytes());
        add(&identity.index.to_le_bytes());
        add(&identity.created.to_le_bytes());
        if !directory {
            add(&identity.modified.to_le_bytes());
            add(&identity.size.to_le_bytes());
        }
    }
    add(&(exclusions.len() as u64).to_be_bytes());
    for exclusion in exclusions {
        if exclusion.as_os_str().is_empty() || exclusion.to_str().is_none() {
            bail!("scheduled exclusions must be nonempty UTF-8 paths");
        }
        add(exclusion.as_os_str().as_encoded_bytes());
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(target_os = "windows")]
pub(super) fn preview_scan(
    executable: &Path,
    roots: &[PathBuf],
    exclusions: &[PathBuf],
    frequency: Frequency,
    policy: Option<ScheduledScanPolicy>,
) -> Result<ScanSchedulePreview> {
    use sha2::{Digest, Sha256};
    if roots.is_empty() {
        bail!("select at least one workspace root");
    }
    if policy.as_ref().is_some_and(|policy| {
        policy.scheduled_bytecode_cleanup || policy.scheduled_artifact_cleanup
    }) {
        bail!("Windows schedules support read-only scans only");
    }
    for root in roots {
        reject_reparse_components(root)?;
    }
    let roots = roots
        .iter()
        .map(|root| normalized_path(root))
        .collect::<Result<Vec<_>>>()?;
    let settings = crate::config::Settings {
        workspace_roots: roots.clone(),
        exclusions: exclusions.to_vec(),
        ..Default::default()
    };
    settings.validate()?;
    let executable = normalized_path(executable)?;
    let scope = scheduled_scope_token(&executable, &roots, &settings.exclusions)?;
    let scheduled_scope_token = if let Some(policy) = policy {
        let token = super::policy_token(scope, policy.clone())?;
        super::verify_configured_source(&policy, &roots, &settings.exclusions)?;
        token
    } else {
        scope
    };
    let sid = current_user_sid()?;
    let service_unit = scan_task_xml(
        &executable,
        &roots,
        &settings.exclusions,
        &scheduled_scope_token,
        &sid,
        frequency,
        true,
    )?;
    let mut hash = Sha256::new();
    hash.update(b"upkit-windows-scan-preview-v1\0");
    hash.update(TASK_PATH.as_bytes());
    hash.update(sid.as_bytes());
    hash.update(scheduled_scope_token.as_bytes());
    hash.update(service_unit.as_bytes());
    Ok(ScanSchedulePreview {
        roots,
        exclusions: settings.exclusions,
        frequency: match frequency {
            Frequency::Daily => "daily",
            Frequency::Weekly => "weekly",
        },
        unit_directory: PathBuf::from(TASK_PATH),
        preview_token: hex::encode(hash.finalize()),
        scheduled_scope_token,
        service_unit,
        timer_unit: String::new(),
        warning: "Preview only; no task is registered. After explicit confirmation, the current Windows user receives one Task Scheduler job with InteractiveToken and LeastPrivilege. It runs only a read-only scan of these roots at 03:00 local time; Windows retention cleanup is not scheduled. Root and executable identities are checked before management and reparse-point roots are rejected, but another process can still change paths after validation or during a scan. A task at the fixed path must match Upkit metadata, current SID, exact scan arguments, XML structure, and state before Upkit can change it.",
    })
}

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TaskSnapshot {
    present: bool,
    #[serde(rename = "taskPath")]
    task_path: Option<String>,
    state: u8,
    enabled: bool,
    #[serde(rename = "lastRun")]
    last_run: Option<String>,
    #[serde(rename = "nextRun")]
    next_run: Option<String>,
    #[serde(rename = "securityOwner")]
    security_owner: Option<String>,
    #[serde(rename = "securityDescriptor")]
    security_descriptor: Option<String>,
    #[serde(rename = "securitySafe")]
    security_safe: bool,
}

#[cfg(any(target_os = "windows", test))]
fn validate_snapshot(
    snapshot: &TaskSnapshot,
    current_sid: &str,
    definition: &TaskDefinition,
) -> Result<()> {
    if !snapshot.present
        || snapshot.task_path.as_deref() != Some(TASK_PATH)
        || !valid_sid(current_sid)
        || definition.sid != current_sid
        || snapshot.security_owner.as_deref() != Some(current_sid)
        || snapshot
            .security_descriptor
            .as_deref()
            .is_none_or(str::is_empty)
        || !snapshot.security_safe
        || snapshot.enabled != definition.enabled
        || (snapshot.enabled && !matches!(snapshot.state, 2..=4))
        || (!snapshot.enabled && snapshot.state != 1)
    {
        bail!("Task Scheduler task identity or state does not match the reviewed Upkit task");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn parse_scan_scope(arguments: &str) -> Result<(Vec<PathBuf>, Vec<PathBuf>, String)> {
    let args = parse_windows_arguments(arguments)?;
    let prefix = [
        "--non-interactive",
        "--offline",
        "--json",
        "--config",
        "NUL",
        "sweep",
        "scan",
    ];
    if args.len() < prefix.len() + 3 || args[..prefix.len()].iter().map(String::as_str).ne(prefix) {
        bail!("Task Scheduler action is not a read-only Upkit scan");
    }
    let scope = args[prefix.len()]
        .strip_prefix("--scope-token=")
        .filter(|token| token.len() >= 64 && token.len() <= 24_644)
        .context("Task Scheduler scan scope token is missing")?
        .to_owned();
    let mut exclusions = Vec::new();
    let mut offset = prefix.len() + 1;
    while let Some(value) = args.get(offset) {
        if value == "--" {
            break;
        }
        let pattern = value
            .strip_prefix("--exclude=")
            .filter(|pattern| !pattern.is_empty())
            .context("Task Scheduler scan has an unsupported argument")?;
        exclusions.push(PathBuf::from(pattern));
        offset += 1;
    }
    if args.get(offset).map(String::as_str) != Some("--") {
        bail!("Task Scheduler scan roots are missing");
    }
    offset += 1;
    let roots = args[offset..].iter().map(PathBuf::from).collect::<Vec<_>>();
    if roots.is_empty() || roots.iter().any(|root| !root.is_absolute()) {
        bail!("Task Scheduler scan roots are not absolute");
    }
    Ok((roots, exclusions, scope))
}

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Debug)]
struct ExistingTask {
    sid: String,
    snapshot: TaskSnapshot,
    definition: TaskDefinition,
    canonical_xml: String,
}

#[cfg(target_os = "windows")]
const TASK_ACL_FUNCTION: &str = r#"
function Test-UpkitTaskAcl([string]$sddl, [string]$sid) {
    try {
        $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl)
        if ((([int]$descriptor.ControlFlags -band 4) -eq 0) -or
            ($null -eq $descriptor.DiscretionaryAcl) -or
            ($null -eq $descriptor.Owner) -or
            ($descriptor.Owner.Value -ne $sid)) { return $false }
        $trusted = @($sid, 'S-1-5-18', 'S-1-5-32-544')
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            if (($ace -isnot [System.Security.AccessControl.CommonAce]) -or $ace.IsCallback) { return $false }
            if ($ace.AceQualifier -notin @([System.Security.AccessControl.AceQualifier]::AccessAllowed, [System.Security.AccessControl.AceQualifier]::AccessDenied)) { return $false }
            if (($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed) -and
                ($ace.SecurityIdentifier.Value -notin $trusted) -and ($ace.AccessMask -ne 0)) { return $false }
        }
        return $true
    } catch { return $false }
}
"#;

#[cfg(target_os = "windows")]
const TASK_LOOKUP_FUNCTION: &str = r#"
function Get-UpkitTask($folder) {
    try { return $folder.GetTask('Upkit-Workspace-Scan') }
    catch {
        $exception = $_.Exception
        while ($null -ne $exception) {
            if ($exception.HResult -eq -2147024894) { return $null }
            $exception = $exception.InnerException
        }
        throw
    }
}
"#;

#[cfg(target_os = "windows")]
const TASK_SNAPSHOT_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
    $sid = $env:UPKIT_TASK_SID
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = $service.GetFolder('\')
    $task = Get-UpkitTask $folder
    if ($null -eq $task) {
        $value = @{present=$false;taskPath=$null;state=0;enabled=$false;lastRun=$null;nextRun=$null;securityOwner=$null;securityDescriptor=$null;securitySafe=$false}
    } else {
        $last = $null
        $next = $null
        if ($task.LastRunTime.Year -gt 1900) { $last = $task.LastRunTime.ToString('o') }
        if ($task.NextRunTime.Year -gt 1900) { $next = $task.NextRunTime.ToString('o') }
        $sddl = $task.GetSecurityDescriptor(7)
        $security = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl)
        $owner = if ($null -eq $security.Owner) { $null } else { $security.Owner.Value }
        $value = @{present=$true;taskPath=$task.Path;state=[int]$task.State;enabled=[bool]$task.Enabled;lastRun=$last;nextRun=$next;securityOwner=$owner;securityDescriptor=$sddl;securitySafe=(Test-UpkitTaskAcl $sddl $sid)}
    }
} catch {
    [Console]::Error.WriteLine('Task Scheduler query failed')
    exit 2
}
[Console]::Out.Write((ConvertTo-Json -InputObject $value -Compress))
"#;

#[cfg(target_os = "windows")]
fn system_binary(name: &str) -> Result<PathBuf> {
    let directory = known_folders::get_known_folder_path(known_folders::KnownFolder::System)
        .context("cannot determine the Windows system directory")?;
    if !directory.is_absolute()
        || Path::new(name)
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("Windows returned an invalid system directory or utility name");
    }
    let path = directory.join(name);
    file_identity(&path, false).context("verify Windows system executable")?;
    normalized_path(&path)
}

#[cfg(target_os = "windows")]
fn run_command(
    mut command: std::process::Command,
    input: Option<&[u8]>,
    limit: usize,
) -> Result<Vec<u8>> {
    use std::{
        io::{Read, Write},
        process::Stdio,
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };
    let mut child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("start Windows Task Scheduler utility")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let input_result = if let Some(input) = input {
        let mut stdin = child.stdin.take().context("open Task Scheduler input")?;
        let input = input.to_vec();
        let (send, receive) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let result = stdin.write_all(&input);
            let _ = send.send(result);
        });
        Some(receive)
    } else {
        None
    };
    let mut stdout = child
        .stdout
        .take()
        .context("capture Task Scheduler output")?;
    let (send, receive) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut data = Vec::new();
        let result = stdout
            .by_ref()
            .take(limit as u64 + 1)
            .read_to_end(&mut data);
        let _ = send.send((result, data));
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "Windows Task Scheduler utility timed out; its outcome is unknown, inspect the task before retrying"
                );
            }
        }
    };
    if let Some(input_result) = input_result {
        input_result
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .context("Task Scheduler input timed out; its outcome is unknown, inspect the task before retrying")?
            .context("Task Scheduler input failed; its outcome is unknown, inspect the task before retrying")?;
    }
    let (read, data) = receive
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .context("Task Scheduler output timed out; its outcome is unknown, inspect the task before retrying")?;
    read.context("read Task Scheduler output")?;
    if data.len() > limit {
        bail!("Task Scheduler output exceeded its size limit");
    }
    if !status.success() {
        bail!(
            "Windows Task Scheduler utility failed; its outcome is unknown, inspect the task before retrying"
        );
    }
    Ok(data)
}

#[cfg(any(target_os = "windows", test))]
static TASK_QUERY_READER_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(any(target_os = "windows", test))]
struct TaskQueryReaderGuard;

#[cfg(any(target_os = "windows", test))]
impl TaskQueryReaderGuard {
    fn acquire() -> Result<Self> {
        TASK_QUERY_READER_ACTIVE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| anyhow::anyhow!("a prior Task Scheduler output reader is still active"))
    }
}

#[cfg(any(target_os = "windows", test))]
impl Drop for TaskQueryReaderGuard {
    fn drop(&mut self) {
        TASK_QUERY_READER_ACTIVE.store(false, Ordering::Release);
    }
}

#[cfg(any(target_os = "windows", test))]
fn query_command_output(
    mut command: std::process::Command,
    limit: usize,
    cancel: &AtomicBool,
) -> Result<Vec<u8>> {
    use std::{
        io::Read,
        process::Stdio,
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    if cancel.load(Ordering::Relaxed) {
        bail!("Task Scheduler query cancelled; task state remains unknown");
    }
    let reader_guard = TaskQueryReaderGuard::acquire()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("start Windows Task Scheduler query")?;
    let mut stdout = child
        .stdout
        .take()
        .context("capture Task Scheduler query output")?;
    let (send, receive) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut data = Vec::new();
        let result = stdout
            .by_ref()
            .take(limit as u64 + 1)
            .read_to_end(&mut data);
        drop(reader_guard);
        let _ = send.send((result, data));
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut captured = None;
    let status = loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = receive.recv_timeout(Duration::from_millis(50));
            bail!("Task Scheduler query cancelled; task state remains unknown");
        }
        if captured.is_none() {
            match receive.try_recv() {
                Ok((read, data)) => {
                    if let Err(error) = read {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(error).context("read Task Scheduler output");
                    }
                    if data.len() > limit {
                        let _ = child.kill();
                        let _ = child.wait();
                        bail!("Task Scheduler output exceeded its size limit");
                    }
                    captured = Some(data);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!("Task Scheduler output reader failed; task state remains unknown");
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = receive.recv_timeout(Duration::from_millis(50));
                bail!("Task Scheduler query timed out; task state remains unknown");
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = receive.recv_timeout(Duration::from_millis(50));
                return Err(error).context("wait for Task Scheduler query");
            }
        }
    };
    if !status.success() {
        bail!("Task Scheduler query failed; task state remains unknown");
    }
    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = receive.recv_timeout(Duration::from_millis(50));
            bail!("Task Scheduler query cancelled; task state remains unknown");
        }
        if let Some(data) = captured.take() {
            return Ok(data);
        }
        match receive.recv_timeout(Duration::from_millis(10)) {
            Ok((read, data)) => {
                read.context("read Task Scheduler output")?;
                if data.len() > limit {
                    bail!("Task Scheduler output exceeded its size limit");
                }
                return Ok(data);
            }
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {
                bail!("Task Scheduler output timed out; task state remains unknown");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("Task Scheduler output reader failed; task state remains unknown");
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn command_output(program: &Path, args: &[&str], limit: usize) -> Result<Vec<u8>> {
    let mut command = std::process::Command::new(program);
    command.args(args);
    run_command(command, None, limit)
}

#[cfg(any(target_os = "windows", test))]
fn parse_whoami_sid(output: &[u8]) -> Result<String> {
    let line = output
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .find(|line| !line.iter().all(u8::is_ascii_whitespace))
        .context("whoami returned no current-user identity")?;
    if output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .count()
        != 1
    {
        bail!("whoami returned an ambiguous identity record");
    }
    let mut quoted = false;
    let mut comma = None;
    let mut offset = 0;
    while offset < line.len() {
        match line[offset] {
            b'"' if quoted && line.get(offset + 1) == Some(&b'"') => offset += 1,
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                comma = Some(offset);
                break;
            }
            _ => {}
        }
        offset += 1;
    }
    let sid = line
        .get(comma.context("whoami output is not CSV")? + 1..)
        .context("whoami output is truncated")?
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let sid = sid.strip_prefix(b"\"").unwrap_or(&sid);
    let sid = sid.strip_suffix(b"\"").unwrap_or(sid);
    let sid = std::str::from_utf8(sid).context("whoami SID is not ASCII")?;
    if !valid_sid(sid) {
        bail!("whoami returned an invalid current-user SID");
    }
    Ok(sid.to_owned())
}

#[cfg(target_os = "windows")]
fn current_user_sid() -> Result<String> {
    let whoami = system_binary("whoami.exe")?;
    let output = command_output(&whoami, &["/user", "/fo", "csv", "/nh"], 4096)?;
    parse_whoami_sid(&output)
}

#[cfg(target_os = "windows")]
fn current_user_sid_with_cancel(cancel: &AtomicBool) -> Result<String> {
    let whoami = system_binary("whoami.exe")?;
    let mut command = std::process::Command::new(&whoami);
    command.args(["/user", "/fo", "csv", "/nh"]);
    let output = query_command_output(command, 4096, cancel)?;
    parse_whoami_sid(&output)
}

#[cfg(target_os = "windows")]
fn manager_snapshot(sid: &str) -> Result<TaskSnapshot> {
    let powershell = system_binary("WindowsPowerShell\\v1.0\\powershell.exe")?;
    let script = task_powershell_script(TASK_SNAPSHOT_SCRIPT);
    let mut command = std::process::Command::new(&powershell);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ])
        .env("UPKIT_TASK_SID", sid);
    let output = run_command(command, None, 16_384)?;
    parse_task_snapshot(&output)
}

#[cfg(target_os = "windows")]
fn manager_snapshot_with_cancel(sid: &str, cancel: &AtomicBool) -> Result<TaskSnapshot> {
    let powershell = system_binary("WindowsPowerShell\\v1.0\\powershell.exe")?;
    let script = task_powershell_script(TASK_SNAPSHOT_SCRIPT);
    let mut command = std::process::Command::new(&powershell);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ])
        .env("UPKIT_TASK_SID", sid);
    let output = query_command_output(command, 16_384, cancel)?;
    parse_task_snapshot(&output)
}

#[cfg(target_os = "windows")]
fn parse_task_snapshot(output: &[u8]) -> Result<TaskSnapshot> {
    let text = std::str::from_utf8(output).context("Task Scheduler status is not UTF-8")?;
    let snapshot: TaskSnapshot =
        serde_json::from_str(text).context("parse Task Scheduler status")?;
    if (!snapshot.present
        && (snapshot.task_path.is_some()
            || snapshot.state != 0
            || snapshot.enabled
            || snapshot.security_owner.is_some()
            || snapshot.security_descriptor.is_some()
            || snapshot.security_safe))
        || (snapshot.present
            && (snapshot.task_path.as_deref() != Some(TASK_PATH)
                || !(1..=4).contains(&snapshot.state)
                || snapshot
                    .security_descriptor
                    .as_deref()
                    .is_none_or(str::is_empty)
                || snapshot
                    .security_descriptor
                    .as_ref()
                    .is_some_and(|sddl| sddl.len() > 4096)))
    {
        bail!("Task Scheduler returned an inconsistent task status");
    }
    Ok(snapshot)
}

#[cfg(any(target_os = "windows", test))]
fn validate_snapshot_stable(before: &TaskSnapshot, after: &TaskSnapshot) -> Result<()> {
    if before != after {
        bail!("Task Scheduler task state changed while it was inspected");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn query_task_xml() -> Result<String> {
    let schtasks = system_binary("schtasks.exe")?;
    let output = command_output(
        &schtasks,
        &["/query", "/tn", TASK_PATH, "/xml"],
        TASK_XML_LIMIT + 4,
    )?;
    decode_task_xml(&output)
}

#[cfg(target_os = "windows")]
fn query_task_xml_with_cancel(cancel: &AtomicBool) -> Result<String> {
    let schtasks = system_binary("schtasks.exe")?;
    let mut command = std::process::Command::new(&schtasks);
    command.args(["/query", "/tn", TASK_PATH, "/xml"]);
    let output = query_command_output(command, TASK_XML_LIMIT + 4, cancel)?;
    decode_task_xml(&output)
}

#[cfg(target_os = "windows")]
fn verify_task_scope(definition: &TaskDefinition) -> Result<()> {
    let (roots, exclusions, token) = parse_scan_scope(&definition.arguments)?;
    let policy = super::policy_from_token(&token)?;
    if policy.as_ref().is_some_and(|policy| {
        policy.scheduled_bytecode_cleanup || policy.scheduled_artifact_cleanup
    }) {
        bail!("Windows only supports read-only scheduled scans");
    }
    let expected_scope = policy
        .as_ref()
        .map_or(token.as_str(), |policy| policy.scope_token.as_str());
    let actual = scheduled_scope_token(Path::new(&definition.command), &roots, &exclusions)?;
    if actual != expected_scope {
        bail!("Task Scheduler scan scope or executable identity changed");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn validate_existing_task(snapshot: TaskSnapshot, sid: &str, xml: &str) -> Result<ExistingTask> {
    let definition = parse_task_xml(xml)?;
    validate_snapshot(&snapshot, sid, &definition)?;
    file_identity(Path::new(&definition.command), false)
        .context("verify scheduled Upkit executable identity")?;
    verify_task_scope(&definition)?;
    let canonical_xml = task_xml(
        &definition.command,
        &definition.arguments,
        &definition.sid,
        definition.frequency,
        definition.enabled,
    )?;
    Ok(ExistingTask {
        sid: sid.to_owned(),
        snapshot,
        definition,
        canonical_xml,
    })
}

#[cfg(target_os = "windows")]
fn read_existing_task() -> Result<Option<ExistingTask>> {
    let sid = current_user_sid()?;
    let before = manager_snapshot(&sid)?;
    if !before.present {
        return Ok(None);
    }
    if before.task_path.as_deref() != Some(TASK_PATH) {
        bail!("Task Scheduler path does not match the Upkit task path");
    }
    let xml = query_task_xml()?;
    let after = manager_snapshot(&sid)?;
    validate_snapshot_stable(&before, &after)?;
    validate_existing_task(after, &sid, &xml).map(Some)
}

#[cfg(target_os = "windows")]
fn read_existing_task_with_cancel(cancel: &AtomicBool) -> Result<Option<ExistingTask>> {
    let sid = current_user_sid_with_cancel(cancel)?;
    let before = manager_snapshot_with_cancel(&sid, cancel)?;
    if !before.present {
        return Ok(None);
    }
    if before.task_path.as_deref() != Some(TASK_PATH) {
        bail!("Task Scheduler path does not match the Upkit task path");
    }
    let xml = query_task_xml_with_cancel(cancel)?;
    let after = manager_snapshot_with_cancel(&sid, cancel)?;
    validate_snapshot_stable(&before, &after)?;
    validate_existing_task(after, &sid, &xml).map(Some)
}

#[cfg(any(target_os = "windows", test))]
fn task_state_label(snapshot: &TaskSnapshot) -> &'static str {
    match snapshot.state {
        1 => "disabled",
        2 => "queued",
        3 => "ready",
        4 => "running",
        _ => "unavailable",
    }
}

#[cfg(target_os = "windows")]
pub(super) fn status() -> crate::maintenance::TimerStatus {
    status_from_result(read_existing_task())
}

#[cfg(any(target_os = "windows", test))]
fn status_with_query(
    cancel: &AtomicBool,
    query: impl FnOnce(&AtomicBool) -> Result<Option<ExistingTask>>,
) -> crate::maintenance::TimerStatus {
    let cancelled = || crate::maintenance::TimerStatus {
        state: "unavailable".into(),
        load_state: None,
        unit_file_state: None,
        last_trigger: None,
        next_trigger: None,
        detail: Some("Task Scheduler query was cancelled; task state remains unknown".into()),
    };
    if cancel.load(Ordering::Relaxed) {
        return cancelled();
    }
    let result = query(cancel);
    if cancel.load(Ordering::Relaxed) {
        return cancelled();
    }
    status_from_result(result)
}

#[cfg(target_os = "windows")]
pub(super) fn status_with_cancel(cancel: &AtomicBool) -> crate::maintenance::TimerStatus {
    status_with_query(cancel, read_existing_task_with_cancel)
}

#[cfg(any(target_os = "windows", test))]
fn status_from_result(existing: Result<Option<ExistingTask>>) -> crate::maintenance::TimerStatus {
    let unavailable = |detail: &'static str| crate::maintenance::TimerStatus {
        state: "unavailable".into(),
        load_state: None,
        unit_file_state: None,
        last_trigger: None,
        next_trigger: None,
        detail: Some(detail.into()),
    };
    let existing = match existing {
        Ok(existing) => existing,
        Err(_) => {
            return unavailable(
                "Task Scheduler state or Upkit task identity could not be verified",
            );
        }
    };
    let Some(existing) = existing else {
        return crate::maintenance::TimerStatus {
            state: "not_found".into(),
            load_state: Some("not-found".into()),
            unit_file_state: None,
            last_trigger: None,
            next_trigger: None,
            detail: Some("No task is registered at the Upkit scan path".into()),
        };
    };
    let enabled = existing.definition.enabled;
    let state = task_state_label(&existing.snapshot);
    crate::maintenance::TimerStatus {
        state: state.into(),
        load_state: Some("registered".into()),
        unit_file_state: Some(if enabled { "enabled" } else { "disabled" }.into()),
        last_trigger: existing.snapshot.last_run,
        next_trigger: existing.snapshot.next_run,
        detail: Some("Verified Task Scheduler path, task owner and access rights, current-user SID, least-privilege principal, and read-only scan action".into()),
    }
}

#[cfg(target_os = "windows")]
pub(super) fn preview_disable() -> Result<DisableSchedulePreview> {
    let existing = read_existing_task()?.context("no task exists at the Upkit scan path")?;
    disable_preview_from_existing(&existing)
}

#[cfg(any(target_os = "windows", test))]
fn disable_preview_from_existing(existing: &ExistingTask) -> Result<DisableSchedulePreview> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"upkit-windows-scan-disable-preview-v1\0");
    hash.update(TASK_PATH.as_bytes());
    hash.update(existing.sid.as_bytes());
    hash.update([
        existing.snapshot.state,
        u8::from(existing.definition.enabled),
    ]);
    hash.update(existing.canonical_xml.as_bytes());
    hash.update(
        existing
            .snapshot
            .security_descriptor
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    hash.update(
        existing
            .snapshot
            .last_run
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    hash.update(
        existing
            .snapshot
            .next_run
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    Ok(DisableSchedulePreview {
        unit_directory: PathBuf::from(TASK_PATH),
        service_unit: existing.canonical_xml.clone(),
        timer_unit: String::new(),
        active_state: task_state_label(&existing.snapshot).into(),
        unit_file_state: Some(
            if existing.definition.enabled {
                "enabled"
            } else {
                "disabled"
            }
            .into(),
        ),
        preview_token: hex::encode(hash.finalize()),
        warning: "Disables only the verified Upkit scan task for the current Windows user. Upkit refuses the change while the task is queued or running and rechecks the complete task snapshot immediately before disabling; Task Scheduler can still change its state after that check and before the command takes effect.",
    })
}

#[cfg(target_os = "windows")]
const TASK_ACL_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$sid = $env:UPKIT_TASK_SID
$acl = Get-Acl -LiteralPath $env:UPKIT_TASK_ACL_PATH
$sections = [System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner
$sddl = $acl.GetSecurityDescriptorSddlForm($sections)
if (-not (Test-UpkitTaskAcl $sddl $sid)) { exit 4 }
[Console]::Out.Write('OK')
"#;

#[cfg(target_os = "windows")]
fn task_powershell_script(body: &str) -> String {
    format!("{TASK_ACL_FUNCTION}\n{TASK_LOOKUP_FUNCTION}\n{body}")
}

#[cfg(target_os = "windows")]
fn verify_private_acl(path: &Path, sid: &str, powershell: &Path) -> Result<()> {
    let script = task_powershell_script(TASK_ACL_SCRIPT);
    let mut command = std::process::Command::new(powershell);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ])
        .env("UPKIT_TASK_ACL_PATH", path)
        .env("UPKIT_TASK_SID", sid);
    let output = run_command(command, None, 4096)?;
    if output != b"OK" {
        bail!(
            "Task Scheduler XML path ACL is not private to the current user and Windows administrators"
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn with_safe_task_xml<T>(
    directory: &Path,
    xml: &str,
    sid: &str,
    powershell: &Path,
    use_file: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    use std::{
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
    };
    const REPARSE: u32 = 0x400;
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const SHARE_READ: u32 = 0x0000_0001;
    let directory_identity = file_identity(directory, true)?;
    verify_private_acl(directory, sid, powershell)?;
    let mut temp = tempfile::NamedTempFile::new_in(directory)
        .context("create private Task Scheduler XML file")?;
    temp.write_all(xml.as_bytes())?;
    temp.as_file().sync_all()?;
    let original = temp.as_file().metadata()?;
    if original.file_attributes() & REPARSE != 0 {
        bail!("Task Scheduler XML file is a reparse point");
    }
    let original_identity = handle_identity(temp.as_file(), false)?;
    let temp_path = temp.into_temp_path();
    let mut lock = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(SHARE_READ)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(&temp_path)
        .context("lock Task Scheduler XML against replacement")?;
    let locked_identity = file_identity(&temp_path, false)?;
    if locked_identity != original_identity {
        bail!("Task Scheduler XML file changed while it was locked");
    }
    let mut bytes = Vec::new();
    (&mut lock)
        .take(TASK_XML_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > TASK_XML_LIMIT || bytes != xml.as_bytes() {
        bail!("Task Scheduler XML file changed before registration");
    }
    verify_private_acl(&temp_path, sid, powershell)?;
    if file_identity(directory, true)? != directory_identity
        || file_identity(&temp_path, false)? != original_identity
    {
        bail!("Task Scheduler XML directory or file identity changed before registration");
    }
    let result = use_file(&temp_path)?;
    if file_identity(directory, true)? != directory_identity
        || file_identity(&temp_path, false)? != original_identity
    {
        bail!("Task Scheduler XML directory or file changed during registration");
    }
    drop(lock);
    drop(temp_path);
    Ok(result)
}

#[cfg(target_os = "windows")]
fn register_task(xml: &str, sid: &str) -> Result<()> {
    let schtasks = system_binary("schtasks.exe")?;
    let powershell = system_binary("WindowsPowerShell\\v1.0\\powershell.exe")?;
    let directory =
        dirs::cache_dir().context("cannot determine the current user's local cache directory")?;
    with_safe_task_xml(&directory, xml, sid, &powershell, |path| {
        let path = path
            .to_str()
            .context("Task Scheduler XML path must be UTF-8")?;
        command_output(
            &schtasks,
            &["/create", "/tn", TASK_PATH, "/xml", path],
            4096,
        )?;
        Ok(())
    })
}

#[cfg(target_os = "windows")]
fn change_task(enabled: bool) -> Result<()> {
    let schtasks = system_binary("schtasks.exe")?;
    command_output(
        &schtasks,
        &[
            "/change",
            "/tn",
            TASK_PATH,
            if enabled { "/enable" } else { "/disable" },
        ],
        4096,
    )?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn delete_task() -> Result<()> {
    let schtasks = system_binary("schtasks.exe")?;
    let mut command = std::process::Command::new(schtasks);
    command.args(["/delete", "/tn", TASK_PATH]);
    run_command(command, Some(b"Y\r\n"), 4096)?;
    Ok(())
}

#[cfg(any(target_os = "windows", test))]
pub(super) fn same_task_except_enabled(left: &str, right: &str) -> Result<bool> {
    let mut left = parse_task_xml(left)?;
    let mut right = parse_task_xml(right)?;
    left.enabled = false;
    right.enabled = false;
    Ok(left == right)
}

#[cfg(target_os = "windows")]
pub(super) fn install_scan(
    executable: &Path,
    plan: &ScanSchedulePreview,
    token: &str,
    frequency: Frequency,
    check_scope: impl Fn() -> Result<()>,
) -> Result<&'static str> {
    if token != plan.preview_token {
        bail!("schedule preview token does not match");
    }
    let current = super::preview_from_plan(executable, plan, frequency)?;
    if current.preview_token != token || !current.timer_unit.is_empty() {
        bail!("schedule plan changed since preview; preview again");
    }
    let sid = current_user_sid()?;
    let current_task = read_existing_task()?;
    if current_task.is_some() {
        bail!("a task already exists at the Upkit scan path; refusing to overwrite it");
    }
    check_scope()?;
    register_task(&current.service_unit, &sid)?;
    check_scope().context("task may have been registered; configuration changed")?;
    let installed = read_existing_task()
        .context("task may have been registered; inspect its state before retrying")?
        .context("Task Scheduler did not report the new task; registration may be partial")?;
    if installed.snapshot.state != 3
        || !installed.definition.enabled
        || installed.canonical_xml != current.service_unit
    {
        bail!(
            "Task Scheduler registration could not be verified; inspect the task before retrying"
        );
    }
    Ok("active_and_enabled")
}

#[cfg(target_os = "windows")]
pub(super) fn disable_scan(plan: &DisableSchedulePreview, token: &str) -> Result<&'static str> {
    if token != plan.preview_token {
        bail!("schedule preview token does not match");
    }
    let current = preview_disable()?;
    if current.preview_token != token || current.active_state != "ready" {
        bail!("Task Scheduler task changed or is queued/running; disable preview again when idle");
    }
    let before = read_existing_task()?.context("Upkit scan task disappeared before disable")?;
    let before = disable_preview_from_existing(&before)?;
    if before.preview_token != token || before.active_state != "ready" {
        bail!("Task Scheduler task changed or is queued/running before disable");
    }
    change_task(false)?;
    let after = read_existing_task()
        .context("task may be disabled; inspect Task Scheduler before retrying")?
        .context("Task Scheduler task disappeared during disable")?;
    if after.snapshot.state == 1
        && !after.definition.enabled
        && same_task_except_enabled(&current.service_unit, &after.canonical_xml)?
    {
        Ok("inactive_and_disabled")
    } else {
        Ok("unverified")
    }
}

#[cfg(target_os = "windows")]
pub(super) fn preview_remove() -> Result<RemoveSchedulePreview> {
    let existing = read_existing_task()?.context("no task exists at the Upkit scan path")?;
    remove_preview_from_existing(&existing)
}

#[cfg(any(target_os = "windows", test))]
fn remove_preview_from_existing(existing: &ExistingTask) -> Result<RemoveSchedulePreview> {
    use sha2::{Digest, Sha256};
    let existing = disable_preview_from_existing(existing)?;
    if existing.active_state != "disabled"
        || existing.unit_file_state.as_deref() != Some("disabled")
    {
        bail!("Task Scheduler task must be disabled and idle before removal");
    }
    let mut hash = Sha256::new();
    hash.update(b"upkit-windows-scan-remove-preview-v1\0");
    hash.update(existing.preview_token.as_bytes());
    Ok(RemoveSchedulePreview {
        existing,
        quarantine_paths: Vec::new(),
        preview_token: hex::encode(hash.finalize()),
        warning: "Permanently unregisters only the verified, disabled Upkit scan task for the current Windows user. It does not delete workspace files or change other tasks. The complete snapshot is rechecked immediately before unregistering, but another process can still change the task after validation.",
    })
}

#[cfg(target_os = "windows")]
pub(super) fn remove_scan(plan: &RemoveSchedulePreview, token: &str) -> Result<&'static str> {
    if token != plan.preview_token {
        bail!("schedule preview token does not match");
    }
    let current = preview_remove()?;
    if current.preview_token != token {
        bail!("Task Scheduler task or state changed since preview; preview again");
    }
    let task = read_existing_task()?.context("Upkit scan task disappeared before removal")?;
    let before = remove_preview_from_existing(&task)?;
    if before.preview_token != token {
        bail!("Task Scheduler task or full security/state snapshot changed before removal");
    }
    delete_task()?;
    let after = read_existing_task()
        .context("Task Scheduler task may have been removed; inspect it before retrying")?;
    if after.is_none() {
        Ok("units_absent")
    } else {
        Ok("unverified")
    }
}

#[cfg(target_os = "windows")]
pub(super) fn enable_scan(
    executable: &Path,
    plan: &EnableSchedulePreview,
    token: &str,
    frequency: Frequency,
    check_scope: impl FnOnce() -> Result<()>,
) -> Result<&'static str> {
    if token != plan.preview_token {
        bail!("schedule preview token does not match");
    }
    let current = super::preview_enable_with_policy(
        executable,
        &plan.intended.roots,
        &plan.intended.exclusions,
        frequency,
        super::policy_from_plan(&plan.intended)?,
    )?;
    if current.preview_token != token {
        bail!("Task Scheduler task, scope, or state changed since preview; preview again");
    }
    check_scope()?;
    let before = super::preview_enable_with_policy(
        executable,
        &plan.intended.roots,
        &plan.intended.exclusions,
        frequency,
        super::policy_from_plan(&plan.intended)?,
    )?;
    if before.preview_token != token {
        bail!("Task Scheduler task or full security/state snapshot changed before enable");
    }
    change_task(true)?;
    let after = read_existing_task()
        .context("task may be enabled; inspect Task Scheduler before retrying")?
        .context("Task Scheduler task disappeared during enable")?;
    if after.snapshot.state == 3
        && after.definition.enabled
        && after.canonical_xml == current.intended.service_unit
    {
        Ok("active_and_enabled")
    } else {
        Ok("unverified")
    }
}

#[cfg(target_os = "windows")]
pub(super) fn edit_scan(
    executable: &Path,
    plan: &EditSchedulePreview,
    token: &str,
    frequency: Frequency,
    check_scope: impl Fn() -> Result<()>,
) -> Result<&'static str> {
    if token != plan.preview_token {
        bail!("schedule edit preview token does not match");
    }
    let current = super::preview_edit_with_policy(
        executable,
        &plan.replacement.roots,
        &plan.replacement.exclusions,
        frequency,
        super::policy_from_plan(&plan.replacement)?,
    )?;
    if current.preview_token != token {
        bail!("old task or replacement scope changed since preview; preview again");
    }
    check_scope()?;
    let removed = remove_scan(&current.previous, &current.previous.preview_token)
        .context("old Task Scheduler task removal failed or was partial")?;
    if removed != "units_absent" {
        bail!(
            "old Task Scheduler task removal could not be verified; replacement was not installed"
        );
    }
    check_scope().context("old task was removed; replacement was not installed")?;
    install_scan(
        executable,
        &current.replacement,
        &current.replacement.preview_token,
        frequency,
        check_scope,
    )
    .context("old task was removed; replacement registration may be partial")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_fake_manager_query_reports_unknown_not_disabled_or_absent() {
        let cancel = AtomicBool::new(false);
        let status = status_with_query(&cancel, |cancel| {
            cancel.store(true, Ordering::Relaxed);
            bail!("fake manager query interrupted")
        });

        assert_eq!(status.state, "unavailable");
        assert_eq!(status.load_state, None);
        assert_eq!(status.unit_file_state, None);
        assert!(status.detail.unwrap().contains("state remains unknown"));
    }

    #[cfg(unix)]
    #[test]
    fn cancelled_fake_query_kills_child_without_waiting_for_a_pipe_descendant() {
        use std::{
            process::Command,
            sync::Arc,
            thread,
            time::{Duration, Instant},
        };

        let fixture = tempfile::tempdir().unwrap();
        let pid_file = fixture.path().join("descendant.pid");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("sleep 5 & echo $! > \"$1\"; exec sleep 30")
            .arg("fake-task-scheduler")
            .arg(&pid_file);
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_query = cancel.clone();
        let pid_query = pid_file.clone();
        let canceller = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !pid_query.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            cancel_query.store(true, Ordering::Relaxed);
        });
        let started = Instant::now();
        let result = query_command_output(command, 4096, &cancel);
        canceller.join().unwrap();

        assert!(result.unwrap_err().to_string().contains("cancelled"));
        assert!(started.elapsed() < Duration::from_secs(1));
        let descendant = std::fs::read_to_string(&pid_file).unwrap();
        let _ = Command::new("sh")
            .arg("-c")
            .arg("kill -TERM \"$1\" 2>/dev/null || true")
            .arg("fake-task-scheduler-cleanup")
            .arg(descendant.trim())
            .status();
        let deadline = Instant::now() + Duration::from_secs(1);
        while TASK_QUERY_READER_ACTIVE.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(!TASK_QUERY_READER_ACTIVE.load(Ordering::Acquire));
    }

    #[test]
    fn task_xml_roundtrips_windows_paths_and_rejects_unsafe_actions() {
        let root = PathBuf::from(r#"C:\Work spaces\quote " path\"#);
        let exclusion = PathBuf::from(r#"glob:**\build & cache\"#);
        let arguments = windows_arguments(
            &scan_arguments(
                std::slice::from_ref(&root),
                std::slice::from_ref(&exclusion),
                &"a".repeat(64),
            )
            .unwrap(),
        )
        .unwrap();
        let argv = parse_windows_arguments(&arguments).unwrap();
        assert_eq!(argv.last().unwrap(), root.to_str().unwrap());
        assert!(
            argv.iter()
                .any(|arg| arg == &format!("--exclude={}", exclusion.display()))
        );

        let xml = task_xml(
            r#"C:\Program Files\Upkit\upkit.exe"#,
            &arguments,
            "S-1-5-21-42-1001",
            Frequency::Weekly,
            true,
        )
        .unwrap();
        let parsed = parse_task_xml(&xml).unwrap();
        assert_eq!(parsed.command, r#"C:\Program Files\Upkit\upkit.exe"#);
        assert_eq!(parsed.arguments, arguments);
        assert_eq!(parsed.sid, "S-1-5-21-42-1001");
        assert_eq!(parsed.frequency, Frequency::Weekly);
        assert!(parsed.enabled);

        for unsafe_xml in [
            xml.replace("LeastPrivilege", "HighestAvailable"),
            xml.replace("InteractiveToken", "Password"),
            xml.replace(
                "</Actions>",
                "<ComHandler><ClassId>fixture</ClassId></ComHandler></Actions>",
            ),
            xml.replace(
                "<Settings>",
                "<Settings><AllowStartOnDemand>true</AllowStartOnDemand>",
            ),
        ] {
            assert!(parse_task_xml(&unsafe_xml).is_err());
        }
    }

    #[test]
    fn decodes_task_xml_utf8_and_utf16_encodings() {
        let xml = task_xml(
            r#"C:\Upkit\upkit.exe"#,
            "\"--non-interactive\"",
            "S-1-5-21-42-1001",
            Frequency::Daily,
            true,
        )
        .unwrap();
        assert_eq!(decode_task_xml(xml.as_bytes()).unwrap(), xml);

        let mut utf8_bom = vec![0xef, 0xbb, 0xbf];
        utf8_bom.extend_from_slice(xml.as_bytes());
        assert_eq!(decode_task_xml(&utf8_bom).unwrap(), xml);

        let mut utf16_bom = vec![0xff, 0xfe];
        for unit in xml.encode_utf16() {
            utf16_bom.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(decode_task_xml(&utf16_bom).unwrap(), xml);

        let utf16_without_bom = xml
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(decode_task_xml(&utf16_without_bom).unwrap(), xml);
        assert!(decode_task_xml(&[0xff, 0xfe, b'<']).is_err());
    }

    #[test]
    fn rejects_noncanonical_arguments_and_task_xml() {
        assert!(parse_windows_arguments("\"unclosed").is_err());
        assert!(parse_windows_arguments("plain unquoted").is_err());
        assert!(valid_sid("S-1-5-21-42-1001"));
        assert!(!valid_sid("S-1-5-21-42-user"));
        assert!(!valid_sid("S-1-18446744073709551615-4294967296"));
        assert!(!valid_sid("S-1-5-21-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15"));
        assert!(xml_escape("bad\0value").is_err());
    }

    fn fixture_definition(enabled: bool) -> TaskDefinition {
        let arguments = windows_arguments(
            &scan_arguments(&[PathBuf::from(r"C:\Work")], &[], &"a".repeat(64)).unwrap(),
        )
        .unwrap();
        parse_task_xml(
            &task_xml(
                r#"C:\Program Files\Upkit\upkit.exe"#,
                &arguments,
                "S-1-5-21-42-1001",
                Frequency::Daily,
                enabled,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn fixture_snapshot() -> TaskSnapshot {
        let sid = "S-1-5-21-42-1001";
        TaskSnapshot {
            present: true,
            task_path: Some(TASK_PATH.into()),
            state: 3,
            enabled: true,
            last_run: None,
            next_run: None,
            security_owner: Some(sid.into()),
            security_descriptor: Some(format!("O:{sid}G:SYD:P(A;;FA;;;{sid})")),
            security_safe: true,
        }
    }

    fn fixture_existing_task(enabled: bool, state: u8) -> ExistingTask {
        let definition = fixture_definition(enabled);
        let mut snapshot = fixture_snapshot();
        snapshot.state = state;
        snapshot.enabled = enabled;
        let canonical_xml = task_xml(
            &definition.command,
            &definition.arguments,
            &definition.sid,
            definition.frequency,
            definition.enabled,
        )
        .unwrap();
        ExistingTask {
            sid: definition.sid.clone(),
            snapshot,
            definition,
            canonical_xml,
        }
    }

    #[test]
    fn task_snapshot_requires_path_sid_state_and_verified_owner_acl() {
        let sid = "S-1-5-21-42-1001";
        let definition = fixture_definition(true);
        let mut snapshot = fixture_snapshot();
        assert!(validate_snapshot(&snapshot, sid, &definition).is_ok());

        for mutate in [
            (|snapshot: &mut TaskSnapshot| snapshot.present = false) as fn(&mut TaskSnapshot),
            (|snapshot| snapshot.task_path = Some("\\Other".into())),
            (|snapshot| snapshot.state = 0),
            (|snapshot| snapshot.state = 1),
            (|snapshot| snapshot.enabled = false),
            (|snapshot| snapshot.security_owner = Some("S-1-5-21-42-1002".into())),
            (|snapshot| snapshot.security_descriptor = None),
            (|snapshot| snapshot.security_safe = false),
        ] {
            let mut altered = snapshot.clone();
            mutate(&mut altered);
            assert!(validate_snapshot(&altered, sid, &definition).is_err());
        }
        assert!(validate_snapshot(&snapshot, "invalid", &definition).is_err());

        snapshot.state = 2;
        assert!(validate_snapshot(&snapshot, sid, &definition).is_ok());
        snapshot.state = 4;
        assert!(validate_snapshot(&snapshot, sid, &definition).is_ok());

        let disabled_definition = fixture_definition(false);
        snapshot = fixture_snapshot();
        snapshot.state = 1;
        snapshot.enabled = false;
        assert!(validate_snapshot(&snapshot, sid, &disabled_definition).is_ok());
    }

    #[test]
    fn task_snapshot_revalidation_detects_manager_or_acl_changes() {
        let before = fixture_snapshot();
        assert!(validate_snapshot_stable(&before, &before.clone()).is_ok());

        let mut changed = before.clone();
        changed.state = 4;
        assert!(validate_snapshot_stable(&before, &changed).is_err());

        let mut changed = before.clone();
        changed.security_descriptor = Some("O:S-1-5-21-42-1001G:SYD:P".into());
        assert!(validate_snapshot_stable(&before, &changed).is_err());
    }

    #[test]
    fn schedule_action_tokens_bind_the_full_task_security_and_state_snapshot() {
        let existing = fixture_existing_task(true, 3);
        let preview = disable_preview_from_existing(&existing).unwrap();

        let mut changed = existing.clone();
        changed.snapshot.state = 4;
        assert_ne!(
            disable_preview_from_existing(&changed)
                .unwrap()
                .preview_token,
            preview.preview_token
        );

        let mut changed = existing.clone();
        changed.snapshot.security_descriptor = Some("changed ACL".into());
        assert_ne!(
            disable_preview_from_existing(&changed)
                .unwrap()
                .preview_token,
            preview.preview_token
        );

        let mut changed = existing;
        changed.canonical_xml = changed.canonical_xml.replace("C:\\Work", "C:\\Other");
        assert_ne!(
            disable_preview_from_existing(&changed)
                .unwrap()
                .preview_token,
            preview.preview_token
        );

        let remove = remove_preview_from_existing(&fixture_existing_task(false, 1)).unwrap();
        assert_eq!(remove.existing.active_state, "disabled");
    }

    #[test]
    fn whoami_fixture_requires_one_unambiguous_valid_sid() {
        assert_eq!(
            parse_whoami_sid(b"\"DOMAIN\\user\",\"S-1-5-21-42-1001\"\r\n").unwrap(),
            "S-1-5-21-42-1001"
        );
        assert_eq!(
            parse_whoami_sid(b"\"DOMAIN\\last, first\",\"S-1-5-21-42-1001\"\r\n").unwrap(),
            "S-1-5-21-42-1001"
        );
        assert!(parse_whoami_sid(b"\"user\",\"not-a-sid\"\r\n").is_err());
        assert!(
            parse_whoami_sid(b"\"user\",\"S-1-5-21-42-1001\"\r\n\"other\",\"S-1-5-21-42-1002\"")
                .is_err()
        );
        assert!(parse_whoami_sid(b"no csv").is_err());
    }

    #[test]
    fn enable_revalidation_ignores_only_task_enabled_flag() {
        let enabled = fixture_definition(true);
        let disabled_xml = task_xml(
            &enabled.command,
            &enabled.arguments,
            &enabled.sid,
            enabled.frequency,
            false,
        )
        .unwrap();
        let enabled_xml = task_xml(
            &enabled.command,
            &enabled.arguments,
            &enabled.sid,
            enabled.frequency,
            true,
        )
        .unwrap();
        assert!(same_task_except_enabled(&enabled_xml, &disabled_xml).unwrap());
        assert!(
            !same_task_except_enabled(&enabled_xml, &disabled_xml.replace("C:\\Work", "C:\\Other"))
                .unwrap()
        );
        assert!(
            !same_task_except_enabled(
                &enabled_xml,
                &disabled_xml.replace("S-1-5-21-42-1001", "S-1-5-21-42-1002")
            )
            .unwrap()
        );
        assert!(
            !same_task_except_enabled(
                &enabled_xml,
                &task_xml(
                    &enabled.command,
                    &enabled.arguments,
                    &enabled.sid,
                    Frequency::Weekly,
                    false,
                )
                .unwrap()
            )
            .unwrap()
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn task_xml_temp_file_fixture_checks_acl_and_removes_the_file() {
        let directory = tempfile::tempdir().unwrap();
        // The Windows temporary directory can use a verbatim (\\?\) path
        // even though scheduling requires a normalized canonical path.
        let directory_path = normalized_path(directory.path()).unwrap();
        let xml = task_xml(
            r#"C:\Program Files\Upkit\upkit.exe"#,
            "\"--non-interactive\"",
            "S-1-5-21-42-1001",
            Frequency::Daily,
            true,
        )
        .unwrap();
        let sid = current_user_sid().unwrap();
        let powershell = system_binary("WindowsPowerShell\\v1.0\\powershell.exe").unwrap();
        // The runner's temp directory can inherit permissions for unrelated
        // users. This security test must provision the *private* directory
        // that the production Task Scheduler workflow requires, not weaken
        // ACL verification to accept the runner's inherited ACL.
        let icacls = system_binary("icacls.exe").unwrap();
        // Grant the current user and the two trusted built-in principals
        // before removing inherited entries, so the test directory stays
        // accessible throughout ACL setup.
        let grant = std::process::Command::new(&icacls)
            .arg(&directory_path)
            .arg("/grant:r")
            .arg(format!("*{sid}:(OI)(CI)F"))
            .arg("*S-1-5-18:(OI)(CI)F")
            .arg("*S-1-5-32-544:(OI)(CI)F")
            .output()
            .unwrap();
        assert!(
            grant.status.success(),
            "could not grant the private Task Scheduler ACL fixture permissions"
        );
        let restrict = std::process::Command::new(&icacls)
            .arg(&directory_path)
            .arg("/inheritance:r")
            .output()
            .unwrap();
        assert!(
            restrict.status.success(),
            "could not remove inherited Task Scheduler ACL fixture permissions"
        );
        // The utility wrapper deliberately redacts Windows command errors.
        // For the isolated ACL fixture report only a status and static error
        // category, never an SDDL, SID, username, or filesystem path.
        let check = std::process::Command::new(&powershell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &task_powershell_script(TASK_ACL_SCRIPT),
            ])
            .env("UPKIT_TASK_ACL_PATH", &directory_path)
            .env("UPKIT_TASK_SID", &sid)
            .output()
            .unwrap();
        let category = if check.status.code() == Some(4) {
            "untrusted_acl_or_owner"
        } else if !check.status.success() {
            "powershell_command_failed"
        } else if check.stdout != b"OK" {
            "unexpected_acl_output"
        } else {
            "verified"
        };
        assert!(
            check.status.success() && check.stdout == b"OK",
            "private ACL fixture verification failed: code={:?}, category={category}",
            check.status.code()
        );
        verify_private_acl(&directory_path, &sid, &powershell).unwrap();
        let (path, stored) = with_safe_task_xml(&directory_path, &xml, &sid, &powershell, |path| {
            Ok((path.to_path_buf(), std::fs::read_to_string(path)?))
        })
        .unwrap();
        assert_eq!(stored, xml);
        assert!(!path.exists());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn scan_preview_rejects_a_fixture_junction_before_resolving_it() {
        use std::process::Command;

        let fixture = tempfile::tempdir().unwrap();
        let target = fixture.path().join("target");
        let junction = fixture.path().join("workspace-junction");
        std::fs::create_dir(&target).unwrap();
        let output = Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let error = preview_scan(
            &std::env::current_exe().unwrap(),
            &[junction],
            &[],
            Frequency::Daily,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("reparse points"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn powershell_task_acl_predicate_rejects_untrusted_read_and_execute_aces() {
        use std::process::Command;

        let sid = "S-1-5-21-42-1001";
        let untrusted = "S-1-5-21-42-1002";
        let powershell = system_binary("WindowsPowerShell\\v1.0\\powershell.exe").unwrap();
        let script = task_powershell_script(
            r#"
$safe = Test-UpkitTaskAcl $env:UPKIT_TEST_SDDL $env:UPKIT_TASK_SID
if ($safe) { [Console]::Out.Write('SAFE') } else { [Console]::Out.Write('UNSAFE') }
"#,
        );
        for (extra_ace, expected) in [
            (format!("(A;;0x1;;;{untrusted})"), &b"UNSAFE"[..]),
            (format!("(A;;0x20;;;{untrusted})"), &b"UNSAFE"[..]),
            (String::new(), &b"SAFE"[..]),
        ] {
            let sddl = format!("O:{sid}G:SYD:P(A;;FA;;;{sid}){extra_ace}");
            let mut command = Command::new(&powershell);
            command
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &script,
                ])
                .env("UPKIT_TASK_SID", sid)
                .env("UPKIT_TEST_SDDL", sddl);
            assert_eq!(run_command(command, None, 4096).unwrap(), expected);
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn powershell_task_lookup_only_maps_missing_task_to_absent() {
        use std::process::Command;

        let powershell = system_binary("WindowsPowerShell\\v1.0\\powershell.exe").unwrap();
        let script = task_powershell_script(
            r#"
$missing = [pscustomobject]@{}
$missing | Add-Member -MemberType ScriptMethod -Name GetTask -Value {
    throw [System.Runtime.InteropServices.COMException]::new('missing fixture', -2147024894)
}
if ($null -ne (Get-UpkitTask $missing)) { exit 4 }
$unreadable = [pscustomobject]@{}
$unreadable | Add-Member -MemberType ScriptMethod -Name GetTask -Value {
    throw [System.Runtime.InteropServices.COMException]::new('denied fixture', -2147024891)
}
try {
    Get-UpkitTask $unreadable | Out-Null
    [Console]::Out.Write('BAD')
} catch {
    [Console]::Out.Write('ERROR')
}
"#,
        );
        let mut command = Command::new(powershell);
        command.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ]);
        assert_eq!(run_command(command, None, 4096).unwrap(), b"ERROR");
    }
}
