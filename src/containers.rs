//! Container inventory and explicitly scoped resource removal.
use serde::Serialize;
use serde_json::Value;
use std::{
    io::Read,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Serialize)]
pub struct EngineStatus {
    pub engine: &'static str,
    pub state: &'static str,
    pub usage: Vec<Value>,
    pub detail: Option<String>,
    pub resources: Vec<ResourceList>,
}

#[derive(Debug, Serialize)]
pub struct ResourceList {
    pub kind: &'static str,
    pub items: Vec<Value>,
    pub error: Option<&'static str>,
}

pub(crate) const BUILD_CACHE: &str = "build cache (selected Buildx builder; snapshot)";
const UNUSED_IMAGES: &str = "unused images (snapshot)";
const UNATTACHED_VOLUMES: &str = "unattached volumes (snapshot)";

pub(crate) fn validate_engine(engine: &str) -> anyhow::Result<()> {
    if !matches!(engine, "docker" | "podman") {
        anyhow::bail!("engine must be docker or podman");
    }
    Ok(())
}

pub(crate) fn validate_full_id(id: &str, resource: &str) -> anyhow::Result<()> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("provide one complete 64-character lowercase hexadecimal {resource} ID");
    }
    Ok(())
}

pub fn status(offline: bool) -> Vec<EngineStatus> {
    status_with_dry_run(offline, false)
}

pub fn status_with_dry_run(offline: bool, dry_run: bool) -> Vec<EngineStatus> {
    let detail = if offline {
        Some("Offline mode skips container engines, which may connect to remote hosts.")
    } else if dry_run {
        Some(
            "Dry-run skips container engine inventory; Docker, Podman, or a PATH wrapper may have side effects.",
        )
    } else {
        None
    };
    if let Some(detail) = detail {
        return ["docker", "podman"]
            .into_iter()
            .map(|engine| EngineStatus {
                engine,
                state: "skipped",
                usage: Vec::new(),
                detail: Some(detail.into()),
                resources: Vec::new(),
            })
            .collect();
    }

    ["docker", "podman"].into_iter().map(inspect).collect()
}

fn inspect(engine: &'static str) -> EngineStatus {
    let result = if let Ok(path) = which::which(engine) {
        query(&path, &["system", "df", "--format", "json"]).map(|usage| (usage, path))
    } else {
        Err(("unavailable", "Executable not found."))
    };
    match result {
        Ok((usage, path)) => EngineStatus {
            engine,
            state: "available",
            usage,
            detail: None,
            resources: list_resources(engine, &path),
        },
        Err((state, detail)) => EngineStatus {
            engine,
            state,
            usage: Vec::new(),
            detail: Some(detail.into()),
            resources: Vec::new(),
        },
    }
}

fn list_resources(engine: &str, path: &std::path::Path) -> Vec<ResourceList> {
    let mut requests: Vec<(&str, &[&str])> = vec![
        (
            "containers",
            &[
                "container",
                "ls",
                "--all",
                "--size",
                "--no-trunc",
                "--format",
                "json",
            ],
        ),
        ("images", &["image", "ls", "--all", "--format", "json"]),
        ("volumes", &["volume", "ls", "--format", "json"]),
        ("networks", &["network", "ls", "--format", "json"]),
        (
            "dangling images",
            &[
                "image",
                "ls",
                "--all",
                "--filter",
                "dangling=true",
                "--no-trunc",
                "--format",
                "json",
            ],
        ),
    ];
    if engine == "docker" {
        requests.push((
            "unattached custom networks (snapshot)",
            &[
                "network",
                "ls",
                "--filter",
                "dangling=true",
                "--filter",
                "type=custom",
                "--no-trunc",
                "--format",
                "json",
            ],
        ));
    }
    if engine == "podman" {
        requests.push((
            "unattached networks",
            &[
                "network",
                "ls",
                "--filter",
                "dangling=true",
                "--no-trunc",
                "--format",
                "json",
            ],
        ));
    }
    requests.push((
        UNATTACHED_VOLUMES,
        &[
            "volume",
            "ls",
            "--filter",
            "dangling=true",
            "--format",
            "json",
        ],
    ));
    let mut lists: Vec<ResourceList> = thread::scope(|scope| {
        let workers: Vec<_> = requests
            .into_iter()
            .map(|(kind, args)| {
                scope.spawn(move || match query(path, args) {
                    Ok(rows) => ResourceList {
                        kind,
                        items: rows.into_iter().map(relevant_fields).collect(),
                        error: None,
                    },
                    Err((_, detail)) => ResourceList {
                        kind,
                        items: Vec::new(),
                        error: Some(detail),
                    },
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| {
                worker.join().unwrap_or(ResourceList {
                    kind: "unknown",
                    items: Vec::new(),
                    error: Some("Inventory worker failed."),
                })
            })
            .collect()
    });
    if engine == "docker" {
        lists.push(build_cache_inventory(path));
    } else if engine == "podman" {
        lists.push(ResourceList {
            kind: "build cache",
            items: Vec::new(),
            error: Some("Detailed Podman build-cache inventory is not supported."),
        });
    }
    if matches!(engine, "docker" | "podman") {
        let images = lists
            .iter()
            .find(|list| list.kind == "images")
            .expect("image inventory request is always present");
        lists.push(unused_image_inventory(engine, path, images));
    }
    lists
}

fn unused_image_inventory(
    engine: &str,
    path: &std::path::Path,
    images: &ResourceList,
) -> ResourceList {
    let result = if images.error.is_some() {
        Err("Full image inventory unavailable; unused-image report omitted.")
    } else {
        query(
            path,
            &["image", "ls", "--all", "--no-trunc", "--format", "json"],
        )
        .map_err(|_| "Complete image IDs are unavailable; unused-image report omitted.")
        .and_then(|rows| {
            let full_images = rows.into_iter().map(relevant_fields).collect::<Vec<_>>();
            if engine == "docker" {
                query_text(path, &["system", "df", "--verbose"])
                    .map_err(|_| "Detailed image usage is unavailable.")
                    .and_then(|output| unused_images_from_system_df(&output, &full_images))
            } else {
                query_text(
                    path,
                    &[
                        "image",
                        "ls",
                        "--all",
                        "--no-trunc",
                        "--format",
                        "{{.Id}} {{.Containers}}",
                    ],
                )
                .map_err(|_| "Podman image container counts are unavailable.")
                .and_then(|output| unused_images_from_podman_template(&output, &full_images))
            }
        })
    };
    match result {
        Ok(items) => ResourceList {
            kind: UNUSED_IMAGES,
            items,
            error: None,
        },
        Err(error) => ResourceList {
            kind: UNUSED_IMAGES,
            items: Vec::new(),
            error: Some(error),
        },
    }
}

fn unused_images_from_system_df(
    output: &str,
    images: &[Value],
) -> Result<Vec<Value>, &'static str> {
    use std::collections::{BTreeMap, HashMap, HashSet};

    if images.iter().any(|image| image_id(image).is_none()) {
        return Err("Full image inventory contains incomplete IDs; no images classified.");
    }
    let mut complete_ids = HashSet::new();
    let mut prefix_ids = HashMap::new();
    for id in images.iter().filter_map(image_id) {
        if complete_ids.insert(id) {
            for length in 12..=id.len() {
                let prefix = &id[..length];
                prefix_ids
                    .entry(prefix)
                    .and_modify(|matched| *matched = None)
                    .or_insert(Some(id));
            }
        }
    }

    let mut in_images = false;
    let mut header_seen = false;
    let mut container_section_seen = false;
    let mut counts = BTreeMap::<String, u64>::new();
    for line in output.lines() {
        let line = line.trim();
        if !in_images {
            if line == "Images space usage:" {
                in_images = true;
            }
            continue;
        }
        if line.ends_with("space usage:") {
            container_section_seen = line == "Containers space usage:";
            break;
        }
        if line.is_empty() {
            continue;
        }
        let columns = line.split_whitespace().collect::<Vec<_>>();
        if !header_seen {
            if columns.first() == Some(&"REPOSITORY")
                && columns.get(2) == Some(&"IMAGE")
                && columns.last() == Some(&"CONTAINERS")
            {
                header_seen = true;
            }
            continue;
        }
        let Some(short_id) = columns.get(2).copied() else {
            return Err("Detailed image usage is incomplete; no images classified.");
        };
        if short_id.len() < 12
            || short_id.len() > 64
            || !short_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("Detailed image usage contains an invalid image ID; no images classified.");
        }
        let count = columns
            .last()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(
                "Detailed image usage contains an invalid container count; no images classified.",
            )?;
        let id = prefix_ids
            .get(short_id)
            .and_then(|id| *id)
            .ok_or("Detailed image usage IDs are incomplete or ambiguous; no images classified.")?;
        if counts
            .insert(id.to_owned(), count)
            .is_some_and(|old| old != count)
        {
            return Err("Detailed image usage disagrees across tags; no images classified.");
        }
    }
    if !in_images || !header_seen || !container_section_seen {
        return Err("Detailed image usage section is missing or truncated; no images classified.");
    }
    if complete_ids.iter().any(|id| !counts.contains_key(*id)) {
        return Err("Detailed image usage omits listed images; no images classified.");
    }
    unused_images_from_counts(images, counts)
}

fn unused_images_from_podman_template(
    output: &str,
    images: &[Value],
) -> Result<Vec<Value>, &'static str> {
    use std::collections::{BTreeMap, HashSet};

    if images.iter().any(|image| image_id(image).is_none()) {
        return Err("Full image inventory contains incomplete IDs; no images classified.");
    }
    let image_ids = images.iter().filter_map(image_id).collect::<HashSet<_>>();
    let mut counts = BTreeMap::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 2 {
            return Err("Podman image count output is incomplete; no images classified.");
        }
        let id = fields[0].strip_prefix("sha256:").unwrap_or(fields[0]);
        if id.len() != 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("Podman image count output has an invalid ID; no images classified.");
        }
        if !image_ids.contains(id) {
            return Err("Podman image count IDs do not match the inventory; no images classified.");
        }
        let count = fields[1]
            .parse::<u64>()
            .map_err(|_| "Podman image count is invalid; no images classified.")?;
        if counts
            .insert(id.to_owned(), count)
            .is_some_and(|previous| previous != count)
        {
            return Err("Podman image counts disagree across tags; no images classified.");
        }
    }
    unused_images_from_counts(images, counts)
}

fn unused_images_from_counts(
    images: &[Value],
    counts: std::collections::BTreeMap<String, u64>,
) -> Result<Vec<Value>, &'static str> {
    use std::collections::{BTreeMap, BTreeSet};

    if images.iter().any(|image| image_id(image).is_none()) {
        return Err("Full image inventory contains incomplete IDs; no images classified.");
    }
    let mut usage = BTreeMap::<String, (u64, BTreeSet<String>, Option<Value>)>::new();
    for image in images {
        let id = image_id(image).expect("image IDs were validated above");
        let Some(count) = counts.get(id).copied() else {
            return Err("Image container counts omit listed images; no images classified.");
        };
        let entry = usage
            .entry(id.to_owned())
            .or_insert_with(|| (count, BTreeSet::new(), None));
        if entry.0 != count {
            return Err("Image container counts disagree across tags; no images classified.");
        }
        if let Some(size) = image.get("Size").or_else(|| image.get("size")) {
            entry.2.get_or_insert_with(|| size.clone());
        }
        if let Some(names) = image
            .get("Names")
            .or_else(|| image.get("names"))
            .and_then(Value::as_array)
        {
            entry
                .1
                .extend(names.iter().filter_map(Value::as_str).map(clean_text));
        }
        if let Some(repository) = image
            .get("Repository")
            .or_else(|| image.get("repository"))
            .and_then(Value::as_str)
            && repository != "<none>"
            && let Some(tag) = image
                .get("Tag")
                .or_else(|| image.get("tag"))
                .and_then(Value::as_str)
            && tag != "<none>"
        {
            entry.1.insert(clean_text(&format!("{repository}:{tag}")));
        }
    }
    if usage.len() != counts.len() {
        return Err("Image container counts include unlisted images; no images classified.");
    }
    Ok(usage
        .into_iter()
        .filter(|(_, (containers, _, _))| *containers == 0)
        .map(|(id, (_, references, size))| {
            let mut item = serde_json::Map::new();
            item.insert("ID".into(), Value::String(id));
            item.insert("Containers".into(), Value::from(0));
            item.insert(
                "References".into(),
                Value::Array(references.into_iter().map(Value::String).collect()),
            );
            if let Some(size) = size {
                item.insert("Size".into(), size);
            }
            Value::Object(item)
        })
        .collect())
}

fn valid_builder_name(builder: &str) -> bool {
    !builder.is_empty()
        && builder.len() <= 128
        && builder.as_bytes()[0].is_ascii_alphanumeric()
        && builder
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn build_cache_inventory(path: &std::path::Path) -> ResourceList {
    let result = (|| {
        let output = query_text(path, &["buildx", "inspect", "--timeout=2s"]).ok()?;
        let mut names = output
            .lines()
            .take_while(|line| line.trim() != "Nodes:")
            .filter_map(|line| line.trim().strip_prefix("Name:").map(str::trim));
        let builder = names.next().filter(|name| valid_builder_name(name))?;
        if names.next().is_some() {
            return None;
        }
        let rows = query(
            path,
            &[
                "buildx",
                "--builder",
                builder,
                "du",
                "--timeout=2s",
                "--format=json",
            ],
        )
        .ok()?;
        rows.into_iter()
            .map(|row| {
                let mut item = relevant_build_cache(row)?;
                item.as_object_mut()?
                    .insert("Builder".into(), builder.into());
                Some(item)
            })
            .collect::<Option<Vec<_>>>()
    })();
    match result {
        Some(items) => ResourceList {
            kind: BUILD_CACHE,
            items,
            error: None,
        },
        None => ResourceList {
            kind: BUILD_CACHE,
            items: Vec::new(),
            error: Some("Buildx builder or cache inventory unavailable or incomplete."),
        },
    }
}

fn relevant_build_cache(row: Value) -> Option<Value> {
    const FIELDS: &[&str] = &[
        "ID",
        "Size",
        "Reclaimable",
        "Shared",
        "Mutable",
        "CreatedAt",
        "LastUsedAt",
        "Type",
        "UsageCount",
    ];
    let Value::Object(mut object) = row else {
        return None;
    };
    if !object
        .get("ID")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty())
        || !object.get("Reclaimable").is_some_and(Value::is_boolean)
        || !object.get("Shared").is_some_and(Value::is_boolean)
        || !object.get("Mutable").is_some_and(Value::is_boolean)
        || !object.get("Size").is_some_and(|size| {
            size.as_u64().is_some() || size.as_str().is_some_and(|value| !value.is_empty())
        })
    {
        return None;
    }
    Some(Value::Object(
        FIELDS
            .iter()
            .filter_map(|key| object.remove(*key).map(|value| ((*key).to_owned(), value)))
            .collect(),
    ))
}

fn build_cache_size_bytes(size: &Value) -> Option<u64> {
    match size {
        Value::Number(number) => number.as_u64(),
        Value::String(size)
            if !size.is_empty() && size.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            size.parse().ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod build_cache_tests {
    use super::{build_cache_size_bytes, relevant_build_cache};
    use serde_json::json;

    #[test]
    fn byte_estimates_accept_only_unsigned_decimal_sizes() {
        assert_eq!(build_cache_size_bytes(&json!(123)), Some(123));
        assert_eq!(build_cache_size_bytes(&json!("123")), Some(123));
        for value in [
            json!(""),
            json!("1MB"),
            json!("1.2"),
            json!("+1"),
            json!("-1"),
            json!("18446744073709551616"),
            json!(-1),
            json!(1.0),
        ] {
            assert_eq!(build_cache_size_bytes(&value), None, "{value}");
        }
        let overflow = serde_json::from_str::<serde_json::Value>("18446744073709551616").unwrap();
        assert_eq!(build_cache_size_bytes(&overflow), None);
    }

    #[test]
    fn inventory_requires_identity_and_status_without_exposing_build_details() {
        let row = json!({"ID":"cache", "Size":"123", "Reclaimable":true, "Shared":false, "Mutable":false, "Description":"private", "Parents":["private"]});
        let sanitized = relevant_build_cache(row.clone()).unwrap();
        assert_eq!(sanitized["ID"], "cache");
        assert!(sanitized.get("Description").is_none());
        assert!(sanitized.get("Parents").is_none());
        let mut human_size = row.clone();
        human_size["Size"] = "1.23MB".into();
        assert!(relevant_build_cache(human_size).is_some());
        for field in ["ID", "Size", "Reclaimable", "Shared", "Mutable"] {
            let mut incomplete = row.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(relevant_build_cache(incomplete).is_none());
        }
    }
}

fn relevant_fields(row: Value) -> Value {
    const FIELDS: &[&str] = &[
        "ID",
        "Id",
        "Names",
        "Name",
        "Image",
        "State",
        "Status",
        "Repository",
        "Tag",
        "Size",
        "Driver",
        "Scope",
        "id",
        "names",
        "name",
        "image",
        "state",
        "status",
        "repository",
        "tag",
        "size",
        "driver",
        "scope",
    ];
    match row {
        Value::Object(mut object) => Value::Object(
            FIELDS
                .iter()
                .filter_map(|key| object.remove(*key).map(|value| ((*key).to_owned(), value)))
                .collect(),
        ),
        _ => Value::Null,
    }
}

fn query(
    path: &std::path::Path,
    args: &[&str],
) -> Result<Vec<Value>, (&'static str, &'static str)> {
    let text = query_text(path, args)?;
    if let Ok(value) = serde_json::from_str::<Value>(&text) {
        return Ok(match value {
            Value::Array(rows) => rows,
            other => vec![other],
        });
    }
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|_| ("error", "Engine returned invalid JSON."))
        })
        .collect()
}

fn query_text(
    path: &std::path::Path,
    args: &[&str],
) -> Result<String, (&'static str, &'static str)> {
    let mut child = Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ("error", "Could not start engine."))?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let (send, receive) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.by_ref().take(1_048_577).read_to_end(&mut bytes);
        let _ = send.send((result, bytes));
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(("error", "Engine query timed out or could not be monitored."));
            }
        }
    };
    if !status.success() {
        return Err((
            "error",
            "Engine query failed; check engine availability and permissions.",
        ));
    }
    let (result, bytes) = receive
        .recv_timeout(Duration::from_millis(100))
        .map_err(|_| ("error", "Engine output was not available."))?;
    result.map_err(|_| ("error", "Could not read engine output."))?;
    if bytes.len() > 1_048_576 {
        return Err(("error", "Engine output exceeded the size limit."));
    }
    String::from_utf8(bytes).map_err(|_| ("error", "Engine output was not UTF-8."))
}

#[derive(Debug, Serialize)]
pub struct RemovalPlan {
    pub engine: String,
    pub engine_identity: String,
    pub container_id: String,
    pub name: String,
    pub writable_bytes: Option<u64>,
    pub preview_token: String,
    pub warning: &'static str,
    #[serde(skip)]
    executable: std::path::PathBuf,
    #[serde(skip)]
    engine_fingerprint: String,
}

#[cfg(test)]
pub(crate) fn test_removal_plan() -> RemovalPlan {
    RemovalPlan {
        engine: "docker".into(),
        engine_identity: "Docker server fixture".into(),
        container_id: "a".repeat(64),
        name: "fixture".into(),
        writable_bytes: Some(123),
        preview_token: "test-token".into(),
        warning: "fixture",
        executable: std::path::PathBuf::from("/fixture"),
        engine_fingerprint: "fixture".into(),
    }
}

fn clean_text(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

fn engine_identity(engine: &str, executable: &std::path::Path) -> anyhow::Result<(String, String)> {
    use anyhow::{Context, bail};
    let info = query(executable, &["info", "--format", "json"])
        .map_err(|(_, detail)| anyhow::anyhow!("engine identity: {detail}"))?;
    if info.len() != 1 {
        bail!("engine identity response was ambiguous");
    }
    let result = if engine == "docker" {
        let server = info[0]
            .get("ID")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .context("Docker server ID unavailable")?;
        (
            format!("Docker server {}", clean_text(server)),
            server.to_owned(),
        )
    } else {
        let store = info[0]
            .pointer("/store/graphRoot")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .context("Podman storage root unavailable")?;
        let host = info[0]
            .pointer("/host/hostname")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .context("Podman host identity unavailable")?;
        (
            format!(
                "Podman host {} storage {}",
                clean_text(host),
                clean_text(store)
            ),
            format!("{host}\0{store}"),
        )
    };
    Ok(result)
}

#[derive(Debug, Serialize)]
pub struct BuildCacheRemovalPlan {
    pub builder: String,
    pub cache_id: String,
    pub engine_identity: String,
    pub size: String,
    #[serde(skip)]
    pub(crate) size_bytes: Option<u64>,
    pub cache_type: String,
    pub preview_token: String,
    pub warning: &'static str,
    #[serde(skip)]
    executable: std::path::PathBuf,
    #[serde(skip)]
    builder_fingerprint: String,
    #[serde(skip)]
    engine_fingerprint: String,
}

#[cfg(test)]
pub(crate) fn test_build_cache_removal_plan() -> BuildCacheRemovalPlan {
    BuildCacheRemovalPlan {
        builder: "fixture".into(),
        cache_id: "a".repeat(25),
        engine_identity: "Docker server fixture".into(),
        size: "1MB".into(),
        size_bytes: None,
        cache_type: "regular".into(),
        preview_token: "fixture".into(),
        warning: "fixture",
        executable: std::path::PathBuf::from("/fixture"),
        builder_fingerprint: "fixture".into(),
        engine_fingerprint: "fixture".into(),
    }
}

fn builder_fingerprint(executable: &std::path::Path, builder: &str) -> anyhow::Result<String> {
    use anyhow::{Context, bail};
    use sha2::{Digest, Sha256};
    if !valid_builder_name(builder) {
        bail!("invalid Buildx builder name");
    }
    let output = query_text(executable, &["buildx", "inspect", builder, "--timeout=2s"])
        .map_err(|(_, detail)| anyhow::anyhow!("Buildx builder inspection: {detail}"))?;
    let mut section = 0;
    let mut name = None;
    let mut driver = None;
    let mut node_name = None;
    let mut endpoint = None;
    let mut state = None;
    let mut error = false;
    let set =
        |slot: &mut Option<String>, value: &str| slot.replace(value.trim().to_owned()).is_some();
    for line in output.lines() {
        let line = line.trim();
        if line == "Nodes:" {
            section += 1;
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            match (section, key) {
                (_, "Error") => error = true,
                (0, "Name") => error |= set(&mut name, value),
                (0, "Driver") => error |= set(&mut driver, value),
                (1, "Name") => error |= set(&mut node_name, value),
                (1, "Endpoint") => error |= set(&mut endpoint, value),
                (1, "Status") => error |= set(&mut state, value),
                _ => {}
            }
        }
    }
    if error
        || section != 1
        || name.as_deref() != Some(builder)
        || !matches!(
            driver.as_deref(),
            Some("docker" | "docker-container" | "remote" | "kubernetes")
        )
        || state.as_deref() != Some("running")
        || node_name.as_deref().is_none_or(str::is_empty)
        || endpoint.as_deref().is_none_or(str::is_empty)
    {
        bail!("builder must have one identifiable, running node with no reported error");
    }
    let mut hash = Sha256::new();
    for value in [
        builder,
        driver.as_deref().context("driver missing")?,
        node_name.as_deref().context("node missing")?,
        endpoint.as_deref().context("endpoint missing")?,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    Ok(hex::encode(hash.finalize()))
}

pub fn build_cache_preview(
    builder: &str,
    id: &str,
    offline: bool,
) -> anyhow::Result<BuildCacheRemovalPlan> {
    use anyhow::{Context, bail};
    use sha2::{Digest, Sha256};
    if offline {
        bail!("container operations are unavailable in offline mode");
    }
    if id.len() != 25
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        bail!("provide one complete 25-character lowercase BuildKit cache ID");
    }
    let executable = which::which("docker")
        .context("Docker not found")?
        .canonicalize()?;
    let (engine_description, engine_fingerprint) = engine_identity("docker", &executable)?;
    let fingerprint = builder_fingerprint(&executable, builder)?;
    let rows = query(
        &executable,
        &[
            "buildx",
            "--builder",
            builder,
            "du",
            "--timeout=2s",
            "--format=json",
        ],
    )
    .map_err(|(_, detail)| anyhow::anyhow!("Buildx cache inventory: {detail}"))?;
    let rows: Vec<_> = rows
        .into_iter()
        .map(relevant_build_cache)
        .collect::<Option<Vec<_>>>()
        .context("Buildx cache inventory contains an incomplete record")?;
    let mut matches = rows
        .iter()
        .filter(|row| row.get("ID").and_then(Value::as_str) == Some(id));
    let row = matches.next().context("selected cache not found")?;
    if matches.next().is_some() {
        bail!("cache ID is ambiguous across builder nodes");
    }
    if row["Reclaimable"] != true || row["Shared"] != false || row["Mutable"] != false {
        bail!("cache must be reclaimable, private and immutable");
    }
    let kind = row
        .get("Type")
        .and_then(Value::as_str)
        .filter(|kind| {
            matches!(
                *kind,
                "regular" | "source.local" | "source.git.checkout" | "exec.cachemount"
            )
        })
        .context("cache type is unavailable or unsupported")?;
    if !row
        .get("CreatedAt")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
    {
        bail!("cache creation timestamp is unavailable");
    }
    if builder_fingerprint(&executable, builder)? != fingerprint {
        bail!("builder changed during inspection");
    }
    if engine_identity("docker", &executable)?.1 != engine_fingerprint {
        bail!("Docker engine changed during inspection");
    }
    let snapshot = serde_json::to_string(row)?;
    let mut hash = Sha256::new();
    for value in [
        "upkit-build-cache-v1",
        &executable.to_string_lossy(),
        &engine_fingerprint,
        &fingerprint,
        builder,
        id,
        &snapshot,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    Ok(BuildCacheRemovalPlan {
        builder: builder.into(),
        cache_id: id.into(),
        engine_identity: engine_description,
        size: row["Size"]
            .as_str()
            .map(clean_text)
            .unwrap_or_else(|| row["Size"].to_string()),
        size_bytes: build_cache_size_bytes(&row["Size"]),
        cache_type: kind.into(),
        preview_token: hex::encode(hash.finalize()),
        executable,
        builder_fingerprint: fingerprint,
        engine_fingerprint,
        warning: "Permanently removes selected cache, which may contain build data; BuildKit may also remove linked metadata or run garbage collection. Builds may redownload or rebuild. Reclaimed space is unknown; builder and cache can change after inspection.",
    })
}

pub fn remove_build_cache(
    plan: &BuildCacheRemovalPlan,
    token: &str,
) -> anyhow::Result<&'static str> {
    use anyhow::{Context, bail};
    if token != plan.preview_token {
        bail!("preview token does not match the selected build cache");
    }
    let current = build_cache_preview(&plan.builder, &plan.cache_id, false)?;
    if current.preview_token != token {
        bail!("builder or cache changed since preview; preview again");
    }
    let filter = format!("id=^{}$", plan.cache_id);
    let mut child = Command::new(&current.executable)
        .args([
            "buildx",
            "--builder",
            &plan.builder,
            "prune",
            "--timeout=2s",
            "--force",
            "--filter",
            &filter,
            "--filter",
            "immutable=\"\"",
            "--filter",
            "private=\"\"",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start build cache removal")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(status)) => {
                bail!("build cache removal failed ({status}); outcome may be partial")
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("build cache removal timed out; outcome unknown");
            }
        }
    }
    if !builder_fingerprint(&current.executable, &plan.builder)
        .is_ok_and(|value| value == current.builder_fingerprint)
    {
        return Ok("unverified_builder_identity");
    }
    if !engine_identity("docker", &current.executable)
        .is_ok_and(|(_, value)| value == current.engine_fingerprint)
    {
        return Ok("unverified_engine_identity");
    }
    let rows = query(
        &current.executable,
        &[
            "buildx",
            "--builder",
            &plan.builder,
            "du",
            "--timeout=2s",
            "--format=json",
        ],
    );
    if !builder_fingerprint(&current.executable, &plan.builder)
        .is_ok_and(|value| value == current.builder_fingerprint)
        || !engine_identity("docker", &current.executable)
            .is_ok_and(|(_, value)| value == current.engine_fingerprint)
    {
        return Ok("unverified_builder_identity");
    }
    match rows {
        Ok(rows)
            if rows
                .iter()
                .any(|row| relevant_build_cache(row.clone()).is_none()) =>
        {
            Ok("unverified_listing")
        }
        Ok(rows)
            if rows
                .iter()
                .any(|row| row.get("ID").and_then(Value::as_str) == Some(&plan.cache_id)) =>
        {
            Ok("still_listed")
        }
        Ok(_) => Ok("verified_absent"),
        Err(_) => Ok("unverified_listing"),
    }
}

pub fn removal_preview(engine: &str, id: &str, offline: bool) -> anyhow::Result<RemovalPlan> {
    use anyhow::{Context, bail};
    use sha2::{Digest, Sha256};
    if offline {
        bail!("container operations are unavailable in offline mode");
    }
    validate_engine(engine)?;
    validate_full_id(id, "container")?;
    let executable = which::which(engine)
        .context("container engine not found")?
        .canonicalize()
        .context("resolve container engine")?;
    let (identity, fingerprint) = engine_identity(engine, &executable)?;
    let inspected = query(&executable, &["container", "inspect", "--size", id])
        .map_err(|(_, detail)| anyhow::anyhow!("container inspection: {detail}"))?;
    if inspected.len() != 1 {
        bail!("container inspection returned an ambiguous result");
    }
    let container = &inspected[0];
    if container
        .get("Id")
        .or_else(|| container.get("ID"))
        .and_then(Value::as_str)
        != Some(id)
    {
        bail!("inspected container ID does not match the selection");
    }
    let state = container
        .get("State")
        .context("container state unavailable")?;
    if state.get("Status").and_then(Value::as_str) != Some("exited")
        || state.get("Running").and_then(Value::as_bool) != Some(false)
        || state.get("Restarting").and_then(Value::as_bool) != Some(false)
    {
        bail!("container is not confirmed stopped and non-restarting");
    }
    let name = container
        .get("Name")
        .and_then(Value::as_str)
        .context("container name unavailable")?;
    let started = state
        .get("StartedAt")
        .and_then(Value::as_str)
        .context("container start time unavailable")?;
    let finished = state
        .get("FinishedAt")
        .and_then(Value::as_str)
        .context("container finish time unavailable")?;
    let restarts = container
        .get("RestartCount")
        .and_then(Value::as_u64)
        .context("container restart count unavailable")?;
    let state_snapshot = serde_json::to_string(state).context("serialize container state")?;
    let size_snapshot = container
        .get("SizeRw")
        .map_or("unknown".into(), Value::to_string);
    let restart_policy = container
        .pointer("/HostConfig/RestartPolicy")
        .map_or("unknown".into(), Value::to_string);
    let mut hash = Sha256::new();
    for value in [
        "upkit-container-removal-v1",
        engine,
        &executable.to_string_lossy(),
        &fingerprint,
        id,
        name,
        started,
        finished,
        &restarts.to_string(),
        &state_snapshot,
        &size_snapshot,
        &restart_policy,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    Ok(RemovalPlan {
        engine: engine.into(),
        engine_identity: identity,
        container_id: id.into(),
        name: clean_text(name),
        writable_bytes: container.get("SizeRw").and_then(Value::as_u64),
        preview_token: hex::encode(hash.finalize()),
        warning: "Removing this stopped container permanently removes its writable layer, configuration and logs. No force or volume-removal option is used; space reclaimed is not guaranteed.",
        executable,
        engine_fingerprint: fingerprint,
    })
}

pub fn remove_stopped(plan: &RemovalPlan, token: &str) -> anyhow::Result<&'static str> {
    use anyhow::{Context, bail};
    if token != plan.preview_token {
        bail!("preview token does not match the selected container");
    }
    let current = removal_preview(&plan.engine, &plan.container_id, false)?;
    if current.preview_token != token {
        bail!("container or engine changed since preview; preview again");
    }
    let mut child = Command::new(&current.executable)
        .args(["container", "rm", "--", &plan.container_id])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start container removal")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(status)) => {
                bail!("container removal failed ({status}); inspect engine state before retrying")
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "container removal timed out or could not be monitored; outcome unknown, inspect engine state before retrying"
                );
            }
        }
    }
    let filter = format!("id={}", plan.container_id);
    let listed = query(
        &current.executable,
        &[
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            &filter,
            "--format",
            "json",
        ],
    );
    let identity = engine_identity(&current.engine, &current.executable);
    if !identity.is_ok_and(|(_, fingerprint)| fingerprint == current.engine_fingerprint) {
        return Ok("unverified_engine_identity");
    }
    match listed {
        Ok(rows) if rows.is_empty() => Ok("verified_absent"),
        Ok(rows)
            if rows.iter().any(|row| {
                row.get("ID")
                    .or_else(|| row.get("Id"))
                    .or_else(|| row.get("id"))
                    .and_then(Value::as_str)
                    == Some(&plan.container_id)
            }) =>
        {
            Ok("still_listed")
        }
        _ => Ok("unverified_listing"),
    }
}

#[derive(Debug, Serialize)]
pub struct ImageRemovalPlan {
    pub engine: String,
    pub engine_identity: String,
    pub image_id: String,
    pub size_bytes: Option<u64>,
    pub preview_token: String,
    pub warning: &'static str,
}

pub(crate) fn image_id(row: &Value) -> Option<&str> {
    row.get("ID")
        .or_else(|| row.get("Id"))
        .or_else(|| row.get("id"))
        .and_then(Value::as_str)
        .map(|id| id.strip_prefix("sha256:").unwrap_or(id))
        .filter(|id| {
            id.len() == 64
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

/// Refuse image previews until engines support a conditional deletion contract.
pub fn image_removal_preview(
    _engine: &str,
    _id: &str,
    _offline: bool,
) -> anyhow::Result<ImageRemovalPlan> {
    anyhow::bail!(
        "dangling image preview and removal are unsupported because Docker and Podman cannot conditionally delete an image while preserving tags added after inspection; use `containers status` for the read-only inventory"
    )
}

pub fn remove_image(_plan: &ImageRemovalPlan, _token: &str) -> anyhow::Result<&'static str> {
    anyhow::bail!(
        "dangling image removal is unsupported until the engine can conditionally delete the reviewed image without removing tags added after preview"
    )
}

#[derive(Debug, Serialize)]
pub struct NetworkRemovalPlan {
    pub engine: String,
    pub engine_identity: String,
    pub network_id: String,
    pub name: String,
    pub preview_token: String,
    pub warning: &'static str,
    #[serde(skip)]
    executable: std::path::PathBuf,
    #[serde(skip)]
    engine_fingerprint: String,
}

#[cfg(test)]
pub(crate) fn test_network_removal_plan() -> NetworkRemovalPlan {
    NetworkRemovalPlan {
        engine: "docker".into(),
        engine_identity: "Docker server fixture".into(),
        network_id: "b".repeat(64),
        name: "fixture".into(),
        preview_token: "fixture".into(),
        warning: "fixture",
        executable: "/fixture".into(),
        engine_fingerprint: "fixture".into(),
    }
}

/// Preview one explicitly selected unused local bridge network.
pub fn network_removal_preview(
    engine: &str,
    id: &str,
    offline: bool,
) -> anyhow::Result<NetworkRemovalPlan> {
    use anyhow::{Context, bail};
    use sha2::{Digest, Sha256};
    if offline {
        bail!("container operations are unavailable in offline mode");
    }
    validate_engine(engine)?;
    validate_full_id(id, "network")?;
    let executable = which::which(engine)
        .context("container engine not found")?
        .canonicalize()
        .context("resolve container engine")?;
    let (identity, fingerprint) = engine_identity(engine, &executable)?;
    let mut args = vec!["network", "ls", "--filter", "dangling=true"];
    if engine == "docker" {
        args.extend(["--filter", "type=custom"]);
    }
    args.extend(["--no-trunc", "--format", "json"]);
    let rows = query(&executable, &args)
        .map_err(|(_, detail)| anyhow::anyhow!("unused network inventory: {detail}"))?;
    if rows.iter().any(|row| image_id(row).is_none())
        || rows.iter().filter(|row| image_id(row) == Some(id)).count() != 1
    {
        bail!("network is not uniquely identified in the unused network inventory");
    }
    let inspected = query(&executable, &["network", "inspect", id])
        .map_err(|(_, detail)| anyhow::anyhow!("network inspection: {detail}"))?;
    if inspected.len() != 1 || image_id(&inspected[0]) != Some(id) {
        bail!("inspected network ID does not match the selection");
    }
    let network = &inspected[0];
    let name = network
        .get("Name")
        .or_else(|| network.get("name"))
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .context("network name unavailable")?;
    let driver = network
        .get("Driver")
        .or_else(|| network.get("driver"))
        .and_then(Value::as_str)
        .context("network driver unavailable")?;
    if driver != "bridge" || matches!(name, "bridge" | "host" | "none" | "podman") {
        bail!("only non-default bridge networks can be selected");
    }
    if engine == "docker" {
        if network.get("Scope").and_then(Value::as_str) != Some("local") {
            bail!("network is not confirmed local");
        }
        if !network
            .get("Containers")
            .is_some_and(|v| v.is_null() || v.as_object().is_some_and(|v| v.is_empty()))
        {
            bail!("network has attached containers or attachment status is unavailable");
        }
    }
    let snapshot = serde_json::to_string(network).context("serialize network identity")?;
    let mut hash = Sha256::new();
    for value in [
        "upkit-network-removal-v1",
        engine,
        &executable.to_string_lossy(),
        &fingerprint,
        id,
        &snapshot,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    Ok(NetworkRemovalPlan {
        engine: engine.into(),
        engine_identity: identity,
        network_id: id.into(),
        name: clean_text(name),
        preview_token: hex::encode(hash.finalize()),
        warning: "Permanently removes this unused network configuration without force. Services may need it later; Podman custom defaults are not independently identified. Attachments and engine state can change after revalidation.",
        executable,
        engine_fingerprint: fingerprint,
    })
}

pub fn remove_network(plan: &NetworkRemovalPlan, token: &str) -> anyhow::Result<&'static str> {
    use anyhow::{Context, bail};
    if token != plan.preview_token {
        bail!("preview token does not match the selected network");
    }
    let current = network_removal_preview(&plan.engine, &plan.network_id, false)?;
    if current.preview_token != token {
        bail!("network or engine changed since preview; preview again");
    }
    let mut child = Command::new(&current.executable)
        .args(["network", "rm", "--", &plan.network_id])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start network removal")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(status)) => {
                bail!("network removal failed ({status}); inspect engine state before retrying")
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "network removal timed out or could not be monitored; outcome unknown, inspect engine state before retrying"
                );
            }
        }
    }
    let listed = query(
        &current.executable,
        &["network", "ls", "--no-trunc", "--format", "json"],
    );
    if !engine_identity(&current.engine, &current.executable)
        .is_ok_and(|(_, fingerprint)| fingerprint == current.engine_fingerprint)
    {
        return Ok("unverified_engine_identity");
    }
    match listed {
        Ok(rows) if rows.iter().any(|row| image_id(row).is_none()) => Ok("unverified_listing"),
        Ok(rows)
            if rows
                .iter()
                .any(|row| image_id(row) == Some(&plan.network_id)) =>
        {
            Ok("still_listed")
        }
        Ok(_) => Ok("verified_absent"),
        Err(_) => Ok("unverified_listing"),
    }
}
