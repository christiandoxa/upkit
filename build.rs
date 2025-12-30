use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(coverage)");
    if let Some(hash) = git_hash() {
        println!("cargo:rustc-env=UPKIT_GIT_HASH={hash}");
    }
    if let Some(date) = build_date() {
        println!("cargo:rustc-env=UPKIT_BUILD_DATE={date}");
    }
}

fn git_hash() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    if dirty {
        hash.push_str("-dirty");
    }
    if hash.is_empty() { None } else { Some(hash) }
}

fn build_date() -> Option<String> {
    if let Ok(output) = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
    {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(format!("{secs}"))
}
