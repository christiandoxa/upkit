use std::process::Command;

#[test]
fn runs_binary() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .args(["--offline", "--dry-run", "--json"])
        .env("HOME", dir.path())
        .env("USERPROFILE", dir.path())
        .env("XDG_DATA_HOME", dir.path().join("data"))
        .output()
        .expect("run upkit");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reports: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let reports = reports.as_array().unwrap();
    let tools: Vec<_> = reports
        .iter()
        .map(|report| report["tool"].as_str().unwrap())
        .collect();
    assert_eq!(tools, ["go", "rust", "node", "python", "flutter", "mojo"]);
    assert!(reports.iter().all(|report| report["latest"].is_null()));
}
