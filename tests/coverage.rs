use std::process::Command;

#[test]
fn runs_binary() {
    let status = Command::new(env!("CARGO_BIN_EXE_upkit"))
        .status()
        .expect("run upkit");
    assert!(status.success());
}
