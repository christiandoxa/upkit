use std::{fs, process::Command};

#[test]
fn inspection_commands_do_not_create_directories_or_edit_shell_configuration() {
    let fixture = tempfile::tempdir().unwrap();
    let home = fixture.path();
    let shell_config = home.join(".bashrc");
    fs::write(&shell_config, "# existing shell configuration\n").unwrap();
    let managed = home.join("managed");
    let bindir = home.join("bin");
    for args in [
        vec!["--json", "check"],
        vec!["check"],
        vec!["--json"],
        vec!["--json", "doctor"],
        vec!["--json", "version"],
        vec!["completions", "bash"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_upkit"))
            .args(["--offline", "--non-interactive", "--home"])
            .arg(&managed)
            .arg("--bindir")
            .arg(&bindir)
            .args(&args)
            .env("HOME", home)
            .env("USERPROFILE", home)
            .env("SHELL", "/bin/bash")
            .env("PATH", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("LOCALAPPDATA", home.join("data"))
            .output()
            .unwrap();
        if !args.contains(&"doctor") {
            assert!(
                output.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if args.contains(&"--json") {
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
        }
        assert_eq!(
            fs::read_to_string(&shell_config).unwrap(),
            "# existing shell configuration\n"
        );
        assert!(!managed.exists(), "{args:?} created the managed directory");
        assert!(!bindir.exists(), "{args:?} created the binary directory");
        assert_eq!(
            fs::read_dir(home).unwrap().count(),
            1,
            "{args:?} changed the home directory"
        );
    }
}
