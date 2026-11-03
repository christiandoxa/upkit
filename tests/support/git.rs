use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

pub fn elf_git() -> Option<PathBuf> {
    [PathBuf::from("/usr/bin/git"), PathBuf::from("/bin/git")]
        .into_iter()
        .chain(which::which("git"))
        .find(|path| {
            let Ok(mut file) = fs::File::open(path) else {
                return false;
            };
            let mut magic = [0u8; 4];
            file.read_exact(&mut magic).is_ok() && magic == *b"\x7fELF"
        })
}

pub fn sentinel_elf_git(directory: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let bin = directory.join("sentinel-bin");
    fs::create_dir_all(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    let source = directory.join("sentinel-git.rs");
    let executable = bin.join("git");
    let sentinel = directory.join("git-was-run");
    fs::write(
        &source,
        r#"
use std::{env, fs::OpenOptions, io::Write};
fn main() {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(env::var_os("UPKIT_TEST_GIT_SENTINEL").expect("sentinel path"))
        .expect("open sentinel")
        .write_all(b"called\n")
        .expect("write sentinel");
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && args[0] == "--version" {
        println!("git version 2.45.0");
    } else if args.contains(&"rev-parse".to_string()) {
        if args.contains(&"--git-path".to_string()) {
            println!("{}", env::var("UPKIT_TEST_GIT_GRAFT_PATH").expect("graft path"));
        } else if args.contains(&"--is-shallow-repository".to_string()) {
            println!("false");
        }
    }
}
"#,
    )
    .unwrap();
    let compiled = Command::new("rustc")
        .args(["--edition=2021"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("run rustc for sentinel Git fixture");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    (bin, sentinel)
}
