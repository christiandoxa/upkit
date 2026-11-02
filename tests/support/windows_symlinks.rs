use std::os::windows::fs::{symlink_dir, symlink_file};

pub fn available() -> bool {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    let folder = dir.path().join("folder");
    std::fs::write(&file, b"fixture").unwrap();
    std::fs::create_dir(&folder).unwrap();
    for result in [
        symlink_file(&file, dir.path().join("file-link")),
        symlink_dir(&folder, dir.path().join("folder-link")),
    ] {
        if let Err(error) = result {
            if error.raw_os_error() == Some(1314) {
                eprintln!("Windows symlink privilege unavailable; provider test skipped");
                return false;
            }
            panic!("Windows symlink probe failed: {error}");
        }
    }
    true
}
