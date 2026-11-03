use anyhow::{Context, Result, bail};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

// shortcut: cap stored symlink paths at 64 MiB; revisit for larger official archives.
const MAX_TAR_SYMLINK_PATH_BYTES: usize = 64 * 1024 * 1024;

fn ensure_empty_destination(destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(destination).context("inspect archive destination")?;
    if !plain_directory(&metadata) {
        bail!("archive destination must be a real directory");
    }
    // shortcut: relies on caller-private staging; use descriptor-relative extraction if staging becomes shared with an attacker.
    if fs::read_dir(destination)?.next().transpose()?.is_some() {
        bail!("archive destination must be empty");
    }
    Ok(())
}

fn plain_directory(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    let reparse_point = {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let reparse_point = false;
    metadata.is_dir() && !metadata.file_type().is_symlink() && !reparse_point
}

fn ensure_tar_parent_directories(destination: &Path, path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let mut current = destination.to_path_buf();
    for component in parent.components() {
        match component {
            Component::Normal(name) => current.push(name),
            Component::CurDir => continue,
            _ => bail!("archive contains an unsafe parent path"),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if plain_directory(&metadata) => {}
            Ok(_) => bail!("archive path traverses a non-directory or linked directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let created = {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::DirBuilderExt;
                        let mut builder = fs::DirBuilder::new();
                        builder.mode(0o755);
                        builder.create(&current)
                    }
                    #[cfg(not(unix))]
                    {
                        fs::create_dir(&current)
                    }
                };
                // Create each implicit parent here so its mode is bounded before extraction continues.
                created.with_context(|| {
                    format!(
                        "create archive parent {}",
                        crate::sweep::display_path(&current)
                    )
                })?;
                if !plain_directory(&fs::symlink_metadata(&current)?) {
                    bail!("archive parent changed while being created");
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspect archive parent {}",
                        crate::sweep::display_path(&current)
                    )
                });
            }
        }
    }
    Ok(())
}

fn safe_link(path: &Path, target: &Path, minimum_depth: usize) -> bool {
    let mut depth = path.parent().map_or(0, |parent| {
        parent
            .components()
            .filter(|part| matches!(part, Component::Normal(_)))
            .count()
    });
    if depth < minimum_depth || target.as_os_str().is_empty() {
        return false;
    }
    for part in target.components() {
        match part {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir if depth > minimum_depth => depth -= 1,
            _ => return false,
        }
    }
    true
}

pub(super) fn unpack_tar_gz(
    archive: &Path,
    destination: &Path,
    minimum_depth: usize,
) -> Result<()> {
    let file = fs::File::open(archive)?;
    unpack_tar(
        flate2::read::GzDecoder::new(file),
        destination,
        minimum_depth,
    )
}

pub(super) fn unpack_tar_zst(
    archive: &Path,
    destination: &Path,
    minimum_depth: usize,
) -> Result<()> {
    let file = fs::File::open(archive).context("open tar.zst archive")?;
    let decoder = zstd::Decoder::new(file).context("decode tar.zst archive")?;
    unpack_tar(decoder, destination, minimum_depth).context("extract tar.zst archive")
}

pub(super) fn unpack_tar(
    reader: impl Read,
    destination: &Path,
    minimum_depth: usize,
) -> Result<()> {
    unpack_tar_with_limit(reader, destination, minimum_depth, 3 * 1024 * 1024 * 1024)
}

pub(super) fn unpack_tar_with_limit(
    reader: impl Read,
    destination: &Path,
    minimum_depth: usize,
    max_bytes: u64,
) -> Result<()> {
    ensure_empty_destination(destination)?;
    let mut tar = tar::Archive::new(reader);
    let mut count = 0u64;
    let mut total = 0u64;
    let mut symlinks = Vec::new();
    let mut symlink_path_bytes = 0usize;
    for entry in tar.entries()? {
        let mut entry = entry?;
        count = count
            .checked_add(1)
            .context("archive entry count overflow")?;
        total = total
            .checked_add(entry.size())
            .context("archive size overflow")?;
        // shortcut: cap extraction at 100,000 entries; revisit for larger official archives.
        if count > 100_000 || total > max_bytes {
            bail!("archive exceeds extraction limits");
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir() || kind.is_symlink() || kind.is_hard_link()) {
            bail!("archive contains a special file");
        }
        let path = entry.path()?;
        if path
            .components()
            .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
        {
            bail!("archive contains an unsafe path");
        }
        if kind.is_symlink()
            && !entry
                .link_name()?
                .is_some_and(|target| safe_link(&path, &target, minimum_depth))
        {
            bail!("archive contains an unsafe symbolic link");
        }
        if kind.is_symlink() {
            add_symlink_path_bytes(&mut symlink_path_bytes, path.as_os_str().len())?;
            symlinks.push(path.to_path_buf());
        }
        ensure_tar_parent_directories(destination, &path)?;
        // Managed-install seals reject group/other-writable entries; keep other archive mode bits.
        entry.set_mask(0o022);
        if !entry.unpack_in(destination)? {
            bail!("archive contains an unsafe path");
        }
    }
    validate_tar_symlinks(destination, &symlinks, minimum_depth)?;
    Ok(())
}

fn add_symlink_path_bytes(total: &mut usize, path_bytes: usize) -> Result<()> {
    *total = total
        .checked_add(path_bytes)
        .context("archive symbolic link path size overflow")?;
    if *total > MAX_TAR_SYMLINK_PATH_BYTES {
        bail!("archive exceeds extraction limits");
    }
    Ok(())
}

fn validate_tar_symlinks(
    destination: &Path,
    symlinks: &[PathBuf],
    minimum_depth: usize,
) -> Result<()> {
    let destination = destination.canonicalize()?;
    for path in symlinks {
        let root = if minimum_depth == 0 {
            destination.clone()
        } else {
            let mut root = destination.clone();
            let mut depth = 0;
            for part in path.components() {
                if let Component::Normal(part) = part {
                    root.push(part);
                    depth += 1;
                    if depth == minimum_depth {
                        break;
                    }
                }
            }
            if depth != minimum_depth {
                bail!("archive symbolic link lacks its expected root");
            }
            root.canonicalize().context("resolve staged archive root")?
        };
        let resolved = destination
            .join(path)
            .canonicalize()
            .context("resolve staged archive symbolic link")?;
        if !resolved.starts_with(root) {
            bail!("archive symbolic link resolves outside its SDK root");
        }
    }
    Ok(())
}

fn windows_zip_path(name: &str) -> Result<std::path::PathBuf> {
    let mut path = std::path::PathBuf::new();
    let name = name.strip_suffix('/').unwrap_or(name);
    for part in name.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with(['.', ' '])
            || part
                .chars()
                .any(|ch| ch.is_control() || "<>:\\\"|?*".contains(ch))
        {
            bail!("archive contains an unsafe Windows path");
        }
        let base = part
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end_matches(' ')
            .to_ascii_uppercase();
        if matches!(
            base.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) || ["COM", "LPT"].iter().any(|prefix| {
            base.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        }) {
            bail!("archive contains a reserved Windows filename");
        }
        path.push(part);
    }
    Ok(path)
}

pub(super) fn unpack_windows_zip(archive: &Path, destination: &Path) -> Result<()> {
    unpack_zip(archive, destination, false, 3 * 1024 * 1024 * 1024)
}

pub(super) fn unpack_flutter_windows_zip(archive: &Path, destination: &Path) -> Result<()> {
    unpack_zip(archive, destination, false, 8 * 1024 * 1024 * 1024)
}

#[cfg(unix)]
pub(super) fn unpack_flutter_macos_zip(archive: &Path, destination: &Path) -> Result<()> {
    unpack_zip(archive, destination, true, 8 * 1024 * 1024 * 1024)
}

fn unpack_zip(archive: &Path, destination: &Path, allow_links: bool, max_bytes: u64) -> Result<()> {
    use std::collections::HashSet;
    ensure_empty_destination(destination)?;
    let mut zip = zip::unstable::read::ZipIterable::try_new(
        fs::File::open(archive)?,
        zip::read::Config::default(),
    )?
    .enforce_header_consistency(true);
    if zip.len() > 100_000 {
        bail!("archive exceeds extraction limits");
    }
    let mut paths = HashSet::new();
    let mut metadata = Vec::new();
    let mut name_bytes = 0usize;
    let mut link_bytes = 0u64;
    let mut total = 0u64;
    for entry in zip.files()? {
        let entry = entry?;
        // shortcut: require Windows-compatible ZIP names on macOS; relax if Flutter ships Unix-only names.
        let path = windows_zip_path(&entry.name()?)?;
        if allow_links && !path.starts_with("flutter") {
            bail!("unexpected Flutter archive root");
        }
        name_bytes = name_bytes
            .checked_add(entry.name_raw().len())
            .context("archive name size overflow")?;
        // shortcut: limit stored ZIP names to 64 MiB; revisit for larger official archives.
        if name_bytes > 64 * 1024 * 1024 {
            bail!("archive exceeds extraction limits");
        }
        let key = path.to_string_lossy().to_lowercase();
        if !paths.insert(key) {
            bail!("archive contains duplicate Windows paths");
        }
        let kind = entry.unix_mode().unwrap_or(0) & 0o170000;
        if entry.encrypted()
            || (entry.is_symlink() && (!allow_links || entry.size() > 16 * 1024))
            || !matches!(kind, 0 | 0o100000 | 0o040000 | 0o120000)
            || (kind == 0o120000 && !entry.is_symlink())
            || (kind == 0o040000 && !entry.is_dir())
            || (kind == 0o100000 && entry.is_dir())
            || (entry.is_dir() && entry.size() != 0)
        {
            bail!("archive contains an unsupported file type");
        }
        if entry.is_symlink() {
            link_bytes = link_bytes
                .checked_add(entry.size())
                .context("archive link size overflow")?;
            // shortcut: cap all ZIP link targets at 8 MiB; raise it for larger official SDKs.
            if link_bytes > 8 * 1024 * 1024 {
                bail!("archive exceeds extraction limits");
            }
        }
        metadata.push((
            path,
            entry.size(),
            entry.compressed_size(),
            entry.crc32(),
            entry.unix_mode(),
            entry.is_dir(),
            entry.compression(),
        ));
        total = total
            .checked_add(entry.size())
            .context("archive size overflow")?;
        if total > max_bytes {
            bail!("archive exceeds extraction limits");
        }
    }
    let entries = zip.files()?;
    let mut links = Vec::new();
    let mut index = 0;
    while let Some(entry) = entries.next() {
        let entry = entry?;
        let path = windows_zip_path(&entry.name()?)?;
        let current = (
            path.clone(),
            entry.size(),
            entry.compressed_size(),
            entry.crc32(),
            entry.unix_mode(),
            entry.is_dir(),
            entry.compression(),
        );
        if metadata.get(index) != Some(&current)
            || entry.encrypted()
            || (entry.is_symlink() && !allow_links)
        {
            bail!("archive changed during extraction");
        }
        index += 1;
        let target = destination.join(&path);
        if entry.is_dir() {
            fs::create_dir_all(target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let size = entry.size();
        let mode = entry.unix_mode();
        let is_link = entry.is_symlink();
        let mut entry = entry.with_reader(entries.reader_mut(), zip::ZipReadOptions::default())?;
        if is_link {
            let mut data = Vec::new();
            (&mut entry)
                .take(size.saturating_add(1))
                .read_to_end(&mut data)?;
            if data.len() as u64 != size {
                bail!("archive entry size does not match its contents");
            }
            let link = std::str::from_utf8(&data).context("non-Unicode Flutter symlink")?;
            let link = Path::new(link);
            if !safe_link(&path, link, 1) {
                bail!("archive contains an unsafe symbolic link");
            }
            links.push((target, link.to_owned()));
        } else {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            if std::io::copy(&mut (&mut entry).take(size.saturating_add(1)), &mut file)? != size {
                bail!("archive entry size does not match its contents");
            }
            #[cfg(unix)]
            if allow_links && let Some(mode) = mode {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(mode & 0o777))?;
            }
            #[cfg(not(unix))]
            let _ = mode;
        }
    }
    if index != metadata.len() {
        bail!("archive changed during extraction");
    }
    #[cfg(unix)]
    if !links.is_empty() {
        use std::os::unix::fs::symlink;
        let root = destination.join("flutter").canonicalize()?;
        for (path, target) in &links {
            symlink(target, path)?;
        }
        for (path, _) in &links {
            let resolved = path
                .canonicalize()
                .context("resolve staged Flutter symbolic link")?;
            if !resolved.starts_with(&root) {
                bail!("Flutter symbolic link resolves outside its SDK");
            }
        }
    }
    #[cfg(not(unix))]
    if !links.is_empty() {
        bail!("Flutter symbolic links are unsupported on this platform");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn archive_parent_errors_escape_terminal_controls_and_non_unicode_paths() {
        use std::{
            ffi::OsString,
            os::unix::{
                ffi::OsStringExt,
                fs::{MetadataExt, PermissionsExt},
            },
        };

        let prefix = OsString::from_vec(b"upkit-\x1b[\xff-".to_vec());
        let destination = tempfile::Builder::new().prefix(&prefix).tempdir().unwrap();
        let overlong_component = "x".repeat(256);
        let error = ensure_tar_parent_directories(
            destination.path(),
            Path::new(&format!("{overlong_component}/file")),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");

        assert!(rendered.contains("inspect archive parent"), "{rendered}");
        assert!(rendered.contains("%1B[%FF-"), "{rendered}");
        assert!(!rendered.contains('\x1b'), "{rendered}");
        assert!(!rendered.contains('\u{fffd}'), "{rendered}");

        if rustix::process::geteuid().as_raw() == 0 {
            eprintln!("SKIP: cannot force the create-error path while running as root");
            return;
        }
        let mode = fs::metadata(destination.path()).unwrap().mode() & 0o777;
        fs::set_permissions(
            destination.path(),
            fs::Permissions::from_mode(mode & !0o222),
        )
        .unwrap();
        let error = ensure_tar_parent_directories(destination.path(), Path::new("missing/file"));
        fs::set_permissions(destination.path(), fs::Permissions::from_mode(mode)).unwrap();
        let rendered = format!("{:#}", error.unwrap_err());
        assert!(rendered.contains("create archive parent"), "{rendered}");
        assert!(rendered.contains("%1B[%FF-"), "{rendered}");
        assert!(!rendered.contains('\x1b'), "{rendered}");
        assert!(!rendered.contains('\u{fffd}'), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn tar_extraction_clears_group_and_other_write_permissions() {
        use std::os::unix::fs::MetadataExt;

        let mut bytes = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut bytes);
            for path in ["python", "python/bin"] {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_mode(0o775);
                header.set_cksum();
                tar.append_data(&mut header, path, std::io::empty())
                    .unwrap();
            }
            let mut header = tar::Header::new_gnu();
            header.set_size(7);
            header.set_mode(0o775);
            header.set_cksum();
            tar.append_data(&mut header, "python/bin/python3", &b"fixture"[..])
                .unwrap();
            tar.finish().unwrap();
        }

        let destination = tempfile::tempdir().unwrap();
        unpack_tar(&bytes[..], destination.path(), 1).unwrap();
        for path in ["python", "python/bin", "python/bin/python3"] {
            let mode = fs::metadata(destination.path().join(path)).unwrap().mode() & 0o777;
            assert_eq!(mode, 0o755, "{path}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn tar_extraction_creates_safe_parents_for_files_without_directory_entries() {
        use std::os::unix::fs::MetadataExt;

        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(7);
        header.set_mode(0o775);
        header.set_cksum();
        tar.append_data(&mut header, "python/bin/python3", &b"fixture"[..])
            .unwrap();
        let bytes = tar.into_inner().unwrap();

        let destination = tempfile::tempdir().unwrap();
        unpack_tar(&bytes[..], destination.path(), 1).unwrap();
        for path in ["python", "python/bin", "python/bin/python3"] {
            let mode = fs::metadata(destination.path().join(path)).unwrap().mode() & 0o777;
            assert_eq!(mode & 0o022, 0, "{path}");
        }
        assert_eq!(
            fs::read(destination.path().join("python/bin/python3")).unwrap(),
            b"fixture"
        );
    }

    #[cfg(unix)]
    #[test]
    fn tar_extraction_does_not_follow_a_symlinked_parent() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("stage");
        let outside = dir.path().join("outside");
        fs::create_dir(&destination).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"fixture").unwrap();

        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, "python/real", std::io::empty())
            .unwrap();
        tar_symlink(&mut tar, "python/link", "real");
        tar_file(&mut tar, "python/link/payload", b"must not be written");
        let bytes = tar.into_inner().unwrap();

        assert!(unpack_tar(&bytes[..], &destination, 1).is_err());
        assert!(!destination.join("python/real/payload").exists());
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"fixture");
        assert!(!outside.join("payload").exists());
    }

    #[test]
    fn link_boundaries_follow_archive_layout() {
        assert!(safe_link(Path::new("sdk/link"), Path::new("../dotnet"), 0));
        assert!(!safe_link(
            Path::new("sdk/link"),
            Path::new("../../outside"),
            0
        ));
        assert!(safe_link(
            Path::new("jdk/bin/java"),
            Path::new("../lib/java"),
            1
        ));
        assert!(!safe_link(
            Path::new("jdk/bin/java"),
            Path::new("../../outside"),
            1
        ));
        assert!(!safe_link(Path::new("link"), Path::new("/outside"), 0));
    }

    fn zip_fixture(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::{Cursor, Write};
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in entries {
            zip.start_file(
                *name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[cfg(unix)]
    fn tar_file(tar: &mut tar::Builder<Vec<u8>>, path: &str, contents: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        tar.append_data(&mut header, path, contents).unwrap();
    }

    #[cfg(unix)]
    fn tar_symlink(tar: &mut tar::Builder<Vec<u8>>, path: &str, target: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o777);
        header.set_size(0);
        header.set_cksum();
        tar.append_link(&mut header, path, target).unwrap();
    }

    #[test]
    fn windows_zip_extracts_and_rejects_unsafe_paths_and_collisions() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("fixture.zip");
        let dest = dir.path().join("stage");
        fs::create_dir(&dest).unwrap();
        fs::write(
            &archive,
            zip_fixture(&[
                ("jdk/bin/java.exe", b"java"),
                ("jdk/bin/javac.exe", b"javac"),
            ]),
        )
        .unwrap();
        unpack_windows_zip(&archive, &dest).unwrap();
        assert_eq!(fs::read(dest.join("jdk/bin/java.exe")).unwrap(), b"java");
        for name in [
            "../escape",
            "/absolute",
            "x/../outside",
            "x\\outside",
            "C:/escape",
            "dir/NUL.txt",
            "dir/COM¹",
            "dir/foo. ",
            "dir/file:stream",
            "dir//file",
        ] {
            assert!(windows_zip_path(name).is_err(), "{name}");
        }
        let stage = dir.path().join("bad-stage");
        fs::create_dir(&stage).unwrap();
        fs::write(
            &archive,
            zip_fixture(&[("safe", b"ok"), ("../escape", b"bad")]),
        )
        .unwrap();
        assert!(unpack_windows_zip(&archive, &stage).is_err());
        assert!(!stage.join("safe").exists());
        assert!(!dir.path().join("escape").exists());
        fs::write(
            &archive,
            zip_fixture(&[("dir/File", b"a"), ("DIR/file", b"b")]),
        )
        .unwrap();
        assert!(unpack_windows_zip(&archive, &stage).is_err());
        assert!(!stage.join("dir").exists());
    }

    #[cfg(unix)]
    #[test]
    fn extractors_reject_a_preexisting_staging_symlink_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"fixture").unwrap();

        let mut tar = tar::Builder::new(Vec::new());
        tar_file(&mut tar, "redirect/payload", b"archive data");
        let tar_bytes = tar.into_inner().unwrap();
        let zip_path = dir.path().join("fixture.zip");
        fs::write(
            &zip_path,
            zip_fixture(&[("redirect/payload", b"archive data")]),
        )
        .unwrap();

        for (name, extract) in [("tar", true), ("zip", false)] {
            let stage = dir.path().join(format!("{name}-stage"));
            fs::create_dir(&stage).unwrap();
            symlink(&outside, stage.join("redirect")).unwrap();

            let error = if extract {
                unpack_tar(&tar_bytes[..], &stage, 0).unwrap_err()
            } else {
                unpack_windows_zip(&zip_path, &stage).unwrap_err()
            };
            assert!(error.to_string().contains("must be empty"), "{error:#}");
            assert_eq!(fs::read(outside.join("keep")).unwrap(), b"fixture");
            assert!(!outside.join("payload").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn flutter_zip_preserves_executables_and_safe_framework_links() {
        use std::{
            io::{Cursor, Write},
            os::unix::fs::PermissionsExt,
        };
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("fixture.zip");
        let stage = dir.path().join("stage");
        fs::create_dir(&stage).unwrap();
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
        zip.start_file("flutter/bin/flutter", options).unwrap();
        zip.write_all(b"executable").unwrap();
        zip.start_file("flutter/framework/Versions/A/asset", options)
            .unwrap();
        zip.write_all(b"asset").unwrap();
        zip.add_symlink("flutter/framework/Versions/Current", "A", options)
            .unwrap();
        zip.add_symlink("flutter/framework/link", "Versions/Current/asset", options)
            .unwrap();
        fs::write(&archive, zip.finish().unwrap().into_inner()).unwrap();
        unpack_flutter_macos_zip(&archive, &stage).unwrap();
        assert_eq!(
            fs::read(stage.join("flutter/framework/link")).unwrap(),
            b"asset"
        );
        assert_ne!(
            fs::metadata(stage.join("flutter/bin/flutter"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn flutter_zip_rejects_escaping_and_dangling_link_chains() {
        use std::io::{Cursor, Write};
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("fixture.zip");
        fs::write(dir.path().join("outside"), "keep").unwrap();
        for (case, target) in [
            ("direct", "../../outside"),
            ("chain", "x/../outside"),
            ("missing", "missing"),
        ] {
            let stage = dir.path().join(case);
            fs::create_dir(&stage).unwrap();
            if case == "chain" {
                fs::write(stage.join("outside"), "keep").unwrap();
            }
            let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
            let options = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
            zip.start_file("flutter/file", options).unwrap();
            zip.write_all(b"fixture").unwrap();
            if case == "chain" {
                zip.add_symlink("flutter/x", ".", options).unwrap();
            }
            zip.add_symlink("flutter/link", target, options).unwrap();
            fs::write(&archive, zip.finish().unwrap().into_inner()).unwrap();
            assert!(
                unpack_flutter_macos_zip(&archive, &stage).is_err(),
                "{case}"
            );
            assert_eq!(
                fs::read_to_string(dir.path().join("outside")).unwrap(),
                "keep"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn flutter_zip_rejects_excessive_symlink_data() {
        use std::io::Cursor;
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("fixture.zip");
        let stage = dir.path().join("stage");
        fs::create_dir(&stage).unwrap();
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        let target = "a".repeat(16 * 1024);
        for index in 0..513 {
            zip.add_symlink(format!("flutter/link-{index}"), &target, options)
                .unwrap();
        }
        fs::write(&archive, zip.finish().unwrap().into_inner()).unwrap();
        let error = unpack_flutter_macos_zip(&archive, &stage).unwrap_err();
        assert!(error.to_string().contains("limits"), "{error:#}");
        assert!(!stage.join("flutter").exists());
    }

    #[test]
    fn windows_zip_rejects_duplicate_names_and_declared_size_bombs() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("fixture.zip");
        let stage = dir.path().join("stage");
        fs::create_dir(&stage).unwrap();
        let mut bytes = zip_fixture(&[("dir/a", b"one"), ("dir/b", b"two")]);
        let mut replacements = 0;
        for index in 0..bytes.len() - 5 {
            if &bytes[index..index + 5] == b"dir/b" {
                bytes[index + 4] = b'a';
                replacements += 1;
            }
        }
        assert_eq!(replacements, 2);
        fs::write(&archive, bytes).unwrap();
        assert!(unpack_windows_zip(&archive, &stage).is_err());
        assert!(!stage.join("dir").exists());
        let mut bytes = zip_fixture(&[("binary", b"content")]);
        let local = bytes.windows(4).position(|p| p == b"PK\x03\x04").unwrap();
        let central = bytes.windows(4).position(|p| p == b"PK\x01\x02").unwrap();
        let size = (3u32 * 1024 * 1024 * 1024 + 1).to_le_bytes();
        bytes[local + 22..local + 26].copy_from_slice(&size);
        bytes[central + 24..central + 28].copy_from_slice(&size);
        fs::write(&archive, bytes).unwrap();
        let error = unpack_windows_zip(&archive, &stage).unwrap_err();
        assert!(error.to_string().contains("limits"), "{error:#}");
        assert!(!stage.join("binary").exists());
    }

    #[test]
    fn windows_zip_rejects_symlinks_and_bad_crc() {
        use std::io::{Cursor, Write};
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("fixture.zip");
        let stage = dir.path().join("stage");
        fs::create_dir(&stage).unwrap();
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zip.add_symlink(
            "link",
            "../outside",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        fs::write(&archive, zip.finish().unwrap().into_inner()).unwrap();
        assert!(unpack_windows_zip(&archive, &stage).is_err());
        assert!(!stage.join("link").exists());
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file(
            "binary",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        zip.write_all(b"unique-fixture-data").unwrap();
        let mut bytes = zip.finish().unwrap().into_inner();
        let offset = bytes
            .windows(b"unique-fixture-data".len())
            .position(|window| window == b"unique-fixture-data")
            .unwrap();
        bytes[offset] ^= 1;
        fs::write(&archive, bytes).unwrap();
        assert!(unpack_windows_zip(&archive, &stage).is_err());
    }

    #[test]
    fn tar_custom_size_limit_stops_before_writing_large_entry() {
        let dir = tempfile::tempdir().unwrap();
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(7);
        header.set_cksum();
        tar.append_data(&mut header, "flutter/file", &b"fixture"[..])
            .unwrap();
        let bytes = tar.into_inner().unwrap();
        let error = unpack_tar_with_limit(&bytes[..], dir.path(), 1, 6).unwrap_err();
        assert!(error.to_string().contains("limits"));
        assert!(!dir.path().join("flutter/file").exists());
    }

    #[cfg(unix)]
    #[test]
    fn tar_rejects_symlink_chain_that_leaves_its_sdk_root() {
        let dir = tempfile::tempdir().unwrap();
        let mut tar = tar::Builder::new(Vec::new());
        tar_file(&mut tar, "outside/keep", b"keep");
        tar_symlink(&mut tar, "sdk/alias", ".");
        tar_symlink(&mut tar, "sdk/alias/deep/escape", "../../outside");
        tar_file(&mut tar, "sdk/alias/deep/escape/written", b"escaped");
        let bytes = tar.into_inner().unwrap();

        assert!(safe_link(Path::new("sdk/alias"), Path::new("."), 1));
        assert!(safe_link(
            Path::new("sdk/alias/deep/escape"),
            Path::new("../../outside"),
            1
        ));
        assert!(unpack_tar(&bytes[..], dir.path(), 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn tar_rejects_dangling_and_cyclic_symlinks() {
        for links in [
            vec![("sdk/links/dangling", "missing")],
            vec![("sdk/links/a", "b"), ("sdk/links/b", "a")],
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut tar = tar::Builder::new(Vec::new());
            tar_file(&mut tar, "sdk/links/payload", b"present");
            for (path, target) in links {
                tar_symlink(&mut tar, path, target);
            }
            let bytes = tar.into_inner().unwrap();
            assert!(unpack_tar(&bytes[..], dir.path(), 1).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn tar_accepts_valid_symlinks_with_sdk_and_destination_roots() {
        let dir = tempfile::tempdir().unwrap();
        let mut sdk_tar = tar::Builder::new(Vec::new());
        tar_file(&mut sdk_tar, "sdk/lib/java", b"java");
        tar_symlink(&mut sdk_tar, "sdk/bin/java", "../lib/java");
        let sdk_bytes = sdk_tar.into_inner().unwrap();

        let stage = dir.path().join("sdk-stage");
        fs::create_dir(&stage).unwrap();
        unpack_tar(&sdk_bytes[..], &stage, 1).unwrap();
        assert_eq!(fs::read(stage.join("sdk/bin/java")).unwrap(), b"java");

        let mut dotnet_tar = tar::Builder::new(Vec::new());
        tar_file(&mut dotnet_tar, "shared/host", b"host");
        tar_symlink(&mut dotnet_tar, "runtime/current-host", "../shared/host");
        let dotnet_bytes = dotnet_tar.into_inner().unwrap();
        let stage = dir.path().join("dotnet-stage");
        fs::create_dir(&stage).unwrap();
        unpack_tar(&dotnet_bytes[..], &stage, 0).unwrap();
        assert_eq!(
            fs::read(stage.join("runtime/current-host")).unwrap(),
            b"host"
        );
    }

    #[test]
    fn tar_symlink_path_limit_checks_size_and_overflow() {
        let mut total = MAX_TAR_SYMLINK_PATH_BYTES - 1;
        assert!(add_symlink_path_bytes(&mut total, 1).is_ok());
        assert!(add_symlink_path_bytes(&mut total, 1).is_err());
        let mut overflow = usize::MAX;
        assert!(add_symlink_path_bytes(&mut overflow, 1).is_err());
    }

    #[test]
    fn rejects_special_files() {
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("special.tar.gz");
        let destination = directory.path().join("stage");
        fs::create_dir(&destination).unwrap();
        let file = fs::File::create(&archive).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Fifo);
        header.set_mode(0o600);
        header.set_size(0);
        header.set_cksum();
        tar.append_data(&mut header, "special", std::io::empty())
            .unwrap();
        tar.into_inner().unwrap().finish().unwrap();
        assert!(
            unpack_tar_gz(&archive, &destination, 0)
                .unwrap_err()
                .to_string()
                .contains("special file")
        );
        assert!(!destination.join("special").exists());
    }
}
