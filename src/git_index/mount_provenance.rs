use anyhow::{Context, Result, bail};
use rustix::fs::{AtFlags, StatxFlags, statx};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, io::Read};

const MAX_MOUNTINFO_BYTES: usize = 1024 * 1024;
const MAX_MOUNTS: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct MountProof {
    pub(super) id: u64,
    pub(super) signature: [u8; 32],
}

struct MountRecord {
    device: String,
    filesystem: String,
    idmapped: bool,
    signature: [u8; 32],
}

pub(super) struct MountTable {
    records: HashMap<u64, MountRecord>,
}

impl MountTable {
    pub(super) fn read_current() -> Result<Self> {
        let file = fs::File::open("/proc/self/mountinfo").context("open mount information")?;
        if rustix::fs::fstatfs(&file)
            .context("inspect mount information filesystem")?
            .f_type
            != rustix::fs::PROC_SUPER_MAGIC
        {
            bail!("mount information is not provided by procfs");
        }
        let mut bytes = Vec::new();
        file.take((MAX_MOUNTINFO_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .context("read mount information")?;
        if bytes.len() > MAX_MOUNTINFO_BYTES {
            bail!("mount information exceeds its size limit");
        }
        Self::parse(std::str::from_utf8(&bytes).context("mount information is not UTF-8")?)
    }

    fn parse(contents: &str) -> Result<Self> {
        if contents.is_empty() || !contents.ends_with('\n') {
            bail!("mount information is incomplete");
        }
        let mut records = HashMap::new();
        for (index, line) in contents.lines().enumerate() {
            if index >= MAX_MOUNTS {
                bail!("mount information has too many records");
            }
            if line.is_empty() {
                bail!("mount information contains an empty record");
            }
            let Some((before, after)) = line.split_once(" - ") else {
                bail!("mount information record has no separator");
            };
            if after.contains(" - ") {
                bail!("mount information record has multiple separators");
            }
            let left = before.split_whitespace().collect::<Vec<_>>();
            let right = after.split_whitespace().collect::<Vec<_>>();
            if left.len() < 6 || right.len() != 3 {
                bail!("mount information record has an invalid field count");
            }
            let id = left[0]
                .parse::<u64>()
                .context("mount information has an invalid mount ID")?;
            if id == 0 {
                bail!("mount information has an invalid mount ID");
            }
            left[1]
                .parse::<u64>()
                .context("mount information has an invalid parent ID")?;
            parse_device(left[2])?;
            let root = decode_field(left[3])?;
            let point = decode_field(left[4])?;
            let source = decode_field(right[1])?;
            if !std::path::Path::new(&root).is_absolute()
                || !std::path::Path::new(&point).is_absolute()
                || left[5].is_empty()
                || right[0].is_empty()
                || source.is_empty()
                || right[2].is_empty()
                || left[6..].iter().any(|field| field.is_empty())
            {
                bail!("mount information record has invalid fields");
            }
            let idmapped = left[5]
                .split(',')
                .chain(right[2].split(','))
                .chain(left[6..].iter().copied())
                .any(is_idmapped_field);
            let mut hash = Sha256::new();
            hash.update(b"upkit-git-mount-record-v1\0");
            hash.update(line.as_bytes());
            let record = MountRecord {
                device: left[2].to_owned(),
                filesystem: right[0].to_owned(),
                idmapped,
                signature: hash.finalize().into(),
            };
            if records.insert(id, record).is_some() {
                bail!("mount information contains a duplicate mount ID");
            }
        }
        if records.is_empty() {
            bail!("mount information has no records");
        }
        Ok(Self { records })
    }

    pub(super) fn prove(&self, file: &fs::File) -> Result<MountProof> {
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata().context("inspect Git path metadata")?;
        let stats = statx(
            file,
            "",
            AtFlags::EMPTY_PATH,
            StatxFlags::BASIC_STATS | StatxFlags::MNT_ID,
        )
        .context("inspect Git mount identity")?;
        let required = StatxFlags::INO | StatxFlags::MODE | StatxFlags::UID | StatxFlags::MNT_ID;
        if stats.stx_mask & required.bits() != required.bits()
            || stats.stx_ino != metadata.ino()
            || u32::from(stats.stx_mode) != metadata.mode()
            || stats.stx_uid != metadata.uid()
            || rustix::fs::makedev(stats.stx_dev_major, stats.stx_dev_minor) as u64
                != metadata.dev()
        {
            bail!("Git path lacks a stable mount identity");
        }
        let record = self
            .records
            .get(&stats.stx_mnt_id)
            .context("Git mount ID is missing from mount information")?;
        let device = format!("{}:{}", stats.stx_dev_major, stats.stx_dev_minor);
        if record.device != device || record.idmapped || !trusted_filesystem(&record.filesystem) {
            bail!("Git path is on an unsupported or remapped filesystem");
        }
        Ok(MountProof {
            id: stats.stx_mnt_id,
            signature: record.signature,
        })
    }

    #[cfg(test)]
    fn proof_for_id(&self, id: u64) -> Option<MountProof> {
        self.records.get(&id).and_then(|record| {
            (!record.idmapped && trusted_filesystem(&record.filesystem)).then_some(MountProof {
                id,
                signature: record.signature,
            })
        })
    }
}

fn parse_device(value: &str) -> Result<(u32, u32)> {
    let Some((major, minor)) = value.split_once(':') else {
        bail!("mount information has an invalid device number");
    };
    if minor.contains(':') {
        bail!("mount information has an invalid device number");
    }
    Ok((
        major
            .parse()
            .context("mount information has an invalid device number")?,
        minor
            .parse()
            .context("mount information has an invalid device number")?,
    ))
}

fn decode_field(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            let digits = bytes
                .get(index + 1..index + 4)
                .context("mount information has an invalid escape")?;
            if !digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
                bail!("mount information has an invalid escape");
            }
            let byte = u16::from(digits[0] - b'0') * 64
                + u16::from(digits[1] - b'0') * 8
                + u16::from(digits[2] - b'0');
            if byte > u16::from(u8::MAX) {
                bail!("mount information has an out-of-range escape");
            }
            decoded.push(byte as u8);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).context("mount information path is not UTF-8")
}

fn is_idmapped_field(field: &str) -> bool {
    field == "idmapped" || field.starts_with("idmapped:")
}

fn trusted_filesystem(filesystem: &str) -> bool {
    matches!(
        filesystem,
        "ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "f2fs" | "tmpfs"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_mount_information_from_procfs() {
        assert!(!MountTable::read_current().unwrap().records.is_empty());
    }

    fn record(id: u64, optional: &str, filesystem: &str) -> String {
        format!("{id} 1 8:1 / /fixture rw,{optional} - {filesystem} /dev/sda1 rw\n")
    }

    #[test]
    fn rejects_idmapped_fuse_duplicate_missing_and_malformed_records() {
        let idmapped = MountTable::parse(&record(1, "idmapped", "ext4")).unwrap();
        assert!(idmapped.proof_for_id(1).is_none());
        let idmapped_optional =
            MountTable::parse("1 1 8:1 / /fixture rw idmapped - ext4 /dev/sda1 rw\n").unwrap();
        assert!(idmapped_optional.proof_for_id(1).is_none());
        for filesystem in ["fuse", "fuseblk", "fuse.sshfs", "nfs", "cifs"] {
            let table = MountTable::parse(&record(1, "rw", filesystem)).unwrap();
            assert!(table.proof_for_id(1).is_none(), "{filesystem}");
        }
        assert!(MountTable::parse(&(record(1, "rw", "ext4") + &record(1, "rw", "ext4"))).is_err());
        assert!(MountTable::parse("not mountinfo\n").is_err());
        assert!(MountTable::parse(&record(1, "rw", "ext4").replace("8:1", "bad")).is_err());
    }

    #[test]
    fn requires_the_exact_statx_mount_id_record_and_allowlisted_filesystem() {
        let table = MountTable::parse(&record(42, "rw", "ext4")).unwrap();
        let proof = table.proof_for_id(42).unwrap();
        assert_eq!(proof.id, 42);
        assert!(table.proof_for_id(43).is_none());
        assert!(
            MountTable::parse(&record(42, "rw", "overlay"))
                .unwrap()
                .proof_for_id(42)
                .is_none()
        );
    }

    #[test]
    fn accepts_tmpfs_as_a_local_kernel_filesystem() {
        assert!(
            MountTable::parse(&record(42, "rw", "tmpfs"))
                .unwrap()
                .proof_for_id(42)
                .is_some()
        );
    }
}
