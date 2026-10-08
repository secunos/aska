//! The two files Qubes split mode moves between qubes (Client Design §8.2), and the rule for
//! every file this client writes: only at a path the user named, never over an existing file.
//!
//! Both files hold what a relay sees anyway — labels and ciphertext — so they are safe to carry
//! through a networked qube. Format (all big-endian):
//!
//! ```text
//! "ASKF" ‖ 0x01 ‖ kind
//!   kind 0x01 (Block):  label(32) ‖ block(class length)
//!   kind 0x02 (bucket): class(1) ‖ count(u32) ‖ count × (label(32) ‖ block(class length))
//! ```

use aska_core::consts::SizeClass;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"ASKF";
const VERSION: u8 = 1;
const KIND_BLOCK: u8 = 1;
const KIND_BUCKET: u8 = 2;

pub type Label = [u8; 32];
/// One relay record: label and Block.
pub type Record = (Label, Vec<u8>);

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// Create a file that did not exist; refuses to overwrite (the user deletes explicitly).
pub fn create_new(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(
                    e.kind(),
                    format!("{} exists; not overwriting", path.display()),
                )
            } else {
                e
            }
        })
}

pub fn write_block(path: &Path, label: &Label, block: &[u8]) -> io::Result<()> {
    if SizeClass::from_len(block.len()).is_none() {
        return Err(bad("block length is not a size class"));
    }
    let mut f = create_new(path)?;
    f.write_all(MAGIC)?;
    f.write_all(&[VERSION, KIND_BLOCK])?;
    f.write_all(label)?;
    f.write_all(block)?;
    f.sync_all()
}

pub fn read_block(path: &Path) -> io::Result<(Label, Vec<u8>)> {
    let mut b = Vec::new();
    File::open(path)?.read_to_end(&mut b)?;
    if b.len() < 6 + 32 || &b[..4] != MAGIC || b[4] != VERSION {
        return Err(bad("not an aska Block file"));
    }
    if b[5] != KIND_BLOCK {
        return Err(bad("this is a bucket file, not a Block file"));
    }
    let mut label = [0u8; 32];
    label.copy_from_slice(&b[6..38]);
    let block = b[38..].to_vec();
    if SizeClass::from_len(block.len()).is_none() {
        return Err(bad("Block length is not a size class"));
    }
    Ok((label, block))
}

pub fn write_bucket(path: &Path, class: u8, records: &[Record]) -> io::Result<()> {
    let size = SizeClass::from_u8(class)
        .ok_or_else(|| bad("bad class"))?
        .len();
    if records.iter().any(|(_, b)| b.len() != size) {
        return Err(bad("record length does not match the class"));
    }
    let mut f = create_new(path)?;
    f.write_all(MAGIC)?;
    f.write_all(&[VERSION, KIND_BUCKET, class])?;
    f.write_all(&(records.len() as u32).to_be_bytes())?;
    for (l, b) in records {
        f.write_all(l)?;
        f.write_all(b)?;
    }
    f.sync_all()
}

pub fn read_bucket(path: &Path) -> io::Result<(u8, Vec<Record>)> {
    let mut b = Vec::new();
    File::open(path)?.read_to_end(&mut b)?;
    if b.len() < 11 || &b[..4] != MAGIC || b[4] != VERSION {
        return Err(bad("not an aska bucket file"));
    }
    if b[5] != KIND_BUCKET {
        return Err(bad("this is a Block file, not a bucket file"));
    }
    let class = b[6];
    let size = SizeClass::from_u8(class)
        .ok_or_else(|| bad("bad class"))?
        .len();
    let count = u32::from_be_bytes([b[7], b[8], b[9], b[10]]) as usize;
    let rec = 32 + size;
    if b.len() != 11 + count * rec {
        return Err(bad("bucket file length does not match its record count"));
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let at = 11 + i * rec;
        let mut label = [0u8; 32];
        label.copy_from_slice(&b[at..at + 32]);
        out.push((label, b[at + 32..at + rec].to_vec()));
    }
    Ok((class, out))
}

/// Overwrite a file's contents with random bytes, flush, then unlink (`profile forget`).
/// Best effort on journaling and copy-on-write filesystems, as documented.
/// A profile path must name a regular file (not a symlink, device or FIFO) of exactly the
/// profile size, or the command refuses it: following a planted symlink to a device could read
/// until memory ran out, and shredding through one would overwrite whatever it pointed at
/// (pre-review C-14, applied to the graphical client in 1.0.0 and to the CLI in 1.1).
pub fn check_profile_path(path: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: not a regular file", path.display()),
        ));
    }
    if meta.len() as usize != aska_core::profile::PROFILE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: not a profile ({} bytes, expected {})",
                path.display(),
                meta.len(),
                aska_core::profile::PROFILE_LEN
            ),
        ));
    }
    Ok(())
}

/// Read a profile file after `check_profile_path`, without following a symlink.
pub fn read_profile(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::OpenOptionsExt;
    check_profile_path(path)?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(aska_core::profile::PROFILE_LEN + 1));
    f.read_to_end(&mut buf)?;
    if buf.len() != aska_core::profile::PROFILE_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a profile"));
    }
    Ok(buf)
}

pub fn shred(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let len = std::fs::symlink_metadata(path)?.len() as usize;
    let mut f = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut noise = vec![0u8; len];
    getrandom_fill(&mut noise)?;
    f.write_all(&noise)?;
    f.sync_all()?;
    drop(f);
    std::fs::remove_file(path)
}

fn getrandom_fill(buf: &mut [u8]) -> io::Result<()> {
    use aska_core::rng::{OsRng, RandomSource};
    let r = OsRng
        .bytes(buf.len())
        .map_err(|_| io::Error::other("randomness unavailable"))?;
    buf.copy_from_slice(&r);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("aska-files-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join(name)
    }

    #[test]
    fn block_round_trip_and_no_overwrite() {
        let p = tmp("block.bin");
        let _ = std::fs::remove_file(&p);
        let label = [7u8; 32];
        let block = vec![1u8; SizeClass::C1.len()];
        write_block(&p, &label, &block).unwrap();
        assert!(
            write_block(&p, &label, &block).is_err(),
            "must not overwrite"
        );
        let (l, b) = read_block(&p).unwrap();
        assert_eq!(l, label);
        assert_eq!(b, block);
        assert!(read_bucket(&p).is_err());
        assert!(write_block(&tmp("bad.bin"), &label, &[0u8; 100]).is_err());
        shred(&p).unwrap();
        assert!(!p.exists());
    }

    #[test]
    fn bucket_round_trip() {
        let p = tmp("bucket.bin");
        let _ = std::fs::remove_file(&p);
        let recs: Vec<Record> = (0..3u8)
            .map(|i| ([i; 32], vec![i; SizeClass::C2.len()]))
            .collect();
        write_bucket(&p, 2, &recs).unwrap();
        let (c, got) = read_bucket(&p).unwrap();
        assert_eq!(c, 2);
        assert_eq!(got, recs);
        assert!(read_block(&p).is_err());
        assert!(
            write_bucket(&tmp("x.bin"), 1, &recs).is_err(),
            "class mismatch"
        );
        std::fs::remove_file(&p).unwrap();
    }
}
