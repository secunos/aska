//! Build fingerprint and release signature (Client Design §3 `fingerprint`, §9.2, §9.4;
//! CLI-10, OPS-03).
//!
//! A binary cannot carry its own hash, so a release carries three things instead: the
//! project's **minisign public key**, the **release tag** and (optionally) the **Rekor
//! transparency entry**, all embedded at release-build time through environment variables.
//! Next to the binary — in the unpacked tarball, or copied by `install.sh` into the user's
//! data directory — lie `SHA256SUMS` (the hashes of the release's binaries) and
//! `SHA256SUMS.minisig` (its minisign signature). `verify()` hashes the running executable,
//! finds those two files, checks the signature with the embedded key and checks that the
//! list names this very binary. Nothing is contacted: the Rekor entry is printed for the
//! user to look up with a browser of their choosing.
//!
//! The out-of-band fingerprint (spoken, on paper, in a Key Card) remains the first check
//! (§9.4). The embedded key can only tell a user that the binary and its signed hash list
//! belong together; it cannot tell them that the publisher is who they think, which is what
//! the out-of-band step is for.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Set by the release pipeline (`scripts/release.sh`): the minisign public key in its
/// one-line base64 form (the second line of `aska-release.pub`). Development builds have none.
pub const RELEASE_PUBKEY: Option<&str> = option_env!("ASKA_RELEASE_PUBKEY");
/// Set by the release pipeline: the git tag of the release, e.g. `v0.1.0-alpha`.
pub const RELEASE_TAG: Option<&str> = option_env!("ASKA_RELEASE_TAG");
/// Set by the release pipeline when the signed hash list was recorded in Rekor:
/// the entry's UUID or URL.
pub const REKOR_ENTRY: Option<&str> = option_env!("ASKA_REKOR_ENTRY");

/// What the signature check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// No release key is embedded: a development build; nothing can be checked.
    NoKey,
    /// A key is embedded but no `SHA256SUMS` + `SHA256SUMS.minisig` pair was found in any of
    /// the places looked at.
    NotFound { looked_in: Vec<PathBuf> },
    /// The signature over `SHA256SUMS` is not by the embedded key, or the file was altered.
    Invalid { file: PathBuf, reason: String },
    /// The signature is valid. `lists_this_binary` says whether `SHA256SUMS` names the hash
    /// of the running executable — a valid signature over a list that does *not* include this
    /// binary means the binary is not the one that was signed.
    Valid {
        file: PathBuf,
        key_id: String,
        trusted_comment: String,
        lists_this_binary: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// SHA-256 of `/proc/self/exe`, lowercase hex; `None` if it could not be read.
    pub own_sha256: Option<String>,
    pub release_tag: Option<String>,
    pub rekor_entry: Option<String>,
    pub signature: Signature,
}

impl Fingerprint {
    /// `Some(true)` = signed release and this binary is in the signed list; `Some(false)` =
    /// a key is embedded but the check failed or found a list without this binary;
    /// `None` = nothing to check against (development build, or no signed list found).
    pub fn verified(&self) -> Option<bool> {
        match &self.signature {
            Signature::NoKey | Signature::NotFound { .. } => None,
            Signature::Invalid { .. } => Some(false),
            Signature::Valid {
                lists_this_binary, ..
            } => Some(*lists_this_binary),
        }
    }
}

/// Hash the running executable.
pub fn own_sha256() -> Option<String> {
    let bytes = std::fs::read("/proc/self/exe").ok()?;
    Some(data_encoding::HEXLOWER.encode(&Sha256::digest(&bytes)))
}

/// Where a signed hash list may lie: beside the binary, one directory up (the tarball
/// layout `bin/aska` with `SHA256SUMS` at the top), and the user's data directory, where
/// `install.sh` copies the two files.
pub fn candidate_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(exe) = std::fs::read_link("/proc/self/exe") {
        if let Some(d) = exe.parent() {
            v.push(d.to_path_buf());
            if let Some(p) = d.parent() {
                v.push(p.to_path_buf());
            }
        }
    }
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")));
    if let Some(d) = data {
        v.push(d.join("aska"));
    }
    v
}

/// Verify `SHA256SUMS.minisig` over `SHA256SUMS` with `pubkey` (minisign's one-line base64
/// public key) and report whether the list names `own` (lowercase hex).
pub fn verify_sums(
    pubkey: &str,
    sums: &[u8],
    sig: &str,
    own: Option<&str>,
    file: &Path,
) -> Signature {
    let pk = match minisign_verify::PublicKey::from_base64(pubkey.trim()) {
        Ok(pk) => pk,
        Err(e) => {
            return Signature::Invalid {
                file: file.to_path_buf(),
                reason: format!("embedded public key unusable: {e}"),
            }
        }
    };
    let signature = match minisign_verify::Signature::decode(sig) {
        Ok(s) => s,
        Err(e) => {
            return Signature::Invalid {
                file: file.to_path_buf(),
                reason: format!("signature file unreadable: {e}"),
            }
        }
    };
    if let Err(e) = pk.verify(sums, &signature, false) {
        return Signature::Invalid {
            file: file.to_path_buf(),
            reason: e.to_string(),
        };
    }
    let text = String::from_utf8_lossy(sums);
    let lists_this_binary = own.is_some_and(|o| {
        text.lines().any(|l| {
            l.split_whitespace()
                .next()
                .is_some_and(|h| h.eq_ignore_ascii_case(o))
        })
    });
    let key_id = key_id_of(pubkey).unwrap_or_default();
    Signature::Valid {
        file: file.to_path_buf(),
        key_id,
        trusted_comment: signature.trusted_comment().to_string(),
        lists_this_binary,
    }
}

/// The 64-bit key id minisign prints for a public key (bytes 2..10 of the decoded key,
/// little-endian, shown as 16 upper-case hex digits).
pub fn key_id_of(pubkey_b64: &str) -> Option<String> {
    let raw = data_encoding::BASE64
        .decode(pubkey_b64.trim().as_bytes())
        .ok()?;
    let id = raw.get(2..10)?;
    let mut be = id.to_vec();
    be.reverse();
    // minisign prints the id as an unpadded hexadecimal number.
    let hex = data_encoding::HEXUPPER.encode(&be);
    let trimmed = hex.trim_start_matches('0');
    Some(if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.into()
    })
}

/// Look for a signed hash list in `dirs` and check it against `pubkey` and `own`.
pub fn find_and_verify(pubkey: &str, own: Option<&str>, dirs: &[PathBuf]) -> Signature {
    for d in dirs {
        let sums = d.join("SHA256SUMS");
        let sig = d.join("SHA256SUMS.minisig");
        if let (Ok(s), Ok(g)) = (std::fs::read(&sums), std::fs::read_to_string(&sig)) {
            return verify_sums(pubkey, &s, &g, own, &sums);
        }
    }
    Signature::NotFound {
        looked_in: dirs.to_vec(),
    }
}

/// Hash the running binary and check it against the signed release list, if any.
pub fn check() -> Fingerprint {
    let own = own_sha256();
    let signature = match RELEASE_PUBKEY {
        None => Signature::NoKey,
        Some(pk) => find_and_verify(pk, own.as_deref(), &candidate_dirs()),
    };
    Fingerprint {
        own_sha256: own,
        release_tag: RELEASE_TAG.map(|s| s.trim().to_string()),
        rekor_entry: REKOR_ENTRY.map(|s| s.trim().to_string()),
        signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throw-away minisign key pair made for this test (`minisign -G -W`), a hash list and
    // its signature (`minisign -S -W -t "aska test"`). Not a release key.
    const PUB: &str = "RWR+yYuD6raIQfFoZbH4AKO6iFtxAgfQljfbhaiiW2ryb69EINpequqr";
    const SUMS: &[u8] = b"abc\n";
    const SIG: &str = "untrusted comment: signature from minisign secret key\n\
RUR+yYuD6raIQfUSPjE7FaNfQ4tuHpIcZNmUIBmnMyJMztfYQKt4f5toFskXXGe0in2WLoGuj5ETetvmHFuVtjElFQQZ0BPOcwg=\n\
trusted comment: aska test\n\
aTvCIRRy58d0b4C1dG6btR7OzZiL/HkTZTqqlpcgTA2BmPIO3W82kECUOSU2Pap/pLGs1NdKuSBWlp9kFyt4Ag==\n";

    #[test]
    fn own_hash_is_stable_hex() {
        let a = own_sha256().unwrap();
        assert_eq!(a, own_sha256().unwrap());
        assert_eq!(a.len(), 64);
        let fp = check();
        assert_eq!(fp.signature == Signature::NoKey, RELEASE_PUBKEY.is_none());
    }

    #[test]
    fn minisign_vector_verifies_and_binds_to_the_listed_hash() {
        let f = Path::new("/x/SHA256SUMS");
        match verify_sums(PUB, SUMS, SIG, Some("abc"), f) {
            Signature::Valid {
                key_id,
                trusted_comment,
                lists_this_binary,
                ..
            } => {
                assert_eq!(key_id, "4188B6EA838BC97E");
                assert_eq!(trusted_comment, "aska test");
                assert!(lists_this_binary);
            }
            other => panic!("{other:?}"),
        }
        // Same signature, a binary that is not in the list.
        assert!(matches!(
            verify_sums(PUB, SUMS, SIG, Some("def"), f),
            Signature::Valid {
                lists_this_binary: false,
                ..
            }
        ));
        // A tampered list.
        assert!(matches!(
            verify_sums(PUB, b"abd\n", SIG, Some("abd"), f),
            Signature::Invalid { .. }
        ));
        // Another key.
        let other = "RWTnZ2bQb0J2Q3Z2bQb0J2Q3Z2bQb0J2Q3Z2bQb0J2Q3Z2bQb0J2Q3Z2";
        assert!(matches!(
            verify_sums(other, SUMS, SIG, Some("abc"), f),
            Signature::Invalid { .. }
        ));
    }

    #[test]
    fn find_and_verify_walks_the_directories() {
        let dir = std::env::temp_dir().join(format!("aska-fp-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let empty = dir.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(matches!(
            find_and_verify(PUB, Some("abc"), std::slice::from_ref(&empty)),
            Signature::NotFound { .. }
        ));
        std::fs::write(dir.join("SHA256SUMS"), SUMS).unwrap();
        std::fs::write(dir.join("SHA256SUMS.minisig"), SIG).unwrap();
        assert_eq!(
            key_id_of("RWT5V2GGmsRQCt66f8aUKnB47taXLIaqcP34+6AP903mV02KMG1qhFAh").as_deref(),
            Some("A50C49A866157F9")
        );
        assert!(matches!(
            find_and_verify(PUB, Some("abc"), &[empty, dir.clone()]),
            Signature::Valid {
                lists_this_binary: true,
                ..
            }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
