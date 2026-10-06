//! The receiving-key path (Block Format §6.5 as made normative by DC-02; decision D-17):
//! X-Wing — ML-KEM-768 (FIPS 203) combined with X25519 through SHA3-256, exactly as in
//! *draft-connolly-cfrg-xwing-kem-11* — with Aska's one deviation on the wire: the X25519
//! half of the ciphertext is written as an **Elligator2 representative of a torsion-dirty
//! point** (DC-02 §2.2), so that a KEM-path Block's KEM region is uniform bytes like the
//! random fill of a symmetric-path Block.
//!
//! The 32-byte decapsulation key is the **receiving seed** the user keeps as 24 words; every
//! other key is re-derived from it here, used, and dropped.
//!
//! Composed from the RustCrypto `ml-kem` crate, `x25519-dalek` and `sha3` rather than an
//! X-Wing crate because the ephemeral X25519 key must be Aska's to choose (rejection-sampled
//! for representability). Test vector 1 of draft-11 is reproduced in the tests.

use crate::consts::{INFO_ROOT_FROM_KEM, KEM_LEN};
use crate::error::Error;
use crate::kdf::hkdf_sha512;
use crate::keys::Root;
use crate::rng::{OsRng, RandomSource};
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// X-Wing encapsulation (public) key: `pk_M ‖ pk_X`.
pub const PK_LEN: usize = 1184 + 32;
/// ML-KEM-768 ciphertext length; the X25519 half fills the rest of the KEM region.
pub const CT_M_LEN: usize = 1088;
/// The receiving seed (= X-Wing decapsulation key).
pub const SEED_LEN: usize = 32;
/// `XWingLabel` (draft-11 §5.3): `\.//^\`.
const LABEL: &[u8; 6] = b"\\.//^\\";

/// A 32-byte shared secret, zeroised on drop.
pub type SharedSecret = Zeroizing<[u8; 32]>;
/// The Block's KEM region: `ct_M ‖ rep_X`.
pub type KemRegion = Zeroizing<[u8; KEM_LEN]>;
/// Standard X-Wing output for the test vectors: `(ss, ct_M, ct_X)`.
pub type StandardEncaps = (SharedSecret, [u8; CT_M_LEN], [u8; 32]);

const _: () = assert!(CT_M_LEN + 32 == KEM_LEN);

/// A receiving key pair derived from a seed. Secrets zeroise on drop.
pub struct Expanded {
    dk_m: DecapsulationKey<MlKem768>,
    sk_x: StaticSecret,
    pk_x: PublicKey,
}

impl std::fmt::Debug for Expanded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Expanded(<redacted>)")
    }
}

impl Expanded {
    /// `expandDecapsulationKey(sk)` (draft-11 §5.2).
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let mut h = Shake256::default();
        h.update(seed);
        let mut out = Zeroizing::new([0u8; 96]);
        h.finalize_xof().read(&mut out[..]);
        let mut seed_m = Zeroizing::new([0u8; 64]);
        seed_m.copy_from_slice(&out[..64]);
        let mut sk_x = Zeroizing::new([0u8; 32]);
        sk_x.copy_from_slice(&out[64..]);
        let dk_m = DecapsulationKey::<MlKem768>::from_seed((*seed_m).into());
        let sk_x = StaticSecret::from(*sk_x);
        let pk_x = PublicKey::from(&sk_x);
        Expanded { dk_m, sk_x, pk_x }
    }

    /// The public encapsulation key `pk_M ‖ pk_X` (1 216 bytes).
    pub fn public_key(&self) -> Box<[u8; PK_LEN]> {
        let mut pk = Box::new([0u8; PK_LEN]);
        pk[..1184].copy_from_slice(&self.dk_m.encapsulation_key().to_bytes());
        pk[1184..].copy_from_slice(self.pk_x.as_bytes());
        pk
    }

    /// Decapsulate a KEM region (`ct_M ‖ rep_X`) to the shared secret. Total: any 1 120
    /// bytes decapsulate to *some* value (ML-KEM's implicit rejection, Elligator2's total
    /// inverse map), so a symmetric-path Block simply yields a secret that matches nothing.
    /// The work is the same for every input.
    pub fn decapsulate(&self, region: &[u8; KEM_LEN]) -> Zeroizing<[u8; 32]> {
        let ct_m = ml_kem::kem::Ciphertext::<MlKem768>::from(
            <[u8; CT_M_LEN]>::try_from(&region[..CT_M_LEN]).expect("length fixed"),
        );
        let rep: [u8; 32] = region[CT_M_LEN..].try_into().expect("length fixed");
        let ct_x = elligator2::from_representative(&rep);
        let ss_m = self.dk_m.decapsulate(&ct_m);
        let ss_x = self.sk_x.diffie_hellman(&PublicKey::from(ct_x));
        combiner(&ss_m, ss_x.as_bytes(), &ct_x, self.pk_x.as_bytes())
    }
}

/// `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)`.
fn combiner(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, LABEL);
    Zeroizing::new(h.finalize().into())
}

/// The OS CSPRNG as the `rand_core` 0.10 generator `elligator2::generate` wants. A failure
/// of the OS source cannot be returned through that interface, so it is remembered and
/// reported by the caller as `Error::Rng`.
struct Rng10 {
    failed: bool,
}

impl rand_core10::TryRng for Rng10 {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        if OsRng.fill(dst).is_err() {
            self.failed = true;
            dst.fill(0);
        }
        Ok(())
    }
}
impl rand_core10::TryCryptoRng for Rng10 {}

/// Encapsulate to a Receiving Key: returns the shared secret and the Block's KEM region
/// `ct_M ‖ rep_X` (DC-02 §2.2: the X25519 half as an Elligator2 representative of a
/// torsion-dirty point, high bits randomised; the dirty point's u-coordinate is what enters
/// the combiner and the DH on both sides).
/// Validate a Receiving Key's public half before anything is composed (§6.1.1 step 1; review
/// finding B-6): the ML-KEM encapsulation key must pass the FIPS 203 modulus check and the
/// X25519 half must not be a low-order or identity point (which would make `ss_X` constant).
pub fn validate_public_key(pk: &[u8; PK_LEN]) -> Result<(), Error> {
    EncapsulationKey::<MlKem768>::new(
        &<[u8; 1184]>::try_from(&pk[..1184])
            .expect("length fixed")
            .into(),
    )
    .map_err(|_| Error::Encoding)?;
    let pk_x: [u8; 32] = pk[1184..].try_into().expect("length fixed");
    // Probe with a fixed non-zero scalar: a low-order public point yields the all-zero
    // shared secret, which x25519-dalek flags as non-contributory.
    let probe = StaticSecret::from([0x5a; 32]);
    let ss = probe.diffie_hellman(&PublicKey::from(pk_x));
    if !ss.was_contributory() {
        return Err(Error::Encoding);
    }
    Ok(())
}

pub fn encapsulate(pk: &[u8; PK_LEN]) -> Result<(SharedSecret, KemRegion), Error> {
    let ek = EncapsulationKey::<MlKem768>::new(
        &<[u8; 1184]>::try_from(&pk[..1184])
            .expect("length fixed")
            .into(),
    )
    .map_err(|_| Error::Encoding)?;
    let pk_x = PublicKey::from(<[u8; 32]>::try_from(&pk[1184..]).expect("length fixed"));
    // ML-KEM half: fresh 32 bytes of randomness for Encaps (FIPS 203 Algorithm 20).
    let m: Zeroizing<[u8; 32]> = Zeroizing::new(OsRng.array()?);
    let (ct_m, ss_m) = ek.encapsulate_deterministic(&(*m).into());
    // X25519 half: rejection-sampled representable dirty point.
    let mut rng = Rng10 { failed: false };
    let hidden = elligator2::generate(&mut rng).ok_or(Error::Rng)?;
    if rng.failed {
        return Err(Error::Rng);
    }
    let ct_x: [u8; 32] = *hidden.point();
    let ss_x = StaticSecret::from(*hidden.secret_bytes()).diffie_hellman(&pk_x);
    let ss = combiner(&ss_m, ss_x.as_bytes(), &ct_x, pk_x.as_bytes());
    let mut region = Zeroizing::new([0u8; KEM_LEN]);
    region[..CT_M_LEN].copy_from_slice(&ct_m);
    region[CT_M_LEN..].copy_from_slice(hidden.representative());
    Ok((ss, region))
}

/// Standard X-Wing `EncapsulateDerand` (clean `ct_X`, no Elligator2) — for the draft's test
/// vectors only. Returns `(ss, ct_M, ct_X)`.
#[doc(hidden)]
pub fn encapsulate_derand_standard(
    pk: &[u8; PK_LEN],
    eseed: &[u8; 64],
) -> Result<StandardEncaps, Error> {
    let ek = EncapsulationKey::<MlKem768>::new(
        &<[u8; 1184]>::try_from(&pk[..1184])
            .expect("length fixed")
            .into(),
    )
    .map_err(|_| Error::Encoding)?;
    let pk_x = PublicKey::from(<[u8; 32]>::try_from(&pk[1184..]).expect("length fixed"));
    let m: [u8; 32] = eseed[..32].try_into().expect("length fixed");
    let ek_x = StaticSecret::from(<[u8; 32]>::try_from(&eseed[32..]).expect("length fixed"));
    let ct_x = PublicKey::from(&ek_x);
    let ss_x = ek_x.diffie_hellman(&pk_x);
    let (ct_m, ss_m) = ek.encapsulate_deterministic(&m.into());
    let ss = combiner(&ss_m, ss_x.as_bytes(), ct_x.as_bytes(), pk_x.as_bytes());
    Ok((ss, ct_m.into(), *ct_x.as_bytes()))
}

/// `R = HKDF-SHA-512("", ss, "aska/v1/root-from-kem", 32)` (Block Format §6.5).
pub fn root_from_shared_secret(ss: &[u8; 32]) -> Root {
    let mut r = Zeroizing::new([0u8; 32]);
    hkdf_sha512(b"", ss, INFO_ROOT_FROM_KEM, &mut r[..]);
    let root = Root::from_bytes(*r);
    r.zeroize();
    root
}

/// A fresh receiving seed from the OS source.
pub fn generate_seed() -> Result<Zeroizing<[u8; SEED_LEN]>, Error> {
    Ok(Zeroizing::new(OsRng.array()?))
}

/// A fresh receiving seed as 24 words (the root's word encoding, §7.1 — same words, a
/// different key: the user keeps these instead of a note key).
pub fn new_seed_words() -> Result<Zeroizing<String>, Error> {
    let seed = generate_seed()?;
    let words = Root::from_bytes(*seed).to_words();
    crate::secret::scrub_stack();
    Ok(words)
}

/// The public Receiving Key for a seed given as 24 words, with the relay hints the receiver
/// will poll. Everything secret is derived, used and dropped inside.
pub fn receiving_key_from_words(
    words: &str,
    relays: &[[u8; 32]],
    size_class: Option<crate::consts::SizeClass>,
    ttl_hours: Option<u16>,
) -> Result<crate::encodings::ReceivingKey, Error> {
    let r = receiving_key_inner(words, relays, size_class, ttl_hours);
    crate::secret::scrub_stack();
    r
}

#[inline(never)]
fn receiving_key_inner(
    words: &str,
    relays: &[[u8; 32]],
    size_class: Option<crate::consts::SizeClass>,
    ttl_hours: Option<u16>,
) -> Result<crate::encodings::ReceivingKey, Error> {
    let seed = Root::from_words(words)?;
    let expanded = Expanded::from_seed(seed.as_bytes());
    let mut rk = crate::encodings::ReceivingKey::new(expanded.public_key());
    rk.relays = relays.to_vec();
    rk.size_class = size_class;
    rk.ttl_hours = ttl_hours;
    Ok(rk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    /// draft-connolly-cfrg-xwing-kem-11, test vector 1.
    #[test]
    fn draft11_vector_1() {
        let sk: [u8; 32] = hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
            .try_into()
            .unwrap();
        let eseed: [u8; 64] = hex("3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2").try_into().unwrap();
        let e = Expanded::from_seed(&sk);
        let pk = e.public_key();
        assert_eq!(&pk[..16], &hex("e2236b35a8c24b39b10aa1323a96a919")[..]);
        let (ss, ct_m, ct_x) = encapsulate_derand_standard(&pk, &eseed).unwrap();
        assert_eq!(&ct_m[..16], &hex("b83aa828d4d62b9a83ceffe1d3d3bb1e")[..]);
        assert_eq!(
            &ss[..],
            &hex("d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384")[..]
        );
        // Decapsulate the standard ciphertext by hand (clean ct_X goes straight in).
        let ss_m = e
            .dk_m
            .decapsulate(&ml_kem::kem::Ciphertext::<MlKem768>::from(ct_m));
        let ss_x = e.sk_x.diffie_hellman(&PublicKey::from(ct_x));
        let ss2 = combiner(&ss_m, ss_x.as_bytes(), &ct_x, e.pk_x.as_bytes());
        assert_eq!(&ss[..], &ss2[..]);
    }

    #[test]
    fn aska_path_round_trips_and_wrong_seed_does_not() {
        let seed = generate_seed().unwrap();
        let e = Expanded::from_seed(&seed);
        let pk = e.public_key();
        for _ in 0..8 {
            let (ss, region) = encapsulate(&pk).unwrap();
            assert_eq!(&e.decapsulate(&region)[..], &ss[..]);
            let other = Expanded::from_seed(&generate_seed().unwrap());
            assert_ne!(&other.decapsulate(&region)[..], &ss[..]);
            // A symmetric-path Block (random KEM region) decapsulates to *something*.
            let random: [u8; KEM_LEN] = OsRng.array().unwrap();
            let _ = e.decapsulate(&random);
            assert_ne!(
                root_from_shared_secret(&ss).as_bytes(),
                root_from_shared_secret(&e.decapsulate(&random)).as_bytes()
            );
        }
    }

    /// DC-02 §2.2 / gate (b): the X25519 half on the wire passes the quadratic-residuosity
    /// test about half the time, like random bytes — and its two high bits are not constant.
    #[test]
    fn representative_is_not_a_montgomery_u_fingerprint() {
        let seed = generate_seed().unwrap();
        let pk = Expanded::from_seed(&seed).public_key();
        let n = 400;
        let mut passes = 0;
        let mut high_bits = [0usize; 4];
        for _ in 0..n {
            let (_, region) = encapsulate(&pk).unwrap();
            let rep: [u8; 32] = region[CT_M_LEN..].try_into().unwrap();
            if elligator2::is_montgomery_u(&rep) {
                passes += 1;
            }
            high_bits[(rep[31] >> 6) as usize] += 1;
        }
        // Binomial(400, 1/2): 200 ± 10; six sigma is 60.
        assert!((140..=260).contains(&passes), "passes = {passes}");
        assert!(high_bits.iter().all(|&c| c > 40), "high bits {high_bits:?}");
    }
}
