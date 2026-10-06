//! Property-style tests (Client Design §10): random round trips, tamper → no plaintext,
//! Shares any-k reconstruct / any-(k−1) fail, encodings round-trip, distinct-key rule.

use aska_core::block::{open, seal, Slot};
use aska_core::consts::*;
use aska_core::encodings::*;
use aska_core::kdf::KdfProfile;
use aska_core::keys::Root;
use aska_core::rng::{OsRng, RandomSource, TestRng};
use aska_core::shares::{combine, split, Share};
use aska_core::Error;

fn rnd(n: usize) -> Vec<u8> {
    OsRng.bytes(n).unwrap()
}
const P2: [KdfProfile; 1] = [KdfProfile::P2];
const P1: [KdfProfile; 1] = [KdfProfile::P1];

#[test]
fn roundtrip_all_classes_random_content() {
    let mut rng = OsRng;
    for class in SizeClass::ALL {
        for _ in 0..3 {
            let r = Root::generate(&mut rng).unwrap();
            let n =
                (u32::from_be_bytes(rng.array().unwrap()) as usize) % (class.max_note_len() / 2);
            let data = rnd(n);
            // use P2 (64 MiB) for speed in property tests where the passphrase is set
            let blk = seal(
                &r,
                class,
                &[Slot::text(&data, Some(b"pw")).profile(KdfProfile::P2)],
                &mut rng,
                None,
                None,
            )
            .unwrap();
            assert_eq!(blk.len(), class.len());
            assert_eq!(open(&blk, &r, Some(b"pw"), &P2).unwrap().data, data);
            assert!(matches!(
                open(&blk, &r, Some(b"wrong"), &P2),
                Err(Error::NoSlot)
            ));
            assert!(matches!(open(&blk, &r, None, &P1), Err(Error::NoSlot)));
        }
    }
}

#[test]
fn max_note_fits_and_one_more_does_not() {
    let r = Root::from_bytes([7u8; 32]);
    for class in SizeClass::ALL {
        let m = class.max_note_len();
        let blk = seal(
            &r,
            class,
            &[Slot::text(&vec![b'a'; m], None)],
            &mut TestRng::new(b"m"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(open(&blk, &r, None, &P1).unwrap().data.len(), m);
        assert_eq!(
            seal(
                &r,
                class,
                &[Slot::text(&vec![b'a'; m + 1], None)],
                &mut TestRng::new(b"m"),
                None,
                None
            )
            .unwrap_err(),
            Error::TooLarge
        );
    }
}

#[test]
fn tamper_anywhere_never_yields_wrong_plaintext() {
    let r = Root::from_bytes([1u8; 32]);
    let data = rnd(300);
    let blk = seal(
        &r,
        SizeClass::C1,
        &[Slot::text(&data, None)],
        &mut TestRng::new(b"t"),
        None,
        None,
    )
    .unwrap();
    for _ in 0..200 {
        let pos = (u32::from_be_bytes(OsRng.array().unwrap()) as usize) % blk.len();
        let mut t = blk.clone();
        t[pos] ^= 1 << (pos % 8);
        if let Ok(o) = open(&t, &r, None, &P1) {
            assert_eq!(
                o.data, data,
                "bit flip at {pos} must be in unused bytes if it still opens"
            );
        }
    }
}

#[test]
fn distinct_slot_keys_and_single_distress_enforced() {
    let r = Root::from_bytes([2u8; 32]);
    let mut rng = TestRng::new(b"d");
    let dup = [
        Slot::text(b"a", Some(b"x")).profile(KdfProfile::P2),
        Slot::text(b"b", Some(b"x")).profile(KdfProfile::P2),
    ];
    assert_eq!(
        seal(&r, SizeClass::C1, &dup, &mut rng, None, None).unwrap_err(),
        Error::BadSlots
    );
    let two_open = [Slot::text(b"a", None), Slot::text(b"b", None)];
    assert_eq!(
        seal(&r, SizeClass::C1, &two_open, &mut rng, None, None).unwrap_err(),
        Error::BadSlots
    );
    let two_distress = [
        Slot::text(b"a", Some(b"x"))
            .profile(KdfProfile::P2)
            .distress(),
        Slot::text(b"b", Some(b"y"))
            .profile(KdfProfile::P2)
            .distress(),
    ];
    assert_eq!(
        seal(&r, SizeClass::C1, &two_distress, &mut rng, None, None).unwrap_err(),
        Error::BadSlots
    );
    // same passphrase, different profile is allowed (different slot key)
    let diff_prof = [
        Slot::text(b"a", Some(b"x")).profile(KdfProfile::P1),
        Slot::text(b"b", Some(b"x")).profile(KdfProfile::P2),
    ];
    let blk = seal(&r, SizeClass::C1, &diff_prof, &mut rng, None, None).unwrap();
    assert_eq!(open(&blk, &r, Some(b"x"), &P1).unwrap().data, b"a");
    assert_eq!(open(&blk, &r, Some(b"x"), &P2).unwrap().data, b"b");
}

#[test]
fn byte_distribution_smoke() {
    // chi-square over byte values of a full 64 KiB Block should be unremarkable (255 dof; reject > 340)
    let r = Root::from_bytes([3u8; 32]);
    let blk = seal(
        &r,
        SizeClass::C3,
        &[
            Slot::text(&vec![b'n'; 4000], None),
            Slot::text(b"decoy", Some(b"p")).profile(KdfProfile::P2),
        ],
        &mut OsRng,
        None,
        None,
    )
    .unwrap();
    let mut counts = [0f64; 256];
    for b in &blk {
        counts[*b as usize] += 1.0;
    }
    let exp = blk.len() as f64 / 256.0;
    let chi: f64 = counts.iter().map(|c| (c - exp).powi(2) / exp).sum();
    assert!(chi < 340.0, "chi-square {chi}");
}

#[test]
fn shares_any_k_reconstruct_any_k_minus_1_fail() {
    let mut rng = OsRng;
    for (k, n) in [(2u8, 3u8), (3, 5)] {
        let r = Root::generate(&mut rng).unwrap();
        let sh = split(&r, k, n, &mut rng).unwrap();
        // all k-subsets
        let idx: Vec<usize> = (0..n as usize).collect();
        for combo in k_subsets(&idx, k as usize) {
            let subset: Vec<Share> = combo
                .iter()
                .map(|&i| Share::from_bytes(&sh[i].to_bytes()[..]).unwrap())
                .collect();
            assert!(combine(&subset).unwrap().ct_eq(&r));
        }
        let fewer: Vec<Share> = (0..k as usize - 1)
            .map(|i| Share::from_bytes(&sh[i].to_bytes()[..]).unwrap())
            .collect();
        assert_eq!(combine(&fewer).unwrap_err(), Error::ShareSet);
        // forged share detected
        let mut bad = Share::from_bytes(&sh[0].to_bytes()[..]).unwrap();
        bad.y[5] ^= 1;
        let mut set: Vec<Share> = vec![bad];
        set.extend((1..k as usize).map(|i| Share::from_bytes(&sh[i].to_bytes()[..]).unwrap()));
        assert_eq!(combine(&set).unwrap_err(), Error::ShareVerify);
        // foreign share rejected
        let other = split(&Root::generate(&mut rng).unwrap(), k, n, &mut rng).unwrap();
        let mut mixed: Vec<Share> = vec![Share::from_bytes(&sh[0].to_bytes()[..]).unwrap()];
        mixed.extend((1..k as usize).map(|i| Share::from_bytes(&other[i].to_bytes()[..]).unwrap()));
        assert_eq!(combine(&mixed).unwrap_err(), Error::ShareSet);
        // text round trip
        for s in &sh {
            assert_eq!(share_decode(&share_encode(s).unwrap()).unwrap(), *s);
        }
    }
}

fn k_subsets(items: &[usize], k: usize) -> Vec<Vec<usize>> {
    if k == 0 {
        return vec![vec![]];
    }
    if items.len() < k {
        return vec![];
    }
    let mut out = k_subsets(&items[1..], k - 1)
        .into_iter()
        .map(|mut v| {
            v.insert(0, items[0]);
            v
        })
        .collect::<Vec<_>>();
    out.extend(k_subsets(&items[1..], k));
    out
}

#[test]
fn words_and_keycard_roundtrip_and_reject() {
    let r = Root::generate(&mut OsRng).unwrap();
    let w = r.to_words();
    assert_eq!(w.split_whitespace().count(), 24);
    assert!(Root::from_words(&w.to_uppercase()).unwrap().ct_eq(&r));
    let mut bad: Vec<&str> = w.split(' ').collect();
    bad[0] = if bad[0] == "zoo" { "zone" } else { "zoo" };
    assert!(Root::from_words(&bad.join(" ")).is_err());

    let mut kc = KeyCard::new(Root::from_bytes(*r.as_bytes()));
    kc.auth_key = Some([9u8; 32]);
    let s = kc.encode().unwrap();
    let back = KeyCard::decode(&s).unwrap();
    assert_eq!(back.auth_key, Some([9u8; 32]));
    let mut mixed = s.clone();
    mixed.replace_range(0..1, "A");
    assert!(
        KeyCard::decode(&mixed).is_err(),
        "mixed case must be rejected"
    );
    // bech32m checksum: BIP-350 vector
    assert_eq!(
        bech32m_decode("A1LQFN3A").unwrap(),
        ("a".to_string(), zeroize::Zeroizing::new(vec![]))
    );
    assert_eq!(bech32m_encode("a", &[]).unwrap().as_str(), "a1lqfn3a");
}

#[test]
fn onion_address_roundtrip() {
    let a = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
    let pk = onion_address_to_pubkey(a).unwrap();
    assert_eq!(onion_pubkey_to_address(&pk), a);
    assert!(onion_address_to_pubkey("notanonion.onion").is_err());
}

#[test]
fn deterministic_rng_reproduces() {
    let r = Root::from_bytes([4u8; 32]);
    let a = seal(
        &r,
        SizeClass::C1,
        &[Slot::text(b"same", None)],
        &mut TestRng::new(b"seed"),
        None,
        None,
    )
    .unwrap();
    let b = seal(
        &r,
        SizeClass::C1,
        &[Slot::text(b"same", None)],
        &mut TestRng::new(b"seed"),
        None,
        None,
    )
    .unwrap();
    assert_eq!(a, b);
    let c = seal(
        &r,
        SizeClass::C1,
        &[Slot::text(b"same", None)],
        &mut OsRng,
        None,
        None,
    )
    .unwrap();
    assert_ne!(a, c);
}

/// §10.3 (review finding A-1): the header index of the sender's first slot is a uniform random
/// position, so opening a decoy proves nothing about a real slot's existence from its index.
#[test]
fn header_index_does_not_reveal_slot_order() {
    let mut rng = OsRng;
    let mut seen_index = [0usize; N_SLOTS];
    const N: usize = 60;
    for _ in 0..N {
        let r = Root::generate(&mut rng).unwrap();
        let slots = vec![
            Slot::text(b"real", None),
            Slot::text(b"decoy", Some(b"south")).profile(KdfProfile::P2),
        ];
        let blk = seal(&r, SizeClass::C1, &slots, &mut rng, None, None).unwrap();
        let real = open(&blk, &r, None, &P2).unwrap();
        let decoy = open(&blk, &r, Some(b"south"), &P2).unwrap();
        assert_eq!(real.data, b"real");
        assert_eq!(decoy.data, b"decoy");
        assert_ne!(real.index, decoy.index);
        seen_index[real.index as usize] += 1;
    }
    // Every header index is used by the real slot sometimes (P(any miss) ≈ 4·(3/4)^60 ≈ 1e-7)
    // and none dominates (each ≈ 15 of 60).
    assert!(
        seen_index.iter().all(|&c| (1..=40).contains(&c)),
        "{seen_index:?}"
    );
}
