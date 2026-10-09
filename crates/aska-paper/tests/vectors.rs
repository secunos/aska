//! Reproduce every vector in `reference/tv_paper.json` (DC-04): the checkerboard, the pad,
//! both tags, the canonical page string and its checksum, the Block-card framing and the
//! Toeplitz convention — so the Rust crate and the Python reference agree byte for byte.

use aska_paper::cards::{split_block, Accepted, CardSet};
use aska_paper::entropy::toeplitz;
use aska_paper::page::{Direction, Page, PageSpec};
use aska_paper::{checkerboard, devtag, handtag, pad, LockedBuf};
use serde::Deserialize;

#[derive(Deserialize)]
struct Doc {
    page: PageVec,
    vectors: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct PageVec {
    set_code: u16,
    direction: String,
    number: u8,
    pad: String,
    hand_keys: Vec<u64>,
    r: u64,
    s: u64,
    canonical: String,
    checksum: String,
    pad_row_checks: Vec<u8>,
}

fn load() -> Doc {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/tv_paper.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("reference/tv_paper.json present"))
        .expect("valid json")
}

fn keys_bytes(keys: &[u64]) -> Vec<u8> {
    keys.iter()
        .flat_map(|k| format!("{k:04}").into_bytes())
        .collect()
}

fn dir(s: &str) -> Direction {
    match s {
        "A" => Direction::A,
        "B" => Direction::B,
        _ => panic!("direction"),
    }
}

#[test]
fn page_and_message_vectors() {
    let doc = load();
    let pv = &doc.page;
    let spec = PageSpec {
        set_code: pv.set_code,
        direction: dir(&pv.direction),
        number: pv.number,
        pad_len: pv.pad.len(),
        hand_tag: true,
    };
    let page = Page::assemble(
        spec,
        pv.pad.as_bytes(),
        &keys_bytes(&pv.hand_keys),
        pv.r,
        pv.s,
    )
    .unwrap();
    assert_eq!(page.canonical(), pv.canonical.as_bytes());
    assert_eq!(&page.checksum()[..], pv.checksum.as_bytes());
    let checks: Vec<u8> = page.pad_rows().map(|(_, _, c)| c).collect();
    assert_eq!(checks, pv.pad_row_checks);
    let parsed = Page::parse_with_checksum(page.qr_payload().as_slice()).unwrap();
    assert_eq!(parsed.canonical(), page.canonical());

    for v in doc.vectors.iter().filter(|v| v["page"] == "P") {
        let text = v["text"].as_str().unwrap();
        let m = checkerboard::encode(text).unwrap();
        assert_eq!(
            m.as_slice(),
            v["digits"].as_str().unwrap().as_bytes(),
            "{}",
            v["id"]
        );
        let c = pad::encipher(m.as_slice(), page.pad()).unwrap();
        assert_eq!(c.as_slice(), v["cipher"].as_str().unwrap().as_bytes());
        let ht = page.hand_tag(c.as_slice()).unwrap();
        assert_eq!(format!("{ht:04}"), v["hand_tag"].as_str().unwrap());
        let dt = page.device_tag(c.as_slice()).unwrap();
        assert_eq!(format!("{dt:019}"), v["device_tag"].as_str().unwrap());
        let keys = page.hand_keys().unwrap();
        handtag::verify(
            c.as_slice(),
            &keys,
            v["hand_tag"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
        let (r, s) = page.device_keys();
        devtag::verify(
            c.as_slice(),
            r,
            s,
            v["device_tag"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
        let back = pad::decipher(c.as_slice(), page.pad()).unwrap();
        assert_eq!(
            checkerboard::from_digits(back.as_slice())
                .unwrap()
                .as_slice(),
            text.as_bytes()
        );
    }
}

#[test]
fn example60_vector_and_cover_pad() {
    let doc = load();
    let v = doc.vectors.iter().find(|v| v["id"] == "TV-P4").unwrap();
    let pad60 = v["pad"].as_str().unwrap().as_bytes();
    let m = checkerboard::encode(v["text"].as_str().unwrap()).unwrap();
    let c = pad::encipher(m.as_slice(), pad60).unwrap();
    assert_eq!(c.as_slice(), v["cipher"].as_str().unwrap().as_bytes());
    let a: Vec<u64> = v["a"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap())
        .collect();
    let mult = keys_bytes(&a);
    let off = format!("{:04}", v["b"].as_u64().unwrap()).into_bytes();
    let keys = handtag::HandKeys {
        multipliers: &mult,
        offset: &off,
    };
    assert_eq!(
        format!("{:04}", handtag::compute(c.as_slice(), &keys).unwrap()),
        v["hand_tag"]
    );
    let dt = devtag::compute(
        c.as_slice(),
        v["r"].as_u64().unwrap(),
        v["s"].as_u64().unwrap(),
    )
    .unwrap();
    assert_eq!(format!("{dt:019}"), v["device_tag"]);
    let inn = checkerboard::encode(v["cover_text"].as_str().unwrap()).unwrap();
    let cover = pad::cover_pad(c.as_slice(), inn.as_slice()).unwrap();
    assert_eq!(
        cover.as_slice(),
        v["cover_pad"].as_str().unwrap().as_bytes()
    );
}

#[test]
fn page_without_hand_keys_vector() {
    let doc = load();
    let v = doc.vectors.iter().find(|v| v["id"] == "TV-P5").unwrap();
    let spec = PageSpec {
        set_code: v["set_code"].as_u64().unwrap() as u16,
        direction: dir(v["direction"].as_str().unwrap()),
        number: v["number"].as_u64().unwrap() as u8,
        pad_len: 200,
        hand_tag: false,
    };
    let page = Page::assemble(
        spec,
        v["pad"].as_str().unwrap().as_bytes(),
        &[],
        v["r"].as_u64().unwrap(),
        v["s"].as_u64().unwrap(),
    )
    .unwrap();
    assert_eq!(
        page.canonical(),
        v["canonical"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        page.qr_payload().as_slice(),
        v["qr_payload"].as_str().unwrap().as_bytes()
    );
    assert!(page.hand_keys().is_none());
}

#[test]
fn block_card_vector() {
    let doc = load();
    let v = doc.vectors.iter().find(|v| v["id"] == "TV-P6").unwrap();
    let block = hex(v["block_hex"].as_str().unwrap());
    let cards: Vec<Vec<u8>> = v["cards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| hex(c.as_str().unwrap()))
        .collect();
    // The reference's cards reassemble in Rust (any order).
    let mut set = CardSet::new();
    for c in cards.iter().rev() {
        let r = set.accept(c).unwrap();
        assert!(matches!(r, Accepted::Added { .. } | Accepted::Complete));
    }
    assert_eq!(set.block().unwrap().as_slice(), &block[..]);
    // Rust's own split (random set id) has the same shape and reassembles too.
    let ours = split_block(&block).unwrap();
    assert_eq!(ours.len(), cards.len());
    assert_eq!(ours[0].len(), cards[0].len());
    assert_eq!(&ours[1][4..7], &cards[1][4..7]); // index, count, class
    assert_eq!(&ours[1][7..7 + 1024], &cards[1][7..7 + 1024]);
}

#[test]
fn toeplitz_convention_vector() {
    let doc = load();
    let v = doc.vectors.iter().find(|v| v["id"] == "TV-P7").unwrap();
    let seed = hex(v["seed_hex"].as_str().unwrap());
    let input = hex(v["input_hex"].as_str().unwrap());
    let m = v["m"].as_u64().unwrap() as usize;
    let mut out = LockedBuf::with_capacity(16);
    toeplitz::extract(&seed, &input, m, &mut out);
    assert_eq!(out.as_slice(), &hex(v["output_hex"].as_str().unwrap())[..]);
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
