//! Apply the deltas that `msdelta.dll` made, and compare with `GetDeltaInfoB`.
//!
//! `scripts/make-fixtures.py` made the deltas in `tests/fixtures/`. The generator in this file
//! makes the same sources and targets from the same seeds.

use msdelta::{DeltaHeader, ErrorKind};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

/// The `SplitMix64` generator, the same as in `scripts/make-fixtures.py`.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
}

const WORDS: [&[u8]; 16] = [
    b"the", b"delta", b"patch", b"source", b"target", b"window", b"huffman", b"rift", b"table",
    b"block", b"length", b"offset", b"match", b"literal", b"stream", b"buffer",
];

fn random_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut rng = Rng(seed);
    (0..n).map(|_| rng.byte()).collect()
}

fn text(seed: u64, n: usize) -> Vec<u8> {
    let mut rng = Rng(seed);
    let mut out = Vec::new();
    while out.len() < n {
        out.extend_from_slice(WORDS[rng.below(WORDS.len())]);
        out.push(if rng.below(8) == 0 { b'\n' } else { b' ' });
    }
    out.truncate(n);
    out
}

fn edit(seed: u64, base: &[u8], edits: usize) -> Vec<u8> {
    let mut rng = Rng(seed);
    let mut data = base.to_vec();
    for _ in 0..edits {
        let mut kind = rng.below(4);
        if data.is_empty() {
            kind = 1;
        }
        let pos = rng.below(data.len() + 1);
        let mut span = 1 + rng.below(64);
        match kind {
            0 => {
                for i in pos..(pos + span).min(data.len()) {
                    data[i] = rng.byte();
                }
            }
            1 => {
                let insert: Vec<u8> = (0..span).map(|_| rng.byte()).collect();
                data.splice(pos..pos, insert);
            }
            2 => {
                data.drain(pos..(pos + span).min(data.len()));
            }
            _ => {
                span = 1 + rng.below(4096);
                let end = (pos + span).min(data.len());
                let block: Vec<u8> = data.drain(pos..end).collect();
                let dest = rng.below(data.len() + 1);
                data.splice(dest..dest, block);
            }
        }
    }
    data
}

fn repeat(pattern: &[u8], n: usize) -> Vec<u8> {
    pattern.iter().copied().cycle().take(n).collect()
}

/// Return the source and the target of a case.
fn case(name: &str) -> (Vec<u8>, Vec<u8>) {
    let rnd = || random_bytes(3, 4096);
    match name {
        "empty-source-text" => (vec![], text(1, 3000)),
        "empty-source-random" => (vec![], random_bytes(2, 65536)),
        "empty-source-repeat" => (vec![], repeat(b"abcdefgh", 300_000)),
        "empty-target" => (rnd(), vec![]),
        "both-empty" => (vec![], vec![]),
        "identical" => (rnd(), rnd()),
        "small-edits" => (rnd(), edit(4, &rnd(), 8)),
        "text-edits" => (text(5, 20000), edit(6, &text(5, 20000), 40)),
        "large-moves" => {
            let big = text(7, 1 << 20);
            let target = edit(8, &big, 200);
            (big, target)
        }
        "far-matches" => {
            let far = random_bytes(11, 400_000);
            let mut target = far[200_000..].to_vec();
            target.extend(random_bytes(12, 1000));
            target.extend_from_slice(&far[..200_000]);
            (far, target)
        }
        "sha1-hash" => (rnd(), edit(9, &rnd(), 4)),
        "no-hash" => (rnd(), edit(10, &rnd(), 4)),
        "file-time" => (vec![], text(13, 500)),
        "executable-set-raw-data" => (rnd(), edit(14, &rnd(), 4)),
        other => panic!("unknown case {other}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn parse_hex(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn manifest() -> serde_json::Map<String, Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manifest.json");
    let Value::Object(map) = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap() else {
        panic!("the manifest is not an object");
    };
    map
}

fn delta(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.delta"));
    std::fs::read(path).unwrap()
}

#[test]
fn the_generator_makes_the_fixture_inputs() {
    for (name, entry) in manifest() {
        let (source, target) = case(&name);
        assert_eq!(
            hex(&Sha256::digest(&source)),
            entry["source_sha256"],
            "{name}"
        );
        assert_eq!(
            hex(&Sha256::digest(&target)),
            entry["target_sha256"],
            "{name}"
        );
    }
}

#[test]
fn the_header_matches_get_delta_info() {
    for (name, entry) in manifest() {
        let header = DeltaHeader::parse(&delta(&name)).unwrap();
        let info = &entry["info"];
        assert_eq!(
            header.file_type_set,
            parse_hex(&info["FileTypeSet"]),
            "{name}"
        );
        assert_eq!(header.file_type, parse_hex(&info["FileType"]), "{name}");
        assert_eq!(header.flags, parse_hex(&info["Flags"]), "{name}");
        assert_eq!(
            header.target_size,
            info["TargetSize"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            header.target_file_time,
            parse_hex(&info["TargetFileTime"]),
            "{name}"
        );
        assert_eq!(
            u64::from(header.target_hash_algorithm),
            parse_hex(&info["TargetHashAlgId"]),
            "{name}"
        );
        assert_eq!(hex(&header.target_hash), info["TargetHash"], "{name}");
    }
}

#[test]
fn each_delta_gives_the_target_of_msdelta_dll() {
    for name in manifest().keys() {
        let (source, target) = case(name);
        let output =
            msdelta::apply(&source, &delta(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(output == target, "{name}: the output is not the target");
    }
}

#[test]
fn a_wrong_source_fails_the_hash_check() {
    let (source, _) = case("small-edits");
    let mut wrong = source;
    wrong[0] ^= 0xff;
    // The first bytes of the target come from the source.
    let error = msdelta::apply(&wrong, &delta("small-edits")).unwrap_err();
    assert_eq!(error.kind, ErrorKind::HashMismatch { algorithm: 0x8003 });
}

#[test]
fn every_truncated_delta_is_an_error() {
    let data = delta("text-edits");
    let (source, _) = case("text-edits");
    for len in 0..data.len() {
        assert!(
            msdelta::apply(&source, &data[..len]).is_err(),
            "truncated to {len}"
        );
    }
}

#[test]
fn the_size_limit_rejects_a_large_target() {
    let options = msdelta::ApplyOptions {
        max_target_size: 1000,
        ..msdelta::ApplyOptions::default()
    };
    let error = msdelta::apply_with(&[], &delta("empty-source-text"), &options).unwrap_err();
    assert_eq!(
        error.kind,
        ErrorKind::LimitExceeded {
            needed: 3000,
            limit: 1000
        }
    );
}
