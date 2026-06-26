//! Slice 1 (#327) conformance suite.
//!
//! Three locks, all exercised through the crate's public API:
//!
//! 1. **#315 KAT parity** — a real `mosslet/key-history/v1` row, byte-for-byte,
//!    is a valid Layer-0 leaf with zero reformatting. The SHA3-512 `entry_hash`
//!    and the RFC 6962 leaf hash match the values produced by the shipped
//!    Mosslet implementation (the same `metamorphic-crypto` crate compiled to
//!    WASM / NIF), reproduced here from `test/mosslet/crypto/key_history_test.exs`.
//!
//! 2. **RFC 6962 / RFC 9162 reference vectors** — canonical inclusion and
//!    consistency proof vectors from the `transparency-dev/merkle` test corpus
//!    (the standard 8-leaf tree) lock the proof math against the ecosystem.
//!
//! 3. **Property round-trips** — for trees of many shapes: every leaf's
//!    generated inclusion proof verifies; consistency between every size pair
//!    verifies; and tampered proofs / roots / indices are rejected.
//!
//! Native-only: gated off wasm32 so `wasm-pack test` (the cross-language KAT
//! job) builds just `tests/cross_language.rs` and not the proptest-backed suites.
#![cfg(not(target_arch = "wasm32"))]

use metamorphic_crypto::b64;
use metamorphic_log::leaf::key_history_v1::Entry;
use metamorphic_log::merkle::MerkleTree;
use metamorphic_log::proof::{verify_consistency, verify_inclusion};

// ===========================================================================
// 1. #315 mosslet/key-history/v1 KAT parity
// ===========================================================================

// Fixed, reproducible key material — identical generators to
// test/mosslet/crypto/key_history_test.exs.
fn x_a() -> Vec<u8> {
    (0u32..32).map(|i| ((i * 7 + 1) % 256) as u8).collect()
}
fn pq_a() -> Vec<u8> {
    (0u32..1600).map(|i| (i % 256) as u8).collect()
}
fn x_b() -> Vec<u8> {
    (0u32..32).map(|i| ((i * 5 + 3) % 256) as u8).collect()
}
fn sp_fixed() -> Vec<u8> {
    (0u32..2625).map(|i| ((i * 3) % 256) as u8).collect()
}

const GENESIS_TS: u64 = 1_700_000_000_000;
const ROTATION_TS: u64 = 1_700_000_100_000;

// LOCKED KAT vectors (cross-SDK contract; mirror of the Elixir KAT).
const KAT_GENESIS_HASH_B64: &str =
    "ueTkShE9EQ1ROe8DFVa0m706AJPrsJyLGt2uSSzmStPty0xtu3gX2zjvBNdgA9swPWYEXx+wEsjDNXbOmzhJFA==";
const KAT_ROTATION_HASH_B64: &str =
    "14CrClVh3k5BrmUQT9FZ3UnE1wZG9820t3eXynXXMwmk6YV1V4ykoCiT79HA1BCWKtq6VU4SYEflZMYeRZoJjQ==";
const KAT_GENESIS_CANON_SIZE: usize = 4293;

// RFC 6962 leaf hashes over the RAW canonical bytes (the Layer-0 leaf bytes).
// Generated from the same metamorphic-crypto sha256 the Mosslet NIF exposes.
const KAT_GENESIS_RFC6962_LEAF_HEX: &str =
    "a429552cdc9dba9b9bc733d2afe0e1beb5f5100184ea8416179dd0d4fd864263";
const KAT_ROTATION_RFC6962_LEAF_HEX: &str =
    "cca5a60048d9c76681a02c7856d310af9c24188a226c4ec1e0cc5f451f95fe35";

fn genesis_entry() -> Entry {
    Entry {
        seq: 0,
        ts_ms: GENESIS_TS,
        enc_x25519: x_a(),
        enc_pq: pq_a(),
        signing_pub: sp_fixed(),
        prev_entry_hash: None,
    }
}

fn rotation_entry() -> Entry {
    Entry {
        seq: 1,
        ts_ms: ROTATION_TS,
        enc_x25519: x_b(),
        enc_pq: pq_a(),
        signing_pub: sp_fixed(),
        prev_entry_hash: Some(b64::decode(KAT_GENESIS_HASH_B64).unwrap()),
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[test]
fn key_history_v1_genesis_canonical_size_is_locked() {
    let canonical = genesis_entry().canonical_bytes().unwrap();
    assert_eq!(canonical.len(), KAT_GENESIS_CANON_SIZE);
}

#[test]
fn key_history_v1_canonical_layout_is_fixed() {
    // u32_be(version=1) || u64_be(seq=0) || u64_be(ts) || lp(x_a) || lp(pq_a)
    // || lp(sp) || lp(prev=empty)
    let canonical = genesis_entry().canonical_bytes().unwrap();
    assert_eq!(&canonical[0..4], &1u32.to_be_bytes()); // version
    assert_eq!(&canonical[4..12], &0u64.to_be_bytes()); // seq
    assert_eq!(&canonical[12..20], &GENESIS_TS.to_be_bytes()); // ts
    // First length prefix is the 32-byte X25519 key.
    assert_eq!(&canonical[20..24], &32u32.to_be_bytes());
    assert_eq!(&canonical[24..56], &x_a()[..]);
    // Genesis prev_entry_hash is a zero-length field at the very end.
    assert_eq!(&canonical[canonical.len() - 4..], &0u32.to_be_bytes());
}

#[test]
fn key_history_v1_genesis_entry_hash_matches_kat() {
    let digest = genesis_entry().entry_hash().unwrap();
    assert_eq!(digest.len(), 64);
    assert_eq!(b64::encode(&digest), KAT_GENESIS_HASH_B64);
}

#[test]
fn key_history_v1_rotation_entry_hash_matches_kat() {
    let digest = rotation_entry().entry_hash().unwrap();
    assert_eq!(b64::encode(&digest), KAT_ROTATION_HASH_B64);
}

#[test]
fn key_history_v1_genesis_rfc6962_leaf_hash_matches_kat() {
    let leaf = genesis_entry().rfc6962_leaf_hash().unwrap();
    assert_eq!(leaf.to_vec(), hex_decode(KAT_GENESIS_RFC6962_LEAF_HEX));
}

#[test]
fn key_history_v1_rotation_rfc6962_leaf_hash_matches_kat() {
    let leaf = rotation_entry().rfc6962_leaf_hash().unwrap();
    assert_eq!(leaf.to_vec(), hex_decode(KAT_ROTATION_RFC6962_LEAF_HEX));
}

#[test]
fn key_history_v1_real_row_is_a_valid_leaf_in_a_tree() {
    // The conformance guarantee: a key-history row drops into the Merkle log
    // unchanged, and its inclusion proof verifies against the tree root.
    let mut tree = MerkleTree::new();
    let genesis = genesis_entry().canonical_bytes().unwrap();
    let rotation = rotation_entry().canonical_bytes().unwrap();
    let g_idx = tree.push(&genesis);
    let r_idx = tree.push(&rotation);
    let root = tree.root();

    // The pushed leaf hash equals the entry's own RFC 6962 leaf hash.
    assert_eq!(
        tree.leaf_hash(g_idx).unwrap(),
        genesis_entry().rfc6962_leaf_hash().unwrap()
    );

    let proof = tree.inclusion_proof(r_idx, tree.size());
    let proof_bytes: Vec<Vec<u8>> = proof.iter().map(|h| h.to_vec()).collect();
    verify_inclusion(
        r_idx,
        tree.size(),
        &rotation_entry().rfc6962_leaf_hash().unwrap(),
        &proof_bytes,
        &root,
    )
    .expect("rotation row must verify as an included leaf");
}

#[test]
fn key_history_v1_context_separation() {
    // Different namespace label => different digest (domain separation lives
    // inside the content hash).
    use metamorphic_log::leaf::{ContextLabel, content_hash};
    let canonical = genesis_entry().canonical_bytes().unwrap();
    let other = ContextLabel::parse("mosslet/other/v1").unwrap();
    let other_digest = content_hash(&other, &canonical);
    assert_ne!(b64::encode(&other_digest), KAT_GENESIS_HASH_B64);
}

// ===========================================================================
// 2. RFC 6962 / RFC 9162 reference vectors (transparency-dev/merkle corpus,
//    the standard 8-leaf tree). Hashes are base64 as in the upstream testdata.
// ===========================================================================

struct InclusionVec {
    leaf_idx: u64,
    tree_size: u64,
    root_b64: &'static str,
    leaf_hash_b64: &'static str,
    proof_b64: &'static [&'static str],
}

const INCLUSION_VECTORS: &[InclusionVec] = &[
    InclusionVec {
        leaf_idx: 0,
        tree_size: 1,
        root_b64: "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
        leaf_hash_b64: "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
        proof_b64: &[],
    },
    InclusionVec {
        leaf_idx: 0,
        tree_size: 8,
        root_b64: "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
        leaf_hash_b64: "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
        proof_b64: &[
            "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
            "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
            "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ=",
        ],
    },
    InclusionVec {
        leaf_idx: 5,
        tree_size: 8,
        root_b64: "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
        leaf_hash_b64: "QnGia+DYqE8L1UyMMC58s6O10fpngKQLzOKHNHfatlg=",
        proof_b64: &[
            "vBoGQ7EuTS18d5GPROD095qDi2z57FtcKD4fTYhZnms=",
            "yoVOoSjtBQtBs1/8G4e46yveRh6eO1WW7Oa51ZdaCuA=",
            "037kGJdt2VdTwcc4Yrk5j6Kiz5tP8P3+izDNlSCWFLc=",
        ],
    },
    InclusionVec {
        leaf_idx: 2,
        tree_size: 3,
        root_b64: "rra8/idLcKFPsGel5VeCZNsPqbUa9eC6FZFY8yngbnc=",
        leaf_hash_b64: "ApjRIpBtz8EIkstTpzmS/FufST6kybrbJ7eRtBJ6f+c=",
        proof_b64: &["+sVCA+fMaWzw38tCySodnbr3CtnmIfS9jZhmLwDjwSU="],
    },
    InclusionVec {
        leaf_idx: 1,
        tree_size: 5,
        root_b64: "Tju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=",
        leaf_hash_b64: "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
        proof_b64: &[
            "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
            "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
            "vBoGQ7EuTS18d5GPROD095qDi2z57FtcKD4fTYhZnms=",
        ],
    },
];

fn proof_bytes(proof_b64: &[&str]) -> Vec<Vec<u8>> {
    proof_b64.iter().map(|s| b64::decode(s).unwrap()).collect()
}

#[test]
fn rfc6962_inclusion_reference_vectors_verify() {
    for v in INCLUSION_VECTORS {
        let root = b64::decode(v.root_b64).unwrap();
        let leaf = b64::decode(v.leaf_hash_b64).unwrap();
        let proof = proof_bytes(v.proof_b64);
        verify_inclusion(v.leaf_idx, v.tree_size, &leaf, &proof, &root).unwrap_or_else(|e| {
            panic!(
                "inclusion vector idx={} size={} failed: {e}",
                v.leaf_idx, v.tree_size
            )
        });
    }
}

#[test]
fn rfc6962_inclusion_reference_vectors_reject_tampering() {
    for v in INCLUSION_VECTORS {
        let root = b64::decode(v.root_b64).unwrap();
        let leaf = b64::decode(v.leaf_hash_b64).unwrap();

        // Wrong root.
        let mut bad_root = root.clone();
        bad_root[0] ^= 0x01;
        assert!(
            verify_inclusion(
                v.leaf_idx,
                v.tree_size,
                &leaf,
                &proof_bytes(v.proof_b64),
                &bad_root
            )
            .is_err()
        );

        // Wrong leaf hash.
        let mut bad_leaf = leaf.clone();
        bad_leaf[0] ^= 0x01;
        assert!(
            verify_inclusion(
                v.leaf_idx,
                v.tree_size,
                &bad_leaf,
                &proof_bytes(v.proof_b64),
                &root
            )
            .is_err()
        );

        // Tampered proof node (only meaningful when the proof is non-empty).
        if !v.proof_b64.is_empty() {
            let mut bad_proof = proof_bytes(v.proof_b64);
            bad_proof[0][0] ^= 0x01;
            assert!(verify_inclusion(v.leaf_idx, v.tree_size, &leaf, &bad_proof, &root).is_err());
        }
    }
}

struct ConsistencyVec {
    size1: u64,
    size2: u64,
    root1_b64: &'static str,
    root2_b64: &'static str,
    proof_b64: &'static [&'static str],
}

const CONSISTENCY_VECTORS: &[ConsistencyVec] = &[
    ConsistencyVec {
        size1: 1,
        size2: 1,
        root1_b64: "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
        root2_b64: "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
        proof_b64: &[],
    },
    ConsistencyVec {
        size1: 1,
        size2: 8,
        root1_b64: "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
        root2_b64: "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
        proof_b64: &[
            "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
            "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
            "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ=",
        ],
    },
    ConsistencyVec {
        size1: 6,
        size2: 8,
        root1_b64: "duZ9rbzfHhDht03cYIq9L5jfsW+851J3tSMqEn8gh+8=",
        root2_b64: "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
        proof_b64: &[
            "DrxdNDf74tsVi58Sah0RjjCBgQMdCpSfje3t68VY72o=",
            "yoVOoSjtBQtBs1/8G4e46yveRh6eO1WW7Oa51ZdaCuA=",
            "037kGJdt2VdTwcc4Yrk5j6Kiz5tP8P3+izDNlSCWFLc=",
        ],
    },
    ConsistencyVec {
        size1: 2,
        size2: 5,
        root1_b64: "+sVCA+fMaWzw38tCySodnbr3CtnmIfS9jZhmLwDjwSU=",
        root2_b64: "Tju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=",
        proof_b64: &[
            "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
            "vBoGQ7EuTS18d5GPROD095qDi2z57FtcKD4fTYhZnms=",
        ],
    },
    ConsistencyVec {
        size1: 6,
        size2: 7,
        root1_b64: "duZ9rbzfHhDht03cYIq9L5jfsW+851J3tSMqEn8gh+8=",
        root2_b64: "3bib5AOAnjJXUNPSY814kpwpQreUKjS3fhIslZSnTIw=",
        proof_b64: &[
            "DrxdNDf74tsVi58Sah0RjjCBgQMdCpSfje3t68VY72o=",
            "sIaT7C5yFZcTBkHoIR5+7cy0wmQTlj7ubB4u0W/7Gl8=",
            "037kGJdt2VdTwcc4Yrk5j6Kiz5tP8P3+izDNlSCWFLc=",
        ],
    },
];

#[test]
fn rfc6962_consistency_reference_vectors_verify() {
    for v in CONSISTENCY_VECTORS {
        let root1 = b64::decode(v.root1_b64).unwrap();
        let root2 = b64::decode(v.root2_b64).unwrap();
        let proof = proof_bytes(v.proof_b64);
        verify_consistency(v.size1, v.size2, &proof, &root1, &root2)
            .unwrap_or_else(|e| panic!("consistency vector {}->{} failed: {e}", v.size1, v.size2));
    }
}

#[test]
fn rfc6962_consistency_reference_vectors_reject_tampering() {
    for v in CONSISTENCY_VECTORS {
        let root1 = b64::decode(v.root1_b64).unwrap();
        let root2 = b64::decode(v.root2_b64).unwrap();

        let mut bad_root2 = root2.clone();
        bad_root2[0] ^= 0x01;
        assert!(
            verify_consistency(
                v.size1,
                v.size2,
                &proof_bytes(v.proof_b64),
                &root1,
                &bad_root2
            )
            .is_err()
        );

        let mut bad_root1 = root1.clone();
        bad_root1[0] ^= 0x01;
        assert!(
            verify_consistency(
                v.size1,
                v.size2,
                &proof_bytes(v.proof_b64),
                &bad_root1,
                &root2
            )
            .is_err()
        );

        if !v.proof_b64.is_empty() {
            let mut bad_proof = proof_bytes(v.proof_b64);
            bad_proof[0][0] ^= 0x01;
            assert!(verify_consistency(v.size1, v.size2, &bad_proof, &root1, &root2).is_err());
        }
    }
}

#[test]
fn rfc6962_empty_and_regression_consistency_errors() {
    let some = vec![0u8; 32];
    // size1 == 0 is meaningless.
    assert!(verify_consistency(0, 4, &[], &some, &some).is_err());
    // size2 < size1 is a regression.
    assert!(verify_consistency(5, 4, &[], &some, &some).is_err());
    // equal sizes with a non-empty proof must fail.
    assert!(verify_consistency(3, 3, &[vec![0u8; 32]], &some, &some).is_err());
}

// ===========================================================================
// 3. Property round-trips against the independent reference tree.
// ===========================================================================

use proptest::prelude::*;

/// Build a tree of `n` distinct leaves and return it.
fn build_tree(n: usize) -> MerkleTree {
    let mut tree = MerkleTree::new();
    for i in 0..n {
        // Distinct leaf bytes per index.
        let leaf = format!("metamorphic-log/leaf/{i}");
        tree.push(leaf.as_bytes());
    }
    tree
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Every leaf's generated inclusion proof verifies against the root.
    #[test]
    fn every_inclusion_proof_round_trips(n in 1usize..=130) {
        let tree = build_tree(n);
        let size = tree.size();
        let root = tree.root();
        for index in 0..size {
            let proof = tree.inclusion_proof(index, size);
            let proof_bytes: Vec<Vec<u8>> = proof.iter().map(|h| h.to_vec()).collect();
            let leaf = tree.leaf_hash(index).unwrap();
            prop_assert!(verify_inclusion(index, size, &leaf, &proof_bytes, &root).is_ok());
        }
    }

    /// A tampered audit path, wrong root, or wrong index is rejected.
    #[test]
    fn inclusion_proofs_reject_tampering(n in 2usize..=130) {
        let tree = build_tree(n);
        let size = tree.size();
        let root = tree.root();
        let index = (n as u64) / 2;
        let proof = tree.inclusion_proof(index, size);
        let proof_bytes: Vec<Vec<u8>> = proof.iter().map(|h| h.to_vec()).collect();
        let leaf = tree.leaf_hash(index).unwrap();

        // Wrong root.
        let mut bad_root = root;
        bad_root[0] ^= 0x01;
        prop_assert!(verify_inclusion(index, size, &leaf, &proof_bytes, &bad_root).is_err());

        // Wrong index (a different existing leaf's hash at this index).
        let other = if index == 0 { 1 } else { index - 1 };
        let other_leaf = tree.leaf_hash(other).unwrap();
        prop_assert!(verify_inclusion(index, size, &other_leaf, &proof_bytes, &root).is_err());

        // Tampered path.
        if !proof_bytes.is_empty() {
            let mut bad = proof_bytes.clone();
            bad[0][0] ^= 0x01;
            prop_assert!(verify_inclusion(index, size, &leaf, &bad, &root).is_err());
        }
    }

    /// Consistency between every (size1, size2) pair verifies.
    #[test]
    fn every_consistency_proof_round_trips(n in 1usize..=64) {
        let tree = build_tree(n);
        for size1 in 1..=n as u64 {
            for size2 in size1..=n as u64 {
                let proof = tree.consistency_proof(size1, size2);
                let proof_bytes: Vec<Vec<u8>> = proof.iter().map(|h| h.to_vec()).collect();
                let root1 = tree.root_at(size1);
                let root2 = tree.root_at(size2);
                prop_assert!(
                    verify_consistency(size1, size2, &proof_bytes, &root1, &root2).is_ok(),
                    "consistency {}->{} of {} failed", size1, size2, n
                );
            }
        }
    }

    /// A consistency proof with a tampered node or wrong new root is rejected.
    #[test]
    fn consistency_proofs_reject_tampering(n in 3usize..=64) {
        let tree = build_tree(n);
        let size1 = (n as u64) / 2 + 1;
        let size2 = n as u64;
        let proof = tree.consistency_proof(size1, size2);
        let proof_bytes: Vec<Vec<u8>> = proof.iter().map(|h| h.to_vec()).collect();
        let root1 = tree.root_at(size1);
        let root2 = tree.root_at(size2);

        let mut bad_root2 = root2;
        bad_root2[0] ^= 0x01;
        prop_assert!(verify_consistency(size1, size2, &proof_bytes, &root1, &bad_root2).is_err());

        if !proof_bytes.is_empty() {
            let mut bad = proof_bytes.clone();
            let last = bad.len() - 1;
            bad[last][0] ^= 0x01;
            prop_assert!(verify_consistency(size1, size2, &bad, &root1, &root2).is_err());
        }
    }
}
