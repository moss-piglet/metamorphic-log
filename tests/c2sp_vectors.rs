//! Slice 2 (#329) C2SP byte-compatibility suite.
//!
//! Locks the wrapped C2SP substrate against the canonical specification
//! vectors, all exercised through the crate's **public API** (the bar set by
//! #316: a wrapper that can't independently recompute is not a verifier):
//!
//! 1. **`signed-note` vectors** — the canonical verifier key + signed note from
//!    the C2SP `signed-note` spec parse, verify (classical Ed25519 via
//!    `metamorphic-crypto`), and re-serialize byte-for-byte; tampering is
//!    rejected.
//!
//! 2. **`tlog-checkpoint` vector** — the canonical checkpoint body from the
//!    spec parses and round-trips byte-for-byte, and a full signed checkpoint
//!    verifies and wires to the Slice-1 inclusion/consistency verifier.
//!
//! 3. **`tlog-tiles` geometry** — the worked tile-index and partial-width
//!    examples from the spec, plus a recompute round-trip proving that level-0
//!    tile leaf hashes reproduce the checkpoint root with the same RFC 6962
//!    hashing as Slice 1.

#![cfg(not(target_arch = "wasm32"))]

use metamorphic_log::checkpoint::Checkpoint;
use metamorphic_log::merkle::MerkleTree;
use metamorphic_log::note::{SignedNote, VerifierKey, sign_ed25519};
use metamorphic_log::tile::{Tile, partial_width, recompute_root, tiles_for_size};

// ===========================================================================
// 1. signed-note canonical vectors (c2sp.org/signed-note)
// ===========================================================================

const SPEC_VKEY: &str = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
const SPEC_NOTE: &str = "This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n";

#[test]
fn signed_note_spec_vector_parses_verifies_round_trips() {
    let vkey = VerifierKey::parse(SPEC_VKEY).unwrap();
    assert_eq!(vkey.key_id(), 0x530d_903a);
    assert_eq!(vkey.encode(), SPEC_VKEY);

    let note = SignedNote::parse(SPEC_NOTE).unwrap();
    assert_eq!(note.text(), "This is an example message.\n");
    let verified = note.verify(&[vkey]).unwrap();
    assert_eq!(verified.len(), 1);

    // Byte-for-byte re-serialization.
    assert_eq!(note.marshal(), SPEC_NOTE);
}

#[test]
fn signed_note_tamper_is_rejected() {
    let vkey = VerifierKey::parse(SPEC_VKEY).unwrap();
    let tampered = SPEC_NOTE.replace("example message", "forged message");
    let note = SignedNote::parse(&tampered).unwrap();
    assert!(note.verify(&[vkey]).is_err());
}

// ===========================================================================
// 2. tlog-checkpoint canonical vector (c2sp.org/tlog-checkpoint)
// ===========================================================================

const SPEC_CHECKPOINT_BODY: &str =
    "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n";

#[test]
fn checkpoint_spec_body_round_trips() {
    let cp = Checkpoint::parse(SPEC_CHECKPOINT_BODY).unwrap();
    assert_eq!(cp.origin(), "example.com/behind-the-sofa");
    assert_eq!(cp.size(), 20_852_163);
    assert_eq!(cp.marshal(), SPEC_CHECKPOINT_BODY);
}

#[test]
fn signed_checkpoint_verifies_and_wires_to_proofs() {
    // Build a real tree, checkpoint it, sign with a fresh Ed25519 witness key,
    // verify end-to-end, and use the verified checkpoint to drive the Slice-1
    // inclusion + consistency verifier.
    let mut tree = MerkleTree::new();
    for i in 0u32..32 {
        tree.push(&i.to_be_bytes());
    }
    let origin = "rome.ct.example.com/tevere";
    let older = Checkpoint::new(origin, tree.size(), tree.root()).unwrap();

    let (seed, pk) = metamorphic_crypto::ed25519_generate_keypair();
    let sig = sign_ed25519(&older.marshal(), origin, &seed).unwrap();
    let signed = SignedNote::new(older.marshal(), vec![sig]).unwrap();
    let vkey = VerifierKey::new_ed25519(origin, &pk).unwrap();

    let parsed = Checkpoint::from_signed_note(&signed.marshal(), &[vkey]).unwrap();
    assert_eq!(parsed, older);

    // Inclusion of leaf 5.
    let inc: Vec<Vec<u8>> = tree
        .inclusion_proof(5, 32)
        .into_iter()
        .map(|h| h.to_vec())
        .collect();
    parsed
        .verify_inclusion(5, &tree.leaf_hash(5).unwrap(), &inc)
        .unwrap();

    // Consistency to a grown tree.
    for i in 32u32..50 {
        tree.push(&i.to_be_bytes());
    }
    let newer = Checkpoint::new(origin, tree.size(), tree.root()).unwrap();
    let cons: Vec<Vec<u8>> = tree
        .consistency_proof(32, 50)
        .into_iter()
        .map(|h| h.to_vec())
        .collect();
    parsed.verify_consistency(&newer, &cons).unwrap();
}

// ===========================================================================
// 3. tlog-tiles geometry + recompute (c2sp.org/tlog-tiles)
// ===========================================================================

#[test]
fn tile_path_spec_example() {
    // Spec: index 1234067 encodes as x001/x234/067.
    let t = Tile::new(2, 1_234_067, 256).unwrap();
    assert_eq!(t.path(), "tile/2/x001/x234/067");
    assert_eq!(Tile::parse_path(&t.path()).unwrap(), t);
}

#[test]
fn partial_width_and_tile_set_for_size_70000() {
    // Spec worked example: tree of size 70,000.
    assert_eq!(partial_width(0, 70_000), 112);
    assert_eq!(partial_width(1, 70_000), 17);
    assert_eq!(partial_width(2, 70_000), 1);

    let tiles = tiles_for_size(70_000);
    let full_l0 = tiles
        .iter()
        .filter(|t| t.level() == 0 && !t.is_partial())
        .count();
    assert_eq!(full_l0, 273);
    assert!(tiles.iter().any(|t| t.level() == 2 && t.width() == 1));
}

#[test]
fn level0_tiles_recompute_checkpoint_root() {
    // Independent recomputation: serialize a tree's level-0 leaf hashes as
    // tiles, parse them back, and recompute the root — it must equal the root a
    // checkpoint would commit.
    let mut tree = MerkleTree::new();
    let size = 600u32; // 2 full L0 tiles (512) + partial 88
    for i in 0..size {
        tree.push(&i.to_be_bytes());
    }
    let checkpoint_root = tree.root();

    // Emit and re-parse the level-0 tiles.
    let mut leaf_hashes = Vec::new();
    for t in tiles_for_size(u64::from(size))
        .into_iter()
        .filter(|t| t.level() == 0)
    {
        let mut bytes = Vec::new();
        for i in 0..t.width() {
            let leaf_index = t.index() * 256 + u64::from(i);
            bytes.extend_from_slice(&tree.leaf_hash(leaf_index).unwrap());
        }
        // Round-trip the tile's bytes through the parser.
        for h in t.hashes(&bytes).unwrap() {
            leaf_hashes.push(h);
        }
    }
    assert_eq!(recompute_root(&leaf_hashes), checkpoint_root);
}
