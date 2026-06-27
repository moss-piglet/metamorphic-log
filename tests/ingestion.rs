//! Slice 7 — deterministic ingestion-primitive conformance.
//!
//! Exercises the public [`metamorphic_log::ingest`] surface from outside the
//! crate (so it doubles as an API-visibility check) and locks the deterministic
//! behaviour a future Elixir/Phoenix operator pipeline (mosskeys, over the #336
//! NIF) must reproduce byte-for-byte: per-namespace monotonic sequencing,
//! idempotent-append dedup keys (with a fixed KAT vector), tile flush geometry
//! that agrees with the audited `tlog-tiles` substrate, and the read-path trait
//! composing with the RFC 6962 verification core.

#![cfg(not(target_arch = "wasm32"))]

use metamorphic_log::error::Error;
use metamorphic_log::ingest::{
    DedupKey, FlushPlan, Namespace, ReadPathError, Sequencer, TileReader, entry_bundles_to_flush,
    plan_flush, recompute_root_via, tiles_to_flush,
};
use metamorphic_log::merkle::MerkleTree;
use metamorphic_log::tile::{TILE_WIDTH, Tile, tiles_for_size};
use std::collections::HashMap;

fn ns(s: &str) -> Namespace {
    Namespace::parse(s).unwrap()
}

#[test]
fn sequencer_replay_is_deterministic() {
    // Two independent sequencers fed the identical call stream produce the
    // identical positions — the property the operator layer relies on.
    let run = || {
        let mut s = Sequencer::new();
        let a = ns("alpha");
        let b = ns("beta");
        vec![
            s.next(&a),
            s.next(&b),
            s.next(&a),
            s.reserve(&a, 3).unwrap().start,
            s.next(&b),
            s.peek(&a),
        ]
    };
    assert_eq!(run(), run());
    assert_eq!(run(), vec![0, 0, 1, 2, 1, 5]);
}

#[test]
fn sequencer_resume_from_durable_state() {
    let mut s = Sequencer::new();
    let a = ns("alpha");
    // Simulate an operator restart: durable store says last committed was 41.
    s.resume_from(&a, 42).unwrap();
    assert_eq!(s.next(&a), 42);
    assert!(matches!(
        s.resume_from(&a, 10),
        Err(Error::SequenceRegression { .. })
    ));
}

#[test]
fn dedup_key_known_answer() {
    // Fixed KAT vector: a future cross-language ingester MUST reproduce this.
    // (namespace = "acme", payload = b"hello", content mode.)
    let key = DedupKey::from_record(&ns("acme"), b"hello");
    assert_eq!(
        key.to_hex(),
        "96a863d339a97f0870c8a72c7bd6dbc96187928e77035ce98d5c43d99fcd9d3cb6b7daf59a70320251e5acf09a5477bf0d8177ce16f00977062df3c8c6ea1f16"
    );
}

#[test]
fn dedup_key_idempotency_and_separation() {
    let a = ns("acme");
    // Idempotent: identical submissions collapse to one key.
    assert_eq!(
        DedupKey::from_record(&a, b"payload"),
        DedupKey::from_record(&a, b"payload")
    );
    // Distinct content, namespaces, and modes never collide.
    assert_ne!(
        DedupKey::from_record(&a, b"payload"),
        DedupKey::from_record(&a, b"payloar")
    );
    assert_ne!(
        DedupKey::from_record(&a, b"x"),
        DedupKey::from_record(&ns("acme2"), b"x")
    );
    assert_ne!(
        DedupKey::from_record(&a, b"x"),
        DedupKey::from_token(&a, b"x")
    );
}

#[test]
fn flush_geometry_agrees_with_substrate_across_sizes() {
    // For a sweep of (old, new) growth steps, the union of "already finalized"
    // (anything not flushed) and "flushed" must exactly reconstruct
    // tiles_for_size(new), and every flushed tile must be a real substrate tile.
    let sizes = [0u64, 1, 255, 256, 257, 511, 512, 65_535, 65_536, 70_000];
    for &old in &sizes {
        for &new in &sizes {
            if new < old {
                assert!(tiles_to_flush(old, new).is_err());
                continue;
            }
            let all: Vec<Tile> = tiles_for_size(new);
            let flushed = tiles_to_flush(old, new).unwrap();
            // Every flushed tile is part of the new tree's tile set.
            for t in &flushed {
                assert!(all.contains(t), "flushed a non-substrate tile {t:?}");
            }
            // Tiles NOT flushed are exactly those already present & identical in
            // the old tree (i.e. in tiles_for_size(old) too).
            let old_tiles = tiles_for_size(old);
            for t in &all {
                if !flushed.contains(t) {
                    assert!(
                        old_tiles.contains(t),
                        "tile {t:?} was skipped but is not finalized in old tree"
                    );
                }
            }
        }
    }
}

#[test]
fn plan_flush_partitions_into_tiles_and_entry_bundles() {
    let plan: FlushPlan = plan_flush(0, 70_000).unwrap();
    assert_eq!(plan.tiles, tiles_for_size(70_000));
    assert_eq!(
        plan.entry_bundles,
        entry_bundles_to_flush(0, 70_000).unwrap()
    );
    assert!(plan.entry_bundles.iter().all(|t| t.level() == 0));
}

/// Logic-only in-memory reader fixture. NOT a storage backend — it exists only
/// to prove the read-path trait composes with the verification core.
struct MemReader {
    tiles: HashMap<String, Vec<u8>>,
}

impl TileReader for MemReader {
    type Error = String;

    fn read_tile(&self, tile: &Tile) -> Result<Vec<u8>, String> {
        self.tiles
            .get(&tile.path())
            .cloned()
            .ok_or_else(|| format!("missing {}", tile.path()))
    }

    fn read_entry_bundle(&self, tile: &Tile) -> Result<Vec<u8>, String> {
        self.tiles
            .get(&tile.entries_path())
            .cloned()
            .ok_or_else(|| format!("missing {}", tile.entries_path()))
    }
}

#[test]
fn read_path_bridge_reproduces_checkpoint_root() {
    let mut tree = MerkleTree::new();
    for i in 0u32..5000 {
        tree.push(&i.to_be_bytes());
    }
    let mut tiles = HashMap::new();
    for tile in tiles_for_size(5000).into_iter().filter(|t| t.level() == 0) {
        let start = tile.index() * u64::from(TILE_WIDTH);
        let mut bytes = Vec::new();
        for i in 0..u64::from(tile.width()) {
            bytes.extend_from_slice(&tree.leaf_hash(start + i).unwrap());
        }
        tiles.insert(tile.path(), bytes);
    }
    let reader = MemReader { tiles };
    assert_eq!(recompute_root_via(&reader, 5000).unwrap(), tree.root());

    // A missing object surfaces as a backend error, never a panic.
    let empty = MemReader {
        tiles: HashMap::new(),
    };
    assert!(matches!(
        recompute_root_via(&empty, 5000),
        Err(ReadPathError::Backend(_))
    ));
}
