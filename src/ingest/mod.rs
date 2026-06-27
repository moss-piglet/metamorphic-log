//! Storage-agnostic, **deterministic** ingestion primitives (Slice 7).
//!
//! This module is the OSS engine's contribution to the *write path*: the small,
//! pure, byte-reproducible building blocks an operator needs to turn a stream of
//! application records into an append-only tiled log. It is deliberately
//! **storage-agnostic and I/O-free** — there is no Broadway/GenStage pipeline,
//! no object-storage client, no network, and no persistence here. Those belong
//! to the operator layer (the paid mosskeys app, per the #290 open-core
//! boundary). What lives here is the deterministic *logic* that such a pipeline
//! must run identically regardless of language or backend, so that two
//! independent ingesters (e.g. this crate and a future Elixir consumer over the
//! sibling NIF, #336) produce **the same bytes and the same tile geometry**.
//!
//! It provides four primitives:
//!
//! 1. [`Sequencer`] — a per-namespace **monotonic sequencer**. Each namespace
//!    gets its own strictly-increasing `u64` position counter (the `seq` that a
//!    record such as [`crate::leaf::key_history_v1`] commits). It is pure
//!    in-memory state with an explicit [`Sequencer::resume_from`] so an operator
//!    can rebuild it from durable storage after a restart without ever rewinding
//!    (monotonicity is enforced, not assumed).
//!
//! 2. [`DedupKey`] — an **idempotent-append** deduplication key. A deterministic,
//!    domain-separated, post-quantum (SHA3-512) digest of `(namespace, payload)`
//!    so that re-submitting the same record — or the same client-supplied
//!    idempotency token — maps to the same key and can be dropped before it
//!    double-appends. Same input ⇒ same key, in any language.
//!
//! 3. [`plan_flush`] / [`tiles_to_flush`] / [`entry_bundles_to_flush`] — the
//!    **tile-write/flush geometry**. Given the log's `old_size` and the
//!    `new_size` after appending a batch, it computes exactly which C2SP
//!    `tlog-tiles` coordinates changed and must be (re)written. It is defined
//!    purely in terms of [`crate::tile`] and is byte-compatible with the audited
//!    Layer-1 substrate: it never invents a tile [`crate::tile::tiles_for_size`]
//!    would not, and never changes a canonical byte.
//!
//! 4. [`TileReader`] — the object-storage / CDN **read-path trait**. An
//!    *interface only*: it describes how a verifier or monitor fetches immutable
//!    tile and entry-bundle bytes by coordinate, with **no** backend
//!    implementation in this crate. A logic-only bridge,
//!    [`recompute_root_via`], reads the level-0 tiles through any `TileReader`
//!    and recomputes the RFC 6962 root via [`crate::tile::recompute_root`],
//!    proving the trait composes with the verification core without performing
//!    any I/O itself.
//!
//! ## Throughput posture (honest framing)
//!
//! These are the *deterministic primitives*, not an end-to-end ingest pipeline.
//! The `benches/ingestion.rs` benchmark measures them in isolation (sequencing +
//! dedup-keying + flush planning) and they run far above the Tessera reference
//! band of ~5k–18k entries/sec. **That number is not an end-to-end claim:**
//! real throughput is bounded by the operator's pipeline (backpressure,
//! batching) and the object-storage/CDN backend — both out of scope for this
//! crate. The primitives are designed not to be the bottleneck.
//!
//! ## Byte / determinism discipline
//!
//! Like every other canonical encoding in this crate, the dedup key uses the
//! fixed discipline (big-endian integers; `u32`-be length-prefixed variable
//! fields; domain-separated context labels) so independent implementations
//! recompute it byte-for-byte. The sequencer and flush geometry are fully
//! determined by their inputs.

use crate::error::{Error, Result};
use crate::merkle::Hash;
use crate::tile::{Tile, recompute_root, tiles_for_size};
use std::collections::BTreeMap;
use std::ops::Range;

pub use crate::coniks::Namespace;

/// Domain-separation context for the content-derived idempotent-append key.
const DEDUP_CONTENT_CONTEXT: &str = "metamorphic-log/ingest-dedup-content/v1";
/// Domain-separation context for the token-derived idempotent-append key.
const DEDUP_TOKEN_CONTEXT: &str = "metamorphic-log/ingest-dedup-token/v1";

/// Append `lp(bytes) = u32_be(len(bytes)) || bytes` to `out`.
///
/// The same `u32`-be length-prefix discipline used by [`crate::leaf`], kept
/// local so field boundaries are unambiguous and two distinct `(namespace,
/// payload)` pairs cannot collide by boundary confusion.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A per-namespace **monotonic sequencer**.
///
/// Assigns strictly-increasing, gap-free `u64` positions *within each
/// namespace*, starting at `0`. Namespaces are fully independent: assigning in
/// one never affects another. The sequencer is pure in-memory state and holds
/// no I/O — durability is the operator's concern. After a restart the operator
/// rebuilds state with [`Sequencer::resume_from`] (typically `last_committed +
/// 1`), which refuses to rewind so monotonicity survives crashes.
///
/// ```
/// use metamorphic_log::ingest::{Namespace, Sequencer};
///
/// let ns = Namespace::parse("acme").unwrap();
/// let mut seq = Sequencer::new();
/// assert_eq!(seq.next(&ns), 0);
/// assert_eq!(seq.next(&ns), 1);
/// assert_eq!(seq.peek(&ns), 2); // next position that would be assigned
/// ```
#[derive(Debug, Clone, Default)]
pub struct Sequencer {
    next: BTreeMap<String, u64>,
}

impl Sequencer {
    /// Create an empty sequencer (every namespace starts at position `0`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            next: BTreeMap::new(),
        }
    }

    /// The next position that [`Sequencer::next`] would assign for `namespace`
    /// (without assigning it). A never-seen namespace peeks at `0`.
    #[must_use]
    pub fn peek(&self, namespace: &Namespace) -> u64 {
        self.next.get(namespace.as_str()).copied().unwrap_or(0)
    }

    /// Assign and return the next monotonic position for `namespace`.
    ///
    /// # Panics
    /// Panics only on `u64` position overflow (after `2^64` appends in a single
    /// namespace), which is not reachable in practice.
    pub fn next(&mut self, namespace: &Namespace) -> u64 {
        let slot = self.next.entry(namespace.as_str().to_string()).or_insert(0);
        let assigned = *slot;
        *slot = assigned
            .checked_add(1)
            .expect("sequence position overflowed u64");
        assigned
    }

    /// Reserve a contiguous block of `count` positions for `namespace`, returning
    /// the half-open range `[start, start + count)`. Useful for batch ingest: the
    /// operator assigns the whole batch in one step while preserving order and
    /// gap-freeness. A `count` of `0` returns an empty range at the current
    /// position and does not advance the counter.
    ///
    /// # Errors
    /// Returns [`Error::SequenceOverflow`] if the block would overflow `u64`.
    pub fn reserve(&mut self, namespace: &Namespace, count: u64) -> Result<Range<u64>> {
        let slot = self.next.entry(namespace.as_str().to_string()).or_insert(0);
        let start = *slot;
        let end = start
            .checked_add(count)
            .ok_or_else(|| Error::SequenceOverflow {
                namespace: namespace.as_str().to_string(),
            })?;
        *slot = end;
        Ok(start..end)
    }

    /// Re-seat the next position for `namespace` from durable storage (e.g. on
    /// restart, to `last_committed_position + 1`).
    ///
    /// This is **monotonic-safe**: it may only move the counter *forward* (or
    /// leave it unchanged). An attempt to set it below the current in-memory
    /// position is rejected rather than silently rewinding, because rewinding
    /// would re-issue an already-assigned position and break append-only
    /// ordering.
    ///
    /// # Errors
    /// Returns [`Error::SequenceRegression`] if `next` is below the current
    /// position for `namespace`.
    pub fn resume_from(&mut self, namespace: &Namespace, next: u64) -> Result<()> {
        let current = self.peek(namespace);
        if next < current {
            return Err(Error::SequenceRegression {
                namespace: namespace.as_str().to_string(),
                current,
                requested: next,
            });
        }
        self.next.insert(namespace.as_str().to_string(), next);
        Ok(())
    }
}

/// An **idempotent-append** deduplication key: a 64-byte SHA3-512 digest that is
/// a deterministic function of `(namespace, payload)`.
///
/// An ingest pipeline keys in-flight and recently-committed records by their
/// `DedupKey`; a re-submission (network retry, at-least-once delivery, a client
/// replaying a request) produces the *same* key and can be dropped before it
/// double-appends. The key is post-quantum (SHA3-512), domain-separated, and
/// namespace-scoped, so keys never collide across namespaces or across the two
/// derivation modes.
///
/// Two derivations are offered:
///
/// - [`DedupKey::from_record`] keys on the **content** itself (the canonical
///   leaf bytes). Identical content in the same namespace is the same record.
/// - [`DedupKey::from_token`] keys on a **client-supplied idempotency token**
///   (e.g. a request UUID). Use this when the same logical submission may carry
///   non-identical bytes (timestamps, nonces) yet must append at most once.
///
/// The key is opaque; compare keys for equality or use [`DedupKey::as_bytes`] /
/// [`DedupKey::to_hex`] as a storage index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DedupKey([u8; 64]);

impl DedupKey {
    /// Derive a content-addressed dedup key from a namespace and the canonical
    /// record bytes: `SHA3-512_ctx("…/content/v1", lp(ns) || lp(payload))`.
    #[must_use]
    pub fn from_record(namespace: &Namespace, payload: &[u8]) -> Self {
        Self::derive(DEDUP_CONTENT_CONTEXT, namespace, payload)
    }

    /// Derive a dedup key from a namespace and a client-supplied idempotency
    /// token: `SHA3-512_ctx("…/token/v1", lp(ns) || lp(token))`.
    #[must_use]
    pub fn from_token(namespace: &Namespace, token: &[u8]) -> Self {
        Self::derive(DEDUP_TOKEN_CONTEXT, namespace, token)
    }

    fn derive(context: &str, namespace: &Namespace, payload: &[u8]) -> Self {
        let mut input = Vec::with_capacity(8 + namespace.as_str().len() + payload.len());
        push_lp(&mut input, namespace.as_str().as_bytes());
        push_lp(&mut input, payload);
        Self(metamorphic_crypto::hash::sha3_512_with_context(
            context, &input,
        ))
    }

    /// The raw 64-byte key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// The key as lowercase hex (128 chars) — a convenient storage-index form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        crate::encoding::hex_encode(&self.0)
    }
}

/// A deterministic **flush plan**: the exact set of C2SP `tlog-tiles`
/// coordinates whose bytes change when a log grows from `old_size` to
/// `new_size`, split into Merkle tiles and level-0 entry bundles.
///
/// This is what an operator's writer flushes after sequencing a batch: every
/// other tile in the tree is already finalized and byte-identical, so only these
/// need to be (re)written to object storage. Computed purely from
/// [`crate::tile`] geometry — it changes no canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushPlan {
    /// Merkle tiles (`tile/<L>/<N>[.p/<W>]`) to (re)write, in
    /// [`tiles_for_size`] order (level 0 first, then by index).
    pub tiles: Vec<Tile>,
    /// Level-0 entry-bundle tiles (`tile/entries/<N>[.p/<W>]`) to (re)write.
    pub entry_bundles: Vec<Tile>,
}

/// The half-open leaf range `[start, end)` a tile covers, computed in `u128` to
/// avoid overflow at high levels. `end` is the exclusive rightmost leaf index.
fn tile_leaf_end(tile: &Tile) -> u128 {
    let span = 256u128.pow(u32::from(tile.level()));
    (u128::from(tile.index()) * 256 + u128::from(tile.width())) * span
}

/// Whether a tile in the `new_size` tree changed relative to `old_size`: it did
/// iff it covers at least one leaf at or beyond `old_size` (a brand-new tile, or
/// a partial tile that grew). Tiles entirely below `old_size` were finalized
/// identically and need no rewrite.
fn tile_is_dirty(tile: &Tile, old_size: u64) -> bool {
    tile_leaf_end(tile) > u128::from(old_size)
}

/// The Merkle tiles that must be (re)written when the log grows from `old_size`
/// to `new_size`.
///
/// Returns them in [`tiles_for_size`] order. Tiles entirely contained below
/// `old_size` are omitted (already finalized, byte-identical).
///
/// # Errors
/// Returns [`Error::SizeRegression`] if `new_size < old_size` — a tiled log is
/// append-only and never shrinks.
pub fn tiles_to_flush(old_size: u64, new_size: u64) -> Result<Vec<Tile>> {
    if new_size < old_size {
        return Err(Error::SizeRegression {
            size1: old_size,
            size2: new_size,
        });
    }
    Ok(tiles_for_size(new_size)
        .into_iter()
        .filter(|t| tile_is_dirty(t, old_size))
        .collect())
}

/// The level-0 **entry-bundle** tiles that must be (re)written when the log
/// grows from `old_size` to `new_size`. These mirror the dirty level-0 Merkle
/// tiles (the entries served alongside `tile/0/...`).
///
/// # Errors
/// Returns [`Error::SizeRegression`] if `new_size < old_size`.
pub fn entry_bundles_to_flush(old_size: u64, new_size: u64) -> Result<Vec<Tile>> {
    Ok(tiles_to_flush(old_size, new_size)?
        .into_iter()
        .filter(|t| t.level() == 0)
        .collect())
}

/// Compute the full [`FlushPlan`] for growing the log from `old_size` to
/// `new_size`.
///
/// # Errors
/// Returns [`Error::SizeRegression`] if `new_size < old_size`.
pub fn plan_flush(old_size: u64, new_size: u64) -> Result<FlushPlan> {
    let tiles = tiles_to_flush(old_size, new_size)?;
    let entry_bundles = tiles.iter().filter(|t| t.level() == 0).copied().collect();
    Ok(FlushPlan {
        tiles,
        entry_bundles,
    })
}

/// The object-storage / CDN **read-path trait** — an interface only.
///
/// A tiled transparency log serves its tree as immutable, content-addressed
/// objects fetched by coordinate (see [`crate::tile`]); a verifier or monitor
/// recomputes roots and proofs from those bytes. This trait abstracts that fetch
/// so the verification core composes with *any* backend (S3, GCS, a CDN edge, a
/// local mirror, a test fixture). **This crate ships no implementation and
/// performs no I/O** — backends live in the operator layer. The associated
/// [`TileReader::Error`] lets implementations surface their own error type
/// without this crate depending on any I/O or async machinery.
pub trait TileReader {
    /// The backend's fetch-error type.
    type Error;

    /// Fetch the raw bytes of the Merkle tile at `tile`'s coordinate
    /// (`tile.path()`), i.e. `tile.width()` consecutive 32-byte hashes.
    ///
    /// # Errors
    /// Returns the backend's error if the object cannot be fetched.
    fn read_tile(&self, tile: &Tile) -> core::result::Result<Vec<u8>, Self::Error>;

    /// Fetch the raw bytes of the level-0 entry bundle at `tile`'s coordinate
    /// (`tile.entries_path()`).
    ///
    /// # Errors
    /// Returns the backend's error if the object cannot be fetched.
    fn read_entry_bundle(&self, tile: &Tile) -> core::result::Result<Vec<u8>, Self::Error>;
}

/// Error from the [`recompute_root_via`] read-path bridge: either the backend
/// failed to fetch a tile, or a fetched tile was malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadPathError<E> {
    /// The [`TileReader`] backend failed to fetch a tile.
    Backend(E),
    /// A fetched tile was structurally invalid (wrong byte length for its
    /// declared width). Wraps a [`crate::Error`].
    Tile(Error),
}

/// Logic-only bridge: read the level-0 tiles of a tree of `size` leaves through
/// any [`TileReader`] and recompute the RFC 6962 root via
/// [`crate::tile::recompute_root`].
///
/// This performs **no I/O itself** — every byte comes from the supplied reader.
/// It exists to demonstrate (and let callers reuse) that the read-path trait
/// composes directly with the verification core: feed the concatenated level-0
/// leaf hashes through the same fixed RFC 6962 hashing and you reproduce the
/// root a checkpoint commits to. `size == 0` yields the empty root.
///
/// # Errors
/// Returns [`ReadPathError::Backend`] if the reader fails, or
/// [`ReadPathError::Tile`] if a returned tile's byte length does not match its
/// declared width.
pub fn recompute_root_via<R: TileReader>(
    reader: &R,
    size: u64,
) -> core::result::Result<Hash, ReadPathError<R::Error>> {
    // Do not pre-allocate from the caller-supplied `size`: the reader may fail
    // before producing any hash, so capacity grows with what is actually read.
    let mut leaf_hashes = Vec::new();
    for tile in tiles_for_size(size).into_iter().filter(|t| t.level() == 0) {
        let bytes = reader.read_tile(&tile).map_err(ReadPathError::Backend)?;
        let hashes = tile.hashes(&bytes).map_err(ReadPathError::Tile)?;
        leaf_hashes.extend_from_slice(&hashes);
    }
    Ok(recompute_root(&leaf_hashes))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use std::collections::HashMap;

    fn ns(s: &str) -> Namespace {
        Namespace::parse(s).unwrap()
    }

    #[test]
    fn sequencer_is_monotonic_and_per_namespace() {
        let mut seq = Sequencer::new();
        let a = ns("alpha");
        let b = ns("beta");
        assert_eq!(seq.next(&a), 0);
        assert_eq!(seq.next(&a), 1);
        assert_eq!(seq.next(&b), 0); // independent namespace
        assert_eq!(seq.next(&a), 2);
        assert_eq!(seq.peek(&a), 3);
        assert_eq!(seq.peek(&b), 1);
    }

    #[test]
    fn reserve_assigns_contiguous_block() {
        let mut seq = Sequencer::new();
        let a = ns("alpha");
        assert_eq!(seq.next(&a), 0);
        assert_eq!(seq.reserve(&a, 5).unwrap(), 1..6);
        assert_eq!(seq.next(&a), 6);
        // Zero-count reservation does not advance.
        assert_eq!(seq.reserve(&a, 0).unwrap(), 7..7);
        assert_eq!(seq.peek(&a), 7);
    }

    #[test]
    fn resume_from_is_monotonic_safe() {
        let mut seq = Sequencer::new();
        let a = ns("alpha");
        seq.next(&a);
        seq.next(&a); // peek now 2
        seq.resume_from(&a, 10).unwrap(); // jump forward (durable max+1)
        assert_eq!(seq.next(&a), 10);
        // Re-seating to the same position is allowed.
        seq.resume_from(&a, 11).unwrap();
        // Rewinding is rejected.
        assert!(matches!(
            seq.resume_from(&a, 5),
            Err(Error::SequenceRegression {
                current: 11,
                requested: 5,
                ..
            })
        ));
    }

    #[test]
    fn dedup_key_is_deterministic_and_scoped() {
        let a = ns("alpha");
        let b = ns("beta");
        let k1 = DedupKey::from_record(&a, b"hello");
        let k2 = DedupKey::from_record(&a, b"hello");
        assert_eq!(k1, k2); // same input => same key
        assert_ne!(k1, DedupKey::from_record(&a, b"world")); // content matters
        assert_ne!(k1, DedupKey::from_record(&b, b"hello")); // namespace-scoped
        // Token mode is domain-separated from content mode.
        assert_ne!(
            DedupKey::from_record(&a, b"x"),
            DedupKey::from_token(&a, b"x")
        );
        assert_eq!(k1.to_hex().len(), 128);
    }

    #[test]
    fn flush_geometry_matches_tile_substrate() {
        // From a fresh log, the flush set equals the full tile set for new_size.
        let plan = plan_flush(0, 70_000).unwrap();
        assert_eq!(plan.tiles, tiles_for_size(70_000));
        assert!(plan.entry_bundles.iter().all(|t| t.level() == 0));
        assert_eq!(
            plan.entry_bundles.len(),
            tiles_for_size(70_000)
                .iter()
                .filter(|t| t.level() == 0)
                .count()
        );
    }

    #[test]
    fn flush_only_touches_changed_tiles() {
        // Grow 256 -> 512. Level-0 tile 0 (leaves 0..256) is finalized and must
        // NOT be reflushed; tile 1 and the new partial level-1 tile must.
        let dirty = tiles_to_flush(256, 512).unwrap();
        assert!(
            !dirty
                .iter()
                .any(|t| t.level() == 0 && t.index() == 0 && !t.is_partial()),
            "finalized level-0 tile 0 must not be reflushed"
        );
        assert!(
            dirty.iter().any(|t| t.level() == 0 && t.index() == 1),
            "new level-0 tile 1 must be flushed"
        );
        assert!(
            dirty.iter().any(|t| t.level() == 1),
            "grown level-1 partial tile must be flushed"
        );
    }

    #[test]
    fn flush_noop_when_size_unchanged() {
        assert!(tiles_to_flush(1000, 1000).unwrap().is_empty());
        assert_eq!(
            plan_flush(1000, 1000).unwrap(),
            FlushPlan {
                tiles: vec![],
                entry_bundles: vec![]
            }
        );
    }

    #[test]
    fn flush_rejects_size_regression() {
        assert!(matches!(
            tiles_to_flush(500, 499),
            Err(Error::SizeRegression {
                size1: 500,
                size2: 499
            })
        ));
        assert!(plan_flush(500, 499).is_err());
        assert!(entry_bundles_to_flush(500, 499).is_err());
    }

    /// An in-memory [`TileReader`] used only to prove the read-path bridge
    /// composes with the verification core. NOT a storage backend.
    struct MemReader {
        tiles: HashMap<String, Vec<u8>>,
    }

    impl MemReader {
        fn from_tree(tree: &MerkleTree, size: u64) -> Self {
            let mut tiles = HashMap::new();
            for tile in tiles_for_size(size).into_iter().filter(|t| t.level() == 0) {
                let start = tile.index() * u64::from(crate::tile::TILE_WIDTH);
                let mut bytes = Vec::new();
                for i in 0..u64::from(tile.width()) {
                    bytes.extend_from_slice(&tree.leaf_hash(start + i).unwrap());
                }
                tiles.insert(tile.path(), bytes);
            }
            Self { tiles }
        }
    }

    impl TileReader for MemReader {
        type Error = String;

        fn read_tile(&self, tile: &Tile) -> core::result::Result<Vec<u8>, String> {
            self.tiles
                .get(&tile.path())
                .cloned()
                .ok_or_else(|| format!("missing tile {}", tile.path()))
        }

        fn read_entry_bundle(&self, tile: &Tile) -> core::result::Result<Vec<u8>, String> {
            self.tiles
                .get(&tile.path())
                .cloned()
                .ok_or_else(|| format!("missing entries {}", tile.entries_path()))
        }
    }

    #[test]
    fn read_path_bridge_recomputes_checkpoint_root() {
        let mut tree = MerkleTree::new();
        for i in 0u32..1000 {
            tree.push(&i.to_be_bytes());
        }
        let reader = MemReader::from_tree(&tree, 1000);
        let root = recompute_root_via(&reader, 1000).unwrap();
        assert_eq!(root, tree.root());
    }

    #[test]
    fn read_path_bridge_empty_tree() {
        let reader = MemReader {
            tiles: HashMap::new(),
        };
        assert_eq!(
            recompute_root_via(&reader, 0).unwrap(),
            crate::merkle::empty_root()
        );
    }

    #[test]
    fn read_path_bridge_surfaces_backend_error() {
        // Reader with no tiles but a non-empty size => backend miss.
        let reader = MemReader {
            tiles: HashMap::new(),
        };
        assert!(matches!(
            recompute_root_via(&reader, 300),
            Err(ReadPathError::Backend(_))
        ));
    }

    #[test]
    fn read_path_bridge_surfaces_malformed_tile() {
        let mut tiles = HashMap::new();
        // Level-0 tile 0 for size 1 is a partial tile of width 1 (32 bytes);
        // give it the wrong length to trigger a Tile error.
        let t = tiles_for_size(1)[0];
        tiles.insert(t.path(), vec![0u8; 31]);
        let reader = MemReader { tiles };
        assert!(matches!(
            recompute_root_via(&reader, 1),
            Err(ReadPathError::Tile(_))
        ));
    }
}
