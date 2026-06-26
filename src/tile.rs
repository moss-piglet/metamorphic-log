//! C2SP [`tlog-tiles`] substrate: tile coordinates, paths, and recompute.
//!
//! A tiled transparency log serves its Merkle tree not as dynamic proof
//! endpoints but as a set of immutable, content-addressed **tiles** — each tile
//! a sequence of consecutive RFC 6962 Merkle Tree Hashes at a given tree
//! *level*. A client (or independent witness) fetches the tiles it needs and
//! recomputes any root or proof itself. This module implements the read side:
//! the tile coordinate system, the exact `tile/<L>/<N>[.p/<W>]` path encoding,
//! the tile/entry-bundle byte layout, and the recompute relationship that lets
//! a verifier reproduce a tile (and ultimately the tree root) from the tiles
//! below it, using the same fixed RFC 6962 hashing as [`crate::merkle`].
//!
//! All Merkle operations are SHA-256 per RFC 6962 (the one ecosystem-fixed,
//! witness-recomputable hashing spot — see [`crate::merkle`]); tiles are merely
//! an alternative *encoding* of that same tree.
//!
//! ## Geometry
//!
//! A full tile is exactly **256 hashes** (8,192 bytes). The *n*-th tile at
//! level *l* holds, for *i* in `0..256`, the hash
//! `MTH(D[(n*256+i) * 256^l : (n*256+i+1) * 256^l])`. Its **start index** is
//! `n * 256^(l+1)` and its **end index** is `(n+1) * 256^(l+1)`. The rightmost
//! tiles of a growing tree are **partial** (1..=255 hashes); a partial tile at
//! level *l* for a tree of size *s* has `floor(s / 256^l) mod 256` hashes and
//! MUST NOT be hashed into the level above.
//!
//! [`tlog-tiles`]: https://c2sp.org/tlog-tiles

use crate::error::{Error, Result};
use crate::merkle::{HASH_LEN, Hash, merkle_tree_hash};

/// The width (in hashes) of a full tile, and the tile fan-out per level.
pub const TILE_WIDTH: u16 = 256;

/// The maximum tile level, inclusive (`tile/<L>/...`, `L` in `0..=63`).
pub const MAX_LEVEL: u8 = 63;

/// A C2SP `tlog-tiles` tile coordinate.
///
/// Identifies a tile by its `level`, its `index` within that level, and its
/// `width` in hashes. A width of [`TILE_WIDTH`] (256) is a *full* tile; a width
/// in `1..=255` is a *partial* tile (the rightmost tile of a tree whose size is
/// not a multiple of the tile span).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tile {
    level: u8,
    index: u64,
    width: u16,
}

impl Tile {
    /// Construct a tile coordinate, validating the level and width.
    ///
    /// # Errors
    /// Returns [`Error::MalformedTile`] if `level > 63` or `width` is not in
    /// `1..=256`.
    pub fn new(level: u8, index: u64, width: u16) -> Result<Self> {
        if level > MAX_LEVEL {
            return Err(Error::MalformedTile(format!(
                "level {level} exceeds maximum {MAX_LEVEL}"
            )));
        }
        if width == 0 || width > TILE_WIDTH {
            return Err(Error::MalformedTile(format!(
                "tile width {width} not in 1..=256"
            )));
        }
        Ok(Self {
            level,
            index,
            width,
        })
    }

    /// The tile level (`0` = leaf-hash tiles).
    #[must_use]
    pub fn level(&self) -> u8 {
        self.level
    }

    /// The tile index within its level.
    #[must_use]
    pub fn index(&self) -> u64 {
        self.index
    }

    /// The tile width in hashes (`256` for a full tile).
    #[must_use]
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Whether this is a partial tile (`width < 256`).
    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.width < TILE_WIDTH
    }

    /// The number of serialized bytes a tile of this width occupies
    /// (`width * 32`).
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.width as usize * HASH_LEN
    }

    /// The Merkle tile path `tile/<L>/<N>[.p/<W>]`.
    ///
    /// `<N>` is encoded as zero-padded 3-digit path elements, all but the last
    /// prefixed with `x` (e.g. index `1234067` → `x001/x234/067`). The
    /// `.p/<W>` suffix is present only for partial tiles.
    #[must_use]
    pub fn path(&self) -> String {
        let mut p = format!("tile/{}/{}", self.level, encode_index(self.index));
        if self.is_partial() {
            p.push_str(&format!(".p/{}", self.width));
        }
        p
    }

    /// The entry-bundle path `tile/entries/<N>[.p/<W>]` for this tile's index
    /// and width. Only meaningful for level-0 coordinates, but defined purely
    /// in terms of `(index, width)`.
    #[must_use]
    pub fn entries_path(&self) -> String {
        let mut p = format!("tile/entries/{}", encode_index(self.index));
        if self.is_partial() {
            p.push_str(&format!(".p/{}", self.width));
        }
        p
    }

    /// Parse a Merkle tile path `tile/<L>/<N>[.p/<W>]`.
    ///
    /// # Errors
    /// Returns [`Error::MalformedTile`] if the path does not match the grammar,
    /// including leading-zero levels/widths, malformed index path elements, or
    /// an out-of-range level/width.
    pub fn parse_path(path: &str) -> Result<Self> {
        let rest = path
            .strip_prefix("tile/")
            .ok_or_else(|| Error::MalformedTile(format!("missing 'tile/' prefix: {path:?}")))?;

        // Split the optional partial suffix `.p/<W>`.
        let (coords, width_override) = match rest.split_once(".p/") {
            Some((coords, w)) => {
                let w = parse_decimal_u16(w)?;
                if !(1..TILE_WIDTH).contains(&w) {
                    return Err(Error::MalformedTile(format!(
                        "partial tile width {w} not in 1..=255"
                    )));
                }
                (coords, Some(w))
            }
            None => (rest, None),
        };

        let (level_str, index_str) = coords
            .split_once('/')
            .ok_or_else(|| Error::MalformedTile(format!("missing level/index: {path:?}")))?;

        let level = parse_decimal_u8(level_str)?;
        let index = decode_index(index_str)?;

        let width = match width_override {
            Some(w) => w,
            None => TILE_WIDTH,
        };
        Self::new(level, index, width)
    }

    /// Interpret raw tile bytes as the tile's sequence of 32-byte hashes,
    /// validating that the byte length matches the declared width.
    ///
    /// # Errors
    /// Returns [`Error::MalformedTile`] if `bytes.len() != width * 32`.
    pub fn hashes(&self, bytes: &[u8]) -> Result<Vec<Hash>> {
        if bytes.len() != self.byte_len() {
            return Err(Error::MalformedTile(format!(
                "tile byte length {} does not match width {} ({} bytes)",
                bytes.len(),
                self.width,
                self.byte_len()
            )));
        }
        Ok(bytes
            .chunks_exact(HASH_LEN)
            .map(|c| {
                let mut h = [0u8; HASH_LEN];
                h.copy_from_slice(c);
                h
            })
            .collect())
    }
}

/// The partial-tile width for `level` in a tree of `size` leaves:
/// `floor(size / 256^level) mod 256`. A return of `0` means there is no tile at
/// this level for this size (it is exactly tile-aligned with nothing left
/// over).
#[must_use]
pub fn partial_width(level: u8, size: u64) -> u16 {
    // 256^level == 2^(8*level). For level >= 8 the span exceeds any u64 tree
    // size, so floor(size / span) is 0 and there is no tile at this level.
    // Short-circuit to avoid overflowing the 256^level computation.
    if level >= 8 {
        return 0;
    }
    let span = 256u128.pow(u32::from(level));
    ((u128::from(size) / span) % 256) as u16
}

/// Enumerate every tile required to represent a tree of `size` leaves, ordered
/// level-by-level (level 0 first) and by index within each level.
///
/// For each level, the full tiles come first (each width 256), followed by at
/// most one trailing partial tile. Returns an empty vector for `size == 0`.
///
/// This is the set of tiles a witness fetches to recompute the tree: feeding
/// the concatenated level-0 leaf hashes through [`recompute_root`] reproduces
/// the checkpoint root.
#[must_use]
pub fn tiles_for_size(size: u64) -> Vec<Tile> {
    let mut tiles = Vec::new();
    if size == 0 {
        return tiles;
    }
    for level in 0..=MAX_LEVEL {
        let span = 256u128.pow(u32::from(level));
        if u128::from(size) < span {
            // No subtree of `256^level` leaves fits: this level (and every
            // higher one) holds no hash. The previous level carried the root.
            break;
        }
        let full = (u128::from(size) / (span * 256)) as u64;
        for n in 0..full {
            tiles.push(Tile {
                level,
                index: n,
                width: TILE_WIDTH,
            });
        }
        let partial = partial_width(level, size);
        if partial > 0 {
            tiles.push(Tile {
                level,
                index: full,
                width: partial,
            });
        }
    }
    tiles
}

/// Recompute the RFC 6962 tree root from the in-order leaf hashes of a tree.
///
/// `leaf_hashes` is the concatenation, in index order, of every level-0 tile's
/// hashes (i.e. the per-entry leaf hashes). The result is the Merkle Tree Hash
/// that a checkpoint at this size commits to. This is independent recomputation
/// (#316): the verifier derives the root itself rather than trusting a served
/// value.
#[must_use]
pub fn recompute_root(leaf_hashes: &[Hash]) -> Hash {
    merkle_tree_hash(leaf_hashes)
}

/// Recompute the single hash that the *parent* (level `l+1`) tile stores for a
/// *full* level-`l` tile: the RFC 6962 Merkle Tree Hash over the tile's 256
/// hashes.
///
/// # Errors
/// Returns [`Error::MalformedTile`] if the tile is partial (partial tiles MUST
/// NOT be hashed into the level above, per the spec).
pub fn parent_hash(tile_hashes: &[Hash]) -> Result<Hash> {
    if tile_hashes.len() != TILE_WIDTH as usize {
        return Err(Error::MalformedTile(format!(
            "parent_hash requires a full 256-hash tile, got {}",
            tile_hashes.len()
        )));
    }
    Ok(merkle_tree_hash(tile_hashes))
}

/// Encode a tile index into `x`-prefixed, zero-padded 3-digit path elements.
fn encode_index(n: u64) -> String {
    let mut parts = vec![format!("{:03}", n % 1000)];
    let mut m = n / 1000;
    while m > 0 {
        parts.push(format!("x{:03}", m % 1000));
        m /= 1000;
    }
    parts.reverse();
    parts.join("/")
}

/// Decode an `x`-prefixed, 3-digit path-element index back into a `u64`.
fn decode_index(s: &str) -> Result<u64> {
    let parts: Vec<&str> = s.split('/').collect();
    let malformed = || Error::MalformedTile(format!("malformed tile index path: {s:?}"));
    let mut value: u64 = 0;
    for (i, part) in parts.iter().enumerate() {
        let is_last = i == parts.len() - 1;
        let digits = if is_last {
            part
        } else {
            part.strip_prefix('x').ok_or_else(malformed)?
        };
        if digits.len() != 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(malformed());
        }
        let group: u64 = digits.parse().map_err(|_| malformed())?;
        value = value
            .checked_mul(1000)
            .and_then(|v| v.checked_add(group))
            .ok_or_else(malformed)?;
    }
    Ok(value)
}

/// Parse a decimal `u8` with no leading zeroes (per the tile-path grammar).
fn parse_decimal_u8(s: &str) -> Result<u8> {
    check_no_leading_zero(s)?;
    s.parse::<u8>()
        .map_err(|_| Error::MalformedTile(format!("invalid decimal byte: {s:?}")))
}

/// Parse a decimal `u16` with no leading zeroes (per the tile-path grammar).
fn parse_decimal_u16(s: &str) -> Result<u16> {
    check_no_leading_zero(s)?;
    s.parse::<u16>()
        .map_err(|_| Error::MalformedTile(format!("invalid decimal: {s:?}")))
}

/// Reject empty strings and multi-digit values with a leading zero.
fn check_no_leading_zero(s: &str) -> Result<()> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::MalformedTile(format!(
            "not a decimal integer: {s:?}"
        )));
    }
    if s.len() > 1 && s.starts_with('0') {
        return Err(Error::MalformedTile(format!(
            "leading zero not allowed: {s:?}"
        )));
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::merkle::{MerkleTree, hash_leaf};
    use proptest::prelude::*;

    #[test]
    fn index_encoding_spec_example() {
        // The worked example from the tlog-tiles spec.
        assert_eq!(encode_index(1_234_067), "x001/x234/067");
        assert_eq!(encode_index(0), "000");
        assert_eq!(encode_index(67), "067");
        assert_eq!(encode_index(1234), "x001/234");
    }

    #[test]
    fn path_round_trip_full_and_partial() {
        let full = Tile::new(2, 1_234_067, TILE_WIDTH).unwrap();
        assert_eq!(full.path(), "tile/2/x001/x234/067");
        assert_eq!(Tile::parse_path(&full.path()).unwrap(), full);

        let partial = Tile::new(1, 5, 17).unwrap();
        assert_eq!(partial.path(), "tile/1/005.p/17");
        assert_eq!(Tile::parse_path(&partial.path()).unwrap(), partial);
    }

    #[test]
    fn parse_rejects_bad_paths() {
        assert!(Tile::parse_path("tile/64/000").is_err()); // level too high
        assert!(Tile::parse_path("tile/00/000").is_err()); // leading zero level
        assert!(Tile::parse_path("tile/0/00").is_err()); // index group not 3 digits
        assert!(Tile::parse_path("tile/0/000.p/256").is_err()); // partial width 256
        assert!(Tile::parse_path("tile/0/000.p/0").is_err()); // partial width 0
        assert!(Tile::parse_path("tile/0/1234/067").is_err()); // missing x prefix
        assert!(Tile::parse_path("checkpoint").is_err());
    }

    #[test]
    fn partial_width_does_not_overflow_for_high_levels() {
        // Levels >= 8 have a span exceeding any u64 size: no tile, no panic.
        assert_eq!(partial_width(8, u64::MAX), 0);
        assert_eq!(partial_width(MAX_LEVEL, u64::MAX), 0);
    }

    #[test]
    fn partial_width_spec_example() {
        // tlog-tiles spec: a tree of size 70,000.
        let size = 70_000;
        assert_eq!(partial_width(0, size), 112); // 70000 mod 256
        assert_eq!(partial_width(1, size), 17); // floor(70000/256)=273; 273 mod 256
        assert_eq!(partial_width(2, size), 1); // floor(70000/65536)=1
    }

    #[test]
    fn tiles_for_size_70000_matches_spec() {
        // 273 full L0 tiles + 1 partial(112) L0 + 1 full L1 + 1 partial(17) L1
        // + 1 partial(1) L2.
        let tiles = tiles_for_size(70_000);
        let l0: Vec<_> = tiles.iter().filter(|t| t.level == 0).collect();
        let l1: Vec<_> = tiles.iter().filter(|t| t.level == 1).collect();
        let l2: Vec<_> = tiles.iter().filter(|t| t.level == 2).collect();

        assert_eq!(l0.iter().filter(|t| !t.is_partial()).count(), 273);
        assert_eq!(l0.iter().filter(|t| t.is_partial()).count(), 1);
        assert_eq!(l0.last().unwrap().width, 112);

        assert_eq!(l1.iter().filter(|t| !t.is_partial()).count(), 1);
        assert_eq!(l1.last().unwrap().width, 17);

        assert_eq!(l2.len(), 1);
        assert_eq!(l2[0].width, 1);
    }

    #[test]
    fn tree_of_size_256_has_partial_level1_width_1() {
        // Spec: a tree of size 256 is a full level-0 tile and a partial level-1
        // tile of width 1.
        let tiles = tiles_for_size(256);
        assert_eq!(tiles.len(), 2);
        assert_eq!((tiles[0].level, tiles[0].width), (0, 256));
        assert_eq!((tiles[1].level, tiles[1].width), (1, 1));
    }

    #[test]
    fn parent_hash_matches_oracle_subtree_root() {
        // A full level-0 tile of 256 leaf hashes recomputes to the level-1 entry
        // (the subtree root over those 256 leaves) per the oracle MerkleTree.
        let mut tree = MerkleTree::new();
        let leaves: Vec<Hash> = (0u32..256).map(|i| hash_leaf(&i.to_be_bytes())).collect();
        for h in &leaves {
            tree.push_leaf_hash(*h);
        }
        let oracle_root = tree.root();
        assert_eq!(parent_hash(&leaves).unwrap(), oracle_root);
        assert!(parent_hash(&leaves[..255]).is_err());
    }

    #[test]
    fn recompute_root_matches_oracle() {
        let mut tree = MerkleTree::new();
        let mut leaf_hashes = Vec::new();
        for i in 0u32..1000 {
            let h = hash_leaf(&i.to_be_bytes());
            leaf_hashes.push(h);
            tree.push_leaf_hash(h);
        }
        assert_eq!(recompute_root(&leaf_hashes), tree.root());
    }

    #[test]
    fn hashes_validates_length() {
        let t = Tile::new(0, 0, 2).unwrap();
        assert!(t.hashes(&[0u8; 64]).is_ok());
        assert!(t.hashes(&[0u8; 63]).is_err());
        assert!(t.hashes(&[0u8; 96]).is_err());
    }

    proptest! {
        #[test]
        fn index_round_trip(n in 0u64..100_000_000) {
            prop_assert_eq!(decode_index(&encode_index(n)).unwrap(), n);
        }

        #[test]
        fn tile_path_round_trip(
            level in 0u8..=MAX_LEVEL,
            index in 0u64..10_000_000,
            width in 1u16..=TILE_WIDTH,
        ) {
            let t = Tile::new(level, index, width).unwrap();
            prop_assert_eq!(Tile::parse_path(&t.path()).unwrap(), t);
        }
    }
}
