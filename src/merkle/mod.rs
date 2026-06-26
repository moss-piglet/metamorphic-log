//! Layer-1: RFC 6962 Merkle tree hashing (and an in-memory reference tree).
//!
//! This module implements the **fixed, audited** tree-node hashing scheme from
//! [RFC 6962] §2.1, using the ecosystem SHA-256 exposed by
//! [`metamorphic_crypto`](crate):
//!
//! ```text
//! empty root  = SHA-256()                      (hash of the empty string)
//! leaf hash   = SHA-256(0x00 || leaf_bytes)
//! node hash   = SHA-256(0x01 || left || right)
//! ```
//!
//! The `0x00` / `0x01` domain-separation prefixes prevent second-preimage
//! attacks that swap a leaf for an interior node. This layer is **never**
//! affected by per-namespace suite/level choice (#290 / #299 / #324): it is the
//! single hashing scheme every independent witness must recompute, so it
//! deliberately uses ecosystem SHA-256 rather than this platform's default
//! SHA3-512 (the one documented non-SHA3 spot, for witness compatibility —
//! #316).
//!
//! It also provides [`MerkleTree`], a small, allocation-friendly in-memory
//! reference tree that computes RFC 6962 roots and **generates** inclusion and
//! consistency proofs. The proof *verifier* lives in [`crate::proof`]; this
//! generator exists so the verifier can be round-tripped against an independent
//! implementation (see the property tests) and so callers/tests have a ready
//! oracle. Both directions implement the RFC directly — no delegation.
//!
//! [RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962

use metamorphic_crypto::hash::sha256;

/// Length in bytes of an RFC 6962 tree node hash (SHA-256).
pub const HASH_LEN: usize = 32;

/// A 32-byte RFC 6962 Merkle node hash.
pub type Hash = [u8; HASH_LEN];

/// Domain-separation prefix for leaf hashing (`0x00`).
const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix for interior-node hashing (`0x01`).
const NODE_PREFIX: u8 = 0x01;

/// The RFC 6962 hash of the empty tree: `SHA-256("")`.
///
/// An empty log's Merkle Tree Hash is defined as the hash of the empty string.
///
/// ```
/// use metamorphic_log::merkle::empty_root;
/// // SHA-256("") — the well-known all-zero-input digest.
/// assert_eq!(
///     empty_root()[..4],
///     [0xe3, 0xb0, 0xc4, 0x42],
/// );
/// ```
#[inline]
#[must_use]
pub fn empty_root() -> Hash {
    sha256(&[])
}

/// Compute the RFC 6962 leaf hash: `SHA-256(0x00 || leaf_bytes)`.
///
/// `leaf_bytes` is the opaque, app-defined Layer-0 record (e.g. an
/// application's canonical record bytes — see [`crate::leaf`]). The tree
/// treats it as opaque.
///
/// ```
/// use metamorphic_log::merkle::hash_leaf;
/// // RFC 6962 leaf hash of the empty leaf.
/// let h = hash_leaf(b"");
/// assert_eq!(h.len(), 32);
/// ```
#[inline]
#[must_use]
pub fn hash_leaf(leaf_bytes: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(1 + leaf_bytes.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(leaf_bytes);
    sha256(&buf)
}

/// Compute the RFC 6962 interior-node hash:
/// `SHA-256(0x01 || left || right)`.
#[inline]
#[must_use]
pub fn hash_children(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 1 + 2 * HASH_LEN];
    buf[0] = NODE_PREFIX;
    buf[1..1 + HASH_LEN].copy_from_slice(left);
    buf[1 + HASH_LEN..].copy_from_slice(right);
    sha256(&buf)
}

/// Largest power of two strictly less than `n`. Requires `n > 1`.
///
/// This is the RFC 6962 split point `k` used by the recursive tree, inclusion
/// path, and consistency proof definitions.
#[inline]
fn largest_power_of_two_below(n: u64) -> u64 {
    debug_assert!(n > 1);
    // Highest set bit of (n - 1): for n in (2^k, 2^{k+1}] this yields 2^k,
    // matching "largest power of two strictly smaller than n".
    let bits = u64::BITS - (n - 1).leading_zeros();
    1u64 << (bits - 1)
}

/// An in-memory RFC 6962 Merkle tree over a list of leaves.
///
/// Stores leaf hashes only; roots and proofs are computed recursively per
/// RFC 6962 §2.1. Intended as a reference/oracle for the verifier in
/// [`crate::proof`] (round-trip property tests) and for callers that need to
/// produce proofs. It is not optimized for huge trees — the production serving
/// path is tile-based (a later slice).
#[derive(Debug, Clone, Default)]
pub struct MerkleTree {
    leaves: Vec<Hash>,
}

impl MerkleTree {
    /// Create an empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Append an opaque leaf record, returning its zero-based index.
    pub fn push(&mut self, leaf_bytes: &[u8]) -> u64 {
        let index = self.leaves.len() as u64;
        self.leaves.push(hash_leaf(leaf_bytes));
        index
    }

    /// Append an already-computed leaf hash, returning its zero-based index.
    pub fn push_leaf_hash(&mut self, leaf_hash: Hash) -> u64 {
        let index = self.leaves.len() as u64;
        self.leaves.push(leaf_hash);
        index
    }

    /// The number of leaves currently in the tree.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// The leaf hash at `index`, if present.
    #[must_use]
    pub fn leaf_hash(&self, index: u64) -> Option<Hash> {
        self.leaves.get(index as usize).copied()
    }

    /// The RFC 6962 Merkle Tree Hash (root) over the first `size` leaves.
    ///
    /// `size == 0` yields [`empty_root`]. Panics if `size` exceeds the number
    /// of leaves.
    #[must_use]
    pub fn root_at(&self, size: u64) -> Hash {
        assert!(size <= self.size(), "root_at: size exceeds tree size");
        mth(&self.leaves[..size as usize])
    }

    /// The RFC 6962 root over all current leaves.
    #[must_use]
    pub fn root(&self) -> Hash {
        self.root_at(self.size())
    }

    /// Generate an RFC 6962 inclusion proof (audit path) for the leaf at
    /// `index` within the tree of `size` leaves.
    ///
    /// Returns the audit path ordered from the lowest level to the highest,
    /// matching the order [`crate::proof::verify_inclusion`] expects. Panics if
    /// `index >= size` or `size` exceeds the tree.
    #[must_use]
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Vec<Hash> {
        assert!(index < size, "inclusion_proof: index beyond size");
        assert!(
            size <= self.size(),
            "inclusion_proof: size exceeds tree size"
        );
        inclusion_path(index, &self.leaves[..size as usize])
    }

    /// Generate an RFC 6962 consistency proof between `size1` and `size2`.
    ///
    /// Requires `0 < size1 <= size2 <= tree size`. Returns the proof ordered as
    /// [`crate::proof::verify_consistency`] expects.
    #[must_use]
    pub fn consistency_proof(&self, size1: u64, size2: u64) -> Vec<Hash> {
        assert!(size1 > 0, "consistency_proof: size1 must be > 0");
        assert!(size1 <= size2, "consistency_proof: size1 > size2");
        assert!(
            size2 <= self.size(),
            "consistency_proof: size2 exceeds tree size"
        );
        consistency_path(size1, &self.leaves[..size2 as usize])
    }
}

/// RFC 6962 §2.1 Merkle Tree Hash over a slice of leaf hashes.
fn mth(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_below(n as u64) as usize;
            let left = mth(&leaves[..k]);
            let right = mth(&leaves[k..]);
            hash_children(&left, &right)
        }
    }
}

/// RFC 6962 §2.1.1 audit path `PATH(m, D[n])` (lowest level first).
fn inclusion_path(m: u64, leaves: &[Hash]) -> Vec<Hash> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = largest_power_of_two_below(n as u64);
    if m < k {
        let mut path = inclusion_path(m, &leaves[..k as usize]);
        path.push(mth(&leaves[k as usize..]));
        path
    } else {
        let mut path = inclusion_path(m - k, &leaves[k as usize..]);
        path.push(mth(&leaves[..k as usize]));
        path
    }
}

/// RFC 6962 §2.1.2 consistency proof `PROOF(m, D[n])`.
fn consistency_path(m: u64, leaves: &[Hash]) -> Vec<Hash> {
    subproof(m, leaves, true)
}

/// RFC 6962 §2.1.2 `SUBPROOF(m, D[n], b)`.
fn subproof(m: u64, leaves: &[Hash], b: bool) -> Vec<Hash> {
    let n = leaves.len() as u64;
    if m == n {
        if b {
            return Vec::new();
        }
        return vec![mth(leaves)];
    }
    let k = largest_power_of_two_below(n);
    if m <= k {
        let mut proof = subproof(m, &leaves[..k as usize], b);
        proof.push(mth(&leaves[k as usize..]));
        proof
    } else {
        let mut proof = subproof(m - k, &leaves[k as usize..], false);
        proof.push(mth(&leaves[..k as usize]));
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_is_sha256_of_empty() {
        // SHA-256("") full digest.
        let expected = hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(empty_root(), expected);
    }

    #[test]
    fn single_empty_leaf_hash() {
        // RFC 6962 leaf hash of the empty leaf: SHA-256(0x00).
        let expected = hex32("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
        assert_eq!(hash_leaf(b""), expected);
    }

    #[test]
    fn largest_power_of_two_below_cases() {
        assert_eq!(largest_power_of_two_below(2), 1);
        assert_eq!(largest_power_of_two_below(3), 2);
        assert_eq!(largest_power_of_two_below(4), 2);
        assert_eq!(largest_power_of_two_below(5), 4);
        assert_eq!(largest_power_of_two_below(8), 4);
        assert_eq!(largest_power_of_two_below(9), 8);
    }

    /// Hex-decode exactly 32 bytes (test helper).
    fn hex32(s: &str) -> Hash {
        assert_eq!(s.len(), 64, "expected 64 hex chars");
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
