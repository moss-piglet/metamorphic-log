//! KEYTRANS **prefix tree** (`draft-ietf-keytrans-protocol-04` §3.3 / §10.9):
//! a bit-traversal trie mapping each `(label, version)` search key — the VRF
//! output — to a commitment to the label's value.
//!
//! ## Structure (NEW — different domain bytes than CONIKS)
//!
//! Unlike the CONIKS sparse depth-256 SHA3-512 tree ([`crate::coniks`]), this is
//! a *compressed* trie: a leaf sits at whatever depth its prefix first becomes
//! unique, and a parent node exists only where two keys diverge. Hashing uses
//! the cipher-suite hash (SHA-256, [`NH`]-byte nodes) with KEYTRANS's own
//! domain-separation bytes (§10.9):
//!
//! - **leaf**: `Hash(0x01 || vrf_output || commitment)`
//! - **parent**: `Hash(0x02 || left || right)`
//! - a **missing child** (a stand-in for an absent subtree) is the all-zero
//!   byte string `0^Nh`.
//!
//! These bytes (`0x01` / `0x02`) and the SHA-256 suite hash are deliberately
//! distinct from both RFC 6962 ([`crate::merkle`]) and the CONIKS context-label
//! scheme, so prefix-tree nodes never collide or cross-verify with either.
//!
//! ## Traversal
//!
//! Search keys are consumed most-significant-bit-first: bit 0 is the MSB of byte
//! 0 and selects the root's left (`0`) or right (`1`) child, bit 1 the next
//! level, and so on. Because VRF outputs are unique per `(label, version)`, no
//! two stored keys are equal, so recursion always terminates at a leaf (one key)
//! or a stand-in (no keys) well before the 256-bit key is exhausted.
//!
//! This slice computes prefix-tree **roots** and the per-leaf membership
//! hashing; inclusion / non-inclusion *proof verification* lands in Slice 9d.

use metamorphic_crypto::hash::sha256;

use crate::commitment::{COMMITMENT_LEN, Commitment};

use super::NH;

/// Length in bytes of a prefix-tree search key (a VRF output, truncated to the
/// suite's `VRF.Nh`). The experimental private suite truncates the 64-byte
/// ECVRF-Ed25519 output to 32 bytes.
pub const SEARCH_KEY_LEN: usize = 32;

/// Domain-separation byte for a prefix-tree leaf (§10.9).
const LEAF_PREFIX: u8 = 0x01;
/// Domain-separation byte for a prefix-tree parent (§10.9).
const PARENT_PREFIX: u8 = 0x02;

/// The stand-in value for a missing child: `0^Nh` (§10.9).
#[must_use]
pub fn stand_in() -> [u8; NH] {
    [0u8; NH]
}

/// The leaf value for a stored `(vrf_output, commitment)` pair (§10.9):
/// `Hash(0x01 || vrf_output || commitment)`.
#[must_use]
pub fn hash_leaf(vrf_output: &[u8; SEARCH_KEY_LEN], commitment: &Commitment) -> [u8; NH] {
    let mut buf = [0u8; 1 + SEARCH_KEY_LEN + COMMITMENT_LEN];
    buf[0] = LEAF_PREFIX;
    buf[1..1 + SEARCH_KEY_LEN].copy_from_slice(vrf_output);
    buf[1 + SEARCH_KEY_LEN..].copy_from_slice(commitment.as_bytes());
    sha256(&buf)
}

/// The parent value for two child values (§10.9):
/// `Hash(0x02 || left || right)`, using [`stand_in`] for an absent child.
#[must_use]
pub fn hash_parent(left: &[u8; NH], right: &[u8; NH]) -> [u8; NH] {
    let mut buf = [0u8; 1 + 2 * NH];
    buf[0] = PARENT_PREFIX;
    buf[1..1 + NH].copy_from_slice(left);
    buf[1 + NH..].copy_from_slice(right);
    sha256(&buf)
}

/// Bit `i` of a search key, most-significant-bit-first (bit 0 = MSB of byte 0).
fn key_bit(key: &[u8; SEARCH_KEY_LEN], i: usize) -> u8 {
    (key[i / 8] >> (7 - (i % 8))) & 1
}

/// Compute the value of the subtree at `depth` over `entries`, each a
/// `(search_key, precomputed_leaf_value)` pair.
///
/// - zero entries → a [`stand_in`] (the subtree is absent),
/// - one entry → its leaf value (a leaf sits wherever it is alone),
/// - many entries → a parent over the `0`/`1` partition of the `depth`-th bit.
fn subtree(entries: &[(&[u8; SEARCH_KEY_LEN], [u8; NH])], depth: usize) -> [u8; NH] {
    match entries.len() {
        0 => stand_in(),
        1 => entries[0].1,
        _ => {
            let (left, right): (Vec<_>, Vec<_>) = entries
                .iter()
                .partition(|(key, _)| key_bit(key, depth) == 0);
            let l = subtree(&left, depth + 1);
            let r = subtree(&right, depth + 1);
            hash_parent(&l, &r)
        }
    }
}

/// A prefix tree: an in-memory map from a search key (VRF output) to a
/// commitment, able to compute its root.
///
/// The operator maintains one logical prefix tree; each modification yields a
/// new root that is recorded in the log tree (the combined-tree construction,
/// [`super`]). This type is the prover side; relying-party proof verification
/// arrives in Slice 9d.
#[derive(Clone, Debug, Default)]
pub struct PrefixTree {
    leaves: Vec<([u8; SEARCH_KEY_LEN], [u8; NH])>,
}

impl PrefixTree {
    /// Create an empty prefix tree.
    #[must_use]
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Insert or replace the entry for `vrf_output`, committing to it as
    /// `Hash(0x01 || vrf_output || commitment)`.
    pub fn insert(&mut self, vrf_output: [u8; SEARCH_KEY_LEN], commitment: &Commitment) {
        let leaf = hash_leaf(&vrf_output, commitment);
        match self.leaves.iter_mut().find(|(k, _)| *k == vrf_output) {
            Some(entry) => entry.1 = leaf,
            None => self.leaves.push((vrf_output, leaf)),
        }
    }

    /// The number of entries in the tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The prefix-tree root. An empty tree has the [`stand_in`] root `0^Nh`.
    #[must_use]
    pub fn root(&self) -> [u8; NH] {
        let entries: Vec<_> = self.leaves.iter().map(|(k, v)| (k, *v)).collect();
        subtree(&entries, 0)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::commitment::Opening;
    use crate::commitment::commit_with_opening;

    fn commitment(tag: u8) -> Commitment {
        commit_with_opening(
            "test/keytrans-commitment/v1",
            &[tag; 4],
            &Opening::from_bytes([tag; 32]),
        )
    }

    fn key(byte0: u8) -> [u8; SEARCH_KEY_LEN] {
        let mut k = [0u8; SEARCH_KEY_LEN];
        k[0] = byte0;
        k
    }

    #[test]
    fn empty_root_is_stand_in() {
        assert_eq!(PrefixTree::new().root(), stand_in());
    }

    #[test]
    fn single_entry_root_is_its_leaf_value() {
        let mut t = PrefixTree::new();
        let k = key(0x80);
        let c = commitment(1);
        t.insert(k, &c);
        assert_eq!(t.root(), hash_leaf(&k, &c));
    }

    #[test]
    fn two_diverging_keys_form_a_parent_at_first_differing_bit() {
        // 0x00.. has MSB 0, 0x80.. has MSB 1: they split at the root.
        let mut t = PrefixTree::new();
        let k0 = key(0x00);
        let k1 = key(0x80);
        let c0 = commitment(1);
        let c1 = commitment(2);
        t.insert(k0, &c0);
        t.insert(k1, &c1);

        let expected = hash_parent(&hash_leaf(&k0, &c0), &hash_leaf(&k1, &c1));
        assert_eq!(t.root(), expected);
    }

    #[test]
    fn keys_sharing_a_prefix_descend_before_branching() {
        // 0x00 and 0x40 share bit0=0, differ at bit1 (0 vs 1). The root is a
        // parent whose left child is itself a parent (the two keys), and whose
        // right child is a stand-in.
        let mut t = PrefixTree::new();
        let k0 = key(0x00); // 0000_0000
        let k1 = key(0x40); // 0100_0000
        let c0 = commitment(3);
        let c1 = commitment(4);
        t.insert(k0, &c0);
        t.insert(k1, &c1);

        let inner = hash_parent(&hash_leaf(&k0, &c0), &hash_leaf(&k1, &c1));
        let expected = hash_parent(&inner, &stand_in());
        assert_eq!(t.root(), expected);
    }

    #[test]
    fn leaf_and_parent_prefixes_differ() {
        let k = key(0x80);
        let c = commitment(5);
        let leaf = hash_leaf(&k, &c);
        // A parent over the same value bytes must not collide with the leaf.
        assert_ne!(leaf, hash_parent(&leaf, &stand_in()));
    }

    #[test]
    fn insert_replaces_existing_key() {
        let mut t = PrefixTree::new();
        let k = key(0x80);
        t.insert(k, &commitment(1));
        t.insert(k, &commitment(2));
        assert_eq!(t.len(), 1);
        assert_eq!(t.root(), hash_leaf(&k, &commitment(2)));
    }

    #[test]
    fn root_is_order_independent() {
        let k0 = key(0x00);
        let k1 = key(0x80);
        let c0 = commitment(1);
        let c1 = commitment(2);

        let mut a = PrefixTree::new();
        a.insert(k0, &c0);
        a.insert(k1, &c1);

        let mut b = PrefixTree::new();
        b.insert(k1, &c1);
        b.insert(k0, &c0);

        assert_eq!(a.root(), b.root());
    }
}
