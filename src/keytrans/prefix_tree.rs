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
use crate::error::{Error, Result};

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
/// `(search_key, commitment)` pair.
///
/// - zero entries → a [`stand_in`] (the subtree is absent),
/// - one entry → its leaf value (a leaf sits wherever it is alone),
/// - many entries → a parent over the `0`/`1` partition of the `depth`-th bit.
fn subtree(entries: &[(&[u8; SEARCH_KEY_LEN], &Commitment)], depth: usize) -> [u8; NH] {
    match entries.len() {
        0 => stand_in(),
        1 => hash_leaf(entries[0].0, entries[0].1),
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
    leaves: Vec<([u8; SEARCH_KEY_LEN], Commitment)>,
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
        match self.leaves.iter_mut().find(|(k, _)| *k == vrf_output) {
            Some(entry) => entry.1 = commitment.clone(),
            None => self.leaves.push((vrf_output, commitment.clone())),
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
        let entries: Vec<_> = self.leaves.iter().map(|(k, c)| (k, c)).collect();
        subtree(&entries, 0)
    }

    /// Generate a single-key membership proof for `search_key` (§11.2).
    ///
    /// Returns an [`PrefixSearchResultType::Inclusion`] proof if `search_key` is
    /// stored, or one of the two non-inclusion shapes otherwise:
    /// [`PrefixSearchResultType::NonInclusionLeaf`] when the search terminates at
    /// a *different* leaf, or [`PrefixSearchResultType::NonInclusionParent`] when
    /// it terminates at a parent whose child in `search_key`'s direction is
    /// absent (a [`stand_in`]).
    ///
    /// The returned [`PrefixProof`] carries the copath sibling values
    /// (`elements`) needed to recompute the root from public inputs via
    /// [`verify_inclusion`] / [`verify_absence`]; it never includes
    /// `search_key`'s own committed value, so an inclusion proof is checked by
    /// re-deriving the leaf from the relying party's `(value, opening)`.
    #[must_use]
    pub fn prove(&self, search_key: &[u8; SEARCH_KEY_LEN]) -> PrefixProof {
        let entries: Vec<_> = self.leaves.iter().map(|(k, c)| (k, c)).collect();
        let mut copath = Vec::new();
        let (result_type, leaf) = prove_subtree(&entries, search_key, 0, &mut copath);
        copath.reverse();
        let depth = match result_type {
            PrefixSearchResultType::NonInclusionParent => copath.len().saturating_sub(1),
            _ => copath.len(),
        };
        PrefixProof {
            result_type,
            leaf,
            depth: depth as u8,
            copath,
        }
    }
}

/// Recursively build a single-key proof, pushing each level's sibling subtree
/// value into `copath` (deepest-first; the caller reverses it to depth order).
fn prove_subtree(
    entries: &[(&[u8; SEARCH_KEY_LEN], &Commitment)],
    key: &[u8; SEARCH_KEY_LEN],
    depth: usize,
    copath: &mut Vec<[u8; NH]>,
) -> (PrefixSearchResultType, Option<PrefixLeaf>) {
    match entries.len() {
        // Only reachable at the root: the whole tree is empty.
        0 => (PrefixSearchResultType::NonInclusionParent, None),
        1 => {
            let (k, c) = entries[0];
            if k == key {
                (PrefixSearchResultType::Inclusion, None)
            } else {
                (
                    PrefixSearchResultType::NonInclusionLeaf,
                    Some(PrefixLeaf {
                        vrf_output: *k,
                        commitment: c.clone(),
                    }),
                )
            }
        }
        _ => {
            let bit = key_bit(key, depth);
            let (mut ours, mut theirs): (Vec<_>, Vec<_>) = (Vec::new(), Vec::new());
            for &e in entries {
                if key_bit(e.0, depth) == bit {
                    ours.push(e);
                } else {
                    theirs.push(e);
                }
            }
            let sibling = subtree(&theirs, depth + 1);
            let result = if ours.is_empty() {
                // Our child is absent: terminal parent at this depth.
                (PrefixSearchResultType::NonInclusionParent, None)
            } else {
                prove_subtree(&ours, key, depth + 1, copath)
            };
            copath.push(sibling);
            result
        }
    }
}

/// The kind of terminal node a prefix-tree search reached (§11.2
/// `PrefixSearchResultType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefixSearchResultType {
    /// A leaf node matching the requested search key.
    Inclusion,
    /// A leaf node *not* matching the requested search key (its value is carried
    /// in the proof, since it cannot be inferred).
    NonInclusionLeaf,
    /// A parent node that lacks the desired child (the child is a [`stand_in`]).
    NonInclusionParent,
}

/// A prefix-tree leaf's revealed contents (§11.2 `PrefixLeaf`): the search key
/// and the commitment stored at a *non-matching* terminal leaf.
///
/// The experimental private suite carries the full [`crate::commitment`]
/// (64-byte SHA3-512) value here, rather than the spec's 32-byte `Hash.Nh`
/// commitment — a documented, version-tagged deviation (the private suite's PQ
/// commitment is wider than the standard suites' HMAC tag).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixLeaf {
    /// The (different) search key stored at the terminal leaf.
    pub vrf_output: [u8; SEARCH_KEY_LEN],
    /// The commitment stored at that leaf.
    pub commitment: Commitment,
}

/// A single-key prefix-tree search proof (§11.2 `PrefixProof`, restricted to one
/// search key).
///
/// `copath` is the left-to-right ordered list of sibling node values along the
/// search path (`elements` in §11.2), indexed by descent depth: `copath[d]` is
/// the sibling subtree value encountered when descending from depth `d` to
/// `d + 1`. Absent subtrees appear as the [`stand_in`] `0^Nh`. The ordering is
/// part of the **movable / experimental** `KEYTRANS_EXP_04` wire surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixProof {
    /// The terminal-node kind.
    pub result_type: PrefixSearchResultType,
    /// The terminal leaf's contents, present iff
    /// [`PrefixSearchResultType::NonInclusionLeaf`].
    pub leaf: Option<PrefixLeaf>,
    /// The depth of the terminal node (§11.2; root is depth 0). Redundant with
    /// `copath.len()` and cross-checked during verification.
    pub depth: u8,
    /// The copath sibling values, in descent-depth order.
    pub copath: Vec<[u8; NH]>,
}

/// Recompute the prefix-tree root by folding `terminal` (the value at descent
/// depth `copath.len()`) up through the copath, choosing the left/right
/// arrangement at each level from `search_key`'s bits (§11.2).
fn recompute_root(
    search_key: &[u8; SEARCH_KEY_LEN],
    terminal: [u8; NH],
    copath: &[[u8; NH]],
) -> [u8; NH] {
    let mut node = terminal;
    for d in (0..copath.len()).rev() {
        node = if key_bit(search_key, d) == 0 {
            hash_parent(&node, &copath[d])
        } else {
            hash_parent(&copath[d], &node)
        };
    }
    node
}

/// Independently verify an **inclusion** proof for `search_key` (§11.2),
/// recomputing the leaf from the relying party's own `commitment`.
///
/// The leaf value `Hash(0x01 || search_key || commitment)` is re-derived from
/// the supplied `commitment` (which the caller obtains by re-opening the
/// directory value), then folded up the copath; the result must equal `root`.
///
/// # Errors
/// - [`Error::MalformedKeytrans`] if `proof` is not an inclusion proof or its
///   stored `depth` is inconsistent with the copath.
/// - [`Error::KeytransRootMismatch`] if the recomputed root does not match
///   `root` (a wrong commitment or tampered copath both surface here).
pub fn verify_inclusion(
    root: &[u8; NH],
    search_key: &[u8; SEARCH_KEY_LEN],
    commitment: &Commitment,
    proof: &PrefixProof,
) -> Result<()> {
    if proof.result_type != PrefixSearchResultType::Inclusion {
        return Err(Error::MalformedKeytrans(
            "verify_inclusion called on a non-inclusion proof".into(),
        ));
    }
    check_depth(proof)?;
    let terminal = hash_leaf(search_key, commitment);
    if recompute_root(search_key, terminal, &proof.copath) == *root {
        Ok(())
    } else {
        Err(Error::KeytransRootMismatch)
    }
}

/// Independently verify a **non-inclusion** (absence) proof for `search_key`
/// (§11.2).
///
/// For [`PrefixSearchResultType::NonInclusionParent`] the terminal value is the
/// [`stand_in`] in `search_key`'s direction; for
/// [`PrefixSearchResultType::NonInclusionLeaf`] it is the revealed *different*
/// leaf, which must (a) not equal `search_key` and (b) share `search_key`'s
/// first `copath.len()` bits (so the search genuinely descended there). The
/// folded result must equal `root`.
///
/// # Errors
/// - [`Error::MalformedKeytrans`] if `proof` is an inclusion proof, a
///   non-inclusion-leaf proof is missing its leaf, the revealed leaf matches
///   `search_key` (a forged absence), the revealed leaf does not share
///   `search_key`'s descent prefix (a cross-key leaf), or `depth` is
///   inconsistent.
/// - [`Error::KeytransRootMismatch`] if the recomputed root does not match
///   `root`.
pub fn verify_absence(
    root: &[u8; NH],
    search_key: &[u8; SEARCH_KEY_LEN],
    proof: &PrefixProof,
) -> Result<()> {
    check_depth(proof)?;
    let terminal = match proof.result_type {
        PrefixSearchResultType::Inclusion => {
            return Err(Error::MalformedKeytrans(
                "verify_absence called on an inclusion proof".into(),
            ));
        }
        PrefixSearchResultType::NonInclusionParent => stand_in(),
        PrefixSearchResultType::NonInclusionLeaf => {
            let leaf = proof.leaf.as_ref().ok_or_else(|| {
                Error::MalformedKeytrans("nonInclusionLeaf proof is missing its leaf".into())
            })?;
            if leaf.vrf_output == *search_key {
                return Err(Error::MalformedKeytrans(
                    "forged absence: terminal leaf matches the search key".into(),
                ));
            }
            for d in 0..proof.copath.len() {
                if key_bit(&leaf.vrf_output, d) != key_bit(search_key, d) {
                    return Err(Error::MalformedKeytrans(
                        "cross-key absence: terminal leaf does not share the search-key prefix"
                            .into(),
                    ));
                }
            }
            hash_leaf(&leaf.vrf_output, &leaf.commitment)
        }
    };
    if recompute_root(search_key, terminal, &proof.copath) == *root {
        Ok(())
    } else {
        Err(Error::KeytransRootMismatch)
    }
}

/// Cross-check the proof's redundant `depth` field against its copath length.
fn check_depth(proof: &PrefixProof) -> Result<()> {
    let expected = match proof.result_type {
        PrefixSearchResultType::NonInclusionParent => proof.copath.len().saturating_sub(1),
        _ => proof.copath.len(),
    };
    if usize::from(proof.depth) == expected {
        Ok(())
    } else {
        Err(Error::MalformedKeytrans(format!(
            "prefix proof depth {} inconsistent with copath length {}",
            proof.depth,
            proof.copath.len()
        )))
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

    // --- Single-key proof generation + recompute-from-public-inputs verify ---

    fn full_key(bytes: [u8; 4]) -> [u8; SEARCH_KEY_LEN] {
        let mut k = [0u8; SEARCH_KEY_LEN];
        k[..4].copy_from_slice(&bytes);
        k
    }

    #[test]
    fn inclusion_proof_verifies_against_recomputed_root() {
        let mut t = PrefixTree::new();
        let entries = [
            (full_key([0x00, 0, 0, 0]), commitment(1)),
            (full_key([0x40, 0, 0, 0]), commitment(2)),
            (full_key([0x80, 0, 0, 0]), commitment(3)),
            (full_key([0xC0, 0, 0, 0]), commitment(4)),
        ];
        for (k, c) in &entries {
            t.insert(*k, c);
        }
        let root = t.root();

        for (k, c) in &entries {
            let proof = t.prove(k);
            assert_eq!(proof.result_type, PrefixSearchResultType::Inclusion);
            assert!(verify_inclusion(&root, k, c, &proof).is_ok());
            // Wrong commitment (tampered value) is rejected.
            assert_eq!(
                verify_inclusion(&root, k, &commitment(99), &proof),
                Err(Error::KeytransRootMismatch)
            );
        }
    }

    #[test]
    fn inclusion_rejects_tampered_path_and_root() {
        let mut t = PrefixTree::new();
        let k = full_key([0x00, 0, 0, 0]);
        let c = commitment(1);
        t.insert(k, &c);
        t.insert(full_key([0x80, 0, 0, 0]), &commitment(2));
        let root = t.root();
        let mut proof = t.prove(&k);
        assert!(verify_inclusion(&root, &k, &c, &proof).is_ok());

        // Tampered copath.
        proof.copath[0][0] ^= 0xFF;
        assert_eq!(
            verify_inclusion(&root, &k, &c, &proof),
            Err(Error::KeytransRootMismatch)
        );

        // Tampered root.
        let proof = t.prove(&k);
        let mut bad_root = root;
        bad_root[0] ^= 0xFF;
        assert_eq!(
            verify_inclusion(&bad_root, &k, &c, &proof),
            Err(Error::KeytransRootMismatch)
        );
    }

    #[test]
    fn non_inclusion_leaf_proof_verifies() {
        // Two keys share bit 0 = 0; searching a third key with bit 0 = 0 that
        // collides down to a leaf yields a nonInclusionLeaf.
        let mut t = PrefixTree::new();
        let present = full_key([0x00, 0, 0, 0]); // 0000_0000
        t.insert(present, &commitment(1));
        t.insert(full_key([0x80, 0, 0, 0]), &commitment(2)); // 1000_0000
        let root = t.root();

        // Absent key 0x20 (0010_0000): shares bit0=0 with `present`, descends to
        // the left leaf (which differs) → nonInclusionLeaf.
        let absent = full_key([0x20, 0, 0, 0]);
        let proof = t.prove(&absent);
        assert_eq!(proof.result_type, PrefixSearchResultType::NonInclusionLeaf);
        assert!(verify_absence(&root, &absent, &proof).is_ok());
    }

    #[test]
    fn non_inclusion_parent_proof_verifies() {
        // One key with bit0 = 0; an absent key with bit0 = 1 terminates at the
        // root parent whose right child is a stand-in → nonInclusionParent.
        let mut t = PrefixTree::new();
        t.insert(full_key([0x00, 0, 0, 0]), &commitment(1));
        let root = t.root();
        // With one entry the root is a leaf, not a parent; add a second left-side
        // key so the root becomes a parent with an absent right child.
        let mut t2 = PrefixTree::new();
        t2.insert(full_key([0x00, 0, 0, 0]), &commitment(1));
        t2.insert(full_key([0x20, 0, 0, 0]), &commitment(2));
        let root2 = t2.root();
        let absent = full_key([0x80, 0, 0, 0]); // bit0 = 1, absent
        let proof = t2.prove(&absent);
        assert_eq!(
            proof.result_type,
            PrefixSearchResultType::NonInclusionParent
        );
        assert!(verify_absence(&root2, &absent, &proof).is_ok());
        let _ = root;
    }

    #[test]
    fn empty_tree_non_inclusion_verifies() {
        let t = PrefixTree::new();
        let root = t.root();
        assert_eq!(root, stand_in());
        let proof = t.prove(&full_key([0x12, 0x34, 0, 0]));
        assert_eq!(
            proof.result_type,
            PrefixSearchResultType::NonInclusionParent
        );
        assert!(proof.copath.is_empty());
        assert!(verify_absence(&root, &full_key([0x12, 0x34, 0, 0]), &proof).is_ok());
    }

    #[test]
    fn forged_absence_for_present_key_is_rejected() {
        let mut t = PrefixTree::new();
        let present = full_key([0x00, 0, 0, 0]);
        t.insert(present, &commitment(1));
        t.insert(full_key([0x80, 0, 0, 0]), &commitment(2));
        let root = t.root();

        // The honest proof for `present` is an inclusion proof; feeding it to
        // verify_absence is rejected as malformed.
        let incl = t.prove(&present);
        assert!(matches!(
            verify_absence(&root, &present, &incl),
            Err(Error::MalformedKeytrans(_))
        ));

        // Forge a nonInclusionLeaf whose revealed leaf IS the search key.
        let forged = PrefixProof {
            result_type: PrefixSearchResultType::NonInclusionLeaf,
            leaf: Some(PrefixLeaf {
                vrf_output: present,
                commitment: commitment(1),
            }),
            depth: incl.copath.len() as u8,
            copath: incl.copath.clone(),
        };
        assert!(matches!(
            verify_absence(&root, &present, &forged),
            Err(Error::MalformedKeytrans(_))
        ));
    }

    #[test]
    fn cross_key_non_inclusion_leaf_is_rejected() {
        let mut t = PrefixTree::new();
        let present = full_key([0x00, 0, 0, 0]);
        t.insert(present, &commitment(1));
        t.insert(full_key([0x80, 0, 0, 0]), &commitment(2));
        let root = t.root();

        // Absent key that descends to the left; forge its proof to reveal the
        // RIGHT leaf (which does not share the descent prefix).
        let absent = full_key([0x20, 0, 0, 0]);
        let mut proof = t.prove(&absent);
        assert_eq!(proof.result_type, PrefixSearchResultType::NonInclusionLeaf);
        proof.leaf = Some(PrefixLeaf {
            vrf_output: full_key([0x80, 0, 0, 0]),
            commitment: commitment(2),
        });
        assert!(matches!(
            verify_absence(&root, &absent, &proof),
            Err(Error::MalformedKeytrans(_))
        ));
    }
}
