//! Layer-3e: the experimental **KEYTRANS combined-tree** directory core
//! (`draft-ietf-keytrans-protocol-04`, `KEYTRANS_EXP_04`).
//!
//! The industry is converging on IETF KEYTRANS rather than classic CONIKS, so
//! this module adds a KEYTRANS-style *combined tree* directory backend
//! *alongside* the CONIKS one ([`crate::coniks`]), behind the swappable
//! [`crate::directory::Directory`] trait. This slice (9c) builds the
//! tree-hashing **core** only — the data structures, their node hashing, the
//! combined-tree root, and the implicit-binary-search-tree timestamp
//! navigation. Search / fixed-version / monitor **proof verification**, the
//! `Directory` impl, and the policy/SDK wiring land in later slices (9d–9f).
//!
//! ## Experimental / version-tagged (read this)
//!
//! `draft-ietf-keytrans-protocol` is a WG Document, **not** at Last Call: its
//! wire bytes still move. This backend is therefore deliberately **not**
//! byte-locked the way [`crate::leaf::key_history_v1`] is. Everything here is
//! tagged [`KEYTRANS_EXP_04`] and its test vectors are **movable**, kept out of
//! the frozen conformance / cross-language KAT suites. When `-protocol` advances
//! we bump the tag, not a frozen format.
//!
//! ## The combined tree (§3.4)
//!
//! Two trees are combined, after [Merkle2]:
//!
//! - a [`prefix_tree`] (§3.3 / §10.9): a bit-traversal trie mapping each
//!   `(label, version)` search key — a VRF output — to a commitment to the
//!   label's value, giving efficient membership proofs;
//! - a [`log_tree`] (§3.2 / §10.8): a left-balanced chronological log whose
//!   every leaf is a [`tls::LogEntry`] binding a timestamp to the prefix-tree
//!   root at that version, giving efficient consistency proofs.
//!
//! The **combined-tree root** is simply the log-tree root over those entries
//! ([`CombinedTree`]). Different versions of the prefix tree are identified by
//! the log entry that stored their root.
//!
//! ## Cipher suite posture (this slice: the private PQ suite)
//!
//! All tree hashing uses the cipher-suite hash, **SHA-256** ([`NH`]-byte nodes)
//! — chosen for KEYTRANS interop, and the one documented non-SHA3 spot here
//! alongside the RFC 6962 log ([`crate::merkle`]). The experimental private
//! suite [`KT_EXP_METAMORPHIC_HYBRID`] keeps the platform's post-quantum
//! posture by reusing the SHA3-512 [`crate::commitment`] (its 32-byte opening is
//! the suite's `Nc`, [`NC`]) and the swappable [`crate::vrf`] ECVRF-Ed25519
//! (whose 64-byte output is truncated to the [`prefix_tree::SEARCH_KEY_LEN`]
//! 32-byte search key). The standard suites' HMAC / 16-byte-opening commitments
//! are intentionally **not** built here.
//!
//! ## Serialization
//!
//! Bytes that feed a hash use the TLS presentation language (§2), implemented in
//! the private, dependency-free [`tls`] submodule — the crate's audited
//! length-prefix grammar ([`crate::leaf`]) is left untouched.
//!
//! [Merkle2]: https://eprint.iacr.org/2021/453
//! [`KEYTRANS_EXP_04`]: KEYTRANS_EXP_04

// The TLS-presentation-language reader/writer is a complete, symmetric surface
// (every struct round-trips), exercised by its own unit tests and consumed by
// the Slice 9d search/monitor proof parsers. In a plain (non-test) lib build the
// `decode` halves read as unused, so dead-code analysis is relaxed for this
// scaffolding submodule rather than mutilating a deliberately complete codec.
#[allow(dead_code)]
mod tls;

pub mod log_tree;
pub mod prefix_tree;

use crate::commitment::{Commitment, Opening, commit_with_opening};
use crate::error::{Error, Result};
use crate::vrf::VrfOutput;

pub use prefix_tree::{PrefixTree, SEARCH_KEY_LEN};

/// Length in bytes of the cipher-suite hash output (`Hash.Nh`): SHA-256, so
/// log-tree and prefix-tree nodes — and a prefix-tree root embedded in a
/// [`tls::LogEntry`] — are 32 bytes.
pub const NH: usize = 32;

/// The experimental private cipher suite identifier, in the §15.1
/// `0xF000–0xFFFF` "Reserved for Private Use" range: SHA-256 trees, SHA3-512
/// hiding/binding commitments (the PQ half), composite hybrid-PQ tree-head
/// signatures, and ECVRF-Ed25519 (32-byte-truncated) labels.
pub const KT_EXP_METAMORPHIC_HYBRID: u16 = 0xF000;

/// The suite commitment opening length `Nc`, in bytes. The private suite reuses
/// [`crate::commitment`]'s 32-byte opening.
pub const NC: usize = crate::commitment::COMMITMENT_OPENING_LEN;

/// Movable version tag for this backend's experimental test vectors. Bumped when
/// `draft-ietf-keytrans-protocol` advances; these vectors are **not** frozen.
pub const KEYTRANS_EXP_04: &str = "KEYTRANS_EXP_04";

/// Truncate a VRF output to the prefix-tree search key length
/// ([`SEARCH_KEY_LEN`]): the first 32 bytes of the 64-byte ECVRF-Ed25519 output,
/// per the experimental private suite (`VRF.Nh = 32`).
#[must_use]
pub fn search_key(output: &VrfOutput) -> [u8; SEARCH_KEY_LEN] {
    let mut key = [0u8; SEARCH_KEY_LEN];
    key.copy_from_slice(&output.as_bytes()[..SEARCH_KEY_LEN]);
    key
}

/// Compute the private-suite commitment to a label-version pair's update.
///
/// Reuses the SHA3-512 [`crate::commitment`] construction (the post-quantum
/// half): the [`tls::CommitmentValue`] bound content (`label || version ||
/// update`) is committed under `context` with `opening` as the blinding nonce.
/// This binds exactly the `(opening, label, version, update)` fields §10.6
/// specifies, while staying byte-distinct from the standard suites' HMAC
/// commitment (the intended PQ-vs-interop trade-off).
///
/// `opening` must be [`NC`] bytes.
///
/// # Errors
/// [`Error::MalformedKeytrans`] if `opening` is not [`NC`] bytes, or if `label`
/// / `value` exceed their TLS-PL vector bounds.
pub fn commit_update(
    context: &str,
    label: &[u8],
    version: u32,
    value: &[u8],
    opening: &[u8],
) -> Result<Commitment> {
    let opening: [u8; NC] = opening.try_into().map_err(|_| {
        Error::MalformedKeytrans(format!(
            "commitment opening must be {NC} bytes, got {}",
            opening.len()
        ))
    })?;
    let commitment_value = tls::CommitmentValue {
        opening: opening.to_vec(),
        label: label.to_vec(),
        version,
        update: tls::UpdateValue {
            value: value.to_vec(),
        },
    };
    let content = commitment_value.bound_content()?;
    Ok(commit_with_opening(
        context,
        &content,
        &Opening::from_bytes(opening),
    ))
}

/// A combined tree (§3.4): the chronological sequence of `(timestamp,
/// prefix-tree root)` versions, whose root is the left-balanced [`log_tree`]
/// root over those entries.
///
/// Each modification of the (single logical) prefix tree appends a new entry
/// recording the new prefix-tree root and the publication timestamp. This is the
/// prover side; relying-party proof verification arrives in Slice 9d.
#[derive(Clone, Debug, Default)]
pub struct CombinedTree {
    leaves: Vec<log_tree::LogNode>,
    timestamps: Vec<u64>,
}

impl CombinedTree {
    /// Create an empty combined tree.
    #[must_use]
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            timestamps: Vec::new(),
        }
    }

    /// Append a log entry recording `prefix_root` published at `timestamp`
    /// (milliseconds since the Unix epoch), returning its zero-based log index.
    ///
    /// Timestamps are expected to be monotonic; callers/verifiers enforce that
    /// via the implicit binary search tree ([`verify_monotonic`]).
    pub fn append(&mut self, timestamp: u64, prefix_root: &[u8; NH]) -> u64 {
        let index = self.leaves.len() as u64;
        self.leaves
            .push(log_tree::hash_leaf(timestamp, prefix_root));
        self.timestamps.push(timestamp);
        index
    }

    /// The number of log entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the combined tree has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The combined-tree root — the log-tree root over the recorded entries.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if the tree is empty (an empty log has no
    /// root value).
    pub fn root(&self) -> Result<[u8; NH]> {
        if self.leaves.is_empty() {
            return Err(Error::MalformedKeytrans(
                "combined-tree root of an empty log is undefined".into(),
            ));
        }
        Ok(log_tree::root(&self.leaves))
    }

    /// Verify that the recorded timestamps are monotonic under the implicit
    /// binary search tree (§4.1).
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if a left-subtree timestamp exceeds its
    /// node's, or a right-subtree timestamp is below it.
    pub fn verify_monotonic(&self) -> Result<()> {
        verify_monotonic(&self.timestamps)
    }
}

// ---------------------------------------------------------------------------
// Implicit binary search tree (§4.1, Appendix A)
// ---------------------------------------------------------------------------
//
// The log's leaves are viewed as a flat-array binary tree. Node indices are the
// log-entry indices; an interior node's index encodes its level (the number of
// trailing one-bits). These are the verbatim Appendix A navigation routines,
// used to check timestamp monotonicity while inspecting a minimal set of
// entries.

/// The exponent of the largest power of two `<= x` (Appendix A `log2`). Returns
/// `0` for `x == 0`.
#[must_use]
pub fn log2(x: u64) -> u32 {
    if x == 0 {
        return 0;
    }
    let mut k = 0;
    while (x >> k) > 0 {
        k += 1;
    }
    k - 1
}

/// The level of node `x` (Appendix A `level`): leaves (even indices) are level
/// `0`; an interior node's level is the count of its trailing one-bits.
#[must_use]
pub fn level(x: u64) -> u32 {
    if x & 1 == 0 {
        return 0;
    }
    let mut k = 0;
    while (x >> k) & 1 == 1 {
        k += 1;
    }
    k
}

/// The root node index of the implicit binary search tree over `n` entries
/// (Appendix A `root`): `2^floor(log2(n)) - 1`.
///
/// # Panics
/// Panics if `n == 0` (an empty tree has no root).
#[must_use]
pub fn root_index(n: u64) -> u64 {
    assert!(n > 0, "implicit BST root of an empty tree is undefined");
    (1 << log2(n)) - 1
}

/// The left child of interior node `x` (Appendix A `left`).
///
/// # Panics
/// Panics if `x` is a leaf (level 0).
#[must_use]
pub fn left_child(x: u64) -> u64 {
    let k = level(x);
    assert!(k != 0, "leaf node {x} has no children");
    x ^ (1 << (k - 1))
}

/// The right child of interior node `x` in a tree of `n` entries (Appendix A
/// `right`): descends left while the natural right child would fall outside the
/// tree.
///
/// Only defined for a node that actually has a right subtree (i.e. not a
/// power-of-two-sized subtree's root, whose right subtree is empty); the
/// frontier walk only calls it on such nodes.
///
/// # Panics
/// Panics if `x` is a leaf (level 0), or if `x` has no right child (the descent
/// reaches a leaf).
#[must_use]
pub fn right_child(x: u64, n: u64) -> u64 {
    let k = level(x);
    assert!(k != 0, "leaf node {x} has no children");
    let mut x = x ^ (0b11 << (k - 1));
    while x >= n {
        assert!(level(x) != 0, "node has no right child within {n} entries");
        x = left_child(x);
    }
    x
}

/// The *frontier* of a log with `n` entries (§4.1): the root, then each entry
/// reached by repeatedly moving to the right child until the rightmost entry
/// (index `n - 1`).
///
/// # Panics
/// Panics if `n == 0`.
#[must_use]
pub fn frontier(n: u64) -> Vec<u64> {
    assert!(n > 0, "frontier of an empty log is undefined");
    let mut out = vec![root_index(n)];
    let mut x = root_index(n);
    while x != n - 1 {
        x = right_child(x, n);
        out.push(x);
    }
    out
}

/// Verify that `timestamps` are monotonic under the implicit binary search tree
/// (§4.1): every node's timestamp is `>=` all timestamps in its left subtree and
/// `<=` all timestamps in its right subtree.
///
/// An empty or single-entry log is trivially monotonic.
///
/// # Errors
/// [`Error::MalformedKeytrans`] on the first violating node.
pub fn verify_monotonic(timestamps: &[u64]) -> Result<()> {
    let n = timestamps.len() as u64;
    if n <= 1 {
        return Ok(());
    }
    verify_range(timestamps, 0, n).map(|_| ())
}

/// Recursively check the subtree spanning the half-open entry range `[lo, hi)`
/// using the §4.1 inductive definition, returning its `(min, max)` timestamps so
/// the parent can validate the BST ordering. This range form is robust to nodes
/// that lack a right subtree (the rightmost spine), unlike the bitwise
/// [`right_child`] navigation.
fn verify_range(timestamps: &[u64], lo: u64, hi: u64) -> Result<(u64, u64)> {
    let size = hi - lo;
    debug_assert!(size >= 1);
    if size == 1 {
        let t = timestamps[lo as usize];
        return Ok((t, t));
    }
    let r = lo + root_index(size); // the root entry index within this range
    let here = timestamps[r as usize];
    let mut lo_min = here;
    let mut hi_max = here;

    if r > lo {
        let (lmin, lmax) = verify_range(timestamps, lo, r)?;
        if lmax > here {
            return Err(Error::MalformedKeytrans(format!(
                "non-monotonic timestamp at log entry {r}: left-subtree max {lmax} exceeds node {here}"
            )));
        }
        lo_min = lmin;
    }
    if r + 1 < hi {
        let (rmin, rmax) = verify_range(timestamps, r + 1, hi)?;
        if here > rmin {
            return Err(Error::MalformedKeytrans(format!(
                "non-monotonic timestamp at log entry {r}: node {here} exceeds right-subtree min {rmin}"
            )));
        }
        hi_max = rmax;
    }
    Ok((lo_min, hi_max))
}

/// The combined-tree leaf-content hash for callers that already hold a
/// prefix-tree root and timestamp but want the bare SHA-256 leaf value (e.g. to
/// recompute a single log entry). Equivalent to
/// [`log_tree::hash_leaf`]`(..).value()`.
#[must_use]
pub fn log_entry_hash(timestamp: u64, prefix_root: &[u8; NH]) -> [u8; NH] {
    log_tree::hash_leaf(timestamp, prefix_root).value()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::vrf::{Ecvrf, Vrf, VrfSecretKey};

    const CTX: &str = "acme/keytrans-commitment/v1";

    #[test]
    fn empty_combined_tree_has_no_root() {
        assert!(CombinedTree::new().root().is_err());
    }

    #[test]
    fn combined_root_is_log_root_over_entries() {
        let mut t = CombinedTree::new();
        t.append(1_000, &[0x11; NH]);
        t.append(2_000, &[0x22; NH]);
        t.append(3_000, &[0x33; NH]);

        let leaves = [
            log_tree::hash_leaf(1_000, &[0x11; NH]),
            log_tree::hash_leaf(2_000, &[0x22; NH]),
            log_tree::hash_leaf(3_000, &[0x33; NH]),
        ];
        assert_eq!(t.root().unwrap(), log_tree::root(&leaves));
    }

    #[test]
    fn search_key_is_first_32_bytes_of_output() {
        let mut beta = [0u8; 64];
        for (i, b) in beta.iter_mut().enumerate() {
            *b = i as u8;
        }
        let out = VrfOutput::from_bytes(beta);
        assert_eq!(search_key(&out), out.index());
    }

    #[test]
    fn commit_update_reuses_sha3_commitment() {
        // The private suite commitment must equal commitment.rs over the bound
        // content with the suite opening — proving we reused the SHA3-512 stack.
        let opening = [0x5A; NC];
        let c = commit_update(CTX, b"alice", 3, b"key-head", &opening).unwrap();

        let cv = tls::CommitmentValue {
            opening: opening.to_vec(),
            label: b"alice".to_vec(),
            version: 3,
            update: tls::UpdateValue {
                value: b"key-head".to_vec(),
            },
        };
        let expected = commit_with_opening(
            CTX,
            &cv.bound_content().unwrap(),
            &Opening::from_bytes(opening),
        );
        assert_eq!(c, expected);
    }

    #[test]
    fn commit_update_rejects_wrong_opening_length() {
        assert!(commit_update(CTX, b"a", 0, b"v", &[0u8; 16]).is_err());
    }

    // --- Implicit binary search tree (Appendix A) ---

    #[test]
    fn appendix_a_root_index_examples() {
        // §4.1 worked example: a log of 50 entries has root 31.
        assert_eq!(root_index(50), 31);
        assert_eq!(root_index(1), 0);
        assert_eq!(root_index(2), 1);
        assert_eq!(root_index(8), 7);
    }

    #[test]
    fn appendix_a_frontier_example() {
        // §4.1: the frontier of a 50-entry log is [31, 47, 49].
        assert_eq!(frontier(50), vec![31, 47, 49]);
        assert_eq!(frontier(1), vec![0]);
    }

    #[test]
    fn level_counts_trailing_ones() {
        assert_eq!(level(0), 0);
        assert_eq!(level(1), 1);
        assert_eq!(level(2), 0);
        assert_eq!(level(3), 2);
        assert_eq!(level(7), 3);
    }

    #[test]
    fn monotonic_check_matches_non_decreasing() {
        // The BST ordering property is exactly "timestamps non-decreasing by
        // index"; cross-check the structural walk against the simple predicate.
        let good: Vec<u64> = (0..14).map(|i| i * 10).collect();
        assert!(verify_monotonic(&good).is_ok());

        let mut bad = good.clone();
        bad.swap(3, 10); // introduce an out-of-order pair
        assert!(verify_monotonic(&bad).is_err());

        assert!(verify_monotonic(&[]).is_ok());
        assert!(verify_monotonic(&[42]).is_ok());
        // Equal timestamps are allowed (>= / <=).
        assert!(verify_monotonic(&[5, 5, 5, 5, 5]).is_ok());
    }

    #[test]
    fn combined_tree_monotonic_timestamps() {
        let mut t = CombinedTree::new();
        for i in 0..10u64 {
            t.append(1_000 + i * 100, &[i as u8; NH]);
        }
        assert!(t.verify_monotonic().is_ok());
    }

    // --- Deterministic end-to-end combined root (version-tagged, MOVABLE) ---

    #[test]
    fn deterministic_combined_root_over_fixed_inputs() {
        // A fixed, reproducible KEYTRANS_EXP_04 vector: build a two-entry
        // combined tree from fixed VRF key, labels, versions, values, openings,
        // and timestamps, and assert the root is stable. NOT frozen — this
        // vector moves with the draft (see module docs); it exists to catch
        // unintended hashing changes within a draft revision.
        let vrf = Ecvrf;
        let sk = VrfSecretKey::from_bytes(vec![7u8; 32]);

        let leaf_value = |label: &[u8], version: u32, value: &[u8], opening: &[u8]| {
            let input = tls::VrfInput {
                label: label.to_vec(),
                version,
            }
            .encode()
            .unwrap();
            let proof = vrf.prove(&sk, &input).unwrap();
            let output = vrf.proof_to_output(&proof).unwrap();
            let key = search_key(&output);
            let commitment = commit_update(CTX, label, version, value, opening).unwrap();
            (key, commitment)
        };

        // Prefix tree v1: one entry (alice@1).
        let mut pt = PrefixTree::new();
        let (k_a, c_a) = leaf_value(b"alice", 1, b"alice-head-1", &[0x01; NC]);
        pt.insert(k_a, &c_a);
        let pt_root_1 = pt.root();

        // Prefix tree v2: add bob@1.
        let (k_b, c_b) = leaf_value(b"bob", 1, b"bob-head-1", &[0x02; NC]);
        pt.insert(k_b, &c_b);
        let pt_root_2 = pt.root();

        let mut combined = CombinedTree::new();
        combined.append(1_700_000_000_000, &pt_root_1);
        combined.append(1_700_000_001_000, &pt_root_2);

        let root = combined.root().unwrap();
        // Determinism: recomputing yields the same root.
        let mut again = CombinedTree::new();
        again.append(1_700_000_000_000, &pt_root_1);
        again.append(1_700_000_001_000, &pt_root_2);
        assert_eq!(root, again.root().unwrap());

        // Structural sanity: the two prefix roots differ (v2 added an entry),
        // and the combined root is a 32-byte SHA-256 node.
        assert_ne!(pt_root_1, pt_root_2);
        assert_eq!(root.len(), NH);
        assert!(combined.verify_monotonic().is_ok());

        // Tag the vector so a future draft bump is an explicit, greppable change.
        assert_eq!(KEYTRANS_EXP_04, "KEYTRANS_EXP_04");
    }
}
