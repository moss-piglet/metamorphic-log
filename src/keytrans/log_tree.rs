//! KEYTRANS **log tree** (`draft-ietf-keytrans-protocol-04` §3.2 / §10.8):
//! a left-balanced binary tree recording, in chronological order, each version
//! of the prefix tree.
//!
//! ## Hashing (NEW — not RFC 6962)
//!
//! The node-tagging *looks* like RFC 6962 ([`crate::merkle`]) but is computed
//! differently, so this is new code rather than a reuse of
//! [`crate::merkle::hash_children`]:
//!
//! - A **leaf**'s value is `Hash(LogEntry)` — the SHA-256 of the TLS-PL
//!   [`crate::keytrans::tls::LogEntry`] (`uint64 timestamp || prefix_tree[Nh]`),
//!   with *no* domain-separation prefix on the leaf hash itself.
//! - A **parent**'s value is `Hash(hashContent(left) || hashContent(right))`,
//!   where `hashContent(node)` prefixes the *child's already-computed value*
//!   with `0x00` if that child is a leaf and `0x01` if it is a parent.
//!
//! Contrast RFC 6962, where the prefix sits on the hash *input* and every
//! interior node uses `0x01` uniformly. Here the prefix depends on whether the
//! child is a leaf or a parent, which matters in a left-balanced tree where a
//! parent's right child can itself be a single leaf.
//!
//! ## Left-balanced structure (§3.2)
//!
//! Given `n` leaves there is a unique left-balanced tree: every parent's left
//! subtree is the largest balanced (power-of-two) subtree that fits, so the
//! split point is the largest power of two strictly less than `n`. This is the
//! same split RFC 6962 uses, so the *shape* is shared with [`crate::merkle`]
//! even though the hashing is not.
//!
//! ## Balanced-subtree-head compression (§3.2)
//!
//! KEYTRANS proofs only ever carry the values of nodes that are the head of a
//! *balanced* subtree; a non-balanced subtree is broken into the
//! smallest-possible number of balanced subtrees. [`full_subtree_heads`]
//! exposes that decomposition — the maximal balanced subtrees of a tree of size
//! `n`, left to right — which is the structure the (Slice 9d) inclusion and
//! consistency proofs are built on. [`combine_heads`] folds those heads back
//! into the root, demonstrating the compression is lossless.

use metamorphic_crypto::hash::sha256;

use std::collections::{BTreeMap, BTreeSet};

use super::NH;
use super::tls::LogEntry;
use crate::error::{Error, Result};

/// A log-tree node value (a SHA-256 digest), tagged with whether it is the value
/// of a leaf or of a parent so the `hashContent` prefix (`0x00` / `0x01`) can be
/// applied when it is folded into its own parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogNode {
    value: [u8; NH],
    is_leaf: bool,
}

impl LogNode {
    /// The node's hash value.
    #[must_use]
    pub fn value(&self) -> [u8; NH] {
        self.value
    }

    /// Whether this node is a leaf (vs. a parent), which selects its
    /// `hashContent` domain-separation byte.
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.is_leaf
    }

    /// Reconstruct a node from a raw value and its structural leaf/parent role.
    ///
    /// Used by [`verify_batch`] to rebuild the [`LogNode`] for a proof element or
    /// retained head whose `is_leaf` flag is *not* transmitted but is determined
    /// by the subtree's size (size 1 ⇒ leaf, otherwise parent).
    fn from_parts(value: [u8; NH], is_leaf: bool) -> Self {
        Self { value, is_leaf }
    }

    /// `hashContent(node)` (§10.8): `0x00 || value` for a leaf, `0x01 || value`
    /// for a parent.
    fn hash_content(&self) -> [u8; 1 + NH] {
        let mut out = [0u8; 1 + NH];
        out[0] = u8::from(!self.is_leaf); // 0x00 leaf, 0x01 parent
        out[1..].copy_from_slice(&self.value);
        out
    }
}

/// The leaf-node value for a log entry: `Hash(LogEntry)` over the TLS-PL
/// [`LogEntry`] bytes (`uint64 timestamp || prefix_tree[Nh]`, §10.8).
///
/// `timestamp` is milliseconds since the Unix epoch; `prefix_tree` is the
/// [`NH`]-byte prefix-tree root at this version (see
/// [`crate::keytrans::prefix_tree`]).
#[must_use]
pub fn hash_leaf(timestamp: u64, prefix_tree: &[u8; NH]) -> LogNode {
    let entry = LogEntry {
        timestamp,
        prefix_tree: *prefix_tree,
    };
    LogNode {
        value: sha256(&entry.encode()),
        is_leaf: true,
    }
}

/// The parent-node value for two children (§10.8):
/// `Hash(hashContent(left) || hashContent(right))`.
#[must_use]
pub fn hash_parent(left: &LogNode, right: &LogNode) -> LogNode {
    let mut buf = [0u8; 2 * (1 + NH)];
    buf[..1 + NH].copy_from_slice(&left.hash_content());
    buf[1 + NH..].copy_from_slice(&right.hash_content());
    LogNode {
        value: sha256(&buf),
        is_leaf: false,
    }
}

/// The largest power of two strictly less than `n` (requires `n > 1`). This is
/// the left-balanced split point: the size of a parent's (balanced) left
/// subtree.
#[inline]
fn split_point(n: usize) -> usize {
    debug_assert!(n > 1);
    let bits = usize::BITS - (n as u64 - 1).leading_zeros();
    1usize << (bits - 1)
}

/// Compute the head node of the left-balanced subtree over `leaves`.
///
/// Panics if `leaves` is empty (a log tree always has at least one leaf; an
/// empty log has no head value).
#[must_use]
pub fn subtree_head(leaves: &[LogNode]) -> LogNode {
    match leaves.len() {
        0 => panic!("log subtree over zero leaves has no head value"),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            let left = subtree_head(&leaves[..k]);
            let right = subtree_head(&leaves[k..]);
            hash_parent(&left, &right)
        }
    }
}

/// The log-tree root over `leaves` (the head of the whole left-balanced tree).
///
/// Panics if `leaves` is empty.
#[must_use]
pub fn root(leaves: &[LogNode]) -> [u8; NH] {
    subtree_head(leaves).value
}

/// The heads of the maximal balanced subtrees of a tree of size `leaves.len()`,
/// in left-to-right order (the §3.2 *full subtrees*).
///
/// A balanced subtree has a power-of-two number of leaves, so the decomposition
/// follows the binary representation of `n`: the leftmost full subtree is the
/// largest power of two `<= n`, then the next chunk, and so on. The number of
/// heads equals the population count of `n`.
///
/// Panics if `leaves` is empty.
#[must_use]
pub fn full_subtree_heads(leaves: &[LogNode]) -> Vec<LogNode> {
    assert!(
        !leaves.is_empty(),
        "full_subtree_heads over zero leaves is undefined"
    );
    let mut heads = Vec::new();
    let mut rest = leaves;
    while !rest.is_empty() {
        let n = rest.len();
        // Largest power of two <= n.
        let chunk = if n.is_power_of_two() {
            n
        } else {
            split_point(n)
        };
        heads.push(subtree_head(&rest[..chunk]));
        rest = &rest[chunk..];
    }
    heads
}

/// Recombine left-to-right balanced-subtree heads into a single node, mirroring
/// the left-balanced structure: the result equals [`root`] over the original
/// leaves.
///
/// Folds from the right so each step makes the current head the left child (a
/// full balanced subtree) and the accumulated remainder the right child.
///
/// Panics if `heads` is empty.
#[must_use]
pub fn combine_heads(heads: &[LogNode]) -> LogNode {
    let (last, init) = heads
        .split_last()
        .expect("combine_heads over zero heads is undefined");
    let mut acc = *last;
    for head in init.iter().rev() {
        acc = hash_parent(head, &acc);
    }
    acc
}

/// The left-to-right balanced-subtree-head sizes of a subtree of `size` leaves:
/// the powers of two in `size`'s binary representation, largest first (the same
/// decomposition [`full_subtree_heads`] produces). For example `size == 6`
/// yields `[4, 2]` and `size == 7` yields `[4, 2, 1]`.
fn balanced_head_sizes(size: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut rest = size;
    while rest > 0 {
        let chunk = if rest.is_power_of_two() {
            rest
        } else {
            split_point(rest)
        };
        out.push(chunk);
        rest -= chunk;
    }
    out
}

/// A subtree the verifier already holds the head value(s) of, retained from a
/// previous version of the log (§11.1 consistency). The retained heads are the
/// [`full_subtree_heads`] of the previous tree of `prev_size` leaves, in
/// left-to-right order.
#[derive(Clone, Debug)]
pub struct RetainedHeads<'a> {
    /// The previous tree size whose full-subtree heads were retained.
    pub prev_size: usize,
    /// The retained head values (`full_subtree_heads` of `[0, prev_size)`).
    pub heads: &'a [[u8; NH]],
}

/// Build the half-open ranges of the balanced-subtree heads tiling `[0, size)`,
/// left to right (paired with their head index).
fn head_ranges(size: usize) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut lo = 0usize;
    for s in balanced_head_sizes(size) {
        ranges.push((lo, lo + s));
        lo += s;
    }
    ranges
}

/// Produce a **batch** inclusion + consistency proof (§11.1): the minimal set of
/// balanced-subtree head values that, combined with the `proved` leaves and any
/// `retained` heads, recompute the root of the `leaves` log tree, in
/// left-to-right node order.
///
/// `proved` is the sorted, deduplicated set of leaf indices to prove included;
/// `retained_prev_size` (if any) is the size of a previous tree whose
/// full-subtree heads the verifier retained. Passing a single index and no
/// retained size yields a plain inclusion proof; passing no indices and a
/// retained size yields a plain consistency proof.
///
/// # Panics
/// Panics if a proved index is out of range or `retained_prev_size` exceeds the
/// current tree size.
#[must_use]
pub fn batch_proof(
    leaves: &[LogNode],
    proved: &[usize],
    retained_prev_size: Option<usize>,
) -> Vec<[u8; NH]> {
    let n = leaves.len();
    assert!(proved.iter().all(|&i| i < n), "proved index out of range");
    let m = retained_prev_size.unwrap_or(0);
    assert!(m <= n, "retained prev_size exceeds current tree size");

    let proved_set: BTreeSet<usize> = proved.iter().copied().collect();
    let retained_ranges: BTreeSet<(usize, usize)> = head_ranges(m).into_iter().collect();

    let mut elements = Vec::new();
    if n > 0 {
        collect_elements(leaves, 0, n, &proved_set, &retained_ranges, &mut elements);
    }
    elements
}

/// Prover-side traversal mirroring [`resolve`]: append the head values of any
/// subtree that is *entirely unknown* (no proved leaf inside, not a retained
/// head, and not containing a retained head), in left-to-right order.
fn collect_elements(
    leaves: &[LogNode],
    lo: usize,
    hi: usize,
    proved: &BTreeSet<usize>,
    retained: &BTreeSet<(usize, usize)>,
    out: &mut Vec<[u8; NH]>,
) {
    let size = hi - lo;
    let proved_inside = proved.range(lo..hi).next().is_some();
    let exact_retained = retained.contains(&(lo, hi));

    if !proved_inside {
        if exact_retained {
            return; // verifier already holds this head
        }
        if !contains_retained_subrange(retained, lo, hi) {
            // Entirely unknown: provide its balanced-subtree heads.
            for (a, b) in head_ranges_within(lo, hi) {
                out.push(subtree_head(&leaves[a..b]).value());
            }
            return;
        }
    }
    // Recurse (contains proved leaves and/or retained sub-heads).
    if size > 1 {
        let k = split_point(size);
        let mid = lo + k;
        collect_elements(leaves, lo, mid, proved, retained, out);
        collect_elements(leaves, mid, hi, proved, retained, out);
    }
}

/// The balanced-subtree head ranges of `[lo, hi)`, offset into the global leaf
/// array.
fn head_ranges_within(lo: usize, hi: usize) -> Vec<(usize, usize)> {
    head_ranges(hi - lo)
        .into_iter()
        .map(|(a, b)| (lo + a, lo + b))
        .collect()
}

/// Whether some retained head range is a *strict* subset of `[lo, hi)` (so the
/// range must be recursed into to reach the retained head).
fn contains_retained_subrange(retained: &BTreeSet<(usize, usize)>, lo: usize, hi: usize) -> bool {
    retained
        .iter()
        .any(|&(a, b)| lo <= a && b <= hi && (a, b) != (lo, hi))
}

/// Independently verify a **batch** inclusion + consistency proof (§11.1),
/// recomputing the root of an `n`-leaf log tree from public inputs only.
///
/// `proved` are the `(index, leaf_value)` pairs being shown included; `retained`
/// (if any) carries the full-subtree heads the verifier retained from a previous
/// tree; `elements` are the provided balanced-subtree head values in
/// left-to-right order. The recomputed root must equal `expected_root`.
///
/// Honors the §11.1 **MUST**: when proved leaves make a retained head redundant
/// (i.e. it can be recomputed from the batch), the recomputed value is checked
/// against the retained value, so a tampered retained head cannot be silently
/// disregarded.
///
/// # Errors
/// - [`Error::MalformedKeytrans`] if `proved` indices are out of range/unsorted,
///   a retained-head count is wrong, or the wrong number of `elements` is
///   supplied.
/// - [`Error::KeytransRootMismatch`] if the recomputed root does not match
///   `expected_root`, or a redundant retained head does not match its recomputed
///   value.
pub fn verify_batch(
    n: usize,
    proved: &[(usize, [u8; NH])],
    retained: Option<&RetainedHeads<'_>>,
    elements: &[[u8; NH]],
    expected_root: &[u8; NH],
) -> Result<()> {
    if n == 0 {
        return Err(Error::MalformedKeytrans(
            "cannot verify a batch proof against an empty log".into(),
        ));
    }
    let mut proved_map: BTreeMap<usize, [u8; NH]> = BTreeMap::new();
    for &(i, v) in proved {
        if i >= n {
            return Err(Error::MalformedKeytrans(format!(
                "proved leaf index {i} is beyond tree size {n}"
            )));
        }
        proved_map.insert(i, v);
    }

    let mut retained_map: BTreeMap<(usize, usize), [u8; NH]> = BTreeMap::new();
    if let Some(r) = retained {
        if r.prev_size == 0 || r.prev_size > n {
            return Err(Error::MalformedKeytrans(format!(
                "retained prev_size {} is not in 1..={n}",
                r.prev_size
            )));
        }
        let ranges = head_ranges(r.prev_size);
        if ranges.len() != r.heads.len() {
            return Err(Error::MalformedKeytrans(format!(
                "retained head count {} does not match prev_size {} ({} expected)",
                r.heads.len(),
                r.prev_size,
                ranges.len()
            )));
        }
        for (range, head) in ranges.into_iter().zip(r.heads.iter()) {
            retained_map.insert(range, *head);
        }
    }

    let mut elems = elements.iter();
    let root = resolve(0, n, &proved_map, &retained_map, &mut elems)?;
    if elems.next().is_some() {
        return Err(Error::MalformedKeytrans(
            "batch proof has unused trailing elements".into(),
        ));
    }
    if root.value() == *expected_root {
        Ok(())
    } else {
        Err(Error::KeytransRootMismatch)
    }
}

/// Verifier-side traversal: recompute the [`LogNode`] for `[lo, hi)` from proved
/// leaves, retained heads, and the provided `elements` iterator. See
/// [`verify_batch`] for the §11.1 MUST check on redundant retained heads.
fn resolve<'a, I>(
    lo: usize,
    hi: usize,
    proved: &BTreeMap<usize, [u8; NH]>,
    retained: &BTreeMap<(usize, usize), [u8; NH]>,
    elements: &mut I,
) -> Result<LogNode>
where
    I: Iterator<Item = &'a [u8; NH]>,
{
    let size = hi - lo;
    let proved_inside = proved.range(lo..hi).next().is_some();
    let exact_retained = retained.get(&(lo, hi)).copied();

    if !proved_inside {
        if let Some(v) = exact_retained {
            return Ok(LogNode::from_parts(v, size == 1));
        }
        let retained_set: BTreeSet<(usize, usize)> = retained.keys().copied().collect();
        if !contains_retained_subrange(&retained_set, lo, hi) {
            // Entirely unknown: consume its balanced-subtree heads as elements.
            return consume_unknown(size, elements);
        }
    }

    let node = if size == 1 {
        let v = proved
            .get(&lo)
            .ok_or_else(|| Error::MalformedKeytrans("internal: expected a proved leaf".into()))?;
        LogNode::from_parts(*v, true)
    } else {
        let k = split_point(size);
        let mid = lo + k;
        let left = resolve(lo, mid, proved, retained, elements)?;
        let right = resolve(mid, hi, proved, retained, elements)?;
        hash_parent(&left, &right)
    };

    // §11.1 MUST: a recomputed redundant retained head must match its value.
    if let Some(v) = exact_retained {
        if node.value() != v {
            return Err(Error::KeytransRootMismatch);
        }
    }
    Ok(node)
}

/// Consume the balanced-subtree head values of an entirely-unknown subtree of
/// `size` leaves from `elements` and recombine them into a single node.
fn consume_unknown<'a, I>(size: usize, elements: &mut I) -> Result<LogNode>
where
    I: Iterator<Item = &'a [u8; NH]>,
{
    let sizes = balanced_head_sizes(size);
    let mut heads = Vec::with_capacity(sizes.len());
    for s in sizes {
        let v = elements.next().ok_or_else(|| {
            Error::MalformedKeytrans("batch proof is missing expected element(s)".into())
        })?;
        heads.push(LogNode::from_parts(*v, s == 1));
    }
    Ok(combine_heads(&heads))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn leaf(ts: u64) -> LogNode {
        hash_leaf(ts, &[ts as u8; NH])
    }

    #[test]
    fn split_point_is_largest_power_of_two_below() {
        assert_eq!(split_point(2), 1);
        assert_eq!(split_point(3), 2);
        assert_eq!(split_point(4), 2);
        assert_eq!(split_point(5), 4);
        assert_eq!(split_point(8), 4);
        assert_eq!(split_point(9), 8);
    }

    #[test]
    fn single_leaf_root_is_the_leaf_value() {
        let l = leaf(1);
        assert_eq!(root(&[l]), l.value());
    }

    #[test]
    fn leaf_and_parent_use_different_hash_content_prefixes() {
        // A two-leaf parent combines two leaf children (0x00 prefix each); a
        // four-leaf root combines two parent children (0x01 prefix each). Build
        // the expectations by hand to lock the §10.8 tagging.
        let a = leaf(1);
        let b = leaf(2);
        let parent_ab = hash_parent(&a, &b);
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.extend_from_slice(&a.value());
        buf.push(0x00);
        buf.extend_from_slice(&b.value());
        assert_eq!(parent_ab.value(), sha256(&buf));
        assert!(!parent_ab.is_leaf());

        let c = leaf(3);
        let d = leaf(4);
        let parent_cd = hash_parent(&c, &d);
        let r = hash_parent(&parent_ab, &parent_cd);
        let mut buf2 = Vec::new();
        buf2.push(0x01);
        buf2.extend_from_slice(&parent_ab.value());
        buf2.push(0x01);
        buf2.extend_from_slice(&parent_cd.value());
        assert_eq!(r.value(), sha256(&buf2));
    }

    #[test]
    fn full_subtree_heads_count_is_popcount() {
        for n in 1usize..=20 {
            let leaves: Vec<_> = (0..n as u64).map(leaf).collect();
            let heads = full_subtree_heads(&leaves);
            assert_eq!(heads.len(), n.count_ones() as usize, "n = {n}");
        }
    }

    #[test]
    fn combine_heads_reconstructs_root_for_all_sizes() {
        // The headline §3.2 property: breaking the tree into balanced subtree
        // heads and recombining yields the exact same root — for every size,
        // including the awkward non-power-of-two ones (5, 6, 7, ...).
        for n in 1usize..=33 {
            let leaves: Vec<_> = (0..n as u64).map(leaf).collect();
            let heads = full_subtree_heads(&leaves);
            assert_eq!(combine_heads(&heads).value(), root(&leaves), "n = {n}");
        }
    }

    #[test]
    fn power_of_two_tree_has_one_full_subtree() {
        for &n in &[1usize, 2, 4, 8, 16] {
            let leaves: Vec<_> = (0..n as u64).map(leaf).collect();
            assert_eq!(full_subtree_heads(&leaves).len(), 1, "n = {n}");
        }
    }

    #[test]
    fn appending_a_leaf_only_changes_the_right_spine() {
        // Figure 2: inserting leaf 5 into a 5-leaf tree leaves the left 4-leaf
        // balanced subtree head unchanged.
        let five: Vec<_> = (0..5u64).map(leaf).collect();
        let six: Vec<_> = (0..6u64).map(leaf).collect();
        let head5 = full_subtree_heads(&five);
        let head6 = full_subtree_heads(&six);
        assert_eq!(head5[0], head6[0]); // the size-4 left subtree is identical
        assert_ne!(root(&five), root(&six));
    }

    // --- Batch inclusion / consistency verification (§11.1) ---

    #[test]
    fn single_leaf_inclusion_verifies_for_all_sizes_and_indices() {
        for n in 1usize..=20 {
            let leaves: Vec<_> = (0..n as u64).map(leaf).collect();
            let r = root(&leaves);
            for i in 0..n {
                let elements = batch_proof(&leaves, &[i], None);
                let proved = [(i, leaves[i].value())];
                assert!(
                    verify_batch(n, &proved, None, &elements, &r).is_ok(),
                    "n = {n}, i = {i}"
                );
            }
        }
    }

    #[test]
    fn inclusion_rejects_tampered_leaf_and_root() {
        let leaves: Vec<_> = (0..7u64).map(leaf).collect();
        let r = root(&leaves);
        let elements = batch_proof(&leaves, &[3], None);

        // Tampered leaf value.
        let bad_leaf = [(3usize, [0xAAu8; NH])];
        assert_eq!(
            verify_batch(7, &bad_leaf, None, &elements, &r),
            Err(Error::KeytransRootMismatch)
        );
        // Tampered root.
        let mut bad_root = r;
        bad_root[0] ^= 0xFF;
        let good_leaf = [(3usize, leaves[3].value())];
        assert_eq!(
            verify_batch(7, &good_leaf, None, &elements, &bad_root),
            Err(Error::KeytransRootMismatch)
        );
        // Tampered element.
        let mut bad_elems = elements.clone();
        bad_elems[0][0] ^= 0xFF;
        assert_eq!(
            verify_batch(7, &good_leaf, None, &bad_elems, &r),
            Err(Error::KeytransRootMismatch)
        );
    }

    #[test]
    fn consistency_verifies_for_growing_trees() {
        for m in 1usize..=12 {
            for n in m..=16 {
                let leaves: Vec<_> = (0..n as u64).map(leaf).collect();
                let r = root(&leaves);
                let prev: Vec<_> = (0..m as u64).map(leaf).collect();
                let retained_heads: Vec<[u8; NH]> = full_subtree_heads(&prev)
                    .iter()
                    .map(LogNode::value)
                    .collect();
                let elements = batch_proof(&leaves, &[], Some(m));
                let retained = RetainedHeads {
                    prev_size: m,
                    heads: &retained_heads,
                };
                assert!(
                    verify_batch(n, &[], Some(&retained), &elements, &r).is_ok(),
                    "m = {m}, n = {n}"
                );
            }
        }
    }

    #[test]
    fn batch_inclusion_plus_consistency_honors_redundant_head_must_check() {
        // m = 4 (one retained head over [0,4)), n = 6, and we prove inclusion of
        // leaf 1 — which lies inside the retained subtree, making that head
        // recomputable from the batch (the §11.1 edge case).
        let n = 6;
        let leaves: Vec<_> = (0..n as u64).map(leaf).collect();
        let r = root(&leaves);
        let prev: Vec<_> = (0..4u64).map(leaf).collect();
        let mut retained_heads: Vec<[u8; NH]> = full_subtree_heads(&prev)
            .iter()
            .map(LogNode::value)
            .collect();

        let elements = batch_proof(&leaves, &[1], Some(4));
        let proved = [(1usize, leaves[1].value())];

        // Honest proof verifies.
        let retained = RetainedHeads {
            prev_size: 4,
            heads: &retained_heads,
        };
        assert!(verify_batch(n, &proved, Some(&retained), &elements, &r).is_ok());

        // Tamper the (redundant) retained head: the MUST check must reject it,
        // even though it is recomputable from the proved leaf + elements.
        retained_heads[0][0] ^= 0xFF;
        let tampered = RetainedHeads {
            prev_size: 4,
            heads: &retained_heads,
        };
        assert_eq!(
            verify_batch(n, &proved, Some(&tampered), &elements, &r),
            Err(Error::KeytransRootMismatch)
        );
    }

    #[test]
    fn verify_batch_rejects_empty_log_and_oob_index() {
        assert!(matches!(
            verify_batch(0, &[], None, &[], &[0u8; NH]),
            Err(Error::MalformedKeytrans(_))
        ));
        let leaves: Vec<_> = (0..4u64).map(leaf).collect();
        let r = root(&leaves);
        assert!(matches!(
            verify_batch(4, &[(9, [0u8; NH])], None, &[], &r),
            Err(Error::MalformedKeytrans(_))
        ));
    }
}
