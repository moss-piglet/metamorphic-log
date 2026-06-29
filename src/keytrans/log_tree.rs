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

use super::NH;
use super::tls::LogEntry;

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
}
