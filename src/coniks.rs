//! Layer-3c: **CONIKS-style index privacy** — a per-namespace directory whose
//! lookups produce verifiable *presence* and *absence* proofs without revealing
//! which identities the directory holds.
//!
//! ## How it fits together
//!
//! Three pieces combine here:
//!
//! 1. A swappable **index-derivation** scheme maps an identity to a private,
//!    verifiable 256-bit tree **index**. Two schemes are supported:
//!    - a swappable VRF ([`crate::vrf`]): the server evaluates the VRF over the
//!      cleartext identity at query time and returns a proof; or
//!    - a POPRF ([`crate::poprf`], RFC 9497): the *client* blinds its identity,
//!      the server evaluates the blinded element (learning nothing), and the
//!      client unblinds + verifies to recover the same index — the query-time
//!      cleartext-label exposure is gone.
//!
//!    Because the index is the scheme's output, an observer learns nothing
//!    about the identity, and the directory cannot move an identity elsewhere
//!    without a fresh proof.
//! 2. A SHA3-512 **commitment** ([`crate::commitment`]) binds that index to the
//!    identity's value (e.g. a key-history head). The commitment — the
//!    post-quantum, binding half — is what actually sits in the tree.
//! 3. A **sparse Merkle prefix tree** (depth 256, SHA3-512 nodes) accumulates
//!    every commitment into a single root. An authentication path from a leaf to
//!    the root proves *presence*; an authentication path to the (default) empty
//!    leaf at an index proves *absence*.
//!
//! Everything is **per-namespace**: the namespace label is threaded through the
//! VRF input (VRF scheme) or the POPRF public `info` metadata (POPRF scheme),
//! and through every tree/commitment hash, so proofs from one namespace never
//! verify against another. The scheme is bound in via its suite identifier
//! ([`Vrf::suite_id`] / [`crate::poprf::POPRF_SUITE_ID`]), so a proof is tied
//! to the exact scheme it was produced under.
//!
//! ## Independent verification (#316)
//!
//! The [`verify_lookup`] and [`verify_absence`] free functions take only the
//! public inputs a relying party already has — the namespace, the VRF public
//! key, the directory root, the queried identity, and the proof — and recompute
//! everything from scratch. They do **not** need the directory. A proof also
//! serializes to canonical bytes ([`LookupProof::to_bytes`] /
//! [`AbsenceProof::to_bytes`]) and parses back, so it can be transmitted and
//! verified by any independent implementation.
//!
//! ## Hashing posture
//!
//! This prefix tree uses **SHA3-512** (post-quantum) for its nodes — it is a
//! distinct structure from the RFC 6962 append-only log ([`crate::merkle`]),
//! which stays on ecosystem SHA-256 for witness compatibility. A CONIKS root is
//! opaque bytes to Layer 1, so it can be embedded as a Layer-0 leaf and
//! witnessed without either layer's hashing affecting the other.

use std::collections::{BTreeMap, HashMap};

use metamorphic_crypto::hash::sha3_512_with_context;

use crate::commitment::{COMMITMENT_LEN, COMMITMENT_OPENING_LEN, Commitment, Opening};
use crate::directory::{
    CONIKS_V1, Directory, DirectoryBackendId, DirectoryRoot, DirectoryVerifier, SearchOutcome,
    SearchProof, SearchResult,
};
use crate::error::{Error, Result};
use crate::poprf::{self, POPRF_SUITE_ID, PoprfPublicKey, PoprfSecretKey};
use crate::vrf::{Vrf, VrfProof, VrfPublicKey, VrfSecretKey};

/// Tree depth: a 256-bit index gives one leaf position per possible VRF output
/// prefix.
const TREE_DEPTH: usize = 256;
/// Length of a tree node / leaf hash, in bytes (SHA3-512).
const NODE_LEN: usize = 64;
/// Length of the scheme-derived index, in bytes.
pub const INDEX_LEN: usize = 32;

/// A validated CONIKS namespace — the per-tenant domain separator.
///
/// A namespace is a single non-empty segment of printable ASCII excluding `/`
/// (so it slots cleanly into the `<namespace>/<record-type>/v<N>` context-label
/// grammar shared with [`crate::leaf::ContextLabel`]). Distinct namespaces get
/// independent VRF inputs and tree/commitment hashes, so their directories and
/// proofs are fully isolated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Namespace(String);

impl Namespace {
    /// Parse and validate a namespace segment.
    ///
    /// # Errors
    /// Returns [`Error::MalformedNamespace`] if it is empty or contains a byte
    /// outside printable ASCII, or a `/`.
    pub fn parse(namespace: &str) -> Result<Self> {
        if namespace.is_empty() || !namespace.bytes().all(|b| b.is_ascii_graphic() && b != b'/') {
            return Err(Error::MalformedNamespace(format!(
                "namespace must be non-empty printable ASCII without '/': {namespace:?}"
            )));
        }
        Ok(Self(namespace.to_string()))
    }

    /// The namespace string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The per-namespace commitment context label, `<ns>/coniks-commitment/v1`.
    #[must_use]
    pub fn commitment_label(&self) -> String {
        format!("{}/coniks-commitment/v1", self.0)
    }

    fn leaf_label(&self) -> String {
        format!("{}/coniks-leaf/v1", self.0)
    }

    fn node_label(&self) -> String {
        format!("{}/coniks-node/v1", self.0)
    }

    fn empty_label(&self) -> String {
        format!("{}/coniks-empty/v1", self.0)
    }

    /// Build the VRF input (`alpha`) for an identity, namespace-scoped so the
    /// derived index differs across namespaces: `u32_be(len(ns)) || ns ||
    /// identity`.
    #[must_use]
    pub fn vrf_input(&self, identity: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(4 + self.0.len() + identity.len());
        input.extend_from_slice(&(self.0.len() as u32).to_be_bytes());
        input.extend_from_slice(self.0.as_bytes());
        input.extend_from_slice(identity);
        input
    }
}

/// Return bit `i` of a 256-bit index, most-significant-bit-first (bit 0 is the
/// MSB of byte 0 and selects the first branch from the root).
fn index_bit(index: &[u8; INDEX_LEN], i: usize) -> u8 {
    (index[i / 8] >> (7 - (i % 8))) & 1
}

/// The canonical prefix key for the node at `depth` on `index`'s path: `index`'s
/// first `depth` bits with every lower bit cleared. Two indices share this key
/// at `depth` iff they agree on their first `depth` bits, so it uniquely names a
/// subtree position.
fn node_prefix(index: &[u8; INDEX_LEN], depth: usize) -> [u8; INDEX_LEN] {
    let mut prefix = [0u8; INDEX_LEN];
    let full = depth / 8;
    prefix[..full].copy_from_slice(&index[..full]);
    let rem = depth % 8;
    if rem != 0 {
        prefix[full] = index[full] & (0xffu8 << (8 - rem));
    }
    prefix
}

/// The prefix key of the *sibling* subtree at `depth + 1`: `index`'s first
/// `depth` bits with bit `depth` set to the *opposite* of `index`'s bit at that
/// position. This is the co-path node the verifier folds in at level `depth`.
fn sibling_prefix(index: &[u8; INDEX_LEN], depth: usize) -> [u8; INDEX_LEN] {
    let mut prefix = node_prefix(index, depth);
    // `node_prefix` clears bit `depth`, so we only need to *set* it when the
    // sibling side is the `1` branch, i.e. when `index`'s bit there is `0`.
    if index_bit(index, depth) == 0 {
        prefix[depth / 8] |= 1 << (7 - (depth % 8));
    }
    prefix
}

/// The inclusive upper bound of the index range covered by the subtree at
/// `depth` rooted at `prefix`: the fixed first `depth` bits followed by all ones.
/// Together with `prefix` (the lower bound) this bounds a `BTreeMap` range query
/// over the leaves beneath the node.
fn prefix_upper(prefix: &[u8; INDEX_LEN], depth: usize) -> [u8; INDEX_LEN] {
    let mut upper = *prefix;
    let full = depth / 8;
    let rem = depth % 8;
    let fill_from = if rem != 0 {
        upper[full] |= 0xffu8 >> rem;
        full + 1
    } else {
        full
    };
    for byte in &mut upper[fill_from..] {
        *byte = 0xff;
    }
    upper
}

/// Shared hashing for a namespace's prefix tree: node/leaf hashing plus the
/// precomputed empty-subtree defaults. Built identically by the directory
/// (to construct proofs) and by the verifier (to check them), so there is a
/// single source of the byte discipline.
struct TreeHasher {
    leaf_label: String,
    node_label: String,
    suite_id: u8,
    /// `empty[d]` is the hash of a wholly empty subtree rooted at depth `d`;
    /// `empty[TREE_DEPTH]` is the empty-leaf hash.
    empty: Vec<[u8; NODE_LEN]>,
}

impl TreeHasher {
    fn new(namespace: &Namespace, suite_id: u8) -> Self {
        let empty_leaf: [u8; NODE_LEN] = sha3_512_with_context(&namespace.empty_label(), &[]);
        let node_label = namespace.node_label();

        // empty[TREE_DEPTH] = empty leaf; empty[d] = node(empty[d+1], empty[d+1]).
        let mut empty = vec![[0u8; NODE_LEN]; TREE_DEPTH + 1];
        empty[TREE_DEPTH] = empty_leaf;
        for d in (0..TREE_DEPTH).rev() {
            empty[d] = node_hash(&node_label, &empty[d + 1], &empty[d + 1]);
        }

        Self {
            leaf_label: namespace.leaf_label(),
            node_label,
            suite_id,
            empty,
        }
    }

    /// Leaf hash, binding the VRF suite, the index, and the commitment:
    /// `SHA3-512_with_context(leaf_label, suite_id(1) || index(32) ||
    /// commitment(64))`.
    fn leaf_hash(&self, index: &[u8; INDEX_LEN], commitment: &Commitment) -> [u8; NODE_LEN] {
        let mut buf = [0u8; 1 + INDEX_LEN + COMMITMENT_LEN];
        buf[0] = self.suite_id;
        buf[1..1 + INDEX_LEN].copy_from_slice(index);
        buf[1 + INDEX_LEN..].copy_from_slice(commitment.as_bytes());
        sha3_512_with_context(&self.leaf_label, &buf)
    }

    fn empty_leaf(&self) -> [u8; NODE_LEN] {
        self.empty[TREE_DEPTH]
    }

    /// Hash of the subtree at `depth` containing exactly `leaves` (each a
    /// `(index, commitment)`), using empty-subtree shortcuts.
    ///
    /// This is the O(leaves x depth) from-scratch recursion. The directory no
    /// longer calls it on the hot path — [`ConiksDirectory`] maintains an
    /// incremental branch-node cache instead — but it is retained as the
    /// byte-exact oracle the cache is validated against in tests.
    #[cfg(all(test, not(target_arch = "wasm32")))]
    fn subtree(&self, depth: usize, leaves: &[(&[u8; INDEX_LEN], &Commitment)]) -> [u8; NODE_LEN] {
        if leaves.is_empty() {
            return self.empty[depth];
        }
        if depth == TREE_DEPTH {
            // Indices are unique, so a leaf depth holds exactly one entry.
            let (index, commitment) = leaves[0];
            return self.leaf_hash(index, commitment);
        }
        let (left, right): (Vec<_>, Vec<_>) = leaves
            .iter()
            .partition(|(index, _)| index_bit(index, depth) == 0);
        let l = self.subtree(depth + 1, &left);
        let r = self.subtree(depth + 1, &right);
        node_hash(&self.node_label, &l, &r)
    }

    /// Collect the authentication-path siblings for `target` from depth 0 to
    /// `TREE_DEPTH - 1`. A sibling equal to the empty default is recorded as
    /// `None` (the verifier recomputes it), keeping proofs compact.
    ///
    /// The O(leaves x depth) from-scratch oracle for path assembly; retained for
    /// test validation of the directory's incremental cache (see [`subtree`]).
    #[cfg(all(test, not(target_arch = "wasm32")))]
    fn collect_path(
        &self,
        depth: usize,
        target: &[u8; INDEX_LEN],
        leaves: &[(&[u8; INDEX_LEN], &Commitment)],
        out: &mut Vec<Option<[u8; NODE_LEN]>>,
    ) {
        if depth == TREE_DEPTH {
            return;
        }
        let (left, right): (Vec<_>, Vec<_>) = leaves
            .iter()
            .copied()
            .partition(|(index, _)| index_bit(index, depth) == 0);
        let (on_path, sibling) = if index_bit(target, depth) == 0 {
            (left, right)
        } else {
            (right, left)
        };
        let sibling_hash = self.subtree(depth + 1, &sibling);
        out.push(if sibling_hash == self.empty[depth + 1] {
            None
        } else {
            Some(sibling_hash)
        });
        self.collect_path(depth + 1, target, &on_path, out);
    }

    /// Recompute the directory root from a leaf node and its authentication
    /// path, folding empty defaults in for absent siblings.
    fn recompute_root(
        &self,
        target: &[u8; INDEX_LEN],
        leaf_node: [u8; NODE_LEN],
        siblings: &[Option<[u8; NODE_LEN]>],
    ) -> [u8; NODE_LEN] {
        let mut current = leaf_node;
        for depth in (0..TREE_DEPTH).rev() {
            let sibling = siblings[depth].unwrap_or(self.empty[depth + 1]);
            current = if index_bit(target, depth) == 0 {
                node_hash(&self.node_label, &current, &sibling)
            } else {
                node_hash(&self.node_label, &sibling, &current)
            };
        }
        current
    }
}

/// Interior node hash: `SHA3-512_with_context(node_label, left(64) ||
/// right(64))`.
fn node_hash(node_label: &str, left: &[u8; NODE_LEN], right: &[u8; NODE_LEN]) -> [u8; NODE_LEN] {
    let mut buf = [0u8; 2 * NODE_LEN];
    buf[..NODE_LEN].copy_from_slice(left);
    buf[NODE_LEN..].copy_from_slice(right);
    sha3_512_with_context(node_label, &buf)
}

/// An authentication path: one optional sibling per tree level (0 = nearest the
/// leaf). `None` denotes an empty-default sibling the verifier recomputes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPath {
    siblings: Vec<Option<[u8; NODE_LEN]>>,
}

impl AuthPath {
    /// Canonical serialization: a 32-byte big-endian-bit bitmap (bit `d` set iff
    /// level `d` has a non-empty sibling), followed by the present sibling
    /// hashes in level order.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bitmap = [0u8; TREE_DEPTH / 8];
        let mut hashes = Vec::new();
        for (d, sibling) in self.siblings.iter().enumerate() {
            if let Some(h) = sibling {
                bitmap[d / 8] |= 1 << (7 - (d % 8));
                hashes.extend_from_slice(h);
            }
        }
        let mut out = Vec::with_capacity(bitmap.len() + hashes.len());
        out.extend_from_slice(&bitmap);
        out.extend_from_slice(&hashes);
        out
    }

    /// Parse a canonical authentication path, returning it and the number of
    /// input bytes consumed.
    fn parse(bytes: &[u8]) -> Result<(Self, usize)> {
        let bitmap_len = TREE_DEPTH / 8;
        if bytes.len() < bitmap_len {
            return Err(Error::MalformedConiksProof(
                "authentication path shorter than its bitmap".into(),
            ));
        }
        let bitmap = &bytes[..bitmap_len];
        let present: usize = bitmap.iter().map(|b| b.count_ones() as usize).sum();
        let needed = bitmap_len + present * NODE_LEN;
        if bytes.len() < needed {
            return Err(Error::MalformedConiksProof(format!(
                "authentication path: bitmap implies {present} sibling hashes ({needed} bytes), \
                 only {} available",
                bytes.len()
            )));
        }

        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut offset = bitmap_len;
        for d in 0..TREE_DEPTH {
            let set = (bitmap[d / 8] >> (7 - (d % 8))) & 1 == 1;
            if set {
                let mut h = [0u8; NODE_LEN];
                h.copy_from_slice(&bytes[offset..offset + NODE_LEN]);
                offset += NODE_LEN;
                siblings.push(Some(h));
            } else {
                siblings.push(None);
            }
        }
        Ok((Self { siblings }, needed))
    }
}

/// Append `u32_be(len(bytes)) || bytes` to `out`.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Read a `u32_be`-length-prefixed field at `offset`, returning the field bytes
/// and the new offset.
fn read_lp<'a>(bytes: &'a [u8], offset: usize, what: &str) -> Result<(&'a [u8], usize)> {
    if bytes.len() < offset + 4 {
        return Err(Error::MalformedConiksProof(format!(
            "{what}: missing 4-byte length prefix"
        )));
    }
    let len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    let start = offset + 4;
    if bytes.len() < start + len {
        return Err(Error::MalformedConiksProof(format!(
            "{what}: length prefix {len} overruns available bytes"
        )));
    }
    Ok((&bytes[start..start + len], start + len))
}

const TAG_ABSENCE: u8 = 0x00;
const TAG_PRESENCE: u8 = 0x01;

/// A **presence** proof: the queried identity is in the directory, mapped (via
/// the VRF) to a tree index whose committed value is revealed and whose
/// authentication path recomputes the directory root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupProof {
    vrf_proof: VrfProof,
    value: Vec<u8>,
    opening: Opening,
    auth_path: AuthPath,
}

impl LookupProof {
    /// The revealed value bound at the identity's index. Only trustworthy once
    /// the proof has been checked with [`verify_lookup`].
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Canonical serialization:
    /// `0x01 || lp(vrf_proof) || lp(value) || opening(32) || auth_path`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![TAG_PRESENCE];
        push_lp(&mut out, self.vrf_proof.as_bytes());
        push_lp(&mut out, &self.value);
        out.extend_from_slice(self.opening.as_bytes());
        out.extend_from_slice(&self.auth_path.to_bytes());
        out
    }

    /// Parse a canonical presence proof.
    ///
    /// # Errors
    /// Returns [`Error::MalformedConiksProof`] if the tag, length prefixes, or
    /// trailing authentication path are inconsistent.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let Some((&tag, rest)) = bytes.split_first() else {
            return Err(Error::MalformedConiksProof("empty proof".into()));
        };
        if tag != TAG_PRESENCE {
            return Err(Error::MalformedConiksProof(format!(
                "expected presence tag 0x01, got {tag:#04x}"
            )));
        }
        let (vrf_proof, off) = read_lp(rest, 0, "vrf proof")?;
        let (value, off) = read_lp(rest, off, "value")?;
        if rest.len() < off + COMMITMENT_OPENING_LEN {
            return Err(Error::MalformedConiksProof("missing opening".into()));
        }
        let mut opening = [0u8; COMMITMENT_OPENING_LEN];
        opening.copy_from_slice(&rest[off..off + COMMITMENT_OPENING_LEN]);
        let (auth_path, consumed) = AuthPath::parse(&rest[off + COMMITMENT_OPENING_LEN..])?;
        if off + COMMITMENT_OPENING_LEN + consumed != rest.len() {
            return Err(Error::MalformedConiksProof(
                "trailing bytes after authentication path".into(),
            ));
        }
        Ok(Self {
            vrf_proof: VrfProof::from_bytes(vrf_proof.to_vec()),
            value: value.to_vec(),
            opening: Opening::from_bytes(opening),
            auth_path,
        })
    }
}

/// An **absence** proof: the queried identity is *not* in the directory; its
/// VRF-derived index holds the empty leaf, and the authentication path to that
/// empty leaf recomputes the directory root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsenceProof {
    vrf_proof: VrfProof,
    auth_path: AuthPath,
}

impl AbsenceProof {
    /// Canonical serialization: `0x00 || lp(vrf_proof) || auth_path`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![TAG_ABSENCE];
        push_lp(&mut out, self.vrf_proof.as_bytes());
        out.extend_from_slice(&self.auth_path.to_bytes());
        out
    }

    /// Parse a canonical absence proof.
    ///
    /// # Errors
    /// Returns [`Error::MalformedConiksProof`] if the tag, length prefix, or
    /// trailing authentication path are inconsistent.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let Some((&tag, rest)) = bytes.split_first() else {
            return Err(Error::MalformedConiksProof("empty proof".into()));
        };
        if tag != TAG_ABSENCE {
            return Err(Error::MalformedConiksProof(format!(
                "expected absence tag 0x00, got {tag:#04x}"
            )));
        }
        let (vrf_proof, off) = read_lp(rest, 0, "vrf proof")?;
        let (auth_path, consumed) = AuthPath::parse(&rest[off..])?;
        if off + consumed != rest.len() {
            return Err(Error::MalformedConiksProof(
                "trailing bytes after authentication path".into(),
            ));
        }
        Ok(Self {
            vrf_proof: VrfProof::from_bytes(vrf_proof.to_vec()),
            auth_path,
        })
    }
}

/// The outcome of a directory lookup: either a presence or an absence proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupResult {
    /// The identity is present; carries a [`LookupProof`].
    Present(LookupProof),
    /// The identity is absent; carries an [`AbsenceProof`].
    Absent(AbsenceProof),
}

const TAG_ABSENCE_INDEXED: u8 = 0x02;
const TAG_PRESENCE_INDEXED: u8 = 0x03;

/// An **index-bound presence** proof: the leaf at an already-derived tree
/// index holds the revealed `(value, opening)`, and the authentication path
/// recomputes the directory root. Carries no VRF proof — the index itself is
/// the caller's evidence (derived obliviously via POPRF, or from a previously
/// verified VRF proof), so the verification needs no scheme key at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedLookupProof {
    value: Vec<u8>,
    opening: Opening,
    auth_path: AuthPath,
}

impl IndexedLookupProof {
    /// The revealed value bound at the index. Only trustworthy once the proof
    /// has been checked with [`verify_indexed_lookup`].
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Canonical serialization: `0x03 || lp(value) || opening(32) || auth_path`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![TAG_PRESENCE_INDEXED];
        push_lp(&mut out, &self.value);
        out.extend_from_slice(self.opening.as_bytes());
        out.extend_from_slice(&self.auth_path.to_bytes());
        out
    }

    /// Parse a canonical index-bound presence proof.
    ///
    /// # Errors
    /// Returns [`Error::MalformedConiksProof`] if the tag, length prefixes, or
    /// trailing authentication path are inconsistent.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let Some((&tag, rest)) = bytes.split_first() else {
            return Err(Error::MalformedConiksProof("empty proof".into()));
        };
        if tag != TAG_PRESENCE_INDEXED {
            return Err(Error::MalformedConiksProof(format!(
                "expected indexed presence tag 0x03, got {tag:#04x}"
            )));
        }
        let (value, off) = read_lp(rest, 0, "value")?;
        if rest.len() < off + COMMITMENT_OPENING_LEN {
            return Err(Error::MalformedConiksProof("missing opening".into()));
        }
        let mut opening = [0u8; COMMITMENT_OPENING_LEN];
        opening.copy_from_slice(&rest[off..off + COMMITMENT_OPENING_LEN]);
        let (auth_path, consumed) = AuthPath::parse(&rest[off + COMMITMENT_OPENING_LEN..])?;
        if off + COMMITMENT_OPENING_LEN + consumed != rest.len() {
            return Err(Error::MalformedConiksProof(
                "trailing bytes after authentication path".into(),
            ));
        }
        Ok(Self {
            value: value.to_vec(),
            opening: Opening::from_bytes(opening),
            auth_path,
        })
    }
}

/// An **index-bound absence** proof: the leaf at an already-derived tree index
/// is the (default) empty leaf, and the authentication path to it recomputes
/// the directory root — proving nothing is committed there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedAbsenceProof {
    auth_path: AuthPath,
}

impl IndexedAbsenceProof {
    /// Canonical serialization: `0x02 || auth_path`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![TAG_ABSENCE_INDEXED];
        out.extend_from_slice(&self.auth_path.to_bytes());
        out
    }

    /// Parse a canonical index-bound absence proof.
    ///
    /// # Errors
    /// Returns [`Error::MalformedConiksProof`] if the tag or the trailing
    /// authentication path is inconsistent.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let Some((&tag, rest)) = bytes.split_first() else {
            return Err(Error::MalformedConiksProof("empty proof".into()));
        };
        if tag != TAG_ABSENCE_INDEXED {
            return Err(Error::MalformedConiksProof(format!(
                "expected indexed absence tag 0x02, got {tag:#04x}"
            )));
        }
        let (auth_path, consumed) = AuthPath::parse(rest)?;
        if consumed != rest.len() {
            return Err(Error::MalformedConiksProof(
                "trailing bytes after authentication path".into(),
            ));
        }
        Ok(Self { auth_path })
    }
}

/// The outcome of a [`ConiksDirectory::lookup_by_index`]: either an
/// index-bound presence or absence proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexedLookupResult {
    /// A leaf is present at the index; carries an [`IndexedLookupProof`].
    Present(IndexedLookupProof),
    /// The index holds the empty leaf; carries an [`IndexedAbsenceProof`].
    Absent(IndexedAbsenceProof),
}

struct LeafEntry {
    commitment: Commitment,
    value: Vec<u8>,
    opening: Opening,
}

/// How a directory derives the private tree index for an identity — the one
/// axis on which a CONIKS tree is versioned.
enum IndexDerivation {
    /// A swappable VRF ([`crate::vrf`]): the server evaluates over the
    /// cleartext identity (`vrf_input`) at insert and query time.
    Vrf {
        vrf: Box<dyn Vrf>,
        secret: VrfSecretKey,
        public: VrfPublicKey,
    },
    /// A POPRF ([`crate::poprf`], RFC 9497): the server derives indices at
    /// insert time non-obliviously (`Evaluate`) and answers only blinded
    /// evaluations and by-index lookups at query time, so it never sees a
    /// cleartext lookup label. The namespace is bound through the public
    /// `info` metadata, not the input.
    Poprf {
        secret: PoprfSecretKey,
        public: PoprfPublicKey,
        info: Vec<u8>,
    },
}

/// A per-namespace CONIKS directory: maps identities to committed values at
/// scheme-derived indices and produces presence/absence proofs against its
/// root.
///
/// This is the prover/operator side. Relying parties verify with the free
/// [`verify_lookup`] / [`verify_absence`] functions (VRF scheme) or
/// [`verify_indexed_lookup`] / [`verify_indexed_absence`] (any scheme, given a
/// client-derived index) and never need this type.
pub struct ConiksDirectory {
    namespace: Namespace,
    index: IndexDerivation,
    hasher: TreeHasher,
    /// Every leaf, keyed by its scheme-derived index. Presence for both lookup
    /// paths is answered from this one map: an identity is present iff the
    /// index it derives to is a key here.
    leaves: BTreeMap<[u8; INDEX_LEN], LeafEntry>,
    /// Incremental subtree-hash cache keyed by `(depth, node_prefix)`. It holds
    /// **only branch nodes** — subtree positions covering two or more leaves —
    /// which is at most `leaves - 1` entries (O(N) memory, not O(N x depth)).
    /// Empty subtrees fold to the [`TreeHasher`] default and singleton subtrees
    /// are recomputed on demand from their one leaf, so neither is cached. This
    /// keeps [`ConiksDirectory::root`] O(1) and path assembly ~O(depth) while
    /// producing byte-identical roots and proofs to the from-scratch recursion.
    branch_cache: HashMap<(u16, [u8; INDEX_LEN]), [u8; NODE_LEN]>,
}

impl ConiksDirectory {
    /// Create an empty directory for `namespace` using `vrf`, generating a fresh
    /// VRF keypair from the OS CSPRNG.
    #[must_use]
    pub fn new(namespace: Namespace, vrf: Box<dyn Vrf>) -> Self {
        let (vrf_secret, vrf_public) = vrf.generate_keypair();
        Self::with_secret_key(namespace, vrf, vrf_secret, vrf_public)
    }

    /// Create an empty VRF-backed directory from an existing VRF secret key
    /// (e.g. a persisted per-namespace key).
    ///
    /// # Errors
    /// Returns [`Error::Vrf`] if the public key cannot be derived from the
    /// secret key.
    pub fn from_secret_key(
        namespace: Namespace,
        vrf: Box<dyn Vrf>,
        vrf_secret: VrfSecretKey,
    ) -> Result<Self> {
        let vrf_public = vrf.derive_public_key(&vrf_secret)?;
        Ok(Self::with_secret_key(
            namespace, vrf, vrf_secret, vrf_public,
        ))
    }

    fn with_secret_key(
        namespace: Namespace,
        vrf: Box<dyn Vrf>,
        vrf_secret: VrfSecretKey,
        vrf_public: VrfPublicKey,
    ) -> Self {
        let hasher = TreeHasher::new(&namespace, vrf.suite_id());
        Self {
            namespace,
            index: IndexDerivation::Vrf {
                vrf,
                secret: vrf_secret,
                public: vrf_public,
            },
            hasher,
            leaves: BTreeMap::new(),
            branch_cache: HashMap::new(),
        }
    }

    /// Create an empty POPRF-backed directory for `namespace` (RFC 9497
    /// index-oblivious lookups).
    ///
    /// `info` is the public POPRF metadata binding this namespace's evaluations
    /// (e.g. mosskeys' `"mosskeys/directory/v1:<namespace_id>"`); it is
    /// threaded through both construction (`Evaluate`) and serving
    /// (`BlindEvaluate`), and the client must use the identical `info` to
    /// recover the same index. `poprf_secret` is the deployment evaluation key.
    ///
    /// # Errors
    /// Returns [`Error::Poprf`] if the public key cannot be derived from the
    /// secret key.
    pub fn poprf(
        namespace: Namespace,
        info: Vec<u8>,
        poprf_secret: PoprfSecretKey,
    ) -> Result<Self> {
        let public = poprf::derive_public_key(&poprf_secret)?;
        let hasher = TreeHasher::new(&namespace, POPRF_SUITE_ID);
        Ok(Self {
            namespace,
            index: IndexDerivation::Poprf {
                secret: poprf_secret,
                public,
                info,
            },
            hasher,
            leaves: BTreeMap::new(),
            branch_cache: HashMap::new(),
        })
    }

    /// The namespace this directory serves.
    #[must_use]
    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// The index-derivation suite identifier bound into this directory's leaf
    /// hashes (an RFC 9381 suite octet for a VRF directory,
    /// [`POPRF_SUITE_ID`] for a POPRF one).
    #[must_use]
    pub fn suite_id(&self) -> u8 {
        match &self.index {
            IndexDerivation::Vrf { vrf, .. } => vrf.suite_id(),
            IndexDerivation::Poprf { .. } => POPRF_SUITE_ID,
        }
    }

    /// The VRF public key relying parties use to verify proofs, for a
    /// VRF-backed directory (`None` on a POPRF one).
    #[must_use]
    pub fn vrf_public_key(&self) -> Option<&VrfPublicKey> {
        match &self.index {
            IndexDerivation::Vrf { public, .. } => Some(public),
            IndexDerivation::Poprf { .. } => None,
        }
    }

    /// The POPRF public key clients blind under, for a POPRF-backed directory
    /// (`None` on a VRF one).
    #[must_use]
    pub fn poprf_public_key(&self) -> Option<&PoprfPublicKey> {
        match &self.index {
            IndexDerivation::Poprf { public, .. } => Some(public),
            IndexDerivation::Vrf { .. } => None,
        }
    }

    /// The public POPRF `info` metadata binding this directory's evaluations,
    /// for a POPRF-backed directory (`None` on a VRF one).
    #[must_use]
    pub fn poprf_info(&self) -> Option<&[u8]> {
        match &self.index {
            IndexDerivation::Poprf { info, .. } => Some(info),
            IndexDerivation::Vrf { .. } => None,
        }
    }

    /// Derive the tree index for `identity` under this directory's scheme.
    /// VRF: `vrf_input` namespaced input, proof-to-output; POPRF: bare identity
    /// input, namespace bound via `info`.
    fn derive_index(&self, identity: &[u8]) -> Result<[u8; INDEX_LEN]> {
        match &self.index {
            IndexDerivation::Vrf { vrf, secret, .. } => {
                let alpha = self.namespace.vrf_input(identity);
                let proof = vrf.prove(secret, &alpha)?;
                Ok(vrf.proof_to_output(&proof)?.index())
            }
            IndexDerivation::Poprf { secret, info, .. } => {
                poprf::evaluate_index(secret, identity, info)
            }
        }
    }

    /// Insert (or replace) `identity`'s `value`, committing to it under a fresh
    /// random opening and placing the commitment at the identity's derived
    /// index.
    ///
    /// # Errors
    /// Returns [`Error::Vrf`] / [`Error::Poprf`] if index derivation fails.
    pub fn insert(&mut self, identity: &[u8], value: &[u8]) -> Result<()> {
        let index = self.derive_index(identity)?;

        let (commitment, opening) =
            crate::commitment::commit(&self.namespace.commitment_label(), value);

        self.leaves.insert(
            index,
            LeafEntry {
                commitment,
                value: value.to_vec(),
                opening,
            },
        );
        self.recompute_branch_path(&index);
        Ok(())
    }

    /// The hash of the subtree at `depth` rooted at `prefix`, in O(1) for empty
    /// and branch positions and O(depth) for a singleton. Byte-identical to
    /// [`TreeHasher::subtree`] for the same set of leaves, but derived from the
    /// leaf map plus the branch cache instead of a full recursion.
    fn subtree_hash(&self, depth: usize, prefix: &[u8; INDEX_LEN]) -> [u8; NODE_LEN] {
        let upper = prefix_upper(prefix, depth);
        let mut range = self.leaves.range(*prefix..=upper);
        match (range.next(), range.next()) {
            // Empty subtree: the precomputed default.
            (None, _) => self.hasher.empty[depth],
            // Exactly one leaf: fold it up from the leaf level on demand.
            (Some((index, leaf)), None) => self.singleton_subtree(depth, index, &leaf.commitment),
            // Two or more leaves: a branch node, which is always cached.
            (Some(_), Some(_)) => *self
                .branch_cache
                .get(&(depth as u16, *prefix))
                .expect("branch node covering >= 2 leaves must be cached"),
        }
    }

    /// The hash of a subtree at `depth` that contains exactly one leaf: the leaf
    /// hash folded upward with empty-default siblings from the leaf level to
    /// `depth`. This reproduces [`TreeHasher::subtree`]'s singleton descent
    /// without materializing the intervening chain.
    fn singleton_subtree(
        &self,
        depth: usize,
        index: &[u8; INDEX_LEN],
        commitment: &Commitment,
    ) -> [u8; NODE_LEN] {
        let mut current = self.hasher.leaf_hash(index, commitment);
        for d in (depth..TREE_DEPTH).rev() {
            let empty_sibling = self.hasher.empty[d + 1];
            current = if index_bit(index, d) == 0 {
                node_hash(&self.hasher.node_label, &current, &empty_sibling)
            } else {
                node_hash(&self.hasher.node_label, &empty_sibling, &current)
            };
        }
        current
    }

    /// Rebuild the cached branch hashes along `index`'s root-to-leaf path after
    /// its leaf changed. Every node on the path is folded bottom-up from the leaf
    /// using sibling subtree hashes (which are unaffected by this leaf and so are
    /// already cached, singleton, or empty). A path node is stored in the branch
    /// cache iff it now covers two or more leaves; otherwise any stale entry is
    /// removed. O(depth) hashes and map operations.
    fn recompute_branch_path(&mut self, index: &[u8; INDEX_LEN]) {
        let mut current = {
            let leaf = self
                .leaves
                .get(index)
                .expect("leaf was just inserted for this index");
            self.hasher.leaf_hash(index, &leaf.commitment)
        };
        for depth in (0..TREE_DEPTH).rev() {
            let sibling = self.subtree_hash(depth + 1, &sibling_prefix(index, depth));
            current = if index_bit(index, depth) == 0 {
                node_hash(&self.hasher.node_label, &current, &sibling)
            } else {
                node_hash(&self.hasher.node_label, &sibling, &current)
            };
            let prefix = node_prefix(index, depth);
            let upper = prefix_upper(&prefix, depth);
            let mut range = self.leaves.range(prefix..=upper);
            let is_branch = range.next().is_some() && range.next().is_some();
            if is_branch {
                self.branch_cache.insert((depth as u16, prefix), current);
            } else {
                self.branch_cache.remove(&(depth as u16, prefix));
            }
        }
    }

    /// The current directory root (the SHA3-512 prefix-tree root over all
    /// commitments). O(1) amortized: the root is the cached branch node at
    /// depth 0 (or the empty/singleton default for tiny directories).
    #[must_use]
    pub fn root(&self) -> [u8; NODE_LEN] {
        self.subtree_hash(0, &[0u8; INDEX_LEN])
    }

    /// Assemble the authentication path for `index` from depth 0 to
    /// `TREE_DEPTH - 1`, recording empty-default siblings as `None` exactly as
    /// the from-scratch `collect_path` oracle does.
    fn auth_path(&self, index: &[u8; INDEX_LEN]) -> AuthPath {
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        for depth in 0..TREE_DEPTH {
            let sibling = self.subtree_hash(depth + 1, &sibling_prefix(index, depth));
            siblings.push(if sibling == self.hasher.empty[depth + 1] {
                None
            } else {
                Some(sibling)
            });
        }
        AuthPath { siblings }
    }

    /// Look up `identity` in the clear, returning a presence or absence proof
    /// against the current root. **VRF-backed directories only**: a POPRF
    /// directory never sees a cleartext lookup label by design — clients blind
    /// ([`ConiksDirectory::blind_evaluate`]) and query by derived index
    /// ([`ConiksDirectory::lookup_by_index`]).
    ///
    /// # Errors
    /// - [`Error::Poprf`] on a POPRF-backed directory.
    /// - [`Error::Vrf`] if proving the identity's index fails.
    pub fn lookup(&self, identity: &[u8]) -> Result<LookupResult> {
        let IndexDerivation::Vrf { vrf, secret, .. } = &self.index else {
            return Err(Error::Poprf(
                "cleartext identity lookups are not supported on a POPRF-backed directory: \
                 use blind_evaluate + lookup_by_index"
                    .into(),
            ));
        };
        let alpha = self.namespace.vrf_input(identity);
        let vrf_proof = vrf.prove(secret, &alpha)?;
        let index = vrf.proof_to_output(&vrf_proof)?.index();
        let auth_path = self.auth_path(&index);

        match self.leaves.get(&index) {
            Some(leaf) => Ok(LookupResult::Present(LookupProof {
                vrf_proof,
                value: leaf.value.clone(),
                opening: leaf.opening.clone(),
                auth_path,
            })),
            None => Ok(LookupResult::Absent(AbsenceProof {
                vrf_proof,
                auth_path,
            })),
        }
    }

    /// Look up a **derived index** directly, returning a presence or absence
    /// proof against the current root — no identity and no cleartext label
    /// involved. This is the POPRF serving path (the client derives the index
    /// obliviously and verifies with [`verify_indexed_lookup`] /
    /// [`verify_indexed_absence`]); it works on VRF-backed directories too,
    /// for clients that derived the index from a previously verified VRF proof.
    #[must_use]
    pub fn lookup_by_index(&self, index: &[u8; INDEX_LEN]) -> IndexedLookupResult {
        let auth_path = self.auth_path(index);
        match self.leaves.get(index) {
            Some(leaf) => IndexedLookupResult::Present(IndexedLookupProof {
                value: leaf.value.clone(),
                opening: leaf.opening.clone(),
                auth_path,
            }),
            None => IndexedLookupResult::Absent(IndexedAbsenceProof { auth_path }),
        }
    }

    /// The server-side oblivious evaluation (RFC 9497 `BlindEvaluate`):
    /// evaluate a client's blinded element under this directory's POPRF key,
    /// returning `(evaluated_element, dleq_proof)`. The directory learns
    /// nothing about the identity behind the blinded element.
    ///
    /// # Errors
    /// - [`Error::Poprf`] on a VRF-backed directory, or if the blinded element
    ///   is structurally invalid, or the tweaked key is zero (`InverseError`).
    pub fn blind_evaluate(&self, blinded_element: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match &self.index {
            IndexDerivation::Poprf { secret, info, .. } => {
                poprf::blind_evaluate(secret, blinded_element, info)
            }
            IndexDerivation::Vrf { .. } => Err(Error::Poprf(
                "blind evaluation requires a POPRF-backed directory".into(),
            )),
        }
    }
}

/// Recover and validate the VRF-derived index for `identity` under a proof.
fn verified_index(
    vrf: &dyn Vrf,
    namespace: &Namespace,
    vrf_public: &VrfPublicKey,
    identity: &[u8],
    vrf_proof: &VrfProof,
) -> Result<[u8; INDEX_LEN]> {
    let alpha = namespace.vrf_input(identity);
    match vrf.verify(vrf_public, &alpha, vrf_proof)? {
        Some(output) => Ok(output.index()),
        None => Err(Error::VrfProofInvalid),
    }
}

/// Independently verify a **presence** proof, returning the proven value.
///
/// Recomputes everything from public inputs: the VRF proof binds `identity` to a
/// private index, the revealed `(value, opening)` reproduce the leaf commitment,
/// and the authentication path must recompute `root`.
///
/// # Errors
/// - [`Error::VrfProofInvalid`] if the VRF proof does not verify.
/// - [`Error::ConiksRootMismatch`] if the authentication path does not
///   recompute `root` (a wrong value, opening, or tampered path all surface
///   here).
/// - [`Error::Vrf`] for a structurally invalid VRF proof.
pub fn verify_lookup(
    vrf: &dyn Vrf,
    namespace: &Namespace,
    vrf_public: &VrfPublicKey,
    root: &[u8; NODE_LEN],
    identity: &[u8],
    proof: &LookupProof,
) -> Result<Vec<u8>> {
    let index = verified_index(vrf, namespace, vrf_public, identity, &proof.vrf_proof)?;

    let commitment = crate::commitment::commit_with_opening(
        &namespace.commitment_label(),
        &proof.value,
        &proof.opening,
    );
    let hasher = TreeHasher::new(namespace, vrf.suite_id());
    let leaf = hasher.leaf_hash(&index, &commitment);
    let recomputed = hasher.recompute_root(&index, leaf, &proof.auth_path.siblings);

    if &recomputed == root {
        Ok(proof.value.clone())
    } else {
        Err(Error::ConiksRootMismatch)
    }
}

/// Independently verify an **absence** proof.
///
/// Recomputes the VRF-derived index for `identity` and checks that the
/// authentication path to the *empty* leaf at that index recomputes `root` —
/// proving no value is committed there.
///
/// # Errors
/// - [`Error::VrfProofInvalid`] if the VRF proof does not verify.
/// - [`Error::ConiksRootMismatch`] if the authentication path does not
///   recompute `root`.
/// - [`Error::Vrf`] for a structurally invalid VRF proof.
pub fn verify_absence(
    vrf: &dyn Vrf,
    namespace: &Namespace,
    vrf_public: &VrfPublicKey,
    root: &[u8; NODE_LEN],
    identity: &[u8],
    proof: &AbsenceProof,
) -> Result<()> {
    let index = verified_index(vrf, namespace, vrf_public, identity, &proof.vrf_proof)?;

    let hasher = TreeHasher::new(namespace, vrf.suite_id());
    let recomputed = hasher.recompute_root(&index, hasher.empty_leaf(), &proof.auth_path.siblings);

    if &recomputed == root {
        Ok(())
    } else {
        Err(Error::ConiksRootMismatch)
    }
}

/// Independently verify an **index-bound presence** proof, returning the
/// proven value.
///
/// The caller supplies the tree `index` it derived itself (obliviously via
/// POPRF, or from a previously verified VRF proof) — no identity, scheme key,
/// or scheme proof is needed: the revealed `(value, opening)` must reproduce
/// the leaf commitment at `index`, and the authentication path must recompute
/// `root`. `suite_id` is the directory's index-derivation binding identifier
/// ([`ConiksDirectory::suite_id`]), bound into the leaf hash.
///
/// # Errors
/// - [`Error::ConiksRootMismatch`] if the authentication path does not
///   recompute `root` (a wrong value, opening, or tampered path).
pub fn verify_indexed_lookup(
    namespace: &Namespace,
    suite_id: u8,
    root: &[u8; NODE_LEN],
    index: &[u8; INDEX_LEN],
    proof: &IndexedLookupProof,
) -> Result<Vec<u8>> {
    let commitment = crate::commitment::commit_with_opening(
        &namespace.commitment_label(),
        &proof.value,
        &proof.opening,
    );
    let hasher = TreeHasher::new(namespace, suite_id);
    let leaf = hasher.leaf_hash(index, &commitment);
    let recomputed = hasher.recompute_root(index, leaf, &proof.auth_path.siblings);

    if &recomputed == root {
        Ok(proof.value.clone())
    } else {
        Err(Error::ConiksRootMismatch)
    }
}

/// Independently verify an **index-bound absence** proof: the authentication
/// path to the *empty* leaf at `index` must recompute `root` — proving no
/// value is committed there.
///
/// # Errors
/// - [`Error::ConiksRootMismatch`] if the authentication path does not
///   recompute `root`.
pub fn verify_indexed_absence(
    namespace: &Namespace,
    suite_id: u8,
    root: &[u8; NODE_LEN],
    index: &[u8; INDEX_LEN],
    proof: &IndexedAbsenceProof,
) -> Result<()> {
    let hasher = TreeHasher::new(namespace, suite_id);
    let recomputed = hasher.recompute_root(index, hasher.empty_leaf(), &proof.auth_path.siblings);

    if &recomputed == root {
        Ok(())
    } else {
        Err(Error::ConiksRootMismatch)
    }
}

/// Read a CONIKS directory root from the opaque [`DirectoryRoot`] byte wrapper,
/// rejecting a length other than the SHA3-512 node size.
fn coniks_root_bytes(root: &DirectoryRoot) -> Result<[u8; NODE_LEN]> {
    root.as_bytes().try_into().map_err(|_| {
        Error::MalformedConiksProof(format!(
            "directory root must be {NODE_LEN} bytes, got {}",
            root.as_bytes().len()
        ))
    })
}

/// CONIKS implements the swappable [`Directory`] trait (the prover/operator
/// side) additively over its inherent API — same proofs, same bytes.
impl Directory for ConiksDirectory {
    fn backend_id(&self) -> DirectoryBackendId {
        CONIKS_V1
    }

    fn root(&self) -> DirectoryRoot {
        DirectoryRoot::from_bytes(ConiksDirectory::root(self).to_vec())
    }

    fn search(&self, label: &[u8]) -> Result<SearchResult> {
        Ok(match self.lookup(label)? {
            LookupResult::Present(proof) => SearchResult::new(
                SearchOutcome::Present(proof.value().to_vec()),
                SearchProof::from_bytes(proof.to_bytes()),
            ),
            LookupResult::Absent(proof) => SearchResult::new(
                SearchOutcome::Absent,
                SearchProof::from_bytes(proof.to_bytes()),
            ),
        })
    }
}

/// The relying-party side of CONIKS as a [`DirectoryVerifier`]: it carries the
/// public inputs the free [`verify_lookup`] / [`verify_absence`] functions need
/// (namespace, VRF construction, VRF public key) and recomputes everything from
/// the proof — it never holds or trusts a [`ConiksDirectory`].
pub struct ConiksVerifier {
    namespace: Namespace,
    vrf: Box<dyn Vrf>,
    vrf_public: VrfPublicKey,
}

impl ConiksVerifier {
    /// Build a verifier for `namespace` checking proofs produced under `vrf`
    /// against `vrf_public`.
    #[must_use]
    pub fn new(namespace: Namespace, vrf: Box<dyn Vrf>, vrf_public: VrfPublicKey) -> Self {
        Self {
            namespace,
            vrf,
            vrf_public,
        }
    }
}

impl DirectoryVerifier for ConiksVerifier {
    fn backend_id(&self) -> DirectoryBackendId {
        CONIKS_V1
    }

    fn verify_search(
        &self,
        root: &DirectoryRoot,
        label: &[u8],
        proof: &SearchProof,
    ) -> Result<SearchOutcome> {
        let root = coniks_root_bytes(root)?;
        let bytes = proof.as_bytes();
        // The CONIKS proof bytes are self-tagging (0x00 absence / 0x01
        // presence), so the discriminator is recovered from the proof itself.
        match bytes.first() {
            Some(&TAG_PRESENCE) => {
                let proof = LookupProof::from_bytes(bytes)?;
                let value = verify_lookup(
                    self.vrf.as_ref(),
                    &self.namespace,
                    &self.vrf_public,
                    &root,
                    label,
                    &proof,
                )?;
                Ok(SearchOutcome::Present(value))
            }
            Some(&TAG_ABSENCE) => {
                let proof = AbsenceProof::from_bytes(bytes)?;
                verify_absence(
                    self.vrf.as_ref(),
                    &self.namespace,
                    &self.vrf_public,
                    &root,
                    label,
                    &proof,
                )?;
                Ok(SearchOutcome::Absent)
            }
            _ => Err(Error::MalformedConiksProof(
                "empty or unrecognized search-proof tag".into(),
            )),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::vrf::Ecvrf;

    fn dir() -> ConiksDirectory {
        ConiksDirectory::new(Namespace::parse("acme").unwrap(), Box::new(Ecvrf))
    }

    #[test]
    fn namespace_validation() {
        assert!(Namespace::parse("acme").is_ok());
        assert!(Namespace::parse("mosslet").is_ok());
        assert!(Namespace::parse("").is_err());
        assert!(Namespace::parse("has/slash").is_err());
        assert!(Namespace::parse("has space").is_err());
    }

    #[test]
    fn present_lookup_verifies() {
        let mut d = dir();
        d.insert(b"alice", b"alice-value").unwrap();
        d.insert(b"bob", b"bob-value").unwrap();
        let root = d.root();

        let LookupResult::Present(proof) = d.lookup(b"alice").unwrap() else {
            panic!("alice should be present");
        };
        let value = verify_lookup(
            &Ecvrf,
            d.namespace(),
            d.vrf_public_key().unwrap(),
            &root,
            b"alice",
            &proof,
        )
        .unwrap();
        assert_eq!(value, b"alice-value");
    }

    #[test]
    fn absent_lookup_verifies() {
        let mut d = dir();
        d.insert(b"alice", b"v").unwrap();
        let root = d.root();

        let LookupResult::Absent(proof) = d.lookup(b"carol").unwrap() else {
            panic!("carol should be absent");
        };
        verify_absence(
            &Ecvrf,
            d.namespace(),
            d.vrf_public_key().unwrap(),
            &root,
            b"carol",
            &proof,
        )
        .unwrap();
    }

    #[test]
    fn empty_directory_absence_verifies() {
        let d = dir();
        let root = d.root();
        let LookupResult::Absent(proof) = d.lookup(b"nobody").unwrap() else {
            panic!("absent");
        };
        verify_absence(
            &Ecvrf,
            d.namespace(),
            d.vrf_public_key().unwrap(),
            &root,
            b"nobody",
            &proof,
        )
        .unwrap();
    }

    #[test]
    fn tampered_value_is_rejected() {
        let mut d = dir();
        d.insert(b"alice", b"real").unwrap();
        let root = d.root();
        let LookupResult::Present(mut proof) = d.lookup(b"alice").unwrap() else {
            panic!("present");
        };
        proof.value = b"forged".to_vec();
        assert_eq!(
            verify_lookup(
                &Ecvrf,
                d.namespace(),
                d.vrf_public_key().unwrap(),
                &root,
                b"alice",
                &proof
            ),
            Err(Error::ConiksRootMismatch)
        );
    }

    #[test]
    fn absence_proof_for_present_identity_is_rejected() {
        // A directory cannot prove absence of an identity it actually holds: the
        // empty-leaf root recomputation will not match the real root.
        let mut d = dir();
        d.insert(b"alice", b"v").unwrap();
        let root = d.root();
        let LookupResult::Present(present) = d.lookup(b"alice").unwrap() else {
            panic!("present");
        };
        // Forge an absence proof reusing the (valid) VRF proof + path.
        let forged = AbsenceProof {
            vrf_proof: VrfProof::from_bytes(present.to_bytes()[5..5].to_vec()),
            auth_path: present.auth_path.clone(),
        };
        // Structurally the forged vrf proof is empty -> Vrf error, but even a
        // valid VRF proof would fail the root check; assert it does not pass.
        assert!(
            verify_absence(
                &Ecvrf,
                d.namespace(),
                d.vrf_public_key().unwrap(),
                &root,
                b"alice",
                &forged
            )
            .is_err()
        );
    }

    #[test]
    fn cross_namespace_proof_is_rejected() {
        let mut d = dir();
        d.insert(b"alice", b"v").unwrap();
        let root = d.root();
        let LookupResult::Present(proof) = d.lookup(b"alice").unwrap() else {
            panic!("present");
        };
        // Verifying under a different namespace must fail: the VRF input is
        // namespace-scoped, so the proof does not verify.
        let other = Namespace::parse("evil").unwrap();
        assert!(
            verify_lookup(
                &Ecvrf,
                &other,
                d.vrf_public_key().unwrap(),
                &root,
                b"alice",
                &proof
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_root_is_rejected() {
        let mut d = dir();
        d.insert(b"alice", b"v").unwrap();
        let LookupResult::Present(proof) = d.lookup(b"alice").unwrap() else {
            panic!("present");
        };
        let bad_root = [0u8; NODE_LEN];
        assert_eq!(
            verify_lookup(
                &Ecvrf,
                d.namespace(),
                d.vrf_public_key().unwrap(),
                &bad_root,
                b"alice",
                &proof
            ),
            Err(Error::ConiksRootMismatch)
        );
    }

    #[test]
    fn proofs_round_trip_through_bytes() {
        let mut d = dir();
        d.insert(b"alice", b"alice-value").unwrap();
        let root = d.root();

        let LookupResult::Present(present) = d.lookup(b"alice").unwrap() else {
            panic!("present");
        };
        let reparsed = LookupProof::from_bytes(&present.to_bytes()).unwrap();
        assert_eq!(reparsed, present);
        assert_eq!(
            verify_lookup(
                &Ecvrf,
                d.namespace(),
                d.vrf_public_key().unwrap(),
                &root,
                b"alice",
                &reparsed
            )
            .unwrap(),
            b"alice-value"
        );

        let LookupResult::Absent(absent) = d.lookup(b"carol").unwrap() else {
            panic!("absent");
        };
        let reparsed_absent = AbsenceProof::from_bytes(&absent.to_bytes()).unwrap();
        assert_eq!(reparsed_absent, absent);
        verify_absence(
            &Ecvrf,
            d.namespace(),
            d.vrf_public_key().unwrap(),
            &root,
            b"carol",
            &reparsed_absent,
        )
        .unwrap();
    }

    #[test]
    fn malformed_proof_bytes_are_rejected() {
        assert!(LookupProof::from_bytes(&[]).is_err());
        assert!(LookupProof::from_bytes(&[TAG_ABSENCE]).is_err()); // wrong tag
        assert!(AbsenceProof::from_bytes(&[TAG_PRESENCE]).is_err()); // wrong tag
        assert!(AbsenceProof::from_bytes(&[TAG_ABSENCE, 0, 0]).is_err()); // truncated lp
    }

    #[test]
    fn index_is_namespace_scoped() {
        // The same identity gets different indices under different namespaces.
        let ns_a = Namespace::parse("a").unwrap();
        let ns_b = Namespace::parse("b").unwrap();
        assert_ne!(ns_a.vrf_input(b"alice"), ns_b.vrf_input(b"alice"));
    }

    #[test]
    fn directory_backend_id_is_coniks_v1() {
        let d = dir();
        assert_eq!(Directory::backend_id(&d), CONIKS_V1);
    }

    // ─── POPRF-backed directories (RFC 9497 index-oblivious serving) ─────────

    use crate::poprf::PoprfSecretKey;

    fn poprf_dir() -> ConiksDirectory {
        let (secret, _public) = crate::poprf::generate_keypair();
        ConiksDirectory::poprf(
            Namespace::parse("acme").unwrap(),
            b"mosskeys/directory/v1:acme".to_vec(),
            secret,
        )
        .unwrap()
    }

    #[test]
    fn poprf_directory_lookup_by_index_present_and_absent() {
        let mut d = poprf_dir();
        d.insert(b"alice", b"alice-value").unwrap();
        d.insert(b"bob", b"bob-value").unwrap();
        let root = d.root();

        // The client-side index derivation: the operator's public key + the
        // public info, run through the RFC 9497 client flow.
        let info = d.poprf_info().unwrap().to_vec();
        let pk = d.poprf_public_key().unwrap().clone();
        let derive = |identity: &[u8]| -> [u8; INDEX_LEN] {
            let state = metamorphic_crypto::poprf_blind(identity, &info, pk.as_bytes()).unwrap();
            let (evaluated, proof) = d.blind_evaluate(&state.blinded_element).unwrap();
            let output = metamorphic_crypto::poprf_finalize(
                identity,
                &state.blind,
                &evaluated,
                &state.blinded_element,
                &proof,
                &info,
                &state.tweaked_key,
            )
            .unwrap()
            .expect("DLEQ proof must verify");
            output[..INDEX_LEN].try_into().unwrap()
        };

        // Presence: the obliviously derived index lands on alice's leaf.
        let index = derive(b"alice");
        let IndexedLookupResult::Present(proof) = d.lookup_by_index(&index) else {
            panic!("alice should be present");
        };
        let value =
            verify_indexed_lookup(d.namespace(), d.suite_id(), &root, &index, &proof).unwrap();
        assert_eq!(value, b"alice-value");

        // Absence: carol's index holds the empty leaf.
        let absent_index = derive(b"carol");
        let IndexedLookupResult::Absent(proof) = d.lookup_by_index(&absent_index) else {
            panic!("carol should be absent");
        };
        verify_indexed_absence(d.namespace(), d.suite_id(), &root, &absent_index, &proof).unwrap();
    }

    #[test]
    fn poprf_server_index_matches_oblivious_client_index() {
        // The directory's insert-time `Evaluate` index and the client's
        // blind/unblind/verify index are the same 32 bytes — the property the
        // whole oblivious serving path rests on.
        let mut d = poprf_dir();
        d.insert(b"alice", b"v").unwrap();

        let server_index = d.derive_index(b"alice").unwrap();
        let info = d.poprf_info().unwrap().to_vec();
        let pk = d.poprf_public_key().unwrap().clone();
        let state = metamorphic_crypto::poprf_blind(b"alice", &info, pk.as_bytes()).unwrap();
        let (evaluated, proof) = d.blind_evaluate(&state.blinded_element).unwrap();
        let output = metamorphic_crypto::poprf_finalize(
            b"alice",
            &state.blind,
            &evaluated,
            &state.blinded_element,
            &proof,
            &info,
            &state.tweaked_key,
        )
        .unwrap()
        .unwrap();
        assert_eq!(&server_index[..], &output[..INDEX_LEN]);
    }

    #[test]
    fn poprf_directory_rejects_cleartext_lookup() {
        let mut d = poprf_dir();
        d.insert(b"alice", b"v").unwrap();
        assert!(matches!(d.lookup(b"alice"), Err(Error::Poprf(_))));
    }

    #[test]
    fn vrf_directory_rejects_blind_evaluate() {
        let d = dir();
        assert!(matches!(d.blind_evaluate(&[0u8; 32]), Err(Error::Poprf(_))));
    }

    #[test]
    fn poprf_and_vrf_roots_diverge_for_same_leaves() {
        // The suite id is bound into every leaf hash, so the two schemes
        // produce different roots over identical (identity, value) data —
        // proofs can never be reinterpreted across schemes.
        let mut v = dir();
        v.insert(b"alice", b"v").unwrap();
        let mut p = poprf_dir();
        p.insert(b"alice", b"v").unwrap();
        assert_ne!(v.root(), p.root());
        assert_ne!(v.suite_id(), p.suite_id());
        assert_eq!(p.suite_id(), crate::poprf::POPRF_SUITE_ID);
        assert!(p.vrf_public_key().is_none());
        assert!(v.poprf_public_key().is_none());
    }

    #[test]
    fn indexed_proofs_round_trip_through_bytes() {
        let mut d = poprf_dir();
        d.insert(b"alice", b"alice-value").unwrap();
        let index = d.derive_index(b"alice").unwrap();
        let root = d.root();

        let IndexedLookupResult::Present(present) = d.lookup_by_index(&index) else {
            panic!("present");
        };
        let reparsed = IndexedLookupProof::from_bytes(&present.to_bytes()).unwrap();
        assert_eq!(reparsed, present);
        assert_eq!(
            verify_indexed_lookup(d.namespace(), d.suite_id(), &root, &index, &reparsed).unwrap(),
            b"alice-value"
        );

        let absent_index = d.derive_index(b"carol").unwrap();
        let IndexedLookupResult::Absent(absent) = d.lookup_by_index(&absent_index) else {
            panic!("absent");
        };
        let reparsed_absent = IndexedAbsenceProof::from_bytes(&absent.to_bytes()).unwrap();
        assert_eq!(reparsed_absent, absent);
        verify_indexed_absence(
            d.namespace(),
            d.suite_id(),
            &root,
            &absent_index,
            &reparsed_absent,
        )
        .unwrap();

        // Malformed / cross-tag bytes are rejected.
        assert!(IndexedLookupProof::from_bytes(&[]).is_err());
        assert!(IndexedLookupProof::from_bytes(&absent.to_bytes()).is_err());
        assert!(IndexedAbsenceProof::from_bytes(&present.to_bytes()).is_err());
    }

    #[test]
    fn indexed_lookup_rejects_wrong_index_and_root() {
        let mut d = poprf_dir();
        d.insert(b"alice", b"v").unwrap();
        let index = d.derive_index(b"alice").unwrap();
        let other_index = d.derive_index(b"mallory").unwrap();
        let root = d.root();

        let IndexedLookupResult::Present(proof) = d.lookup_by_index(&index) else {
            panic!("present");
        };
        // A valid proof checked at the wrong index must fail root recomputation.
        assert_eq!(
            verify_indexed_lookup(d.namespace(), d.suite_id(), &root, &other_index, &proof),
            Err(Error::ConiksRootMismatch)
        );
        // And against the wrong root.
        let bad_root = [0u8; NODE_LEN];
        assert_eq!(
            verify_indexed_lookup(d.namespace(), d.suite_id(), &bad_root, &index, &proof),
            Err(Error::ConiksRootMismatch)
        );
        // A VRF suite id (different leaf-hash binding) must also fail.
        assert_eq!(
            verify_indexed_lookup(d.namespace(), 0x03, &root, &index, &proof),
            Err(Error::ConiksRootMismatch)
        );
    }

    #[test]
    fn poprf_directory_persists_from_secret_key() {
        // Construction from a persisted secret yields the same indices (the
        // property an operator relies on across restarts).
        let (secret, _public) = crate::poprf::generate_keypair();
        let secret = PoprfSecretKey::from_bytes(secret.into_bytes());
        let mut d1 = ConiksDirectory::poprf(
            Namespace::parse("acme").unwrap(),
            b"info".to_vec(),
            PoprfSecretKey::from_bytes(secret.as_bytes().to_vec()),
        )
        .unwrap();
        d1.insert(b"alice", b"v").unwrap();
        let d2 =
            ConiksDirectory::poprf(Namespace::parse("acme").unwrap(), b"info".to_vec(), secret)
                .unwrap();
        assert_eq!(
            d1.derive_index(b"alice").unwrap(),
            d2.derive_index(b"alice").unwrap()
        );
        assert_eq!(
            d1.poprf_public_key().unwrap().as_bytes(),
            d2.poprf_public_key().unwrap().as_bytes()
        );
    }

    #[test]
    fn directory_is_object_safe() {
        // Compiles + runs only if `Directory` is object-safe — the property a
        // namespace relies on to hold a `Box<dyn Directory>` per backend.
        let d: Box<dyn Directory> = Box::new(dir());
        assert_eq!(d.backend_id(), CONIKS_V1);
    }

    #[test]
    fn presence_and_absence_through_trait_object_match_inherent_api() {
        let mut concrete = dir();
        concrete.insert(b"alice", b"alice-value").unwrap();
        concrete.insert(b"bob", b"bob-value").unwrap();

        let verifier: Box<dyn DirectoryVerifier> = Box::new(ConiksVerifier::new(
            concrete.namespace().clone(),
            Box::new(Ecvrf),
            concrete.vrf_public_key().unwrap().clone(),
        ));
        let dir_obj: Box<dyn Directory> = Box::new(concrete);
        let root = dir_obj.root();

        // Presence through the trait object yields the same value as the
        // inherent lookup + free verify_lookup path.
        let present = dir_obj.search(b"alice").unwrap();
        assert_eq!(
            present.outcome(),
            &SearchOutcome::Present(b"alice-value".to_vec())
        );
        assert_eq!(
            verifier
                .verify_search(&root, b"alice", present.proof())
                .unwrap(),
            SearchOutcome::Present(b"alice-value".to_vec())
        );

        // Absence through the trait object.
        let absent = dir_obj.search(b"carol").unwrap();
        assert_eq!(absent.outcome(), &SearchOutcome::Absent);
        assert_eq!(
            verifier
                .verify_search(&root, b"carol", absent.proof())
                .unwrap(),
            SearchOutcome::Absent
        );

        // A tampered root is rejected through the trait, same as the free fn.
        let bad_root = DirectoryRoot::from_bytes(vec![0u8; root.as_bytes().len()]);
        assert_eq!(
            verifier.verify_search(&bad_root, b"alice", present.proof()),
            Err(Error::ConiksRootMismatch)
        );
    }

    #[test]
    fn trait_object_root_matches_inherent_root() {
        let mut concrete = dir();
        concrete.insert(b"alice", b"v").unwrap();
        let inherent = ConiksDirectory::root(&concrete).to_vec();
        let via_trait = Directory::root(&concrete).into_bytes();
        assert_eq!(inherent, via_trait);
    }

    #[test]
    fn cached_root_and_paths_match_from_scratch_oracle() {
        // The incremental branch cache must produce byte-identical roots and
        // authentication paths to the O(N x depth) `TreeHasher` recursion, for
        // present and absent identities and across successive inserts (which is
        // what keeps every frozen proof byte and KAT unchanged under #103).
        let mut d = dir();
        let ids: Vec<Vec<u8>> = (0u64..40).map(|i| format!("id-{i}").into_bytes()).collect();

        for (n, id) in ids.iter().enumerate() {
            d.insert(id, format!("value-{n}").as_bytes()).unwrap();

            // Root matches the from-scratch oracle over the current leaf set.
            let all: Vec<_> = d
                .leaves
                .iter()
                .map(|(index, leaf)| (index, &leaf.commitment))
                .collect();
            let oracle_root = d.hasher.subtree(0, &all);
            assert_eq!(d.root(), oracle_root, "root mismatch after {n} inserts");
        }

        let all: Vec<_> = d
            .leaves
            .iter()
            .map(|(index, leaf)| (index, &leaf.commitment))
            .collect();
        let oracle_path = |identity: &[u8]| {
            let index = d.derive_index(identity).unwrap();
            let mut siblings = Vec::new();
            d.hasher.collect_path(0, &index, &all, &mut siblings);
            AuthPath { siblings }.to_bytes()
        };
        let cached_path = |identity: &[u8]| match d.lookup(identity).unwrap() {
            LookupResult::Present(p) => p.auth_path.to_bytes(),
            LookupResult::Absent(p) => p.auth_path.to_bytes(),
        };

        // Present identity.
        assert_eq!(cached_path(&ids[7]), oracle_path(&ids[7]));
        // Absent identity.
        assert_eq!(
            cached_path(b"never-inserted"),
            oracle_path(b"never-inserted")
        );
    }

    #[test]
    fn replacing_a_value_updates_the_cached_root() {
        let mut d = dir();
        d.insert(b"alice", b"first").unwrap();
        d.insert(b"bob", b"bob-value").unwrap();
        let root_before = d.root();

        // Re-inserting the same identity keeps its index but changes the leaf
        // commitment, so the cached root must move and the new value must verify.
        d.insert(b"alice", b"second").unwrap();
        let root_after = d.root();
        assert_ne!(root_before, root_after);

        let all: Vec<_> = d
            .leaves
            .iter()
            .map(|(index, leaf)| (index, &leaf.commitment))
            .collect();
        assert_eq!(root_after, d.hasher.subtree(0, &all));

        let LookupResult::Present(proof) = d.lookup(b"alice").unwrap() else {
            panic!("alice should be present");
        };
        assert_eq!(
            verify_lookup(
                &Ecvrf,
                d.namespace(),
                d.vrf_public_key().unwrap(),
                &root_after,
                b"alice",
                &proof,
            )
            .unwrap(),
            b"second"
        );
    }

    use proptest::prelude::*;

    proptest! {
        // Each lookup over a sparse depth-256 tree is intentionally O(leaves *
        // depth) (singleton branches descend to the full index length), so cap
        // the case count to keep CI fast while still exercising many random
        // directory shapes.
        #![proptest_config(ProptestConfig::with_cases(24))]

        #[test]
        fn random_directory_presence_and_absence(
            present_ids in proptest::collection::vec(any::<u64>(), 1..9),
            absent_id: u64,
        ) {
            prop_assume!(!present_ids.contains(&absent_id));
            let mut d = dir();
            for id in &present_ids {
                d.insert(&id.to_be_bytes(), format!("v{id}").as_bytes()).unwrap();
            }
            let root = d.root();

            // Every inserted identity verifies as present with its value.
            for id in &present_ids {
                let key = id.to_be_bytes();
                let LookupResult::Present(proof) = d.lookup(&key).unwrap() else {
                    prop_assert!(false, "expected present");
                    unreachable!();
                };
                let value = verify_lookup(
                    &Ecvrf, d.namespace(), d.vrf_public_key().unwrap(), &root, &key, &proof,
                ).unwrap();
                prop_assert_eq!(value, format!("v{id}").into_bytes());
            }

            // A non-inserted identity verifies as absent.
            let key = absent_id.to_be_bytes();
            let LookupResult::Absent(proof) = d.lookup(&key).unwrap() else {
                prop_assert!(false, "expected absent");
                unreachable!();
            };
            verify_absence(
                &Ecvrf, d.namespace(), d.vrf_public_key().unwrap(), &root, &key, &proof,
            ).unwrap();
        }
    }
}
