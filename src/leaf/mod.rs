//! Layer-0: canonical leaf encoding and content hashing.
//!
//! A transparency-log leaf is **opaque, app-defined record bytes**. Layer 1
//! (the Merkle tree, [`crate::merkle`]) treats them as a byte string and never
//! inspects their structure, so an application's canonical record drops in as a
//! leaf with *zero reformatting*.
//!
//! This module provides:
//!
//! 1. [`ContextLabel`] — the versioned `<namespace>/<record-type>/v<N>` domain
//!    separator used by the intra-chain content hash. The label lives *inside*
//!    the content hash (it never touches Layer 1's tile mechanics), giving
//!    cross-protocol / cross-context separation while keeping the Merkle layer
//!    label-agnostic (#299 / #290).
//!
//! 2. [`content_hash`] — the generic intra-chain leaf-content hash,
//!    `sha3_512_with_context(label, content)` from
//!    [`metamorphic_crypto`](crate). This is the per-identity continuity
//!    linkage; it is **independent** from, and must not be confused with, the
//!    RFC 6962 Merkle leaf hash ([`crate::merkle::hash_leaf`]). The same leaf
//!    bytes feed both linkages without reformatting either.
//!
//! 3. The [`key_history_v1`] conformance instance — the byte-exact
//!    `mosslet/key-history/v1` canonical leaf format shipped in Mosslet
//!    (`assets/js/crypto/key_history.js`, locked by
//!    `test/mosslet/crypto/key_history_test.exs`). This is the first real-world
//!    leaf shape and the seed of the cross-language KAT suite (#315 / #299).
//!
//! ## Byte-layout discipline (fixed, audited — version-bump-or-nothing)
//!
//! All canonical encodings in this crate use a single, fixed discipline so that
//! independent witnesses and cross-language SDKs recompute byte-for-byte:
//!
//! - integers are **big-endian** (`u32` / `u64`),
//! - variable-length fields are **`u32`-be length-prefixed** (`lp(x) =
//!   u32_be(len(x)) || x`),
//! - the layout is never reordered; a change is a new version label, never a
//!   silent reinterpretation.

use crate::error::{Error, Result};

/// A validated, versioned context label of the form
/// `<namespace>/<record-type>/v<N>`.
///
/// Used as the SHA3-512 domain separator for [`content_hash`]. The grammar is
/// deliberately small and strict so labels are unambiguous across tenants and
/// versions:
///
/// - exactly three `/`-separated, non-empty segments,
/// - the third segment is `v` followed by one or more ASCII digits (no leading
///   zero unless the version is literally `0`),
/// - all characters are printable ASCII excluding `/` within a segment.
///
/// ```
/// use metamorphic_log::leaf::ContextLabel;
///
/// let label = ContextLabel::parse("mosslet/key-history/v1").unwrap();
/// assert_eq!(label.as_str(), "mosslet/key-history/v1");
/// assert_eq!(label.namespace(), "mosslet");
/// assert_eq!(label.record_type(), "key-history");
/// assert_eq!(label.version(), 1);
///
/// assert!(ContextLabel::parse("missing/version").is_err());
/// assert!(ContextLabel::parse("a/b/v01").is_err()); // no leading zeros
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContextLabel {
    label: String,
    namespace_len: usize,
    record_type_len: usize,
    version: u64,
}

impl ContextLabel {
    /// Parse and validate a `<namespace>/<record-type>/v<N>` label.
    ///
    /// # Errors
    /// Returns [`Error::MalformedLeaf`] if the label does not match the grammar.
    pub fn parse(label: &str) -> Result<Self> {
        let mut parts = label.split('/');
        let namespace = parts.next().unwrap_or("");
        let record_type = parts.next().unwrap_or("");
        let version_seg = parts.next().unwrap_or("");
        if parts.next().is_some() {
            return Err(Error::MalformedLeaf(format!(
                "context label has too many '/'-segments: {label:?}"
            )));
        }

        let valid_segment =
            |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic() && b != b'/');
        if !valid_segment(namespace) || !valid_segment(record_type) {
            return Err(Error::MalformedLeaf(format!(
                "context label segments must be non-empty printable ASCII: {label:?}"
            )));
        }

        let digits = version_seg.strip_prefix('v').ok_or_else(|| {
            Error::MalformedLeaf(format!(
                "context label version must start with 'v': {label:?}"
            ))
        })?;
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::MalformedLeaf(format!(
                "context label version must be 'v' followed by digits: {label:?}"
            )));
        }
        if digits.len() > 1 && digits.starts_with('0') {
            return Err(Error::MalformedLeaf(format!(
                "context label version must not have leading zeros: {label:?}"
            )));
        }
        let version: u64 = digits.parse().map_err(|_| {
            Error::MalformedLeaf(format!("context label version overflow: {label:?}"))
        })?;

        Ok(Self {
            label: label.to_string(),
            namespace_len: namespace.len(),
            record_type_len: record_type.len(),
            version,
        })
    }

    /// The full label string, e.g. `"mosslet/key-history/v1"`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.label
    }

    /// The namespace segment, e.g. `"mosslet"`.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.label[..self.namespace_len]
    }

    /// The record-type segment, e.g. `"key-history"`.
    #[must_use]
    pub fn record_type(&self) -> &str {
        let start = self.namespace_len + 1;
        &self.label[start..start + self.record_type_len]
    }

    /// The numeric version `N`, e.g. `1`.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }
}

/// Generic intra-chain leaf-content hash:
/// `sha3_512_with_context(label, content)` (64 bytes).
///
/// This is the per-identity continuity linkage (e.g. `#315`'s `entry_hash` that
/// the next entry chains to via `prev_entry_hash`). It is computed over the
/// leaf *content* a given record type chooses to commit; the
/// [`key_history_v1`] instance, matching the shipped Mosslet format, commits the
/// **base64 of the canonical bytes** (see that module).
///
/// This hash is deliberately distinct from the RFC 6962 Merkle leaf hash
/// ([`crate::merkle::hash_leaf`]): one provides per-identity continuity
/// (SHA3-512, PQ posture), the other provides global append-only ordering
/// (ecosystem SHA-256, witness compatibility). The two must never be confused.
#[must_use]
pub fn content_hash(label: &ContextLabel, content: &[u8]) -> [u8; 64] {
    metamorphic_crypto::hash::sha3_512_with_context(label.as_str(), content)
}

/// Append `lp(bytes) = u32_be(len(bytes)) || bytes` to `out`.
///
/// The `u32`-be length prefix makes field boundaries unambiguous, so distinct
/// records cannot collide by boundary confusion.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The `mosslet/key-history/v1` conformance instance.
///
/// This is the first real-world Layer-0 leaf shape and the seed of the
/// cross-language KAT suite. The byte layout, the SHA3-512 `entry_hash`
/// framing, and the RFC 6962 leaf hash here are byte-for-byte identical to the
/// shipped Mosslet implementation (`assets/js/crypto/key_history.js`, locked by
/// `test/mosslet/crypto/key_history_test.exs`). A real key-history row is a
/// valid leaf with **zero reformatting**.
pub mod key_history_v1 {
    use super::{ContextLabel, Error, Result, content_hash, push_lp};
    use crate::merkle::{Hash, hash_leaf};

    /// The canonical context label for this record type.
    pub const CONTEXT: &str = "mosslet/key-history/v1";

    /// The canonical leaf format version (the `1` in `v1`).
    pub const VERSION: u32 = 1;

    /// A `mosslet/key-history/v1` entry's public fields (raw, decoded bytes).
    ///
    /// Mirrors the canonical-format inputs in `key_history.js`. The encryption
    /// and signing public keys are the raw (already base64-decoded) key bytes;
    /// `prev_entry_hash` is the raw 64-byte SHA3-512 digest of the previous
    /// entry, or `None` for the genesis entry (seq 0).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Entry {
        /// Monotonic sequence number; genesis is `0`.
        pub seq: u64,
        /// Unix epoch milliseconds (UTC) at which the entry was created.
        pub ts_ms: u64,
        /// Recipient X25519 encryption public key (raw bytes).
        pub enc_x25519: Vec<u8>,
        /// Recipient ML-KEM encryption public key (raw bytes).
        pub enc_pq: Vec<u8>,
        /// The hybrid signing public key this entry pins (raw bytes).
        pub signing_pub: Vec<u8>,
        /// Raw previous-entry hash (64 bytes), or `None` for genesis.
        pub prev_entry_hash: Option<Vec<u8>>,
    }

    impl Entry {
        /// Build the canonical, byte-reproducible serialization of this entry.
        ///
        /// ```text
        /// canonical(entry) =
        ///     u32_be(VERSION = 1)
        ///  || u64_be(seq)
        ///  || u64_be(ts_ms)
        ///  || lp(enc_x25519)
        ///  || lp(enc_pq)
        ///  || lp(signing_pub)
        ///  || lp(prev_entry_hash)   // 0-length for genesis
        /// ```
        ///
        /// # Errors
        /// Returns [`Error::MalformedLeaf`] if `prev_entry_hash` is present but
        /// empty (genesis must use `None`, not an empty vector) — this keeps the
        /// genesis/rotation distinction unambiguous.
        pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
            if matches!(self.prev_entry_hash.as_deref(), Some([])) {
                return Err(Error::MalformedLeaf(
                    "prev_entry_hash present but empty; genesis must use None".into(),
                ));
            }
            let prev: &[u8] = self.prev_entry_hash.as_deref().unwrap_or(&[]);
            let mut out = Vec::new();
            out.extend_from_slice(&VERSION.to_be_bytes());
            out.extend_from_slice(&self.seq.to_be_bytes());
            out.extend_from_slice(&self.ts_ms.to_be_bytes());
            push_lp(&mut out, &self.enc_x25519);
            push_lp(&mut out, &self.enc_pq);
            push_lp(&mut out, &self.signing_pub);
            push_lp(&mut out, prev);
            Ok(out)
        }

        /// Compute the intra-chain `entry_hash` (64-byte SHA3-512), byte-for-byte
        /// identical to the shipped `#315` value.
        ///
        /// ```text
        /// entry_hash = sha3_512_with_context(
        ///     "mosslet/key-history/v1",
        ///     canonical_bytes,
        /// )
        /// ```
        ///
        /// The shipped Mosslet/WASM API passes the canonical bytes across the
        /// JS↔WASM boundary as base64 and base64-*decodes* them before hashing,
        /// so the hashed input is the **raw canonical bytes** — exactly the same
        /// Layer-0 leaf bytes the RFC 6962 leaf hash consumes. The next entry
        /// chains to this digest via `prev_entry_hash`.
        ///
        /// # Errors
        /// Propagates [`Entry::canonical_bytes`] errors.
        pub fn entry_hash(&self) -> Result<[u8; 64]> {
            let canonical = self.canonical_bytes()?;
            let label = ContextLabel::parse(CONTEXT)?;
            Ok(content_hash(&label, &canonical))
        }

        /// Compute the RFC 6962 Merkle leaf hash `SHA-256(0x00 || canonical)`
        /// over the **raw canonical bytes** (the Layer-0 leaf bytes).
        ///
        /// This is the global append-only ordering linkage and is independent of
        /// [`Entry::entry_hash`].
        ///
        /// # Errors
        /// Propagates [`Entry::canonical_bytes`] errors.
        pub fn rfc6962_leaf_hash(&self) -> Result<Hash> {
            Ok(hash_leaf(&self.canonical_bytes()?))
        }
    }
}
