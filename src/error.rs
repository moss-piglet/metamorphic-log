//! Error types for the transparency-log engine.
//!
//! This module defines the crate-wide [`Error`](enum@Error) enum and [`Result`]
//! alias. Variants are added slice-by-slice as the verification core, tile
//! substrate, checkpoint signing, and CONIKS layers land. Slice 1 (#327)
//! introduces the canonical-leaf and RFC 6962 / RFC 9162 proof-verification
//! variants.

use thiserror::Error;

/// Convenience alias for results returned by this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// All possible errors from transparency-log operations.
///
/// The enum is `#[non_exhaustive]`: downstream code must include a wildcard arm
/// so new variants in later slices are not a breaking change.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A generic verification failure with a human-readable explanation.
    ///
    /// Prefer one of the specific variants below where it applies; this exists
    /// for cases that do not warrant a dedicated variant.
    #[error("verification failed: {0}")]
    Verification(String),

    /// A leaf index was greater than or equal to the tree size.
    ///
    /// Inclusion proofs require `0 <= index < size`.
    #[error("leaf index {index} is beyond tree size {size}")]
    IndexBeyondSize {
        /// The requested leaf index.
        index: u64,
        /// The tree size the proof was verified against.
        size: u64,
    },

    /// The supplied proof had the wrong number of hashes for the given
    /// `(index, size)` (inclusion) or `(size1, size2)` (consistency).
    #[error("wrong proof size: got {got}, want {want}")]
    WrongProofSize {
        /// The number of hashes actually supplied.
        got: usize,
        /// The number of hashes the proof shape requires.
        want: usize,
    },

    /// A hash in a proof, leaf, or root did not have the expected byte length
    /// (RFC 6962 SHA-256 nodes are always 32 bytes).
    #[error("invalid hash length: got {got} bytes, want {want}")]
    InvalidHashLength {
        /// The actual byte length.
        got: usize,
        /// The expected byte length.
        want: usize,
    },

    /// A recomputed root did not match the supplied/expected root.
    ///
    /// This is the headline negative outcome of inclusion and consistency
    /// verification: the proof did not bind the claimed leaf/old-tree to the
    /// supplied root.
    #[error("root mismatch: recomputed root does not match the expected root")]
    RootMismatch,

    /// A consistency proof was requested from an empty (size-0) tree, which is
    /// not meaningful: there is no earlier root to be consistent with.
    #[error("consistency proof from an empty tree is meaningless")]
    EmptyTreeConsistency,

    /// `size2 < size1` for a consistency proof. Consistency is only defined
    /// when the second (newer) tree is at least as large as the first.
    #[error("tree size regression: size2 ({size2}) < size1 ({size1})")]
    SizeRegression {
        /// The earlier (smaller) tree size.
        size1: u64,
        /// The later (claimed larger) tree size.
        size2: u64,
    },

    /// A consistency proof between two equal tree sizes carried a non-empty
    /// proof. When `size1 == size2` the proof MUST be empty and the two roots
    /// MUST be equal.
    #[error("consistency proof between equal sizes must be empty")]
    NonEmptyEqualSizeProof,

    /// The canonical leaf encoding was malformed (e.g. a length-prefixed field
    /// would overrun the available bytes, or a context label is invalid).
    #[error("malformed canonical leaf: {0}")]
    MalformedLeaf(String),

    /// A C2SP `tlog-tiles` tile coordinate or tile-path component was invalid
    /// (e.g. level out of range, partial-tile width out of `1..=255`, or a path
    /// that does not match `tile/<L>/<N>[.p/<W>]`).
    #[error("malformed tile: {0}")]
    MalformedTile(String),

    /// A C2SP `checkpoint` note body was malformed (missing origin/size/root
    /// lines, a non-decimal or leading-zero size, an empty extension line, or a
    /// root hash that is not exactly 32 bytes once base64-decoded).
    #[error("malformed checkpoint: {0}")]
    MalformedCheckpoint(String),

    /// A C2SP `signed-note` could not be parsed (not valid UTF-8, a forbidden
    /// ASCII control character, no blank-line/signature separator, or a
    /// malformed signature line / verifier key).
    #[error("malformed signed note: {0}")]
    MalformedNote(String),

    /// A signature line referenced a known key (matching name **and** key id)
    /// but the signature failed to verify. Per the C2SP `signed-note` spec the
    /// whole note is rejected in this case.
    #[error("invalid signature for known key {name:?} (key id {key_id:08x})")]
    InvalidSignature {
        /// The key name from the verifier / signature line.
        name: String,
        /// The 4-byte key id, as a big-endian `u32`.
        key_id: u32,
    },

    /// The note parsed correctly but no signature from any supplied trusted key
    /// verified, so the note text MUST NOT be trusted.
    #[error("note has no verifiable signature from a trusted key")]
    NoTrustedSignature,

    /// An additive hybrid post-quantum composite signature could not be produced
    /// or its key material could not be decoded/derived (via the
    /// metamorphic-crypto composite primitive). A *verification* failure of an
    /// otherwise well-formed line is reported as [`Error::InvalidSignature`]
    /// instead, matching the classical path and the C2SP `signed-note` rule.
    #[error("hybrid composite signature error: {0}")]
    HybridSignature(String),

    /// A CONIKS namespace label was malformed (empty, or containing a byte
    /// outside the printable-ASCII-excluding-`/` set). The namespace is the
    /// per-tenant domain separator threaded through every VRF, commitment, and
    /// prefix-tree hash, so it must be unambiguous.
    #[error("malformed namespace: {0}")]
    MalformedNamespace(String),

    /// A VRF operation failed structurally (e.g. a key/proof of the wrong byte
    /// length, or a proof component that is not a valid curve point). A VRF
    /// proof that is well-formed but does not verify against `(public_key,
    /// alpha)` is reported as [`Error::VrfProofInvalid`], not this variant.
    #[error("vrf error: {0}")]
    Vrf(String),

    /// A VRF proof was well-formed but did not verify: the claimed
    /// identity→index binding is not authentic under the namespace's VRF public
    /// key. CONIKS lookup/absence proofs are rejected in this case, because the
    /// private index they rely on is unproven.
    #[error("vrf proof did not verify against the namespace public key")]
    VrfProofInvalid,

    /// A commitment failed to open: the supplied `(value, opening)` does not
    /// reproduce the committed digest. The commitment binds an index to a value
    /// (SHA3-512, post-quantum), so a mismatch means the proof does not bind the
    /// claimed value.
    #[error("commitment did not open to the claimed value")]
    CommitmentMismatch,

    /// A CONIKS lookup or absence proof was structurally malformed (e.g. an
    /// authentication-path component of the wrong length, or a sibling bitmap
    /// inconsistent with the supplied sibling hashes).
    #[error("malformed coniks proof: {0}")]
    MalformedConiksProof(String),

    /// A CONIKS lookup or absence proof was well-formed but did not verify: the
    /// authentication path did not recompute the expected directory root. This
    /// is the headline negative outcome of CONIKS proof verification.
    #[error(
        "coniks proof root mismatch: recomputed directory root does not match the expected root"
    )]
    ConiksRootMismatch,

    /// A [`NamespacePolicy`](crate::policy::NamespacePolicy) record was
    /// structurally malformed: an unknown enum tag, a length-prefixed field that
    /// overruns the buffer, an invalid namespace, a `prev_policy_hash` that is
    /// present but not exactly 64 bytes, or a field combination that is illegal
    /// in this format version (e.g. a `commitment_hash` that does not match the
    /// one derived from `security_level`, a `vrf_mode` other than `Classical`,
    /// or `PureCnsa2` at a level below Cat-5).
    #[error("malformed namespace policy: {0}")]
    MalformedPolicy(String),

    /// A proposed policy migration was rejected: the new version does not chain
    /// to the prior one (`prev_policy_hash` / `policy_schema_version` /
    /// `effective_from` discontinuity), or it would **weaken** the namespace's
    /// declared posture (e.g. Cat-5 → Cat-3, a commitment-hash downgrade, or a
    /// VRF-mode downgrade). Migrations are append-only and may only strengthen;
    /// a weakening is surfaced here rather than silently applied.
    #[error("policy migration rejected: {0}")]
    PolicyMigrationRejected(String),

    /// The **declared == observed** check failed: an artifact's *observed* crypto
    /// posture does not match the *declared* [`NamespacePolicy`] posture. This is
    /// the headline negative outcome of policy enforcement — a checkpoint
    /// signature, CONIKS VRF suite, or commitment-hash parameter that disagrees
    /// with what the active policy version requires is a hard rejection (no
    /// silent downgrade).
    ///
    /// [`NamespacePolicy`]: crate::policy::NamespacePolicy
    #[error("posture mismatch: declared {declared}, observed {observed}")]
    PostureMismatch {
        /// The posture the active policy version declares.
        declared: String,
        /// The posture actually observed on the artifact.
        observed: String,
    },

    /// No [`NamespacePolicy`](crate::policy::NamespacePolicy) version is in force
    /// for the requested tree position (or the policy chain is empty), so a
    /// verifier cannot resolve which posture an entry at that position was
    /// required to use. An entry can only be enforced against a policy whose
    /// half-open validity range `[effective_from_n, effective_from_{n+1})`
    /// contains its position.
    #[error("no namespace policy in force: {0}")]
    UnknownNamespacePolicy(String),
}
