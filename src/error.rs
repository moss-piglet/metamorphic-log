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
}
