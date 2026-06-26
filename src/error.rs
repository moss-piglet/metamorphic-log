//! Error types for the transparency-log engine.
//!
//! This module defines the crate-wide [`Error`] enum and [`Result`] alias. Like
//! the rest of the v0.1 skeleton it is intentionally minimal: variants are added
//! slice-by-slice as the verification core, tile substrate, checkpoint signing,
//! and CONIKS layers land.

use thiserror::Error;

/// Convenience alias for results returned by this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// All possible errors from transparency-log operations.
///
/// Variants are introduced as functionality lands in later slices (canonical
/// leaf encoding, Merkle hashing, inclusion/consistency proof verification,
/// tile addressing, checkpoint/signed-note parsing, and VRF lookups).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A proof, leaf, or checkpoint was malformed or failed verification.
    #[error("verification failed: {0}")]
    Verification(String),
}
