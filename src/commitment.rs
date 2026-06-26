//! Layer-3b: **SHA3-512 hash-based commitments** binding an index to a value.
//!
//! A CONIKS directory does not store a raw `(identity, value)` pair at a tree
//! position — it stores a *commitment* to the value. The commitment is
//! **binding** (the directory cannot later open it to a different value) and
//! **hiding** (the committed bytes reveal nothing about the value without the
//! opening). A lookup proof reveals the value and its opening so the recipient
//! can check the commitment binds to exactly that value.
//!
//! This is the **post-quantum** half of the privacy layer: the binding property
//! rests on SHA3-512 collision resistance (NIST Category 5), independent of the
//! classical VRF. Even if the index-privacy VRF were broken, commitments would
//! still bind.
//!
//! ## Construction (stable wire format — reproduce exactly for parity)
//!
//! ```text
//! opening    = 32 random bytes (the per-commitment blinding nonce)
//! commitment = SHA3-512_with_context(context, opening (32) || value)
//! ```
//!
//! The fixed-length 32-byte opening sits first, so the `(opening, value)`
//! boundary is unambiguous without a length prefix, and the
//! [`metamorphic_crypto::hash::sha3_512_with_context`] framing binds the
//! commitment to a versioned `context` label (CONIKS passes a per-namespace
//! label, so commitments never collide or cross-verify between namespaces).
//!
//! Hiding holds because the 32-byte opening is high-entropy and secret until
//! revealed; binding holds because finding two `(opening, value)` pairs with the
//! same SHA3-512 digest is infeasible.

use metamorphic_crypto::hash::sha3_512_with_context;

use crate::error::{Error, Result};

/// Length of a commitment opening (blinding nonce), in bytes.
pub const COMMITMENT_OPENING_LEN: usize = 32;
/// Length of a commitment digest, in bytes (a SHA3-512 output).
pub const COMMITMENT_LEN: usize = 64;

/// A hiding, binding commitment to a value (a 64-byte SHA3-512 digest).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Commitment([u8; COMMITMENT_LEN]);

/// The opening (blinding nonce) for a [`Commitment`]. Revealing it, together
/// with the value, lets anyone re-derive and check the commitment.
#[derive(Clone, PartialEq, Eq)]
pub struct Opening([u8; COMMITMENT_OPENING_LEN]);

impl Commitment {
    /// Wrap a raw 64-byte commitment digest.
    #[must_use]
    pub fn from_bytes(bytes: [u8; COMMITMENT_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw 64-byte commitment digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; COMMITMENT_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Commitment({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

impl Opening {
    /// Wrap a raw 32-byte opening.
    #[must_use]
    pub fn from_bytes(bytes: [u8; COMMITMENT_OPENING_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw 32-byte opening.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; COMMITMENT_OPENING_LEN] {
        &self.0
    }
}

// The opening is a blinding nonce, not long-term key material, but it is secret
// until deliberately revealed in a proof, so keep it out of `Debug` output.
impl core::fmt::Debug for Opening {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Opening(..)")
    }
}

/// Derive a commitment from a value and an explicit opening (deterministic).
///
/// Use this to recompute a commitment during verification, or when the opening
/// is generated elsewhere. To create a fresh commitment, prefer [`commit`],
/// which samples the opening from the OS CSPRNG.
#[must_use]
pub fn commit_with_opening(context: &str, value: &[u8], opening: &Opening) -> Commitment {
    let mut framed = Vec::with_capacity(COMMITMENT_OPENING_LEN + value.len());
    framed.extend_from_slice(opening.as_bytes());
    framed.extend_from_slice(value);
    Commitment(sha3_512_with_context(context, &framed))
}

/// Create a fresh commitment to `value`, sampling a random 32-byte opening from
/// the OS CSPRNG. Returns `(commitment, opening)`; keep the opening to reveal in
/// a lookup proof.
#[must_use]
pub fn commit(context: &str, value: &[u8]) -> (Commitment, Opening) {
    let mut nonce = [0u8; COMMITMENT_OPENING_LEN];
    getrandom::getrandom(&mut nonce).expect("OS CSPRNG unavailable");
    let opening = Opening(nonce);
    let commitment = commit_with_opening(context, value, &opening);
    (commitment, opening)
}

/// Check that `commitment` opens to `value` under `opening` and `context`.
///
/// # Errors
/// Returns [`Error::CommitmentMismatch`] if the recomputed commitment does not
/// equal `commitment` (wrong value, wrong opening, or wrong context).
pub fn verify_commitment(
    context: &str,
    commitment: &Commitment,
    value: &[u8],
    opening: &Opening,
) -> Result<()> {
    if &commit_with_opening(context, value, opening) == commitment {
        Ok(())
    } else {
        Err(Error::CommitmentMismatch)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    const CTX: &str = "acme/coniks-commitment/v1";

    #[test]
    fn commit_then_verify_opens() {
        let (c, o) = commit(CTX, b"public key bytes");
        assert!(verify_commitment(CTX, &c, b"public key bytes", &o).is_ok());
    }

    #[test]
    fn wrong_value_does_not_open() {
        let (c, o) = commit(CTX, b"value-a");
        assert_eq!(
            verify_commitment(CTX, &c, b"value-b", &o),
            Err(Error::CommitmentMismatch)
        );
    }

    #[test]
    fn wrong_opening_does_not_open() {
        let (c, _o) = commit(CTX, b"value");
        let other = Opening::from_bytes([0u8; COMMITMENT_OPENING_LEN]);
        assert_eq!(
            verify_commitment(CTX, &c, b"value", &other),
            Err(Error::CommitmentMismatch)
        );
    }

    #[test]
    fn different_context_does_not_open() {
        // Cross-namespace separation: a commitment made under one namespace
        // label must not verify under another.
        let (c, o) = commit(CTX, b"value");
        assert_eq!(
            verify_commitment("other/coniks-commitment/v1", &c, b"value", &o),
            Err(Error::CommitmentMismatch)
        );
    }

    #[test]
    fn fresh_commitments_are_hiding_across_calls() {
        // Two commitments to the same value use independent random openings and
        // therefore differ (so the digest leaks nothing about the value).
        let (c1, _) = commit(CTX, b"same");
        let (c2, _) = commit(CTX, b"same");
        assert_ne!(c1, c2);
    }

    #[test]
    fn deterministic_for_fixed_opening() {
        let o = Opening::from_bytes([5u8; COMMITMENT_OPENING_LEN]);
        assert_eq!(
            commit_with_opening(CTX, b"v", &o),
            commit_with_opening(CTX, b"v", &o)
        );
    }

    #[test]
    fn matches_documented_framing() {
        let o = Opening::from_bytes([3u8; COMMITMENT_OPENING_LEN]);
        let value = b"explicit framing check";
        let mut framed = Vec::new();
        framed.extend_from_slice(o.as_bytes());
        framed.extend_from_slice(value);
        let expected = sha3_512_with_context(CTX, &framed);
        assert_eq!(commit_with_opening(CTX, value, &o).as_bytes(), &expected);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn commit_verify_roundtrip(value: Vec<u8>, nonce: [u8; 32]) {
            let opening = Opening::from_bytes(nonce);
            let c = commit_with_opening(CTX, &value, &opening);
            prop_assert!(verify_commitment(CTX, &c, &value, &opening).is_ok());
        }

        #[test]
        fn distinct_values_distinct_commitments(a: Vec<u8>, b: Vec<u8>, nonce: [u8; 32]) {
            prop_assume!(a != b);
            let opening = Opening::from_bytes(nonce);
            prop_assert_ne!(
                commit_with_opening(CTX, &a, &opening),
                commit_with_opening(CTX, &b, &opening)
            );
        }
    }
}
