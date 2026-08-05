//! Layer-3e: **POPRF-backed index derivation** (RFC 9497) — the oblivious
//! sibling of the VRF abstraction ([`crate::vrf`]) for CONIKS-style index
//! privacy.
//!
//! With the classical VRF, the directory must see a cleartext identity at query
//! time to produce its index proof. With this POPRF (OPRF(ristretto255,
//! SHA-512), RFC 9497 modePOPRF) the *client* blinds its identity, the server
//! evaluates the blinded element (learning nothing), and the client unblinds
//! and verifies a DLEQ proof to recover the **same deterministic index** the
//! server derives non-obliviously when constructing the tree. The CONIKS
//! prefix tree, commitments, and proofs are unchanged; only the evaluation
//! becomes interactive and oblivious.
//!
//! ## Namespace binding: `info`, not the VRF input
//!
//! A VRF binds the namespace through its *input* (`vrf_input`: `len(ns) || ns
//! || identity`). A POPRF instead binds the namespace through its **public
//! `info` metadata** (the tweak that derives the per-namespace evaluation key
//! from the single deployment keypair), so the POPRF `input` is the bare
//! identity. The operator chooses the `info` string (mosskeys uses
//! `"mosskeys/directory/v1:<namespace_id>"`); this crate treats it as opaque
//! bytes, threaded identically through construction ([`evaluate_index`]) and
//! serving ([`blind_evaluate`]) so the two always agree.
//!
//! ## What lives where
//!
//! Every primitive comes from [`metamorphic_crypto::poprf`] (the single source
//! of truth, pinned to the RFC 9497 test vectors). This module is only the
//! opaque-byte ↔ primitive plumbing plus the CONIKS index-derivation
//! convention (the first 32 bytes of the 64-byte POPRF output, exactly as
//! [`crate::vrf::VrfOutput::index`] truncates the VRF output). The client-side
//! crypto (blind / unblind / DLEQ verify) is exported from
//! `metamorphic-crypto` directly (native and WASM); it needs nothing from this
//! crate.
//!
//! ## Post-quantum posture (honest framing)
//!
//! Like the VRF it replaces, this construction is **classical** (ristretto255
//! discrete log). Blinding removes the *query-time* cleartext-label exposure
//! today; recorded transcripts are not post-quantum private
//! (harvest-now/unblind-later). The post-quantum-privacy track is the same
//! #304 research item noted in [`crate::vrf`]. Index privacy remains the only
//! non-PQ property in the engine.

use core::fmt;

use crate::error::{Error, Result};

/// The CONIKS index-derivation binding identifier for POPRF(ristretto255,
/// SHA-512), mixed into the CONIKS leaf hash exactly as the RFC 9381 VRF suite
/// octets are. A private allocation (`0x80`), not an RFC 9497 identifier.
pub const POPRF_SUITE_ID: u8 = metamorphic_crypto::POPRF_RISTRETTO255_SHA512_SUITE;

/// The 256-bit tree-index length (the leading half of the 64-byte POPRF
/// output), matching [`crate::vrf::VrfOutput::index`].
pub const POPRF_INDEX_LEN: usize = 32;

/// An opaque POPRF secret key (the deployment evaluation key). The concrete
/// byte encoding is the RFC 9497 canonical scalar. Treat the bytes as secret
/// material.
#[derive(Clone)]
pub struct PoprfSecretKey(Vec<u8>);

/// An opaque POPRF public key (published so clients can blind under it and
/// verify DLEQ proofs). The concrete byte encoding is the RFC 9497
/// ristretto255 element.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PoprfPublicKey(Vec<u8>);

macro_rules! byte_wrapper {
    ($t:ty, $what:literal) => {
        impl $t {
            #[doc = concat!("Wrap raw ", $what, " bytes.")]
            #[must_use]
            pub fn from_bytes(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }

            #[doc = concat!("Borrow the raw ", $what, " bytes.")]
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            #[doc = concat!("Consume into the raw ", $what, " bytes.")]
            #[must_use]
            pub fn into_bytes(self) -> Vec<u8> {
                self.0
            }
        }
    };
}

byte_wrapper!(PoprfSecretKey, "secret-key");
byte_wrapper!(PoprfPublicKey, "public-key");

// Avoid leaking secret-key bytes through `Debug`.
impl fmt::Debug for PoprfSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PoprfSecretKey(..)")
    }
}

/// Derive the POPRF public key for a secret key (published as the deployment's
/// evaluation public key).
///
/// # Errors
/// Returns [`Error::Poprf`] if the secret key is structurally invalid.
pub fn derive_public_key(secret_key: &PoprfSecretKey) -> Result<PoprfPublicKey> {
    let pk = metamorphic_crypto::poprf_public_key(secret_key.as_bytes())
        .map_err(|e| Error::Poprf(e.to_string()))?;
    Ok(PoprfPublicKey(pk.to_vec()))
}

/// Generate a fresh POPRF keypair from the OS CSPRNG, as `(secret, public)`.
/// Intended for tests and tooling; a deployment derives its stable key from a
/// managed secret via [`derive_key_pair`].
#[must_use]
pub fn generate_keypair() -> (PoprfSecretKey, PoprfPublicKey) {
    let (sk, pk) = metamorphic_crypto::poprf_generate_keypair();
    (PoprfSecretKey(sk.to_vec()), PoprfPublicKey(pk.to_vec()))
}

/// Derive a POPRF keypair deterministically from a 32-byte seed and a public
/// `key_info` string (RFC 9497 §3.2.1 `DeriveKeyPair`) — how an operator turns
/// a managed master secret into a stable deployment evaluation key.
///
/// # Errors
/// Returns [`Error::Poprf`] if the seed is not exactly 32 bytes.
pub fn derive_key_pair(seed: &[u8], key_info: &[u8]) -> Result<(PoprfSecretKey, PoprfPublicKey)> {
    let (sk, pk) = metamorphic_crypto::poprf_derive_key_pair(seed, key_info)
        .map_err(|e| Error::Poprf(e.to_string()))?;
    Ok((PoprfSecretKey(sk.to_vec()), PoprfPublicKey(pk.to_vec())))
}

/// The server-side, non-oblivious index derivation (RFC 9497 §3.3.3
/// `Evaluate`): the 256-bit CONIKS tree index for `identity` under
/// `secret_key` and the namespace-binding public `info`.
///
/// The operator runs this when constructing or updating the tree (it already
/// holds the cleartext identity); a relying party derives the *same* index
/// obliviously via blind → [`blind_evaluate`] → unblind + verify →
/// `metamorphic_crypto::poprf_finalize`, then takes the leading 32 bytes.
///
/// # Errors
/// Returns [`Error::Poprf`] if the secret key is structurally invalid or the
/// evaluation hits a degenerate element (a ~2^-252 event; `InverseError`
/// signals a compromised key).
pub fn evaluate_index(
    secret_key: &PoprfSecretKey,
    identity: &[u8],
    info: &[u8],
) -> Result<[u8; POPRF_INDEX_LEN]> {
    let output = metamorphic_crypto::poprf_evaluate(secret_key.as_bytes(), identity, info)
        .map_err(|e| Error::Poprf(e.to_string()))?;
    let mut index = [0u8; POPRF_INDEX_LEN];
    index.copy_from_slice(&output[..POPRF_INDEX_LEN]);
    Ok(index)
}

/// The server-side oblivious evaluation (RFC 9497 §3.3.3 `BlindEvaluate`):
/// evaluate a client's blinded element under `secret_key` tweaked by `info`,
/// returning `(evaluated_element, dleq_proof)`. The server learns nothing
/// about the identity behind `blinded_element`.
///
/// # Errors
/// Returns [`Error::Poprf`] if the secret key or blinded element is
/// structurally invalid, or the tweaked key is zero (`InverseError` — per the
/// RFC, a key-compromise signal that should trigger rotation).
pub fn blind_evaluate(
    secret_key: &PoprfSecretKey,
    blinded_element: &[u8],
    info: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (evaluated, proof) =
        metamorphic_crypto::poprf_blind_evaluate(secret_key.as_bytes(), blinded_element, info)
            .map_err(|e| Error::Poprf(e.to_string()))?;
    Ok((evaluated.to_vec(), proof.to_vec()))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn derive_key_pair_is_deterministic() {
        let (sk1, pk1) = derive_key_pair(&[7u8; 32], b"test").unwrap();
        let (sk2, pk2) = derive_key_pair(&[7u8; 32], b"test").unwrap();
        assert_eq!(sk1.as_bytes(), sk2.as_bytes());
        assert_eq!(pk1, pk2);
        assert_eq!(derive_public_key(&sk1).unwrap(), pk1);
    }

    #[test]
    fn evaluate_index_is_32_bytes_and_info_bound() {
        let (sk, _pk) = generate_keypair();
        let a = evaluate_index(&sk, b"alice", b"info-1").unwrap();
        assert_eq!(a, evaluate_index(&sk, b"alice", b"info-1").unwrap());
        assert_ne!(a, evaluate_index(&sk, b"alice", b"info-2").unwrap());
    }

    #[test]
    fn suite_id_is_private_range() {
        assert_eq!(POPRF_SUITE_ID, 0x80);
    }

    #[test]
    fn bad_secret_is_structural_error() {
        let bad = PoprfSecretKey::from_bytes(vec![0u8; 31]);
        assert!(matches!(
            evaluate_index(&bad, b"x", b"i"),
            Err(Error::Poprf(_))
        ));
        assert!(matches!(derive_public_key(&bad), Err(Error::Poprf(_))));
        assert!(matches!(
            blind_evaluate(&bad, &[0u8; 32], b"i"),
            Err(Error::Poprf(_))
        ));
    }
}
