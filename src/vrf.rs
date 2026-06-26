//! Layer-3a: the swappable **verifiable random function (VRF)** abstraction.
//!
//! A VRF is the engine behind CONIKS-style *index privacy* ([`crate::coniks`]):
//! it maps a (private) identity index to a pseudorandom value `beta` together
//! with a proof `pi` that `beta` was computed correctly under a published VRF
//! public key. The directory places each identity at the tree position derived
//! from `beta`, so the position is verifiable and non-equivocable, yet the
//! directory never has to reveal which identities it holds.
//!
//! ## Why a trait
//!
//! The VRF construction is deliberately **pluggable** behind the [`Vrf`] trait,
//! for two reasons spelled out in the project's VRF research (#304):
//!
//! 1. **A post-quantum future.** Today's default is classical
//!    ([`Ecvrf`], RFC 9381 ECVRF-edwards25519-SHA512-TAI). There is no audited,
//!    production-grade lattice VRF yet, so a post-quantum VRF is **not built**.
//!    When one exists, it becomes another `Vrf` implementation; nothing else in
//!    the engine changes.
//! 2. **A hybrid path that is safe to design in now.** The combined output of a
//!    classical and a post-quantum VRF can be mixed via SHA3-512 so the result
//!    stays pseudorandom if *either* half is secure (closing the
//!    harvest-now/decrypt-later de-anonymisation exposure), while *uniqueness*
//!    stays anchored on the audited classical half. That output combiner —
//!    [`hybrid_output`] — is implemented here because it needs no lattice
//!    crypto; only the post-quantum `Vrf` half it would consume is missing.
//!
//! The trait is intentionally **byte-oriented and object-safe**
//! ([`VrfSecretKey`] / [`VrfPublicKey`] / [`VrfProof`] / [`VrfOutput`] are
//! opaque byte wrappers), so a namespace can hold a `Box<dyn Vrf>` and swap
//! constructions without the CONIKS layer caring which one is in use.
//!
//! ## Post-quantum posture (honest framing)
//!
//! The default VRF is **classical**. Index-privacy is the *only* property in
//! this engine that is not post-quantum from day one. Integrity, authenticity,
//! confidentiality, and the SHA3-512 commitments ([`crate::commitment`]) do not
//! depend on the VRF. The primitives are not FIPS-validated.

use core::fmt;

use crate::error::{Error, Result};

/// VRF output (`beta`): the 64-byte pseudorandom value a verified proof yields.
///
/// CONIKS derives the private tree index from this value (see
/// [`VrfOutput::index`]).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VrfOutput([u8; 64]);

impl VrfOutput {
    /// Wrap a raw 64-byte VRF output.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The raw 64-byte output.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// The 256-bit (32-byte) tree index derived from this output: the first 32
    /// bytes of `beta`, consumed most-significant-bit-first as the root-to-leaf
    /// path in the CONIKS prefix tree.
    ///
    /// Because `beta` is pseudorandom and unique per `(key, input)`, the derived
    /// index is a stable, verifiable, privacy-preserving position: an observer
    /// who sees the index learns nothing about the identity, and the directory
    /// cannot move an identity to a different position without a fresh VRF
    /// proof.
    #[must_use]
    pub fn index(&self) -> [u8; 32] {
        let mut index = [0u8; 32];
        index.copy_from_slice(&self.0[..32]);
        index
    }
}

// Avoid leaking output bytes through `Debug` in logs; show only the type.
impl fmt::Debug for VrfOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VrfOutput(..)")
    }
}

/// An opaque VRF secret key. The concrete byte encoding is defined by the
/// [`Vrf`] implementation. Treat the bytes as secret material.
#[derive(Clone)]
pub struct VrfSecretKey(Vec<u8>);

/// An opaque VRF public key. The concrete byte encoding is defined by the
/// [`Vrf`] implementation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VrfPublicKey(Vec<u8>);

/// An opaque VRF proof (`pi`). The concrete byte encoding is defined by the
/// [`Vrf`] implementation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VrfProof(Vec<u8>);

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

byte_wrapper!(VrfSecretKey, "secret-key");
byte_wrapper!(VrfPublicKey, "public-key");
byte_wrapper!(VrfProof, "proof");

// Avoid leaking secret-key bytes through `Debug`.
impl fmt::Debug for VrfSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VrfSecretKey(..)")
    }
}

/// A swappable verifiable random function.
///
/// Implementations are stateless strategy objects (the keys are passed in), so
/// a single instance can serve a whole namespace. All methods are byte-oriented
/// and the trait is object-safe, so callers can hold a `Box<dyn Vrf>`.
pub trait Vrf {
    /// A stable identifier for the construction. For RFC 9381 suites this is the
    /// ciphersuite octet (e.g. `0x03` for ECVRF-edwards25519-SHA512-TAI); a
    /// future composite/hybrid construction uses its own reserved identifier.
    /// It is mixed into CONIKS domain separation so proofs are bound to the
    /// exact VRF construction and cannot be reinterpreted under another.
    fn suite_id(&self) -> u8;

    /// Generate a fresh keypair from the OS CSPRNG, as `(secret, public)`.
    fn generate_keypair(&self) -> (VrfSecretKey, VrfPublicKey);

    /// Derive the public key for a secret key.
    ///
    /// # Errors
    /// Returns [`Error::Vrf`] if the secret key is structurally invalid.
    fn derive_public_key(&self, secret_key: &VrfSecretKey) -> Result<VrfPublicKey>;

    /// Produce a proof `pi` that binds `alpha` to its VRF output under
    /// `secret_key`.
    ///
    /// # Errors
    /// Returns [`Error::Vrf`] if the secret key is structurally invalid or the
    /// proof cannot be produced.
    fn prove(&self, secret_key: &VrfSecretKey, alpha: &[u8]) -> Result<VrfProof>;

    /// Verify a proof and, on success, return the VRF output.
    ///
    /// Returns `Ok(Some(output))` if the proof is valid, `Ok(None)` if it is
    /// well-formed but cryptographically invalid (wrong key, tampered input, or
    /// forgery).
    ///
    /// # Errors
    /// Returns [`Error::Vrf`] if `public_key` or `proof` is structurally invalid
    /// (e.g. the wrong byte length).
    fn verify(
        &self,
        public_key: &VrfPublicKey,
        alpha: &[u8],
        proof: &VrfProof,
    ) -> Result<Option<VrfOutput>>;

    /// Recover the VRF output from a proof **without** verifying it. Only safe
    /// on a proof already verified with [`Vrf::verify`] (which returns the
    /// output directly) or whose provenance is independently trusted.
    ///
    /// # Errors
    /// Returns [`Error::Vrf`] if the proof is structurally invalid.
    fn proof_to_output(&self, proof: &VrfProof) -> Result<VrfOutput>;
}

/// Classical **ECVRF-edwards25519-SHA512-TAI** (RFC 9381 ciphersuite `0x03`),
/// the default CONIKS VRF.
///
/// This is a thin adapter over [`metamorphic_crypto`]'s audited `vrf` primitive
/// (which is itself built on the in-tree `curve25519-dalek` backend and locked
/// to RFC 9381's official test vectors). No cryptography lives here — only the
/// opaque-byte ↔ primitive plumbing.
///
/// RFC 9381's sibling suite `ECVRF-edwards25519-SHA512-ELL2` (`0x04`,
/// constant-time Elligator2 hash-to-curve) is a designed-in future addition: it
/// lands when the released curve backend exposes a conformant hash-to-curve
/// (curve25519-dalek 5.x). Because [`Vrf::suite_id`] is bound into CONIKS domain
/// separation, adding it is purely additive and never invalidates a `0x03`
/// proof. The two suites are interchangeable behind this trait; index privacy as
/// observed by a verifier is identical.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ecvrf;

impl Vrf for Ecvrf {
    fn suite_id(&self) -> u8 {
        metamorphic_crypto::ECVRF_EDWARDS25519_SHA512_TAI_SUITE
    }

    fn generate_keypair(&self) -> (VrfSecretKey, VrfPublicKey) {
        let (sk, pk) = metamorphic_crypto::ecvrf_generate_keypair();
        (VrfSecretKey(sk.to_vec()), VrfPublicKey(pk.to_vec()))
    }

    fn derive_public_key(&self, secret_key: &VrfSecretKey) -> Result<VrfPublicKey> {
        let pk = metamorphic_crypto::ecvrf_public_key(secret_key.as_bytes())
            .map_err(|e| Error::Vrf(e.to_string()))?;
        Ok(VrfPublicKey(pk.to_vec()))
    }

    fn prove(&self, secret_key: &VrfSecretKey, alpha: &[u8]) -> Result<VrfProof> {
        let pi = metamorphic_crypto::ecvrf_prove(secret_key.as_bytes(), alpha)
            .map_err(|e| Error::Vrf(e.to_string()))?;
        Ok(VrfProof(pi.to_vec()))
    }

    fn verify(
        &self,
        public_key: &VrfPublicKey,
        alpha: &[u8],
        proof: &VrfProof,
    ) -> Result<Option<VrfOutput>> {
        let beta = metamorphic_crypto::ecvrf_verify(public_key.as_bytes(), alpha, proof.as_bytes())
            .map_err(|e| Error::Vrf(e.to_string()))?;
        Ok(beta.map(VrfOutput))
    }

    fn proof_to_output(&self, proof: &VrfProof) -> Result<VrfOutput> {
        let beta = metamorphic_crypto::ecvrf_proof_to_hash(proof.as_bytes())
            .map_err(|e| Error::Vrf(e.to_string()))?;
        Ok(VrfOutput(beta))
    }
}

/// Domain-separation tag for the designed-in hybrid VRF output combiner.
pub const HYBRID_OUTPUT_DST: &str = "metamorphic.app/vrf-hybrid-output/v1";

/// Combine a classical and a post-quantum VRF output into a single hybrid output
/// (the **designed-in**, not-yet-load-bearing hybrid path from #304).
///
/// ```text
/// hybrid_beta = SHA3-512_with_context(
///     "metamorphic.app/vrf-hybrid-output/v1",
///     classical_beta (64) || pq_beta (64),
/// )
/// ```
///
/// ## Why this is safe to ship before a post-quantum VRF exists
///
/// This function is *only* the output mixer; it does not, by itself, make a
/// hybrid VRF. A full hybrid VRF additionally requires a post-quantum [`Vrf`]
/// implementation whose proof is verified **alongside** the classical one
/// (strict-AND), and that PQ half does not exist yet (no audited lattice VRF).
/// The mixer is defined now so the wire/derivation format is fixed in advance:
///
/// - **Privacy is belt-and-suspenders.** SHA3-512 over both halves stays
///   pseudorandom if *either* input is secret, so a future quantum break of the
///   classical curve does not retroactively de-anonymise recorded transcripts.
/// - **Uniqueness stays anchored on the audited classical half.** We never claim
///   the (future, unaudited) lattice half contributes uniqueness; a hybrid VRF
///   built on this mixer must take the *classical* proof as the authority for
///   uniqueness. This keeps the one cryptographic property with no standardized
///   combiner resting on standardized, audited crypto.
///
/// When an audited PQ VRF lands, the hybrid construction is: verify both proofs
/// (strict-AND), then derive the index from `hybrid_output(classical, pq)`.
#[must_use]
pub fn hybrid_output(classical: &VrfOutput, pq: &VrfOutput) -> VrfOutput {
    let mut framed = [0u8; 128];
    framed[..64].copy_from_slice(classical.as_bytes());
    framed[64..].copy_from_slice(pq.as_bytes());
    VrfOutput(metamorphic_crypto::hash::sha3_512_with_context(
        HYBRID_OUTPUT_DST,
        &framed,
    ))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn ecvrf_suite_id_is_tai() {
        assert_eq!(Ecvrf.suite_id(), 0x03);
    }

    #[test]
    fn prove_verify_roundtrip_through_trait() {
        let vrf = Ecvrf;
        let (sk, pk) = vrf.generate_keypair();
        let alpha = b"alice@example.com";
        let pi = vrf.prove(&sk, alpha).unwrap();
        let out = vrf.verify(&pk, alpha, &pi).unwrap();
        assert_eq!(out, Some(vrf.proof_to_output(&pi).unwrap()));
    }

    #[test]
    fn derive_public_key_matches_keygen() {
        let vrf = Ecvrf;
        let (sk, pk) = vrf.generate_keypair();
        assert_eq!(vrf.derive_public_key(&sk).unwrap(), pk);
    }

    #[test]
    fn verify_rejects_tampered_input() {
        let vrf = Ecvrf;
        let (sk, pk) = vrf.generate_keypair();
        let pi = vrf.prove(&sk, b"original").unwrap();
        assert_eq!(vrf.verify(&pk, b"tampered", &pi).unwrap(), None);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let vrf = Ecvrf;
        let (sk, _pk) = vrf.generate_keypair();
        let (_sk2, pk2) = vrf.generate_keypair();
        let pi = vrf.prove(&sk, b"x").unwrap();
        assert_eq!(vrf.verify(&pk2, b"x", &pi).unwrap(), None);
    }

    #[test]
    fn structural_errors_surface_as_vrf_error() {
        let vrf = Ecvrf;
        let bad_pk = VrfPublicKey::from_bytes(vec![0u8; 31]);
        let pi = VrfProof::from_bytes(vec![0u8; 80]);
        assert!(matches!(vrf.verify(&bad_pk, b"x", &pi), Err(Error::Vrf(_))));
    }

    #[test]
    fn index_is_first_32_bytes_of_output() {
        let mut beta = [0u8; 64];
        for (i, b) in beta.iter_mut().enumerate() {
            *b = i as u8;
        }
        let out = VrfOutput::from_bytes(beta);
        assert_eq!(&out.index()[..], &beta[..32]);
    }

    #[test]
    fn hybrid_output_is_deterministic_and_order_sensitive() {
        let a = VrfOutput::from_bytes([1u8; 64]);
        let b = VrfOutput::from_bytes([2u8; 64]);
        assert_eq!(hybrid_output(&a, &b), hybrid_output(&a, &b));
        // Swapping the halves changes the output (classical/PQ roles are fixed).
        assert_ne!(hybrid_output(&a, &b), hybrid_output(&b, &a));
    }

    #[test]
    fn hybrid_output_matches_documented_framing() {
        let a = VrfOutput::from_bytes([7u8; 64]);
        let b = VrfOutput::from_bytes([9u8; 64]);
        let mut framed = Vec::new();
        framed.extend_from_slice(a.as_bytes());
        framed.extend_from_slice(b.as_bytes());
        let expected = metamorphic_crypto::hash::sha3_512_with_context(HYBRID_OUTPUT_DST, &framed);
        assert_eq!(hybrid_output(&a, &b).as_bytes(), &expected);
    }

    #[test]
    fn vrf_is_object_safe() {
        // Compiles only if `Vrf` is object-safe — the property the CONIKS layer
        // relies on to hold a `Box<dyn Vrf>` per namespace.
        let vrf: Box<dyn Vrf> = Box::new(Ecvrf);
        assert_eq!(vrf.suite_id(), 0x03);
    }
}
