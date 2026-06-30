//! Layer-3d: the swappable **directory** abstraction.
//!
//! A *directory* maps a label (an identity, an email, a username) to a value
//! (a key-history head) and answers lookups with a proof that an independent
//! relying party can check against a published root — without trusting the
//! operator. [`crate::coniks`] is the first backend; an IETF KEYTRANS
//! combined-tree backend lands in a later slice behind this same trait.
//!
//! ## Why a trait
//!
//! The directory construction is deliberately **pluggable** behind the
//! [`Directory`] / [`DirectoryVerifier`] traits, mirroring the swappable VRF
//! pattern in [`crate::vrf`]:
//!
//! 1. **CONIKS today.** The shipped backend is the sparse SHA3-512 prefix tree
//!    in [`crate::coniks`], which answers presence/absence lookups.
//! 2. **KEYTRANS tomorrow.** The industry is converging on IETF KEYTRANS's
//!    combined log-tree + prefix-tree directory. It becomes another backend
//!    behind this trait; callers holding a `Box<dyn Directory>` swap it in
//!    without caring which construction is in use. KEYTRANS-only surface
//!    (fixed-version search, monitoring, the binary version ladder) lands as
//!    inherent methods / a future `KeytransExt` sub-trait — it is deliberately
//!    *not* forced into this base trait.
//!
//! The base trait is the **common denominator** every directory family
//! actually supports: a backend identifier, a current root, and a
//! search-and-verify surface. It is intentionally **byte-oriented and
//! object-safe** ([`DirectoryRoot`] / [`SearchProof`] are opaque byte wrappers,
//! the [`crate::vrf::VrfProof`] pattern), so a namespace can hold a
//! `Box<dyn Directory>` and a relying party a `Box<dyn DirectoryVerifier>`.
//!
//! ## Backend identifier vs. domain separation (read this)
//!
//! [`Directory::backend_id`] is the directory-layer analogue of
//! [`crate::vrf::Vrf::suite_id`]: a stable discriminator for the backend
//! family and version that distinguishes one construction's proofs from
//! another's. The eventual intent is to **bind it into proof domain
//! separation** so a proof can never be replayed across backends — exactly as
//! `suite_id` is mixed into the CONIKS leaf hash today.
//!
//! In this slice (the trait-extraction scaffold) the identifier is **exposed but
//! not yet mixed into any hash**: doing so would change the already-frozen CONIKS
//! serialized bytes (and the `key_history_v1` conformance vectors), which is a
//! versioned, opt-in change, not a zero-behavior-change refactor. Binding
//! `backend_id` into the byte stream is therefore deferred to a future format
//! version bump. Until then it is purely a runtime discriminator.

use crate::error::Result;

/// A stable identifier for a directory backend family + version.
///
/// This is the directory-layer counterpart to [`crate::vrf::Vrf::suite_id`]: it
/// names the construction a proof was produced under so proofs cannot be
/// reinterpreted across backends. See the [module docs](self) for why it is not
/// yet mixed into proof bytes in this slice.
///
/// Codes are allocated per backend family: `0x0001` is the shipped CONIKS
/// prefix-tree directory ([`CONIKS_V1`]); the experimental KEYTRANS backend
/// claims its own code when it lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DirectoryBackendId(u16);

impl DirectoryBackendId {
    /// Construct a backend id from its raw code. Prefer the provided constants
    /// (e.g. [`CONIKS_V1`]) over hand-rolling a code.
    #[must_use]
    pub const fn from_u16(code: u16) -> Self {
        Self(code)
    }

    /// The raw backend code.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// The shipped CONIKS prefix-tree directory backend ([`crate::coniks`]).
pub const CONIKS_V1: DirectoryBackendId = DirectoryBackendId::from_u16(0x0001);

/// The experimental KEYTRANS combined-tree directory backend
/// ([`crate::keytrans`]), `KEYTRANS_EXP_04`.
///
/// The code `0xF004` sits in the §15.1 `0xF000–0xFFFF` "Reserved for Private
/// Use" range (matching the private cipher suite
/// [`crate::keytrans::KT_EXP_METAMORPHIC_HYBRID`] = `0xF000`), with the low
/// nibble `4` tracking the pinned `draft-ietf-keytrans-protocol-04`. It is
/// **experimental and version-tagged**, *not* a frozen wire identifier: it is
/// bumped when the draft advances, never byte-locked like [`CONIKS_V1`].
pub const KEYTRANS_EXP_V04: DirectoryBackendId = DirectoryBackendId::from_u16(0xF004);

/// A directory's current root: the published value every proof recomputes
/// against. The concrete bytes are defined by the backend (for CONIKS, the
/// 64-byte SHA3-512 prefix-tree root); callers treat them as opaque.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DirectoryRoot(Vec<u8>);

/// An opaque, self-describing directory search proof. The concrete byte
/// encoding is defined by the backend (for CONIKS, the tagged
/// [`crate::coniks::LookupProof`] / [`crate::coniks::AbsenceProof`] bytes, which
/// already carry their own presence/absence discriminator).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SearchProof(Vec<u8>);

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

byte_wrapper!(DirectoryRoot, "root");
byte_wrapper!(SearchProof, "proof");

/// The verified outcome of a directory search: the queried label is either
/// **present** with a value, or **absent**.
///
/// When returned by [`Directory::search`] the value is the operator's own data;
/// when returned by [`DirectoryVerifier::verify_search`] it has been recomputed
/// from the proof against the supplied root and is trustworthy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchOutcome {
    /// The label is present; carries its bound value.
    Present(Vec<u8>),
    /// The label is absent from the directory.
    Absent,
}

/// The result of a [`Directory::search`]: the [`SearchOutcome`] together with
/// the [`SearchProof`] a relying party verifies via
/// [`DirectoryVerifier::verify_search`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResult {
    outcome: SearchOutcome,
    proof: SearchProof,
}

impl SearchResult {
    /// Build a search result from its outcome and proof.
    #[must_use]
    pub fn new(outcome: SearchOutcome, proof: SearchProof) -> Self {
        Self { outcome, proof }
    }

    /// The (operator-side) outcome of the search.
    #[must_use]
    pub fn outcome(&self) -> &SearchOutcome {
        &self.outcome
    }

    /// The proof a relying party verifies against the directory root.
    #[must_use]
    pub fn proof(&self) -> &SearchProof {
        &self.proof
    }

    /// Decompose into the outcome and proof.
    #[must_use]
    pub fn into_parts(self) -> (SearchOutcome, SearchProof) {
        (self.outcome, self.proof)
    }
}

/// A swappable directory backend (the prover/operator side).
///
/// The base trait is the common denominator every backend supports: identify
/// the construction, expose the current root, and answer a label search with a
/// verifiable proof. KEYTRANS-only surface lives as inherent methods / a future
/// `KeytransExt` sub-trait and never pollutes this trait. All methods are
/// byte-oriented and the trait is object-safe, so callers can hold a
/// `Box<dyn Directory>`.
pub trait Directory {
    /// The backend family + version this directory implements. Bound into proof
    /// domain separation in a future format version (see the [module
    /// docs](self)); a runtime discriminator only in this slice.
    fn backend_id(&self) -> DirectoryBackendId;

    /// The current published root the directory's proofs recompute against.
    fn root(&self) -> DirectoryRoot;

    /// Look up `label`, returning its [`SearchOutcome`] and a [`SearchProof`]
    /// against the current [`root`](Directory::root).
    ///
    /// For CONIKS this is presence/absence lookup; for KEYTRANS it is the
    /// greatest-version search.
    ///
    /// # Errors
    /// Backend-specific. The CONIKS backend returns [`crate::Error::Vrf`] if
    /// proving the label's private index fails.
    fn search(&self, label: &[u8]) -> Result<SearchResult>;
}

/// The relying-party side: recompute everything from public inputs and check a
/// [`SearchProof`] against a [`DirectoryRoot`], no directory instance required.
///
/// This mirrors the free [`crate::coniks::verify_lookup`] /
/// [`crate::coniks::verify_absence`] functions; a verifier carries the public
/// inputs those functions need (namespace, VRF public key, VRF construction).
/// Object-safe, so a relying party can hold a `Box<dyn DirectoryVerifier>`.
pub trait DirectoryVerifier {
    /// The backend family + version this verifier checks proofs for. Must match
    /// the [`Directory::backend_id`] that produced the proof.
    fn backend_id(&self) -> DirectoryBackendId;

    /// Verify `proof` for `label` against `root`, returning the recomputed
    /// [`SearchOutcome`].
    ///
    /// # Errors
    /// Backend-specific. The CONIKS backend returns
    /// [`crate::Error::VrfProofInvalid`] if the VRF proof does not verify,
    /// [`crate::Error::ConiksRootMismatch`] if the authentication path does not
    /// recompute `root`, and [`crate::Error::MalformedConiksProof`] /
    /// [`crate::Error::Vrf`] for structurally invalid inputs.
    fn verify_search(
        &self,
        root: &DirectoryRoot,
        label: &[u8],
        proof: &SearchProof,
    ) -> Result<SearchOutcome>;
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn coniks_v1_backend_id_code() {
        assert_eq!(CONIKS_V1.as_u16(), 0x0001);
        assert_eq!(DirectoryBackendId::from_u16(0x0001), CONIKS_V1);
    }

    #[test]
    fn byte_wrappers_round_trip() {
        let root = DirectoryRoot::from_bytes(vec![1, 2, 3]);
        assert_eq!(root.as_bytes(), &[1, 2, 3]);
        assert_eq!(root.into_bytes(), vec![1, 2, 3]);

        let proof = SearchProof::from_bytes(vec![4, 5]);
        assert_eq!(proof.as_bytes(), &[4, 5]);
        assert_eq!(proof.into_bytes(), vec![4, 5]);
    }

    #[test]
    fn search_result_into_parts() {
        let result = SearchResult::new(
            SearchOutcome::Present(b"v".to_vec()),
            SearchProof::from_bytes(vec![0x01]),
        );
        assert_eq!(result.outcome(), &SearchOutcome::Present(b"v".to_vec()));
        let (outcome, proof) = result.into_parts();
        assert_eq!(outcome, SearchOutcome::Present(b"v".to_vec()));
        assert_eq!(proof.as_bytes(), &[0x01]);
    }

    #[test]
    fn directory_traits_are_object_safe() {
        // Compiles only if `Directory` and `DirectoryVerifier` are object-safe —
        // the property a namespace relies on to hold a `Box<dyn Directory>` and a
        // relying party a `Box<dyn DirectoryVerifier>` while swapping backends.
        fn assert_directory_object_safe(_: &dyn Directory) {}
        fn assert_verifier_object_safe(_: &dyn DirectoryVerifier) {}

        let _ = assert_directory_object_safe;
        let _ = assert_verifier_object_safe;
    }
}
