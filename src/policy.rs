//! Layer-0: the per-namespace **`NamespacePolicy`** — a signed, in-log,
//! versioned record that declares a namespace's cryptographic posture, plus the
//! **declared == observed** enforcement that rejects any artifact whose
//! *observed* posture disagrees with the *declared* one (no silent downgrade).
//!
//! ## What this layer is (and is not)
//!
//! Per the project's invariant wall (#290 / #299 / #324), the Layer-1 substrate
//! — the SHA-256 tree-node hash, the canonical leaf byte layout, and the
//! RFC 6962 / RFC 9162 proof protocol — is **fixed and audited** so independent
//! witnesses can recompute every root *without knowing anything about a
//! namespace's suite*. A `NamespacePolicy` never touches those bytes. It lives
//! at the metadata layer the scoping doc (#324) defines as the **only** legal
//! flexibility point: a namespace's selectable post-quantum posture
//! (checkpoint-signature suite/level, commitment-hash strength, VRF privacy
//! mode). A suite-unaware verifier still recomputes every root; suite-awareness
//! only *adds* enforcement of the PQ/privacy artifacts layered around the
//! unchanged canonical bytes.
//!
//! ## The record
//!
//! [`NamespacePolicy`] is itself a canonical, byte-disciplined Layer-0 leaf
//! (mirroring [`crate::leaf`]'s grammar: `u32`-be length prefixes, `u64`-be
//! integers, big-endian, never reordered). Its fields (#324 Q1):
//!
//! - `namespace` — the per-tenant [`crate::coniks::Namespace`] this policy
//!   governs (immutable identity of the directory).
//! - `policy_schema_version` (`u32`) — the version of this record, **also** the
//!   migration sequence number (each migration is `+1`; see [`PolicyChain`]).
//! - `security_level` ([`SecurityLevel`]) — `Cat3` / `Cat5`; a forced explicit
//!   choice (the SDK suggests `Cat5`).
//! - `checkpoint_suite` ([`CheckpointSuite`]) — `Hybrid` (default) /
//!   `HybridMatched` / `PureCnsa2`; the orthogonal CNSA-posture knob (#312).
//! - `commitment_hash` ([`CommitmentHash`]) — `Sha3_256` (Cat-3) / `Sha3_512`
//!   (Cat-5), **derived** from the level under the bundle but stored explicitly
//!   so a future expert/decoupled mode is a non-breaking read.
//! - `vrf_mode` ([`VrfMode`]) — `Classical` (default; the **only** legal value
//!   in v0.1, per #304), with `HybridOutput` / `PurePqExperimental` scoped but
//!   not yet built.
//! - `effective_from` (`u64`) — the tree size / checkpoint index at which this
//!   version takes force (the epoch boundary).
//! - `created_at` (`u64`) — informational Unix-ms timestamp; ordering authority
//!   is `effective_from` + log position, never wall-clock.
//! - `prev_policy_hash` — the 64-byte SHA3-512 [`NamespacePolicy::policy_hash`]
//!   of the prior version, or `None` for the genesis version (the chain link).
//!
//! ## Signed, in-log, versioned
//!
//! A policy is published as a [`SignedPolicy`]: the canonical record bytes
//! signed by the namespace **root signing key** via the same single-source-of-
//! truth composite primitive ([`metamorphic_crypto::sign`] /
//! [`metamorphic_crypto::verify`]) that backs the Slice-3 hybrid checkpoint note
//! line, under the versioned context label `<namespace>/namespace-policy/v1`.
//! The root key is pinned TOFU on first contact (same trust-bootstrap as the
//! #291/#315 signed key-history; the log provides *continuity*, not first-
//! contact trust). Because ML-DSA signing is hedged, the signature **bytes are
//! not reproducible**, but **verification is deterministic** — so the KATs lock
//! the deterministic verifying key and canonical bytes, not signature bytes.
//!
//! ## Immutability + versioned migration
//!
//! A policy is immutable within its version. A change is a **new** version that
//! chains to the prior one via `prev_policy_hash`, with a strictly greater
//! `effective_from` and `policy_schema_version + 1`. [`PolicyChain`] holds the
//! ordered list, validates the chain, and enforces that migrations may only
//! **strengthen** posture (a weakening is [`Error::PolicyMigrationRejected`]).
//! Each version owns the half-open range `[effective_from_n, effective_from_{n+1})`,
//! and [`PolicyChain::active_at`] resolves the policy in force at a tree
//! position (the authority for what a namespace *required* there).
//!
//! ## Declared == observed (the headline)
//!
//! [`NamespacePolicy::enforce_checkpoint_signing_key`] /
//! [`NamespacePolicy::enforce_checkpoint_signature`] map an observed checkpoint
//! hybrid key/signature to its `(Suite, SignatureLevel)` via the v0.8.1
//! [`metamorphic_crypto::signature_posture`] /
//! [`metamorphic_crypto::signature_posture_from_signature`] accessors and
//! compare it to the declared posture; [`NamespacePolicy::enforce_vrf_suite_id`]
//! checks the Slice-4 CONIKS [`crate::vrf::Vrf::suite_id`] (#332); and
//! [`NamespacePolicy::enforce_commitment_hash`] checks the commitment parameter.
//! Any mismatch is [`Error::PostureMismatch`] — a hard rejection. This crate
//! re-derives **no** private crypto wire tags; it only *consumes* the typed,
//! opaque metamorphic-crypto accessors.
//!
//! ## Honest framing
//!
//! This makes a namespace's posture **verifiable**, not stronger. It is a safe
//! menu with safe defaults (classical-default hybrid); customers cannot select
//! free-form or silently-weaker posture, and any downgrade is logged and
//! rejected. The primitives are not FIPS-validated and this project makes no
//! FIPS-validation claim.

use metamorphic_crypto::{SignatureLevel, Suite};

use crate::coniks::Namespace;
use crate::directory::{CONIKS_V1, DirectoryBackendId, KEYTRANS_EXP_V04};
use crate::error::{Error, Result};
use crate::leaf::{ContextLabel, content_hash};
use crate::merkle::{Hash, hash_leaf};

/// The highest canonical byte-layout version of the [`NamespacePolicy`] record
/// this build emits and accepts (the discipline version, distinct from the
/// per-record [`NamespacePolicy::policy_schema_version`]). A layout change is a
/// new value here, never a silent reinterpretation.
///
/// **v1 → v2 (Slice 9e).** v1 records (the only layout through Slice 5–9d)
/// carry the four posture axes (`security_level`, `checkpoint_suite`,
/// `commitment_hash`, `vrf_mode`). v2 *appends* the two Layer-3 directory axes
/// ([`DirectoryMode`] + [`KeytransSuite`]). The layout is **backward
/// compatible**: a policy on the default CONIKS route serializes byte-for-byte
/// as a v1 record (the appended axes are at their defaults and omitted), so
/// every frozen v1 vector still round-trips unchanged; only a policy that
/// selects the experimental [`DirectoryMode::Keytrans`] route emits a v2 record.
/// [`NamespacePolicy::parse`] reads both versions.
pub const POLICY_FORMAT_VERSION: u32 = 2;

/// The original v1 record layout (the four-axis posture record). Still emitted
/// verbatim for CONIKS-route policies so the frozen Slice-5 KATs are unchanged.
const POLICY_FORMAT_VERSION_V1: u32 = 1;

/// The fixed canonical byte-layout version of the [`SignedPolicy`] envelope.
pub const SIGNED_POLICY_FORMAT_VERSION: u32 = 1;

/// Length of a [`NamespacePolicy::policy_hash`] (a SHA3-512 digest), in bytes.
pub const POLICY_HASH_LEN: usize = 64;

/// The bundled NIST security level for a namespace's posture (#324 Q3).
///
/// `Cat3` and `Cat5` are the v0.1 menu; `security_level` is a forced explicit
/// choice at namespace creation (no default). The level selects the ML-DSA
/// parameter set for checkpoint signatures and, under the bundle, the
/// [`CommitmentHash`] strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityLevel {
    /// NIST Category 3 (ML-DSA-65; ~AES-192). Bundles [`CommitmentHash::Sha3_256`].
    Cat3,
    /// NIST Category 5 (ML-DSA-87; ~AES-256). Bundles [`CommitmentHash::Sha3_512`].
    Cat5,
}

impl SecurityLevel {
    const TAG_CAT3: u8 = 0x03;
    const TAG_CAT5: u8 = 0x05;

    fn tag(self) -> u8 {
        match self {
            SecurityLevel::Cat3 => Self::TAG_CAT3,
            SecurityLevel::Cat5 => Self::TAG_CAT5,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            Self::TAG_CAT3 => Ok(SecurityLevel::Cat3),
            Self::TAG_CAT5 => Ok(SecurityLevel::Cat5),
            other => Err(Error::MalformedPolicy(format!(
                "unknown security_level tag 0x{other:02x}"
            ))),
        }
    }

    /// Monotone posture rank (higher is stronger), used by migration checks.
    fn rank(self) -> u8 {
        match self {
            SecurityLevel::Cat3 => 0,
            SecurityLevel::Cat5 => 1,
        }
    }

    /// The metamorphic-crypto [`SignatureLevel`] this level maps to for
    /// declared == observed checkpoint-posture enforcement.
    #[must_use]
    pub fn signature_level(self) -> SignatureLevel {
        match self {
            SecurityLevel::Cat3 => SignatureLevel::Cat3,
            SecurityLevel::Cat5 => SignatureLevel::Cat5,
        }
    }

    /// The [`CommitmentHash`] derived from this level under the v0.1 bundle.
    #[must_use]
    pub fn derived_commitment_hash(self) -> CommitmentHash {
        match self {
            SecurityLevel::Cat3 => CommitmentHash::Sha3_256,
            SecurityLevel::Cat5 => CommitmentHash::Sha3_512,
        }
    }
}

/// The additive PQ **checkpoint-signature suite** a namespace declares (#312 /
/// #324 Q2). Orthogonal to [`SecurityLevel`]: `Hybrid` is the default and
/// strict-AND backstop; `PureCnsa2` is the pure-PQ CNSA-2.0 box (Cat-5 only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckpointSuite {
    /// Default: classical + PQ strict-AND composite (the #312 default).
    Hybrid,
    /// Classical partner matched to the PQ category (Ed448 at Cat-3, P-521 at
    /// Cat-5).
    HybridMatched,
    /// Pure post-quantum, no classical half (CNSA 2.0). Legal only at Cat-5.
    PureCnsa2,
}

impl CheckpointSuite {
    const TAG_HYBRID: u8 = 0x01;
    const TAG_HYBRID_MATCHED: u8 = 0x02;
    const TAG_PURE_CNSA2: u8 = 0x03;

    fn tag(self) -> u8 {
        match self {
            CheckpointSuite::Hybrid => Self::TAG_HYBRID,
            CheckpointSuite::HybridMatched => Self::TAG_HYBRID_MATCHED,
            CheckpointSuite::PureCnsa2 => Self::TAG_PURE_CNSA2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            Self::TAG_HYBRID => Ok(CheckpointSuite::Hybrid),
            Self::TAG_HYBRID_MATCHED => Ok(CheckpointSuite::HybridMatched),
            Self::TAG_PURE_CNSA2 => Ok(CheckpointSuite::PureCnsa2),
            other => Err(Error::MalformedPolicy(format!(
                "unknown checkpoint_suite tag 0x{other:02x}"
            ))),
        }
    }

    /// The metamorphic-crypto [`Suite`] this maps to for declared == observed
    /// checkpoint-posture enforcement.
    #[must_use]
    pub fn crypto_suite(self) -> Suite {
        match self {
            CheckpointSuite::Hybrid => Suite::Hybrid,
            CheckpointSuite::HybridMatched => Suite::HybridMatched,
            CheckpointSuite::PureCnsa2 => Suite::PureCnsa2,
        }
    }
}

/// The Layer-3 **commitment-hash strength** (#324 Q3), derived from
/// [`SecurityLevel`] under the v0.1 bundle but stored explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommitmentHash {
    /// SHA3-256 (Cat-3 bundle).
    Sha3_256,
    /// SHA3-512 (Cat-5 bundle).
    Sha3_512,
}

impl CommitmentHash {
    const TAG_SHA3_256: u8 = 0x01;
    const TAG_SHA3_512: u8 = 0x02;

    fn tag(self) -> u8 {
        match self {
            CommitmentHash::Sha3_256 => Self::TAG_SHA3_256,
            CommitmentHash::Sha3_512 => Self::TAG_SHA3_512,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            Self::TAG_SHA3_256 => Ok(CommitmentHash::Sha3_256),
            Self::TAG_SHA3_512 => Ok(CommitmentHash::Sha3_512),
            other => Err(Error::MalformedPolicy(format!(
                "unknown commitment_hash tag 0x{other:02x}"
            ))),
        }
    }

    fn rank(self) -> u8 {
        match self {
            CommitmentHash::Sha3_256 => 0,
            CommitmentHash::Sha3_512 => 1,
        }
    }
}

/// The Layer-3 **VRF privacy mode** (#324 Q3 / #304). In v0.1 only `Classical`
/// is legal; `HybridOutput` and `PurePqExperimental` are scoped for the future
/// hybrid path but rejected as malformed until that path is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VrfMode {
    /// Classical ECVRF-edwards25519 (RFC 9381 ciphersuite `0x03`); the v0.1
    /// default and only legal value.
    Classical,
    /// Designed-in hybrid output combiner (classical || PQ via SHA3-512). Scoped
    /// but **not** legal in v0.1 (no audited lattice VRF — #304).
    HybridOutput,
    /// Experimental pure-PQ VRF. Scoped but **not** legal in v0.1.
    PurePqExperimental,
}

impl VrfMode {
    const TAG_CLASSICAL: u8 = 0x01;
    const TAG_HYBRID_OUTPUT: u8 = 0x02;
    const TAG_PURE_PQ: u8 = 0x03;

    fn tag(self) -> u8 {
        match self {
            VrfMode::Classical => Self::TAG_CLASSICAL,
            VrfMode::HybridOutput => Self::TAG_HYBRID_OUTPUT,
            VrfMode::PurePqExperimental => Self::TAG_PURE_PQ,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            Self::TAG_CLASSICAL => Ok(VrfMode::Classical),
            Self::TAG_HYBRID_OUTPUT => Ok(VrfMode::HybridOutput),
            Self::TAG_PURE_PQ => Ok(VrfMode::PurePqExperimental),
            other => Err(Error::MalformedPolicy(format!(
                "unknown vrf_mode tag 0x{other:02x}"
            ))),
        }
    }

    fn rank(self) -> u8 {
        match self {
            VrfMode::Classical => 0,
            VrfMode::HybridOutput => 1,
            VrfMode::PurePqExperimental => 2,
        }
    }

    /// The CONIKS [`crate::vrf::Vrf::suite_id`] this mode requires, for
    /// declared == observed VRF enforcement. Returns `None` for modes that have
    /// no built construction in v0.1.
    #[must_use]
    pub fn expected_vrf_suite_id(self) -> Option<u8> {
        match self {
            VrfMode::Classical => Some(metamorphic_crypto::ECVRF_EDWARDS25519_SHA512_TAI_SUITE),
            VrfMode::HybridOutput | VrfMode::PurePqExperimental => None,
        }
    }
}

/// The Layer-3 **directory backend route** a namespace declares (Slice 9e,
/// design §3.3). This is the directory-layer analogue of [`VrfMode`]: a tagged
/// posture axis whose non-default value was *reserved-but-rejected* until the
/// backend was built.
///
/// - [`DirectoryMode::Coniks`] (default) selects the shipped, frozen CONIKS
///   prefix-tree directory ([`crate::coniks`], [`crate::directory::CONIKS_V1`]).
/// - [`DirectoryMode::Keytrans`] selects the experimental IETF KEYTRANS
///   combined-tree directory ([`crate::keytrans`],
///   [`crate::directory::KEYTRANS_EXP_V04`]). As of Slice 9e it is **legal as an
///   experimental, version-tagged route** (no longer rejected at validation),
///   so a namespace can opt into the industry-aligned KEYTRANS construction; the
///   route is only meaningful together with a [`KeytransSuite`].
///
/// The route is recorded so a relying party can enforce **declared == observed**
/// on the backend that actually served a proof (see
/// [`NamespacePolicy::enforce_directory_backend`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DirectoryMode {
    /// Classic CONIKS sparse prefix tree — the default and, through Slice 9d,
    /// the only route. Serializes as a v1 record.
    #[default]
    Coniks,
    /// Experimental IETF KEYTRANS combined tree (`KEYTRANS_EXP_04`). Legal as an
    /// experimental route from Slice 9e; selects a v2 record.
    Keytrans,
}

impl DirectoryMode {
    const TAG_CONIKS: u8 = 0x01;
    const TAG_KEYTRANS: u8 = 0x02;

    fn tag(self) -> u8 {
        match self {
            DirectoryMode::Coniks => Self::TAG_CONIKS,
            DirectoryMode::Keytrans => Self::TAG_KEYTRANS,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            Self::TAG_CONIKS => Ok(DirectoryMode::Coniks),
            Self::TAG_KEYTRANS => Ok(DirectoryMode::Keytrans),
            other => Err(Error::MalformedPolicy(format!(
                "unknown directory_mode tag 0x{other:02x}"
            ))),
        }
    }
}

/// The Layer-3 **KEYTRANS cipher suite** a namespace declares (Slice 9e, design
/// §3.3), only meaningful when [`DirectoryMode::Keytrans`] is the route.
///
/// As of 0.1.4 all three suites are **built and legal** (still
/// `KEYTRANS_EXP_04` / movable — the KEYTRANS wire bytes track the draft and are
/// not byte-frozen like the CONIKS / policy-v1 / key_history_v1 vectors):
///
/// - [`KeytransSuite::MetamorphicHybridExp`] (`0xF000`, default) — the private,
///   experimental hybrid-PQ suite: SHA-256 trees for KEYTRANS interop, the
///   SHA3-512 [`crate::commitment`] (the PQ half), composite hybrid-PQ tree-head
///   signatures, and ECVRF-Ed25519 labels.
/// - [`KeytransSuite::Kt128Sha256P256`] (`0x0001`) — the on-spec IETF standard
///   suite: `HMAC-SHA256(Kc, CommitmentValue)` commitment (§10.6) and
///   ECVRF-P256-SHA256-TAI labels (no truncation).
/// - [`KeytransSuite::Kt128Sha256Ed25519`] (`0x0002`) — the on-spec IETF
///   standard suite: `HMAC-SHA256(Kc, CommitmentValue)` commitment and
///   ECVRF-Ed25519 labels (output truncated to 32 bytes).
///
/// Choosing a standard suite gives the standardized HMAC / curve construction
/// for KEYTRANS conformance; the private suite trades interop for a
/// post-quantum commitment. The classical VRFs provide index privacy only and
/// are not FIPS-validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum KeytransSuite {
    /// `0xF000` — the experimental private hybrid-PQ suite (default).
    #[default]
    MetamorphicHybridExp,
    /// `0x0002` — standard `KT_128_SHA256_Ed25519` (HMAC-SHA256 + ECVRF-Ed25519).
    Kt128Sha256Ed25519,
    /// `0x0001` — standard `KT_128_SHA256_P256` (HMAC-SHA256 + ECVRF-P256).
    Kt128Sha256P256,
}

impl KeytransSuite {
    const ID_METAMORPHIC_HYBRID_EXP: u16 = crate::keytrans::KT_EXP_METAMORPHIC_HYBRID;
    const ID_KT128_SHA256_ED25519: u16 = 0x0002;
    const ID_KT128_SHA256_P256: u16 = 0x0001;

    /// The §15.1 cipher-suite identifier carried on the wire.
    #[must_use]
    pub fn suite_id(self) -> u16 {
        match self {
            KeytransSuite::MetamorphicHybridExp => Self::ID_METAMORPHIC_HYBRID_EXP,
            KeytransSuite::Kt128Sha256Ed25519 => Self::ID_KT128_SHA256_ED25519,
            KeytransSuite::Kt128Sha256P256 => Self::ID_KT128_SHA256_P256,
        }
    }

    fn from_id(id: u16) -> Result<Self> {
        match id {
            Self::ID_METAMORPHIC_HYBRID_EXP => Ok(KeytransSuite::MetamorphicHybridExp),
            Self::ID_KT128_SHA256_ED25519 => Ok(KeytransSuite::Kt128Sha256Ed25519),
            Self::ID_KT128_SHA256_P256 => Ok(KeytransSuite::Kt128Sha256P256),
            other => Err(Error::MalformedPolicy(format!(
                "unknown keytrans_suite id 0x{other:04x}"
            ))),
        }
    }

    /// Whether this suite has a built construction. All three suites are built
    /// as of Slice 9 (0.1.4): the private experimental suite plus the on-spec
    /// IETF standard `KT_128_SHA256_P256` / `KT_128_SHA256_Ed25519` suites. Kept
    /// as an explicit predicate so a *future* reserved identifier can be added
    /// (returning `false`) without touching the validation flow.
    #[must_use]
    pub fn is_built(self) -> bool {
        matches!(
            self,
            KeytransSuite::MetamorphicHybridExp
                | KeytransSuite::Kt128Sha256Ed25519
                | KeytransSuite::Kt128Sha256P256
        )
    }

    /// The directory [`DirectoryBackendId`] this suite is served under, or
    /// `None` for a reserved (not-yet-built) suite. Drives **declared ==
    /// observed** for the directory backend (the suite analogue of
    /// [`CheckpointSuite::crypto_suite`]).
    ///
    /// All built KEYTRANS suites share the combined-tree backend
    /// ([`KEYTRANS_EXP_V04`]); the suite (curve + commitment) is distinguished by
    /// [`KeytransSuite::suite_id`], carried in the policy record and enforced
    /// alongside the backend id.
    #[must_use]
    pub fn backend_id(self) -> Option<DirectoryBackendId> {
        if self.is_built() {
            Some(KEYTRANS_EXP_V04)
        } else {
            None
        }
    }
}

/// The versioned, canonical, signed-in-log per-namespace policy record.
///
/// Construct via [`NamespacePolicy::new`] (which validates well-formedness),
/// serialize via [`NamespacePolicy::canonical_bytes`], and parse via
/// [`NamespacePolicy::parse`]. See the module docs for the field set and the
/// invariant wall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespacePolicy {
    namespace: Namespace,
    policy_schema_version: u32,
    security_level: SecurityLevel,
    checkpoint_suite: CheckpointSuite,
    commitment_hash: CommitmentHash,
    vrf_mode: VrfMode,
    effective_from: u64,
    created_at: u64,
    prev_policy_hash: Option<[u8; POLICY_HASH_LEN]>,
    directory_mode: DirectoryMode,
    keytrans_suite: KeytransSuite,
}

impl NamespacePolicy {
    /// The canonical context-label record type for a namespace policy.
    pub const RECORD_TYPE: &'static str = "namespace-policy";

    /// Build and validate a namespace policy.
    ///
    /// Enforces the v0.1 well-formedness rules: `commitment_hash` must equal the
    /// one derived from `security_level` (the bundle), `vrf_mode` must be
    /// `Classical`, `PureCnsa2` requires Cat-5, and `prev_policy_hash` (if
    /// present) must be exactly 64 bytes. `policy_schema_version` must be `>= 1`.
    ///
    /// # Errors
    /// Returns [`Error::MalformedPolicy`] for any violation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        namespace: Namespace,
        policy_schema_version: u32,
        security_level: SecurityLevel,
        checkpoint_suite: CheckpointSuite,
        commitment_hash: CommitmentHash,
        vrf_mode: VrfMode,
        effective_from: u64,
        created_at: u64,
        prev_policy_hash: Option<[u8; POLICY_HASH_LEN]>,
    ) -> Result<Self> {
        let policy = Self {
            namespace,
            policy_schema_version,
            security_level,
            checkpoint_suite,
            commitment_hash,
            vrf_mode,
            effective_from,
            created_at,
            prev_policy_hash,
            directory_mode: DirectoryMode::Coniks,
            keytrans_suite: KeytransSuite::MetamorphicHybridExp,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Build and validate a namespace policy on the experimental **KEYTRANS**
    /// directory route (Slice 9e). Identical to [`NamespacePolicy::new`] but
    /// selects [`DirectoryMode::Keytrans`] under the given [`KeytransSuite`],
    /// emitting a v2 record.
    ///
    /// The suite must be *built* ([`KeytransSuite::is_built`]); as of 0.1.4 all
    /// defined suites are built, so this rejects only a future reserved
    /// identifier.
    ///
    /// # Errors
    /// Returns [`Error::MalformedPolicy`] for any well-formedness violation
    /// (including a not-yet-built `keytrans_suite`).
    #[allow(clippy::too_many_arguments)]
    pub fn new_keytrans(
        namespace: Namespace,
        policy_schema_version: u32,
        security_level: SecurityLevel,
        checkpoint_suite: CheckpointSuite,
        commitment_hash: CommitmentHash,
        vrf_mode: VrfMode,
        effective_from: u64,
        created_at: u64,
        prev_policy_hash: Option<[u8; POLICY_HASH_LEN]>,
        keytrans_suite: KeytransSuite,
    ) -> Result<Self> {
        let policy = Self {
            namespace,
            policy_schema_version,
            security_level,
            checkpoint_suite,
            commitment_hash,
            vrf_mode,
            effective_from,
            created_at,
            prev_policy_hash,
            directory_mode: DirectoryMode::Keytrans,
            keytrans_suite,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Convenience constructor for the bundled DX surface (#324 Q3): the
    /// `commitment_hash` is derived from `security_level`, `vrf_mode` is
    /// `Classical`, and this is the genesis version (`policy_schema_version = 1`,
    /// `prev_policy_hash = None`).
    ///
    /// # Errors
    /// Returns [`Error::MalformedPolicy`] (e.g. `PureCnsa2` below Cat-5).
    pub fn genesis(
        namespace: Namespace,
        security_level: SecurityLevel,
        checkpoint_suite: CheckpointSuite,
        effective_from: u64,
        created_at: u64,
    ) -> Result<Self> {
        Self::new(
            namespace,
            1,
            security_level,
            checkpoint_suite,
            security_level.derived_commitment_hash(),
            VrfMode::Classical,
            effective_from,
            created_at,
            None,
        )
    }

    fn validate(&self) -> Result<()> {
        if self.policy_schema_version == 0 {
            return Err(Error::MalformedPolicy(
                "policy_schema_version must be >= 1".into(),
            ));
        }
        // v0.1 bundle: commitment_hash is derived from security_level.
        if self.commitment_hash != self.security_level.derived_commitment_hash() {
            return Err(Error::MalformedPolicy(format!(
                "commitment_hash {:?} does not match the one derived from security_level {:?}",
                self.commitment_hash, self.security_level
            )));
        }
        // v0.1: only Classical VRF is legal (no audited lattice VRF — #304).
        if self.vrf_mode != VrfMode::Classical {
            return Err(Error::MalformedPolicy(format!(
                "vrf_mode {:?} is not legal in v0.1 (only Classical)",
                self.vrf_mode
            )));
        }
        // PureCnsa2 is a Cat-5-only box (mirrors metamorphic-crypto).
        if self.checkpoint_suite == CheckpointSuite::PureCnsa2
            && self.security_level != SecurityLevel::Cat5
        {
            return Err(Error::MalformedPolicy(
                "PureCnsa2 checkpoint_suite requires security_level Cat5".into(),
            ));
        }
        if matches!(self.prev_policy_hash.as_ref(), Some(h) if h.len() != POLICY_HASH_LEN) {
            return Err(Error::MalformedPolicy(
                "prev_policy_hash must be 64 bytes".into(),
            ));
        }
        // Layer-3 directory axes (Slice 9e). The KEYTRANS suite is only
        // meaningful on the KEYTRANS route; on the CONIKS route it must be the
        // default so the record serializes as a backward-compatible v1 layout.
        match self.directory_mode {
            DirectoryMode::Coniks => {
                if self.keytrans_suite != KeytransSuite::default() {
                    return Err(Error::MalformedPolicy(format!(
                        "keytrans_suite {:?} is only meaningful on the Keytrans route",
                        self.keytrans_suite
                    )));
                }
            }
            DirectoryMode::Keytrans => {
                // Every KEYTRANS suite is built as of 0.1.4; a future reserved
                // (not-yet-built) identifier would be rejected here, mirroring
                // VrfMode::PurePqExperimental.
                if !self.keytrans_suite.is_built() {
                    return Err(Error::MalformedPolicy(format!(
                        "keytrans_suite {:?} is reserved but not built",
                        self.keytrans_suite
                    )));
                }
            }
        }
        Ok(())
    }

    /// The governed namespace.
    #[must_use]
    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// The record / migration-sequence version.
    #[must_use]
    pub fn policy_schema_version(&self) -> u32 {
        self.policy_schema_version
    }

    /// The declared security level.
    #[must_use]
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// The declared checkpoint-signature suite.
    #[must_use]
    pub fn checkpoint_suite(&self) -> CheckpointSuite {
        self.checkpoint_suite
    }

    /// The declared commitment-hash strength.
    #[must_use]
    pub fn commitment_hash(&self) -> CommitmentHash {
        self.commitment_hash
    }

    /// The declared VRF privacy mode.
    #[must_use]
    pub fn vrf_mode(&self) -> VrfMode {
        self.vrf_mode
    }

    /// The declared Layer-3 directory route (Slice 9e).
    #[must_use]
    pub fn directory_mode(&self) -> DirectoryMode {
        self.directory_mode
    }

    /// The declared KEYTRANS cipher suite (Slice 9e). Only meaningful when
    /// [`directory_mode`](Self::directory_mode) is [`DirectoryMode::Keytrans`];
    /// the default [`KeytransSuite`] otherwise.
    #[must_use]
    pub fn keytrans_suite(&self) -> KeytransSuite {
        self.keytrans_suite
    }

    /// The fixed canonical byte-layout version this policy serializes to: `1`
    /// for the default CONIKS route (a backward-compatible v1 record) and `2`
    /// when the experimental [`DirectoryMode::Keytrans`] route is selected.
    #[must_use]
    fn format_version(&self) -> u32 {
        match self.directory_mode {
            DirectoryMode::Coniks => POLICY_FORMAT_VERSION_V1,
            DirectoryMode::Keytrans => POLICY_FORMAT_VERSION,
        }
    }

    /// The directory [`DirectoryBackendId`] this policy declares it will be
    /// served under: [`crate::directory::CONIKS_V1`] on the CONIKS route, or the
    /// declared [`KeytransSuite`]'s backend id on the KEYTRANS route (`None` if
    /// that suite is reserved/not built).
    #[must_use]
    pub fn declared_directory_backend_id(&self) -> Option<DirectoryBackendId> {
        match self.directory_mode {
            DirectoryMode::Coniks => Some(CONIKS_V1),
            DirectoryMode::Keytrans => self.keytrans_suite.backend_id(),
        }
    }

    /// The tree size / checkpoint index at which this version takes force.
    #[must_use]
    pub fn effective_from(&self) -> u64 {
        self.effective_from
    }

    /// The informational creation timestamp (Unix milliseconds).
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// The 64-byte previous-version hash, or `None` for the genesis version.
    #[must_use]
    pub fn prev_policy_hash(&self) -> Option<&[u8; POLICY_HASH_LEN]> {
        self.prev_policy_hash.as_ref()
    }

    /// The declared `(Suite, SignatureLevel)` checkpoint posture — what an
    /// observed checkpoint signature must match.
    #[must_use]
    pub fn declared_checkpoint_posture(&self) -> (Suite, SignatureLevel) {
        (
            self.checkpoint_suite.crypto_suite(),
            self.security_level.signature_level(),
        )
    }

    /// The canonical context label for this policy, `<namespace>/namespace-policy/v1`.
    ///
    /// # Errors
    /// Propagates [`ContextLabel::parse`] errors (cannot occur for a valid
    /// namespace).
    pub fn context_label(&self) -> Result<ContextLabel> {
        ContextLabel::parse(&format!(
            "{}/{}/v{}",
            self.namespace.as_str(),
            Self::RECORD_TYPE,
            self.format_version()
        ))
    }

    /// Build the canonical, byte-reproducible serialization of this policy.
    ///
    /// ```text
    /// canonical(policy) =
    ///     u32_be(format_version)          // 1 (CONIKS route) or 2 (KEYTRANS route)
    ///  || lp(namespace)
    ///  || u32_be(policy_schema_version)
    ///  || u8(security_level tag)
    ///  || u8(checkpoint_suite tag)
    ///  || u8(commitment_hash tag)
    ///  || u8(vrf_mode tag)
    ///  || u64_be(effective_from)
    ///  || u64_be(created_at)
    ///  || lp(prev_policy_hash)            // 0-length for genesis
    ///  || [ u8(directory_mode tag) || u16_be(keytrans_suite id) ]   // v2 only
    /// ```
    ///
    /// The v2 directory axes are **appended** after the v1 fields, so a
    /// CONIKS-route policy (the default) emits exactly the v1 byte layout and
    /// every frozen Slice-5 vector round-trips unchanged.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let ns = self.namespace.as_str().as_bytes();
        let prev: &[u8] = self.prev_policy_hash.as_ref().map_or(&[], |h| h.as_slice());
        let mut out = Vec::with_capacity(4 + 4 + ns.len() + 4 + 4 + 8 + 8 + 4 + prev.len());
        out.extend_from_slice(&self.format_version().to_be_bytes());
        push_lp(&mut out, ns);
        out.extend_from_slice(&self.policy_schema_version.to_be_bytes());
        out.push(self.security_level.tag());
        out.push(self.checkpoint_suite.tag());
        out.push(self.commitment_hash.tag());
        out.push(self.vrf_mode.tag());
        out.extend_from_slice(&self.effective_from.to_be_bytes());
        out.extend_from_slice(&self.created_at.to_be_bytes());
        push_lp(&mut out, prev);
        if self.directory_mode != DirectoryMode::Coniks {
            out.push(self.directory_mode.tag());
            out.extend_from_slice(&self.keytrans_suite.suite_id().to_be_bytes());
        }
        out
    }

    /// Parse a policy from its canonical bytes, validating the layout, the enum
    /// tags, and the v0.1 well-formedness rules. Accepts both the v1 (CONIKS)
    /// and v2 (KEYTRANS-route) layouts; a v1 record reads as the default
    /// [`DirectoryMode::Coniks`] route.
    ///
    /// # Errors
    /// Returns [`Error::MalformedPolicy`] for an unknown format version, an
    /// unknown enum tag, a length-prefix overrun, trailing bytes, a
    /// `prev_policy_hash` that is present but not 64 bytes, or any rule violation.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut cur = Cursor::new(bytes);
        let format_version = cur.u32()?;
        if format_version != POLICY_FORMAT_VERSION_V1 && format_version != POLICY_FORMAT_VERSION {
            return Err(Error::MalformedPolicy(format!(
                "unknown policy format version {format_version}"
            )));
        }
        let ns_bytes = cur.lp()?;
        let namespace = core::str::from_utf8(ns_bytes)
            .map_err(|_| Error::MalformedPolicy("namespace is not valid UTF-8".into()))
            .and_then(Namespace::parse)?;
        let policy_schema_version = cur.u32()?;
        let security_level = SecurityLevel::from_tag(cur.u8()?)?;
        let checkpoint_suite = CheckpointSuite::from_tag(cur.u8()?)?;
        let commitment_hash = CommitmentHash::from_tag(cur.u8()?)?;
        let vrf_mode = VrfMode::from_tag(cur.u8()?)?;
        let effective_from = cur.u64()?;
        let created_at = cur.u64()?;
        let prev = cur.lp()?;
        let prev_policy_hash = match prev.len() {
            0 => None,
            POLICY_HASH_LEN => {
                let mut h = [0u8; POLICY_HASH_LEN];
                h.copy_from_slice(prev);
                Some(h)
            }
            other => {
                return Err(Error::MalformedPolicy(format!(
                    "prev_policy_hash is {other} bytes, want 0 (genesis) or {POLICY_HASH_LEN}"
                )));
            }
        };
        // v2 appends the Layer-3 directory axes; v1 records default to CONIKS.
        let (directory_mode, keytrans_suite) = if format_version == POLICY_FORMAT_VERSION {
            let directory_mode = DirectoryMode::from_tag(cur.u8()?)?;
            let keytrans_suite = KeytransSuite::from_id(cur.u16()?)?;
            (directory_mode, keytrans_suite)
        } else {
            (DirectoryMode::Coniks, KeytransSuite::default())
        };
        if !cur.is_empty() {
            return Err(Error::MalformedPolicy(
                "trailing bytes after policy record".into(),
            ));
        }

        let policy = Self {
            namespace,
            policy_schema_version,
            security_level,
            checkpoint_suite,
            commitment_hash,
            vrf_mode,
            effective_from,
            created_at,
            prev_policy_hash,
            directory_mode,
            keytrans_suite,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// The intra-chain `policy_hash`: the 64-byte SHA3-512 content hash over the
    /// canonical bytes under the `<namespace>/namespace-policy/v1` label.
    ///
    /// The next version chains to this digest via `prev_policy_hash`. Note this
    /// is computed over the **policy** bytes, not the [`SignedPolicy`] envelope,
    /// so the (hedged, non-reproducible) signature never affects the chain.
    ///
    /// # Errors
    /// Propagates [`NamespacePolicy::context_label`] errors.
    pub fn policy_hash(&self) -> Result<[u8; POLICY_HASH_LEN]> {
        let label = self.context_label()?;
        Ok(content_hash(&label, &self.canonical_bytes()))
    }

    /// The RFC 6962 Merkle leaf hash `SHA-256(0x00 || canonical)` over the raw
    /// canonical policy bytes (the Layer-0 leaf hash; independent of
    /// [`NamespacePolicy::policy_hash`]).
    #[must_use]
    pub fn rfc6962_leaf_hash(&self) -> Hash {
        hash_leaf(&self.canonical_bytes())
    }

    // === Declared == observed enforcement ===

    /// Enforce that an **observed** checkpoint hybrid signing **public key**
    /// matches this policy's declared checkpoint posture.
    ///
    /// The observed posture is read from the key's self-describing tag via the
    /// typed, opaque [`metamorphic_crypto::signature_posture`] accessor (no wire
    /// tags re-derived here); a structurally malformed key surfaces as a
    /// mismatch rather than a panic.
    ///
    /// # Errors
    /// Returns [`Error::PostureMismatch`] if the observed `(Suite,
    /// SignatureLevel)` differs from [`NamespacePolicy::declared_checkpoint_posture`].
    pub fn enforce_checkpoint_signing_key(&self, public_key_b64: &str) -> Result<()> {
        let observed = metamorphic_crypto::signature_posture(public_key_b64).map_err(|e| {
            Error::PostureMismatch {
                declared: posture_str(self.declared_checkpoint_posture()),
                observed: format!("undecodable checkpoint key ({e})"),
            }
        })?;
        self.check_checkpoint_posture(observed)
    }

    /// Enforce that an **observed** checkpoint composite **signature** matches
    /// this policy's declared checkpoint posture (the signature counterpart to
    /// [`NamespacePolicy::enforce_checkpoint_signing_key`], via
    /// [`metamorphic_crypto::signature_posture_from_signature`]).
    ///
    /// # Errors
    /// Returns [`Error::PostureMismatch`] on any disagreement.
    pub fn enforce_checkpoint_signature(&self, signature_b64: &str) -> Result<()> {
        let observed = metamorphic_crypto::signature_posture_from_signature(signature_b64)
            .map_err(|e| Error::PostureMismatch {
                declared: posture_str(self.declared_checkpoint_posture()),
                observed: format!("undecodable checkpoint signature ({e})"),
            })?;
        self.check_checkpoint_posture(observed)
    }

    fn check_checkpoint_posture(&self, observed: (Suite, SignatureLevel)) -> Result<()> {
        let declared = self.declared_checkpoint_posture();
        if observed == declared {
            Ok(())
        } else {
            Err(Error::PostureMismatch {
                declared: posture_str(declared),
                observed: posture_str(observed),
            })
        }
    }

    /// Enforce that an **observed** CONIKS VRF suite id (the Slice-4
    /// [`crate::vrf::Vrf::suite_id`], #332) matches this policy's declared
    /// [`VrfMode`].
    ///
    /// # Errors
    /// Returns [`Error::PostureMismatch`] if the observed suite id differs from
    /// the one the declared mode requires (or if the declared mode has no built
    /// construction in v0.1).
    pub fn enforce_vrf_suite_id(&self, observed_suite_id: u8) -> Result<()> {
        match self.vrf_mode.expected_vrf_suite_id() {
            Some(expected) if expected == observed_suite_id => Ok(()),
            expected => Err(Error::PostureMismatch {
                declared: expected.map_or_else(
                    || format!("vrf_mode {:?} (no built suite)", self.vrf_mode),
                    |e| format!("vrf_mode {:?} (suite_id 0x{e:02x})", self.vrf_mode),
                ),
                observed: format!("vrf suite_id 0x{observed_suite_id:02x}"),
            }),
        }
    }

    /// Enforce that an **observed** commitment-hash parameter matches this
    /// policy's declared [`CommitmentHash`].
    ///
    /// # Errors
    /// Returns [`Error::PostureMismatch`] on disagreement.
    pub fn enforce_commitment_hash(&self, observed: CommitmentHash) -> Result<()> {
        if observed == self.commitment_hash {
            Ok(())
        } else {
            Err(Error::PostureMismatch {
                declared: format!("commitment_hash {:?}", self.commitment_hash),
                observed: format!("commitment_hash {observed:?}"),
            })
        }
    }

    /// Enforce that an **observed** directory backend (the
    /// [`crate::directory::Directory::backend_id`] that actually served a proof)
    /// matches this policy's declared route + suite (Slice 9e).
    ///
    /// A namespace declaring [`DirectoryMode::Keytrans`] under a given
    /// [`KeytransSuite`] must be served by exactly that backend
    /// ([`crate::directory::KEYTRANS_EXP_V04`] for the experimental suite); a
    /// CONIKS-route namespace must be served by
    /// [`crate::directory::CONIKS_V1`]. Any disagreement — including a route that
    /// declares a reserved/not-built suite — is a hard rejection.
    ///
    /// # Errors
    /// Returns [`Error::PostureMismatch`] on any disagreement.
    pub fn enforce_directory_backend(&self, observed: DirectoryBackendId) -> Result<()> {
        match self.declared_directory_backend_id() {
            Some(expected) if expected == observed => Ok(()),
            expected => Err(Error::PostureMismatch {
                declared: expected.map_or_else(
                    || {
                        format!(
                            "directory_mode {:?} / keytrans_suite {:?} (no built backend)",
                            self.directory_mode, self.keytrans_suite
                        )
                    },
                    |e| {
                        format!(
                            "directory_mode {:?} (backend 0x{:04x})",
                            self.directory_mode,
                            e.as_u16()
                        )
                    },
                ),
                observed: format!("directory backend 0x{:04x}", observed.as_u16()),
            }),
        }
    }
}

/// A snapshot of an artifact's **observed** crypto posture, for a single
/// declared == observed check against the active [`NamespacePolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedPosture {
    /// The observed checkpoint `(Suite, SignatureLevel)` (decoded from the
    /// checkpoint key/signature via the metamorphic-crypto accessors).
    pub checkpoint: (Suite, SignatureLevel),
    /// The observed CONIKS [`crate::vrf::Vrf::suite_id`].
    pub vrf_suite_id: u8,
    /// The observed commitment-hash parameter.
    pub commitment_hash: CommitmentHash,
}

impl NamespacePolicy {
    /// Enforce declared == observed across all three posture axes at once
    /// (checkpoint signature, CONIKS VRF suite, commitment hash). Any single
    /// mismatch is a hard rejection.
    ///
    /// # Errors
    /// Returns the first [`Error::PostureMismatch`] encountered.
    pub fn enforce_observed(&self, observed: &ObservedPosture) -> Result<()> {
        self.check_checkpoint_posture(observed.checkpoint)?;
        self.enforce_vrf_suite_id(observed.vrf_suite_id)?;
        self.enforce_commitment_hash(observed.commitment_hash)?;
        Ok(())
    }
}

fn posture_str(p: (Suite, SignatureLevel)) -> String {
    format!("{:?}/{:?}", p.0, p.1)
}

/// A [`NamespacePolicy`] together with the namespace root key's composite
/// signature over its canonical bytes (the signed, in-log artifact).
///
/// The signature is produced by the same single-source-of-truth composite
/// primitive that backs the Slice-3 hybrid checkpoint line, under the versioned
/// context label `<namespace>/namespace-policy/v1`. ML-DSA signing is hedged, so
/// the signature bytes are not reproducible, but verification is deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPolicy {
    policy: NamespacePolicy,
    signing_public_key: Vec<u8>,
    signature: Vec<u8>,
}

impl SignedPolicy {
    /// Sign `policy` with a metamorphic-crypto hybrid composite secret key
    /// (base64), binding the signature to the `<namespace>/namespace-policy/v1`
    /// context.
    ///
    /// # Errors
    /// Returns [`Error::HybridSignature`] if the secret key cannot be
    /// decoded/derived or the composite signature cannot be produced, and
    /// propagates [`NamespacePolicy::context_label`] errors.
    pub fn sign(policy: NamespacePolicy, secret_key_b64: &str) -> Result<Self> {
        let ctx = policy.context_label()?;
        let canonical = policy.canonical_bytes();
        let public_key_b64 = metamorphic_crypto::derive_public_key(secret_key_b64)
            .map_err(|e| Error::HybridSignature(format!("invalid policy signing key: {e}")))?;
        let signing_public_key = metamorphic_crypto::b64::decode(&public_key_b64)
            .map_err(|e| Error::HybridSignature(format!("undecodable policy public key: {e}")))?;
        let sig_b64 = metamorphic_crypto::sign(&canonical, ctx.as_str(), secret_key_b64)
            .map_err(|e| Error::HybridSignature(format!("policy signing failed: {e}")))?;
        let signature = metamorphic_crypto::b64::decode(&sig_b64)
            .map_err(|e| Error::HybridSignature(format!("undecodable policy signature: {e}")))?;
        Ok(Self {
            policy,
            signing_public_key,
            signature,
        })
    }

    /// Build a signed policy from already-produced parts (e.g. parsed from the
    /// log). Does **not** verify the signature; call [`SignedPolicy::verify`].
    #[must_use]
    pub fn from_parts(
        policy: NamespacePolicy,
        signing_public_key: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            policy,
            signing_public_key,
            signature,
        }
    }

    /// The wrapped policy.
    #[must_use]
    pub fn policy(&self) -> &NamespacePolicy {
        &self.policy
    }

    /// The namespace root signing public key (metamorphic-crypto composite
    /// `tag || classical_pk || ml_dsa_pk`).
    #[must_use]
    pub fn signing_public_key(&self) -> &[u8] {
        &self.signing_public_key
    }

    /// The composite signature bytes over the canonical policy.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Verify the policy's own composite signature under the namespace's
    /// `<namespace>/namespace-policy/v1` context. On success returns the verified
    /// [`NamespacePolicy`].
    ///
    /// A relying party should additionally check that `signing_public_key`
    /// matches the TOFU-pinned namespace root key (this is the application's
    /// first-contact trust decision, not this library's).
    ///
    /// # Errors
    /// Returns [`Error::InvalidSignature`] if the signature does not verify, and
    /// propagates [`NamespacePolicy::context_label`] errors. A structurally
    /// malformed key/signature is treated as a verification failure, never a
    /// panic.
    pub fn verify(&self) -> Result<&NamespacePolicy> {
        let ctx = self.policy.context_label()?;
        let canonical = self.policy.canonical_bytes();
        let sig_b64 = metamorphic_crypto::b64::encode(&self.signature);
        let pk_b64 = metamorphic_crypto::b64::encode(&self.signing_public_key);
        let ok = metamorphic_crypto::verify(&canonical, ctx.as_str(), &sig_b64, &pk_b64)
            .unwrap_or(false);
        if ok {
            Ok(&self.policy)
        } else {
            Err(Error::InvalidSignature {
                name: format!("{}/namespace-policy", self.policy.namespace.as_str()),
                key_id: 0,
            })
        }
    }

    /// Build the canonical serialization of the signed envelope:
    ///
    /// ```text
    /// signed_canonical =
    ///     u32_be(SIGNED_POLICY_FORMAT_VERSION = 1)
    ///  || lp(policy_canonical_bytes)
    ///  || lp(signing_public_key)
    ///  || lp(signature)
    /// ```
    ///
    /// This is the Layer-0 leaf placed in the log.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let policy = self.policy.canonical_bytes();
        let mut out = Vec::with_capacity(
            4 + 12 + policy.len() + self.signing_public_key.len() + self.signature.len(),
        );
        out.extend_from_slice(&SIGNED_POLICY_FORMAT_VERSION.to_be_bytes());
        push_lp(&mut out, &policy);
        push_lp(&mut out, &self.signing_public_key);
        push_lp(&mut out, &self.signature);
        out
    }

    /// Parse a signed envelope from its canonical bytes (does **not** verify the
    /// signature; call [`SignedPolicy::verify`]).
    ///
    /// # Errors
    /// Returns [`Error::MalformedPolicy`] for an unknown format version, a
    /// length-prefix overrun, an empty key/signature, or trailing bytes; and
    /// propagates [`NamespacePolicy::parse`] errors.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut cur = Cursor::new(bytes);
        let format_version = cur.u32()?;
        if format_version != SIGNED_POLICY_FORMAT_VERSION {
            return Err(Error::MalformedPolicy(format!(
                "unknown signed-policy format version {format_version}"
            )));
        }
        let policy = NamespacePolicy::parse(cur.lp()?)?;
        let signing_public_key = cur.lp()?.to_vec();
        let signature = cur.lp()?.to_vec();
        if signing_public_key.is_empty() || signature.is_empty() {
            return Err(Error::MalformedPolicy(
                "signed policy must carry a non-empty key and signature".into(),
            ));
        }
        if !cur.is_empty() {
            return Err(Error::MalformedPolicy(
                "trailing bytes after signed policy envelope".into(),
            ));
        }
        Ok(Self {
            policy,
            signing_public_key,
            signature,
        })
    }
}

/// An ordered, validated list of [`NamespacePolicy`] versions for one namespace.
///
/// The chain enforces immutability-by-versioning and only-legal-strengthening
/// migration (see [`PolicyChain::push`]). Each version `n` owns the half-open
/// validity range `[effective_from_n, effective_from_{n+1})`;
/// [`PolicyChain::active_at`] resolves the policy in force at a tree position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyChain {
    versions: Vec<NamespacePolicy>,
}

impl PolicyChain {
    /// Start a chain from a genesis policy.
    ///
    /// # Errors
    /// Returns [`Error::PolicyMigrationRejected`] if the policy is not a valid
    /// genesis (it must have `prev_policy_hash == None`).
    pub fn genesis(policy: NamespacePolicy) -> Result<Self> {
        if policy.prev_policy_hash.is_some() {
            return Err(Error::PolicyMigrationRejected(
                "genesis policy must not carry a prev_policy_hash".into(),
            ));
        }
        Ok(Self {
            versions: vec![policy],
        })
    }

    /// The ordered policy versions.
    #[must_use]
    pub fn versions(&self) -> &[NamespacePolicy] {
        &self.versions
    }

    /// The most recent (currently active) policy version.
    #[must_use]
    pub fn latest(&self) -> &NamespacePolicy {
        self.versions
            .last()
            .expect("a PolicyChain always has at least the genesis version")
    }

    /// Append a migration to the chain, enforcing the #324 rules:
    ///
    /// - same `namespace`;
    /// - `policy_schema_version` is exactly `prev + 1`;
    /// - `effective_from` is strictly greater than the prior version's;
    /// - `prev_policy_hash` equals the prior version's [`NamespacePolicy::policy_hash`];
    /// - the migration does not **weaken** posture (security level, commitment
    ///   hash, or VRF mode may only stay the same or strengthen).
    ///
    /// # Errors
    /// Returns [`Error::PolicyMigrationRejected`] for any rule violation.
    pub fn push(&mut self, next: NamespacePolicy) -> Result<()> {
        let prev = self.latest();

        if next.namespace != prev.namespace {
            return Err(Error::PolicyMigrationRejected(format!(
                "namespace changed from {:?} to {:?}",
                prev.namespace.as_str(),
                next.namespace.as_str()
            )));
        }
        if next.policy_schema_version != prev.policy_schema_version + 1 {
            return Err(Error::PolicyMigrationRejected(format!(
                "policy_schema_version must increment by 1 ({} -> {}), got {}",
                prev.policy_schema_version,
                prev.policy_schema_version + 1,
                next.policy_schema_version
            )));
        }
        if next.effective_from <= prev.effective_from {
            return Err(Error::PolicyMigrationRejected(format!(
                "effective_from must strictly increase ({} -> {})",
                prev.effective_from, next.effective_from
            )));
        }
        let expected_prev = prev.policy_hash()?;
        match next.prev_policy_hash {
            Some(h) if h == expected_prev => {}
            Some(_) => {
                return Err(Error::PolicyMigrationRejected(
                    "prev_policy_hash does not chain to the prior version".into(),
                ));
            }
            None => {
                return Err(Error::PolicyMigrationRejected(
                    "migration must carry a prev_policy_hash".into(),
                ));
            }
        }
        if next.security_level.rank() < prev.security_level.rank()
            || next.commitment_hash.rank() < prev.commitment_hash.rank()
            || next.vrf_mode.rank() < prev.vrf_mode.rank()
        {
            return Err(Error::PolicyMigrationRejected(format!(
                "migration would weaken posture (prev {:?}/{:?}/{:?} -> next {:?}/{:?}/{:?})",
                prev.security_level,
                prev.commitment_hash,
                prev.vrf_mode,
                next.security_level,
                next.commitment_hash,
                next.vrf_mode
            )));
        }

        self.versions.push(next);
        Ok(())
    }

    /// Resolve the policy version in force at tree `position`: the version whose
    /// half-open range `[effective_from_n, effective_from_{n+1})` contains it.
    ///
    /// # Errors
    /// Returns [`Error::UnknownNamespacePolicy`] if `position` precedes the
    /// genesis `effective_from` (no version was yet in force).
    pub fn active_at(&self, position: u64) -> Result<&NamespacePolicy> {
        if position < self.versions[0].effective_from {
            return Err(Error::UnknownNamespacePolicy(format!(
                "tree position {position} precedes the genesis effective_from {}",
                self.versions[0].effective_from
            )));
        }
        // Versions are stored in strictly increasing effective_from order, so
        // the last one whose effective_from <= position is in force.
        let active = self
            .versions
            .iter()
            .rev()
            .find(|p| p.effective_from <= position)
            .expect("position >= genesis effective_from guarantees a match");
        Ok(active)
    }
}

// === Length-prefix discipline (mirrors `crate::leaf`) ===

/// Append `lp(bytes) = u32_be(len(bytes)) || bytes` to `out`.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A minimal big-endian, length-prefix-aware reader over a canonical byte buffer.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| {
                Error::MalformedPolicy(format!(
                    "field of {n} bytes overruns the {}-byte buffer at offset {}",
                    self.buf.len(),
                    self.pos
                ))
            })?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn lp(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn ns() -> Namespace {
        Namespace::parse("acme").unwrap()
    }

    fn cat5_pure() -> NamespacePolicy {
        NamespacePolicy::genesis(
            ns(),
            SecurityLevel::Cat5,
            CheckpointSuite::PureCnsa2,
            0,
            1_700_000,
        )
        .unwrap()
    }

    #[test]
    fn genesis_derives_commitment_hash_and_classical_vrf() {
        let p = NamespacePolicy::genesis(ns(), SecurityLevel::Cat3, CheckpointSuite::Hybrid, 0, 0)
            .unwrap();
        assert_eq!(p.commitment_hash(), CommitmentHash::Sha3_256);
        assert_eq!(p.vrf_mode(), VrfMode::Classical);
        assert_eq!(p.policy_schema_version(), 1);
        assert!(p.prev_policy_hash().is_none());

        let p5 = cat5_pure();
        assert_eq!(p5.commitment_hash(), CommitmentHash::Sha3_512);
    }

    #[test]
    fn canonical_round_trips_byte_for_byte() {
        let p = cat5_pure();
        let bytes = p.canonical_bytes();
        let parsed = NamespacePolicy::parse(&bytes).unwrap();
        assert_eq!(parsed, p);
        assert_eq!(parsed.canonical_bytes(), bytes);
    }

    #[test]
    fn parse_rejects_malformed() {
        // Truncated.
        assert!(matches!(
            NamespacePolicy::parse(&[0, 0, 0, 1]),
            Err(Error::MalformedPolicy(_))
        ));
        // Trailing bytes.
        let mut b = cat5_pure().canonical_bytes();
        b.push(0xff);
        assert!(matches!(
            NamespacePolicy::parse(&b),
            Err(Error::MalformedPolicy(_))
        ));
    }

    #[test]
    fn rejects_commitment_hash_not_matching_level() {
        let r = NamespacePolicy::new(
            ns(),
            1,
            SecurityLevel::Cat5,
            CheckpointSuite::Hybrid,
            CommitmentHash::Sha3_256, // wrong: Cat5 derives Sha3_512
            VrfMode::Classical,
            0,
            0,
            None,
        );
        assert!(matches!(r, Err(Error::MalformedPolicy(_))));
    }

    #[test]
    fn rejects_non_classical_vrf_and_purecnsa2_below_cat5() {
        assert!(matches!(
            NamespacePolicy::new(
                ns(),
                1,
                SecurityLevel::Cat5,
                CheckpointSuite::Hybrid,
                CommitmentHash::Sha3_512,
                VrfMode::HybridOutput,
                0,
                0,
                None,
            ),
            Err(Error::MalformedPolicy(_))
        ));
        assert!(matches!(
            NamespacePolicy::genesis(ns(), SecurityLevel::Cat3, CheckpointSuite::PureCnsa2, 0, 0),
            Err(Error::MalformedPolicy(_))
        ));
    }

    #[test]
    fn policy_hash_is_stable_and_context_bound() {
        let p = cat5_pure();
        assert_eq!(p.policy_hash().unwrap(), p.policy_hash().unwrap());
        // Different namespace => different hash (context separation).
        let other = NamespacePolicy::genesis(
            Namespace::parse("other").unwrap(),
            SecurityLevel::Cat5,
            CheckpointSuite::PureCnsa2,
            0,
            1_700_000,
        )
        .unwrap();
        assert_ne!(p.policy_hash().unwrap(), other.policy_hash().unwrap());
    }

    #[test]
    fn enforce_vrf_suite_id_classical() {
        let p = cat5_pure();
        assert!(p.enforce_vrf_suite_id(0x03).is_ok());
        assert!(matches!(
            p.enforce_vrf_suite_id(0x04),
            Err(Error::PostureMismatch { .. })
        ));
    }

    #[test]
    fn enforce_commitment_hash() {
        let p = cat5_pure();
        assert!(p.enforce_commitment_hash(CommitmentHash::Sha3_512).is_ok());
        assert!(matches!(
            p.enforce_commitment_hash(CommitmentHash::Sha3_256),
            Err(Error::PostureMismatch { .. })
        ));
    }

    #[test]
    fn migration_strengthen_ok_weaken_rejected() {
        let g = NamespacePolicy::genesis(ns(), SecurityLevel::Cat3, CheckpointSuite::Hybrid, 0, 0)
            .unwrap();
        let mut chain = PolicyChain::genesis(g.clone()).unwrap();

        // Strengthen Cat3 -> Cat5 (commitment hash bundles up too).
        let v2 = NamespacePolicy::new(
            ns(),
            2,
            SecurityLevel::Cat5,
            CheckpointSuite::Hybrid,
            CommitmentHash::Sha3_512,
            VrfMode::Classical,
            100,
            1,
            Some(g.policy_hash().unwrap()),
        )
        .unwrap();
        chain.push(v2.clone()).unwrap();
        assert_eq!(chain.versions().len(), 2);

        // Weaken Cat5 -> Cat3 is rejected.
        let weak = NamespacePolicy::new(
            ns(),
            3,
            SecurityLevel::Cat3,
            CheckpointSuite::Hybrid,
            CommitmentHash::Sha3_256,
            VrfMode::Classical,
            200,
            2,
            Some(v2.policy_hash().unwrap()),
        )
        .unwrap();
        assert!(matches!(
            chain.push(weak),
            Err(Error::PolicyMigrationRejected(_))
        ));
    }

    #[test]
    fn migration_rejects_bad_chain_links() {
        let g = NamespacePolicy::genesis(ns(), SecurityLevel::Cat3, CheckpointSuite::Hybrid, 0, 0)
            .unwrap();
        let mut chain = PolicyChain::genesis(g.clone()).unwrap();

        // Wrong prev hash.
        let bad_prev = NamespacePolicy::new(
            ns(),
            2,
            SecurityLevel::Cat3,
            CheckpointSuite::Hybrid,
            CommitmentHash::Sha3_256,
            VrfMode::Classical,
            10,
            1,
            Some([0u8; POLICY_HASH_LEN]),
        )
        .unwrap();
        assert!(matches!(
            chain.push(bad_prev),
            Err(Error::PolicyMigrationRejected(_))
        ));

        // Non-incrementing version.
        let bad_ver = NamespacePolicy::new(
            ns(),
            3,
            SecurityLevel::Cat3,
            CheckpointSuite::Hybrid,
            CommitmentHash::Sha3_256,
            VrfMode::Classical,
            10,
            1,
            Some(g.policy_hash().unwrap()),
        )
        .unwrap();
        assert!(matches!(
            chain.push(bad_ver),
            Err(Error::PolicyMigrationRejected(_))
        ));
    }

    #[test]
    fn active_at_resolves_half_open_ranges() {
        let g = NamespacePolicy::genesis(ns(), SecurityLevel::Cat3, CheckpointSuite::Hybrid, 5, 0)
            .unwrap();
        let mut chain = PolicyChain::genesis(g.clone()).unwrap();
        let v2 = NamespacePolicy::new(
            ns(),
            2,
            SecurityLevel::Cat5,
            CheckpointSuite::Hybrid,
            CommitmentHash::Sha3_512,
            VrfMode::Classical,
            10,
            1,
            Some(g.policy_hash().unwrap()),
        )
        .unwrap();
        chain.push(v2).unwrap();

        assert!(matches!(
            chain.active_at(4),
            Err(Error::UnknownNamespacePolicy(_))
        ));
        assert_eq!(chain.active_at(5).unwrap().policy_schema_version(), 1);
        assert_eq!(chain.active_at(9).unwrap().policy_schema_version(), 1);
        assert_eq!(chain.active_at(10).unwrap().policy_schema_version(), 2);
        assert_eq!(chain.active_at(1000).unwrap().policy_schema_version(), 2);
    }

    // === Slice 9e: directory axes (DirectoryMode + KeytransSuite) ===

    use crate::directory::{CONIKS_V1, KEYTRANS_EXP_V04};

    fn keytrans_policy(suite: KeytransSuite) -> Result<NamespacePolicy> {
        NamespacePolicy::new_keytrans(
            ns(),
            1,
            SecurityLevel::Cat5,
            CheckpointSuite::Hybrid,
            CommitmentHash::Sha3_512,
            VrfMode::Classical,
            0,
            1_700_000,
            None,
            suite,
        )
    }

    #[test]
    fn coniks_default_serializes_as_v1_unchanged() {
        // The default route is CONIKS, which must emit a v1 record (format
        // version 1, no appended directory axes) — the backward-compat wall.
        let p = NamespacePolicy::genesis(ns(), SecurityLevel::Cat3, CheckpointSuite::Hybrid, 0, 0)
            .unwrap();
        assert_eq!(p.directory_mode(), DirectoryMode::Coniks);
        let bytes = p.canonical_bytes();
        assert_eq!(&bytes[..4], &1u32.to_be_bytes());
        // Round-trips, and the format byte stays 1.
        let parsed = NamespacePolicy::parse(&bytes).unwrap();
        assert_eq!(parsed, p);
        assert_eq!(parsed.directory_mode(), DirectoryMode::Coniks);
        assert_eq!(parsed.declared_directory_backend_id(), Some(CONIKS_V1));
    }

    #[test]
    fn keytrans_route_round_trips_as_v2() {
        let p = keytrans_policy(KeytransSuite::MetamorphicHybridExp).unwrap();
        let bytes = p.canonical_bytes();
        assert_eq!(&bytes[..4], &2u32.to_be_bytes());
        let parsed = NamespacePolicy::parse(&bytes).unwrap();
        assert_eq!(parsed, p);
        assert_eq!(parsed.directory_mode(), DirectoryMode::Keytrans);
        assert_eq!(parsed.keytrans_suite(), KeytransSuite::MetamorphicHybridExp);
        assert_eq!(parsed.canonical_bytes(), bytes);
        assert_eq!(
            parsed.declared_directory_backend_id(),
            Some(KEYTRANS_EXP_V04)
        );
    }

    #[test]
    fn keytrans_standard_suites_are_legal() {
        // As of 0.1.4 the on-spec IETF standard suites are built and legal on
        // the KEYTRANS route (they were reserved-but-rejected through 0.1.3).
        for suite in [
            KeytransSuite::Kt128Sha256Ed25519,
            KeytransSuite::Kt128Sha256P256,
        ] {
            let p = keytrans_policy(suite).unwrap();
            assert_eq!(p.keytrans_suite(), suite);
            assert!(suite.is_built());
            // All KEYTRANS suites are served under the combined-tree backend.
            assert_eq!(p.declared_directory_backend_id(), Some(KEYTRANS_EXP_V04));
            // A v2 record carrying a standard suite round-trips byte-for-byte.
            let bytes = p.canonical_bytes();
            assert_eq!(&bytes[..4], &2u32.to_be_bytes());
            let parsed = NamespacePolicy::parse(&bytes).unwrap();
            assert_eq!(parsed, p);
            assert_eq!(parsed.keytrans_suite(), suite);
        }
    }

    #[test]
    fn keytrans_suite_ids_match_spec() {
        // §15.1 wire identifiers.
        assert_eq!(KeytransSuite::Kt128Sha256P256.suite_id(), 0x0001);
        assert_eq!(KeytransSuite::Kt128Sha256Ed25519.suite_id(), 0x0002);
        assert_eq!(
            KeytransSuite::MetamorphicHybridExp.suite_id(),
            crate::keytrans::KT_EXP_METAMORPHIC_HYBRID
        );
    }

    #[test]
    fn enforce_directory_backend_declared_equals_observed() {
        let coniks =
            NamespacePolicy::genesis(ns(), SecurityLevel::Cat3, CheckpointSuite::Hybrid, 0, 0)
                .unwrap();
        assert!(coniks.enforce_directory_backend(CONIKS_V1).is_ok());
        assert!(matches!(
            coniks.enforce_directory_backend(KEYTRANS_EXP_V04),
            Err(Error::PostureMismatch { .. })
        ));

        let keytrans = keytrans_policy(KeytransSuite::MetamorphicHybridExp).unwrap();
        assert!(keytrans.enforce_directory_backend(KEYTRANS_EXP_V04).is_ok());
        assert!(matches!(
            keytrans.enforce_directory_backend(CONIKS_V1),
            Err(Error::PostureMismatch { .. })
        ));
    }

    #[test]
    fn v1_parse_defaults_to_coniks_route() {
        // A hand-built v1 record (no appended axes) reads as the CONIKS route.
        let p =
            NamespacePolicy::genesis(ns(), SecurityLevel::Cat5, CheckpointSuite::PureCnsa2, 0, 0)
                .unwrap();
        let v1 = p.canonical_bytes();
        let parsed = NamespacePolicy::parse(&v1).unwrap();
        assert_eq!(parsed.directory_mode(), DirectoryMode::Coniks);
        assert_eq!(parsed.keytrans_suite(), KeytransSuite::default());
    }

    #[test]
    fn keytrans_route_migrates_and_chains() {
        // A KEYTRANS-route policy participates in the version chain exactly like
        // a CONIKS one (the new axes are carried through migration).
        let g = keytrans_policy(KeytransSuite::MetamorphicHybridExp).unwrap();
        let mut chain = PolicyChain::genesis(g.clone()).unwrap();
        let v2 = NamespacePolicy::new_keytrans(
            ns(),
            2,
            SecurityLevel::Cat5,
            CheckpointSuite::Hybrid,
            CommitmentHash::Sha3_512,
            VrfMode::Classical,
            100,
            1,
            Some(g.policy_hash().unwrap()),
            KeytransSuite::MetamorphicHybridExp,
        )
        .unwrap();
        chain.push(v2).unwrap();
        assert_eq!(chain.latest().directory_mode(), DirectoryMode::Keytrans);
    }
}
