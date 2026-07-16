//! Native **verification** SDK via UniFFI (Swift / Kotlin / Python), opt-in
//! behind the `uniffi` cargo feature.
//!
//! This module is the *native FFI personality* of the crate: a thin, logic-free
//! shell over the rlib core, exactly analogous to [`crate::wasm`]. Every export
//! marshals its arguments and delegates straight to [`crate::proof`],
//! [`crate::checkpoint`], [`crate::note`], [`crate::coniks`],
//! [`crate::commitment`], [`crate::policy`], and [`crate::keytrans`]. It
//! performs **no** Merkle, signature, VRF, commitment, or policy logic of its
//! own — so the verifications it runs are byte-for-byte identical to the native
//! crate and the WASM SDK (locked by the same cross-language KAT vectors).
//!
//! ## Verification-only
//!
//! Unlike the WASM SDK, the native SDK deliberately exposes **no** signing /
//! producer surface: no note/checkpoint signing, no verifier-key encoding, no
//! policy signing. No secret key material ever crosses this boundary — only
//! public verifier keys, roots, and proofs. Constant-time and crypto paths stay
//! entirely in the audited [`metamorphic_crypto`] core.
//!
//! ## Conventions (idiomatic native, contrast with the base64-string WASM SDK)
//!
//! - Binary values (Merkle hashes, roots, proofs, identities, commitments,
//!   openings, canonical bytes) cross as raw **`Vec<u8>`** — mapped to Swift
//!   `Data`, Kotlin `ByteArray`, Python `bytes`. Merkle hashes are 32 bytes,
//!   SHA3-512 digests / CONIKS roots are 64 bytes.
//! - C2SP `checkpoint` / `signed-note` bodies, `VerifierKey`s, namespaces, and
//!   context labels cross as their canonical **UTF-8 `String`** form.
//! - Opaque, self-describing metamorphic-crypto **encoded** public keys and
//!   signatures (used by declared==observed policy enforcement) cross as their
//!   canonical **base64 `String`** token — they are decoded by the crypto core,
//!   not this crate.
//! - Verification predicates return `()` on success (throw the typed
//!   [`VerifyError`] on any failure); lookups return the proven value.

use crate::checkpoint::Checkpoint;
use crate::commitment::{Commitment, Opening};
use crate::coniks::{AbsenceProof, LookupProof, Namespace};
use crate::directory::{DirectoryBackendId, SearchOutcome};
use crate::keytrans::{KeytransVerifier, KtSuite};
use crate::leaf::ContextLabel;
use crate::leaf::key_history_v1::Entry;
use crate::note::{SignedNote, VerifierKey};
use crate::policy::{
    CheckpointSuite as CoreCheckpointSuite, CommitmentHash as CoreCommitmentHash,
    DirectoryMode as CoreDirectoryMode, KeytransSuite as CoreKeytransSuite, NamespacePolicy,
    SecurityLevel as CoreSecurityLevel, SignedPolicy, VrfMode as CoreVrfMode,
};
use crate::proof;
use crate::vrf::{Ecvrf, VrfPublicKey};

// ---------------------------------------------------------------------------
// FFI-owned boundary error (single, flat, message-carrying). Maps from the
// crate's rich `#[non_exhaustive]` `Error` without leaking internal variants.
// ---------------------------------------------------------------------------

/// A verification failure surfaced across the FFI boundary.
///
/// Carries the human-readable message of the underlying typed [`crate::Error`]
/// (tamper, forgery, posture mismatch, malformed input, or a decode error).
/// Kept flat and owned by the FFI layer so the boundary is stable and the
/// crate's internal `#[non_exhaustive]` error enum can evolve freely.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum VerifyError {
    /// The verification failed; `0` is the underlying reason.
    #[error("{0}")]
    Verification(String),
}

impl From<crate::Error> for VerifyError {
    fn from(e: crate::Error) -> Self {
        VerifyError::Verification(e.to_string())
    }
}

type FfiResult<T> = core::result::Result<T, VerifyError>;

// ---------------------------------------------------------------------------
// FFI-owned boundary records / enums (no internal types leak).
// ---------------------------------------------------------------------------

/// A verified checkpoint head — the trustworthy `{ origin, size, root,
/// extensions }` of a C2SP signed checkpoint note.
#[derive(uniffi::Record)]
pub struct CheckpointHead {
    /// The log origin (identity) line.
    pub origin: String,
    /// The tree size (number of leaves).
    pub size: u64,
    /// The 32-byte RFC 6962 root hash at `size`.
    pub root: Vec<u8>,
    /// Any C2SP extension lines, in order.
    pub extensions: Vec<String>,
}

impl From<&Checkpoint> for CheckpointHead {
    fn from(cp: &Checkpoint) -> Self {
        CheckpointHead {
            origin: cp.origin().to_string(),
            size: cp.size(),
            root: cp.root_hash().to_vec(),
            extensions: cp.extensions().to_vec(),
        }
    }
}

/// The outcome of a KEYTRANS search / fixed-version verification: whether the
/// label is present and, if so, its bound value.
#[derive(uniffi::Record)]
pub struct SearchResult {
    /// `true` if the label is present in the directory.
    pub present: bool,
    /// The bound value when `present`, otherwise `None`.
    pub value: Option<Vec<u8>>,
}

impl From<&SearchOutcome> for SearchResult {
    fn from(outcome: &SearchOutcome) -> Self {
        match outcome {
            SearchOutcome::Present(value) => SearchResult {
                present: true,
                value: Some(value.clone()),
            },
            SearchOutcome::Absent => SearchResult {
                present: false,
                value: None,
            },
        }
    }
}

/// NIST-style security category a namespace declares.
#[derive(uniffi::Enum)]
pub enum SecurityLevel {
    /// Category 3.
    Cat3,
    /// Category 5.
    Cat5,
}

/// The checkpoint-signing posture a namespace declares.
#[derive(uniffi::Enum)]
pub enum CheckpointSuite {
    /// Additive hybrid (classical + PQ).
    Hybrid,
    /// Hybrid with matched security levels.
    HybridMatched,
    /// Pure CNSA 2.0 (PQ-only).
    PureCnsa2,
}

/// The commitment hash parameter a namespace declares.
#[derive(uniffi::Enum)]
pub enum CommitmentHash {
    /// SHA3-256.
    Sha3_256,
    /// SHA3-512.
    Sha3_512,
}

/// The CONIKS VRF mode a namespace declares.
#[derive(uniffi::Enum)]
pub enum VrfMode {
    /// Classical ECVRF-Ed25519.
    Classical,
    /// Hybrid VRF output.
    HybridOutput,
    /// Experimental pure-PQ VRF.
    PurePqExperimental,
}

/// The directory backend a namespace declares.
#[derive(uniffi::Enum)]
pub enum DirectoryMode {
    /// CONIKS prefix-tree directory.
    Coniks,
    /// Experimental KEYTRANS combined-tree directory.
    Keytrans,
}

/// The KEYTRANS suite a namespace declares (meaningful only in
/// [`DirectoryMode::Keytrans`]).
#[derive(uniffi::Enum)]
pub enum KeytransSuite {
    /// Experimental Metamorphic hybrid suite.
    MetamorphicHybridExp,
    /// On-spec `KT_128_SHA256_Ed25519`.
    Kt128Sha256Ed25519,
    /// On-spec `KT_128_SHA256_P256`.
    Kt128Sha256P256,
}

/// The verified declared posture of a namespace policy.
#[derive(uniffi::Record)]
pub struct PolicyPosture {
    /// The namespace this policy governs.
    pub namespace: String,
    /// The policy schema version.
    pub policy_schema_version: u32,
    /// The declared security level.
    pub security_level: SecurityLevel,
    /// The declared checkpoint-signing suite.
    pub checkpoint_suite: CheckpointSuite,
    /// The declared commitment hash parameter.
    pub commitment_hash: CommitmentHash,
    /// The declared VRF mode.
    pub vrf_mode: VrfMode,
    /// The declared directory backend.
    pub directory_mode: DirectoryMode,
    /// The declared KEYTRANS suite.
    pub keytrans_suite: KeytransSuite,
    /// Tree position from which this version takes effect.
    pub effective_from: u64,
    /// Creation timestamp (unix ms).
    pub created_at: u64,
    /// The 64-byte canonical policy hash.
    pub policy_hash: Vec<u8>,
    /// The 32-byte RFC 6962 leaf hash of this policy record.
    pub rfc6962_leaf_hash: Vec<u8>,
}

impl From<&NamespacePolicy> for PolicyPosture {
    fn from(policy: &NamespacePolicy) -> Self {
        PolicyPosture {
            namespace: policy.namespace().as_str().to_string(),
            policy_schema_version: policy.policy_schema_version(),
            security_level: match policy.security_level() {
                CoreSecurityLevel::Cat3 => SecurityLevel::Cat3,
                CoreSecurityLevel::Cat5 => SecurityLevel::Cat5,
            },
            checkpoint_suite: match policy.checkpoint_suite() {
                CoreCheckpointSuite::Hybrid => CheckpointSuite::Hybrid,
                CoreCheckpointSuite::HybridMatched => CheckpointSuite::HybridMatched,
                CoreCheckpointSuite::PureCnsa2 => CheckpointSuite::PureCnsa2,
            },
            commitment_hash: match policy.commitment_hash() {
                CoreCommitmentHash::Sha3_256 => CommitmentHash::Sha3_256,
                CoreCommitmentHash::Sha3_512 => CommitmentHash::Sha3_512,
            },
            vrf_mode: match policy.vrf_mode() {
                CoreVrfMode::Classical => VrfMode::Classical,
                CoreVrfMode::HybridOutput => VrfMode::HybridOutput,
                CoreVrfMode::PurePqExperimental => VrfMode::PurePqExperimental,
            },
            directory_mode: match policy.directory_mode() {
                CoreDirectoryMode::Coniks => DirectoryMode::Coniks,
                CoreDirectoryMode::Keytrans => DirectoryMode::Keytrans,
            },
            keytrans_suite: match policy.keytrans_suite() {
                CoreKeytransSuite::MetamorphicHybridExp => KeytransSuite::MetamorphicHybridExp,
                CoreKeytransSuite::Kt128Sha256Ed25519 => KeytransSuite::Kt128Sha256Ed25519,
                CoreKeytransSuite::Kt128Sha256P256 => KeytransSuite::Kt128Sha256P256,
            },
            effective_from: policy.effective_from(),
            created_at: policy.created_at(),
            policy_hash: policy.policy_hash().map(|h| h.to_vec()).unwrap_or_default(),
            rfc6962_leaf_hash: policy.rfc6962_leaf_hash().to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers (logic-free marshalling only).
// ---------------------------------------------------------------------------

fn to_array_32(bytes: &[u8], what: &str) -> FfiResult<[u8; 32]> {
    <[u8; 32]>::try_from(bytes)
        .map_err(|_| VerifyError::Verification(format!("{what} must be exactly 32 bytes")))
}

fn to_array_64(bytes: &[u8], what: &str) -> FfiResult<[u8; 64]> {
    <[u8; 64]>::try_from(bytes)
        .map_err(|_| VerifyError::Verification(format!("{what} must be exactly 64 bytes")))
}

fn parse_vkeys(vkeys: &[String]) -> FfiResult<Vec<VerifierKey>> {
    vkeys
        .iter()
        .map(|v| VerifierKey::parse(v).map_err(VerifyError::from))
        .collect()
}

fn build_entry(
    seq: u64,
    ts_ms: u64,
    enc_x25519: Vec<u8>,
    enc_pq: Vec<u8>,
    signing_pub: Vec<u8>,
    prev_entry_hash: Option<Vec<u8>>,
) -> Entry {
    let prev_entry_hash = match prev_entry_hash {
        Some(h) if !h.is_empty() => Some(h),
        _ => None,
    };
    Entry {
        seq,
        ts_ms,
        enc_x25519,
        enc_pq,
        signing_pub,
        prev_entry_hash,
    }
}

fn verified_policy(signed: &[u8]) -> FfiResult<NamespacePolicy> {
    let signed = SignedPolicy::parse(signed)?;
    signed.verify()?;
    Ok(signed.policy().clone())
}

fn keytrans_verifier(context: &str, vrf_public: Vec<u8>) -> KeytransVerifier {
    KeytransVerifier::new(
        context,
        Box::new(Ecvrf),
        VrfPublicKey::from_bytes(vrf_public),
    )
}

fn keytrans_verifier_for_suite(
    suite_id: u16,
    context: &str,
    vrf_public: Vec<u8>,
) -> FfiResult<KeytransVerifier> {
    let suite = KtSuite::from_suite_id(suite_id)?;
    Ok(KeytransVerifier::new_with_suite(
        context,
        suite,
        suite.vrf(),
        VrfPublicKey::from_bytes(vrf_public),
    ))
}

// ---------------------------------------------------------------------------
// RFC 6962 / 9162 inclusion + consistency (bare Merkle verifier core).
// ---------------------------------------------------------------------------

/// Verify an RFC 6962 inclusion proof.
///
/// `leaf_hash` and `root` are 32-byte SHA-256 hashes; `proof` is the audit path
/// as an ordered list of 32-byte hashes. Succeeds iff the leaf at `index` in a
/// tree of `size` leaves is included under `root`.
#[uniffi::export]
pub fn verify_inclusion(
    index: u64,
    size: u64,
    leaf_hash: Vec<u8>,
    proof: Vec<Vec<u8>>,
    root: Vec<u8>,
) -> FfiResult<()> {
    proof::verify_inclusion(index, size, &leaf_hash, &proof, &root)?;
    Ok(())
}

/// Verify an RFC 6962 consistency proof between two tree sizes — the monitor's
/// anti-equivocation walk.
///
/// `root1` / `root2` are the 32-byte roots at `size1` / `size2`. Succeeds iff
/// the `size2` tree is a consistent append-only extension of the `size1` tree.
#[uniffi::export]
pub fn verify_consistency(
    size1: u64,
    size2: u64,
    proof: Vec<Vec<u8>>,
    root1: Vec<u8>,
    root2: Vec<u8>,
) -> FfiResult<()> {
    proof::verify_consistency(size1, size2, &proof, &root1, &root2)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Layer-0 canonical leaf: mosslet/key-history/v1 conformance instance.
// ---------------------------------------------------------------------------

/// Compute the canonical Layer-0 leaf bytes of a `mosslet/key-history/v1`
/// entry. A missing / empty `prev_entry_hash` is the genesis sentinel.
#[uniffi::export]
pub fn key_history_v1_canonical_bytes(
    seq: u64,
    ts_ms: u64,
    enc_x25519: Vec<u8>,
    enc_pq: Vec<u8>,
    signing_pub: Vec<u8>,
    prev_entry_hash: Option<Vec<u8>>,
) -> FfiResult<Vec<u8>> {
    let entry = build_entry(seq, ts_ms, enc_x25519, enc_pq, signing_pub, prev_entry_hash);
    Ok(entry.canonical_bytes()?)
}

/// Compute the SHA3-512 (context-bound) intra-chain entry hash of a
/// `mosslet/key-history/v1` entry (64-byte digest).
#[uniffi::export]
pub fn key_history_v1_entry_hash(
    seq: u64,
    ts_ms: u64,
    enc_x25519: Vec<u8>,
    enc_pq: Vec<u8>,
    signing_pub: Vec<u8>,
    prev_entry_hash: Option<Vec<u8>>,
) -> FfiResult<Vec<u8>> {
    let entry = build_entry(seq, ts_ms, enc_x25519, enc_pq, signing_pub, prev_entry_hash);
    Ok(entry.entry_hash()?.to_vec())
}

/// Compute the intra-chain entry hash under a caller-supplied `context` label
/// (e.g. `"acme/key-history/v1"`), letting any application brand its leaves.
#[uniffi::export]
pub fn key_history_entry_hash_with_context(
    context: String,
    seq: u64,
    ts_ms: u64,
    enc_x25519: Vec<u8>,
    enc_pq: Vec<u8>,
    signing_pub: Vec<u8>,
    prev_entry_hash: Option<Vec<u8>>,
) -> FfiResult<Vec<u8>> {
    let label = ContextLabel::parse(&context)?;
    let entry = build_entry(seq, ts_ms, enc_x25519, enc_pq, signing_pub, prev_entry_hash);
    Ok(entry.entry_hash_with_context(&label)?.to_vec())
}

/// Compute the RFC 6962 leaf hash (`SHA-256(0x00 || canonical)`) of a
/// `mosslet/key-history/v1` entry — feed it straight into [`verify_inclusion`].
#[uniffi::export]
pub fn key_history_v1_rfc6962_leaf_hash(
    seq: u64,
    ts_ms: u64,
    enc_x25519: Vec<u8>,
    enc_pq: Vec<u8>,
    signing_pub: Vec<u8>,
    prev_entry_hash: Option<Vec<u8>>,
) -> FfiResult<Vec<u8>> {
    let entry = build_entry(seq, ts_ms, enc_x25519, enc_pq, signing_pub, prev_entry_hash);
    Ok(entry.rfc6962_leaf_hash()?.to_vec())
}

// ---------------------------------------------------------------------------
// C2SP checkpoint / signed-note (classical Ed25519 + additive hybrid PQ).
// ---------------------------------------------------------------------------

/// Verify a C2SP `signed-note` against a set of trusted verifier keys. Returns
/// the number of trusted signature lines that verified (always `>= 1`).
#[uniffi::export]
pub fn verify_signed_note(note_text: String, vkeys: Vec<String>) -> FfiResult<u32> {
    let trusted = parse_vkeys(&vkeys)?;
    let note = SignedNote::parse(&note_text)?;
    Ok(note.verify(&trusted)?.len() as u32)
}

/// Parse and verify a signed checkpoint note, returning the verified checkpoint
/// head. Fails on a malformed body or if no trusted signature verifies.
#[uniffi::export]
pub fn checkpoint_verify(note_text: String, vkeys: Vec<String>) -> FfiResult<CheckpointHead> {
    let trusted = parse_vkeys(&vkeys)?;
    let cp = Checkpoint::from_signed_note(&note_text, &trusted)?;
    Ok((&cp).into())
}

/// Parse an (already-trusted) checkpoint **body** text without signature
/// verification, returning its head.
#[uniffi::export]
pub fn checkpoint_parse(body_text: String) -> FfiResult<CheckpointHead> {
    let cp = Checkpoint::parse(&body_text)?;
    Ok((&cp).into())
}

/// Verify inclusion of a leaf against a *verified* signed checkpoint note.
/// Parses + verifies the checkpoint (using `vkeys`), then checks the inclusion
/// proof against that checkpoint's size and root.
#[uniffi::export]
pub fn checkpoint_verify_inclusion(
    note_text: String,
    vkeys: Vec<String>,
    leaf_index: u64,
    leaf_hash: Vec<u8>,
    proof: Vec<Vec<u8>>,
) -> FfiResult<()> {
    let trusted = parse_vkeys(&vkeys)?;
    let cp = Checkpoint::from_signed_note(&note_text, &trusted)?;
    cp.verify_inclusion(leaf_index, &leaf_hash, &proof)?;
    Ok(())
}

/// Monitor anti-equivocation: verify two *verified* signed checkpoint notes are
/// consistent append-only views of the same log.
#[uniffi::export]
pub fn checkpoint_verify_consistency(
    older_note: String,
    newer_note: String,
    vkeys: Vec<String>,
    proof: Vec<Vec<u8>>,
) -> FfiResult<()> {
    let trusted = parse_vkeys(&vkeys)?;
    let older = Checkpoint::from_signed_note(&older_note, &trusted)?;
    let newer = Checkpoint::from_signed_note(&newer_note, &trusted)?;
    older.verify_consistency(&newer, &proof)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CONIKS index-privacy proofs + SHA3-512 commitment opening.
// ---------------------------------------------------------------------------

/// Verify a CONIKS **presence** (lookup) proof against a directory root.
///
/// `root` is the 64-byte directory root; `proof` is the canonical `LookupProof`
/// bytes. Returns the proven value.
#[uniffi::export]
pub fn coniks_verify_lookup(
    namespace: String,
    vrf_public: Vec<u8>,
    root: Vec<u8>,
    identity: Vec<u8>,
    proof: Vec<u8>,
) -> FfiResult<Vec<u8>> {
    let ns = Namespace::parse(&namespace)?;
    let vrf_public = VrfPublicKey::from_bytes(vrf_public);
    let root = to_array_64(&root, "coniks root")?;
    let proof = LookupProof::from_bytes(&proof)?;
    Ok(crate::coniks::verify_lookup(
        &Ecvrf,
        &ns,
        &vrf_public,
        &root,
        &identity,
        &proof,
    )?)
}

/// Verify a CONIKS **absence** proof against a directory root. Succeeds iff
/// `identity` is provably absent under `root`.
#[uniffi::export]
pub fn coniks_verify_absence(
    namespace: String,
    vrf_public: Vec<u8>,
    root: Vec<u8>,
    identity: Vec<u8>,
    proof: Vec<u8>,
) -> FfiResult<()> {
    let ns = Namespace::parse(&namespace)?;
    let vrf_public = VrfPublicKey::from_bytes(vrf_public);
    let root = to_array_64(&root, "coniks root")?;
    let proof = AbsenceProof::from_bytes(&proof)?;
    crate::coniks::verify_absence(&Ecvrf, &ns, &vrf_public, &root, &identity, &proof)?;
    Ok(())
}

/// Verify a SHA3-512 commitment opening. `commitment` is 64 bytes, `opening` is
/// 32 bytes. Succeeds iff `commitment == SHA3-512_with_context(context, opening
/// || value)`.
#[uniffi::export]
pub fn verify_commitment(
    context: String,
    commitment: Vec<u8>,
    value: Vec<u8>,
    opening: Vec<u8>,
) -> FfiResult<()> {
    let commitment = Commitment::from_bytes(to_array_64(&commitment, "commitment")?);
    let opening = Opening::from_bytes(to_array_32(&opening, "opening")?);
    crate::commitment::verify_commitment(&context, &commitment, &value, &opening)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// NamespacePolicy: parse + verify + declared == observed enforcement.
// ---------------------------------------------------------------------------

/// Parse and verify a signed namespace policy, returning the declared posture.
/// `envelope` is the canonical `SignedPolicy` envelope bytes.
#[uniffi::export]
pub fn signed_policy_verify(envelope: Vec<u8>) -> FfiResult<PolicyPosture> {
    let parsed = SignedPolicy::parse(&envelope)?;
    let policy = parsed.verify()?;
    Ok(policy.into())
}

/// Enforce **declared == observed** for an observed checkpoint signing key.
/// `public_key` is the opaque metamorphic-crypto base64 public-key token.
#[uniffi::export]
pub fn policy_enforce_checkpoint_signing_key(
    envelope: Vec<u8>,
    public_key: String,
) -> FfiResult<()> {
    verified_policy(&envelope)?.enforce_checkpoint_signing_key(&public_key)?;
    Ok(())
}

/// Enforce **declared == observed** for an observed checkpoint signature.
/// `signature` is the opaque metamorphic-crypto base64 signature token.
#[uniffi::export]
pub fn policy_enforce_checkpoint_signature(envelope: Vec<u8>, signature: String) -> FfiResult<()> {
    verified_policy(&envelope)?.enforce_checkpoint_signature(&signature)?;
    Ok(())
}

/// Enforce **declared == observed** for an observed CONIKS VRF `suite_id`.
#[uniffi::export]
pub fn policy_enforce_vrf_suite_id(envelope: Vec<u8>, observed_suite_id: u8) -> FfiResult<()> {
    verified_policy(&envelope)?.enforce_vrf_suite_id(observed_suite_id)?;
    Ok(())
}

/// Enforce **declared == observed** for an observed commitment-hash parameter.
#[uniffi::export]
pub fn policy_enforce_commitment_hash(
    envelope: Vec<u8>,
    observed: CommitmentHash,
) -> FfiResult<()> {
    let observed = match observed {
        CommitmentHash::Sha3_256 => CoreCommitmentHash::Sha3_256,
        CommitmentHash::Sha3_512 => CoreCommitmentHash::Sha3_512,
    };
    verified_policy(&envelope)?.enforce_commitment_hash(observed)?;
    Ok(())
}

/// Enforce **declared == observed** for an observed directory backend id (the
/// raw `u16` code, e.g. `0x0001` CONIKS, `0xF004` KEYTRANS_EXP_04).
#[uniffi::export]
pub fn policy_enforce_directory_backend(
    envelope: Vec<u8>,
    observed_backend_id: u16,
) -> FfiResult<()> {
    verified_policy(&envelope)?
        .enforce_directory_backend(DirectoryBackendId::from_u16(observed_backend_id))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Experimental KEYTRANS combined-tree directory verification
// (KEYTRANS_EXP_04 — version-tagged, movable bytes).
// ---------------------------------------------------------------------------

/// Verify an experimental KEYTRANS greatest-version search proof (§6) against a
/// combined-tree root (experimental private suite).
#[uniffi::export]
pub fn keytrans_verify_search(
    context: String,
    vrf_public: Vec<u8>,
    root: Vec<u8>,
    label: Vec<u8>,
    proof: Vec<u8>,
) -> FfiResult<SearchResult> {
    let verifier = keytrans_verifier(&context, vrf_public);
    let outcome = verifier.verify_search_bytes(&root, &label, &proof)?;
    Ok((&outcome).into())
}

/// Verify an experimental KEYTRANS fixed-version search proof (§7).
#[uniffi::export]
pub fn keytrans_verify_fixed_version(
    context: String,
    vrf_public: Vec<u8>,
    root: Vec<u8>,
    label: Vec<u8>,
    proof: Vec<u8>,
) -> FfiResult<SearchResult> {
    let verifier = keytrans_verifier(&context, vrf_public);
    let outcome = verifier.verify_fixed_version_bytes(&root, &label, &proof)?;
    Ok((&outcome).into())
}

/// Verify an experimental KEYTRANS monitoring proof (§8). Succeeds iff the
/// monitored version's binary ladder is all inclusions under the root.
#[uniffi::export]
pub fn keytrans_verify_monitor(
    context: String,
    vrf_public: Vec<u8>,
    root: Vec<u8>,
    label: Vec<u8>,
    proof: Vec<u8>,
) -> FfiResult<()> {
    let verifier = keytrans_verifier(&context, vrf_public);
    verifier.verify_monitor_bytes(&root, &label, &proof)?;
    Ok(())
}

/// Verify an experimental KEYTRANS greatest-version search proof (§6) under an
/// explicit §15.1 `suite_id` (on-spec IETF standard suites).
#[uniffi::export]
pub fn keytrans_verify_search_suite(
    suite_id: u16,
    context: String,
    vrf_public: Vec<u8>,
    root: Vec<u8>,
    label: Vec<u8>,
    proof: Vec<u8>,
) -> FfiResult<SearchResult> {
    let verifier = keytrans_verifier_for_suite(suite_id, &context, vrf_public)?;
    let outcome = verifier.verify_search_bytes(&root, &label, &proof)?;
    Ok((&outcome).into())
}

/// Verify an experimental KEYTRANS fixed-version search proof (§7) under an
/// explicit §15.1 `suite_id`.
#[uniffi::export]
pub fn keytrans_verify_fixed_version_suite(
    suite_id: u16,
    context: String,
    vrf_public: Vec<u8>,
    root: Vec<u8>,
    label: Vec<u8>,
    proof: Vec<u8>,
) -> FfiResult<SearchResult> {
    let verifier = keytrans_verifier_for_suite(suite_id, &context, vrf_public)?;
    let outcome = verifier.verify_fixed_version_bytes(&root, &label, &proof)?;
    Ok((&outcome).into())
}

/// Verify an experimental KEYTRANS monitoring proof (§8) under an explicit
/// §15.1 `suite_id`.
#[uniffi::export]
pub fn keytrans_verify_monitor_suite(
    suite_id: u16,
    context: String,
    vrf_public: Vec<u8>,
    root: Vec<u8>,
    label: Vec<u8>,
    proof: Vec<u8>,
) -> FfiResult<()> {
    let verifier = keytrans_verifier_for_suite(suite_id, &context, vrf_public)?;
    verifier.verify_monitor_bytes(&root, &label, &proof)?;
    Ok(())
}
