//! Browser **verification, monitor, and signing** SDK via `wasm-bindgen`
//! (Slice 6).
//!
//! This module is the WASM *personality* of the crate: a thin, logic-free
//! shell over the rlib core. Every export base64/text-marshals its arguments
//! and delegates straight to [`crate::proof`], [`crate::checkpoint`],
//! [`crate::note`], [`crate::coniks`], [`crate::commitment`], and
//! [`crate::policy`]. It performs **no** Merkle, signature, VRF, or policy logic
//! of its own — so the verifications it runs and the bytes it computes are
//! identical to the native crate. The cross-language byte-parity KAT
//! (`tests/cross_language.rs` + the `wasm-bindgen-test` suite) locks this.
//!
//! Alongside the original verification/monitor surface, this SDK also surfaces
//! the **producer** helpers a browser client needs to sign its own C2SP
//! artifacts: classical Ed25519 and additive hybrid PQ note signing
//! ([`note_sign_ed25519`], [`note_sign_hybrid`]), a one-call checkpoint signer
//! ([`checkpoint_sign_hybrid`]), verifier-key encoding ([`vkey_encode_hybrid`],
//! [`vkey_encode_ed25519`]), and namespace-policy signing
//! ([`signed_policy_sign`]). Secret keys never leave the audited
//! metamorphic-crypto primitives; this layer only marshals base64/text.
//!
//! ## Conventions (matching the metamorphic-crypto WASM SDK)
//!
//! - Binary values cross the JS boundary as **standard base64** strings
//!   (padded; matching `btoa`/`atob`). Merkle hashes are 32 bytes, SHA3-512
//!   digests / CONIKS roots are 64 bytes.
//! - Proof audit paths and trusted-key sets cross as **arrays of base64 / text
//!   strings**.
//! - C2SP `checkpoint` / `signed-note` bodies and `VerifierKey`s cross as their
//!   canonical **UTF-8 text** form.
//! - Verification predicates return `true` on success and **throw** a JS
//!   `Error` (carrying the typed [`crate::Error`] message) on any failure —
//!   tamper, forgery, posture mismatch, or malformed input are all rejections.
//!
//! ## Post-quantum posture
//!
//! Unchanged from the rlib: integrity, authentication, and commitments are
//! post-quantum from day one; only CONIKS index-privacy defaults to the
//! classical ECVRF. Nothing here is FIPS-validated and this SDK makes no such
//! claim.

use wasm_bindgen::prelude::*;

use crate::checkpoint::{self, Checkpoint};
use crate::commitment::{Commitment, Opening};
use crate::coniks::{AbsenceProof, LookupProof, Namespace};
use crate::directory::DirectoryBackendId;
use crate::keytrans::{KeytransVerifier, KtSuite};
use crate::leaf::ContextLabel;
use crate::leaf::key_history_v1::Entry;
use crate::note::{self, SignedNote, VerifierKey};
use crate::policy::{
    CheckpointSuite, CommitmentHash, DirectoryMode, KeytransSuite, NamespacePolicy, SecurityLevel,
    SignedPolicy, VrfMode,
};
use crate::proof::{verify_consistency, verify_inclusion};
use crate::vrf::{Ecvrf, VrfPublicKey};

use metamorphic_crypto::b64;

// ---------------------------------------------------------------------------
// RFC 6962 / 9162 inclusion + consistency (verification + monitor core)
// ---------------------------------------------------------------------------

/// Verify an RFC 6962 inclusion proof.
///
/// `leaf_hash_b64` and `root_b64` are 32-byte SHA-256 hashes; `proof_b64` is the
/// audit path as an array of 32-byte base64 hashes. Returns `true` if the leaf
/// at `index` in a tree of `size` leaves is included under `root`; throws
/// otherwise.
#[wasm_bindgen(js_name = "verifyInclusion")]
pub fn verify_inclusion_wasm(
    index: u64,
    size: u64,
    leaf_hash_b64: &str,
    proof_b64: Vec<String>,
    root_b64: &str,
) -> Result<bool, JsValue> {
    let leaf = decode(leaf_hash_b64)?;
    let proof = decode_proof(&proof_b64)?;
    let root = decode(root_b64)?;
    verify_inclusion(index, size, &leaf, &proof, &root).map_err(to_js)?;
    Ok(true)
}

/// Verify an RFC 6962 consistency proof between two tree sizes — the monitor's
/// anti-equivocation walk.
///
/// `root1_b64` / `root2_b64` are the 32-byte roots at `size1` / `size2`;
/// `proof_b64` is the consistency proof as base64 hashes. Returns `true` if the
/// `size2` tree is a consistent append-only extension of the `size1` tree;
/// throws otherwise.
#[wasm_bindgen(js_name = "verifyConsistency")]
pub fn verify_consistency_wasm(
    size1: u64,
    size2: u64,
    proof_b64: Vec<String>,
    root1_b64: &str,
    root2_b64: &str,
) -> Result<bool, JsValue> {
    let proof = decode_proof(&proof_b64)?;
    let root1 = decode(root1_b64)?;
    let root2 = decode(root2_b64)?;
    verify_consistency(size1, size2, &proof, &root1, &root2).map_err(to_js)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Layer-0 canonical leaf: mosslet/key-history/v1 conformance instance
// ---------------------------------------------------------------------------

/// Compute the canonical Layer-0 leaf bytes of a `mosslet/key-history/v1` entry.
///
/// Returns base64 of the canonical bytes. `prev_entry_hash_b64` must be absent
/// (or empty) for the genesis entry and the 64-byte SHA3-512 of the previous
/// entry otherwise. The raw canonical bytes feed both the SHA3-512 entry hash
/// and the RFC 6962 leaf hash.
#[wasm_bindgen(js_name = "keyHistoryV1CanonicalBytes")]
pub fn key_history_v1_canonical_bytes(
    seq: u64,
    ts_ms: u64,
    enc_x25519_b64: &str,
    enc_pq_b64: &str,
    signing_pub_b64: &str,
    prev_entry_hash_b64: Option<String>,
) -> Result<String, JsValue> {
    let entry = build_entry(
        seq,
        ts_ms,
        enc_x25519_b64,
        enc_pq_b64,
        signing_pub_b64,
        prev_entry_hash_b64,
    )?;
    Ok(b64::encode(&entry.canonical_bytes().map_err(to_js)?))
}

/// Compute the SHA3-512 (context-bound) intra-chain entry hash of a
/// `mosslet/key-history/v1` entry. Returns the 64-byte digest as base64.
#[wasm_bindgen(js_name = "keyHistoryV1EntryHash")]
pub fn key_history_v1_entry_hash(
    seq: u64,
    ts_ms: u64,
    enc_x25519_b64: &str,
    enc_pq_b64: &str,
    signing_pub_b64: &str,
    prev_entry_hash_b64: Option<String>,
) -> Result<String, JsValue> {
    let entry = build_entry(
        seq,
        ts_ms,
        enc_x25519_b64,
        enc_pq_b64,
        signing_pub_b64,
        prev_entry_hash_b64,
    )?;
    Ok(b64::encode(&entry.entry_hash().map_err(to_js)?))
}

/// Compute the SHA3-512 (context-bound) intra-chain entry hash of a key-history
/// entry under a caller-supplied `context` label, letting any application brand
/// its leaves with its own `<namespace>/key-history/v1` namespace.
///
/// This is the **recommended** entry-hash export for applications other than
/// the frozen Mosslet fixture: pass your own label (e.g.
/// `"acme/key-history/v1"`) as `context` so the domain separator reflects where
/// the entry comes from. The canonical bytes and RFC 6962 leaf hash are
/// brand-independent (reuse [`key_history_v1_canonical_bytes`] /
/// [`key_history_v1_rfc6962_leaf_hash`] unchanged); only this entry hash varies
/// by label. Returns the 64-byte digest as base64. Throws if `context` is not a
/// valid `<namespace>/<record-type>/v<N>` label.
#[wasm_bindgen(js_name = "keyHistoryEntryHashWithContext")]
pub fn key_history_entry_hash_with_context(
    context: &str,
    seq: u64,
    ts_ms: u64,
    enc_x25519_b64: &str,
    enc_pq_b64: &str,
    signing_pub_b64: &str,
    prev_entry_hash_b64: Option<String>,
) -> Result<String, JsValue> {
    let label = ContextLabel::parse(context).map_err(to_js)?;
    let entry = build_entry(
        seq,
        ts_ms,
        enc_x25519_b64,
        enc_pq_b64,
        signing_pub_b64,
        prev_entry_hash_b64,
    )?;
    Ok(b64::encode(
        &entry.entry_hash_with_context(&label).map_err(to_js)?,
    ))
}

/// Compute the RFC 6962 leaf hash (`SHA-256(0x00 || canonical)`) of a
/// `mosslet/key-history/v1` entry. Returns the 32-byte hash as base64 — feed it
/// straight into [`verify_inclusion_wasm`].
#[wasm_bindgen(js_name = "keyHistoryV1Rfc6962LeafHash")]
pub fn key_history_v1_rfc6962_leaf_hash(
    seq: u64,
    ts_ms: u64,
    enc_x25519_b64: &str,
    enc_pq_b64: &str,
    signing_pub_b64: &str,
    prev_entry_hash_b64: Option<String>,
) -> Result<String, JsValue> {
    let entry = build_entry(
        seq,
        ts_ms,
        enc_x25519_b64,
        enc_pq_b64,
        signing_pub_b64,
        prev_entry_hash_b64,
    )?;
    Ok(b64::encode(&entry.rfc6962_leaf_hash().map_err(to_js)?))
}

// ---------------------------------------------------------------------------
// C2SP checkpoint / signed-note (classical Ed25519 + additive hybrid PQ)
// ---------------------------------------------------------------------------

/// Verify a C2SP `signed-note` against a set of trusted verifier keys.
///
/// `vkeys` is an array of encoded `VerifierKey` strings (Ed25519 and/or the
/// additive `MetamorphicHybrid` composite). Returns the number of trusted
/// signature lines that verified (always `>= 1` on success); throws if no
/// trusted signature verifies or a known key's line is forged.
#[wasm_bindgen(js_name = "verifySignedNote")]
pub fn verify_signed_note(note_text: &str, vkeys: Vec<String>) -> Result<u32, JsValue> {
    let trusted = parse_vkeys(&vkeys)?;
    let note = SignedNote::parse(note_text).map_err(to_js)?;
    let verified = note.verify(&trusted).map_err(to_js)?;
    Ok(verified.len() as u32)
}

/// Parse and verify a signed checkpoint note, returning the checkpoint head.
///
/// Verifies at least one trusted signature (Ed25519 or hybrid PQ), then returns
/// `{ origin, size, rootB64, extensions }`. Throws on a malformed body or if no
/// trusted signature verifies.
#[wasm_bindgen(js_name = "checkpointVerify")]
pub fn checkpoint_verify(note_text: &str, vkeys: Vec<String>) -> Result<JsValue, JsValue> {
    let trusted = parse_vkeys(&vkeys)?;
    let cp = Checkpoint::from_signed_note(note_text, &trusted).map_err(to_js)?;
    Ok(checkpoint_to_js(&cp))
}

/// Parse an (already-trusted) checkpoint **body** text without signature
/// verification. Returns `{ origin, size, rootB64, extensions }`.
#[wasm_bindgen(js_name = "checkpointParse")]
pub fn checkpoint_parse(body_text: &str) -> Result<JsValue, JsValue> {
    let cp = Checkpoint::parse(body_text).map_err(to_js)?;
    Ok(checkpoint_to_js(&cp))
}

/// Verify inclusion of a leaf against a *verified* signed checkpoint note.
///
/// Parses + verifies the checkpoint (using `vkeys`), then checks the inclusion
/// proof against that checkpoint's size and root. Returns `true`; throws on any
/// failure.
#[wasm_bindgen(js_name = "checkpointVerifyInclusion")]
pub fn checkpoint_verify_inclusion(
    note_text: &str,
    vkeys: Vec<String>,
    leaf_index: u64,
    leaf_hash_b64: &str,
    proof_b64: Vec<String>,
) -> Result<bool, JsValue> {
    let trusted = parse_vkeys(&vkeys)?;
    let cp = Checkpoint::from_signed_note(note_text, &trusted).map_err(to_js)?;
    let leaf = decode(leaf_hash_b64)?;
    let proof = decode_proof(&proof_b64)?;
    cp.verify_inclusion(leaf_index, &leaf, &proof)
        .map_err(to_js)?;
    Ok(true)
}

/// Monitor anti-equivocation: verify two *verified* signed checkpoint notes are
/// consistent append-only views of the same log.
///
/// Both `older_note` and `newer_note` are verified against `vkeys`, then the
/// consistency proof between their sizes/roots is checked. Returns `true`;
/// throws on a malformed note, an untrusted/forged signature, or an
/// inconsistency (equivocation).
#[wasm_bindgen(js_name = "checkpointVerifyConsistency")]
pub fn checkpoint_verify_consistency(
    older_note: &str,
    newer_note: &str,
    vkeys: Vec<String>,
    proof_b64: Vec<String>,
) -> Result<bool, JsValue> {
    let trusted = parse_vkeys(&vkeys)?;
    let older = Checkpoint::from_signed_note(older_note, &trusted).map_err(to_js)?;
    let newer = Checkpoint::from_signed_note(newer_note, &trusted).map_err(to_js)?;
    let proof = decode_proof(&proof_b64)?;
    older.verify_consistency(&newer, &proof).map_err(to_js)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// C2SP note / checkpoint / vkey signing + encoding (producer helpers)
// ---------------------------------------------------------------------------

/// Sign UTF-8 `text` with an additive hybrid PQ composite secret key, returning
/// the complete C2SP `signed-note` text (body + blank line + the hybrid
/// signature line).
///
/// `text` must be the exact note body (ending in a newline). `name` is the
/// C2SP key name; `secret_key_b64` is the base64 metamorphic-crypto composite
/// secret key. The composite signs under the fixed internal hybrid context.
/// Throws on an invalid name, an undecodable/underivable secret key, or a
/// signing failure.
#[wasm_bindgen(js_name = "noteSignHybrid")]
pub fn note_sign_hybrid(text: &str, name: &str, secret_key_b64: &str) -> Result<String, JsValue> {
    let sig = note::sign_hybrid(text, name, secret_key_b64).map_err(to_js)?;
    let note = SignedNote::new(text.to_string(), vec![sig]).map_err(to_js)?;
    Ok(note.marshal())
}

/// Sign UTF-8 `text` with a raw 32-byte Ed25519 seed, returning the complete
/// classical (witness-compatible) C2SP `signed-note` text.
///
/// `text` must be the exact note body (ending in a newline). `name` is the
/// C2SP key name; `seed_b64` is the base64 32-byte Ed25519 seed. Throws on an
/// invalid name or a seed that is not 32 bytes.
#[wasm_bindgen(js_name = "noteSignEd25519")]
pub fn note_sign_ed25519(text: &str, name: &str, seed_b64: &str) -> Result<String, JsValue> {
    let seed = decode(seed_b64)?;
    let sig = note::sign_ed25519(text, name, &seed).map_err(to_js)?;
    let note = SignedNote::new(text.to_string(), vec![sig]).map_err(to_js)?;
    Ok(note.marshal())
}

/// Build a checkpoint body and sign it with a hybrid PQ composite secret key in
/// one call, returning the complete C2SP `signed-note` text ready to publish.
///
/// `origin` is the log identity line; `size` the tree size; `root_b64` the
/// base64 of the exactly 32-byte RFC 6962 root at `size`; `name` the C2SP key
/// name (usually the origin); `secret_key_b64` the base64 composite secret key.
/// Wraps [`crate::checkpoint::sign_checkpoint_hybrid`]. Throws on a malformed
/// checkpoint (empty origin, non-32-byte root) or a signing failure.
#[wasm_bindgen(js_name = "checkpointSignHybrid")]
pub fn checkpoint_sign_hybrid(
    origin: &str,
    size: u64,
    root_b64: &str,
    name: &str,
    secret_key_b64: &str,
) -> Result<String, JsValue> {
    checkpoint::sign_checkpoint_hybrid(origin, size, root_b64, name, secret_key_b64).map_err(to_js)
}

/// Encode a hybrid composite verifier key (`vkey`) from a key name and the
/// metamorphic-crypto composite public key bytes (`tag || classical_pk ||
/// ml_dsa_pk`, base64). The stored `namespace.public_signing_key` is exactly
/// this composite public key. Returns the `<name>+<hex keyid>+<base64(type ||
/// pubkey)>` string; throws on an invalid name or empty public key.
#[wasm_bindgen(js_name = "vkeyEncodeHybrid")]
pub fn vkey_encode_hybrid(name: &str, public_key_b64: &str) -> Result<String, JsValue> {
    let public_key = decode(public_key_b64)?;
    let vkey = VerifierKey::new_hybrid(name, &public_key).map_err(to_js)?;
    Ok(vkey.encode())
}

/// Encode an Ed25519 verifier key (`vkey`) from a key name and 32-byte public
/// key (base64). Returns the C2SP `vkey` string; throws on an invalid name or a
/// public key that is not 32 bytes.
#[wasm_bindgen(js_name = "vkeyEncodeEd25519")]
pub fn vkey_encode_ed25519(name: &str, public_key_b64: &str) -> Result<String, JsValue> {
    let public_key = decode(public_key_b64)?;
    let vkey = VerifierKey::new_ed25519(name, &public_key).map_err(to_js)?;
    Ok(vkey.encode())
}

/// Sign a namespace policy with a hybrid composite secret key, returning the
/// canonical `SignedPolicy` envelope as base64 (the Layer-0 leaf).
///
/// This mirrors the [`signed_policy_verify`] posture surface: the declared
/// axes are given as their canonical string tags (as emitted by
/// [`signed_policy_verify`]). `prev_policy_hash_b64` is the base64 64-byte hash
/// of the previous policy version, or `null`/omitted for a genesis policy;
/// `secret_key_b64` is the namespace root composite secret key.
///
/// The `directory_mode` selects the CONIKS ([`NamespacePolicy::new`]) or
/// KEYTRANS ([`NamespacePolicy::new_keytrans`]) constructor; `keytrans_suite`
/// is only meaningful on the KEYTRANS route. Throws on an invalid tag, a
/// well-formedness violation, or a signing failure.
#[wasm_bindgen(js_name = "signedPolicySign")]
#[allow(clippy::too_many_arguments)]
pub fn signed_policy_sign(
    namespace: &str,
    policy_schema_version: u32,
    security_level: &str,
    checkpoint_suite: &str,
    commitment_hash: &str,
    vrf_mode: &str,
    directory_mode: &str,
    keytrans_suite: &str,
    effective_from: u64,
    created_at: u64,
    prev_policy_hash_b64: Option<String>,
    secret_key_b64: &str,
) -> Result<String, JsValue> {
    let policy = build_policy(
        namespace,
        policy_schema_version,
        security_level,
        checkpoint_suite,
        commitment_hash,
        vrf_mode,
        directory_mode,
        keytrans_suite,
        effective_from,
        created_at,
        prev_policy_hash_b64,
    )?;
    let signed = SignedPolicy::sign(policy, secret_key_b64).map_err(to_js)?;
    Ok(b64::encode(&signed.canonical_bytes()))
}

// ---------------------------------------------------------------------------
// CONIKS index privacy: presence / absence proof verification
// ---------------------------------------------------------------------------

/// Verify a CONIKS **presence** (lookup) proof against a directory root.
///
/// Uses the classical ECVRF (`suite 0x03`). `vrf_public_b64` is the VRF public
/// key, `root_b64` the 64-byte directory root, `identity_b64` the looked-up
/// identity bytes, and `proof_b64` the canonical `LookupProof` bytes. Returns
/// the proven value as base64; throws if the proof, VRF output, or root is
/// invalid.
#[wasm_bindgen(js_name = "coniksVerifyLookup")]
pub fn coniks_verify_lookup(
    namespace: &str,
    vrf_public_b64: &str,
    root_b64: &str,
    identity_b64: &str,
    proof_b64: &str,
) -> Result<String, JsValue> {
    let ns = Namespace::parse(namespace).map_err(to_js)?;
    let vrf_public = VrfPublicKey::from_bytes(decode(vrf_public_b64)?);
    let root = decode_array_64(root_b64)?;
    let identity = decode(identity_b64)?;
    let proof = LookupProof::from_bytes(&decode(proof_b64)?).map_err(to_js)?;
    let value = crate::coniks::verify_lookup(&Ecvrf, &ns, &vrf_public, &root, &identity, &proof)
        .map_err(to_js)?;
    Ok(b64::encode(&value))
}

/// Verify a CONIKS **absence** proof against a directory root.
///
/// Same inputs as [`coniks_verify_lookup`] but `proof_b64` is a canonical
/// `AbsenceProof`. Returns `true` if `identity` is provably absent under
/// `root`; throws otherwise.
#[wasm_bindgen(js_name = "coniksVerifyAbsence")]
pub fn coniks_verify_absence(
    namespace: &str,
    vrf_public_b64: &str,
    root_b64: &str,
    identity_b64: &str,
    proof_b64: &str,
) -> Result<bool, JsValue> {
    let ns = Namespace::parse(namespace).map_err(to_js)?;
    let vrf_public = VrfPublicKey::from_bytes(decode(vrf_public_b64)?);
    let root = decode_array_64(root_b64)?;
    let identity = decode(identity_b64)?;
    let proof = AbsenceProof::from_bytes(&decode(proof_b64)?).map_err(to_js)?;
    crate::coniks::verify_absence(&Ecvrf, &ns, &vrf_public, &root, &identity, &proof)
        .map_err(to_js)?;
    Ok(true)
}

/// Verify a SHA3-512 commitment opening.
///
/// `commitment_b64` is the 64-byte commitment, `opening_b64` the 32-byte
/// opening. Returns `true` if `commitment == SHA3-512_with_context(context,
/// opening || value)`; throws otherwise.
#[wasm_bindgen(js_name = "verifyCommitment")]
pub fn verify_commitment_wasm(
    context: &str,
    commitment_b64: &str,
    value_b64: &str,
    opening_b64: &str,
) -> Result<bool, JsValue> {
    let commitment = Commitment::from_bytes(decode_array_64(commitment_b64)?);
    let value = decode(value_b64)?;
    let opening = Opening::from_bytes(decode_array_32(opening_b64)?);
    crate::commitment::verify_commitment(context, &commitment, &value, &opening).map_err(to_js)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// NamespacePolicy: parse + verify + declared == observed enforcement
// ---------------------------------------------------------------------------

/// Parse and verify a signed namespace policy.
///
/// `signed_b64` is the canonical `SignedPolicy` envelope. Verifies the composite
/// signature binds the policy under `<namespace>/namespace-policy/v1`, then
/// returns the declared posture as
/// `{ namespace, policySchemaVersion, securityLevel, checkpointSuite,
/// commitmentHash, vrfMode, effectiveFrom, createdAt, policyHashB64,
/// rfc6962LeafHashB64 }`. Throws on a malformed envelope or invalid signature.
#[wasm_bindgen(js_name = "signedPolicyVerify")]
pub fn signed_policy_verify(signed_b64: &str) -> Result<JsValue, JsValue> {
    let signed = SignedPolicy::parse(&decode(signed_b64)?).map_err(to_js)?;
    let policy = signed.verify().map_err(to_js)?;
    policy_to_js(policy)
}

/// Enforce **declared == observed** for an observed checkpoint signing key.
///
/// Verifies the signed policy, then maps `public_key_b64` to its
/// `(Suite, SignatureLevel)` posture via the metamorphic-crypto opaque accessor
/// and compares it to the declared checkpoint posture. Returns `true` on match;
/// throws on a posture mismatch.
#[wasm_bindgen(js_name = "policyEnforceCheckpointSigningKey")]
pub fn policy_enforce_checkpoint_signing_key(
    signed_b64: &str,
    public_key_b64: &str,
) -> Result<bool, JsValue> {
    let policy = verified_policy(signed_b64)?;
    policy
        .enforce_checkpoint_signing_key(public_key_b64)
        .map_err(to_js)?;
    Ok(true)
}

/// Enforce **declared == observed** for an observed checkpoint signature.
#[wasm_bindgen(js_name = "policyEnforceCheckpointSignature")]
pub fn policy_enforce_checkpoint_signature(
    signed_b64: &str,
    signature_b64: &str,
) -> Result<bool, JsValue> {
    let policy = verified_policy(signed_b64)?;
    policy
        .enforce_checkpoint_signature(signature_b64)
        .map_err(to_js)?;
    Ok(true)
}

/// Enforce **declared == observed** for an observed CONIKS VRF `suite_id`.
#[wasm_bindgen(js_name = "policyEnforceVrfSuiteId")]
pub fn policy_enforce_vrf_suite_id(
    signed_b64: &str,
    observed_suite_id: u8,
) -> Result<bool, JsValue> {
    let policy = verified_policy(signed_b64)?;
    policy
        .enforce_vrf_suite_id(observed_suite_id)
        .map_err(to_js)?;
    Ok(true)
}

/// Enforce **declared == observed** for an observed commitment-hash parameter.
///
/// `observed` is `"sha3_256"` or `"sha3_512"`.
#[wasm_bindgen(js_name = "policyEnforceCommitmentHash")]
pub fn policy_enforce_commitment_hash(signed_b64: &str, observed: &str) -> Result<bool, JsValue> {
    let policy = verified_policy(signed_b64)?;
    policy
        .enforce_commitment_hash(parse_commitment_hash(observed)?)
        .map_err(to_js)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Experimental KEYTRANS combined-tree directory: search / fixed-version /
// monitor verification (KEYTRANS_EXP_04 — version-tagged, MOVABLE bytes)
// ---------------------------------------------------------------------------

/// Verify an experimental **KEYTRANS** greatest-version search proof (§6)
/// against a combined-tree root.
///
/// `context` is the commitment context label; `vrf_public_b64` the
/// ECVRF-Ed25519 public key; `root_b64` the 32-byte combined-tree root;
/// `label_b64` the searched label bytes; `proof_b64` the movable `tls`
/// search-proof blob (e.g. from a `Directory::search` result). Returns
/// `{ present: bool, valueB64: string | null }`; throws on any verification
/// failure.
///
/// **Experimental / movable:** these proof bytes are `KEYTRANS_EXP_04`-tagged
/// and move with `draft-ietf-keytrans-protocol`; they are deliberately *not*
/// frozen like the `key_history_v1` / CONIKS / policy-v1 vectors.
#[wasm_bindgen(js_name = "keytransVerifySearch")]
pub fn keytrans_verify_search(
    context: &str,
    vrf_public_b64: &str,
    root_b64: &str,
    label_b64: &str,
    proof_b64: &str,
) -> Result<JsValue, JsValue> {
    let verifier = keytrans_verifier(context, vrf_public_b64)?;
    let outcome = verifier
        .verify_search_bytes(&decode(root_b64)?, &decode(label_b64)?, &decode(proof_b64)?)
        .map_err(to_js)?;
    Ok(search_outcome_to_js(&outcome))
}

/// Verify an experimental KEYTRANS fixed-version search proof (§7). Same inputs
/// as [`keytrans_verify_search`]; returns `{ present, valueB64 }`.
#[wasm_bindgen(js_name = "keytransVerifyFixedVersion")]
pub fn keytrans_verify_fixed_version(
    context: &str,
    vrf_public_b64: &str,
    root_b64: &str,
    label_b64: &str,
    proof_b64: &str,
) -> Result<JsValue, JsValue> {
    let verifier = keytrans_verifier(context, vrf_public_b64)?;
    let outcome = verifier
        .verify_fixed_version_bytes(&decode(root_b64)?, &decode(label_b64)?, &decode(proof_b64)?)
        .map_err(to_js)?;
    Ok(search_outcome_to_js(&outcome))
}

/// Verify an experimental KEYTRANS monitoring proof (§8). Returns `true` if the
/// monitored version's binary ladder is all inclusions under the root; throws
/// on a downgrade or any inconsistency.
#[wasm_bindgen(js_name = "keytransVerifyMonitor")]
pub fn keytrans_verify_monitor(
    context: &str,
    vrf_public_b64: &str,
    root_b64: &str,
    label_b64: &str,
    proof_b64: &str,
) -> Result<bool, JsValue> {
    let verifier = keytrans_verifier(context, vrf_public_b64)?;
    verifier
        .verify_monitor_bytes(&decode(root_b64)?, &decode(label_b64)?, &decode(proof_b64)?)
        .map_err(to_js)
}

// --- Suite-aware variants (on-spec IETF standard suites) -------------------
//
// The functions above default to the experimental private suite
// (`0xF000`, ECVRF-Ed25519 + SHA3-512 commitment). These `*Suite` variants take
// the §15.1 `suiteId` so the browser can verify the on-spec standard suites
// (`0x0001` KT_128_SHA256_P256, `0x0002` KT_128_SHA256_Ed25519 — HMAC-SHA256
// commitment) with behaviour identical to native. Still `KEYTRANS_EXP_04` /
// movable.

/// Verify an experimental KEYTRANS greatest-version search proof (§6) under an
/// explicit §15.1 `suite_id`. Otherwise identical to [`keytrans_verify_search`].
#[wasm_bindgen(js_name = "keytransVerifySearchSuite")]
pub fn keytrans_verify_search_suite(
    suite_id: u16,
    context: &str,
    vrf_public_b64: &str,
    root_b64: &str,
    label_b64: &str,
    proof_b64: &str,
) -> Result<JsValue, JsValue> {
    let verifier = keytrans_verifier_for_suite(suite_id, context, vrf_public_b64)?;
    let outcome = verifier
        .verify_search_bytes(&decode(root_b64)?, &decode(label_b64)?, &decode(proof_b64)?)
        .map_err(to_js)?;
    Ok(search_outcome_to_js(&outcome))
}

/// Verify an experimental KEYTRANS fixed-version search proof (§7) under an
/// explicit §15.1 `suite_id`.
#[wasm_bindgen(js_name = "keytransVerifyFixedVersionSuite")]
pub fn keytrans_verify_fixed_version_suite(
    suite_id: u16,
    context: &str,
    vrf_public_b64: &str,
    root_b64: &str,
    label_b64: &str,
    proof_b64: &str,
) -> Result<JsValue, JsValue> {
    let verifier = keytrans_verifier_for_suite(suite_id, context, vrf_public_b64)?;
    let outcome = verifier
        .verify_fixed_version_bytes(&decode(root_b64)?, &decode(label_b64)?, &decode(proof_b64)?)
        .map_err(to_js)?;
    Ok(search_outcome_to_js(&outcome))
}

/// Verify an experimental KEYTRANS monitoring proof (§8) under an explicit
/// §15.1 `suite_id`.
#[wasm_bindgen(js_name = "keytransVerifyMonitorSuite")]
pub fn keytrans_verify_monitor_suite(
    suite_id: u16,
    context: &str,
    vrf_public_b64: &str,
    root_b64: &str,
    label_b64: &str,
    proof_b64: &str,
) -> Result<bool, JsValue> {
    let verifier = keytrans_verifier_for_suite(suite_id, context, vrf_public_b64)?;
    verifier
        .verify_monitor_bytes(&decode(root_b64)?, &decode(label_b64)?, &decode(proof_b64)?)
        .map_err(to_js)
}

/// Enforce **declared == observed** for an observed directory backend id/// (Slice 9e): the verified policy's declared route + suite must match the
/// backend that served a proof. `observed_backend_id` is the raw `u16` code
/// (e.g. `0x0001` CONIKS, `0xF004` KEYTRANS_EXP_04). Returns `true` on match;
/// throws on mismatch.
#[wasm_bindgen(js_name = "policyEnforceDirectoryBackend")]
pub fn policy_enforce_directory_backend(
    signed_b64: &str,
    observed_backend_id: u16,
) -> Result<bool, JsValue> {
    let policy = verified_policy(signed_b64)?;
    policy
        .enforce_directory_backend(DirectoryBackendId::from_u16(observed_backend_id))
        .map_err(to_js)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Internal helpers (logic-free marshalling only)
// ---------------------------------------------------------------------------
/// Decode a base64 string into bytes, surfacing decode errors as JS exceptions.
fn decode(s: &str) -> Result<Vec<u8>, JsValue> {
    b64::decode(s).map_err(|e| JsValue::from_str(&format!("base64 decode error: {e}")))
}

/// Decode an array of base64 strings into a Merkle proof / audit path.
fn decode_proof(proof_b64: &[String]) -> Result<Vec<Vec<u8>>, JsValue> {
    proof_b64.iter().map(|s| decode(s)).collect()
}

/// Decode a base64 string into a fixed 64-byte array (CONIKS root / commitment).
fn decode_array_64(s: &str) -> Result<[u8; 64], JsValue> {
    let v = decode(s)?;
    v.try_into()
        .map_err(|_| JsValue::from_str("expected 64 bytes"))
}

/// Decode a base64 string into a fixed 32-byte array (commitment opening).
fn decode_array_32(s: &str) -> Result<[u8; 32], JsValue> {
    let v = decode(s)?;
    v.try_into()
        .map_err(|_| JsValue::from_str("expected 32 bytes"))
}

/// Parse an array of encoded `VerifierKey` strings.
fn parse_vkeys(vkeys: &[String]) -> Result<Vec<VerifierKey>, JsValue> {
    vkeys
        .iter()
        .map(|v| VerifierKey::parse(v).map_err(to_js))
        .collect()
}

/// Build a `key_history_v1::Entry` from base64/text fields. A missing or empty
/// `prev_entry_hash` is the genesis sentinel (`None`).
fn build_entry(
    seq: u64,
    ts_ms: u64,
    enc_x25519_b64: &str,
    enc_pq_b64: &str,
    signing_pub_b64: &str,
    prev_entry_hash_b64: Option<String>,
) -> Result<Entry, JsValue> {
    let prev_entry_hash = match prev_entry_hash_b64 {
        Some(ref s) if !s.is_empty() => Some(decode(s)?),
        _ => None,
    };
    Ok(Entry {
        seq,
        ts_ms,
        enc_x25519: decode(enc_x25519_b64)?,
        enc_pq: decode(enc_pq_b64)?,
        signing_pub: decode(signing_pub_b64)?,
        prev_entry_hash,
    })
}

/// Parse a JS commitment-hash string into a [`CommitmentHash`].
fn parse_commitment_hash(s: &str) -> Result<CommitmentHash, JsValue> {
    let normalized: String = s
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    match normalized.as_str() {
        "sha3256" => Ok(CommitmentHash::Sha3_256),
        "sha3512" => Ok(CommitmentHash::Sha3_512),
        other => Err(JsValue::from_str(&format!(
            "invalid commitment hash \"{other}\": expected \"sha3_256\" or \"sha3_512\""
        ))),
    }
}

/// Parse + verify a signed policy, returning the authentic policy.
fn verified_policy(signed_b64: &str) -> Result<NamespacePolicy, JsValue> {
    let signed = SignedPolicy::parse(&decode(signed_b64)?).map_err(to_js)?;
    signed.verify().map_err(to_js)?;
    Ok(signed.policy().clone())
}

/// Normalize a JS enum tag: drop `_`/`-` separators and lowercase, so both the
/// camelCase form emitted by [`signed_policy_verify`] (`"hybridMatched"`) and a
/// snake_case form (`"hybrid_matched"`) parse identically.
fn normalize_tag(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '_' && *c != '-')
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Parse a JS security-level tag into a [`SecurityLevel`].
fn parse_security_level(s: &str) -> Result<SecurityLevel, JsValue> {
    match normalize_tag(s).as_str() {
        "cat3" => Ok(SecurityLevel::Cat3),
        "cat5" => Ok(SecurityLevel::Cat5),
        other => Err(JsValue::from_str(&format!(
            "invalid security level \"{other}\": expected \"cat3\" or \"cat5\""
        ))),
    }
}

/// Parse a JS checkpoint-suite tag into a [`CheckpointSuite`].
fn parse_checkpoint_suite(s: &str) -> Result<CheckpointSuite, JsValue> {
    match normalize_tag(s).as_str() {
        "hybrid" => Ok(CheckpointSuite::Hybrid),
        "hybridmatched" => Ok(CheckpointSuite::HybridMatched),
        "purecnsa2" => Ok(CheckpointSuite::PureCnsa2),
        other => Err(JsValue::from_str(&format!(
            "invalid checkpoint suite \"{other}\": expected \"hybrid\", \"hybridMatched\", or \"pureCnsa2\""
        ))),
    }
}

/// Parse a JS VRF-mode tag into a [`VrfMode`].
fn parse_vrf_mode(s: &str) -> Result<VrfMode, JsValue> {
    match normalize_tag(s).as_str() {
        "classical" => Ok(VrfMode::Classical),
        "hybridoutput" => Ok(VrfMode::HybridOutput),
        "purepqexperimental" => Ok(VrfMode::PurePqExperimental),
        other => Err(JsValue::from_str(&format!(
            "invalid vrf mode \"{other}\": expected \"classical\", \"hybridOutput\", or \"purePqExperimental\""
        ))),
    }
}

/// Parse a JS directory-mode tag into a [`DirectoryMode`].
fn parse_directory_mode(s: &str) -> Result<DirectoryMode, JsValue> {
    match normalize_tag(s).as_str() {
        "coniks" => Ok(DirectoryMode::Coniks),
        "keytrans" => Ok(DirectoryMode::Keytrans),
        other => Err(JsValue::from_str(&format!(
            "invalid directory mode \"{other}\": expected \"coniks\" or \"keytrans\""
        ))),
    }
}

/// Parse a JS KEYTRANS-suite tag into a [`KeytransSuite`].
fn parse_keytrans_suite(s: &str) -> Result<KeytransSuite, JsValue> {
    match normalize_tag(s).as_str() {
        "metamorphichybridexp" => Ok(KeytransSuite::MetamorphicHybridExp),
        "kt128sha256ed25519" => Ok(KeytransSuite::Kt128Sha256Ed25519),
        "kt128sha256p256" => Ok(KeytransSuite::Kt128Sha256P256),
        other => Err(JsValue::from_str(&format!(
            "invalid keytrans suite \"{other}\": expected \"metamorphicHybridExp\", \"kt128Sha256Ed25519\", or \"kt128Sha256P256\""
        ))),
    }
}

/// Build + validate a [`NamespacePolicy`] from the JS posture surface, choosing
/// the CONIKS or KEYTRANS constructor from `directory_mode`.
#[allow(clippy::too_many_arguments)]
fn build_policy(
    namespace: &str,
    policy_schema_version: u32,
    security_level: &str,
    checkpoint_suite: &str,
    commitment_hash: &str,
    vrf_mode: &str,
    directory_mode: &str,
    keytrans_suite: &str,
    effective_from: u64,
    created_at: u64,
    prev_policy_hash_b64: Option<String>,
) -> Result<NamespacePolicy, JsValue> {
    let ns = Namespace::parse(namespace).map_err(to_js)?;
    let level = parse_security_level(security_level)?;
    let cp_suite = parse_checkpoint_suite(checkpoint_suite)?;
    let commit = parse_commitment_hash(commitment_hash)?;
    let vrf = parse_vrf_mode(vrf_mode)?;
    let dir = parse_directory_mode(directory_mode)?;
    let prev_hash = match prev_policy_hash_b64 {
        Some(ref s) if !s.is_empty() => {
            let bytes = decode(s)?;
            Some(
                <[u8; 64]>::try_from(bytes.as_slice())
                    .map_err(|_| JsValue::from_str("prev_policy_hash must be 64 bytes"))?,
            )
        }
        _ => None,
    };
    match dir {
        DirectoryMode::Coniks => NamespacePolicy::new(
            ns,
            policy_schema_version,
            level,
            cp_suite,
            commit,
            vrf,
            effective_from,
            created_at,
            prev_hash,
        )
        .map_err(to_js),
        DirectoryMode::Keytrans => {
            let kt_suite = parse_keytrans_suite(keytrans_suite)?;
            NamespacePolicy::new_keytrans(
                ns,
                policy_schema_version,
                level,
                cp_suite,
                commit,
                vrf,
                effective_from,
                created_at,
                prev_hash,
                kt_suite,
            )
            .map_err(to_js)
        }
    }
}

/// Build a KEYTRANS relying-party verifier from the commitment context and the
/// ECVRF-Ed25519 public key (the experimental private suite's VRF).
fn keytrans_verifier(context: &str, vrf_public_b64: &str) -> Result<KeytransVerifier, JsValue> {
    let vrf_public = VrfPublicKey::from_bytes(decode(vrf_public_b64)?);
    Ok(KeytransVerifier::new(context, Box::new(Ecvrf), vrf_public))
}

/// Build a KEYTRANS relying-party verifier for an explicit §15.1 suite id,
/// selecting the suite's VRF and commitment width.
fn keytrans_verifier_for_suite(
    suite_id: u16,
    context: &str,
    vrf_public_b64: &str,
) -> Result<KeytransVerifier, JsValue> {
    let suite = KtSuite::from_suite_id(suite_id).map_err(to_js)?;
    let vrf_public = VrfPublicKey::from_bytes(decode(vrf_public_b64)?);
    Ok(KeytransVerifier::new_with_suite(
        context,
        suite,
        suite.vrf(),
        vrf_public,
    ))
}

/// Build the `{ present, valueB64 }` object from a verified search outcome.
fn search_outcome_to_js(outcome: &crate::directory::SearchOutcome) -> JsValue {
    use crate::directory::SearchOutcome;
    let obj = js_sys::Object::new();
    match outcome {
        SearchOutcome::Present(value) => {
            set(&obj, "present", &JsValue::TRUE);
            set(&obj, "valueB64", &b64::encode(value).into());
        }
        SearchOutcome::Absent => {
            set(&obj, "present", &JsValue::FALSE);
            set(&obj, "valueB64", &JsValue::NULL);
        }
    }
    obj.into()
}

/// Build the `{ origin, size, rootB64, extensions }` checkpoint object.
fn checkpoint_to_js(cp: &Checkpoint) -> JsValue {
    let obj = js_sys::Object::new();
    set(&obj, "origin", &cp.origin().into());
    set(&obj, "size", &(cp.size() as f64).into());
    set(&obj, "rootB64", &b64::encode(cp.root_hash()).into());
    let exts = js_sys::Array::new();
    for ext in cp.extensions() {
        exts.push(&JsValue::from_str(ext));
    }
    set(&obj, "extensions", &exts.into());
    obj.into()
}

/// Build the declared-posture object from a verified policy.
fn policy_to_js(policy: &NamespacePolicy) -> Result<JsValue, JsValue> {
    use crate::policy::{CheckpointSuite, DirectoryMode, KeytransSuite, SecurityLevel, VrfMode};

    let security_level = match policy.security_level() {
        SecurityLevel::Cat3 => "cat3",
        SecurityLevel::Cat5 => "cat5",
    };
    let checkpoint_suite = match policy.checkpoint_suite() {
        CheckpointSuite::Hybrid => "hybrid",
        CheckpointSuite::HybridMatched => "hybridMatched",
        CheckpointSuite::PureCnsa2 => "pureCnsa2",
    };
    let commitment_hash = match policy.commitment_hash() {
        CommitmentHash::Sha3_256 => "sha3_256",
        CommitmentHash::Sha3_512 => "sha3_512",
    };
    let vrf_mode = match policy.vrf_mode() {
        VrfMode::Classical => "classical",
        VrfMode::HybridOutput => "hybridOutput",
        VrfMode::PurePqExperimental => "purePqExperimental",
    };
    let directory_mode = match policy.directory_mode() {
        DirectoryMode::Coniks => "coniks",
        DirectoryMode::Keytrans => "keytrans",
    };
    let keytrans_suite = match policy.keytrans_suite() {
        KeytransSuite::MetamorphicHybridExp => "metamorphicHybridExp",
        KeytransSuite::Kt128Sha256Ed25519 => "kt128Sha256Ed25519",
        KeytransSuite::Kt128Sha256P256 => "kt128Sha256P256",
    };

    let obj = js_sys::Object::new();
    set(&obj, "namespace", &policy.namespace().as_str().into());
    set(
        &obj,
        "policySchemaVersion",
        &(policy.policy_schema_version() as f64).into(),
    );
    set(&obj, "securityLevel", &security_level.into());
    set(&obj, "checkpointSuite", &checkpoint_suite.into());
    set(&obj, "commitmentHash", &commitment_hash.into());
    set(&obj, "vrfMode", &vrf_mode.into());
    set(&obj, "directoryMode", &directory_mode.into());
    set(&obj, "keytransSuite", &keytrans_suite.into());
    set(
        &obj,
        "effectiveFrom",
        &(policy.effective_from() as f64).into(),
    );
    set(&obj, "createdAt", &(policy.created_at() as f64).into());
    set(
        &obj,
        "policyHashB64",
        &b64::encode(&policy.policy_hash().map_err(to_js)?).into(),
    );
    set(
        &obj,
        "rfc6962LeafHashB64",
        &b64::encode(&policy.rfc6962_leaf_hash()).into(),
    );
    Ok(obj.into())
}

/// Set a property on a JS object (the `Reflect::set` never fails for a plain
/// `Object`, so the error is unreachable in practice).
fn set(obj: &js_sys::Object, key: &str, value: &JsValue) {
    let _ = js_sys::Reflect::set(obj, &JsValue::from_str(key), value);
}

/// Convert a typed [`crate::Error`] into a thrown JS `Error`.
fn to_js(e: crate::Error) -> JsValue {
    JsValue::from_str(&e.to_string())
}
