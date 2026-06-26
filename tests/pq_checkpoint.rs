//! Slice 3 (#331) additive hybrid post-quantum checkpoint signing/verify suite.
//!
//! Exercises everything through the crate's **public API** (the #316 bar: a
//! wrapper that can't independently recompute is not a verifier):
//!
//! 1. **Hybrid KAT vectors** — a deterministic composite verifier key (derived
//!    from fixed seeds; `derive_public_key` is deterministic) parses, reports
//!    its `(Suite, SecurityLevel)` posture tag, and re-encodes byte-for-byte;
//!    and a *stored* signed checkpoint note (ML-DSA signing is hedged, so the
//!    signature bytes are captured once and **verification** is locked) parses,
//!    verifies via the composite strict-AND primitive, and wires to the Slice-1
//!    verifier — while tampering and cross-type confusion are rejected.
//!
//! 2. **Property tests** — composite sign↔verify accept/reject, multi-line
//!    notes carrying both a classical Ed25519 line and a hybrid PQ line, and
//!    cross-type confusion (a hybrid line is ignored by a classical-only
//!    verifier, never mis-accepted).

use metamorphic_log::checkpoint::Checkpoint;
use metamorphic_log::error::Error;
use metamorphic_log::note::{
    HYBRID_SIG_IDENTIFIER, SignatureType, SignedNote, VerifierKey, sign_ed25519, sign_hybrid,
};
use proptest::prelude::*;

// ===========================================================================
// 1. Hybrid composite KAT vectors (deterministic key material)
// ===========================================================================

/// Hybrid Cat-3 secret key built from fixed seeds: base64 of
/// `0x02 || [0x11; 32] (ed25519 seed) || [0x22; 32] (ml-dsa seed)`.
const HYBRID_KAT_SK: &str =
    "AhERERERERERERERERERERERERERERERERERERERERERIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";

/// The deterministic verifier key (`vkey`) for [`HYBRID_KAT_SK`]. The public key
/// is derived deterministically from the secret key, so this string is stable.
const HYBRID_KAT_VKEY: &str = "metamorphic.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";

/// The checkpoint body the KAT note commits to.
const HYBRID_KAT_BODY: &str =
    "metamorphic.app/kat\n10\nq1bnDR7DLfXk0sCC5tD4hbsBLg7p+9Gd4tT8H9wYnKE=\n";

/// A captured signed checkpoint note (base64 of its full wire bytes) carrying a
/// single hybrid composite line over [`HYBRID_KAT_BODY`]. Locks the note-line
/// byte layout: this exact note MUST verify under [`HYBRID_KAT_VKEY`].
const HYBRID_KAT_NOTE_B64: &str = include_str!("vectors/hybrid_kat_note.b64");

fn kat_note() -> String {
    String::from_utf8(metamorphic_crypto::b64::decode(HYBRID_KAT_NOTE_B64.trim()).unwrap()).unwrap()
}

#[test]
fn hybrid_vkey_parses_reports_posture_and_round_trips() {
    let vkey = VerifierKey::parse(HYBRID_KAT_VKEY).unwrap();
    assert_eq!(vkey.name(), "metamorphic.app/kat");
    assert_eq!(vkey.signature_type(), SignatureType::MetamorphicHybrid);
    // Hybrid Cat-3 composite => leading posture tag 0x02 (mirrors #312).
    assert_eq!(vkey.hybrid_posture_tag(), Some(0x02));
    // The carried public key begins with the composite tag and is the full
    // metamorphic-crypto public-key material.
    assert_eq!(vkey.public_key().first(), Some(&0x02));
    // Byte-for-byte vkey round trip across the multi-byte 0xff type identifier.
    assert_eq!(vkey.encode(), HYBRID_KAT_VKEY);
}

#[test]
fn hybrid_kat_vkey_derives_deterministically_from_secret_key() {
    // `derive_public_key` is deterministic, so the fixed secret key reproduces
    // the pinned verifier key byte-for-byte (locks the key-id + vkey encoding).
    let pk_b64 = metamorphic_crypto::derive_public_key(HYBRID_KAT_SK).unwrap();
    let pk = metamorphic_crypto::b64::decode(&pk_b64).unwrap();
    let vkey = VerifierKey::new_hybrid("metamorphic.app/kat", &pk).unwrap();
    assert_eq!(vkey.encode(), HYBRID_KAT_VKEY);
}

#[test]
fn hybrid_kat_note_parses_verifies_and_wires_to_verifier() {
    let vkey = VerifierKey::parse(HYBRID_KAT_VKEY).unwrap();
    let note = kat_note();

    // The stored note verifies via the composite strict-AND primitive...
    let parsed = SignedNote::parse(&note).unwrap();
    assert_eq!(parsed.verify(std::slice::from_ref(&vkey)).unwrap().len(), 1);
    // ...and re-serializes byte-for-byte.
    assert_eq!(parsed.marshal(), note);

    // The checkpoint body parses and equals the committed head, and the signed
    // note round-trips through the higher-level checkpoint API.
    let cp = Checkpoint::from_signed_note(&note, &[vkey]).unwrap();
    assert_eq!(cp.marshal(), HYBRID_KAT_BODY);
    assert_eq!(cp.origin(), "metamorphic.app/kat");
    assert_eq!(cp.size(), 10);
}

#[test]
fn hybrid_kat_note_rejects_tamper_and_unknown_keys() {
    let vkey = VerifierKey::parse(HYBRID_KAT_VKEY).unwrap();
    let note = kat_note();
    let parsed = SignedNote::parse(&note).unwrap();

    // Forge a different body but keep the captured signatures: strict-AND fails.
    let forged = SignedNote::new(
        "metamorphic.app/kat\n11\nq1bnDR7DLfXk0sCC5tD4hbsBLg7p+9Gd4tT8H9wYnKE=\n".to_string(),
        parsed.signatures().to_vec(),
    )
    .unwrap();
    assert!(matches!(
        forged.verify(&[vkey]),
        Err(Error::InvalidSignature { .. })
    ));

    // An empty/unrelated trust set ignores the hybrid line entirely.
    assert!(matches!(parsed.verify(&[]), Err(Error::NoTrustedSignature)));
}

#[test]
fn hybrid_identifier_is_the_0xff_escape() {
    // The on-the-wire type identifier MUST use the C2SP 0xff escape with a
    // longer namespaced label (never an assigned/reserved single byte).
    assert_eq!(HYBRID_SIG_IDENTIFIER.first(), Some(&0xff));
    assert_eq!(
        &HYBRID_SIG_IDENTIFIER[1..],
        b"metamorphic.app/composite-mldsa-ed25519/v1"
    );
}

// ===========================================================================
// 2. Property tests
// ===========================================================================

/// Note text: non-empty, ends in newline, no forbidden control characters.
fn note_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 ./:_-]{1,120}".prop_map(|s| format!("{s}\n"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// A freshly signed hybrid note verifies, and any change to the text is
    /// rejected by the composite strict-AND verifier.
    #[test]
    fn hybrid_sign_verify_accepts_and_rejects_tamper(text in note_text()) {
        let kp = metamorphic_crypto::generate_signing_keypair(); // Hybrid Cat-3
        let pk = metamorphic_crypto::b64::decode(&kp.public_key).unwrap();
        let vkey = VerifierKey::new_hybrid("metamorphic.app/p", &pk).unwrap();

        let sig = sign_hybrid(&text, "metamorphic.app/p", &kp.secret_key).unwrap();
        let note = SignedNote::new(text.clone(), vec![sig.clone()]).unwrap();
        prop_assert_eq!(note.verify(std::slice::from_ref(&vkey)).unwrap().len(), 1);

        let tampered = SignedNote::new(format!("x{text}"), vec![sig]).unwrap();
        let rejected = matches!(
            tampered.verify(&[vkey]),
            Err(Error::InvalidSignature { .. })
        );
        prop_assert!(rejected);
    }

    /// A note co-signed by a classical Ed25519 line AND a hybrid PQ line:
    /// a classical-only verifier accepts via Ed25519 and IGNORES the unknown PQ
    /// line; a PQ-aware verifier with both keys accepts both.
    #[test]
    fn classical_and_hybrid_coexist_no_confusion(text in note_text()) {
        let (seed, ed_pk) = metamorphic_crypto::ed25519_generate_keypair();
        let kp = metamorphic_crypto::generate_signing_keypair();
        let pq_pk = metamorphic_crypto::b64::decode(&kp.public_key).unwrap();

        let ed_sig = sign_ed25519(&text, "log/ed", &seed).unwrap();
        let pq_sig = sign_hybrid(&text, "log/pq", &kp.secret_key).unwrap();
        let note = SignedNote::new(text, vec![ed_sig, pq_sig]).unwrap();

        let ed_vkey = VerifierKey::new_ed25519("log/ed", &ed_pk).unwrap();
        let pq_vkey = VerifierKey::new_hybrid("log/pq", &pq_pk).unwrap();

        // Classical-only verifier: exactly one verified signature (the Ed25519
        // one); the hybrid line is an unknown key and is ignored, not accepted.
        prop_assert_eq!(note.verify(std::slice::from_ref(&ed_vkey)).unwrap().len(), 1);
        // Both keys trusted: both lines verify.
        prop_assert_eq!(note.verify(&[ed_vkey, pq_vkey]).unwrap().len(), 2);
    }
}
