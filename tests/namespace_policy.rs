//! Slice 5 (#333) per-namespace `NamespacePolicy` + declared == observed suite.
//!
//! Everything runs through the crate's **public API** (the #316 bar):
//!
//! 1. **KAT vectors** — fixed key material locks the canonical policy bytes, the
//!    deterministic verifying key, and the deterministic `policy_hash`; a
//!    *stored* signed policy (ML-DSA signing is hedged, so the signature bytes
//!    are captured once and **verification** is locked) parses and verifies its
//!    own composite signature byte-for-byte, while a tampered body is rejected.
//!
//! 2. **Declared == observed** — a policy enforces its declared posture against
//!    an observed checkpoint signing key / signature (via the metamorphic-crypto
//!    v0.8.1 posture accessors) and the Slice-4 CONIKS VRF suite id; a downgrade
//!    or mismatch is a hard rejection.
//!
//! 3. **Property tests** — canonical round-trip, signed verify accept/reject,
//!    legal/illegal migration, declared==observed accept/reject across real
//!    per-(Suite,Level) keypairs, and cross-namespace/version rejection.

#![cfg(not(target_arch = "wasm32"))]

use metamorphic_crypto::{
    SIGN_CONTEXT_V1, SignatureLevel, Suite, generate_signing_keypair_suite, sign, signature_posture,
};
use metamorphic_log::coniks::Namespace;
use metamorphic_log::error::Error;
use metamorphic_log::policy::{
    CheckpointSuite, CommitmentHash, NamespacePolicy, ObservedPosture, PolicyChain, SecurityLevel,
    SignedPolicy, VrfMode,
};
use metamorphic_log::vrf::{Ecvrf, Vrf};
use proptest::prelude::*;

// ===========================================================================
// 1. KAT vectors (fixed key material)
// ===========================================================================

/// Hybrid Cat-3 secret key built from fixed seeds (same fixture as the Slice-3
/// checkpoint KAT): base64 of `0x02 || [0x11; 32] || [0x22; 32]`.
const KAT_SK: &str =
    "AhERERERERERERERERERERERERERERERERERERERERERIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";

/// The deterministic composite verifying key (base64) for [`KAT_SK`].
/// `derive_public_key` is deterministic, so this is stable.
const KAT_PK_B64: &str = "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";

/// The deterministic 64-byte `policy_hash` (hex) of the KAT genesis policy.
const KAT_POLICY_HASH_HEX: &str = "e025dd924f7fb976d3283c48b7c3cf9573eaca158f4772205f43586aae64dbe38c2a3df75de681610ca602ab802dc60306a1398e7591640bf16d3ea6ae8d2e97";

/// The canonical bytes (hex) of the KAT genesis policy. Locks the byte layout.
const KAT_POLICY_CANONICAL_HEX: &str = "000000010000000f6d6574616d6f72706869632e617070000000010301010100000000000000000000018bcfe5680000000000";

/// A captured signed policy (base64 of its canonical envelope) over the KAT
/// policy under [`KAT_SK`]. ML-DSA is hedged, so the *signature bytes* are not
/// reproducible — this fixture locks **verification** (and the deterministic
/// verifying key + canonical policy bytes), exactly per the slice's KAT rule.
const KAT_SIGNED_B64: &str = include_str!("vectors/namespace_policy_signed.b64");

fn kat_namespace() -> Namespace {
    Namespace::parse("metamorphic.app").unwrap()
}

fn kat_policy() -> NamespacePolicy {
    NamespacePolicy::genesis(
        kat_namespace(),
        SecurityLevel::Cat3,
        CheckpointSuite::Hybrid,
        0,
        1_700_000_000_000,
    )
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn kat_canonical_bytes_and_policy_hash_are_locked() {
    let p = kat_policy();
    assert_eq!(hex(&p.canonical_bytes()), KAT_POLICY_CANONICAL_HEX);
    assert_eq!(hex(&p.policy_hash().unwrap()), KAT_POLICY_HASH_HEX);

    // Parse-from-canonical reproduces the policy byte-for-byte.
    assert_eq!(NamespacePolicy::parse(&p.canonical_bytes()).unwrap(), p);
}

#[test]
fn kat_verifying_key_is_deterministic() {
    // The fixed secret key derives the pinned verifying key byte-for-byte.
    assert_eq!(
        metamorphic_crypto::derive_public_key(KAT_SK).unwrap(),
        KAT_PK_B64
    );
}

#[test]
fn kat_signed_policy_parses_and_verifies() {
    let bytes = metamorphic_crypto::b64::decode(KAT_SIGNED_B64.trim()).unwrap();
    let signed = SignedPolicy::parse(&bytes).unwrap();

    // The stored signed policy verifies its own composite signature...
    let policy = signed.verify().unwrap();
    assert_eq!(*policy, kat_policy());
    // ...carries the pinned root key...
    assert_eq!(
        metamorphic_crypto::b64::encode(signed.signing_public_key()),
        KAT_PK_B64
    );
    // ...and re-serializes byte-for-byte.
    assert_eq!(
        metamorphic_crypto::b64::encode(&signed.canonical_bytes()),
        KAT_SIGNED_B64.trim()
    );
}

#[test]
fn kat_signed_policy_rejects_tampered_body() {
    let bytes = metamorphic_crypto::b64::decode(KAT_SIGNED_B64.trim()).unwrap();
    let signed = SignedPolicy::parse(&bytes).unwrap();

    // Forge a different policy (Cat5) but keep the captured signature: verify
    // fails because the signature does not cover these bytes.
    let forged = SignedPolicy::from_parts(
        NamespacePolicy::genesis(
            kat_namespace(),
            SecurityLevel::Cat5,
            CheckpointSuite::Hybrid,
            0,
            1_700_000_000_000,
        )
        .unwrap(),
        signed.signing_public_key().to_vec(),
        signed.signature().to_vec(),
    );
    assert!(matches!(
        forged.verify(),
        Err(Error::InvalidSignature { .. })
    ));
}

// ===========================================================================
// 2. Declared == observed (headline)
// ===========================================================================

#[test]
fn declared_equals_observed_against_checkpoint_key() {
    // The KAT policy declares Hybrid/Cat3; the KAT signing key IS Hybrid/Cat3,
    // so enforcement accepts. (Independent confirmation via the accessor.)
    let p = kat_policy();
    assert_eq!(
        signature_posture(KAT_PK_B64).unwrap(),
        (Suite::Hybrid, SignatureLevel::Cat3)
    );
    assert!(p.enforce_checkpoint_signing_key(KAT_PK_B64).is_ok());

    // A policy declaring Cat5 must hard-reject the observed Cat3 key (downgrade).
    let cat5 = NamespacePolicy::genesis(
        kat_namespace(),
        SecurityLevel::Cat5,
        CheckpointSuite::Hybrid,
        0,
        0,
    )
    .unwrap();
    assert!(matches!(
        cat5.enforce_checkpoint_signing_key(KAT_PK_B64),
        Err(Error::PostureMismatch { .. })
    ));
}

#[test]
fn declared_equals_observed_against_coniks_vrf_suite() {
    // The default CONIKS VRF is classical ECVRF (suite 0x03); a Classical-mode
    // policy accepts it, and any other observed suite is a hard rejection.
    let p = kat_policy();
    assert_eq!(p.vrf_mode(), VrfMode::Classical);
    assert!(p.enforce_vrf_suite_id(Ecvrf.suite_id()).is_ok());
    assert!(matches!(
        p.enforce_vrf_suite_id(0x04),
        Err(Error::PostureMismatch { .. })
    ));
}

#[test]
fn enforce_observed_combined_axes() {
    let p = kat_policy();
    let good = ObservedPosture {
        checkpoint: (Suite::Hybrid, SignatureLevel::Cat3),
        vrf_suite_id: Ecvrf.suite_id(),
        commitment_hash: CommitmentHash::Sha3_256,
    };
    assert!(p.enforce_observed(&good).is_ok());

    // Any single axis disagreeing fails the whole check.
    let bad_commit = ObservedPosture {
        commitment_hash: CommitmentHash::Sha3_512,
        ..good.clone()
    };
    assert!(matches!(
        p.enforce_observed(&bad_commit),
        Err(Error::PostureMismatch { .. })
    ));
}

#[test]
fn declared_equals_observed_across_real_keypairs() {
    // For each legal (Suite, Level) we generate a real keypair, declare a policy
    // for it, and confirm declared == observed accepts; a mismatched declaration
    // rejects. This locks the contract end-to-end through real key material.
    let cases = [
        (
            Suite::Hybrid,
            SignatureLevel::Cat3,
            CheckpointSuite::Hybrid,
            SecurityLevel::Cat3,
        ),
        (
            Suite::Hybrid,
            SignatureLevel::Cat5,
            CheckpointSuite::Hybrid,
            SecurityLevel::Cat5,
        ),
        (
            Suite::HybridMatched,
            SignatureLevel::Cat3,
            CheckpointSuite::HybridMatched,
            SecurityLevel::Cat3,
        ),
        (
            Suite::HybridMatched,
            SignatureLevel::Cat5,
            CheckpointSuite::HybridMatched,
            SecurityLevel::Cat5,
        ),
        (
            Suite::PureCnsa2,
            SignatureLevel::Cat5,
            CheckpointSuite::PureCnsa2,
            SecurityLevel::Cat5,
        ),
    ];

    for (suite, level, ck_suite, sec_level) in cases {
        let kp = generate_signing_keypair_suite(suite, level).unwrap();
        let policy = NamespacePolicy::genesis(kat_namespace(), sec_level, ck_suite, 0, 0).unwrap();

        // Accept: declared posture == observed key posture.
        policy
            .enforce_checkpoint_signing_key(&kp.public_key)
            .unwrap();

        // Accept: and via an observed signature too.
        let sig = sign(b"checkpoint body", SIGN_CONTEXT_V1, &kp.secret_key).unwrap();
        policy.enforce_checkpoint_signature(&sig).unwrap();

        // Reject: a Hybrid/Cat3 declaration must reject anything that is not
        // exactly Hybrid/Cat3.
        let strict = NamespacePolicy::genesis(
            kat_namespace(),
            SecurityLevel::Cat3,
            CheckpointSuite::Hybrid,
            0,
            0,
        )
        .unwrap();
        let expected_match = suite == Suite::Hybrid && level == SignatureLevel::Cat3;
        assert_eq!(
            strict
                .enforce_checkpoint_signing_key(&kp.public_key)
                .is_ok(),
            expected_match
        );
    }
}

// ===========================================================================
// 3. Migration
// ===========================================================================

#[test]
fn legal_and_illegal_migrations() {
    let ns = kat_namespace();
    let g = NamespacePolicy::genesis(
        ns.clone(),
        SecurityLevel::Cat3,
        CheckpointSuite::Hybrid,
        0,
        0,
    )
    .unwrap();
    let mut chain = PolicyChain::genesis(g.clone()).unwrap();

    // Legal: strengthen Cat3 -> Cat5 with a correct chain link + new epoch.
    let v2 = NamespacePolicy::new(
        ns.clone(),
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
    assert_eq!(chain.latest().policy_schema_version(), 2);

    // Illegal: weaken back to Cat3.
    let weaken = NamespacePolicy::new(
        ns.clone(),
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
        chain.push(weaken),
        Err(Error::PolicyMigrationRejected(_))
    ));

    // Illegal: cross-namespace migration.
    let cross = NamespacePolicy::new(
        Namespace::parse("evil").unwrap(),
        3,
        SecurityLevel::Cat5,
        CheckpointSuite::Hybrid,
        CommitmentHash::Sha3_512,
        VrfMode::Classical,
        300,
        3,
        Some(v2.policy_hash().unwrap()),
    )
    .unwrap();
    assert!(matches!(
        chain.push(cross),
        Err(Error::PolicyMigrationRejected(_))
    ));
}

// ===========================================================================
// 4. Property tests
// ===========================================================================

prop_compose! {
    fn arb_policy()(
        ns in "[a-z][a-z0-9.-]{0,12}",
        level in prop::sample::select(vec![SecurityLevel::Cat3, SecurityLevel::Cat5]),
        suite in prop::sample::select(vec![
            CheckpointSuite::Hybrid,
            CheckpointSuite::HybridMatched,
            CheckpointSuite::PureCnsa2,
        ]),
        effective_from in any::<u64>(),
        created_at in any::<u64>(),
    ) -> Option<NamespacePolicy> {
        let namespace = Namespace::parse(&ns).ok()?;
        // PureCnsa2 is Cat-5 only; skip the illegal combination.
        NamespacePolicy::genesis(namespace, level, suite, effective_from, created_at).ok()
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// canonical_bytes → parse → canonical_bytes is the identity.
    #[test]
    fn canonical_round_trip(p in arb_policy()) {
        prop_assume!(p.is_some());
        let p = p.unwrap();
        let bytes = p.canonical_bytes();
        let parsed = NamespacePolicy::parse(&bytes).unwrap();
        prop_assert_eq!(&parsed, &p);
        prop_assert_eq!(parsed.canonical_bytes(), bytes);
    }

    /// A signed policy verifies, and any change to the policy body is rejected.
    #[test]
    fn signed_verify_accept_reject(p in arb_policy()) {
        prop_assume!(p.is_some());
        let p = p.unwrap();
        let kp = metamorphic_crypto::generate_signing_keypair(); // Hybrid Cat-3
        let signed = SignedPolicy::sign(p.clone(), &kp.secret_key).unwrap();
        prop_assert!(signed.verify().is_ok());

        // Tamper: re-wrap a different epoch under the same captured signature.
        let other = NamespacePolicy::new(
            p.namespace().clone(),
            p.policy_schema_version(),
            p.security_level(),
            p.checkpoint_suite(),
            p.commitment_hash(),
            p.vrf_mode(),
            p.effective_from().wrapping_add(1),
            p.created_at(),
            p.prev_policy_hash().copied(),
        ).unwrap();
        let forged = SignedPolicy::from_parts(other, signed.signing_public_key().to_vec(), signed.signature().to_vec());
        let rejected = matches!(forged.verify(), Err(Error::InvalidSignature { .. }));
        prop_assert!(rejected);
    }

    /// declared == observed accepts a matching checkpoint key and rejects a
    /// mismatched declaration, over real keypairs.
    #[test]
    fn declared_observed_accept_reject(level in prop::sample::select(vec![SignatureLevel::Cat3, SignatureLevel::Cat5])) {
        let kp = generate_signing_keypair_suite(Suite::Hybrid, level).unwrap();
        let sec_level = match level {
            SignatureLevel::Cat3 => SecurityLevel::Cat3,
            SignatureLevel::Cat5 => SecurityLevel::Cat5,
            SignatureLevel::Cat2 => unreachable!(),
        };
        let matching = NamespacePolicy::genesis(kat_namespace(), sec_level, CheckpointSuite::Hybrid, 0, 0).unwrap();
        prop_assert!(matching.enforce_checkpoint_signing_key(&kp.public_key).is_ok());

        let other_level = match sec_level {
            SecurityLevel::Cat3 => SecurityLevel::Cat5,
            SecurityLevel::Cat5 => SecurityLevel::Cat3,
        };
        let mismatched = NamespacePolicy::genesis(kat_namespace(), other_level, CheckpointSuite::Hybrid, 0, 0).unwrap();
        let rejected = matches!(
            mismatched.enforce_checkpoint_signing_key(&kp.public_key),
            Err(Error::PostureMismatch { .. })
        );
        prop_assert!(rejected);
    }
}
