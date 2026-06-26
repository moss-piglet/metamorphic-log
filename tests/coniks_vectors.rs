//! Slice 4 (#332) known-answer & reference vectors for the CONIKS index-privacy
//! layer: the swappable VRF ([`metamorphic_log::vrf`]), SHA3-512 commitments
//! ([`metamorphic_log::commitment`]), and the per-namespace directory with
//! lookup/absence proofs ([`metamorphic_log::coniks`]).
//!
//! These lock the **byte discipline** the same way the Slice 1/2/3 conformance
//! vectors do: a regression in any hash framing, the VRF wiring, the index
//! derivation, or the empty-tree construction changes a pinned constant and
//! fails here.
//!
//! Note on determinism (mirrors the Slice-3 hybrid-signature note): the
//! classical ECVRF-TAI proof is fully deterministic, so the VRF proof, output,
//! and derived index are pinned byte-for-byte. Commitments are deterministic for
//! a *fixed opening*, so a fixed-opening commitment is pinned; freshly created
//! commitments use a random opening (hiding) and are therefore verified, not
//! byte-pinned. A directory built with random openings has a non-reproducible
//! root, so end-to-end coverage pins the deterministic empty-directory root and
//! otherwise verifies serialized proofs round-trip and check out.

use metamorphic_log::commitment::{Opening, commit_with_opening, verify_commitment};
use metamorphic_log::coniks::{
    AbsenceProof, ConiksDirectory, LookupProof, LookupResult, Namespace, verify_absence,
    verify_lookup,
};
use metamorphic_log::vrf::{Ecvrf, Vrf, VrfOutput, VrfSecretKey, hybrid_output};

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The classical VRF, driven through the [`Vrf`] trait, reproduces RFC 9381
/// Appendix B.3 Example 16 (ECVRF-edwards25519-SHA512-TAI) byte-for-byte. This
/// proves the trait/opaque-byte plumbing preserves the audited primitive's
/// exact output, and pins the index derivation (first 32 bytes of `beta`).
#[test]
fn vrf_trait_reproduces_rfc9381_example_16() {
    let vrf = Ecvrf;
    let sk = VrfSecretKey::from_bytes(hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));

    let pi = vrf.prove(&sk, b"").unwrap();
    assert_eq!(
        pi.as_bytes(),
        &hex(
            "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f\
             26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab126\
             8a1b0db10836d9826a528ca76567805"
        )[..],
        "VRF proof (pi)"
    );

    let beta = vrf.proof_to_output(&pi).unwrap();
    assert_eq!(
        beta.as_bytes().as_slice(),
        &hex(
            "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff\
             66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"
        )[..],
        "VRF output (beta)"
    );

    // The CONIKS tree index is the first 32 bytes of beta, MSB-first.
    assert_eq!(
        &beta.index()[..],
        &hex("90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff")[..],
        "derived 256-bit index"
    );
}

/// The designed-in hybrid VRF output combiner is pinned to its documented
/// framing `SHA3-512_with_context(DST, classical(64) || pq(64))`. (No PQ VRF
/// exists yet; this locks the combiner's wire format in advance.)
#[test]
fn hybrid_output_combiner_vector() {
    let classical = VrfOutput::from_bytes([0x11; 64]);
    let pq = VrfOutput::from_bytes([0x22; 64]);
    // Pinned constant: a regression in the DST or framing changes this.
    assert_eq!(
        hybrid_output(&classical, &pq).as_bytes().as_slice(),
        &hex(
            "3a81b05f400f86888e81dfc6d6e6da945a51db6dc84a99aa9b328ea901a26c00\
             f137ce27915b73366e1e056d0ed06f0f6bdc35d8d14ff7e0d6dad3f1d5157f56"
        )[..],
    );
}

/// A SHA3-512 commitment with a *fixed* opening is deterministic and pinned to
/// its documented framing, including the per-namespace context label.
#[test]
fn commitment_fixed_opening_vector() {
    let opening = Opening::from_bytes([7u8; 32]);
    let commitment = commit_with_opening("mosslet/coniks-commitment/v1", b"value-bytes", &opening);
    assert_eq!(
        commitment.as_bytes().as_slice(),
        &hex(
            "21d390c8041326c07dcca27f95e49cffc1bab834b71059f9421711b4785cda58\
             79d6132c6df9eb736128f815854adad599859c4e2d2b20e26d30b2227663bf80"
        )[..],
    );
    // And it opens.
    assert!(
        verify_commitment(
            "mosslet/coniks-commitment/v1",
            &commitment,
            b"value-bytes",
            &opening
        )
        .is_ok()
    );
}

/// The empty-directory root for a namespace depends only on the namespace's
/// (fixed) empty/node labels, so it is deterministic and pinned. This locks the
/// empty-subtree default construction up the full depth-256 tree.
#[test]
fn empty_directory_root_vector() {
    let d = ConiksDirectory::new(Namespace::parse("mosslet").unwrap(), Box::new(Ecvrf));
    assert_eq!(
        &d.root()[..],
        &hex(
            "23375b6c5fff8ccca0e9b7baccc36d4441b1890e38c3e6c1852ae81a25b193d1\
             b2af993cb1920263a1eced68da61ffe41548684917a0e0b883927b3adbff6d13"
        )[..],
    );
}

/// End-to-end reference flow: build a small directory, then prove and
/// independently verify both a present and an absent identity — including a
/// full serialize → parse → verify round-trip, the property an external SDK
/// relies on (#316).
#[test]
fn reference_directory_present_and_absent_roundtrip() {
    let mut d = ConiksDirectory::new(Namespace::parse("mosslet").unwrap(), Box::new(Ecvrf));
    d.insert(b"alice@example.com", b"key-history-head-A")
        .unwrap();
    d.insert(b"bob@example.com", b"key-history-head-B").unwrap();
    let root = d.root();

    // Present: serialize, reparse, verify, and recover the exact value.
    let LookupResult::Present(present) = d.lookup(b"alice@example.com").unwrap() else {
        panic!("alice present");
    };
    let present = LookupProof::from_bytes(&present.to_bytes()).unwrap();
    let value = verify_lookup(
        &Ecvrf,
        d.namespace(),
        d.vrf_public_key(),
        &root,
        b"alice@example.com",
        &present,
    )
    .unwrap();
    assert_eq!(value, b"key-history-head-A");

    // Absent: serialize, reparse, verify.
    let LookupResult::Absent(absent) = d.lookup(b"carol@example.com").unwrap() else {
        panic!("carol absent");
    };
    let absent = AbsenceProof::from_bytes(&absent.to_bytes()).unwrap();
    verify_absence(
        &Ecvrf,
        d.namespace(),
        d.vrf_public_key(),
        &root,
        b"carol@example.com",
        &absent,
    )
    .unwrap();
}
