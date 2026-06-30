//! Slice 6 (#335) **cross-language byte-parity KAT** — Rust core ↔ WASM.
//!
//! These tests exercise the `wasm-bindgen` exports in [`metamorphic_log::wasm`]
//! against the **same** locked known-answer vectors the native suites use
//! (`tests/conformance.rs`, `tests/pq_checkpoint.rs`, `tests/coniks_vectors.rs`,
//! `tests/namespace_policy.rs`). Because the WASM layer is a logic-free shell
//! over the rlib, reproducing those vectors byte-identically *through the WASM
//! boundary* is the cross-language byte-parity proof: the browser
//! verification/monitor SDK computes exactly what the native core computes.
//!
//! Run with `wasm-pack test --node` (the CI cross-language-KAT job). ML-DSA
//! signing is hedged, so — exactly as in the native suites — we lock
//! *verification* and the deterministic vkey/canonical bytes, never regenerated
//! signature bytes.
#![cfg(target_arch = "wasm32")]

use metamorphic_log::wasm::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

// Mirror of `tests/conformance.rs` fixed key material (identical generators), so
// the WASM leaf hashes must match the locked Elixir/native KAT byte-for-byte.
const KAT_GENESIS_HASH_B64: &str =
    "ueTkShE9EQ1ROe8DFVa0m706AJPrsJyLGt2uSSzmStPty0xtu3gX2zjvBNdgA9swPWYEXx+wEsjDNXbOmzhJFA==";
const KAT_GENESIS_RFC6962_LEAF_HEX: &str =
    "a429552cdc9dba9b9bc733d2afe0e1beb5f5100184ea8416179dd0d4fd864263";
const GENESIS_TS: u64 = 1_700_000_000_000;

// Mirror of `tests/pq_checkpoint.rs`.
const HYBRID_KAT_SK: &str =
    "AhERERERERERERERERERERERERERERERERERERERERERIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";
const HYBRID_KAT_NOTE_B64: &str = include_str!("vectors/hybrid_kat_note.b64");

// Mirror of `tests/namespace_policy.rs`.
const KAT_POLICY_HASH_HEX: &str = "e025dd924f7fb976d3283c48b7c3cf9573eaca158f4772205f43586aae64dbe38c2a3df75de681610ca602ab802dc60306a1398e7591640bf16d3ea6ae8d2e97";
const KAT_SIGNED_B64: &str = include_str!("vectors/namespace_policy_signed.b64");

// Mirror of `tests/coniks_vectors.rs` fixed-opening commitment vector.
const COMMITMENT_CTX: &str = "mosslet/coniks-commitment/v1";
const COMMITMENT_VEC_HEX: &str = "21d390c8041326c07dcca27f95e49cffc1bab834b71059f9421711b4785cda58\
                                  79d6132c6df9eb736128f815854adad599859c4e2d2b20e26d30b2227663bf80";

wasm_bindgen_test_configure!(run_in_node_experimental);

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

fn b64(bytes: &[u8]) -> String {
    metamorphic_crypto::b64::encode(bytes)
}

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn get_str(obj: &JsValue, key: &str) -> String {
    js_sys::Reflect::get(obj, &JsValue::from_str(key))
        .unwrap()
        .as_string()
        .unwrap()
}

fn get_f64(obj: &JsValue, key: &str) -> f64 {
    js_sys::Reflect::get(obj, &JsValue::from_str(key))
        .unwrap()
        .as_f64()
        .unwrap()
}

// Generators identical to tests/conformance.rs genesis_entry().
fn x_a() -> Vec<u8> {
    (0u32..32).map(|i| ((i * 7 + 1) % 256) as u8).collect()
}
fn pq_a() -> Vec<u8> {
    (0u32..1600).map(|i| (i % 256) as u8).collect()
}
fn sp_fixed() -> Vec<u8> {
    (0u32..2625).map(|i| ((i * 3) % 256) as u8).collect()
}

// RFC 6962 8-leaf inclusion vector (idx 0, size 8) from the transparency-dev corpus.
const ROOT8_B64: &str = "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=";
const LEAF0_B64: &str = "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=";
fn proof0_8() -> Vec<String> {
    vec![
        "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=".into(),
        "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=".into(),
        "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ=".into(),
    ]
}

// --------------------------------------------------------------------------
// 1. RFC 6962 inclusion + consistency (verification + monitor core)
// --------------------------------------------------------------------------

#[wasm_bindgen_test]
fn wasm_verify_inclusion_matches_reference_vector() {
    assert!(verify_inclusion_wasm(0, 8, LEAF0_B64, proof0_8(), ROOT8_B64).unwrap());
}

#[wasm_bindgen_test]
fn wasm_verify_inclusion_rejects_tampered_root() {
    let mut root = metamorphic_crypto::b64::decode(ROOT8_B64).unwrap();
    root[0] ^= 0x01;
    assert!(verify_inclusion_wasm(0, 8, LEAF0_B64, proof0_8(), &b64(&root)).is_err());
}

#[wasm_bindgen_test]
fn wasm_verify_consistency_matches_reference_vector() {
    // size 1 -> 8 consistency vector.
    let root1 = "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=";
    assert!(verify_consistency_wasm(1, 8, proof0_8(), root1, ROOT8_B64).unwrap());
}

#[wasm_bindgen_test]
fn wasm_verify_consistency_rejects_equivocation() {
    let root1 = "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=";
    let mut bad = metamorphic_crypto::b64::decode(ROOT8_B64).unwrap();
    bad[0] ^= 0x01;
    assert!(verify_consistency_wasm(1, 8, proof0_8(), root1, &b64(&bad)).is_err());
}

// --------------------------------------------------------------------------
// 2. Layer-0 canonical leaf: mosslet/key-history/v1 byte parity
// --------------------------------------------------------------------------

#[wasm_bindgen_test]
fn wasm_key_history_v1_entry_hash_matches_native_kat() {
    let got = key_history_v1_entry_hash(
        0,
        GENESIS_TS,
        &b64(&x_a()),
        &b64(&pq_a()),
        &b64(&sp_fixed()),
        None,
    )
    .unwrap();
    assert_eq!(got, KAT_GENESIS_HASH_B64);
}

#[wasm_bindgen_test]
fn wasm_key_history_v1_rfc6962_leaf_hash_matches_native_kat() {
    let got = key_history_v1_rfc6962_leaf_hash(
        0,
        GENESIS_TS,
        &b64(&x_a()),
        &b64(&pq_a()),
        &b64(&sp_fixed()),
        None,
    )
    .unwrap();
    assert_eq!(
        metamorphic_crypto::b64::decode(&got).unwrap(),
        hex(KAT_GENESIS_RFC6962_LEAF_HEX)
    );
}

// --------------------------------------------------------------------------
// 3. Checkpoint / signed-note: classical + additive hybrid-PQ (verify-locked)
// --------------------------------------------------------------------------

fn kat_note() -> String {
    String::from_utf8(metamorphic_crypto::b64::decode(HYBRID_KAT_NOTE_B64.trim()).unwrap()).unwrap()
}

// Derive the deterministic hybrid vkey from the fixed secret (vkey bytes ARE
// deterministic; only the signature bytes are hedged).
fn kat_vkey() -> String {
    let pk_b64 = metamorphic_crypto::derive_public_key(HYBRID_KAT_SK).unwrap();
    let pk = metamorphic_crypto::b64::decode(&pk_b64).unwrap();
    metamorphic_log::note::VerifierKey::new_hybrid("metamorphic.app/kat", &pk)
        .unwrap()
        .encode()
}

#[wasm_bindgen_test]
fn wasm_verify_signed_note_accepts_hybrid_kat() {
    assert_eq!(
        verify_signed_note(&kat_note(), vec![kat_vkey()]).unwrap(),
        1
    );
}

#[wasm_bindgen_test]
fn wasm_checkpoint_verify_parses_hybrid_kat_head() {
    let cp = checkpoint_verify(&kat_note(), vec![kat_vkey()]).unwrap();
    assert_eq!(get_str(&cp, "origin"), "metamorphic.app/kat");
    assert_eq!(get_f64(&cp, "size") as u64, 10);
    assert_eq!(
        get_str(&cp, "rootB64"),
        "q1bnDR7DLfXk0sCC5tD4hbsBLg7p+9Gd4tT8H9wYnKE="
    );
}

#[wasm_bindgen_test]
fn wasm_signed_note_rejects_untrusted_keyset() {
    assert!(verify_signed_note(&kat_note(), vec![]).is_err());
}

#[wasm_bindgen_test]
fn wasm_signed_note_rejects_tampered_body() {
    let mut note = kat_note();
    note.replace_range(0..1, "X"); // corrupt the signed body
    assert!(verify_signed_note(&note, vec![kat_vkey()]).is_err());
}

// --------------------------------------------------------------------------
// 4. NamespacePolicy: parse + verify + declared == observed
// --------------------------------------------------------------------------

#[wasm_bindgen_test]
fn wasm_signed_policy_verify_matches_native_kat() {
    let p = signed_policy_verify(KAT_SIGNED_B64.trim()).unwrap();
    assert_eq!(get_str(&p, "namespace"), "metamorphic.app");
    assert_eq!(get_str(&p, "securityLevel"), "cat3");
    assert_eq!(get_str(&p, "checkpointSuite"), "hybrid");
    assert_eq!(get_str(&p, "commitmentHash"), "sha3_256");
    assert_eq!(get_str(&p, "vrfMode"), "classical");
    assert_eq!(
        metamorphic_crypto::b64::decode(&get_str(&p, "policyHashB64")).unwrap(),
        hex(KAT_POLICY_HASH_HEX)
    );
}

#[wasm_bindgen_test]
fn wasm_signed_policy_verify_rejects_tamper() {
    let mut bytes = metamorphic_crypto::b64::decode(KAT_SIGNED_B64.trim()).unwrap();
    let n = bytes.len();
    bytes[n - 1] ^= 0x01; // corrupt the signature tail
    assert!(signed_policy_verify(&b64(&bytes)).is_err());
}

#[wasm_bindgen_test]
fn wasm_policy_enforce_commitment_hash_declared_equals_observed() {
    // Declared Cat-3 => Sha3_256; matching observed accepts, mismatch rejects.
    assert!(policy_enforce_commitment_hash(KAT_SIGNED_B64.trim(), "sha3_256").unwrap());
    assert!(policy_enforce_commitment_hash(KAT_SIGNED_B64.trim(), "sha3_512").is_err());
}

#[wasm_bindgen_test]
fn wasm_policy_enforce_vrf_suite_id_declared_equals_observed() {
    // Classical VRF mode expects ECVRF suite 0x03.
    assert!(policy_enforce_vrf_suite_id(KAT_SIGNED_B64.trim(), 0x03).unwrap());
    assert!(policy_enforce_vrf_suite_id(KAT_SIGNED_B64.trim(), 0x04).is_err());
}

// --------------------------------------------------------------------------
// 5. CONIKS index privacy: commitment vector + lookup/absence routing
// --------------------------------------------------------------------------

#[wasm_bindgen_test]
fn wasm_verify_commitment_matches_fixed_opening_vector() {
    let opening = [7u8; 32];
    let commitment = hex(COMMITMENT_VEC_HEX);
    assert!(
        verify_commitment_wasm(
            COMMITMENT_CTX,
            &b64(&commitment),
            &b64(b"value-bytes"),
            &b64(&opening),
        )
        .unwrap()
    );
}

#[wasm_bindgen_test]
fn wasm_verify_commitment_rejects_wrong_value() {
    let opening = [7u8; 32];
    let commitment = hex(COMMITMENT_VEC_HEX);
    assert!(
        verify_commitment_wasm(
            COMMITMENT_CTX,
            &b64(&commitment),
            &b64(b"WRONG-bytes"),
            &b64(&opening),
        )
        .is_err()
    );
}

#[wasm_bindgen_test]
fn wasm_coniks_lookup_and_absence_route_through_verifier() {
    use metamorphic_log::coniks::{ConiksDirectory, LookupResult, Namespace};
    use metamorphic_log::vrf::Ecvrf;

    let mut d = ConiksDirectory::new(Namespace::parse("mosslet").unwrap(), Box::new(Ecvrf));
    d.insert(b"alice@example.com", b"key-history-head-A")
        .unwrap();
    d.insert(b"bob@example.com", b"key-history-head-B").unwrap();
    let root = b64(&d.root());
    let vrf_pub = b64(d.vrf_public_key().as_bytes());

    let LookupResult::Present(present) = d.lookup(b"alice@example.com").unwrap() else {
        panic!("alice present");
    };
    let value = coniks_verify_lookup(
        "mosslet",
        &vrf_pub,
        &root,
        &b64(b"alice@example.com"),
        &b64(&present.to_bytes()),
    )
    .unwrap();
    assert_eq!(
        metamorphic_crypto::b64::decode(&value).unwrap(),
        b"key-history-head-A"
    );

    let LookupResult::Absent(absent) = d.lookup(b"carol@example.com").unwrap() else {
        panic!("carol absent");
    };
    assert!(
        coniks_verify_absence(
            "mosslet",
            &vrf_pub,
            &root,
            &b64(b"carol@example.com"),
            &b64(&absent.to_bytes()),
        )
        .unwrap()
    );

    // A presence proof for an absent identity must be rejected.
    assert!(
        coniks_verify_lookup(
            "mosslet",
            &vrf_pub,
            &root,
            &b64(b"carol@example.com"),
            &b64(&present.to_bytes()),
        )
        .is_err()
    );
}

// --------------------------------------------------------------------------
// 6. Experimental KEYTRANS combined-tree directory (KEYTRANS_EXP_04)
//
//    VERSION-TAGGED, MOVABLE — explicitly NOT a frozen vector. These bytes move
//    with `draft-ietf-keytrans-protocol` until Last Call, so this test locks
//    only Rust↔JS byte-parity of *verification* for the experimental suite
//    (the prover runs in-wasm, the WASM SDK verifier checks its output). It is
//    deliberately separate from and does not perturb the frozen
//    `key_history_v1` / CONIKS / policy-v1 vectors above.
// --------------------------------------------------------------------------

#[wasm_bindgen_test]
fn wasm_keytrans_search_fixed_version_and_monitor_verify() {
    use metamorphic_log::keytrans::{KeytransDirectory, KeytransExt};
    use metamorphic_log::vrf::Ecvrf;
    use metamorphic_log::vrf::Vrf;

    const CTX: &str = "metamorphic.app/keytrans-commitment/exp04";

    // Deterministic VRF keypair so the run is reproducible within a draft rev.
    let vrf = Ecvrf;
    let (sk, pk) = vrf.generate_keypair();
    let mut dir = KeytransDirectory::new(CTX, Box::new(Ecvrf), sk, pk.clone());
    dir.update(b"alice", b"head-v0", 1_000, &[1u8; 32]).unwrap();
    dir.update(b"alice", b"head-v1", 2_000, &[2u8; 32]).unwrap();
    dir.update(b"alice", b"head-v2", 3_000, &[3u8; 32]).unwrap();
    dir.update(b"bob", b"bob-v0", 4_000, &[4u8; 32]).unwrap();

    let root = b64(&dir.combined_root().unwrap());
    let vrf_pub = b64(pk.as_bytes());

    // Greatest-version search: verify through the WASM SDK byte path.
    let search = dir.prove_search(b"alice").unwrap();
    let search_b64 = b64(&search.encode().unwrap());
    let outcome =
        keytrans_verify_search(CTX, &vrf_pub, &root, &b64(b"alice"), &search_b64).unwrap();
    assert!(
        js_sys::Reflect::get(&outcome, &JsValue::from_str("present"))
            .unwrap()
            .as_bool()
            .unwrap()
    );
    assert_eq!(get_str(&outcome, "valueB64"), b64(b"head-v2"));

    // Absent label.
    let absent = dir.prove_search(b"carol").unwrap();
    let absent_b64 = b64(&absent.encode().unwrap());
    let outcome =
        keytrans_verify_search(CTX, &vrf_pub, &root, &b64(b"carol"), &absent_b64).unwrap();
    assert!(
        !js_sys::Reflect::get(&outcome, &JsValue::from_str("present"))
            .unwrap()
            .as_bool()
            .unwrap()
    );

    // Fixed-version search.
    let fv = dir.prove_fixed_version(b"alice", 1).unwrap();
    let fv_b64 = b64(&fv.encode().unwrap());
    let outcome =
        keytrans_verify_fixed_version(CTX, &vrf_pub, &root, &b64(b"alice"), &fv_b64).unwrap();
    assert_eq!(get_str(&outcome, "valueB64"), b64(b"head-v1"));

    // Monitor proof.
    let mon = dir.prove_monitor(b"alice", 2).unwrap();
    let mon_b64 = b64(&mon.encode().unwrap());
    assert!(keytrans_verify_monitor(CTX, &vrf_pub, &root, &b64(b"alice"), &mon_b64).unwrap());

    // A tampered root is rejected through the WASM byte path.
    let mut bad = metamorphic_crypto::b64::decode(&root).unwrap();
    bad[0] ^= 0xFF;
    assert!(
        keytrans_verify_search(CTX, &vrf_pub, &b64(&bad), &b64(b"alice"), &search_b64).is_err()
    );
}

#[wasm_bindgen_test]
fn wasm_signed_policy_verify_surfaces_directory_axes() {
    // The frozen v1 policy KAT is a CONIKS-route record; the SDK now surfaces
    // the Slice-9e directory axes (default CONIKS / experimental suite) without
    // changing the frozen v1 bytes.
    let p = signed_policy_verify(KAT_SIGNED_B64.trim()).unwrap();
    assert_eq!(get_str(&p, "directoryMode"), "coniks");
    assert_eq!(get_str(&p, "keytransSuite"), "metamorphicHybridExp");
    // Declared CONIKS route enforces against the CONIKS backend id (0x0001).
    assert!(policy_enforce_directory_backend(KAT_SIGNED_B64.trim(), 0x0001).unwrap());
    assert!(policy_enforce_directory_backend(KAT_SIGNED_B64.trim(), 0xF004).is_err());
}
