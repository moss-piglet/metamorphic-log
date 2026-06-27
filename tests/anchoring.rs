//! Slice 8 (#338) — backend-agnostic anchoring conformance.
//!
//! Exercises the public [`metamorphic_log::anchor`] surface from outside the
//! crate (so it doubles as an API-visibility check) and locks the deterministic
//! behaviour a future cross-language operator (mosskeys, over the #336 NIF) must
//! reproduce byte-for-byte:
//!
//! 1. **Byte-locked KAT** — a fixed checkpoint head + medium + locator pins the
//!    canonical [`AnchorRecord`] bytes, the medium-independent anchor
//!    commitment, and the RFC 6962 leaf hash. A cross-language ingester MUST
//!    reproduce these exactly.
//! 2. **Consistency between anchors** — [`verify_anchored`] accepts honest
//!    append-only growth between two anchored heads and rejects an equivocating
//!    fork, without trusting the operator or the medium.
//! 3. **CommitmentSink bridge** — the interface-only trait composes with the
//!    format through the logic-only write/read bridges (in-memory fixture, NOT a
//!    storage backend).

#![cfg(not(target_arch = "wasm32"))]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use metamorphic_log::anchor::{
    AnchorCommitment, AnchorLink, AnchorRecord, CommitmentSink, Medium, SinkError,
    anchor_checkpoint_via, verify_anchored, verify_commitment_via,
};
use metamorphic_log::checkpoint::Checkpoint;
use metamorphic_log::error::Error;
use metamorphic_log::merkle::MerkleTree;

// ===========================================================================
// 1. Byte-locked KAT (fixed head + medium + locator)
// ===========================================================================

/// The KAT log origin.
const KAT_ORIGIN: &str = "metamorphic.app/anchor-kat";
/// The KAT medium identifier.
const KAT_MEDIUM: &str = "ethereum/mainnet";
/// The KAT opaque locator bytes (an example chain tx id).
const KAT_LOCATOR: &[u8] = b"0x0123456789abcdef";

/// The RFC 6962 root (hex) of the 16-leaf KAT tree (leaves `u32_be(0..16)`).
const KAT_ROOT_HEX: &str = "62a77d6fd48269288f766d07046e320b07fa34c21e57f78a45e110768dcf9308";

/// The canonical [`AnchorRecord`] bytes (hex). Locks the byte layout end-to-end.
const KAT_CANONICAL_HEX: &str = "000000010000001a6d6574616d6f72706869632e6170702f616e63686f722d6b617400000000000000100000002062a77d6fd48269288f766d07046e320b07fa34c21e57f78a45e110768dcf93080200000010657468657265756d2f6d61696e6e657400000012307830313233343536373839616263646566";

/// The medium-independent anchor commitment (hex), SHA3-512 over the head.
const KAT_COMMITMENT_HEX: &str = "097402306312e282cbc09999cc1cade1455060e07a491a5d50a1ef5ed4377e391020d29f216607b7877d3ac33b7157d2b9e946d953c008b05e530b1b29c49472";

/// The RFC 6962 Layer-0 leaf hash (hex) of the canonical record bytes.
const KAT_LEAF_HEX: &str = "8a922055e04227ffb8fce65452119b9db8367f3da61d8690c7b382724e076cb1";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build the 16-leaf KAT checkpoint and its tree.
fn kat_checkpoint() -> (Checkpoint, MerkleTree) {
    let mut tree = MerkleTree::new();
    for i in 0u32..16 {
        tree.push(&i.to_be_bytes());
    }
    let cp = Checkpoint::new(KAT_ORIGIN, tree.size(), tree.root()).unwrap();
    (cp, tree)
}

fn kat_record() -> AnchorRecord {
    let (cp, _) = kat_checkpoint();
    AnchorRecord::for_checkpoint(
        &cp,
        AnchorCommitment::Sha3_512,
        Medium::parse(KAT_MEDIUM).unwrap(),
        KAT_LOCATOR.to_vec(),
    )
    .unwrap()
}

#[test]
fn kat_canonical_commitment_and_leaf_are_locked() {
    let (cp, _) = kat_checkpoint();
    assert_eq!(hex(cp.root_hash()), KAT_ROOT_HEX);

    let rec = kat_record();
    assert_eq!(hex(&rec.canonical_bytes()), KAT_CANONICAL_HEX);
    assert_eq!(hex(&rec.anchor_commitment()), KAT_COMMITMENT_HEX);
    assert_eq!(hex(&rec.rfc6962_leaf_hash()), KAT_LEAF_HEX);

    // Parse-from-canonical reproduces the record byte-for-byte.
    let parsed = AnchorRecord::parse(&rec.canonical_bytes()).unwrap();
    assert_eq!(parsed, rec);
    assert_eq!(hex(&parsed.canonical_bytes()), KAT_CANONICAL_HEX);
}

#[test]
fn kat_commitment_is_medium_independent() {
    // The same head anchored to a different medium with a different locator
    // produces the identical commitment (defence-in-depth: many media, one head).
    let (cp, _) = kat_checkpoint();
    let notary = AnchorRecord::for_checkpoint(
        &cp,
        AnchorCommitment::Sha3_512,
        Medium::parse("rfc3161").unwrap(),
        b"notary-receipt-7".to_vec(),
    )
    .unwrap();
    assert_eq!(hex(&notary.anchor_commitment()), KAT_COMMITMENT_HEX);
}

#[test]
fn parse_rejects_tampered_and_unknown_tag() {
    let rec = kat_record();

    // Flip the commitment-algorithm tag to an unknown value (0x01 is reserved).
    let mut bytes = rec.canonical_bytes();
    let tag_offset = bytes.len() - (4 + KAT_MEDIUM.len() + 4 + KAT_LOCATOR.len()) - 1;
    bytes[tag_offset] = 0x01;
    assert!(matches!(
        AnchorRecord::parse(&bytes),
        Err(Error::MalformedAnchor(_))
    ));
}

// ===========================================================================
// 2. Consistency between anchors (the headline audit)
// ===========================================================================

#[test]
fn anchored_heads_must_be_append_only_consistent() {
    let origin = "operator.example/transparency";
    let mut tree = MerkleTree::new();
    for i in 0u32..100 {
        tree.push(&i.to_be_bytes());
    }
    let older = Checkpoint::new(origin, tree.size(), tree.root()).unwrap();
    let older_rec = AnchorRecord::for_checkpoint(
        &older,
        AnchorCommitment::Sha3_512,
        Medium::parse("dc3").unwrap(),
        b"anchor-100".to_vec(),
    )
    .unwrap();
    // The older anchor verifies on its own (binding only).
    verify_anchored(&older, &older_rec, None).unwrap();

    // Grow the log and anchor the newer head.
    for i in 100u32..250 {
        tree.push(&i.to_be_bytes());
    }
    let newer = Checkpoint::new(origin, tree.size(), tree.root()).unwrap();
    let newer_rec = AnchorRecord::for_checkpoint(
        &newer,
        AnchorCommitment::Sha3_512,
        Medium::parse("dc3").unwrap(),
        b"anchor-250".to_vec(),
    )
    .unwrap();
    let proof: Vec<Vec<u8>> = tree
        .consistency_proof(100, 250)
        .into_iter()
        .map(|h| h.to_vec())
        .collect();

    // A third party audits "no equivocation between the two anchored heads".
    let link = AnchorLink::new(&older, &proof);
    verify_anchored(&newer, &newer_rec, Some(&link)).unwrap();

    // An operator presenting an inconsistent (forked) newer head is caught even
    // though it carries a valid-looking attestation: the consistency proof from
    // the older anchored head cannot bind a fork.
    let mut fork = MerkleTree::new();
    for i in 0u32..250 {
        // Diverge from leaf 100 onward.
        let v = if i < 100 { i } else { i.wrapping_add(7) };
        fork.push(&v.to_be_bytes());
    }
    let forged = Checkpoint::new(origin, fork.size(), fork.root()).unwrap();
    let forged_rec = AnchorRecord::for_checkpoint(
        &forged,
        AnchorCommitment::Sha3_512,
        Medium::parse("dc3").unwrap(),
        b"anchor-forged".to_vec(),
    )
    .unwrap();
    assert!(matches!(
        verify_anchored(&forged, &forged_rec, Some(&link)),
        Err(Error::RootMismatch)
    ));
}

#[test]
fn attestation_must_bind_the_checkpoint() {
    let (cp, _) = kat_checkpoint();
    let rec = kat_record();
    verify_anchored(&cp, &rec, None).unwrap();

    // A checkpoint with a different size is not bound by this attestation.
    let mut tree = MerkleTree::new();
    for i in 0u32..17 {
        tree.push(&i.to_be_bytes());
    }
    let other = Checkpoint::new(KAT_ORIGIN, tree.size(), tree.root()).unwrap();
    assert!(matches!(
        verify_anchored(&other, &rec, None),
        Err(Error::AnchorMismatch(_))
    ));
}

// ===========================================================================
// 3. CommitmentSink bridge (interface-only trait composes with the format)
// ===========================================================================

/// Logic-only in-memory sink. NOT a storage backend — it exists only to prove
/// the bridges compose with the format and the verification core.
#[derive(Default)]
struct MemSink {
    store: RefCell<HashMap<Vec<u8>, Vec<u8>>>,
    next: Cell<u64>,
}

impl CommitmentSink for MemSink {
    type Error = String;

    fn put_commitment(&self, commitment: &[u8]) -> Result<Vec<u8>, String> {
        let id = self.next.get();
        self.next.set(id + 1);
        let locator = format!("mem:{id}").into_bytes();
        self.store
            .borrow_mut()
            .insert(locator.clone(), commitment.to_vec());
        Ok(locator)
    }

    fn get_commitment(&self, locator: &[u8]) -> Result<Vec<u8>, String> {
        self.store
            .borrow()
            .get(locator)
            .cloned()
            .ok_or_else(|| format!("missing locator {}", String::from_utf8_lossy(locator)))
    }
}

#[test]
fn sink_write_then_read_verifies() {
    let sink = MemSink::default();
    let (cp, _) = kat_checkpoint();

    let rec = anchor_checkpoint_via(
        &sink,
        &cp,
        AnchorCommitment::Sha3_512,
        Medium::parse("dc3").unwrap(),
    )
    .unwrap();
    assert!(rec.binds(&cp));
    // The published commitment equals the KAT commitment (medium-independent).
    assert_eq!(hex(&rec.anchor_commitment()), KAT_COMMITMENT_HEX);

    // Read-path bridge: the medium genuinely attests to this head.
    verify_commitment_via(&sink, &rec).unwrap();

    // A locator the medium never saw surfaces as a backend miss, never a panic.
    let bogus = AnchorRecord::for_checkpoint(
        &cp,
        AnchorCommitment::Sha3_512,
        Medium::parse("dc3").unwrap(),
        b"mem:404".to_vec(),
    )
    .unwrap();
    assert!(matches!(
        verify_commitment_via(&sink, &bogus),
        Err(SinkError::Backend(_))
    ));
}
