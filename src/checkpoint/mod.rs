//! C2SP [`tlog-checkpoint`] signed tree heads (over the [`crate::note`]
//! substrate).
//!
//! A *checkpoint* is a [signed note](crate::note) whose text is a precisely
//! formatted Merkle tree head. The note text is at least three newline-separated
//! lines:
//!
//! ```text
//! <origin>\n          (1) unique log identity, non-empty
//! <tree size>\n       (2) ASCII decimal leaf count, no leading zeroes
//! <base64 root hash>\n (3) base64 of the RFC 6962 root at that size
//! [<extension line>\n] (4) optional, opaque, non-empty (NOT RECOMMENDED)
//! ```
//!
//! This module parses/serializes that body byte-for-byte and wires it to the
//! Slice-1 proof verifier: a consistency walk between two checkpoints uses
//! [`crate::proof::verify_consistency`], and an inclusion check against a
//! checkpoint uses [`crate::proof::verify_inclusion`]. Checkpoints are designed
//! for external witness co-signing from day one — verification of the signature
//! lines is handled by [`crate::note::SignedNote::verify`]. A checkpoint can
//! carry **both** a classical Ed25519 line (so the C2SP witness network can
//! recompute and co-sign) **and** an additive hybrid post-quantum composite line
//! (so our own verifiers/monitors get PQ authenticity); a verifier accepts any
//! mix of trusted [`crate::note::VerifierKey`] types.
//!
//! [`tlog-checkpoint`]: https://c2sp.org/tlog-checkpoint

use crate::encoding::{base64_decode, base64_encode};
use crate::error::{Error, Result};
use crate::merkle::{HASH_LEN, Hash};
use crate::note::{self, SignedNote, VerifierKey};
use crate::proof;

/// A parsed checkpoint (signed-tree-head body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    origin: String,
    size: u64,
    root_hash: Hash,
    extensions: Vec<String>,
}

impl Checkpoint {
    /// Build a checkpoint with no extension lines.
    ///
    /// # Errors
    /// Returns [`Error::MalformedCheckpoint`] if `origin` is empty or contains a
    /// newline.
    pub fn new(origin: &str, size: u64, root_hash: Hash) -> Result<Self> {
        Self::with_extensions(origin, size, root_hash, Vec::new())
    }

    /// Build a checkpoint with explicit extension lines.
    ///
    /// # Errors
    /// Returns [`Error::MalformedCheckpoint`] if `origin` is empty/contains a
    /// newline, or any extension line is empty or contains a newline.
    pub fn with_extensions(
        origin: &str,
        size: u64,
        root_hash: Hash,
        extensions: Vec<String>,
    ) -> Result<Self> {
        if origin.is_empty() || origin.contains('\n') {
            return Err(Error::MalformedCheckpoint(
                "origin must be non-empty and contain no newline".into(),
            ));
        }
        for ext in &extensions {
            if ext.is_empty() || ext.contains('\n') {
                return Err(Error::MalformedCheckpoint(
                    "extension lines must be non-empty and contain no newline".into(),
                ));
            }
        }
        Ok(Self {
            origin: origin.to_string(),
            size,
            root_hash,
            extensions,
        })
    }

    /// The log origin (identity) line.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The tree size (number of leaves).
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The RFC 6962 root hash at this tree size.
    #[must_use]
    pub fn root_hash(&self) -> &Hash {
        &self.root_hash
    }

    /// The opaque extension lines (usually empty).
    #[must_use]
    pub fn extensions(&self) -> &[String] {
        &self.extensions
    }

    /// Parse a checkpoint body (the note text), byte-for-byte per the spec.
    ///
    /// # Errors
    /// Returns [`Error::MalformedCheckpoint`] for a missing/empty origin, a
    /// non-decimal or leading-zero size, a root hash that is not exactly 32
    /// bytes once base64-decoded, fewer than three lines, or an empty extension
    /// line.
    pub fn parse(text: &str) -> Result<Self> {
        let mut lines = text.lines();
        let origin = lines
            .next()
            .ok_or_else(|| Error::MalformedCheckpoint("missing origin line".into()))?;
        let size_str = lines
            .next()
            .ok_or_else(|| Error::MalformedCheckpoint("missing tree-size line".into()))?;
        let root_b64 = lines
            .next()
            .ok_or_else(|| Error::MalformedCheckpoint("missing root-hash line".into()))?;

        if origin.is_empty() {
            return Err(Error::MalformedCheckpoint("empty origin line".into()));
        }

        // Tree size: ASCII decimal, no leading zeroes (unless exactly "0").
        if size_str.is_empty() || !size_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::MalformedCheckpoint(format!(
                "tree size is not decimal: {size_str:?}"
            )));
        }
        if size_str.len() > 1 && size_str.starts_with('0') {
            return Err(Error::MalformedCheckpoint(format!(
                "tree size has a leading zero: {size_str:?}"
            )));
        }
        let size: u64 = size_str
            .parse()
            .map_err(|_| Error::MalformedCheckpoint(format!("tree size overflow: {size_str:?}")))?;

        let root_bytes = base64_decode(root_b64).map_err(|_| {
            Error::MalformedCheckpoint(format!("root hash is not valid base64: {root_b64:?}"))
        })?;
        let root_hash: Hash = root_bytes.as_slice().try_into().map_err(|_| {
            Error::MalformedCheckpoint(format!(
                "root hash is {} bytes, want {HASH_LEN}",
                root_bytes.len()
            ))
        })?;

        let mut extensions = Vec::new();
        for ext in lines {
            if ext.is_empty() {
                return Err(Error::MalformedCheckpoint("empty extension line".into()));
            }
            extensions.push(ext.to_string());
        }

        Ok(Self {
            origin: origin.to_string(),
            size,
            root_hash,
            extensions,
        })
    }

    /// Serialize the checkpoint body (the note text), ending in a newline.
    #[must_use]
    pub fn marshal(&self) -> String {
        let mut out = String::new();
        out.push_str(&self.origin);
        out.push('\n');
        out.push_str(&self.size.to_string());
        out.push('\n');
        out.push_str(&base64_encode(&self.root_hash));
        out.push('\n');
        for ext in &self.extensions {
            out.push_str(ext);
            out.push('\n');
        }
        out
    }

    /// Parse and verify a full signed checkpoint, returning the checkpoint body.
    ///
    /// The `msg` is the complete signed note (body + blank line + signature
    /// lines). It is verified against `trusted` (at least one trusted signature
    /// — e.g. the log's Ed25519 key, or a witness co-signature — must verify),
    /// then its body is parsed as a checkpoint.
    ///
    /// # Errors
    /// Propagates [`crate::note::SignedNote::parse`] / `verify` errors and
    /// [`Checkpoint::parse`] errors.
    pub fn from_signed_note(msg: &str, trusted: &[VerifierKey]) -> Result<Self> {
        let note = SignedNote::parse(msg)?;
        note.verify(trusted)?;
        Self::parse(note.text())
    }

    /// Verify that `leaf_hash` is included at `leaf_index` in the tree committed
    /// by this checkpoint, using the Slice-1 RFC 6962/9162 verifier.
    ///
    /// # Errors
    /// Propagates [`crate::proof::verify_inclusion`] errors (index out of range,
    /// wrong proof size, hash-length, or root mismatch).
    pub fn verify_inclusion(
        &self,
        leaf_index: u64,
        leaf_hash: &[u8],
        proof: &[Vec<u8>],
    ) -> Result<()> {
        proof::verify_inclusion(leaf_index, self.size, leaf_hash, proof, &self.root_hash)
    }

    /// Verify that this (older) checkpoint is consistent with a `newer` one —
    /// i.e. the newer tree is an append-only extension — using the Slice-1
    /// RFC 6962/9162 consistency verifier. This is the anti-equivocation walk a
    /// monitor performs across checkpoints.
    ///
    /// # Errors
    /// Propagates [`crate::proof::verify_consistency`] errors, including a root
    /// mismatch if the proof does not bind both tree heads.
    pub fn verify_consistency(&self, newer: &Checkpoint, proof: &[Vec<u8>]) -> Result<()> {
        proof::verify_consistency(
            self.size,
            newer.size,
            proof,
            &self.root_hash,
            &newer.root_hash,
        )
    }
}

/// Build a checkpoint body and sign it with a metamorphic-crypto hybrid
/// composite secret key, returning the complete C2SP `signed-note` text (body +
/// blank line + the additive PQ signature line) ready to publish.
///
/// This is the one-call convenience path for the common producer flow. It
/// wraps [`Checkpoint::new`], [`Checkpoint::marshal`],
/// [`crate::note::sign_hybrid`], [`SignedNote::new`], and
/// [`SignedNote::marshal`] so a caller never has to hand-assemble the byte
/// layout. `root_b64` is the base64 of the exactly 32-byte RFC 6962 root at
/// `size`; `name` is the C2SP key name (the log origin); `secret_key_b64` is
/// the base64 composite secret key (`tag || classical_seed || ml_dsa_seed`).
/// The matching [`VerifierKey::new_hybrid`] (derived from the secret key's
/// public half) verifies the produced note.
///
/// The returned note carries a single hybrid line. For a checkpoint that ALSO
/// carries a classical Ed25519 (`0x01`) line under the same name — so stock
/// Ed25519-only C2SP witnesses can verify and co-sign it — use
/// [`sign_checkpoint_dual`].
///
/// # Errors
/// Returns [`Error::MalformedCheckpoint`] if `origin`/`size`/`root_b64` do not
/// form a valid checkpoint (empty origin, wrong-length root, non-base64 root),
/// and propagates [`crate::note::sign_hybrid`] errors
/// ([`Error::HybridSignature`] for an undecodable/underivable secret key or a
/// signing failure, or [`Error::MalformedNote`] for an invalid `name`).
pub fn sign_checkpoint_hybrid(
    origin: &str,
    size: u64,
    root_b64: &str,
    name: &str,
    secret_key_b64: &str,
) -> Result<String> {
    let root_hash = decode_root(root_b64)?;
    let body = Checkpoint::new(origin, size, root_hash)?.marshal();
    let sig = note::sign_hybrid(&body, name, secret_key_b64)?;
    Ok(SignedNote::new(body, vec![sig])?.marshal())
}

/// Build a checkpoint body and sign it **twice** with ONE metamorphic-crypto
/// hybrid composite secret key — once as the additive hybrid post-quantum line
/// and once as a classical Ed25519 (`0x01`) line, both under the same key
/// `name` (the log origin) — returning the complete dual-line C2SP
/// `signed-note` text ready to publish.
///
/// This is the witness-interop producer flow: stock C2SP witness software
/// (omniwitness, armored-witness, sigsum) verifies Ed25519 `0x01` log lines
/// only, while our own verifiers trust the hybrid line. `signed-note` is
/// explicitly multi-signature with unknown-key-ignored, so the one note serves
/// both worlds and stays backward compatible with single-line consumers in
/// both directions. The Ed25519 half of the composite key signs the bare note
/// text while the hybrid line signs under
/// [`crate::note::HYBRID_SIG_CONTEXT`], so the two uses of the same classical
/// key stay domain-separated. The two lines share the key name but carry
/// different key ids (the key id commits to the signature type), exactly as
/// the spec allows.
///
/// Arguments and validation match [`sign_checkpoint_hybrid`]; the matching
/// verifier keys are [`VerifierKey::new_hybrid`] (hybrid line) and
/// [`VerifierKey::new_ed25519_from_hybrid`] (Ed25519 line), both derived from
/// the same composite public key. Requires a `Suite::Hybrid` composite key
/// (Ed25519 classical half); the matched-suite (Ed448/P-521) and pure-PQ keys
/// have no Ed25519 half and are rejected.
///
/// # Errors
/// Returns [`Error::MalformedCheckpoint`] if `origin`/`size`/`root_b64` do not
/// form a valid checkpoint, [`Error::HybridSignature`] if the secret key is
/// undecodable/underivable or is not a `Suite::Hybrid` key, and
/// [`Error::MalformedNote`] for an invalid `name` or a signing failure.
pub fn sign_checkpoint_dual(
    origin: &str,
    size: u64,
    root_b64: &str,
    name: &str,
    secret_key_b64: &str,
) -> Result<String> {
    let root_hash = decode_root(root_b64)?;
    let body = Checkpoint::new(origin, size, root_hash)?.marshal();
    let hybrid_sig = note::sign_hybrid(&body, name, secret_key_b64)?;
    let ed25519_seed = note::hybrid_secret_ed25519_seed(secret_key_b64)?;
    let ed25519_sig = note::sign_ed25519(&body, name, &ed25519_seed)?;
    Ok(SignedNote::new(body, vec![hybrid_sig, ed25519_sig])?.marshal())
}

/// Decode a base64 RFC 6962 root hash, enforcing the exact 32-byte length.
fn decode_root(root_b64: &str) -> Result<Hash> {
    let root_bytes = base64_decode(root_b64).map_err(|_| {
        Error::MalformedCheckpoint(format!("root hash is not valid base64: {root_b64:?}"))
    })?;
    root_bytes.as_slice().try_into().map_err(|_| {
        Error::MalformedCheckpoint(format!(
            "root hash is {} bytes, want {HASH_LEN}",
            root_bytes.len()
        ))
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use crate::note::{sign_ed25519, sign_hybrid};

    /// The canonical checkpoint body from the tlog-checkpoint spec.
    const SPEC_BODY: &str =
        "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n";

    #[test]
    fn parses_spec_checkpoint_body() {
        let cp = Checkpoint::parse(SPEC_BODY).unwrap();
        assert_eq!(cp.origin(), "example.com/behind-the-sofa");
        assert_eq!(cp.size(), 20_852_163);
        assert_eq!(cp.extensions().len(), 0);
        // Round-trips byte-for-byte.
        assert_eq!(cp.marshal(), SPEC_BODY);
    }

    #[test]
    fn rejects_malformed_bodies() {
        assert!(Checkpoint::parse("origin\n").is_err()); // too few lines
        assert!(Checkpoint::parse("origin\n01\nAAAA\n").is_err()); // leading zero size
        assert!(Checkpoint::parse("origin\nxx\nAAAA\n").is_err()); // non-decimal size
        // Root hash wrong length (4 bytes, not 32).
        assert!(Checkpoint::parse("origin\n5\nAAAAAA==\n").is_err());
    }

    #[test]
    fn extension_lines_round_trip() {
        let root = [7u8; HASH_LEN];
        let cp = Checkpoint::with_extensions(
            "example.com/log",
            42,
            root,
            vec!["ext one".into(), "ext two".into()],
        )
        .unwrap();
        let body = cp.marshal();
        assert_eq!(Checkpoint::parse(&body).unwrap(), cp);
    }

    #[test]
    fn signed_checkpoint_round_trip_and_verify() {
        let mut tree = MerkleTree::new();
        for i in 0u32..10 {
            tree.push(&i.to_be_bytes());
        }
        let cp = Checkpoint::new("origin.example/log", tree.size(), tree.root()).unwrap();

        let (seed, pk) = metamorphic_crypto::ed25519_generate_keypair();
        let sig = sign_ed25519(&cp.marshal(), "origin.example/log", &seed).unwrap();
        let note = SignedNote::new(cp.marshal(), vec![sig]).unwrap();

        let vkey = VerifierKey::new_ed25519("origin.example/log", &pk).unwrap();
        let parsed = Checkpoint::from_signed_note(&note.marshal(), &[vkey]).unwrap();
        assert_eq!(parsed, cp);
    }

    #[test]
    fn checkpoint_wires_inclusion_and_consistency() {
        let mut tree = MerkleTree::new();
        for i in 0u32..8 {
            tree.push(&i.to_be_bytes());
        }
        let older = Checkpoint::new("o", tree.size(), tree.root()).unwrap();

        // Inclusion of leaf 3 against the size-8 checkpoint.
        let proof: Vec<Vec<u8>> = tree
            .inclusion_proof(3, 8)
            .into_iter()
            .map(|h| h.to_vec())
            .collect();
        let leaf = tree.leaf_hash(3).unwrap();
        older.verify_inclusion(3, &leaf, &proof).unwrap();

        // Grow the tree and check consistency older -> newer.
        for i in 8u32..16 {
            tree.push(&i.to_be_bytes());
        }
        let newer = Checkpoint::new("o", tree.size(), tree.root()).unwrap();
        let cproof: Vec<Vec<u8>> = tree
            .consistency_proof(8, 16)
            .into_iter()
            .map(|h| h.to_vec())
            .collect();
        older.verify_consistency(&newer, &cproof).unwrap();
    }

    #[test]
    fn checkpoint_co_signed_classical_and_pq() {
        let mut tree = MerkleTree::new();
        for i in 0u32..10 {
            tree.push(&i.to_be_bytes());
        }
        let cp = Checkpoint::new("origin.example/log", tree.size(), tree.root()).unwrap();
        let body = cp.marshal();

        // The log signs the SAME checkpoint body with a classical Ed25519 key
        // (witness-compatible) and an additive hybrid PQ composite key.
        let (seed, ed_pk) = metamorphic_crypto::ed25519_generate_keypair();
        let pq_kp = metamorphic_crypto::generate_signing_keypair();
        let pq_pk = crate::encoding::base64_decode(&pq_kp.public_key).unwrap();

        let ed_sig = sign_ed25519(&body, "origin.example/log", &seed).unwrap();
        let pq_sig = sign_hybrid(&body, "origin.example/log-pq", &pq_kp.secret_key).unwrap();
        let note = SignedNote::new(body, vec![ed_sig, pq_sig]).unwrap();

        let ed_vkey = VerifierKey::new_ed25519("origin.example/log", &ed_pk).unwrap();
        let pq_vkey = VerifierKey::new_hybrid("origin.example/log-pq", &pq_pk).unwrap();

        // A classical-only witness verifies and recomputes from the Ed25519 line.
        let parsed_classical =
            Checkpoint::from_signed_note(&note.marshal(), std::slice::from_ref(&ed_vkey)).unwrap();
        assert_eq!(parsed_classical, cp);

        // A PQ-aware verifier with both trusted keys verifies the full set.
        let parsed_pq = Checkpoint::from_signed_note(&note.marshal(), &[ed_vkey, pq_vkey]).unwrap();
        assert_eq!(parsed_pq, cp);
    }

    #[test]
    fn sign_checkpoint_hybrid_convenience_round_trips() {
        let mut tree = MerkleTree::new();
        for i in 0u32..10 {
            tree.push(&i.to_be_bytes());
        }
        let root_b64 = crate::encoding::base64_encode(&tree.root());

        let kp = metamorphic_crypto::generate_signing_keypair();
        let pk = crate::encoding::base64_decode(&kp.public_key).unwrap();

        // One call produces the full signed-note text.
        let note_text = sign_checkpoint_hybrid(
            "origin.example/log",
            tree.size(),
            &root_b64,
            "origin.example/log",
            &kp.secret_key,
        )
        .unwrap();

        // The derived verifier key verifies the produced note and yields the
        // expected head — identical to the hand-assembled path.
        let vkey = VerifierKey::new_hybrid("origin.example/log", &pk).unwrap();
        let parsed = Checkpoint::from_signed_note(&note_text, &[vkey]).unwrap();
        let expected = Checkpoint::new("origin.example/log", tree.size(), tree.root()).unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn sign_checkpoint_hybrid_rejects_bad_root() {
        let kp = metamorphic_crypto::generate_signing_keypair();
        // Root that is not 32 bytes once decoded.
        let err = sign_checkpoint_hybrid("o", 1, "AAAA", "o", &kp.secret_key).unwrap_err();
        assert!(matches!(err, Error::MalformedCheckpoint(_)));
    }

    /// A dual-signed fixture: Cat-3 composite key over a size-10 tree, with the
    /// checkpoint body and both verifier keys derived from the one composite
    /// public key.
    struct DualFixture {
        note_text: String,
        body: String,
        hybrid_vkey: VerifierKey,
        ed25519_vkey: VerifierKey,
    }

    fn dual_fixture() -> DualFixture {
        let mut tree = MerkleTree::new();
        for i in 0u32..10 {
            tree.push(&i.to_be_bytes());
        }
        let root_b64 = crate::encoding::base64_encode(&tree.root());
        let kp = metamorphic_crypto::generate_signing_keypair();
        let pk = crate::encoding::base64_decode(&kp.public_key).unwrap();

        let note_text = sign_checkpoint_dual(
            "origin.example/log",
            10,
            &root_b64,
            "origin.example/log",
            &kp.secret_key,
        )
        .unwrap();
        DualFixture {
            body: Checkpoint::new("origin.example/log", 10, tree.root())
                .unwrap()
                .marshal(),
            note_text,
            hybrid_vkey: VerifierKey::new_hybrid("origin.example/log", &pk).unwrap(),
            ed25519_vkey: VerifierKey::new_ed25519_from_hybrid("origin.example/log", &pk).unwrap(),
        }
    }

    #[test]
    fn sign_checkpoint_dual_round_trips_and_each_line_verifies_independently() {
        let f = dual_fixture();
        let note = SignedNote::parse(&f.note_text).unwrap();
        assert_eq!(note.text(), f.body);
        assert_eq!(note.signatures().len(), 2);

        // The hybrid vkey alone verifies exactly the hybrid line; the derived
        // 0x01 vkey alone verifies exactly the Ed25519 line; together they
        // verify both. This is the stock-witness / PQ-verifier split.
        let hybrid_only = note.verify(std::slice::from_ref(&f.hybrid_vkey)).unwrap();
        assert_eq!(hybrid_only.len(), 1);
        assert_eq!(hybrid_only[0].key_id(), f.hybrid_vkey.key_id());

        let ed25519_only = note.verify(std::slice::from_ref(&f.ed25519_vkey)).unwrap();
        assert_eq!(ed25519_only.len(), 1);
        assert_eq!(ed25519_only[0].key_id(), f.ed25519_vkey.key_id());

        let both = note
            .verify(&[f.hybrid_vkey.clone(), f.ed25519_vkey.clone()])
            .unwrap();
        assert_eq!(both.len(), 2);

        // And the body parses as the expected checkpoint either way.
        let parsed = Checkpoint::from_signed_note(&f.note_text, &[f.ed25519_vkey]).unwrap();
        assert_eq!(parsed, Checkpoint::parse(&f.body).unwrap());
    }

    #[test]
    fn sign_checkpoint_dual_lines_share_name_with_distinct_key_ids() {
        let f = dual_fixture();
        let note = SignedNote::parse(&f.note_text).unwrap();
        let (hybrid_line, ed25519_line) = (&note.signatures()[0], &note.signatures()[1]);

        // Same name (the origin), different key ids (the key id commits to the
        // signature type), each matching its own verifier key.
        assert_eq!(hybrid_line.name(), "origin.example/log");
        assert_eq!(ed25519_line.name(), "origin.example/log");
        assert_ne!(hybrid_line.key_id(), ed25519_line.key_id());
        assert_eq!(hybrid_line.key_id(), f.hybrid_vkey.key_id());
        assert_eq!(ed25519_line.key_id(), f.ed25519_vkey.key_id());

        // The derived 0x01 vkey encode/parse round-trips (it is what gets
        // published for witness registration).
        let encoded = f.ed25519_vkey.encode();
        let parsed = VerifierKey::parse(&encoded).unwrap();
        assert_eq!(parsed.signature_type(), crate::note::SignatureType::Ed25519);
        assert_eq!(parsed, f.ed25519_vkey);
    }

    #[test]
    fn sign_checkpoint_dual_rejects_tamper() {
        let f = dual_fixture();
        // Grow the tree by one leaf without re-signing: the body no longer
        // matches either signature.
        let tampered = f
            .note_text
            .replace("origin.example/log\n10\n", "origin.example/log\n11\n");
        let note = SignedNote::parse(&tampered).unwrap();
        assert!(matches!(
            note.verify(&[f.hybrid_vkey.clone(), f.ed25519_vkey.clone()]),
            Err(Error::InvalidSignature { .. })
        ));
        assert!(matches!(
            note.verify(std::slice::from_ref(&f.ed25519_vkey)),
            Err(Error::InvalidSignature { .. })
        ));
    }

    #[test]
    fn sign_checkpoint_dual_rejects_non_hybrid_suite() {
        // Pure-PQ (no classical half) and matched-suite (Ed448/P-521 classical)
        // keys have no Ed25519 half to mint the 0x01 line from.
        for suite in [
            metamorphic_crypto::Suite::PureCnsa2,
            metamorphic_crypto::Suite::HybridMatched,
        ] {
            let kp = metamorphic_crypto::generate_signing_keypair_suite(
                suite,
                metamorphic_crypto::SignatureLevel::Cat5,
            )
            .unwrap();
            let root_b64 = crate::encoding::base64_encode(&[7u8; HASH_LEN]);
            let err = sign_checkpoint_dual("o", 1, &root_b64, "o", &kp.secret_key).unwrap_err();
            assert!(matches!(err, Error::HybridSignature(_)), "suite {suite:?}");

            // The public-half vkey derivation rejects the same key.
            let pk = crate::encoding::base64_decode(&kp.public_key).unwrap();
            let err = VerifierKey::new_ed25519_from_hybrid("o", &pk).unwrap_err();
            assert!(matches!(err, Error::HybridSignature(_)), "suite {suite:?}");
        }
    }

    #[test]
    fn sign_checkpoint_dual_rejects_bad_root() {
        let kp = metamorphic_crypto::generate_signing_keypair();
        let err = sign_checkpoint_dual("o", 1, "AAAA", "o", &kp.secret_key).unwrap_err();
        assert!(matches!(err, Error::MalformedCheckpoint(_)));
    }
}
