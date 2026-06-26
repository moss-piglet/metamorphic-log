//! C2SP [`signed-note`] parsing, serialization, and verification.
//!
//! A *signed note* is UTF-8 text followed by a blank line and one or more
//! signature lines, each of the form:
//!
//! ```text
//! — <key name> <base64(uint32 key id || signature)>\n
//! ```
//!
//! (the leading character is an em dash, `U+2014`, then a space). The text the
//! signatures cover **includes the final newline but not the separating blank
//! line**. This module parses and serializes that wire format byte-for-byte
//! compatibly with the deployed ecosystem (Go's `sumdb/note`, sigsum,
//! transparency-dev), and verifies **classical Ed25519** witness/log signature
//! lines via the single-source-of-truth primitive
//! [`metamorphic_crypto::ed25519_verify`].
//!
//! ## Key ids and verifier keys
//!
//! The 4-byte key id binds a signature to a `(name, signature-type, public
//! key)` tuple:
//!
//! ```text
//! key id = SHA-256(key name || 0x0A || signature type || public key)[:4]   (big-endian u32)
//! ```
//!
//! A *verifier key* (`vkey`) is the text encoding a verifier shares:
//!
//! ```text
//! <key name>+<hex(key id)>+<base64(signature type || public key)>
//! ```
//!
//! ## Additive hybrid post-quantum signatures (Slice 3)
//!
//! The model is intentionally multi-signature and signature-type-tagged. A note
//! may carry any number of signature lines, and verifiers MUST ignore lines
//! from unknown keys. This is exactly what lets an **additive hybrid
//! post-quantum** signature line ([`SignatureType::MetamorphicHybrid`]) slot in
//! alongside the classical [`SignatureType::Ed25519`] line with **no format
//! churn**: classical C2SP witnesses keep verifying (and co-signing) the Ed25519
//! line and can still recompute the tree, while our own PQ-aware verifiers and
//! monitors additionally check the composite line for post-quantum authenticity.
//!
//! ### Signature-type assignment (the central design decision)
//!
//! The additive PQ primitive is the metamorphic-crypto composite signature
//! ([`metamorphic_crypto::sign`] / [`metamorphic_crypto::verify`]): **ML-DSA
//! (FIPS 204) + a classical partner (Ed25519, or Ed448/ECDSA-P-521 in the
//! matched suites), strict-AND**, with a 1-byte version/suite tag prefixing a
//! self-describing wire format, signing a length-prefixed context-framed message
//! (`I2OSP(len(ctx),8) || ctx || msg`). This construction matches **no**
//! C2SP-assigned `signed-note` signature type:
//!
//! - `0x06` is **single-algorithm** *timestamped ML-DSA-44 (sub)tree
//!   cosignatures* (per `c2sp.org/tlog-cosignature`): one algorithm, a timestamp
//!   prefix, and cosignature-specific note semantics. Reusing it would
//!   misrepresent our hybrid composite to real ML-DSA-44 cosignature verifiers.
//! - `0x02` (ECDSA) and `0x04` (timestamped Ed25519 cosignatures) likewise
//!   describe other constructions.
//! - `0xfa`–`0xfe` are **reserved for future use by C2SP** — not ours to claim.
//!
//! C2SP provides exactly one correct escape: `0xff`, "reserved for signature
//! types without an identifier byte assigned by this specification", which it
//! RECOMMENDS be followed by "a longer identifier that is unlikely to collide".
//! We therefore assign our composite the multi-byte type identifier
//! [`HYBRID_SIG_IDENTIFIER`] (`0xff` followed by a versioned namespace label).
//! This is forward-interop-safe: a C2SP verifier that doesn't know our key
//! simply ignores the line (unknown key), and we never squat an assigned or
//! reserved byte.
//!
//! The signature-type identifier participates in the key id and `vkey` exactly
//! as the spec describes (`key id = SHA-256(name || 0x0A || type id ||
//! pubkey)[:4]`; `vkey = name+hex(id)+base64(type id || pubkey)`); the spec's
//! formula is defined over the full (multi-byte) type identifier, so nothing in
//! the key-id/`vkey` math changes — only the identifier is longer. The composite
//! *public key* material carried after the identifier is the metamorphic-crypto
//! public key bytes (`tag || classical_pk || ml_dsa_pk`); its leading tag
//! self-describes the `(Suite, SecurityLevel)` posture (see
//! [`VerifierKey::hybrid_posture_tag`]), which the Slice-5 policy layer can later
//! reconcile (declared == observed). The composite signature bytes carried after
//! the key id are the metamorphic-crypto signature blob verbatim.
//!
//! ### Signing context
//!
//! The composite signs the note text under the fixed, versioned context
//! [`HYBRID_SIG_CONTEXT`]. This binds a hybrid note signature to its purpose and
//! is reproduced byte-identically across native Rust, WASM, and the Elixir NIF
//! (the framing is metamorphic-crypto's `I2OSP(len(ctx),8) || ctx || msg`).
//! Because ML-DSA signing is hedged/randomized, composite signature **bytes are
//! not reproducible**, but **verification is fully deterministic** — so our KATs
//! pin the (deterministic) public key / `vkey` and lock a stored signature that
//! [`SignedNote::verify`] accepts byte-for-byte.
//!
//! [`signed-note`]: https://c2sp.org/signed-note
//! [`metamorphic_crypto::sign`]: metamorphic_crypto::sign()
//! [`metamorphic_crypto::verify`]: metamorphic_crypto::verify()

use crate::encoding::{base64_decode, base64_encode, hex_decode, hex_encode};
use crate::error::{Error, Result};

/// The em dash + space prefix that begins every signature line (`U+2014 ` ).
const SIG_PREFIX: &str = "— ";
/// The blank-line separator between the note text and the signature block.
const SIG_SPLIT: &str = "\n\n";
/// Maximum number of signatures parsed from a single note (DoS guard). The spec
/// requires accepting at least 16; we mirror Go's generous limit of 100.
const MAX_SIGNATURES: usize = 100;

/// The C2SP `signed-note` type identifier for the metamorphic-crypto hybrid
/// composite signature (ML-DSA + classical, strict-AND).
///
/// It uses the spec's `0xff` escape ("signature types without an identifier byte
/// assigned by this specification") followed by a versioned namespace label that
/// is "unlikely to collide", as the spec RECOMMENDS. See the module-level docs
/// for why no assigned/reserved byte fits this construction.
pub const HYBRID_SIG_IDENTIFIER: &[u8] = b"\xffmetamorphic.app/composite-mldsa-ed25519/v1";

/// The fixed, versioned signing context bound into every hybrid composite note
/// signature (metamorphic-crypto frames it as `I2OSP(len(ctx),8) || ctx ||
/// note_text`). Changing this label is a breaking change to the hybrid line.
pub const HYBRID_SIG_CONTEXT: &str = "metamorphic.app/signed-note/v1";

/// A note signature algorithm, identified by its C2SP `signed-note` type
/// identifier (one or more bytes).
///
/// [`SignatureType::Ed25519`] (`0x01`) is the classical, witness-compatible
/// algorithm. [`SignatureType::MetamorphicHybrid`] (the `0xff`-escaped
/// [`HYBRID_SIG_IDENTIFIER`]) is the additive post-quantum composite. Other
/// assigned bytes (ECDSA `0x02`, the cosignature types, etc.) are recognized as
/// *unknown* and their lines are ignored by verifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureType {
    /// `0x01` — Ed25519 over the note text (RFC 8032).
    Ed25519,
    /// [`HYBRID_SIG_IDENTIFIER`] — the metamorphic-crypto ML-DSA + classical
    /// composite (strict-AND), over the note text under [`HYBRID_SIG_CONTEXT`].
    MetamorphicHybrid,
}

impl SignatureType {
    /// The on-the-wire type identifier (one byte for Ed25519, the multi-byte
    /// `0xff`-escaped label for the hybrid composite).
    #[must_use]
    pub fn type_identifier(self) -> &'static [u8] {
        match self {
            SignatureType::Ed25519 => &[0x01],
            SignatureType::MetamorphicHybrid => HYBRID_SIG_IDENTIFIER,
        }
    }

    /// Detect the signature type from the leading bytes of encoded key material
    /// (`type identifier || public key`), returning the type and the byte length
    /// of its identifier prefix.
    fn detect(key: &[u8]) -> Result<(SignatureType, usize)> {
        if key.first() == Some(&0x01) {
            return Ok((SignatureType::Ed25519, 1));
        }
        if key.starts_with(HYBRID_SIG_IDENTIFIER) {
            return Ok((
                SignatureType::MetamorphicHybrid,
                HYBRID_SIG_IDENTIFIER.len(),
            ));
        }
        Err(Error::MalformedNote(format!(
            "unsupported signature type (leading byte 0x{:02x})",
            key.first().copied().unwrap_or(0)
        )))
    }
}

/// A trusted verifier key: the data needed to recognize and check signatures
/// from one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierKey {
    name: String,
    key_id: u32,
    sig_type: SignatureType,
    public_key: Vec<u8>,
}

impl VerifierKey {
    /// Build an Ed25519 verifier key from a name and 32-byte public key,
    /// computing the key id per the spec.
    ///
    /// # Errors
    /// Returns [`Error::MalformedNote`] if the name is invalid or the public key
    /// is not 32 bytes.
    pub fn new_ed25519(name: &str, public_key: &[u8]) -> Result<Self> {
        if !is_valid_name(name) {
            return Err(Error::MalformedNote(format!("invalid key name: {name:?}")));
        }
        if public_key.len() != 32 {
            return Err(Error::MalformedNote(format!(
                "Ed25519 public key must be 32 bytes, got {}",
                public_key.len()
            )));
        }
        let key_id = compute_key_id(name, SignatureType::Ed25519.type_identifier(), public_key);
        Ok(Self {
            name: name.to_string(),
            key_id,
            sig_type: SignatureType::Ed25519,
            public_key: public_key.to_vec(),
        })
    }

    /// Build a hybrid composite verifier key from a name and the
    /// metamorphic-crypto public key bytes (`tag || classical_pk || ml_dsa_pk`),
    /// computing the key id per the spec over [`HYBRID_SIG_IDENTIFIER`].
    ///
    /// # Errors
    /// Returns [`Error::MalformedNote`] if the name is invalid or the public key
    /// is empty.
    pub fn new_hybrid(name: &str, public_key: &[u8]) -> Result<Self> {
        if !is_valid_name(name) {
            return Err(Error::MalformedNote(format!("invalid key name: {name:?}")));
        }
        if public_key.is_empty() {
            return Err(Error::MalformedNote(
                "hybrid composite public key must be non-empty".into(),
            ));
        }
        let key_id = compute_key_id(
            name,
            SignatureType::MetamorphicHybrid.type_identifier(),
            public_key,
        );
        Ok(Self {
            name: name.to_string(),
            key_id,
            sig_type: SignatureType::MetamorphicHybrid,
            public_key: public_key.to_vec(),
        })
    }

    /// Parse a verifier key string `<name>+<hex key id>+<base64(type||key)>`.
    ///
    /// # Errors
    /// Returns [`Error::MalformedNote`] if the structure, hex id, base64, key
    /// length, or recomputed key id is invalid, or [`Error::MalformedNote`] for
    /// an unsupported signature type.
    pub fn parse(vkey: &str) -> Result<Self> {
        let malformed = || Error::MalformedNote(format!("malformed verifier key: {vkey:?}"));
        let (name, rest) = vkey.split_once('+').ok_or_else(malformed)?;
        let (hash_hex, key_b64) = rest.split_once('+').ok_or_else(malformed)?;

        if hash_hex.len() != 8 {
            return Err(malformed());
        }
        let hash_bytes = hex_decode(hash_hex)?;
        let declared_id =
            u32::from_be_bytes([hash_bytes[0], hash_bytes[1], hash_bytes[2], hash_bytes[3]]);

        let key = base64_decode(key_b64)?;
        if key.is_empty() || !is_valid_name(name) {
            return Err(malformed());
        }

        // key id is computed over the full (type-identifier || public-key)
        // material, exactly as the spec defines it.
        let computed_id = key_hash(name, &key);
        if computed_id != declared_id {
            return Err(Error::MalformedNote(format!(
                "verifier key id mismatch: declared {declared_id:08x}, computed {computed_id:08x}"
            )));
        }

        let (sig_type, id_len) = SignatureType::detect(&key)?;
        let public_key = &key[id_len..];
        match sig_type {
            SignatureType::Ed25519 if public_key.len() != 32 => return Err(malformed()),
            SignatureType::MetamorphicHybrid if public_key.is_empty() => return Err(malformed()),
            _ => {}
        }

        Ok(Self {
            name: name.to_string(),
            key_id: declared_id,
            sig_type,
            public_key: public_key.to_vec(),
        })
    }

    /// Encode this verifier key as a `vkey` string.
    #[must_use]
    pub fn encode(&self) -> String {
        let id = self.sig_type.type_identifier();
        let mut key = Vec::with_capacity(id.len() + self.public_key.len());
        key.extend_from_slice(id);
        key.extend_from_slice(&self.public_key);
        format!(
            "{}+{}+{}",
            self.name,
            hex_encode(&self.key_id.to_be_bytes()),
            base64_encode(&key)
        )
    }

    /// The key name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The 4-byte key id as a big-endian `u32`.
    #[must_use]
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// The signature algorithm.
    #[must_use]
    pub fn signature_type(&self) -> SignatureType {
        self.sig_type
    }

    /// The raw public key material (`type identifier`-stripped): the 32-byte
    /// Ed25519 key, or the metamorphic-crypto composite public key bytes
    /// (`tag || classical_pk || ml_dsa_pk`) for a hybrid key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// For a [`SignatureType::MetamorphicHybrid`] key, the metamorphic-crypto
    /// composite **posture tag** — the leading byte of the composite public key
    /// that self-describes its `(Suite, SecurityLevel)` (e.g. `0x02` = Hybrid
    /// Cat-3). Returns `None` for non-hybrid keys.
    ///
    /// This is informational only; the authoritative posture decode lives in
    /// metamorphic-crypto. It is surfaced so the Slice-5 `NamespacePolicy` layer
    /// can later reconcile the *declared* posture against this *observed* tag
    /// without this crate reimplementing any crypto.
    #[must_use]
    pub fn hybrid_posture_tag(&self) -> Option<u8> {
        match self.sig_type {
            SignatureType::MetamorphicHybrid => self.public_key.first().copied(),
            SignatureType::Ed25519 => None,
        }
    }
}

/// A single signature line parsed from a note (not yet verified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    name: String,
    key_id: u32,
    /// The signature bytes following the 4-byte key id.
    signature: Vec<u8>,
}

impl Signature {
    /// The key name from the signature line.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The 4-byte key id as a big-endian `u32`.
    #[must_use]
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// The raw signature bytes (after the key id).
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The base64 signature blob (`key id || signature`) as it appears on the
    /// wire.
    #[must_use]
    fn to_base64(&self) -> String {
        let mut blob = Vec::with_capacity(4 + self.signature.len());
        blob.extend_from_slice(&self.key_id.to_be_bytes());
        blob.extend_from_slice(&self.signature);
        base64_encode(&blob)
    }
}

/// A parsed signed note: the signed text plus its (still unverified) signature
/// lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedNote {
    text: String,
    signatures: Vec<Signature>,
}

impl SignedNote {
    /// Create a signed note from text and signatures.
    ///
    /// # Errors
    /// Returns [`Error::MalformedNote`] if `text` does not end in a newline.
    pub fn new(text: String, signatures: Vec<Signature>) -> Result<Self> {
        if !text.ends_with('\n') {
            return Err(Error::MalformedNote("note text must end in newline".into()));
        }
        Ok(Self { text, signatures })
    }

    /// The note text (including its final newline; excluding the separating
    /// blank line). This is the exact byte string signatures are computed over.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The parsed signature lines.
    #[must_use]
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Parse a complete signed-note byte string.
    ///
    /// Mirrors the reference Go `note.Open` structural parse: validates UTF-8
    /// and the no-control-characters rule, splits the text from the trailing
    /// signature block at the **last** blank line, and parses each signature
    /// line. Signatures are not verified here; call [`SignedNote::verify`].
    ///
    /// # Errors
    /// Returns [`Error::MalformedNote`] for any structural violation.
    pub fn parse(msg: &str) -> Result<Self> {
        // UTF-8 is guaranteed by `&str`. Reject ASCII control chars except '\n'.
        if msg.bytes().any(|b| b < 0x20 && b != b'\n') {
            return Err(Error::MalformedNote(
                "note contains a forbidden control character".into(),
            ));
        }

        let split = msg
            .rfind(SIG_SPLIT)
            .ok_or_else(|| Error::MalformedNote("missing blank-line signature separator".into()))?;
        let text = &msg[..split + 1];
        let sig_block = &msg[split + 2..];
        if sig_block.is_empty() || !sig_block.ends_with('\n') {
            return Err(Error::MalformedNote(
                "signature block is empty or unterminated".into(),
            ));
        }

        let mut signatures = Vec::new();
        for line in sig_block.lines() {
            let body = line.strip_prefix(SIG_PREFIX).ok_or_else(|| {
                Error::MalformedNote(format!("signature line missing '— ' prefix: {line:?}"))
            })?;
            let (name, b64) = body
                .split_once(' ')
                .ok_or_else(|| Error::MalformedNote("signature line missing space".into()))?;
            if !is_valid_name(name) || b64.is_empty() {
                return Err(Error::MalformedNote(format!(
                    "invalid signature line name/blob: {line:?}"
                )));
            }
            let blob = base64_decode(b64)?;
            if blob.len() < 5 {
                return Err(Error::MalformedNote("signature blob too short".into()));
            }
            let key_id = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]);
            signatures.push(Signature {
                name: name.to_string(),
                key_id,
                signature: blob[4..].to_vec(),
            });
            if signatures.len() > MAX_SIGNATURES {
                return Err(Error::MalformedNote("too many signatures".into()));
            }
        }

        Self::new(text.to_string(), signatures)
    }

    /// Serialize this signed note to its canonical byte string:
    /// `text || "\n" || signature lines`.
    #[must_use]
    pub fn marshal(&self) -> String {
        let mut out = String::with_capacity(self.text.len() + 1 + self.signatures.len() * 80);
        out.push_str(&self.text);
        out.push('\n');
        for sig in &self.signatures {
            out.push_str(SIG_PREFIX);
            out.push_str(&sig.name);
            out.push(' ');
            out.push_str(&sig.to_base64());
            out.push('\n');
        }
        out
    }

    /// Verify the note against a set of trusted verifier keys.
    ///
    /// Following the C2SP `signed-note` rules:
    /// - signatures whose `(name, key id)` match no trusted key are **ignored**;
    /// - if a signature from a *known* key fails to verify, the whole note is
    ///   rejected ([`Error::InvalidSignature`]);
    /// - if no signature from a trusted key verifies, the note is rejected
    ///   ([`Error::NoTrustedSignature`]).
    ///
    /// On success returns references to the signatures that verified.
    ///
    /// # Errors
    /// [`Error::InvalidSignature`] or [`Error::NoTrustedSignature`] as above.
    pub fn verify<'a>(&'a self, trusted: &[VerifierKey]) -> Result<Vec<&'a Signature>> {
        let mut verified = Vec::new();
        for sig in &self.signatures {
            let Some(key) = trusted
                .iter()
                .find(|k| k.key_id == sig.key_id && k.name == sig.name)
            else {
                continue; // unknown key: ignore
            };

            let ok = match key.sig_type {
                SignatureType::Ed25519 => {
                    // A wrong-length signature/key is a verification failure, not
                    // a structural parse error at this point.
                    metamorphic_crypto::ed25519_verify(
                        &key.public_key,
                        self.text.as_bytes(),
                        &sig.signature,
                    )
                    .unwrap_or(false)
                }
                SignatureType::MetamorphicHybrid => {
                    // Independently verify the composite (strict-AND ML-DSA +
                    // classical) via the single-source-of-truth primitive. The
                    // metamorphic-crypto API speaks base64; a malformed blob or
                    // key decodes to a verification failure here, never a panic.
                    let sig_b64 = base64_encode(&sig.signature);
                    let pk_b64 = base64_encode(&key.public_key);
                    metamorphic_crypto::verify(
                        self.text.as_bytes(),
                        HYBRID_SIG_CONTEXT,
                        &sig_b64,
                        &pk_b64,
                    )
                    .unwrap_or(false)
                }
            };

            if ok {
                verified.push(sig);
            } else {
                return Err(Error::InvalidSignature {
                    name: sig.name.clone(),
                    key_id: sig.key_id,
                });
            }
        }

        if verified.is_empty() {
            return Err(Error::NoTrustedSignature);
        }
        Ok(verified)
    }
}

/// Sign `text` with a raw Ed25519 seed, producing a [`Signature`] line for the
/// given key name.
///
/// Provided for tests, tooling, and (eventually) emitting our own classical
/// witness-compatible line. `text` must be the exact note text (ending in a
/// newline); the signature is computed over it via the single-source-of-truth
/// [`metamorphic_crypto::ed25519_sign`].
///
/// # Errors
/// Returns [`Error::MalformedNote`] for an invalid name, and propagates a
/// primitive error if `seed` is not 32 bytes.
pub fn sign_ed25519(text: &str, name: &str, seed: &[u8]) -> Result<Signature> {
    if !is_valid_name(name) {
        return Err(Error::MalformedNote(format!("invalid key name: {name:?}")));
    }
    let public_key = metamorphic_crypto::ed25519_public_key(seed)
        .map_err(|e| Error::MalformedNote(format!("invalid Ed25519 seed: {e}")))?;
    let key_id = compute_key_id(name, SignatureType::Ed25519.type_identifier(), &public_key);
    let signature = metamorphic_crypto::ed25519_sign(seed, text.as_bytes())
        .map_err(|e| Error::MalformedNote(format!("Ed25519 signing failed: {e}")))?;
    Ok(Signature {
        name: name.to_string(),
        key_id,
        signature: signature.to_vec(),
    })
}

/// Sign `text` with a metamorphic-crypto hybrid composite secret key (base64
/// `tag || classical_seed || ml_dsa_seed`), producing an additive PQ
/// [`Signature`] line for the given key name.
///
/// The signature is the composite (strict-AND ML-DSA + classical) over the note
/// text under [`HYBRID_SIG_CONTEXT`], computed via the single-source-of-truth
/// [`metamorphic_crypto::sign`]. Because ML-DSA signing is hedged, the bytes are
/// not reproducible (but verification is deterministic). The matching verifier
/// key is derived from the secret key's public half (see
/// [`metamorphic_crypto::derive_public_key`]) and carried in the line's key id.
///
/// # Errors
/// Returns [`Error::MalformedNote`] for an invalid name, and
/// [`Error::HybridSignature`] if the secret key cannot be decoded/derived or the
/// composite signature cannot be produced.
pub fn sign_hybrid(text: &str, name: &str, secret_key_b64: &str) -> Result<Signature> {
    if !is_valid_name(name) {
        return Err(Error::MalformedNote(format!("invalid key name: {name:?}")));
    }
    let public_key_b64 = metamorphic_crypto::derive_public_key(secret_key_b64)
        .map_err(|e| Error::HybridSignature(format!("invalid hybrid secret key: {e}")))?;
    let public_key = base64_decode(&public_key_b64)?;
    let key_id = compute_key_id(
        name,
        SignatureType::MetamorphicHybrid.type_identifier(),
        &public_key,
    );
    let sig_b64 = metamorphic_crypto::sign(text.as_bytes(), HYBRID_SIG_CONTEXT, secret_key_b64)
        .map_err(|e| Error::HybridSignature(format!("hybrid signing failed: {e}")))?;
    let signature = base64_decode(&sig_b64)?;
    Ok(Signature {
        name: name.to_string(),
        key_id,
        signature,
    })
}

/// `keyHash` over the full encoded key material (`type identifier || public
/// key`): the big-endian `u32` of `SHA-256(name || 0x0A || key)[:4]`.
fn key_hash(name: &str, key: &[u8]) -> u32 {
    let mut buf = Vec::with_capacity(name.len() + 1 + key.len());
    buf.extend_from_slice(name.as_bytes());
    buf.push(0x0A);
    buf.extend_from_slice(key);
    let digest = metamorphic_crypto::hash::sha256(&buf);
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

/// Compute the key id from a name, signature-type identifier, and public key.
fn compute_key_id(name: &str, type_id: &[u8], public_key: &[u8]) -> u32 {
    let mut key = Vec::with_capacity(type_id.len() + public_key.len());
    key.extend_from_slice(type_id);
    key.extend_from_slice(public_key);
    key_hash(name, &key)
}

/// A key name is valid iff it is non-empty and contains no Unicode whitespace
/// or `+`.
fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(|c| c.is_whitespace() || c == '+')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical example verifier key + signed note from the signed-note
    /// spec. Locking these proves byte-for-byte parse + verify interop.
    const SPEC_VKEY: &str = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
    const SPEC_NOTE: &str = "This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n";

    #[test]
    fn spec_vkey_parses_and_round_trips() {
        let vkey = VerifierKey::parse(SPEC_VKEY).unwrap();
        assert_eq!(vkey.name(), "example.com/foo");
        assert_eq!(vkey.key_id(), 0x530d_903a);
        assert_eq!(vkey.signature_type(), SignatureType::Ed25519);
        assert_eq!(vkey.encode(), SPEC_VKEY);
    }

    #[test]
    fn spec_note_parses_and_verifies() {
        let vkey = VerifierKey::parse(SPEC_VKEY).unwrap();
        let note = SignedNote::parse(SPEC_NOTE).unwrap();
        assert_eq!(note.text(), "This is an example message.\n");
        assert_eq!(note.signatures().len(), 1);
        assert_eq!(note.signatures()[0].key_id(), 0x530d_903a);

        let verified = note.verify(&[vkey]).unwrap();
        assert_eq!(verified.len(), 1);

        // Marshalling reproduces the exact wire bytes.
        assert_eq!(note.marshal(), SPEC_NOTE);
    }

    #[test]
    fn tampered_text_fails_verification() {
        let vkey = VerifierKey::parse(SPEC_VKEY).unwrap();
        let tampered = SPEC_NOTE.replace("example message", "EVIL message");
        let note = SignedNote::parse(&tampered).unwrap();
        assert!(matches!(
            note.verify(&[vkey]),
            Err(Error::InvalidSignature { .. })
        ));
    }

    #[test]
    fn unknown_key_is_ignored_not_trusted() {
        // No trusted keys at all → note has no verifiable signature.
        let note = SignedNote::parse(SPEC_NOTE).unwrap();
        assert!(matches!(note.verify(&[]), Err(Error::NoTrustedSignature)));
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (seed, pk) = metamorphic_crypto::ed25519_generate_keypair();
        let text = "origin.example/log\n7\ncm9vdA==\n".to_string();
        let sig = sign_ed25519(&text, "origin.example/log", &seed).unwrap();
        let note = SignedNote::new(text.clone(), vec![sig]).unwrap();

        let vkey = VerifierKey::new_ed25519("origin.example/log", &pk).unwrap();
        let verified = note.verify(&[vkey]).unwrap();
        assert_eq!(verified.len(), 1);

        // Parse(marshal(x)) == x round trip.
        let reparsed = SignedNote::parse(&note.marshal()).unwrap();
        assert_eq!(reparsed, note);
    }

    #[test]
    fn parse_rejects_control_chars_and_missing_separator() {
        assert!(SignedNote::parse("no separator\n").is_err());
        assert!(SignedNote::parse("bad\x01char\n\n— a b AAAAAA==\n").is_err());
    }

    #[test]
    fn key_id_matches_spec_formula() {
        // Recompute the spec key id from the decoded public key.
        let vkey = VerifierKey::parse(SPEC_VKEY).unwrap();
        let recomputed = compute_key_id(
            vkey.name(),
            SignatureType::Ed25519.type_identifier(),
            &vkey.public_key,
        );
        assert_eq!(recomputed, 0x530d_903a);
    }

    #[test]
    fn hybrid_type_identifier_uses_0xff_escape() {
        // The hybrid identifier MUST start with the C2SP 0xff escape and be
        // longer than one byte (a namespaced label), per the spec recommendation.
        let id = SignatureType::MetamorphicHybrid.type_identifier();
        assert_eq!(id.first(), Some(&0xff));
        assert!(id.len() > 1);
        // Ed25519 stays a single 0x01 byte (byte-identical classical path).
        assert_eq!(SignatureType::Ed25519.type_identifier(), &[0x01]);
    }

    #[test]
    fn hybrid_sign_verify_and_vkey_round_trip() {
        let kp = metamorphic_crypto::generate_signing_keypair(); // Hybrid Cat-3
        let pk = base64_decode(&kp.public_key).unwrap();
        let text = "origin.example/log\n7\ncm9vdA==\n".to_string();

        let sig = sign_hybrid(&text, "origin.example/log", &kp.secret_key).unwrap();
        let note = SignedNote::new(text, vec![sig]).unwrap();

        let vkey = VerifierKey::new_hybrid("origin.example/log", &pk).unwrap();
        assert_eq!(vkey.signature_type(), SignatureType::MetamorphicHybrid);
        // Posture tag is the composite's leading byte (0x02 = Hybrid Cat-3).
        assert_eq!(vkey.hybrid_posture_tag(), Some(0x02));
        // vkey encodes and re-parses byte-for-byte (multi-byte type identifier).
        assert_eq!(VerifierKey::parse(&vkey.encode()).unwrap(), vkey);

        let verified = note.verify(&[vkey]).unwrap();
        assert_eq!(verified.len(), 1);

        // Parse(marshal(x)) == x round trip across the larger PQ blob.
        let reparsed = SignedNote::parse(&note.marshal()).unwrap();
        assert_eq!(reparsed, note);
    }

    #[test]
    fn hybrid_tampered_text_is_rejected() {
        let kp = metamorphic_crypto::generate_signing_keypair();
        let pk = base64_decode(&kp.public_key).unwrap();
        let text = "origin.example/log\n7\ncm9vdA==\n".to_string();
        let sig = sign_hybrid(&text, "origin.example/log", &kp.secret_key).unwrap();
        let note = SignedNote::new(text, vec![sig]).unwrap();

        // Forge a note with the same signatures but different text.
        let forged = SignedNote::new(
            "origin.example/log\n8\nZXZpbA==\n".to_string(),
            note.signatures().to_vec(),
        )
        .unwrap();
        let vkey = VerifierKey::new_hybrid("origin.example/log", &pk).unwrap();
        assert!(matches!(
            forged.verify(&[vkey]),
            Err(Error::InvalidSignature { .. })
        ));
    }

    #[test]
    fn classical_and_hybrid_lines_coexist() {
        let (seed, ed_pk) = metamorphic_crypto::ed25519_generate_keypair();
        let kp = metamorphic_crypto::generate_signing_keypair();
        let pk = base64_decode(&kp.public_key).unwrap();
        let text = "origin.example/log\n9\ncm9vdA==\n".to_string();

        let ed_sig = sign_ed25519(&text, "origin.example/log", &seed).unwrap();
        let pq_sig = sign_hybrid(&text, "origin.example/log-pq", &kp.secret_key).unwrap();
        let note = SignedNote::new(text, vec![ed_sig, pq_sig]).unwrap();

        let ed_vkey = VerifierKey::new_ed25519("origin.example/log", &ed_pk).unwrap();
        let pq_vkey = VerifierKey::new_hybrid("origin.example/log-pq", &pk).unwrap();

        // A classical-only verifier accepts the note via the Ed25519 line and
        // ignores the unknown PQ line.
        assert_eq!(
            note.verify(std::slice::from_ref(&ed_vkey)).unwrap().len(),
            1
        );
        // A PQ-aware verifier with both keys accepts both lines.
        assert_eq!(note.verify(&[ed_vkey, pq_vkey]).unwrap().len(), 2);
    }
}
