//! Backend-agnostic **anchoring / attestation** (Slice 8, #338).
//!
//! A transparency log's anti-equivocation guarantee is only as strong as a
//! relying party's ability to detect a *split view*: an operator showing one
//! checkpoint to Alice and a different, inconsistent one to Bob. Independent
//! witnesses ([`crate::note`]) are one defence. **Anchoring** is the other:
//! periodically committing a checkpoint's signed tree head to an external,
//! hard-to-equivocate medium — a blockchain transaction, a notary receipt
//! ([RFC 3161]), object-lock / WORM storage, or another transparency log — so
//! that the operator cannot later present a tree that disagrees with what was
//! anchored without that contradiction being publicly visible.
//!
//! This module is the OSS engine's contribution to anchoring: the **format**
//! and the **verification**. It is deliberately *backend-agnostic and I/O-free*.
//! There is no network client, no chain RPC, no notary integration, and no
//! anchor *cadence / fee / confirmation-depth* policy here — those are the
//! operator's job (the paid mosskeys app, per the #290 open-core boundary). What
//! lives here is:
//!
//! 1. [`AnchorRecord`] — the canonical, byte-locked **attestation record** that
//!    binds a checkpoint *head* (`origin`, `size`, `root_hash`) to an **opaque
//!    locator** plus an agnostic **[`Medium`]** tag. The locator is fully opaque
//!    bytes, so a chain transaction id, a block height, a notary receipt
//!    handle, or a DC3 object key all serialise identically. The medium tag is a
//!    free-form (validated) identifier, so new media never need a library
//!    release.
//!
//! 2. [`CommitmentSink`] — the **interface-only** trait an operator implements
//!    for its medium (mirroring the Slice-7 [`crate::ingest::TileReader`]: an
//!    associated [`CommitmentSink::Error`], no async, no I/O in this crate). A
//!    logic-only bridge ([`verify_commitment_via`], [`anchor_checkpoint_via`])
//!    shows the trait composes with the format without performing any I/O
//!    itself.
//!
//! 3. [`verify_anchored`] — the **verification helper** that a third party uses
//!    to audit *“the operator never equivocated between anchored heads”* without
//!    trusting the operator or the anchoring medium. It checks the attestation
//!    actually binds the checkpoint, and (given a previous anchored head + an
//!    RFC 9162 consistency proof) recomputes append-only consistency via
//!    [`crate::proof::verify_consistency`].
//!
//! ## Honest framing (no zero-knowledge here)
//!
//! This is **plain anchoring** — publish a checkpoint-head commitment and prove
//! consistency between successive anchored heads. It is the 90% case and
//! involves **zero** zero-knowledge machinery. An optional ZK-anchoring
//! enhancement is a *separate*, design-spike-first effort (#339) and is **not**
//! coupled to this format.
//!
//! ## What the commitment is (and why it is not operator-tunable at runtime)
//!
//! The value committed to the medium is the [`AnchorRecord::anchor_commitment`]:
//! a fixed-size digest over the canonical checkpoint *head* under a versioned,
//! domain-separated context. The hash is selected from a small **safe menu**
//! ([`AnchorCommitment`]) encoded as a self-describing tag byte in the record,
//! **not** a free-form operator input. A transparency log only works if every
//! independent verifier recomputes the same bytes; letting operators inject
//! arbitrary hash functions would fragment interoperability and invite downgrade
//! attacks. Adding a new algorithm to the menu is therefore a deliberate,
//! reviewed, additive change (a new tag), exactly like the Layer-0 canonical
//! formats it sits beside. In v0.1 the menu has a single entry, SHA3-512, which
//! is already post-quantum-grade (~256-bit collision resistance) for the public
//! head it digests.
//!
//! ## Byte / determinism discipline
//!
//! Like every canonical encoding in this crate, [`AnchorRecord`] uses the fixed
//! discipline — big-endian integers, `u32`-be length-prefixed (`lp`) variable
//! fields, a domain-separated context label — so independent implementations
//! (native, WASM, the Elixir NIF) recompute it byte-for-byte. It touches **no**
//! audited Layer-1 / CONIKS / VRF / policy canonical bytes.
//!
//! [RFC 3161]: https://www.rfc-editor.org/rfc/rfc3161

use metamorphic_crypto::hash::sha3_512_with_context;

use crate::checkpoint::Checkpoint;
use crate::error::{Error, Result};
use crate::merkle::{HASH_LEN, Hash, hash_leaf};

/// The fixed canonical byte-layout version of the [`AnchorRecord`] (the
/// discipline version). A layout change is a new value here, never a silent
/// reinterpretation.
pub const ANCHOR_FORMAT_VERSION: u32 = 1;

/// The versioned, domain-separated context label under which the
/// [`AnchorRecord::anchor_commitment`] is computed. Bumping the format version
/// (and this label) is the algorithm-agility path for the commitment.
pub const ANCHOR_COMMITMENT_CONTEXT: &str = "metamorphic-log/anchor-commitment/v1";

/// Maximum length, in bytes, of a [`Medium`] identifier. Bounded so the `u32`
/// length-prefix can never be abused and the value stays index-friendly.
pub const MAX_MEDIUM_LEN: usize = 255;

/// The **safe menu** of hash algorithms for the anchor commitment, encoded as a
/// self-describing tag byte in the [`AnchorRecord`].
///
/// This is intentionally a *closed, reviewed* menu rather than a free-form
/// operator input: every independent verifier must recompute the same
/// commitment, so the algorithm is part of the agreed-upon wire format, not a
/// runtime knob. Tags are shared with [`crate::policy::CommitmentHash`] for
/// cross-layer coherence (`0x02` = SHA3-512). Adding a member (e.g. a future
/// SHA3-256 variant, reserved `0x01`, or a future PQ hash) is an additive change
/// and would first require the matching domain-separated primitive in
/// `metamorphic-crypto` — this crate never frames a hash itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AnchorCommitment {
    /// SHA3-512 over the canonical checkpoint head, domain-separated by
    /// [`ANCHOR_COMMITMENT_CONTEXT`]. Produces a 64-byte commitment. The v0.1
    /// default and only entry; already post-quantum-grade for a public head.
    Sha3_512,
}

impl AnchorCommitment {
    const TAG_SHA3_512: u8 = 0x02;

    /// The self-describing tag byte for this algorithm (stored in the record).
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            AnchorCommitment::Sha3_512 => Self::TAG_SHA3_512,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            Self::TAG_SHA3_512 => Ok(AnchorCommitment::Sha3_512),
            other => Err(Error::MalformedAnchor(format!(
                "unknown anchor commitment algorithm tag 0x{other:02x}"
            ))),
        }
    }

    /// The byte length of a commitment produced by this algorithm.
    #[must_use]
    pub fn digest_len(self) -> usize {
        match self {
            AnchorCommitment::Sha3_512 => 64,
        }
    }

    /// Compute the commitment over the canonical checkpoint `head` bytes under
    /// [`ANCHOR_COMMITMENT_CONTEXT`].
    #[must_use]
    fn compute(self, head: &[u8]) -> Vec<u8> {
        match self {
            AnchorCommitment::Sha3_512 => {
                sha3_512_with_context(ANCHOR_COMMITMENT_CONTEXT, head).to_vec()
            }
        }
    }
}

/// A validated, agnostic **medium identifier** — the backend an attestation was
/// committed to.
///
/// Kept deliberately free-form (within a strict grammar) so the crate never
/// needs a release to support a new anchoring backend: `"dc3"`,
/// `"ethereum/mainnet"`, `"ethereum/sepolia"`, `"opentimestamps"`, `"rfc3161"`,
/// or `"c2sp-tlog/sunlight"` are all valid. The grammar is small and strict so
/// identifiers stay unambiguous and index-friendly:
///
/// - non-empty and at most [`MAX_MEDIUM_LEN`] bytes,
/// - every byte is printable ASCII (`0x21..=0x7e`) — no whitespace, no control
///   characters (so it never carries hidden bytes or accidental PII whitespace).
///
/// `/` is permitted so identifiers can be hierarchical (chain + network).
///
/// ```
/// use metamorphic_log::anchor::Medium;
///
/// let m = Medium::parse("ethereum/mainnet").unwrap();
/// assert_eq!(m.as_str(), "ethereum/mainnet");
///
/// assert!(Medium::parse("").is_err());            // empty
/// assert!(Medium::parse("has space").is_err());   // whitespace
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Medium(String);

impl Medium {
    /// Parse and validate a medium identifier.
    ///
    /// # Errors
    /// Returns [`Error::MalformedAnchor`] if `id` is empty, longer than
    /// [`MAX_MEDIUM_LEN`] bytes, or contains a byte outside printable ASCII.
    pub fn parse(id: &str) -> Result<Self> {
        if id.is_empty() {
            return Err(Error::MalformedAnchor("medium must be non-empty".into()));
        }
        if id.len() > MAX_MEDIUM_LEN {
            return Err(Error::MalformedAnchor(format!(
                "medium is {} bytes, exceeds the {MAX_MEDIUM_LEN}-byte maximum",
                id.len()
            )));
        }
        if !id.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(Error::MalformedAnchor(
                "medium must be printable ASCII with no whitespace or control bytes".into(),
            ));
        }
        Ok(Self(id.to_string()))
    }

    /// The medium identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The canonical, byte-locked **anchor attestation record**.
///
/// Binds a checkpoint *head* — `(origin, size, root_hash)` — to an opaque
/// external-commitment `locator` and an agnostic [`Medium`] tag, plus the
/// [`AnchorCommitment`] algorithm used. Construct via
/// [`AnchorRecord::for_checkpoint`] (which lifts the head straight off a
/// [`Checkpoint`], so operators never hand-wire the binding) or
/// [`AnchorRecord::new`]; serialise via [`AnchorRecord::canonical_bytes`]; parse
/// via [`AnchorRecord::parse`].
///
/// The record is itself a valid Layer-0 leaf ([`AnchorRecord::rfc6962_leaf_hash`])
/// so an operator may *also* log its attestations if it wishes. It is **not**
/// signed on its own — the anchored head it references is already a signed
/// checkpoint, and the anchoring medium provides the hard-to-equivocate
/// property. The record is designed to be *wrappable*: a future signed envelope
/// (mirroring [`crate::policy::SignedPolicy`] over
/// [`crate::policy::NamespacePolicy`]) can add an operator signature — and, if a
/// compliance use-case ever needs it, an authenticated timestamp — additively,
/// without changing these core bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRecord {
    origin: String,
    size: u64,
    root_hash: Hash,
    commitment_alg: AnchorCommitment,
    medium: Medium,
    locator: Vec<u8>,
}

impl AnchorRecord {
    /// Build an attestation binding an explicit checkpoint head to a locator.
    ///
    /// Prefer [`AnchorRecord::for_checkpoint`] when you hold the [`Checkpoint`].
    ///
    /// # Errors
    /// Returns [`Error::MalformedAnchor`] if `origin` is empty or contains a
    /// newline (matching the checkpoint origin rule), or if `locator` is empty
    /// (an empty external-commitment locator is meaningless).
    pub fn new(
        origin: &str,
        size: u64,
        root_hash: Hash,
        commitment_alg: AnchorCommitment,
        medium: Medium,
        locator: Vec<u8>,
    ) -> Result<Self> {
        if origin.is_empty() || origin.contains('\n') {
            return Err(Error::MalformedAnchor(
                "origin must be non-empty and contain no newline".into(),
            ));
        }
        if locator.is_empty() {
            return Err(Error::MalformedAnchor("locator must be non-empty".into()));
        }
        Ok(Self {
            origin: origin.to_string(),
            size,
            root_hash,
            commitment_alg,
            medium,
            locator,
        })
    }

    /// Build an attestation by lifting the head `(origin, size, root_hash)` off
    /// `checkpoint`. This is the recommended constructor: it guarantees the
    /// attestation binds exactly the checkpoint the operator anchored.
    ///
    /// # Errors
    /// Returns [`Error::MalformedAnchor`] if `locator` is empty (the checkpoint
    /// origin is already validated to be non-empty and newline-free).
    pub fn for_checkpoint(
        checkpoint: &Checkpoint,
        commitment_alg: AnchorCommitment,
        medium: Medium,
        locator: Vec<u8>,
    ) -> Result<Self> {
        Self::new(
            checkpoint.origin(),
            checkpoint.size(),
            *checkpoint.root_hash(),
            commitment_alg,
            medium,
            locator,
        )
    }

    /// The bound checkpoint origin (log identity).
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The bound checkpoint tree size.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The bound RFC 6962 root hash at `size`.
    #[must_use]
    pub fn root_hash(&self) -> &Hash {
        &self.root_hash
    }

    /// The commitment algorithm this attestation declares.
    #[must_use]
    pub fn commitment_alg(&self) -> AnchorCommitment {
        self.commitment_alg
    }

    /// The medium the attestation was committed to.
    #[must_use]
    pub fn medium(&self) -> &Medium {
        &self.medium
    }

    /// The opaque external-commitment locator bytes.
    #[must_use]
    pub fn locator(&self) -> &[u8] {
        &self.locator
    }

    /// Whether this attestation binds `checkpoint`'s head exactly.
    #[must_use]
    pub fn binds(&self, checkpoint: &Checkpoint) -> bool {
        self.origin == checkpoint.origin()
            && self.size == checkpoint.size()
            && &self.root_hash == checkpoint.root_hash()
    }

    /// The canonical checkpoint-*head* bytes that the commitment digests. This
    /// is medium-independent (it excludes the medium tag and locator), so the
    /// same head produces the same commitment regardless of where it is
    /// anchored:
    ///
    /// ```text
    /// head = u32_be(ANCHOR_FORMAT_VERSION = 1)
    ///     || lp(origin)
    ///     || u64_be(size)
    ///     || lp(root_hash)
    /// ```
    #[must_use]
    pub fn head_bytes(&self) -> Vec<u8> {
        head_bytes(&self.origin, self.size, &self.root_hash)
    }

    /// The fixed-size commitment over the checkpoint head — the value an
    /// operator publishes to the external medium. Computed via the declared
    /// [`AnchorCommitment`] algorithm under [`ANCHOR_COMMITMENT_CONTEXT`]; its
    /// length is [`AnchorCommitment::digest_len`].
    #[must_use]
    pub fn anchor_commitment(&self) -> Vec<u8> {
        self.commitment_alg.compute(&self.head_bytes())
    }

    /// Build the canonical, byte-reproducible serialisation of this record:
    ///
    /// ```text
    /// canonical(anchor) =
    ///     u32_be(ANCHOR_FORMAT_VERSION = 1)
    ///  || lp(origin)
    ///  || u64_be(size)
    ///  || lp(root_hash)
    ///  || u8(commitment_alg tag)
    ///  || lp(medium)
    ///  || lp(locator)
    /// ```
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let origin = self.origin.as_bytes();
        let medium = self.medium.as_str().as_bytes();
        let mut out = Vec::with_capacity(
            4 + 4 + origin.len() + 8 + 4 + HASH_LEN + 1 + 4 + medium.len() + 4 + self.locator.len(),
        );
        out.extend_from_slice(&ANCHOR_FORMAT_VERSION.to_be_bytes());
        push_lp(&mut out, origin);
        out.extend_from_slice(&self.size.to_be_bytes());
        push_lp(&mut out, &self.root_hash);
        out.push(self.commitment_alg.tag());
        push_lp(&mut out, medium);
        push_lp(&mut out, &self.locator);
        out
    }

    /// Parse a record from its canonical bytes, validating the layout, the
    /// format version, the commitment-algorithm tag, the medium grammar, and the
    /// non-empty origin/locator rules.
    ///
    /// # Errors
    /// Returns [`Error::MalformedAnchor`] for an unknown format version, an
    /// unknown algorithm tag, a length-prefix overrun, a `root_hash` that is not
    /// exactly 32 bytes, an invalid medium, an empty origin/locator, or trailing
    /// bytes after the record.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut cur = Cursor::new(bytes);
        let format_version = cur.u32()?;
        if format_version != ANCHOR_FORMAT_VERSION {
            return Err(Error::MalformedAnchor(format!(
                "unknown anchor format version {format_version}"
            )));
        }
        let origin = core::str::from_utf8(cur.lp()?)
            .map_err(|_| Error::MalformedAnchor("origin is not valid UTF-8".into()))?
            .to_string();
        let size = cur.u64()?;
        let root_slice = cur.lp()?;
        let root_hash: Hash = root_slice.try_into().map_err(|_| {
            Error::MalformedAnchor(format!(
                "root_hash is {} bytes, want {HASH_LEN}",
                root_slice.len()
            ))
        })?;
        let commitment_alg = AnchorCommitment::from_tag(cur.u8()?)?;
        let medium = core::str::from_utf8(cur.lp()?)
            .map_err(|_| Error::MalformedAnchor("medium is not valid UTF-8".into()))
            .and_then(Medium::parse)?;
        let locator = cur.lp()?.to_vec();
        if !cur.is_empty() {
            return Err(Error::MalformedAnchor(
                "trailing bytes after anchor record".into(),
            ));
        }
        Self::new(&origin, size, root_hash, commitment_alg, medium, locator)
    }

    /// The RFC 6962 Merkle leaf hash `SHA-256(0x00 || canonical)` over the raw
    /// canonical record bytes, so an operator may log its attestations as
    /// Layer-0 leaves. Independent of the [`AnchorRecord::anchor_commitment`].
    #[must_use]
    pub fn rfc6962_leaf_hash(&self) -> Hash {
        hash_leaf(&self.canonical_bytes())
    }
}

/// Build the canonical, medium-independent checkpoint-head bytes (shared by
/// [`AnchorRecord::head_bytes`] and [`anchor_checkpoint_via`]).
fn head_bytes(origin: &str, size: u64, root_hash: &Hash) -> Vec<u8> {
    let origin = origin.as_bytes();
    let mut out = Vec::with_capacity(4 + 4 + origin.len() + 8 + 4 + HASH_LEN);
    out.extend_from_slice(&ANCHOR_FORMAT_VERSION.to_be_bytes());
    push_lp(&mut out, origin);
    out.extend_from_slice(&size.to_be_bytes());
    push_lp(&mut out, root_hash);
    out
}

/// A previously-anchored head and the RFC 9162 consistency proof linking it to
/// the checkpoint under verification.
///
/// Grouping the two into one borrow keeps the [`verify_anchored`] signature
/// stable as the ecosystem grows: future link metadata (e.g. a referenced
/// witness co-signature) becomes an additive field rather than a breaking
/// signature change. Construct via [`AnchorLink::new`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct AnchorLink<'a> {
    /// The previously-anchored (older) checkpoint head.
    pub prev_checkpoint: &'a Checkpoint,
    /// The RFC 9162 consistency proof from `prev_checkpoint` to the checkpoint
    /// under verification (each hash exactly 32 bytes).
    pub consistency_proof: &'a [Vec<u8>],
}

impl<'a> AnchorLink<'a> {
    /// Build a link from a previous anchored checkpoint and the consistency
    /// proof connecting it to the newer checkpoint.
    #[must_use]
    pub fn new(prev_checkpoint: &'a Checkpoint, consistency_proof: &'a [Vec<u8>]) -> Self {
        Self {
            prev_checkpoint,
            consistency_proof,
        }
    }
}

/// Verify an anchored checkpoint: that `attestation` binds `checkpoint`'s head,
/// and — given a previous anchored head — that the two are append-only
/// consistent.
///
/// This is the third-party audit of *“the operator never equivocated between
/// anchored heads”*: it trusts neither the operator nor the anchoring medium.
/// It does **not** itself fetch the locator from the medium (that is the
/// operator's [`CommitmentSink`] — see [`verify_commitment_via`]); it verifies
/// the *log-side* binding and consistency that the anchored commitment attests
/// to.
///
/// - The attestation must bind `checkpoint` exactly (`origin`, `size`,
///   `root_hash`), else [`Error::AnchorMismatch`].
/// - If `prev` is `Some`, its `prev_checkpoint` must share `checkpoint`'s origin
///   (anchoring is per-log), and the supplied consistency proof must prove
///   `checkpoint` is an append-only extension of `prev_checkpoint` via
///   [`crate::proof::verify_consistency`]. A fork or rewrite surfaces as
///   [`Error::RootMismatch`]; a size regression as [`Error::SizeRegression`].
///
/// To recompute roots from tiles instead of carrying a precomputed proof,
/// compose [`crate::ingest::recompute_root_via`] over a
/// [`crate::ingest::TileReader`] to obtain each head's root, build the proof,
/// and call this function.
///
/// # Errors
/// Returns [`Error::AnchorMismatch`] if the attestation does not bind the
/// checkpoint or the previous head is for a different origin, and propagates
/// [`crate::proof::verify_consistency`] errors.
pub fn verify_anchored(
    checkpoint: &Checkpoint,
    attestation: &AnchorRecord,
    prev: Option<&AnchorLink<'_>>,
) -> Result<()> {
    if !attestation.binds(checkpoint) {
        return Err(Error::AnchorMismatch(format!(
            "attestation head (origin {:?}, size {}) does not bind checkpoint (origin {:?}, size {})",
            attestation.origin(),
            attestation.size(),
            checkpoint.origin(),
            checkpoint.size(),
        )));
    }

    if let Some(link) = prev {
        if link.prev_checkpoint.origin() != checkpoint.origin() {
            return Err(Error::AnchorMismatch(format!(
                "previous anchored head origin {:?} differs from checkpoint origin {:?}",
                link.prev_checkpoint.origin(),
                checkpoint.origin(),
            )));
        }
        link.prev_checkpoint
            .verify_consistency(checkpoint, link.consistency_proof)?;
    }
    Ok(())
}

/// The object-storage / chain / notary **commitment sink** — an interface only.
///
/// An operator implements this for its anchoring medium: [`put_commitment`]
/// publishes the [`AnchorRecord::anchor_commitment`] bytes and returns the
/// opaque locator that addresses them (a tx id, block height, receipt handle,
/// object key, …); [`get_commitment`] fetches the bytes previously published at
/// a locator. **This crate ships no implementation and performs no I/O** — the
/// associated [`CommitmentSink::Error`] lets implementations surface their own
/// error type without this crate depending on any I/O or async machinery
/// (mirroring the Slice-7 [`crate::ingest::TileReader`]).
///
/// [`put_commitment`]: CommitmentSink::put_commitment
/// [`get_commitment`]: CommitmentSink::get_commitment
pub trait CommitmentSink {
    /// The backend's error type.
    type Error;

    /// Publish `commitment` to the external medium, returning the opaque locator
    /// that addresses it.
    ///
    /// # Errors
    /// Returns the backend's error if the commitment cannot be published.
    fn put_commitment(&self, commitment: &[u8]) -> core::result::Result<Vec<u8>, Self::Error>;

    /// Fetch the commitment bytes previously published at `locator`.
    ///
    /// # Errors
    /// Returns the backend's error if the object cannot be fetched.
    fn get_commitment(&self, locator: &[u8]) -> core::result::Result<Vec<u8>, Self::Error>;
}

/// Error from the [`CommitmentSink`] logic-only bridges: either the backend
/// failed, or the fetched commitment did not match the recomputed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkError<E> {
    /// The [`CommitmentSink`] backend failed to publish or fetch.
    Backend(E),
    /// The commitment fetched from the medium did not equal the commitment
    /// recomputed from the attestation's checkpoint head — the medium does not
    /// attest to this head (a forged or mismatched locator).
    CommitmentMismatch,
}

/// Logic-only **write-path** bridge: compute a checkpoint's anchor commitment,
/// publish it through `sink`, and return the resulting [`AnchorRecord`].
///
/// Performs **no I/O itself** — only `sink.put_commitment` touches the medium.
/// It exists to show the [`CommitmentSink`] trait composes with the format
/// (and to give operators a correct, reusable recipe).
///
/// # Errors
/// Returns [`SinkError::Backend`] if the sink fails to publish, and propagates
/// [`AnchorRecord::for_checkpoint`] errors (mapped through
/// [`SinkError::Backend`] is *not* done — a record-construction error is a
/// programming error surfaced as [`Error`]). See the return type.
pub fn anchor_checkpoint_via<S: CommitmentSink>(
    sink: &S,
    checkpoint: &Checkpoint,
    commitment_alg: AnchorCommitment,
    medium: Medium,
) -> core::result::Result<AnchorRecord, SinkError<S::Error>> {
    let head = head_bytes(
        checkpoint.origin(),
        checkpoint.size(),
        checkpoint.root_hash(),
    );
    let commitment = commitment_alg.compute(&head);
    let locator = sink
        .put_commitment(&commitment)
        .map_err(SinkError::Backend)?;
    // `for_checkpoint` only fails on an empty locator; a sink returning an empty
    // locator is a backend contract violation, surfaced as a mismatch rather
    // than a panic.
    AnchorRecord::for_checkpoint(checkpoint, commitment_alg, medium, locator)
        .map_err(|_| SinkError::CommitmentMismatch)
}

/// Logic-only **read-path** bridge: fetch the commitment `attestation` points at
/// through `sink` and check it equals the commitment recomputed from the
/// attestation's checkpoint head.
///
/// Performs **no I/O itself** — only `sink.get_commitment` touches the medium.
/// On success the medium genuinely attests to this checkpoint head. This is the
/// medium-side counterpart to the log-side [`verify_anchored`]: together they
/// prove *the head was anchored* and *the operator never equivocated between
/// anchored heads*.
///
/// # Errors
/// Returns [`SinkError::Backend`] if the sink fails to fetch, or
/// [`SinkError::CommitmentMismatch`] if the fetched bytes do not equal the
/// recomputed commitment.
pub fn verify_commitment_via<S: CommitmentSink>(
    sink: &S,
    attestation: &AnchorRecord,
) -> core::result::Result<(), SinkError<S::Error>> {
    let fetched = sink
        .get_commitment(attestation.locator())
        .map_err(SinkError::Backend)?;
    if fetched == attestation.anchor_commitment() {
        Ok(())
    } else {
        Err(SinkError::CommitmentMismatch)
    }
}

// === Length-prefix discipline (mirrors `crate::leaf` / `crate::policy`) ===

/// Append `lp(bytes) = u32_be(len(bytes)) || bytes` to `out`.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A minimal big-endian, length-prefix-aware reader over a canonical buffer.
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
                Error::MalformedAnchor(format!(
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
    use crate::merkle::MerkleTree;
    use std::collections::HashMap;

    fn checkpoint_at(origin: &str, n: u32) -> (Checkpoint, MerkleTree) {
        let mut tree = MerkleTree::new();
        for i in 0..n {
            tree.push(&i.to_be_bytes());
        }
        let cp = Checkpoint::new(origin, tree.size(), tree.root()).unwrap();
        (cp, tree)
    }

    fn medium() -> Medium {
        Medium::parse("ethereum/mainnet").unwrap()
    }

    #[test]
    fn medium_grammar() {
        assert!(Medium::parse("dc3").is_ok());
        assert!(Medium::parse("opentimestamps").is_ok());
        assert!(Medium::parse("ethereum/sepolia").is_ok());
        assert!(Medium::parse("").is_err());
        assert!(Medium::parse("has space").is_err());
        assert!(Medium::parse("line\nbreak").is_err());
        assert!(Medium::parse(&"x".repeat(MAX_MEDIUM_LEN + 1)).is_err());
    }

    #[test]
    fn for_checkpoint_binds_head() {
        let (cp, _) = checkpoint_at("origin.example/log", 10);
        let rec =
            AnchorRecord::for_checkpoint(&cp, AnchorCommitment::Sha3_512, medium(), vec![1, 2, 3])
                .unwrap();
        assert!(rec.binds(&cp));
        assert_eq!(rec.origin(), cp.origin());
        assert_eq!(rec.size(), cp.size());
        assert_eq!(rec.root_hash(), cp.root_hash());
    }

    #[test]
    fn rejects_empty_locator() {
        let (cp, _) = checkpoint_at("o", 4);
        assert!(matches!(
            AnchorRecord::for_checkpoint(&cp, AnchorCommitment::Sha3_512, medium(), vec![]),
            Err(Error::MalformedAnchor(_))
        ));
    }

    #[test]
    fn canonical_round_trips_byte_for_byte() {
        let (cp, _) = checkpoint_at("origin.example/log", 7);
        let rec = AnchorRecord::for_checkpoint(
            &cp,
            AnchorCommitment::Sha3_512,
            medium(),
            b"0xdeadbeef".to_vec(),
        )
        .unwrap();
        let bytes = rec.canonical_bytes();
        let parsed = AnchorRecord::parse(&bytes).unwrap();
        assert_eq!(parsed, rec);
        assert_eq!(parsed.canonical_bytes(), bytes);
    }

    #[test]
    fn parse_rejects_malformed() {
        let (cp, _) = checkpoint_at("o", 4);
        let rec = AnchorRecord::for_checkpoint(&cp, AnchorCommitment::Sha3_512, medium(), vec![9])
            .unwrap();

        // Truncated.
        assert!(matches!(
            AnchorRecord::parse(&[0, 0, 0, 1]),
            Err(Error::MalformedAnchor(_))
        ));
        // Trailing bytes.
        let mut b = rec.canonical_bytes();
        b.push(0xff);
        assert!(matches!(
            AnchorRecord::parse(&b),
            Err(Error::MalformedAnchor(_))
        ));
        // Unknown format version.
        let mut bad_ver = rec.canonical_bytes();
        bad_ver[3] = 0x02;
        assert!(matches!(
            AnchorRecord::parse(&bad_ver),
            Err(Error::MalformedAnchor(_))
        ));
    }

    #[test]
    fn commitment_is_over_head_only_and_medium_independent() {
        let (cp, _) = checkpoint_at("origin.example/log", 12);
        let on_chain = AnchorRecord::for_checkpoint(
            &cp,
            AnchorCommitment::Sha3_512,
            Medium::parse("ethereum/mainnet").unwrap(),
            b"tx-1".to_vec(),
        )
        .unwrap();
        let on_notary = AnchorRecord::for_checkpoint(
            &cp,
            AnchorCommitment::Sha3_512,
            Medium::parse("rfc3161").unwrap(),
            b"receipt-2".to_vec(),
        )
        .unwrap();
        // Same head => same commitment regardless of medium/locator.
        assert_eq!(on_chain.anchor_commitment(), on_notary.anchor_commitment());
        assert_eq!(on_chain.anchor_commitment().len(), 64);

        // A different head => different commitment.
        let (cp2, _) = checkpoint_at("origin.example/log", 13);
        let other = AnchorRecord::for_checkpoint(
            &cp2,
            AnchorCommitment::Sha3_512,
            medium(),
            b"tx-3".to_vec(),
        )
        .unwrap();
        assert_ne!(on_chain.anchor_commitment(), other.anchor_commitment());
    }

    #[test]
    fn verify_anchored_binding_only() {
        let (cp, _) = checkpoint_at("origin.example/log", 9);
        let rec = AnchorRecord::for_checkpoint(&cp, AnchorCommitment::Sha3_512, medium(), vec![7])
            .unwrap();
        verify_anchored(&cp, &rec, None).unwrap();

        // A record bound to a different checkpoint is rejected.
        let (other, _) = checkpoint_at("origin.example/log", 11);
        assert!(matches!(
            verify_anchored(&other, &rec, None),
            Err(Error::AnchorMismatch(_))
        ));
    }

    #[test]
    fn verify_anchored_consistency_between_anchors() {
        let origin = "origin.example/log";
        let (older, mut tree) = checkpoint_at(origin, 8);
        for i in 8u32..16 {
            tree.push(&i.to_be_bytes());
        }
        let newer = Checkpoint::new(origin, tree.size(), tree.root()).unwrap();
        let proof: Vec<Vec<u8>> = tree
            .consistency_proof(8, 16)
            .into_iter()
            .map(|h| h.to_vec())
            .collect();

        let newer_rec = AnchorRecord::for_checkpoint(
            &newer,
            AnchorCommitment::Sha3_512,
            medium(),
            b"tx-newer".to_vec(),
        )
        .unwrap();

        // Honest append-only growth verifies.
        let link = AnchorLink::new(&older, &proof);
        verify_anchored(&newer, &newer_rec, Some(&link)).unwrap();

        // An equivocating "newer" head (different tree) fails consistency.
        let mut forked = MerkleTree::new();
        for i in 0u32..16 {
            forked.push(&(i ^ 0xffff).to_be_bytes());
        }
        let forged = Checkpoint::new(origin, forked.size(), forked.root()).unwrap();
        let forged_rec = AnchorRecord::for_checkpoint(
            &forged,
            AnchorCommitment::Sha3_512,
            medium(),
            b"tx-forged".to_vec(),
        )
        .unwrap();
        assert!(verify_anchored(&forged, &forged_rec, Some(&link)).is_err());
    }

    #[test]
    fn verify_anchored_rejects_cross_origin_prev() {
        let (older, _) = checkpoint_at("origin.a/log", 8);
        let (newer, _) = checkpoint_at("origin.b/log", 16);
        let rec =
            AnchorRecord::for_checkpoint(&newer, AnchorCommitment::Sha3_512, medium(), vec![1])
                .unwrap();
        let proof: Vec<Vec<u8>> = Vec::new();
        let link = AnchorLink::new(&older, &proof);
        assert!(matches!(
            verify_anchored(&newer, &rec, Some(&link)),
            Err(Error::AnchorMismatch(_))
        ));
    }

    /// Logic-only in-memory sink. NOT a storage backend — it exists only to
    /// prove the bridges compose with the format.
    #[derive(Default)]
    struct MemSink {
        store: std::cell::RefCell<HashMap<Vec<u8>, Vec<u8>>>,
        next: std::cell::Cell<u64>,
    }

    impl CommitmentSink for MemSink {
        type Error = String;

        fn put_commitment(&self, commitment: &[u8]) -> core::result::Result<Vec<u8>, String> {
            let id = self.next.get();
            self.next.set(id + 1);
            let locator = format!("mem:{id}").into_bytes();
            self.store
                .borrow_mut()
                .insert(locator.clone(), commitment.to_vec());
            Ok(locator)
        }

        fn get_commitment(&self, locator: &[u8]) -> core::result::Result<Vec<u8>, String> {
            self.store
                .borrow()
                .get(locator)
                .cloned()
                .ok_or_else(|| "missing locator".to_string())
        }
    }

    #[test]
    fn sink_bridges_round_trip() {
        let sink = MemSink::default();
        let (cp, _) = checkpoint_at("origin.example/log", 20);

        let rec = anchor_checkpoint_via(&sink, &cp, AnchorCommitment::Sha3_512, medium()).unwrap();
        assert!(rec.binds(&cp));

        // The published commitment verifies back through the medium.
        verify_commitment_via(&sink, &rec).unwrap();

        // A locator the medium never saw is a backend miss.
        let bogus = AnchorRecord::for_checkpoint(
            &cp,
            AnchorCommitment::Sha3_512,
            medium(),
            b"mem:does-not-exist".to_vec(),
        )
        .unwrap();
        assert!(matches!(
            verify_commitment_via(&sink, &bogus),
            Err(SinkError::Backend(_))
        ));
    }

    #[test]
    fn sink_detects_commitment_mismatch() {
        let sink = MemSink::default();
        let (cp, _) = checkpoint_at("origin.example/log", 20);
        let rec = anchor_checkpoint_via(&sink, &cp, AnchorCommitment::Sha3_512, medium()).unwrap();

        // Tamper: point a different head's attestation at the SAME locator. The
        // fetched commitment is for the original head, so it will not match.
        let (cp2, _) = checkpoint_at("origin.example/log", 21);
        let tampered = AnchorRecord::for_checkpoint(
            &cp2,
            AnchorCommitment::Sha3_512,
            medium(),
            rec.locator().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            verify_commitment_via(&sink, &tampered),
            Err(SinkError::CommitmentMismatch)
        ));
    }

    #[test]
    fn record_is_loggable_as_leaf() {
        let (cp, _) = checkpoint_at("o", 5);
        let rec =
            AnchorRecord::for_checkpoint(&cp, AnchorCommitment::Sha3_512, medium(), vec![1, 2])
                .unwrap();
        // Layer-0 leaf hash is stable and matches hashing the canonical bytes.
        assert_eq!(rec.rfc6962_leaf_hash(), hash_leaf(&rec.canonical_bytes()));
    }
}
