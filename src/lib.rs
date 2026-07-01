//! # metamorphic-log
//!
//! Tamper-evident, append-only **transparency log** engine and verification SDK
//! for the Metamorphic platform. It implements the cryptographic *verification*
//! core (RFC 6962 / RFC 9162 Merkle inclusion + consistency proofs over an
//! ecosystem-fixed SHA-256 tree), wraps the [C2SP `tlog-tiles`] substrate for
//! storage/serving, supports externally witnessed `checkpoint` / `signed-note`
//! co-signing, layers in **hybrid post-quantum** checkpoint signatures, and adds
//! CONIKS-style index privacy via a swappable VRF.
//!
//! ## Single source of truth for primitives
//!
//! This crate contains **no cryptographic primitives of its own**. Every hash,
//! signature, KEM, and KDF comes from [`metamorphic_crypto`] — the audited,
//! RustCrypto-only core. There is no parallel crypto stack here.
//!
//! ## What a transparency log does (and does not) provide
//!
//! - **Provides:** post-pin *continuity*, *anti-equivocation* (via independent
//!   witnesses co-signing checkpoints), and *tamper-evidence* over an
//!   append-only Merkle log.
//! - **Does NOT provide:** first-contact / bootstrap trust. A transparency log
//!   cannot tell you whether the *first* key you ever saw for a peer is
//!   genuine — that is a Trust-On-First-Use (TOFU) problem your application
//!   must handle separately from this library (e.g. out-of-band fingerprint or
//!   safety-number verification).
//!
//! These layers state their PQ posture plainly: integrity, authentication,
//! confidentiality, and commitments are post-quantum from day one; only
//! index-privacy (the CONIKS VRF) defaults to a classical construction with a
//! designed-in hybrid path. The primitives are not FIPS-validated, and this
//! project does not claim FIPS validation.
//!
//! ## Standards spine
//!
//! - RFC 6962 / RFC 9162 — Merkle log + inclusion/consistency proofs
//! - C2SP `tlog-tiles`, `tlog-witness`, `checkpoint` / `signed-note`
//! - RFC 9381 — ECVRF-edwards25519 (CONIKS index privacy)
//! - FIPS 203 / 204 + CNSA 2.0 — post-quantum primitives (via
//!   [`metamorphic_crypto`])
//! - NIST SP 800-56C / 800-108 — KDF roles
//!
//! [C2SP `tlog-tiles`]: https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md
//!
//! ## Status
//!
//! Slices 1–9c are implemented.
//!
//! **Slice 1 (#327) — conformance core:** the canonical Layer-0 leaf encoding
//! ([`leaf`]), the fixed RFC 6962 Merkle hashing ([`merkle`]), and RFC 6962 /
//! RFC 9162 inclusion + consistency proof *verification* ([`proof`]). The leaf
//! layer is application-agnostic: any app defines its own opaque record type
//! under a versioned context label. As a worked, byte-locked conformance
//! instance it ships [`leaf::key_history_v1`] (the format used by Mosslet, the
//! first consumer).
//!
//! **Slice 2 (#329) — C2SP substrate (WRAP):** the [`tile`] module wraps the
//! `tlog-tiles` substrate (tile coordinates, `tile/<L>/<N>[.p/<W>]` paths, and
//! recompute-from-tiles consistent with [`merkle`]); [`checkpoint`] parses and
//! serializes the `tlog-checkpoint` signed-tree-head body and wires it to the
//! Slice-1 inclusion/consistency verifier; and [`note`] parses/serializes the
//! `signed-note` format and verifies **classical Ed25519** witness co-signature
//! lines via [`metamorphic_crypto::ed25519_verify`].
//!
//! **Slice 3 (#331) — additive hybrid post-quantum checkpoint signing (Layer
//! 2):** [`note`] gains an additive [`note::SignatureType::MetamorphicHybrid`]
//! line — the metamorphic-crypto **ML-DSA + classical composite** (strict-AND),
//! assigned via the C2SP `0xff` escape with a versioned identifier so it never
//! squats an assigned type. Classical Ed25519 stays byte-identical, so a
//! checkpoint can be co-signed by both a witness-compatible Ed25519 key and our
//! forward-secure PQ key; a verifier accepts any mix of trusted key types. The
//! CONIKS VRF layer lands in Slice 4.
//!
//! **Slice 4 (#332) — CONIKS index privacy (Layer 3):** a swappable VRF
//! ([`vrf`]) with a classical ECVRF-edwards25519-SHA512-TAI default (RFC 9381,
//! via [`metamorphic_crypto`]) and a designed-in — not yet built — hybrid/PQ
//! path; SHA3-512 hash-based [`commitment`]s binding an index to a value; and a
//! per-namespace [`coniks`] directory whose lookups yield independently
//! verifiable **presence** and **absence** (index-hiding) proofs over a sparse
//! SHA3-512 prefix tree. Index privacy is the *only* classical property here;
//! the commitments and everything below are post-quantum.
//!
//! **Slice 5 (#333) — per-namespace policy + declared == observed enforcement
//! (Layer 0):** [`policy`] adds the signed, in-log, versioned
//! [`policy::NamespacePolicy`] record that declares a namespace's selectable PQ
//! posture (checkpoint suite/level, commitment-hash strength, VRF privacy mode)
//! within the #324 safe menu — never touching the audited Layer-1 canonical
//! bytes. A [`policy::SignedPolicy`] binds the record under the namespace root
//! key via the Slice-3 composite primitive; a [`policy::PolicyChain`] enforces
//! immutability-by-versioning and only-legal-strengthening migration. The
//! headline is **declared == observed**: a verifier hard-rejects any checkpoint
//! signature, CONIKS VRF suite, or commitment parameter whose *observed* posture
//! disagrees with the *declared* one — using the metamorphic-crypto v0.8.1
//! typed posture accessors, re-deriving no private wire tags. This makes posture
//! *verifiable*, not stronger.
//!
//! **Slice 6 (#335) — browser verification + monitor SDK ([`wasm`]):** a thin
//! `wasm-bindgen` personality over the rlib core, adding no log or crypto logic,
//! only base64/text marshalling across the JS boundary (proven by the
//! cross-language byte-parity KAT). Only compiled for `wasm32`.
//!
//! **Slice 7 (#337) — deterministic ingestion primitives ([`ingest`]):**
//! storage-agnostic, I/O-free write-path building blocks — a per-namespace
//! monotonic [`ingest::Sequencer`], an idempotent-append [`ingest::DedupKey`],
//! the tile-write/flush geometry ([`ingest::plan_flush`], byte-compatible with
//! the audited [`tile`] substrate), and the object-storage/CDN read-path
//! [`ingest::TileReader`] trait (interface only — no backend, no I/O). The
//! Broadway/GenStage ingest pipeline and real storage/CDN wiring belong to the
//! operator layer (mosskeys), not this OSS crate (#290 open-core boundary); the
//! primitives are equally consumable by that future pipeline.
//!
//! **Slice 8 (#338) — backend-agnostic anchoring ([`anchor`]):** format +
//! verification for committing a checkpoint's signed tree head to an external,
//! hard-to-equivocate medium (blockchain, notary, object-lock storage, another
//! transparency log). The byte-locked [`anchor::AnchorRecord`] binds a checkpoint
//! head (`origin`/`size`/`root_hash`) to an opaque locator + an agnostic
//! [`anchor::Medium`] tag, with a self-describing safe-menu commitment algorithm
//! ([`anchor::AnchorCommitment`], SHA3-512 in v0.1); [`anchor::verify_anchored`]
//! recomputes RFC 9162 consistency between successive anchored heads (reusing
//! [`proof::verify_consistency`]) so a third party audits *no equivocation*
//! without trusting the operator or the medium; and the interface-only
//! [`anchor::CommitmentSink`] trait (mirroring the Slice-7
//! [`ingest::TileReader`]) lets an operator wire a real medium with no I/O in
//! this crate. This is **plain anchoring** — zero zero-knowledge; the optional
//! ZK enhancement is the separate #339. Anchor cadence, fees, confirmation
//! depth, and the medium clients belong to the operator layer (#290).
//!
//! **Slice 9b (#339-adjacent, Slice 9) — swappable directory trait
//! ([`directory`]):** a pure-scaffold extraction, ahead of the IETF KEYTRANS
//! combined-tree backend. The object-safe [`directory::Directory`] /
//! [`directory::DirectoryVerifier`] traits capture the common denominator every
//! directory family supports — a [`directory::DirectoryBackendId`], a current
//! [`directory::DirectoryRoot`], and a search-and-verify surface over opaque
//! [`directory::SearchProof`] bytes — mirroring the swappable [`vrf`] pattern so
//! a namespace can hold a `Box<dyn Directory>` and swap CONIKS ↔ KEYTRANS
//! without callers caring. The existing [`coniks`] directory + its free
//! `verify_lookup` / `verify_absence` functions are refactored *behind* the
//! trait with **zero behavior change**: no new wire bytes, and every CONIKS KAT
//! still passes byte-for-byte. KEYTRANS-only surface (fixed-version search,
//! monitoring, the binary version ladder) is deliberately kept out of the base
//! trait, landing later as inherent methods / a `KeytransExt` sub-trait. The
//! backend identifier is *exposed but not yet mixed into proof bytes* (that
//! would change frozen formats — deferred to a version bump).
//!
//! **Slice 9c (#339, Slice 9) — KEYTRANS combined-tree core ([`keytrans`]):**
//! the NEW experimental `KEYTRANS_EXP_04` directory backend's tree-hashing core,
//! ahead of its proofs (9d) and policy/SDK wiring (9e–9f). A left-balanced
//! [`keytrans::log_tree`] (§3.2 / §10.8) whose leaf is `Hash(LogEntry{timestamp,
//! prefix_tree[Nh]})` with `hashContent` `0x00`/`0x01` leaf/parent tagging and
//! balanced-subtree-head proof compression; a bit-traversal
//! [`keytrans::prefix_tree`] (§3.3 / §10.9) with `Hash(0x01 || vrf_output ||
//! commitment)` leaves, `Hash(0x02 || left || right)` parents, and `0^Nh`
//! stand-in nodes; the [`keytrans::CombinedTree`] root (§3.4); and the
//! implicit-binary-search-tree timestamp-monotonicity navigation (§4.1 /
//! Appendix A). The suite hash is **SHA-256** (KEYTRANS interop); the
//! experimental private suite reuses the SHA3-512 [`commitment`] (the PQ half)
//! and the [`vrf`] ECVRF-Ed25519 (32-byte-truncated) label. Bytes that feed a
//! hash use the TLS presentation language via the private, dependency-free
//! [`keytrans::tls`](keytrans) submodule — the audited length-prefix grammar is
//! untouched. This backend is **version-tagged and movable**, deliberately
//! *not* byte-locked like [`leaf::key_history_v1`]; search / fixed-version /
//! monitor proof verification and the [`directory::Directory`] impl land in
//! later slices.
//!
//! **Slice 9d (#339, Slice 9) — KEYTRANS proofs ([`keytrans`]):** the
//! relying-party-verifiable proof surface over the 9c core, in the CONIKS
//! recompute-from-public-inputs posture. [`keytrans::ladder`] implements the §5
//! / Appendix B binary ladders (`base` / `fixed_version` / `monitor` /
//! `greatest_version`) and the §6.1 Reasonable-Monitoring-Window
//! distinguished-entry selection over the implicit BST.
//! [`keytrans::prefix_tree`] gains single-key proof generation and free
//! `verify_inclusion` / `verify_absence` (§11.2 inclusion / nonInclusionLeaf /
//! nonInclusionParent, recomputing the prefix root from the copath with `0^Nh`
//! stand-ins). [`keytrans::log_tree`] gains
//! [`keytrans::log_tree::verify_batch`] — composed inclusion + consistency
//! (§11.1) recombining proved leaves, retained full-subtree heads, and provided
//! balanced-subtree heads, including the §11.1 **MUST** check that a redundant
//! retained head matches its recomputed value. The private `keytrans::tls`
//! submodule gains the §11.1 `InclusionProof` and §11.2 `PrefixProof` /
//! `PrefixSearchResult` / `PrefixLeaf` wire structs (`uint16` vectors).
//! [`keytrans::KeytransDirectory`] implements the base [`directory::Directory`]
//! through greatest-version search (§6); the additive, object-safe
//! [`keytrans::KeytransExt`] sub-trait adds §7 fixed-version and §8 monitor
//! proofs without touching the base trait or the CONIKS impl; and
//! [`keytrans::KeytransVerifier`] recomputes every root from public inputs
//! (VRF-verifying each `(label, version)` lookup, the prefix copath, then the
//! log-tree inclusion) under the new experimental backend id
//! [`directory::KEYTRANS_EXP_V04`]. Everything is `KEYTRANS_EXP_04`-tagged and
//! **movable**; proofs are produced against the current log head (the §6–§8
//! frontier-recursion drivers are a separable, movable refinement), and no
//! frozen public wire bytes are added.
//!
//! **Slice 9e (#339, Slice 9) — KEYTRANS policy + WASM + cross-language KAT:**
//! the experimental KEYTRANS backend becomes *selectable* and *verifiable from
//! the SDK*. [`policy::NamespacePolicy`] gains two Layer-3 posture axes:
//! [`policy::DirectoryMode`] (`Coniks` default / `Keytrans`) and
//! [`policy::KeytransSuite`] (`MetamorphicHybridExp` = the `0xF000` private
//! hybrid-PQ suite; the on-spec IETF standard `Kt128Sha256{P256,Ed25519}`
//! suites). The record format is bumped to [`policy::POLICY_FORMAT_VERSION`]
//! `= 2`, but **backward-compatibly**: a default CONIKS-route policy still
//! serializes as a v1 record, so every frozen Slice-5 policy KAT round-trips
//! byte-for-byte; only a `Keytrans`-route policy emits a v2 record.
//! `declared == observed` extends to the directory backend
//! ([`policy::NamespacePolicy::enforce_directory_backend`]). The 9d byte-oriented
//! [`directory::DirectoryVerifier::verify_search`] stub is now **wired**: the
//! private `keytrans::tls` submodule gains a movable, length-prefix-disciplined
//! wire codec for the top-level search / fixed-version / monitor proofs, so a
//! `Box<dyn DirectoryVerifier>` (and the browser SDK) decodes an opaque
//! [`directory::SearchProof`] and dispatches to the typed
//! recompute-from-public-inputs verify (the typed inherent methods remain). The
//! [`wasm`] SDK surfaces `keytransVerifySearch` / `keytransVerifyFixedVersion` /
//! `keytransVerifyMonitor` and `policyEnforceDirectoryBackend`, and a
//! version-tagged Rust↔JS byte-parity KAT (explicitly **movable**, separate from
//! the frozen `key_history_v1` vectors) locks the experimental suite. Everything
//! stays `KEYTRANS_EXP_04`-tagged; the KEYTRANS wire bytes are **not** frozen.
//!
//! **Slice 9 (0.1.4) — on-spec IETF standard suites:** the standard §15.1
//! suites [`policy::KeytransSuite::Kt128Sha256P256`] (`0x0001`) and
//! [`policy::KeytransSuite::Kt128Sha256Ed25519`] (`0x0002`) are now **built and
//! legal** (they were reserved-but-rejected through 0.1.3). Each computes the
//! §10.6 commitment as `HMAC-SHA256(Kc, CommitmentValue)` (16-byte opening,
//! 32-byte tag) via [`metamorphic_crypto::hmac_sha256`], and derives search keys
//! with ECVRF-P256-SHA256-TAI ([`vrf::EcvrfP256`], no truncation) and
//! ECVRF-Ed25519 (truncated to 32 bytes) respectively. The directory core
//! ([`keytrans::KtSuite`]) suite-dispatches the commitment construction, opening
//! length, commitment-tag width, and VRF; the private
//! [`policy::KeytransSuite::MetamorphicHybridExp`] suite (SHA3-512 commitment,
//! the post-quantum trade-off) is unchanged and remains the default. The
//! standard suites are still `KEYTRANS_EXP_04`-tagged and **movable** (the
//! KEYTRANS wire tracks the draft until Last Call); their classical VRFs provide
//! index privacy only and are not FIPS-validated.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod anchor;
pub mod checkpoint;
pub mod commitment;
pub mod coniks;
pub mod directory;
mod encoding;
pub mod error;
pub mod ingest;
pub mod keytrans;
pub mod leaf;
pub mod merkle;
pub mod note;
pub mod policy;
pub mod proof;
pub mod tile;
pub mod vrf;

/// Browser **verification + monitor** SDK (`wasm-bindgen`), Slice 6.
///
/// A thin personality over the rlib core: every export base64/text-marshals its
/// arguments and delegates straight to the verification functions in [`proof`],
/// [`checkpoint`], [`note`], [`coniks`], and [`policy`]. It contains **no**
/// parallel log or crypto logic, so the bytes it produces and the verifications
/// it performs are identical to the native crate (proven by the cross-language
/// byte-parity KAT). Only compiled for `wasm32`.
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use error::{Error, Result};
pub use proof::{verify_consistency, verify_inclusion};
