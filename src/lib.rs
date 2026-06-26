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
//! Slices 1–5 are implemented.
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

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod checkpoint;
pub mod commitment;
pub mod coniks;
mod encoding;
pub mod error;
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
