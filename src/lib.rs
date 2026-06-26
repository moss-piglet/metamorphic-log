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
//! This is the v0.1 skeleton: the module spine below is laid out but the log /
//! verification logic lands slice-by-slice (see the project board). No log or
//! crypto logic is implemented yet.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod checkpoint;
pub mod error;
pub mod leaf;
pub mod merkle;
pub mod proof;

pub use error::{Error, Result};

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        // Trivial smoke test so `cargo test` exercises the crate skeleton.
        // Real conformance tests arrive in Slice 1 (#327).
        assert_eq!(2 + 2, 4);
    }
}
