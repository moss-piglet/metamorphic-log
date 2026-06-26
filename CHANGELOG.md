# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Additive hybrid post-quantum checkpoint signing (Slice 3).** A second,
  *additive* signature line that gives our own verifiers/monitors post-quantum
  authenticity while the classical Ed25519 line keeps the C2SP witness network
  able to recompute and co-sign:
  - `note::SignatureType::MetamorphicHybrid` — the metamorphic-crypto **ML-DSA +
    classical composite** (strict-AND), verified directly via
    `metamorphic_crypto::verify`. Assigned the C2SP `signed-note` **`0xff`
    escape** with a versioned namespaced identifier
    (`HYBRID_SIG_IDENTIFIER`), so it never squats an assigned/reserved type;
    no assigned cosignature byte (e.g. single-algorithm `0x06`) fits the hybrid
    composite construction. Classical Ed25519 stays byte-identical.
  - `note::sign_hybrid` (over the versioned `HYBRID_SIG_CONTEXT`) and
    `VerifierKey::new_hybrid`; `VerifierKey` parse/encode and the key-id formula
    now carry the multi-byte type identifier and the composite public-key
    material (`tag || classical_pk || ml_dsa_pk`).
  - `VerifierKey::hybrid_posture_tag` surfaces the composite's self-describing
    `(Suite, SecurityLevel)` posture byte for the future policy layer
    (declared == observed), without reimplementing any crypto.
  - A checkpoint can be co-signed by **both** a witness-compatible Ed25519 key
    and a PQ composite key; a verifier accepts any mix of trusted key types.
  - New `Error::HybridSignature` variant; KAT vectors (deterministic
    composite vkey + a stored signed-note that verifies byte-for-byte — ML-DSA
    signing is hedged, so *verification* is locked, not the signature bytes) and
    `proptest` coverage (sign/verify accept-reject, classical+PQ co-existence,
    cross-type confusion rejection).
- **C2SP substrate / WRAP (Slice 2).** `tile` (tlog-tiles coordinates,
  `tile/<L>/<N>[.p/<W>]` paths, partial-tile geometry, recompute-from-tiles),
  `checkpoint` (tlog-checkpoint signed-tree-head parse/serialize wired to the
  Slice-1 inclusion/consistency verifier), `note` (byte-exact C2SP signed-note
  parse/serialize + classical Ed25519 witness verify via
  `metamorphic_crypto::ed25519_verify`), and a dependency-free `encoding`
  (strict RFC 4648 base64 + hex). C2SP canonical spec vectors + proptest.
- **Conformance core (Slice 1).** The verification math for the log:
  - `leaf`: the fixed, length-prefixed canonical-leaf discipline (`u32`-be
    length prefixes, `u64`-be integers, big-endian) with a validated
    `ContextLabel` (`<namespace>/<record-type>/v<N>`) domain separator, the
    generic intra-chain `content_hash` (SHA3-512-with-context), and a worked
    `key_history_v1` example record type (the byte-locked conformance instance).
  - `merkle`: RFC 6962 tree hashing over ecosystem SHA-256 (`empty_root`,
    `hash_leaf`, `hash_children`) plus an in-memory reference `MerkleTree` that
    computes roots and generates inclusion/consistency proofs.
  - `proof`: RFC 6962 / RFC 9162 inclusion and consistency proof
    *verification* implemented directly (`verify_inclusion`,
    `verify_consistency`, and the `root_from_*` building blocks).
  - Typed `Error` variants for the verification core (index/size, proof size,
    hash length, root mismatch, consistency edge cases, malformed leaf).
- **#315 KAT parity.** A real `mosslet/key-history/v1` row is a valid Layer-0
  leaf with zero reformatting; the SHA3-512 `entry_hash` and RFC 6962 leaf hash
  match the shipped Mosslet vectors byte-for-byte.
- **Conformance tests.** #315 known-answer vectors, the canonical
  `transparency-dev/merkle` RFC 6962 inclusion/consistency reference vectors,
  and `proptest` round-trips (every inclusion proof verifies; consistency
  between every size pair verifies; tampered proofs/roots/indices are rejected).

### Bootstrap (Slice 0)

- Initial repository bootstrap (Slice 0): `Cargo.toml` (edition 2024, MSRV 1.85,
  `MIT OR Apache-2.0`, `crate-type = ["cdylib", "rlib"]`, size-optimized release
  profile), dual `LICENSE-MIT` / `LICENSE-APACHE`, `SECURITY.md`, `README.md`,
  this changelog, `.gitignore`, and `Cargo.lock`.
- Dependency on the published [`metamorphic-crypto`](https://github.com/moss-piglet/metamorphic-crypto)
  crate as the single source of truth for all cryptographic primitives (with a
  documented, commented-out `[patch.crates-io]` path override for local
  co-development).
- `#![forbid(unsafe_code)]` crate root with the layering-spine module skeleton:
  `leaf` (canonical encoding), `merkle` (RFC 6962 hashing), `proof`
  (inclusion/consistency), `checkpoint` (signed-note / witness co-signing), and
  `error`. Stubs only — no log or crypto logic yet.
- GitHub Actions CI (`fmt --check`, `clippy -D warnings`, `cargo test`,
  `wasm32-unknown-unknown` check, `rustsec/audit-check`, MSRV-1.85 floor build),
  with all third-party action refs SHA-pinned; Dependabot and FUNDING config.

[Unreleased]: https://github.com/moss-piglet/metamorphic-log/commits/main
