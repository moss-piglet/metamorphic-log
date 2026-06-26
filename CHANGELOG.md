# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Conformance core (Slice 1).** The verification math for the log:
  - `leaf`: the fixed, length-prefixed canonical-leaf discipline (`u32`-be
    length prefixes, `u64`-be integers, big-endian) with a validated
    `ContextLabel` (`<namespace>/<record-type>/v<N>`) domain separator, the
    generic intra-chain `content_hash` (SHA3-512-with-context), and the
    byte-exact `mosslet/key-history/v1` conformance instance.
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
