# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
