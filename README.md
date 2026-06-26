# metamorphic-log

A tamper-evident, append-only **transparency log** engine and verification SDK.
Built by [Moss Piglet Corporation](https://mosspiglet.dev) to support privacy-
first software, including [Metamorphic](https://metamorphic.app) and [Mosslet](https://mosslet.com).

It implements the cryptographic _verification core_ over an append-only Merkle
log (RFC 6962 / RFC 9162), wraps the [C2SP `tlog-tiles`][tlog-tiles] substrate
for storage and serving, supports externally **witnessed** checkpoints for
anti-equivocation, layers in **hybrid post-quantum** checkpoint signatures, and
adds CONIKS-style index privacy via a swappable VRF.

> **Status:** v0.1 skeleton. The module spine is laid out; log and verification
> logic land slice-by-slice. No log/crypto logic is implemented yet.

## Single source of truth for primitives

This crate contains **no cryptographic primitives of its own**. Every hash
(SHA-256 / SHA3-512), signature (composite hybrid PQ), KEM (ML-KEM), and KDF
comes from [`metamorphic-crypto`][crypto], the audited, RustCrypto-only core.
**There is no parallel crypto stack here.**

## What a transparency log does — and does not — provide

A transparency log gives you, **after** you have a key to anchor on:

- **Continuity** — the history you observe is append-only and self-consistent
  over time (consistency proofs).
- **Anti-equivocation** — the operator cannot show different histories to
  different observers without detection, because independent **witnesses**
  co-sign checkpoints.
- **Tamper-evidence** — any retroactive edit to the log breaks an inclusion or
  consistency proof.

It does **not** solve:

- **First-contact / bootstrap trust.** A transparency log cannot tell you whether
  the _first_ key you ever saw for a peer is the genuine one. That is a
  Trust-On-First-Use (TOFU) problem your application must handle separately from
  this library (for example, with out-of-band fingerprint or safety-number
  verification). The log makes a key _accountable over time_; it does not vouch
  for its origin.

## Cryptographic posture

- **PQ from day one** for integrity, authentication, confidentiality, and
  commitments. Checkpoints are designed for hybrid post-quantum signing via
  `metamorphic-crypto`'s composite (ML-DSA + classical) signatures.
- **Index-privacy** (the CONIKS VRF) defaults to a classical
  ECVRF-edwards25519 construction (RFC 9381), behind a swappable trait with a
  hybrid-output path designed in. This is the _only_ layer with a classical
  default in v0.1.
- Primitives are hybrid post-quantum, pure-Rust, and NCC-audited (via
  `metamorphic-crypto`). They are **not** FIPS-validated, and this project does
  not claim FIPS validation.

## Standards spine

- **RFC 6962** / **RFC 9162** — Merkle log; inclusion + consistency proofs
- **C2SP** [`tlog-tiles`][tlog-tiles], `tlog-witness`, `checkpoint` /
  `signed-note` — interoperable substrate enabling reciprocal witnessing
- **RFC 9381** — ECVRF-edwards25519 (CONIKS index privacy)
- **FIPS 203 / 204** + **CNSA 2.0** — post-quantum primitives (via
  [`metamorphic-crypto`][crypto])
- **NIST SP 800-56C / 800-108** — KDF roles

## Module layout

| Module       | Layer | Responsibility                                              |
| ------------ | ----- | ----------------------------------------------------------- |
| `leaf`       | 0     | Canonical, length-prefixed leaf encoding                    |
| `merkle`     | 1     | RFC 6962 SHA-256 tree-node hashing (fixed, witness-audited) |
| `proof`      | 1     | Inclusion + consistency proof verification                  |
| `checkpoint` | 2     | Signed-note / witnessed checkpoints; hybrid PQ signing      |
| `error`      | —     | Crate-wide error type                                       |

## Safety & supply chain

- `#![forbid(unsafe_code)]` at this layer
- RustCrypto-only dependencies; primitives delegated to `metamorphic-crypto`
- Edition 2024, MSRV 1.85, dual-licensed `MIT OR Apache-2.0`
- CI runs `fmt --check`, `clippy -D warnings`, tests, a `wasm32-unknown-unknown`
  check, `cargo audit`, and an MSRV-floor build; all action refs are SHA-pinned
- See [`SECURITY.md`](SECURITY.md) for the disclosure process

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

[crypto]: https://github.com/moss-piglet/metamorphic-crypto
[tlog-tiles]: https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md
