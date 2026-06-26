# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this crate, **do not open a public issue**.

Please report it privately via one of:

- **GitHub Security Advisories**: [Report a vulnerability](https://github.com/moss-piglet/metamorphic-log/security/advisories/new)
- **Email**: security@metamorphic.app

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

This policy covers the `metamorphic-log` Rust crate and its verification/monitor
SDKs, including:

- Canonical leaf encoding and RFC 6962 / RFC 9162 Merkle hashing
- Inclusion and consistency proof verification
- Checkpoint / signed-note parsing and (hybrid PQ) checkpoint signature verification
- CONIKS-style index-privacy (VRF) verification
- WASM / NIF / UniFFI bindings

Cryptographic primitives themselves live in
[`metamorphic-crypto`](https://github.com/moss-piglet/metamorphic-crypto);
report primitive-level issues there.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Security Design

- `#![forbid(unsafe_code)]` — no unsafe Rust at this layer
- **Single source of truth:** all cryptographic primitives come from the audited
  [`metamorphic-crypto`](https://github.com/moss-piglet/metamorphic-crypto) crate
  (SHA-256 / SHA3-512, composite hybrid PQ signatures, ML-KEM). There is **no
  parallel crypto stack** in this repository.
- All other dependencies are from the audited
  [RustCrypto](https://github.com/RustCrypto) project
- Secret key material is zeroized after use via `zeroize` (in `metamorphic-crypto`)
- OS CSPRNG only (no userspace PRNG)
- The fixed Layer-1 invariants (SHA-256 tree hashing, canonical leaf byte
  layout, RFC 6962/9162 proof protocol) are auditable and recomputable by
  independent witnesses
