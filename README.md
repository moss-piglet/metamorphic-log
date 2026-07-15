# metamorphic-log

A tamper-evident, append-only **transparency log** engine and verification SDK.
Built by [Moss Piglet Corporation](https://mosspiglet.dev) to support privacy-
first software, including [Metamorphic](https://metamorphic.app) and [Mosslet](https://mosslet.com).

It implements the cryptographic _verification core_ over an append-only Merkle
log (RFC 6962 / RFC 9162), wraps the [C2SP `tlog-tiles`][tlog-tiles] substrate
for storage and serving, supports externally **witnessed** checkpoints for
anti-equivocation, layers in **hybrid post-quantum** checkpoint signatures, and
adds CONIKS-style index privacy via a swappable VRF.

> **Status:** v0.1, building slice-by-slice. Implemented: the **conformance
> core** (canonical Layer-0 leaf encoding, RFC 6962 Merkle hashing, RFC 6962 /
> RFC 9162 inclusion + consistency verification), the **C2SP `tlog-tiles`**
> substrate with `checkpoint` / `signed-note` parsing and classical Ed25519
> witness verification, **additive hybrid post-quantum** checkpoint signing,
> **CONIKS** index privacy (swappable VRF + SHA3-512 commitments + lookup/absence
> proofs), the signed per-namespace **policy** layer with declared == observed
> enforcement, and the **browser verification + monitor SDK** (WASM). The leaf
> layer is application-agnostic — any app defines its own opaque record type
> under a versioned `<namespace>/<record-type>/v<N>` context label; the bundled
> `key_history_v1` conformance instance (the format used by
> [Mosslet](https://mosslet.com), the first consumer) is reproduced
> byte-for-byte by the native crate **and** the WASM SDK. Ingestion/scale
> primitives land in a later slice.

## Browser verification + monitor SDK (WASM)

The crate ships a `wasm-bindgen` personality (the `wasm` module, `wasm32`-only)
so a browser can **monitor the log itself** instead of trusting a server. It is
a thin shell over the rlib core — no parallel logic — published to npm as
[`@f0rest8/metamorphic-log`](npm-README.md). It exposes the full verification
surface: `verifyInclusion` / `verifyConsistency`, checkpoint/signed-note
verification (Ed25519 + hybrid PQ), CONIKS `coniksVerifyLookup` /
`coniksVerifyAbsence`, and `signedPolicyVerify` + the declared == observed
`policyEnforce*` checks. A **cross-language byte-parity KAT**
(`tests/cross_language.rs`, run under `wasm-pack test --node`) proves the WASM
exports reproduce the native KAT vectors byte-for-byte. The Elixir NIF
(`metamorphic_log`, Rustler + dirty schedulers) ships in its own sibling Hex
package, mirroring the `metamorphic_crypto` precedent of a thin NIF over the
published crate.

## Verifying proofs

```rust
use metamorphic_log::{verify_inclusion, verify_consistency};

// Prove a leaf is committed at `index` in a tree of `size` whose head is `root`.
verify_inclusion(index, size, leaf_hash, &audit_path, root)?;

// Prove the tree of `size2`/`root2` is an append-only extension of `size1`/`root1`.
verify_consistency(size1, size2, &proof, root1, root2)?;
```

## Defining a leaf (any application)

A log leaf is **opaque, app-defined bytes** — the Merkle layer never inspects
them, so your canonical record drops in with zero reformatting. You choose a
versioned context label (`"acme/user-keys/v1"`, `"example-app/audit-event/v2"`,
…) as the domain separator for the per-record content hash. The bundled
`metamorphic_log::leaf::key_history_v1` module is a worked example of such a
record type (and the byte-locked conformance fixture); model your own on it.

For the common **key-history** shape specifically, you do not need to hand-roll
the hash: build a `key_history_v1::Entry` and call
`entry.entry_hash_with_context(&label)` (or the free
`key_history_entry_hash_with_context(&label, &entry)`) with your own
`"<namespace>/key-history/v1"` label. This is the **recommended** way to produce
a branded key-history leaf — the label binds the intra-chain domain separator to
your namespace, so auditors can tell whose key history a chain belongs to. The
canonical bytes and the RFC 6962 leaf hash are brand-independent; only the
continuity `entry_hash` varies by label. The frozen `entry_hash()` (the
`mosslet/key-history/v1` conformance value) is retained and simply delegates to
`entry_hash_with_context` with that fixed label. In the browser SDK the matching
export is `keyHistoryEntryHashWithContext(context, …)`.

## Index privacy (CONIKS)

A `coniks::ConiksDirectory` maps identities to committed values at
VRF-derived, privacy-preserving tree positions, and answers lookups with
**presence** or **absence** proofs that a relying party verifies independently —
from only the namespace, the VRF public key, the directory root, and the proof.

```rust
use metamorphic_log::coniks::{ConiksDirectory, LookupResult, Namespace, verify_lookup};
use metamorphic_log::vrf::Ecvrf;

let mut dir = ConiksDirectory::new(Namespace::parse("acme")?, Box::new(Ecvrf));
dir.insert(b"alice@example.com", b"key-history-head")?;
let root = dir.root();

let LookupResult::Present(proof) = dir.lookup(b"alice@example.com")? else {
    unreachable!()
};
// Independent verification — no access to the directory needed.
let value = verify_lookup(
    &Ecvrf, dir.namespace(), dir.vrf_public_key(), &root, b"alice@example.com", &proof,
)?;
assert_eq!(value, b"key-history-head");
```

The VRF is swappable behind the `vrf::Vrf` trait (classical ECVRF today; a
hybrid PQ construction slots in later with no format change). Commitments
(`commitment`) are SHA3-512 — post-quantum and binding regardless of the VRF.

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
  ECVRF-edwards25519-SHA512-TAI construction (RFC 9381 ciphersuite `0x03`),
  behind a swappable trait. The constant-time `ELL2` (`0x04`) suite and a
  hybrid (PQ + classical) output path are designed in but not built — the
  former lands with a curve backend that exposes a conformant hash-to-curve, the
  latter when an audited lattice VRF exists. This is the _only_ layer with a
  classical default in v0.1.
- Primitives are hybrid post-quantum, pure-Rust, and NCC-audited (via
  `metamorphic-crypto`). They are **not** FIPS-validated, and this project does
  not claim FIPS validation.

## Standards spine

- **RFC 6962** / **RFC 9162** — Merkle log; inclusion + consistency proofs
- **C2SP** [`tlog-tiles`][tlog-tiles], `tlog-witness`, `checkpoint` /
  `signed-note` — interoperable substrate enabling reciprocal witnessing
- **RFC 9381** — ECVRF-edwards25519 (`0x03`) and ECVRF-P256 (`0x01`) —
  index-privacy VRFs
- **`draft-ietf-keytrans-protocol`** — experimental IETF KEYTRANS combined-tree
  directory (`keytrans`, `KEYTRANS_EXP_04` — movable, not byte-frozen)
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
| `vrf`        | 3     | Swappable VRF trait; ECVRF-Ed25519 (default) + ECVRF-P256   |
| `commitment` | 3     | SHA3-512 hiding/binding index→value commitments             |
| `coniks`     | 3     | Per-namespace directory; presence + absence (index privacy) |
| `keytrans`   | 3     | Experimental IETF KEYTRANS combined-tree directory (movable)|
| `anchor`     | —     | Backend-agnostic checkpoint anchoring/attestation records   |
| `policy`     | 0     | Signed, versioned namespace policy; declared == observed    |
| `note`       | 2     | C2SP `signed-note` parse/verify (Ed25519 + hybrid PQ lines) |
| `tile`       | 2     | C2SP `tlog-tiles` coordinates / serving geometry            |
| `wasm`       | —     | Browser verification + monitor SDK (`wasm32`-only)          |
| `error`      | —     | Crate-wide error type                                       |

## Safety & supply chain

- `#![forbid(unsafe_code)]` at this layer
- RustCrypto-only dependencies; primitives delegated to `metamorphic-crypto`
- Edition 2024, MSRV 1.85, dual-licensed `MIT OR Apache-2.0`
- CI runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, tests, a `wasm32-unknown-unknown`
  check, a `wasm-pack` SDK build, the cross-language byte-parity KAT
  (`wasm-pack test --node`), `cargo audit`, and an MSRV-floor build; all action
  refs are SHA-pinned. The tagged release pipeline adds CycloneDX SBOM, cosign
  keyless signing, build-provenance attestation, and OIDC trusted publishing to
  crates.io + npm
- See [`SECURITY.md`](SECURITY.md) for the disclosure process

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

[crypto]: https://github.com/moss-piglet/metamorphic-crypto
[tlog-tiles]: https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md
