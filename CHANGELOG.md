# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-06-26

Slice 7 of EPIC #325 — the **final** v0.1 slice. Adds storage-agnostic,
deterministic **ingestion primitives** to the Rust crate and closes the v0.1
EPIC. No canonical byte format changes: Layer-1 (RFC 6962 SHA-256 tree, leaf
byte layout), the Slice-4 CONIKS/VRF formats, and the Slice-5 policy record are
all untouched. The audited Slice-6 `wasm` shell is unchanged (no new WASM
exports this slice). The Broadway/GenStage ingest pipeline and real
object-storage/CDN wiring remain out of scope — they belong to the operator
layer (mosskeys), per the #290 open-core boundary; these primitives are designed
to be equally consumable by that future pipeline (and by the deferred #336
Elixir NIF).

### Added

- **Deterministic ingestion primitives (Slice 7, #337).** A new, I/O-free,
  storage-agnostic `ingest` module — the OSS engine's contribution to the write
  path. Pure logic only: no pipeline, no network, no storage backend.
  - `ingest::Sequencer` — a per-namespace **monotonic sequencer** assigning
    strictly-increasing, gap-free `u64` positions per namespace (`next`,
    `peek`, batch `reserve`), with a monotonic-safe `resume_from` for rebuilding
    state from durable storage on restart (rejects rewinds via the new
    `Error::SequenceRegression`; block reservations are overflow-checked via
    `Error::SequenceOverflow`).
  - `ingest::DedupKey` — an **idempotent-append** dedup key: a deterministic,
    domain-separated, namespace-scoped SHA3-512 digest (via `metamorphic-crypto`)
    over the fixed `lp()` discipline, in content (`from_record`) and
    client-token (`from_token`) modes. A fixed cross-language KAT vector locks
    the bytes a future Elixir ingester must reproduce.
  - `ingest::plan_flush` / `tiles_to_flush` / `entry_bundles_to_flush` — the
    **tile-write/flush geometry**: exactly which C2SP `tlog-tiles` coordinates
    change when the log grows from `old_size` to `new_size`. Defined purely in
    terms of the audited `tile` substrate (byte-compatible; finalized tiles are
    never rewritten), with append-only `Error::SizeRegression` enforcement.
  - `ingest::TileReader` — the object-storage / CDN **read-path trait**
    (interface only; **no** backend, **no** I/O in this crate), plus a logic-only
    `recompute_root_via` bridge that reads level-0 tiles through any `TileReader`
    and recomputes the RFC 6962 root via the verification core, proving the trait
    composes without performing any I/O itself.
- **Ingestion conformance + throughput benchmark.** `tests/ingestion.rs` locks
  sequencer determinism/replay, the dedup-key KAT + idempotency/separation, the
  flush geometry against the substrate across a size sweep, and the read-path
  bridge reproducing a checkpoint root. `benches/ingestion.rs` is a
  dependency-free (`harness = false`, no criterion) throughput benchmark showing
  the primitives sit far above the Tessera reference band (~5k–18k entries/sec) —
  honestly framed as primitive-level, not an end-to-end ingest claim. CI gains
  dedicated `ingestion` and `throughput-benchmark` jobs, and the `clippy` gate is
  widened to `--all-targets` (now also linting benches).

## [0.1.1] - 2026-06-26

First **automated** release, cut to validate the end-to-end OIDC supply-chain
pipeline (`.github/workflows/release.yml`): crates.io trusted publishing →
`wasm-pack` SDK build → CycloneDX SBOM → SHA-512 checksums → keyless cosign
signatures → build-provenance attestation → npm trusted publishing → GitHub
Release with artifacts. The `0.1.0` release on both registries was a manual
bootstrap with no changelog section, no git tag, and no SBOM/cosign/attestation
artifacts; this is the first tag-driven release, so it both **formally stamps
the engine work below** (Slices 1–6, already present in the `0.1.0` source) and
**ships the supply-chain artifacts for the first time**. No source or
canonical-byte-format changes from `0.1.0` — only the version bump and this
changelog entry.

### Added

- **WASM verification + monitor SDK + cross-language byte-parity KAT (Slice 6).**
  The browser personality of the engine — a thin `wasm-bindgen` shell over the
  rlib core that adds **no** log or crypto logic, only base64/text marshalling
  across the JS boundary. Gated to `wasm32`, so native builds (and the separate
  sibling Elixir NIF package) never pull in `wasm-bindgen` / `js-sys`:
  - `wasm` module exports the full verification + monitor surface:
    `verifyInclusion` / `verifyConsistency` (RFC 6962 core + the monitor's
    anti-equivocation walk); `keyHistoryV1CanonicalBytes` / `…EntryHash` /
    `…Rfc6962LeafHash` (the Layer-0 leaf conformance instance); `verifySignedNote`
    / `checkpointVerify` / `checkpointVerifyInclusion` /
    `checkpointVerifyConsistency` (classical Ed25519 **and** additive hybrid-PQ
    checkpoint co-signatures); `coniksVerifyLookup` / `coniksVerifyAbsence` /
    `verifyCommitment` (CONIKS index privacy); and `signedPolicyVerify` +
    `policyEnforceCheckpointSigningKey` / `…CheckpointSignature` / `…VrfSuiteId`
    / `…CommitmentHash` (NamespacePolicy parse/verify + declared == observed).
    Verification predicates return `true` and **throw** the typed `Error` on any
    failure; tamper, forgery, and posture mismatch are rejections through every
    binding.
  - **Cross-language byte-parity KAT** (`tests/cross_language.rs`, run under
    `wasm-pack test --node`): the WASM exports reproduce the **same** canonical
    leaf bytes, `policy_hash`, RFC 6962 leaf hash, checkpoint/note verification,
    CONIKS proofs, and declared == observed results as the native KAT vectors —
    byte-for-byte. ML-DSA signing is hedged, so (as in Slices 3/5) the KAT locks
    *verification* and the deterministic vkey/canonical bytes, never regenerated
    signature bytes. The proptest-backed native suites and in-`src` unit tests
    are gated off `wasm32` so the wasm test target builds cleanly.
  - **Supply-chain release pipeline** (`.github/workflows/release.yml`, #328):
    on a `v*` tag, runs the quality gates + `cargo audit`, publishes the crate to
    **crates.io** via OIDC trusted publishing, builds the WASM SDK with
    `wasm-pack`, generates a CycloneDX **SBOM**, computes SHA-512 checksums,
    **cosign**-signs the artifacts (keyless OIDC), attaches build-provenance
    **attestation**, and publishes `@f0rest8/metamorphic-log` to **npm** via OIDC
    trusted publishing — all third-party actions SHA-pinned, credentials scoped
    to a protectable `release` environment.
  - CI gains a `wasm-build` job (`wasm-pack build`) and a `cross-language-kat`
    job (Node 22 + `wasm-pack test --node`) alongside the existing
    fmt/clippy/test/wasm32-check/audit/MSRV jobs.
  - Scope note: the Elixir NIF (`metamorphic_log`, Rustler + dirty schedulers)
    is deferred to its own sibling Hex package — mirroring the `metamorphic_crypto`
    precedent of a thin NIF over the **published** crate — and lands after this
    crate is on crates.io. WASM-first; UniFFI deferred (no native-app consumers
    yet). Honest framing: this surfaces the existing engine to the browser; it
    changes no canonical byte format and is not FIPS validated.
- **Per-namespace policy + declared == observed enforcement (Slice 5).** A
  signed, in-log, versioned `policy::NamespacePolicy` record that declares a
  namespace's selectable post-quantum posture — the only legal flexibility point
  (#324), never touching the audited Layer-1 canonical bytes:
  - `policy::NamespacePolicy`: a canonical, byte-disciplined Layer-0 leaf
    (`u32`-be length prefixes, `u64`-be integers, big-endian; mirrors the
    `leaf` / `coniks` grammar) carrying `namespace`, `policy_schema_version`,
    `security_level` (`Cat3` / `Cat5`), `checkpoint_suite` (`Hybrid` default /
    `HybridMatched` / `PureCnsa2`), `commitment_hash` (`Sha3_256` / `Sha3_512`,
    derived from the level), `vrf_mode` (`Classical` only in v0.1; `HybridOutput`
    / `PurePqExperimental` scoped per #304), `effective_from`, `created_at`, and
    a `prev_policy_hash` chain link. Construction validates the v0.1 bundle
    (commitment-hash derived from level, Classical VRF, `PureCnsa2` ⇒ Cat-5);
    `policy_hash` is the SHA3-512 content hash over the policy bytes (the chain
    linkage), distinct from the RFC 6962 leaf hash.
  - `policy::SignedPolicy`: binds the canonical policy under the namespace root
    key via the same composite primitive as the Slice-3 hybrid checkpoint line
    (`metamorphic_crypto::sign` / `verify`) under the
    `<namespace>/namespace-policy/v1` context, serialized as a Layer-0 leaf.
  - `policy::PolicyChain`: an ordered policy history enforcing
    immutability-by-versioning and only-legal-**strengthening** migration
    (same namespace, `policy_schema_version + 1`, strictly increasing
    `effective_from`, correct `prev_policy_hash`; a weakening is rejected).
    `active_at` resolves the version in force at a tree position over half-open
    `[effective_from_n, effective_from_{n+1})` ranges.
  - **Declared == observed** (the headline): `enforce_checkpoint_signing_key` /
    `enforce_checkpoint_signature` map an observed checkpoint hybrid key/signature
    to `(Suite, SignatureLevel)` via the metamorphic-crypto **0.8.1** typed,
    opaque `signature_posture` / `signature_posture_from_signature` accessors and
    compare to the declared posture; `enforce_vrf_suite_id` checks the Slice-4
    CONIKS `Vrf::suite_id` (#332); `enforce_commitment_hash` checks the
    commitment parameter; `enforce_observed` checks all three at once. Any
    mismatch is a hard rejection. This crate re-derives **no** private crypto
    wire tags — it only consumes the typed accessors.
  - New `Error` variants: `MalformedPolicy`, `PolicyMigrationRejected`,
    `PostureMismatch`, `UnknownNamespacePolicy`.
  - KAT/reference vectors (`tests/namespace_policy.rs`): fixed key material locks
    the canonical policy bytes, the deterministic verifying key, and the
    deterministic `policy_hash`; a stored signed policy verifies its own
    composite signature byte-for-byte (ML-DSA signing is hedged, so
    **verification** is locked, not the signature bytes); plus declared==observed
    accept/reject over real per-`(Suite, Level)` keypairs, legal/illegal
    migration, cross-namespace/version rejection, and `proptest` round-trips.
    Honest framing: this makes posture *verifiable*, not stronger — not FIPS
    validated. Depends on `metamorphic-crypto` 0.8.1.
- **CONIKS-style index privacy (Slice 4).** A swappable VRF plus SHA3-512
  commitments and a per-namespace directory with independently verifiable
  presence/absence proofs — the index-privacy layer:
  - `vrf`: a byte-oriented, object-safe `Vrf` trait (`generate_keypair` /
    `derive_public_key` / `prove` / `verify` / `proof_to_output`) with a
    classical `Ecvrf` default — **ECVRF-edwards25519-SHA512-TAI** (RFC 9381
    ciphersuite `0x03`) via the new `metamorphic_crypto` `vrf` primitive. The
    constant-time `ELL2` (`0x04`) suite is a designed-in future addition (it
    lands with a curve backend exposing a conformant hash-to-curve,
    curve25519-dalek 5.x); because `suite_id` is bound into CONIKS domain
    separation, adding it never invalidates a `0x03` proof. `hybrid_output`
    implements the designed-in PQ+classical output combiner
    (`SHA3-512_with_context(DST, classical || pq)`); the PQ `Vrf` half is not
    built (no audited lattice VRF exists).
  - `commitment`: SHA3-512 hiding/binding commitments
    (`commit` / `commit_with_opening` / `verify_commitment`) under a
    per-namespace context label — the post-quantum binding half, independent of
    the classical VRF.
  - `coniks`: a per-namespace `ConiksDirectory` over a sparse depth-256 SHA3-512
    prefix tree. `insert` places a value's commitment at its VRF-derived index;
    `lookup` returns a `LookupResult::Present(LookupProof)` or
    `Absent(AbsenceProof)`. The free `verify_lookup` / `verify_absence`
    functions recompute everything from public inputs (namespace, VRF public
    key, root, identity, proof) with no access to the directory (#316); proofs
    serialize to canonical bytes and parse back. The namespace is threaded
    through the VRF input and every tree/commitment hash, so proofs never
    cross-verify between namespaces.
  - New `Error` variants: `MalformedNamespace`, `Vrf`, `VrfProofInvalid`,
    `CommitmentMismatch`, `MalformedConiksProof`, `ConiksRootMismatch`.
  - KAT/reference vectors (`tests/coniks_vectors.rs`): the VRF trait reproduces
    RFC 9381 Appendix B.3 Example 16 byte-for-byte; pinned fixed-opening
    commitment, hybrid-output combiner, and empty-directory root; plus
    serialize→parse→verify round-trips and `proptest` over random directories
    (present + absent). Depends on `metamorphic-crypto` 0.8.0.
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

[Unreleased]: https://github.com/moss-piglet/metamorphic-log/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/moss-piglet/metamorphic-log/releases/tag/v0.1.2
[0.1.1]: https://github.com/moss-piglet/metamorphic-log/releases/tag/v0.1.1
