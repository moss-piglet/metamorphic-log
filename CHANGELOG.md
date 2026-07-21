# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-07-21

Adds interoperability with the C2SP [`tlog-witness`](https://c2sp.org/tlog-witness)
ecosystem by teaching the note layer to recognize and verify **v1 cosignatures**
(`tlog-cosignature`, <https://c2sp.org/tlog-cosignature>) in both flavors: the
classical **Ed25519** type (`0x04`, what deployed witnesses emit today) and the
**post-quantum ML-DSA-44** type (`0x06`, the spec's recommended PQ cosignature).
This is the missing cryptographic piece behind split-view protection: a verifier
configured with a witness's key can now confirm that an independent witness
co-signed a checkpoint, and a single note can carry the log's hybrid PQ line plus
real Ed25519 and ML-DSA-44 witness cosignatures at once. Purely additive:
existing Ed25519 (`0x01`) and hybrid composite lines, all wire formats, and every
KAT vector are unchanged.

Requires `metamorphic-crypto` 0.10.7, which surfaces the raw ML-DSA-44 (FIPS 204)
interop primitives the `0x06` path uses (the PQ sibling of the `ed25519_*`
primitives the `0x04` path uses).

### Added

- `note::SignatureType::CosignatureV1Ed25519` (`0x04`) — a C2SP
  `tlog-cosignature` v1 Ed25519 cosignature. The on-wire signature blob is
  `u64 timestamp (big-endian) || ed25519_signature[64]` (a
  `timestamped_signature`), and the signed message is the domain-separated
  `cosignature/v1` header, a `time <decimal>` line, and the whole cosigned note
  body. `SignedNote::verify` now checks these lines against a matching witness
  verifier key.
- `note::SignatureType::CosignatureV1MlDsa44` (`0x06`) — the post-quantum C2SP
  `tlog-cosignature` v1 ML-DSA-44 cosignature. The on-wire blob is
  `u64 timestamp (big-endian) || ml_dsa_44_signature[2420]`, and the signed
  message is the spec's `cosigned_message` TLS-style struct (label
  `subtree/v1\n\0`, cosigner name, timestamp, log origin, subtree bounds, root
  hash) built from the cosigned checkpoint's fields. Unlike the Ed25519 type it
  commits to the cosigner name. Unknown/other cosignature types remain ignored.
- `note::VerifierKey::new_cosignature_ed25519` /
  `note::VerifierKey::new_cosignature_mldsa44` — build a witness verifier key
  from a cosigner name (a schema-less URL) and Ed25519 (32-byte) or ML-DSA-44
  (1312-byte) public key. The key id coincides with the generic signed-note key
  id over the `0x04`/`0x06` type identifier, matching the cosignature spec's
  `SHA-256(name || "\n" || type || pk)[:4]`. `VerifierKey::parse`/`encode`
  round-trip both.
- `note::sign_cosignature_ed25519` / `note::sign_cosignature_mldsa44` — produce a
  v1 cosignature line over a note body / checkpoint at a given POSIX timestamp
  from a raw Ed25519 or ML-DSA-44 seed. This is what a witness (including our
  own, when acting as one) emits after verifying log consistency.
- `note::cosignature_v1_message`, `note::COSIGNATURE_V1_HEADER`,
  `note::cosignature_v1_mldsa44_message`, and `note::COSIGNATURE_V1_MLDSA44_LABEL`
  — the domain-separated signed-message builders and their fixed labels, exposed
  for tooling that needs to reproduce the exact cosigned bytes.
- Tests locking both cosignature wire formats: sign/verify round trips, vkey
  key-id derivation and encode/parse round trips, tampered-timestamp and
  tampered-body rejection, and mixed checkpoints carrying the log's hybrid line
  alongside independent Ed25519 and ML-DSA-44 witness cosignatures (all
  verifying, each witness line also verifying on its own).

## [0.2.1] - 2026-07-18

Additive performance work on the CONIKS directory. The `ConiksDirectory` now
maintains an incremental branch-node cache so reading the root is O(1) amortized
and assembling a lookup's authentication path is ~O(depth), instead of the prior
O(N-leaves x depth) recompute on every `root()` and `lookup()` call. This is the
CONIKS analog of the tile-proof perf work tracked for the RFC 6962 layer. No wire
format, byte discipline, proof output, or verifier behavior changes: roots and
proofs remain byte-for-byte identical, and every KAT vector is unchanged.

### Changed

- `coniks::ConiksDirectory` caches subtree hashes for branch nodes (positions
  covering two or more leaves) and rebuilds only the O(depth) path affected by an
  insert. `root()` reads the cached depth-0 node; `lookup()` assembles the
  authentication path from the cache, recomputing empty defaults and singleton
  subtrees on demand. Memory is O(N) (at most `leaves - 1` cached branch nodes),
  not O(N x depth): empty subtrees fold to the precomputed default and singleton
  subtrees are derived from their one leaf on demand, so neither is stored. The
  full from-scratch recursion is retained as the byte-exact test oracle.

### Added

- Tests `coniks::cached_root_and_paths_match_from_scratch_oracle` and
  `coniks::replacing_a_value_updates_the_cached_root` — lock the incremental
  cache to byte-identical roots and authentication paths versus the from-scratch
  `TreeHasher` recursion across successive inserts and value replacement.

## [0.2.0] - 2026-07-18

Adds a `Send + Sync` supertrait bound to the [`vrf::Vrf`] trait so a directory
that owns a `Box<dyn Vrf>` can be built once and served concurrently by a
multi-threaded operator (the server-side directory-construction path used by the
Elixir NIF's stateful directory resource). No wire format, byte discipline, or
proof output changes: this is purely a trait bound.

### Changed (possibly breaking)

- `vrf::Vrf` now requires `Send + Sync` (`pub trait Vrf: Send + Sync`). This is
  the idiomatic, thread-safe-by-construction posture for a server-side crypto
  strategy trait, matching the wider ecosystem's signing/verification traits. It
  is a **possibly-breaking** change only for a downstream `impl Vrf` on a
  `!Send`/`!Sync` type; the in-tree implementations (`Ecvrf`, `EcvrfP256`) are
  zero-sized and satisfy it unchanged. Minor bump (pre-1.0) per SemVer, called
  out here honestly. No frozen format, KAT vector, or public function signature
  is affected.

### Added

- Test: `vrf::boxed_vrf_is_send_and_sync_across_threads` — a dependency-free
  proof that a `Box<dyn Vrf>` moves into a spawned thread and is shared across a
  scoped thread, locking in the new bound.

## [0.1.11] - 2026-07-15

Additive, non-breaking. Exposes a **context-parameterized key-history entry
hash** so any application can brand its key-history leaves with its own
`<namespace>/key-history/v1` label through this crate's audited byte discipline,
instead of hand-rolling the hash or dropping to `metamorphic-crypto`. The frozen
`mosslet/key-history/v1` conformance instance and all its cross-language KATs are
byte-for-byte unchanged.

### Added

- `key_history_v1::Entry::entry_hash_with_context(&ContextLabel)` — the branded
  intra-chain entry hash, `sha3_512_with_context(label, canonical_bytes)`. This
  is now the **recommended** entry point for applications other than the frozen
  Mosslet fixture. `Entry::entry_hash()` is retained and now delegates to it with
  the frozen `CONTEXT`, proving equivalence.
- `key_history_v1::key_history_entry_hash_with_context(&ContextLabel, &Entry)` —
  free-function form of the above.
- WASM: `keyHistoryEntryHashWithContext(context, seq, ts_ms, enc_x25519_b64,
  enc_pq_b64, signing_pub_b64, prev?)` — mirrors `keyHistoryV1EntryHash` but takes
  a `context` label first (parsed via `ContextLabel`), so browser clients can
  brand their leaves too. `keyHistoryV1EntryHash` is unchanged.
- KATs: the frozen label reproduces the locked digest via the new API, while a
  second label (`mosskeys/key-history/v1`) yields a different `entry_hash` even
  though the canonical bytes and RFC 6962 leaf hash are identical — native and
  WASM.

### Documentation

- README + module docs recommend branding key-history leaves with your own
  namespace label via `entry_hash_with_context` /
  `keyHistoryEntryHashWithContext`, clarifying that the label binds the
  domain separator so auditors can tell whose key history a chain belongs to.

## [0.1.10] - 2026-07-09

Supply-chain bump. **No library changes** — crate source, wire formats, byte
layouts, and all conformance vectors are byte-for-byte identical to 0.1.9.

### Changed

- Bump `metamorphic-crypto` dependency from 0.10.2 to 0.10.5. This pulls in the
  upstream ML-DSA signing-stack hardening (a shared native `on_signing_stack`
  guard and an 8 MiB WASM shadow-stack linker bump) at the primitives layer.
  `sign_hybrid` continues to delegate directly to `metamorphic_crypto::sign` and
  remains a pure function with no behavioural change.

### Documentation

- README: correct the CI lint command to the copy-pasteable
  `cargo clippy --all-targets -- -D warnings` (the `-D warnings` lint level must
  follow the `--` separator), and update the WASM-SDK section to reflect that the
  Elixir NIF (`metamorphic_log`) now ships rather than being a deferred
  follow-up.

## [0.1.9] - 2026-07-09

Release-plumbing patch. **No library changes** — crate source, wire formats,
byte layouts, and all conformance vectors are byte-for-byte identical to 0.1.7.

The 0.1.8 release published to crates.io but then failed at the npm publish step
(`Cannot find module 'sigstore'`), leaving npm and the GitHub Release
unpublished. This release fixes the npm setup and completes the artifacts.

### Changed

- CI: the release workflow now uses Node 24 (which bundles a complete
  npm >= 11.5.1) for npm trusted publishing, instead of the in-place
  `npm install -g npm@latest` self-upgrade. That self-upgrade path is currently
  broken — it leaves npm unable to resolve its bundled `sigstore` module during
  provenance generation. A guard also fails fast if npm is older than 11.5.1.

## [0.1.8] - 2026-07-09

Release-plumbing patch. **No library changes** — the crate source, wire
formats, byte layouts, and all conformance vectors are byte-for-byte identical
to 0.1.7.

The 0.1.7 release run published to crates.io but then aborted at that step on a
resumed run (`crate ... already exists on crates.io index`), leaving npm and the
GitHub Release unpublished. This release ships the fix and completes the npm +
GitHub Release artifacts.

### Changed

- CI: the crates.io and npm publish steps in the release workflow are now
  idempotent — a resumed/re-run release detects an already-published version,
  warns, and continues so the remaining steps (npm, GitHub Release) finish
  instead of aborting a half-published release. Any other publish error still
  fails fast.

## [0.1.7] - 2026-07-08

Surfaces the **signing (producer) layer** in the WASM SDK and adds a one-call
checkpoint-signing convenience to the core, unblocking client-signed C2SP
checkpoints in downstream consumers (mosskeys #38b). **Additive only** — no wire
format, byte layout, or KAT changes; the CONIKS, policy-v1, `key_history_v1`,
and RFC 6962 tlog conformance vectors are byte-for-byte unchanged, and every
existing verification/monitor export is untouched.

### Added

- `checkpoint::sign_checkpoint_hybrid(origin, size, root_b64, name, sk)` — the
  one-call producer path that builds a checkpoint body and returns the complete
  signed-note text, sharing the `Checkpoint::new` + `note::sign_hybrid` +
  `SignedNote` code path (no new byte layout).
- WASM SDK producer helpers (thin, logic-free shells over the existing core
  signing primitives): `noteSignHybrid`, `noteSignEd25519`,
  `checkpointSignHybrid`, `vkeyEncodeHybrid`, `vkeyEncodeEd25519`, and
  `signedPolicySign` (mirrors the `signedPolicyVerify` posture surface, via
  `NamespacePolicy::new` / `new_keytrans` + `SignedPolicy::sign`).
- `wasm-bindgen-test` round-trip coverage for all new producer helpers (sign →
  derive vkey → SDK-verify, plus tampered / foreign-key / malformed-input
  rejection). ML-DSA signing is hedged, so bytes are not reproducible; the tests
  lock the round trip, not regenerated signature bytes.

The fixed C2SP hybrid note context (`HYBRID_SIG_CONTEXT`) remains an internal,
non-customizable interop invariant.

## [0.1.6] - 2026-07-08

Supply-chain bump: `metamorphic-crypto` 0.10.0 → 0.10.2, propagating the
`cmov` 0.5.3 → 0.5.4 security fix (RustSec **GHSA-3rjw-m598-pq24 /
CVE-2026-50185**, aarch64 `Cmov`/`CmovEq` correctness), the `aes-gcm`
rc → stable (0.11.0) bump, and `anyhow` 1.0.103 (clears RUSTSEC-2026-0190,
build-tooling-only). Dependency-only — **no wire/KAT/API changes**; CONIKS,
policy-v1, `key_history_v1`, and RFC 6962 tlog conformance vectors are
byte-for-byte unchanged.

## [0.1.5] - 2026-07-01

Supply-chain bump: `metamorphic-crypto` 0.9.0 → 0.10.0. 0.10.0 is additive only —
it adds a standalone HKDF-SHA512 primitive (parity) that this crate does not use;
its commitments continue to use HMAC-SHA256. **No wire/KAT/API changes** — the
CONIKS, policy-v1, `key_history_v1`, and RFC 6962 tlog conformance vectors are
byte-for-byte unchanged. `p256` stays pinned at `=0.14.0-rc.14`.

## [0.1.4] - 2026-06-30

Slice 9 of EPIC #325 — makes the experimental **IETF KEYTRANS** directory
backend **on-spec**: the two standardized `draft-ietf-keytrans-protocol-04`
§15.1 cipher suites now *work*, rather than being present-but-rejected. A
namespace that chooses KEYTRANS for standards conformance gets the standardized
HMAC-SHA256 / P-256 construction. Everything KEYTRANS remains
`KEYTRANS_EXP_04`-tagged and **movable** (its wire bytes track the draft until
Last Call); the classical VRFs provide index privacy only and are not
FIPS-validated. **No frozen KATs change** — the CONIKS, policy-v1,
`key_history_v1`, and RFC 6962 tlog conformance vectors are byte-for-byte
unchanged, and a default CONIKS-route policy still serializes as a v1 record.

### Added

- **On-spec IETF standard KEYTRANS suites (§15.1).** `KT_128_SHA256_P256`
  (`0x0001`) and `KT_128_SHA256_Ed25519` (`0x0002`) are now built and legal
  (previously reserved-but-rejected through 0.1.3):
  - `keytrans::KtSuite` — the directory-core suite descriptor that
    suite-dispatches the commitment construction, opening length (`Nc`),
    commitment-tag width, and VRF. Exposes `suite_id`, `from_suite_id`,
    `opening_len`, `commitment_len`, `vrf`, and `commit`.
  - Commitment (§10.6): the standard suites compute
    `HMAC-SHA256(Kc, CommitmentValue::encode())` via
    `metamorphic_crypto::hmac_sha256`, with the fixed §15.1 key `Kc`
    (`keytrans::KC`, the literal 16 bytes `d821f8790d97709796b4d7903357c3f5`)
    and `Nc = 16` (`keytrans::NC_STANDARD`), yielding a 32-byte tag. The private
    `MetamorphicHybridExp` suite keeps its 64-byte SHA3-512 commitment
    (the post-quantum trade-off) and remains the default.
  - `vrf::EcvrfP256` — a `Vrf` adapter over
    `metamorphic_crypto::vrf_p256` (ECVRF-P256-SHA256-TAI, RFC 9381 suite
    `0x01`). Its 32-byte output is the prefix-tree search key verbatim (no
    truncation); `KT_128_SHA256_Ed25519` reuses `vrf::Ecvrf` truncated to 32
    bytes.
  - `keytrans::KtCommitment` — a variable-width commitment tag (32 or 64 bytes)
    so the on-spec HMAC tag and the private SHA3-512 tag share one prefix-tree /
    proof code path.
  - `KeytransDirectory::new_with_suite` / `KeytransVerifier::new_with_suite`
    select a suite (the existing `new` constructors default to the private
    experimental suite, unchanged). The proof decoders
    (`KeytransSearchProof::decode` et al.) take the suite's `commitment_len`.
  - `policy::KeytransSuite::{Kt128Sha256P256, Kt128Sha256Ed25519}` are legal on
    the `Keytrans` route; `is_built()` / `backend_id()` /
    `declared_directory_backend_id()` report them served under the combined-tree
    backend `KEYTRANS_EXP_V04` (the suite is distinguished by its §15.1 id).
  - WASM SDK: `keytransVerifySearchSuite` / `keytransVerifyFixedVersionSuite` /
    `keytransVerifyMonitorSuite` take a §15.1 `suiteId`, verifying the standard
    suites in the browser identically to native. The existing 5-argument
    functions still default to the private experimental suite.
- **Movable standard-suite KATs.** Fixed HMAC-SHA256 commitment vectors and
  prover→verifier round-trip vectors (search / fixed-version / monitor) for both
  standard suites. Tagged `KEYTRANS_EXP_04` / movable — kept out of the frozen
  conformance and cross-language suites.

### Changed

- Bumped `metamorphic-crypto` to `0.9.0` (adds `hmac_sha256` and the
  `vrf_p256` ECVRF-P256-SHA256-TAI primitive; consumed from crates.io, no patch
  or path dependency).
- Documentation across `lib.rs`, `policy::KeytransSuite`, and the `keytrans`
  module now describes the standard suites as legal-experimental (still
  movable), replacing the earlier "reserved but rejected" framing.

## [0.1.3] - 2026-06-28

Slice 8 of EPIC #325 — the **first post-v0.1 anchoring slice**. Adds
backend-agnostic **anchoring / attestation** support to the Rust crate:
format + verification for committing a checkpoint's signed tree head to an
external, hard-to-equivocate medium (blockchain, notary, object-lock storage,
another transparency log). No canonical byte-format changes to any audited
layer: Layer-1 (RFC 6962 SHA-256 tree, leaf byte layout), the Slice-4
CONIKS/VRF formats, and the Slice-5 policy record are all untouched. The
audited Slice-6 `wasm` shell is unchanged (WASM SDK wiring is deferred this
slice). The medium clients, anchor cadence, fees, and confirmation depth remain
out of scope — they belong to the operator layer (mosskeys), per the #290
open-core boundary. This is **plain anchoring** with zero zero-knowledge; the
optional ZK enhancement is the separate, design-spike-first #339.

### Added

- **Backend-agnostic anchoring (Slice 8, #338).** A new, I/O-free,
  backend-agnostic `anchor` module — the OSS engine's contribution to anchoring,
  owning **format + verification only**.
  - `anchor::AnchorRecord` — the canonical, byte-locked **attestation record**
    binding a checkpoint head (`origin` / `size` / `root_hash`) to an **opaque
    locator** plus an agnostic `anchor::Medium` tag, so a chain tx id, block
    height, notary receipt, or object key all serialise identically. Uses the
    fixed `lp()` discipline (big-endian, `u32`-be length prefixes); round-trips
    byte-for-byte and is itself a valid Layer-0 leaf (`rfc6962_leaf_hash`) so an
    operator may log its attestations. Designed to be *wrappable* (a future
    signed envelope can be added additively, mirroring `SignedPolicy`).
  - `anchor::AnchorCommitment` — a self-describing **safe-menu** commitment
    algorithm encoded as a tag byte (SHA3-512 in v0.1, sharing
    `policy::CommitmentHash` tags). The commitment is computed over the
    medium-independent checkpoint head under a versioned, domain-separated
    context, so the same head yields the same commitment regardless of medium.
    Algorithm choice is part of the agreed wire format (not a runtime knob),
    preventing interop fragmentation / downgrade attacks; adding an algorithm is
    a deliberate, additive change.
  - `anchor::verify_anchored` — the **verification helper**: checks an
    attestation binds a checkpoint and, given a previous anchored head + an
    RFC 9162 consistency proof (grouped in the forward-stable, `#[non_exhaustive]`
    `anchor::AnchorLink`), recomputes append-only consistency via
    `proof::verify_consistency` so a third party audits *no equivocation between
    anchored heads* without trusting the operator or the medium.
  - `anchor::CommitmentSink` — the medium **commitment sink trait** (interface
    only; **no** backend, **no** I/O in this crate; associated `Error`, mirroring
    the Slice-7 `TileReader`), plus logic-only `anchor_checkpoint_via` /
    `verify_commitment_via` bridges proving the trait composes with the format
    without performing any I/O itself.
  - New `Error::MalformedAnchor` and `Error::AnchorMismatch` variants.
- **Anchoring conformance.** `tests/anchoring.rs` locks a byte-locked KAT
  (canonical record bytes + medium-independent commitment + Layer-0 leaf hash) a
  cross-language operator must reproduce, the consistency-between-anchors audit
  (accept honest growth, reject an equivocating fork), and the `CommitmentSink`
  bridge round-trip. CI gains a dedicated `anchoring` job.

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

[Unreleased]: https://github.com/moss-piglet/metamorphic-log/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/moss-piglet/metamorphic-log/releases/tag/v0.1.5
[0.1.4]: https://github.com/moss-piglet/metamorphic-log/releases/tag/v0.1.4
[0.1.3]: https://github.com/moss-piglet/metamorphic-log/releases/tag/v0.1.3
[0.1.2]: https://github.com/moss-piglet/metamorphic-log/releases/tag/v0.1.2
[0.1.1]: https://github.com/moss-piglet/metamorphic-log/releases/tag/v0.1.1
