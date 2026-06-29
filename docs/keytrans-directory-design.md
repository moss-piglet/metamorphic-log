# KEYTRANS combined-tree directory backend — design note (Slice 9a)

**Status:** design-only, awaiting user review. **No tree/implementation code lands in 9a.**
**Pins:** `draft-ietf-keytrans-protocol-04` (2026-04-16, WG Document — *not* Last Call, wire bytes
still move) and `draft-ietf-keytrans-architecture-08` (2026-04-12, effectively stable).
**Tracking:** task #18. **Issue:** Slice 9.

> **On placement.** The crate has no prior `docs/` (or `doc/`) directory — design rationale
> has historically lived in module rustdoc and root markdown (`README.md`, `SECURITY.md`,
> `CHANGELOG.md`), with GitHub issue numbers cited inline. This is the crate's first
> standalone design note, so it gets a new `docs/` directory (Cargo does not compile it,
> so it cannot perturb CI). The *durable* design rationale will still be folded into module
> rustdoc when 9b–9f land, matching the established convention; this file is the
> human-review artifact that gates that work.

---

## 0. Why this slice exists (honest framing)

The industry is converging on **IETF KEYTRANS**, not classic CONIKS. We are *adding* a
KEYTRANS-style **combined-tree** directory backend *alongside* the existing CONIKS backend
(`src/coniks.rs`), selectable per-namespace through the existing policy posture machinery.
We are **not** replacing CONIKS, and we are **not** chasing OPTIKS-the-paper (a research
optimization within the same combined-tree family, not a standard).

Because `-protocol-04` is still a WG Document, the KEYTRANS backend ships as a
**versioned / experimental** backend behind a trait — explicitly *not* a byte-locked
conformance fixture in the mould of `leaf::key_history_v1`. The byte-locked KAT discipline
(`tests/conformance.rs`, cross-language parity in `tests/cross_language.rs`) stays reserved
for formats we are willing to freeze forever. KEYTRANS bytes are version-tagged and may move
until `-protocol` reaches Last Call.

Our **hybrid-PQ differentiator is preserved**: the KEYTRANS draft does *not* mandate PQ. Our
SHA3-512 commitments and composite hybrid-PQ checkpoint signing remain, expressed as a
**private/experimental KEYTRANS cipher suite** in the `0xF000–0xFFFF` "Reserved for Private
Use" range of the §15.1 registry.

This work lives entirely in **metamorphic-log** (directory model). `metamorphic-crypto`
already supplies every primitive KEYTRANS needs (SHA-256, SHA3-512, HMAC, ECVRF/RFC 9381,
composite hybrid-PQ signatures). **No new crypto crate work.**

---

## 1. Mapping KEYTRANS onto existing layers — REUSE vs NEW

KEYTRANS's **combined tree** (`§3.4`, after [Merkle2]) is a **log tree** (`§3.2`, RFC-6962-like,
left-balanced) whose leaves each commit to a *version of a prefix tree* plus a timestamp,
combined with a **prefix tree** (`§3.3`, bit-traversal trie with stand-in nodes) that maps a
`(label, version)` search key to a **commitment** to the label's value. The search key is a
**VRF output** (`§10.7`). This is structurally the same family as our Layer-3 stack, but the
*hashing inputs, node tagging, and serialization* differ enough that the trees themselves are
NEW code — what we reuse is the *primitive layer* and the *trait/posture pattern*.

| Concern | Existing (CONIKS path) | KEYTRANS (`-protocol-04`) | Verdict |
|---|---|---|---|
| **Log tree** | `merkle` — RFC 6962 SHA-256, `hash_leaf = SHA-256(0x00‖x)`, `hash_children = SHA-256(0x01‖l‖r)` (`src/merkle/mod.rs:7-11`) | `§10.8` log tree: leaf `= Hash(LogEntry{u64 timestamp; opaque prefix_tree[Nh]})`, `hashContent` prefixes leaves `0x00`/parents `0x01`; **suite hash** (SHA-256 in shipped suites); proofs carry **only balanced-subtree heads** (`§3.2`) | **NEW tree, REUSED hashing primitive.** Node-tagging convention (`0x00`/`0x01`) is identical to RFC 6962, so `merkle::hash_leaf`/`hash_children` are reusable *building blocks*, but the **leaf content** (timestamp ‖ prefix-tree root) and the **balanced-head proof compression** are new. We do **not** reuse `merkle::MerkleTree`'s proof shape directly. |
| **Prefix tree** | `coniks` — depth-256 **sparse** tree, SHA3-512 nodes, per-namespace context labels (`<ns>/coniks-{leaf,node,empty}/v1`), VRF-output index (`src/coniks.rs:53-59, 94-108`) | `§3.3` + `§10.9`: bit-traversal trie with **stand-in nodes**; leaf `= Hash(0x01 ‖ vrf_output ‖ commitment)`, parent `= Hash(0x02 ‖ left ‖ right)`, missing child `= 0^Nh` | **NEW tree.** Different domain-separation bytes (`0x01`/`0x02` vs our context-string labels), different empty/stand-in convention, suite-hash (SHA-256) not fixed-SHA3-512. Shares the *concept* (VRF-output → commitment) but not the bytes. |
| **Commitment** | `commitment` — `SHA3-512_with_context(ctx, opening(32) ‖ value)`, `COMMITMENT_LEN = 64` (`src/commitment.rs:16-39`) | `§10.6`: `HMAC(Kc, CommitmentValue{opaque opening[Nc]; label; u32 version; UpdateValue update})`, `Nc = 16`, `Kc` fixed per suite | **NEW construction for the standard suites** (HMAC, 16-byte opening, structured value). **REUSED construction for our private suite:** a `0xF0xx` suite keeps the SHA3-512 hiding/binding commitment as the PQ half. The trait abstracts both (see §3). |
| **VRF** | `vrf` — swappable `Vrf` trait, default `Ecvrf` = ECVRF-edwards25519-SHA512-TAI (RFC 9381, suite `0x03`), `suite_id()` bound into proofs (`src/vrf.rs:138-211`) | `§10.7`: VRF over `VrfInput{label; u32 version}`; suites use **ECVRF-P256-SHA256-TAI** or **ECVRF-EDWARDS25519-SHA512-TAI (truncated to 32 bytes)**, both RFC 9381 | **REUSED, directly.** Our `vrf::Vrf` trait + `Ecvrf` already covers the Ed25519 suite (modulo 32-byte output truncation, a thin adapter). P-256 is a future `Vrf` impl. This is the cleanest reuse in the whole slice. |
| **Encoding** | length-prefixed canonical grammar: `u32`-be lengths (`lp(x)=u32_be(len)‖x`), `u64`-be ints, never reordered (`src/leaf/mod.rs:33-42`); plus private `encoding.rs` = Base64/hex for C2SP textual wire | `§2`: **cryptographic computations MUST use TLS presentation language [RFC 8446]** | **NEW.** This is the single biggest divergence (see §1.1 and §5). |

### 1.1 Serialization: TLS presentation language vs our length-prefix grammar

`§2` is explicit: *"cryptographic computations MUST be done with the TLS presentation language
format to ensure the protocol's security properties are maintained."* Our canonical encoding
is `u32`-be length-prefixed, big-endian, never-reordered (`leaf/mod.rs`). These are **not**
byte-compatible — TLS-PL uses variable-width vector length headers (`<0..2^8-1>`, etc.),
fixed-size opaque fields, and struct concatenation without our `u32` prefix discipline.

**Resolution (proposed):** the KEYTRANS backend gets its **own** minimal TLS-PL
serialization helpers, scoped to the `keytrans` module — it does **not** reinterpret or
extend the crate's canonical length-prefix grammar. We keep two encodings deliberately:

- `leaf`/`coniks`/`policy`/`anchor` keep the audited length-prefix grammar (frozen formats).
- `keytrans` implements exactly the TLS-PL structures the draft requires for the bytes that
  feed hashes/signatures (`TreeHeadTBS`, `LogEntry`, `VrfInput`, `CommitmentValue`,
  `UpdateValue`, `AuditorTreeHeadTBS`). These are small, fixed by the spec, and the right
  place for them is a private `keytrans::tls` submodule with a tiny, dependency-free
  reader/writer (mirroring how `encoding.rs` is a private, dependency-free helper).

We do **not** pull in a general TLS crate — RustCrypto-only / dependency-discipline holds.
The TLS-PL surface KEYTRANS needs is small and stable enough to hand-roll and unit-test.

---

## 2. Proposed shared `directory::Directory` trait

Mirrors the `vrf::Vrf` swappable-trait pattern (`src/vrf.rs:138-191`): byte-oriented,
object-safe, primitives passed in, so a namespace can hold a `Box<dyn Directory>` and swap
CONIKS ↔ KEYTRANS without callers caring. Keep it **minimal** and additive. This is the
**only** thing 9b extracts; 9b refactors `coniks` behind it with **zero behavior change**.

Shape (illustrative — final names settled in 9b; **not** committed code):

```text
pub trait Directory {
    /// Stable identifier for the backend family + version, mixed into domain
    /// separation exactly like `Vrf::suite_id` is. e.g. CONIKS_V1, KEYTRANS_EXP_04.
    fn backend_id(&self) -> DirectoryBackendId;

    /// Current signed tree head / root the proofs are relative to.
    fn root(&self) -> DirectoryRoot;

    /// Look up a label: present (with value + proof) or absent (with proof).
    /// CONIKS: existing LookupResult. KEYTRANS: greatest-version search (§6).
    fn search(&self, label: &[u8]) -> Result<SearchResult>;
}

/// Relying-party side — recompute everything from public inputs, no directory needed
/// (mirrors coniks::verify_lookup / verify_absence at src/coniks.rs:636,673).
pub trait DirectoryVerifier {
    fn verify_search(&self, root: &DirectoryRoot, label: &[u8], proof: &SearchProof)
        -> Result<SearchOutcome>;
}
```

Notes / boundaries:

- **Trait stays small.** CONIKS today exposes only presence/absence lookup (no append-proof,
  no monitor-history API — `src/coniks.rs`). KEYTRANS adds fixed-version search (`§7`),
  monitoring (`§8`, contact + owner), binary-ladder version discovery (App. B), and
  consistency over the log tree. We do **not** force all of that into the base trait. The
  base trait covers the **common denominator** (backend id, root, search + verify). KEYTRANS-
  only surface (fixed-version, monitor proofs, binary ladder) lives as **inherent methods**
  on the KEYTRANS type and/or a `KeytransExt` sub-trait introduced in 9d — additive, never
  polluting the CONIKS impl.
- **Object-safe.** Opaque byte-wrapper newtypes for roots/proofs (the `vrf.rs`
  `VrfProof`/`VrfOutput` pattern, `src/vrf.rs:88-129`) keep `Box<dyn Directory>` viable and
  add an object-safety test (cf. `src/vrf.rs:376-381`).
- **`backend_id()` is bound into proofs**, exactly as `vrf::suite_id()` is mixed into CONIKS
  domain separation, so a proof can never be replayed across backends.

---

## 3. Hybrid-PQ posture → private KEYTRANS cipher suite + `policy::DirectoryMode`

### 3.1 Private/experimental cipher suite

`§15.1` reserves `0xF000–0xFFFF` for **Private Use**. We register (privately/experimentally)
a suite that keeps our PQ posture, conceptually:

```text
0xF0xx  KT_EXP_METAMORPHIC_HYBRID
        Hash       = SHA-256 (log/prefix tree, for KEYTRANS interop)
        Commitment = SHA3-512 hiding/binding (our commitment.rs construction, PQ half)
        Signature  = composite hybrid-PQ (note::SignatureType::MetamorphicHybrid, Slice 3)
        VRF        = ECVRF-EDWARDS25519-SHA512-TAI (32-byte truncation), with a
                     designed-in hybrid VRF path (vrf::hybrid_output) for the future.
```

Two honest caveats to record:

1. The standard suites (`0x0001 KT_128_SHA256_P256`, `0x0002 KT_128_SHA256_Ed25519`) use
   **HMAC** commitments with a 16-byte opening (`§10.6`). Our SHA3-512 commitment is **not**
   byte-compatible. So a KEYTRANS verifier expecting a standard suite will **not** verify our
   private-suite trees, and vice versa — this is the intended trade-off: interop on the
   *structure*, divergence on the *PQ commitment bytes*. Tagged via `backend_id()` / suite id.
2. The tree-head signature (`§10.2`, over `TreeHeadTBS`) is where our composite hybrid-PQ
   checkpoint signing slots in — see §3.3.

### 3.2 Tree-head signature mapping (review-confirmed)

The tree-head signature (`§10.2`, over the TLS-PL `TreeHeadTBS`) carries the *signature
algorithm selected by the suite*. We map our composite hybrid-PQ `note` signing (Slice 3,
C2SP `0xff` escape) onto that slot: the signed bytes become TLS-PL `TreeHeadTBS` instead of a
C2SP checkpoint blob, but the **algorithm is unchanged**, so the audited `note` layer is not
modified — it just signs a different byte string.

- **Pro:** zero change to `note`; PQ posture preserved end-to-end (commitment *and* tree-head
  signature are both PQ under the private suite).
- **Con / tradeoff:** a `0xF0xx` tree head carries a composite hybrid signature that stock
  KEYTRANS auditors cannot verify — the same interop boundary as the commitment (§3.1, caveat
  1), and the same resolution: tagged by suite id, opt-in per namespace. Users selecting a
  standard suite get a standard-algorithm tree-head signature instead. No new tradeoff beyond
  what the suite choice already implies.

### 3.3 `policy::NamespacePolicy` gains a `DirectoryMode` axis (+ a separate suite axis)

**Design decision (review-confirmed):** the *route* (CONIKS vs KEYTRANS) and the *cipher
suite within the KEYTRANS route* are **two separate posture axes**, not one. This is what lets
a service like mosskeys serve users' differing ecosystem preferences: pick the route, and
within it we do it to-spec for the best interop/security/privacy/performance. A user who wants
maximum PQ posture picks our private hybrid-PQ suite; a user who needs to interoperate with
stock KEYTRANS verifiers/auditors picks a standard suite — same route, different suite.

`NamespacePolicy` (`src/policy.rs:329-340`) already models posture as a set of tagged enum
axes (`SecurityLevel`, `CheckpointSuite`, `CommitmentHash`, `VrfMode`), each with
`const TAG_*: u8`, `tag()`/`from_tag()`, `rank()`, and a typed accessor into
`metamorphic-crypto`. We add **two** axes, following that exact pattern:

```text
/// Layer-3 directory backend selection. v0.1 legal value: Coniks (default).
/// Keytrans is scoped + experimental; rejected as malformed until 9c–9e land,
/// mirroring how VrfMode::{HybridOutput, PurePqExperimental} are reserved-but-rejected
/// (src/policy.rs:264-277).
pub enum DirectoryMode { Coniks, Keytrans }   // tags 0x01 / 0x02

/// KEYTRANS cipher suite, only meaningful when DirectoryMode::Keytrans.
/// MetamorphicHybridExp = our private 0xF0xx PQ suite (default for mosskeys
/// namespaces); the standard suites trade PQ for stock-ecosystem interop.
pub enum KeytransSuite {
    MetamorphicHybridExp,   // 0xF0xx — SHA3-512 commitment + composite hybrid-PQ sig
    Kt128Sha256Ed25519,     // 0x0002 — standard, HMAC commitment, ECVRF-Ed25519
    Kt128Sha256P256,        // 0x0001 — standard, HMAC commitment, ECVRF-P256
}
```

- Format-version discipline: bump `POLICY_FORMAT_VERSION` when the fields become wire-legal,
  per the crate's "version-bump-or-nothing" rule (`src/leaf/mod.rs:33-42`).
- Until 9e, `DirectoryMode::Keytrans` parses but is **rejected at policy validation** (same
  treatment as `VrfMode::PurePqExperimental` today), so the fields can exist without making
  unfinished KEYTRANS trees reachable in production. `KeytransSuite` is only validated when
  the route is `Keytrans`.
- `declared == observed` (Slice 5) extends naturally: an operator declaring `Keytrans` +
  a given suite must serve a KEYTRANS-backed directory under that exact suite.
- The suite (not `DirectoryMode`) drives the commitment construction (§3.1), the VRF
  ciphersuite, and   the tree-head signature algorithm (§3.2) via a typed accessor, exactly as
  `CheckpointSuite::crypto_suite()` does today.

---

## 4. Sub-slice plan (9b–9f)

Each sub-slice ties to an issue, keeps CI green (`fmt --check`, `clippy -D warnings`, tests,
`wasm32` check, `wasm-pack` SDK build, cross-language KAT, `cargo audit`, MSRV-floor), and is
clearly marked **experimental / version-tagged** (`KEYTRANS_EXP_04`).

| Slice | Scope | Acceptance |
|---|---|---|
| **9b — trait extraction** | Introduce `directory::Directory` (+ `DirectoryVerifier`). Refactor `coniks` to implement it. **Pure scaffold, ZERO behavior change.** No KEYTRANS code. | All existing CONIKS tests + KATs pass **unchanged** byte-for-byte. New object-safety test. `Box<dyn Directory>` round-trips a CONIKS lookup. No new public bytes. |
| **9c — combined-tree core** | NEW `keytrans` module: left-balanced log tree with balanced-head proof compression (`§3.2`), bit-traversal prefix tree with stand-in nodes (`§3.3`/`§10.9`), combined-tree root (`§3.4`), implicit BST monotonic-timestamp navigation (`§4.1`/App. A). Private `keytrans::tls` (TLS-PL helpers). Reuse `commitment` (SHA3-512, private suite) + `vrf` (Ed25519). | Deterministic root over fixed inputs (internal vector, **version-tagged, not frozen**). Log-tree inclusion/consistency verify. Prefix-tree membership verify. `wasm32` compiles. No `cargo audit` regressions. |
| **9d — proofs: search / update / monitor** | Greatest-version search (`§6`) + binary ladder (`§5`/App. B); fixed-version search (`§7`); self-monitor proof verification (`§8`, owner first, contact next). `KeytransExt` sub-trait for KEYTRANS-only surface. **Version-tagged experimental.** | Search/fixed-version/monitor proofs verify against a recomputed root from public inputs only (CONIKS `verify_*` style). RMW / distinguished-entry logic (`§6.1`) unit-tested. Clearly labelled experimental in rustdoc. |
| **9e — policy + WASM + KAT** | Add `policy::DirectoryMode` + `KeytransSuite` axes (rejected-until-now → now legal as experimental). Surface KEYTRANS verify + suite selection in `wasm` SDK. Add a **version-tagged** cross-language byte-parity KAT (parallel to `key_history_v1`, but explicitly labelled experimental/movable). | `DirectoryMode::Keytrans` + `KeytransSuite` parse + validate. `wasm-pack` build green. Cross-language KAT passes Rust↔JS for the experimental suite, with a comment stating bytes may move until `-protocol` Last Call. |
| **9f — NIF + mosskeys** | Expose KEYTRANS directory via `metamorphic_log` NIF; then mosskeys exposes per-namespace `Keytrans` as a new `DirectoryMode` enum value in the existing policy menu (#345). | NIF round-trips a KEYTRANS verify. mosskeys can select `Keytrans` per namespace. Operator ingest/storage explicitly out of scope (see §5, #290). |

---

## 5. Risks & out-of-scope

**Moving wire format.** `-protocol-04` is a WG Document; bytes change. *Mitigation:* the whole
backend is `KEYTRANS_EXP_04`-tagged, behind the trait, and **not** a frozen KAT. When
`-protocol` advances we bump the tag, not the crate's frozen formats. The byte-locked
`key_history_v1` discipline is deliberately **not** applied here.

**TLS-PL adoption cost.** New serialization surface (`§2`) divergent from our length-prefix
grammar. *Mitigation:* hand-roll a small, private, dependency-free `keytrans::tls` covering
only the spec structs that feed crypto; unit-test each against draft examples; **do not**
touch the audited canonical grammar or add a TLS dependency.

**Witness / `tlog-tiles` interop.** Our Layer-2 (`tile`, `checkpoint`, `note`, RFC 6962
SHA-256, C2SP) is the witness-compatible spine (`src/merkle/mod.rs:14-19`, #316). KEYTRANS's
log tree uses balanced-head proof compression (`§3.2`) and a different leaf content
(timestamp ‖ prefix-tree root). *Risk:* the KEYTRANS log tree is **not** a drop-in for the
existing witness/tile pipeline. **Decision (review-confirmed):** for Slice 9, KEYTRANS log
heads are anchored via the **backend-agnostic `anchor` layer (Slice 8)** — which simply
commits to a head and absorbs a KEYTRANS tree head cleanly — and we **do not** fork the
RFC-6962 witness recompute path. Stock KEYTRANS already provides its own auditor tree-head
signature (`§10.3`) for the auditor role. Exposing KEYTRANS heads to the **C2SP witness
network** (independent Ed25519 witness co-signatures) is a genuine but separable ecosystem
feature, deferred to a **future Slice 10 (task #19)** — gated on 9f and `-protocol` Last Call.

**WASM SDK + cross-language KAT.** New verify paths must compile to `wasm32` and round-trip
Rust↔JS. *Mitigation:* 9e adds an explicitly *experimental, movable* KAT (separate from the
frozen `key_history_v1` vectors in `tests/conformance.rs` / `tests/cross_language.rs`), so a
spec revision does not break the frozen conformance suite.

**Out of scope (open-core boundary, #290).** Operator-layer ingest/storage — sequencing,
persistence, serving — stays out of this OSS crate. metamorphic-log provides the
directory *model* + *verification* (recompute-from-public-inputs, the CONIKS `verify_*`
posture). The same I/O-free discipline as `ingest` (Slice 7) applies.

**mosskeys is not blocked by this slice.** mosskeys can build its directory-mode-selection UI
now against the existing CONIKS/policy menu (#345); `Keytrans` becomes a new enum value when
9f lands.

---

## 6. Review gate — RESOLVED

Reviewed with the user; all five points are decided. Recorded here for the 9b kickoff:

1. **TLS-PL approach** — ✅ private, hand-rolled `keytrans::tls` (no TLS dependency, no change
   to the canonical length-prefix grammar; round-trip + draft-example KATs per struct). (§1.1, §5)
2. **Trait minimalism** — ✅ base `Directory` = backend-id + root + search/verify; KEYTRANS-only
   surface as inherent methods, promoted to `KeytransExt` in 9d only if a caller needs it. (§2)
3. **Private suite `0xF0xx`** — ✅ keep it as the mosskeys default (PQ differentiator), but make
   it **configurable**: route (CONIKS/KEYTRANS) and KEYTRANS suite (private hybrid-PQ vs
   standard) are **separate per-namespace posture axes**, so users can choose PQ posture *or*
   stock-ecosystem interop. mosskeys supports both. (§3.1, §3.3)
4. **`policy` axes** — ✅ add `DirectoryMode` *and* `KeytransSuite`, both rejected-until-9e,
   mirroring `VrfMode` reserved variants. (§3.3)
5. **Witness/tile boundary** — ✅ anchor KEYTRANS heads via the Slice-8 `anchor` layer; do
   **not** re-plumb the C2SP witness pipeline now. C2SP witness exposure deferred to a future
   **Slice 10 (task #19)**. (§5)

**Next action: begin 9b (trait extraction) — pure scaffold, zero behavior change.**
</content>
</invoke>
