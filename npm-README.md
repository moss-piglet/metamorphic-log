# @f0rest8/metamorphic-log

Browser **verification + monitor SDK** for the
[metamorphic-log](https://github.com/moss-piglet/metamorphic-log) transparency
log: RFC 6962 / RFC 9162 Merkle inclusion + consistency proofs, C2SP
`tlog-tiles` checkpoints and `signed-note` co-signatures (classical Ed25519 **and**
additive hybrid post-quantum), CONIKS-style index-privacy lookup/absence proofs,
and signed per-namespace policy with **declared == observed** posture enforcement.

Built for [Metamorphic](https://metamorphic.app) and
[Mosslet](https://mosslet.com) — privacy-first apps by
[Moss Piglet Corporation](https://mosspiglet.dev) — so the browser can monitor
the log itself rather than trusting a server.

This package is a WebAssembly build of the `metamorphic-log` Rust crate. It is a
**thin personality over the audited Rust core**: it performs no Merkle,
signature, VRF, or policy logic of its own, so every verification and every byte
it computes is identical to the native crate (locked by a cross-language
byte-parity KAT). All cryptographic primitives come from
[metamorphic-crypto](https://github.com/moss-piglet/metamorphic-crypto); there is
no parallel crypto stack.

> **Verification, not bootstrap trust.** A transparency log proves *continuity*,
> *append-only consistency*, and *anti-equivocation* — it cannot vouch for the
> *first* key you ever saw for a peer (a Trust-On-First-Use problem your app must
> solve out of band). Integrity, authentication, and commitments are
> post-quantum from day one; only CONIKS index-privacy defaults to a classical
> ECVRF. Nothing here is FIPS-validated and this package makes no such claim.

## Install

```bash
npm install @f0rest8/metamorphic-log
```

## Quick start

```js
import init, {
  verifyInclusion,
  verifyConsistency,
  checkpointVerify,
} from "@f0rest8/metamorphic-log";

// Initialize the WASM module once before calling any function.
await init();

// All functions are synchronous after init(). Verification predicates return
// `true` on success and THROW on any failure (tamper, forgery, posture
// mismatch, malformed input).
const ok = verifyInclusion(index, size, leafHashB64, proofB64Array, rootB64);
```

## Conventions

- Binary values cross the boundary as **standard base64** strings (padded, like
  `btoa`/`atob`). Merkle hashes are 32 bytes; SHA3-512 digests / CONIKS roots are
  64 bytes.
- Proof audit paths and trusted-key sets are **arrays of base64 / text strings**.
- C2SP `checkpoint` / `signed-note` bodies and `VerifierKey`s cross as their
  canonical **UTF-8 text** form.

## API overview

### Inclusion + consistency (the monitor core)

```js
import { verifyInclusion, verifyConsistency } from "@f0rest8/metamorphic-log";

// Throws unless the leaf at `index` is included under `root`.
verifyInclusion(index, size, leafHashB64, proofB64Array, rootB64);

// Anti-equivocation: throws unless the size2 tree is an append-only extension
// of the size1 tree.
verifyConsistency(size1, size2, proofB64Array, root1B64, root2B64);
```

### Layer-0 leaf: `mosslet/key-history/v1`

```js
import {
  keyHistoryV1CanonicalBytes,
  keyHistoryV1EntryHash,
  keyHistoryV1Rfc6962LeafHash,
} from "@f0rest8/metamorphic-log";

// Pass an absent/empty prevEntryHash for the genesis entry.
const leafHash = keyHistoryV1Rfc6962LeafHash(
  seq, tsMs, encX25519B64, encPqB64, signingPubB64, prevEntryHashB64,
);
// Feed leafHash straight into verifyInclusion().
```

### Checkpoints + signed notes (Ed25519 + hybrid PQ)

```js
import {
  verifySignedNote,
  checkpointVerify,
  checkpointVerifyInclusion,
  checkpointVerifyConsistency,
} from "@f0rest8/metamorphic-log";

// Number of trusted signatures that verified (>= 1), or throws.
const n = verifySignedNote(noteText, [vkey1, vkey2]);

// Parse + verify a signed checkpoint note → { origin, size, rootB64, extensions }.
const head = checkpointVerify(noteText, [vkey1]);

// Verify a leaf against a verified checkpoint.
checkpointVerifyInclusion(noteText, [vkey1], leafIndex, leafHashB64, proofB64Array);

// Monitor: verify two checkpoints are a consistent, non-equivocating view.
checkpointVerifyConsistency(olderNote, newerNote, [vkey1], proofB64Array);
```

### CONIKS index privacy

```js
import {
  coniksVerifyLookup,
  coniksVerifyAbsence,
  verifyCommitment,
} from "@f0rest8/metamorphic-log";

// Returns the proven value (base64); throws if the proof/VRF/root is invalid.
const valueB64 = coniksVerifyLookup(namespace, vrfPublicB64, rootB64, identityB64, proofB64);

// Throws unless `identity` is provably absent under `root`.
coniksVerifyAbsence(namespace, vrfPublicB64, rootB64, identityB64, proofB64);

verifyCommitment(context, commitmentB64, valueB64, openingB64);
```

### Namespace policy: declared == observed

```js
import {
  signedPolicyVerify,
  policyEnforceCheckpointSigningKey,
  policyEnforceCheckpointSignature,
  policyEnforceVrfSuiteId,
  policyEnforceCommitmentHash,
} from "@f0rest8/metamorphic-log";

// Verify the signed policy → declared posture object.
const policy = signedPolicyVerify(signedPolicyB64);
// { namespace, policySchemaVersion, securityLevel, checkpointSuite,
//   commitmentHash, vrfMode, effectiveFrom, createdAt, policyHashB64,
//   rfc6962LeafHashB64 }

// Hard-reject any observed posture that disagrees with the declared one.
policyEnforceCheckpointSigningKey(signedPolicyB64, observedPublicKeyB64);
policyEnforceCheckpointSignature(signedPolicyB64, observedSignatureB64);
policyEnforceVrfSuiteId(signedPolicyB64, observedSuiteId);          // e.g. 0x03
policyEnforceCommitmentHash(signedPolicyB64, "sha3_256");           // or "sha3_512"
```

## License

MIT OR Apache-2.0. See
[LICENSE-MIT](https://github.com/moss-piglet/metamorphic-log/blob/main/LICENSE-MIT)
and
[LICENSE-APACHE](https://github.com/moss-piglet/metamorphic-log/blob/main/LICENSE-APACHE).
