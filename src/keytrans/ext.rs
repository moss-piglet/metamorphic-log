//! KEYTRANS **directory + verifier** and the [`KeytransExt`] sub-trait
//! (`draft-ietf-keytrans-protocol-04` §5–§8, §11), the relying-party-verifiable
//! search / fixed-version / monitor surface over the Slice 9c combined-tree
//! core.
//!
//! [`KeytransDirectory`] is the operator/prover side. It maintains the single
//! logical [`PrefixTree`] and the chronological [`CombinedTree`], appending a
//! new version each time a label's value is updated (a VRF-derived search key
//! committing to the value via [`commit_update`]). It implements the
//! object-safe base [`Directory`] trait through the **greatest-version search**
//! (§6) common denominator, and the KEYTRANS-only **fixed-version** (§7) and
//! **monitor** (§8) surface through the additive [`KeytransExt`] sub-trait —
//! never polluting the base trait or the CONIKS impl.
//!
//! [`KeytransVerifier`] is the relying-party side. Mirroring the CONIKS
//! [`crate::coniks::verify_lookup`] posture, it recomputes **everything from
//! public inputs**: it VRF-verifies each `(label, version)` lookup to a search
//! key, recomputes the prefix-tree root from the [`PrefixProof`] copath, then
//! recomputes the combined-tree root from the log-tree
//! [`crate::keytrans::log_tree::verify_batch`] inclusion proof, and checks it
//! equals the published [`DirectoryRoot`]. It holds no [`KeytransDirectory`].
//!
//! ## Scope / experimental posture
//!
//! Everything here is `KEYTRANS_EXP_04`-tagged and **movable**. To keep the
//! slice tractable, the search / fixed-version / monitor proofs are produced and
//! verified **against the current (rightmost) log entry** — a faithful
//! greatest-version-at-head proof. The §6/§7/§8 *frontier recursion* and
//! distinguished-entry / contact-monitoring drivers (built on [`super::ladder`])
//! are a separable, movable refinement; the binary-ladder and distinguished-entry
//! primitives they need already live in [`super::ladder`]. Tree-head signing
//! (`TreeHeadTBS`) and policy/SDK wiring are out of scope (later slices).

use std::collections::BTreeMap;

use crate::directory::{
    Directory, DirectoryBackendId, DirectoryRoot, DirectoryVerifier, KEYTRANS_EXP_V04,
    SearchOutcome, SearchProof, SearchResult,
};
use crate::error::{Error, Result};
use crate::vrf::{Vrf, VrfProof, VrfPublicKey, VrfSecretKey};

use super::ladder::base_binary_ladder;
use super::prefix_tree::{self, KtCommitment, PrefixProof, PrefixSearchResultType, SEARCH_KEY_LEN};
use super::{CombinedTree, KtSuite, NH, PrefixTree, log_entry_hash, log_tree, search_key, tls};

/// One rung of a binary ladder: a `(label, version)` lookup and its proof.
///
/// Carries the VRF proof binding `(label, version)` to a search key, the
/// prefix-tree [`PrefixProof`] at that key, and — for an *inclusion* rung — the
/// commitment stored there (so the verifier can recompute the leaf without the
/// operator revealing the value, except at the greatest version).
#[derive(Clone, Debug)]
pub struct LadderStep {
    /// The looked-up version.
    pub version: u32,
    /// The VRF proof for `VrfInput { label, version }` (§10.7).
    pub vrf_proof: VrfProof,
    /// The prefix-tree search proof at the derived search key.
    pub prefix_proof: PrefixProof,
    /// The commitment stored at the search key (present iff the rung is an
    /// inclusion proof).
    pub commitment: Option<KtCommitment>,
}

/// A greatest-version search proof (§6) against the current log head.
#[derive(Clone, Debug)]
pub struct KeytransSearchProof {
    /// The inspected log entry's zero-based index.
    pub entry_index: u64,
    /// The number of log entries (the combined tree's size).
    pub tree_size: u64,
    /// The inspected entry's creation timestamp.
    pub timestamp: u64,
    /// The prefix-tree root recorded by the inspected entry.
    pub prefix_root: [u8; NH],
    /// The log-tree inclusion proof binding the entry into the combined root.
    pub log_inclusion: Vec<[u8; NH]>,
    /// The claimed greatest version of the label (`None` if absent).
    pub greatest_version: Option<u32>,
    /// The search binary ladder proving the claimed greatest version.
    pub ladder: Vec<LadderStep>,
    /// The greatest version's value + opening, revealed so the verifier can
    /// return [`SearchOutcome::Present`] (absent ⇒ `None`).
    pub revealed: Option<RevealedValue>,
}

/// The value + opening revealed for a present label's greatest version.
#[derive(Clone, Debug)]
pub struct RevealedValue {
    /// The label's value at its greatest version.
    pub value: Vec<u8>,
    /// The commitment opening that binds it.
    pub opening: Vec<u8>,
}

/// A fixed-version search proof (§7) against the current log head: a single
/// `(label, version)` lookup.
#[derive(Clone, Debug)]
pub struct KeytransFixedVersionProof {
    /// The inspected log entry's zero-based index.
    pub entry_index: u64,
    /// The number of log entries.
    pub tree_size: u64,
    /// The inspected entry's creation timestamp.
    pub timestamp: u64,
    /// The prefix-tree root recorded by the inspected entry.
    pub prefix_root: [u8; NH],
    /// The log-tree inclusion proof.
    pub log_inclusion: Vec<[u8; NH]>,
    /// The single lookup for the target version.
    pub step: LadderStep,
    /// The target version's value + opening, revealed iff present.
    pub revealed: Option<RevealedValue>,
}

/// A monitoring proof (§8) against the current log head: a monitoring binary
/// ladder (all inclusions) for a known version.
#[derive(Clone, Debug)]
pub struct KeytransMonitorProof {
    /// The inspected log entry's zero-based index.
    pub entry_index: u64,
    /// The number of log entries.
    pub tree_size: u64,
    /// The inspected entry's creation timestamp.
    pub timestamp: u64,
    /// The prefix-tree root recorded by the inspected entry.
    pub prefix_root: [u8; NH],
    /// The log-tree inclusion proof.
    pub log_inclusion: Vec<[u8; NH]>,
    /// The monitored version.
    pub version: u32,
    /// The monitoring binary ladder (every rung must show inclusion).
    pub ladder: Vec<LadderStep>,
}

impl KeytransSearchProof {
    /// Serialize to the experimental, **movable** `tls` search-proof byte blob
    /// (the object-safe [`SearchProof`] payload). Bytes move with the draft.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if an embedded vector exceeds its bound.
    pub fn encode(&self) -> Result<Vec<u8>> {
        tls::encode_search_proof(self)
    }

    /// Parse from the `tls` search-proof byte blob.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] on a malformed blob.
    pub fn decode(bytes: &[u8], commitment_len: usize) -> Result<Self> {
        tls::decode_search_proof(bytes, commitment_len)
    }
}

impl KeytransFixedVersionProof {
    /// Serialize to the experimental, movable `tls` fixed-version byte blob.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if an embedded vector exceeds its bound.
    pub fn encode(&self) -> Result<Vec<u8>> {
        tls::encode_fixed_version_proof(self)
    }

    /// Parse from the `tls` fixed-version byte blob.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] on a malformed blob.
    pub fn decode(bytes: &[u8], commitment_len: usize) -> Result<Self> {
        tls::decode_fixed_version_proof(bytes, commitment_len)
    }
}

impl KeytransMonitorProof {
    /// Serialize to the experimental, movable `tls` monitor byte blob.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if an embedded vector exceeds its bound.
    pub fn encode(&self) -> Result<Vec<u8>> {
        tls::encode_monitor_proof(self)
    }

    /// Parse from the `tls` monitor byte blob.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] on a malformed blob.
    pub fn decode(bytes: &[u8], commitment_len: usize) -> Result<Self> {
        tls::decode_monitor_proof(bytes, commitment_len)
    }
}

/// Per-label operator state: the ordered version history.
#[derive(Clone, Debug, Default)]
struct LabelState {
    versions: Vec<VersionData>,
}

/// One stored version of a label: its commitment, value, and opening.
#[derive(Clone, Debug)]
struct VersionData {
    commitment: KtCommitment,
    value: Vec<u8>,
    opening: Vec<u8>,
}

/// The current log-head context shared by every proof builder.
#[derive(Clone, Debug)]
struct HeadContext {
    entry_index: u64,
    tree_size: u64,
    timestamp: u64,
    prefix_root: [u8; NH],
    log_inclusion: Vec<[u8; NH]>,
}

/// The KEYTRANS combined-tree **directory** (operator/prover side).
///
/// Holds a swappable [`Vrf`] and its keypair, the commitment `context`, the
/// growing [`PrefixTree`] and per-version snapshots of its root, and the
/// [`CombinedTree`] over those versions. Each [`update`](Self::update) appends a
/// new version.
pub struct KeytransDirectory {
    context: String,
    suite: KtSuite,
    vrf: Box<dyn Vrf>,
    vrf_secret: VrfSecretKey,
    vrf_public: VrfPublicKey,
    prefix: PrefixTree,
    snapshots: Vec<[u8; NH]>,
    combined: CombinedTree,
    labels: BTreeMap<Vec<u8>, LabelState>,
}

impl KeytransDirectory {
    /// Create an empty directory committing under `context`, using `vrf` and the
    /// keypair `(vrf_secret, vrf_public)`, on the default experimental
    /// [`KtSuite::MetamorphicHybridExp`] suite.
    ///
    /// For an on-spec IETF standard suite, use
    /// [`KeytransDirectory::new_with_suite`] and pass the suite's matching VRF
    /// ([`KtSuite::vrf`]).
    #[must_use]
    pub fn new(
        context: impl Into<String>,
        vrf: Box<dyn Vrf>,
        vrf_secret: VrfSecretKey,
        vrf_public: VrfPublicKey,
    ) -> Self {
        Self::new_with_suite(
            context,
            KtSuite::MetamorphicHybridExp,
            vrf,
            vrf_secret,
            vrf_public,
        )
    }

    /// Create an empty directory on an explicit [`KtSuite`]. `vrf` must be the
    /// suite's VRF (see [`KtSuite::vrf`]) and `(vrf_secret, vrf_public)` a
    /// matching keypair.
    #[must_use]
    pub fn new_with_suite(
        context: impl Into<String>,
        suite: KtSuite,
        vrf: Box<dyn Vrf>,
        vrf_secret: VrfSecretKey,
        vrf_public: VrfPublicKey,
    ) -> Self {
        Self {
            context: context.into(),
            suite,
            vrf,
            vrf_secret,
            vrf_public,
            prefix: PrefixTree::new(),
            snapshots: Vec::new(),
            combined: CombinedTree::new(),
            labels: BTreeMap::new(),
        }
    }

    /// The cipher suite this directory serves.
    #[must_use]
    pub fn suite(&self) -> KtSuite {
        self.suite
    }

    /// The relying-party public key for proofs this directory produces.
    #[must_use]
    pub fn vrf_public(&self) -> &VrfPublicKey {
        &self.vrf_public
    }

    /// Derive the search key for `(label, version)` via the VRF, returning the
    /// key and the proof binding it.
    fn derive_key(&self, label: &[u8], version: u32) -> Result<([u8; SEARCH_KEY_LEN], VrfProof)> {
        let alpha = tls::VrfInput {
            label: label.to_vec(),
            version,
        }
        .encode()?;
        let proof = self.vrf.prove(&self.vrf_secret, &alpha)?;
        let output = self.vrf.proof_to_output(&proof)?;
        Ok((search_key(&output), proof))
    }

    /// Append a new version of `label` with `value`, published at `timestamp`
    /// (milliseconds since the Unix epoch) and blinded by `opening` (the suite's
    /// [`KtSuite::opening_len`] `Nc` bytes). Returns the new zero-based version
    /// number.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if `opening` is not the suite's `Nc` bytes,
    /// the VRF fails, or the commitment inputs exceed their TLS-PL bounds.
    pub fn update(
        &mut self,
        label: &[u8],
        value: &[u8],
        timestamp: u64,
        opening: &[u8],
    ) -> Result<u32> {
        if opening.len() != self.suite.opening_len() {
            return Err(Error::MalformedKeytrans(format!(
                "commitment opening must be {} bytes for {:?}",
                self.suite.opening_len(),
                self.suite
            )));
        }
        let version = self
            .labels
            .get(label)
            .map_or(0, |s| s.versions.len() as u32);
        let (key, _proof) = self.derive_key(label, version)?;
        let commitment = self
            .suite
            .commit(&self.context, label, version, value, opening)?;
        self.prefix.insert(key, &commitment);
        let prefix_root = self.prefix.root();
        self.snapshots.push(prefix_root);
        self.combined.append(timestamp, &prefix_root);
        self.labels
            .entry(label.to_vec())
            .or_default()
            .versions
            .push(VersionData {
                commitment,
                value: value.to_vec(),
                opening: opening.to_vec(),
            });
        Ok(version)
    }

    /// The combined-tree root.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if the directory is empty.
    pub fn combined_root(&self) -> Result<[u8; NH]> {
        self.combined.root()
    }

    /// Build a single ladder rung for `(label, version)` against the current
    /// prefix tree, looking up the VRF-derived key and proving inclusion (with
    /// its commitment) or non-inclusion.
    fn ladder_step(&self, label: &[u8], version: u32) -> Result<LadderStep> {
        let (key, vrf_proof) = self.derive_key(label, version)?;
        let prefix_proof = self.prefix.prove(&key);
        let commitment = match prefix_proof.result_type {
            PrefixSearchResultType::Inclusion => self
                .labels
                .get(label)
                .and_then(|s| s.versions.get(version as usize))
                .map(|v| v.commitment.clone()),
            _ => None,
        };
        Ok(LadderStep {
            version,
            vrf_proof,
            prefix_proof,
            commitment,
        })
    }

    /// The current head entry's context, or an error if the directory is empty.
    fn head_context(&self) -> Result<HeadContext> {
        let n = self.combined.leaves.len();
        if n == 0 {
            return Err(Error::MalformedKeytrans(
                "cannot prove against an empty keytrans directory".into(),
            ));
        }
        Ok(HeadContext {
            entry_index: (n - 1) as u64,
            tree_size: n as u64,
            timestamp: self.combined.timestamps[n - 1],
            prefix_root: self.snapshots[n - 1],
            log_inclusion: log_tree::batch_proof(&self.combined.leaves, &[n - 1], None),
        })
    }

    /// Produce a greatest-version search proof (§6) at the current head.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if the directory is empty, or the VRF fails.
    pub fn prove_search(&self, label: &[u8]) -> Result<KeytransSearchProof> {
        let HeadContext {
            entry_index,
            tree_size,
            timestamp,
            prefix_root,
            log_inclusion,
        } = self.head_context()?;

        let greatest = self
            .labels
            .get(label)
            .filter(|s| !s.versions.is_empty())
            .map(|s| (s.versions.len() - 1) as u32);

        let (ladder_versions, revealed) = match greatest {
            None => (vec![0u32], None),
            Some(g) => {
                let versions: Vec<u32> = base_binary_ladder(u64::from(g))
                    .into_iter()
                    .map(|v| v as u32)
                    .collect();
                let vd = &self.labels[label].versions[g as usize];
                let revealed = Some(RevealedValue {
                    value: vd.value.clone(),
                    opening: vd.opening.to_vec(),
                });
                (versions, revealed)
            }
        };

        let ladder = ladder_versions
            .into_iter()
            .map(|v| self.ladder_step(label, v))
            .collect::<Result<Vec<_>>>()?;

        Ok(KeytransSearchProof {
            entry_index,
            tree_size,
            timestamp,
            prefix_root,
            log_inclusion,
            greatest_version: greatest,
            ladder,
            revealed,
        })
    }
}

/// KEYTRANS-only directory surface (§7 fixed-version search, §8 monitoring),
/// kept **additive** to the base [`Directory`] trait so it never pollutes the
/// CONIKS backend. Implemented by [`KeytransDirectory`].
pub trait KeytransExt {
    /// Produce a fixed-version search proof (§7) for `(label, version)` against
    /// the current head.
    ///
    /// # Errors
    /// Backend-specific; see [`KeytransDirectory`].
    fn prove_fixed_version(&self, label: &[u8], version: u32) -> Result<KeytransFixedVersionProof>;

    /// Produce a monitoring proof (§8) for a known `(label, version)` against the
    /// current head (a monitoring binary ladder, all inclusions).
    ///
    /// # Errors
    /// Backend-specific; see [`KeytransDirectory`].
    fn prove_monitor(&self, label: &[u8], version: u32) -> Result<KeytransMonitorProof>;
}

impl KeytransExt for KeytransDirectory {
    fn prove_fixed_version(&self, label: &[u8], version: u32) -> Result<KeytransFixedVersionProof> {
        let HeadContext {
            entry_index,
            tree_size,
            timestamp,
            prefix_root,
            log_inclusion,
        } = self.head_context()?;
        let step = self.ladder_step(label, version)?;
        let revealed = if step.prefix_proof.result_type == PrefixSearchResultType::Inclusion {
            self.labels
                .get(label)
                .and_then(|s| s.versions.get(version as usize))
                .map(|v| RevealedValue {
                    value: v.value.clone(),
                    opening: v.opening.to_vec(),
                })
        } else {
            None
        };
        Ok(KeytransFixedVersionProof {
            entry_index,
            tree_size,
            timestamp,
            prefix_root,
            log_inclusion,
            step,
            revealed,
        })
    }

    fn prove_monitor(&self, label: &[u8], version: u32) -> Result<KeytransMonitorProof> {
        let HeadContext {
            entry_index,
            tree_size,
            timestamp,
            prefix_root,
            log_inclusion,
        } = self.head_context()?;
        // Monitoring ladder: every version <= target, all expected to be
        // inclusions (§8.1). Reuse base_binary_ladder filtered to <= version.
        let versions: Vec<u32> = super::ladder::monitor_binary_ladder(u64::from(version), &[])
            .into_iter()
            .map(|v| v as u32)
            .collect();
        let ladder = versions
            .into_iter()
            .map(|v| self.ladder_step(label, v))
            .collect::<Result<Vec<_>>>()?;
        Ok(KeytransMonitorProof {
            entry_index,
            tree_size,
            timestamp,
            prefix_root,
            log_inclusion,
            version,
            ladder,
        })
    }
}

impl Directory for KeytransDirectory {
    fn backend_id(&self) -> DirectoryBackendId {
        KEYTRANS_EXP_V04
    }

    fn root(&self) -> DirectoryRoot {
        // An empty directory has no root; expose the all-zero stand-in so the
        // object-safe trait stays total. Verification of any proof against it
        // fails (there are no entries to prove).
        let root = self.combined.root().unwrap_or([0u8; NH]);
        DirectoryRoot::from_bytes(root.to_vec())
    }

    fn search(&self, label: &[u8]) -> Result<SearchResult> {
        let proof = self.prove_search(label)?;
        let outcome = match (&proof.greatest_version, &proof.revealed) {
            (Some(_), Some(r)) => SearchOutcome::Present(r.value.clone()),
            _ => SearchOutcome::Absent,
        };
        // Encode the typed proof into the object-safe, byte-oriented
        // `SearchProof` (the experimental, movable `tls` wire), so a
        // `Box<dyn DirectoryVerifier>` can verify it without the typed surface.
        let bytes = tls::encode_search_proof(&proof)?;
        Ok(SearchResult::new(outcome, SearchProof::from_bytes(bytes)))
    }
}

// ---------------------------------------------------------------------------
// Relying-party verification (recompute everything from public inputs).
// ---------------------------------------------------------------------------

/// The KEYTRANS relying-party **verifier**: the public inputs needed to
/// recompute proofs (the commitment `context`, the swappable [`Vrf`], and the
/// VRF public key). Holds no directory.
pub struct KeytransVerifier {
    context: String,
    suite: KtSuite,
    vrf: Box<dyn Vrf>,
    vrf_public: VrfPublicKey,
}

impl KeytransVerifier {
    /// Build a verifier checking proofs produced under `vrf` against
    /// `vrf_public`, with commitments under `context`, on the default
    /// experimental [`KtSuite::MetamorphicHybridExp`] suite.
    ///
    /// For an on-spec IETF standard suite, use
    /// [`KeytransVerifier::new_with_suite`] with the suite's matching VRF.
    #[must_use]
    pub fn new(context: impl Into<String>, vrf: Box<dyn Vrf>, vrf_public: VrfPublicKey) -> Self {
        Self::new_with_suite(context, KtSuite::MetamorphicHybridExp, vrf, vrf_public)
    }

    /// Build a verifier on an explicit [`KtSuite`]. `vrf` must be the suite's
    /// VRF (see [`KtSuite::vrf`]).
    #[must_use]
    pub fn new_with_suite(
        context: impl Into<String>,
        suite: KtSuite,
        vrf: Box<dyn Vrf>,
        vrf_public: VrfPublicKey,
    ) -> Self {
        Self {
            context: context.into(),
            suite,
            vrf,
            vrf_public,
        }
    }

    /// The cipher suite this verifier checks against.
    #[must_use]
    pub fn suite(&self) -> KtSuite {
        self.suite
    }

    /// Recompute the combined-tree root from a log entry's `(timestamp,
    /// prefix_root)` and its inclusion proof, and check it equals `root`.
    fn check_combined_root(
        &self,
        root: &[u8; NH],
        entry_index: u64,
        tree_size: u64,
        timestamp: u64,
        prefix_root: &[u8; NH],
        log_inclusion: &[[u8; NH]],
    ) -> Result<()> {
        let entry_leaf = log_entry_hash(timestamp, prefix_root);
        log_tree::verify_batch(
            tree_size as usize,
            &[(entry_index as usize, entry_leaf)],
            None,
            log_inclusion,
            root,
        )
    }

    /// VRF-verify a ladder rung and check its prefix proof against `prefix_root`,
    /// returning whether the rung proved inclusion.
    fn check_step(&self, prefix_root: &[u8; NH], label: &[u8], step: &LadderStep) -> Result<bool> {
        let alpha = tls::VrfInput {
            label: label.to_vec(),
            version: step.version,
        }
        .encode()?;
        let output = self
            .vrf
            .verify(&self.vrf_public, &alpha, &step.vrf_proof)?
            .ok_or(Error::VrfProofInvalid)?;
        let key = search_key(&output);

        match step.prefix_proof.result_type {
            PrefixSearchResultType::Inclusion => {
                let commitment = step.commitment.as_ref().ok_or_else(|| {
                    Error::MalformedKeytrans(
                        "inclusion ladder rung is missing its commitment".into(),
                    )
                })?;
                prefix_tree::verify_inclusion(prefix_root, &key, commitment, &step.prefix_proof)?;
                Ok(true)
            }
            _ => {
                prefix_tree::verify_absence(prefix_root, &key, &step.prefix_proof)?;
                Ok(false)
            }
        }
    }

    /// Verify a greatest-version search proof (§6), returning the recomputed
    /// [`SearchOutcome`].
    ///
    /// Recomputes the combined root from the log inclusion proof; VRF-verifies
    /// and checks each ladder rung against the entry's prefix root; checks the
    /// ladder is exactly `base_binary_ladder(greatest)` with inclusion iff
    /// `version <= greatest`; and, for a present label, re-opens the revealed
    /// value to the greatest version's committed leaf.
    ///
    /// # Errors
    /// [`Error::KeytransRootMismatch`] / [`Error::VrfProofInvalid`] /
    /// [`Error::CommitmentMismatch`] / [`Error::MalformedKeytrans`] on any
    /// inconsistency.
    pub fn verify_search(
        &self,
        root: &[u8; NH],
        label: &[u8],
        proof: &KeytransSearchProof,
    ) -> Result<SearchOutcome> {
        self.check_combined_root(
            root,
            proof.entry_index,
            proof.tree_size,
            proof.timestamp,
            &proof.prefix_root,
            &proof.log_inclusion,
        )?;

        // The ladder versions must match the canonical ladder for the claim.
        let expected: Vec<u32> = match proof.greatest_version {
            None => vec![0],
            Some(g) => base_binary_ladder(u64::from(g))
                .into_iter()
                .map(|v| v as u32)
                .collect(),
        };
        if proof
            .ladder
            .iter()
            .map(|s| s.version)
            .ne(expected.iter().copied())
        {
            return Err(Error::MalformedKeytrans(
                "search ladder versions do not match the canonical binary ladder".into(),
            ));
        }

        for step in &proof.ladder {
            let included = self.check_step(&proof.prefix_root, label, step)?;
            let expected_inclusion = proof.greatest_version.is_some_and(|g| step.version <= g);
            if included != expected_inclusion {
                return Err(Error::MalformedKeytrans(format!(
                    "ladder rung version {} inclusion {included} contradicts claimed greatest {:?}",
                    step.version, proof.greatest_version
                )));
            }
        }

        match (proof.greatest_version, &proof.revealed) {
            (Some(g), Some(r)) => {
                // Re-open the revealed value and match it to the greatest
                // version's inclusion commitment.
                let recomputed =
                    self.suite
                        .commit(&self.context, label, g, &r.value, &r.opening)?;
                let committed = proof
                    .ladder
                    .iter()
                    .find(|s| s.version == g)
                    .and_then(|s| s.commitment.as_ref())
                    .ok_or_else(|| {
                        Error::MalformedKeytrans(
                            "greatest version is missing its inclusion commitment".into(),
                        )
                    })?;
                if &recomputed != committed {
                    return Err(Error::CommitmentMismatch);
                }
                Ok(SearchOutcome::Present(r.value.clone()))
            }
            (None, _) => Ok(SearchOutcome::Absent),
            (Some(_), None) => Err(Error::MalformedKeytrans(
                "present label is missing its revealed value".into(),
            )),
        }
    }

    /// Verify a fixed-version search proof (§7), returning the recomputed
    /// [`SearchOutcome`] for the target version.
    ///
    /// # Errors
    /// As [`verify_search`](Self::verify_search).
    pub fn verify_fixed_version(
        &self,
        root: &[u8; NH],
        label: &[u8],
        proof: &KeytransFixedVersionProof,
    ) -> Result<SearchOutcome> {
        self.check_combined_root(
            root,
            proof.entry_index,
            proof.tree_size,
            proof.timestamp,
            &proof.prefix_root,
            &proof.log_inclusion,
        )?;
        let included = self.check_step(&proof.prefix_root, label, &proof.step)?;
        if !included {
            return Ok(SearchOutcome::Absent);
        }
        let revealed = proof.revealed.as_ref().ok_or_else(|| {
            Error::MalformedKeytrans("present fixed version is missing its revealed value".into())
        })?;
        let recomputed = self.suite.commit(
            &self.context,
            label,
            proof.step.version,
            &revealed.value,
            &revealed.opening,
        )?;
        let committed = proof.step.commitment.as_ref().ok_or_else(|| {
            Error::MalformedKeytrans("inclusion is missing its commitment".into())
        })?;
        if &recomputed != committed {
            return Err(Error::CommitmentMismatch);
        }
        Ok(SearchOutcome::Present(revealed.value.clone()))
    }

    /// Verify a monitoring proof (§8): every rung of the monitoring ladder must
    /// VRF-verify and show inclusion against the entry's prefix root, and the
    /// ladder must match the canonical monitoring ladder for `version`.
    ///
    /// # Errors
    /// [`Error::KeytransRootMismatch`] if a rung is not an inclusion or the
    /// combined root does not recompute; other variants on structural failure.
    pub fn verify_monitor(
        &self,
        root: &[u8; NH],
        label: &[u8],
        proof: &KeytransMonitorProof,
    ) -> Result<()> {
        self.check_combined_root(
            root,
            proof.entry_index,
            proof.tree_size,
            proof.timestamp,
            &proof.prefix_root,
            &proof.log_inclusion,
        )?;
        let expected: Vec<u32> =
            super::ladder::monitor_binary_ladder(u64::from(proof.version), &[])
                .into_iter()
                .map(|v| v as u32)
                .collect();
        if proof
            .ladder
            .iter()
            .map(|s| s.version)
            .ne(expected.iter().copied())
        {
            return Err(Error::MalformedKeytrans(
                "monitor ladder versions do not match the canonical monitoring ladder".into(),
            ));
        }
        for step in &proof.ladder {
            if !self.check_step(&proof.prefix_root, label, step)? {
                // A monitoring ladder rung that is not an inclusion is a
                // downgrade — the headline negative outcome.
                return Err(Error::KeytransRootMismatch);
            }
        }
        Ok(())
    }

    // --- Byte-oriented verify (decode the movable `tls` wire, then dispatch to
    //     the typed verify above). These back the object-safe `DirectoryVerifier`
    //     trait and the WASM SDK, so a `Box<dyn DirectoryVerifier>` / a browser
    //     can verify a KEYTRANS proof without the typed surface. ---

    /// Verify a byte-encoded greatest-version search proof (§6) against a
    /// byte-encoded combined root, returning the recomputed [`SearchOutcome`].
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if `root` is not [`NH`] bytes or the proof
    /// blob is malformed; otherwise as
    /// [`verify_search`](Self::verify_search).
    pub fn verify_search_bytes(
        &self,
        root: &[u8],
        label: &[u8],
        proof: &[u8],
    ) -> Result<SearchOutcome> {
        let root = root_array(root)?;
        let typed = tls::decode_search_proof(proof, self.suite.commitment_len())?;
        self.verify_search(&root, label, &typed)
    }

    /// Verify a byte-encoded fixed-version search proof (§7).
    ///
    /// # Errors
    /// As [`verify_search_bytes`](Self::verify_search_bytes).
    pub fn verify_fixed_version_bytes(
        &self,
        root: &[u8],
        label: &[u8],
        proof: &[u8],
    ) -> Result<SearchOutcome> {
        let root = root_array(root)?;
        let typed = tls::decode_fixed_version_proof(proof, self.suite.commitment_len())?;
        self.verify_fixed_version(&root, label, &typed)
    }

    /// Verify a byte-encoded monitoring proof (§8). Returns `true` on success
    /// (a non-throwing boolean for the SDK).
    ///
    /// # Errors
    /// As [`verify_search_bytes`](Self::verify_search_bytes); a downgrade is
    /// [`Error::KeytransRootMismatch`].
    pub fn verify_monitor_bytes(&self, root: &[u8], label: &[u8], proof: &[u8]) -> Result<bool> {
        let root = root_array(root)?;
        let typed = tls::decode_monitor_proof(proof, self.suite.commitment_len())?;
        self.verify_monitor(&root, label, &typed)?;
        Ok(true)
    }
}

/// Convert opaque root bytes into the fixed [`NH`]-byte combined-tree root.
fn root_array(root: &[u8]) -> Result<[u8; NH]> {
    root.try_into().map_err(|_| {
        Error::MalformedKeytrans(format!(
            "combined root must be {NH} bytes, got {}",
            root.len()
        ))
    })
}

impl DirectoryVerifier for KeytransVerifier {
    fn backend_id(&self) -> DirectoryBackendId {
        KEYTRANS_EXP_V04
    }

    fn verify_search(
        &self,
        root: &DirectoryRoot,
        label: &[u8],
        proof: &SearchProof,
    ) -> Result<SearchOutcome> {
        // The object-safe byte path: decode the movable `tls` search-proof wire
        // and dispatch to the typed, recompute-from-public-inputs verify. The
        // richly-typed inherent `verify_search` / `verify_fixed_version` /
        // `verify_monitor` remain available for callers that hold typed proofs.
        self.verify_search_bytes(root.as_bytes(), label, proof.as_bytes())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::vrf::{Ecvrf, EcvrfP256};

    const CTX: &str = "acme/keytrans-commitment/v1";

    fn directory() -> KeytransDirectory {
        let vrf = Ecvrf;
        let (sk, pk) = vrf.generate_keypair();
        KeytransDirectory::new(CTX, Box::new(Ecvrf), sk, pk)
    }

    fn verifier(dir: &KeytransDirectory) -> KeytransVerifier {
        KeytransVerifier::new(CTX, Box::new(Ecvrf), dir.vrf_public().clone())
    }

    /// Build a directory + matching verifier for an on-spec standard suite.
    fn standard_pair(suite: KtSuite) -> (KeytransDirectory, KeytransVerifier) {
        let (sk, pk) = suite.vrf().generate_keypair();
        let dir = KeytransDirectory::new_with_suite(CTX, suite, suite.vrf(), sk, pk.clone());
        let ver = KeytransVerifier::new_with_suite(CTX, suite, suite.vrf(), pk);
        (dir, ver)
    }

    // --- Standard-suite round-trip KATs (KEYTRANS_EXP_04, MOVABLE) ---
    //
    // Prover -> verifier round-trips for both on-spec IETF suites, exercising
    // the 16-byte opening / 32-byte HMAC-SHA256 commitment path end to end
    // (search, fixed-version, monitor), plus the byte-oriented SDK path with the
    // suite's commitment width. These vectors are experimental / movable — they
    // track the draft and are NOT in the frozen conformance / cross-language
    // suites.

    #[test]
    fn standard_suites_search_fixed_version_monitor_round_trip() {
        for suite in [KtSuite::Kt128Sha256P256, KtSuite::Kt128Sha256Ed25519] {
            let (mut dir, ver) = standard_pair(suite);
            let op = vec![0x5A; suite.opening_len()]; // Nc = 16 bytes
            for i in 0..5u32 {
                dir.update(
                    b"alice",
                    format!("head-v{i}").as_bytes(),
                    1_000 + u64::from(i) * 1_000,
                    &op,
                )
                .unwrap();
            }
            dir.update(b"bob", b"bob-v0", 9_000, &op).unwrap();
            let root = dir.combined_root().unwrap();

            // Greatest-version search (present + absent).
            let search = dir.prove_search(b"alice").unwrap();
            assert_eq!(search.greatest_version, Some(4));
            assert_eq!(
                ver.verify_search(&root, b"alice", &search).unwrap(),
                SearchOutcome::Present(b"head-v4".to_vec())
            );
            let absent = dir.prove_search(b"carol").unwrap();
            assert_eq!(
                ver.verify_search(&root, b"carol", &absent).unwrap(),
                SearchOutcome::Absent
            );

            // Fixed-version.
            let fv = dir.prove_fixed_version(b"alice", 2).unwrap();
            assert_eq!(
                ver.verify_fixed_version(&root, b"alice", &fv).unwrap(),
                SearchOutcome::Present(b"head-v2".to_vec())
            );

            // Monitor.
            let mon = dir.prove_monitor(b"alice", 3).unwrap();
            assert!(ver.verify_monitor(&root, b"alice", &mon).is_ok());

            // Byte-oriented path uses the suite's 32-byte commitment width.
            let clen = suite.commitment_len();
            assert_eq!(clen, 32);
            let search_bytes = search.encode().unwrap();
            assert_eq!(
                ver.verify_search_bytes(&root, b"alice", &search_bytes)
                    .unwrap(),
                SearchOutcome::Present(b"head-v4".to_vec())
            );
            assert_eq!(
                KeytransSearchProof::decode(&search_bytes, clen)
                    .unwrap()
                    .greatest_version,
                Some(4)
            );

            // A tampered revealed value is rejected (commitment mismatch).
            let mut forged = search.clone();
            forged.revealed = Some(RevealedValue {
                value: b"forged".to_vec(),
                opening: op.clone(),
            });
            assert_eq!(
                ver.verify_search(&root, b"alice", &forged),
                Err(Error::CommitmentMismatch)
            );
        }
    }

    #[test]
    fn standard_suite_rejects_wrong_opening_length() {
        let suite = KtSuite::Kt128Sha256P256;
        let (mut dir, _ver) = standard_pair(suite);
        // 32-byte opening is wrong for a standard suite (Nc = 16).
        assert!(matches!(
            dir.update(b"alice", b"v", 1_000, &[0u8; 32]),
            Err(Error::MalformedKeytrans(_))
        ));
    }

    #[test]
    fn standard_suites_backend_id_is_combined_tree() {
        let (dir, ver) = standard_pair(KtSuite::Kt128Sha256Ed25519);
        assert_eq!(Directory::backend_id(&dir), KEYTRANS_EXP_V04);
        assert_eq!(DirectoryVerifier::backend_id(&ver), KEYTRANS_EXP_V04);
        assert_eq!(EcvrfP256.suite_id(), 0x01);
    }

    fn opening(tag: u8) -> [u8; crate::keytrans::NC] {
        [tag; crate::keytrans::NC]
    }

    #[test]
    fn greatest_version_search_present_verifies() {
        let mut dir = directory();
        dir.update(b"alice", b"head-v0", 1_000, &opening(1))
            .unwrap();
        dir.update(b"alice", b"head-v1", 2_000, &opening(2))
            .unwrap();
        dir.update(b"alice", b"head-v2", 3_000, &opening(3))
            .unwrap();
        dir.update(b"bob", b"bob-v0", 4_000, &opening(4)).unwrap();

        let root = dir.combined_root().unwrap();
        let v = verifier(&dir);
        let proof = dir.prove_search(b"alice").unwrap();
        assert_eq!(proof.greatest_version, Some(2));
        assert_eq!(
            v.verify_search(&root, b"alice", &proof).unwrap(),
            SearchOutcome::Present(b"head-v2".to_vec())
        );
    }

    #[test]
    fn greatest_version_search_absent_verifies() {
        let mut dir = directory();
        dir.update(b"alice", b"x", 1_000, &opening(1)).unwrap();
        let root = dir.combined_root().unwrap();
        let v = verifier(&dir);
        let proof = dir.prove_search(b"carol").unwrap();
        assert_eq!(proof.greatest_version, None);
        assert_eq!(
            v.verify_search(&root, b"carol", &proof).unwrap(),
            SearchOutcome::Absent
        );
    }

    #[test]
    fn search_rejects_tampered_root_and_wrong_label() {
        let mut dir = directory();
        dir.update(b"alice", b"v0", 1_000, &opening(1)).unwrap();
        dir.update(b"alice", b"v1", 2_000, &opening(2)).unwrap();
        let root = dir.combined_root().unwrap();
        let v = verifier(&dir);
        let proof = dir.prove_search(b"alice").unwrap();

        let mut bad_root = root;
        bad_root[0] ^= 0xFF;
        assert_eq!(
            v.verify_search(&bad_root, b"alice", &proof),
            Err(Error::KeytransRootMismatch)
        );

        // Verifying alice's proof under a different label re-derives different
        // search keys, so the prefix proofs no longer recompute the root.
        assert!(v.verify_search(&root, b"mallory", &proof).is_err());
    }

    #[test]
    fn search_rejects_tampered_revealed_value() {
        let mut dir = directory();
        dir.update(b"alice", b"real", 1_000, &opening(1)).unwrap();
        let root = dir.combined_root().unwrap();
        let v = verifier(&dir);
        let mut proof = dir.prove_search(b"alice").unwrap();
        proof.revealed = Some(RevealedValue {
            value: b"forged".to_vec(),
            opening: opening(1).to_vec(),
        });
        assert_eq!(
            v.verify_search(&root, b"alice", &proof),
            Err(Error::CommitmentMismatch)
        );
    }

    #[test]
    fn search_rejects_overclaimed_greatest_version() {
        let mut dir = directory();
        dir.update(b"alice", b"v0", 1_000, &opening(1)).unwrap();
        dir.update(b"alice", b"v1", 2_000, &opening(2)).unwrap();
        let root = dir.combined_root().unwrap();
        let v = verifier(&dir);
        let mut proof = dir.prove_search(b"alice").unwrap();
        // Lie: claim greatest is 5. The ladder no longer matches base_binary_ladder(5).
        proof.greatest_version = Some(5);
        assert!(v.verify_search(&root, b"alice", &proof).is_err());
    }

    #[test]
    fn fixed_version_search_verifies_present_and_absent() {
        let mut dir = directory();
        dir.update(b"alice", b"v0", 1_000, &opening(1)).unwrap();
        dir.update(b"alice", b"v1", 2_000, &opening(2)).unwrap();
        let root = dir.combined_root().unwrap();
        let v = verifier(&dir);

        let p0 = dir.prove_fixed_version(b"alice", 0).unwrap();
        assert_eq!(
            v.verify_fixed_version(&root, b"alice", &p0).unwrap(),
            SearchOutcome::Present(b"v0".to_vec())
        );

        let p9 = dir.prove_fixed_version(b"alice", 9).unwrap();
        assert_eq!(
            v.verify_fixed_version(&root, b"alice", &p9).unwrap(),
            SearchOutcome::Absent
        );
    }

    #[test]
    fn monitor_proof_verifies_and_rejects_downgrade() {
        let mut dir = directory();
        for i in 0..5u32 {
            dir.update(
                b"alice",
                format!("v{i}").as_bytes(),
                1_000 + u64::from(i) * 1_000,
                &opening(i as u8 + 1),
            )
            .unwrap();
        }
        let root = dir.combined_root().unwrap();
        let v = verifier(&dir);
        let proof = dir.prove_monitor(b"alice", 3).unwrap();
        assert!(v.verify_monitor(&root, b"alice", &proof).is_ok());

        // Tamper a rung's VRF proof → rejected.
        let mut bad = proof.clone();
        if let Some(step) = bad.ladder.first_mut() {
            let mut pbytes = step.vrf_proof.as_bytes().to_vec();
            pbytes[0] ^= 0xFF;
            step.vrf_proof = VrfProof::from_bytes(pbytes);
        }
        assert!(v.verify_monitor(&root, b"alice", &bad).is_err());
    }

    #[test]
    fn directory_and_verifier_backend_ids_match() {
        let dir = directory();
        let v = verifier(&dir);
        assert_eq!(Directory::backend_id(&dir), KEYTRANS_EXP_V04);
        assert_eq!(DirectoryVerifier::backend_id(&v), KEYTRANS_EXP_V04);
    }

    #[test]
    fn traits_are_object_safe() {
        fn dir_obj(_: &dyn Directory) {}
        fn ver_obj(_: &dyn DirectoryVerifier) {}
        fn ext_obj(_: &dyn KeytransExt) {}
        let _ = (dir_obj, ver_obj, ext_obj);
    }

    #[test]
    fn search_through_base_directory_trait() {
        let mut dir = directory();
        dir.update(b"alice", b"value", 1_000, &opening(1)).unwrap();
        let result = Directory::search(&dir, b"alice").unwrap();
        assert_eq!(result.outcome(), &SearchOutcome::Present(b"value".to_vec()));
    }

    #[test]
    fn byte_oriented_verify_search_round_trips_through_trait() {
        // The object-safe `Box<dyn Directory>` -> `Box<dyn DirectoryVerifier>`
        // path: search produces an opaque `SearchProof` blob that the verifier
        // decodes (the movable `tls` wire) and validates from public inputs.
        let mut dir = directory();
        dir.update(b"alice", b"head-v0", 1_000, &opening(1))
            .unwrap();
        dir.update(b"alice", b"head-v1", 2_000, &opening(2))
            .unwrap();
        dir.update(b"bob", b"bob-v0", 3_000, &opening(3)).unwrap();

        let verifier: Box<dyn DirectoryVerifier> = Box::new(verifier(&dir));
        let boxed: Box<dyn Directory> = Box::new(dir);
        let root = boxed.root();
        let result = boxed.search(b"alice").unwrap();
        let (outcome, proof) = result.into_parts();
        assert_eq!(outcome, SearchOutcome::Present(b"head-v1".to_vec()));

        let verified = verifier.verify_search(&root, b"alice", &proof).unwrap();
        assert_eq!(verified, SearchOutcome::Present(b"head-v1".to_vec()));

        // A tampered root is rejected through the byte path too.
        let mut bad = root.into_bytes();
        bad[0] ^= 0xFF;
        assert!(
            verifier
                .verify_search(&DirectoryRoot::from_bytes(bad), b"alice", &proof)
                .is_err()
        );
    }

    #[test]
    fn byte_oriented_fixed_version_and_monitor_round_trip() {
        let mut dir = directory();
        for i in 0..5u32 {
            dir.update(
                b"alice",
                format!("v{i}").as_bytes(),
                1_000 + u64::from(i) * 1_000,
                &opening(i as u8 + 1),
            )
            .unwrap();
        }
        let root = dir.combined_root().unwrap();
        let v = verifier(&dir);

        let fv = dir.prove_fixed_version(b"alice", 2).unwrap();
        let fv_bytes = fv.encode().unwrap();
        assert_eq!(
            v.verify_fixed_version_bytes(&root, b"alice", &fv_bytes)
                .unwrap(),
            SearchOutcome::Present(b"v2".to_vec())
        );

        let mon = dir.prove_monitor(b"alice", 3).unwrap();
        let mon_bytes = mon.encode().unwrap();
        assert!(v.verify_monitor_bytes(&root, b"alice", &mon_bytes).unwrap());

        // Round-trip the typed proofs through the wire too (experimental suite:
        // 64-byte commitment tags).
        let clen = KtSuite::MetamorphicHybridExp.commitment_len();
        assert_eq!(
            KeytransFixedVersionProof::decode(&fv_bytes, clen)
                .unwrap()
                .step
                .version,
            2
        );
        assert_eq!(
            KeytransMonitorProof::decode(&mon_bytes, clen)
                .unwrap()
                .version,
            3
        );
    }
}
