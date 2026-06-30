//! Private, dependency-free **TLS presentation language** helpers for the
//! KEYTRANS combined-tree backend.
//!
//! `draft-ietf-keytrans-protocol-04` §2 is explicit: *"cryptographic
//! computations MUST be done with the TLS presentation language [RFC 8446]
//! format to ensure the protocol's security properties are maintained."* The
//! rest of this crate uses its own audited `u32`-big-endian length-prefix
//! grammar ([`crate::leaf`]); that grammar is **not** byte-compatible with
//! TLS-PL and is deliberately left untouched. Instead, the KEYTRANS backend gets
//! its own tiny TLS-PL reader/writer, scoped to exactly the structs whose bytes
//! feed a hash or a signature.
//!
//! This mirrors how [`crate::encoding`] is a small, private, dependency-free
//! helper rather than a pulled-in crate: we do **not** add a general TLS
//! dependency (RustCrypto-only / minimal-dependency discipline). The surface
//! TLS-PL needs here is small and spec-fixed.
//!
//! ## What is covered (this slice)
//!
//! The combined-tree *core* (Slice 9c) hashes four structures, so those four
//! round-trip through this module:
//!
//! - [`VrfInput`] (§10.7) — the VRF is evaluated over `label || version`.
//! - [`UpdateValue`] (§10.5) — the value a commitment opens to. Only the
//!   *default* deployment mode is modelled; the third-party-management
//!   `UpdateSuffix` (a signature) is out of scope until a slice needs it.
//! - [`CommitmentValue`] (§10.6) — the structured input to the commitment.
//! - [`LogEntry`] (§10.8) — a log-tree leaf: a timestamp plus the prefix-tree
//!   root at that version.
//!
//! `TreeHeadTBS` / `AuditorTreeHeadTBS` (§10.2 / §10.3) are intentionally absent
//! — they are the bytes a *signed* tree head covers, which lands with the slice
//! that signs heads, not the tree-core slice.
//!
//! ## TLS-PL primitives used
//!
//! - integers (`uint8/16/32/64`) are fixed-width **big-endian**;
//! - `opaque x[n]` is exactly `n` bytes, no length prefix;
//! - `opaque x<0..2^8-1>` / `<0..2^16-1>` / `<0..2^32-1>` are a `1`/`2`/`4`-byte
//!   big-endian length header followed by the bytes.
//!
//! Every `decode` is strict: a length header that overruns the buffer, or
//! trailing bytes after the outermost struct, is a [`Error::MalformedKeytrans`].

use crate::error::{Error, Result};

use super::NH;

/// A forward-only cursor that reads TLS-presentation-language fields from a byte
/// slice, tracking how much input has been consumed.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn need(&self, n: usize, what: &str) -> Result<usize> {
        let end = self.offset.checked_add(n).ok_or_else(|| {
            Error::MalformedKeytrans(format!("{what}: length {n} overflows offset"))
        })?;
        if end > self.bytes.len() {
            return Err(Error::MalformedKeytrans(format!(
                "{what}: need {n} bytes at offset {}, only {} available",
                self.offset,
                self.bytes.len() - self.offset
            )));
        }
        Ok(end)
    }

    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        let end = self.need(n, what)?;
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn u8(&mut self, what: &str) -> Result<u8> {
        Ok(self.take(1, what)?[0])
    }

    fn u32(&mut self, what: &str) -> Result<u32> {
        let b = self.take(4, what)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self, what: &str) -> Result<u64> {
        let b = self.take(8, what)?;
        Ok(u64::from_be_bytes(b.try_into().unwrap()))
    }

    /// Read an `opaque x<0..2^8-1>` vector (1-byte length header).
    fn vec_u8(&mut self, what: &str) -> Result<Vec<u8>> {
        let len = self.u8(what)? as usize;
        Ok(self.take(len, what)?.to_vec())
    }

    /// Read a `uint16` (big-endian).
    fn u16(&mut self, what: &str) -> Result<u16> {
        let b = self.take(2, what)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Read an `opaque x<0..2^16-1>` vector (2-byte length header).
    fn vec_u16(&mut self, what: &str) -> Result<Vec<u8>> {
        let len = self.u16(what)? as usize;
        Ok(self.take(len, what)?.to_vec())
    }

    /// Read an `opaque x<0..2^32-1>` vector (4-byte length header).
    fn vec_u32(&mut self, what: &str) -> Result<Vec<u8>> {
        let len = self.u32(what)? as usize;
        Ok(self.take(len, what)?.to_vec())
    }

    /// Consume the reader, erroring if any input is left over after the
    /// outermost struct.
    fn finish(self, what: &str) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::MalformedKeytrans(format!(
                "{what}: {} trailing byte(s) after struct",
                self.bytes.len() - self.offset
            )))
        }
    }
}

/// Append a `1`-byte-length-prefixed (`<0..2^8-1>`) vector, validating the
/// length bound.
fn write_vec_u8(out: &mut Vec<u8>, bytes: &[u8], what: &str) -> Result<()> {
    let len = u8::try_from(bytes.len()).map_err(|_| {
        Error::MalformedKeytrans(format!(
            "{what}: {} bytes exceeds the <0..2^8-1> vector bound (255)",
            bytes.len()
        ))
    })?;
    out.push(len);
    out.extend_from_slice(bytes);
    Ok(())
}

/// Append a `4`-byte-length-prefixed (`<0..2^32-1>`) vector, validating the
/// length bound.
fn write_vec_u32(out: &mut Vec<u8>, bytes: &[u8], what: &str) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| {
        Error::MalformedKeytrans(format!(
            "{what}: {} bytes exceeds the <0..2^32-1> vector bound",
            bytes.len()
        ))
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Append a `2`-byte-length-prefixed (`<0..2^16-1>`) vector, validating the
/// length bound.
fn write_vec_u16(out: &mut Vec<u8>, bytes: &[u8], what: &str) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| {
        Error::MalformedKeytrans(format!(
            "{what}: {} bytes exceeds the <0..2^16-1> vector bound (65535)",
            bytes.len()
        ))
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// The VRF input (`draft-ietf-keytrans-protocol-04` §10.7): the label-version
/// pair the VRF is evaluated over to derive a prefix-tree search key.
///
/// ```text
/// struct {
///   opaque label<0..2^8-1>;
///   uint32 version;
/// } VrfInput;
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfInput {
    /// The label (identity) being searched for. At most 255 bytes.
    pub label: Vec<u8>,
    /// The label's version number.
    pub version: u32,
}

impl VrfInput {
    /// Serialize to canonical TLS-PL bytes.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if `label` exceeds 255 bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(1 + self.label.len() + 4);
        write_vec_u8(&mut out, &self.label, "VrfInput.label")?;
        out.extend_from_slice(&self.version.to_be_bytes());
        Ok(out)
    }

    /// Parse canonical TLS-PL bytes.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] on a length header that overruns the buffer
    /// or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let label = r.vec_u8("VrfInput.label")?;
        let version = r.u32("VrfInput.version")?;
        r.finish("VrfInput")?;
        Ok(Self { label, version })
    }
}

/// The value a prefix-tree commitment opens to
/// (`draft-ietf-keytrans-protocol-04` §10.5), in the *default* deployment mode
/// (no third-party-management `UpdateSuffix`).
///
/// ```text
/// struct {
///   opaque value<0..2^32-1>;
///   UpdateSuffix suffix;   // empty in the default mode
/// } UpdateValue;
/// ```
///
/// The third-party-management suffix (a Service-Operator signature) is not
/// modelled here; it is added by the slice that needs that deployment mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateValue {
    /// The value associated with the label-version pair.
    pub value: Vec<u8>,
}

impl UpdateValue {
    /// Serialize to canonical TLS-PL bytes.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if `value` exceeds the `<0..2^32-1>` bound.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(4 + self.value.len());
        write_vec_u32(&mut out, &self.value, "UpdateValue.value")?;
        Ok(out)
    }

    /// Parse canonical TLS-PL bytes.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] on a length header that overruns the buffer
    /// or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let value = r.vec_u32("UpdateValue.value")?;
        r.finish("UpdateValue")?;
        Ok(Self { value })
    }
}

/// The structured input to a commitment (`draft-ietf-keytrans-protocol-04`
/// §10.6).
///
/// ```text
/// struct {
///   opaque opening[Nc];
///   opaque label<0..2^8-1>;
///   uint32 version;
///   UpdateValue update;
/// } CommitmentValue;
/// ```
///
/// `Nc` is the cipher-suite opening length. The experimental private suite
/// reuses [`crate::commitment`]'s 32-byte opening, so `opening` is expected to
/// be [`crate::commitment::COMMITMENT_OPENING_LEN`] bytes; the length is carried
/// by the value rather than re-encoded, since `opaque opening[Nc]` is a
/// fixed-width field with no in-band length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentValue {
    /// The commitment opening (blinding nonce), `Nc` bytes.
    pub opening: Vec<u8>,
    /// The label being committed. At most 255 bytes.
    pub label: Vec<u8>,
    /// The label's version number.
    pub version: u32,
    /// The value the commitment opens to.
    pub update: UpdateValue,
}

impl CommitmentValue {
    /// Serialize to canonical TLS-PL bytes. `opening` is written verbatim as the
    /// fixed-width `opaque opening[Nc]` field, so its length is the suite's
    /// `Nc`.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if `label` or the embedded value exceeds its
    /// vector bound.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.opening);
        write_vec_u8(&mut out, &self.label, "CommitmentValue.label")?;
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.update.encode()?);
        Ok(out)
    }

    /// Serialize the **bound content** of the commitment — every field except
    /// the fixed-width `opening` — as `label<0..2^8-1> || version || update`.
    ///
    /// The experimental private suite computes its commitment by feeding this
    /// content (with the suite opening as the blinding nonce) to
    /// [`crate::commitment`]'s SHA3-512 construction, which supplies the opening
    /// framing itself. Standard suites instead HMAC the full [`encode`] output;
    /// both bind exactly the same `(opening, label, version, update)` fields.
    ///
    /// [`encode`]: CommitmentValue::encode
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if `label` or the embedded value exceeds its
    /// vector bound.
    pub fn bound_content(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        write_vec_u8(&mut out, &self.label, "CommitmentValue.label")?;
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.update.encode()?);
        Ok(out)
    }

    /// Parse canonical TLS-PL bytes, given the suite's fixed opening length
    /// `nc`.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] on a length header that overruns the buffer
    /// or trailing bytes.
    pub fn decode(bytes: &[u8], nc: usize) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let opening = r.take(nc, "CommitmentValue.opening")?.to_vec();
        let label = r.vec_u8("CommitmentValue.label")?;
        let version = r.u32("CommitmentValue.version")?;
        // UpdateValue is the remaining bytes; re-validate it through its own
        // strict decoder rather than trusting the tail.
        let update_bytes = &r.bytes[r.offset..];
        let update = UpdateValue::decode(update_bytes)?;
        Ok(Self {
            opening,
            label,
            version,
            update,
        })
    }
}

/// A log-tree leaf (`draft-ietf-keytrans-protocol-04` §10.8): the timestamp at
/// which the leaf was created together with the prefix-tree root at that
/// version.
///
/// ```text
/// struct {
///   uint64 timestamp;
///   opaque prefix_tree[Hash.Nh];
/// } LogEntry;
/// ```
///
/// `timestamp` is milliseconds since the Unix epoch; `prefix_tree` is exactly
/// [`NH`] bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    /// Creation time, in milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// The prefix-tree root after this entry's modifications, `Hash.Nh` bytes.
    pub prefix_tree: [u8; NH],
}

impl LogEntry {
    /// Serialize to canonical TLS-PL bytes (fixed length: `8 + NH`).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + NH);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.prefix_tree);
        out
    }

    /// Parse canonical TLS-PL bytes.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if the input is not exactly `8 + NH` bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let timestamp = r.u64("LogEntry.timestamp")?;
        let prefix_tree: [u8; NH] = r
            .take(NH, "LogEntry.prefix_tree")?
            .try_into()
            .expect("take returned NH bytes");
        r.finish("LogEntry")?;
        Ok(Self {
            timestamp,
            prefix_tree,
        })
    }
}

// ===========================================================================
// Slice 9d proof wire structs (§11.1 / §11.2) — experimental, MOVABLE.
// ===========================================================================

use super::prefix_tree::{PrefixLeaf, PrefixProof, PrefixSearchResultType, SEARCH_KEY_LEN};
use crate::commitment::{COMMITMENT_LEN, Commitment};

/// `PrefixSearchResultType` (§11.2) wire codes.
const PREFIX_RESULT_INCLUSION: u8 = 1;
const PREFIX_RESULT_NON_INCLUSION_LEAF: u8 = 2;
const PREFIX_RESULT_NON_INCLUSION_PARENT: u8 = 3;

/// Encode a left-to-right list of `Hash.Nh`-byte node values as the §11.1 /
/// §11.2 `HashValue elements<0..2^16-1>` field (a 2-byte byte-length header
/// followed by the concatenated 32-byte hashes).
///
/// # Errors
/// [`Error::MalformedKeytrans`] if the encoded byte length exceeds the
/// `<0..2^16-1>` vector bound.
pub fn encode_hash_vector(hashes: &[[u8; NH]]) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(hashes.len() * NH);
    for h in hashes {
        body.extend_from_slice(h);
    }
    let mut out = Vec::with_capacity(2 + body.len());
    write_vec_u16(&mut out, &body, "HashValue elements")?;
    Ok(out)
}

/// Decode a §11.1 / §11.2 `HashValue elements<0..2^16-1>` field into a list of
/// `Hash.Nh`-byte node values.
///
/// # Errors
/// [`Error::MalformedKeytrans`] if the length header overruns the buffer, the
/// body is not a whole number of [`NH`]-byte hashes, or there are trailing
/// bytes.
pub fn decode_hash_vector(bytes: &[u8]) -> Result<Vec<[u8; NH]>> {
    let mut r = Reader::new(bytes);
    let hashes = read_hash_vector(&mut r, "HashValue elements")?;
    r.finish("HashValue elements")?;
    Ok(hashes)
}

/// Read a `HashValue elements<0..2^16-1>` field from `r`.
fn read_hash_vector(r: &mut Reader<'_>, what: &str) -> Result<Vec<[u8; NH]>> {
    let body = r.vec_u16(what)?;
    if body.len() % NH != 0 {
        return Err(Error::MalformedKeytrans(format!(
            "{what}: {} bytes is not a multiple of the {NH}-byte hash size",
            body.len()
        )));
    }
    Ok(body
        .chunks_exact(NH)
        .map(|c| {
            let mut h = [0u8; NH];
            h.copy_from_slice(c);
            h
        })
        .collect())
}

/// The KEYTRANS log-tree batch inclusion/consistency proof (§11.1
/// `InclusionProof`): the left-to-right `elements` node values.
///
/// ```text
/// struct {
///   HashValue elements<0..2^16-1>;
/// } InclusionProof;
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    /// The provided balanced-subtree head values, in left-to-right order.
    pub elements: Vec<[u8; NH]>,
}

impl InclusionProof {
    /// Serialize to canonical TLS-PL bytes.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if the encoded `elements` exceed the
    /// `<0..2^16-1>` bound.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_hash_vector(&self.elements)
    }

    /// Parse canonical TLS-PL bytes.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] on a malformed length header or trailing
    /// bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            elements: decode_hash_vector(bytes)?,
        })
    }
}

impl PrefixProof {
    /// Serialize a single-key prefix-tree proof to canonical TLS-PL bytes
    /// (§11.2 `PrefixProof`, with a one-element `results` array).
    ///
    /// The experimental private suite carries the full 64-byte
    /// [`crate::commitment`] in a `nonInclusionLeaf` leaf rather than the spec's
    /// 32-byte `Hash.Nh` commitment — a documented, version-tagged deviation.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] if the result/copath sizes exceed their
    /// vector bounds.
    pub fn encode(&self) -> Result<Vec<u8>> {
        // results<0..2^8-1>: one PrefixSearchResult.
        let mut result = Vec::new();
        match self.result_type {
            PrefixSearchResultType::Inclusion => result.push(PREFIX_RESULT_INCLUSION),
            PrefixSearchResultType::NonInclusionParent => {
                result.push(PREFIX_RESULT_NON_INCLUSION_PARENT);
            }
            PrefixSearchResultType::NonInclusionLeaf => {
                result.push(PREFIX_RESULT_NON_INCLUSION_LEAF);
                let leaf = self.leaf.as_ref().ok_or_else(|| {
                    Error::MalformedKeytrans("nonInclusionLeaf proof is missing its leaf".into())
                })?;
                result.extend_from_slice(&leaf.vrf_output);
                result.extend_from_slice(leaf.commitment.as_bytes());
            }
        }
        result.push(self.depth);

        let mut out = Vec::new();
        write_vec_u8(&mut out, &result, "PrefixProof.results")?;
        out.extend_from_slice(&encode_hash_vector(&self.copath)?);
        Ok(out)
    }

    /// Parse a single-key prefix-tree proof from canonical TLS-PL bytes.
    ///
    /// # Errors
    /// [`Error::MalformedKeytrans`] on an unknown result type, a `results` array
    /// that is not exactly one entry, a malformed length header, or trailing
    /// bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let results = r.vec_u8("PrefixProof.results")?;
        let mut rr = Reader::new(&results);
        let result_type_byte = rr.u8("PrefixSearchResult.result_type")?;
        let (result_type, leaf) = match result_type_byte {
            PREFIX_RESULT_INCLUSION => (PrefixSearchResultType::Inclusion, None),
            PREFIX_RESULT_NON_INCLUSION_PARENT => {
                (PrefixSearchResultType::NonInclusionParent, None)
            }
            PREFIX_RESULT_NON_INCLUSION_LEAF => {
                let vrf_output: [u8; SEARCH_KEY_LEN] = rr
                    .take(SEARCH_KEY_LEN, "PrefixLeaf.vrf_output")?
                    .try_into()
                    .expect("take returned SEARCH_KEY_LEN bytes");
                let commitment: [u8; COMMITMENT_LEN] = rr
                    .take(COMMITMENT_LEN, "PrefixLeaf.commitment")?
                    .try_into()
                    .expect("take returned COMMITMENT_LEN bytes");
                (
                    PrefixSearchResultType::NonInclusionLeaf,
                    Some(PrefixLeaf {
                        vrf_output,
                        commitment: Commitment::from_bytes(commitment),
                    }),
                )
            }
            other => {
                return Err(Error::MalformedKeytrans(format!(
                    "unknown PrefixSearchResultType {other}"
                )));
            }
        };
        let depth = rr.u8("PrefixSearchResult.depth")?;
        rr.finish("PrefixProof.results (expected exactly one result)")?;

        let copath = read_hash_vector(&mut r, "PrefixProof.elements")?;
        r.finish("PrefixProof")?;
        Ok(Self {
            result_type,
            leaf,
            depth,
            copath,
        })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn vrf_input_round_trips() {
        let input = VrfInput {
            label: b"alice@example.com".to_vec(),
            version: 7,
        };
        let bytes = input.encode().unwrap();
        assert_eq!(VrfInput::decode(&bytes).unwrap(), input);
    }

    #[test]
    fn vrf_input_draft_example_bytes() {
        // label = "ab" (0x61 0x62), version = 1.
        // <0..2^8-1>: 0x02 || "ab" || uint32(1).
        let input = VrfInput {
            label: b"ab".to_vec(),
            version: 1,
        };
        assert_eq!(
            input.encode().unwrap(),
            vec![0x02, b'a', b'b', 0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn vrf_input_rejects_oversize_label() {
        let input = VrfInput {
            label: vec![0u8; 256],
            version: 0,
        };
        assert!(matches!(input.encode(), Err(Error::MalformedKeytrans(_))));
    }

    #[test]
    fn update_value_round_trips() {
        let uv = UpdateValue {
            value: b"the-key-history-head".to_vec(),
        };
        let bytes = uv.encode().unwrap();
        assert_eq!(UpdateValue::decode(&bytes).unwrap(), uv);
    }

    #[test]
    fn update_value_draft_example_bytes() {
        // value = "hi" => uint32(2) || "hi".
        let uv = UpdateValue {
            value: b"hi".to_vec(),
        };
        assert_eq!(
            uv.encode().unwrap(),
            vec![0x00, 0x00, 0x00, 0x02, b'h', b'i']
        );
    }

    #[test]
    fn commitment_value_round_trips() {
        let cv = CommitmentValue {
            opening: vec![0xAB; 32],
            label: b"bob".to_vec(),
            version: 42,
            update: UpdateValue {
                value: b"v".to_vec(),
            },
        };
        let bytes = cv.encode().unwrap();
        assert_eq!(CommitmentValue::decode(&bytes, 32).unwrap(), cv);
    }

    #[test]
    fn commitment_value_draft_example_bytes() {
        // opening = 0x00..(4 bytes for the example), label = "a", version = 3,
        // update.value = "" => 0x00000000.
        let cv = CommitmentValue {
            opening: vec![0x11, 0x22, 0x33, 0x44],
            label: b"a".to_vec(),
            version: 3,
            update: UpdateValue { value: Vec::new() },
        };
        assert_eq!(
            cv.encode().unwrap(),
            vec![
                0x11, 0x22, 0x33, 0x44, // opening[4]
                0x01, b'a', // label<0..2^8-1>
                0x00, 0x00, 0x00, 0x03, // version
                0x00, 0x00, 0x00, 0x00, // update.value<0..2^32-1> (empty)
            ]
        );
    }

    #[test]
    fn log_entry_round_trips() {
        let entry = LogEntry {
            timestamp: 1_700_000_000_000,
            prefix_tree: [0x5A; NH],
        };
        let bytes = entry.encode();
        assert_eq!(bytes.len(), 8 + NH);
        assert_eq!(LogEntry::decode(&bytes).unwrap(), entry);
    }

    #[test]
    fn log_entry_draft_example_bytes() {
        // timestamp = 1 (uint64 BE), prefix_tree = 32 * 0x00.
        let entry = LogEntry {
            timestamp: 1,
            prefix_tree: [0u8; NH],
        };
        let mut expected = vec![0, 0, 0, 0, 0, 0, 0, 1];
        expected.extend_from_slice(&[0u8; NH]);
        assert_eq!(entry.encode(), expected);
    }

    #[test]
    fn decoders_reject_truncated_and_trailing() {
        assert!(VrfInput::decode(&[0x05, b'a']).is_err()); // length header overruns
        assert!(UpdateValue::decode(&[0x00, 0x00, 0x00]).is_err()); // short header
        assert!(LogEntry::decode(&[0u8; 8 + NH - 1]).is_err()); // too short
        let mut trailing = LogEntry {
            timestamp: 0,
            prefix_tree: [0u8; NH],
        }
        .encode();
        trailing.push(0xFF);
        assert!(LogEntry::decode(&trailing).is_err()); // trailing byte
    }

    #[test]
    fn inclusion_proof_round_trips() {
        let proof = InclusionProof {
            elements: vec![[0x11; NH], [0x22; NH], [0x33; NH]],
        };
        let bytes = proof.encode().unwrap();
        // 2-byte length header = 3 * 32 = 96 bytes.
        assert_eq!(&bytes[..2], &[0x00, 0x60]);
        assert_eq!(InclusionProof::decode(&bytes).unwrap(), proof);
    }

    #[test]
    fn inclusion_proof_empty_and_misaligned() {
        let empty = InclusionProof { elements: vec![] };
        assert_eq!(empty.encode().unwrap(), vec![0x00, 0x00]);
        assert_eq!(InclusionProof::decode(&[0x00, 0x00]).unwrap(), empty);
        // A body whose length is not a multiple of NH is rejected.
        assert!(InclusionProof::decode(&[0x00, 0x05, 1, 2, 3, 4, 5]).is_err());
    }

    #[test]
    fn prefix_proof_round_trips_all_result_types() {
        use super::super::prefix_tree::{PrefixLeaf, PrefixProof, PrefixSearchResultType};

        let inclusion = PrefixProof {
            result_type: PrefixSearchResultType::Inclusion,
            leaf: None,
            depth: 2,
            copath: vec![[0xAA; NH], [0xBB; NH]],
        };
        let bytes = inclusion.encode().unwrap();
        assert_eq!(PrefixProof::decode(&bytes).unwrap(), inclusion);

        let parent = PrefixProof {
            result_type: PrefixSearchResultType::NonInclusionParent,
            leaf: None,
            depth: 1,
            copath: vec![[0xCC; NH], [0xDD; NH]],
        };
        let bytes = parent.encode().unwrap();
        assert_eq!(PrefixProof::decode(&bytes).unwrap(), parent);

        let non_incl_leaf = PrefixProof {
            result_type: PrefixSearchResultType::NonInclusionLeaf,
            leaf: Some(PrefixLeaf {
                vrf_output: [0x5A; SEARCH_KEY_LEN],
                commitment: Commitment::from_bytes([0x6B; COMMITMENT_LEN]),
            }),
            depth: 3,
            copath: vec![[0x01; NH], [0x02; NH], [0x03; NH]],
        };
        let bytes = non_incl_leaf.encode().unwrap();
        assert_eq!(PrefixProof::decode(&bytes).unwrap(), non_incl_leaf);
    }

    #[test]
    fn prefix_proof_rejects_unknown_result_type_and_trailing() {
        use super::super::prefix_tree::{PrefixProof, PrefixSearchResultType};
        // results = [0xFF, depth=0]; unknown result type 0xFF.
        let bytes = vec![0x02, 0xFF, 0x00, 0x00, 0x00];
        assert!(PrefixProof::decode(&bytes).is_err());

        // Trailing byte after a well-formed inclusion proof is rejected.
        let p = PrefixProof {
            result_type: PrefixSearchResultType::Inclusion,
            leaf: None,
            depth: 0,
            copath: vec![],
        };
        let mut bytes = p.encode().unwrap();
        bytes.push(0xAB);
        assert!(PrefixProof::decode(&bytes).is_err());
    }
}
