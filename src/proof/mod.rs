//! Inclusion and consistency proof verification (RFC 6962 / RFC 9162).
//!
//! This is the heart of Slice 1 (#327): a *real* verifier that recomputes
//! Merkle roots from proofs and compares them against the supplied root. The
//! proof MATH is implemented directly here (a verifier that delegates
//! verification is not a verifier, per #316/#299) using the standard,
//! well-tested decomposition from RFC 9162 §2.1.3.2 (inclusion) and §2.1.4.2
//! (consistency). All node hashing goes through the fixed RFC 6962 scheme in
//! [`crate::merkle`].
//!
//! - [`verify_inclusion`] proves a leaf is committed at a given index in a tree
//!   of a given size whose head is `root`.
//! - [`verify_consistency`] proves a tree of `size2` (root `root2`) is an
//!   append-only extension of a tree of `size1` (root `root1`) — the
//!   anti-equivocation / tamper-evidence property.
//!
//! The lower-level [`root_from_inclusion_proof`] and
//! [`root_from_consistency_proof`] return the recomputed root(s) for callers
//! that want to compare against a signed checkpoint themselves.

use crate::error::{Error, Result};
use crate::merkle::{HASH_LEN, Hash, hash_children};

/// Number of trailing-zero bits in `x`; `64` if `x == 0`.
#[inline]
fn trailing_zeros(x: u64) -> u32 {
    x.trailing_zeros()
}

/// Bit-length of `x` (position of the highest set bit); `0` if `x == 0`.
#[inline]
fn bit_len(x: u64) -> u32 {
    u64::BITS - x.leading_zeros()
}

/// Count of set bits in `x`.
#[inline]
fn ones_count(x: u64) -> u32 {
    x.count_ones()
}

/// Validate that every hash in `proof` (and the implied node size) is exactly
/// [`HASH_LEN`] bytes, returning a typed error otherwise.
fn check_hash_len(bytes: &[u8]) -> Result<Hash> {
    let arr: Hash = bytes.try_into().map_err(|_| Error::InvalidHashLength {
        got: bytes.len(),
        want: HASH_LEN,
    })?;
    Ok(arr)
}

/// `innerProofSize` from RFC 9162: the number of proof hashes below the point
/// where the paths to leaf `index` and leaf `size-1` diverge.
#[inline]
fn inner_proof_size(index: u64, size: u64) -> u32 {
    bit_len(index ^ (size - 1))
}

/// `decompInclProof`: split an inclusion proof into its `(inner, border)`
/// component lengths. Their sum is the required proof length.
#[inline]
fn decomp_incl_proof(index: u64, size: u64) -> (u32, u32) {
    let inner = inner_proof_size(index, size);
    let border = ones_count(index >> inner);
    (inner, border)
}

/// `chainInner`: fold the lower `inner` proof hashes into `seed`, choosing left
/// or right placement by the bits of `index`.
fn chain_inner(seed: Hash, proof: &[Hash], index: u64) -> Hash {
    let mut acc = seed;
    for (i, h) in proof.iter().enumerate() {
        acc = if (index >> i) & 1 == 0 {
            hash_children(&acc, h)
        } else {
            hash_children(h, &acc)
        };
    }
    acc
}

/// `chainInnerRight`: like [`chain_inner`] but only folds in hashes that lie to
/// the *left* of the path (used to recompute the earlier subtree root in a
/// consistency proof).
fn chain_inner_right(seed: Hash, proof: &[Hash], index: u64) -> Hash {
    let mut acc = seed;
    for (i, h) in proof.iter().enumerate() {
        if (index >> i) & 1 == 1 {
            acc = hash_children(h, &acc);
        }
    }
    acc
}

/// `chainBorderRight`: fold the upper (border) proof hashes, all of which are
/// left-side subtree hashes.
fn chain_border_right(seed: Hash, proof: &[Hash]) -> Hash {
    let mut acc = seed;
    for h in proof {
        acc = hash_children(h, &acc);
    }
    acc
}

/// Recompute the Merkle root implied by an inclusion proof.
///
/// Returns the root that the `(leaf_hash, index, size, proof)` tuple recomputes
/// to. Requires `0 <= index < size` and a proof of the exact RFC-mandated
/// length; otherwise returns a typed [`Error`].
///
/// This is the building block of [`verify_inclusion`]; use it directly when you
/// want to compare the recomputed root against a signed checkpoint yourself.
pub fn root_from_inclusion_proof(
    index: u64,
    size: u64,
    leaf_hash: &[u8],
    proof: &[Vec<u8>],
) -> Result<Hash> {
    if index >= size {
        return Err(Error::IndexBeyondSize { index, size });
    }
    let leaf = check_hash_len(leaf_hash)?;

    let (inner, border) = decomp_incl_proof(index, size);
    let want = (inner + border) as usize;
    if proof.len() != want {
        return Err(Error::WrongProofSize {
            got: proof.len(),
            want,
        });
    }

    let nodes: Vec<Hash> = proof
        .iter()
        .map(|h| check_hash_len(h))
        .collect::<Result<_>>()?;

    let (inner_nodes, border_nodes) = nodes.split_at(inner as usize);
    let res = chain_inner(leaf, inner_nodes, index);
    Ok(chain_border_right(res, border_nodes))
}

/// Verify an RFC 6962 / RFC 9162 inclusion proof.
///
/// Recomputes the root from `(leaf_hash, index, size, proof)` and checks it
/// against `root`. On success the log has proven that `leaf_hash` is committed
/// at `index` in the tree of `size` leaves whose head is `root`.
///
/// # Errors
/// - [`Error::IndexBeyondSize`] if `index >= size`.
/// - [`Error::InvalidHashLength`] if any hash is not 32 bytes.
/// - [`Error::WrongProofSize`] if the proof length is wrong for `(index, size)`.
/// - [`Error::RootMismatch`] if the recomputed root differs from `root`.
pub fn verify_inclusion(
    index: u64,
    size: u64,
    leaf_hash: &[u8],
    proof: &[Vec<u8>],
    root: &[u8],
) -> Result<()> {
    let expected = check_hash_len(root)?;
    let calc = root_from_inclusion_proof(index, size, leaf_hash, proof)?;
    if calc == expected {
        Ok(())
    } else {
        Err(Error::RootMismatch)
    }
}

/// Recompute the newer root (`root2`) implied by a consistency proof, after
/// verifying the proof is internally consistent with `root1`.
///
/// Returns the recomputed `size2` root. Requires `0 < size1 <= size2`.
///
/// # Errors
/// - [`Error::SizeRegression`] if `size2 < size1`.
/// - [`Error::EmptyTreeConsistency`] if `size1 == 0`.
/// - [`Error::NonEmptyEqualSizeProof`] if `size1 == size2` but the proof is
///   non-empty.
/// - [`Error::WrongProofSize`] / [`Error::InvalidHashLength`] for malformed
///   proofs.
/// - [`Error::RootMismatch`] if the proof does not reproduce `root1`.
pub fn root_from_consistency_proof(
    size1: u64,
    size2: u64,
    proof: &[Vec<u8>],
    root1: &[u8],
) -> Result<Hash> {
    if size2 < size1 {
        return Err(Error::SizeRegression { size1, size2 });
    }
    if size1 == 0 {
        return Err(Error::EmptyTreeConsistency);
    }
    let root1 = check_hash_len(root1)?;
    if size1 == size2 {
        if !proof.is_empty() {
            return Err(Error::NonEmptyEqualSizeProof);
        }
        return Ok(root1);
    }
    // size1 < size2 from here, so a non-empty proof is required.
    if proof.is_empty() {
        return Err(Error::WrongProofSize { got: 0, want: 1 });
    }

    let (inner_full, border) = decomp_incl_proof(size1 - 1, size2);
    let shift = trailing_zeros(size1);
    let inner = inner_full - shift; // shift < inner_full since size1 < size2.

    // The proof includes the root of the sub-tree of size 2^shift, unless
    // size1 *is* that 2^shift, in which case root1 itself is that seed.
    let (seed, start): (Hash, usize) = if size1 == (1u64 << shift) {
        (root1, 0)
    } else {
        (check_hash_len(&proof[0])?, 1)
    };

    let want = start + (inner + border) as usize;
    if proof.len() != want {
        return Err(Error::WrongProofSize {
            got: proof.len(),
            want,
        });
    }

    let nodes: Vec<Hash> = proof[start..]
        .iter()
        .map(|h| check_hash_len(h))
        .collect::<Result<_>>()?;
    let (inner_nodes, border_nodes) = nodes.split_at(inner as usize);

    // Chaining starts at level `shift`.
    let mask = (size1 - 1) >> shift;

    // Verify the earlier root reproduces root1.
    let hash1 = chain_inner_right(seed, inner_nodes, mask);
    let hash1 = chain_border_right(hash1, border_nodes);
    if hash1 != root1 {
        return Err(Error::RootMismatch);
    }

    // Recompute the newer root.
    let hash2 = chain_inner(seed, inner_nodes, mask);
    Ok(chain_border_right(hash2, border_nodes))
}

/// Verify an RFC 6962 / RFC 9162 consistency proof.
///
/// Proves that the tree of `size2` (head `root2`) is an append-only extension
/// of the tree of `size1` (head `root1`): no earlier entry was modified,
/// reordered, or removed. This is the anti-equivocation property a monitor
/// walks across checkpoints.
///
/// # Errors
/// Same conditions as [`root_from_consistency_proof`], plus
/// [`Error::RootMismatch`] if the recomputed newer root differs from `root2`.
pub fn verify_consistency(
    size1: u64,
    size2: u64,
    proof: &[Vec<u8>],
    root1: &[u8],
    root2: &[u8],
) -> Result<()> {
    let expected2 = check_hash_len(root2)?;
    let calc2 = root_from_consistency_proof(size1, size2, proof, root1)?;
    if calc2 == expected2 {
        Ok(())
    } else {
        Err(Error::RootMismatch)
    }
}
