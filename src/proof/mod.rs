//! Inclusion and consistency proofs (RFC 6962 / RFC 9162).
//!
//! Defines the proof structures and verification routines for Merkle inclusion
//! proofs (a leaf is in the tree at a given size) and consistency proofs (an
//! older tree head is a prefix of a newer one). The proof protocol is a fixed,
//! audited invariant shared with external witnesses (#299 / #290).
//!
//! Skeleton only — proof verification lands in Slice 1 (#327).
