//! Layer-1: RFC 6962 Merkle tree hashing.
//!
//! Implements the fixed tree-node hashing scheme — leaf hash `H(0x00 || leaf)`
//! and interior hash `H(0x01 || left || right)` — where `H` is the ecosystem
//! SHA-256 from [`metamorphic_crypto`](crate). This layer is **fixed and
//! audited** for witness recomputation and is never affected by per-namespace
//! suite/level choice (#290 / #299 / #324).
//!
//! Skeleton only — hashing lands in Slice 1 (#327).
