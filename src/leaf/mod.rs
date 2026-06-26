//! Layer-0: canonical leaf encoding.
//!
//! Defines the byte-exact, length-prefixed canonical serialization of log
//! leaves (e.g. the `mosslet/key-history/v1` label family). The byte layout and
//! length-prefix discipline (`u32`-be length prefixes, `u64`-be integers, all
//! big-endian) are a **fixed, audited Layer-1 invariant**: customer suite/level
//! choice never touches it, so independent witnesses can recompute it. See
//! board tasks #299 and #290.
//!
//! Skeleton only — canonical encoding lands in Slice 1 (#327).
