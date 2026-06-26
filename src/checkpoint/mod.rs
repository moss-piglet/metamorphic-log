//! Checkpoints and signed notes (C2SP `checkpoint` / `signed-note`).
//!
//! Defines the signed tree-head ("checkpoint") format and `signed-note`
//! parsing, including multiple signature lines so external witnesses can
//! co-sign for anti-equivocation (`tlog-witness`). Checkpoints are designed for
//! external witness co-signing from day one, and additive **hybrid
//! post-quantum** checkpoint signatures come from
//! [`metamorphic_crypto`](crate)'s composite signature suite (#312).
//!
//! Skeleton only — checkpoint parsing/signing lands in later slices.
