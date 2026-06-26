//! Throughput benchmark for the Slice-7 deterministic ingestion primitives.
//!
//! Run with `cargo bench --bench ingestion` (release profile). It is a
//! dependency-free `harness = false` binary (no criterion) — in keeping with
//! this crate's minimal dependency surface — that measures the *primitives in
//! isolation*: per-namespace sequencing, idempotent-append dedup keying, and
//! tile flush planning.
//!
//! ## Honest framing
//!
//! The numbers printed here are **not** an end-to-end ingest throughput claim.
//! The Tessera reference band (~5k–18k entries/sec, per EPIC #325) is an
//! *end-to-end* figure that includes a backpressured pipeline and an
//! object-storage/CDN backend — both out of scope for this OSS crate and owned
//! by the operator layer (mosskeys). What this benchmark shows is that the
//! deterministic primitives sit comfortably *above* that band, i.e. they are
//! designed not to be the bottleneck. The asserted floors below are deliberately
//! conservative (far under typical measured throughput) so CI catches only a
//! catastrophic regression, never flaking on a loaded shared runner.

use std::hint::black_box;
use std::time::Instant;

use metamorphic_log::ingest::Namespace;
use metamorphic_log::ingest::{DedupKey, Sequencer, plan_flush, tiles_to_flush};

const TESSERA_LOW: f64 = 5_000.0;

fn rate(label: &str, ops: u64, secs: f64, floor: f64) {
    let per_sec = ops as f64 / secs;
    let times_tessera = per_sec / TESSERA_LOW;
    println!(
        "{label:<28} {ops:>10} ops in {secs:>8.4}s = {per_sec:>14.0}/s  (~{times_tessera:>6.1}x Tessera-low)"
    );
    assert!(
        per_sec >= floor,
        "{label} throughput {per_sec:.0}/s fell below the conservative floor {floor:.0}/s"
    );
}

fn bench_sequencer() {
    let ns = Namespace::parse("bench").unwrap();
    let mut seq = Sequencer::new();
    let n: u64 = 5_000_000;
    let start = Instant::now();
    for _ in 0..n {
        black_box(seq.next(black_box(&ns)));
    }
    rate(
        "sequencer.next",
        n,
        start.elapsed().as_secs_f64(),
        200_000.0,
    );
}

fn bench_dedup() {
    let ns = Namespace::parse("bench").unwrap();
    // A representative key-history-sized payload (~200 bytes).
    let payload = vec![0xa5u8; 200];
    let n: u64 = 1_000_000;
    let start = Instant::now();
    for i in 0..n {
        let mut p = payload.clone();
        p[0] = i as u8;
        black_box(DedupKey::from_record(black_box(&ns), black_box(&p)));
    }
    rate(
        "dedup_key.from_record",
        n,
        start.elapsed().as_secs_f64(),
        50_000.0,
    );
}

fn bench_flush_planning() {
    // Plan the incremental flush for each 256-entry batch as the log grows to
    // ~1M entries: the per-batch work an operator does on every flush.
    let batches: u64 = 4_096;
    let batch = 256u64;
    let start = Instant::now();
    let mut size = 0u64;
    for _ in 0..batches {
        let new = size + batch;
        black_box(plan_flush(black_box(size), black_box(new)).unwrap());
        size = new;
    }
    rate(
        "plan_flush (256/batch)",
        batches * batch,
        start.elapsed().as_secs_f64(),
        50_000.0,
    );

    // Single full-tree flush geometry for a 1M-entry tree.
    let start = Instant::now();
    let reps: u64 = 1_000;
    for _ in 0..reps {
        black_box(tiles_to_flush(black_box(0), black_box(1_000_000)).unwrap());
    }
    let secs = start.elapsed().as_secs_f64();
    println!(
        "{:<28} {:>10} full-tree plans in {:>8.4}s = {:>14.0}/s",
        "tiles_to_flush(0,1M)",
        reps,
        secs,
        reps as f64 / secs
    );
}

fn main() {
    println!("metamorphic-log Slice-7 ingestion primitives — throughput");
    println!("(deterministic primitives only; NOT an end-to-end ingest claim)\n");
    bench_sequencer();
    bench_dedup();
    bench_flush_planning();
}
