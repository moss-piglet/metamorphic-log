//! KEYTRANS **binary ladders** (`draft-ietf-keytrans-protocol-04` §5 / Appendix
//! B) and **distinguished-entry selection** (§6.1).
//!
//! A *binary ladder* (§5) is a series of version lookups against a single log
//! entry's prefix tree that bounds the greatest version of a label present in
//! that entry. The base ladder walks powers-of-two-minus-one (`0, 1, 3, 7, …`)
//! until the first non-inclusion, then binary-searches between the last included
//! and the first excluded version, exactly pinning the greatest version. The
//! §5 worked example — greatest version `6` ⇒ lookups `[0, 1, 3, 7, 5, 6]` — is
//! reproduced by [`base_binary_ladder`].
//!
//! These functions are the **verbatim** Appendix B algorithms (their Python
//! source is mirrored line-for-line) and are pure: they return only the *list of
//! versions to look up*, never an inclusion/non-inclusion verdict — the verdict
//! is recomputed from the prefix-tree proofs in [`super::prefix_tree`]. The
//! caller (the §6–§8 search / monitor drivers) supplies the contextual bounds
//! (`left_inclusion`, `right_non_inclusion`, …) used to drop redundant lookups.
//!
//! [`select_distinguished`] implements the §6.1 *Reasonable Monitoring Window*
//! (RMW) recursion that marks the regularly-spaced, stable *distinguished* log
//! entries, expressed over the implicit binary search tree (§4.1 / Appendix A)
//! using the same robust half-open-range navigation as
//! [`super::verify_monotonic`].
//!
//! Everything here is experimental / version-tagged ([`super::KEYTRANS_EXP_04`])
//! and may move until `draft-ietf-keytrans-protocol` reaches Last Call.

use super::root_index;

/// The versions looked up to establish that `n` is the greatest version of a
/// label that exists (§5 / Appendix B `base_binary_ladder`).
///
/// Emits powers of two minus one (`0, 1, 3, 7, …`) until a value exceeds `n`,
/// then binary-searches between the last included and first excluded bound. The
/// §5 example `base_binary_ladder(6) == [0, 1, 3, 7, 5, 6]`.
#[must_use]
pub fn base_binary_ladder(n: u64) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();

    // Output powers of two minus one until reaching a value greater than n.
    loop {
        let value = (1u64 << out.len()) - 1;
        out.push(value);
        if value > n {
            break;
        }
    }

    // Binary search between the established lower and upper bounds.
    let mut lower_bound = out[out.len() - 2];
    let mut upper_bound = out[out.len() - 1];

    while lower_bound + 1 < upper_bound {
        let value = (lower_bound + upper_bound) / 2;
        out.push(value);
        if value <= n {
            lower_bound = value;
        } else {
            upper_bound = value;
        }
    }

    out
}

/// The versions looked up in a **fixed-version** search binary ladder (§7 /
/// Appendix B `fixed_version_binary_ladder`): target version `t`, with `n` the
/// greatest version present in the inspected prefix tree.
///
/// The ladder ends after the first lookup that resolves whether the greatest
/// version is `>=`, `==`, or `< t`, and drops any version already proven
/// included to the left (`left_inclusion`) or excluded to the right
/// (`right_non_inclusion`).
#[must_use]
pub fn fixed_version_binary_ladder(
    t: u64,
    n: u64,
    left_inclusion: &[u64],
    right_non_inclusion: &[u64],
) -> Vec<u64> {
    // (Inclusion for a version >= t) OR (non-inclusion for a version <= t).
    let would_end = |v: u64| (v <= n && v >= t) || (v > n && v <= t);
    let would_be_duplicate =
        |v: u64| left_inclusion.contains(&v) || right_non_inclusion.contains(&v);

    let out = base_binary_ladder(n);
    truncate_after_end(&out, would_end)
        .into_iter()
        .filter(|v| !would_be_duplicate(*v))
        .collect()
}

/// The versions looked up in a **monitoring** binary ladder (§8.1 / Appendix B
/// `monitor_binary_ladder`): monitored version `t`. Every lookup is `<= t` (an
/// honest log answers each with inclusion), dropping any already proven included
/// to the left (`left_inclusion`).
#[must_use]
pub fn monitor_binary_ladder(t: u64, left_inclusion: &[u64]) -> Vec<u64> {
    base_binary_ladder(t)
        .into_iter()
        .filter(|v| *v <= t && !left_inclusion.contains(v))
        .collect()
}

/// The versions looked up in a **greatest-version** search binary ladder (§6.2 /
/// Appendix B `greatest_version_binary_ladder`): globally greatest version `t`,
/// with `n` the greatest present in the inspected prefix tree.
///
/// `distinguished` selects the redundancy rule: a distinguished log entry drops
/// versions already looked up in the *same* entry (`same_entry`); otherwise it
/// drops versions proven included to the left (`left_inclusion`) or excluded to
/// the right (`right_non_inclusion`).
#[must_use]
pub fn greatest_version_binary_ladder(
    t: u64,
    n: u64,
    distinguished: bool,
    left_inclusion: &[u64],
    right_non_inclusion: &[u64],
    same_entry: &[u64],
) -> Vec<u64> {
    // Non-inclusion for a version <= t.
    let would_end = |v: u64| v > n && v <= t;
    let would_be_duplicate = |v: u64| {
        if distinguished {
            same_entry.contains(&v)
        } else {
            left_inclusion.contains(&v) || right_non_inclusion.contains(&v)
        }
    };

    let out = base_binary_ladder(t);
    truncate_after_end(&out, would_end)
        .into_iter()
        .filter(|v| !would_be_duplicate(*v))
        .collect()
}

/// Keep the ladder up to and including the first version satisfying `would_end`
/// (Appendix B's `end = next((i+1 ...), len(out))` then `out[:end]`).
fn truncate_after_end(out: &[u64], would_end: impl Fn(u64) -> bool) -> Vec<u64> {
    let end = out
        .iter()
        .position(|&v| would_end(v))
        .map_or(out.len(), |i| i + 1);
    out[..end].to_vec()
}

/// Select the **distinguished** log entries of an `n`-entry log under the
/// Reasonable Monitoring Window `rmw` (§6.1), returning their entry indices in
/// ascending order.
///
/// Distinguished entries are chosen by the §6.1 recursion over the implicit
/// binary search tree so that there is roughly one per RMW interval: starting at
/// the root with bounding timestamps `(0, rightmost)`, an entry is distinguished
/// iff its bounding interval is at least one RMW wide, and the recursion then
/// descends to both children with the node's own timestamp as the new inner
/// bound. The strict `< rmw` test (not `<=`) makes `rmw == 0` mark every entry,
/// per the §6.1 note.
///
/// The resulting set is *regularly spaced* and *stable*: an entry, once
/// distinguished, stays distinguished as the log grows.
///
/// An empty log has no distinguished entries.
#[must_use]
pub fn select_distinguished(timestamps: &[u64], rmw: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let n = timestamps.len() as u64;
    if n == 0 {
        return out;
    }
    let rightmost = timestamps[(n - 1) as usize];
    recurse_distinguished(timestamps, 0, n, 0, rightmost, rmw, &mut out);
    out.sort_unstable();
    out
}

/// The §6.1 recursion over the half-open entry range `[lo, hi)`, whose implicit
/// BST root is `lo + root_index(hi - lo)`. `left_ts` / `right_ts` are the
/// bounding timestamps passed down from the parent (timestamp 0 / rightmost at
/// the top level).
fn recurse_distinguished(
    timestamps: &[u64],
    lo: u64,
    hi: u64,
    left_ts: u64,
    right_ts: u64,
    rmw: u64,
    out: &mut Vec<u64>,
) {
    // Step 2: terminate unless the bounding interval is at least one RMW wide.
    if right_ts.saturating_sub(left_ts) < rmw {
        return;
    }
    let r = lo + root_index(hi - lo);
    out.push(r);
    let this_ts = timestamps[r as usize];

    // Step 3: left child subtree spans [lo, r).
    if r > lo {
        recurse_distinguished(timestamps, lo, r, left_ts, this_ts, rmw, out);
    }
    // Step 4: right child subtree spans [r + 1, hi).
    if r + 1 < hi {
        recurse_distinguished(timestamps, r + 1, hi, this_ts, right_ts, rmw, out);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn base_ladder_matches_section5_example() {
        // §5: greatest version 6 ⇒ lookups [0, 1, 3, 7, 5, 6].
        assert_eq!(base_binary_ladder(6), vec![0, 1, 3, 7, 5, 6]);
    }

    #[test]
    fn base_ladder_small_cases() {
        assert_eq!(base_binary_ladder(0), vec![0, 1]);
        assert_eq!(base_binary_ladder(1), vec![0, 1, 3, 2]);
        assert_eq!(base_binary_ladder(2), vec![0, 1, 3, 2]);
        // The terminating power-of-two-minus-one (> n) is always included.
        assert!(base_binary_ladder(10).contains(&15));
    }

    #[test]
    fn base_ladder_pins_n_uniquely() {
        // The ladder always contains n itself and a single value > n that
        // terminated the power-of-two phase, for a range of greatest versions.
        for n in 0u64..64 {
            let ladder = base_binary_ladder(n);
            assert!(ladder.contains(&n), "n = {n}");
            assert!(ladder.iter().any(|&v| v > n), "n = {n}");
        }
    }

    #[test]
    fn fixed_version_ladder_truncates_and_dedups() {
        // Target 6, greatest present 6: same shape as the base ladder, since
        // every lookup is needed to confirm equality (would_end first true at v=6).
        assert_eq!(
            fixed_version_binary_ladder(6, 6, &[], &[]),
            vec![0, 1, 3, 7, 5, 6]
        );
        // Dropping a version already proven included to the left.
        let l = fixed_version_binary_ladder(6, 6, &[3], &[]);
        assert!(!l.contains(&3));
        assert!(l.contains(&6));
        // Dropping a version already proven excluded to the right.
        let r = fixed_version_binary_ladder(6, 6, &[], &[7]);
        assert!(!r.contains(&7));
    }

    #[test]
    fn fixed_version_ladder_ends_early_when_greater_present() {
        // n (greatest present) = 10 > t = 2: ends at the first inclusion for a
        // version >= t.
        let l = fixed_version_binary_ladder(2, 10, &[], &[]);
        assert_eq!(*l.last().unwrap(), 3); // 0,1,3 — 3 is first v>=t with v<=n
    }

    #[test]
    fn monitor_ladder_only_keeps_versions_at_most_target() {
        let l = monitor_binary_ladder(6, &[]);
        assert!(l.iter().all(|&v| v <= 6));
        assert!(l.contains(&6));
        // Dedup against left inclusions.
        assert!(!monitor_binary_ladder(6, &[1, 3]).contains(&1));
    }

    #[test]
    fn greatest_version_ladder_distinguished_vs_frontier_dedup() {
        // Distinguished entry dedups against same_entry; frontier entry dedups
        // against left_inclusion / right_non_inclusion.
        let dist = greatest_version_binary_ladder(6, 6, true, &[1], &[7], &[3]);
        assert!(!dist.contains(&3)); // same_entry dropped
        assert!(dist.contains(&1)); // left_inclusion NOT dropped when distinguished

        let front = greatest_version_binary_ladder(6, 6, false, &[1], &[7], &[3]);
        assert!(!front.contains(&1)); // left_inclusion dropped
        assert!(!front.contains(&7)); // right_non_inclusion dropped
        assert!(front.contains(&3)); // same_entry NOT consulted when on frontier
    }

    #[test]
    fn distinguished_rmw_zero_marks_every_entry() {
        // §6.1 note: the strict `< rmw` test makes rmw == 0 mark every entry.
        let timestamps: Vec<u64> = (0..13).map(|i| i * 100).collect();
        let dist = select_distinguished(&timestamps, 0);
        assert_eq!(dist, (0..13).collect::<Vec<_>>());
    }

    #[test]
    fn distinguished_empty_and_single() {
        assert_eq!(select_distinguished(&[], 10), Vec::<u64>::new());
        // A single entry: bounding interval is [0, ts0]; distinguished iff wide.
        assert_eq!(select_distinguished(&[1000], 500), vec![0]);
        assert_eq!(select_distinguished(&[100], 5000), Vec::<u64>::new());
    }

    #[test]
    fn distinguished_are_regularly_spaced() {
        // Evenly-spaced timestamps, RMW = 4 intervals' worth: distinguished
        // entries should partition the log at ~RMW intervals.
        let timestamps: Vec<u64> = (0..16).map(|i| i * 10).collect();
        let rmw = 40;
        let dist = select_distinguished(&timestamps, rmw);
        assert!(!dist.is_empty());
        // The root (index root_index(16) = 15? no, 16 is power of two → 15) is
        // distinguished since [0, 150] spans >= rmw.
        assert!(dist.contains(&root_index(16)));
    }

    #[test]
    fn distinguished_are_stable_as_log_grows() {
        // Stability (§6.1): an entry distinguished in a smaller log stays
        // distinguished as the log grows. Compare prefixes of a growing log.
        let full: Vec<u64> = (0..32).map(|i| i * 10).collect();
        let rmw = 30;
        let dist_small = select_distinguished(&full[..16], rmw);
        let dist_large = select_distinguished(&full[..24], rmw);
        for d in &dist_small {
            assert!(
                dist_large.contains(d),
                "entry {d} lost distinguished status as log grew"
            );
        }
    }
}
