// SPDX-License-Identifier: MIT

//! match — the irreducible algorithm this module exists to implement: THE
//! FABLE CORE. Everything else in `pping` (the bounded `TsTable` in
//! `table.zig`, the TCP Timestamps option parser in `parse.zig`, the
//! `Estimator` shell in `root.zig`) is mechanical plumbing built and fully
//! tested around this ONE seam. **Status: implemented** — `matchEcho` is no
//! longer a stub; `gate.fable_core_implemented` is `true` (see `gate.zig`),
//! so every test that reaches it runs for real and reports PASS, not SKIP.
//!
//! **Why this is the hard part, and what a naive implementation gets
//! wrong:** Pollere's pping observes RTT for free from a TCP flow's own
//! self-clocking, by matching each TSecr echo back to the TSval that
//! produced it (RFC 7323 §3.2 — every segment with the Timestamps option
//! carries BOTH a TSval it is asserting now and a TSecr echoing the peer's
//! most recently valid TSval). The naive version — "remember every TSval you
//! see, and whenever a TSecr matches one, report the delta" — is wrong in
//! two ways that matter on a real flow:
//!   1. **Duplicate/delayed ACKs re-echo the same TSecr.** TCP does not
//!      advance which TSval it echoes just because more segments arrive
//!      without new data to acknowledge — a delayed ACK, a duplicate ACK
//!      from loss/reordering, or a keepalive can all carry the SAME TSecr
//!      value more than once. If each one were allowed to produce a fresh
//!      sample against a still-present stored TSval, later — inflated —
//!      duplicates would masquerade as fresh (and wrong) RTT measurements.
//!      The fix is the **first-echo-only rule**: the FIRST TSecr that
//!      matches a stored TSval consumes it (deletes it from the table); any
//!      later segment carrying the same TSecr value finds nothing there and
//!      correctly produces no sample.
//!   2. **Unbounded memory.** A flow that runs for hours, or one direction
//!      of which stalls mid-stream (so its TSvals never get echoed), must
//!      not accumulate state forever. Bounding requires both a capacity
//!      ceiling (this module's `Config.capacity`, enforced per `TsTable`,
//!      see `table.zig`) and a time-based ceiling (`Config.max_age` — an
//!      entry nobody echoes within a few worst-case RTTs is never coming
//!      back and should be forgotten), and `matchEcho` is the one place
//!      that must apply both without also silently starving legitimate
//!      long-lived flows.
//!
//! Matching is **exact-value on TSval** (an integer equality check, not a
//! range/closest-match heuristic), which is what makes this scheme agnostic
//! to each host's TSval clock rate (Linux, BSD, Windows all pick their own
//! tick rate per RFC 7323 §5.3) and to TSval wraparound — an equality check
//! never needs to reason about which of two values is "ahead" the way a
//! subtraction-based comparison would.

const std = @import("std");
const root = @import("root.zig");
const table_mod = @import("table.zig");
const TsTable = table_mod.TsTable;

/// THE FABLE CORE.
///
/// Called once per `Estimator.observe(obs)` (see `root.zig`), already
/// pointed at the correct pair of tables for `obs.dir`:
///   - `same_dir`: the bounded TSval table for packets flowing the SAME way
///     as this observation (`obs.dir`) — the table `obs.tsval` may need to
///     be INSERTED into (the "insert side").
///   - `opp_dir`: the bounded TSval table for the OPPOSITE direction — the
///     table `obs.tsecr` must be MATCHED against (the "echo side"). Always a
///     distinct `TsTable` instance from `same_dir` (a flow's two directions
///     never share storage — see `Estimator.observe`), so there is no
///     self-matching case to special-case here.
///   - `cfg`: `Config.capacity` (both tables were allocated at exactly this
///     size — see `TsTable.init` in `root.zig`'s `Estimator.init`) and
///     `Config.max_age`, the aging cutoff.
///   - `obs`: the parsed observation — `obs.dir`, `obs.tsval`, `obs.tsecr`,
///     and `obs.now` (a caller-supplied, monotonically non-decreasing clock
///     reading in whatever unit `Config.max_age` is also expressed in;
///     `matchEcho` must not assume any particular unit or read a wall clock
///     itself — see `TsTable.evictOlderThan`'s saturating-age note for why
///     even a caller that violates monotonicity must not crash).
///
/// **Required behavior, in order — this is the full spec, not a hint:**
///
///  1. **Echo match (opposite-direction table).** Look up `obs.tsecr` in
///     `opp_dir` via `TsTable.indexOf`/`get`. If found, this observation
///     completes a genuine round trip: the sample's `rtt` is
///     `obs.now - entry.first_seen` (the time elapsed since THIS side first
///     saw that TSval go out, per `Estimator`'s bookkeeping when it was
///     inserted — see step 3 of a PRIOR call). Exact-value match only — see
///     the module doc for why. `obs.tsecr == 0` is not special-cased: it is
///     simply looked up like any other value, and only matches if `0` was
///     genuinely a stored TSval (extremely unlikely on a live flow, but
///     correctness must not special-case it away).
///  2. **First-echo consume.** The MOMENT step 1 finds a match, the matched
///     entry MUST be removed from `opp_dir` (`TsTable.removeAt`) before this
///     call returns — this is the first-echo-only rule from the module doc:
///     a later observation carrying the identical `tsecr` value (a delayed
///     or duplicate ACK re-echoing the same TSval) must find NOTHING there
///     and correctly produce no second sample. This is the single
///     highest-value correctness property this function exists to
///     guarantee — get it wrong and every duplicate/delayed ACK inflates
///     the sample stream with spurious extra RTTs.
///  3. **No match.** If step 1 finds nothing (aged out already, evicted for
///     capacity, never sent in that direction, or this is early in the
///     flow before any TSval has round-tripped), this is NOT an error —
///     most segments on a real flow are pure data or pure ACKs that do not
///     complete a probe. Proceed to step 4 regardless; return `null` for
///     the sample half of this call's result.
///  4. **Insert (same-direction table), first-seen only.** Check whether
///     `same_dir` already has a live entry for `obs.tsval`
///     (`TsTable.indexOf`). If NOT, this is the first time this TSval has
///     been seen going out in this direction — insert `(obs.tsval,
///     obs.now)`. If an entry ALREADY exists (this segment is a
///     retransmission, or otherwise replays a TSval TCP has already sent —
///     TCP does not advance TSval on retransmit), do **not** overwrite
///     it: the FIRST time a TSval was sent is what an eventual echo's RTT
///     must be measured against. Overwriting on a later resend would
///     silently redefine "first echo" as "most recent echo" and corrupt
///     the measurement for every flow with retransmits — exactly the kind
///     of subtle bug this module's doc / KAT corpus (`kat.zig`) exists to
///     catch.
///  5. **Bounded eviction, applied to BOTH tables, in this order:**
///       a. **Aging first.** Before considering whether there is room for
///          step 4's insert, sweep `same_dir` (`TsTable.evictOlderThan(
///          obs.now, cfg.max_age)`) — and, since it costs nothing extra and
///          keeps `opp_dir` from silently growing stale entries forever on
///          a half-duplex-bursty flow, sweep `opp_dir` the same way too.
///          Aging is unconditional (run it on every call, not just when a
///          table happens to be full) so memory is bounded over TIME, not
///          just over count.
///       b. **Capacity eviction, only if still needed.** If, after aging,
///          `same_dir` is still at `cfg.capacity` AND step 4 determined an
///          insert is needed (no existing entry for `obs.tsval`), make room
///          by evicting the single entry with the smallest `first_seen`
///          (`TsTable.oldestIndex` + `removeAt`) — i.e. the entry that has
///          been waiting longest for an echo that has not come. This is a
///          bounded FIFO-ish policy: the table's allocation NEVER grows
///          (`TsTable.insert` itself refuses to grow — see `table.zig`),
///          and the newest observation is never the one silently dropped.
///       c. **Why aging must run before capacity-eviction is decided:** an
///          entry past `max_age` is always a worse thing to keep than an
///          entry still within its window, even if the still-valid entry
///          happens to have a numerically smaller `first_seen` within that
///          window (e.g. right after a burst) — so age-based eviction must
///          have already run and shrunk the table before "is capacity
///          eviction even still necessary" is evaluated. Skipping step 5a
///          (or reordering it after 5b) can evict a still-useful in-flight
///          entry to make room that aging alone would have freed anyway.
///  6. **No double-count.** Steps 1–2 (match/consume) touch `opp_dir`; steps
///     4–5 (insert/evict) touch `same_dir` (plus 5a's incidental sweep of
///     `opp_dir`). These are logically independent — a single call MAY both
///     consume a match from `opp_dir` AND insert a fresh entry into
///     `same_dir` (an ordinary data segment that happens to also complete a
///     round trip), but the function returns exactly one `?RttSample`:
///     step 4's insert never itself produces a sample, only step 1's match
///     does.
///
/// Returns the `RttSample` from step 1 if a match was found (and consumed
/// per step 2), or `null` otherwise. Steps 3–5 always run regardless of
/// which branch of 1–2 was taken.
pub fn matchEcho(
    same_dir: *TsTable,
    opp_dir: *TsTable,
    cfg: root.Config,
    obs: root.Observation,
) ?root.RttSample {
    // Step 5a: unconditional aging sweep of BOTH tables, before anything
    // else. Running it before the echo lookup (not merely before the
    // capacity decision) is what makes "aged out already" in step 3 true
    // within a single call: an entry past `max_age` must be gone by the
    // time step 1 looks for it, so a long-stale TSval can never produce a
    // (huge, meaningless) RTT sample. This also keeps memory bounded over
    // TIME on every call, not just when a table happens to be full.
    _ = same_dir.evictOlderThan(obs.now, cfg.max_age);
    _ = opp_dir.evictOlderThan(obs.now, cfg.max_age);

    // Steps 1-2: echo match against the opposite direction's table, with
    // first-echo consume. Exact-value equality on TSval (indexOf) — no
    // range/closest-match heuristic, no wraparound reasoning, and tsecr==0
    // is looked up like any other value.
    var sample: ?root.RttSample = null;
    if (opp_dir.indexOf(obs.tsecr)) |idx| {
        const first_seen = opp_dir.entries[idx].first_seen;
        // Saturating subtraction: `obs.now` is documented as monotonically
        // non-decreasing, but a caller that violates that must degrade to a
        // clamped-to-zero RTT, never Debug-panic / ReleaseFast-UB on
        // underflow (mirrors `TsTable.evictOlderThan`'s saturating age).
        sample = .{
            .rtt = obs.now -| first_seen,
            .tsval = obs.tsecr,
            .at = obs.now,
        };
        // First-echo-only rule: consume the entry NOW, so a later duplicate
        // or delayed ACK re-echoing the same TSecr finds nothing and
        // correctly produces no second, inflated sample.
        opp_dir.removeAt(idx);
    }

    // Step 4: insert into the same-direction table, first-seen only. An
    // existing entry (a retransmission replaying the same TSval) is left
    // untouched — the FIRST send time is what an eventual echo measures
    // against.
    if (same_dir.indexOf(obs.tsval) == null) {
        // Step 5b: capacity eviction, only now that aging has already run
        // and only because an insert is actually needed. Evict the single
        // entry that has waited longest for an echo.
        if (same_dir.isFull()) {
            if (same_dir.oldestIndex()) |oldest| same_dir.removeAt(oldest);
        }
        // Only still-Full case left is capacity == 0 (oldestIndex was null
        // on an empty-and-full table): drop the observation rather than
        // grow — the table's allocation never grows.
        same_dir.insert(obs.tsval, obs.now) catch |err| switch (err) {
            error.Full => {},
        };
    }

    // Step 6: exactly one sample max per call, and only from step 1's match.
    return sample;
}

test "match: file is reachable from the build (does not itself invoke the stub)" {
    // Intentionally does NOT call `matchEcho` — real calls belong to
    // `kat.zig` / `property.zig`, gated behind `gate.fable_core_implemented`
    // (see `gate.zig`). This anchors the file + its doc comment in
    // `zig build test-pping` regardless of the gate's value.
    try std.testing.expect(true);
}
