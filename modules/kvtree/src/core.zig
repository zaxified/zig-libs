// SPDX-License-Identifier: MIT

//! core — THE FABLE CORE. The three functions this module exists to prove
//! correct, each `@panic("TODO(fable/core): …")` until a Fable agent fills it
//! in and `gate.fable_core_implemented` flips to `true`. Everything else in
//! `kvtree` (page/node codecs + B-tree split/merge in `format.zig`, the
//! `Pager` + freelist container in `pager.zig`, the read/descend/cursor path in
//! `root.zig`, and the whole property harness in `harness.zig`) is mechanical,
//! real today, and exists to hold THESE three to account.
//!
//! Why a COW B-tree, and where the irreducible correctness actually sits:
//! snapshot isolation and crash-safety are *emergent* from copy-on-write plus
//! an atomic meta-page swap — there is no separate write-ahead-log state
//! machine to get wrong (the LMDB/BoltDB argument, and why we chose it over
//! B-tree+WAL). But "emergent" is not "free": the emergence is exactly these
//! three invariants, and a subtle bug in any of them is a silently-lost commit,
//! a torn recovered tree, or a reader observing a page that was recycled out
//! from under it. That is the class of bug only a VOPR/model-checker catches,
//! which is why the harness (not a human eyeballing the diff) is the acceptance
//! gate.
//!
//!  1. `commit`  — the atomic-commit invariant (crash-safety kernel).
//!  2. `recover` — the crash-recovery meta-selection invariant.
//!  3. `reclaimGate` — the MVCC page-lifecycle / reader-snapshot-GC invariant.

const std = @import("std");
const format = @import("format.zig");
const pager_mod = @import("pager.zig");

const Meta = format.Meta;
const PageId = format.PageId;
const Pager = pager_mod.Pager;

/// One buffered mutation from an open read-write transaction. `commit` applies
/// a whole sorted batch of these against the base tree in a single atomic step.
pub const Change = union(enum) {
    /// Insert or overwrite. `key`/`val` are borrowed for the duration of the
    /// commit call (the caller owns the txn's staging arena).
    put: struct { key: []const u8, val: []const u8 },
    /// Delete `key` if present.
    del: []const u8,
};

pub const CommitError = error{
    /// A storage side effect (write / fsync / …) failed mid-commit. A correct
    /// `commit` guarantees this leaves the LAST committed meta intact and
    /// adoptable — the new state atomically did-not-happen.
    CommitFailed,
    EntryTooLarge,
    OutOfMemory,
    /// Any lower-level storage error surfaced verbatim (see `pager.zig`).
    Storage,
};

pub const RecoverError = error{
    /// Neither meta page is a structurally-valid, in-bounds committed state —
    /// the store is not recoverable (as opposed to merely torn at the tail,
    /// which a correct `commit`/`recover` pair must always survive).
    Unrecoverable,
    Storage,
    OutOfMemory,
};

// ── 1. commit — the atomic-commit invariant (crash-safety kernel) ────────────

/// Apply `changes` to the tree rooted at `base`, copy-on-write, and make the
/// result durable as a new committed version — atomically with respect to a
/// crash at ANY point.
///
/// **The irreducible invariant.** The commit sequence MUST establish, and
/// recovery MUST rely on, this ordering: every newly-written data/freelist page
/// reaches stable storage (fsync) *before* the meta page that references them
/// is written, and that meta page itself is durable (fsync) before the commit
/// is acknowledged. A crash between those fsyncs must leave the PREVIOUS meta
/// as the highest-valid one, so recovery adopts the last fully-committed tree
/// and the half-written new tree is simply unreachable garbage (its pages were
/// never linked by a durable meta). Get this ordering wrong — write the meta
/// before its pages are durable, or reuse the wrong meta slot, or fail to fsync
/// — and a crash yields a meta pointing at pages that do not exist yet: a torn
/// tree, unrecoverable, undetectable without this harness. Copy-on-write is
/// what makes the atomicity possible (the old tree is never mutated in place,
/// so it remains intact until the single meta-pointer swap), but the *ordering
/// and the double-buffered meta slot choice* are this function's to get right.
///
/// It must also drive the freelist correctly: pages the COW made dead this
/// commit are handed to the freelist tagged with THIS txn id, and only pages
/// whose freeing txn passes `reclaimGate` against the oldest live reader may be
/// pulled for reuse (see below) — the point where the crash-safety kernel and
/// the MVCC kernel meet.
///
/// Returns the newly-committed meta (already durable). `oldest_reader_txn` is
/// the lowest `txn_id` any still-open read snapshot is pinned to (or
/// `base.txn_id + 1`, i.e. "no older reader", when none is open).
pub fn commit(
    pager: *Pager,
    base: Meta,
    changes: []const Change,
    oldest_reader_txn: u64,
) CommitError!Meta {
    _ = pager;
    _ = base;
    _ = changes;
    _ = oldest_reader_txn;
    @panic("TODO(fable/core): COW apply + durability-ordered meta-page swap + freelist accounting — the atomic-commit invariant. See this function's doc comment and harness.zig's serializability/recovery checks.");
}

// ── 2. recover — the crash-recovery meta-selection invariant ─────────────────

/// Open-time recovery: read both meta pages and adopt the correct committed
/// state after an arbitrary crash.
///
/// **The irreducible invariant.** Among meta pages 0 and 1, adopt the one with
/// the HIGHEST `txn_id` that is BOTH structurally valid (`format.Meta.decode`
/// non-null — magic/version/geometry/CRC all hold) AND semantically in-bounds
/// (its `root`, `free_root` and every page they transitively reference are
/// `< high_water`, and `high_water` does not exceed the actual file length).
/// The subtlety a crash exposes: the newer meta slot may be TORN (its write was
/// interrupted) — then its CRC fails and the OLDER meta is the right adopt; but
/// a torn write can also leave a *structurally* valid page with stale-but-CRC-
/// consistent bytes, so txn_id ordering, not slot position, decides. Choosing
/// the torn/newer meta, or failing to bounds-check its pointers, surfaces a
/// tree that references never-written pages. This is the exact dual of
/// `commit`'s ordering guarantee, and the two are only correct together.
pub fn recover(pager: *Pager) RecoverError!Meta {
    _ = pager;
    @panic("TODO(fable/core): pick the highest-txn_id valid+in-bounds meta page after a crash — the recovery-selection invariant. See this function's doc comment and harness.zig's recovered-prefix check.");
}

// ── 3. reclaimGate — the MVCC page-lifecycle / reader-snapshot-GC invariant ──

/// May a page that became dead in commit `free_txn` be recycled for writing
/// now, given that the oldest still-open read snapshot is pinned to
/// `oldest_reader_txn`?
///
/// **The irreducible invariant.** A COW reader holds a whole immutable tree
/// version by pinning a root (a meta's `txn_id`); it never takes a lock and
/// never blocks the writer. That freedom is safe ONLY if a page that was live
/// in any version a reader can still see is NEVER overwritten. A page freed by
/// commit `free_txn` was still part of the tree of every version `< free_txn`;
/// therefore it may be reused only once no open reader is pinned to a version
/// `< free_txn`. The whole of snapshot isolation rests on this one predicate
/// being exactly right — off by one (reusing a page an equal-txn reader still
/// needs) is a torn read / phantom that no single-threaded test can provoke and
/// only the concurrent-reader property check catches. The predicate looks
/// small; its substance is that `commit` must feed it the right `free_txn`
/// per parked page and the right `oldest_reader_txn` — which is why it lives
/// here in the gated core rather than as a plausible-looking one-liner.
pub fn reclaimGate(free_txn: u64, oldest_reader_txn: u64) bool {
    _ = free_txn;
    _ = oldest_reader_txn;
    @panic("TODO(fable/core): the freed-page-vs-oldest-reader safety predicate — the MVCC page-lifecycle invariant. See this function's doc comment and harness.zig's snapshot-isolation check.");
}

// ── type-only test (compiles the signatures; never calls the stubs) ──────────

const testing = std.testing;

test "core types + signatures resolve without invoking the stubs" {
    // Exercise the plain-data types and prove the function pointers type-check,
    // WITHOUT calling into the panicking bodies (mirrors election.zig).
    const c: Change = .{ .put = .{ .key = "k", .val = "v" } };
    try testing.expect(c == .put);
    const d: Change = .{ .del = "k" };
    try testing.expect(d == .del);
    try testing.expect(@TypeOf(&commit) != @TypeOf(&recover));
    try testing.expect(@TypeOf(&reclaimGate) == *const fn (u64, u64) bool);
}
