// SPDX-License-Identifier: MIT

//! core — THE FABLE CORE. The three functions this module exists to prove
//! correct — now IMPLEMENTED (`gate.fable_core_implemented` is `true`; the
//! formerly-gated property tests in `harness.zig` run for real). Everything
//! else in `kvtree` (page/node codecs + B-tree node split in `format.zig`,
//! the `Pager` + freelist container in `pager.zig`, the read/descend/cursor
//! path in `root.zig`, and the whole property harness in `harness.zig`) is
//! mechanical and exists to hold THESE three to account.
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

const Allocator = std.mem.Allocator;
const Meta = format.Meta;
const PageId = format.PageId;
const Pager = pager_mod.Pager;
const Freelist = pager_mod.Freelist;
const page_size = format.page_size;

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
///
/// **The implemented write/fsync sequence** (and why each step is where it is):
///
///   1. COW-apply the batch: every node on a mutated root-to-leaf path is
///      rebuilt into a FRESH page (freelist-reused only past `reclaimGate`, or
///      grown); the base tree is never written to. Split separators thread up
///      recursively, growing a new root when the old one splits.
///   2. Write the new freelist page (also COW — the old one is dead now).
///   3. `fsync` #1 — every page the new meta will reference is on stable
///      media BEFORE any meta write. A crash up to here leaves both meta
///      slots exactly as they were: the new pages are unreachable garbage.
///   4. Write the new meta, `txn_id = base.txn_id + 1`, into slot
///      `txn_id % 2` — strict parity alternation means this is never the slot
///      holding `base`, so a torn meta write can only destroy the
///      grandparent meta (txn-2), which `recover` would not have adopted
///      anyway while `base` (txn-1, durable, untouched) is present.
///   5. `fsync` #2 — the linearization point. The commit exists if and only
///      if this completes; only then is it acknowledged.
///
/// Freed-page discipline: pages the COW made dead are parked on the freelist
/// tagged with THIS txn — but only AFTER every allocation of this commit has
/// been made, so an in-flight commit can never recycle a page its own base
/// tree still references (the previous durable meta must stay intact until
/// step 5; `reclaimGate` alone cannot see this case, it only knows readers).
pub fn commit(
    gpa: Allocator,
    pager: *Pager,
    base: Meta,
    changes: []const Change,
    oldest_reader_txn: u64,
) CommitError!Meta {
    if (changes.len == 0) return base; // an empty txn commits nothing

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A failed commit must leave the pager exactly at the base state: pages
    // grown but never durably written would otherwise poison the NEXT commit
    // (its meta's high_water could exceed the durable file length, and
    // recovery would rightly reject that meta).
    const saved_high_water = pager.high_water;
    errdefer pager.high_water = saved_high_water;

    // Load the base freelist (the old freelist page itself dies this commit).
    var fl = Freelist{};
    if (base.free_root != 0) {
        var page: [page_size]u8 = undefined;
        try readForCommit(pager, base.free_root, &page);
        fl = Freelist.decode(arena, &page) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Corrupt => error.Storage,
        };
    }

    var ctx = Ctx{
        .arena = arena,
        .pager = pager,
        .fl = &fl,
        .oldest_reader_txn = oldest_reader_txn,
    };

    // Fold the ordered change list into one final op per key (last wins).
    const ops = try reduceChanges(arena, changes);

    // COW-apply down the tree; thread split separators back up, growing new
    // root levels for as long as the previous level still split.
    var pieces = try applyRec(&ctx, base.root, ops);
    while (pieces.len > 1) {
        var nb = format.BranchBuilder.init(arena, pieces[0].id);
        for (pieces[1..]) |p|
            nb.cells.append(arena, .{ .sep = p.sep, .child = p.id }) catch return error.OutOfMemory;
        pieces = try finishNodes(format.BranchBuilder, &ctx, nb);
    }
    const new_root = pieces[0].id;
    const new_txn = base.txn_id + 1;

    // The old freelist page is dead too (it was rebuilt above into `fl`).
    if (base.free_root != 0)
        ctx.freed.append(arena, base.free_root) catch return error.OutOfMemory;

    // Allocate the new freelist page BEFORE parking this commit's freed pages
    // (see the doc comment: an in-flight commit must never recycle a page the
    // still-durable base tree references).
    const new_free_root = ctx.allocPage();
    for (ctx.freed.items) |pid| {
        // Scaffold bound: a single freelist page (chaining is a documented
        // backlog item). Overflow LEAKS the excess ids — the file merely
        // stays larger; never a correctness issue.
        if (fl.len() >= Freelist.capacity) break;
        fl.push(arena, pid, new_txn) catch return error.OutOfMemory;
    }

    var buf: [page_size]u8 = undefined;
    fl.encode(&buf);
    pager.writePage(new_free_root, &buf) catch return error.CommitFailed;

    // fsync #1: all referenced pages durable before any meta write.
    pager.sync() catch return error.CommitFailed;

    const new_meta = Meta{
        .txn_id = new_txn,
        .root = new_root,
        .free_root = new_free_root,
        .free_count = fl.len(),
        .high_water = pager.high_water,
    };
    new_meta.encode(&buf);
    // The slot `base` does NOT occupy (strict txn-parity alternation).
    const slot: PageId = @intCast(new_txn % 2);
    pager.writePage(slot, &buf) catch return error.CommitFailed;

    // fsync #2: the linearization point — the commit exists iff this returns.
    pager.sync() catch return error.CommitFailed;

    return new_meta;
}

// ── commit internals: COW apply + split threading ────────────────────────────

/// One replacement page for a subtree: `pieces[0]` takes the original child's
/// slot (its `sep` is never read); every further piece carries the separator
/// promoted/carried out of the split that created it.
const Piece = struct { sep: []const u8, id: PageId };

/// The final effect on one key after folding a txn's ordered change list.
const Op = struct { key: []const u8, val: ?[]const u8 };

const Ctx = struct {
    arena: Allocator,
    pager: *Pager,
    fl: *Freelist,
    oldest_reader_txn: u64,
    /// Base-tree pages made dead by this commit (parked on the freelist only
    /// after all of this commit's allocations — see `commit`'s doc comment).
    freed: std.ArrayList(PageId) = .empty,

    /// A fresh page for the new tree version: reuse a freed page only past
    /// the MVCC reclaim gate, otherwise grow the file.
    fn allocPage(self: *Ctx) PageId {
        return self.fl.popReusable(self.oldest_reader_txn) orelse self.pager.growOne();
    }
};

fn readForCommit(pager: *Pager, id: PageId, buf: *[page_size]u8) CommitError!void {
    pager.readPage(id, buf) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Storage,
    };
}

/// Fold `changes` (ordered, possibly repeating keys) into a sorted list of
/// final per-key effects — last writer wins, exactly the reference `Model`'s
/// semantics.
fn reduceChanges(arena: Allocator, changes: []const Change) CommitError![]Op {
    var ops: std.ArrayList(Op) = .empty;
    for (changes) |c| {
        const key: []const u8, const val: ?[]const u8 = switch (c) {
            .put => |p| .{ p.key, p.val },
            .del => |k| .{ k, null },
        };
        var lo: usize = 0;
        var hi: usize = ops.items.len;
        var found = false;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, ops.items[mid].key, key)) {
                .lt => lo = mid + 1,
                .gt => hi = mid,
                .eq => {
                    lo = mid;
                    found = true;
                    break;
                },
            }
        }
        if (found)
            ops.items[lo].val = val
        else
            ops.insert(arena, lo, .{ .key = key, .val = val }) catch return error.OutOfMemory;
    }
    return ops.items;
}

/// COW-apply `ops` (sorted, non-empty) to the subtree rooted at `id`. The
/// original node becomes dead; the replacement piece(s) are written to fresh
/// pages and returned for the parent to link (piece 0 in place, the rest
/// inserted with their separators — the parent-insert half of a split).
fn applyRec(ctx: *Ctx, id: PageId, ops: []const Op) CommitError![]Piece {
    var page: [page_size]u8 = undefined;
    try readForCommit(ctx.pager, id, &page);
    ctx.freed.append(ctx.arena, id) catch return error.OutOfMemory;

    switch (format.kindOf(&page)) {
        .leaf => {
            var b = format.LeafBuilder.fromPage(ctx.arena, &page) catch return error.OutOfMemory;
            for (ops) |op| {
                if (op.val) |v| {
                    b.put(op.key, v) catch |e| return switch (e) {
                        error.EntryTooLarge => error.EntryTooLarge,
                        error.OutOfMemory => error.OutOfMemory,
                    };
                } else {
                    _ = b.del(op.key);
                }
            }
            return finishNodes(format.LeafBuilder, ctx, b);
        },
        .branch => {
            const b = format.BranchBuilder.fromPage(ctx.arena, &page) catch return error.OutOfMemory;
            const ncells = b.cells.items.len;
            // Rebuild the branch, routing each op run to its child: child i
            // covers [sep[i-1], sep[i]) with a key EQUAL to a separator going
            // right — the exact dual of the read path's childIndexFor.
            var nb = format.BranchBuilder.init(ctx.arena, b.leftmost);
            var op_i: usize = 0;
            var ci: usize = 0;
            while (ci <= ncells) : (ci += 1) {
                const child = if (ci == 0) b.leftmost else b.cells.items[ci - 1].child;
                if (ci > 0)
                    nb.cells.append(ctx.arena, .{ .sep = b.cells.items[ci - 1].sep, .child = child }) catch return error.OutOfMemory;
                const start = op_i;
                while (op_i < ops.len and
                    (ci == ncells or std.mem.lessThan(u8, ops[op_i].key, b.cells.items[ci].sep)))
                    op_i += 1;
                if (op_i > start) {
                    const sub = try applyRec(ctx, child, ops[start..op_i]);
                    // First piece replaces the child pointer in place…
                    if (ci == 0)
                        nb.leftmost = sub[0].id
                    else
                        nb.cells.items[nb.cells.items.len - 1].child = sub[0].id;
                    // …each further piece threads its promoted separator in
                    // right after it (recursive split, parent-insert half).
                    for (sub[1..]) |p|
                        nb.cells.append(ctx.arena, .{ .sep = p.sep, .child = p.id }) catch return error.OutOfMemory;
                }
                // An untouched child keeps its page: structural sharing with
                // the base version is what makes MVCC snapshots cheap.
            }
            std.debug.assert(op_i == ops.len);
            return finishNodes(format.BranchBuilder, ctx, nb);
        },
    }
}

/// Split `first` for as long as any piece overflows, then write every piece
/// to a freshly-allocated page. Works for leaves and branches (both split
/// types expose `{ right, sep }`).
fn finishNodes(comptime B: type, ctx: *Ctx, first: B) CommitError![]Piece {
    var builders: std.ArrayList(B) = .empty;
    var seps: std.ArrayList([]const u8) = .empty;
    builders.append(ctx.arena, first) catch return error.OutOfMemory;
    seps.append(ctx.arena, "") catch return error.OutOfMemory; // pieces[0].sep is never read
    var i: usize = 0;
    while (i < builders.items.len) {
        if (builders.items[i].overflows()) {
            const sp = builders.items[i].split() catch return error.OutOfMemory;
            builders.insert(ctx.arena, i + 1, sp.right) catch return error.OutOfMemory;
            seps.insert(ctx.arena, i + 1, sp.sep) catch return error.OutOfMemory;
            // No advance: the left half may still overflow.
        } else i += 1;
    }
    const pieces = ctx.arena.alloc(Piece, builders.items.len) catch return error.OutOfMemory;
    var buf: [page_size]u8 = undefined;
    for (builders.items, seps.items, pieces) |*b, sep, *piece| {
        const pid = ctx.allocPage();
        b.encode(&buf);
        ctx.pager.writePage(pid, &buf) catch return error.CommitFailed;
        piece.* = .{ .sep = sep, .id = pid };
    }
    return pieces;
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
///
/// Why this dual is correct against `commit`'s ordering: the previously
/// committed meta is durable and NEVER written by the in-flight commit
/// (parity alternation), so it always survives as a valid candidate; the
/// in-flight meta slot can hold (a) the grandparent meta — structurally valid
/// but lower txn_id, loses the ordering contest; (b) a torn write — CRC
/// fails; or (c) the complete new meta — in which case fsync #1 already made
/// every page it references durable, so adopting it is adopting a complete
/// committed tree (an unacknowledged-but-durable commit, which is a legal
/// recovery target). No fourth state exists.
pub fn recover(gpa: Allocator, pager: *Pager) RecoverError!Meta {
    var buf: [page_size]u8 = undefined;
    var cands: [2]?Meta = .{ null, null };
    const slots = [2]PageId{ format.meta_page_a, format.meta_page_b };
    for (slots, &cands) |pid, *cand| {
        pager.readPage(pid, &buf) catch |e| switch (e) {
            error.Corrupt => continue, // file too short for this slot
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Storage,
        };
        cand.* = Meta.decode(&buf); // structural validation only
    }

    // txn_id decides; slot position NEVER does (a torn write can leave a
    // structurally-valid stale meta in either slot).
    var first = cands[0];
    var second = cands[1];
    if (first == null or (second != null and second.?.txn_id > first.?.txn_id))
        std.mem.swap(?Meta, &first, &second);
    for ([2]?Meta{ first, second }) |cand| {
        const m = cand orelse continue;
        if (try candidateValid(gpa, pager, m)) return m;
    }
    return error.Unrecoverable;
}

/// Semantic in-bounds validation of one structurally-valid meta candidate:
/// `high_water` within the real file, and every page the meta transitively
/// references (tree walk + freelist entries) a real data page below
/// `high_water`. Trusts NOTHING in the referenced pages (bounds-checked
/// accessors, cycle guard) — a stale meta must be rejectable, not a crash.
fn candidateValid(gpa: Allocator, pager: *Pager, m: Meta) RecoverError!bool {
    const file_pages = pager.fileSizePages() catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Storage,
    };
    if (m.high_water > file_pages) return false;
    if (!pageIdOk(m.root, m.high_water)) return false;

    var buf: [page_size]u8 = undefined;
    var stack: std.ArrayList(PageId) = .empty;
    defer stack.deinit(gpa);
    stack.append(gpa, m.root) catch return error.OutOfMemory;
    var visited: u64 = 0;
    while (stack.pop()) |id| {
        visited += 1;
        if (visited > m.high_water) return false; // cycle — not a tree
        pager.readPage(id, &buf) catch |e| switch (e) {
            error.Corrupt => return false,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Storage,
        };
        switch (buf[0]) {
            @intFromEnum(format.NodeKind.leaf) => {}, // nothing below a leaf
            @intFromEnum(format.NodeKind.branch) => {
                const br = format.branchViewSafe(&buf) orelse return false;
                if (!pageIdOk(br.leftmost(), m.high_water)) return false;
                stack.append(gpa, br.leftmost()) catch return error.OutOfMemory;
                var i: usize = 0;
                while (i < br.count()) : (i += 1) {
                    const child = br.rightChildAt(i);
                    if (!pageIdOk(child, m.high_water)) return false;
                    stack.append(gpa, child) catch return error.OutOfMemory;
                }
            },
            else => return false, // not a node page
        }
    }

    if (m.free_root == 0) return m.free_count == 0;
    if (!pageIdOk(m.free_root, m.high_water)) return false;
    pager.readPage(m.free_root, &buf) catch |e| switch (e) {
        error.Corrupt => return false,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Storage,
    };
    const n = std.mem.readInt(u16, buf[0..2], .little);
    if (n > Freelist.capacity) return false;
    if (@as(u64, n) != m.free_count) return false;
    var k: usize = 0;
    while (k < n) : (k += 1) {
        const off = 2 + k * Freelist.entry_bytes;
        const id = std.mem.readInt(u32, buf[off .. off + 4][0..4], .little);
        if (!pageIdOk(id, m.high_water)) return false;
    }
    return true;
}

fn pageIdOk(id: PageId, high_water: u64) bool {
    return id >= format.first_data_page and id < high_water;
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
    // Derivation of the boundary: a page freed by commit `free_txn` is part
    // of the trees of versions `a .. free_txn-1` (allocated at `a`, removed
    // by the `free_txn` commit) and of NO version at or above `free_txn`. A
    // reader pinned exactly AT `free_txn` reads a tree that already excludes
    // the page, so equality is safe; only a reader pinned strictly BELOW
    // `free_txn` can still reach it. Hence `<=`, not `<`.
    //
    // What this predicate deliberately does NOT decide: a page freed by the
    // IN-FLIGHT commit (free_txn == base.txn_id + 1 == the no-reader default
    // of oldest_reader_txn) passes this gate, yet must not be recycled by
    // that same commit — the previous durable meta still references it until
    // the commit's final fsync. That is writer-ordering, not reader-safety,
    // and `commit` enforces it by parking its freed pages only after all of
    // its allocations are done.
    return free_txn <= oldest_reader_txn;
}

// ── unit tests (the full property/crash coverage lives in harness.zig) ───────

const testing = std.testing;

test "core types + signatures resolve without invoking the stubs" {
    // Kept from the scaffold: the plain-data types and function types resolve.
    const c: Change = .{ .put = .{ .key = "k", .val = "v" } };
    try testing.expect(c == .put);
    const d: Change = .{ .del = "k" };
    try testing.expect(d == .del);
    try testing.expect(@TypeOf(&commit) != @TypeOf(&recover));
    try testing.expect(@TypeOf(&reclaimGate) == *const fn (u64, u64) bool);
}

test "reclaimGate: equal-txn reader is safe, strictly-older reader blocks" {
    // Freed at 5: dead in versions >= 5, live in versions < 5.
    try testing.expect(reclaimGate(5, 5)); // reader AT 5 no longer sees it
    try testing.expect(reclaimGate(5, 6)); // only newer readers
    try testing.expect(!reclaimGate(5, 4)); // a version-4 reader still needs it
    try testing.expect(!reclaimGate(5, 0)); // ancient pinned snapshot blocks all
}
