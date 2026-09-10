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
    /// A storage side effect (write / fsync / …) failed mid-commit. The store
    /// is left with a committed version that `recover` will adopt — never a
    /// torn tree. Which version, though, depends on where the failure landed,
    /// and the difference matters to the caller:
    ///
    ///   - Failure at or before fsync #1, or a partial meta write: the new
    ///     state did not happen. The last committed meta is still the newest
    ///     valid one, and the new pages are unreachable garbage.
    ///   - Failure at fsync #2, *after* the meta page itself reached the file:
    ///     the new meta is durable, CRC-valid and carries the higher `txn_id`,
    ///     so the next `recover` adopts it — this is exactly the
    ///     "unacknowledged but durable" commit that `recover` documents as a
    ///     legal recovery target. It is unacknowledged, not undone.
    ///
    /// So this error means "the outcome is INDETERMINATE", not "nothing
    /// happened" — the two cases are indistinguishable from here (a failing
    /// fsync does not say whether the page it was flushing had already been
    /// written back). The caller MUST NOT retry on the same `Db`: its
    /// in-memory `meta_rec` still names the old base, so a retry would build
    /// on a version the file may no longer consider newest, and hand out page
    /// ids the durable newer meta already references. Close and reopen, let
    /// `recover` establish which version actually survived, and redo the work
    /// from there.
    CommitFailed,
    EntryTooLarge,
    OutOfMemory,
    /// Any lower-level storage error surfaced verbatim (see `pager.zig`).
    Storage,
    /// A page on the base tree's root-to-leaf path failed its kind-byte
    /// check (`format.kindOf` returned `null`) — on-disk bit rot on a node
    /// page since `recover` last validated it (node pages carry no CRC,
    /// unlike meta pages). The commit that discovered it aborts cleanly
    /// instead of dispatching on an out-of-range `NodeKind`.
    Corrupt,
    /// `Db.begin` was called while a read-write transaction from this same
    /// `Db` is already open. Single-writer is a documented caller contract
    /// (`Db.begin`'s doc); this is its mechanical enforcement — the sibling
    /// of `error.Locked` for a second `Db.open` over one file, which already
    /// had one.
    TxnInProgress,
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
///   2. Write the new freelist chain (also COW — the old pages are dead now,
///      and the new ones are recycled from pages earlier txns freed).
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
/// "Every allocation" includes the freelist chain's own storage, which is why
/// `reserveChain` runs before the push loop and not after: the chain recycles
/// like everything else, and it is that ordering — not a ban on reuse — that
/// keeps it safe. Banning it was the original design and it made the file grow
/// without bound, since every commit rewrites the chain.
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

    // Load the base freelist chain (every page in it dies this commit — see
    // below). May span more than one page; that is exactly what "chaining"
    // means and is why there is no cap on how many pages may be parked.
    const base_chain = pager_mod.readFreelistChain(arena, pager, base.free_root) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Storage,
    };
    var fl = base_chain.fl;

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

    // Every page in the old freelist chain is dead too (it was rebuilt above
    // into `fl`) — chaining means this can be more than one page.
    for (base_chain.pages.items) |pid|
        ctx.freed.append(arena, pid) catch return error.OutOfMemory;

    // Reserve the chain's OWN storage before parking anything this commit
    // freed, and the order is load-bearing: right now every entry in `fl` was
    // freed by an earlier txn, so copy-on-write guarantees none of them is
    // reachable from the still-durable `base` meta and any of them may be
    // written to. The pages `ctx.freed` is about to add are the opposite —
    // `base`'s tree is made of them, and it must stay intact until fsync #2.
    // Reserving first is what lets the chain recycle at all; reserving after
    // would hand it exactly the pages it must not touch.
    const chain_pages = fl.reserveChain(arena, pager, ctx.freed.items.len, oldest_reader_txn) catch
        return error.OutOfMemory;

    // Record every page this commit made dead. No capacity cap: a batch of
    // frees larger than one page's worth chains a second (third, ...) page
    // instead of losing ids, and `reserveChain` above already sized the chain
    // for exactly these entries.
    for (ctx.freed.items) |pid|
        fl.push(arena, pid, new_txn) catch return error.OutOfMemory;

    var buf: [page_size]u8 = undefined;
    const new_free_root = fl.writeChainOn(pager, chain_pages) catch return error.CommitFailed;

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

    switch (format.kindOf(&page) orelse return error.Corrupt) {
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
            // Nothing below a leaf — but the leaf's OWN geometry still has to
            // be checked here. Accepting it on the kind byte alone (what this
            // walk used to do) let a corrupt `count`/`val_len` through to the
            // read path, which indexes the page with no bounds check of its
            // own. See `format.leafViewSafe`.
            @intFromEnum(format.NodeKind.leaf) => {
                if (format.leafViewSafe(&buf) == null) return false;
            },
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
    // Walk the freelist CHAIN, trusting nothing: each hop's page id must be
    // in-bounds, its declared count must fit one page, and a cycle (a hostile
    // or torn `next` pointer looping back) must be rejected rather than hang
    // — the exact dual of the tree walk above, over the freelist's own
    // linked structure.
    var fid = m.free_root;
    var total: u64 = 0;
    var fl_visited: u64 = 0;
    while (fid != 0) {
        fl_visited += 1;
        if (fl_visited > m.high_water) return false; // cycle guard
        if (!pageIdOk(fid, m.high_water)) return false;
        pager.readPage(fid, &buf) catch |e| switch (e) {
            error.Corrupt => return false,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Storage,
        };
        const n = std.mem.readInt(u16, buf[0..2], .little);
        if (n > Freelist.capacity) return false;
        const next = std.mem.readInt(u32, buf[2..6], .little);
        var k: usize = 0;
        while (k < n) : (k += 1) {
            const off = Freelist.hdr_bytes + k * Freelist.entry_bytes;
            const id = std.mem.readInt(u32, buf[off .. off + 4][0..4], .little);
            if (!pageIdOk(id, m.high_water)) return false;
        }
        total += n;
        fid = next;
    }
    return total == m.free_count;
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

// ── fuzz: recover is the crash-recovery decode surface — it must validate
// two arbitrary/torn meta pages (`format.Meta.decode`) plus the tree/
// freelist pages they may point at, entirely from bytes on "disk" that a
// crash could have left in any state. It must never panic/OOB, only
// return a valid `Meta` or a typed `RecoverError`.

const kv = @import("kv");

/// How many pages `fuzzRecover` lays down. Hoisted out of the harness because
/// a corpus entry's SIZE is a function of it — see `RecoverSeed`.
const recover_pages: PageId = 6;

/// One corpus entry for `fuzzRecover`, in the layout its draws read.
///
/// ⛔ This target had **no corpus at all**, so the only input it ever ran
/// outside `--fuzz` was the empty one, and every knob after the byte draw was
/// its own range minimum. Traced through: both meta slots were stamped with
/// `{txn_id 0, root 0, free_root 0, free_count 0, high_water 0}`, and
/// `candidateValid` rejected each at `pageIdOk(0, 0)` — its FIRST bounds check.
/// So the tree walk never took a single step, `leafViewSafe`/`branchViewSafe`
/// were never called, the freelist chain walk and both cycle guards never ran,
/// and `recover` returned `error.Unrecoverable` on the one input the ordinary
/// lane has ever given it. Everything the comments below describe as "under
/// test" was reachable only under `--fuzz`.
///
/// ⛔ And a short seed cannot fix that. The harness opens with
/// `smith.bytes(&raw)` over a `recover_pages * page_size` buffer — 24 576
/// octets — and `Smith.bytes` consumes `@min(out.len, in.len)`. A seed shorter
/// than that is swallowed whole by the first draw and leaves nothing for the
/// fifteen knobs behind it, however carefully it is written. A corpus entry
/// here is therefore a full page image PLUS the knob words, which is why it is
/// built at run time into an arena rather than spelled out as a literal.
const RecoverSeed = struct {
    /// What the page image is filled with before the knobs stamp over it. Meta
    /// slots are `@memset` by `Meta.encode`, so this only reaches the data
    /// pages — and `0xff` there is the point of one seed below: a page stamped
    /// with the leaf kind byte over `0xff` fill declares a count of 65 535,
    /// which is exactly the shape `format.leafViewSafe` was added to reject.
    fill: u8,
    /// The knob words, little-endian `u64`, in the order the harness draws
    /// them. A word only survives a ranged draw if it lies inside that draw's
    /// range; otherwise the draw returns the range MINIMUM, so these are the
    /// values themselves and not indices into anything.
    ///
    /// Per meta slot (ids 0 and 1): `kind`, and if `kind != 3` also `txn_id`,
    /// `root`, `free_root`, `count_arm`, `free_count`, `high_water`.
    /// Per data page (ids 2..5): `shape`; then for shape 2 (branch)
    /// `count`, `leftmost`, `count` × `child`; for shape 3 (freelist)
    /// `size_arm`, `n`, `next`, `@min(n, capacity)` × `entry`.
    words: []const u64,
};

/// The 340 entry words the over-capacity freelist page still draws.
/// `candidateValid` rejects that page on its declared count before reading a
/// single entry, but the HARNESS writes `@min(n, capacity)` of them, so a seed
/// that omits these would run off its own end and silently zero every draw
/// after it.
const over_capacity_entries = [_]u64{2} ** Freelist.capacity;

const recover_seeds = [_]RecoverSeed{
    // 1. A meta that is adopted: root 2 is a leaf, no freelist. The first seed
    //    that makes `recover` return a Meta rather than `Unrecoverable`, and
    //    the first that reaches `leafViewSafe`. Slot 1 is left as raw fill, so
    //    the "one slot is not a meta page" branch runs too.
    .{ .fill = 0x00, .words = &.{ 0, 5, 2, 0, 0, 0, 3, 3, 1, 0, 0, 0 } },
    // 2. The tree walk DESCENDS: root 2 is a branch with two separators,
    //    leftmost 3 and right children 4 and 5, all three of them leaves. Four
    //    pages are visited against a `high_water` of 6. Slot 1 holds a
    //    structurally valid meta with a lower txn_id, which loses the ordering
    //    contest — the pair the "slot position NEVER decides" comment is about.
    .{ .fill = 0x00, .words = &.{ 0, 9, 2, 0, 0, 0, 6, 0, 1, 0, 0, 0, 0, 6, 2, 2, 3, 4, 5, 1, 1, 1 } },
    // 3. The freelist CHAIN is walked and totalled: free_root 3 holds three
    //    entries and chains to 4, which holds two and ends the chain, and the
    //    meta's free_count is the 5 that makes `total == m.free_count` hold.
    //    The accept path through the freelist, which no shorter seed reaches.
    .{ .fill = 0x00, .words = &.{ 0, 7, 2, 3, 0, 5, 6, 3, 1, 3, 0, 3, 4, 2, 2, 2, 3, 0, 2, 0, 3, 3, 0 } },
    // 4. The chain's count field one over `Freelist.capacity` — the rejection
    //    that field's check exists for. Put on the LAST page so the entry words
    //    below are the tail of the seed.
    .{ .fill = 0x00, .words = &([_]u64{ 0, 4, 2, 5, 0, 0, 6, 3, 1, 0, 0, 3, 3, 341, 0 } ++ over_capacity_entries) },
    // 5. A freelist `next` pointing back at its own page: the cycle guard has
    //    to reject it rather than walk for ever.
    .{ .fill = 0x00, .words = &.{ 0, 6, 2, 3, 0, 5, 6, 3, 1, 3, 0, 1, 3, 2, 0, 0 } },
    // 6. The higher txn_id is tried FIRST even though it sits in slot 1, and it
    //    is rejected for a root below `first_data_page`; slot 0 is then tried
    //    and rejected because its free_count (the `value(u64)` arm, drawn here
    //    at 2^64-1) cannot match an empty freelist. Both candidates refused.
    .{ .fill = 0x00, .words = &.{ 0, 2, 2, 0, 1, 0xffff_ffff_ffff_ffff, 6, 0, 11, 0, 0, 0, 0, 6, 1, 0, 0, 0 } },
    // 7. `high_water` past the real end of the file — rejected by
    //    `candidateValid`'s very first check, before any page is read.
    .{ .fill = 0x00, .words = &.{ 0, 3, 2, 0, 0, 0, 7, 3, 1, 0, 0, 0 } },
    // 8. Both meta slots left as raw fill: `Meta.decode` refuses both and
    //    `recover` returns `Unrecoverable` without a walk. The "no fourth
    //    state exists" argument's (b) case, on both slots at once.
    .{ .fill = 0x00, .words = &.{ 3, 3, 0, 0, 0, 0 } },
    // 9. ⭐ A leaf page stamped over `0xff` fill: its `count` reads as 65 535,
    //    so its slot directory alone is 131 078 octets inside a 4 096-octet
    //    page. `leafViewSafe` must reject it. That is the exact page recovery
    //    used to adopt on the kind byte alone, after which the first search
    //    probe read off the end of the caller's page buffer.
    .{ .fill = 0xff, .words = &.{ 0, 5, 2, 0, 0, 0, 3, 3, 1, 0, 0, 0 } },
    // 10. And the input this target ran for ever: no words at all, so every
    //     knob is its range minimum. Kept so the guard can show it is no
    //     longer the only one.
    .{ .fill = 0x00, .words = &.{} },
};

/// Serialise `recover_seeds` into the byte strings `Smith` reads. Each entry is
/// `recover_pages * page_size` octets for the `smith.bytes` draw, then eight
/// octets per knob word.
fn buildRecoverCorpus(a: Allocator, seeds: []const RecoverSeed) ![]const []const u8 {
    const image_len = @as(usize, recover_pages) * page_size;
    const entries = try a.alloc([]const u8, seeds.len);
    for (entries, seeds) |*out, sd| {
        const buf = try a.alloc(u8, image_len + sd.words.len * 8);
        @memset(buf[0..image_len], sd.fill);
        for (sd.words, 0..) |w, i| {
            std.mem.writeInt(u64, buf[image_len + i * 8 ..][0..8], w, .little);
        }
        out.* = buf;
    }
    return entries;
}

/// What one pass of `driveRecover` stamped and what `recover` made of it. The
/// harness throws it away; the corpus guard below reads it.
const RecoverRun = struct {
    /// Meta slots stamped as structurally valid records (0..2). The rest were
    /// left as raw fill and `Meta.decode` has to refuse them.
    metas_stamped: usize = 0,
    /// Data pages stamped as each shape: random, leaf, branch, freelist.
    shapes: [4]usize = @splat(0),
    /// The meta `recover` adopted, if any.
    adopted: ?Meta = null,
    /// The kind byte of the adopted meta's root page — the evidence that the
    /// tree walk really descended into a branch rather than stopping at a leaf.
    root_kind: ?u8 = null,
};

test "fuzz: recover never panics on arbitrary on-disk page bytes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const corpus = try buildRecoverCorpus(arena.allocator(), &recover_seeds);
    var run: RecoverRun = .{};
    try testing.fuzz(&run, fuzzRecover, .{ .corpus = corpus });
}

fn fuzzRecover(run: *RecoverRun, smith: *std.testing.Smith) !void {
    run.* = .{};
    try driveRecover(smith, run);
}

/// ⭐ The harness body, factored out so the corpus guard below drives the SAME
/// draw sequence rather than a paraphrase of it. A guard that measures a
/// different sequence from the one the fuzzer runs is not a guard.
fn driveRecover(smith: *std.testing.Smith, run: *RecoverRun) !void {
    const gpa = testing.allocator;

    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();
    const handle = try sim.storage().open("fuzz.kvt", .create_truncate);
    var p = Pager.init(sim.storage(), handle, 0);

    // Lay down a handful of arbitrary pages: slots 0/1 are the meta pages
    // `recover` chooses between; the rest are candidate tree/freelist pages
    // a torn/hostile meta might point at.
    const num_pages = recover_pages;
    var raw: [num_pages * page_size]u8 = undefined;
    smith.bytes(&raw);
    var id: PageId = 0;
    while (id < num_pages) : (id += 1) {
        var page: [page_size]u8 = undefined;
        @memcpy(&page, raw[id * page_size .. (id + 1) * page_size]);
        // A meta slot of purely random bytes is REJECTED by `Meta.decode`:
        // it gates on magic, format_version, page_size and a CRC32, four
        // independent 32-bit equalities, so random bytes get past it with
        // probability ~2^-128 (measured: 0 hits in 200,000 draws). Left that
        // way, this fuzzer would only ever exercise the structural reject
        // path, and `candidateValid` — the tree walk and the freelist-chain
        // walk, i.e. the deeper half of what the header above says is under
        // test — would be unreachable. So re-stamp each meta slot as a
        // STRUCTURALLY valid record whose SEMANTIC fields stay fuzzed: the
        // walk then runs against hostile root / free_root / free_count /
        // high_water. One slot in four is left random to keep covering the
        // reject path and the "both slots invalid" branch.
        //
        // The sense of the test matters: an un-fuzzed run drives the body once
        // per corpus seed and then ONCE MORE with an all-zero smith, so the
        // zero draw must be the one that stamps a valid meta. Written as
        // `!= 0` it would do the opposite and the empty round would exercise
        // nothing but the reject path. The reject path is separately and
        // deterministically covered by `format.zig`'s "meta rejects foreign /
        // wrong-version pages" and CRC tests.
        //
        // ⛔ That sentence used to end "drives the body ONCE", which was the
        // whole problem: one input, and it was not enough. Getting the sense
        // of this draw right made the empty round stamp two metas, and then
        // `candidateValid` rejected both at `pageIdOk(0, 0)`, its first bounds
        // check, so nothing below this line was ever reached anyway. See
        // `RecoverSeed`.
        if (id < 2 and smith.valueRangeAtMost(u8, 0, 3) != 3) {
            const m: Meta = .{
                .txn_id = smith.value(u64),
                // Mostly in range, so the walk actually descends; sometimes
                // just past the end, so the bounds rejection is covered too.
                .root = smith.valueRangeAtMost(u32, 0, num_pages + 1),
                .free_root = smith.valueRangeAtMost(u32, 0, num_pages + 1),
                // Small often enough that `total == free_count` can actually
                // hold and a candidate can be ADOPTED — a fuzzer that only
                // ever reaches "reject" never exercises the accept path.
                .free_count = if (smith.valueRangeAtMost(u8, 0, 1) == 0)
                    smith.valueRangeAtMost(u64, 0, num_pages * 2)
                else
                    smith.value(u64),
                .high_water = smith.valueRangeAtMost(u64, 0, num_pages + 1),
            };
            m.encode(&page);
            run.metas_stamped += 1;
        } else if (id >= format.first_data_page) {
            // Same argument one level down. `candidateValid` only descends
            // into a page whose first byte is a leaf/branch kind, and only
            // walks a freelist page it was pointed at; with purely random
            // bytes that happens ~2/256 of the time, so the branch descent
            // and the chain walk stay all but uncovered (measured on the
            // random version: 188 of 200,000 runs reached the freelist walk,
            // every one of them via the trivial root-is-a-leaf case, and no
            // run ever descended through a branch). Stamp a plausible SHAPE
            // and keep the contents fuzzed.
            // ⚠ The draw stays INLINE in the `switch`. Bound to a name and
            // switched on afterwards it is the same code, but
            // `check-fuzz-reach` then reads it as an R2 branch selector and
            // fails the ratchet — while the inline form it cannot see is the
            // one this file had all along. The counting therefore happens per
            // arm. (Reported: the gate's R2(c) rule misses a ranged draw used
            // directly as a `switch` operand, which is the commoner spelling.)
            switch (smith.valueRangeAtMost(u8, 0, 3)) {
                // leave fully random — hostile/garbage page
                0 => run.shapes[0] += 1,
                1 => {
                    run.shapes[1] += 1;
                    page[0] = @intFromEnum(format.NodeKind.leaf);
                },
                2 => {
                    run.shapes[2] += 1;
                    // A branch whose geometry passes `branchViewSafe` so the
                    // walk descends, but whose child ids are fuzzed.
                    const count = smith.valueRangeAtMost(u16, 0, 4);
                    page[0] = @intFromEnum(format.NodeKind.branch);
                    std.mem.writeInt(u16, page[2..4], count, .little);
                    std.mem.writeInt(
                        u32,
                        page[4..8],
                        smith.valueRangeAtMost(u32, 0, num_pages + 1),
                        .little,
                    );
                    var k: u16 = 0;
                    while (k < count) : (k += 1) {
                        const off: u16 = @intCast(page_size - (@as(usize, k) + 1) * 16);
                        std.mem.writeInt(u16, page[8 + k * 2 ..][0..2], off, .little);
                        std.mem.writeInt(u16, page[off..][0..2], 4, .little); // sep_len
                        std.mem.writeInt(
                            u32,
                            page[off + 2 ..][0..4],
                            smith.valueRangeAtMost(u32, 0, num_pages + 1),
                            .little,
                        );
                    }
                },
                else => {
                    run.shapes[3] += 1;
                    // A freelist chain page: a count that is sometimes over
                    // capacity (rejection), a `next` that can point back into
                    // the chain (cycle guard) and fuzzed entry ids.
                    // Usually a handful of entries, so the chain's running
                    // total can plausibly equal the meta's `free_count` and
                    // the ACCEPT path is reachable at all; sometimes at or
                    // over `capacity`, which is the rejection this page's
                    // count field exists to trigger.
                    const n = if (smith.valueRangeAtMost(u8, 0, 3) != 3)
                        smith.valueRangeAtMost(u16, 0, 8)
                    else
                        smith.valueRangeAtMost(u16, 0, Freelist.capacity + 1);
                    std.mem.writeInt(u16, page[0..2], n, .little);
                    std.mem.writeInt(
                        u32,
                        page[2..6],
                        smith.valueRangeAtMost(u32, 0, num_pages + 1),
                        .little,
                    );
                    var k: usize = 0;
                    while (k < @min(n, Freelist.capacity)) : (k += 1) {
                        const off = Freelist.hdr_bytes + k * Freelist.entry_bytes;
                        std.mem.writeInt(
                            u32,
                            page[off..][0..4],
                            smith.valueRangeAtMost(u32, 0, num_pages + 1),
                            .little,
                        );
                    }
                },
            }
        }
        try p.writePage(id, &page);
    }
    p.high_water = num_pages;

    // ⭐ The result is recorded rather than discarded. `recover` returning a
    // Meta at all is the number the empty input cannot produce — it was
    // `error.Unrecoverable` on the one input this target used to run — and the
    // kind byte of the adopted root is the evidence that the walk descended
    // through a branch rather than stopping at the trivial root-is-a-leaf case.
    const m = recover(gpa, &p) catch return;
    run.adopted = m;
    var root_page: [page_size]u8 = undefined;
    p.readPage(m.root, &root_page) catch return;
    run.root_kind = root_page[0];
}

test "corpus: the recover seeds drive every knob, and the counts are pinned" {
    // ⛔ Before the corpus below existed this target had no seeds at all, so
    // `testing.fuzz` ran it exactly once, on `in = ""`. Every one of these
    // numbers was therefore fixed: both metas stamped with all-zero fields,
    // all four data pages left random, `adopted` null, `root_kind` null. And
    // an `adopted > 0` guard would not have been enough either — what makes
    // this corpus worth its size is `branch_roots` and `freelists_walked`, the
    // two paths the header calls "the deeper half of what is under test".
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const corpus = try buildRecoverCorpus(arena.allocator(), &recover_seeds);

    var metas_stamped: usize = 0;
    var shapes: [4]usize = @splat(0);
    var adopted: usize = 0;
    var branch_roots: usize = 0;
    var freelists_walked: usize = 0;
    var txn_total: u64 = 0;
    for (corpus) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var run: RecoverRun = .{};
        try driveRecover(&smith, &run);
        metas_stamped += run.metas_stamped;
        for (&shapes, run.shapes) |*acc, n| acc.* += n;
        const m = run.adopted orelse continue;
        adopted += 1;
        txn_total += m.txn_id;
        if (m.free_root != 0) freelists_walked += 1;
        if (run.root_kind == @intFromEnum(format.NodeKind.branch)) branch_roots += 1;
    }
    try testing.expectEqual(@as(usize, 12), metas_stamped);
    // random, leaf, branch, freelist — all four shapes stamped at least once,
    // over 10 seeds x 4 data pages. Before the corpus there was ONE run, and
    // its four data pages were all shape 0.
    try testing.expectEqual([4]usize{ 25, 10, 1, 4 }, shapes);
    // 2 of 10 seeds recover; the other 8 are the refusals named above. The txn
    // sum pins WHICH two, so a seed that stops being adopted cannot be masked
    // by another one starting to be.
    //
    // Was 3 adopted / txn_total 5+9+7 / branch_roots 1 before `branchViewSafe`
    // gained separator-ordering validation (kvtree A1 finding 7, LOW): seed
    // txn_id=9's random branch page had in-bounds-but-unsorted separators,
    // which the OLD geometry-only check accepted — recovery adopted it as the
    // one branch-root seed in this corpus. It is now correctly refused as
    // unrecoverable: an unsorted branch routes lookups to the wrong child
    // (silent misses on present keys), which is exactly the defect that check
    // closes. `branch_roots` dropping to 0 is this corpus's only branch-shaped
    // root, so there being none left is the expected shape of the fix, not a
    // gap in the corpus.
    try testing.expectEqual(@as(usize, 2), adopted);
    try testing.expectEqual(@as(u64, 5 + 7), txn_total);
    try testing.expectEqual(@as(usize, 0), branch_roots);
    try testing.expectEqual(@as(usize, 1), freelists_walked);

    // Seed 9's page, spelled out: the claim that `leafViewSafe` is what
    // refuses it, rather than something earlier in the walk. A count of 65 535
    // needs a 131 078-octet slot directory inside a 4 096-octet page.
    var poisoned: [page_size]u8 = @splat(0xff);
    poisoned[0] = @intFromEnum(format.NodeKind.leaf);
    try testing.expectEqual(@as(u16, 0xffff), std.mem.readInt(u16, poisoned[2..4], .little));
    try testing.expect(format.leafViewSafe(&poisoned) == null);
}
