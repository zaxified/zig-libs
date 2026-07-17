// SPDX-License-Identifier: MIT

//! mpmc — a Michael-Scott multi-producer/multi-consumer lock-free queue, the
//! proving consumer for `ebr.zig`. Split like `ebr.zig`:
//!
//!  • **Mechanical (real today):** the `Node` type, the queue struct, `init`
//!    (allocate the dummy sentinel + point head/tail at it), `deinit` (drain
//!    the chain back to the pool), and `reclaimNode` (the type-erased free
//!    callback the Fable `dequeue` hands to `ebr.retire`).
//!
//!  • **THE FABLE CORE (gated `@panic` stubs):** `enqueue` and `dequeue` —
//!    the CAS loops. Their difficulty is exactly what EBR exists to tame plus
//!    what it does not: the tail-lag "helping" swing, the head/tail CAS
//!    ordering, and — because EBR keeps a retired node physically alive until
//!    no thread is pinned on it — the ABA problem is dissolved (no reused
//!    address can fool a CAS while a reader is pinned), so no tagged/DCAS
//!    pointer is needed. Getting that interaction right is the core.
//!
//! Reference design: Michael & Scott, "Simple, Fast, and Practical
//! Non-Blocking and Blocking Concurrent Queue Algorithms" (PODC 1996), with
//! reclamation delegated to `ebr` rather than the paper's freelist+counter.
//!
//! `value` is a plain `u64` payload: the harness packs a producer id + a
//! per-producer sequence number into it so the multiset invariant can detect
//! lost / duplicated / corrupted items (see `harness.zig`).

const std = @import("std");
const gate = @import("gate.zig");
const ebr = @import("ebr.zig");
const pool = @import("pool.zig");

pub const Pool = pool.NodePool(Node);

/// A queue node. `next` is atomic because producers/consumers race on it;
/// `value` is written before the node is linked and read after, so it needs
/// no atomicity of its own. Poisoned to `0xA5A5…` while on the pool free list.
pub const Node = struct {
    value: u64,
    next: std.atomic.Value(?*Node),
};

pub const MpmcQueue = struct {
    /// Points at the dummy sentinel; the real front is `head.next`.
    head: std.atomic.Value(*Node),
    /// Points at (or lags just behind) the last node.
    tail: std.atomic.Value(*Node),
    node_pool: *Pool,
    domain: *ebr.Domain,

    /// Build an empty queue: acquire a dummy sentinel node and point both
    /// head and tail at it (the Michael-Scott invariant that the queue is
    /// never physically empty). Mechanical.
    pub fn init(node_pool: *Pool, domain: *ebr.Domain) (pool.Error || std.mem.Allocator.Error)!MpmcQueue {
        const dummy = try node_pool.acquire();
        dummy.* = .{ .value = 0, .next = .init(null) };
        return .{
            .head = .init(dummy),
            .tail = .init(dummy),
            .node_pool = node_pool,
            .domain = domain,
        };
    }

    /// Drain every still-linked node back to the pool. Mechanical. Assumes
    /// the domain is quiescent (no threads pinned) — the caller's contract at
    /// teardown. Nodes already retired-and-reclaimed are on the pool free list
    /// and are freed by `Pool.deinit`, not here (no double free).
    pub fn deinit(self: *MpmcQueue) void {
        var cur: ?*Node = self.head.load(.monotonic);
        while (cur) |node| {
            const nxt = node.next.load(.monotonic);
            self.node_pool.release(node);
            cur = nxt;
        }
        self.* = undefined;
    }

    /// Type-erased reclaim callback: return a retired node to its pool. The
    /// Fable `dequeue` passes `.{ .ptr = old_head, .ctx = self.node_pool,
    /// .reclaim = reclaimNode }` to `ebr.retire`. Mechanical wiring.
    pub fn reclaimNode(ctx: *anyopaque, ptr: *anyopaque) void {
        const p: *Pool = @ptrCast(@alignCast(ctx));
        const node: *Node = @ptrCast(@alignCast(ptr));
        p.release(node);
    }

    // ── THE FABLE CORE — gated `@panic` stubs ────────────────────────────────

    /// Enqueue `value`. Michael-Scott: acquire a node under an EBR pin, CAS it
    /// onto `tail.next`, then swing `tail` forward — helping a lagging tail if
    /// another producer's CAS beat this one. The pin + EBR reclamation are
    /// what make it safe to dereference `tail`/`tail.next` without them being
    /// freed underfoot.
    pub fn enqueue(self: *MpmcQueue, p: *ebr.Participant, value: u64) (pool.Error || std.mem.Allocator.Error)!void {
        _ = self;
        _ = p;
        _ = value;
        @panic("TODO(fable/core): MS-queue enqueue — pin (enterCritical), acquire a node, CAS it onto tail.next, swing tail with the lagging-tail helping rule, unpin");
    }

    /// Dequeue the front value, or `null` if empty. Michael-Scott: under an
    /// EBR pin, read head/tail/head.next, handle the tail-lag case, CAS head
    /// forward, read the value out of the NEW dummy, then `retire` the old
    /// dummy through EBR (never free it inline — a concurrent dequeuer may
    /// still be reading it; that is the whole point of the reclamation core).
    pub fn dequeue(self: *MpmcQueue, p: *ebr.Participant) ?u64 {
        _ = self;
        _ = p;
        @panic("TODO(fable/core): MS-queue dequeue — pin, read head/tail/next, CAS head forward, read value, retire the old dummy via ebr.retire(reclaimNode) — NEVER free it inline, unpin");
    }
};

// ── tests (mechanical construction only; ops are exercised by harness) ───────

const testing = std.testing;

test "init builds a non-empty (dummy-sentinel) queue; deinit drains it" {
    var d = try ebr.Domain.init(testing.allocator, .{ .max_participants = 1 });
    defer d.deinit();
    var np = Pool.init(testing.allocator);
    defer np.deinit();

    var q = try MpmcQueue.init(&np, &d);
    // Michael-Scott invariant: head == tail == the dummy, and the queue is
    // never physically empty even when logically empty.
    try testing.expectEqual(q.head.load(.monotonic), q.tail.load(.monotonic));
    try testing.expectEqual(@as(?*Node, null), q.head.load(.monotonic).next.load(.monotonic));
    q.deinit();

    // The dummy went back to the pool and is intact-poisoned there.
    try np.verifyQuiescent();
}
