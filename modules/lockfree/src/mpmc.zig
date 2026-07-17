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
const atomic = @import("atomic.zig");

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

    // ── THE FABLE CORE ───────────────────────────────────────────────────────
    //
    // Ordering discipline: every cross-thread load and CAS of `head`, `tail`
    // and `Node.next` is `.seq_cst`. This is not queue-local caution — it is a
    // requirement imposed by the EBR grace-period proof (ebr.zig, theorem at
    // `tryAdvance`): the proof anchors "which threads may hold a pointer to a
    // retired node" in the seq_cst total order S, and that anchoring needs the
    // pointer loads and the unlink CAS themselves to be members of S. Demoting
    // them to acquire/release would keep the queue's own linearizability but
    // silently invalidate the reclamation proof. (On x86_64 the cost is nil:
    // seq_cst loads are plain MOVs and every CAS is a LOCK CMPXCHG anyway;
    // only the pin/unpin stores in ebr.zig pay an XCHG.)
    //
    // ABA safety — why raw pointer CAS needs no tag/DCAS here: an ABA failure
    // would require the bit-pattern of a node address to reappear (node freed,
    // reallocated, relinked) between a thread's read of that pointer and its
    // CAS on it. Every read of head/tail/next in these loops happens inside an
    // EBR pin, and by the grace-period theorem a node reachable to this pinned
    // thread cannot complete reclamation — hence cannot re-enter the pool's
    // free list, hence cannot be re-acquired and relinked — until this thread
    // unpins. So for the whole window between a read and its dependent CAS,
    // address equality IS identity equality: a successful CAS proves the
    // location still holds the very node observed, not a recycled twin. EBR
    // does not prevent the A→B→A *sequence* — it makes it unrepresentable
    // within a pin by pinning the A node's lifetime.

    /// Enqueue `value`. Michael-Scott producer: link the new node onto the
    /// unique node whose `next` is null (the true last node), then swing
    /// `tail` forward, helping a lagging tail when observed.
    ///
    /// Linearization point: the successful `tail.next` CAS (null→node). After
    /// it, the node is reachable from head and exactly one dequeue will
    /// consume it; the tail swing is pure helping and may be done by anyone.
    ///
    /// Per-step argument:
    ///  • The node is fully initialized (`value`, `next = null`) BEFORE the
    ///    link CAS publishes it; the CAS (⊇ release) + the consumer's seq_cst
    ///    (⊇ acquire) read of `next` transfer that initialization. The
    ///    handoff of the node memory itself from a past incarnation is
    ///    ordered by the pool's internal lock (release by the freeing thread,
    ///    acquire here) — no thread can still touch the old incarnation, per
    ///    the EBR theorem.
    ///  • `tail` load: seq_cst — may still be superseded a cycle later, which
    ///    every subsequent step tolerates: if `t` has been passed, `t.next`
    ///    is permanently non-null (a linked node's `next` never returns to
    ///    null within an incarnation), so we take the help branch and retry;
    ///    dereferencing `t` stays safe under the pin even if `t` was retired
    ///    meanwhile (EBR keeps it physically alive until we unpin).
    ///  • Link CAS on `t.next` (null→node): success proves `t.next` was
    ///    still null at the CAS — so `t` was still the last node and head
    ///    cannot yet have passed it (head only advances over a non-null
    ///    `next`), so the new node is reachable: no lost enqueue. ABA on
    ///    "null→non-null→null" is structurally impossible within a pin: a
    ///    node's `next`, once set, is never cleared until the node is
    ///    reclaimed and reused, which the pin forbids.
    ///  • Tail-swing CAS (t→node / t→n): failure means another thread already
    ///    helped — never retried, never an error. ABA-safe under the pin as
    ///    above.
    pub fn enqueue(self: *MpmcQueue, p: *ebr.Participant, value: u64) (pool.Error || std.mem.Allocator.Error)!void {
        // Acquire + initialize the node BEFORE pinning: keeps critical
        // sections (which stall reclamation domain-wide) as short as
        // possible, and the pool's own lock never nests inside a pin.
        const node = try self.node_pool.acquire();
        node.* = .{ .value = value, .next = .init(null) };

        // Pin PER ATTEMPT, never across a backoff. A `Backoff.pause` can
        // escalate to an OS yield; a loser that stays pinned through it is a
        // stale-epoch straggler that freezes `tryAdvance` for every thread
        // (measured during bring-up: with pins held across backoff, the
        // epoch froze entirely under 8-consumer contention, and quiescing
        // threads could not drain their bags). Unpinning first costs two
        // atomic ops per retry; every pointer read and its dependent CAS
        // still share one pin, which is all the ABA argument needs.
        var backoff: atomic.Backoff = .{};
        while (true) {
            const guard = self.domain.enterCritical(p);
            const t = self.tail.load(.seq_cst);
            if (t.next.load(.seq_cst)) |n| {
                // Lagging tail: help swing it, then retry immediately —
                // helping is progress (ours or another producer's).
                _ = self.tail.cmpxchgStrong(t, n, .seq_cst, .seq_cst);
                guard.release();
                continue;
            }
            if (t.next.cmpxchgStrong(null, node, .seq_cst, .seq_cst) == null) {
                // Linked (linearized). Swing tail; a failure means someone
                // helped us — equally done.
                _ = self.tail.cmpxchgStrong(t, node, .seq_cst, .seq_cst);
                guard.release();
                return;
            }
            // Lost the link race to another producer.
            guard.release();
            backoff.pause();
        }
    }

    /// Dequeue the front value, or `null` if empty. Michael-Scott consumer:
    /// advance `head` over the current dummy, consume the NEW dummy's value,
    /// and retire the old dummy through EBR.
    ///
    /// Linearization points: the successful `head` CAS (non-empty case); the
    /// `h.next` load that returned null (empty case — `next` transitions
    /// null→non-null exactly once per incarnation, so a null read proves `h`
    /// was still the last node at that instant, and since head can only pass
    /// a node whose `next` is non-null, `h` was still the dummy: the queue
    /// was genuinely empty at that moment).
    ///
    /// Per-step argument:
    ///  • All three reads (`head`, `tail`, `h.next`) are seq_cst, both for
    ///    the queue logic and because they are the "pointer loads" the EBR
    ///    theorem orders against the unlink (ebr.zig). Dereferencing `h`
    ///    (for `.next`) and `n` (for `.value`) is safe even if another
    ///    consumer retires them concurrently: we are pinned, so their memory
    ///    cannot be poisoned/reused until we unpin.
    ///  • `h == t` with non-null next = lagging tail: help swing, retry.
    ///    This preserves the invariant that `tail` never falls behind `head`
    ///    — required so a retired node can never be re-exposed through
    ///    `tail`.
    ///  • `n.value` is read BEFORE the head CAS: after our CAS another
    ///    consumer may immediately dequeue past `n` and retire it, and
    ///    although EBR keeps `n` alive while we are pinned, reading first
    ///    makes the value's validity depend only on the enqueuer's
    ///    publish→our-acquire edge — one less thing owner-verify has to
    ///    trust. The read is a plain load: `value` is written exactly once,
    ///    before the link CAS that published the node, and we obtained `n`
    ///    from that publish (or S-later), so the write happens-before this
    ///    read; the only other writer of those bytes is the pool's poison
    ///    memset, excluded by the EBR theorem while we hold the pin.
    ///  • Head CAS (h→n): success = we own the old dummy `h` exclusively
    ///    (exactly one CAS can move head off `h`), so exactly one retire per
    ///    node — no double-free; and consuming `n.value` exactly once — the
    ///    multiset invariant. ABA-safe under the pin (see file header note).
    ///  • `retire(h)` runs program-order AFTER the successful unlink CAS and
    ///    inside the same pin — the two preconditions of `Domain.retire`'s
    ///    tag argument. Never freed inline: another consumer that read the
    ///    same `h` may be dereferencing `h.next` right now.
    ///  • `tryAdvance` runs on every call, but strictly AFTER the unpin
    ///    (defers run LIFO: release first, then tryAdvance). This placement
    ///    is load-bearing for liveness: the scan takes ~max_participants
    ///    loads, so a thread that scans while still pinned is a stale-pin
    ///    straggler blocking every OTHER scanner for the whole scan — with
    ///    several consumers doing that in tight loops, advances all but stop
    ///    (measured during bring-up: epoch +27 over 3.6M ops, and three
    ///    quiescing consumers livelocked each other for 1000 straight
    ///    attempts). Unpinned-scan keeps pins as short as the queue op and
    ///    costs nothing in safety — the reclaim theorem (ebr.zig) never
    ///    assumes the advancing/draining thread is pinned. The empty-path
    ///    calls are what let a quiescing consumer (the harness drain loop)
    ///    advance the epoch by itself and empty its own bags before
    ///    `unregister` asserts they are empty. Amortization is a non-goal
    ///    here; a production consumer may batch it.
    pub fn dequeue(self: *MpmcQueue, p: *ebr.Participant) ?u64 {
        defer self.domain.tryAdvance(p); // runs unpinned, after every release

        // Pin PER ATTEMPT, never across a backoff — same rationale (and same
        // measured epoch-freeze) as in `enqueue`. The retire still happens
        // inside the same pin as (and program-order after) the successful
        // unlink CAS, which is `Domain.retire`'s contract.
        var backoff: atomic.Backoff = .{};
        while (true) {
            const guard = self.domain.enterCritical(p);
            const h = self.head.load(.seq_cst);
            const t = self.tail.load(.seq_cst);
            const n = h.next.load(.seq_cst) orelse {
                guard.release();
                return null;
            };
            if (h == t) {
                // Lagging tail (an enqueuer linked but has not swung yet):
                // help, then retry immediately — helping is progress.
                _ = self.tail.cmpxchgStrong(t, n, .seq_cst, .seq_cst);
                guard.release();
                continue;
            }
            const value = n.value;
            if (self.head.cmpxchgStrong(h, n, .seq_cst, .seq_cst) == null) {
                self.domain.retire(p, .{
                    .ptr = h,
                    .ctx = self.node_pool,
                    .reclaim = reclaimNode,
                }) catch {
                    // `dequeue`'s `?u64` signature cannot surface allocator
                    // failure (scaffold limitation, reported). Steady state
                    // never allocates (drained bags keep capacity); an OOM
                    // here would mean losing the node or freeing it under
                    // readers — refuse both, loudly.
                    @panic("lockfree: allocator failure while retiring a node; dequeue cannot surface errors");
                };
                guard.release();
                return value;
            }
            // Lost the head race to another consumer.
            guard.release();
            backoff.pause();
        }
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
