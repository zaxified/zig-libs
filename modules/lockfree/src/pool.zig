// SPDX-License-Identifier: MIT

//! pool — a poisoning node pool. **Mechanical**, plus it carries the
//! in-tree *use-after-free teeth* for this module: because sanitizers are
//! not usable here (TSan/ASan link libc, violating the zero-libc invariant —
//! and a TSan smoke probe on this toolchain silently failed to flag a blatant
//! data race; see SPEC §"Verification"), a UAF in the reclamation core cannot
//! be caught by a sanitizer. So the pool compensates: every freed node is
//! overwritten with a `0xA5` poison pattern and pushed onto a free list that
//! `acquire` **reuses first**. A reclamation bug that hands a node back to the
//! allocator while a thread still dereferences it will therefore (a) read a
//! recognizable poison value — `0xA5A5…`, whose high tag bits are never a
//! valid producer id, so the harness's multiset checker flags it as
//! `Corrupted` — and/or (b) trip `verifyQuiescent`, which asserts every node
//! sitting on the free list still holds intact poison.
//!
//! Concurrency: the pool IS shared mutable state — producers `acquire`
//! concurrently with each other and with reclaim-path `release`s, all racing
//! on `free_head` and on the `all` list. EBR only guarantees that a given
//! *node*'s handoff is quiescent; it says nothing about the pool's own
//! bookkeeping. (The scaffold originally claimed the pool needed no internal
//! synchronization — that was a latent data race; the gated stress test
//! drives `acquire` from 8 producer threads at once.) A `SpinLock` therefore
//! guards every entry point. Its release/acquire pair also carries the
//! happens-before edge for node memory handoff between a freeing thread and
//! the next acquiring thread, so the poison write, the poison check and the
//! new owner's initialization never race.
//!
//! The lock makes `acquire`/`release` not lock-free; node allocation never
//! was (it can hit the general-purpose allocator). The lock-free guarantees
//! of the queue concern its head/tail/next CAS loops, not allocation.

const std = @import("std");
const atomic = @import("atomic.zig");

/// The byte the free list is poisoned with. Chosen so a `u64` view reads as
/// `0xA5A5A5A5A5A5A5A5`, whose top 16 bits (`0xA5A5`) exceed any realistic
/// producer id — the harness recognizes it as corruption, not a live value.
pub const poison_byte: u8 = 0xA5;

pub const Error = error{
    /// A node on the free list no longer holds intact poison — something
    /// wrote to it after it was freed (a use-after-free), or the pool is
    /// corrupt. This is the canary tripping.
    CanaryTripped,
};

/// A pool of `T` nodes with poison-on-free and free-list reuse. `T` must be a
/// struct (the node type); the pool never interprets its fields.
pub fn NodePool(comptime T: type) type {
    return struct {
        const Self = @This();

        /// One backing slot. `next_free` links it into the free stack while
        /// retired; `live` tracks whether the slot is currently handed out
        /// (bookkeeping for `verifyQuiescent`).
        const Slot = struct {
            node: T,
            next_free: ?*Slot,
            live: bool,
        };

        allocator: std.mem.Allocator,
        /// LIFO free list — reused before allocating fresh, so a UAF reliably
        /// lands on a poisoned, still-referenced slot.
        free_head: ?*Slot,
        /// Every slot ever allocated, for teardown + `verifyQuiescent` sweep.
        all: std.ArrayListUnmanaged(*Slot),
        /// Guards `free_head`/`all` and orders node-memory handoff across
        /// threads (see the file doc comment).
        lock: atomic.SpinLock,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .free_head = null,
                .all = .empty,
                .lock = .{},
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.all.items) |slot| self.allocator.destroy(slot);
            self.all.deinit(self.allocator);
            self.* = undefined;
        }

        fn slotOf(node: *T) *Slot {
            return @fieldParentPtr("node", node);
        }

        /// Hand out a node — reusing a freed (poisoned) slot first. On reuse
        /// the slot's poison is verified intact BEFORE the node is returned,
        /// so a UAF that corrupted a free-listed slot is caught at the next
        /// `acquire` even if `verifyQuiescent` is never called. Mechanical.
        pub fn acquire(self: *Self) (Error || std.mem.Allocator.Error)!*T {
            self.lock.lock();
            defer self.lock.unlock();
            if (self.free_head) |slot| {
                try checkPoison(slot);
                self.free_head = slot.next_free;
                slot.next_free = null;
                slot.live = true;
                return &slot.node;
            }
            // `all` is the *only* record of a slot's existence — `deinit`'s
            // destroy sweep walks nothing else — so growing it must happen
            // BEFORE the slot exists. The obvious `create` + `append` order
            // leaks: `create` succeeds, the independent `append` fails, and the
            // fresh slot is then unreachable from `all` for the rest of the
            // pool's life. Reserving first leaves no fallible step between the
            // allocation and the record of it.
            try self.all.ensureUnusedCapacity(self.allocator, 1);
            const slot = try self.allocator.create(Slot);
            slot.* = .{ .node = undefined, .next_free = null, .live = true };
            self.all.appendAssumeCapacity(slot);
            return &slot.node;
        }

        /// Retire a node: poison its bytes and push it on the free list.
        /// Mechanical. (The *decision* that it is safe to do this — that no
        /// thread can still reach the node — is EBR's job, not the pool's.)
        pub fn release(self: *Self, node: *T) void {
            const slot = slotOf(node);
            std.debug.assert(slot.live);
            self.lock.lock();
            defer self.lock.unlock();
            @memset(std.mem.asBytes(&slot.node), poison_byte);
            slot.live = false;
            slot.next_free = self.free_head;
            self.free_head = slot;
        }

        /// Assert every node currently on the free list still holds intact
        /// poison. A use-after-free WRITE to a retired node flips a poison
        /// byte and is caught here. Deterministic; the harness calls it after
        /// a stress run drains the queue. This is the pool's canary.
        pub fn verifyQuiescent(self: *Self) Error!void {
            self.lock.lock();
            defer self.lock.unlock();
            var cur = self.free_head;
            while (cur) |slot| : (cur = slot.next_free) {
                try checkPoison(slot);
            }
        }

        fn checkPoison(slot: *Slot) Error!void {
            const bytes = std.mem.asBytes(&slot.node);
            for (bytes) |b| {
                if (b != poison_byte) return Error.CanaryTripped;
            }
        }
    };
}

// ── tests (mechanical + the deterministic canary teeth; all run today) ───────

const testing = std.testing;

const TestNode = struct {
    value: u64,
    next: ?*TestNode,
};

test "acquire/release round-trips and reuses freed slots" {
    var pool = NodePool(TestNode).init(testing.allocator);
    defer pool.deinit();

    const a = try pool.acquire();
    a.* = .{ .value = 1, .next = null };
    pool.release(a);

    // Reuse: the freed slot comes back (free list is LIFO, single slot).
    const b = try pool.acquire();
    try testing.expectEqual(a, b); // same backing slot reused
    try pool.verifyQuiescent(); // nothing on the free list now
}

test "verifyQuiescent passes for a properly poisoned free list" {
    var pool = NodePool(TestNode).init(testing.allocator);
    defer pool.deinit();
    const a = try pool.acquire();
    const b = try pool.acquire();
    pool.release(a);
    pool.release(b);
    try pool.verifyQuiescent(); // both freed slots hold intact poison
}

test "CANARY TEETH: a use-after-free write to a freed node is caught" {
    var pool = NodePool(TestNode).init(testing.allocator);
    defer pool.deinit();

    const a = try pool.acquire();
    a.* = .{ .value = 42, .next = null };
    pool.release(a); // `a` is now poisoned and on the free list

    // Simulate a use-after-free: a stale thread writes through the dangling
    // pointer. A correct reclamation scheme guarantees this never happens;
    // the poison canary exists to catch it when it does.
    a.value = 0xDEADBEEF;

    // The canary must trip — deterministically, every run.
    try testing.expectError(error.CanaryTripped, pool.verifyQuiescent());
}

test "CANARY TEETH: a UAF is also caught at the next acquire, not just the sweep" {
    var pool = NodePool(TestNode).init(testing.allocator);
    defer pool.deinit();
    const a = try pool.acquire();
    pool.release(a);
    a.next = a; // stale write corrupts the poisoned slot
    try testing.expectError(error.CanaryTripped, pool.acquire());
}

test "acquire leaks no slot when the allocator fails part-way through" {
    // The defect: `acquire` used to `create(Slot)` and only then `append` the
    // pointer to `self.all`. Those are two independent allocations; when the
    // second failed, the freshly created slot was never recorded, and
    // `deinit`'s destroy sweep — which walks `self.all` and nothing else —
    // could never find it again. Exactly one leaked `Slot` per pool, on
    // exactly the sweep index where the *append's* growth is the failing
    // allocation.
    //
    // The sweep drives every fail index a growing pool can reach, so it does
    // not depend on knowing which one that is; the whole point is that one of
    // them used to end with `allocations - deallocations == 1`.
    var idx: usize = 0;
    while (idx < 24) : (idx += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = idx });
        const gpa = failing.allocator();
        {
            var pool = NodePool(TestNode).init(gpa);
            defer pool.deinit();
            // Acquire until the induced failure hits (or the budget is spent);
            // `release` first so some rounds also exercise the free-list path.
            var n: usize = 0;
            while (n < 16) : (n += 1) {
                const node = pool.acquire() catch break;
                if (n % 3 == 2) pool.release(node);
            }
        }
        try testing.expectEqual(failing.allocations, failing.deallocations);
    }
}
