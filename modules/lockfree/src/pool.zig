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
//! The pool is single-owner by design: EBR guarantees `acquire`/`release`
//! happen only while the caller holds the domain quiescent for that node, so
//! the pool itself needs no internal synchronization. (The harness drives it
//! single-threaded for the deterministic canary test, and via EBR for the
//! gated concurrent test.)

const std = @import("std");

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

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .free_head = null,
                .all = .empty,
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
            if (self.free_head) |slot| {
                try checkPoison(slot);
                self.free_head = slot.next_free;
                slot.next_free = null;
                slot.live = true;
                return &slot.node;
            }
            const slot = try self.allocator.create(Slot);
            slot.* = .{ .node = undefined, .next_free = null, .live = true };
            try self.all.append(self.allocator, slot);
            return &slot.node;
        }

        /// Retire a node: poison its bytes and push it on the free list.
        /// Mechanical. (The *decision* that it is safe to do this — that no
        /// thread can still reach the node — is EBR's job, not the pool's.)
        pub fn release(self: *Self, node: *T) void {
            const slot = slotOf(node);
            std.debug.assert(slot.live);
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
