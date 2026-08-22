// SPDX-License-Identifier: MIT

//! What an ICMP echo prober does with `seqmap`: reserve a sequence id per
//! outstanding probe, correlate an incoming echo reply back to the target
//! that sent it, recognise a duplicate reply, and release the slot so the
//! id can be reused. Also drives the table to exhaustion to show the
//! round-robin cursor parks on the stuck id rather than skipping ahead.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export). If a
//! type needed to call the API is not public, or an error cannot be named
//! from outside, this file stops compiling. The module's own tests cannot
//! notice either, because they live inside it.

const std = @import("std");
const seqmap = @import("seqmap");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var m = try seqmap.SeqMap.init(gpa);
    defer m.deinit(gpa);

    // Two hosts, each with one outstanding probe.
    const host_a: u32 = 1; // caller's own target-table index
    const host_b: u32 = 2;
    const seq_a = try m.add(host_a, 0, 1_000_000);
    const seq_b = try m.add(host_b, 0, 1_000_050);
    std.debug.print("sent probe to host_a as seq={d}, host_b as seq={d}\n", .{ seq_a, seq_b });

    // Host B's echo reply lands first. Correlate it back to its target and
    // mark it answered, without releasing the slot yet — a caller usually
    // waits a short grace period to catch a duplicate before recycling.
    if (m.fetchPtr(seq_b)) |entry| {
        entry.answered = true;
        const rtt_ns = 1_050_000 - entry.sent_ns;
        std.debug.print("reply for seq={d}: target={d} rtt={d}ns\n", .{ seq_b, entry.target, rtt_ns });
    } else {
        return error.UnexpectedUnmatchedReply;
    }

    // A duplicate reply for the same id (network-level retransmit) is still
    // findable and visibly already-answered — the caller can count it as a
    // dup instead of a second RTT sample.
    const dup = m.fetch(seq_b) orelse return error.ExpectedStillReserved;
    std.debug.print("duplicate reply for seq={d}: already answered={}\n", .{ seq_b, dup.answered });
    if (!dup.answered) return error.ExpectedAnswered;
    m.release(seq_b);

    // A reply for an id that was never handed out (or already released) is
    // the normal "not ours" case, not an error.
    const stale = m.fetch(seq_b);
    std.debug.print("post-release lookup for seq={d}: {}\n", .{ seq_b, stale != null });
    if (stale != null) return error.ExpectedReleased;

    // host_a's probe never got an answer within budget — still resolvable
    // via fetch so the caller can log the target that timed out.
    const timed_out = m.fetch(seq_a) orelse return error.ExpectedStillOutstanding;
    std.debug.print("seq={d} timed out for target={d}\n", .{ seq_a, timed_out.target });
    m.release(seq_a);

    // Drive the table to exhaustion: fill every one of the 65536 ids, then
    // show `add` fails by NAME rather than silently wrapping past an
    // occupied slot.
    var filled: usize = 0;
    while (filled < seqmap.capacity) : (filled += 1) {
        _ = m.add(99, 0, 0) catch |err| switch (err) {
            error.Exhausted => break,
        };
    }
    if (m.add(99, 0, 0)) |_| {
        return error.ExpectedExhausted;
    } else |err| switch (err) {
        error.Exhausted => std.debug.print("table full at {d} entries: add correctly refused\n", .{filled}),
    }

    // Releasing the exact id the cursor is parked on immediately unblocks
    // the next add — no scan through the other 65535 ids. The cursor is
    // parked on 2: that's where the fill loop started (0 and 1 were already
    // free from host_a/host_b above, so the round-robin wrap filled them
    // last, leaving the cursor back at its starting point, now occupied).
    m.release(2);
    const reused = try m.add(100, 0, 0);
    std.debug.print("after releasing the cursor's id, next add returned seq={d}\n", .{reused});
    if (reused != 2) return error.ExpectedImmediateReuse;

    m.clear();
}
