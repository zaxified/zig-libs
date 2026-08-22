// SPDX-License-Identifier: MIT

//! What an L2-over-overlay data plane does with `ethfrag`: split an inner
//! Ethernet frame too large for the tunnel's carrier MTU into wire fragments,
//! feed them into the receive-side reassembler out of order (as UDP would
//! deliver them), and get the original frame back byte-identical. Then show
//! the reassembler's adversarial posture: a retransmitted duplicate fragment
//! is rejected by name and drops the whole in-flight datagram, per RFC 5722.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `ethfrag` does not export.

const std = @import("std");
const ethfrag = @import("ethfrag");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // An inner Ethernet frame larger than the tunnel's carrier MTU, so it has
    // to be split. 3000 bytes, patterned so reassembly can be checked
    // byte-for-byte rather than just by length.
    var inner_frame: [3000]u8 = undefined;
    for (&inner_frame, 0..) |*b, i| b.* = @truncate(i * 31 + 7);

    // Carrier path: outer UDP/tunnel header reserves 28 bytes on top of this
    // codec's own 8-byte header; the carrier's own MTU is 1200.
    const carrier_mtu: usize = 1200;
    const header_overhead: usize = 28;
    const frag_id: u16 = 0xBEEF;

    const frags = try ethfrag.fragment(gpa, &inner_frame, frag_id, carrier_mtu, header_overhead);
    defer ethfrag.freeFragments(gpa, frags);
    std.debug.print("split {d}-byte frame into {d} fragment(s)\n", .{ inner_frame.len, frags.len });

    // Receive side: bounded reassembler, caller-clocked timeout.
    var r = ethfrag.Reassembler.init(gpa, .{
        .max_inflight = 64,
        .timeout_ns = 2 * std.time.ns_per_s,
    });
    defer r.deinit();

    // Deliver in reverse order, as an unreliable carrier might.
    var reassembled: ?[]u8 = null;
    var now_ns: u64 = 0;
    var i: usize = frags.len;
    while (i > 0) {
        i -= 1;
        switch (try r.insert(frags[i].bytes, now_ns)) {
            .incomplete => {},
            .complete => |bytes| reassembled = bytes,
        }
        now_ns += std.time.ns_per_ms;
    }

    if (reassembled) |bytes| {
        defer gpa.free(bytes);
        const identical = std.mem.eql(u8, &inner_frame, bytes);
        std.debug.print("reassembled {d} bytes, identical to original: {}\n", .{ bytes.len, identical });
    } else {
        std.debug.print("reassembly did not complete\n", .{});
    }

    // Adversarial case: replay the very first fragment for a fresh datagram
    // id, then replay it again byte-for-byte. RFC 5722 says an exact
    // duplicate is treated the same as any other overlap and the whole
    // datagram is dropped, not just the offending fragment.
    var r2 = ethfrag.Reassembler.init(gpa, .{ .max_inflight = 4, .timeout_ns = 1_000_000_000 });
    defer r2.deinit();

    const replay_id: u16 = 0x1234;
    const replay_frags = try ethfrag.fragment(gpa, "hello, replayed frame", replay_id, 512, 0);
    defer ethfrag.freeFragments(gpa, replay_frags);

    _ = try r2.insert(replay_frags[0].bytes, 0);
    std.debug.print("after first delivery: {d} datagram(s) in flight\n", .{r2.inflightCount()});

    // Same fragment bytes arrive a second time.
    if (r2.insert(replay_frags[0].bytes, 1)) |_| {
        std.debug.print("duplicate fragment was unexpectedly accepted\n", .{});
    } else |err| switch (err) {
        error.OverlappingFragment => std.debug.print(
            "duplicate fragment rejected (OverlappingFragment), datagram dropped\n",
            .{},
        ),
        else => return err,
    }
    std.debug.print("after duplicate: {d} datagram(s) in flight\n", .{r2.inflightCount()});
}
