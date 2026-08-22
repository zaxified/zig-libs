// SPDX-License-Identifier: MIT

//! What an edge node on a dual-homed customer segment does with `df-elect`:
//! decode an inbound Hello off the fabric, decide whether this node is the
//! Designated Forwarder for its segment, and gate a BUM frame with the
//! split-horizon rule before forwarding it.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const df_elect = @import("df-elect");

/// The segment this node (id 3) shares with its peer (id 4). Lower priority
/// wins the DF election — node 3 is the owner here.
const segment: df_elect.EdgeSegment = .{
    .id = 1,
    .nodes = .{ 3, 4 },
    .priority = .{ 10, 20 },
};

pub fn main() !void {
    // A Hello just arrived off the wire from the peer, claiming liveness on
    // this segment. Decode it the way a real dispatch loop would.
    var hello_buf: [df_elect.Hello.wire_len]u8 = undefined;
    (df_elect.Hello{ .origin = 4, .seq = 900, .segment = segment.id }).encode(&hello_buf);

    const hello = df_elect.Hello.decode(&hello_buf) catch |err| switch (err) {
        error.Truncated, error.InvalidEncoding => {
            std.debug.print("malformed Hello, dropping\n", .{});
            return;
        },
    };
    std.debug.print("Hello from node {d}, seq {d}, segment {d}\n", .{ hello.origin, hello.seq, hello.segment });

    // Build this node's view of the segment from what it knows (its own
    // priority from the static topology, the peer's liveness from the Hello
    // just decoded) and ask for a DF decision.
    const self_id = segment.nodes[0];
    const peer_id = segment.otherOf(self_id);
    const view: df_elect.SegmentView = .{
        .self_id = self_id,
        .self_priority = segment.priorityOf(self_id).?,
        .peer_id = peer_id,
        .peer_priority = segment.priorityOf(peer_id).?,
        .peer_alive = true, // a fresh Hello was just seen
    };

    // No concrete frame in flight yet — this is the standing DF status.
    const standing = df_elect.decide(view, null, segment.id);
    std.debug.print("node {d} is_df={}\n", .{ self_id, standing.is_df });

    // A BUM frame arrives from the network side (no ingress segment) and
    // must be gated by split-horizon before this node forwards it toward
    // its own segment.
    var wan_buf: [df_elect.BumFrame.wire_len]u8 = undefined;
    (df_elect.BumFrame{ .origin = 99, .seq = 1, .ingress_segment = df_elect.no_ingress }).encode(&wan_buf);
    const wan_frame = try df_elect.BumFrame.decode(&wan_buf);
    const wan_decision = df_elect.decide(view, wan_frame.ingress_segment, segment.id);
    std.debug.print("WAN-side frame: is_df={} allow_forward={}\n", .{ standing.is_df, wan_decision.allow_forward });

    // A BUM frame that ingressed from THIS segment's own CE side must never
    // be reflected back onto it, independent of DF status — the
    // split-horizon backstop.
    var ce_buf: [df_elect.BumFrame.wire_len]u8 = undefined;
    (df_elect.BumFrame{ .origin = peer_id, .seq = 2, .ingress_segment = segment.id }).encode(&ce_buf);
    const ce_frame = try df_elect.BumFrame.decode(&ce_buf);
    const ce_decision = df_elect.decide(view, ce_frame.ingress_segment, segment.id);
    std.debug.print("same-segment frame: allow_forward={} (must be false)\n", .{ce_decision.allow_forward});
    std.debug.assert(!ce_decision.allow_forward);

    // A truncated frame off the wire must be rejected by name, not panic.
    if (df_elect.Hello.decode(hello_buf[0..3])) |_| {
        unreachable;
    } else |err| switch (err) {
        error.Truncated => std.debug.print("truncated Hello correctly rejected\n", .{}),
        error.InvalidEncoding => return err,
    }
}
