// SPDX-License-Identifier: MIT

//! What an edge node on a multihomed customer segment does with `df-elect`:
//! decode a peer's Hello off the fabric, work out which member is the
//! Designated Forwarder for each Ethernet tag (RFC 7432 mod N and RFC 8584
//! HRW), take a role only after the DF wait, fail over when a peer
//! disappears, and gate a BUM frame with split-horizon before delivering it.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const df_elect = @import("df-elect");

/// A check that survives EVERY optimize mode, unlike a debug-only assert:
/// `-Doptimize=ReleaseFast` compiles those out, and `scripts/test.sh` does not
/// merely BUILD the examples, it RUNS them in the lane's own optimize mode --
/// so in a release lane the check vanished and the example went on printing
/// that it had passed. See `scripts/checks/check-example-assert.py`.
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

/// A site multihomed to three edge nodes (the PE addresses order them).
const members = [_]df_elect.Member{
    .{ .node = 3, .addr = 0x0a00_0003 },
    .{ .node = 4, .addr = 0x0a00_0004 },
    .{ .node = 5, .addr = 0x0a00_0005 },
};
const segment: df_elect.EdgeSegment = .{
    .id = 1,
    .esi = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01 },
    .members = &members,
    .tags = &.{ 10, 11, 12 },
};

pub fn main() !void {
    try segment.validate();
    const cfg: df_elect.ElectConfig = .{};

    // A Hello arrives from node 4: it is alive and sees all three members.
    var hello_buf: [df_elect.Hello.wire_len]u8 = undefined;
    (df_elect.Hello{ .origin = 4, .seq = 900, .segment = segment.id, .view = 0b111 }).encode(&hello_buf);
    const hello = df_elect.Hello.decode(&hello_buf) catch |err| switch (err) {
        error.Truncated, error.InvalidEncoding => {
            std.debug.print("malformed Hello, dropping\n", .{});
            return;
        },
    };
    std.debug.print("Hello from node {d}, seq {d}, view 0b{b:0>3}\n", .{ hello.origin, hello.seq, hello.view });

    // Service carving over the full member list: tag V goes to ordinal
    // V mod 3 (RFC 7432 §8.5); HRW spreads the same tags by hash.
    for (segment.tags) |tag| {
        const by_mod = df_elect.designatedForwarder(.modulo, segment.esi, &members, tag).?;
        const by_hrw = df_elect.designatedForwarder(.hrw, segment.esi, &members, tag).?;
        std.debug.print("tag {d}: DF by mod-N = node {d}, by HRW = node {d}\n", .{ tag, by_mod, by_hrw });
    }
    must(df_elect.designatedForwarder(.modulo, segment.esi, &members, 10).? == 4, @src()); // 10 mod 3 = 1

    // This node is 4, the mod-N DF for tag 10. It takes the role only after
    // its view has named it for `df_wait` ticks.
    var role: df_elect.Role = .{};
    role = df_elect.stepRole(role, true, 1000, cfg.df_wait);
    must(!role.is_df, @src());
    role = df_elect.stepRole(role, true, 1000 + cfg.df_wait, cfg.df_wait);
    must(role.is_df, @src());
    std.debug.print("node 4 holds tag 10 after the {d}-tick DF wait\n", .{cfg.df_wait});

    // Node 5 goes silent past `stale_after`: the survivors re-carve. Tag 11
    // was node 5's (11 mod 3 = 2); over {3, 4} it becomes 11 mod 2 = 1.
    const survivors = members[0..2];
    const new_df = df_elect.designatedForwarder(.modulo, segment.esi, survivors, 11).?;
    std.debug.print("node 5 gone: tag 11 fails over to node {d}\n", .{new_df});
    must(new_df == 4, @src());

    // A network-side BUM frame on tag 10 may be delivered by the DF; a frame
    // that ingressed from this very segment must never be reflected back.
    var wan_buf: [df_elect.BumFrame.wire_len]u8 = undefined;
    (df_elect.BumFrame{ .origin = 99, .seq = 1, .ingress_segment = df_elect.no_ingress, .tag = 10 }).encode(&wan_buf);
    const wan = try df_elect.BumFrame.decode(&wan_buf);
    const deliver_wan = role.is_df and df_elect.allowForward(wan.ingress_segment, segment.id);
    std.debug.print("WAN-side frame on tag {d}: deliver={}\n", .{ wan.tag, deliver_wan });
    must(deliver_wan, @src());

    var ce_buf: [df_elect.BumFrame.wire_len]u8 = undefined;
    (df_elect.BumFrame{ .origin = 3, .seq = 2, .ingress_segment = segment.id, .tag = 10 }).encode(&ce_buf);
    const ce = try df_elect.BumFrame.decode(&ce_buf);
    const deliver_ce = role.is_df and df_elect.allowForward(ce.ingress_segment, segment.id);
    std.debug.print("same-segment frame: deliver={} (must be false)\n", .{deliver_ce});
    must(!deliver_ce, @src());

    // A truncated frame off the wire is rejected by name, not a panic.
    if (df_elect.Hello.decode(hello_buf[0..3])) |_| {
        must(false, @src());
    } else |err| switch (err) {
        error.Truncated => std.debug.print("truncated Hello correctly rejected\n", .{}),
        error.InvalidEncoding => return err,
    }
}
