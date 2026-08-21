// SPDX-License-Identifier: MIT

//! What a consumer does with `conntrack` without a kernel: build the exact
//! request bytes `Socket.get` would send over `NETLINK_NETFILTER`, and
//! decode a hand-assembled `IPCTNL_MSG_CT_NEW` reply the way `EventIterator`
//! and the dump engine do — down to the wire, never opening a socket. The
//! whole ctnetlink attribute grammar (`wire.appendTuple`, `wire.CTA.*`) is
//! public precisely so a consumer can build/inspect these messages offline,
//! e.g. to log what would be sent or to replay a packet capture.
//!
//! Built against the PUBLISHED module (`@import("conntrack")`) only — plus
//! the sibling `netlink` module, whose attribute codec `conntrack` itself is
//! built on and re-exports nothing of its own (see the finding below).

const std = @import("std");
const conntrack = @import("conntrack");
const netlink = @import("netlink");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── build a GET request and show its wire bytes ─────────────────────
    // `buildGetRequest` is exactly what `Socket.get` sends; a consumer that
    // wants to log/replay the request without a live socket gets the same
    // bytes a packet capture would show.
    const tuple: conntrack.Tuple = .{
        .src = .{ .v4 = .{ 10, 0, 0, 1 } },
        .dst = .{ .v4 = .{ 10, 0, 0, 2 } },
        .proto = conntrack.IPPROTO.UDP,
        .src_port = 5000,
        .dst_port = 53,
    };
    const req = try conntrack.buildGetRequest(gpa, 1, .ipv4, .orig, tuple);
    defer gpa.free(req);
    std.debug.print("GET request: {d} bytes, first byte 0x{x:0>2} (nfgen_family=ipv4)\n", .{
        req.len,
        req[netlink.codec.header_len],
    });

    // ── decode a hand-assembled reply, the way EventIterator would ──────
    // A real reply comes off the kernel socket; here it is built with the
    // same public helpers `wire.appendTuple` uses internally, then decoded
    // with the exact function `EventIterator`/`dump` call.
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(gpa);
    try conntrack.wire.appendNfgenmsg(gpa, &payload, .ipv4, 0);
    try conntrack.wire.appendTuple(gpa, &payload, conntrack.wire.CTA.TUPLE_ORIG, tuple);
    try conntrack.wire.appendTuple(gpa, &payload, conntrack.wire.CTA.TUPLE_REPLY, tuple.invert());
    try netlink.codec.appendAttrBe32(gpa, &payload, conntrack.wire.CTA.STATUS, conntrack.IPS.SEEN_REPLY | conntrack.IPS.ASSURED);
    try netlink.codec.appendAttrBe32(gpa, &payload, conntrack.wire.CTA.TIMEOUT, 120);

    const flow = try conntrack.decodeFlow(payload.items);
    std.debug.print(
        "decoded flow: family={s} proto={d} src_port={d} dst_port={d} assured={}\n",
        .{
            @tagName(flow.family),
            flow.orig.proto.?,
            flow.orig.src_port.?,
            flow.orig.dst_port.?,
            flow.hasStatus(conntrack.IPS.ASSURED),
        },
    );

    // A truncated reply never panics — it is the first thing done with
    // kernel-delivered bytes on an event socket.
    if (conntrack.decodeFlow(payload.items[0 .. payload.items.len - 2])) |_| {
        return error.TruncatedReplyShouldHaveFailed;
    } else |err| switch (err) {
        error.Truncated, error.BadLength => std.debug.print("truncated reply rejected: {s}\n", .{@errorName(err)}),
        else => return err,
    }
}
