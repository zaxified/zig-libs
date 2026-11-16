// SPDX-License-Identifier: MIT

//! What a server behind a load balancer does with `proxyproto`, both sides of
//! the wire in one process:
//!
//! 1. The balancer side writes a v2 header (with an ALPN TLV and the CRC32C
//!    TLV) in front of the client's first bytes.
//! 2. The server side reads it over a `std.Io.Reader` from a TRUSTED peer and
//!    learns the real client address; the client's bytes stay in the reader
//!    for the real protocol.
//! 3. The same bytes from a peer NOT in the trusted list are refused.
//! 4. A connection without a header (a health check that speaks HTTP
//!    directly) leaves every byte for the protocol.
//! 5. The v1 text form, as older balancers send it.
//!
//! This is an example in the gate sense: built against the PUBLISHED module
//! (`deps` only), so a type or error the API needs but does not export stops
//! it compiling.

const std = @import("std");
const pp = @import("proxyproto");
const netaddr = @import("netaddr");

pub fn main() !void {
    const balancer = netaddr.parseIp("10.0.0.5").?;
    const stranger = netaddr.parseIp("203.0.113.9").?;
    const trusted = [_]netaddr.Prefix{netaddr.parsePrefix("10.0.0.0/24").?};

    const hdr: pp.Header = .{
        .family = .tcp4,
        .source = .{ .inet = .{ .ip = netaddr.parseIp("198.51.100.7").?, .port = 51234 } },
        .destination = .{ .inet = .{ .ip = netaddr.parseIp("192.0.2.10").?, .port = 443 } },
    };
    // One TLV: ALPN "h2" (type 0x01, length 2).
    const tlvs = [_]u8{ pp.tlv_type.alpn, 0, 2, 'h', '2' };
    const request = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";

    // 1. Balancer side.
    var wire_buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&wire_buf);
    try pp.writeV2Crc(&w, hdr, &tlvs);
    try w.writeAll(request);
    const wire = w.buffered();
    std.debug.print("balancer wrote {d} header bytes + {d} request bytes\n", .{ wire.len - request.len, request.len });

    // 2. Server side, trusted peer.
    {
        var r: std.Io.Reader = .fixed(wire);
        var hbuf: [pp.default_max_v2_len]u8 = undefined;
        const got = (try pp.read(&r, &hbuf, .{ .peer = balancer, .trusted = &trusted, .required = true })) orelse
            return error.NoHeader;
        const src = got.source.?.inet;
        std.debug.print("trusted peer: client {f} port {d}, alpn {s}\n", .{ src.ip, src.port, (try got.alpn()).? });
        if (src.port != 51234 or !std.mem.eql(u8, (try got.alpn()).?, "h2")) return error.WrongHeader;
        // The client's request is still in the reader, untouched.
        const rest = r.buffered();
        if (!std.mem.eql(u8, rest, request)) return error.RequestLost;
        std.debug.print("request left for the protocol: {d} bytes\n", .{rest.len});
    }

    // 3. The same bytes from a peer outside the trusted list.
    {
        var r: std.Io.Reader = .fixed(wire);
        var hbuf: [pp.default_max_v2_len]u8 = undefined;
        if (pp.read(&r, &hbuf, .{ .peer = stranger, .trusted = &trusted })) |_| {
            return error.StrangerAccepted;
        } else |err| switch (err) {
            error.UntrustedPeer => std.debug.print("untrusted peer: refused ({t})\n", .{err}),
            else => return err,
        }
    }

    // 4. No header at all: nothing is consumed.
    {
        var r: std.Io.Reader = .fixed(request);
        var hbuf: [pp.default_max_v2_len]u8 = undefined;
        const got = try pp.read(&r, &hbuf, .{ .peer = balancer, .trusted = &trusted });
        if (got != null or r.buffered().len != request.len) return error.HeaderInvented;
        std.debug.print("no header: all {d} bytes left for the protocol\n", .{r.buffered().len});
    }

    // 5. The v1 text form, parsed from a buffer the caller manages.
    {
        var v1_buf: [pp.max_v1_len]u8 = undefined;
        var w1: std.Io.Writer = .fixed(&v1_buf);
        try pp.writeV1(&w1, hdr);
        const line = w1.buffered();
        std.debug.print("v1 line: {s}", .{line});
        switch (try pp.parse(line)) {
            .header => |p| if (p.consumed != line.len or !p.h.source.?.eql(hdr.source.?)) return error.V1Mismatch,
            else => return error.V1NotParsed,
        }
    }
    std.debug.print("ok\n", .{});
}
