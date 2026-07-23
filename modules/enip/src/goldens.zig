// SPDX-License-Identifier: MIT

//! Byte-exact frames captured from **real traffic between two independent
//! third-party implementations**, recorded through an encapsulation-aware
//! proxy sitting between an EtherNet/IP client and an EtherNet/IP target that
//! are neither of them this module.
//!
//! Two client stacks appear here:
//!
//! * `.cpppo` — the `cpppo` EtherNet/IP client (a mature independent Python
//!   CIP stack that ships both a client and a simulated target). It wraps
//!   every request in an `Unconnected_Send` with a `1/0` route path by
//!   default, and its `--simple` mode sends the bare CIP message, so both
//!   routing shapes are pinned.
//! * `.pycomm3` — the `pycomm3` Logix driver, a second, independently written
//!   stack. It sends **no** `Unconnected_Send` wrapper, uses a
//!   `Large_Forward_Open` where cpppo uses the small form, and stamps its own
//!   sender context — three differences worth having in the table.
//!
//! The target on the other side was the `cpppo` simulated EtherNet/IP server.
//!
//! Both were used **as black boxes only** — to generate wire traffic and to
//! act as a live peer. No third-party source was read as a design reference;
//! under CONVENTIONS §5 that is a test oracle, not a design reference. See
//! SPEC.md.
//!
//! ## Anonymisation
//!
//! Two fields are **length-preserving substitutions**, applied identically
//! everywhere they appear (the `ListIdentity` replies, `Get_Attributes_All`
//! and `Get_Attribute_Single` attribute 7):
//!
//! * the product name `"…-…/… LOGIX…"` the simulator reports → the same
//!   twenty characters `"SIMULATED-CIP-DEVICE"`;
//! * the serial number → `0x00C0FFEE`.
//!
//! Nothing else was touched. Both fields are inside length-prefixed regions,
//! so every frame still decodes and re-encodes byte-identically, and the
//! substitution changes no length, offset or checksum anywhere. It is recorded
//! here because a golden table is exactly where a device identity would
//! otherwise be published by accident.
//!
//! ## What is asserted over the whole table
//!
//! 1. every frame decodes at the encapsulation layer and **re-encodes to the
//!    identical octets**;
//! 2. every data-carrying frame's CPF envelope decodes, obeys the item
//!    ordering rules and re-encodes identically;
//! 3. every CIP request and reply inside decodes and re-encodes identically,
//!    and every request's EPATH is rebuilt **from its decoded segments** — so
//!    the path encoder is what is being checked, not a memcpy;
//! 4. a coverage assertion fails if the table ever stops containing each
//!    encapsulation command, each CPF item type, the routed and unrouted
//!    shapes, connected and unconnected messaging, both `Forward_Open` sizes,
//!    a Multiple Service Packet, both fragmented services and an error reply.

const std = @import("std");
const encap = @import("encap.zig");
const cpf = @import("cpf.zig");
const cip = @import("cip.zig");
const epath = @import("epath.zig");
const connmgr = @import("connmgr.zig");
const types = @import("types.zig");

pub const Direction = enum { to_target, from_target };
pub const Source = enum { cpppo, pycomm3 };
pub const Link = enum { tcp, udp };

pub const Golden = struct {
    name: []const u8,
    dir: Direction,
    source: Source,
    link: Link,
    hex: []const u8,
};

/// Largest captured frame, and therefore the buffer every test here needs.
pub const max_frame_len: usize = 128;

pub const table = [_]Golden{
    .{ .name = "register session request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "65000400000000000000000000000000000000000000000001000000" },
    .{ .name = "register session reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "650004009df34c690000000000000000000000000000000001000000" },
    .{ .name = "list identity request over tcp", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "630000009df34c6900000000000000000000000000000000" },
    .{ .name = "list identity reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "63003c009df34c690000000000000000000000000000000001000c00360001000002af1200000000000000000000000001000e003600140b6031eeffc0001453494d554c415445442d4349502d444556494345ff" },
    .{ .name = "list interfaces request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "640000009df34c6900000000000000000000000000000000" },
    .{ .name = "list interfaces reply with no items", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "640002009df34c69000000000000000000000000000000000000" },
    .{ .name = "list services request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "040000000ddf346e00000000000000000000000000000000" },
    .{ .name = "list services reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "040019000ddf346e0000000000000000000000000000000001000001130001002000436f6d6d756e69636174696f6e7300" },
    .{ .name = "legacy command 0x0001 request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "010000008c14b7e200000000000000000000000000000000" },
    .{ .name = "legacy command 0x0001 reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "01002a008c14b7e200000000000000000000000000000000010001002400010000000002af12000000000000000000000000302e302e302e30000000000000000000" },
    .{ .name = "read tag SCADA direct no route request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "6f001e00ce6d935200000000300000000000000000000000000000000800020000000000b2000e004c05910553434144410028000100" },
    .{ .name = "read tag SCADA direct no route reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "6f001800ce6d935200000000300000000000000000000000000000000800020000000000b2000800cc000000c3000100" },
    .{ .name = "write tag SCADA element 1 INT 42 request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "6f002200ce6d935200000000310000000000000000000000000000000800020000000000b20012004d0591055343414441002801c30001002a00" },
    .{ .name = "write tag SCADA element 1 reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "6f001400ce6d935200000000310000000000000000000000000000000800020000000000b2000400cd000000" },
    .{ .name = "read tag SCADA via unconnected send request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "6f002c000ddf346e00000000300000000000000000000000000000000800020000000000b2001c00520220062401059d0e004c0591055343414441002800010001000100" },
    .{ .name = "read tag SCADA via unconnected send reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "6f0018000ddf346e00000000300000000000000000000000000000000800020000000000b2000800cc000000c3000100" },
    .{ .name = "multiple service packet three reads request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "6f005a004a0bcdfc00000000300000000000000000000000000000000800020000000000b2004a00520220062401059d3c000a022002240103000800160026004c059105534341444100280002004c0691075465737454616700280001004c0691075265616c546167002800010001000100" },
    .{ .name = "multiple service packet three reads reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "6f003a004a0bcdfc00000000300000000000000000000000000000000800020000000000b2002a008a0000000300080012001c00cc000000c30000000000cc000000c4000b000000cc000000ca0000000000" },
    .{ .name = "read tag fragmented SCADA 10 elements request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "6f0030005801593200000000300000000000000000000000000000000800020000000000b2002000520220062401059d12005205910553434144410028000a000000000001000100" },
    .{ .name = "read tag fragmented SCADA 10 elements reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "6f002a005801593200000000300000000000000000000000000000000800020000000000b2001a00d2000000c30000000000000000000000f9ff0000000000000000" },
    .{ .name = "write tag fragmented SCADA 4 INTs request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "6f003a00244fe0cf00000000300000000000000000000000000000000800020000000000b2002a00520220062401059d1c00530591055343414441002800c300040000000000010002000300040001000100" },
    .{ .name = "write tag fragmented SCADA 4 INTs reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "6f001400244fe0cf00000000300000000000000000000000000000000800020000000000b2000400d3000000" },
    .{ .name = "write tag SSTRING hello request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "6f003600570d03ce00000000300000000000000000000000000000000800020000000000b2002600520220062401059d18004d06910853686f72745374722800da0001000568656c6c6f01000100" },
    .{ .name = "write tag SSTRING hello reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "6f001400570d03ce00000000300000000000000000000000000000000800020000000000b2000400cd000000" },
    .{ .name = "read tag SSTRING two elements request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "6f002e00570d03ce00000000310000000000000000000000000000000800020000000000b2001e00520220062401059d10004c06910853686f72745374722800020001000100" },
    .{ .name = "read tag SSTRING two elements reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "6f001d00570d03ce00000000310000000000000000000000000000000800020000000000b2000d00cc000000da000568656c6c6f00" },
    .{ .name = "read tag unknown name request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "6f00300029809b3600000000300000000000000000000000000000000800020000000000b2002000520220062401059d12004c0791094e6f53756368546167002800010001000100" },
    .{ .name = "read tag unknown name encapsulation error reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "6f00000029809b3608000000300000000000000000000000" },
    .{ .name = "read tag against a logical identity path request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "6f0028007b44b1eb00000000300000000000000000000000000000000800020000000000b2001800520220062401059d0a004c03200124013001010001000100" },
    .{ .name = "read tag against a logical identity path error reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "6f0000007b44b1eb08000000300000000000000000000000" },
    .{ .name = "forward open request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "6f004000a36e009500000000000000000000000000000000000000000800020000000000b2003000540220062401059dfecc0000fffffffffecc3412010000000000000080841e00fe4380841e00fe43a303010020022401" },
    .{ .name = "forward open reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "6f002e00a36e009500000000000000000000000000000000000000000800020000000000b2001e00d4000000152114fbfffffffffecc34120100000080841e0080841e000000" },
    .{ .name = "send unit data read tag SCADA sequence 0 request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "70002400a36e0095000000000000000000000000000000000000000008000200a1000400152114fbb100100000004c05910553434144410028000200" },
    .{ .name = "send unit data read tag SCADA sequence 0 reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "70002000a36e0095000000000000000000000000000000000000000008000200a1000400152114fbb1000c000000cc000000c30001000200" },
    .{ .name = "send unit data read tag TestTag sequence 1 request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "70002600a36e0095000000000000000000000000000000000000000008000200a1000400152114fbb100120001004c069107546573745461670028000100" },
    .{ .name = "send unit data read tag TestTag sequence 1 reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "70002000a36e0095000000000000000000000000000000000000000008000200a1000400152114fbb1000c000100cc000000c4000b000000" },
    .{ .name = "forward close request", .dir = .to_target, .source = .cpppo, .link = .tcp, .hex = "6f002800a36e009500000000000000000000000000000000000000000800020000000000b20018004e0220062401059dfecc3412010000000300010020022401" },
    .{ .name = "forward close reply", .dir = .from_target, .source = .cpppo, .link = .tcp, .hex = "6f001e00a36e009500000000000000000000000000000000000000000800020000000000b2000e00ce000000fecc3412010000000000" },
    .{ .name = "register session request with sender context", .dir = .to_target, .source = .pycomm3, .link = .tcp, .hex = "6500040000000000000000005f7079636f6d6d5f0000000001000000" },
    .{ .name = "register session reply with sender context", .dir = .from_target, .source = .pycomm3, .link = .tcp, .hex = "650004005120abd5000000005f7079636f6d6d5f0000000001000000" },
    .{ .name = "list identity request over tcp", .dir = .to_target, .source = .pycomm3, .link = .tcp, .hex = "630000005120abd5000000005f7079636f6d6d5f00000000" },
    .{ .name = "list identity reply", .dir = .from_target, .source = .pycomm3, .link = .tcp, .hex = "63003c005120abd5000000005f7079636f6d6d5f0000000001000c00360001000002af1200000000000000000000000001000e003600140b6031eeffc0001453494d554c415445442d4349502d444556494345ff" },
    .{ .name = "unregister session request", .dir = .to_target, .source = .pycomm3, .link = .tcp, .hex = "660000005120abd5000000005f7079636f6d6d5f00000000" },
    .{ .name = "get attributes all identity request", .dir = .to_target, .source = .pycomm3, .link = .tcp, .hex = "6f00180067f0a726000000005f7079636f6d6d5f00000000000000000a00020000000000b20008000102200124010000" },
    .{ .name = "get attributes all identity reply", .dir = .from_target, .source = .pycomm3, .link = .tcp, .hex = "6f003b0067f0a726000000005f7079636f6d6d5f00000000000000000a00020000000000b2002b008100000001000e003600140b6031eeffc0001453494d554c415445442d4349502d444556494345ff000000" },
    .{ .name = "get attribute single identity vendor id request", .dir = .to_target, .source = .pycomm3, .link = .tcp, .hex = "6f001a0067f0a726000000005f7079636f6d6d5f00000000000000000a00020000000000b2000a000e032001240130010000" },
    .{ .name = "get attribute single identity vendor id reply", .dir = .from_target, .source = .pycomm3, .link = .tcp, .hex = "6f00160067f0a726000000005f7079636f6d6d5f00000000000000000a00020000000000b20006008e0000000100" },
    .{ .name = "get attribute single identity product name request", .dir = .to_target, .source = .pycomm3, .link = .tcp, .hex = "6f001a0067f0a726000000005f7079636f6d6d5f00000000000000000a00020000000000b2000a000e032001240130070000" },
    .{ .name = "get attribute single identity product name reply", .dir = .from_target, .source = .pycomm3, .link = .tcp, .hex = "6f00290067f0a726000000005f7079636f6d6d5f00000000000000000a00020000000000b20019008e0000001453494d554c415445442d4349502d444556494345" },
    .{ .name = "large forward open request", .dir = .to_target, .source = .pycomm3, .link = .tcp, .hex = "6f00420067f0a726000000005f7079636f6d6d5f00000000000000000a00020000000000b20032005b02200624010a05000000005bbca9dc27040910ab4289180700000001402000a00f004201402000a00f0042a30220022401" },
    .{ .name = "large forward open reply", .dir = .from_target, .source = .pycomm3, .link = .tcp, .hex = "6f002e0067f0a726000000005f7079636f6d6d5f00000000000000000a00020000000000b2001e00db000000f12ea2835bbca9dc27040910ab42891801402000014020000000" },
    .{ .name = "send unit data get attributes all request", .dir = .to_target, .source = .pycomm3, .link = .tcp, .hex = "70001c0067f0a726000000005f7079636f6d6d5f00000000000000000a000200a1000400f12ea283b10008000100010220012401" },
    .{ .name = "send unit data get attributes all reply", .dir = .from_target, .source = .pycomm3, .link = .tcp, .hex = "7000410067f0a726000000005f7079636f6d6d5f00000000000000000a000200a1000400f12ea283b1002d0001008100000001000e003600140b6031eeffc0001453494d554c415445442d4349502d444556494345ff000000" },
    .{ .name = "forward close request", .dir = .to_target, .source = .pycomm3, .link = .tcp, .hex = "6f00260067f0a726000000005f7079636f6d6d5f00000000000000000a00020000000000b20016004e02200624010a0527040910ab428918020020022401" },
    .{ .name = "forward close reply", .dir = .from_target, .source = .pycomm3, .link = .tcp, .hex = "6f001e0067f0a726000000005f7079636f6d6d5f00000000000000000a00020000000000b2000e00ce00000027040910ab4289180000" },
    .{ .name = "get attribute single unknown attribute request", .dir = .to_target, .source = .pycomm3, .link = .tcp, .hex = "6f001a008c5d6ad2000000005f7079636f6d6d5f00000000000000000a00020000000000b2000a000e032001240130630000" },
    .{ .name = "get attribute single unknown attribute error reply", .dir = .from_target, .source = .pycomm3, .link = .tcp, .hex = "6f0014008c5d6ad2000000005f7079636f6d6d5f00000000000000000a00020000000000b20004008e000800" },
    .{ .name = "get attribute single unknown class request", .dir = .to_target, .source = .pycomm3, .link = .tcp, .hex = "6f001a008c5d6ad2000000005f7079636f6d6d5f00000000000000000a00020000000000b2000a000e032077240130010000" },
    .{ .name = "get attribute single unknown class encapsulation error reply", .dir = .from_target, .source = .pycomm3, .link = .tcp, .hex = "6f0000008c5d6ad2080000005f7079636f6d6d5f00000000" },
    .{ .name = "udp broadcast list identity request", .dir = .to_target, .source = .cpppo, .link = .udp, .hex = "630000000000000000000000000000000000000000000000" },
    .{ .name = "udp broadcast list identity reply", .dir = .from_target, .source = .cpppo, .link = .udp, .hex = "63003c00000000000000000000000000000000000000000001000c00360001000002af1200000000000000000000000001000e003600140b6031eeffc0001453494d554c415445442d4349502d444556494345ff" },
};

/// Decodes a golden's hex into `buf`.
pub fn bytesOf(g: Golden, buf: []u8) ![]u8 {
    const n = g.hex.len / 2;
    if (n > buf.len) return error.BufferTooSmall;
    _ = try std.fmt.hexToBytes(buf[0..n], g.hex);
    return buf[0..n];
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "every golden decodes at the encapsulation layer and re-encodes exactly" {
    var buf: [max_frame_len]u8 = undefined;
    var round: [max_frame_len]u8 = undefined;
    for (table) |g| {
        const wire = try bytesOf(g, &buf);
        const msg = encap.decode(wire) catch |e| {
            std.debug.print("golden '{s}' failed to decode: {t}\n", .{ g.name, e });
            return e;
        };
        const again = try encap.encode(msg, &round);
        testing.expectEqualSlices(u8, wire, again) catch |e| {
            std.debug.print("golden '{s}' did not re-encode\n", .{g.name});
            return e;
        };
    }
}

/// A frame's decoded CPF envelope, or null when the frame carries none.
fn envelopeOf(msg: encap.Message, storage: []cpf.Item) !?cpf.Envelope {
    switch (msg.command) {
        .send_rr_data, .send_unit_data => {},
        else => return null,
    }
    // An error reply carries no body at all, which is legal and is exactly
    // what two of the captured replies do.
    if (!msg.status.isSuccess() or msg.data.len == 0) return null;
    return try cpf.decodeEnvelope(msg.data, storage);
}

test "every data-carrying golden's CPF envelope obeys the ordering rules and re-encodes" {
    var buf: [max_frame_len]u8 = undefined;
    var round: [max_frame_len]u8 = undefined;
    var storage: [8]cpf.Item = undefined;
    var checked: usize = 0;
    for (table) |g| {
        const wire = try bytesOf(g, &buf);
        const msg = try encap.decode(wire);
        const env = (try envelopeOf(msg, &storage)) orelse continue;
        cpf.validateDataOrder(env.list) catch |e| {
            std.debug.print("golden '{s}' has a bad CPF item order\n", .{g.name});
            return e;
        };
        const again = try cpf.encodeEnvelope(
            env.interface_handle,
            env.timeout,
            env.list.items,
            &round,
        );
        testing.expectEqualSlices(u8, msg.data, again) catch |e| {
            std.debug.print("golden '{s}' CPF did not re-encode\n", .{g.name});
            return e;
        };
        checked += 1;
    }
    try testing.expect(checked >= 30);
}

/// The CIP message inside a frame, with the connected-data sequence count
/// stripped where there is one.
fn cipOf(msg: encap.Message, storage: []cpf.Item) !?[]const u8 {
    const env = (try envelopeOf(msg, storage)) orelse return null;
    const item = env.list.dataItem() orelse return null;
    return switch (item.type_id) {
        .unconnected_data => item.data,
        .connected_data => (try cpf.ConnectedData.decode(item)).payload,
        else => null,
    };
}

test "every CIP message inside a golden re-encodes, and every path from its segments" {
    var buf: [max_frame_len]u8 = undefined;
    var round: [max_frame_len]u8 = undefined;
    var path_round: [max_frame_len]u8 = undefined;
    var storage: [8]cpf.Item = undefined;
    var requests: usize = 0;
    var replies: usize = 0;
    for (table) |g| {
        const wire = try bytesOf(g, &buf);
        const msg = try encap.decode(wire);
        const body = (try cipOf(msg, &storage)) orelse continue;
        if (g.dir == .to_target) {
            const req = cip.Request.decode(body) catch |e| {
                std.debug.print("golden '{s}' CIP request failed: {t}\n", .{ g.name, e });
                return e;
            };
            // The path is rebuilt from its *decoded segments*, so the EPATH
            // encoder is what is under test rather than a copy.
            const path_again = epath.reencode(req.path, &path_round) catch |e| {
                std.debug.print("golden '{s}' EPATH failed: {t}\n", .{ g.name, e });
                return e;
            };
            testing.expectEqualSlices(u8, req.path, path_again) catch |e| {
                std.debug.print("golden '{s}' EPATH did not re-encode\n", .{g.name});
                return e;
            };
            const again = try req.encode(&round);
            testing.expectEqualSlices(u8, body, again) catch |e| {
                std.debug.print("golden '{s}' CIP request did not re-encode\n", .{g.name});
                return e;
            };
            requests += 1;
        } else {
            const rep = cip.Reply.decode(body) catch |e| {
                std.debug.print("golden '{s}' CIP reply failed: {t}\n", .{ g.name, e });
                return e;
            };
            const again = try rep.encode(&round);
            testing.expectEqualSlices(u8, body, again) catch |e| {
                std.debug.print("golden '{s}' CIP reply did not re-encode\n", .{g.name});
                return e;
            };
            replies += 1;
        }
    }
    try testing.expect(requests >= 15);
    try testing.expect(replies >= 15);
}

test "every Unconnected_Send and Forward_Open body re-encodes from its fields" {
    var buf: [max_frame_len]u8 = undefined;
    var round: [max_frame_len]u8 = undefined;
    var storage: [8]cpf.Item = undefined;
    var wrapped: usize = 0;
    var opens: usize = 0;
    var closes: usize = 0;
    for (table) |g| {
        if (g.dir != .to_target) continue;
        const wire = try bytesOf(g, &buf);
        const msg = try encap.decode(wire);
        const body = (try cipOf(msg, &storage)) orelse continue;
        const req = try cip.Request.decode(body);
        const class = (try req.classCode()) orelse continue;
        if (class != connmgr.class_code) continue;
        switch (req.service) {
            connmgr.Service.unconnected_send => {
                const us = try connmgr.UnconnectedSend.decode(req.data);
                const again = try us.encode(&round);
                try testing.expectEqualSlices(u8, req.data, again);
                // …and the embedded message is itself a valid CIP request.
                _ = try cip.Request.decode(us.embedded);
                wrapped += 1;
            },
            connmgr.Service.forward_open, connmgr.Service.large_forward_open => {
                const large = req.service == connmgr.Service.large_forward_open;
                const fo = try connmgr.ForwardOpen.decode(req.data, large);
                const again = try fo.encode(&round);
                try testing.expectEqualSlices(u8, req.data, again);
                opens += 1;
            },
            connmgr.Service.forward_close => {
                const fc = try connmgr.ForwardClose.decode(req.data);
                const again = try fc.encode(&round);
                try testing.expectEqualSlices(u8, req.data, again);
                closes += 1;
            },
            else => {},
        }
    }
    try testing.expect(wrapped >= 5);
    try testing.expectEqual(@as(usize, 2), opens);
    try testing.expectEqual(@as(usize, 2), closes);
}

// ── field-by-field assertions on a representative subset ───────────────────

fn find(name: []const u8) Golden {
    for (table) |g| {
        if (std.mem.eql(u8, g.name, name)) return g;
    }
    unreachable;
}

fn decodeNamed(name: []const u8, buf: []u8) !encap.Message {
    const wire = try bytesOf(find(name), buf);
    return encap.decode(wire);
}

test "the register session exchange" {
    var buf: [max_frame_len]u8 = undefined;
    const req = try decodeNamed("register session request", &buf);
    try testing.expectEqual(encap.Command.register_session, req.command);
    try testing.expectEqual(@as(u32, 0), req.session_handle);
    const rs = try encap.RegisterSessionData.decode(req.data);
    try testing.expectEqual(@as(u16, 1), rs.version);
    try testing.expectEqual(@as(u16, 0), rs.options_flags);

    var buf2: [max_frame_len]u8 = undefined;
    const rep = try decodeNamed("register session reply", &buf2);
    try testing.expect(rep.session_handle != 0);
    try testing.expect(rep.status.isSuccess());

    // The second stack stamps a sender context and the target echoes it.
    var buf3: [max_frame_len]u8 = undefined;
    const ctx_req = try decodeNamed("register session request with sender context", &buf3);
    var buf4: [max_frame_len]u8 = undefined;
    const ctx_rep = try decodeNamed("register session reply with sender context", &buf4);
    try testing.expectEqualSlices(u8, &ctx_req.sender_context, &ctx_rep.sender_context);
    try testing.expect(!std.mem.allEqual(u8, &ctx_req.sender_context, 0));
}

test "the list identity reply carries a full CIP identity item" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("list identity reply", &buf);
    var storage: [4]cpf.Item = undefined;
    const list = try cpf.decode(msg.data, &storage);
    try testing.expectEqual(@as(usize, 1), list.items.len);
    const item = list.find(.list_identity_response).?;
    const ident = try encap.Identity.decode(item.data);
    try testing.expectEqual(@as(u16, 1), ident.encapsulation_version);
    try testing.expectEqual(@as(u16, 1), ident.vendor_id);
    try testing.expectEqual(@as(u16, 14), ident.device_type);
    try testing.expectEqual(@as(u16, 54), ident.product_code);
    try testing.expectEqual(@as(u8, 20), ident.revision_major);
    try testing.expectEqual(@as(u8, 11), ident.revision_minor);
    try testing.expectEqual(@as(u32, 0x00C0FFEE), ident.serial_number);
    try testing.expectEqualStrings("SIMULATED-CIP-DEVICE", ident.product_name);
    try testing.expectEqual(encap.DeviceState.unimplemented, ident.state);
    // The socket address inside is big-endian: port 44818 on the wire.
    try testing.expectEqual(@as(u16, 44818), ident.socket_address.port);
    try testing.expectEqual(@as(i16, 2), ident.socket_address.family);
}

test "the same identity arrives over a UDP broadcast" {
    var buf: [max_frame_len]u8 = undefined;
    const req = try decodeNamed("udp broadcast list identity request", &buf);
    try testing.expectEqual(encap.Command.list_identity, req.command);
    try testing.expectEqual(@as(usize, 24), req.total_len);
    try testing.expectEqual(@as(u32, 0), req.session_handle);

    var buf2: [max_frame_len]u8 = undefined;
    const rep = try decodeNamed("udp broadcast list identity reply", &buf2);
    // A discovery reply carries no session handle: the datagram is unsolicited
    // as far as the session layer is concerned.
    try testing.expectEqual(@as(u32, 0), rep.session_handle);
    var storage: [4]cpf.Item = undefined;
    const list = try cpf.decode(rep.data, &storage);
    const ident = try encap.Identity.decode(list.find(.list_identity_response).?.data);
    try testing.expectEqualStrings("SIMULATED-CIP-DEVICE", ident.product_name);
}

test "the list services reply's name is 15 octets, not the spec's 16" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("list services reply", &buf);
    var storage: [4]cpf.Item = undefined;
    const list = try cpf.decode(msg.data, &storage);
    const item = list.find(.list_services_response).?;
    const svc = try encap.Service.decode(item.data);
    try testing.expectEqual(@as(u16, 1), svc.version);
    try testing.expectEqual(encap.Service.supports_tcp_encapsulation, svc.capability_flags);
    try testing.expectEqualStrings("Communications", svc.trimmedName());
    try testing.expectEqual(@as(usize, 15), svc.name.len);
}

test "list interfaces answers an empty item list, which is legal" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("list interfaces reply with no items", &buf);
    var storage: [4]cpf.Item = undefined;
    const list = try cpf.decode(msg.data, &storage);
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "an unrouted read tag is the bare CIP message in a null-address CPF" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("read tag SCADA direct no route request", &buf);
    var storage: [4]cpf.Item = undefined;
    const env = try cpf.decodeEnvelope(msg.data, &storage);
    try testing.expectEqual(@as(u32, 0), env.interface_handle);
    try cpf.validateDataOrder(env.list);
    try testing.expectEqual(cpf.ItemType.null_address, env.list.addressItem().?.type_id);
    try testing.expectEqual(@as(usize, 0), env.list.addressItem().?.data.len);

    const req = try cip.Request.decode(env.list.dataItem().?.data);
    try testing.expectEqual(cip.LogixService.read_tag, req.service);
    try testing.expectEqualStrings("SCADA", (try epath.findSymbol(req.path)).?);
    try testing.expectEqual(@as(?u32, 0), try epath.findLogical(req.path, .member));
    try testing.expectEqual(@as(u16, 1), (try types.ReadTagRequest.decode(req.data)).count);

    var buf2: [max_frame_len]u8 = undefined;
    const rep_msg = try decodeNamed("read tag SCADA direct no route reply", &buf2);
    var storage2: [4]cpf.Item = undefined;
    const rep_env = try cpf.decodeEnvelope(rep_msg.data, &storage2);
    const rep = try cip.Reply.decode(rep_env.list.dataItem().?.data);
    try testing.expectEqual(cip.LogixService.read_tag, rep.service);
    try testing.expect(rep.general_status.isSuccess());
    const td = try types.TagData.decode(rep.data);
    try testing.expectEqual(types.DataType.int, td.type);
    try testing.expectEqual(@as(?usize, 1), td.elementCount());
    try testing.expectEqual(@as(i64, 1), (try td.at(0)).asInt().?);
}

test "a routed read tag carries an Unconnected_Send with a backplane route" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("read tag SCADA via unconnected send request", &buf);
    var storage: [4]cpf.Item = undefined;
    const env = try cpf.decodeEnvelope(msg.data, &storage);
    const outer = try cip.Request.decode(env.list.dataItem().?.data);
    try testing.expectEqual(connmgr.Service.unconnected_send, outer.service);
    try testing.expectEqual(@as(?u32, connmgr.class_code), try outer.classCode());
    const us = try connmgr.UnconnectedSend.decode(outer.data);
    try testing.expectEqual(@as(u8, 5), us.timeout.priority_time_tick);
    try testing.expectEqual(@as(u8, 157), us.timeout.timeout_ticks);
    try testing.expectEqual(@as(u32, 5024), us.timeout.milliseconds());
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00 }, us.route_path);
    var it = epath.Iterator.init(us.route_path);
    const seg = (try it.next()).?;
    try testing.expectEqual(@as(u16, 1), seg.port.port);
    try testing.expectEqualSlices(u8, &[_]u8{0}, seg.port.link);
    const inner = try cip.Request.decode(us.embedded);
    try testing.expectEqual(cip.LogixService.read_tag, inner.service);
    try testing.expectEqualStrings("SCADA", (try epath.findSymbol(inner.path)).?);
}

test "the multiple service packet's offsets are relative to the count field" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("multiple service packet three reads request", &buf);
    var storage: [4]cpf.Item = undefined;
    const env = try cpf.decodeEnvelope(msg.data, &storage);
    const outer = try cip.Request.decode(env.list.dataItem().?.data);
    const us = try connmgr.UnconnectedSend.decode(outer.data);
    const inner = try cip.Request.decode(us.embedded);
    try testing.expectEqual(@intFromEnum(cip.Service.multiple_service_packet), inner.service);
    try testing.expectEqual(
        @as(?u32, @intFromEnum(cip.ClassCode.message_router)),
        try inner.classCode(),
    );
    const ms = try cip.MultipleService.decode(inner.data);
    try testing.expectEqual(@as(usize, 3), ms.count);
    // Three offsets, so the first message starts at 2 + 3*2 = 8.
    try testing.expectEqual(@as(u16, 8), std.mem.readInt(u16, inner.data[2..4], .little));
    const names = [_][]const u8{ "SCADA", "TestTag", "RealTag" };
    for (names, 0..) |want, i| {
        const sub = try cip.Request.decode(try ms.at(i));
        try testing.expectEqual(cip.LogixService.read_tag, sub.service);
        try testing.expectEqualStrings(want, (try epath.findSymbol(sub.path)).?);
    }
    // …and the reply's table has the same shape with different offsets.
    var buf2: [max_frame_len]u8 = undefined;
    const rep_msg = try decodeNamed("multiple service packet three reads reply", &buf2);
    var storage2: [4]cpf.Item = undefined;
    const rep_env = try cpf.decodeEnvelope(rep_msg.data, &storage2);
    const rep = try cip.Reply.decode(rep_env.list.dataItem().?.data);
    try testing.expectEqual(@intFromEnum(cip.Service.multiple_service_packet), rep.service);
    const rms = try cip.MultipleService.decode(rep.data);
    try testing.expectEqual(@as(usize, 3), rms.count);
    const want_types = [_]types.DataType{ .int, .dint, .real };
    for (want_types, 0..) |want, i| {
        const sub = try cip.Reply.decode(try rms.at(i));
        try testing.expect(sub.general_status.isSuccess());
        try testing.expectEqual(want, (try types.TagData.decode(sub.data)).type);
    }
}

test "the fragmented read carries a byte offset and the reply ten INTs" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("read tag fragmented SCADA 10 elements request", &buf);
    var storage: [4]cpf.Item = undefined;
    const env = try cpf.decodeEnvelope(msg.data, &storage);
    const outer = try cip.Request.decode(env.list.dataItem().?.data);
    const us = try connmgr.UnconnectedSend.decode(outer.data);
    const inner = try cip.Request.decode(us.embedded);
    // 0x52 on a symbolic path is Read Tag Fragmented, *not* Unconnected_Send.
    try testing.expectEqual(cip.LogixService.read_tag_fragmented, inner.service);
    try testing.expectEqual(@as(?u32, null), try inner.classCode());
    const r = try types.ReadTagFragmentedRequest.decode(inner.data);
    try testing.expectEqual(@as(u16, 10), r.count);
    try testing.expectEqual(@as(u32, 0), r.byte_offset);

    var buf2: [max_frame_len]u8 = undefined;
    const rep_msg = try decodeNamed("read tag fragmented SCADA 10 elements reply", &buf2);
    var storage2: [4]cpf.Item = undefined;
    const rep_env = try cpf.decodeEnvelope(rep_msg.data, &storage2);
    const rep = try cip.Reply.decode(rep_env.list.dataItem().?.data);
    try testing.expectEqual(cip.LogixService.read_tag_fragmented, rep.service);
    try testing.expect(rep.general_status.isSuccess());
    const td = try types.TagData.decode(rep.data);
    try testing.expectEqual(types.DataType.int, td.type);
    try testing.expectEqual(@as(?usize, 10), td.elementCount());
    try testing.expectEqual(@as(i64, -7), (try td.at(5)).asInt().?);
}

test "the fragmented write puts its offset between the count and the values" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("write tag fragmented SCADA 4 INTs request", &buf);
    var storage: [4]cpf.Item = undefined;
    const env = try cpf.decodeEnvelope(msg.data, &storage);
    const outer = try cip.Request.decode(env.list.dataItem().?.data);
    const us = try connmgr.UnconnectedSend.decode(outer.data);
    const inner = try cip.Request.decode(us.embedded);
    try testing.expectEqual(cip.LogixService.write_tag_fragmented, inner.service);
    const w = try types.WriteTagFragmentedRequest.decode(inner.data);
    try testing.expectEqual(types.DataType.int, w.type);
    try testing.expectEqual(@as(u16, 4), w.count);
    try testing.expectEqual(@as(u32, 0), w.byte_offset);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 0, 2, 0, 3, 0, 4, 0 }, w.values);
}

test "a SHORT_STRING round trips through a write and a read" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("write tag SSTRING hello request", &buf);
    var storage: [4]cpf.Item = undefined;
    const env = try cpf.decodeEnvelope(msg.data, &storage);
    const us = try connmgr.UnconnectedSend.decode(
        (try cip.Request.decode(env.list.dataItem().?.data)).data,
    );
    const inner = try cip.Request.decode(us.embedded);
    try testing.expectEqual(cip.LogixService.write_tag, inner.service);
    // "ShortStr" is eight characters, so the symbol segment has **no** pad.
    try testing.expectEqualStrings("ShortStr", (try epath.findSymbol(inner.path)).?);
    try testing.expectEqual(@as(usize, 6 * 2), inner.path.len);
    const w = try types.WriteTagRequest.decode(inner.data);
    try testing.expectEqual(types.DataType.short_string, w.type);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x05, 'h', 'e', 'l', 'l', 'o' }, w.values);

    var buf2: [max_frame_len]u8 = undefined;
    const rep_msg = try decodeNamed("read tag SSTRING two elements reply", &buf2);
    var storage2: [4]cpf.Item = undefined;
    const rep_env = try cpf.decodeEnvelope(rep_msg.data, &storage2);
    const rep = try cip.Reply.decode(rep_env.list.dataItem().?.data);
    const td = try types.TagData.decode(rep.data);
    try testing.expectEqual(types.DataType.short_string, td.type);
    try testing.expectEqualStrings("hello", (try td.at(0)).string);
    try testing.expectEqualStrings("", (try td.at(1)).string);
}

test "the forward open handshake and the connection it opens" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("forward open request", &buf);
    var storage: [4]cpf.Item = undefined;
    const env = try cpf.decodeEnvelope(msg.data, &storage);
    const req = try cip.Request.decode(env.list.dataItem().?.data);
    try testing.expectEqual(connmgr.Service.forward_open, req.service);
    const fo = try connmgr.ForwardOpen.decode(req.data, false);
    try testing.expectEqual(@as(u16, 510), fo.o_to_t_params.size);
    try testing.expect(fo.o_to_t_params.variable);
    try testing.expectEqual(connmgr.ConnectionType.point_to_point, fo.t_to_o_params.connection_type);
    try testing.expectEqual(@as(u32, 2_000_000), fo.o_to_t_rpi);
    try testing.expect(fo.transport_class.server);
    try testing.expectEqual(@as(u4, 3), fo.transport_class.class);
    // Route, then the message router at the far end.
    try testing.expectEqual(@as(usize, 3), try epath.countSegments(fo.connection_path));
    try testing.expectEqual(
        @as(?u32, @intFromEnum(cip.ClassCode.message_router)),
        try epath.findLogical(fo.connection_path, .class),
    );

    var buf2: [max_frame_len]u8 = undefined;
    const rep_msg = try decodeNamed("forward open reply", &buf2);
    var storage2: [4]cpf.Item = undefined;
    const rep_env = try cpf.decodeEnvelope(rep_msg.data, &storage2);
    const rep = try cip.Reply.decode(rep_env.list.dataItem().?.data);
    try testing.expect(rep.general_status.isSuccess());
    const fr = try connmgr.ForwardOpenReply.decode(rep.data);
    // The target replaced the originator's placeholder O→T id with its own…
    try testing.expect(fr.o_to_t_connection_id != fo.o_to_t_connection_id);
    // …and echoed the triple unchanged, which is what a close will match on.
    try testing.expectEqual(fo.connection_serial, fr.connection_serial);
    try testing.expectEqual(fo.originator_vendor_id, fr.originator_vendor_id);
    try testing.expectEqual(fo.originator_serial, fr.originator_serial);

    // The connected messages that follow use that id and count sequences.
    var buf3: [max_frame_len]u8 = undefined;
    const unit = try decodeNamed("send unit data read tag SCADA sequence 0 request", &buf3);
    var storage3: [4]cpf.Item = undefined;
    const unit_env = try cpf.decodeEnvelope(unit.data, &storage3);
    try cpf.validateDataOrder(unit_env.list);
    try testing.expectEqual(
        fr.o_to_t_connection_id,
        try cpf.connectionId(unit_env.list.addressItem().?),
    );
    // The envelope timeout is meaningless on a connected send — the
    // connection's own timeout governs — and the two captured stacks put
    // different values in it (8 and 10). It is decoded and preserved rather
    // than validated, because validating it would reject real traffic.
    try testing.expectEqual(@as(u16, 8), unit_env.timeout);
    const cd = try cpf.ConnectedData.decode(unit_env.list.dataItem().?);
    try testing.expectEqual(@as(u16, 0), cd.sequence_count);
    var buf4: [max_frame_len]u8 = undefined;
    const unit2 = try decodeNamed("send unit data read tag TestTag sequence 1 request", &buf4);
    var storage4: [4]cpf.Item = undefined;
    const unit2_env = try cpf.decodeEnvelope(unit2.data, &storage4);
    try testing.expectEqual(
        @as(u16, 1),
        (try cpf.ConnectedData.decode(unit2_env.list.dataItem().?)).sequence_count,
    );

    // The close matches the triple and the target confirms it.
    var buf5: [max_frame_len]u8 = undefined;
    const close = try decodeNamed("forward close request", &buf5);
    var storage5: [4]cpf.Item = undefined;
    const close_env = try cpf.decodeEnvelope(close.data, &storage5);
    const close_req = try cip.Request.decode(close_env.list.dataItem().?.data);
    try testing.expectEqual(connmgr.Service.forward_close, close_req.service);
    const fc = try connmgr.ForwardClose.decode(close_req.data);
    try testing.expectEqual(fo.connection_serial, fc.connection_serial);
    try testing.expectEqual(fo.originator_vendor_id, fc.originator_vendor_id);
    try testing.expectEqual(fo.originator_serial, fc.originator_serial);
}

test "the second stack opens a large connection the small form cannot express" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("large forward open request", &buf);
    var storage: [4]cpf.Item = undefined;
    const env = try cpf.decodeEnvelope(msg.data, &storage);
    const req = try cip.Request.decode(env.list.dataItem().?.data);
    try testing.expectEqual(connmgr.Service.large_forward_open, req.service);
    const fo = try connmgr.ForwardOpen.decode(req.data, true);
    try testing.expectEqual(@as(u16, 4000), fo.o_to_t_params.size);
    // 4000 does not fit the nine bits the small form has, which is the whole
    // reason this service exists.
    try testing.expect(fo.o_to_t_params.size > connmgr.ConnectionParameters.max_small_size);
    try testing.expectEqual(@as(?u16, null), fo.o_to_t_params.toU16());
    try testing.expectEqual(@as(u8, 7), fo.connection_timeout_multiplier);
    // This stack routes nothing: the connection path is just the message router.
    try testing.expectEqual(@as(usize, 2), try epath.countSegments(fo.connection_path));
}

test "the identity object answers Get_Attributes_All and Get_Attribute_Single" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("get attributes all identity request", &buf);
    var storage: [4]cpf.Item = undefined;
    const env = try cpf.decodeEnvelope(msg.data, &storage);
    // This stack sends no Unconnected_Send at all — the CIP message is bare.
    const req = try cip.Request.decode(env.list.dataItem().?.data);
    try testing.expectEqual(@intFromEnum(cip.Service.get_attributes_all), req.service);
    try testing.expectEqual(@as(?u32, @intFromEnum(cip.ClassCode.identity)), try req.classCode());
    // …and it asks for a ten-second encapsulation timeout where cpppo asks 0.
    try testing.expectEqual(@as(u16, 10), env.timeout);

    var buf2: [max_frame_len]u8 = undefined;
    const rep_msg = try decodeNamed("get attributes all identity reply", &buf2);
    var storage2: [4]cpf.Item = undefined;
    const rep_env = try cpf.decodeEnvelope(rep_msg.data, &storage2);
    const rep = try cip.Reply.decode(rep_env.list.dataItem().?.data);
    try testing.expect(rep.general_status.isSuccess());
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, rep.data[0..2], .little));
    try testing.expectEqual(@as(u32, 0x00C0FFEE), std.mem.readInt(u32, rep.data[10..14], .little));
    try testing.expectEqual(@as(u8, 20), rep.data[14]);
    try testing.expectEqualStrings("SIMULATED-CIP-DEVICE", rep.data[15..35]);

    var buf3: [max_frame_len]u8 = undefined;
    const single = try decodeNamed("get attribute single identity product name request", &buf3);
    var storage3: [4]cpf.Item = undefined;
    const single_env = try cpf.decodeEnvelope(single.data, &storage3);
    const single_req = try cip.Request.decode(single_env.list.dataItem().?.data);
    try testing.expectEqual(@as(?u32, 7), try epath.findLogical(single_req.path, .attribute));

    var buf4: [max_frame_len]u8 = undefined;
    const name_rep_msg = try decodeNamed("get attribute single identity product name reply", &buf4);
    var storage4: [4]cpf.Item = undefined;
    const name_env = try cpf.decodeEnvelope(name_rep_msg.data, &storage4);
    const name_rep = try cip.Reply.decode(name_env.list.dataItem().?.data);
    try testing.expectEqualStrings(
        "SIMULATED-CIP-DEVICE",
        (try types.decodeValue(.short_string, name_rep.data)).string,
    );
}

test "error replies arrive at two different layers" {
    // A CIP-layer error: the reply is a Message Router reply with a non-zero
    // general status and no data at all.
    var buf: [max_frame_len]u8 = undefined;
    const cip_err = try decodeNamed("get attribute single unknown attribute error reply", &buf);
    try testing.expect(cip_err.status.isSuccess());
    var storage: [4]cpf.Item = undefined;
    const env = try cpf.decodeEnvelope(cip_err.data, &storage);
    const rep = try cip.Reply.decode(env.list.dataItem().?.data);
    try testing.expectEqual(@intFromEnum(cip.Service.get_attribute_single), rep.service);
    try testing.expectEqual(cip.GeneralStatus.service_not_supported, rep.general_status);
    try testing.expectEqual(@as(usize, 0), rep.additional_status.len);
    try testing.expectEqual(@as(usize, 0), rep.data.len);
    try testing.expectEqual(@as(?u16, null), rep.extendedStatus());

    // An encapsulation-layer error: a non-zero status and a **zero-length**
    // body, so there is no CIP message to decode at all. A decoder that
    // insists on a CPF envelope here fails on real traffic.
    var buf2: [max_frame_len]u8 = undefined;
    const encap_err = try decodeNamed("read tag unknown name encapsulation error reply", &buf2);
    try testing.expect(!encap_err.status.isSuccess());
    try testing.expectEqual(@as(usize, 0), encap_err.data.len);
    try testing.expectEqual(@as(usize, encap.header_len), encap_err.total_len);

    var buf3: [max_frame_len]u8 = undefined;
    const class_err = try decodeNamed(
        "get attribute single unknown class encapsulation error reply",
        &buf3,
    );
    try testing.expect(!class_err.status.isSuccess());
    try testing.expectEqual(@as(usize, 0), class_err.data.len);
}

test "an unregister session request is a bare header and gets no reply" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("unregister session request", &buf);
    try testing.expectEqual(encap.Command.unregister_session, msg.command);
    try testing.expectEqual(@as(usize, encap.header_len), msg.total_len);
    try testing.expect(msg.session_handle != 0);
    // Nothing in the table answers it, which is the protocol's own rule.
    for (table) |g| {
        if (g.dir == .from_target and std.mem.indexOf(u8, g.name, "unregister") != null) {
            return error.UnexpectedReply;
        }
    }
}

test "a legacy command survives a decode without being understood" {
    var buf: [max_frame_len]u8 = undefined;
    const msg = try decodeNamed("legacy command 0x0001 request", &buf);
    try testing.expect(!msg.command.isKnown());
    try testing.expectEqual(@as(u16, 1), @intFromEnum(msg.command));
    var buf2: [max_frame_len]u8 = undefined;
    const rep = try decodeNamed("legacy command 0x0001 reply", &buf2);
    try testing.expect(rep.status.isSuccess());
    // Its body is still a CPF item list, with an item type nothing names.
    var storage: [4]cpf.Item = undefined;
    const list = try cpf.decode(rep.data, &storage);
    try testing.expectEqual(@as(usize, 1), list.items.len);
    try testing.expectEqual(@as(u16, 1), @intFromEnum(list.items[0].type_id));
}

// ── coverage: the table must not silently rot ──────────────────────────────

fn noteType(t: types.DataType, int: *bool, dint: *bool, real: *bool, sstring: *bool) void {
    switch (t) {
        .int => int.* = true,
        .dint => dint.* = true,
        .real => real.* = true,
        .short_string => sstring.* = true,
        else => {},
    }
}

test "the golden table covers every shape this module claims to handle" {
    var buf: [max_frame_len]u8 = undefined;
    var storage: [8]cpf.Item = undefined;

    var saw_nop = false;
    var saw_register = false;
    var saw_unregister = false;
    var saw_list_identity = false;
    var saw_list_services = false;
    var saw_list_interfaces = false;
    var saw_rr = false;
    var saw_unit = false;
    var saw_udp = false;
    var saw_null_address = false;
    var saw_connected_address = false;
    var saw_unconnected_data = false;
    var saw_connected_data = false;
    var saw_identity_item = false;
    var saw_services_item = false;
    var saw_unconnected_send = false;
    var saw_forward_open = false;
    var saw_large_forward_open = false;
    var saw_forward_close = false;
    var saw_multiple = false;
    var saw_read_tag = false;
    var saw_write_tag = false;
    var saw_read_frag = false;
    var saw_write_frag = false;
    var saw_get_all = false;
    var saw_get_single = false;
    var saw_cip_error = false;
    var saw_encap_error = false;
    var saw_both_sources = [_]bool{ false, false };
    var saw_int = false;
    var saw_dint = false;
    var saw_real = false;
    var saw_sstring = false;

    for (table) |g| {
        saw_both_sources[@intFromEnum(g.source)] = true;
        if (g.link == .udp) saw_udp = true;
        const wire = try bytesOf(g, &buf);
        const msg = try encap.decode(wire);
        switch (msg.command) {
            .nop => saw_nop = true,
            .register_session => saw_register = true,
            .unregister_session => saw_unregister = true,
            .list_identity => saw_list_identity = true,
            .list_services => saw_list_services = true,
            .list_interfaces => saw_list_interfaces = true,
            .send_rr_data => saw_rr = true,
            .send_unit_data => saw_unit = true,
            else => {},
        }
        if (!msg.status.isSuccess()) saw_encap_error = true;
        if (msg.data.len == 0) continue;

        if (msg.command == .list_identity or msg.command == .list_services) {
            const list = cpf.decode(msg.data, &storage) catch continue;
            if (list.find(.list_identity_response) != null) saw_identity_item = true;
            if (list.find(.list_services_response) != null) saw_services_item = true;
            continue;
        }
        const env = (envelopeOf(msg, &storage) catch continue) orelse continue;
        for (env.list.items) |it| switch (it.type_id) {
            .null_address => saw_null_address = true,
            .connected_address => saw_connected_address = true,
            .unconnected_data => saw_unconnected_data = true,
            .connected_data => saw_connected_data = true,
            else => {},
        };
        const body = (cipOf(msg, &storage) catch continue) orelse continue;
        if (g.dir == .to_target) {
            var req = cip.Request.decode(body) catch continue;
            const class = (req.classCode() catch null);
            if (class != null and class.? == connmgr.class_code) {
                switch (req.service) {
                    connmgr.Service.unconnected_send => {
                        saw_unconnected_send = true;
                        const us = connmgr.UnconnectedSend.decode(req.data) catch continue;
                        req = cip.Request.decode(us.embedded) catch continue;
                    },
                    connmgr.Service.forward_open => saw_forward_open = true,
                    connmgr.Service.large_forward_open => saw_large_forward_open = true,
                    connmgr.Service.forward_close => saw_forward_close = true,
                    else => {},
                }
            }
            switch (req.service) {
                @intFromEnum(cip.Service.multiple_service_packet) => saw_multiple = true,
                @intFromEnum(cip.Service.get_attributes_all) => saw_get_all = true,
                @intFromEnum(cip.Service.get_attribute_single) => saw_get_single = true,
                cip.LogixService.read_tag => saw_read_tag = true,
                cip.LogixService.write_tag => saw_write_tag = true,
                cip.LogixService.read_tag_fragmented => saw_read_frag = true,
                cip.LogixService.write_tag_fragmented => saw_write_frag = true,
                else => {},
            }
        } else {
            const rep = cip.Reply.decode(body) catch continue;
            if (!rep.general_status.isSuccess()) saw_cip_error = true;
            if (rep.general_status.hasData() and rep.data.len >= 2) {
                if (rep.service == @intFromEnum(cip.Service.multiple_service_packet)) {
                    // The batched replies are where the type variety lives.
                    const ms = cip.MultipleService.decode(rep.data) catch continue;
                    var i: usize = 0;
                    while (i < ms.count) : (i += 1) {
                        const sub_bytes = ms.at(i) catch break;
                        const sub = cip.Reply.decode(sub_bytes) catch break;
                        if (!sub.general_status.hasData()) continue;
                        const td = types.TagData.decode(sub.data) catch continue;
                        noteType(td.type, &saw_int, &saw_dint, &saw_real, &saw_sstring);
                    }
                    continue;
                }
                if (types.TagData.decode(rep.data)) |td| {
                    noteType(td.type, &saw_int, &saw_dint, &saw_real, &saw_sstring);
                } else |_| {}
            }
        }
    }

    // `NOP` is never captured: it is write-only, so no proxy sees a pair for
    // it. Everything else must be present.
    try testing.expect(!saw_nop);
    const checks = [_]struct { got: bool, what: []const u8 }{
        .{ .got = saw_register, .what = "RegisterSession" },
        .{ .got = saw_unregister, .what = "UnRegisterSession" },
        .{ .got = saw_list_identity, .what = "ListIdentity" },
        .{ .got = saw_list_services, .what = "ListServices" },
        .{ .got = saw_list_interfaces, .what = "ListInterfaces" },
        .{ .got = saw_rr, .what = "SendRRData" },
        .{ .got = saw_unit, .what = "SendUnitData" },
        .{ .got = saw_udp, .what = "a UDP discovery pair" },
        .{ .got = saw_null_address, .what = "a null address item" },
        .{ .got = saw_connected_address, .what = "a connected address item" },
        .{ .got = saw_unconnected_data, .what = "an unconnected data item" },
        .{ .got = saw_connected_data, .what = "a connected data item" },
        .{ .got = saw_identity_item, .what = "a ListIdentity item" },
        .{ .got = saw_services_item, .what = "a ListServices item" },
        .{ .got = saw_unconnected_send, .what = "Unconnected_Send" },
        .{ .got = saw_forward_open, .what = "Forward_Open" },
        .{ .got = saw_large_forward_open, .what = "Large_Forward_Open" },
        .{ .got = saw_forward_close, .what = "Forward_Close" },
        .{ .got = saw_multiple, .what = "Multiple_Service_Packet" },
        .{ .got = saw_read_tag, .what = "Read Tag" },
        .{ .got = saw_write_tag, .what = "Write Tag" },
        .{ .got = saw_read_frag, .what = "Read Tag Fragmented" },
        .{ .got = saw_write_frag, .what = "Write Tag Fragmented" },
        .{ .got = saw_get_all, .what = "Get_Attributes_All" },
        .{ .got = saw_get_single, .what = "Get_Attribute_Single" },
        .{ .got = saw_cip_error, .what = "a CIP-layer error reply" },
        .{ .got = saw_encap_error, .what = "an encapsulation-layer error reply" },
        .{ .got = saw_both_sources[0], .what = "traffic from the first client stack" },
        .{ .got = saw_both_sources[1], .what = "traffic from the second client stack" },
        .{ .got = saw_int, .what = "an INT tag read" },
        .{ .got = saw_dint, .what = "a DINT tag read" },
        .{ .got = saw_real, .what = "a REAL tag read" },
        .{ .got = saw_sstring, .what = "a SHORT_STRING tag read" },
    };
    for (checks) |c| {
        if (!c.got) {
            std.debug.print("golden coverage lost: {s}\n", .{c.what});
            return error.CoverageLost;
        }
    }
}

test "no golden carries a real device identity" {
    // The anonymisation is asserted, not merely documented: a future capture
    // pasted in without substituting these fields fails here.
    var buf: [max_frame_len]u8 = undefined;
    for (table) |g| {
        const wire = try bytesOf(g, &buf);
        try testing.expect(std.mem.indexOf(u8, wire, "LOGIX") == null);
        try testing.expect(std.mem.indexOf(u8, wire, "1756") == null);
    }
}
