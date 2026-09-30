// SPDX-License-Identifier: MIT
//! python-fido2 2.2.1 as a black-box oracle: for every PIN operation and both
//! protocols, the request bytes this module sends equal, byte for byte, the
//! request bytes python-fido2 sent (`fido2_vectors.zig`, produced by
//! `tools/gen_fido2_vectors.py`), and the token this module decrypts from the
//! scripted response equals the token python-fido2 obtained.

const std = @import("std");
const v = @import("fido2_vectors.zig");
const framing = @import("framing.zig");
const getinfo = @import("getinfo.zig");
const clientpin = @import("clientpin.zig");
const ctap2pin = @import("ctap2pin");
const testutil = @import("testutil.zig");

const testing = std.testing;

fn unhex(comptime N: usize, s: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const Op = enum {
    get_pin_retries,
    get_uv_retries,
    set_pin,
    set_pin_utf8,
    change_pin,
    get_pin_token_legacy,
    get_pin_token_mc_ga,
    get_pin_token_cm_no_rpid,
    get_pin_token_lbw_acfg,
    get_uv_token,
};

fn opOf(name: []const u8) Op {
    // "p1_get_uv_token" -> "get_uv_token"
    return std.meta.stringToEnum(Op, name[3..]).?;
}

fn runCase(c: v.Case) !void {
    const a = testing.allocator;
    // The random script: the platform scalar, then every IV python drew.
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(a);
    const scalar = unhex(32, v.platform_scalar);
    if (c.requests.len > 1) try script.appendSlice(a, &scalar); // only session operations draw one
    for (c.ivs) |iv| try script.appendSlice(a, iv);
    var rnd: testutil.ScriptRandom = .{ .bytes = script.items };

    var tr = testutil.ScriptTransport.init(a, c.responses);
    defer tr.deinit();
    const protocol = try ctap2pin.Protocol.fromWire(c.protocol);
    const client = clientpin.Client.init(a, tr.transport(), rnd.random(), protocol);

    var result_hex: [64]u8 = undefined;
    var result_len: usize = 0;
    switch (opOf(c.name)) {
        .get_pin_retries => {
            const r = try client.getPinRetries();
            try testing.expectEqual(@as(u32, 8), r.retries);
            try testing.expectEqual(@as(?bool, false), r.power_cycle_required);
            try testing.expectEqualStrings("(8, False)", c.result);
        },
        .get_uv_retries => {
            try testing.expectEqual(@as(u32, 3), try client.getUvRetries());
            try testing.expectEqualStrings("3", c.result);
        },
        .set_pin => try client.setPin("1234"),
        .set_pin_utf8 => try client.setPin("p\u{e4}ssw\u{f6}rd\u{20ac}"),
        .change_pin => try client.changePin("1234", "secret-pin-9"),
        else => {
            var tok = switch (opOf(c.name)) {
                .get_pin_token_legacy => try client.getPinToken("1234"),
                .get_pin_token_mc_ga => try client.getPinUvAuthTokenUsingPin("1234", .{ .mc = true, .ga = true }, "example.com"),
                .get_pin_token_cm_no_rpid => try client.getPinUvAuthTokenUsingPin("1234", .{ .cm = true }, null),
                .get_pin_token_lbw_acfg => try client.getPinUvAuthTokenUsingPin("1234", .{ .lbw = true, .acfg = true, .be = true }, null),
                .get_uv_token => try client.getPinUvAuthTokenUsingUv(.{ .ga = true }, "example.com"),
                else => unreachable,
            };
            defer tok.deinit();
            const hex = std.fmt.bytesToHex(tok.bytes, .lower);
            @memcpy(result_hex[0 .. tok.len * 2], hex[0 .. tok.len * 2]);
            result_len = tok.len * 2;
            try testing.expectEqualStrings(c.result, result_hex[0..result_len]);
        },
    }

    // Byte-for-byte request equality with python-fido2.
    try testing.expectEqual(c.requests.len, tr.requests.items.len);
    for (c.requests, tr.requests.items) |want, got| try testing.expectEqualSlices(u8, want, got);
    try testing.expect(rnd.consumedAll());
}

test "oracle: every PIN operation x both protocols matches python-fido2 byte for byte" {
    try testing.expectEqual(@as(usize, 20), v.cases.len);
    inline for (v.cases) |c| try runCase(c);
}

test "oracle: authenticatorGetInfo request and python-composed response" {
    const a = testing.allocator;
    inline for (v.cases) |c| {
        if (comptime std.mem.endsWith(u8, c.name, "_get_pin_retries")) {
            var tr = testutil.ScriptTransport.init(a, &.{c.info_response});
            defer tr.deinit();
            const info = try getinfo.get(a, tr.transport(), 1200);
            try testing.expectEqual(@as(usize, 1), tr.requests.items.len);
            try testing.expectEqualSlices(u8, c.info_request, tr.requests.items[0]);
            try testing.expect(info.versions.fido_2_1 and info.versions.fido_2_0);
            try testing.expectEqualSlices(u8, &unhex(16, v.aaguid), &info.aaguid);
            try testing.expectEqual(@as(?bool, true), info.options.client_pin);
            try testing.expectEqual(@as(?bool, true), info.options.pin_uv_auth_token);
            try testing.expectEqual(@as(?bool, true), info.options.uv);
            try testing.expectEqual(@as(?bool, true), info.options.cred_mgmt);
            try testing.expectEqual(@as(?bool, true), info.options.large_blobs);
            try testing.expectEqual(@as(?u64, 1200), info.max_msg_size);
            try testing.expectEqual(@as(u32, 4), info.effectiveMinPinLength());
            try testing.expectEqual(ctap2pin.Protocol.fromWire(c.protocol) catch unreachable, info.preferredProtocol().?);
        }
    }
}
