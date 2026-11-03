// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over stun's `decode` + accessors harness (added
//! 2026-10-09). The harness body is generic over its source of choices
//! (`fn(comptime S, *S, gpa)`). The first draw is one `slice` of bytes (the
//! datagram, as `std.testing.fuzz` seeds it); a second, ranged draw picks a
//! SHAPE: 0 = the bytes as they are, 1-3 = patch them into a message with a
//! valid header (type bits, 4-aligned length, magic cookie) and, for 2 / 3, an
//! XOR-MAPPED-ADDRESS / ERROR-CODE attribute first, so random bytes reach the
//! walk and the accessors. Past the end of a corpus seed the ranged draw
//! answers 0, so a seed stays a raw datagram.
//!
//! Driver: `STUN_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const stun = @import("root.zig");
const netaddr = @import("netaddr");

pub const Label = enum { rejected, decoded, attributes_walked, mapped_address, error_code, other_address, response_origin, alternate_server, xor_peer, uint32_attr, sha256_verified, password_algorithms, built, build_refused, built_sha256, built_roundtrip, respond_refused, respond_400, respond_401, respond_420, respond_sha256, respond_ok };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// `testing.fuzz`'s source: the bytes come FIRST, in one `slice` draw, and the
/// harness reads every choice from them. Past the end a ranged draw answers its
/// minimum (shape 0 = the raw datagram).
pub const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        if (self.cur.at >= self.cur.bytes.len) return at_least;
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn slice(self: *ScriptSource, buf: []u8) u32 {
        const left = self.cur.bytes.len -| self.cur.at;
        const n = @min(buf.len, left);
        @memcpy(buf[0..n], self.cur.bytes[self.cur.at..][0..n]);
        self.cur.at += n;
        return @intCast(n);
    }
};

fn putAttr(packet: []u8, at: usize, typ: u16, value_len: u16) void {
    std.mem.writeInt(u16, packet[at..][0..2], typ, .big);
    std.mem.writeInt(u16, packet[at + 2 ..][0..2], value_len, .big);
}

pub fn decodeHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var packet: [1024]u8 = @splat(0);
    var len: usize = src.slice(&packet);
    const shape = src.valueRangeAtMost(u8, 0, 6);
    if (shape != 0) {
        // Message length: the drawn bytes, rounded to 4, at least the header
        // (and room for the attribute a shape asks for).
        const want: usize = switch (shape) {
            2 => 20 + 4 + 20, // XOR-MAPPED-ADDRESS, room for an IPv6 value
            3 => 20 + 4 + 8, // ERROR-CODE: 4 octets of class/number + reason
            4 => 20 + 4 + 32, // MESSAGE-INTEGRITY-SHA256, 16..32 byte tag
            5 => 20 + 4 + 4, // PRIORITY
            6 => 20 + 4 + 8, // PASSWORD-ALGORITHMS: one entry, parameters 0..4
            else => 20 + (len -| 20) / 4 * 4,
        };
        len = @max(want, 20);
        packet[0] &= 0x3F;
        std.mem.writeInt(u16, packet[2..4], @intCast(len - 20), .big);
        std.mem.writeInt(u32, packet[4..8], 0x2112A442, .big);
        switch (shape) {
            2 => {
                const v6 = packet[21] & 1 == 1;
                const types = [_]u16{ 0x0020, 0x802C, 0x802B, 0x8023, 0x0012 };
                putAttr(&packet, 20, types[packet[22] % types.len], if (v6) 20 else 8);
                packet[24] = 0;
                packet[25] = if (v6) 2 else 1;
                std.mem.writeInt(u16, packet[2..4], if (v6) 24 else 12, .big);
                len = if (v6) 44 else 32;
            },
            3 => {
                putAttr(&packet, 20, 0x0009, 8);
                packet[24] = 0;
                packet[25] = 0;
                packet[26] = 3 + packet[26] % 3; // class 3..5
            },
            4 => {
                // A MESSAGE-INTEGRITY-SHA256 that is CORRECT for key "key" (tag
                // 16, 20, .. 32 bytes), so the HMAC runs to a true comparison.
                const tl: usize = 16 + (@as(usize, packet[21]) % 5) * 4;
                putAttr(&packet, 20, 0x001C, @intCast(tl));
                len = 24 + tl;
                std.mem.writeInt(u16, packet[2..4], @intCast(4 + tl), .big);
                var mac: [32]u8 = undefined;
                var h = std.crypto.auth.hmac.sha2.HmacSha256.init("key");
                h.update(packet[0..20]);
                h.final(&mac);
                @memcpy(packet[24..][0..tl], mac[0..tl]);
            },
            5 => putAttr(&packet, 20, 0x0024, 4),
            6 => {
                putAttr(&packet, 20, 0x8002, 8);
                packet[26] = 0;
                packet[27] %= 5;
            },
            else => {},
        }
    }

    const msg = stun.decode(packet[0..len]) catch {
        mark(.rejected);
        return;
    };
    mark(.decoded);
    // A decoded message must survive every accessor, the attribute walk and
    // both verifiers; decode borrows the input, so nothing to free.
    if (msg.xorMappedAddress()) |o| {
        if (o != null) mark(.mapped_address);
    } else |_| {}
    _ = msg.plainMappedAddress() catch {};
    _ = msg.mappedAddress() catch {};
    if (msg.errorCode()) |o| {
        if (o != null) mark(.error_code);
    } else |_| {}
    _ = msg.verifyFingerprint();
    _ = msg.verifyMessageIntegrity("key");
    // The RFC 5780 / ICE / TURN accessors and the SHA-256 MAC: every
    // address-valued type, and a 4-byte read of the attribute the packet
    // happens to carry first.
    for ([_]u16{ 0x802C, 0x802B, 0x8023, 0x0004, 0x0005, 0x0012, 0x0016, 0x0020 }) |typ| {
        if (msg.address(typ)) |o| {
            if (o != null) switch (typ) {
                0x802C => mark(.other_address),
                0x802B => mark(.response_origin),
                0x8023 => mark(.alternate_server),
                0x0012 => mark(.xor_peer),
                else => {},
            };
        } else |_| {}
        _ = msg.addressCovered(typ) catch {};
    }
    _ = msg.mappedAddressCovered() catch {};
    _ = msg.uint32Covered(0x0024) catch {};
    _ = msg.userhash() catch {};
    _ = msg.passwordAlgorithm() catch {};
    if (msg.passwordAlgorithms()) |pa| {
        var pit = pa;
        var seen = false;
        while (pit.next() catch null) |_| seen = true;
        if (seen) mark(.password_algorithms);
    }
    if (msg.uint32(0x0024)) |o| {
        if (o != null) mark(.uint32_attr);
    } else |_| {}
    _ = msg.changeRequest() catch {};
    _ = msg.uint32(0x000D) catch {};
    if (msg.verifyMessageIntegritySha256("key")) mark(.sha256_verified) else if (shape == 4) return error.ValidSha256DidNotVerify;
    _ = stun.looksLikeStun(packet[0..len]);
    var it = msg.attributes();
    var walked = false;
    while (it.next()) |_| walked = true;
    if (walked) mark(.attributes_walked);
}

/// The mutating API: a random sequence of `Builder` operations into a buffer
/// of a drawn (often too small) size, then everything that was accepted must
/// decode and verify. `shape` bytes decide each step; a refusal ends the
/// message (the builder must leave it decodable up to the last accepted
/// attribute).
pub fn buildHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var script: [64]u8 = @splat(0);
    const n = src.slice(&script);
    var out: [160]u8 = undefined;
    const size: usize = src.valueRangeAtMost(u8, 0, 160);
    var txid: stun.TransactionId = undefined;
    for (&txid, 0..) |*t, i| t.* = script[i % @max(n, 1)] +% @as(u8, @intCast(i));
    var b = stun.Builder.init(out[0..size], .request, .binding, txid) catch {
        mark(.build_refused);
        return;
    };
    var mac_mode: u2 = 0; // 1 = SHA-1, 2 = SHA-256
    var tag: u8 = 32;
    var key_len: usize = 0;
    var fingerprint = false;
    var refused = false;
    var steps: usize = 0;
    const Rec = struct { typ: u16, ip: netaddr.Ip, port: u16 };
    var recs: [12]Rec = undefined;
    var n_recs: usize = 0;
    const v4: netaddr.Ip = .{ .v4 = .{ script[0], script[1], script[2], script[3] } };
    const v6: netaddr.Ip = .{ .v6 = script[4..20].* };
    for (script[0..@min(n, 12)]) |op| {
        steps += 1;
        const ip = if (op & 0x80 != 0) v6 else v4;
        const port: u16 = (@as(u16, op) << 8) | script[steps % 64];
        const atyp: u16 = switch (op % 13) {
            0 => 0x8020 + @as(u16, op & 0x0F) + 0x000C, // 0x802C..0x803B
            1 => 0x0020,
            2 => 0x0012,
            else => 0,
        };
        const r: anyerror!void = switch (op % 13) {
            0, 1, 2 => b.addAddress(atyp, ip, port),
            3 => b.addUint32(0x0024, @as(u32, op) * 0x01010101),
            4 => b.addChangeRequest(op & 1 != 0, op & 2 != 0),
            5 => b.addUsername(script[0..@min(n, op % 17)]),
            6 => b.addErrorCode(300 + @as(u16, op), script[0..@min(n, op % 40)]),
            7 => blk: {
                if (mac_mode != 0 or fingerprint) break :blk {};
                mac_mode = 1;
                key_len = @min(n, op % 9);
                break :blk b.addMessageIntegrity(script[0..key_len]);
            },
            8 => blk: {
                if (mac_mode != 0 or fingerprint) break :blk {};
                mac_mode = 2;
                tag = 16 + (op % 6) * 4; // 16..36: the last is out of range
                key_len = @min(n, op % 9);
                break :blk b.addMessageIntegritySha256(script[0..key_len], tag);
            },
            9 => blk: {
                if (fingerprint) break :blk {};
                fingerprint = true;
                break :blk b.addFingerprint();
            },
            10 => b.addAttribute(@as(u16, op) | 0x8100, script[0..@min(n, op % 23)]),
            11 => b.addPasswordAlgorithms(&.{ .{ .algorithm = 2 }, .{ .algorithm = op, .params = script[0..@min(n, op % 7)] } }),
            else => b.addUserhash(script[0..@min(n, op % 5)], "realm"),
        };
        r catch {
            refused = true;
            break;
        };
        if (atyp != 0) {
            recs[n_recs] = .{ .typ = atyp, .ip = ip, .port = port };
            n_recs += 1;
        }
        // FINGERPRINT is always last; attributes after a MAC are legal
        // (ignored by §14.5) and exercise the covered-region rule.
        if (fingerprint) break;
    }
    if (refused) mark(.build_refused);
    const wire = b.finish();
    const m = stun.decode(wire) catch return error.BuilderOutputDoesNotDecode;
    mark(.built);
    if (m.length != wire.len - stun.header_len) return error.BuilderLengthMismatch;
    var it = m.attributes();
    while (it.next()) |_| {}
    if (fingerprint and !refused and !m.verifyFingerprint()) return error.FingerprintDoesNotVerify;
    if (!refused and mac_mode == 2 and tag >= 16 and tag <= 32) {
        mark(.built_sha256);
        if (!m.verifyMessageIntegritySha256(script[0..key_len])) return error.Sha256DoesNotVerify;
        mark(.built_roundtrip);
    }
    if (!refused and mac_mode == 1) {
        if (!m.verifyMessageIntegrity(script[0..key_len])) return error.Sha1DoesNotVerify;
    }
    // Every accepted address attribute reads back as written: the first of
    // each type is what `address` returns (XOR types un-XORed, v6 included).
    for (recs[0..n_recs], 0..) |rec, i| {
        const dup = for (recs[0..i]) |e| {
            if (e.typ == rec.typ) break true;
        } else false;
        if (dup) continue;
        const got = (m.address(rec.typ) catch return error.AddressDoesNotDecode) orelse return error.AddressMissing;
        if (got.port != rec.port or !got.ip.eql(rec.ip)) return error.AddressRoundTrip;
    }
    // Every address-valued helper survives whatever was built.
    _ = m.address(0x802C) catch {};
    if (m.passwordAlgorithms()) |pa| {
        var pit = pa;
        while (pit.next() catch null) |_| {}
    }
    _ = m.mappedAddress() catch {};
}

/// `bindingResponse` over requests a client could really send, with the server's
/// keys, tag and buffer drawn. The status every response must carry is computed
/// here from what the request was built with, not from the responder's own checks.
pub fn respondHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var script: [32]u8 = @splat(0);
    const n = src.slice(&script);
    const bits = script[0];
    const with_user = bits & 1 != 0;
    const user_behind_mac = bits & 2 != 0;
    const unknown_in_front = script[1] % 8 == 0;
    const unknown_behind = bits & 4 != 0;
    const req_sha1 = bits & 8 != 0;
    const req_sha256 = bits & 16 != 0;
    const req_fp = bits & 32 != 0;
    const srv_sha1 = script[2] & 1 != 0;
    const srv_sha256 = script[2] & 2 != 0;
    const wrong_sha1 = script[2] & 4 != 0;
    const wrong_sha256 = script[2] & 8 != 0;
    const key = "the shared key";

    var rq: [256]u8 = undefined;
    var txid: stun.TransactionId = undefined;
    for (&txid, 0..) |*t, i| t.* = script[3 + i];
    var b = try stun.Builder.init(&rq, .request, .binding, txid);
    const name = script[16..][0..@min(n -| 16, 16)];
    if (with_user) try b.addUsername(name);
    if (unknown_in_front) try b.addAttribute(0x0030, "zz");
    if (req_sha1) try b.addMessageIntegrity(key);
    if (req_sha256) try b.addMessageIntegritySha256(key, 16 + (script[15] % 5) * 4);
    const has_mac = req_sha1 or req_sha256;
    if (has_mac and user_behind_mac) try b.addUsername("late");
    if (has_mac and unknown_behind) try b.addAttribute(0x0031, "zz");
    if (req_fp) try b.addFingerprint();
    const req = try stun.decode(b.finish());

    const from: stun.AddressPort = .{
        .ip = if (script[1] & 16 != 0) .{ .v6 = script[0..16].* } else .{ .v4 = script[4..8].* },
        .port = std.mem.readInt(u16, script[8..10], .big),
    };
    const tag = script[10];
    const opts: stun.ResponderOptions = .{
        .integrity_key = if (srv_sha1) (if (wrong_sha1) "another key" else key) else null,
        .integrity_key_sha256 = if (srv_sha256) (if (wrong_sha256) "another key" else key) else null,
        .integrity_sha256_tag = tag,
        .fingerprint = script[1] & 32 != 0,
        .software = if (script[1] & 64 != 0) "zig" else null,
    };

    var out: [256]u8 = undefined;
    const size: usize = if (script[11] & 1 == 0) out.len else src.valueRangeAtMost(u16, 0, out.len);
    const wire = stun.bindingResponse(req, from, out[0..size], opts) catch |e| {
        if (size == out.len) return e; // with room, this request always earns an answer
        mark(.respond_refused);
        return;
    };
    const r = try stun.decode(wire);
    if (!std.mem.eql(u8, &r.transaction_id, &txid)) return error.ResponseTransactionId;
    if (opts.fingerprint and !r.verifyFingerprint()) return error.ResponseFingerprint;

    const keyed = srv_sha1 or srv_sha256;
    const want: u16 = if (unknown_in_front)
        420
    else if (keyed and (!with_user or (srv_sha1 and !req_sha1) or (srv_sha256 and !req_sha256)))
        400
    else if ((srv_sha1 and wrong_sha1) or (srv_sha256 and wrong_sha256))
        401
    else
        0;
    if (want != 0) {
        if (r.class != .error_response) return error.ExpectedErrorResponse;
        const got = (try r.errorCode()) orelse return error.ResponseWithoutErrorCode;
        if (got.code != want) return error.WrongErrorCode;
        if ((try r.mappedAddress()) != null) return error.ErrorResponseLeaksAddress;
        switch (want) {
            400 => mark(.respond_400),
            401 => mark(.respond_401),
            else => mark(.respond_420),
        }
        return;
    }
    if (r.class != .success_response) return error.ExpectedSuccessResponse;
    const ap = (try r.mappedAddressCovered()) orelse return error.ResponseWithoutAddress;
    if (ap.port != from.port or !ap.ip.eql(from.ip)) return error.ResponseWrongAddress;
    if (srv_sha1 and !r.verifyMessageIntegrity(key)) return error.ResponseSha1;
    if (srv_sha256) {
        if (!r.verifyMessageIntegritySha256(key)) return error.ResponseSha256;
        const legal = tag >= 16 and tag <= 32 and tag % 4 == 0;
        if (r.find(0x001C).?.value.len != (if (legal) tag else 32)) return error.ResponseTagLength;
        mark(.respond_sha256);
    }
    mark(.respond_ok);
}

test "fuzz driver: STUN_FUZZ (respond)" {
    try fuzz_driver.run(respondHarness, .{ .prefix = "STUN_FUZZ_RESPOND", .name = "stun-respond" });
}

test "fuzz driver: STUN_FUZZ (build)" {
    try fuzz_driver.run(buildHarness, .{ .prefix = "STUN_FUZZ_BUILD", .name = "stun-build" });
}

test "fuzz driver: STUN_FUZZ (decode)" {
    try fuzz_driver.run(decodeHarness, .{ .prefix = "STUN_FUZZ", .name = "stun-decode" });
}

test "fuzz harness: 400 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        decodeHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("stun seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        buildHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("stun build seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (0..400) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        respondHarness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("stun respond seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 400 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}
