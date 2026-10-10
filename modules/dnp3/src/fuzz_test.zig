// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for dnp3 (added 2026-10-10).
//!
//! `DNP3_FUZZ=<runs>[,<first seed>]` runs the harnesses (testkit's fuzz
//! driver; `_ONLY` selects one by name, `_MS`, `_SEEDFILE`, `_INPUT` as
//! documented there). Each is generic over its source of choices.
//! - `dnp3-fragment` and `dnp3-session` (`outstation.zig`, beside the fixture
//!   and the hostile-field tables): structured application fragments straight
//!   into `Outstation.handle`, and wrapped in data-link frames (own, neighbour
//!   and broadcast destinations, damaged CRCs) into `Session.feedFrame`; the
//!   response series must terminate and anything emitted decode.
//! - `dnp3-sa` (here): Secure Authentication v5 as an oracle: a wrapped
//!   session-key pair unwraps, a flipped octet or another update key does not;
//!   a reply MAC verifies, a flipped MAC, challenge, ASDU or key does not; the
//!   g120 object decoders round-trip and never panic on damage.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const sa = @import("sa.zig");
pub const fuzz_driver = testkit.fuzz.driver;

/// `frame` into `buf` with 0-3 octets damaged (half within the first 16) and
/// maybe truncated. The driver's `Rng` only.
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        const span = if (src.value(bool)) @min(n, 16) else n;
        buf[src.index(span)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels (see jwt's fuzz_test.zig).
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

fn flipBit(src: anytype, buf: []u8) void {
    buf[src.index(buf.len)] ^= @as(u8, 1) << @intCast(src.valueRangeAtMost(u8, 0, 7));
}

const SaMark = Marker(enum {
    unwrapped,
    wrap_flip_refused,
    wrong_update_key_refused,
    truncated_wrap_refused,
    mac_verified,
    mac_flip_refused,
    challenge_flip_refused,
    asdu_flip_refused,
    wrong_key_refused,
    short_mac_refused,
    objects_roundtrip,
    objects_damaged,
});

const hmac_algs = [_]sa.HmacAlgorithm{ .hmac_sha1_trunc_4, .hmac_sha1_trunc_8, .hmac_sha1_trunc_10, .hmac_sha256_trunc_8, .hmac_sha256_trunc_16 };

pub fn fuzzSa(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    // Session-key wrap / unwrap.
    var update: [32]u8 = undefined;
    var control: [32]u8 = undefined;
    var monitor: [32]u8 = undefined;
    src.bytes(&update);
    src.bytes(&control);
    src.bytes(&monitor);
    const klen: usize = if (src.value(bool)) 16 else 32;
    const ulen: usize = if (src.value(bool)) 16 else 32;
    var wrapped_buf: [96]u8 = undefined;
    const wrapped = try sa.wrapSessionKeys(update[0..ulen], control[0..klen], monitor[0..klen], &wrapped_buf);
    var out_buf: [64]u8 = undefined;
    const keys = try sa.unwrapSessionKeys(update[0..ulen], wrapped, klen, &out_buf);
    if (!std.mem.eql(u8, keys.control_key, control[0..klen]) or !std.mem.eql(u8, keys.monitoring_key, monitor[0..klen])) return error.UnwrapChangedTheKeys;
    SaMark.mark(.unwrapped);
    {
        var bad: [96]u8 = undefined;
        @memcpy(bad[0..wrapped.len], wrapped);
        flipBit(src, bad[0..wrapped.len]);
        if (sa.unwrapSessionKeys(update[0..ulen], bad[0..wrapped.len], klen, &out_buf)) |_| return error.FlippedWrapAccepted else |_| SaMark.mark(.wrap_flip_refused);
        var other = update;
        flipBit(src, other[0..ulen]);
        if (sa.unwrapSessionKeys(other[0..ulen], wrapped, klen, &out_buf)) |_| return error.WrongUpdateKeyAccepted else |_| SaMark.mark(.wrong_update_key_refused);
        if (sa.unwrapSessionKeys(update[0..ulen], wrapped[0..src.index(wrapped.len)], klen, &out_buf)) |_| return error.TruncatedWrapAccepted else |_| SaMark.mark(.truncated_wrap_refused);
    }

    // Reply MAC over challenge message ++ ASDU.
    const alg = hmac_algs[src.index(hmac_algs.len)];
    var key: [32]u8 = undefined;
    src.bytes(&key);
    const key_len: usize = if (src.value(bool)) 16 else 32;
    var challenge: [40]u8 = undefined;
    var asdu: [60]u8 = undefined;
    src.bytes(&challenge);
    src.bytes(&asdu);
    const cl = 8 + src.index(33);
    const al = 1 + src.index(asdu.len);
    var mac_buf: [sa.mac.max_len]u8 = undefined;
    const tag = try sa.computeReplyMac(alg, key[0..key_len], challenge[0..cl], asdu[0..al], &mac_buf);
    if (!sa.verifyReplyMac(alg, key[0..key_len], challenge[0..cl], asdu[0..al], tag)) return error.GenuineMacRefused;
    SaMark.mark(.mac_verified);
    {
        var t2: [sa.mac.max_len]u8 = undefined;
        @memcpy(t2[0..tag.len], tag);
        flipBit(src, t2[0..tag.len]);
        if (sa.verifyReplyMac(alg, key[0..key_len], challenge[0..cl], asdu[0..al], t2[0..tag.len])) return error.FlippedMacAccepted;
        SaMark.mark(.mac_flip_refused);
        var c2 = challenge;
        flipBit(src, c2[0..cl]);
        if (sa.verifyReplyMac(alg, key[0..key_len], c2[0..cl], asdu[0..al], tag)) return error.FlippedChallengeAccepted;
        SaMark.mark(.challenge_flip_refused);
        var a2 = asdu;
        flipBit(src, a2[0..al]);
        if (sa.verifyReplyMac(alg, key[0..key_len], challenge[0..cl], a2[0..al], tag)) return error.FlippedAsduAccepted;
        SaMark.mark(.asdu_flip_refused);
        var k2 = key;
        flipBit(src, k2[0..key_len]);
        if (sa.verifyReplyMac(alg, k2[0..key_len], challenge[0..cl], asdu[0..al], tag)) return error.WrongKeyAccepted;
        SaMark.mark(.wrong_key_refused);
        if (sa.verifyReplyMac(alg, key[0..key_len], challenge[0..cl], asdu[0..al], tag[0..src.index(tag.len)])) return error.ShortMacAccepted;
        SaMark.mark(.short_mac_refused);
    }

    // The g120 objects: round trip, then damage.
    var obj: [128]u8 = undefined;
    var data: [40]u8 = undefined;
    src.bytes(&data);
    const dl = src.index(data.len + 1);
    const chal: sa.Challenge = .{
        .challenge_seq_num = src.value(u32),
        .user_number = src.value(u16),
        .mac_algorithm = alg,
        .reason = @enumFromInt(src.value(u8)),
        .challenge_data = data[0..dl],
    };
    const enc = try chal.encode(&obj);
    const back = try sa.Challenge.decode(enc);
    if (back.challenge_seq_num != chal.challenge_seq_num or back.user_number != chal.user_number or !std.mem.eql(u8, back.challenge_data, data[0..dl])) return error.ChallengeRoundTripFailed;
    var framed: [160]u8 = undefined;
    const fo = try sa.encodeObject(.challenge, enc, &framed);
    const dobj = try sa.decodeObject(fo);
    if (dobj.consumed != fo.len or !std.mem.eql(u8, dobj.data, enc)) return error.ObjectRoundTripFailed;
    SaMark.mark(.objects_roundtrip);
    var dmg: [160]u8 = undefined;
    const n = damage(src, &dmg, fo);
    if (sa.decodeObject(dmg[0..n])) |o| _ = sa.Challenge.decode(o.data) catch {} else |_| {}
    _ = sa.SessionKeyStatus.decode(dmg[0..n]) catch {};
    _ = sa.SessionKeyChange.decode(dmg[0..n]) catch {};
    _ = sa.SaError.decode(dmg[0..n]) catch {};
    _ = sa.Reply.decode(dmg[0..n]) catch {};
    _ = sa.AggressiveModeRequest.decode(dmg[0..n]) catch {};
    _ = sa.SessionKeyStatusRequest.decode(dmg[0..n]) catch {};
    SaMark.mark(.objects_damaged);
}

fn fuzzSaSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzSa(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: Secure Authentication wrap, MAC and objects as an oracle" {
    try testing.fuzz({}, fuzzSaSmith, .{});
}

test "fuzz driver: DNP3_FUZZ (sa)" {
    try fuzz_driver.run(fuzzSa, .{ .prefix = "DNP3_FUZZ", .name = "dnp3-sa" });
}

test "fuzz harness: sa, 300 seeds, reaches every outcome" {
    try SaMark.reach(fuzzSa, "dnp3-sa", 300);
}
