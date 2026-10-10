// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for noise (added 2026-10-10).
//!
//! `NOISE_FUZZ=<runs>[,<first seed>]` runs the harnesses (testkit's fuzz
//! driver; `_ONLY` selects one by name, `_MS`, `_SEEDFILE`, `_INPUT` as
//! documented there). Each is generic over its source of choices.
//! - `noise-handshake`: a whole in-memory handshake of a random pattern from
//!   the catalog (every one-way, fundamental and deferred pattern, plus
//!   XXpsk3 and IKpsk2) with random payloads. Undamaged: both sides complete,
//!   every payload arrives, the handshake hashes agree, and the transport
//!   states carry a message each way. ONE message on the way is damaged
//!   (0-3 octets, truncation) or replaced by random bytes: the reader refuses
//!   it with a typed error, or -- if it accepts -- the handshake must not
//!   complete on both sides (every octet of a message is mixed into the hash
//!   the next message authenticates).
//! - `noise-transport`: a transport `CipherState` pair: genuine messages
//!   open; a flipped ciphertext / ad bit, a truncation, a replay and an
//!   out-of-order delivery are refused without advancing the nonce; rekey in
//!   step keeps the pair in sync, rekey of one side only does not.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const noise = @import("root.zig");
pub const fuzz_driver = testkit.fuzz.driver;

const S = noise.DefaultSuite;

/// `frame` into `buf` with 0-3 octets damaged (half within the first 64) and
/// maybe truncated. The driver's `Rng` only.
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        const span = if (src.value(bool)) @min(n, 64) else n;
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

// ── noise-handshake ─────────────────────────────────────────────────────────

const all_patterns = noise.patterns.catalog ++ [_]noise.HandshakePattern{
    noise.withPsk(noise.patterns.XX, &.{3}),
    noise.withPsk(noise.patterns.IK, &.{2}),
};

const HsMark = Marker(enum {
    completed,
    psk_completed,
    multi_message,
    refused_short,
    refused_auth,
    refused_dh,
    accepted_then_refused,
});

pub fn fuzzHandshake(comptime S2: type, src: *S2, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const patterns = all_patterns;
    const pattern = patterns[src.index(patterns.len)];
    var seed_bytes: [64]u8 = undefined;
    src.bytes(&seed_bytes);
    const ini_kp = try S.KeyPair.generateDeterministic(seed_bytes[0..32].*);
    const rsp_kp = try S.KeyPair.generateDeterministic(seed_bytes[32..64].*);
    var psk: [1][32]u8 = undefined;
    src.bytes(&psk[0]);
    var prng = std.Random.DefaultPrng.init(src.value(u64));
    const rng = prng.random();

    var ini: S.HandshakeState = .{};
    var rsp: S.HandshakeState = .{};
    const has_psk = std.mem.indexOf(u8, pattern.name, "psk") != null;
    const psks: []const [32]u8 = if (has_psk) &psk else &.{};
    try ini.init(pattern, true, "fuzz", &.{ .s = &ini_kp, .rs = rsp_kp.public_key, .psks = psks });
    try rsp.init(pattern, false, "fuzz", &.{ .s = &rsp_kp, .rs = ini_kp.public_key, .psks = psks });

    const n_msgs = pattern.message_patterns.len;
    // Which message is tampered with (n_msgs: none), and how.
    var at: usize = n_msgs;
    var raw_replace = false;
    if (S2 == fuzz_driver.Rng) {
        if (src.valueRangeAtMost(u8, 0, 9) >= 3) {
            at = src.index(n_msgs);
            raw_replace = src.valueRangeAtMost(u8, 0, 7) == 0;
        }
    } else {
        at = 0;
        raw_replace = true;
    }

    var ti: [2]S.CipherState = undefined;
    var tr: [2]S.CipherState = undefined;
    var tampered = false;
    var completed_both = true;
    var i: usize = 0;
    while (i < n_msgs) : (i += 1) {
        const writer = if (i % 2 == 0) &ini else &rsp;
        const reader = if (i % 2 == 0) &rsp else &ini;
        const wt = if (i % 2 == 0) &ti else &tr;
        const rt = if (i % 2 == 0) &tr else &ti;
        var payload: [40]u8 = undefined;
        const pl = src.index(payload.len + 1);
        src.bytes(payload[0..pl]);
        var wire: [512]u8 = undefined;
        const w = writer.writeMessage(rng, payload[0..pl], &wire, wt) catch |e| {
            // After an accepted, damaged message the writer's own DH can fail
            // (a low-order ephemeral): the handshake is dead, as it should be.
            if (!tampered) return e;
            HsMark.mark(.accepted_then_refused);
            return;
        };
        var msg: [512]u8 = undefined;
        var mlen = w.len;
        @memcpy(msg[0..mlen], wire[0..mlen]);
        if (i == at) {
            if (raw_replace) {
                mlen = src.slice(&msg);
            } else if (S2 == fuzz_driver.Rng) {
                mlen = damage(src, &msg, wire[0..w.len]);
                // An ephemeral that is a low-order point (all zero, or u = 1).
                if (mlen >= S.DHLEN and src.valueRangeAtMost(u8, 0, 5) == 0) {
                    @memset(msg[0..S.DHLEN], 0);
                    msg[0] = src.valueRangeAtMost(u8, 0, 1);
                }
            }
            tampered = mlen != w.len or !std.mem.eql(u8, msg[0..mlen], wire[0..w.len]);
        }
        var plain: [512]u8 = undefined;
        const r = reader.readMessage(msg[0..mlen], &plain, rt) catch |e| {
            switch (e) {
                error.MessageTooShort => HsMark.mark(.refused_short),
                error.DecryptionFailed => HsMark.mark(.refused_auth),
                error.DhFailed => HsMark.mark(.refused_dh),
                else => {},
            }
            if (!tampered) {
                std.debug.print("noise-handshake: a genuine message {d} of {s} was refused: {t}\n", .{ i, pattern.name, e });
                return error.GenuineMessageRefused;
            }
            completed_both = false;
            break;
        };
        if (!tampered and !std.mem.eql(u8, plain[0..r.len], payload[0..pl])) return error.PayloadChanged;
        if (r.complete != w.complete) return error.CompletionDisagrees;
    }
    if (!completed_both) return;

    // Both sides are through the pattern.
    if (!std.mem.eql(u8, &ini.symmetric_state.getHandshakeHash(), &rsp.symmetric_state.getHandshakeHash())) {
        if (!tampered) return error.HandshakeHashesDisagree;
        HsMark.mark(.accepted_then_refused);
        return;
    }
    if (tampered) {
        std.debug.print("noise-handshake: {s} COMPLETED on both sides with message {d} damaged\n", .{ pattern.name, at });
        return error.DamagedHandshakeCompleted;
    }
    // Transport: a message each way.
    var out: [64]u8 = undefined;
    var c: [64 + 16]u8 = undefined;
    try ti[0].encryptWithAd("", "to responder", c[0 .. 12 + 16]);
    try tr[0].decryptWithAd("", c[0 .. 12 + 16], out[0..12]);
    if (!std.mem.eql(u8, out[0..12], "to responder")) return error.TransportBroken;
    try tr[1].encryptWithAd("", "to initiator", c[0 .. 12 + 16]);
    try ti[1].decryptWithAd("", c[0 .. 12 + 16], out[0..12]);
    if (!std.mem.eql(u8, out[0..12], "to initiator")) return error.TransportBroken;
    HsMark.mark(.completed);
    if (has_psk) HsMark.mark(.psk_completed);
    if (n_msgs > 2) HsMark.mark(.multi_message);
}

fn fuzzHandshakeSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzHandshake(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: a handshake with one message damaged never completes" {
    try testing.fuzz({}, fuzzHandshakeSmith, .{});
}

test "fuzz driver: NOISE_FUZZ (handshake)" {
    try fuzz_driver.run(fuzzHandshake, .{ .prefix = "NOISE_FUZZ", .name = "noise-handshake", .scale = 3 });
}

test "fuzz harness: handshake, 600 seeds, reaches every outcome" {
    try HsMark.reach(fuzzHandshake, "noise-handshake", 600);
}

// ── noise-transport ─────────────────────────────────────────────────────────

const TrMark = Marker(enum {
    genuine,
    flip_refused,
    ad_refused,
    truncated_refused,
    replay_refused,
    out_of_order_refused,
    rekey_in_step,
    rekey_one_side_refused,
});

pub fn fuzzTransport(comptime S2: type, src: *S2, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var key: [32]u8 = undefined;
    src.bytes(&key);
    var a: S.CipherState = .{};
    var b: S.CipherState = .{};
    a.initializeKey(&key);
    b.initializeKey(&key);

    var ad: [16]u8 = undefined;
    src.bytes(&ad);
    const adl = src.index(ad.len + 1);
    var p1: [48]u8 = undefined;
    var p2: [48]u8 = undefined;
    const l1 = src.index(p1.len + 1);
    const l2 = src.index(p2.len + 1);
    src.bytes(p1[0..l1]);
    src.bytes(p2[0..l2]);
    var c1: [48 + 16]u8 = undefined;
    var c2: [48 + 16]u8 = undefined;
    try a.encryptWithAd(ad[0..adl], p1[0..l1], c1[0 .. l1 + 16]);
    try a.encryptWithAd(ad[0..adl], p2[0..l2], c2[0 .. l2 + 16]);
    const n1 = l1 + 16;
    const n2 = l2 + 16;
    var out: [64]u8 = undefined;

    // Out of order: the second first.
    if (b.decryptWithAd(ad[0..adl], c2[0..n2], &out)) |_| return error.OutOfOrderAccepted else |_| TrMark.mark(.out_of_order_refused);
    if (b.n != 0) return error.NonceAdvancedOnFailure;
    // A flipped ciphertext bit, a flipped ad bit, a truncation.
    {
        var f = c1;
        flipBit(src, f[0..n1]);
        if (b.decryptWithAd(ad[0..adl], f[0..n1], &out)) |_| return error.FlippedCiphertextAccepted else |_| TrMark.mark(.flip_refused);
        if (adl > 0) {
            var ad2 = ad;
            flipBit(src, ad2[0..adl]);
            if (b.decryptWithAd(ad2[0..adl], c1[0..n1], &out)) |_| return error.FlippedAdAccepted else |_| TrMark.mark(.ad_refused);
        }
        const cut = 1 + src.index(n1);
        if (b.decryptWithAd(ad[0..adl], c1[0 .. n1 - cut], &out)) |_| return error.TruncatedAccepted else |_| TrMark.mark(.truncated_refused);
        if (b.n != 0) return error.NonceAdvancedOnFailure;
    }
    // Genuine, in order; then the replay.
    try b.decryptWithAd(ad[0..adl], c1[0..n1], &out);
    if (!std.mem.eql(u8, out[0..l1], p1[0..l1])) return error.WrongPlaintext;
    TrMark.mark(.genuine);
    if (b.decryptWithAd(ad[0..adl], c1[0..n1], &out)) |_| return error.ReplayAccepted else |_| TrMark.mark(.replay_refused);
    try b.decryptWithAd(ad[0..adl], c2[0..n2], &out);
    if (!std.mem.eql(u8, out[0..l2], p2[0..l2])) return error.WrongPlaintext;

    // Rekey, in step and one-sided.
    a.rekey();
    b.rekey();
    var c3: [48 + 16]u8 = undefined;
    try a.encryptWithAd(ad[0..adl], p1[0..l1], c3[0..n1]);
    try b.decryptWithAd(ad[0..adl], c3[0..n1], &out);
    if (!std.mem.eql(u8, out[0..l1], p1[0..l1])) return error.WrongPlaintext;
    TrMark.mark(.rekey_in_step);
    a.rekey();
    try a.encryptWithAd(ad[0..adl], p2[0..l2], c3[0..n2]);
    if (b.decryptWithAd(ad[0..adl], c3[0..n2], &out)) |_| return error.RekeyOneSideAccepted else |_| TrMark.mark(.rekey_one_side_refused);
    b.rekey();
    try b.decryptWithAd(ad[0..adl], c3[0..n2], &out);
}

fn fuzzTransportSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzTransport(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: transport cipher states: damage, replay, reorder and rekey" {
    try testing.fuzz({}, fuzzTransportSmith, .{});
}

test "fuzz driver: NOISE_FUZZ (transport)" {
    try fuzz_driver.run(fuzzTransport, .{ .prefix = "NOISE_FUZZ", .name = "noise-transport" });
}

test "fuzz harness: transport, 300 seeds, reaches every outcome" {
    try TrMark.reach(fuzzTransport, "noise-transport", 300);
}
