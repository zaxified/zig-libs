// SPDX-License-Identifier: MIT
//! Error-edge tests of the handshake state machine: out-buffer sizes at every
//! stage, pattern validation, completion and the wipe after it. They exist
//! because a whole-module mutation run found every one of these bounds and
//! refusals unpinned.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const patterns = root.patterns;

const TestSuite = root.DefaultSuite;

test "CipherState: an out buffer one byte short is refused, exactly enough works (keyed or not, both directions)" {
    const S = TestSuite;
    var cs: S.CipherState = .{};
    var out: [64]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, cs.encryptWithAd("", "abcd", out[0..3]));
    try cs.encryptWithAd("", "abcd", out[0..4]);
    try testing.expectError(error.BufferTooSmall, cs.decryptWithAd("", "abcd", out[0..3]));
    try cs.decryptWithAd("", "abcd", out[0..4]);

    const key: [32]u8 = @splat(7);
    cs.initializeKey(&key);
    try testing.expectError(error.BufferTooSmall, cs.encryptWithAd("", "abcd", out[0 .. 4 + S.TAGLEN - 1]));
    try testing.expectEqual(@as(u64, 0), cs.n);
    try cs.encryptWithAd("", "abcd", out[0 .. 4 + S.TAGLEN]);
    var ct: [4 + S.TAGLEN]u8 = out[0 .. 4 + S.TAGLEN].*;
    var rx: S.CipherState = .{};
    rx.initializeKey(&key);
    try testing.expectError(error.BufferTooSmall, rx.decryptWithAd("", &ct, out[0..3]));
    try testing.expectEqual(@as(u64, 0), rx.n);
    try rx.decryptWithAd("", &ct, out[0..4]);
    try testing.expectEqualSlices(u8, "abcd", out[0..4]);
}

test "SymmetricState: encryptAndHash/decryptAndHash demand the exact out size; a ciphertext shorter than the tag is refused" {
    const S = TestSuite;
    var ss: S.SymmetricState = .{};
    ss.initializeSymmetric("test");
    var out: [64]u8 = undefined;
    // No key yet: the out buffer must be exactly as long as the input.
    try testing.expectError(error.BufferTooSmall, ss.encryptAndHash("abcd", out[0..5]));
    try testing.expectError(error.BufferTooSmall, ss.encryptAndHash("abcd", out[0..3]));
    try testing.expectError(error.BufferTooSmall, ss.decryptAndHash("abcd", out[0..5]));
    try testing.expectError(error.BufferTooSmall, ss.decryptAndHash("abcd", out[0..3]));
    // With a key: a ciphertext shorter than the tag, and an out buffer longer
    // than plaintext + tag.
    ss.mixKey("ikm");
    const short: [S.TAGLEN - 1]u8 = @splat(0);
    try testing.expectError(error.BufferTooSmall, ss.decryptAndHash(&short, out[0..0]));
    try testing.expectError(error.BufferTooSmall, ss.encryptAndHash("abcd", out[0 .. 4 + S.TAGLEN + 1]));
}

test "SymmetricState.initializeSymmetric drops a key mixed in earlier" {
    const S = TestSuite;
    var ss: S.SymmetricState = .{};
    ss.initializeSymmetric("first");
    ss.mixKey("ikm");
    try testing.expect(ss.cipher_state.hasKey());
    ss.initializeSymmetric("second");
    try testing.expect(!ss.cipher_state.hasKey());
    try testing.expectEqual(@as(usize, 0), ss.cipher_state.overhead());
}

test "HandshakeState.init: the longest name that fits is accepted, one more is not; a pre-message key listed twice is refused" {
    const S = TestSuite;
    const max_name = 128 - 6 - S.name_suffix.len;
    const ok_name: [max_name]u8 = @splat('A');
    const bad_name: [max_name + 1]u8 = @splat('A');
    var hs: S.HandshakeState = .{};
    var p = patterns.NN;
    p.name = &ok_name;
    try hs.init(p, true, "", &.{});
    p.name = &bad_name;
    try testing.expectError(error.InvalidPattern, hs.init(p, true, "", &.{}));

    const kp = try @as(anyerror!S.KeyPair, S.KeyPair.generateDeterministic(@splat(1)));
    var dup_s = patterns.NN;
    dup_s.pre_message_responder = &.{ .s, .s };
    try testing.expectError(error.InvalidPattern, hs.init(dup_s, true, "", &.{ .rs = kp.public_key }));
    // A message-less body, so only the pre-message check can refuse it (NN's
    // own `e` would trip the later duplicate check and hide a missing one).
    const dup_e: patterns.HandshakePattern = .{ .name = "DUPE", .pre_message_initiator = &.{ .e, .e }, .message_patterns = &.{&.{}} };
    try testing.expectError(error.InvalidPattern, hs.init(dup_e, true, "", &.{ .e = &kp }));
}

test "a completed handshake leaves no key material in either HandshakeState and refuses further messages" {
    const S = TestSuite;
    var prng = std.Random.DefaultPrng.init(5);
    const random = prng.random();
    var ini: S.HandshakeState = .{};
    var rsp: S.HandshakeState = .{};
    try ini.init(patterns.NN, true, "", &.{});
    try rsp.init(patterns.NN, false, "", &.{});
    var buf: [128]u8 = undefined;
    var pay: [16]u8 = undefined;
    var tx: [2]S.CipherState = undefined;
    var rx: [2]S.CipherState = undefined;
    const w1 = try ini.writeMessage(random, "", &buf, &tx);
    _ = try rsp.readMessage(buf[0..w1.len], &pay, &rx);
    // The responder completes by writing, the initiator by reading.
    const w2 = try rsp.writeMessage(random, "", &buf, &rx);
    try testing.expect(w2.complete);
    const r2 = try ini.readMessage(buf[0..w2.len], &pay, &tx);
    try testing.expect(r2.complete);
    for ([_]*S.HandshakeState{ &ini, &rsp }) |hs| {
        try testing.expect(hs.e != null);
        for (hs.e.?.secret_key) |b| try testing.expectEqual(@as(u8, 0), b);
        for (hs.symmetric_state.ck) |b| try testing.expectEqual(@as(u8, 0), b);
        for (hs.symmetric_state.cipher_state.k) |b| try testing.expectEqual(@as(u8, 0), b);
        try testing.expect(!hs.symmetric_state.cipher_state.hasKey());
        try testing.expectError(error.HandshakeComplete, hs.writeMessage(random, "", &buf, &tx));
        try testing.expectError(error.HandshakeComplete, hs.readMessage(buf[0..32], &pay, &tx));
    }
}

/// Two parties of `pattern` (fixed static keys), replayed to just before
/// message `step`, so a test can probe that one message with different buffers.
const EdgeRun = struct {
    const S = TestSuite;
    ini: S.HandshakeState = .{},
    rsp: S.HandshakeState = .{},
    prng: std.Random.DefaultPrng = std.Random.DefaultPrng.init(42),

    fn start(self: *EdgeRun, pattern: patterns.HandshakePattern, step: usize, payload: []const u8) !void {
        const ki = try @as(anyerror!S.KeyPair, S.KeyPair.generateDeterministic(@splat(1)));
        const kr = try @as(anyerror!S.KeyPair, S.KeyPair.generateDeterministic(@splat(2)));
        try self.ini.init(pattern, true, "", &.{ .s = &ki });
        try self.rsp.init(pattern, false, "", &.{ .s = &kr });
        var big: [256]u8 = undefined;
        var pl: [64]u8 = undefined;
        var tr: [2]S.CipherState = undefined;
        for (0..step) |m| {
            const w = if (m % 2 == 0) &self.ini else &self.rsp;
            const r = if (m % 2 == 0) &self.rsp else &self.ini;
            const s = try w.writeMessage(self.prng.random(), payload, &big, &tr);
            _ = try r.readMessage(big[0..s.len], &pl, &tr);
        }
    }

    fn writer(self: *EdgeRun, step: usize) *S.HandshakeState {
        return if (step % 2 == 0) &self.ini else &self.rsp;
    }

    fn reader(self: *EdgeRun, step: usize) *S.HandshakeState {
        return if (step % 2 == 0) &self.rsp else &self.ini;
    }
};

fn expectBufferEdges(comptime pattern: patterns.HandshakePattern, payload: []const u8) !void {
    const S = TestSuite;
    var tr: [2]S.CipherState = undefined;
    inline for (0..pattern.message_patterns.len) |step| {
        // The message's length, from a run with room to spare.
        var wire: [256]u8 = undefined;
        var run: EdgeRun = .{};
        try run.start(pattern, step, payload);
        const need = (try run.writer(step).writeMessage(run.prng.random(), payload, &wire, &tr)).len;
        // Writing: every shorter buffer is refused, exactly `need` is enough.
        for (0..need + 1) |have| {
            var r2: EdgeRun = .{};
            try r2.start(pattern, step, payload);
            var out: [256]u8 = undefined;
            const res = r2.writer(step).writeMessage(r2.prng.random(), payload, out[0..have], &tr);
            if (have < need) {
                try testing.expectError(error.BufferTooSmall, res);
            } else {
                try testing.expectEqual(need, (try res).len);
            }
        }
        // Reading: a payload buffer one byte short is refused, exactly enough works.
        for (0..payload.len + 1) |have| {
            var r3: EdgeRun = .{};
            try r3.start(pattern, step, payload);
            const sent = (try r3.writer(step).writeMessage(r3.prng.random(), payload, &wire, &tr)).len;
            var pl: [64]u8 = undefined;
            const res = r3.reader(step).readMessage(wire[0..sent], pl[0..have], &tr);
            if (have < payload.len) {
                try testing.expectError(error.BufferTooSmall, res);
            } else {
                try testing.expectEqual(payload.len, (try res).len);
                try testing.expectEqualSlices(u8, payload, pl[0..have]);
            }
        }
    }
}

test "writeMessage/readMessage: a too small out buffer is refused at every stage, an exact one works" {
    // NN with an empty payload: message 1 is the bare ephemeral, DHLEN bytes.
    try expectBufferEdges(patterns.NN, "");
    try expectBufferEdges(patterns.NN, "hello");
    try expectBufferEdges(patterns.XX, "hello");
    // IN sends `e, s` before any key exists: no tag anywhere in message 1, so
    // an empty payload fits in exactly DHLEN + DHLEN bytes.
    try expectBufferEdges(patterns.IN, "");
    try expectBufferEdges(patterns.IN, "hello");
}

test "mutation 2026-11-25: CipherState.wipe zeroes the key and the nonce counter and empties the state" {
    const S = TestSuite;
    var cs: S.CipherState = .{};
    const key: [32]u8 = @splat(9);
    cs.initializeKey(&key);
    var out: [4 + S.TAGLEN]u8 = undefined;
    try cs.encryptWithAd("", "abcd", &out);
    try cs.encryptWithAd("", "abcd", &out);
    try testing.expectEqual(@as(u64, 2), cs.n);
    cs.wipe();
    try testing.expectEqual(@as(u64, 0), cs.n);
    try testing.expect(!cs.hasKey());
    try testing.expect(std.mem.allEqual(u8, &cs.k, 0));
    // Empty again: encrypt is the identity, and re-keying starts a fresh counter.
    var plain: [4]u8 = undefined;
    try cs.encryptWithAd("", "abcd", &plain);
    try testing.expectEqualSlices(u8, "abcd", &plain);
    cs.initializeKey(&key);
    try testing.expectEqual(@as(u64, 0), cs.n);
}
