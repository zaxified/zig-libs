// SPDX-License-Identifier: MIT

//! stream_test — the version-2 streaming format: round trips across the
//! chunk boundaries, a byte-exact cross-check of the payload against
//! `tlock.age`'s whole-buffer STREAM (which decrypts drand Go-`tle` files
//! byte-exactly), the AND negatives, and the stream-specific attacks
//! (truncation, reordering, appended bytes, the streaming release).
//! The time gate uses the same genuine quicknet round-1000 vector as
//! `security_test.zig`.

const std = @import("std");
const tlock = @import("tlock");
const hqc = @import("hqc");
const envelope = @import("envelope.zig");
const stream = @import("stream.zig");
const fx = @import("security_test.zig");

const testing = std.testing;
const age = tlock.age;
const Env = envelope.Envelope128;
const Kem = hqc.Hqc128;
const Sha256 = std.crypto.hash.sha2.Sha256;

const chunk = stream.chunk_bytes;
const prefix_bytes = stream.Stream(Kem).prefix_bytes;

fn pattern(gpa: std.mem.Allocator, len: usize) ![]u8 {
    const pt = try gpa.alloc(u8, len);
    for (pt, 0..) |*b, i| b.* = @truncate(i *% 131 +% 7);
    return pt;
}

/// Seal `pt` with the fixed test randomness; caller frees.
fn sealAlloc(pt: []const u8, kp: Kem.KeyPair) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer aw.deinit();
    var r: std.Io.Reader = .fixed(pt);
    try Env.sealStream(testing.allocator, &aw.writer, &r, kp.ek, fx.quicknetPubkey(), fx.seal_round, fx.fixedRandomness());
    return aw.toOwnedSlice();
}

const Opened = struct {
    result: stream.StreamOpenError!void,
    written: []u8,
};

/// Open `wire`; returns the error union AND whatever was written (the
/// streaming release is part of the contract). Caller frees `written`.
fn openCollect(wire: []const u8, dk: Kem.DecapsKey, sig: tlock.bls12_381.g1.Affine) !Opened {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer aw.deinit();
    var r: std.Io.Reader = .fixed(wire);
    const result = Env.openStream(testing.allocator, &aw.writer, &r, dk, sig);
    return .{ .result = result, .written = try aw.toOwnedSlice() };
}

fn expectOpenError(wire: []const u8, dk: Kem.DecapsKey, sig: tlock.bls12_381.g1.Affine, allowed: []const anyerror) !void {
    const o = try openCollect(wire, dk, sig);
    defer testing.allocator.free(o.written);
    if (o.result) |_| {
        return error.TestUnexpectedSuccess;
    } else |err| {
        for (allowed) |a| if (err == a) return;
        std.debug.print("unexpected error {s}\n", .{@errorName(err)});
        return error.TestUnexpectedError;
    }
}

const sizes = [_]usize{ 0, 1, chunk - 1, chunk, chunk + 1, 2 * chunk, 2 * chunk + 5 };

test "stream round-trips across every chunk boundary, at exactly streamSealedLen" {
    const kp = fx.recipientKeypair(0x01);
    for (sizes) |len| {
        const pt = try pattern(testing.allocator, len);
        defer testing.allocator.free(pt);
        const wire = try sealAlloc(pt, kp);
        defer testing.allocator.free(wire);
        try testing.expectEqual(Env.streamSealedLen(len), wire.len);

        const o = try openCollect(wire, kp.dk, fx.round1000Signature());
        defer testing.allocator.free(o.written);
        try o.result;
        try testing.expectEqualSlices(u8, pt, o.written);
    }
}

test "the payload is byte-exactly tlock.age's whole-buffer STREAM under the derived key" {
    // `tlock.age.sealPayload`/`openPayload` are the loops `tlock`'s
    // Go-`tle` whole-file KAT runs, so this pins the streaming sealer's
    // chunking (one-byte lookahead, full last chunk, empty payload) to an
    // implementation anchored outside this module. The key is recomputed
    // here from the documented derivation, not taken from `sealStream`.
    const kp = fx.recipientKeypair(0x01);
    const rnd = fx.fixedRandomness();
    const ss = Kem.encaps(kp.ek, &rnd.kem_coins).ss;
    for (sizes) |len| {
        const pt = try pattern(testing.allocator, len);
        defer testing.allocator.free(pt);
        const wire = try sealAlloc(pt, kp);
        defer testing.allocator.free(wire);

        var th: [32]u8 = undefined;
        Sha256.hash(wire[0..prefix_bytes], &th, .{});
        const key = stream.deriveStreamKey(rnd.s_time, ss, Env.suite_id, fx.seal_round, th);

        const want = try testing.allocator.alloc(u8, age.sealedLen(len));
        defer testing.allocator.free(want);
        age.sealPayload(want, key, pt);
        try testing.expectEqualSlices(u8, want, wire[prefix_bytes..]);

        const back = try testing.allocator.alloc(u8, try age.openedLen(wire.len - prefix_bytes));
        defer testing.allocator.free(back);
        try age.openPayload(back, key, wire[prefix_bytes..]);
        try testing.expectEqualSlices(u8, pt, back);
    }
}

test "stream round-trips across all three HQC parameter sets" {
    inline for (.{
        .{ envelope.Envelope128, hqc.Hqc128 },
        .{ envelope.Envelope192, hqc.Hqc192 },
        .{ envelope.Envelope256, hqc.Hqc256 },
    }) |pair| {
        const E = pair[0];
        const K = pair[1];
        const kp = K.keypair(&[_]u8{0x07} ** 32);
        const rnd: E.SealRandomness = .{
            .s_time = [_]u8{0x44} ** envelope.time_secret_bytes,
            .tlock_sigma = [_]u8{0x55} ** envelope.time_secret_bytes,
            .kem_coins = [_]u8{0x66} ** K.coins_bytes,
        };
        const pt = "the launch codes expire at dawn";
        var aw: std.Io.Writer.Allocating = .init(testing.allocator);
        defer aw.deinit();
        var r: std.Io.Reader = .fixed(pt);
        try E.sealStream(testing.allocator, &aw.writer, &r, kp.ek, fx.quicknetPubkey(), fx.seal_round, rnd);

        var out: std.Io.Writer.Allocating = .init(testing.allocator);
        defer out.deinit();
        var r2: std.Io.Reader = .fixed(aw.written());
        try E.openStream(testing.allocator, &out.writer, &r2, kp.dk, fx.round1000Signature());
        try testing.expectEqualSlices(u8, pt, out.written());
    }
}

test "AND: the wrong round signature closes the time gate, the wrong HQC key fails the first tag" {
    const kp = fx.recipientKeypair(0x01);
    const wire = try sealAlloc("secret", kp);
    defer testing.allocator.free(wire);
    try expectOpenError(wire, kp.dk, fx.wrongSignature(), &.{error.TimeGateClosed});
    const other = fx.recipientKeypair(0x09);
    try expectOpenError(wire, other.dk, fx.round1000Signature(), &.{error.AuthFailed});
}

test "every header and lock byte is bound: flipping any one fails, never opens" {
    const kp = fx.recipientKeypair(0x01);
    const wire = try sealAlloc("secret", kp);
    defer testing.allocator.free(wire);
    const Case = struct { off: usize, allowed: []const anyerror };
    const cases = [_]Case{
        .{ .off = 0, .allowed = &.{error.BadMagic} },
        .{ .off = 4, .allowed = &.{error.UnsupportedVersion} },
        .{ .off = 5, .allowed = &.{error.SuiteMismatch} },
        // flags: unconstrained by the parser, bound only through the key.
        .{ .off = 6, .allowed = &.{error.AuthFailed} },
        // round: the time lock still opens (its ciphertext is intact), so
        // only the key binding refuses it.
        .{ .off = 7, .allowed = &.{error.AuthFailed} },
        .{ .off = stream.stream_header_bytes + 5, .allowed = &.{ error.MalformedTimeLock, error.TimeGateClosed } },
        .{ .off = stream.stream_header_bytes + 127, .allowed = &.{ error.MalformedTimeLock, error.TimeGateClosed } },
        .{ .off = stream.stream_header_bytes + 128 + 10, .allowed = &.{error.AuthFailed} },
        .{ .off = prefix_bytes - 1, .allowed = &.{error.AuthFailed} },
        .{ .off = prefix_bytes, .allowed = &.{error.AuthFailed} },
        .{ .off = wire.len - 1, .allowed = &.{error.AuthFailed} },
    };
    const bad = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(bad);
    for (cases) |c| {
        @memcpy(bad, wire);
        bad[c.off] ^= 0x01;
        try expectOpenError(bad, kp.dk, fx.round1000Signature(), c.allowed);
    }
}

test "stream attacks: truncation, reordering, appended bytes" {
    const kp = fx.recipientKeypair(0x01);
    const pt = try pattern(testing.allocator, 2 * chunk + 5);
    defer testing.allocator.free(pt);
    const wire = try sealAlloc(pt, kp);
    defer testing.allocator.free(wire);
    const sig = fx.round1000Signature();
    const c0 = prefix_bytes;
    const c1 = c0 + stream.sealed_chunk_bytes;
    const c2 = c1 + stream.sealed_chunk_bytes;

    // Truncated inside the header / locks.
    try expectOpenError(wire[0 .. stream.stream_header_bytes - 1], kp.dk, sig, &.{error.Truncated});
    try expectOpenError(wire[0 .. prefix_bytes - 1], kp.dk, sig, &.{error.Truncated});
    // No payload at all: not even the one chunk the empty plaintext seals to.
    try expectOpenError(wire[0..prefix_bytes], kp.dk, sig, &.{error.MalformedPayload});
    // Truncated at a chunk boundary: the now-final chunk was sealed as
    // non-last, so its tag fails under the last flag.
    try expectOpenError(wire[0..c2], kp.dk, sig, &.{error.AuthFailed});
    try expectOpenError(wire[0..c1], kp.dk, sig, &.{error.AuthFailed});
    // Truncated inside the last chunk, and down to a stub shorter than a tag.
    try expectOpenError(wire[0 .. wire.len - 1], kp.dk, sig, &.{error.AuthFailed});
    try expectOpenError(wire[0 .. c2 + 3], kp.dk, sig, &.{error.MalformedPayload});
    // One byte appended.
    const longer = try std.mem.concat(testing.allocator, u8, &.{ wire, "x" });
    defer testing.allocator.free(longer);
    try expectOpenError(longer, kp.dk, sig, &.{error.AuthFailed});
    // Chunks 0 and 1 swapped.
    const swapped = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(swapped);
    @memcpy(swapped[c0..c1], wire[c1..c2]);
    @memcpy(swapped[c1..c2], wire[c0..c1]);
    try expectOpenError(swapped, kp.dk, sig, &.{error.AuthFailed});
    // A chunk dropped (chunk 1 removed).
    const dropped = try std.mem.concat(testing.allocator, u8, &.{ wire[0..c1], wire[c2..] });
    defer testing.allocator.free(dropped);
    try expectOpenError(dropped, kp.dk, sig, &.{error.AuthFailed});
}

test "streaming release: chunks before a tampered one are written, authentic and in order, and the open fails" {
    // Pins the documented contract: output is complete only on success.
    const kp = fx.recipientKeypair(0x01);
    const pt = try pattern(testing.allocator, 2 * chunk + 5);
    defer testing.allocator.free(pt);
    const wire = try sealAlloc(pt, kp);
    defer testing.allocator.free(wire);
    wire[prefix_bytes + stream.sealed_chunk_bytes + 100] ^= 0x80; // inside chunk 1

    const o = try openCollect(wire, kp.dk, fx.round1000Signature());
    defer testing.allocator.free(o.written);
    try testing.expectError(error.AuthFailed, o.result);
    try testing.expectEqualSlices(u8, pt[0..chunk], o.written);
}

test "version 1 and version 2 each refuse the other's wire" {
    const kp = fx.recipientKeypair(0x01);
    const v1 = try Env.seal(testing.allocator, "secret", kp.ek, fx.quicknetPubkey(), fx.seal_round, fx.fixedRandomness());
    defer testing.allocator.free(v1);
    try expectOpenError(v1, kp.dk, fx.round1000Signature(), &.{error.UnsupportedVersion});

    const v2 = try sealAlloc("secret", kp);
    defer testing.allocator.free(v2);
    try testing.expectError(error.UnsupportedVersion, Env.parse(v2));
}

test "a stream sealed for one HQC set is SuiteMismatch for another" {
    const kp = fx.recipientKeypair(0x01);
    const wire = try sealAlloc("secret", kp);
    defer testing.allocator.free(wire);
    const kp256 = hqc.Hqc256.keypair(&[_]u8{0x01} ** 32);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var r: std.Io.Reader = .fixed(wire);
    try testing.expectError(error.SuiteMismatch, envelope.Envelope256.openStream(testing.allocator, &out.writer, &r, kp256.dk, fx.round1000Signature()));
}

test "sealStream and openStream release their memory on allocation failure" {
    const kp = fx.recipientKeypair(0x01);
    const pt = "secret";
    {
        var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
        var aw: std.Io.Writer.Allocating = .init(testing.allocator);
        defer aw.deinit();
        var r: std.Io.Reader = .fixed(pt);
        try testing.expectError(error.OutOfMemory, Env.sealStream(fa.allocator(), &aw.writer, &r, kp.ek, fx.quicknetPubkey(), fx.seal_round, fx.fixedRandomness()));
    }
    const wire = try sealAlloc(pt, kp);
    defer testing.allocator.free(wire);
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var r: std.Io.Reader = .fixed(wire);
    try testing.expectError(error.OutOfMemory, Env.openStream(fa.allocator(), &aw.writer, &r, kp.dk, fx.round1000Signature()));
}
