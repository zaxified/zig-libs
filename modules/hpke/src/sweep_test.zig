// SPDX-License-Identifier: MIT
//! No-panic sweep tests (wave GZ). Each test names the finding it kills; the
//! ones named "(sweep clean)" pin a bound that already held.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const testing = std.testing;
const aesgcm = @import("aesgcm");
const suite = @import("suite.zig");
const dhkem = @import("dhkem.zig");
const schedule = @import("schedule.zig");

const Aead = aesgcm.Aes128Gcm;
const Ctx = schedule.Context(Aead, 32);

/// Run `body` in a forked child with its stderr captured into `buf`; returns
/// the captured length and whether the child died from a signal (a panic
/// aborts). A child past five seconds counts as hung.
const Child = struct { died: bool, len: usize };

fn runChild(comptime body: fn () void, buf: []u8) !Child {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
    if (rc == 0) {
        _ = linux.dup2(fds[1], 2);
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        body();
        linux.exit_group(0);
    }
    _ = linux.close(fds[1]);
    defer _ = linux.close(fds[0]);
    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = 0;
    var waited_ms: usize = 0;
    while (true) {
        const r = linux.waitpid(pid, @ptrCast(&status), linux.W.NOHANG);
        if (linux.errno(r) != .SUCCESS) return error.WaitFailed;
        if (r == @as(usize, @intCast(pid))) break;
        if (waited_ms >= 5000) {
            _ = linux.kill(pid, .KILL);
            _ = linux.waitpid(pid, @ptrCast(&status), 0);
            return error.ChildHung;
        }
        const ts: linux.timespec = .{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
        waited_ms += 10;
    }
    const n = linux.read(fds[0], buf.ptr, buf.len);
    return .{ .died = linux.W.IFSIGNALED(status), .len = if (linux.errno(n) == .SUCCESS) n else 0 };
}

fn expectPanicMessage(comptime body: fn () void, needle: []const u8) !void {
    var buf: [8192]u8 = undefined;
    const c = try runChild(body, &buf);
    try testing.expect(c.died);
    try testing.expect(std.mem.find(u8, buf[0..c.len], needle) != null);
}

// Needles live in consts, never inline in the expectPanicMessage call: the
// child's stack trace prints the caller's source line (GS trap).
const needle_i2osp = "panic: hpke: i2osp: value does not fit in n bytes";
const needle_os2ip = "panic: hpke: os2ip: more than 8 bytes";

fn testCtx() Ctx {
    return .{ .key = @splat(1), .base_nonce = @splat(2), .exporter_secret = @splat(3) };
}

// ── HP-1: export / expand length past 255 * Nh ──────────────────────────────

test "labeledExpand: an output past 255*Nh is LabelTooLong, exactly 255*Nh works, for all three KDFs (sweep HP-1)" {
    const sid = suite.suiteId(0x0020, 0x0001, 0x0001);
    var big: [255 * 64 + 1]u8 = undefined;
    inline for (.{ 32, 48, 64 }) |nh| {
        const Kdf = schedule.KdfOf(nh);
        const prk: [nh]u8 = @splat(5);
        try testing.expectError(error.LabelTooLong, suite.labeledExpand(Kdf, &sid, &prk, "x", "", big[0 .. 255 * nh + 1]));
        try suite.labeledExpand(Kdf, &sid, &prk, "x", "", big[0 .. 255 * nh]);
        try suite.labeledExpand(Kdf, &sid, &prk, "x", "", big[0..0]);
    }
}

test "Context.exportSecret: length 255*Nh+1 is an error, never an assert or a wrapped counter (sweep HP-1)" {
    const sid = suite.suiteId(0x0020, 0x0001, 0x0001);
    const ctx = testCtx();
    var big: [255 * 32 + 1]u8 = undefined;
    try testing.expectError(error.LabelTooLong, ctx.exportSecret(&sid, "ctx", &big));
    // The ceiling itself is a valid export, and its blocks do not repeat
    // (a wrapped counter would repeat block 0 at block 256).
    try ctx.exportSecret(&sid, "ctx", big[0 .. 255 * 32]);
    try testing.expect(!std.mem.eql(u8, big[0..32], big[255 * 32 - 32 ..][0..32]));
    // 0 bytes is a no-op; past u16 stays an error.
    try ctx.exportSecret(&sid, "ctx", big[0..0]);
    const huge = try testing.allocator.alloc(u8, 70_000);
    defer testing.allocator.free(huge);
    try testing.expectError(error.LabelTooLong, ctx.exportSecret(&sid, "ctx", huge));
}

test "Context.exportSecret: an exporter_context too long for the label scratch is LabelTooLong (sweep clean)" {
    const sid = suite.suiteId(0x0020, 0x0001, 0x0001);
    const ctx = testCtx();
    var out: [32]u8 = undefined;
    const long = try testing.allocator.alloc(u8, 64 * 1024);
    defer testing.allocator.free(long);
    @memset(long, 'x');
    try testing.expectError(error.LabelTooLong, ctx.exportSecret(&sid, long, &out));
    try ctx.exportSecret(&sid, long[0..400], &out);
}

// ── HP-2: i2osp / os2ip contract ────────────────────────────────────────────

fn childI2osp2() void {
    var v: u64 = 0x1_0000;
    std.mem.doNotOptimizeAway(&v);
    _ = suite.i2osp(2, v);
}
fn childI2osp1() void {
    var v: u64 = 256;
    std.mem.doNotOptimizeAway(&v);
    _ = suite.i2osp(1, v);
}
fn childOs2ip9() void {
    var n: usize = 9;
    std.mem.doNotOptimizeAway(&n);
    const bytes: [9]u8 = @splat(1);
    _ = suite.os2ip(bytes[0..n]);
}

test "i2osp with a value that does not fit, and os2ip of more than 8 bytes, are checked panics (sweep HP-2)" {
    try expectPanicMessage(childI2osp2, needle_i2osp);
    try expectPanicMessage(childI2osp1, needle_i2osp);
    try expectPanicMessage(childOs2ip9, needle_os2ip);
    // Boundaries that must stay valid.
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff }, &suite.i2osp(2, 0xffff));
    try testing.expectEqualSlices(u8, &.{0xff}, &suite.i2osp(1, 255));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), suite.os2ip(&suite.i2osp(8, std.math.maxInt(u64))));
    try testing.expectEqual(@as(u64, 0), suite.os2ip(&.{}));
}

// ── sequence counter (sweep clean) ──────────────────────────────────────────

test "seal/open at the sequence ceiling: MessageLimitReached, output untouched, no wrap (sweep clean)" {
    var s = testCtx();
    s.seq = std.math.maxInt(u64);
    var out: [5 + Aead.tag_length]u8 = @splat(0xaa);
    try testing.expectError(error.MessageLimitReached, s.seal("", "hello", &out));
    try testing.expectEqualSlices(u8, &@as([out.len]u8, @splat(0xaa)), &out);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), s.seq);

    var r = testCtx();
    r.seq = std.math.maxInt(u64);
    var pt: [5]u8 = @splat(0xaa);
    try testing.expectError(error.MessageLimitReached, r.open("", &out, &pt));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), r.seq);
}

test "the last usable sequence number seals and opens once, then both sides stop (sweep clean)" {
    const last = std.math.maxInt(u64) - 1;
    var s = testCtx();
    s.seq = last;
    var r = testCtx();
    r.seq = last;
    var ct: [5 + Aead.tag_length]u8 = undefined;
    try s.seal("aad", "hello", &ct);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), s.seq);
    var pt: [5]u8 = undefined;
    try r.open("aad", &ct, &pt);
    try testing.expectEqualStrings("hello", &pt);
    try testing.expectError(error.MessageLimitReached, s.seal("aad", "hello", &ct));
    try testing.expectError(error.MessageLimitReached, r.open("aad", &ct, &pt));
}

test "open: a ciphertext shorter than the tag, a wrong out length and a bad tag are errors that keep seq (sweep clean)" {
    var r = testCtx();
    var pt: [64]u8 = undefined;
    var ct: [64]u8 = @splat(0x42);
    for (0..Aead.tag_length) |n| try testing.expectError(error.DecryptionFailed, r.open("", ct[0..n], pt[0..0]));
    try testing.expectError(error.InvalidLength, r.open("", ct[0..32], pt[0..3]));
    try testing.expectError(error.DecryptionFailed, r.open("", ct[0..32], pt[0 .. 32 - Aead.tag_length]));
    try testing.expectEqual(@as(u64, 0), r.seq);
    var s = testCtx();
    var out: [4]u8 = undefined;
    try testing.expectError(error.InvalidLength, s.seal("", "abc", &out));
    try testing.expectEqual(@as(u64, 0), s.seq);
}

// ── key schedule inputs (sweep clean) ───────────────────────────────────────

test "keySchedule: psk with base mode, psk without id, short psk are errors; 64 KiB info / psk_id are fine (sweep clean)" {
    const sid = suite.suiteId(0x0020, 0x0001, 0x0001);
    const ss: [32]u8 = @splat(9);
    var ctx: Ctx = undefined;
    const psk: [32]u8 = @splat(7);
    const short: [31]u8 = @splat(7);
    try testing.expectError(error.InconsistentPsk, schedule.keySchedule(Aead, 32, &ctx, .base, &sid, &ss, "", &psk, "id"));
    try testing.expectError(error.InconsistentPsk, schedule.keySchedule(Aead, 32, &ctx, .psk, &sid, &ss, "", &psk, ""));
    try testing.expectError(error.InconsistentPsk, schedule.keySchedule(Aead, 32, &ctx, .psk, &sid, &ss, "", "", ""));
    try testing.expectError(error.PskTooShort, schedule.keySchedule(Aead, 32, &ctx, .psk, &sid, &ss, "", &short, "id"));

    const big = try testing.allocator.alloc(u8, 64 * 1024);
    defer testing.allocator.free(big);
    @memset(big, 'i');
    try schedule.keySchedule(Aead, 32, &ctx, .psk, &sid, &ss, big, &psk, big);
    try schedule.keySchedule(Aead, 32, &ctx, .base, &sid, &ss, big, "", "");
}

// ── KEM inputs from the network (sweep clean) ───────────────────────────────

fn expectRejected(r: anytype) !void {
    if (r) |_| return error.TestUnexpectedResult else |e| {
        const name = @errorName(e);
        if (std.mem.eql(u8, name, "DeserializeError") or std.mem.eql(u8, name, "DhFailed")) return;
        return error.TestUnexpectedResult;
    }
}

test "X25519Kem: every low-order u-coordinate as enc / pkS is DhFailed, not a shared secret (sweep clean)" {
    const K = dhkem.X25519Kem;
    var kp: K.KeyPair = undefined;
    K.deriveKeyPair(&kp, "recipient ikm");
    var other: K.KeyPair = undefined;
    K.deriveKeyPair(&other, "other ikm");
    const low_order = [_][32]u8{
        @splat(0), // 0
        [_]u8{1} ++ @as([31]u8, @splat(0)), // 1
        // order 8 points (RFC 7748 / Bernstein list)
        .{ 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
        .{ 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57 },
        // p-1, p, p+1
        [_]u8{0xec} ++ @as([30]u8, @splat(0xff)) ++ [_]u8{0x7f},
        [_]u8{0xed} ++ @as([30]u8, @splat(0xff)) ++ [_]u8{0x7f},
        [_]u8{0xee} ++ @as([30]u8, @splat(0xff)) ++ [_]u8{0x7f},
    };
    var ss: [K.Nsecret]u8 = undefined;
    for (low_order) |pt| {
        try testing.expectError(error.DhFailed, K.decap(&ss, pt, &kp));
        try testing.expectError(error.DhFailed, K.authDecap(&ss, other.public_key, &kp, pt));
        var enc: K.Encapped = undefined;
        try testing.expectError(error.DhFailed, K.encapDeterministic(&enc, pt, &other));
        try testing.expectError(error.DhFailed, K.authEncapDeterministic(&enc, pt, &kp, &other));
        var ctx: schedule.Context(Aead, 32) = undefined;
        try testing.expectError(error.DhFailed, schedule.setupBaseR(K, Aead, 32, &ctx, pt, &kp, "info"));
    }
}

fn nistBadPoints(comptime K: type) [6]K.PublicKey {
    const half = (K.Npk - 1) / 2;
    const zero: K.PublicKey = @splat(0);
    var tag00 = zero;
    tag00[0] = 0x00; // SEC1 "infinity" tag in a full-length buffer
    var tag02 = zero;
    tag02[0] = 0x02; // compressed tag, wrong length
    var origin = zero;
    origin[0] = 0x04; // (0, 0): not on the curve
    var ones: K.PublicKey = @splat(0xff);
    ones[0] = 0x04; // coordinates >= p
    var xy1 = zero;
    xy1[0] = 0x04;
    xy1[half] = 1;
    xy1[2 * half] = 1; // (1, 1): not on the curve
    return .{ zero, tag00, tag02, origin, ones, xy1 };
}

test "P-256/P-384/P-521 Kems: malformed, off-curve and infinity points are rejected on every entry (sweep clean)" {
    inline for (.{ dhkem.P256Kem, dhkem.P384Kem, dhkem.P521Kem }) |K| {
        var kp: K.KeyPair = undefined;
        K.deriveKeyPair(&kp, "recipient ikm");
        var other: K.KeyPair = undefined;
        K.deriveKeyPair(&other, "other ikm");
        var ss: [K.Nsecret]u8 = undefined;
        for (nistBadPoints(K)) |bad| {
            try expectRejected(K.decap(&ss, bad, &kp));
            try expectRejected(K.authDecap(&ss, other.public_key, &kp, bad));
            try expectRejected(K.authDecap(&ss, bad, &kp, other.public_key));
            var enc: K.Encapped = undefined;
            try expectRejected(K.encapDeterministic(&enc, bad, &other));
            try expectRejected(K.authEncapDeterministic(&enc, bad, &kp, &other));
            var ctx: schedule.Context(Aead, K.Nsecret) = undefined;
            try expectRejected(schedule.setupBaseR(K, Aead, K.Nsecret, &ctx, bad, &kp, "info"));
        }
        // Positive control: the recipient's own valid public key as enc works.
        try K.decap(&ss, other.public_key, &kp);
    }
}

// ── REV-hpke-1: `out` is zeroed on every error path ─────────────────────────

fn expectZeroed(ptr: anytype) !void {
    for (std.mem.asBytes(ptr)) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "keySchedule zeroes out on the early precondition errors too (sweep REV-hpke-1)" {
    const sid = suite.suiteId(0x0020, 0x0001, 0x0001);
    const ss: [32]u8 = @splat(9);
    const psk: [32]u8 = @splat(7);
    const short: [31]u8 = @splat(7);
    var ctx: Ctx = undefined;
    @memset(std.mem.asBytes(&ctx), 0xaa);
    try testing.expectError(error.InconsistentPsk, schedule.keySchedule(Aead, 32, &ctx, .base, &sid, &ss, "", &psk, "id"));
    try expectZeroed(&ctx);
    @memset(std.mem.asBytes(&ctx), 0xaa);
    try testing.expectError(error.PskTooShort, schedule.keySchedule(Aead, 32, &ctx, .psk, &sid, &ss, "", &short, "id"));
    try expectZeroed(&ctx);
}

test "setupBaseR / setupPskR zero the Context when the KEM or the key schedule fails (sweep REV-hpke-1)" {
    const K = dhkem.X25519Kem;
    var kp: K.KeyPair = undefined;
    K.deriveKeyPair(&kp, "recipient ikm");
    var other: K.KeyPair = undefined;
    K.deriveKeyPair(&other, "other ikm");
    var ctx: Ctx = undefined;
    // KEM error: low-order enc.
    @memset(std.mem.asBytes(&ctx), 0xaa);
    try testing.expectError(error.DhFailed, schedule.setupBaseR(K, Aead, 32, &ctx, @splat(0), &kp, "info"));
    try expectZeroed(&ctx);
    // Key-schedule error after a successful KEM: short psk.
    @memset(std.mem.asBytes(&ctx), 0xaa);
    const short: [8]u8 = @splat(1);
    try testing.expectError(error.PskTooShort, schedule.setupPskR(K, Aead, 32, &ctx, other.public_key, &kp, "info", &short, "id"));
    try expectZeroed(&ctx);
}

test "setupBaseS zeroes Setup when the KEM fails (sweep REV-hpke-1)" {
    const K = dhkem.X25519Kem;
    var eph: K.KeyPair = undefined;
    K.deriveKeyPair(&eph, "eph ikm");
    var setup: schedule.Setup(K, Aead, 32) = undefined;
    @memset(std.mem.asBytes(&setup), 0xaa);
    try testing.expectError(error.DhFailed, schedule.setupBaseSDeterministic(K, Aead, 32, &setup, @splat(0), &eph, "info"));
    try expectZeroed(&setup);
    // (A key-schedule error after a successful sender-side KEM needs a bad psk;
    // setupPskSDeterministic below covers it.)
    var other: K.KeyPair = undefined;
    K.deriveKeyPair(&other, "other ikm");
    const short: [8]u8 = @splat(1);
    @memset(std.mem.asBytes(&setup), 0xaa);
    try testing.expectError(error.PskTooShort, schedule.setupPskSDeterministic(K, Aead, 32, &setup, other.public_key, &eph, "info", &short, "id"));
    try expectZeroed(&setup);
}

test "every KEM entry point zeroes its out parameter on error (sweep REV-hpke-1)" {
    inline for (.{ dhkem.X25519Kem, dhkem.P256Kem, dhkem.P384Kem, dhkem.P521Kem }) |K| {
        var kp: K.KeyPair = undefined;
        K.deriveKeyPair(&kp, "recipient ikm");
        var other: K.KeyPair = undefined;
        K.deriveKeyPair(&other, "other ikm");
        const bad: K.PublicKey = @splat(0);
        var ss: [K.Nsecret]u8 = undefined;
        var enc: K.Encapped = undefined;

        @memset(&ss, 0xaa);
        try expectRejected(K.decap(&ss, bad, &kp));
        try expectZeroed(&ss);
        @memset(&ss, 0xaa);
        try expectRejected(K.authDecap(&ss, other.public_key, &kp, bad));
        try expectZeroed(&ss);
        @memset(&ss, 0xaa);
        try expectRejected(K.authDecap(&ss, bad, &kp, other.public_key));
        try expectZeroed(&ss);
        @memset(std.mem.asBytes(&enc), 0xaa);
        try expectRejected(K.encapDeterministic(&enc, bad, &other));
        try expectZeroed(&enc);
        @memset(std.mem.asBytes(&enc), 0xaa);
        try expectRejected(K.authEncapDeterministic(&enc, bad, &kp, &other));
        try expectZeroed(&enc);
    }
}

// ── blind review 2026-10-31: the expanded AES key never goes stale ──────────

test "Context built from undefined, then fields set, seals like the literal-built one (review MED-1)" {
    var a = testCtx();
    var b: Ctx = undefined;
    b.key = a.key;
    b.base_nonce = a.base_nonce;
    b.seq = 0;
    b.exporter_secret = a.exporter_secret;
    var ca: [5 + Aead.tag_length]u8 = undefined;
    var cb: [5 + Aead.tag_length]u8 = undefined;
    try a.seal("aad", "hello", &ca);
    try b.seal("aad", "hello", &cb);
    try testing.expectEqualSlices(u8, &ca, &cb);
}

test "rewriting key after a seal re-expands it (review MED-2)" {
    var a = testCtx();
    var ct: [5 + Aead.tag_length]u8 = undefined;
    try a.seal("aad", "hello", &ct);
    a.key = @splat(9);
    a.seq = 0;
    try a.seal("aad", "hello", &ct);
    var fresh = testCtx();
    fresh.key = @splat(9);
    var pt: [5]u8 = undefined;
    try fresh.open("aad", &ct, &pt);
    try testing.expectEqualStrings("hello", &pt);
}

test "max_message_len matches the AEAD limits (review LOW-1)" {
    try testing.expectEqual(@as(u64, 16 * ((1 << 32) - 2)), Ctx.max_message_len);
}
