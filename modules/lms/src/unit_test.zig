// SPDX-License-Identifier: MIT
//! Round trips, the stateful discipline, structural rejections and the
//! tree-cache differential. RFC vectors are in `kat_test.zig`.

const std = @import("std");
const lms = @import("root.zig");
const core = @import("core.zig");

const gpa = std.testing.allocator;
const Level = lms.Level;

fn seedOf(b: u8) [32]u8 {
    return @splat(b);
}

fn idOf(b: u8) [16]u8 {
    return @splat(b);
}

test "coef: the RFC's worked examples (S = 0x1234)" {
    const s = [_]u8{ 0x12, 0x34 };
    try std.testing.expectEqual(@as(u8, 0), core.coef(&s, 7, 1));
    try std.testing.expectEqual(@as(u8, 1), core.coef(&s, 0, 4));
    try std.testing.expectEqual(@as(u8, 2), core.coef(&s, 1, 4));
    try std.testing.expectEqual(@as(u8, 3), core.coef(&s, 2, 4));
    try std.testing.expectEqual(@as(u8, 4), core.coef(&s, 3, 4));
    try std.testing.expectEqual(@as(u8, 0x12), core.coef(&s, 0, 8));
    try std.testing.expectEqual(@as(u8, 0x34), core.coef(&s, 1, 8));
    try std.testing.expectEqual(@as(u8, 0), core.coef(&s, 0, 2)); // 00 01 00 10
    try std.testing.expectEqual(@as(u8, 1), core.coef(&s, 1, 2));
    try std.testing.expectEqual(@as(u8, 2), core.coef(&s, 3, 2));
}

test "Cksm: extreme message hashes" {
    // Q = 0: every digit contributes its maximum, sum = (n*8/w) * (2^w - 1) = 256*...
    const zero: [32]u8 = @splat(0);
    const ones: [32]u8 = @splat(0xff);
    for ([_]lms.OtsParamSet{ .sha256_n32_w1, .sha256_n32_w2, .sha256_n32_w4, .sha256_n32_w8 }) |o| {
        const z = core.withChecksum(o, &zero);
        // sum = 256 bits in total for w-bit digits: 256/w digits * (2^w - 1)
        const sum: u32 = (256 / @as(u32, o.w())) * ((@as(u32, 1) << o.w()) - 1);
        try std.testing.expectEqual(@as(u16, @intCast(sum << o.ls())), std.mem.readInt(u16, z[32..34], .big));
        const f = core.withChecksum(o, &ones);
        try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, f[32..34], .big));
    }
}

fn qOf(sig: []const u8) u32 {
    return std.mem.readInt(u32, sig[0..4], .big);
}

test "LMS round trip for every LM-OTS w at H5, index strictly increasing" {
    for ([_]lms.OtsParamSet{ .sha256_n32_w1, .sha256_n32_w2, .sha256_n32_w4, .sha256_n32_w8 }) |o| {
        var sk = try lms.LmsSecretKey.init(gpa, .sha256_m32_h5, o, idOf(7), seedOf(9));
        defer sk.deinit();
        const pk_bytes = sk.publicKey().toBytes();
        var buf: [lms.max_lms_signature_length]u8 = undefined;
        var last: ?u32 = null;
        for ([_][]const u8{ "first", "second", "" }) |msg| {
            const sig = try sk.sign(msg, &buf);
            try std.testing.expectEqual(lms.lmsSignatureLength(.sha256_m32_h5, o), sig.len);
            const q = qOf(sig);
            if (last) |l| try std.testing.expect(q > l);
            last = q;
            try std.testing.expectEqual(q + 1, sk.q); // advanced past the leaf just used
            try std.testing.expect(lms.lmsVerify(&pk_bytes, msg, sig));
            try std.testing.expect(!lms.lmsVerify(&pk_bytes, "other", sig));
            // A wrong-length signature never verifies.
            try std.testing.expect(!lms.lmsVerify(&pk_bytes, msg, sig[0 .. sig.len - 1]));
        }
        try std.testing.expectEqual(@as(u32, 3), sk.q);
    }
}

test "LMS round trip at H10 (w2), and an unrelated key rejects" {
    var sk = try lms.LmsSecretKey.init(gpa, .sha256_m32_h10, .sha256_n32_w2, idOf(1), seedOf(2));
    defer sk.deinit();
    var other = try lms.LmsSecretKey.init(gpa, .sha256_m32_h5, .sha256_n32_w2, idOf(1), seedOf(2));
    defer other.deinit();
    var buf: [lms.max_lms_signature_length]u8 = undefined;
    const sig = try sk.sign("h10", &buf);
    try std.testing.expect(sk.publicKey().verify("h10", sig));
    try std.testing.expect(!other.publicKey().verify("h10", sig));
}

test "LMS: exhausted key returns KeyExhausted and never signs again" {
    var sk = try lms.LmsSecretKey.init(gpa, .sha256_m32_h5, .sha256_n32_w1, idOf(3), seedOf(4));
    defer sk.deinit();
    var buf: [lms.max_lms_signature_length]u8 = undefined;
    var last: i64 = -1;
    for (0..32) |_| {
        const sig = try sk.sign("m", &buf);
        try std.testing.expect(qOf(sig) > last);
        last = qOf(sig);
    }
    try std.testing.expectEqual(@as(i64, 31), last);
    try std.testing.expectError(error.KeyExhausted, sk.sign("m", &buf));
    try std.testing.expectEqual(@as(u32, 32), sk.q);
}

test "LMS: OutputTooSmall consumes no leaf" {
    var sk = try lms.LmsSecretKey.init(gpa, .sha256_m32_h5, .sha256_n32_w8, idOf(3), seedOf(4));
    defer sk.deinit();
    var small: [100]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, sk.sign("m", &small));
    try std.testing.expectEqual(@as(u32, 0), sk.q);
}

test "tree cache height changes cost, never the signature" {
    var full = try lms.Tree.initCached(gpa, .sha256_m32_h5, .sha256_n32_w1, idOf(5), seedOf(6), 0);
    defer full.deinit();
    const len = lms.lmsSignatureLength(.sha256_m32_h5, .sha256_n32_w1);
    var a: [lms.max_lms_signature_length]u8 = undefined;
    var b: [lms.max_lms_signature_length]u8 = undefined;
    for ([_]u5{ 2, 3, 5 }) |c| {
        var t = try lms.Tree.initCached(gpa, .sha256_m32_h5, .sha256_n32_w1, idOf(5), seedOf(6), c);
        defer t.deinit();
        try std.testing.expectEqualSlices(u8, &full.root(), &t.root());
        try std.testing.expectEqual((@as(usize, 1) << (5 - c + 1)) - 1, t.nodes.len);
        for ([_]u32{ 0, 1, 6, 17, 31 }) |q| {
            full.sign(q, "msg", a[0..len]);
            t.sign(q, "msg", b[0..len]);
            try std.testing.expectEqualSlices(u8, a[0..len], b[0..len]);
        }
    }
}

/// T[r] straight from §5.3's recursive definition, independent of `Tree`'s
/// stack traversal and node cache.
fn recursiveNode(o: lms.OtsParamSet, h: u5, id: *const [16]u8, seed: *const [32]u8, r: u32) [32]u8 {
    const leaves = @as(u32, 1) << h;
    if (r >= leaves) {
        const k = core.otsPublicKeyHash(o, id, r - leaves, seed);
        return core.leafHash(id, r, &k);
    }
    const l = recursiveNode(o, h, id, seed, 2 * r);
    const rr = recursiveNode(o, h, id, seed, 2 * r + 1);
    return core.intrHash(id, r, &l, &rr);
}

test "tree root equals the recursive definition of T[1] (§5.3)" {
    var t = try lms.Tree.init(gpa, .sha256_m32_h5, .sha256_n32_w1, idOf(0x42), seedOf(0x24));
    defer t.deinit();
    const want = recursiveNode(.sha256_n32_w1, 5, &t.id, &t.seed, 1);
    try std.testing.expectEqualSlices(u8, &want, &t.root());
    // Every cached node, not only the root.
    for (1..t.nodes.len + 1) |r| {
        const w = recursiveNode(.sha256_n32_w1, 5, &t.id, &t.seed, @intCast(r));
        try std.testing.expectEqualSlices(u8, &w, &t.nodes[r - 1]);
    }
}

fn levelsOf(comptime spec: []const struct { lms.ParamSet, lms.OtsParamSet }) [spec.len]Level {
    var out: [spec.len]Level = undefined;
    inline for (spec, 0..) |s, i| out[i] = .{ .lms = s[0], .ots = s[1] };
    return out;
}

test "HSS round trip for L = 1 .. 8 (H5, w1 at every level)" {
    inline for (1..9) |count| {
        const levels = [_]Level{.{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w1 }} ** count;
        var sk = try lms.SecretKey.init(gpa, &levels, seedOf(count), idOf(count), null);
        defer sk.deinit();
        const pk_bytes = sk.publicKey().toBytes();
        try std.testing.expectEqual(@as(u32, count), std.mem.readInt(u32, pk_bytes[0..4], .big));
        try std.testing.expectEqual(lms.hssSignatureLength(&levels), sk.signatureLength());
        const buf = try gpa.alloc(u8, sk.signatureLength());
        defer gpa.free(buf);
        for ([_][]const u8{ "alpha", "beta", "gamma" }) |msg| {
            const sig = try sk.sign(msg, buf);
            try std.testing.expectEqual(std.mem.readInt(u32, sig[0..4], .big), count - 1);
            try std.testing.expect(lms.hssVerify(&pk_bytes, msg, sig));
            try std.testing.expect(!lms.hssVerify(&pk_bytes, "delta", sig));
        }
    }
}

test "HSS with mixed parameter sets per level, H10 and H5, w1/w2/w4" {
    const levels = levelsOf(&.{
        .{ .sha256_m32_h5, .sha256_n32_w2 },
        .{ .sha256_m32_h10, .sha256_n32_w1 },
        .{ .sha256_m32_h5, .sha256_n32_w4 },
    });
    var sk = try lms.SecretKey.init(gpa, &levels, seedOf(11), idOf(12), null);
    defer sk.deinit();
    const buf = try gpa.alloc(u8, sk.signatureLength());
    defer gpa.free(buf);
    const sig = try sk.sign("mixed", buf);
    try std.testing.expect(sk.publicKey().verify("mixed", sig));
    try std.testing.expect(lms.hssVerify(&sk.publicKey().toBytes(), "mixed", sig));
}

/// The leaf index used at every level, read out of a signature.
fn signatureQs(sig: []const u8, levels: []const Level, out: *[lms.max_levels]u32) void {
    var off: usize = 4;
    for (levels, 0..) |lv, i| {
        out[i] = std.mem.readInt(u32, sig[off..][0..4], .big);
        off += lms.lmsSignatureLength(lv.lms, lv.ots) + lms.LmsPublicKey.encoded_len;
    }
}

test "HSS L=2: the position increases strictly across a lower-tree boundary and every signature verifies" {
    const levels = [_]Level{.{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w1 }} ** 2;
    var sk = try lms.SecretKey.init(gpa, &levels, seedOf(1), idOf(2), null);
    defer sk.deinit();
    const pk = sk.publicKey().toBytes();
    const buf = try gpa.alloc(u8, sk.signatureLength());
    defer gpa.free(buf);
    var prev: [lms.max_levels]u32 = undefined;
    var have = false;
    for (0..70) |i| {
        const sig = try sk.sign("m", buf);
        var qs: [lms.max_levels]u32 = undefined;
        signatureQs(sig, &levels, &qs);
        try std.testing.expectEqual(@as(u32, @intCast(i / 32)), qs[0]);
        try std.testing.expectEqual(@as(u32, @intCast(i % 32)), qs[1]);
        if (have) {
            const greater = qs[0] > prev[0] or (qs[0] == prev[0] and qs[1] > prev[1]);
            try std.testing.expect(greater);
        }
        prev = qs;
        have = true;
        try std.testing.expect(lms.hssVerify(&pk, "m", sig));
    }
    const pos = sk.position();
    try std.testing.expectEqual(@as(u32, 2), pos.q[0]);
    try std.testing.expectEqual(@as(u32, 6), pos.q[1]);
    try std.testing.expect(!pos.exhausted);
}

test "HSS: an exhausted key refuses, after exactly the product of the tree sizes" {
    const levels = [_]Level{.{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w1 }} ** 2;
    var sk = try lms.SecretKey.init(gpa, &levels, seedOf(5), idOf(6), null);
    defer sk.deinit();
    const pk = sk.publicKey().toBytes();
    const buf = try gpa.alloc(u8, sk.signatureLength());
    defer gpa.free(buf);
    for (0..1024) |i| {
        const sig = try sk.sign("m", buf);
        if (i % 251 == 0 or i == 1023) try std.testing.expect(lms.hssVerify(&pk, "m", sig));
    }
    try std.testing.expect(sk.position().exhausted);
    try std.testing.expectError(error.KeyExhausted, sk.sign("m", buf));
    try std.testing.expectError(error.KeyExhausted, sk.sign("m", buf));
}

test "HSS: a key restored at a position signs exactly what the walked key would" {
    const levels = [_]Level{.{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w1 }} ** 2;
    var a = try lms.SecretKey.init(gpa, &levels, seedOf(8), idOf(9), null);
    defer a.deinit();
    const buf_a = try gpa.alloc(u8, a.signatureLength());
    defer gpa.free(buf_a);
    for (0..36) |_| _ = try a.sign("walk", buf_a);
    const restored_at = a.position();
    try std.testing.expectEqual(@as(u32, 1), restored_at.q[0]);
    try std.testing.expectEqual(@as(u32, 4), restored_at.q[1]);

    var b = try lms.SecretKey.init(gpa, &levels, seedOf(8), idOf(9), restored_at);
    defer b.deinit();
    const buf_b = try gpa.alloc(u8, b.signatureLength());
    defer gpa.free(buf_b);
    const sa = try a.sign("same message", buf_a);
    const sb = try b.sign("same message", buf_b);
    try std.testing.expectEqualSlices(u8, sa, sb);
    try std.testing.expect(a.publicKey().verify("same message", sa));
}

test "HSS init validation" {
    const one = [_]Level{.{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w1 }};
    try std.testing.expectError(error.InvalidLevels, lms.SecretKey.init(gpa, &.{}, seedOf(1), idOf(1), null));
    const nine = one ** 9;
    try std.testing.expectError(error.InvalidLevels, lms.SecretKey.init(gpa, &nine, seedOf(1), idOf(1), null));
    var bad: lms.Position = .{};
    bad.q[0] = 32;
    try std.testing.expectError(error.InvalidPosition, lms.SecretKey.init(gpa, &one, seedOf(1), idOf(1), bad));
    var last: lms.Position = .{};
    last.q[0] = 31;
    var sk = try lms.SecretKey.init(gpa, &one, seedOf(1), idOf(1), last);
    defer sk.deinit();
    var buf: [1000 * 10]u8 = undefined;
    _ = try sk.sign("x", &buf);
    try std.testing.expect(sk.position().exhausted);
    try std.testing.expectError(error.KeyExhausted, sk.sign("x", &buf));
}

const Log = struct {
    calls: usize = 0,
    fail: bool = false,
    last: lms.Position = .{},
    fn write(ctx: *anyopaque, next: lms.Position) anyerror!void {
        const self: *Log = @ptrCast(@alignCast(ctx));
        if (self.fail) return error.DiskFull;
        self.calls += 1;
        self.last = next;
    }
    fn hook(self: *Log) lms.Persist {
        return .{ .ctx = self, .write = write };
    }
};

test "SigningKey: the next position is persisted before signing; a failed write burns no leaf" {
    const levels = [_]Level{.{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w1 }} ** 2;
    var log: Log = .{};
    const sk = try lms.SecretKey.init(gpa, &levels, seedOf(3), idOf(3), null);
    var handle: lms.SigningKey = undefined;
    lms.SigningKey.init(&handle, sk, log.hook());
    defer handle.deinit();
    const buf = try gpa.alloc(u8, handle.sk.signatureLength());
    defer gpa.free(buf);

    _ = try handle.sign("one", buf);
    try std.testing.expectEqual(@as(usize, 1), log.calls);
    try std.testing.expectEqual(@as(u32, 1), log.last.q[1]); // the position AFTER the signature
    try std.testing.expectEqual(@as(u32, 1), handle.position().q[1]);

    log.fail = true;
    try std.testing.expectError(error.PersistFailed, handle.sign("two", buf));
    try std.testing.expectEqual(@as(u32, 1), handle.position().q[1]); // unchanged
    log.fail = false;
    const sig = try handle.sign("two", buf);
    var qs: [lms.max_levels]u32 = undefined;
    signatureQs(sig, &levels, &qs);
    try std.testing.expectEqual(@as(u32, 1), qs[1]); // the leaf the failed call did not spend

    // A buffer that is too small fails before the hook runs.
    const calls = log.calls;
    try std.testing.expectError(error.OutputTooSmall, handle.sign("three", buf[0..100]));
    try std.testing.expectEqual(calls, log.calls);
}

test "SigningKey: a copied handle refuses to sign" {
    const levels = [_]Level{.{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w1 }};
    const sk = try lms.SecretKey.init(gpa, &levels, seedOf(3), idOf(3), null);
    var handle: lms.SigningKey = undefined;
    lms.SigningKey.init(&handle, sk, null);
    defer handle.deinit();
    const buf = try gpa.alloc(u8, handle.sk.signatureLength());
    defer gpa.free(buf);
    var copy = handle;
    try std.testing.expectError(error.KeyHandleCopied, copy.sign("x", buf));
    _ = try handle.sign("x", buf);
}

test "deinit wipes the seeds" {
    const levels = [_]Level{.{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w1 }} ** 2;
    var sk = try lms.SecretKey.init(gpa, &levels, seedOf(0xAA), idOf(1), null);
    const buf = try gpa.alloc(u8, sk.signatureLength());
    defer gpa.free(buf);
    _ = try sk.sign("m", buf); // builds the level-1 tree, whose seed is derived
    const t0 = &sk.trees[0].?;
    const t1 = &sk.trees[1].?;
    try std.testing.expect(!std.mem.allEqual(u8, &t0.seed, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &t1.seed, 0));
    sk.deinit();
    try std.testing.expect(std.mem.allEqual(u8, &sk.seed, 0));
    var lk = try lms.LmsSecretKey.init(gpa, .sha256_m32_h5, .sha256_n32_w1, idOf(1), seedOf(0xBB));
    lk.deinit();
    try std.testing.expect(std.mem.allEqual(u8, &lk.tree.seed, 0));
}

test "public-key parsers: every wrong length and typecode is a typed error" {
    const good = (lms.LmsPublicKey{
        .lms = .sha256_m32_h10,
        .ots = .sha256_n32_w4,
        .id = idOf(1),
        .root = seedOf(2),
    }).toBytes();
    const parsed = try lms.LmsPublicKey.parse(&good);
    try std.testing.expectEqual(lms.ParamSet.sha256_m32_h10, parsed.lms);
    try std.testing.expectEqualSlices(u8, &good, &parsed.toBytes());
    for ([_]usize{ 0, 1, 7 }) |l| try std.testing.expectError(error.InvalidLength, lms.LmsPublicKey.parse(good[0..l]));
    try std.testing.expectError(error.InvalidLength, lms.LmsPublicKey.parse(good[0..55]));
    var longer: [57]u8 = undefined;
    @memcpy(longer[0..56], &good);
    longer[56] = 0;
    try std.testing.expectError(error.InvalidLength, lms.LmsPublicKey.parse(&longer));
    var t = good;
    for ([_]u32{ 0, 4, 10, 0xffffffff }) |code| {
        std.mem.writeInt(u32, t[0..4], code, .big);
        try std.testing.expectError(error.UnsupportedLmsType, lms.LmsPublicKey.parse(&t));
    }
    t = good;
    for ([_]u32{ 0, 5, 0xffffffff }) |code| {
        std.mem.writeInt(u32, t[4..8], code, .big);
        try std.testing.expectError(error.UnsupportedOtsType, lms.LmsPublicKey.parse(&t));
    }

    var h: [60]u8 = undefined;
    std.mem.writeInt(u32, h[0..4], 3, .big);
    @memcpy(h[4..], &good);
    const hp = try lms.HssPublicKey.parse(&h);
    try std.testing.expectEqual(@as(u8, 3), hp.levels);
    try std.testing.expectEqualSlices(u8, &h, &hp.toBytes());
    for ([_]u32{ 0, 9, 0x01000002, 0xffffffff }) |lv| {
        std.mem.writeInt(u32, h[0..4], lv, .big);
        try std.testing.expectError(error.InvalidLevels, lms.HssPublicKey.parse(&h));
    }
    std.mem.writeInt(u32, h[0..4], 1, .big);
    try std.testing.expectError(error.InvalidLength, lms.HssPublicKey.parse(h[0..59]));
    try std.testing.expectError(error.InvalidLength, lms.HssPublicKey.parse(h[0..3]));
    try std.testing.expect(!lms.hssVerify(h[0..59], "m", "sig"));
    try std.testing.expect(!lms.lmsVerify(&.{}, "m", &.{}));
}

test "signature parsing: length, typecode, index and level-count lies are rejected" {
    const levels = [_]Level{
        .{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w1 },
        .{ .lms = .sha256_m32_h5, .ots = .sha256_n32_w2 },
    };
    var sk = try lms.SecretKey.init(gpa, &levels, seedOf(1), idOf(1), null);
    defer sk.deinit();
    const pk = sk.publicKey().toBytes();
    const good_buf = try gpa.alloc(u8, sk.signatureLength() + 1);
    defer gpa.free(good_buf);
    const good = try sk.sign("msg", good_buf);
    try std.testing.expect(lms.hssVerify(&pk, "msg", good));

    // Length: shorter, longer, and every prefix of the fixed header.
    try std.testing.expect(!lms.hssVerify(&pk, "msg", good[0 .. good.len - 1]));
    good_buf[good.len] = 0;
    try std.testing.expect(!lms.hssVerify(&pk, "msg", good_buf[0 .. good.len + 1]));
    for (0..80) |l| try std.testing.expect(!lms.hssVerify(&pk, "msg", good[0..l]));

    const bad = try gpa.dupe(u8, good);
    defer gpa.free(bad);
    const len0 = lms.lmsSignatureLength(levels[0].lms, levels[0].ots);
    const ots0 = levels[0].ots.sigLen();
    const w = struct {
        fn put(b: []u8, off: usize, v: u32) void {
            std.mem.writeInt(u32, b[off..][0..4], v, .big);
        }
    };
    // Nspk: 0, 2, huge.
    for ([_]u32{ 0, 2, 0xffffffff, 0x100 }) |v| {
        @memcpy(bad, good);
        w.put(bad, 0, v);
        try std.testing.expect(!lms.hssVerify(&pk, "msg", bad));
    }
    // q of the first signature: the first invalid one, and the largest.
    for ([_]u32{ 32, 33, 0x80000000, 0xffffffff }) |v| {
        @memcpy(bad, good);
        w.put(bad, 4, v);
        try std.testing.expect(!lms.hssVerify(&pk, "msg", bad));
    }
    // Typecodes inside the first signature (LM-OTS at +4, LMS at +4+ots_len).
    for ([_]usize{ 4 + 4, 4 + 4 + ots0 }) |off| {
        for ([_]u32{ 0, 1, 2, 5, 6, 0xffffffff }) |v| {
            @memcpy(bad, good);
            const cur = std.mem.readInt(u32, bad[off..][0..4], .big);
            if (v == cur) continue;
            w.put(bad, off, v);
            try std.testing.expect(!lms.hssVerify(&pk, "msg", bad));
        }
    }
    // The embedded level-1 public key: unsupported typecodes, and a foreign
    // (but valid) parameter set, which changes the length the rest must have.
    const pub1 = 4 + len0;
    for ([_]usize{ pub1, pub1 + 4 }) |off| {
        for ([_]u32{ 0, 4, 99, 0xffffffff }) |v| {
            @memcpy(bad, good);
            w.put(bad, off, v);
            try std.testing.expect(!lms.hssVerify(&pk, "msg", bad));
        }
    }
    @memcpy(bad, good);
    w.put(bad, pub1 + 4, lms.OtsParamSet.sha256_n32_w8.typecode());
    try std.testing.expect(!lms.hssVerify(&pk, "msg", bad));
    // The last signature's q.
    const last = pub1 + 56;
    for ([_]u32{ 32, 0xffffffff }) |v| {
        @memcpy(bad, good);
        w.put(bad, last, v);
        try std.testing.expect(!lms.hssVerify(&pk, "msg", bad));
    }
}

test "the LM-OTS randomizer is derived, deterministic and leaf-specific" {
    const c0 = core.deriveRandomizer(&idOf(1), 0, &seedOf(2));
    const c0b = core.deriveRandomizer(&idOf(1), 0, &seedOf(2));
    const c1 = core.deriveRandomizer(&idOf(1), 1, &seedOf(2));
    try std.testing.expectEqualSlices(u8, &c0, &c0b);
    try std.testing.expect(!std.mem.eql(u8, &c0, &c1));
    // And distinct from every private chain start value x_q[i], i <= 264.
    for (0..265) |i| {
        const x = core.deriveX(&idOf(1), 0, @intCast(i), &seedOf(2));
        try std.testing.expect(!std.mem.eql(u8, &x, &c0));
    }
}
