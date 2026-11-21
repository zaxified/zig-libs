// SPDX-License-Identifier: MIT

//! Fuzz harness for the byte codecs (`Bfv(P).decode*`): damaged encodings of
//! every object kind and raw bytes. Whatever a decoder accepts must re-encode
//! to exactly the bytes it read; nothing may panic.
//!
//! Driver: `BFV_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver). Harness
//! name: `bfv-codec`. An in-suite reach test requires both outcomes.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const params = @import("params.zig");
const Bfv = @import("bfv.zig").Bfv;

const B = Bfv(params.test_tiny);

const Label = enum { accepted, refused };
var counts: [2]usize = @splat(0);
fn mark(comptime l: Label) void {
    counts[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// Valid encodings of every kind, from one fixed scripted key set.
const Corpus = struct {
    sk: [B.secret_key_bytes]u8,
    pk: [B.public_key_bytes]u8,
    rlk: [B.relin_key_bytes]u8,
    gk: [B.galois_key_bytes]u8,
    ct: [B.ciphertextBytes(3)]u8,
    ct_len: usize,
};
var corpus: ?Corpus = null;

fn getCorpus() *const Corpus {
    if (corpus == null) {
        const inst = B.init() catch unreachable;
        var prng = std.Random.DefaultPrng.init(0xf0);
        const rnd = prng.random();
        var kp: B.KeyPair = undefined;
        inst.keyGenForTest(rnd, &kp);
        var rlk: B.RelinKey = undefined;
        inst.genRelinKeyForTest(&kp.sk, rnd, &rlk);
        var gk: B.GaloisKey = undefined;
        inst.genGaloisKeyForTest(&kp.sk, 3, rnd, &gk) catch unreachable;
        var c: Corpus = undefined;
        B.encodeSecretKey(&kp.sk, &c.sk);
        B.encodePublicKey(&kp.pk, &c.pk);
        B.encodeRelinKey(&rlk, &c.rlk);
        B.encodeGaloisKey(&gk, &c.gk);
        var pt = B.Plaintext.zero(params.test_tiny.t);
        pt.coeffs[0] = 1;
        const ct = inst.encryptForTest(&kp.pk, &pt, rnd);
        c.ct_len = (B.encodeCiphertext(&ct, &c.ct) catch unreachable).len;
        corpus = c;
    }
    return &corpus.?;
}

fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

pub fn fuzzCodec(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const c = getCorpus();
    var buf: [B.ciphertextBytes(3) + 16]u8 = undefined;
    const kind = src.index(5);
    const frame: []const u8 = switch (kind) {
        0 => &c.sk,
        1 => &c.pk,
        2 => &c.rlk,
        3 => &c.gk,
        else => c.ct[0..c.ct_len],
    };
    const n = if (src.value(bool)) damage(src, &buf, frame) else src.slice(&buf);
    const in = buf[0..n];
    var out: [B.ciphertextBytes(3)]u8 = undefined;
    switch (kind) {
        0 => {
            var sk: B.SecretKey = undefined;
            B.decodeSecretKey(in, &sk) catch return mark(.refused);
            B.encodeSecretKey(&sk, out[0..B.secret_key_bytes]);
            try testing.expectEqualSlices(u8, in, out[0..B.secret_key_bytes]);
        },
        1 => {
            var pk: B.PublicKey = undefined;
            B.decodePublicKey(in, &pk) catch return mark(.refused);
            B.encodePublicKey(&pk, out[0..B.public_key_bytes]);
            try testing.expectEqualSlices(u8, in, out[0..B.public_key_bytes]);
        },
        2 => {
            var rlk: B.RelinKey = undefined;
            B.decodeRelinKey(in, &rlk) catch return mark(.refused);
            var o2: [B.relin_key_bytes]u8 = undefined;
            B.encodeRelinKey(&rlk, &o2);
            try testing.expectEqualSlices(u8, in, &o2);
        },
        3 => {
            var gk: B.GaloisKey = undefined;
            B.decodeGaloisKey(in, &gk) catch return mark(.refused);
            var o2: [B.galois_key_bytes]u8 = undefined;
            B.encodeGaloisKey(&gk, &o2);
            try testing.expectEqualSlices(u8, in, &o2);
        },
        else => {
            const ct = B.decodeCiphertext(in) catch return mark(.refused);
            const enc = try B.encodeCiphertext(&ct, &out);
            try testing.expectEqualSlices(u8, in, enc);
        },
    }
    mark(.accepted);
}

fn fuzzCodecSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [4096]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzCodec(testkit.fuzz.ScriptSource, &src, testing.allocator);
}

test "fuzz: damaged codec input never panics; whatever decodes re-encodes to the same bytes" {
    try testing.fuzz({}, fuzzCodecSmith, .{});
}

test "fuzz driver: BFV_FUZZ (codec)" {
    try fuzz_driver.run(fuzzCodec, .{ .prefix = "BFV_FUZZ", .name = "bfv-codec" });
}

test "fuzz harness: codec, 300 seeds, reaches both outcomes" {
    counts = @splat(0);
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        try fuzzCodec(fuzz_driver.Rng, &rng, testing.allocator);
    }
    try testing.expect(counts[0] > 0 and counts[1] > 0);
}
