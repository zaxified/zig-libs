// SPDX-License-Identifier: MIT

//! interop_test — this module against tfhe-rs 1.8.1, the external anchor the
//! scheme used to lack. `testdata/tfhers_vectors.bin` is written by
//! `tools/tfhers` (`vectors`), which drives tfhe-rs through its public API as
//! a black box with deterministic seeds; regenerating it is byte-identical.
//! The opposite direction — this module's keys and ciphertexts through
//! tfhe-rs — is `tools/tfhers`'s `check`, fed by `tools/tfhers/emit_zig.zig`
//! (transcript in `tools/tfhers/zig_checked.txt`).
//!
//! What the vectors pin:
//!
//!   * the three tfhe-rs boolean parameter sets, field by field and the
//!     Gaussian widths bit for bit (`params.tfhers_*`);
//!   * `gadget.decompose` digit for digit against tfhe-rs's `SignedDecomposer`
//!     on 2 000 inputs, half of them with a planted tie;
//!   * the key, GGSW and key-switch-key layouts: tfhe-rs's standard-domain
//!     containers are loaded verbatim and used by this module's code;
//!   * `keySwitch` **byte-identical** to tfhe-rs's `keyswitch_lwe_ciphertext`;
//!   * modulus switch, blind rotation (external product, CMux) and sample
//!     extraction: this module's exact NTT bootstrap of tfhe-rs's ciphertexts
//!     with tfhe-rs's bootstrap key is **byte-identical** to tfhe-rs's f64-FFT
//!     `programmable_bootstrap_lwe_ciphertext` at the small set (the FFT is
//!     exact at that size);
//!   * `codec.zig`'s payloads: tfhe-rs's containers, word for word;
//!   * the boolean gates: tfhe-rs's gate outputs decrypt here, and this
//!     module's gates on tfhe-rs's ciphertexts and keys compute the same
//!     function — at a small `k = 2` set and at `DEFAULT_PARAMETERS`.

const std = @import("std");
const testing = std.testing;
const params = @import("params.zig");
const gadget = @import("gadget.zig");
const boolean = @import("boolean.zig");
const tfhe = @import("tfhe.zig");

const T = u32;
const data = @embedFile("testdata/tfhers_vectors.bin");

/// The record with tag `tag`: `tag[4] | len u32 | len u32 words`, LE.
fn record(comptime tag: []const u8) []align(1) const u32 {
    var i: usize = 0;
    while (i < data.len) {
        const len = std.mem.readInt(u32, data[i + 4 ..][0..4], .little);
        const body = data[i + 8 ..][0 .. 4 * len];
        if (std.mem.eql(u8, data[i..][0..4], tag)) return std.mem.bytesAsSlice(u32, body);
        i += 8 + 4 * len;
    }
    @panic("missing record " ++ tag);
}

fn word(w: []align(1) const u32, i: usize) u32 {
    return std.mem.littleToNative(u32, w[i]);
}

const gate_names = [_][]const u8{ "and", "nand", "or", "nor", "xor", "xnor", "mux" };

fn expected(g: usize, a: bool, b: bool, c: bool) bool {
    return switch (g) {
        0 => a and b,
        1 => !(a and b),
        2 => a or b,
        3 => !(a or b),
        4 => a != b,
        5 => a == b,
        6 => if (c) a else b,
        else => unreachable,
    };
}

/// Loaders from tfhe-rs's standard containers. Element by element: the
/// orders are the same, the Zig struct layout is not promised to be.
fn Loader(comptime F: type) type {
    return struct {
        fn lweKey(comptime dim: usize, w: []align(1) const u32) F.LweKey(dim) {
            std.debug.assert(w.len == dim);
            var key: F.LweKey(dim) = undefined;
            for (&key.s, 0..) |*s, i| s.* = word(w, i);
            return key;
        }
        fn glweKey(w: []align(1) const u32) F.GlweKey {
            std.debug.assert(w.len == F.glwe_dim * F.ring_degree);
            var key: F.GlweKey = undefined;
            for (&key.s, 0..) |*p, j| {
                for (&p.c, 0..) |*c, i| c.* = word(w, j * F.ring_degree + i);
            }
            return key;
        }
        fn lwe(comptime dim: usize, w: []align(1) const u32, idx: usize) F.Lwe(dim) {
            const base = idx * (dim + 1);
            var ct: F.Lwe(dim) = undefined;
            for (&ct.a, 0..) |*x, i| x.* = word(w, base + i);
            ct.b = word(w, base + dim);
            return ct;
        }
        fn bsk(allocator: std.mem.Allocator, w: []align(1) const u32) !F.BootstrapKey {
            const N = F.ring_degree;
            const k = F.glwe_dim;
            std.debug.assert(w.len == F.lwe_dim * F.ggsw_rows * (k + 1) * N);
            const key = try F.BootstrapKey.alloc(allocator);
            var at: usize = 0;
            for (key.ggsw) |*g| {
                for (&g.rows) |*rw| {
                    for (0..k + 1) |c| {
                        const dst = if (c < k) &rw.mask[c] else &rw.body;
                        for (&dst.c) |*x| {
                            x.* = word(w, at);
                            at += 1;
                        }
                    }
                }
            }
            return key;
        }
        fn ksk(allocator: std.mem.Allocator, w: []align(1) const u32) !F.KeySwitchKey {
            std.debug.assert(w.len == F.big_lwe_dim * F.parameters.ell_ks * (F.lwe_dim + 1));
            const key = try F.KeySwitchKey.alloc(allocator);
            for (key.rows, 0..) |*r, i| r.* = lwe(F.lwe_dim, w, i);
            return key;
        }
    };
}

test "the tfhe-rs boolean parameter sets are params.tfhers_*" {
    const sets = .{ .{ "PARD", params.tfhers_default }, .{ "PARL", params.tfhers_tfhe_lib }, .{ "PARE", params.tfhers_2m165 } };
    inline for (sets) |s| {
        const w = record(s[0]);
        const p: params.Params = s[1];
        try testing.expectEqual(@as(u32, @intCast(p.n)), word(w, 0));
        try testing.expectEqual(@as(u32, @intCast(p.k)), word(w, 1));
        try testing.expectEqual(@as(u32, @intCast(p.N)), word(w, 2));
        try testing.expectEqual(@as(u32, p.bg_bits), word(w, 3));
        try testing.expectEqual(@as(u32, @intCast(p.ell)), word(w, 4));
        try testing.expectEqual(@as(u32, p.bks_bits), word(w, 5));
        try testing.expectEqual(@as(u32, @intCast(p.ell_ks)), word(w, 6));
        const lwe_bits = @as(u64, word(w, 7)) | @as(u64, word(w, 8)) << 32;
        const glwe_bits = @as(u64, word(w, 9)) | @as(u64, word(w, 10)) << 32;
        try testing.expectEqual(lwe_bits, @as(u64, @bitCast(p.lwe_noise.gaussian)));
        try testing.expectEqual(glwe_bits, @as(u64, @bitCast(p.glwe_noise.gaussian)));
    }
}

test "gadget.decompose = tfhe-rs SignedDecomposer, digit for digit (2 000 inputs, 1 000 planted ties)" {
    const shapes = .{ .{ "DEC0", 3, 5 }, .{ "DEC1", 10, 2 }, .{ "DEC2", 2, 8 }, .{ "DEC3", 7, 3 }, .{ "DEC4", 6, 3 } };
    inline for (shapes) |s| {
        const w = record(s[0]);
        const bl: u6 = s[1];
        const lc: usize = s[2];
        try testing.expectEqual(@as(u32, bl), word(w, 0));
        try testing.expectEqual(@as(u32, lc), word(w, 1));
        var i: usize = 2;
        var n: usize = 0;
        while (i < w.len) : (i += 1 + lc) {
            const got = gadget.decompose(bl, lc, word(w, i));
            for (0..lc) |l| try testing.expectEqual(@as(i32, @bitCast(word(w, i + 1 + l))), got[l]);
            n += 1;
        }
        try testing.expectEqual(@as(usize, 400), n);
    }
}

/// tools/tfhers's `small_params()`.
const Small = tfhe.Tfhe(.{
    .n = 16,
    .k = 2,
    .N = 64,
    .bg_bits = 6,
    .ell = 3,
    .bks_bits = 3,
    .ell_ks = 6,
    .lwe_noise = .{ .gaussian = 0x1p-22 },
    .glwe_noise = .{ .gaussian = 0x1p-28 },
});
const SL = Loader(Small);

fn smallBits() [32]bool {
    var bits: [32]bool = undefined;
    const w = record("SBIT");
    for (&bits, 0..) |*b, i| b.* = word(w, i) == 1;
    return bits;
}

test "small k = 2 set: tfhe-rs ciphertexts decrypt under tfhe-rs keys read in this module's layout" {
    const lwe = SL.lweKey(16, record("SLSK"));
    const bits = smallBits();
    for (bits, 0..) |b, i| {
        const ct = SL.lwe(16, record("SINP"), i);
        try testing.expectEqual(b, boolean.decode(Small.lwePhase(16, &lwe, &ct)));
    }
}

test "small k = 2 set: keySwitch is byte-identical to tfhe-rs's key switch" {
    var ksk = try SL.ksk(testing.allocator, record("SKSK"));
    defer ksk.deinit(testing.allocator);
    for (0..32) |i| {
        const big = SL.lwe(128, record("SPBS"), i);
        const want = SL.lwe(16, record("SKS_"), i);
        const got = Small.keySwitch(&ksk, &big);
        try testing.expectEqualSlices(u32, &want.a, &got.a);
        try testing.expectEqual(want.b, got.b);
    }
}

test "small k = 2 set: this module's bootstrap of tfhe-rs's inputs with tfhe-rs's key is byte-identical to tfhe-rs's PBS" {
    var bsk = try SL.bsk(testing.allocator, record("SBSK"));
    defer bsk.deinit(testing.allocator);
    var pk = try Small.PreparedBootstrapKey.init(testing.allocator, &bsk);
    defer pk.deinit(testing.allocator);
    const glwe = SL.glweKey(record("SGSK"));
    const big_key = Small.extractGlweKey(&glwe);
    const bits = smallBits();
    var lut: Small.Poly = undefined;
    for (&lut.c) |*c| c.* = boolean.true_value;

    for (bits, 0..) |b, i| {
        const ct = SL.lwe(16, record("SINP"), i);
        const theirs = SL.lwe(128, record("SPBS"), i);
        const ours = pk.bootstrapBig(&lut, &ct);
        // The unprepared reference agrees with the prepared path exactly.
        var a_tilde: [16]usize = undefined;
        for (&a_tilde, ct.a) |*at, ai| at.* = Small.modSwitchScalar(ai);
        const ref = Small.sampleExtract(&Small.blindRotate(&bsk, &lut, Small.modSwitchScalar(ct.b), &a_tilde));
        try testing.expectEqualSlices(u8, std.mem.asBytes(&ref), std.mem.asBytes(&ours));
        // Byte-identical to tfhe-rs: at this size its f64 FFT rounds every
        // product back to the exact integer (measured: 0 coefficients differ),
        // so the exact NTT path here and the FFT path there meet bit for bit.
        // A different rotation, extraction index, mod switch or gadget
        // convention would put unrelated values in every coefficient.
        try testing.expectEqualSlices(u32, &theirs.a, &ours.a);
        try testing.expectEqual(theirs.b, ours.b);
        try testing.expectEqual(b, boolean.decode(Small.lwePhase(128, &big_key, &ours)));
    }
}

test "small k = 2 set: tfhe-rs's gate outputs decrypt here, and this module's gates on tfhe-rs's keys agree" {
    const lwe = SL.lweKey(16, record("SLSK"));
    var bsk = try SL.bsk(testing.allocator, record("SBSK"));
    defer bsk.deinit(testing.allocator);
    const ksk = try SL.ksk(testing.allocator, record("SKSK"));
    var sk = try Small.ServerKey.fromKeys(testing.allocator, &bsk, ksk);
    defer sk.deinit(testing.allocator);
    const bits = smallBits();
    inline for (gate_names, 0..) |name, g| {
        const outs = record(std.fmt.comptimePrint("SGT{d}", .{g}));
        for (0..16) |i| {
            const a = SL.lwe(16, record("SINP"), 2 * i);
            const b = SL.lwe(16, record("SINP"), 2 * i + 1);
            const c = SL.lwe(16, record("SINP"), (2 * i + 2) % 32);
            const want = expected(g, bits[2 * i], bits[2 * i + 1], bits[(2 * i + 2) % 32]);
            const theirs = SL.lwe(16, outs, i);
            try testing.expectEqual(want, boolean.decode(Small.lwePhase(16, &lwe, &theirs)));
            const ours = if (comptime std.mem.eql(u8, name, "mux")) sk.mux(&c, &a, &b) else @field(Small.ServerKey, name)(&sk, &a, &b);
            try testing.expectEqual(want, boolean.decode(Small.lwePhase(16, &lwe, &ours)));
        }
    }
}

const Default = tfhe.Tfhe(params.tfhers_default);
const DL = Loader(Default);

test "DEFAULT_PARAMETERS: tfhe-rs ciphertexts and gate outputs decrypt here; this module's gates on them agree" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var ck: Default.ClientKey = .{ .lwe = DL.lweKey(805, record("DLSK")), .glwe = DL.glweKey(record("DGSK")) };
    defer ck.deinit();
    var bits: [8]bool = undefined;
    for (&bits, 0..) |*b, i| b.* = word(record("DBIT"), i) == 1;
    for (bits, 0..) |b, i| try testing.expectEqual(b, ck.decrypt(&DL.lwe(805, record("DINP"), i)));

    // Our own evaluation key for tfhe-rs's secret keys.
    var sk = try Default.ServerKey.generate(testing.allocator, &ck, io);
    defer sk.deinit(testing.allocator);
    inline for (gate_names, 0..) |name, g| {
        const outs = record(std.fmt.comptimePrint("DGT{d}", .{g}));
        for (0..2) |i| {
            const a = DL.lwe(805, record("DINP"), 2 * i);
            const b = DL.lwe(805, record("DINP"), 2 * i + 1);
            const c = DL.lwe(805, record("DINP"), (2 * i + 2) % 8);
            const want = expected(g, bits[2 * i], bits[2 * i + 1], bits[(2 * i + 2) % 8]);
            try testing.expectEqual(want, ck.decrypt(&DL.lwe(805, outs, i)));
            const ours = if (comptime std.mem.eql(u8, name, "mux")) sk.mux(&c, &a, &b) else @field(Default.ServerKey, name)(&sk, &a, &b);
            try testing.expectEqual(want, ck.decrypt(&ours));
        }
    }
}

test "codec payloads are tfhe-rs's standard containers, word for word" {
    var bsk = try SL.bsk(testing.allocator, record("SBSK"));
    defer bsk.deinit(testing.allocator);
    var ksk = try SL.ksk(testing.allocator, record("SKSK"));
    defer ksk.deinit(testing.allocator);
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const C = Small.Codec;
    try C.writeBootstrapKey(&aw.writer, &bsk);
    try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(record("SBSK")), aw.written()[24..]);
    aw.clearRetainingCapacity();
    try C.writeKeySwitchKey(&aw.writer, &ksk);
    try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(record("SKSK")), aw.written()[24..]);
    aw.clearRetainingCapacity();
    const ct = SL.lwe(16, record("SINP"), 5);
    try C.writeLwe(&aw.writer, &ct);
    try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(record("SINP"))[5 * 17 * 4 ..][0 .. 17 * 4], aw.written()[24..]);
}
