// SPDX-License-Identifier: MIT

//! codec — byte encodings of TFHE keys and ciphertexts, so a client can ship
//! its evaluation key and its ciphertexts to a server (the point of the
//! scheme) and read the results back.
//!
//! ## Format
//!
//! A 24-byte header, then the payload:
//!
//!   | bytes | field                                                    |
//!   |-------|----------------------------------------------------------|
//!   | 0–3   | magic `"TFHE"`                                           |
//!   | 4     | format version (1)                                       |
//!   | 5     | `Kind`                                                   |
//!   | 6–7   | zero                                                     |
//!   | 8–19  | `n`, `k`, `N` (u32 LE each)                              |
//!   | 20–23 | `bg_bits`, `ell`, `bks_bits`, `ell_ks` (one byte each)   |
//!
//! The payload is u32 little-endian words in **tfhe-rs's standard-domain
//! container order** (see `tfhe.zig`, "Layout"): a ciphertext's words are
//! exactly tfhe-rs's `LweCiphertext` container, a bootstrap key's exactly its
//! standard `LweBootstrapKey`, and so on (`interop_test.zig` compares the
//! payload of a tfhe-rs key read in this module with tfhe-rs's own words).
//! The header is this module's: tfhe-rs's own serialisation (bincode plus
//! its versioning layer) is not reproduced.
//!
//! A wrong kind byte or non-zero reserved bytes (6–7) are `error.WrongKind`.
//! The header's parameter fingerprint makes a decoder refuse bytes produced
//! for another parameter set (`error.ParameterMismatch`); the error widths are
//! not part of it, since they do not change the shape. Secret-key words must
//! be 0 or 1 (`error.InvalidKey`). A server key is written as its standard-
//! domain bootstrap key followed by its key-switch key, and read straight
//! into the NTT domain one GGSW at a time — no second copy of the 53 MB key.

const std = @import("std");

pub const magic = "TFHE";
pub const version: u8 = 1;
pub const header_len = 24;

pub const Kind = enum(u8) {
    /// `LweN` — a ciphertext under the small key (boolean ciphertexts).
    lwe = 1,
    /// `LweBig` — a ciphertext under the big (extracted GLWE) key.
    lwe_big = 2,
    /// `ClientKey`: the small LWE key, then the GLWE key. SECRET.
    client_key = 3,
    /// `BootstrapKey` (standard domain).
    bootstrap_key = 4,
    /// `KeySwitchKey`.
    key_switch_key = 5,
    /// `ServerKey`: a bootstrap key payload, then a key-switch key payload.
    server_key = 6,
};

pub const DecodeError = error{
    BadMagic,
    UnsupportedVersion,
    WrongKind,
    ParameterMismatch,
    InvalidKey,
} || std.Io.Reader.Error;

/// Encoders and decoders for the instance `F = Tfhe(P)`.
pub fn Codec(comptime F: type) type {
    const P = F.parameters;
    const n = F.lwe_dim;
    const k = F.glwe_dim;
    const N = F.ring_degree;

    return struct {
        /// Encoded length of `kind`, header included.
        pub fn encodedLen(kind: Kind) usize {
            const words: usize = switch (kind) {
                .lwe => n + 1,
                .lwe_big => F.big_lwe_dim + 1,
                .client_key => n + k * N,
                .bootstrap_key => bskWords(),
                .key_switch_key => kskWords(),
                .server_key => bskWords() + kskWords(),
            };
            return header_len + 4 * words;
        }
        fn bskWords() usize {
            return n * F.ggsw_rows * (k + 1) * N;
        }
        fn kskWords() usize {
            return F.big_lwe_dim * P.ell_ks * (n + 1);
        }

        fn writeHeader(w: *std.Io.Writer, kind: Kind) std.Io.Writer.Error!void {
            try w.writeAll(magic);
            try w.writeAll(&.{ version, @intFromEnum(kind), 0, 0 });
            try w.writeInt(u32, @intCast(n), .little);
            try w.writeInt(u32, @intCast(k), .little);
            try w.writeInt(u32, @intCast(N), .little);
            try w.writeAll(&.{ P.bg_bits, @intCast(P.ell), P.bks_bits, @intCast(P.ell_ks) });
        }

        fn readHeader(r: *std.Io.Reader, kind: Kind) DecodeError!void {
            // `readSliceAll`, not `takeArray`: the latter needs a reader
            // buffer of at least `header_len` bytes.
            var hb: [header_len]u8 = undefined;
            try r.readSliceAll(&hb);
            const h = &hb;
            if (!std.mem.eql(u8, h[0..4], magic)) return error.BadMagic;
            if (h[4] != version) return error.UnsupportedVersion;
            if (h[5] != @intFromEnum(kind) or h[6] != 0 or h[7] != 0) return error.WrongKind;
            const ok = std.mem.readInt(u32, h[8..12], .little) == n and
                std.mem.readInt(u32, h[12..16], .little) == k and
                std.mem.readInt(u32, h[16..20], .little) == N and
                h[20] == P.bg_bits and h[21] == P.ell and h[22] == P.bks_bits and h[23] == P.ell_ks;
            if (!ok) return error.ParameterMismatch;
        }

        fn writeWords(w: *std.Io.Writer, words: []const u32) std.Io.Writer.Error!void {
            for (words) |v| try w.writeInt(u32, v, .little);
        }
        fn readWords(r: *std.Io.Reader, out: []u32) std.Io.Reader.Error!void {
            for (out) |*v| v.* = try r.takeInt(u32, .little);
        }
        fn readBits(r: *std.Io.Reader, out: []u32) DecodeError!void {
            var bad: u32 = 0;
            for (out) |*v| {
                v.* = try r.takeInt(u32, .little);
                bad |= v.* >> 1;
            }
            if (bad != 0) return error.InvalidKey;
        }

        fn writeGgsw(w: *std.Io.Writer, g: *const F.Ggsw) std.Io.Writer.Error!void {
            for (&g.rows) |*rw| {
                for (&rw.mask) |*p| try writeWords(w, &p.c);
                try writeWords(w, &rw.body.c);
            }
        }
        fn readGgsw(r: *std.Io.Reader, g: *F.Ggsw) std.Io.Reader.Error!void {
            for (&g.rows) |*rw| {
                for (&rw.mask) |*p| try readWords(r, &p.c);
                try readWords(r, &rw.body.c);
            }
        }
        fn writeLweBody(comptime dim: usize, w: *std.Io.Writer, ct: *const F.Lwe(dim)) std.Io.Writer.Error!void {
            try writeWords(w, &ct.a);
            try w.writeInt(u32, ct.b, .little);
        }
        fn readLweBody(comptime dim: usize, r: *std.Io.Reader) std.Io.Reader.Error!F.Lwe(dim) {
            var ct: F.Lwe(dim) = undefined;
            try readWords(r, &ct.a);
            ct.b = try r.takeInt(u32, .little);
            return ct;
        }
        fn writeKskBody(w: *std.Io.Writer, ksk: *const F.KeySwitchKey) std.Io.Writer.Error!void {
            for (ksk.rows) |*rw| try writeLweBody(n, w, rw);
        }
        fn readKskBody(allocator: std.mem.Allocator, r: *std.Io.Reader) (DecodeError || std.mem.Allocator.Error)!F.KeySwitchKey {
            var ksk = try F.KeySwitchKey.alloc(allocator);
            errdefer ksk.deinit(allocator);
            for (ksk.rows) |*rw| rw.* = try readLweBody(n, r);
            return ksk;
        }

        // ── ciphertexts ──────────────────────────────────────────────────────

        pub fn writeLwe(w: *std.Io.Writer, ct: *const F.LweN) std.Io.Writer.Error!void {
            try writeHeader(w, .lwe);
            try writeLweBody(n, w, ct);
        }
        pub fn readLwe(r: *std.Io.Reader) DecodeError!F.LweN {
            try readHeader(r, .lwe);
            return readLweBody(n, r);
        }
        pub fn writeLweBig(w: *std.Io.Writer, ct: *const F.LweBig) std.Io.Writer.Error!void {
            try writeHeader(w, .lwe_big);
            try writeLweBody(F.big_lwe_dim, w, ct);
        }
        pub fn readLweBig(r: *std.Io.Reader) DecodeError!F.LweBig {
            try readHeader(r, .lwe_big);
            return readLweBody(F.big_lwe_dim, r);
        }

        // ── keys ─────────────────────────────────────────────────────────────

        /// The client's SECRET keys. Whoever reads these bytes decrypts
        /// everything; store them like any other private key.
        pub fn writeClientKey(w: *std.Io.Writer, ck: *const F.ClientKey) std.Io.Writer.Error!void {
            try writeHeader(w, .client_key);
            try writeWords(w, &ck.lwe.s);
            for (&ck.glwe.s) |*p| try writeWords(w, &p.c);
        }
        pub fn readClientKey(r: *std.Io.Reader) DecodeError!F.ClientKey {
            try readHeader(r, .client_key);
            var ck: F.ClientKey = undefined;
            errdefer ck.deinit();
            try readBits(r, &ck.lwe.s);
            for (&ck.glwe.s) |*p| try readBits(r, &p.c);
            return ck;
        }

        pub fn writeBootstrapKey(w: *std.Io.Writer, bsk: *const F.BootstrapKey) std.Io.Writer.Error!void {
            try writeHeader(w, .bootstrap_key);
            for (bsk.ggsw) |*g| try writeGgsw(w, g);
        }
        pub fn readBootstrapKey(allocator: std.mem.Allocator, r: *std.Io.Reader) (DecodeError || std.mem.Allocator.Error)!F.BootstrapKey {
            try readHeader(r, .bootstrap_key);
            var bsk = try F.BootstrapKey.alloc(allocator);
            errdefer bsk.deinit(allocator);
            for (bsk.ggsw) |*g| try readGgsw(r, g);
            return bsk;
        }

        pub fn writeKeySwitchKey(w: *std.Io.Writer, ksk: *const F.KeySwitchKey) std.Io.Writer.Error!void {
            try writeHeader(w, .key_switch_key);
            try writeKskBody(w, ksk);
        }
        pub fn readKeySwitchKey(allocator: std.mem.Allocator, r: *std.Io.Reader) (DecodeError || std.mem.Allocator.Error)!F.KeySwitchKey {
            try readHeader(r, .key_switch_key);
            return readKskBody(allocator, r);
        }

        /// The evaluation key: what a client sends to the server.
        pub fn writeServerKey(w: *std.Io.Writer, sk: *const F.ServerKey) std.Io.Writer.Error!void {
            try writeHeader(w, .server_key);
            var g: F.Ggsw = undefined;
            for (0..n) |i| {
                sk.bsk.getGgsw(i, &g);
                try writeGgsw(w, &g);
            }
            try writeKskBody(w, &sk.ksk);
        }
        pub fn readServerKey(allocator: std.mem.Allocator, r: *std.Io.Reader) (DecodeError || std.mem.Allocator.Error)!F.ServerKey {
            try readHeader(r, .server_key);
            var pk = try F.PreparedBootstrapKey.alloc(allocator);
            errdefer pk.deinit(allocator);
            var g: F.Ggsw = undefined;
            for (0..n) |i| {
                try readGgsw(r, &g);
                pk.setGgsw(i, &g);
            }
            const ksk = try readKskBody(allocator, r);
            return .{ .bsk = pk, .ksk = ksk };
        }
    };
}

const testing = std.testing;
const tfhe = @import("tfhe.zig");

const Small = tfhe.Tfhe(.{
    .n = 16,
    .k = 2,
    .N = 64,
    .bg_bits = 6,
    .ell = 3,
    .bks_bits = 3,
    .ell_ks = 6,
    .lwe_noise = .{ .uniform = 1 << 8 },
    .glwe_noise = .{ .uniform = 1 << 6 },
});
const Other = tfhe.Tfhe(.{
    .n = 16,
    .k = 2,
    .N = 64,
    .bg_bits = 6,
    .ell = 3,
    .bks_bits = 3,
    .ell_ks = 5,
    .lwe_noise = .{ .uniform = 1 << 8 },
    .glwe_noise = .{ .uniform = 1 << 6 },
});
const C = Codec(Small);

test "every kind round-trips at its stated length, and a decoded server key evaluates" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var ck = Small.ClientKey.generate(io);
    defer ck.deinit();
    var sk = try Small.ServerKey.generate(testing.allocator, &ck, io);
    defer sk.deinit(testing.allocator);

    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    const w = &aw.writer;

    const t = ck.encrypt(true, io);
    try C.writeLwe(w, &t);
    try testing.expectEqual(C.encodedLen(.lwe), aw.written().len);
    try C.writeClientKey(w, &ck);
    try C.writeServerKey(w, &sk);
    var big: Small.LweBig = undefined;
    for (&big.a, 0..) |*x, i| x.* = @intCast(i * 7919);
    big.b = 42;
    try C.writeLweBig(w, &big);
    try testing.expectEqual(C.encodedLen(.lwe) + C.encodedLen(.client_key) + C.encodedLen(.server_key) + C.encodedLen(.lwe_big), aw.written().len);

    var r: std.Io.Reader = .fixed(aw.written());
    const t2 = try C.readLwe(&r);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&t), std.mem.asBytes(&t2));
    var ck2 = try C.readClientKey(&r);
    defer ck2.deinit();
    try testing.expectEqualSlices(u8, std.mem.asBytes(&ck), std.mem.asBytes(&ck2));
    var sk2 = try C.readServerKey(testing.allocator, &r);
    defer sk2.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(sk.bsk.polys), std.mem.sliceAsBytes(sk2.bsk.polys));
    try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(sk.ksk.rows), std.mem.sliceAsBytes(sk2.ksk.rows));
    const big2 = try C.readLweBig(&r);
    try testing.expectEqualSlices(u8, std.mem.asBytes(&big), std.mem.asBytes(&big2));
    try testing.expectError(error.EndOfStream, r.takeByte());

    const f = ck.encrypt(false, io);
    try testing.expect(!ck2.decrypt(&sk2.@"and"(&t2, &f)));
    try testing.expect(ck2.decrypt(&sk2.@"or"(&t2, &f)));
}

test "bootstrap and key-switch keys round-trip on their own" {
    var prng = std.Random.DefaultPrng.init(31);
    const rnd = prng.random();
    const lwe = Small.lweKeyGenForTest(16, rnd);
    const glwe = Small.glweKeyGenForTest(rnd);
    var bsk = try Small.bootstrapKeyGenForTest(testing.allocator, &lwe, &glwe, rnd);
    defer bsk.deinit(testing.allocator);
    var ksk = try Small.keySwitchKeyGenForTest(testing.allocator, &glwe, &lwe, rnd);
    defer ksk.deinit(testing.allocator);
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try C.writeBootstrapKey(&aw.writer, &bsk);
    try C.writeKeySwitchKey(&aw.writer, &ksk);
    try testing.expectEqual(C.encodedLen(.bootstrap_key) + C.encodedLen(.key_switch_key), aw.written().len);
    var r: std.Io.Reader = .fixed(aw.written());
    var bsk2 = try C.readBootstrapKey(testing.allocator, &r);
    defer bsk2.deinit(testing.allocator);
    var ksk2 = try C.readKeySwitchKey(testing.allocator, &r);
    defer ksk2.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(bsk.ggsw), std.mem.sliceAsBytes(bsk2.ggsw));
    try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(ksk.rows), std.mem.sliceAsBytes(ksk2.rows));
}

test "the header: layout pinned, and every field is checked" {
    const ct = Small.lweTrivial(16, 0x2000_0000);
    var buf: [C.encodedLen(.lwe)]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try C.writeLwe(&w, &ct);
    try testing.expectEqualSlices(u8, "TFHE\x01\x01\x00\x00\x10\x00\x00\x00\x02\x00\x00\x00\x40\x00\x00\x00\x06\x03\x03\x06", buf[0..24]);
    // payload = the LWE container, LE: 16 zero words then b.
    try testing.expect(std.mem.allEqual(u8, buf[24 .. 24 + 64], 0));
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x20", buf[24 + 64 ..]);

    const cases = [_]struct { usize, u8, DecodeError }{
        .{ 0, 'X', error.BadMagic },
        .{ 4, 2, error.UnsupportedVersion },
        .{ 5, @intFromEnum(Kind.lwe_big), error.WrongKind },
        .{ 6, 1, error.WrongKind },
        .{ 8, 17, error.ParameterMismatch },
        .{ 12, 3, error.ParameterMismatch },
        .{ 16, 128, error.ParameterMismatch },
        .{ 20, 7, error.ParameterMismatch },
        .{ 21, 2, error.ParameterMismatch },
        .{ 22, 4, error.ParameterMismatch },
        .{ 23, 5, error.ParameterMismatch },
    };
    for (cases) |c| {
        var bad = buf;
        bad[c[0]] = c[1];
        var r: std.Io.Reader = .fixed(&bad);
        try testing.expectError(c[2], C.readLwe(&r));
    }
    // A set differing only in ℓ_ks: the fingerprint tells them apart.
    var r: std.Io.Reader = .fixed(&buf);
    try testing.expectError(error.ParameterMismatch, Codec(Other).readLwe(&r));
    // Truncation anywhere is EndOfStream.
    for ([_]usize{ 0, 10, 24, buf.len - 1 }) |len| {
        var rt: std.Io.Reader = .fixed(buf[0..len]);
        try testing.expectError(error.EndOfStream, C.readLwe(&rt));
    }
}

test "a client key with a non-binary coefficient is refused" {
    var prng = std.Random.DefaultPrng.init(32);
    const rnd = prng.random();
    const ck: Small.ClientKey = .{ .lwe = Small.lweKeyGenForTest(16, rnd), .glwe = Small.glweKeyGenForTest(rnd) };
    var buf: [C.encodedLen(.client_key)]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try C.writeClientKey(&w, &ck);
    for ([_]usize{ 24, 24 + 4 * 15, 24 + 4 * 16, buf.len - 4 }) |at| {
        for ([_]u8{ 2, 0xff }) |v| {
            var bad = buf;
            bad[at] = v;
            var r: std.Io.Reader = .fixed(&bad);
            try testing.expectError(error.InvalidKey, C.readClientKey(&r));
        }
        var hi = buf;
        hi[at + 3] = 0x80;
        var r: std.Io.Reader = .fixed(&hi);
        try testing.expectError(error.InvalidKey, C.readClientKey(&r));
    }
}
