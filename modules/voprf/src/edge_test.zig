// SPDX-License-Identifier: MIT

//! Edge tests the RFC vectors cannot reach: bounds that only the generic
//! protocol layer enforces (the 2^16 - 1 batch limit, a hash that lands on the
//! identity, a `DeriveKeyPair` that draws zero), the per-argument length
//! checks of every batch entry point, and the group backends' own refusals.
//!
//! `Toy` is a throwaway ciphersuite for `Protocol(G)`: the additive group of
//! integers mod the prime `2^61 - 1` with `1` as generator and SHA-256 as the
//! hash. It is NOT a secure group (discrete logs are a division) — it exists
//! because the generic layer only needs a prime-order group's algebra, and a
//! toy makes a 65 535-element batch cost milliseconds and lets a test decide
//! what the hash functions return.

const std = @import("std");
const testing = std.testing;
const voprf = @import("root.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

const P: u64 = (1 << 61) - 1;

const Toy = struct {
    pub const Point = u64;
    pub const identifier = "TOY-SHA256";
    pub const Ne = 8;
    pub const Ns = 8;
    pub const Nh = 32;
    pub const Lw = 16;
    pub const burn_scale = 1;
    pub const base: Point = 1;

    /// `hashToGroup` returns the identity while set.
    pub var hash_identity = false;
    /// `hashToScalar` for `DeriveKeyPair` returns zero for counters below this.
    pub var derive_zero_below: usize = 0;

    fn rd(b: [8]u8) u64 {
        return std.mem.readInt(u64, &b, .little);
    }
    fn wr(v: u64) [8]u8 {
        var out: [8]u8 = undefined;
        std.mem.writeInt(u64, &out, v, .little);
        return out;
    }
    fn digest(parts: []const []const u8, comptime dst: []const u8) [32]u8 {
        var h = Sha256.init(.{});
        for (parts) |p| h.update(p);
        h.update(dst);
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
    pub fn hashToGroup(parts: []const []const u8, comptime dst: []const u8) Point {
        if (hash_identity) return 0;
        const d = digest(parts, dst);
        return 1 + std.mem.readInt(u64, d[0..8], .little) % (P - 1);
    }
    pub fn hashToScalar(parts: []const []const u8, comptime dst: []const u8) [Ns]u8 {
        if (comptime std.mem.startsWith(u8, dst, "DeriveKeyPair")) {
            if (parts[3][0] < derive_zero_below) return wr(0);
        }
        const d = digest(parts, dst);
        return wr(@intCast(std.mem.readInt(u128, d[0..16], .little) % P));
    }
    pub fn reduceWide(wide: *const [Lw]u8) [Ns]u8 {
        return wr(@intCast(std.mem.readInt(u128, wide, .little) % P));
    }
    pub fn hash(parts: []const []const u8) [Nh]u8 {
        var h = Sha256.init(.{});
        for (parts) |p| h.update(p);
        var out: [Nh]u8 = undefined;
        h.final(&out);
        return out;
    }
    pub fn encode(p: Point) [Ne]u8 {
        return wr(p);
    }
    pub fn decode(b: [Ne]u8) voprf.groups.ElementError!Point {
        const v = rd(b);
        if (v == 0 or v >= P) return error.InvalidElement;
        return v;
    }
    pub fn isIdentity(p: Point) bool {
        return p == 0;
    }
    pub fn add(a: Point, b: Point) Point {
        return @intCast((@as(u128, a) + b) % P);
    }
    pub fn mulSecret(p: Point, s: *const [Ns]u8) Point {
        return @intCast(@as(u128, p) * rd(s.*) % P);
    }
    pub fn mulBaseSecret(s: *const [Ns]u8) Point {
        return mulSecret(base, s);
    }
    pub fn mulPublic(p: Point, s: [Ns]u8) voprf.groups.IdentityError!Point {
        const r = mulSecret(p, &s);
        if (r == 0) return error.IdentityElement;
        return r;
    }
    pub fn mulBasePublic(s: [Ns]u8) voprf.groups.IdentityError!Point {
        return mulPublic(base, s);
    }
    pub fn sAdd(a: [Ns]u8, b: [Ns]u8) [Ns]u8 {
        return wr(@intCast((@as(u128, rd(a)) + rd(b)) % P));
    }
    pub fn sSub(a: [Ns]u8, b: [Ns]u8) [Ns]u8 {
        return wr(@intCast((@as(u128, rd(a)) + P - rd(b)) % P));
    }
    pub fn sMul(a: [Ns]u8, b: [Ns]u8) [Ns]u8 {
        return wr(@intCast(@as(u128, rd(a)) * rd(b) % P));
    }
    pub fn sInvert(a: [Ns]u8) [Ns]u8 {
        var result: u128 = 1;
        var b: u128 = rd(a);
        var e: u64 = P - 2;
        while (e != 0) : (e >>= 1) {
            if (e & 1 == 1) result = result * b % P;
            b = b * b % P;
        }
        return wr(@intCast(result));
    }
    pub fn sCanonical(a: [Ns]u8) voprf.groups.ScalarError!void {
        if (rd(a) >= P) return error.InvalidScalar;
    }
};

const T = voprf.Protocol(Toy);

fn sc(v: u64) [8]u8 {
    return Toy.wr(v);
}

fn resetToy() void {
    Toy.hash_identity = false;
    Toy.derive_zero_below = 0;
}

test "toy ciphersuite: the generic layer round-trips OPRF, VOPRF and POPRF over it" {
    resetToy();
    const seed: [32]u8 = @splat(9);
    var kp: T.KeyPair = undefined;
    try T.deriveKeyPair(.voprf, &seed, "k", &kp);
    const blind = sc(12345);
    const blinded = try T.blind(.voprf, "input", &blind);
    const ev = try T.blindEvaluateVerifiable(&kp.sk, kp.pk, blinded, &sc(777));
    var out: [32]u8 = undefined;
    try T.finalizeVerifiable("input", &blind, ev.evaluated_element, blinded, kp.pk, ev.proof, &out);
    var direct: [32]u8 = undefined;
    try T.evaluate(.voprf, &kp.sk, "input", &direct);
    try testing.expectEqualSlices(u8, &direct, &out);
}

test "a hash that lands on the identity is InvalidInput at hashToGroup, blind and evaluate" {
    resetToy();
    defer resetToy();
    Toy.hash_identity = true;
    try testing.expectError(error.InvalidInput, T.hashToGroup(.oprf, "x"));
    try testing.expectError(error.InvalidInput, T.blind(.oprf, "x", &sc(5)));
    var out: [32]u8 = undefined;
    try testing.expectError(error.InvalidInput, T.evaluate(.oprf, &sc(5), "x", &out));
}

test "DeriveKeyPair retries through counter 255, refuses a zero key, and gives up after 256 zeros" {
    resetToy();
    defer resetToy();
    const seed: [32]u8 = @splat(3);
    var kp: T.KeyPair = undefined;
    const zero = sc(0);
    // The first draw is zero: the key must come from a later counter, never zero.
    Toy.derive_zero_below = 1;
    try T.deriveKeyPair(.oprf, &seed, "i", &kp);
    try testing.expect(!std.mem.eql(u8, &kp.sk, &zero));
    // Counter bytes advance: zero for 0..9 still ends with a key.
    Toy.derive_zero_below = 10;
    try T.deriveKeyPair(.oprf, &seed, "i", &kp);
    try testing.expect(!std.mem.eql(u8, &kp.sk, &zero));
    // Only counter 255 is non-zero: the last attempt of the RFC's loop counts.
    Toy.derive_zero_below = 255;
    try T.deriveKeyPair(.oprf, &seed, "i", &kp);
    try testing.expect(!std.mem.eql(u8, &kp.sk, &zero));
    // Every counter 0..255 is zero.
    Toy.derive_zero_below = 256;
    try testing.expectError(error.DeriveKeyPairFailed, T.deriveKeyPair(.oprf, &seed, "i", &kp));
}

test "a batch of exactly 2^16 - 1 is proved and verified, 2^16 is refused with the outputs untouched" {
    resetToy();
    const n = voprf.max_batch_length;
    const g = T.Element.generator;
    const blinded = try testing.allocator.alloc(T.Element, n + 1);
    defer testing.allocator.free(blinded);
    const outs = try testing.allocator.alloc(T.Element, n + 1);
    defer testing.allocator.free(outs);
    for (blinded, 0..) |*b, i| b.* = .{ .p = 2 + i };
    const sk = sc(424242);
    const pk = T.Element{ .p = Toy.mulBaseSecret(&sk) };
    const r = sc(99);

    // VOPRF, at the limit.
    const proof = try T.blindEvaluateVerifiableBatch(&sk, pk, blinded[0..n], outs[0..n], &r);
    try T.verifyProof(.voprf, g, pk, blinded[0..n], outs[0..n], proof);
    // Over the limit: refused by the server before it writes an output, and by the verifier.
    @memset(outs, g);
    try testing.expectError(error.ProofGenerationFailed, T.blindEvaluateVerifiableBatch(&sk, pk, blinded, outs, &r));
    for (outs) |o| try testing.expectEqual(@as(u64, 1), o.p);
    try testing.expectError(error.InvalidProof, T.verifyProof(.voprf, g, pk, blinded, outs, proof));
    try testing.expectError(error.ProofGenerationFailed, T.generateProof(.voprf, &sk, g, pk, blinded, outs, &r));

    // POPRF, at the limit and over it.
    _ = try T.blindEvaluatePoprfBatch(&sk, blinded[0..n], "info", outs[0..n], &r);
    @memset(outs, g);
    try testing.expectError(error.ProofGenerationFailed, T.blindEvaluatePoprfBatch(&sk, blinded, "info", outs, &r));
    for (outs) |o| try testing.expectEqual(@as(u64, 1), o.p);
}

test "generateProof and verifyProof refuse an empty batch and lists of different lengths" {
    resetToy();
    const g = T.Element.generator;
    const sk = sc(5);
    const pk = T.Element{ .p = Toy.mulBaseSecret(&sk) };
    const two = [_]T.Element{ g, pk };
    const proof = T.Proof{ .c = sc(1), .s = sc(2) };
    try testing.expectError(error.ProofGenerationFailed, T.generateProof(.voprf, &sk, g, pk, &.{}, &.{}, &sc(7)));
    try testing.expectError(error.ProofGenerationFailed, T.generateProof(.voprf, &sk, g, pk, &two, two[0..1], &sc(7)));
    try testing.expectError(error.ProofGenerationFailed, T.generateProof(.voprf, &sk, g, pk, two[0..1], &two, &sc(7)));
    try testing.expectError(error.InvalidProof, T.verifyProof(.voprf, g, pk, &.{}, &.{}, proof));
    try testing.expectError(error.InvalidProof, T.verifyProof(.voprf, g, pk, &two, two[0..1], proof));
    try testing.expectError(error.InvalidProof, T.verifyProof(.voprf, g, pk, two[0..1], &two, proof));
}

test "every batch finalizer names a length that differs from the others, one argument at a time" {
    resetToy();
    const g = T.Element.generator;
    const pk = g;
    const proof = T.Proof{ .c = sc(1), .s = sc(2) };
    const bs = [_][8]u8{ sc(3), sc(4), sc(5) };
    const els = [_]T.Element{ g, g, g };
    const ins = [_][]const u8{ "a", "b", "c" };
    var outs: [3][32]u8 = undefined;
    // all equal but zero: empty
    try testing.expectError(error.EmptyBatch, T.finalizeVerifiableBatch(&.{}, &.{}, &.{}, &.{}, pk, proof, outs[0..0]));
    try testing.expectError(error.EmptyBatch, T.finalizePoprfBatch(&.{}, &.{}, &.{}, &.{}, proof, "i", pk, outs[0..0]));
    // inputs has 2, one other argument has 3 (blinds, evaluated, blinded, outputs in turn)
    try testing.expectError(error.MismatchedLengths, T.finalizeVerifiableBatch(ins[0..2], &bs, els[0..2], els[0..2], pk, proof, outs[0..2]));
    try testing.expectError(error.MismatchedLengths, T.finalizeVerifiableBatch(ins[0..2], bs[0..2], &els, els[0..2], pk, proof, outs[0..2]));
    try testing.expectError(error.MismatchedLengths, T.finalizeVerifiableBatch(ins[0..2], bs[0..2], els[0..2], &els, pk, proof, outs[0..2]));
    try testing.expectError(error.MismatchedLengths, T.finalizeVerifiableBatch(ins[0..2], bs[0..2], els[0..2], els[0..2], pk, proof, &outs));
    try testing.expectError(error.MismatchedLengths, T.finalizeVerifiableBatch(&ins, bs[0..2], els[0..2], els[0..2], pk, proof, outs[0..2]));
    try testing.expectError(error.MismatchedLengths, T.finalizePoprfBatch(ins[0..2], &bs, els[0..2], els[0..2], proof, "i", pk, outs[0..2]));
    try testing.expectError(error.MismatchedLengths, T.finalizePoprfBatch(ins[0..2], bs[0..2], &els, els[0..2], proof, "i", pk, outs[0..2]));
    try testing.expectError(error.MismatchedLengths, T.finalizePoprfBatch(ins[0..2], bs[0..2], els[0..2], &els, proof, "i", pk, outs[0..2]));
    try testing.expectError(error.MismatchedLengths, T.finalizePoprfBatch(ins[0..2], bs[0..2], els[0..2], els[0..2], proof, "i", pk, &outs));
    try testing.expectError(error.MismatchedLengths, T.finalizePoprfBatch(&ins, bs[0..2], els[0..2], els[0..2], proof, "i", pk, outs[0..2]));
}

test "a 65536-byte entry in a batch input, or in finalizePoprfUnverified's info, is InputTooLong" {
    resetToy();
    const long = try testing.allocator.alloc(u8, voprf.max_input_length + 1);
    defer testing.allocator.free(long);
    @memset(long, 'x');
    const g = T.Element.generator;
    const proof = T.Proof{ .c = sc(1), .s = sc(2) };
    const b = sc(3);
    var outs: [1][32]u8 = undefined;
    var out: [32]u8 = undefined;
    try testing.expectError(error.InputTooLong, T.finalizePoprfBatch(&.{long}, &.{b}, &.{g}, &.{g}, proof, "i", g, &outs));
    try testing.expectError(error.InputTooLong, T.finalizeVerifiableBatch(&.{ "x", long }, &.{ b, b }, &.{ g, g }, &.{ g, g }, g, proof, outs[0..1]));
    try testing.expectError(error.InputTooLong, T.finalizePoprfUnverified("x", &b, g, long, &out));
    try testing.expectError(error.InputTooLong, T.finalizePoprfUnverified(long, &b, g, "i", &out));
}

test "wipe zeroes the server key in every role, on every suite" {
    inline for (@typeInfo(voprf.Ciphersuite).@"enum".field_names) |name| {
        const S = voprf.Suite(@field(voprf.Ciphersuite, name));
        const seed: [32]u8 = @splat(0x21);
        const zero: [S.Ns]u8 = @splat(0);
        var os = try S.OprfServer.derive(&seed, "i");
        try testing.expect(!std.mem.eql(u8, &os.sk, &zero));
        os.wipe();
        try testing.expectEqualSlices(u8, &zero, &os.sk);
        var vs = try S.VoprfServer.derive(&seed, "i");
        try testing.expect(!std.mem.eql(u8, &vs.key_pair.sk, &zero));
        vs.wipe();
        try testing.expectEqualSlices(u8, &zero, &vs.key_pair.sk);
        var ps = try S.PoprfServer.derive(&seed, "i");
        try testing.expect(!std.mem.eql(u8, &ps.key_pair.sk, &zero));
        ps.wipe();
        try testing.expectEqualSlices(u8, &zero, &ps.key_pair.sk);
    }
}

test "group backends: the identity is refused on decode, a zero public multiple is an error, a degenerate encode is all zero" {
    inline for (@typeInfo(voprf.Ciphersuite).@"enum".field_names) |name| {
        const S = voprf.Suite(@field(voprf.Ciphersuite, name));
        const G = S.Group;
        const zero: [S.Ns]u8 = @splat(0);
        // encode(identity) is Ne zero bytes (the only element a secret zero can produce), and decode refuses it.
        const id_enc = G.encode(G.mulSecret(G.base, &zero));
        try testing.expectEqualSlices(u8, &@as([S.Ne]u8, @splat(0)), &id_enc);
        try testing.expectError(error.InvalidElement, S.Element.fromBytes(id_enc));
        // mulPublic and mulBasePublic report a zero product as an error, never as a value.
        try testing.expectError(error.IdentityElement, G.mulPublic(G.base, zero));
        try testing.expectError(error.IdentityElement, G.mulBasePublic(zero));
        // A real element still decodes and round-trips.
        const gen = S.Element.generator.toBytes();
        try testing.expectEqualSlices(u8, &gen, &(try S.Element.fromBytes(gen)).toBytes());
    }
}

test "NIST suites: only the 0x02/0x03 compressed prefixes decode" {
    inline for (.{ voprf.P256Sha256, voprf.P384Sha384, voprf.P521Sha512 }) |S| {
        var enc = S.Element.generator.toBytes();
        for ([_]u8{ 0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff }) |prefix| {
            enc[0] = prefix;
            try testing.expectError(error.InvalidElement, S.Element.fromBytes(enc));
        }
    }
}
