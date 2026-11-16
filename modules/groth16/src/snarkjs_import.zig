// SPDX-License-Identifier: MIT
//! snarkjs JSON importer — the reading half of `snarkjs_export.zig`: parses
//! `proof.json`, `verification_key.json` and `public.json` into this
//! module's `bn254`-typed values, so a Zig server can verify proofs a browser
//! made with snarkjs (2026-11-16).
//!
//! It accepts exactly the shape `snarkjs_export.zig` writes and its tests pin
//! (the same shape snarkjs itself writes, see that file's doc comment):
//!   - `"protocol": "groth16"` and `"curve": "bn128"`, both required;
//!   - a field element is a JSON string of decimal digits — no sign, no `0x`,
//!     no leading zeros (except `"0"`), and strictly below the field modulus;
//!   - a `G1` point is `[x, y, "1"]` (infinity `["0","1","0"]`), a `G2` point is
//!     `[[x0,x1],[y0,y1],["1","0"]]` in MATH order `(c0, c1)` (infinity
//!     `[["0","0"],["1","0"],["0","0"]]`);
//!   - every `G1` point must be on the curve, every `G2` point on the twist AND
//!     in the order-`r` subgroup.
//! Unknown extra object members (snarkjs's `vk_alphabeta_12`, for one) are
//! ignored; a `nPublic` member, when present, must equal `IC.len - 1`.
//! Anything else is an error, never a panic. The input is untrusted.

const std = @import("std");
const bn254 = @import("bn254");
const field = @import("field.zig");
const Fr = field.Fr;
const Fp = bn254.Fp;
const G1 = bn254.G1;
const G2 = bn254.G2;

pub const ImportError = error{
    /// The text is not valid JSON.
    InvalidJson,
    /// A required member is absent, or a value has the wrong JSON type/shape
    /// (an array of the wrong length, a number where a string belongs, ...).
    InvalidShape,
    /// `"protocol"` is not `"groth16"`.
    WrongProtocol,
    /// `"curve"` is not `"bn128"`.
    WrongCurve,
    /// A number is not a canonical decimal below the modulus (empty, sign,
    /// leading zero, non-digit, too large, or `>= p` / `>= r`).
    NonCanonicalNumber,
    /// A `G1` point is not on the curve, or a `G2` point is not on the twist.
    NotOnCurve,
    /// A `G2` point is on the twist but outside the order-`r` subgroup.
    NotInSubgroup,
    /// `nPublic` disagrees with the number of `IC` entries.
    PublicCountMismatch,
    OutOfMemory,
};

const Value = std.json.Value;

/// Parses a canonical decimal string below 2^256 into 32 BE bytes (the range check against p or r is the caller's `fromBytes`).
fn decimalToBytes(s: []const u8) ImportError![32]u8 {
    if (s.len == 0 or s.len > 78) return error.NonCanonicalNumber;
    if (s.len > 1 and s[0] == '0') return error.NonCanonicalNumber;
    var v: u256 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return error.NonCanonicalNumber;
        const m = @mulWithOverflow(v, @as(u256, 10));
        if (m[1] != 0) return error.NonCanonicalNumber;
        const a = @addWithOverflow(m[0], @as(u256, c - '0'));
        if (a[1] != 0) return error.NonCanonicalNumber;
        v = a[0];
    }
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, v, .big);
    return out;
}

fn str(v: Value) ImportError![]const u8 {
    return switch (v) {
        .string => |s| s,
        else => error.InvalidShape,
    };
}

fn arr(v: Value, n: usize) ImportError![]const Value {
    switch (v) {
        .array => |a| {
            if (a.items.len != n) return error.InvalidShape;
            return a.items;
        },
        else => return error.InvalidShape,
    }
}

fn fpFrom(v: Value) ImportError!Fp {
    return Fp.fromBytes(try decimalToBytes(try str(v))) catch error.NonCanonicalNumber;
}

fn isLit(v: Value, lit: []const u8) bool {
    return switch (v) {
        .string => |s| std.mem.eql(u8, s, lit),
        else => false,
    };
}

fn g1From(v: Value) ImportError!G1.Affine {
    const a = try arr(v, 3);
    const x = try fpFrom(a[0]);
    const y = try fpFrom(a[1]);
    if (isLit(a[2], "0")) {
        // The identity as snarkjs's API writes it: ["0","1","0"], nothing else.
        if (!x.isZero() or !y.eql(Fp.one)) return error.InvalidShape;
        return G1.Affine.identity;
    }
    if (!isLit(a[2], "1")) return error.InvalidShape;
    const p = G1.Affine{ .x = x, .y = y };
    if (!G1.Jacobian.fromAffine(p).subgroupCheck()) return error.NotOnCurve; // G1: on curve == in subgroup
    return p;
}

fn fp2From(v: Value) ImportError!bn254.Fp2 {
    const a = try arr(v, 2);
    return .{ .c0 = try fpFrom(a[0]), .c1 = try fpFrom(a[1]) };
}

fn g2From(v: Value) ImportError!G2.Affine {
    const a = try arr(v, 3);
    const x = try fp2From(a[0]);
    const y = try fp2From(a[1]);
    const z = try arr(a[2], 2);
    if (isLit(z[0], "0") and isLit(z[1], "0")) {
        if (!x.isZero() or !y.eql(bn254.Fp2.one)) return error.InvalidShape;
        return G2.Affine.identity;
    }
    if (!isLit(z[0], "1") or !isLit(z[1], "0")) return error.InvalidShape;
    const p = G2.Affine{ .x = x, .y = y };
    const j = G2.Jacobian.fromAffine(p);
    if (!j.isOnCurve()) return error.NotOnCurve;
    if (!j.subgroupCheck()) return error.NotInSubgroup;
    return p;
}

fn parseRoot(arena: std.mem.Allocator, json: []const u8) ImportError!std.json.ObjectMap {
    const v = std.json.parseFromSliceLeaky(Value, arena, json, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };
    return switch (v) {
        .object => |o| o,
        else => error.InvalidShape,
    };
}

fn member(o: std.json.ObjectMap, name: []const u8) ImportError!Value {
    return o.get(name) orelse error.InvalidShape;
}

fn checkTags(o: std.json.ObjectMap) ImportError!void {
    if (!isLit(try member(o, "protocol"), "groth16")) return error.WrongProtocol;
    if (!isLit(try member(o, "curve"), "bn128")) return error.WrongCurve;
}

/// Parses a `proof.json`. Allocates only scratch (freed before returning).
pub fn parseProof(allocator: std.mem.Allocator, json: []const u8) ImportError!bn254.Groth16Proof {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const o = try parseRoot(arena.allocator(), json);
    try checkTags(o);
    return .{
        .a = try g1From(try member(o, "pi_a")),
        .b = try g2From(try member(o, "pi_b")),
        .c = try g1From(try member(o, "pi_c")),
    };
}

/// Parses a `verification_key.json`. The returned key's `ic` is allocated
/// with `allocator`: free it with `freeVerifyingKey`.
pub fn parseVerifyingKey(allocator: std.mem.Allocator, json: []const u8) ImportError!bn254.Groth16VerifyingKey {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const o = try parseRoot(arena.allocator(), json);
    try checkTags(o);
    const ic_json = switch (try member(o, "IC")) {
        .array => |a| a.items,
        else => return error.InvalidShape,
    };
    if (ic_json.len == 0) return error.InvalidShape;
    if (o.get("nPublic")) |np| {
        const n: i64 = switch (np) {
            .integer => |i| i,
            else => return error.InvalidShape,
        };
        if (n < 0 or @as(u64, @intCast(n)) != ic_json.len - 1) return error.PublicCountMismatch;
    }
    var vk: bn254.Groth16VerifyingKey = undefined;
    vk.alpha_g1 = try g1From(try member(o, "vk_alpha_1"));
    vk.beta_g2 = try g2From(try member(o, "vk_beta_2"));
    vk.gamma_g2 = try g2From(try member(o, "vk_gamma_2"));
    vk.delta_g2 = try g2From(try member(o, "vk_delta_2"));
    const ic = try allocator.alloc(G1.Affine, ic_json.len);
    errdefer allocator.free(ic);
    for (ic_json, ic) |j, *p| p.* = try g1From(j);
    vk.ic = ic;
    return vk;
}

/// Frees what `parseVerifyingKey` allocated.
pub fn freeVerifyingKey(allocator: std.mem.Allocator, vk: bn254.Groth16VerifyingKey) void {
    allocator.free(vk.ic);
}

/// Parses a `public.json`: a bare array of canonical decimal strings below
/// the scalar-field modulus. Free the result with `allocator.free`.
pub fn parsePublic(allocator: std.mem.Allocator, json: []const u8) ImportError![]Fr {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const v = std.json.parseFromSliceLeaky(Value, arena.allocator(), json, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };
    const items = switch (v) {
        .array => |a| a.items,
        else => return error.InvalidShape,
    };
    const out = try allocator.alloc(Fr, items.len);
    errdefer allocator.free(out);
    for (items, out) |it, *f| f.* = Fr.fromBytes(try decimalToBytes(try str(it))) catch return error.NonCanonicalNumber;
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const exp = @import("snarkjs_export.zig");

fn g1Eq(a: G1.Affine, b: G1.Affine) bool {
    if (a.infinity or b.infinity) return a.infinity == b.infinity;
    return a.x.eql(b.x) and a.y.eql(b.y);
}

fn g2Eq(a: G2.Affine, b: G2.Affine) bool {
    if (a.infinity or b.infinity) return a.infinity == b.infinity;
    return a.x.eql(b.x) and a.y.eql(b.y);
}

fn proofEq(a: bn254.Groth16Proof, b: bn254.Groth16Proof) bool {
    return g1Eq(a.a, b.a) and g2Eq(a.b, b.b) and g1Eq(a.c, b.c);
}

fn g2Point(k: u64) G2.Affine {
    return G2.Jacobian.fromAffine(G2.Affine.generator).scalarMul(field.frFromU64(k)).toAffine();
}
fn g1Point(k: u64) G1.Affine {
    return G1.Jacobian.fromAffine(G1.Affine.generator).scalarMul(field.frFromU64(k)).toAffine();
}

test "round trip: proofJson -> parseProof (generators, multiples, infinity)" {
    const proofs = [_]bn254.Groth16Proof{
        .{ .a = G1.Affine.generator, .b = G2.Affine.generator, .c = g1Point(7) },
        .{ .a = g1Point(123456789), .b = g2Point(987654321), .c = g1Point(2) },
        .{ .a = G1.Affine.identity, .b = G2.Affine.identity, .c = G1.Affine.identity },
    };
    for (proofs) |p| {
        const js = try exp.proofJson(testing.allocator, p);
        defer testing.allocator.free(js);
        const back = try parseProof(testing.allocator, js);
        try testing.expect(proofEq(p, back));
    }
}

test "round trip: verifyingKeyJson -> parseVerifyingKey, and publicJson -> parsePublic" {
    const ic = [_]G1.Affine{ g1Point(3), G1.Affine.generator, g1Point(11) };
    const vk = bn254.Groth16VerifyingKey{
        .alpha_g1 = g1Point(5),
        .beta_g2 = g2Point(6),
        .gamma_g2 = G2.Affine.generator,
        .delta_g2 = g2Point(8),
        .ic = &ic,
    };
    const js = try exp.verifyingKeyJson(testing.allocator, vk);
    defer testing.allocator.free(js);
    const back = try parseVerifyingKey(testing.allocator, js);
    defer freeVerifyingKey(testing.allocator, back);
    try testing.expect(g1Eq(vk.alpha_g1, back.alpha_g1));
    try testing.expect(g2Eq(vk.beta_g2, back.beta_g2));
    try testing.expect(g2Eq(vk.gamma_g2, back.gamma_g2));
    try testing.expect(g2Eq(vk.delta_g2, back.delta_g2));
    try testing.expectEqual(ic.len, back.ic.len);
    for (ic, back.ic) |a, b| try testing.expect(g1Eq(a, b));

    const inputs = [_]Fr{ field.frFromU64(9), field.frFromU64(16), Fr.zero.sub(Fr.one) };
    const pj = try exp.publicJson(testing.allocator, &inputs);
    defer testing.allocator.free(pj);
    const pb = try parsePublic(testing.allocator, pj);
    defer testing.allocator.free(pb);
    try testing.expectEqual(inputs.len, pb.len);
    for (inputs, pb) |a, b| try testing.expect(a.eql(b));
}

const real_vk = @embedFile("testdata/snarkjs/vk.json");
const real_proof = @embedFile("testdata/snarkjs/proof.json");
const real_public = @embedFile("testdata/snarkjs/public.json");
const ours_proof = @embedFile("testdata/snarkjs/ours_proof.json");

test "snarkjs's own files: parse, then the proof verifies under the parsed key" {
    const vk = try parseVerifyingKey(testing.allocator, real_vk);
    defer freeVerifyingKey(testing.allocator, vk);
    const proof = try parseProof(testing.allocator, real_proof);
    const public = try parsePublic(testing.allocator, real_public);
    defer testing.allocator.free(public);
    try testing.expectEqual(@as(usize, 3), vk.ic.len);
    try testing.expect(try bn254.groth16Verify(vk, proof, public));
    // our own proof (accepted by snarkjs) round-trips through reader and exporter
    const ours = try parseProof(testing.allocator, ours_proof);
    const js = try exp.proofJson(testing.allocator, ours);
    defer testing.allocator.free(js);
    try testing.expectEqualStrings(std.mem.trimEnd(u8, ours_proof, "\n"), js);
    // a tampered public input is rejected by the verifier, not the reader
    var bad = try testing.allocator.dupe(Fr, public);
    defer testing.allocator.free(bad);
    bad[0] = bad[0].add(Fr.one);
    try testing.expect(!try bn254.groth16Verify(vk, proof, bad));
}

fn proofWith(buf: []u8, pi_a: []const u8, pi_b: []const u8, tail: []const u8) ![]u8 {
    return std.fmt.bufPrint(buf, "{{\"pi_a\":{s},\"pi_b\":{s},\"pi_c\":[\"1\",\"2\",\"1\"],{s}}}", .{ pi_a, pi_b, tail });
}

const good_b = "[[\"10857046999023057135944570762232829481370756359578518086990519993285655852781\",\"11559732032986387107991004021392285783925812861821192530917403151452391805634\"],[\"8495653923123431417604973247489272438418190587263600148770280649306958101930\",\"4082367875863433681332203403145435568316851327593401208105741076214120093531\"],[\"1\",\"0\"]]";
const tags = "\"protocol\":\"groth16\",\"curve\":\"bn128\"";

test "parseProof refuses what it must" {
    var buf: [2048]u8 = undefined;
    const a_ok = "[\"1\",\"2\",\"1\"]";
    _ = try parseProof(testing.allocator, try proofWith(&buf, a_ok, good_b, tags));

    // wrong protocol / curve / missing tags
    try testing.expectError(error.WrongProtocol, parseProof(testing.allocator, try proofWith(&buf, a_ok, good_b, "\"protocol\":\"plonk\",\"curve\":\"bn128\"")));
    try testing.expectError(error.WrongCurve, parseProof(testing.allocator, try proofWith(&buf, a_ok, good_b, "\"protocol\":\"groth16\",\"curve\":\"bls12381\"")));
    try testing.expectError(error.InvalidShape, parseProof(testing.allocator, try proofWith(&buf, a_ok, good_b, "\"protocol\":\"groth16\"")));
    // not JSON / not an object
    try testing.expectError(error.InvalidJson, parseProof(testing.allocator, "{\"pi_a\":"));
    try testing.expectError(error.InvalidShape, parseProof(testing.allocator, "[]"));
    // non-canonical numbers
    try testing.expectError(error.NonCanonicalNumber, parseProof(testing.allocator, try proofWith(&buf, "[\"01\",\"2\",\"1\"]", good_b, tags)));
    try testing.expectError(error.NonCanonicalNumber, parseProof(testing.allocator, try proofWith(&buf, "[\"-1\",\"2\",\"1\"]", good_b, tags)));
    try testing.expectError(error.NonCanonicalNumber, parseProof(testing.allocator, try proofWith(&buf, "[\"0x1\",\"2\",\"1\"]", good_b, tags)));
    try testing.expectError(error.NonCanonicalNumber, parseProof(testing.allocator, try proofWith(&buf, "[\"\",\"2\",\"1\"]", good_b, tags)));
    // x = p (the modulus itself) and a 79-digit number
    try testing.expectError(error.NonCanonicalNumber, parseProof(testing.allocator, try proofWith(&buf, "[\"21888242871839275222246405745257275088696311157297823662689037894645226208583\",\"2\",\"1\"]", good_b, tags)));
    try testing.expectError(error.NonCanonicalNumber, parseProof(testing.allocator, try proofWith(&buf, "[\"1000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"2\",\"1\"]", good_b, tags)));
    // a JSON number instead of a string
    try testing.expectError(error.InvalidShape, parseProof(testing.allocator, try proofWith(&buf, "[1,\"2\",\"1\"]", good_b, tags)));
    // shape: wrong length, z != 1
    try testing.expectError(error.InvalidShape, parseProof(testing.allocator, try proofWith(&buf, "[\"1\",\"2\"]", good_b, tags)));
    try testing.expectError(error.InvalidShape, parseProof(testing.allocator, try proofWith(&buf, "[\"1\",\"2\",\"2\"]", good_b, tags)));
    // not on the curve: (1, 3)
    try testing.expectError(error.NotOnCurve, parseProof(testing.allocator, try proofWith(&buf, "[\"1\",\"3\",\"1\"]", good_b, tags)));
    // identity must be exactly ["0","1","0"]
    try testing.expectError(error.InvalidShape, parseProof(testing.allocator, try proofWith(&buf, "[\"1\",\"1\",\"0\"]", good_b, tags)));
    // G2 not on the twist: bump x.c0 of the generator
    const bad_b = try std.mem.replaceOwned(u8, testing.allocator, good_b, "10857046999023057135944570762232829481370756359578518086990519993285655852781", "10857046999023057135944570762232829481370756359578518086990519993285655852782");
    defer testing.allocator.free(bad_b);
    try testing.expectError(error.NotOnCurve, parseProof(testing.allocator, try proofWith(&buf, a_ok, bad_b, tags)));
    // G2 swapped halves (c1, c0): a different, off-curve point
    const swapped = "[[\"11559732032986387107991004021392285783925812861821192530917403151452391805634\",\"10857046999023057135944570762232829481370756359578518086990519993285655852781\"],[\"8495653923123431417604973247489272438418190587263600148770280649306958101930\",\"4082367875863433681332203403145435568316851327593401208105741076214120093531\"],[\"1\",\"0\"]]";
    try testing.expectError(error.NotOnCurve, parseProof(testing.allocator, try proofWith(&buf, a_ok, swapped, tags)));
}

test "parseProof refuses an on-twist G2 point outside the subgroup" {
    // Scan x = (v, 0) for a twist point; all but a ~1/r fraction are off-subgroup.
    var v: u8 = 1;
    var tested = false;
    while (v < 100) : (v += 1) {
        const xf = bn254.Fp2{ .c0 = try Fp.fromInt(u8, v), .c1 = Fp.zero };
        const y = xf.square().mul(xf).add(G2.twistB()).sqrt() orelse continue;
        const pt = G2.Affine{ .x = xf, .y = y };
        try testing.expect(!G2.Jacobian.fromAffine(pt).subgroupCheck());
        var aw: std.Io.Writer.Allocating = .init(testing.allocator);
        defer aw.deinit();
        try exp.writeG2(&aw.writer, pt);
        var buf: [2048]u8 = undefined;
        try testing.expectError(error.NotInSubgroup, parseProof(testing.allocator, try proofWith(&buf, "[\"1\",\"2\",\"1\"]", aw.writer.buffered(), tags)));
        tested = true;
        break;
    }
    try testing.expect(tested);
}

test "parseVerifyingKey refuses wrong tags, nPublic mismatch, empty IC; parsePublic refuses non-canonical" {
    const ic = [_]G1.Affine{ g1Point(3), g1Point(4) };
    const vk = bn254.Groth16VerifyingKey{ .alpha_g1 = g1Point(5), .beta_g2 = g2Point(6), .gamma_g2 = g2Point(7), .delta_g2 = g2Point(8), .ic = &ic };
    const js = try exp.verifyingKeyJson(testing.allocator, vk);
    defer testing.allocator.free(js);

    const wrong_proto = try std.mem.replaceOwned(u8, testing.allocator, js, "\"groth16\"", "\"plonk\"");
    defer testing.allocator.free(wrong_proto);
    try testing.expectError(error.WrongProtocol, parseVerifyingKey(testing.allocator, wrong_proto));
    const wrong_curve = try std.mem.replaceOwned(u8, testing.allocator, js, "\"bn128\"", "\"bls12381\"");
    defer testing.allocator.free(wrong_curve);
    try testing.expectError(error.WrongCurve, parseVerifyingKey(testing.allocator, wrong_curve));
    const wrong_n = try std.mem.replaceOwned(u8, testing.allocator, js, "\"nPublic\":1", "\"nPublic\":2");
    defer testing.allocator.free(wrong_n);
    try testing.expectError(error.PublicCountMismatch, parseVerifyingKey(testing.allocator, wrong_n));
    const no_ic = try std.mem.replaceOwned(u8, testing.allocator, js, "\"IC\":[", "\"IX\":[");
    defer testing.allocator.free(no_ic);
    try testing.expectError(error.InvalidShape, parseVerifyingKey(testing.allocator, no_ic));
    // off-curve IC entry: IC[0] = (1, 3)
    var buf: [4096]u8 = undefined;
    const bad = try std.fmt.bufPrint(&buf, "{{{s},\"nPublic\":0,\"vk_alpha_1\":[\"1\",\"2\",\"1\"],\"vk_beta_2\":{s},\"vk_gamma_2\":{s},\"vk_delta_2\":{s},\"IC\":[[\"1\",\"3\",\"1\"]]}}", .{ tags, good_b, good_b, good_b });
    try testing.expectError(error.NotOnCurve, parseVerifyingKey(testing.allocator, bad));
    const empty = try std.fmt.bufPrint(&buf, "{{{s},\"vk_alpha_1\":[\"1\",\"2\",\"1\"],\"vk_beta_2\":{s},\"vk_gamma_2\":{s},\"vk_delta_2\":{s},\"IC\":[]}}", .{ tags, good_b, good_b, good_b });
    try testing.expectError(error.InvalidShape, parseVerifyingKey(testing.allocator, empty));

    try testing.expectError(error.NonCanonicalNumber, parsePublic(testing.allocator, "[\"21888242871839275222246405745257275088548364400416034343698204186575808495617\"]"));
    try testing.expectError(error.NonCanonicalNumber, parsePublic(testing.allocator, "[\"007\"]"));
    try testing.expectError(error.InvalidShape, parsePublic(testing.allocator, "[7]"));
    try testing.expectError(error.InvalidShape, parsePublic(testing.allocator, "{}"));
    try testing.expectError(error.InvalidJson, parsePublic(testing.allocator, "[\"7\""));
    const none = try parsePublic(testing.allocator, "[]");
    defer testing.allocator.free(none);
    try testing.expectEqual(@as(usize, 0), none.len);
}
