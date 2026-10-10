// SPDX-License-Identifier: MIT

//! Shared plumbing for bn254's deterministic fuzz driver (added 2026-10-10).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `BN254_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `bn254-ecadd`, `bn254-ecmul`, `bn254-ecpairing`, `bn254-algebra`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the octets after the frame, if any, are dropped) with 0-3
/// octets damaged and maybe truncated: random bytes alone almost never get
/// past the first grammar check of these parsers.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (corpus.len == 0 or !src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
    return damage(src, buf, frame);
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated (the
/// driver's `Rng` only; the damage is drawn from `src`).
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels. `mark` also feeds the
/// driver's `REACH` report; `reach` runs `seeds` seeds in the ordinary test
/// binary and fails with `error.HarnessDoesNotReach` if a label never fired.
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

// ── harnesses ───────────────────────────────────────────────────────────

const pc = @import("precompiles.zig");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const Cursor = testkit.fuzz.Cursor;
const Rng = fuzz_driver.Rng;

const CallMark = Marker(enum { genuine_accepted, accepted, refused, reencodes });
const PairMark = Marker(enum { genuine_accepted, accepted, refused, bad_length, false_result });
const AlgebraMark = Marker(enum { sum_of_multiples, order_wraps, inverse, identity, commutes, bilinear, flipped_pairing_false });

/// BN254 group order r.
const group_order: u256 = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

fn scalarBytes(v: u256) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, v, .big);
    return out;
}

fn randScalar(k: *Cursor) u256 {
    var b: [32]u8 = undefined;
    for (&b) |*x| x.* = k.byte();
    b[0] = 0; // keep a+b+r from overflowing 2^256
    return std.mem.readInt(u256, &b, .big);
}

fn mulG(s: u256) ![64]u8 {
    var in: [96]u8 = undefined;
    in[0..64].* = g1.toBytes(g1.Affine.generator);
    in[64..96].* = scalarBytes(s);
    return pc.ecMul(&in);
}

/// Calldata made of genuine points with 0-3 octets damaged (the driver) or the
/// raw draw (`Smith`); a coordinate pushed to p..p+small is one of the damages.
fn drawCall(comptime S: type, src: *S, buf: []u8, points: usize, tail: usize) !usize {
    if (S != Rng) return src.slice(buf);
    var raw: [64]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };
    if (k.byte() & 3 == 3) return src.slice(buf);
    var off: usize = 0;
    for (0..points) |_| {
        buf[off..][0..64].* = try mulG(randScalar(&k));
        off += 64;
    }
    for (0..tail) |_| {
        buf[off] = k.byte();
        off += 1;
    }
    if (tail > 0) @memcpy(buf[off - tail ..][0..tail], &scalarBytes(randScalar(&k)));
    const len = off;
    const hits = if (k.byte() & 1 == 0) k.ranged(1, 3) else 0;
    for (0..hits) |_| buf[k.ranged(0, @intCast(len - 1))] = k.byte();
    // x >= p
    if (k.ranged(0, 15) == 0) @memset(buf[0..32], 0xff);
    return if (k.ranged(0, 7) == 0) k.ranged(0, @intCast(len)) else len;
}

fn addSmith(_: void, s: *testing.Smith) !void {
    return fuzzEcAdd(testing.Smith, s, testing.allocator);
}
test "fuzz: ecAdd never crashes on arbitrary calldata" {
    try testing.fuzz({}, addSmith, .{});
}
test "fuzz driver: BN254_FUZZ (ecAdd)" {
    try fuzz_driver.run(fuzzEcAdd, .{ .prefix = "BN254_FUZZ", .name = "bn254-ecadd", .scale = 4 });
}
test "fuzz harness: ecAdd, 300 seeds, reaches every outcome" {
    try CallMark.reach(fuzzEcAdd, "bn254-ecadd", 300);
}

fn fuzzEcAdd(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var buf: [256]u8 = undefined;
    const len = try drawCall(S, src, &buf, 2, 0);
    const out = pc.ecAdd(buf[0..len]) catch {
        CallMark.mark(.refused);
        return;
    };
    CallMark.mark(.accepted);
    // The result is a valid point: adding the identity returns it unchanged.
    var again: [128]u8 = undefined;
    again[0..64].* = out;
    again[64..128].* = @splat(0);
    if (!std.mem.eql(u8, &(try pc.ecAdd(&again)), &out)) return error.ResultNotCanonical;
    CallMark.mark(.reencodes);
    if (len == 128) CallMark.mark(.genuine_accepted);
}

fn mulSmith(_: void, s: *testing.Smith) !void {
    return fuzzEcMul(testing.Smith, s, testing.allocator);
}
test "fuzz: ecMul never crashes on arbitrary calldata" {
    try testing.fuzz({}, mulSmith, .{});
}
test "fuzz driver: BN254_FUZZ (ecMul)" {
    try fuzz_driver.run(fuzzEcMul, .{ .prefix = "BN254_FUZZ", .name = "bn254-ecmul", .scale = 4 });
}
test "fuzz harness: ecMul, 300 seeds, reaches every outcome" {
    try CallMark.reach(fuzzEcMul, "bn254-ecmul", 300);
}

fn fuzzEcMul(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var buf: [256]u8 = undefined;
    const len = try drawCall(S, src, &buf, 1, 32);
    const out = pc.ecMul(buf[0..len]) catch {
        CallMark.mark(.refused);
        return;
    };
    CallMark.mark(.accepted);
    var again: [96]u8 = undefined;
    again[0..64].* = out;
    again[64..96].* = scalarBytes(1);
    if (!std.mem.eql(u8, &(try pc.ecMul(&again)), &out)) return error.ResultNotCanonical;
    CallMark.mark(.reencodes);
    if (len == 96) CallMark.mark(.genuine_accepted);
}

fn pairSmith(_: void, s: *testing.Smith) !void {
    return fuzzEcPairing(testing.Smith, s, testing.allocator);
}
test "fuzz: ecPairing never crashes on arbitrary calldata" {
    try testing.fuzz({}, pairSmith, .{});
}
test "fuzz driver: BN254_FUZZ (ecPairing)" {
    try fuzz_driver.run(fuzzEcPairing, .{ .prefix = "BN254_FUZZ", .name = "bn254-ecpairing", .scale = 10 });
}
test "fuzz harness: ecPairing, 200 seeds, reaches every outcome" {
    try PairMark.reach(fuzzEcPairing, "bn254-ecpairing", 200);
}

fn fuzzEcPairing(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [3 * 192 + 8]u8 = undefined;
    var len: usize = undefined;
    var intact = false;
    if (S == Rng) {
        var raw: [64]u8 = undefined;
        const n: usize = src.slice(&raw);
        var k: Cursor = .{ .bytes = raw[0..n] };
        if (k.byte() & 3 == 3) {
            len = src.slice(&buf);
        } else {
            // e(aG, Q) * e(-aG, Q) (* more) : a valid, true pairing check.
            const pairs = k.ranged(0, 2);
            len = pairs * 192;
            const g2b = g2.toBytes(g2.Affine.generator);
            for (0..pairs) |i| {
                const a = try mulG(randScalar(&k));
                buf[i * 192 ..][0..64].* = a;
                buf[i * 192 + 64 ..][0..128].* = g2b;
            }
            if (pairs == 2) {
                // second point = -first, so the product is 1
                const p = try g1.fromBytes(buf[0..64]);
                buf[192..][0..64].* = g1.toBytes(g1.Jacobian.fromAffine(p).negate().toAffine());
            }
            const hits = if (k.byte() & 1 == 0) k.ranged(1, 3) else 0;
            for (0..hits) |_| if (len > 0) {
                buf[k.ranged(0, @intCast(len - 1))] = k.byte();
            };
            intact = hits == 0 and pairs == 2;
            if (k.ranged(0, 15) == 0) len += k.ranged(1, 7); // not a multiple of 192
        }
    } else {
        len = src.slice(&buf);
    }
    const result = pc.ecPairingCheck(gpa, buf[0..len]) catch |e| {
        if (e == error.BadLength) {
            PairMark.mark(.bad_length);
            return;
        }
        if (intact) return error.GenuinePairingRefused;
        PairMark.mark(.refused);
        return;
    };
    PairMark.mark(.accepted);
    if (!result) PairMark.mark(.false_result);
    if (intact) {
        if (!result) return error.GenuinePairingFalse;
        PairMark.mark(.genuine_accepted);
    }
}

fn algebraSmith(_: void, s: *testing.Smith) !void {
    return fuzzAlgebra(testing.Smith, s, testing.allocator);
}
test "fuzz: the BN254 group and pairing obey their laws" {
    try testing.fuzz({}, algebraSmith, .{});
}
test "fuzz driver: BN254_FUZZ (algebra)" {
    try fuzz_driver.run(fuzzAlgebra, .{ .prefix = "BN254_FUZZ", .name = "bn254-algebra", .scale = 100 });
}
test "fuzz harness: algebra, 8 seeds, reaches every outcome" {
    try AlgebraMark.reach(fuzzAlgebra, "bn254-algebra", 8);
}

fn fuzzAlgebra(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [128]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };
    const a = randScalar(&k);
    const b = randScalar(&k);
    const pa = try mulG(a);
    const pb = try mulG(b);
    // (a+b)G == aG + bG
    var add_in: [128]u8 = undefined;
    add_in[0..64].* = pa;
    add_in[64..128].* = pb;
    const sum_pt = try pc.ecAdd(&add_in);
    if (!std.mem.eql(u8, &sum_pt, &(try mulG(a + b)))) return error.NotDistributive;
    AlgebraMark.mark(.sum_of_multiples);
    // The scalar wraps at the group order.
    if (!std.mem.eql(u8, &pa, &(try mulG(a + group_order)))) return error.OrderDoesNotWrap;
    if (!std.mem.allEqual(u8, &(try mulG(group_order)), 0)) return error.OrderMultipleNotIdentity;
    AlgebraMark.mark(.order_wraps);
    // P + (-P) == O, P + O == P, O * s == O, P * 0 == O.
    const neg = g1.toBytes(g1.Jacobian.fromAffine(try g1.fromBytes(&pa)).negate().toAffine());
    var inv_in: [128]u8 = undefined;
    inv_in[0..64].* = pa;
    inv_in[64..128].* = neg;
    if (!std.mem.allEqual(u8, &(try pc.ecAdd(&inv_in)), 0)) return error.NoInverse;
    AlgebraMark.mark(.inverse);
    var id_in: [128]u8 = undefined;
    id_in[0..64].* = pa;
    id_in[64..128].* = @splat(0);
    if (!std.mem.eql(u8, &(try pc.ecAdd(&id_in)), &pa)) return error.NoIdentity;
    if (!std.mem.allEqual(u8, &(try mulG(0)), 0)) return error.ZeroTimesNotIdentity;
    AlgebraMark.mark(.identity);
    var swap_in: [128]u8 = undefined;
    swap_in[0..64].* = pb;
    swap_in[64..128].* = pa;
    if (!std.mem.eql(u8, &(try pc.ecAdd(&swap_in)), &sum_pt)) return error.NotCommutative;
    AlgebraMark.mark(.commutes);

    // Bilinearity: e(aG,Q) e(bG,Q) e(-(a+b)G,Q) == 1, and not with (a+b+1).
    const g2b = g2.toBytes(g2.Affine.generator);
    var call: [3 * 192]u8 = undefined;
    call[0..64].* = pa;
    call[64..192].* = g2b;
    call[192..256].* = pb;
    call[256..384].* = g2b;
    const total = try mulG(a + b);
    call[384..448].* = g1.toBytes(g1.Jacobian.fromAffine(try g1.fromBytes(&total)).negate().toAffine());
    call[448..576].* = g2b;
    if (!(try pc.ecPairingCheck(gpa, &call))) return error.BilinearityBroken;
    AlgebraMark.mark(.bilinear);
    const plus1 = try mulG(a + b + 1);
    call[384..448].* = g1.toBytes(g1.Jacobian.fromAffine(try g1.fromBytes(&plus1)).negate().toAffine());
    if (try pc.ecPairingCheck(gpa, &call)) return error.WrongSumPairs;
    AlgebraMark.mark(.flipped_pairing_false);
}
