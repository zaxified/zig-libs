// SPDX-License-Identifier: MIT

//! Shared plumbing for bulletproofs's deterministic fuzz driver (added 2026-10-10).
//!
//! The harness BODIES stay in `root.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (every harness
//! begins with one `slice`, so corpus seeds replay as before). This file
//! holds what they share with the driver: the reach counters with the N-seed
//! in-suite check, and the input draw.
//!
//! Driver: `BULLETPROOFS_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `bulletproofs-rp-decode`, `bulletproofs-ipa-decode`, `bulletproofs-prove-verify`.

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

const bp = @import("root.zig");
const Cursor = testkit.fuzz.Cursor;
const Rng = fuzz_driver.Rng;
const n_bits: usize = 8;

const RpMark = Marker(enum { genuine_accepted, accepted, refused, canonical, damaged_decodes, damaged_refused_by_verify });
const IpaMark = Marker(enum { genuine_accepted, accepted, refused, canonical });
const PvMark = Marker(enum { genuine_accepted, wrong_commitment_refused, wrong_domain_refused, flipped_refused, out_of_range_refused });

/// One genuine proof (v = 200, n = 8), proved once and reused by the decoder
/// harnesses, which damage its serialisation. The driver is single-threaded.
const Genuine = struct {
    var ready = false;
    var gens: bp.Generators = undefined;
    var commitment: bp.Ristretto255 = undefined;
    var bytes: []u8 = &.{};
    var ipa_bytes: []u8 = &.{};

    fn get() !void {
        if (ready) return;
        const a = std.heap.page_allocator;
        gens = try bp.Generators.init(a, n_bits);
        const v: u64 = 200;
        const gamma = [_]u8{5} ++ [_]u8{0} ** 31;
        commitment = bp.commit(gens, [_]u8{@truncate(v)} ++ [_]u8{0} ** 31, gamma);
        var t = bp.Transcript.init(bp.rangeproof_domain);
        const proof = try bp.prove(a, testing.io, gens, &t, &v, gamma);
        defer proof.deinit(a);
        bytes = try proof.toBytesAlloc(a);
        ipa_bytes = try proof.ipa.toBytesAlloc(a);
        ready = true;
    }
};

fn rpSmith(_: void, s: *testing.Smith) !void {
    return fuzzRpDecode(testing.Smith, s, testing.allocator);
}
test "fuzz: RangeProof decoder never panics; a decodable damaged proof does not verify" {
    try testing.fuzz({}, rpSmith, .{});
}
test "fuzz driver: BULLETPROOFS_FUZZ (rp-decode)" {
    try fuzz_driver.run(fuzzRpDecode, .{ .prefix = "BULLETPROOFS_FUZZ", .name = "bulletproofs-rp-decode", .scale = 4 });
}
test "fuzz harness: rp-decode, 200 seeds, reaches every outcome" {
    try RpMark.reach(fuzzRpDecode, "bulletproofs-rp-decode", 200);
}

fn fuzzRpDecode(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    try Genuine.get();
    var buf: [1024]u8 = undefined;
    var len: usize = undefined;
    var intact = false;
    if (S == Rng) {
        var raw: [32]u8 = undefined;
        const n: usize = src.slice(&raw);
        var k: Cursor = .{ .bytes = raw[0..n] };
        if (k.byte() & 3 == 3) {
            len = src.slice(&buf);
        } else {
            len = Genuine.bytes.len;
            @memcpy(buf[0..len], Genuine.bytes);
            const hits = if (k.byte() & 1 == 0) k.ranged(1, 3) else 0;
            for (0..hits) |_| buf[k.ranged(0, @intCast(len - 1))] = k.byte();
            if (k.ranged(0, 15) == 0) len = k.ranged(0, @intCast(len));
            intact = std.mem.eql(u8, buf[0..len], Genuine.bytes);
        }
    } else {
        len = src.slice(&buf);
    }
    const proof = bp.RangeProof.fromBytesAlloc(gpa, buf[0..len]) catch {
        if (intact) return error.GenuineProofRefused;
        RpMark.mark(.refused);
        return;
    };
    defer proof.deinit(gpa);
    RpMark.mark(.accepted);
    const again = try proof.toBytesAlloc(gpa);
    defer gpa.free(again);
    if (!std.mem.eql(u8, again, buf[0..len])) return error.AcceptedProofNotCanonical;
    RpMark.mark(.canonical);
    var t = bp.Transcript.init(bp.rangeproof_domain);
    const ok = bp.verify(Genuine.gens, &t, Genuine.commitment, proof);
    if (std.mem.eql(u8, buf[0..len], Genuine.bytes)) {
        if (!ok) return error.GenuineProofDoesNotVerify;
        RpMark.mark(.genuine_accepted);
    } else {
        RpMark.mark(.damaged_decodes);
        if (ok) return error.DamagedProofVerifies;
        RpMark.mark(.damaged_refused_by_verify);
    }
}

fn ipaSmith(_: void, s: *testing.Smith) !void {
    return fuzzIpaDecode(testing.Smith, s, testing.allocator);
}
test "fuzz: InnerProductProof decoder never panics and accepts only canonical encodings" {
    try testing.fuzz({}, ipaSmith, .{});
}
test "fuzz driver: BULLETPROOFS_FUZZ (ipa-decode)" {
    try fuzz_driver.run(fuzzIpaDecode, .{ .prefix = "BULLETPROOFS_FUZZ", .name = "bulletproofs-ipa-decode" });
}
test "fuzz harness: ipa-decode, 200 seeds, reaches every outcome" {
    try IpaMark.reach(fuzzIpaDecode, "bulletproofs-ipa-decode", 200);
}

fn fuzzIpaDecode(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    try Genuine.get();
    var buf: [1024]u8 = undefined;
    var len: usize = undefined;
    var intact = false;
    if (S == Rng) {
        var raw: [32]u8 = undefined;
        const n: usize = src.slice(&raw);
        var k: Cursor = .{ .bytes = raw[0..n] };
        if (k.byte() & 3 == 3) {
            len = src.slice(&buf);
        } else {
            len = Genuine.ipa_bytes.len;
            @memcpy(buf[0..len], Genuine.ipa_bytes);
            const hits = if (k.byte() & 1 == 0) k.ranged(1, 3) else 0;
            for (0..hits) |_| buf[k.ranged(0, @intCast(len - 1))] = k.byte();
            if (k.ranged(0, 15) == 0) len = k.ranged(0, @intCast(len));
            intact = std.mem.eql(u8, buf[0..len], Genuine.ipa_bytes);
        }
    } else {
        len = src.slice(&buf);
    }
    const proof = bp.InnerProductProof.fromBytesAlloc(gpa, buf[0..len]) catch {
        if (intact) return error.GenuineIpaRefused;
        IpaMark.mark(.refused);
        return;
    };
    defer proof.deinit(gpa);
    IpaMark.mark(.accepted);
    if (intact) IpaMark.mark(.genuine_accepted);
    const again = try proof.toBytesAlloc(gpa);
    defer gpa.free(again);
    if (!std.mem.eql(u8, again, buf[0..len])) return error.AcceptedIpaNotCanonical;
    IpaMark.mark(.canonical);
}

fn pvSmith(_: void, s: *testing.Smith) !void {
    return fuzzProveVerify(testing.Smith, s, testing.allocator);
}
test "fuzz: a genuine range proof verifies and every damaged claim is refused" {
    try testing.fuzz({}, pvSmith, .{});
}
test "fuzz driver: BULLETPROOFS_FUZZ (prove-verify)" {
    try fuzz_driver.run(fuzzProveVerify, .{ .prefix = "BULLETPROOFS_FUZZ", .name = "bulletproofs-prove-verify", .scale = 40 });
}
test "fuzz harness: prove-verify, 20 seeds, reaches every outcome" {
    try PvMark.reach(fuzzProveVerify, "bulletproofs-prove-verify", 20);
}

fn fuzzProveVerify(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    try Genuine.get();
    var raw: [64]u8 = undefined;
    const n: usize = src.slice(&raw);
    var k: Cursor = .{ .bytes = raw[0..n] };
    const gens = Genuine.gens;
    const v: u64 = k.byte();
    var gamma: [32]u8 = undefined;
    for (&gamma) |*x| x.* = k.byte();
    gamma[31] &= 0x0f; // canonical scalar
    const v_bytes = [_]u8{@truncate(v)} ++ [_]u8{0} ** 31;
    const commitment = bp.commit(gens, v_bytes, gamma);
    var pt = bp.Transcript.init(bp.rangeproof_domain);
    const proof = try bp.prove(gpa, testing.io, gens, &pt, &v, gamma);
    defer proof.deinit(gpa);
    var vt = bp.Transcript.init(bp.rangeproof_domain);
    if (!bp.verify(gens, &vt, commitment, proof)) return error.GenuineProofRefused;
    PvMark.mark(.genuine_accepted);
    // Another value's commitment.
    const other = bp.commit(gens, [_]u8{@truncate(v +% 1)} ++ [_]u8{0} ** 31, gamma);
    var t2 = bp.Transcript.init(bp.rangeproof_domain);
    if (bp.verify(gens, &t2, other, proof)) return error.WrongCommitmentVerifies;
    PvMark.mark(.wrong_commitment_refused);
    // A different transcript domain.
    var t3 = bp.Transcript.init("bulletproofs/other");
    if (bp.verify(gens, &t3, commitment, proof)) return error.WrongDomainVerifies;
    PvMark.mark(.wrong_domain_refused);
    // A flipped bit anywhere in the serialisation.
    const bytes = try proof.toBytesAlloc(gpa);
    defer gpa.free(bytes);
    bytes[k.ranged(0, @intCast(bytes.len - 1))] ^= @as(u8, 1) << @intCast(k.ranged(0, 7));
    if (bp.RangeProof.fromBytesAlloc(gpa, bytes)) |bad| {
        defer bad.deinit(gpa);
        var t4 = bp.Transcript.init(bp.rangeproof_domain);
        if (bp.verify(gens, &t4, commitment, bad)) return error.FlippedProofVerifies;
    } else |_| {}
    PvMark.mark(.flipped_refused);
    // v outside [0, 2^n) is refused by the prover.
    const big: u64 = (@as(u64, 1) << @intCast(n_bits)) + k.byte();
    var t5 = bp.Transcript.init(bp.rangeproof_domain);
    if (bp.prove(gpa, testing.io, gens, &t5, &big, gamma)) |p| {
        p.deinit(gpa);
        return error.OutOfRangeValueProved;
    } else |e| if (e != error.ValueOutOfRange) return e;
    PvMark.mark(.out_of_range_refused);
}
