// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for voprf (added 2026-10-10): `VOPRF_FUZZ=<runs>[,<first seed>]`
//! (testkit's driver; `_ONLY` selects a harness by name). Harness names:
//! `voprf-decode` (Element / Proof / scalar decoders: accepted means
//! canonical, i.e. re-encodes to the input), `voprf-oprf`, `voprf-verifiable`
//! and `voprf-poprf` (a genuine exchange agrees with the direct evaluation;
//! a damaged wire element is never a silent success: it differs or is
//! refused, and a verifiable proof with ONE flipped bit in the evaluated
//! element, the proof or the public key is refused).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
pub const Cursor = testkit.fuzz.Cursor;

/// Reach counters for one harness's labels. `mark` also feeds the driver's
/// `REACH` report; `reach` runs `seeds` seeds in the ordinary test binary and
/// fails with `error.HarnessDoesNotReach` if a label never fired.
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

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated.
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

/// Deterministic bytes from a knob cursor (its first octets seed a PRNG).
pub fn expand(knobs: *Cursor, out: []u8) void {
    var s: u64 = 0;
    for (0..8) |_| s = (s << 8) | knobs.byte();
    var prng = std.Random.DefaultPrng.init(s);
    prng.random().bytes(out);
}

/// Smith-side wrapper so `--fuzz` keeps working: the harness bodies are
/// generic over `S`; `testing.fuzz` hands them a `std.testing.Smith`.
pub fn smithWrap(comptime harness: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            try harness(std.testing.Smith, smith, testing.allocator);
        }
    }.f;
}

const voprf = @import("root.zig");
const shim = @import("test_shim.zig");
const Element = voprf.Element;
const Proof = voprf.Proof;
const Ne = voprf.Ne;
const Ns = voprf.Ns;

fn flipBit(knobs: *Cursor, bytes: []u8) void {
    const at = knobs.ranged(0, @intCast(bytes.len - 1));
    bytes[at] ^= @as(u8, 1) << @intCast(knobs.ranged(0, 7));
}

const DecodeMark = Marker(enum { element_ok, element_refused, proof_ok, proof_refused, scalar_ok, scalar_refused });

fn fuzzDecode(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [8]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    // Genuine encodings to damage: an element, a proof.
    var seed: [32]u8 = undefined;
    expand(&knobs, &seed);
    const kp = try shim.deriveKeyPair(.voprf, seed, "fuzz");
    var buf: [Proof.encoded_length]u8 = undefined;
    var wide: [64]u8 = undefined;
    expand(&knobs, &wide);
    const r = shim.scalarFromWideBytes(wide);
    const genuine_proof = (try shim.generateProof(.voprf, kp.sk, Element.generator, kp.pk, &.{Element.generator}, &.{kp.pk}, r)).toBytes();
    const pk_bytes = kp.pk.toBytes();
    const frames = [_][]const u8{ &pk_bytes, &genuine_proof, &seed };
    const which = knobs.ranged(0, 2);
    var fresh: [Proof.encoded_length]u8 = undefined;
    src.bytes(&fresh);
    const n = damage(src, &buf, frames[which]);
    // Pad/truncate to the fixed width the decoders take.
    var fixed: [Proof.encoded_length]u8 = fresh;
    @memcpy(fixed[0..n], buf[0..n]);
    if (Element.fromBytes(fixed[0..Ne].*)) |e| {
        // Canonical: an accepted encoding re-encodes to the same octets.
        if (!std.mem.eql(u8, &e.toBytes(), fixed[0..Ne])) return error.NonCanonicalElementAccepted;
        DecodeMark.mark(.element_ok);
    } else |_| DecodeMark.mark(.element_refused);
    if (Proof.fromBytes(fixed)) |p| {
        if (!std.mem.eql(u8, &p.toBytes(), &fixed)) return error.NonCanonicalProofAccepted;
        DecodeMark.mark(.proof_ok);
    } else |_| DecodeMark.mark(.proof_refused);
    if (voprf.deserializeScalar(fixed[0..Ns].*)) |s| {
        if (!std.mem.eql(u8, &s, fixed[0..Ns])) return error.NonCanonicalScalarAccepted;
        DecodeMark.mark(.scalar_ok);
    } else |_| DecodeMark.mark(.scalar_refused);
}

test "fuzz: voprf decoders are canonical" {
    try testing.fuzz({}, smithWrap(fuzzDecode), .{});
}
test "fuzz driver: VOPRF_FUZZ (decode)" {
    try fuzz_driver.run(fuzzDecode, .{ .prefix = "VOPRF_FUZZ", .name = "voprf-decode" });
}
test "fuzz harness: decode, 400 seeds, reaches every outcome" {
    try DecodeMark.reach(fuzzDecode, "voprf-decode", 400);
}

const ExMark = Marker(enum { genuine_accepted, damaged_blinded_differs, damaged_blinded_refused, damaged_evaluated_differs, damaged_evaluated_refused });

const Setup = struct {
    kp: voprf.KeyPair,
    input: [24]u8,
    input_len: usize,
    blind_scalar: [Ns]u8,
    r: [Ns]u8,
    info: [12]u8,
    info_len: usize,

    fn make(knobs: *Cursor, comptime mode: voprf.Mode) !Setup {
        var s: Setup = undefined;
        var seed: [32]u8 = undefined;
        expand(knobs, &seed);
        s.kp = try shim.deriveKeyPair(mode, seed, "fuzz");
        expand(knobs, &s.input);
        s.input_len = knobs.ranged(0, 24);
        var wide: [64]u8 = undefined;
        expand(knobs, &wide);
        s.blind_scalar = shim.scalarFromWideBytes(wide);
        expand(knobs, &wide);
        s.r = shim.scalarFromWideBytes(wide);
        expand(knobs, &s.info);
        s.info_len = knobs.ranged(0, 12);
        return s;
    }
};

fn fuzzOprf(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [8]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    const s = try Setup.make(&knobs, .oprf);
    const input = s.input[0..s.input_len];
    const direct = try shim.evaluate(.oprf, s.kp.sk, input);
    const blinded = try shim.blind(.oprf, input, s.blind_scalar);
    const wire = blinded.toBytes();
    const evaluated = voprf.Element.fromBytes(wire) catch return error.GenuineElementRefused;
    const ev = shim.blindEvaluate(s.kp.sk, evaluated);
    const out = try shim.finalize(input, s.blind_scalar, ev);
    if (!std.mem.eql(u8, &out, &direct)) return error.OprfDisagreesWithDirect;
    ExMark.mark(.genuine_accepted);

    // A damaged blinded element on the server side.
    var dw = wire;
    flipBit(&knobs, &dw);
    if (Element.fromBytes(dw)) |e| {
        const out2 = try shim.finalize(input, s.blind_scalar, shim.blindEvaluate(s.kp.sk, e));
        if (std.mem.eql(u8, &out2, &direct)) return error.DamagedBlindedAgrees;
        ExMark.mark(.damaged_blinded_differs);
    } else |_| ExMark.mark(.damaged_blinded_refused);
    // A damaged evaluated element on the client side.
    var ew = ev.toBytes();
    flipBit(&knobs, &ew);
    if (Element.fromBytes(ew)) |e| {
        if (shim.finalize(input, s.blind_scalar, e)) |o| {
            if (std.mem.eql(u8, &o, &direct)) return error.DamagedEvaluatedAgrees;
            ExMark.mark(.damaged_evaluated_differs);
        } else |_| ExMark.mark(.damaged_evaluated_refused);
    } else |_| ExMark.mark(.damaged_evaluated_refused);
}

test "fuzz: voprf oprf exchange" {
    try testing.fuzz({}, smithWrap(fuzzOprf), .{});
}
test "fuzz driver: VOPRF_FUZZ (oprf)" {
    try fuzz_driver.run(fuzzOprf, .{ .prefix = "VOPRF_FUZZ", .name = "voprf-oprf" });
}
test "fuzz harness: oprf, 100 seeds, reaches every outcome" {
    try ExMark.reach(fuzzOprf, "voprf-oprf", 100);
}

const VMark = Marker(enum { genuine_accepted, flipped_evaluated_refused, flipped_proof_refused, flipped_pk_refused, wrong_blinded_refused });

fn fuzzVerifiable(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [8]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    const s = try Setup.make(&knobs, .voprf);
    const input = s.input[0..s.input_len];
    const direct = try shim.evaluate(.voprf, s.kp.sk, input);
    const blinded = try shim.blind(.voprf, input, s.blind_scalar);
    const ev = try shim.blindEvaluateVerifiable(s.kp.sk, s.kp.pk, blinded, s.r);
    const out = shim.finalizeVerifiable(input, s.blind_scalar, ev.evaluated_element, blinded, s.kp.pk, ev.proof) catch return error.GenuineProofRefused;
    if (!std.mem.eql(u8, &out, &direct)) return error.VoprfDisagreesWithDirect;
    VMark.mark(.genuine_accepted);

    var ew = ev.evaluated_element.toBytes();
    flipBit(&knobs, &ew);
    if (Element.fromBytes(ew)) |e| {
        if (shim.finalizeVerifiable(input, s.blind_scalar, e, blinded, s.kp.pk, ev.proof)) |_| return error.FlippedEvaluatedAccepted else |_| {}
    } else |_| {}
    VMark.mark(.flipped_evaluated_refused);
    var pw = ev.proof.toBytes();
    flipBit(&knobs, &pw);
    if (Proof.fromBytes(pw)) |p| {
        if (shim.finalizeVerifiable(input, s.blind_scalar, ev.evaluated_element, blinded, s.kp.pk, p)) |_| return error.FlippedProofAccepted else |_| {}
    } else |_| {}
    VMark.mark(.flipped_proof_refused);
    var kw = s.kp.pk.toBytes();
    flipBit(&knobs, &kw);
    if (Element.fromBytes(kw)) |pk2| {
        if (shim.finalizeVerifiable(input, s.blind_scalar, ev.evaluated_element, blinded, pk2, ev.proof)) |_| return error.FlippedKeyAccepted else |_| {}
    } else |_| {}
    VMark.mark(.flipped_pk_refused);
    // A proof for a different blinded element.
    var other = s.blind_scalar;
    other[0] ^= 1;
    const blinded2 = try shim.blind(.voprf, input, other);
    if (!std.mem.eql(u8, &blinded2.toBytes(), &blinded.toBytes())) {
        if (shim.finalizeVerifiable(input, s.blind_scalar, ev.evaluated_element, blinded2, s.kp.pk, ev.proof)) |_| return error.WrongBlindedAccepted else |_| {}
        VMark.mark(.wrong_blinded_refused);
    }
}

test "fuzz: voprf verifiable exchange" {
    try testing.fuzz({}, smithWrap(fuzzVerifiable), .{});
}
test "fuzz driver: VOPRF_FUZZ (verifiable)" {
    try fuzz_driver.run(fuzzVerifiable, .{ .prefix = "VOPRF_FUZZ", .name = "voprf-verifiable", .scale = 10 });
}
test "fuzz harness: verifiable, 100 seeds, reaches every outcome" {
    try VMark.reach(fuzzVerifiable, "voprf-verifiable", 100);
}

const PMark = Marker(enum { genuine_accepted, flipped_evaluated_refused, flipped_proof_refused, flipped_key_refused, wrong_info_refused });

fn fuzzPoprf(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [8]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    const s = try Setup.make(&knobs, .poprf);
    const input = s.input[0..s.input_len];
    const info = s.info[0..s.info_len];
    const direct = try shim.evaluatePoprf(s.kp.sk, input, info);
    const bl = try shim.blindPoprf(input, info, s.kp.pk, s.blind_scalar);
    const ev = try shim.blindEvaluatePoprf(s.kp.sk, bl.blinded_element, info, s.r);
    const out = shim.finalizePoprf(input, s.blind_scalar, ev.evaluated_element, bl.blinded_element, ev.proof, info, bl.tweaked_key) catch return error.GenuineProofRefused;
    if (!std.mem.eql(u8, &out, &direct)) return error.PoprfDisagreesWithDirect;
    PMark.mark(.genuine_accepted);

    var ew = ev.evaluated_element.toBytes();
    flipBit(&knobs, &ew);
    if (Element.fromBytes(ew)) |e| {
        if (shim.finalizePoprf(input, s.blind_scalar, e, bl.blinded_element, ev.proof, info, bl.tweaked_key)) |_| return error.FlippedEvaluatedAccepted else |_| {}
    } else |_| {}
    PMark.mark(.flipped_evaluated_refused);
    var pw = ev.proof.toBytes();
    flipBit(&knobs, &pw);
    if (Proof.fromBytes(pw)) |p| {
        if (shim.finalizePoprf(input, s.blind_scalar, ev.evaluated_element, bl.blinded_element, p, info, bl.tweaked_key)) |_| return error.FlippedProofAccepted else |_| {}
    } else |_| {}
    PMark.mark(.flipped_proof_refused);
    var kw = bl.tweaked_key.toBytes();
    flipBit(&knobs, &kw);
    if (Element.fromBytes(kw)) |k2| {
        if (shim.finalizePoprf(input, s.blind_scalar, ev.evaluated_element, bl.blinded_element, ev.proof, info, k2)) |_| return error.FlippedKeyAccepted else |_| {}
    } else |_| {}
    PMark.mark(.flipped_key_refused);
    // The same evaluation under a different info string: the tweaked key
    // differs, so the proof does not verify.
    var info2: [13]u8 = undefined;
    @memcpy(info2[0..info.len], info);
    info2[info.len] = 0x5a;
    const bl2 = try shim.blindPoprf(input, info2[0 .. info.len + 1], s.kp.pk, s.blind_scalar);
    if (shim.finalizePoprf(input, s.blind_scalar, ev.evaluated_element, bl.blinded_element, ev.proof, info2[0 .. info.len + 1], bl2.tweaked_key)) |_| return error.WrongInfoAccepted else |_| {}
    PMark.mark(.wrong_info_refused);
}

test "fuzz: voprf poprf exchange" {
    try testing.fuzz({}, smithWrap(fuzzPoprf), .{});
}
test "fuzz driver: VOPRF_FUZZ (poprf)" {
    try fuzz_driver.run(fuzzPoprf, .{ .prefix = "VOPRF_FUZZ", .name = "voprf-poprf", .scale = 10 });
}
test "fuzz harness: poprf, 100 seeds, reaches every outcome" {
    try PMark.reach(fuzzPoprf, "voprf-poprf", 100);
}
