// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `prove` (audit finding B12), kept in the
//! module per `CONVENTIONS.md` §9: the instrument that checks one module lives
//! with that module, not in an audit note.
//!
//! Method (same as `bip340`'s, `k256`'s and `xmss`'s probes): paint a stack
//! window, call `prove` at that depth, then copy an equally large
//! UNINITIALISED buffer claimed there to the heap — before anything else runs,
//! because recomputing a needle (`z`) would overwrite the window — and search
//! the copy. ReleaseFast/ReleaseSmall only: Debug and ReleaseSafe fill
//! `undefined` with 0xaa, so the scan cannot see a dead frame there.
//!
//! Needles: the witness `v` (8-byte little-endian) and its 32-byte scalar
//! `v_bytes`, the blinding factor `γ`, `z²·γ` (with the public challenge `z`
//! that is `γ`), and every random blinding scalar `prove` drew (`alpha`, `s_L`,
//! `s_R`, `rho`, `tau1`, `tau2`), which `rangeproof.test_randoms` records in
//! test builds. What this found before `prove`'s burn is recorded at
//! `rangeproof.prove_stack_burn`.
//!
//! ⛔ A zero is only readable next to the two controls in the same binary: a
//! NEGATIVE control (a call that never sees a secret, must find 0) and a
//! POSITIVE control (a call that parks `γ` in a local, must find it).

const std = @import("std");
const builtin = @import("builtin");
const bp = @import("root.zig");
const rangeproof = @import("rangeproof.zig");
const scalar = bp.Ristretto255.scalar;

const WINDOW = 256 * 1024;

const secret_gamma: [32]u8 = .{
    0xa7, 0x3d, 0x91, 0xe4, 0x5c, 0x08, 0xbb, 0x27, 0x6f, 0xd2, 0x14, 0x8a, 0x39, 0xc6, 0x70, 0x1b,
    0x4e, 0xf5, 0x82, 0x2c, 0x9b, 0x60, 0xa3, 0x17, 0xd8, 0x45, 0xee, 0x03, 0x7a, 0x51, 0xcf, 0x0d,
};
// High-entropy, so an 8-byte needle cannot match unrelated state by chance.
// Module-level: `prove` takes a pointer, and the witness must not sit in the
// probe's own frames.
var secret_v: u64 = 0x7ae2_c519_0f6b_83d4;

var gens: bp.Generators = undefined;
var last_a: bp.Ristretto255 = undefined;
var last_s: bp.Ristretto255 = undefined;
var dead: *[WINDOW]u8 = undefined;

noinline fn paint() void {
    var buf: [WINDOW]u8 = undefined;
    @memset(&buf, 0xC7);
    std.mem.doNotOptimizeAway(&buf);
}

/// Copy the uninitialised window at the depth the previous call used to the
/// heap. Volatile reads so the buffer cannot be folded away.
noinline fn snapshot() void {
    var buf: [WINDOW]u8 = undefined;
    const p: [*]volatile u8 = @ptrCast(&buf);
    for (dead, 0..) |*d, i| d.* = p[i];
    std.mem.doNotOptimizeAway(&buf);
}

noinline fn runProve() void {
    var t = bp.Transcript.init(bp.rangeproof_domain);
    const proof = bp.prove(std.testing.allocator, gens, &t, &secret_v, secret_gamma) catch unreachable;
    last_a = proof.a;
    last_s = proof.s;
    proof.deinit(std.testing.allocator);
}

/// Negative control: public data only, same depth.
noinline fn callInnocent() void {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("public", &out, .{});
    std.mem.doNotOptimizeAway(&out);
}

/// Positive control: parks `γ` in a stack local and returns.
noinline fn callLeaky() void {
    var local: [512]u8 = undefined;
    @memset(&local, 0);
    local[100..132].* = secret_gamma;
    std.mem.doNotOptimizeAway(&local);
}

fn count(needle: []const u8) usize {
    var hits: usize = 0;
    var i: usize = 0;
    while (i + needle.len <= WINDOW) : (i += 1) {
        if (std.mem.eql(u8, dead[i..][0..needle.len], needle)) hits += 1;
    }
    return hits;
}

/// Bytes below the snapshot frame's top the previous call left different from
/// the paint, burn included. Sizes `prove_stack_burn`; printed, not asserted.
fn dirtyBytes() usize {
    var i: usize = 0;
    while (i < WINDOW and dead[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

fn vBytes() [32]u8 {
    var b: [32]u8 = @splat(0);
    std.mem.writeInt(u64, b[0..8], secret_v, .little);
    return b;
}

/// `z²·γ` for the proof `runProve` just made: replay its transcript up to `z`
/// from the public points.
fn z2Gamma() [32]u8 {
    var t = bp.Transcript.init(bp.rangeproof_domain);
    t.appendU64("n", gens.n);
    t.appendPoint("V", bp.commit(gens, vBytes(), secret_gamma));
    t.appendPoint("A", last_a);
    t.appendPoint("S", last_s);
    _ = t.challengeScalar("y");
    const z = t.challengeScalar("z");
    return scalar.mul(scalar.mul(z, z), secret_gamma);
}

test "STACKPROBE (A1 B12): no witness or blinding secret on the dead stack after prove()" {
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) return error.SkipZigTest;
    const gpa = std.testing.allocator;

    gens = try bp.Generators.init(gpa, 64);
    defer gens.deinit(gpa);
    dead = try gpa.create([WINDOW]u8);
    defer gpa.destroy(dead);

    var v8: [8]u8 = undefined;
    std.mem.writeInt(u64, &v8, secret_v, .little);
    const vb = vBytes();

    std.debug.print("\n=== STACKPROBE bulletproofs B12 ({t}, window {d} KiB) ===\n", .{ builtin.mode, WINDOW / 1024 });

    paint();
    callInnocent();
    snapshot();
    const neg = count(&v8) + count(&vb) + count(&secret_gamma);
    paint();
    callLeaky();
    snapshot();
    const pos = count(&secret_gamma);
    std.debug.print("  NEG control {d}, POS control (gamma parked) {d}\n", .{ neg, pos });
    try std.testing.expectEqual(@as(usize, 0), neg);
    try std.testing.expect(pos >= 1); // the scan can see a parked secret

    for (0..3) |round| {
        rangeproof.test_random_count = 0;
        paint();
        runProve();
        snapshot();

        const v8_hits = count(&v8);
        const vb_hits = count(&vb);
        const gamma_hits = count(&secret_gamma);
        const z2g_hits = count(&z2Gamma());
        var random_hits: usize = 0;
        var randoms_present: usize = 0;
        for (rangeproof.test_randoms[0..rangeproof.test_random_count]) |r| {
            const c = count(&r);
            random_hits += c;
            if (c > 0) randoms_present += 1;
        }
        std.debug.print("  prove #{d}: v={d} v_bytes={d} gamma={d} z2gamma={d} randoms {d}/{d} present ({d} copies); dirty below the call {d} B\n", .{
            round, v8_hits, vb_hits, gamma_hits, z2g_hits, randoms_present, rangeproof.test_random_count, random_hits, dirtyBytes(),
        });

        try std.testing.expect(rangeproof.test_random_count > 0); // the hook recorded the draws
        try std.testing.expectEqual(@as(usize, 0), v8_hits);
        try std.testing.expectEqual(@as(usize, 0), vb_hits);
        try std.testing.expectEqual(@as(usize, 0), gamma_hits);
        try std.testing.expectEqual(@as(usize, 0), z2g_hits);
        try std.testing.expectEqual(@as(usize, 0), random_hits);
    }
}
