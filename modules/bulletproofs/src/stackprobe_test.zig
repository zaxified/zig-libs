// SPDX-License-Identifier: MIT

//! Dead-stack residue probe for `prove` (audit finding B12), kept in the
//! module per `CONVENTIONS.md` §9: the instrument that checks one module lives
//! with that module, not in an audit note.
//!
//! Method as `p256`'s `stackprobe_test.zig` (direct region, 2026-10-08: the
//! earlier "scan a local buffer at the call's depth" form was blind to the top
//! few hundred bytes of the measured call): paint a stack region below the
//! probe, run one call under a `PAD`-deep shim, snapshot the region into a
//! static buffer and search the snapshot. ReleaseFast/ReleaseSmall only: Debug
//! and ReleaseSafe fill `undefined` with 0xaa, so the scan cannot see a dead
//! frame there.
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

const PAD = 2048;

var region_lo: usize = 0;
var snap: [WINDOW]u8 = undefined;

/// An address inside a frame called from the probe, at the depth
/// `paint`/`shim`/`snapshot` start at.
noinline fn stackHere() usize {
    var x: u8 = 0;
    std.mem.doNotOptimizeAway(&x);
    return @intFromPtr(&x);
}

noinline fn paint() void {
    const p: [*]volatile u8 = @ptrFromInt(region_lo);
    for (0..WINDOW) |i| p[i] = 0xC7;
}

/// Run `call` `PAD` bytes deeper than the probe, so its frames lie inside the
/// region. `pad` is touched after the call too, so it cannot be a tail call.
noinline fn shim(call: *const fn () void) void {
    var pad: [PAD]u8 = undefined;
    std.mem.doNotOptimizeAway(&pad);
    call();
    std.mem.doNotOptimizeAway(&pad);
}

noinline fn snapshot() void {
    const p: [*]const volatile u8 = @ptrFromInt(region_lo);
    for (&snap, 0..) |*d, i| d.* = p[i];
}

/// How deep the last call's frames reached below the region's top.
fn dirtyDepth() usize {
    var i: usize = 0;
    while (i < WINDOW and snap[i] == 0xC7) : (i += 1) {}
    return WINDOW - i;
}

/// Zero the callee-saved registers before a measured call: they still hold
/// the TEST's values (needles it just computed) and the call's prologue
/// spills them into its frame, where the scan would credit them to the call.
inline fn scrubCalleeSaved() void {
    if (builtin.cpu.arch == .x86_64) asm volatile (
        \\xorl %%ebx, %%ebx
        \\xorl %%r12d, %%r12d
        \\xorl %%r13d, %%r13d
        \\xorl %%r14d, %%r14d
        \\xorl %%r15d, %%r15d
        ::: .{ .rbx = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true });
}

/// `inline`: as its own frame it would run the call deeper than the region top.
inline fn measure(call: *const fn () void) void {
    scrubCalleeSaved();
    paint();
    shim(call);
    snapshot();
}

noinline fn runProve() void {
    var t = bp.Transcript.init(bp.rangeproof_domain);
    const proof = bp.prove(std.testing.allocator, std.testing.io, gens, &t, &secret_v, secret_gamma) catch unreachable;
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
        if (std.mem.eql(u8, snap[i..][0..needle.len], needle)) hits += 1;
    }
    return hits;
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
    rangeproof.appendDomainSep(&t, gens.n);
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

    var v8: [8]u8 = undefined;
    std.mem.writeInt(u64, &v8, secret_v, .little);
    const vb = vBytes();

    // Every number below is printed only when an assertion fails: the lane
    // treats stderr from a passing test as a FAIL (scripts/lib/test-lib.sh).
    errdefer std.debug.print("\n=== STACKPROBE bulletproofs B12 ({t}, window {d} KiB) ===\n", .{ builtin.mode, WINDOW / 1024 });

    region_lo = stackHere() - PAD - WINDOW;

    measure(callInnocent);
    const neg = count(&v8) + count(&vb) + count(&secret_gamma);
    measure(callLeaky);
    const pos = count(&secret_gamma);
    errdefer std.debug.print("  NEG control {d}, POS control (gamma parked) {d}\n", .{ neg, pos });
    try std.testing.expectEqual(@as(usize, 0), neg);
    try std.testing.expect(pos >= 1); // the scan can see a parked secret

    for (0..3) |round| {
        rangeproof.test_random_count = 0;
        measure(runProve);

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
        const random_count = rangeproof.test_random_count;
        const dirty = dirtyDepth();
        errdefer std.debug.print("  prove #{d}: v={d} v_bytes={d} gamma={d} z2gamma={d} randoms {d}/{d} present ({d} copies); dirty below the call {d} B\n", .{
            round, v8_hits, vb_hits, gamma_hits, z2g_hits, randoms_present, random_count, random_hits, dirty,
        });

        try std.testing.expect(rangeproof.test_random_count > 0); // the hook recorded the draws
        try std.testing.expectEqual(@as(usize, 0), v8_hits);
        try std.testing.expectEqual(@as(usize, 0), vb_hits);
        try std.testing.expectEqual(@as(usize, 0), gamma_hits);
        try std.testing.expectEqual(@as(usize, 0), z2g_hits);
        try std.testing.expectEqual(@as(usize, 0), random_hits);
    }
}
