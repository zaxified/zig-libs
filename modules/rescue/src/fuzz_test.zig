// SPDX-License-Identifier: MIT
//! Fuzz harnesses.
//!
//! There is no parser here — every input is already a field element — so what
//! is worth fuzzing is *structural*: properties the fixed vectors cannot state.
//!
//!   * the permutation must be a **permutation** (injective, and invertible by
//!     `permuteInverse` on any state, including ones no sponge can reach);
//!   * the field's Solinas reduction must agree with `u128 % p` on inputs a
//!     round-number sweep never produces;
//!   * the two sponge framings must not collide with each other.
//!
//! Run with:
//!
//! ```sh
//! zig build test-rescue --fuzz --release=safe
//! ```
//!
//! `--release=safe` is not optional: a plain `--fuzz` in Debug does not
//! actually fuzz in this toolchain.

const std = @import("std");
const gl = @import("goldilocks.zig");
const params = @import("params.zig");
const perm = @import("perm.zig");
const rpo = @import("rpo.zig");
const xlix = @import("xlix.zig");

const P128 = perm.Permutation(params.Instance.bits128);

fn arbitraryFe(smith: *std.testing.Smith) gl.Fe {
    return gl.fromU64(smith.value(u64));
}

fn fuzzInjective(_: void, smith: *std.testing.Smith) !void {
    var a: P128.State = undefined;
    for (&a) |*x| x.* = arbitraryFe(smith);

    // Perturb exactly one slot by a non-zero delta, so the inputs are
    // guaranteed distinct and the outputs therefore must be too.
    const slot = smith.value(u8) % P128.width;
    var delta = arbitraryFe(smith);
    if (delta == 0) delta = 1;

    var b = a;
    b[slot] = gl.add(b[slot], delta);

    var oa = a;
    var ob = b;
    P128.permute(&oa);
    P128.permute(&ob);
    try std.testing.expect(!std.mem.eql(gl.Fe, &oa, &ob));
}

test "fuzz: the RPO permutation is injective" {
    try std.testing.fuzz({}, fuzzInjective, .{});
}

fn fuzzRoundTrip(_: void, smith: *std.testing.Smith) !void {
    var st: P128.State = undefined;
    for (&st) |*x| x.* = arbitraryFe(smith);
    const original = st;
    P128.permute(&st);
    P128.permuteInverse(&st);
    try std.testing.expectEqualSlices(gl.Fe, &original, &st);
}

test "fuzz: permuteInverse undoes permute on arbitrary states" {
    try std.testing.fuzz({}, fuzzRoundTrip, .{});
}

fn fuzzField(_: void, smith: *std.testing.Smith) !void {
    const a = arbitraryFe(smith);
    const b = arbitraryFe(smith);
    const wide: u128 = (@as(u128, smith.value(u64)) << 64) | smith.value(u64);
    try std.testing.expectEqual(@as(u64, @intCast((@as(u128, a) * b) % gl.P)), gl.mul(a, b));
    try std.testing.expectEqual(@as(u64, @intCast((@as(u128, a) + b) % gl.P)), gl.add(a, b));
    try std.testing.expectEqual(@as(u64, @intCast((@as(u128, a) + gl.P - b) % gl.P)), gl.sub(a, b));
    try std.testing.expectEqual(@as(u64, @intCast(wide % gl.P)), gl.reduce128(wide));
    try std.testing.expectEqual(a, gl.sboxInv(gl.sbox(a)));
}

test "fuzz: Goldilocks arithmetic agrees with a u128 modulo oracle" {
    try std.testing.fuzz({}, fuzzField, .{});
}

/// `testkit.fuzz.seed`, aliased so the corpus below reads as the element
/// sequences it is. A corpus entry is not the sequence: `Smith.slice` reads a
/// little-endian `u32` length first.
const seed = @import("testkit").fuzz.seed;

/// Element sequences, eight octets per element, big-endian so a seed reads in
/// the order it is spelled. The framing collision property is about the LENGTH
/// of the sequence (the two framings pad differently), so the corpus is a
/// length sweep — including the rate boundary, where a sequence that fills the
/// rate exactly is the one case a padding rule can get wrong.
///
/// ⚠ 24 elements = 192 octets is the harness's buffer exactly. A seed longer
/// than the buffer is not a large seed, it is the EMPTY one.
const framing_seeds = [_][]const u8{
    seed(""), // the empty sequence: the single input `spec128.hash` refuses, and the ONLY one this target ever ran
    seed(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 }), // one element
    seed(&[_]u8{0} ** 16), // two zero elements: distinct from one, and from none
    seed(&[_]u8{0xFF} ** 16), // two elements above the Goldilocks modulus, so `fromU64` reduces
    seed(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 } ** 7), // seven: one short of the rate
    seed(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 } ** 8), // eight: the rate exactly, where the padding rules diverge
    seed(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 } ** 9), // nine: one past the rate, a second absorb
    seed(&[_]u8{0xAB} ** 128), // sixteen elements: two full rates
    seed(&[_]u8{0xCD} ** 192), // twenty-four: the buffer exactly
    seed(&[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1, 2 }), // a trailing partial element: nine octets, so the last is dropped
};

test "corpus: every framing seed reaches the sponge, and the elements absorbed are pinned" {
    // ⭐ The measurement, executable. `elements` is the second number and it
    // is the load-bearing one: the empty sequence is LEGALLY refused by
    // `spec128.hash` (`Error.EmptyInput`), which is exactly the path the
    // collapsed harness took on every run — so a guard counting "hashes that
    // did not error" would have been satisfied by nothing at all. An absorbed
    // element cannot come from an empty draw.
    var nonempty: usize = 0;
    var elements: usize = 0;
    var hashed: usize = 0;
    var empty_refusals: usize = 0;
    for (framing_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [24 * 8]u8 = undefined;
        const got: usize = smith.slice(&raw);
        if (got != 0) nonempty += 1;
        var buf: [24]gl.Fe = undefined;
        const n = got / 8;
        for (buf[0..n], 0..) |*x, i| x.* = gl.fromU64(std.mem.readInt(u64, raw[i * 8 ..][0..8], .big));
        elements += n;
        if (rpo.spec128.hash(buf[0..n])) |_| {
            hashed += 1;
        } else |_| empty_refusals += 1;
    }
    // Measured 2026-09-07. Before the draw was fixed: 1 round, 0 non-empty,
    // 0 elements absorbed, 1 empty refusal — the whole target.
    try std.testing.expectEqual(framing_seeds.len - 1, nonempty); // the deliberate empty seed
    try std.testing.expectEqual(@as(usize, 1 + 2 + 2 + 7 + 8 + 9 + 16 + 24 + 1), elements);
    try std.testing.expectEqual(framing_seeds.len - 1, hashed);
    try std.testing.expectEqual(@as(usize, 1), empty_refusals);
}

fn fuzzFramings(_: void, smith: *std.testing.Smith) !void {
    // ⚠ ONE byte-first draw. What stood here was `smith.value(u8)` as the
    // harness's FIRST act, and a `Smith` scalar draw reads eight octets as a
    // little-endian `u64`, returning the range minimum when fewer remain.
    // With no corpus this target ran exactly one input, empty, so `n` was 0
    // on every run: it took `spec128.hash`'s `EmptyInput` branch and
    // returned, and the collision property it exists to state — that the two
    // framings never agree — was never once evaluated. The comment above
    // about length 0 being "deliberately in range" was true and beside the
    // point: 0 was not merely in range, it was the ONLY value ever drawn.
    //
    // The elements now come from one byte draw, eight octets each,
    // big-endian, so a corpus entry is a readable element sequence and the
    // fuzzer still drives every element because it drives the slice.
    var raw: [24 * 8]u8 = undefined;
    const got: usize = smith.slice(&raw);
    var buf: [24]gl.Fe = undefined;
    const n = got / 8;
    for (buf[0..n], 0..) |*x, i| x.* = gl.fromU64(std.mem.readInt(u64, raw[i * 8 ..][0..8], .big));
    const input = buf[0..n];

    const a = rpo.spec128.hash(input) catch |err| {
        // The empty sequence is the single input this framing refuses; the
        // miden framing defines it. Anything else refused is a finding.
        try std.testing.expectEqual(rpo.spec128.Error.EmptyInput, err);
        try std.testing.expectEqual(@as(usize, 0), input.len);
        return;
    };
    const b = rpo.Rpo256.hashElements(input);
    try std.testing.expect(!std.mem.eql(gl.Fe, &a, &b));

    // The same elements through the same framing must agree with themselves —
    // trivial, but it is what catches a stateful `state` slipping into scope.
    try std.testing.expectEqualSlices(gl.Fe, &a, &try rpo.spec128.hash(input));
}

test "fuzz: the two RPO sponge framings never collide" {
    try std.testing.fuzz({}, fuzzFramings, .{ .corpus = &framing_seeds });
}

fn fuzzXlixDiffers(_: void, smith: *std.testing.Smith) !void {
    var st: xlix.State = undefined;
    for (&st) |*x| x.* = arbitraryFe(smith);
    var a = st;
    var b: P128.State = st;
    xlix.permute(&a);
    P128.permute(&b);
    try std.testing.expect(!std.mem.eql(gl.Fe, &a, &b));
}

test "fuzz: Rescue-XLIX and RPO never agree" {
    try std.testing.fuzz({}, fuzzXlixDiffers, .{});
}
