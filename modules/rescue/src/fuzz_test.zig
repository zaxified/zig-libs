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

fn fuzzFramings(_: void, smith: *std.testing.Smith) !void {
    var buf: [24]gl.Fe = undefined;
    // Length 0 is deliberately **in** range. It used to start at 1, which is why
    // no fuzz run ever reached `spec.hash`'s empty-input path — the one that was
    // guarded by an assert and therefore undefined behaviour in a release build.
    const n = smith.value(u8) % (buf.len + 1);
    for (buf[0..n]) |*x| x.* = arbitraryFe(smith);
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
    try std.testing.fuzz({}, fuzzFramings, .{});
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
