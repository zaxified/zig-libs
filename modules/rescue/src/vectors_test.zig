// SPDX-License-Identifier: MIT

//! **Grade 1 — published known-answer vectors, byte-exact.**
//!
//! Every value asserted here was published by someone else and extracted from
//! their file by script (see `upstream_vectors.zig` for the extraction command
//! and the SHA-256 of each source file). Nothing in this file was produced by
//! running this module and writing down what came out; that would make the
//! module worthless as an anchor and is the one mistake worth failing over.
//!
//! Coverage:
//!
//! | vectors | source | what they pin |
//! |---|---|---|
//! | 19 | RPO report, 128-bit instance | permutation + spec sponge, `m = 12` |
//! | 19 | RPO report, 160-bit instance | permutation + spec sponge, `m = 16` |
//! | 19 | miden-crypto `EXPECTED` | permutation + the deployed `Rpo256` framing |
//! | 1 | Winterfell `apply_permutation` | the original Rescue-XLIX permutation |
//!
//! The 128-bit report vectors and the miden vectors ride the *same*
//! permutation through *different* sponges, so between them they pin the
//! permutation twice over and each framing once.

const std = @import("std");
const gl = @import("goldilocks.zig");
const rpo = @import("rpo.zig");
const xlix = @import("xlix.zig");
const up = @import("upstream_vectors.zig");

/// The inputs every published table uses: `[0, 1, .., n-1]`.
fn counting(comptime n: usize) [n]gl.Fe {
    var out: [n]gl.Fe = undefined;
    for (0..n) |i| out[i] = i;
    return out;
}

test "RPO report, 128-bit instance: all 19 published digests" {
    inline for (up.spec_128, 1..) |expected, n| {
        const input = comptime counting(n);
        const got = rpo.spec128.hash(&input);
        try std.testing.expectEqualSlices(gl.Fe, &expected, &got);
    }
}

test "RPO report, 160-bit instance: all 19 published digests" {
    inline for (up.spec_160, 1..) |expected, n| {
        const input = comptime counting(n);
        const got = rpo.spec160.hash(&input);
        try std.testing.expectEqualSlices(gl.Fe, &expected, &got);
    }
}

test "miden-crypto Rpo256::hash_elements: all 19 published digests" {
    inline for (up.miden_rpo256, 1..) |expected, n| {
        const input = comptime counting(n);
        const got = rpo.Rpo256.hashElements(&input);
        try std.testing.expectEqualSlices(gl.Fe, &expected, &got);
    }
}

test "Winterfell Rp64_256::apply_permutation: the Rescue-XLIX known answer" {
    var state: xlix.State = up.winterfell_xlix_perm_in;
    xlix.permute(&state);
    try std.testing.expectEqualSlices(gl.Fe, &up.winterfell_xlix_perm_out, &state);
}

test "the two sponges disagree on every input, as they must" {
    // Not a vector — a guard. `spec128` and `Rpo256` are the same permutation
    // behind different framings; if a future refactor made one silently call
    // the other's absorb, both vector sets above would still have to pass, but
    // this would not.
    inline for (1..20) |n| {
        const input = comptime counting(n);
        const a = rpo.spec128.hash(&input);
        const b = rpo.Rpo256.hashElements(&input);
        try std.testing.expect(!std.mem.eql(gl.Fe, &a, &b));
    }
}

test "digest serialisation matches Miden's four little-endian u64s" {
    // Miden's `Word` -> bytes is four canonical u64s, little-endian. The first
    // published digest, byte-reversed by hand from the same extracted numbers.
    const d = rpo.Rpo256.hashElements(&.{0});
    const bytes = rpo.Rpo256.digestToBytes(d);
    for (up.miden_rpo256[0], 0..) |limb, i| {
        try std.testing.expectEqual(limb, std.mem.readInt(u64, bytes[i * 8 ..][0..8], .little));
    }
}
