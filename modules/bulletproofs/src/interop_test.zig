// SPDX-License-Identifier: MIT

//! interop_test — the module's external anchor: dalek-cryptography/
//! bulletproofs 4.0.0 and merlin 3.0.0, run as black boxes by
//! `tools/dalek/`, which wrote `interop_vectors.zig`.
//!
//! - Merlin: scripted transcripts replayed through `Transcript`; every
//!   challenge must equal merlin's bytes.
//! - Generators: dalek's Pedersen bases `B`/`B_blinding` are this module's
//!   `g`/`h`. The vector generators are pinned transitively: a dalek proof
//!   verifies only over dalek's `G_vec`/`H_vec`.
//! - dalek -> here: every proof dalek made (and verified) is accepted by
//!   `verify`, and survives `fromBytesAlloc`/`toBytesAlloc` byte-exact.
//! - here -> dalek: `zig_proofs_dalek_accepted` were made by `prove` and
//!   accepted by dalek's `verify_single` when the file was generated (the
//!   tool aborts otherwise). They are re-checked here only as regression.
//! - Controls: another label, another width, a flipped byte, a swapped
//!   commitment — each must be rejected, so acceptance above is not a
//!   verifier that says yes to everything.

const std = @import("std");
const bp = @import("root.zig");
const vectors = @import("interop_vectors.zig");
const Ristretto255 = bp.Ristretto255;

const talloc = std.testing.allocator;

fn hexAlloc(hex: []const u8) ![]u8 {
    const out = try talloc.alloc(u8, hex.len / 2);
    errdefer talloc.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn point(hex: []const u8) !Ristretto255 {
    var b: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, hex);
    return Ristretto255.fromBytes(b);
}

/// Verifies `bytes` as a proof for `v` under a fresh transcript `label` and
/// `n`-wide generators.
fn verifyWith(label: []const u8, n: usize, v: Ristretto255, bytes: []const u8) !bool {
    const gens = try bp.Generators.init(talloc, n);
    defer gens.deinit(talloc);
    const proof = bp.RangeProof.fromBytesAlloc(talloc, bytes) catch return false;
    defer proof.deinit(talloc);
    var t = bp.Transcript.init(label);
    return bp.verify(gens, &t, v, proof);
}

test "merlin: every scripted challenge equals merlin 3.0.0's bytes" {
    try std.testing.expect(vectors.merlin_scripts.len >= 3);
    var challenges: usize = 0;
    for (vectors.merlin_scripts) |script| {
        var t = bp.Transcript.init(script.label);
        for (script.ops) |op| switch (op) {
            .append => |a| t.appendMessage(a.label, a.msg),
            .append_u64 => |a| t.appendU64(a.label, a.v),
            .challenge => |c| {
                const got = try talloc.alloc(u8, c.out.len);
                defer talloc.free(got);
                t.challengeBytes(c.label, got);
                try std.testing.expectEqualSlices(u8, c.out, got);
                challenges += 1;
            },
        };
    }
    try std.testing.expect(challenges >= 8);
}

test "generators: dalek's PedersenGens B and B_blinding are g and h" {
    const gens = try bp.Generators.init(talloc, 8);
    defer gens.deinit(talloc);
    try std.testing.expect((try point(vectors.pedersen_b)).equivalent(gens.g));
    try std.testing.expect((try point(vectors.pedersen_b_blinding)).equivalent(gens.h));
}

test "dalek -> here: every dalek proof verifies and re-encodes byte-exact" {
    try std.testing.expect(vectors.dalek_proofs.len >= 12);
    var widths = std.bit_set.IntegerBitSet(65).initEmpty();
    for (vectors.dalek_proofs) |c| {
        const bytes = try hexAlloc(c.proof);
        defer talloc.free(bytes);
        try std.testing.expect(try verifyWith(vectors.label, c.n, try point(c.v), bytes));

        const proof = try bp.RangeProof.fromBytesAlloc(talloc, bytes);
        defer proof.deinit(talloc);
        const again = try proof.toBytesAlloc(talloc);
        defer talloc.free(again);
        try std.testing.expectEqualSlices(u8, bytes, again);
        widths.set(c.n);
    }
    for ([_]usize{ 8, 16, 32, 64 }) |n| try std.testing.expect(widths.isSet(n));
}

test "here -> dalek: the proofs dalek accepted still verify here" {
    try std.testing.expect(vectors.zig_proofs_dalek_accepted.len >= 12);
    for (vectors.zig_proofs_dalek_accepted) |c| {
        const bytes = try hexAlloc(c.proof);
        defer talloc.free(bytes);
        try std.testing.expect(try verifyWith(vectors.label, c.n, try point(c.v), bytes));
    }
}

test "controls: another label, width, commitment or a flipped byte is rejected" {
    for (vectors.dalek_proofs, 0..) |c, i| {
        const bytes = try hexAlloc(c.proof);
        defer talloc.free(bytes);
        const v = try point(c.v);

        // The Merlin label is bound first; any other one changes every
        // challenge.
        try std.testing.expect(!try verifyWith("doctest example", c.n, v, bytes));
        // Wider generators: the round count no longer matches.
        if (c.n < 64) try std.testing.expect(!try verifyWith(vectors.label, c.n * 2, v, bytes));
        // Another case's commitment.
        const other = vectors.dalek_proofs[(i + 1) % vectors.dalek_proofs.len];
        if (!std.mem.eql(u8, other.v, c.v))
            try std.testing.expect(!try verifyWith(vectors.label, c.n, try point(other.v), bytes));
        // One flipped bit in each 32-byte element (a point flip usually
        // fails to decode, which is a rejection too).
        var off: usize = 0;
        while (off < bytes.len) : (off += 32) {
            const work = try talloc.dupe(u8, bytes);
            defer talloc.free(work);
            work[off + 1] ^= 0x01;
            try std.testing.expect(!try verifyWith(vectors.label, c.n, v, work));
        }
    }
}
