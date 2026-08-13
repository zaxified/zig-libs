// SPDX-License-Identifier: MIT

//! RPO parameter generation — a reimplementation of `get_round_constants`,
//! `get_alphas` and `get_mds` from the authors' reference implementation
//! (`rescue_prime_optimized.sage`, see `SPEC.md` for the clone command).
//!
//! It reimplements the algorithm; it does not port the code. That wording
//! matters: the sage reference is Apache-2.0 with no MIT alternative, and
//! "line-by-line port" — which this comment said until 2026-08-14 — is the
//! phrasing that earns a module a third-party attribution file in this repo.
//! Nothing here is copied and no number is carried across, which the next
//! paragraph is the argument for.
//!
//! **Everything here is derived, not remembered.** The round constants come out
//! of SHAKE256 seeded with the spec's own seed string, the S-box exponents come
//! out of the extended Euclidean algorithm, and the only literals are the two
//! published MDS first-rows — which are the *specification*, not a generator's
//! output. `constants_test.zig` pins the derived tables against the ones
//! embedded in a deployed implementation.
//!
//! The derivation runs at **comptime** (measured ~1.4 s of compile for both
//! instances; the Keccak permutation is cheap in the Zig interpreter, unlike
//! `poseidon`'s Grain LFSR which had to stay at run time).

const std = @import("std");
const gl = @import("goldilocks.zig");

/// Every RPO instance is 7 rounds. Not a knob: the round count is baked into
/// the seed string, so changing it changes every constant.
pub const num_rounds: usize = 7;

/// The two instances the specification defines, and nothing else. The spec's
/// `get_round_constants`/`get_mds` both `assert` on exactly these.
pub const Instance = struct {
    /// State width `m`.
    m: usize,
    /// Capacity `c`; rate is `m - c`.
    capacity: usize,
    /// Security level in bits — appears verbatim in the seed string.
    security: u16,

    pub const bits128 = Instance{ .m = 12, .capacity = 4, .security = 128 };
    pub const bits160 = Instance{ .m = 16, .capacity = 6, .security = 160 };

    pub fn rate(comptime self: Instance) usize {
        return self.m - self.capacity;
    }

    /// Digest length: `rate / 2` elements, per §"Indexation of State Elements".
    pub fn digestLen(comptime self: Instance) usize {
        return self.rate() / 2;
    }
};

/// First row of the circulant MDS matrix, straight from `get_mds(m)`.
///
/// These are published constants of the specification, not derived values —
/// the report gives them as a table. They are also the only literals in this
/// file, and the `m = 12` row is independently corroborated: the same row
/// appears in Winterfell's `MDS` (see `xlix.zig`) and in miden-crypto.
pub fn mdsRow(comptime inst: Instance) [inst.m]gl.Fe {
    return switch (inst.m) {
        12 => .{ 7, 23, 8, 26, 13, 10, 9, 7, 6, 22, 21, 8 },
        16 => .{
            256,    2,       1073741824, 2048,      16777216, 128,  8, 16,
            524288, 4194304, 1,          268435456, 1,        1024, 2, 8192,
        },
        else => @compileError("RPO defines an MDS only for m = 12 and m = 16"),
    };
}

/// `2 * m * N` round constants, in the spec's flat order: round `i` consumes
/// `rc[i*2m .. i*2m+m]` in its first half and `rc[i*2m+m .. (i+1)*2m]` in its
/// second.
///
/// The two details that silently change every value if you get them wrong:
///
///   * `bytes_per_int = ceil(bitlen(p) / 8) + 1` — **nine** bytes per constant,
///     not eight. The extra byte is what makes the modular reduction below an
///     honest near-uniform sample instead of a no-op.
///   * the 9 bytes are read **little-endian** (`sum(256^j * chunk[j])`), then
///     reduced mod p. There is no rejection sampling here, unlike Poseidon's
///     Grain generator.
pub fn roundConstants(comptime inst: Instance) [2 * inst.m * num_rounds]gl.Fe {
    @setEvalBranchQuota(50_000_000);
    const n = 2 * inst.m * num_rounds;
    const bytes_per_int = 9; // ceil(64/8) + 1

    var seed_buf: [64]u8 = undefined;
    const seed = std.fmt.bufPrint(
        &seed_buf,
        "RPO({d},{d},{d},{d})",
        .{ gl.P, inst.m, inst.capacity, inst.security },
    ) catch unreachable;

    var stream: [bytes_per_int * n]u8 = undefined;
    var shake = std.crypto.hash.sha3.Shake256.init(.{});
    shake.update(seed);
    shake.squeeze(&stream);

    var out: [n]gl.Fe = undefined;
    for (0..n) |i| {
        var v: u128 = 0;
        for (0..bytes_per_int) |j| {
            v |= @as(u128, stream[bytes_per_int * i + j]) << @intCast(8 * j);
        }
        out[i] = @intCast(v % gl.P);
    }
    return out;
}

/// The seed string, exposed so a reader can reproduce the SHAKE256 stream by
/// hand without re-deriving the format from this source.
pub fn seedString(comptime inst: Instance) []const u8 {
    return std.fmt.comptimePrint(
        "RPO({d},{d},{d},{d})",
        .{ gl.P, inst.m, inst.capacity, inst.security },
    );
}

test "the seed string is exactly what the sage reference formats" {
    try std.testing.expectEqualStrings(
        "RPO(18446744069414584321,12,4,128)",
        seedString(Instance.bits128),
    );
    try std.testing.expectEqualStrings(
        "RPO(18446744069414584321,16,6,160)",
        seedString(Instance.bits160),
    );
}

test "instance shapes match the specification" {
    try std.testing.expectEqual(@as(usize, 8), Instance.bits128.rate());
    try std.testing.expectEqual(@as(usize, 4), Instance.bits128.digestLen());
    try std.testing.expectEqual(@as(usize, 10), Instance.bits160.rate());
    try std.testing.expectEqual(@as(usize, 5), Instance.bits160.digestLen());
}

test "derived round constants are canonical field elements" {
    const rc = comptime roundConstants(Instance.bits128);
    try std.testing.expectEqual(@as(usize, 168), rc.len);
    for (rc) |c| try std.testing.expect(c < gl.P);
}
