// SPDX-License-Identifier: MIT

//! prg — the DPF length-doubling pseudo-random generator and seed→group
//! `convert`, both **fully real and ungated** (mechanical hashing, no
//! cryptographic judgment). These are the deterministic primitives the
//! correction-word core in `dpf.zig` is built ON TOP of; they are NOT the
//! Fable-hard part.
//!
//! ## PRG definition (module-defined, SHA-256, random-oracle model)
//!
//! `G : {0,1}^128 → ({0,1}^128 × {0,1}) ^ 2` maps a 16-byte seed to a Left
//! and a Right (child-seed, control-bit) pair:
//!
//! ```
//! e0 = SHA256(seed ++ 0x00)      e1 = SHA256(seed ++ 0x01)
//! s_l = e0[0..16]   t_l = e0[16] & 1
//! s_r = e1[0..16]   t_r = e1[16] & 1
//! ```
//!
//! `convert(L, seed)` maps a leaf seed into the output group Z_{2^{8L}}:
//!
//! ```
//! cv = SHA256(seed ++ 0x02)      convert = LE_int(cv[0..L])   (mod 2^{8L})
//! ```
//!
//! **Why SHA-256 and not fixed-key AES.** Fixed-key AES (Matyas–Meyer–Oseas)
//! is the performance-standard DPF PRG. We deliberately pick SHA-256 for
//! Phase 1 because (a) it is a random-oracle-model PRG that instantiates the
//! BGI construction just as validly, and (b) it is reproducible in any
//! language's stdlib (Python `hashlib`), which is exactly what lets the
//! module's correctness be anchored byte-exact against an INDEPENDENT
//! re-derivation rather than only self-consistency (see SPEC.md
//! §"External-reference anchoring"). An AES-fixed-key PRG is a scoped-out
//! performance increment (SPEC.md §"Scoped out").

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// seed length in bytes (λ = 128 bits)
pub const seed_len = 16;
pub const Seed = [seed_len]u8;

/// one PRG expansion: a Left and a Right (child seed, control bit) pair.
pub const Expanded = struct {
    s_l: Seed,
    t_l: u1,
    s_r: Seed,
    t_r: u1,
};

/// `G(seed)` — the length-doubling PRG. Deterministic; pure computation.
pub fn prg(seed: Seed) Expanded {
    var e0: [32]u8 = undefined;
    var e1: [32]u8 = undefined;
    {
        var h = Sha256.init(.{});
        h.update(&seed);
        h.update(&[_]u8{0x00});
        h.final(&e0);
    }
    {
        var h = Sha256.init(.{});
        h.update(&seed);
        h.update(&[_]u8{0x01});
        h.final(&e1);
    }
    return .{
        .s_l = e0[0..seed_len].*,
        .t_l = @truncate(e0[seed_len]),
        .s_r = e1[0..seed_len].*,
        .t_r = @truncate(e1[seed_len]),
    };
}

/// `convert(L, seed)` — map a leaf seed into the output group Z_{2^{8L}}.
/// Returns an unsigned integer of `8*L` bits (little-endian of the hash).
pub fn convert(comptime L: usize, seed: Seed) std.meta.Int(.unsigned, 8 * L) {
    var cv: [32]u8 = undefined;
    var h = Sha256.init(.{});
    h.update(&seed);
    h.update(&[_]u8{0x02});
    h.final(&cv);
    const Int = std.meta.Int(.unsigned, 8 * L);
    if (L > 32) @compileError("convert: L must be <= 32 (SHA-256 output width)");
    var buf: [L]u8 = undefined;
    @memcpy(&buf, cv[0..L]);
    return std.mem.readInt(Int, &buf, .little);
}

// ── tests (REAL, ungated) ─────────────────────────────────────────────────

test "prg is deterministic" {
    const s: Seed = [_]u8{0x00} ** 16;
    const a = prg(s);
    const b = prg(s);
    try std.testing.expectEqualSlices(u8, &a.s_l, &b.s_l);
    try std.testing.expectEqualSlices(u8, &a.s_r, &b.s_r);
    try std.testing.expectEqual(a.t_l, b.t_l);
    try std.testing.expectEqual(a.t_r, b.t_r);
}

test "prg self-check vs recomputed SHA-256 (pins the exact construction)" {
    // Independent recomputation of the documented definition; this is what the
    // Python reference (kat_vectors.zig provenance) matches byte-exact.
    const s: Seed = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var e0: [32]u8 = undefined;
    Sha256.hash(&(s ++ [_]u8{0x00}), &e0, .{});
    const got = prg(s);
    try std.testing.expectEqualSlices(u8, e0[0..16], &got.s_l);
    try std.testing.expectEqual(@as(u1, @truncate(e0[16])), got.t_l);
}

test "prg left/right differ" {
    const s: Seed = [_]u8{0xAB} ** 16;
    const e = prg(s);
    try std.testing.expect(!std.mem.eql(u8, &e.s_l, &e.s_r));
}

test "convert is deterministic and width-correct" {
    const s: Seed = [_]u8{0x42} ** 16;
    const c4a = convert(4, s);
    const c4b = convert(4, s);
    try std.testing.expectEqual(c4a, c4b);
    try std.testing.expectEqual(@as(type, u32), @TypeOf(c4a));
    try std.testing.expectEqual(@as(type, u64), @TypeOf(convert(8, s)));
}
