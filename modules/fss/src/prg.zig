// SPDX-License-Identifier: MIT

//! prg — the DPF length-doubling pseudo-random generators and the seed→group
//! `convert`, both **fully real and ungated** (mechanical hashing, no
//! cryptographic judgment). These are the deterministic primitives the
//! correction-word core in `dpf.zig` is built ON TOP of; they are NOT the
//! Fable-hard part.
//!
//! ## Two instantiations, both live
//!
//! `Dpf`/`Mpf` are generic over the PRG. Two are shipped and the choice is
//! **part of the key format** (see `Key.key_format` in `dpf.zig`):
//!
//! | | `Aes128Mmo` (**default**) | `Sha256` |
//! |---|---|---|
//! | primitive | fixed-key AES-128, MMO-with-σ | SHA-256 |
//! | calls per tree node | 2 AES blocks (one `encryptWide`) | 2 compressions |
//! | constant time | **only where AES is in hardware** | always |
//! | reproducible in a stdlib-only script | needs an AES library | `hashlib`, anywhere |
//! | format tag | `0x02` | `0x01` |
//!
//! The construction in `dpf.zig` is byte-for-byte the same code for both, so
//! the recorded KAT vectors in `kat_vectors.zig` — an independent re-derivation
//! over the **SHA-256** instantiation — still pin the correction-word logic
//! after the default moved to AES. That is why `Sha256` was kept rather than
//! deleted: it is the module's anchor, not dead weight. See SPEC.md
//! §"External-reference anchoring".
//!
//! ## PRG interface
//!
//! A PRG is a (possibly stateful) value type with:
//!   - `pub const id: []const u8` — appears verbatim in `Key.key_format`
//!   - `pub const format_tag: u8` — the byte `Key.toBytesTagged` writes
//!   - `pub const constant_time: bool` — true if it is data-independent on
//!     THIS build target
//!   - `pub fn init() Self` — hoisted once per Gen/Eval entry point, so any
//!     per-instance setup (AES key expansion) is paid once per traversal, not
//!     once per node
//!   - `pub fn expand(self, Seed) Expanded`
//!   - `pub fn convert(self, comptime L, Seed) uint(8*L)`
//!
//! ## `Sha256` PRG (module-defined, random-oracle model)
//!
//! `G : {0,1}^128 → ({0,1}^128 × {0,1}) ^ 2`:
//!
//! ```
//! e0 = SHA256(seed ++ 0x00)      e1 = SHA256(seed ++ 0x01)
//! s_l = e0[0..16]   t_l = e0[16] & 1
//! s_r = e1[0..16]   t_r = e1[16] & 1
//! cv  = SHA256(seed ++ 0x02)     convert = LE_int(cv[0..L])
//! ```
//!
//! ## `Aes128Mmo` PRG (the performance-standard instantiation)
//!
//! Fixed-key AES in the Matyas–Meyer–Oseas shape with the σ pre-mix of
//! Guo–Kolesnikov–Rosulek–Roy ("Efficient and Secure Multiparty Computation
//! from Fixed-Key Block Ciphers", IEEE S&P 2020), which is what the DPF
//! literature and the fast DPF codebases use:
//!
//! ```
//! σ(x)     = (x_H ⊕ x_L) ‖ x_H          (8-byte halves, x_H = x[0..8])
//! H_j(x)   = AES_k(σ(x ⊕ j)) ⊕ σ(x ⊕ j)  (j XORed into byte 0)
//! b_l = H_0(seed)   s_l = b_l   t_l = b_l[0] & 1
//! b_r = H_1(seed)   s_r = b_r   t_r = b_r[0] & 1
//! convert = LE_int((H_2(seed) ‖ H_3(seed))[0..L])
//! ```
//!
//! Three things about this are deliberate and each is pinned by a test below.
//!
//! **Why σ and not plain `AES_k(x) ⊕ x`.** The DPF hands the PRG inputs that
//! are XOR-correlated by construction: off the α-path both parties hold the
//! same seed, and on it their seeds are related through the seed correction
//! word that the *other* party also holds. Plain MMO is correlation-robust but
//! not *circular* correlation-robust under XOR offsets; σ is exactly the fix
//! GKRRR introduced for that setting, at the price of a handful of XORs.
//!
//! **Why the control bit is the low bit of the seed.** One AES call yields 128
//! bits, not 129. Taking `t` as the lowest bit of the same block (BGI16 §3.2's
//! own remark) keeps it at one block per child; the seed then carries 127 bits
//! of conditional entropy, which is the standard trade and what makes the AES
//! PRG twice as cheap as a hash that must produce 17 bytes per child.
//!
//! **Constant-time caveat, stated rather than assumed.** `std.crypto.core.aes`
//! dispatches to AES-NI (x86-64) or the ARMv8 crypto extensions when the build
//! target has them, and those are data-independent. Where it does NOT
//! (`std.crypto.core.aes.has_hardware_support == false`), std falls back to a
//! T-table implementation whose table indices depend on the data; std applies
//! cache-line-granular mitigations (`std.options.side_channels_mitigations`,
//! default `.medium`) but does not claim constant time. The SHA-256
//! instantiation has no such caveat. `Aes128Mmo.constant_time` exposes this so
//! a caller on a soft-AES target can choose `Sha256` deliberately instead of
//! discovering the trade later. Everything ABOVE the PRG — the tree walk in
//! `dpf.zig` — is branch-free on secret bits for both instantiations.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const aes = std.crypto.core.aes;
const Aes128 = aes.Aes128;

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

/// The PRG `Dpf`/`Mpf` use when the caller does not say otherwise.
/// **Changed from `Sha256` to `Aes128Mmo`**; see `Key.key_format` for what
/// that means for stored keys.
pub const default = Aes128Mmo;

// ── SHA-256 instantiation ─────────────────────────────────────────────────

/// The original, stdlib-hash instantiation. Slower, constant time everywhere,
/// and reproducible from any language's standard library — which is why it,
/// not the default, is what the recorded KAT vectors are stated over.
pub const Sha256Prg = struct {
    pub const id = "sha256";
    pub const format_tag: u8 = 0x01;
    pub const constant_time = true;

    /// Stateless; `init` exists only so both PRGs present one interface.
    pub fn init() Sha256Prg {
        return .{};
    }

    /// `G(seed)` — the length-doubling PRG. Deterministic; pure computation.
    pub fn expand(_: Sha256Prg, seed: Seed) Expanded {
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
    pub fn convert(_: Sha256Prg, comptime L: usize, seed: Seed) std.meta.Int(.unsigned, 8 * L) {
        if (L > 32) @compileError("convert: L must be <= 32 (SHA-256 output width)");
        var cv: [32]u8 = undefined;
        var h = Sha256.init(.{});
        h.update(&seed);
        h.update(&[_]u8{0x02});
        h.final(&cv);
        const Int = std.meta.Int(.unsigned, 8 * L);
        var buf: [L]u8 = undefined;
        @memcpy(&buf, cv[0..L]);
        return std.mem.readInt(Int, &buf, .little);
    }
};

// ── fixed-key AES instantiation (default) ─────────────────────────────────

/// Fixed-key AES-128 in the MMO-with-σ shape. See the module doc for the
/// definition, for why σ is there, and for the constant-time caveat on
/// targets without hardware AES.
pub const Aes128Mmo = struct {
    /// AES round keys for `fixed_key`, expanded ONCE per Gen/Eval entry point.
    enc: aes.AesEncryptCtx(Aes128),

    pub const id = "aes128-mmo";
    pub const format_tag: u8 = 0x02;
    /// AES-NI / ARMv8-AES are data-independent; the T-table fallback is not.
    pub const constant_time = aes.has_hardware_support;

    /// The PUBLIC fixed key. It is a nothing-up-my-sleeve ASCII string, not a
    /// secret and not a parameter: fixed-key AES models the cipher under one
    /// published key as a random permutation, so every party — and every
    /// re-implementation — must use this exact key or the keys will not
    /// interoperate. 16 bytes exactly.
    pub const fixed_key: [16]u8 = "fss-dpf-fixedkey".*;

    /// Tweaks, XORed into byte 0 of the seed before σ. Distinct tweaks under
    /// one key is what separates the two children from each other and both
    /// from `convert`; one key (rather than three) is also what lets the two
    /// children go through a single `encryptWide` and pipeline.
    pub const tweak_left: u8 = 0;
    pub const tweak_right: u8 = 1;
    pub const tweak_convert: u8 = 2; // and 3 for the second convert block

    pub fn init() Aes128Mmo {
        return .{ .enc = Aes128.initEnc(fixed_key) };
    }

    /// σ(x) = (x_H ⊕ x_L) ‖ x_H, over 8-byte halves with `x_H = x[0..8]`.
    /// Byte order is a convention, so it is pinned by a test rather than left
    /// to a reader's assumption.
    pub fn sigma(x: [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        for (0..8) |i| out[i] = x[i] ^ x[8 + i];
        for (0..8) |i| out[8 + i] = x[i];
        return out;
    }

    /// One MMO step WITHOUT σ: `AES_k(x) ⊕ x`. Exposed because it is the piece
    /// with a real external vector — FIPS-197's own AES-128 example fixes
    /// `AES_k(x)`, and the XOR is then arithmetic, so `mmo` can be pinned
    /// against a number this repo did not choose. See the test below.
    pub fn mmo(self: Aes128Mmo, x: [16]u8) [16]u8 {
        var out: [16]u8 = undefined;
        self.enc.encrypt(&out, &x);
        for (&out, x) |*d, s| d.* ^= s;
        return out;
    }

    /// `H_j(x) = AES_k(σ(x ⊕ j)) ⊕ σ(x ⊕ j)`.
    fn h(self: Aes128Mmo, seed: Seed, tweak: u8) [16]u8 {
        var x = seed;
        x[0] ^= tweak;
        return self.mmo(sigma(x));
    }

    pub fn expand(self: Aes128Mmo, seed: Seed) Expanded {
        // Both children under the SAME key, so one wide call: on AES-NI the
        // two blocks pipeline instead of serializing on round latency.
        var x_l = seed;
        x_l[0] ^= tweak_left;
        var x_r = seed;
        x_r[0] ^= tweak_right;
        const p_l = sigma(x_l);
        const p_r = sigma(x_r);

        var src: [32]u8 = undefined;
        src[0..16].* = p_l;
        src[16..32].* = p_r;
        var dst: [32]u8 = undefined;
        self.enc.encryptWide(2, &dst, &src);

        // the MMO feed-forward, one child at a time
        var b_l: [16]u8 = dst[0..16].*;
        var b_r: [16]u8 = dst[16..32].*;
        for (&b_l, p_l) |*d, q| d.* ^= q;
        for (&b_r, p_r) |*d, q| d.* ^= q;

        return .{
            .s_l = b_l,
            .t_l = @truncate(b_l[0]),
            .s_r = b_r,
            .t_r = @truncate(b_r[0]),
        };
    }

    pub fn convert(self: Aes128Mmo, comptime L: usize, seed: Seed) std.meta.Int(.unsigned, 8 * L) {
        if (L > 32) @compileError("convert: L must be <= 32 (two AES blocks)");
        const Int = std.meta.Int(.unsigned, 8 * L);
        var cv: [32]u8 = undefined;
        cv[0..16].* = self.h(seed, tweak_convert);
        // A second block only when the output group is wider than one block;
        // L <= 16 is the overwhelmingly common case and costs one AES call.
        if (L > 16) cv[16..32].* = self.h(seed, tweak_convert + 1);
        var buf: [L]u8 = undefined;
        @memcpy(&buf, cv[0..L]);
        return std.mem.readInt(Int, &buf, .little);
    }
};

// ── tests (REAL, ungated) ─────────────────────────────────────────────────

const prgs = .{ Sha256Prg, Aes128Mmo };

test "every PRG: expand is deterministic" {
    inline for (prgs) |P| {
        const p = P.init();
        const s: Seed = [_]u8{0x00} ** 16;
        const a = p.expand(s);
        const b = p.expand(s);
        try std.testing.expectEqualSlices(u8, &a.s_l, &b.s_l);
        try std.testing.expectEqualSlices(u8, &a.s_r, &b.s_r);
        try std.testing.expectEqual(a.t_l, b.t_l);
        try std.testing.expectEqual(a.t_r, b.t_r);
    }
}

test "every PRG: left/right differ, and a one-bit seed change changes both" {
    inline for (prgs) |P| {
        const p = P.init();
        const s: Seed = [_]u8{0xAB} ** 16;
        const e = p.expand(s);
        try std.testing.expect(!std.mem.eql(u8, &e.s_l, &e.s_r));
        var s2 = s;
        s2[7] ^= 0x01;
        const e2 = p.expand(s2);
        try std.testing.expect(!std.mem.eql(u8, &e.s_l, &e2.s_l));
        try std.testing.expect(!std.mem.eql(u8, &e.s_r, &e2.s_r));
    }
}

test "every PRG: convert is deterministic and width-correct" {
    inline for (prgs) |P| {
        const p = P.init();
        const s: Seed = [_]u8{0x42} ** 16;
        try std.testing.expectEqual(p.convert(4, s), p.convert(4, s));
        try std.testing.expectEqual(@as(type, u32), @TypeOf(p.convert(4, s)));
        try std.testing.expectEqual(@as(type, u64), @TypeOf(p.convert(8, s)));
        // the two-block path (L > 16) must also be stable and non-trivial
        try std.testing.expectEqual(p.convert(32, s), p.convert(32, s));
        try std.testing.expect(p.convert(32, s) >> 128 != 0);
    }
}

test "every PRG: convert is separated from both children" {
    // convert(s) must not be a prefix/copy of either child seed — a wiring
    // slip that would make the leaf value predictable from the tree.
    inline for (prgs) |P| {
        const p = P.init();
        const s: Seed = [_]u8{0x5A} ** 16;
        const e = p.expand(s);
        const cv = p.convert(16, s);
        var cv_bytes: [16]u8 = undefined;
        std.mem.writeInt(u128, &cv_bytes, cv, .little);
        try std.testing.expect(!std.mem.eql(u8, &cv_bytes, &e.s_l));
        try std.testing.expect(!std.mem.eql(u8, &cv_bytes, &e.s_r));
    }
}

test "the two PRGs are genuinely different functions" {
    const s: Seed = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const a = Sha256Prg.init().expand(s);
    const b = Aes128Mmo.init().expand(s);
    try std.testing.expect(!std.mem.eql(u8, &a.s_l, &b.s_l));
    try std.testing.expect(!std.mem.eql(u8, &a.s_r, &b.s_r));
    try std.testing.expect(Sha256Prg.format_tag != Aes128Mmo.format_tag);
}

test "Sha256 PRG: self-check vs recomputed SHA-256 (pins the exact construction)" {
    // Independent recomputation of the documented definition; this is what the
    // Python reference (kat_vectors.zig provenance) matches byte-exact.
    const s: Seed = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var e0: [32]u8 = undefined;
    Sha256.hash(&(s ++ [_]u8{0x00}), &e0, .{});
    const got = Sha256Prg.init().expand(s);
    try std.testing.expectEqualSlices(u8, e0[0..16], &got.s_l);
    try std.testing.expectEqual(@as(u1, @truncate(e0[16])), got.t_l);
}

test "EXTERNAL: the MMO step against the FIPS-197 AES-128 worked example" {
    // The ONE piece of this module with a real external vector. FIPS-197
    // Appendix B fixes AES-128 for key 2b7e1516..3c and plaintext 3243f6a8..34;
    // MMO is that ciphertext XOR the plaintext, so the expected value below is
    // an XOR of two published constants, not a number this repo chose. What it
    // anchors: that our AES call is AES, with the block bytes fed in the order
    // the standard uses. What it does NOT anchor: the DPF construction, or the
    // σ/tweak/control-bit conventions layered on top — those are this module's
    // own and stay anchored by kat_vectors.zig over the SHA-256 PRG.
    const fips_key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const fips_pt = [_]u8{ 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
    const fips_ct = [_]u8{ 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };
    var want: [16]u8 = undefined;
    for (&want, fips_ct, fips_pt) |*d, c, p| d.* = c ^ p;

    const ctx = Aes128Mmo{ .enc = Aes128.initEnc(fips_key) };
    try std.testing.expectEqualSlices(u8, &want, &ctx.mmo(fips_pt));
}

test "Aes128Mmo: sigma is the documented (x_H ^ x_L) || x_H" {
    var x: [16]u8 = undefined;
    for (&x, 0..) |*d, i| d.* = @truncate(i);
    const s = Aes128Mmo.sigma(x);
    for (0..8) |i| try std.testing.expectEqual(x[i] ^ x[8 + i], s[i]);
    for (0..8) |i| try std.testing.expectEqual(x[i], s[8 + i]);
    // σ is a permutation: distinct inputs stay distinct.
    var y = x;
    y[3] ^= 0x80;
    try std.testing.expect(!std.mem.eql(u8, &s, &Aes128Mmo.sigma(y)));
}

test "Aes128Mmo: expand is exactly the documented H_0/H_1, and t is the seed's low bit" {
    // Recompute the definition the long way (no encryptWide, one block at a
    // time) and require the batched implementation to agree — the batching is
    // a performance detail and must not be able to change the bytes.
    const p = Aes128Mmo.init();
    const s: Seed = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    var x_l = s;
    x_l[0] ^= Aes128Mmo.tweak_left;
    var x_r = s;
    x_r[0] ^= Aes128Mmo.tweak_right;
    const want_l = p.mmo(Aes128Mmo.sigma(x_l));
    const want_r = p.mmo(Aes128Mmo.sigma(x_r));

    const got = p.expand(s);
    try std.testing.expectEqualSlices(u8, &want_l, &got.s_l);
    try std.testing.expectEqualSlices(u8, &want_r, &got.s_r);
    try std.testing.expectEqual(@as(u1, @truncate(want_l[0])), got.t_l);
    try std.testing.expectEqual(@as(u1, @truncate(want_r[0])), got.t_r);
}

test "Aes128Mmo: the LEFT child is the UNTWEAKED MMO — the link to the FIPS anchor" {
    // Why this exists, in one sentence: swapping `tweak_left` and
    // `tweak_right` is a CONSISTENT change — Gen and every evaluator use the
    // swapped PRG alike, so every round trip, every differential oracle and
    // every positive control in this module stays green (verified by running
    // that mutation). Nothing else here could see it.
    //
    // It dies here because `tweak_left` is 0 BY DEFINITION, which makes the
    // left child exactly `MMO(σ(seed))` — and `mmo` is the one step pinned
    // against FIPS-197 above. Stated precisely, so nobody over-reads it: this
    // is a CHAIN, not a vector. It reduces the left child to the externally
    // anchored primitive plus two conventions (σ, the fixed key) that are
    // pinned separately; it is not an external value for the child seed, and
    // no such value exists offline.
    try std.testing.expectEqual(@as(u8, 0), Aes128Mmo.tweak_left);
    try std.testing.expect(Aes128Mmo.tweak_right != Aes128Mmo.tweak_left);
    try std.testing.expect(Aes128Mmo.tweak_convert != Aes128Mmo.tweak_left);
    try std.testing.expect(Aes128Mmo.tweak_convert != Aes128Mmo.tweak_right);

    const p = Aes128Mmo.init();
    const s: Seed = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa };
    const untweaked = p.mmo(Aes128Mmo.sigma(s));
    const e = p.expand(s);
    try std.testing.expectEqualSlices(u8, &untweaked, &e.s_l);
    try std.testing.expect(!std.mem.eql(u8, &untweaked, &e.s_r));
}

test "Aes128Mmo: the fixed key is the documented public constant" {
    try std.testing.expectEqualSlices(u8, "fss-dpf-fixedkey", &Aes128Mmo.fixed_key);
    try std.testing.expectEqual(@as(usize, 16), Aes128Mmo.fixed_key.len);
}

test "every PRG: control bits are not stuck (both values appear over many seeds)" {
    inline for (prgs) |P| {
        const p = P.init();
        var saw: [4]bool = @splat(false);
        var s: Seed = @splat(0);
        for (0..256) |i| {
            s[0] = @truncate(i);
            s[1] = @truncate(i * 7);
            const e = p.expand(s);
            saw[@as(usize, e.t_l) * 2 + e.t_r] = true;
        }
        for (saw) |b| try std.testing.expect(b);
    }
}
