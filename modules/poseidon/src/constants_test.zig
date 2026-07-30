// SPDX-License-Identifier: MIT
//! Pins the **derived parameters** — round constants and MDS matrices —
//! against upstream's published ones.
//!
//! `vectors_test.zig` already proves the whole thing end to end, so why pin
//! the constants separately? Because the two failures look completely
//! different. A vector mismatch says "something in this module is wrong"; a
//! digest mismatch says "the generator drifted", and points straight at
//! `grain.zig` — the one file where a subtle change (rejection vs reduction,
//! the output filter, the seed layout) silently reshapes every number while
//! everything still compiles and round-trips.
//!
//! ## Provenance, and how to reproduce every number below
//!
//! **BN254, t = 2..17** — `circomlibjs/src/poseidon_constants.json`, the table
//! circom/snarkjs circuits are actually compiled against.
//!
//! ```sh
//! git clone --depth 1 https://github.com/iden3/circomlibjs.git
//! # spot-check one value by hand:
//! jq -r '.C[1][0], .M[1][0][0]' circomlibjs/src/poseidon_constants.json
//! # the digests asserted below:
//! python3 - <<'PY'
//! import json, hashlib
//! d = json.load(open("circomlibjs/src/poseidon_constants.json"))
//! h = lambda v: hashlib.sha256(b"".join(int(x, 16).to_bytes(32, "big") for x in v)).hexdigest()
//! for t in range(2, 18):
//!     print(t, h(d["C"][t - 2]), h([x for row in d["M"][t - 2] for x in row]))
//! PY
//! ```
//!
//! **BLS12-381, t = 3 and t = 5** — the Poseidon authors' own reference
//! scripts, which carry their constants as literals.
//!
//! ```sh
//! git clone --depth 1 https://extgit.iaik.tugraz.at/krypto/hadeshash.git
//! python3 - <<'PY'
//! import re, hashlib
//! h = lambda v: hashlib.sha256(b"".join(int(x, 16).to_bytes(32, "big") for x in v)).hexdigest()
//! for t in (3, 5):
//!     s = open(f"hadeshash/code/poseidonperm_x5_255_{t}.sage").read()
//!     grab = lambda name: re.findall(r"'(0x[0-9a-fA-F]+)'",
//!                                    re.search(name + r" = \[(.*?)\]\n", s, re.S).group(1))
//!     print(t, h(grab("round_constants")), h(grab("MDS_matrix")))
//! PY
//! ```
//!
//! The digest is over the constants' **big-endian 32-byte encodings,
//! concatenated in order** — round constants in generation order, MDS
//! row-major. That is exactly what `digestOf` computes over the derived
//! tables.
//!
//! The two upstream sources agree where they overlap: BN254 `t = 3`'s `C` and
//! `M` in circomlibjs' JSON are byte-identical to the literals in
//! `hadeshash/code/poseidonperm_x5_254_3.sage`. That agreement matters — the
//! pin is not resting on one project's transcription.

const std = @import("std");
const grain = @import("grain.zig");
const bn = @import("bn254_poseidon.zig");
const bls = @import("bls12_381_poseidon.zig");

const Digests = struct { c: [64]u8, m: [64]u8 };

/// SHA-256 over the concatenated big-endian encodings of a derived instance's
/// round constants, and separately of its MDS matrix.
fn digestOf(P: anytype) Digests {
    var hc: std.crypto.hash.sha2.Sha256 = .init(.{});
    for (P.round_constants) |x| hc.update(&x.toBytes());
    var hm: std.crypto.hash.sha2.Sha256 = .init(.{});
    for (P.mds) |row| for (row) |x| hm.update(&x.toBytes());

    var cd: [32]u8 = undefined;
    var md: [32]u8 = undefined;
    hc.final(&cd);
    hm.final(&md);

    var out: Digests = undefined;
    _ = std.fmt.bufPrint(&out.c, "{x}", .{&cd}) catch unreachable;
    _ = std.fmt.bufPrint(&out.m, "{x}", .{&md}) catch unreachable;
    return out;
}

const Pin = struct { c: *const [64:0]u8, m: *const [64:0]u8 };

/// Indexed by `t - 2`.
const bn254_pins = [16]Pin{
    .{ .c = "55647472b416cc9fafb46d90700fa370a30e8b62df0b5faad63718fa47bb95ea", .m = "ee6760f2328521e6eb47b07a8f160cefd8494acb9764cd107342295ed9e71fde" },
    .{ .c = "870ea1d5f78fbd8d8359ee638d7f5428c9fd576d824e8785c0f7e394c13fdd83", .m = "6f7e4dc2fa882610d9b291d90f0b6eee6d3c5c88e9fba8951afe0a8cd16ceb43" },
    .{ .c = "6865752856529c24e01885ae09ed0f5f20d745b5689c3649b2c141b5736add95", .m = "7e036f27d64b04f7ed9250f5cc8453738a93e53ecae8b7bcddda579889c5325d" },
    .{ .c = "2282e35b2b85896a3c4eef32bb643912f972f0a2a649b73bcfa62a49b428fbf5", .m = "97a5a51b644929e8d1c86b51c253bf4e3cae6cfed83d4298349d9826be04bf7c" },
    .{ .c = "3639c24cffc8274cff47dc2cc303fac0a536cf9b83647fed8f042729b3c68fc6", .m = "fc2059ccc44d254d20f9fa246e678d1fafe3ab978e8f70c20922da4ffc9c9455" },
    .{ .c = "ffa02f18ab9d034c22cea203c07be93bb57e3638043abbadf19e000ef8b93743", .m = "4f28c4376291a427852d4717cfa726363f684dd981e62f0de0e56cb7aa3a448d" },
    .{ .c = "a55639745589cbe22cdda65b79aa35c9709bfa16b4bbe94ca0362c81db92ccd4", .m = "722351b99421ad15e3bd6f93661a0db10e1557eef486da29417c07a0d0e08dfd" },
    .{ .c = "08e4d91c4bf67701619eea429113113797cba5ae0e928da48e5034a29c59fab4", .m = "b56502ac2283e3600662071ba9fed5a21f5cd286c495efe0b71bb33bde7c190d" },
    .{ .c = "6ccd9e16aa91be270d6f2897230942bf40a80ccdef0957cc0d2a71acd225cba4", .m = "23078cc289154fad3197c8a2bf2b7670b743238307d8e905a2c18b72a7b9f71f" },
    .{ .c = "c1465bc4eaa75531ef7a3dada3a7e1ef1a9e456615c6ec69e4f32b5f1f96d783", .m = "881bb568de7e9213e99dec915e45bcb5362e09060aba7ecf83517e4208b56c42" },
    .{ .c = "b19c0ad210d886fda4a69447658868de8b46ce94a34199a6490a7fe02b4c96d0", .m = "1831ad11f8f26816c583ef430427c679616dfbe8c60e39e1d3b669d18ab191b3" },
    .{ .c = "2ea6e94c16cbd3f4e5c0cfa9fa1b57d984a7ae79e436598f00bd67f89227d495", .m = "1eafa3693c6be61a792dcfaae2e2658e80d990b951a505052485b5bbe22d2c77" },
    .{ .c = "ae3c82b977f37666a3adb3c3529f30b920ebc1ba0f7ed832444cc0732d2e12d4", .m = "7b44c7b22de1b8dbc068710bd91c1355f0226c1a86914c32d845540247b0aa85" },
    .{ .c = "7fe08fbe7b5dc7fbfe7b944664cf4809043acfb470e9b7367a4adb6a9d984b92", .m = "09295fb49cc4f015adc2f8a45f09031b6db71772c9323cdd437da15038e470ed" },
    .{ .c = "20915851057a86d07615e929780c78a30d824f172fc0d38ce3c80d10043a4ac4", .m = "118e937c90efe71254dcba1180d5710c3de635a19de2467e080001ee2656825a" },
    .{ .c = "5c67bdd5278847fd9f3d7ff2c237644529c62027a23166e23bcc600ce19b7757", .m = "a002afa63bd1cf067480088c37fb3946a94bd5740e2eedfe7186eef8f4b3f2d5" },
};

test "BN254 derived constants match circomlib's, all 16 widths" {
    inline for (2..18) |t| {
        const P = bn.Perm(t).init();
        const d = digestOf(P);
        const pin = bn254_pins[t - 2];
        std.testing.expectEqualStrings(pin.c, &d.c) catch |e| {
            std.debug.print("round-constant digest mismatch at t={d}\n", .{t});
            return e;
        };
        std.testing.expectEqualStrings(pin.m, &d.m) catch |e| {
            std.debug.print("MDS digest mismatch at t={d}\n", .{t});
            return e;
        };
    }
}

test "BLS12-381 derived constants match the authors' sage references" {
    const p3 = bls.Perm(3).init();
    const d3 = digestOf(p3);
    try std.testing.expectEqualStrings("30ee37058c0f84b0d8e3e8f28691822874a5757b9afee31a2feb305f7f88e2b0", &d3.c);
    try std.testing.expectEqualStrings("6b24c1e7470ba9d9cc9990dcc9d7a3067a2d3e033ccfd3d0eec307e5cb14cb4c", &d3.m);

    const p5 = bls.Perm(5).init();
    const d5 = digestOf(p5);
    try std.testing.expectEqualStrings("40840907e30de82e789c2272f49b72ff0ecd61e1ddf55055b31e36b53d0792f1", &d5.c);
    try std.testing.expectEqualStrings("44793a31413eb9fe972960edc91aed0c437210b0f224e3466a76e3e555d2900d", &d5.m);
}

// ── literal pins, so an auditor can eyeball rather than re-run a script ─────

fn expectFrHex(want_hex: *const [64:0]u8, got: anytype) !void {
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, want_hex);
    try std.testing.expectEqualSlices(u8, &want, &got.toBytes());
}

test "BN254 t=3 first/last round constants and full MDS, verbatim from upstream" {
    // `hadeshash/code/poseidonperm_x5_254_3.sage`, its `round_constants[…]`
    // and `MDS_matrix` literals. Byte-identical to
    // `jq -r '.C[1][0], .M[1][]'` on circomlibjs' `poseidon_constants.json` —
    // two independent transcriptions of the same generator output.
    const P = bn.Perm(3).init();
    try std.testing.expectEqual(@as(usize, (8 + 57) * 3), P.round_constants.len);

    try expectFrHex("0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e", P.round_constants[0]);
    try expectFrHex("00f1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e864", P.round_constants[1]);
    try expectFrHex("08dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5", P.round_constants[2]);
    try expectFrHex("1da55cc900f0d21f4a3e694391918a1b3c23b2ac773c6b3ef88e2e4228325161", P.round_constants[194]);

    try expectFrHex("109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b", P.mds[0][0]);
    try expectFrHex("16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0", P.mds[0][1]);
    try expectFrHex("2b90bba00fca0589f617e7dcbfe82e0df706ab640ceb247b791a93b74e36736d", P.mds[0][2]);
    try expectFrHex("2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771", P.mds[1][0]);
    try expectFrHex("2e2419f9ec02ec394c9871c832963dc1b89d743c8c7b964029b2311687b1fe23", P.mds[1][1]);
    try expectFrHex("101071f0032379b697315876690f053d148d4e109f5fb065c8aacc55a0f89bfa", P.mds[1][2]);
    try expectFrHex("143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7", P.mds[2][0]);
    try expectFrHex("176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911", P.mds[2][1]);
    try expectFrHex("19a3fc0a56702bf417ba7fee3802593fa644470307043f7773279cd71d25d5e0", P.mds[2][2]);
}

test "BLS12-381 t=3 first/last round constant and MDS[0][0], verbatim from upstream" {
    // `hadeshash/code/poseidonperm_x5_255_3.sage`.
    const P = bls.Perm(3).init();
    try expectFrHex("6c4ffa723eaf1a7bf74905cc7dae4ca9ff4a2c3bc81d42e09540d1f250910880", P.round_constants[0]);
    try expectFrHex("57b33094aeff828377897b56e1c432978d07c668ef25a36bc5e2e835aaeff725", P.round_constants[194]);
    try expectFrHex("3d955d6c02fe4d7cb500e12f2b55eff668a7b4386bd27413766713c93f2acfcd", P.mds[0][0]);
}

// ── the round-number tables themselves ─────────────────────────────────────

test "N_ROUNDS_P matches circomlib exactly, non-monotonicity included" {
    // Copied out of `circuits/poseidon.circom` and `src/poseidon_reference.js`
    // (identical in both). The dips at t=4, t=12 and t=15 are real — they come
    // from rounding R_P up to a multiple of t — and are exactly the kind of
    // thing a well-meaning "fix" would smooth away.
    const want = [16]u10{ 56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68 };
    try std.testing.expectEqualSlices(u10, &want, &bn.N_ROUNDS_P);
    try std.testing.expectEqual(@as(u10, 8), bn.N_ROUNDS_F);
    try std.testing.expectEqual(@as(u10, 8), bls.N_ROUNDS_F);
}

test "every R_P is divisible by its t — the fingerprint of circomlib's rounding" {
    // circomlib's stated deviation from the paper is "rounded up to nearest
    // integer that divides by t" (see SPEC.md §Divergences 2). That is a
    // checkable claim about the whole table, and it is what makes the dips
    // non-typos: 56 for t=4 is 56, but 57 for t=3 had to go up from 56.
    for (bn.N_ROUNDS_P, 2..) |r_p, t| {
        try std.testing.expectEqual(@as(u10, 0), r_p % @as(u10, @intCast(t)));
    }
    // Both BLS12-381 widths obey it too: 57 % 3 == 0, 60 % 5 == 0.
    try std.testing.expectEqual(@as(u12, 0), bls.Perm(3).r_p % 3);
    try std.testing.expectEqual(@as(u12, 0), bls.Perm(5).r_p % 5);
}

test "every shipped parameter set accepts its FIRST MDS candidate" {
    // The claim `SPEC.md` used to make in prose, now an assertion. Upstream's
    // `generate_matrix` redraws when `algorithm_1`/`2`/`3` reject a candidate,
    // and a redraw consumes another `2t` Grain values — so if any of these
    // were `> 1`, the constants below could not have matched circomlib's.
    //
    // Both directions matter. This test says the security checks change
    // nothing here (so the pins above are unaffected by adding them), and
    // `rejection_test.zig` says the loop is not dead code.
    inline for (2..18) |t| {
        const tab = try grain.derive(bn.Perm(t).config);
        try std.testing.expectEqual(@as(usize, 1), tab.mds_candidates);
    }
    try std.testing.expectEqual(@as(usize, 1), (try grain.derive(bls.Perm(3).config)).mds_candidates);
    try std.testing.expectEqual(@as(usize, 1), (try grain.derive(bls.Perm(5).config)).mds_candidates);
}

test "round-constant count is (R_F + R_P) * t for every width" {
    inline for (2..18) |t| {
        const P = bn.Perm(t).init();
        try std.testing.expectEqual((@as(usize, 8) + bn.N_ROUNDS_P[t - 2]) * t, P.round_constants.len);
    }
}

// ── structural checks on the derived matrix ────────────────────────────────

test "MDS is invertible (necessary for the permutation to be a permutation)" {
    // Gaussian elimination over Fr on the t=3 matrix. A Cauchy matrix is MDS
    // by construction, so this cannot fail for a correct derivation — it is
    // here as a cheap structural check that the batch inversion in
    // `grain.derive` did not scramble the entries: a transposed or shifted
    // write would still produce t*t perfectly plausible field elements.
    const P = bn.Perm(3).init();
    const Fr = bn.Fr;
    var a: [3][3]Fr = P.mds;
    var det = Fr.one;
    for (0..3) |col| {
        var piv: ?usize = null;
        for (col..3) |row| {
            if (!a[row][col].isZero()) {
                piv = row;
                break;
            }
        }
        const p = piv orelse return error.SingularMds;
        if (p != col) {
            const tmp = a[p];
            a[p] = a[col];
            a[col] = tmp;
            det = det.neg();
        }
        det = det.mul(a[col][col]);
        const inv = try a[col][col].inv();
        for (col + 1..3) |row| {
            const f = a[row][col].mul(inv);
            for (col..3) |k| a[row][k] = a[row][k].sub(f.mul(a[col][k]));
        }
    }
    try std.testing.expect(!det.isZero());
}

test "derive is deterministic" {
    // Two independent `init()` calls must produce byte-identical tables.
    // Cheap, but it is the property that lets a caller build one instance at
    // startup and share it, and it would catch an uninitialised-memory bug in
    // the `undefined` scratch arrays inside `derive`.
    const a = bn.Perm(4).init();
    const b = bn.Perm(4).init();
    for (a.round_constants, b.round_constants) |x, y| {
        try std.testing.expectEqualSlices(u8, &x.toBytes(), &y.toBytes());
    }
    for (a.mds, b.mds) |ra, rb| {
        for (ra, rb) |x, y| try std.testing.expectEqualSlices(u8, &x.toBytes(), &y.toBytes());
    }
}

// ── the generator's own shape ──────────────────────────────────────────────

test "grain: every round constant is canonical" {
    // Round constants must all be < p. The reduction path would satisfy that
    // too, so this is not the discriminator (the digests are) — it documents
    // the invariant `derive` relies on: it calls `Fr.fromBytes`, which
    // *rejects* non-canonical input, so a reduction-only implementation would
    // not merely produce different numbers, it would hit `unreachable`.
    const P = bn.Perm(3).init();
    const r = std.mem.readInt(u256, &@import("bn254").scalar.r_bytes, .big);
    for (P.round_constants) |c| {
        const be = c.toBytes();
        try std.testing.expect(std.mem.readInt(u256, &be, .big) < r);
    }
}

test "grain: the LFSR stream depends on every seed field" {
    // n, t, R_F and R_P all feed the 80-bit seed; changing any one must change
    // the stream, or two different parameter sets could silently share
    // constants.
    const base = firstWord(254, 3, 8, 57);
    try std.testing.expect(base != firstWord(255, 3, 8, 57)); // n
    try std.testing.expect(base != firstWord(254, 4, 8, 57)); // t
    try std.testing.expect(base != firstWord(254, 3, 6, 57)); // R_F
    try std.testing.expect(base != firstWord(254, 3, 8, 56)); // R_P
}

fn firstWord(n: u12, t: u12, r_f: u10, r_p: u10) u256 {
    var l: grain.Lfsr = .init(n, t, r_f, r_p);
    return l.nextNum(254);
}
