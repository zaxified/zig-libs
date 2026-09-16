// SPDX-License-Identifier: MIT

//! Emit machine-readable vectors for an EXTERNAL differential oracle.
//!
//! Prints, as hex, the key material and then one line per trial:
//!
//!   V <m> <r> <c> <dec>       encrypt/decrypt round trip
//!   A <c1> <c2> <cadd> <dec>  addCiphertexts
//!   P <c1> <m2> <cadd> <dec>  addPlaintext
//!   M <c1> <k>  <cmul> <dec>  mulPlaintext
//!
//! and finally `END`, which `oracle_paillier.py` requires: without it a probe
//! that died halfway produces a short stream the oracle would happily compare
//! and call clean.
//!
//! Build and run it (from the repository root):
//!
//!     scripts/capped zig build-exe --cache-dir .zig-cache \
//!       -femit-bin=.zig-cache/paillier-oracle/probe_vectors \
//!       --dep paillier --dep montint \
//!       -Mroot=modules/paillier/tools/probe_vectors.zig \
//!       --dep montint -Mpaillier=modules/paillier/src/root.zig \
//!       -Mmontint=modules/montint/src/root.zig
//!     .zig-cache/paillier-oracle/probe_vectors 512 200 2>&1 \
//!       | modules/paillier/tools/oracle_paillier.py
//!
//! ⚠ `2>&1` is NOT decoration. Every line is written with
//! `std.debug.print`, which goes to STDERR, so a plain `>` or `|`
//! captures nothing and the oracle sees an empty stream. Dropping it
//! produced exactly that on 2026-09-16: probe exit 0, zero lines.
//!
//! ⚠ `--dep testkit` is NOT needed here and that is not an oversight: the
//! module's `@import("testkit")` sits in test-only code, so a `build-exe`
//! never reaches it (measured 2026-09-16: exit 0 without it). A `zig test` of
//! the same module DOES need it -- see tools/mutate.py.
//!
//! ⚠ It drives the module through its PUBLIC API only; the Python side
//! recomputes every line from n/g/lambda/mu with `pow(x, y, m)` alone, from
//! the Paillier 1999 formulas rather than from this module. That is the whole
//! point -- two implementations that share no code.
const std = @import("std");
const paillier = @import("paillier");

var out_buf: [1 << 16]u8 = undefined;

fn hex(fe: paillier.Fe) []const u8 {
    var b: [paillier.modulus_sq_bytes]u8 = undefined;
    fe.toBytes(&b, .big) catch unreachable;
    var i: usize = 0;
    while (i + 1 < b.len and b[i] == 0) i += 1;
    const src = b[i..];
    const s = std.fmt.bufPrint(&out_buf, "{x}", .{src}) catch unreachable;
    // bufPrint reuses one buffer, so callers must consume before the next call
    return s;
}

fn p(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt, args);
}

fn printFe(label: []const u8, fe: paillier.Fe) void {
    var b: [paillier.modulus_sq_bytes]u8 = undefined;
    fe.toBytes(&b, .big) catch unreachable;
    var i: usize = 0;
    while (i + 1 < b.len and b[i] == 0) i += 1;
    p("{s} {x}\n", .{ label, b[i..] });
}

fn feHexInline(fe: paillier.Fe) void {
    var b: [paillier.modulus_sq_bytes]u8 = undefined;
    fe.toBytes(&b, .big) catch unreachable;
    var i: usize = 0;
    while (i + 1 < b.len and b[i] == 0) i += 1;
    p(" {x}", .{b[i..]});
}

pub fn main(init: std.process.Init.Minimal) !void {
    var args = init.args.iterate();
    _ = args.next();
    const bits: usize = if (args.next()) |s| (std.fmt.parseInt(usize, s, 10) catch 512) else 512;
    const trials: usize = if (args.next()) |s| (std.fmt.parseInt(usize, s, 10) catch 200) else 200;

    var prng = std.Random.DefaultPrng.init(0x0AC1E5);
    const random = prng.random();
    const kp = try paillier.generate(random, bits);
    const pk = kp.public;
    const sk = kp.secret;

    var nb: [paillier.modulus_bytes]u8 = undefined;
    const n_len = (pk.n.bits() + 7) / 8;
    try pk.nToBytes(nb[0..n_len]);
    p("N {x}\n", .{nb[0..n_len]});
    printFe("G", pk.g);
    printFe("LAMBDA", sk.lambda);
    printFe("MU", sk.mu);

    var mb: [paillier.modulus_bytes]u8 = undefined;
    var rb: [paillier.modulus_bytes]u8 = undefined;
    for (0..trials) |t| {
        random.bytes(mb[0..n_len]);
        mb[0] = 0;
        random.bytes(rb[0..n_len]);
        rb[0] = 0;
        if (std.mem.allEqual(u8, rb[0..n_len], 0)) rb[n_len - 1] = 3;
        const m = try paillier.Fe.fromBytes(pk.n_sq, mb[0..n_len], .big);
        const r = try paillier.Fe.fromBytes(pk.n_sq, rb[0..n_len], .big);
        const c = try paillier.encrypt(pk, m, r);
        const dec = paillier.decrypt(sk, c) catch {
            p("SKIP encrypt-produced-nonunit trial={d}\n", .{t});
            continue;
        };
        p("V", .{});
        feHexInline(m);
        feHexInline(r);
        feHexInline(c.c);
        feHexInline(dec);
        p("\n", .{});

        if (t % 4 == 0) {
            // second ciphertext for the homomorphic rows
            random.bytes(mb[0..n_len]);
            mb[0] = 0;
            random.bytes(rb[0..n_len]);
            rb[0] = 0;
            if (std.mem.allEqual(u8, rb[0..n_len], 0)) rb[n_len - 1] = 5;
            const m2 = try paillier.Fe.fromBytes(pk.n_sq, mb[0..n_len], .big);
            const r2 = try paillier.Fe.fromBytes(pk.n_sq, rb[0..n_len], .big);
            const c2 = try paillier.encrypt(pk, m2, r2);

            const cadd = paillier.addCiphertexts(pk, c, c2);
            if (paillier.decrypt(sk, cadd)) |d| {
                p("A", .{});
                feHexInline(c.c);
                feHexInline(c2.c);
                feHexInline(cadd.c);
                feHexInline(d);
                p("\n", .{});
            } else |_| {}

            const cpt = try paillier.addPlaintext(pk, c, m2);
            if (paillier.decrypt(sk, cpt)) |d| {
                p("P", .{});
                feHexInline(c.c);
                feHexInline(m2);
                feHexInline(cpt.c);
                feHexInline(d);
                p("\n", .{});
            } else |_| {}

            const cmul = try paillier.mulPlaintext(pk, c, m2);
            if (paillier.decrypt(sk, cmul)) |d| {
                p("M", .{});
                feHexInline(c.c);
                feHexInline(m2);
                feHexInline(cmul.c);
                feHexInline(d);
                p("\n", .{});
            } else |_| {}
        }
    }
    p("END\n", .{});
}
