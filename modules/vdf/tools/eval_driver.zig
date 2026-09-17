// SPDX-License-Identifier: MIT

//! Half of an external value oracle for `eval` (finding O1, A1 audit,
//! disposition 2026-09-17): prints `y = 5^(2^k) mod N` — N the RSA-2048
//! Factoring Challenge modulus this module ships (`group.rsa2048ChallengeModulus`),
//! x = 5 — through the module's PUBLIC API only, so `openssl_oracle.py`'s
//! independent computation of the same value (OpenSSL's `BN_mod_exp`, no
//! shared code) can be diffed against it byte for byte at a `k` far beyond
//! the shipped KATs (largest in `kat_test.zig` is `T = 10_000`).
//!
//! WHAT IT NEEDS: the live module, nothing else (pure Zig, no toolchain).
//!
//! Build and run it (from the repository root; `vdf` needs `montint` behind
//! it, same three-module wiring as `modules/paillier/tools/probe_vectors.zig`):
//!
//!     scripts/capped zig build-exe --cache-dir .zig-cache/o1-vdf \
//!       -femit-bin=.zig-cache/o1-vdf/eval_driver \
//!       --dep vdf --dep montint \
//!       -Mroot=modules/vdf/tools/eval_driver.zig \
//!       --dep montint -Mvdf=modules/vdf/src/root.zig \
//!       -Mmontint=modules/montint/src/root.zig
//!     .zig-cache/o1-vdf/eval_driver 200000
//!
//! WHAT IT PRODUCES: one line, `y <512 lowercase hex chars>` — the
//! module's canonical (quotient-folded, `group.canonicalize`) representative
//! of `5^(2^k)` in Z_N*/{±1}, zero-padded to `modulus_bytes`.
//!
//! ⚠ OpenSSL's raw `BN_mod_exp` does NOT fold into the quotient the way this
//! module's `eval` does (`group.zig`'s module doc comment: Z_N*/{±1}, not
//! Z_N* itself) — `openssl_oracle.py` applies the same `min(v, N-v)` fold in
//! Python before printing, so the two hex lines are directly comparable.
const std = @import("std");
const vdf = @import("vdf");

pub fn main(init: std.process.Init.Minimal) !void {
    var args = init.args.iterate();
    _ = args.next();
    const k: u64 = if (args.next()) |s| (std.fmt.parseInt(u64, s, 10) catch 200000) else 200000;

    const m = vdf.group.rsa2048ChallengeModulus();
    var xb: [vdf.group.modulus_bytes]u8 = [_]u8{0} ** vdf.group.modulus_bytes;
    xb[vdf.group.modulus_bytes - 1] = 5;
    const x = try vdf.group.elementFromBytes(m, &xb);

    const y = vdf.eval(m, x, k);

    var yb: [vdf.group.modulus_bytes]u8 = undefined;
    try vdf.group.toBytes(y, &yb);
    std.debug.print("y {x}\n", .{yb[0..]});
}
