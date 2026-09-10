// SPDX-License-Identifier: MIT
//! ctgrind harness for `paillier` — the instrument for `SPEC.md`'s
//! "Constant-time discipline" section, and the one item in it that is
//! DELIBERATELY NOT constant-time:
//!
//!   "`decrypt`'s `c^λ mod n²` and `mulPlaintext`'s `c^k mod n²` are routed
//!    through `montint` (constant-time Montgomery ladder) — `λ` is
//!    secret-key material, `k` may be a secret scalar." (paillier F5,
//!    wave-3 audit: `mulPlaintext` used to go through `std.crypto.ff`'s
//!    `Modulus.pow` instead — same constant-time posture, ~5× slower)
//!   "**Known caveat:** `decrypt`'s L-function drops to `std.math.big.int`
//!    for the exact `(x−1)/n` division (`ff` has no exact-division
//!    primitive), and that division is variable-time in `x` — a
//!    per-decryption, plaintext-derived value. […] It is accepted rather
//!    than made constant-time because […]"
//!   "This also makes `m = 0` fall out for free (1 + 0·n = 1) with no
//!    data-dependent branch, and means a possibly-secret plaintext `m`
//!    never enters a bit-scanned exponent path at all on the standard-`g`
//!    path." (SPEC.md, "The `g = n+1` binomial shortcut")
//!
//! Until this harness none of those three sentences had a measurement
//! behind it. Run it through `../../../scripts/ctgrind.sh paillier` once the
//! coordinator has wired the per-module TARGETS/MODES/PATTERN/LABEL block
//! (this file intentionally does NOT touch `scripts/ctgrind.sh` — see the
//! "Suggested config" section at the bottom of this comment); until then,
//! drive it directly:
//!
//!   zig build ctgrind -Dctgrind-module=paillier -Dctgrind-valgrind=true
//!   zig build ctgrind -Dctgrind-module=paillier -Dctgrind-valgrind=false
//!   valgrind --tool=memcheck --error-exitcode=99 --num-callers=20 \
//!       zig-out/ctgrind/ctgrind-paillier <target> <taint>
//!
//! `<target>` is one of `crt`/`noncrt`/`mul`/`addm` (see `Target` below),
//! `<taint>` is `yes`/`no`.
//!
//! ## What is tainted, and what is deliberately NOT
//!
//! A single 2048-bit key is derived ONCE via `fromPrimes`, entirely
//! untainted (key derivation is a one-time, explicitly variable-time cost
//! by the module's own SPEC — same posture as `rsa`'s harness building its
//! `SecretKey` via `fromPrimes` before any taint). A fixed ciphertext is
//! likewise built with the PUBLIC key before any taint exists — the
//! attacker-chosen public input, never part of the claim.
//!
//! Then, per target:
//!
//!   - `crt`    — decrypt's CRT path (`SecretKey.crt != null`, the path
//!                every `fromPrimes`/`generate`-derived key actually takes).
//!                Taints `lambda`, `mu`, and the ENTIRE `crt` block
//!                (`p_sq`/`q_sq`/`p_sq_mont`/`q_sq_mont`/`dp`/`dq`/
//!                `p_sq_fe`/`p_sq_inv`) — per `SecretKey.deinit`'s own doc
//!                comment, `p_sq`/`q_sq` are factorization-equivalent to
//!                `p`/`q` (a square root away), so leaving them untainted
//!                would let the ladder consume the secret factors through a
//!                channel the taint never reached. `n`/`n_sq`/`n_sq_mont`
//!                stay untainted (public, shared with `PublicKey`).
//!   - `noncrt` — decrypt's single-modulus fallback (`SecretKey.crt ==
//!                null`, the path a key loaded via `SecretKey.fromBytes`
//!                takes — no factors available). A second `SecretKey` is
//!                built via `fromBytes` from the first key's own
//!                `n`/`lambda`/`mu` bytes (untainted), then `lambda`/`mu`
//!                are tainted; `n`/`n_sq`/`n_sq_mont` stay public.
//!   - `mul`    — `mulPlaintext`'s scalar `k` (the exponent `montint`'s
//!                `montModexpSecret` consumes since paillier F5, wave-3
//!                audit — previously `pk.n_sq.pow`; the value `k.isZero()`
//!                branches on directly in `root.zig` before ever reaching
//!                the modexp, unchanged by F5) is tainted; the ciphertext
//!                operand is the fixed untainted public one.
//!   - `addm`   — `addPlaintext`'s plaintext `m` is tainted; same fixed
//!                ciphertext operand. Exercises `gPow`'s binomial-shortcut
//!                path for the standard generator `g = n+1` — SPEC.md's
//!                claim above is that this path never branches on `m` at
//!                all, which is exactly what this row is evidence for or
//!                against.
//!
//! Neither the public key, nor either ciphertext, nor `n`/`n_sq`/
//! `n_sq_mont` is ever tainted in any target.
//!
//! ## The two traps (see `ct25519`'s or `rsa`'s harness for the same shape)
//!
//! 1. `std.valgrind.doClientRequest` compiles to nothing without
//!    `-fvalgrind` (off by default outside Debug) — the driver script (once
//!    wired) builds both ways so this shows up as its own trap row, not a
//!    silent false clean.
//! 2. The optimizer could in principle keep a defined copy of a tainted
//!    field from before `makeMemUndefined` ran (every taint target here
//!    builds the whole value untainted first, then taints specific fields
//!    in place). `reloadVolatile` forces one real byte-by-byte load of the
//!    WHOLE value through a volatile pointer immediately before the call
//!    under test, so the private op cannot be fed a pre-taint copy.
//!
//! ## The propagation proof
//!
//! After the call, the result is formatted through `std.debug.print`,
//! which is NOT constant-time by design (digit/hex formatting branches on
//! the value). Its contexts are reported separately (the WITNESS bucket,
//! per `scripts/ctgrind.sh`'s classifier) from the target's own contexts,
//! so a zero count inside `root.zig` (or, for `crt`/`noncrt`, inside std's
//! `math/big/int.zig`) means "no branch found", not "taint never arrived".
//!
//! ## Suggested config for `scripts/ctgrind.sh` (coordinator wires this)
//!
//!   TARGETS[paillier]="crt noncrt mul addm"
//!   MODES[paillier]="ReleaseFast"
//!   PATTERN[paillier/crt]='root[.]zig|int[.]zig|math[.]zig|mem[.]zig|memcpy[.]zig|memmove[.]zig|compiler_rt[.]zig'
//!   PATTERN[paillier/noncrt]='root[.]zig|int[.]zig|math[.]zig|mem[.]zig|memcpy[.]zig|memmove[.]zig|compiler_rt[.]zig'
//!   PATTERN[paillier/mul]='root[.]zig'
//!   PATTERN[paillier/addm]='root[.]zig'
//!   LABEL[paillier/crt]="paillier decrypt CRT (lambda/mu/p_sq/q_sq)"
//!   LABEL[paillier/noncrt]="paillier decrypt non-CRT (lambda/mu)"
//!   LABEL[paillier/mul]="paillier mulPlaintext (k)"
//!   LABEL[paillier/addm]="paillier addPlaintext (m)"
//!
//! `int[.]zig|math[.]zig|mem[.]zig|memcpy[.]zig|memmove[.]zig|compiler_rt[.]zig`
//! mirrors exactly what `threshold_ecdsa`'s own PATTERN already lists for
//! its `root[.]zig` (paillier) frames — see `scripts/ctgrind.sh`'s
//! `PATTERN[threshold_ecdsa/share]` — because that is where this harness's
//! own `crt`/`noncrt` measurement (below) attributes the L-function's
//! `divFloor` frames. Re-check against a fresh `--stacks` run before
//! trusting it blindly; `root[.]zig` alone is NOT enough (see this
//! module's own report: it undercounted).

const std = @import("std");
const builtin = @import("builtin");
const paillier = @import("root.zig");
const Fe = paillier.Fe;

/// Duplicated from `root.zig`'s private `hexLit`-equivalent parsing need —
/// same shape as `rsa`'s harness. `@setEvalBranchQuota` sized for two
/// 1024-bit (256 hex-char) primes.
fn hexLit(comptime hex: []const u8) [hex.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(200_000);
        var out: [hex.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
        return out;
    }
}

// Two 1024-bit primes for a ~2048-bit `n`, sized to match the module's
// `modulus_bits = 2048` design point (a toy key would land on montint's
// smallest limb slot regardless of the branch structure, but a realistic
// width is what a real caller's decrypt actually runs, and matches this
// module's own SPEC.md framing of `rsa`-equivalent key strength). NOT a
// KAT: generated once via `openssl genrsa 2048` and `openssl rsa -text`
// purely as a convenient source of two large probable primes (Paillier
// only needs two large primes — nothing RSA-specific about `p`/`q`
// themselves) and hardcoded here so repeated runs of the table are
// comparable. Never used as an RSA key anywhere; not secret in any
// meaningful sense (freshly generated for this harness, not reused from
// any real key), but tainted below anyway, as a real secret key would be.
const harness_p = hexLit("ffa6785823fbfe8213aa06dd0600cf63d768f4eb7875785ffbd7d0c52b975ff897c5c8676aa426ed672423a4e087917a1299451e0a8cf7e6fb36333ed2f82fc8ca211c366bec715a49cdb072cadab8e0bec33d3e933407df696adf5a6b6bc951b3490c7da26ab5d18b58df9c2e746bcb904be74a579487e0f5ba4016038ed7e9");
const harness_q = hexLit("d7bcc906669556262185d0bfb6b82b8b0e7dc20015b749ac16d7de5034d194656a893d3dbfa510304c34db89670072b0c06d46b32e9f1a1fad532b92a31762e783b06f345e6b404ee17c353f225bb1ffd30b62889d7045639c6a821dc2ee8993b4607774e940a038f9f4c50c45da786bff53aa8e7d664e46daed6f4b17ffa30b");

/// Force one real byte-by-byte load of `s` through a volatile pointer, so
/// the private op cannot be fed a copy of `T` that predates
/// `makeMemUndefined` — see trap 2 in the module doc comment above.
fn reloadVolatile(comptime T: type, s: *const T) T {
    var out: T = undefined;
    const src = std.mem.asBytes(s);
    const dst = std.mem.asBytes(&out);
    for (dst, src) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Target = enum { crt, noncrt, mul, addm };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "crt")) return .crt;
    if (std.mem.eql(u8, s, "noncrt")) return .noncrt;
    if (std.mem.eql(u8, s, "mul")) return .mul;
    if (std.mem.eql(u8, s, "addm")) return .addm;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn taintBytes(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

/// Print an `Fe` (plaintext / decrypt result) as hex bytes — the
/// propagation witness. Buffer sized to the widest possible canonical
/// value (`modulus_sq_bytes`); `Fe.toBytes` only needs `>=` the value's
/// own width.
fn printFe(label: []const u8, fe: Fe) void {
    var buf: [paillier.modulus_sq_bytes]u8 = undefined;
    fe.toBytes(&buf, .big) catch unreachable;
    std.debug.print("{s}={x}\n", .{ label, buf });
}

fn printCiphertext(label: []const u8, c: paillier.Ciphertext) void {
    var buf: [paillier.modulus_sq_bytes]u8 = undefined;
    c.toBytes(&buf) catch unreachable;
    std.debug.print("{s}={x}\n", .{ label, buf });
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = try parseTarget(target_arg);
    const taint = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={} target={s}\n", .{ builtin.valgrind_support, target_arg });

    // One-time key derivation (variable-time by SPEC's own admission,
    // exactly like `rsa.SecretKey.fromPrimes`) runs entirely on the
    // UNTAINTED fixed primes above — the one-time key-import/derivation
    // cost the module's doc comment excludes from the constant-time claim,
    // not the per-operation path this harness measures.
    const kp = try paillier.fromPrimes(&harness_p, &harness_q);
    const pk = kp.public;

    // A fixed, public "attacker-chosen" ciphertext for the decrypt targets,
    // and a fixed public ciphertext operand for the homomorphic-op targets
    // — both built with the PUBLIC key, before any taint exists.
    const m0 = try Fe.fromPrimitive(u64, pk.n_sq, 0x1234_5678_9abc_def0);
    const r0 = try Fe.fromPrimitive(u64, pk.n_sq, 0x0fed_cba9_8765_4321);
    const c0 = try paillier.encrypt(pk, m0, r0);

    switch (target) {
        .crt => {
            // The default path every `fromPrimes`/`generate` key takes.
            var sk = kp.secret;
            std.debug.assert(sk.crt != null);
            taintBytes(taint, std.mem.asBytes(&sk.lambda));
            taintBytes(taint, std.mem.asBytes(&sk.mu));
            // Entire CRT block: p_sq/q_sq are factorization-equivalent to
            // p/q (SecretKey.deinit's own doc comment), so every field
            // derived from them is secret material too.
            taintBytes(taint, std.mem.asBytes(&sk.crt.?));
            const sk_reloaded = reloadVolatile(paillier.SecretKey, &sk);

            const m = try paillier.decrypt(sk_reloaded, c0);
            printFe("m", m);
        },
        .noncrt => {
            // Single-modulus fallback: a key loaded via `fromBytes` carries
            // no factors, so `sk.crt == null` and `decrypt` cannot take the
            // CRT branch at all. Re-derive such a key from the first key's
            // own (untainted) n/lambda/mu bytes.
            var n_buf: [paillier.modulus_bytes]u8 = undefined;
            const n_len = kp.secret.nByteLen();
            try kp.secret.nToBytes(n_buf[0..n_len]);
            var lambda_buf: [paillier.modulus_sq_bytes]u8 = undefined;
            try kp.secret.lambdaToBytes(&lambda_buf);
            var mu_buf: [paillier.modulus_bytes]u8 = undefined;
            try kp.secret.muToBytes(mu_buf[0..n_len]);

            var sk = try paillier.SecretKey.fromBytes(n_buf[0..n_len], &lambda_buf, mu_buf[0..n_len]);
            std.debug.assert(sk.crt == null);
            taintBytes(taint, std.mem.asBytes(&sk.lambda));
            taintBytes(taint, std.mem.asBytes(&sk.mu));
            const sk_reloaded = reloadVolatile(paillier.SecretKey, &sk);

            const m = try paillier.decrypt(sk_reloaded, c0);
            printFe("m", m);
        },
        .mul => {
            // `mulPlaintext`'s scalar `k` — a secret exponent in a future
            // MtA context (module doc comment on `mulPlaintext`). The
            // ciphertext operand `c0` is the fixed public one, untainted.
            var k = try Fe.fromPrimitive(u64, pk.n_sq, 0x9e37_79b9_7f4a_7c15);
            taintBytes(taint, std.mem.asBytes(&k));
            const k_reloaded = reloadVolatile(Fe, &k);

            const c = try paillier.mulPlaintext(pk, c0, k_reloaded);
            printCiphertext("c", c);
        },
        .addm => {
            // `addPlaintext`'s plaintext `m` — exercises `gPow`'s
            // binomial-shortcut path for the standard generator, which
            // SPEC.md claims never branches on `m` at all.
            var m = try Fe.fromPrimitive(u64, pk.n_sq, 0x4242_4242_4242_4242);
            taintBytes(taint, std.mem.asBytes(&m));
            const m_reloaded = reloadVolatile(Fe, &m);

            const c = try paillier.addPlaintext(pk, c0, m_reloaded);
            printCiphertext("c", c);
        },
    }
}
