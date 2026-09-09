// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Threat
//! model / limits" bullet ("`preSign`/`adapt` DO handle secret data ...
//! and must use the same constant-time masked-select discipline ... never
//! branch on the parity bit itself"), as an actual committed program. Run
//! it through `zig build ctgrind -Dctgrind-module=adaptor
//! -Dctgrind-valgrind=<true|false> -Doptimize=ReleaseFast` plus `valgrind
//! --tool=memcheck --error-exitcode=99 --num-callers=20` by hand —
//! `scripts/ctgrind.sh` has no per-module TARGETS/MODES/PATTERN/LABEL entry
//! for `adaptor` yet; the suggested lines are at the bottom of this comment
//! for the coordinator to paste in.
//!
//! NOT wired into `zig build test-adaptor` — memcheck's context count is
//! valgrind's own verdict, not something a Zig test can assert on. `zig
//! build check-ctgrind` compiles it so it cannot rot into an unbuildable
//! recipe.
//!
//! ## The two secrets this module has, and why they get THREE targets
//!
//! An adaptor signature has two genuinely different secrets flowing through
//! it, and conflating them into one target would blur exactly the
//! distinction `SPEC.md`'s threat model draws:
//!
//! * **`presign`** — the SIGNER's private key `sk` entering `preSign`. That
//!   one taint reaches, end to end, the effective (possibly-negated)
//!   signing scalar `d`, the deterministic nonce material
//!   (`t_pad`/`rand`/`k0`), `R = k0·G`, `R_hat = R + T`, the
//!   `needs_negation` masked select (`root.zig:334-339`, this module's OWN
//!   from-scratch constant-time discipline — `bip340.sign`'s step 7 does
//!   the analogous thing but this is a different masked select over a
//!   different pair of candidates), and `s_prime = k + e·d`.
//! * **`adapt`** — the ADAPTOR SECRET `t` entering `adapt`. Tainted
//!   directly at `adapt`'s own `adaptor_secret` parameter (not derived from
//!   `presign`'s taint — a fresh, independent taint site, because `adapt`
//!   is a function a DIFFERENT party calls, one who never touches `sk`).
//! * **`extract`** — the adaptor secret `t` **coming back out** of
//!   `extract`. `extract` does not receive `t` as a parameter at all; it
//!   receives a completed signature whose `s = s_prime + t_used` field is
//!   where `t` is actually encoded, so THIS target taints `full_sig.s`
//!   directly (constructed from a real, honestly-adapted signature — see
//!   "The fixture" below) rather than chaining a taint through a live
//!   `adapt` call. That keeps `extract`'s own contexts from being
//!   convolved with `adapt`'s.
//!
//! `preSign`/`preVerify`'s OTHER inputs (`msg`, `aux_rand`, the adaptor
//! POINT `T`, the public key) are never tainted — see `SPEC.md`'s own
//! "Constant-time" bullet ("`preVerify` handles only PUBLIC data") and its
//! aux-rand paragraph (same rationale as `bip340`'s: defense-in-depth, not
//! secrecy). `preVerify` itself has no target here for the identical reason
//! `bip340`'s harness excludes `verify`/`verifyBatch`.
//!
//! ## The fixture (`adapt`/`extract` targets only)
//!
//! Both targets need a PLAUSIBLE, self-consistent `PreSignature`/signature
//! pair to operate on. `buildFixture` produces one by running `preSign` and
//! `adapt` on fixed, ALWAYS-DEFINED material (a different domain-separated
//! secret key/adaptor-secret than any tainted one below) — this executes
//! with zero undefined bytes regardless of the harness's own `--taint`
//! switch, so it contributes nothing to either target's contexts; only the
//! byte buffer each target explicitly re-taints afterward (a copy of
//! `t_bytes` for `adapt`, a copy of `full_sig.s` for `extract`) is ever
//! marked undefined.
//!
//! ## The two traps (see `ct25519`'s harness for the fuller writeup)
//!
//! 1. `std.valgrind.doClientRequest` opens with
//!    `if (!builtin.valgrind_support) return default;`, off by default
//!    outside Debug. Built WITHOUT `-fvalgrind`, every client request
//!    compiles to nothing and `--taint=yes` silently behaves like
//!    `--taint=no` — measured as its own row below, not assumed.
//! 2. An optimizer is in principle free to keep a defined copy of a secret
//!    in a register rather than reading back the memory `makeMemUndefined`
//!    marked. `reloadVolatile` forces one real load from freshly-tainted
//!    memory immediately before the call under test. Defensive, not
//!    demonstrated on this host/compiler.
//! 3. ReleaseFast only — `Debug`/`ReleaseSafe` add overflow checks in the
//!    field/scalar arithmetic underneath (`k256`'s `field.zig`, std's
//!    `crypto/pcurves/common.zig`) that branch on tainted values and bury
//!    the signal, same reason every module here except `chachapoly` states
//!    its claim at ReleaseFast.
//!
//! ## own vs delegate, and the `root[.]zig` trap
//!
//! `adaptor` depends on `bip340` and `k256`, both of which ALSO have a
//! `root.zig` — the same basename collision `blindrsa`'s and `rsa`'s
//! harnesses already ran into (`scripts/ctgrind.sh`'s `PATTERN` comment for
//! `blindrsa/blind`). A pattern containing `root[.]zig` therefore buckets
//! `adaptor/root.zig` AND `bip340/root.zig` together as "in-file" — stated
//! here rather than papered over. The per-line breakdown in the report this
//! harness backs marks each context adaptor-own, bip340-inherited, or
//! k256/std-inherited by its QUALIFIED symbol name, not by which pattern
//! bucket it fell into.
//!
//! * `presign` calls into `bip340.KeyPair.fromSecretKey` (which itself
//!   calls `k256.Secp256k1.combMulBase`) and does its OWN
//!   `Secp256k1.combMulBase`/`.add`/`.rejectIdentity`/`.affineCoordinates`
//!   for `R`/`R_hat`, so the same `group.zig`/`field.zig`/`fast_core.zig`
//!   files `k256`'s own `comb` target and `bip340`'s `sign` target already
//!   measure are exercised here too, for the identical reason
//!   `bip340/sign`'s own PATTERN names them.
//! * `adapt` touches NO point arithmetic at all — every operation is a
//!   `Secp256k1.scalar.Scalar` method (`fromBytes`/`isZero`/`neg`/`add`),
//!   which is std's generic `Field()` type from
//!   `crypto/pcurves/common.zig` (k256's own `scalar.zig` is a bare
//!   re-export, per its own doc comment — same fact `k256/sign`'s PATTERN
//!   comment already records).
//! * `extract` starts the same as `adapt` (scalar-only: `fromBytes`,
//!   `.sub`, `.neg`) but then calls `Secp256k1.combMulBase(y_used...)` to
//!   re-derive `T` from the recovered scalar, landing back in
//!   `group.zig`/`field.zig`/`fast_core.zig` — the SAME `rejectIdentity()`
//!   shape `k256`'s `comb` target and `bip340`'s `sign` target already
//!   measure (see the module-level context in `scripts/ctgrind.sh`'s
//!   comment about that class: probability ≈2^-256, an accepted, known
//!   shape rather than a new defect).
//!
//! ## The propagation witness
//!
//! Every target's result is formatted with `std.debug.print`, which is not
//! constant-time, so a tainted byte reaching it always produces contexts of
//! its own. A non-zero total next to a small, itemised in-file count is
//! what makes the itemisation mean "no branch found" rather than "the taint
//! never arrived".
//!
//! ## Suggested config lines for scripts/ctgrind.sh (coordinator to paste in)
//!
//! ```
//! TARGETS[adaptor]="presign adapt extract"
//! MODES[adaptor]="ReleaseFast"
//! PATTERN[adaptor/presign]='root[.]zig|hash[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig'
//! PATTERN[adaptor/adapt]='root[.]zig|common[.]zig'
//! PATTERN[adaptor/extract]='root[.]zig|common[.]zig|group[.]zig|field[.]zig|fast_core[.]zig'
//! LABEL[adaptor/presign]='adaptor preSign (sk+nonce)+bip340+k256 comb'
//! LABEL[adaptor/adapt]='adaptor adapt (t)+std scalar'
//! LABEL[adaptor/extract]='adaptor extract (t out)+k256 comb+std scalar'
//! ```
//! ⚠ `root[.]zig` in every pattern above matches BOTH `adaptor/src/root.zig`
//! and `bip340/src/root.zig` (see "own vs delegate" above) — read the
//! qualified symbol name, not just the bucket, when attributing a specific
//! context.

const std = @import("std");
const builtin = @import("builtin");
const adaptor = @import("root.zig");
const bip340 = @import("bip340");

/// Deterministic "random" secret material. Computed at runtime (not folded
/// at comptime) so tainting it marks memory the code under test actually
/// reads.
fn secretBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

/// A scalar comfortably inside `[1, n)`: clearing the top byte keeps the
/// value below the curve/group order, so callers get a realistic input
/// rather than one that happens to exercise the reduction/zero edge.
fn secretScalar(comptime domain: []const u8) [32]u8 {
    var s = secretBytes(32, domain);
    s[0] = 0;
    if (s[31] == 0) s[31] = 1;
    return s;
}

/// Forces one real load from `s` through a volatile pointer, one byte at a
/// time, so the code under test cannot be fed a copy that predates
/// `makeMemUndefined` — see trap 2 in the module doc comment above.
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

fn taintIf(cond: bool, bytes: []u8) void {
    if (cond) std.valgrind.memcheck.makeMemUndefined(bytes);
}

const Target = enum { presign, adapt, extract };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "presign")) return .presign;
    if (std.mem.eql(u8, s, "adapt")) return .adapt;
    if (std.mem.eql(u8, s, "extract")) return .extract;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

/// A self-consistent `(PreSignature, AdaptorPoint, t, completed signature)`
/// tuple, built from fixed, ALWAYS-DEFINED material — see "The fixture" in
/// the module doc comment. Never tainted itself; `adapt`/`extract` below
/// each re-taint only the one buffer their own target cares about.
const Fixture = struct {
    presig: adaptor.PreSignature,
    adaptor_point: adaptor.AdaptorPoint,
    t_bytes: [32]u8,
    full_sig: bip340.Signature,
};

fn buildFixture(io: std.Io) !Fixture {
    const sk = try bip340.SecretKey.fromBytes(secretScalar("ctgrind-adaptor-harness-fixture-signer-key-v1"));
    const t_bytes = secretScalar("ctgrind-adaptor-harness-fixture-adaptor-secret-v1");
    const adaptor_point = try adaptor.AdaptorPoint.fromSecret(t_bytes);
    const aux_rand = secretBytes(32, "ctgrind-adaptor-harness-fixture-aux-rand-v1");
    const msg = "ctgrind harness message";

    const presig = try adaptor.preSign(sk, msg, aux_rand, adaptor_point, io);
    const sig_bytes = try adaptor.adapt(presig, t_bytes);
    const full_sig = try bip340.Signature.fromBytes(sig_bytes);

    return .{ .presig = presig, .adaptor_point = adaptor_point, .t_bytes = t_bytes, .full_sig = full_sig };
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    // `preSign`'s signature threads an `io` through (unused by `preSign`
    // itself — deterministic once `aux_rand` is in hand — but required for
    // API symmetry with the sibling modules' `sign` functions, per
    // `root.zig`'s own doc comment).
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    switch (target) {
        .presign => {
            // Tainted: the SIGNER's private key. Everything preSign derives
            // from it (effective scalar d, nonce material, R/R_hat, the
            // needs_negation masked select, s_prime) inherits the taint.
            var sk_bytes = secretScalar("ctgrind-adaptor-harness-presign-signer-key-v1");
            taintIf(tainted, &sk_bytes);
            const sk_raw = reloadVolatile(32, &sk_bytes);
            const sk = try bip340.SecretKey.fromBytes(sk_raw);

            // PUBLIC by construction — never tainted. The adaptor point T is
            // derived from an arbitrary fixed scalar purely to get a valid
            // curve point; that originating scalar plays no further role and
            // is not this target's secret (the presigner never learns it
            // either, in the real protocol).
            const t_pub_bytes = secretScalar("ctgrind-adaptor-harness-presign-adaptor-point-v1");
            const adaptor_point = try adaptor.AdaptorPoint.fromSecret(t_pub_bytes);
            const msg = "ctgrind harness message";
            const aux_rand = secretBytes(32, "ctgrind-adaptor-harness-presign-aux-rand-v1");

            const presig = try adaptor.preSign(sk, msg, aux_rand, adaptor_point, io);
            std.debug.print("r={x} s_prime={x} needs_negation={}\n", .{ presig.r, presig.s_prime, presig.needs_negation });
        },
        .adapt => {
            const fx = try buildFixture(io);

            // Tainted: the ADAPTOR SECRET t entering adapt's own parameter —
            // a fresh copy, independent of the fixture's (always-defined) one.
            var t_bytes = fx.t_bytes;
            taintIf(tainted, &t_bytes);
            const t_raw = reloadVolatile(32, &t_bytes);

            const sig = try adaptor.adapt(fx.presig, t_raw);
            std.debug.print("sig={x}\n", .{sig});
        },
        .extract => {
            const fx = try buildFixture(io);

            // Tainted: full_sig.s — the field that ENCODES t
            // (s = s_prime + t_used) and that extract's whole job is to
            // recover t back out of. presig (including s_prime) and
            // adaptor_point are left untainted: both are ordinary wire/public
            // data a counterparty already holds before extraction.
            var s_bytes = fx.full_sig.s;
            taintIf(tainted, &s_bytes);
            const s_raw = reloadVolatile(32, &s_bytes);
            const tainted_sig = bip340.Signature{ .r = fx.full_sig.r, .s = s_raw };

            const recovered = try adaptor.extract(fx.presig, tainted_sig, fx.adaptor_point);
            std.debug.print("recovered={x}\n", .{recovered});
        },
    }
}
