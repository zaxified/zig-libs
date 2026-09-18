// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for the reasoning
//! `ibe.zig`'s `fp12Pow` doc comment already carries ("no secret-dependent
//! branch and no secret-dependent memory access", citing audit finding "ibe
//! F4"), as an actual committed program instead of an unmeasured paragraph.
//! Run it through `../../../scripts/checks/ctgrind.sh ibe` (once the coordinator
//! adds the `TARGETS`/`MODES`/`PATTERN`/`LABEL` entries this file's doc
//! comment suggests below — that script REFUSES an unlisted module rather
//! than silently skipping it). Until then, by hand:
//!
//!   zig build ctgrind -Dctgrind-module=ibe -Dctgrind-valgrind=true  -Doptimize=ReleaseFast
//!   zig build ctgrind -Dctgrind-module=ibe -Dctgrind-valgrind=false -Doptimize=ReleaseFast
//!   valgrind --tool=memcheck --error-exitcode=99 --num-callers=20 \
//!       zig-out/ctgrind/ctgrind-ibe <extract|decrypt|fp12pow> <yes|no>
//!
//! NOT wired into `zig build test-ibe` — memcheck's context count is
//! valgrind's own verdict, not something a Zig test can assert on. `zig
//! build check-ctgrind` compiles it (a rot guard, no valgrind) once
//! `build.zig`'s harness discovery picks this file up by its path existing
//! (automatic — no `build.zig` edit needed, see that file's
//! `ctgrindHarnesses`).
//!
//! ## Why three targets, and why they are NOT symmetric
//!
//! A prior triage pass (`~/CML/20260901-zig-libs-audit/ctgrind-triage-3.md`)
//! looked at `ibe`'s three secret-consuming entry points and reached a
//! per-entry-point, not per-module, verdict:
//!
//! - `extract(msk, id)` is "a clean single-call delegate to `bls12_381`"
//!   (`g1.Jacobian.fromAffine(qid).scalarMul(msk)`) — the SAME ladder
//!   `bls12_381`'s own `g1_scalarmul` ctgrind target already measures, no
//!   surrounding branch of `ibe`'s own. Triage verdict: NO by itself.
//! - `decrypt(d_id, ct)` is "one `pairing.pairing` call" — also fine on its
//!   own, plus this module's own `h2`/`h3`/`h4` tag-hashing and the FO
//!   consistency compare, none of which the triage flagged.
//! - `encrypt(mpk, id, message, sigma)` is what "tips the whole module to
//!   NEEDS": it calls a module-LOCAL `fp12Pow(gid, r)` — "adapted from
//!   `tlock.zig`'s `fp12Pow`" per `ibe.zig`'s own doc comment — with
//!   detailed inline constant-time reasoning (4-bit windowed
//!   exponentiation, `fp12CtSelect`/`fp6CtSelect` full-table scan, no
//!   leading-zero skip) but, until this file, zero empirical measurement.
//!
//! So this harness does not drive `encrypt` end to end (that would also
//! taint `message`/`sigma`, which are NOT the master secret key or the
//! per-identity private key this module's threat model protects — they are
//! the sender's own plaintext and randomness, out of scope for "WHAT TO
//! TAINT" here). Instead the THIRD target calls `fp12Pow` directly through
//! `ibe.zig`'s own `testing_fp12Pow` test hook, tainting only the EXPONENT
//! — the one operand `fp12Pow`'s own doc comment argues must be "treated
//! exactly like a secret scalar" (`r = H3(sigma, M)` is secret-derived: it
//! leaks `sigma`, hence the message, if it leaks). The base (`Gid`, a real
//! pairing of two public points) is left clean, mirroring `bls12_381`'s own
//! `g1_scalarmul`/`g2_scalarmul` targets tainting only the scalar and never
//! the point being multiplied.
//!
//! ## Verified before relying on it
//!
//! Per the campaign's own two prior false headlines, `fp12Pow`'s existence
//! and shape were confirmed by reading `ibe.zig` directly before writing
//! this file, not taken from the triage note: it is real (`ibe.zig` lines
//! ~226-262), a 4-bit fixed-window exponentiation over `Fp12`, using
//! `fp12CtSelect`/`fp6CtSelect` (full 16-entry scans, never `table[idx]`)
//! and exported as `pub const testing_fp12Pow = fp12Pow;` specifically so a
//! test/harness file can reach it without widening the module's real public
//! API.
//!
//! ## What is tainted, and what deliberately is not
//!
//! Per this campaign's "WHAT TO TAINT" instruction: the master secret key
//! (`msk`, entering `extract`) and the identity-based private key (`d_id`,
//! entering `decrypt`) — never the identity string, the ciphertext, or the
//! master PUBLIC key (`mpk`), all public by construction. The third target
//! taints `fp12Pow`'s exponent for the reason given above (the module's own
//! doc comment treats it as secret-equivalent even though it is
//! encryption-side, not key material) — this is evidence for `ibe.zig`'s
//! own claim about `fp12Pow`, not a re-statement of the msk/d_id rule.
//!
//! - `.extract` — taints `msk` (an `Fr` scalar). `id` is a fixed public
//!   string, never tainted.
//! - `.decrypt` — taints the WHOLE `d_id` (`g1.Affine`: `x`, `y`,
//!   `infinity`) entering `decrypt`. `ct` (`u`/`v`/`w`) is built from a
//!   real, matching, CLEAN `encrypt` call and never tainted — same
//!   reasoning `bls12_381`'s harness gives for leaving the multiplied POINT
//!   clean in its `scalarmul` targets: tainting public data would report
//!   its own ordinary handling as a finding nobody claims. Unlike `Fp`/`Fr`
//!   (whose `fromBytes` does a canonicality check this harness deliberately
//!   parses BEFORE tainting, per `bls12_381`'s convention), `decrypt` takes
//!   `d_id` as a bare `g1.Affine` with no parse step at all — so there is
//!   no validation-on-public-wire-data boundary to exclude, and the entire
//!   struct is fair game to taint in one call.
//! - `.fp12pow` — taints only the exponent `r` (`Fr`); the base `Gid` (a
//!   real pairing value) stays clean.
//!
//! Each target additionally taints a KAT-fixed, deterministically-derived
//! (SHAKE256-seeded, not a real random draw) value so repeated runs of the
//! table are comparable — not a correctness KAT, a diagnostic input only.
//!
//! ## The two traps (see `ct25519`'s/`bls12_381`'s harnesses for the same shape)
//!
//! 1. `std.valgrind.doClientRequest` opens with
//!    `if (!builtin.valgrind_support) return default;`, off by default
//!    outside Debug. Built WITHOUT `-fvalgrind`, every client request
//!    compiles to nothing and `--taint=yes` silently behaves like
//!    `--taint=no`. The driver script builds both ways so this shows up as
//!    its own (trap) row, not a silent false clean.
//! 2. The optimizer is in principle free to keep a defined copy of a
//!    tainted value around from before `makeMemUndefined` ran (a spilled
//!    register, a CSE'd expression). `reloadVolatile` forces one real
//!    byte-by-byte load through a volatile pointer immediately before each
//!    tainted value is used, so the code under test cannot be handed a
//!    stale defined copy. Like `ct25519`'s harness, this is DEFENSIVE, not
//!    demonstrated on today's compiler — stated as insurance, not as an
//!    observed requirement.
//!
//! ## The propagation proof
//!
//! Every target formats its result through `std.debug.print` (NOT
//! constant-time — branches on the value it is printing), reported
//! separately from the target's own contexts (the WITNESS bucket in
//! `scripts/checks/ctgrind.sh`'s classifier). A nonzero witness count is what
//! proves the taint travelled all the way to an observable branch, so a
//! zero count inside `ibe`'s/`bls12_381`'s own code means "no branch
//! found", not "taint never arrived".
//!
//! ## Expected inherited substrate (read before treating a nonzero as new)
//!
//! `bls12_381`'s own harness (measured 2026-09-08) found that
//! `G1.Jacobian.scalarMul`/`G2.Jacobian.scalarMul` are the SAME code
//! `.extract` drives here, and separately that `std.crypto.ff`'s
//! `Uint.toBytes` (`ff.zig:150`) branches on an overflow check reached by
//! every scalar-to-bytes conversion — contradicting `bls12_381`'s own
//! `SPEC.md:387` "no secret-dependent branches" claim. If `.extract`'s
//! table shows nonzero contexts in `ff.zig` (via `Fr.toBytes`/scalar
//! conversion inside the ladder) or in `g1.zig`/`fp.zig`, that is the SAME
//! inherited substrate, not a new `ibe` defect — see the report's
//! ibe-own vs. inherited split for the actual attribution.

const std = @import("std");
const builtin = @import("builtin");
const bls12_381 = @import("bls12_381");
const ibe_mod = @import("ibe.zig");

const g1 = bls12_381.g1;
const g2 = bls12_381.g2;
const pairing = bls12_381.pairing;
const Fr = bls12_381.Fr;

/// Deterministic "random" bytes, computed at runtime (not folded at
/// comptime) so tainting them actually marks memory the code under test
/// reads. Not a KAT — a diagnostic input, not a correctness one; the fixed
/// domain tag only keeps repeated runs of the table comparable. Same shape
/// as `bls12_381`'s harness.
fn secretBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

/// Forces one real byte-by-byte load of `s` through a volatile pointer —
/// see trap 2 above. Generic over any fixed-size `T` (a byte array or a
/// plain-old-data struct like `g1.Affine`), same shape as `blindrsa`'s
/// harness.
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

const Target = enum { extract, decrypt, fp12pow };
const Taint = enum { yes, no };

fn taintBytes(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

/// A tainted (iff `taint == .yes`) `Fr` scalar. The raw bytes are reloaded
/// through a volatile pointer and canonicalized (`r[0] = 0`; `bls12_381`'s
/// scalar modulus `r`'s top byte is `0x73`, so a top byte of `0` is
/// unconditionally `< r`) BEFORE `Fr.fromBytes` parses them — that parse's
/// own canonicality check is validation on data this harness does not make
/// any claim about, so it deliberately runs on a value not yet tainted.
/// What is tainted is the VALUE the resulting `Fr` carries, exactly
/// `bls12_381`'s harness's `secretFr` convention.
fn secretFr(comptime domain: []const u8, taint: Taint) !Fr {
    var raw = secretBytes(Fr.encoded_bytes, domain);
    raw[0] = 0;
    const reloaded = reloadVolatile([Fr.encoded_bytes]u8, &raw);
    var v = try Fr.fromBytes(reloaded);
    taintBytes(taint, std.mem.asBytes(&v));
    return v;
}

/// A real, internally-consistent, CLEAN (never tainted) `(d_id, ct)` pair:
/// a fresh deterministic `msk`/`mpk`, `d_id = extract(msk, id)`, and
/// `ct = encrypt(mpk, id, message, sigma)` for fixed message/sigma. This is
/// fixture construction, not the measured region — the `.decrypt` target
/// taints a RELOADED COPY of `d_id` only, right before the call under test.
fn buildDecryptFixture() !struct { d_id: g1.Affine, ct: ibe_mod.Ciphertext } {
    const msk = try secretFr("ctgrind-ibe-harness-fixture-msk-v1", .no);
    const mpk = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(msk).toAffine();
    const id = "ctgrind-ibe-harness-identity@example.com";
    const d_id = ibe_mod.extract(msk, id);
    const message = [_]u8{0xAB} ** ibe_mod.block_bytes;
    const sigma = [_]u8{0x11} ** ibe_mod.block_bytes;
    const ct = ibe_mod.encrypt(mpk, id, message, sigma);
    return .{ .d_id = d_id, .ct = ct };
}

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "extract")) return .extract;
    if (std.mem.eql(u8, s, "decrypt")) return .decrypt;
    if (std.mem.eql(u8, s, "fp12pow")) return .fp12pow;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = try parseTarget(target_arg);
    const taint = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={} target={s}\n", .{ builtin.valgrind_support, target_arg });

    switch (target) {
        .extract => {
            // The master secret key `msk` entering `extract`. `id` is a
            // fixed public identity string — never tainted.
            const msk = try secretFr("ctgrind-ibe-harness-msk-v1", taint);
            const id = "ctgrind-ibe-harness-identity@example.com";
            const d = ibe_mod.extract(msk, id);

            // Propagation proof.
            std.debug.print("d.x={x}\n", .{d.x.toBytes()});
            std.debug.print("d.y={x}\n", .{d.y.toBytes()});
        },
        .decrypt => {
            // The identity-based private key `d_id` entering `decrypt`.
            // `ct` comes from a real, matching, CLEAN `encrypt` call and is
            // never tainted.
            const fixture = try buildDecryptFixture();
            var d_id = reloadVolatile(g1.Affine, &fixture.d_id);
            taintBytes(taint, std.mem.asBytes(&d_id));

            const message = ibe_mod.decrypt(d_id, fixture.ct) catch |err| {
                // Reachable only if the fixture's own (msk, id, message,
                // sigma) ever stop agreeing with each other, which the
                // fixed values above do not. Handled anyway so a future
                // change to the fixture fails loudly instead of silently
                // skipping the call under test.
                std.debug.print("decrypt rejected: {t}\n", .{err});
                return err;
            };

            // Propagation proof.
            std.debug.print("message={x}\n", .{message});
        },
        .fp12pow => {
            // `fp12Pow`'s exponent `r` — secret-derived in the real
            // `encrypt` path (`r = H3(sigma, message)`) and treated by
            // `ibe.zig`'s own doc comment as "exactly like a secret
            // scalar". The base `Gid` is a real pairing of two PUBLIC
            // points and stays clean, mirroring `bls12_381`'s own
            // `scalarmul` targets never tainting the point.
            const gid = pairing.pairing(g1.Affine.generator, g2.Affine.generator);
            const r = try secretFr("ctgrind-ibe-harness-fp12pow-exponent-v1", taint);
            const result = ibe_mod.testing_fp12Pow(gid, r);

            // Propagation proof.
            std.debug.print("result={x}\n", .{result.toBytes()});
        },
    }
}

// ── suggested scripts/checks/ctgrind.sh config (coordinator: paste in, do not
// generate mechanically — every existing entry carries hand-written
// reasoning in its own comment; this follows the same shape) ─────────────
//
// declare -A TARGETS=(
//     [ibe]="extract decrypt fp12pow"
// )
// declare -A MODES=(
//     [ibe]="ReleaseFast"
// )
// declare -A PATTERN=(
//     # `extract`'s own body is one line delegating straight into
//     # `bls12_381`'s G1 ladder -- the SAME files `bls12_381/g1_scalarmul`
//     # already measures. `ibe.zig` is listed anyway so a future change to
//     # `extract` itself (not just the delegate) is not silently excluded.
//     [ibe/extract]='ibe[.]zig|g1[.]zig|fp[.]zig|scalar[.]zig'
//     # `decrypt`'s own pairing + H2/H3/H4 tag-hashing + FO compare
//     # (`ibe.zig`, `ciphersuite.zig`) plus the full inherited pairing
//     # internals (`bls12_381`) and std's SHA-256/512 (both live in
//     # `sha2.zig`). The FO check's own compare is a KNOWN, documented
//     # non-constant-time byte compare on a value whose outcome is public
//     # by design (`ibe.zig`: "The check's outcome (accept/reject) is
//     # public, so a non-constant-time byte compare is fine here") -- an
//     # expected non-zero, not a defect, if it shows up attributed to
//     # `ibe.zig`.
//     [ibe/decrypt]='ibe[.]zig|ciphersuite[.]zig|pairing[.]zig|fp[.]zig|fp2[.]zig|fp6[.]zig|fp12[.]zig|g1[.]zig|g2[.]zig|scalar[.]zig|sha2[.]zig'
//     # `fp12Pow`/`fp12CtSelect`/`fp6CtSelect` are all private helpers in
//     # `ibe.zig` itself -- the finding this target exists for. `Fp12.mul`/
//     # `.square`/`Fp2.ctSelect` bottom out in `bls12_381`'s tower
//     # arithmetic.
//     [ibe/fp12pow]='ibe[.]zig|fp12[.]zig|fp6[.]zig|fp2[.]zig|fp[.]zig'
// )
// declare -A LABEL=(
//     [ibe/extract]='ibe extract (msk -> bls12_381 G1)'
//     [ibe/decrypt]='ibe decrypt (d_id -> pairing+hash+FO)'
//     [ibe/fp12pow]='ibe fp12Pow (Gt windowed exponentiation, ibe F4)'
// )
