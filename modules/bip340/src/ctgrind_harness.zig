// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Constant-time"
//! bullet ("`sign` DOES handle secret data (`d`, the derived nonce `k`) and
//! should be written with the same care as any Schnorr/ECDSA signer") and for
//! the step-7 claim in `root.zig`'s `sign` doc comment ("a constant-time
//! masked byte select between the two candidate scalars (no branch on `R.y`'s
//! parity, which is one bit derived from the secret nonce hash)"), as an
//! actual committed program instead of a sentence nobody re-checks. Run it
//! through `zig build ctgrind -Dctgrind-module=bip340 -Dctgrind-valgrind=…`
//! plus `valgrind --tool=memcheck` by hand — `scripts/ctgrind.sh` has no
//! per-module TARGETS/MODES/PATTERN/LABEL entry for `bip340` yet; the
//! suggested lines are at the bottom of this comment for the coordinator to
//! paste in.
//!
//! NOT wired into `zig build test-bip340` — memcheck's context count is
//! valgrind's own output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## The one target: `sign`
//!
//! `sign` (`root.zig`'s top-level `sign`, BIP340 "Default Signing") is the
//! module's ONLY shipped secret-data path. `verify`/`verifyBatch` are
//! deliberately excluded — `SPEC.md` states "NOT required for
//! verify/verifyBatch (BIP340 § "Verification" explicitly notes this — all
//! their inputs are public)" and tainting a scalar into `mulDoubleBasePublic`
//! would light up memcheck by design, measuring nothing about a claim (the
//! same wrong-target failure mode `k256`'s and `p256`'s own harnesses refuse).
//!
//! Tainted: the 32-byte BIP340 secret key `sk` that `sign` receives. That one
//! taint reaches, end to end, every secret-derived value the spec's 10 steps
//! define: the effective (possibly negated) signing scalar `d`, the
//! deterministic nonce material `t`/`rand`/`k'`, the nonce point `R`'s
//! coordinates, the step-7 masked-selected nonce `k`, and the final scalar
//! `s = k + e·d mod n`.
//!
//! NOT tainted (both PUBLIC by BIP340, same convention `k256`'s own `sign`
//! target and `p256`'s use): `msg` (the verifier has it) and `aux_rand` (BIP340
//! hashes it into the nonce but does not treat it as a secret the scheme
//! protects — see `root.zig`'s `sign` doc comment, step 3).
//!
//! ## bip340-own vs k256-inherited
//!
//! `sign`'s call graph crosses into `k256` twice with the tainted scalar
//! (`KeyPair.fromSecretKey`'s `combMulBase(sk.bytes)` for the public-key
//! derivation, and `sign`'s own `combMulBase(k0.toBytes())` for the nonce
//! commitment `R = k'·G`), and k256's `comb` target already measures exactly
//! that function with a tainted scalar (`modules/k256/src/ctgrind_harness.zig`,
//! `group.zig:346`'s `rejectIdentity` context). This harness's PATTERN
//! therefore has to name `k256`'s files too — attributing this module's own
//! two `combMulBase` calls to "k256's problem" instead would be the evasion
//! `scripts/ctgrind.sh`'s header exists to refuse (same reasoning as
//! `bolt8/dh`'s and `k256/sign`'s patterns). The per-line breakdown below
//! marks each context bip340-own or k256/std-inherited.
//!
//! ## The two traps (see `ct25519`'s harness for the fuller writeup)
//!
//! 1. `std.valgrind.doClientRequest` opens with
//!    `if (!builtin.valgrind_support) return default;`, off by default outside
//!    Debug. Built WITHOUT `-fvalgrind`, every client request compiles to
//!    nothing and `--taint=yes` silently behaves like `--taint=no` — measured
//!    as its own row below, not assumed.
//! 2. An optimizer is in principle free to keep a defined copy of `sk` in a
//!    register rather than reading back the memory `makeMemUndefined` marked.
//!    `reloadVolatile` forces one real load from freshly-tainted memory
//!    immediately before the call under test. Defensive, not demonstrated on
//!    this host/compiler.
//! 3. ReleaseFast only — `Debug`/`ReleaseSafe` add overflow checks in the
//!    field arithmetic underneath (k256's `field.zig`) that branch on tainted
//!    values and bury the signal, and Debug's self-hosted backend is not
//!    readable by valgrind's DWARF parser at all (`scripts/ctgrind.sh` §
//!    MODES).
//!
//! ## The propagation witness
//!
//! The result (public key + signature bytes) is formatted with
//! `std.debug.print`, which is not constant-time, so a tainted byte reaching
//! it always produces contexts of its own. A non-zero total next to a small,
//! itemised in-file count is what makes the itemisation mean "no branch
//! found" rather than "the harness never ran".
//!
//! ## Suggested config lines for scripts/ctgrind.sh (coordinator to paste in)
//!
//! ```
//! TARGETS[bip340]="sign"
//! MODES[bip340]="ReleaseFast"
//! PATTERN[bip340/sign]='root[.]zig|hash[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig'
//! LABEL[bip340/sign]='bip340 sign+k256 comb+std scalar'
//! ```
//! `common[.]zig` in the pattern is std's `crypto/pcurves/common.zig`, reached
//! through `k256/src/scalar.zig`'s verbatim re-export of std's scalar field —
//! see the per-line breakdown for why that file is named rather than folded
//! into "unattr".

const std = @import("std");
const builtin = @import("builtin");
const bip340 = @import("root.zig");

/// Deterministic "random" secret key material. Computed at runtime (not
/// folded at comptime) so tainting it marks memory `sign` actually reads.
fn secretBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

/// A secret key comfortably inside `[1, n)`: clearing the top byte keeps the
/// value below the curve order, so `sign` gets a realistic input rather than
/// one that happens to exercise the reduction/zero edge.
fn secretScalar(comptime domain: []const u8) [32]u8 {
    var s = secretBytes(32, domain);
    s[0] = 0;
    if (s[31] == 0) s[31] = 1;
    return s;
}

/// Forces one real load from `s` through a volatile pointer, one byte at a
/// time, so `sign` cannot be fed a copy that predates `makeMemUndefined` —
/// see trap 2 above.
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Target = enum { sign };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "sign")) return .sign;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn taintIf(cond: bool, bytes: []u8) void {
    if (cond) std.valgrind.memcheck.makeMemUndefined(bytes);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;
    _ = target; // only one target exists today; kept for parity with every other harness's CLI shape

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    // `sign`'s signature is `(SecretKey, msg, aux_rand, std.Io)` — the `io`
    // parameter is unused by `sign` itself (deterministic once `aux_rand` is
    // in hand, per its own doc comment) but must be threaded through, same
    // as `kat_test.zig` does.
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var sk_bytes = secretScalar("ctgrind-bip340-harness-secret-key-v1");
    taintIf(tainted, &sk_bytes);
    const sk_raw = reloadVolatile(32, &sk_bytes);
    const sk = try bip340.SecretKey.fromBytes(sk_raw);

    // PUBLIC by BIP340 (see the module doc comment above) — never tainted, so
    // a branch on either cannot be mistaken for a secret-dependent one.
    const msg = "ctgrind harness message";
    const aux_rand = secretBytes(32, "ctgrind-bip340-harness-aux-rand-v1");

    const sig = try bip340.sign(sk, msg, aux_rand, io);
    std.debug.print("sig={x}\n", .{sig});
}
