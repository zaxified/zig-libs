// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s std-recon
//! paragraph ("`mul(scalar, .big)` is the constant-time scalar-mult ... and
//! `scalar.rejectNonCanonical` screens the private scalar") and its
//! `timing_safe.eql`/`verify` claim ("both `verify`s compare MACs in
//! constant time and fail closed"), as an actual committed program instead
//! of a paragraph nobody re-runs. Run it through
//! `../../../scripts/ctgrind.sh ctap2pin` once the coordinator adds this
//! module's config block to that shared script (the suggested
//! TARGETS/MODES/PATTERN lines are below); until then, by hand:
//!
//!     zig build ctgrind -Dctgrind-module=ctap2pin -Dctgrind-valgrind=true  -Doptimize=ReleaseFast
//!     zig build ctgrind -Dctgrind-module=ctap2pin -Dctgrind-valgrind=false -Doptimize=ReleaseFast   # the no-`-fvalgrind` trap row
//!     valgrind --tool=memcheck --error-exitcode=99 --num-callers=20 \
//!         zig-out/ctgrind/ctgrind-ctap2pin <ecdh|one|two|token> <yes|no>
//!
//! NOT wired into `zig build test-ctap2pin` — memcheck's context count is
//! valgrind's own verdict, not something a Zig test can assert on. `zig
//! build check-ctgrind` (module-wide, not filterable by `-Dctgrind-module`)
//! still compiles this file at Debug so it cannot rot into an unbuildable
//! recipe; that compile proves nothing about any one context count.
//!
//! Suggested `scripts/ctgrind.sh` config (added here as a comment only —
//! that script is coordinator-owned, per this task's instructions):
//!
//!     TARGETS[ctap2pin]="ecdh one two token"
//!     MODES[ctap2pin]="ReleaseFast"
//!     PATTERN[ctap2pin/ecdh]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig|scalar[.]zig'
//!     PATTERN[ctap2pin/one]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig|scalar[.]zig|sha2[.]zig'
//!     PATTERN[ctap2pin/two]='root[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig|scalar[.]zig|hkdf[.]zig|sha2[.]zig'
//!     PATTERN[ctap2pin/token]='root[.]zig|hmac[.]zig|sha2[.]zig'
//!     LABEL[ctap2pin]="ctap2pin ECDH+PIN/token"
//!
//! ## The four targets
//!
//! * `ecdh` — `ecdhZ` in isolation: the platform's ECDH private scalar
//!   against a FIXED, PUBLIC authenticator point that is deliberately NOT
//!   the base point, so `P256.mul`'s internal `isBasePointRepr` redirect
//!   (`group.zig:307`, a branch on the PUBLIC point, never the secret
//!   scalar) takes the variable-base `mulCtWindowed` branch — see "the
//!   second p256 path" below. The narrowest measurement of the `allEqual`
//!   lead this harness exists to check.
//! * `one` / `two` — `One.encapsulate` / `Two.encapsulate` end to end: the
//!   SHIPPED path a platform actually calls (`root.zig:216`/`:285`). Both
//!   run `publicKeyFromScalar` (fixed-base `combMulBase` — the SAME code
//!   `p256`'s own `comb` target measured in round 1) *and* `ecdhZ`
//!   (variable-base `mulCtWindowed`) on the same tainted scalar, then the
//!   protocol's own `kdf` on the resulting `Z` (SHA-256 for One,
//!   HKDF-SHA-256 for Two).
//! * `token` — the PIN/pinUvAuthToken side, deliberately NOT a scalar: CTAP
//!   2.1's `pinUvAuthToken` (and the PIN it is ultimately derived from)
//!   carries far less entropy than a 256-bit ECDH scalar, so a timing
//!   dependence on it is worth far more to an attacker than the same
//!   dependence on the scalar. Taints a 16-byte (Protocol One's shortest
//!   legal token) and a 32-byte (Protocol Two's fixed token size) key and
//!   drives each through `authenticate` + `verify`. The message and the
//!   recomputed signature stay PUBLIC — a real verifier has both — so this
//!   measures the HMAC key schedule and the MAC compare, not a wire value.
//!
//! Neither the authenticator's public key (`peerKey()` below, always a
//! fixed compile-unknown-but-never-tainted point) nor any wire message is
//! ever tainted, per this task's instructions.
//!
//! ## The `allEqual` lead, verified against source (not inherited)
//!
//! A triage pass reported `ecdhZ` branching directly on raw secret-key
//! bytes via `std.mem.allEqual` before reaching `p256`. CONFIRMED at
//! `root.zig:162`:
//!
//!     if (std.mem.allEqual(u8, &private_scalar, 0)) return error.InvalidScalar;
//!
//! and `std.mem.allEqual` (zig 0.16.0, `lib/std/mem.zig:1172`) is
//!
//!     pub fn allEqual(comptime T: type, slice: []const T, scalar: T) bool {
//!         for (slice) |item| { if (item != scalar) return false; }
//!         return true;
//!     }
//!
//! — an early-exit loop directly over the SECRET scalar's bytes: the number
//! of loop iterations executed before the `return false` fires is a
//! function of how many of the scalar's leading bytes happen to equal zero,
//! which is secret-dependent. Every real scalar this harness feeds in is
//! non-zero (see `platformScalar` below), so the loop runs to completion in
//! this specific measurement either way — the DEPENDENCE is structural
//! (iteration count varies with secret content), not something this
//! harness's fixed inputs can force to manifest as a *differing* memcheck
//! count between two runs. It is still a real class-1 branch on secret
//! bytes and is named as one in the table below if valgrind's DWARF
//! attribution puts a context at this line; if it does not (plausible: a
//! single unconditional-looking loop with a fixed trip count in this
//! specific run may not read as a "conditional jump on uninitialised value"
//! to memcheck at all), that absence is reported as an absence, not
//! papered over. `ecdh`/`one`/`two` all taint `private_scalar` /
//! `platform_scalar` before this line runs, so all three targets exercise
//! it on the tainted path. It lives in ctap2pin's OWN file (`root.zig`), so
//! it is attributed to THIS module's PATTERN, not delegated to `p256` or
//! std.
//!
//! `rejectNonCanonical` (`root.zig:161`, and again inside
//! `publicKeyFromScalar`/`ecdhZ` for `one`/`two`) resolves to
//! `std.crypto.ecc.P256.scalar.rejectNonCanonical` — `p256`'s own
//! `scalar.zig:30` re-exports std's scalar type verbatim rather than
//! implementing its own — so this is the SAME degenerate canonicality check
//! `p256`'s round-1 `sign` harness already measured (1 context, std's
//! `crypto/pcurves/common.zig:75`): expect the same negligible-probability
//! shape here, not a new finding, and it is why `common[.]zig`/`scalar[.]zig`
//! are in this harness's suggested PATTERN rather than left to fall into
//! `unattr`.
//!
//! ## The second p256 path: `mulCtWindowed`
//!
//! `p256`'s own harness only ever drives the fixed-base `comb`
//! (`combMulBase`). `ecdhZ`'s `point.mul(private_scalar, .big)`
//! (`root.zig:164`) multiplies the tainted scalar against the
//! AUTHENTICATOR's point — never the compile-time `basePoint` constant —
//! so `P256.mul`'s `isBasePointRepr` redirect (`group.zig:307`, a branch on
//! the PUBLIC point, not the secret scalar) takes the variable-base
//! `mulCtWindowed` branch (`group.zig:360`) instead. Per round 5's note
//! that this path "had never been measured" before, `ecdh`/`one`/`two` are
//! the first real measurement of it from a genuine module consumer (not a
//! synthetic p256-internal harness call).
//!
//! ## The two traps (see `ct25519`/`p256`'s harnesses for the fuller writeup)
//!
//! 1. `-fvalgrind` is off by default outside Debug. Built without it, every
//!    `std.valgrind.doClientRequest` compiles to nothing and `taint=yes`
//!    silently behaves like `taint=no` — a clean run that measured nothing.
//!    Both builds are run so this is its own row, not a silent false clean.
//! 2. The optimizer could in principle keep a defined register copy of the
//!    tainted bytes rather than re-reading the memory `makeMemUndefined`
//!    marked. `reloadVolatile` forces one real load through a volatile
//!    pointer immediately before the call under test — defensive, per the
//!    other harnesses' own measurement that this is precaution rather than
//!    an observed requirement on this compiler/host.
//! 3. ReleaseFast only, per `scripts/ctgrind.sh`'s MODES note:
//!    Debug/ReleaseSafe add overflow checks on wide-integer field arithmetic
//!    that branch on tainted values and bury the signal (measured elsewhere
//!    in this collection at tens of thousands of contexts for the same
//!    class of code), and Debug's self-hosted backend cannot be read by
//!    valgrind's DWARF parser at all.
//!
//! ## The propagation witness
//!
//! Every target formats its result through `std.debug.print`, which is not
//! constant-time by design — a tainted byte reaching it always produces
//! contexts of its own. A non-zero total next to a small (or zero) in-file
//! count is what makes that count mean "no branch found" rather than "the
//! harness never ran".

const std = @import("std");
const builtin = @import("builtin");
const ctap2pin = @import("root.zig");

/// Deterministic byte material, computed at RUNTIME (not folded at
/// comptime) so tainting it marks memory the code under test actually
/// reads. Not a KAT — a diagnostic tool, not a correctness test.
fn deriveBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
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

/// A platform ECDH scalar comfortably inside `[1, n)`: clearing the top
/// byte keeps the value below the P-256 group order, and the explicit
/// zero-guard keeps it away from the `allEqual` degenerate case by
/// construction (the same convention `p256`'s own harness uses for
/// `secretScalar`), so every target exercises the REAL multiply, not the
/// `InvalidScalar` early return.
fn platformScalar(comptime domain: []const u8) [32]u8 {
    var s = deriveBytes(32, domain);
    s[0] = 0;
    if (s[31] == 0) s[31] = 1;
    return s;
}

/// The authenticator's PUBLIC key-agreement key: a fixed point, never
/// tainted (a real caller receives exactly this shape over the wire as a
/// COSE_Key). Deliberately built from a scalar OTHER than the one that
/// derives the base point, so the resulting point is not `P256.basePoint`
/// and `ecdhZ`'s internal multiply takes the variable-base
/// `mulCtWindowed` path rather than the fixed-base `combMulBase` redirect
/// — see "the second p256 path" above.
fn peerKey() ctap2pin.PublicKey {
    const scalar = platformScalar("ctgrind-ctap2pin-harness-PUBLIC-peer-scalar-v1");
    return ctap2pin.publicKeyFromScalar(scalar) catch unreachable;
}

const Target = enum { ecdh, one, two, token };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "ecdh")) return .ecdh;
    if (std.mem.eql(u8, s, "one")) return .one;
    if (std.mem.eql(u8, s, "two")) return .two;
    if (std.mem.eql(u8, s, "token")) return .token;
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
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    switch (target) {
        .ecdh => {
            // `ecdhZ` in isolation. `peer` is PUBLIC and never tainted.
            const peer = peerKey();
            var scalar = platformScalar("ctgrind-ctap2pin-harness-ecdh-scalar-v1");
            taintIf(tainted, &scalar);
            const s = reloadVolatile(32, &scalar);

            const z = try ctap2pin.ecdhZ(s, peer);
            std.debug.print("z={x}\n", .{z});
        },
        .one => {
            // The SHIPPED platform-side path: `One.encapsulate` runs
            // `publicKeyFromScalar` (fixed-base) AND `ecdhZ` (variable-base)
            // on the same tainted scalar, then `One.kdf` (SHA-256).
            const peer = peerKey();
            var scalar = platformScalar("ctgrind-ctap2pin-harness-one-scalar-v1");
            taintIf(tainted, &scalar);
            const s = reloadVolatile(32, &scalar);

            const enc = try ctap2pin.One.encapsulate(s, peer);
            std.debug.print("pk.x={x} secret={x}\n", .{ enc.platform_key_agreement.x, enc.shared_secret });
        },
        .two => {
            // Same shape as `one`, through `Two.encapsulate` (HKDF-SHA-256
            // `kdf` instead of a single SHA-256).
            const peer = peerKey();
            var scalar = platformScalar("ctgrind-ctap2pin-harness-two-scalar-v1");
            taintIf(tainted, &scalar);
            const s = reloadVolatile(32, &scalar);

            const enc = try ctap2pin.Two.encapsulate(s, peer);
            std.debug.print("pk.x={x} secret={x}\n", .{ enc.platform_key_agreement.x, enc.shared_secret });
        },
        .token => {
            // The PIN/pinUvAuthToken side. `msg` is PUBLIC (a real verifier
            // has the message it is authenticating). Protocol One's token
            // may legally be 16 or 32 bytes; 16 is the case measured here,
            // as the closer stand-in for genuinely low-entropy PIN-derived
            // material. Protocol Two's token is always 32 bytes.
            const msg = "ctgrind harness message";

            var key_one = deriveBytes(16, "ctgrind-ctap2pin-harness-token-one-v1");
            taintIf(tainted, &key_one);
            const k1 = reloadVolatile(16, &key_one);
            const sig1 = try ctap2pin.One.authenticate(&k1, msg);
            const ok1 = ctap2pin.One.verify(&k1, msg, &sig1);

            var key_two = deriveBytes(32, "ctgrind-ctap2pin-harness-token-two-v1");
            taintIf(tainted, &key_two);
            const k2 = reloadVolatile(32, &key_two);
            const sig2 = ctap2pin.Two.authenticate(&k2, msg);
            const ok2 = ctap2pin.Two.verify(&k2, msg, &sig2);

            std.debug.print("one sig={x} ok={} | two sig={x} ok={}\n", .{ sig1, ok1, sig2, ok2 });
        },
    }
}
