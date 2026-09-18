// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for the claim at `root.zig:53`
//! ("Sign commits `k·G` constant-time; `verify` is vartime on public inputs")
//! and for `meta.doc`'s "constant-time comb sign, vartime wNAF verify", as an
//! actual committed program instead of a sentence nobody re-checks. Run it
//! through `../../../scripts/checks/ctgrind.sh p256`.
//!
//! NOT wired into `zig build test-p256` — memcheck's context count is
//! valgrind's own output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## The two targets
//!
//! * `comb` — `group.P256.combMulBase`, the fixed-base constant-time multiply
//!   `s·G`. This is the ONE structural speedup p256 has for a secret scalar
//!   against the fixed base point (P-256 has no GLV endomorphism, so unlike
//!   k256 there is no second fast path to also cover) — `group.zig:431`'s
//!   doc names it as backing both the ECDSA nonce commitment `k·G` and the
//!   public-key derivation `d·G`. The scalar is tainted; the point (`G`) is a
//!   compile-time public constant.
//! * `sign` — `EcdsaP256Sha256.KeyPair.generateDeterministic` +
//!   `.sign(msg, null)` end to end from a tainted 32-byte seed: the SHIPPED
//!   secret path (`root.zig:50`–`55`), rewired onto by jwt's ES256 signer and
//!   jwe's ECDH-ES. `EcdsaP256Sha256` is `std.crypto.sign.ecdsa.Ecdsa(P256,
//!   Sha256)` — std's generic ECDSA scaffolding driven by THIS module's
//!   curve — so both the key derivation (`KeyPair.fromSecretKey`, one
//!   `P256.mul` call that redirects to `combMulBase` via
//!   `isBasePointRepr`) and the nonce commitment inside `Signer.finalize`
//!   (`Curve.basePoint.mul(k, .big)`, same redirect) run on p256's own
//!   arithmetic; only the deterministic-nonce HMAC-DRBG and the final
//!   `r`/`s` scalar arithmetic live in std's `ecdsa.zig` and
//!   `crypto/pcurves/common.zig`. Message and (absent) noise are PUBLIC —
//!   `null` noise is what makes the signature reproducible run to run, which
//!   this harness relies on for nothing but is worth stating: it is not a
//!   secret input either way.
//!
//! ## What is deliberately NOT a target
//!
//! `ecdsaVerify` / `P256.mulPublic` / `P256.mulDoubleBasePublic` and the wNAF
//! machinery under them are documented VARIABLE-TIME on PUBLIC inputs
//! (`sign.zig:263`, `group.zig:520`/`:544`). Tainting a scalar into them would
//! light up memcheck by design — that would measure the harness, not the
//! module, and is exactly the wrong-target failure mode this repo's other
//! harnesses (`k256`'s `mulPublic`/`mulPublicGlv` exclusion, `ct25519`'s
//! oracle-only `std` target) all document by naming what they refuse to pin.
//! There is no constant-time claim on the verify path to measure here.
//!
//! `P256.mul` (the general variable-base CT multiply for a non-fixed point)
//! is also not a target: nothing in this module's own shipped API calls it
//! with a secret scalar — every secret-scalar multiply that `EcdsaP256Sha256`
//! performs is against the fixed base point and is redirected to
//! `combMulBase` (`group.zig:290`–`312`, `isBasePointRepr`). A consumer
//! reaching `P256.mul` with a secret scalar over an arbitrary point (e.g. an
//! ECDH-style use from `jwe`) is a claim about `jwe`, not about `p256`, and
//! belongs in that module's own harness if it exists.
//!
//! ## The two traps (see `ct25519`'s harness for the fuller writeup)
//!
//! 1. `std.valgrind.doClientRequest` opens with
//!    `if (!builtin.valgrind_support) return default;`, off by default outside
//!    Debug. Built WITHOUT `-fvalgrind`, every client request compiles to
//!    nothing and `--taint=yes` silently behaves like `--taint=no`. The driver
//!    builds both ways and prints it as its own row.
//! 2. An optimizer is in principle free to keep a defined copy of the scalar
//!    in a register rather than reading back the memory
//!    `makeMemUndefined` marked. `reloadVolatile` forces one real load from
//!    freshly-tainted memory immediately before the call under test.
//!    Defensive, not demonstrated on this host/compiler — see `ct25519`'s
//!    harness for the measurement showing this is precaution, not an observed
//!    requirement.
//! 3. ReleaseFast only. `Debug`/`ReleaseSafe` add overflow checks inside
//!    `field.zig`'s wide-integer (`u256`/`u512`) reduction that branch on
//!    tainted values and bury the signal, and Debug's self-hosted backend
//!    cannot be read by valgrind's DWARF parser at all
//!    (`scripts/checks/ctgrind.sh` § MODES).
//!
//! ## The propagation witness
//!
//! Results are formatted with `std.debug.print`, which is not constant-time,
//! so a tainted byte reaching the formatter always produces contexts of its
//! own. A non-zero total next to a small (or zero) in-file count is what
//! makes that count mean "no branch found" rather than "the harness never
//! ran".

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const P256 = root.P256;
const EcdsaP256Sha256 = root.EcdsaP256Sha256;

/// Deterministic secret material. Computed at runtime (not folded at
/// comptime) so tainting it marks memory the code under test actually reads.
fn secretBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

/// Forces one real load from `s` through a volatile pointer, one byte at a
/// time, so the code under test cannot be fed a copy that predates
/// `makeMemUndefined` — see trap 2 above.
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

/// A scalar comfortably inside `[1, n)`: clearing the top byte keeps the
/// value below the group order, so `combMulBase` gets a realistic input
/// rather than one that happens to exercise the reduction edge.
fn secretScalar(comptime domain: []const u8) [32]u8 {
    var s = secretBytes(32, domain);
    s[0] = 0;
    if (s[31] == 0) s[31] = 1;
    return s;
}

const Target = enum { comb, sign };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "comb")) return .comb;
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

    std.debug.print("valgrind_support={} field_asm_active={}\n", .{
        builtin.valgrind_support,
        root.field_asm_active,
    });

    switch (target) {
        .comb => {
            // The fixed-base CT multiply on its own, isolated from the ECDSA
            // scaffolding around it: `group.zig:431`'s claim is about THIS
            // function, and `sign` below only reaches it indirectly.
            var k = secretScalar("ctgrind-p256-harness-comb-scalar-v1");
            taintIf(tainted, &k);
            const s = reloadVolatile(32, &k);

            const q = try P256.combMulBase(s, .big);

            // Raw projective coordinates via `Fe.toBytes` (a branch-free
            // limb write), not `affineCoordinates`: that runs `Fe.invert`,
            // a separate claim this target does not make.
            std.debug.print("x={x}\n", .{q.x.toBytes(.big)});
            std.debug.print("y={x}\n", .{q.y.toBytes(.big)});
            std.debug.print("z={x}\n", .{q.z.toBytes(.big)});
        },
        .sign => {
            // The SHIPPED path: a 32-byte seed feeds both the deterministic
            // secret-scalar derivation and the pubkey/nonce commitments,
            // exactly as jwt/jwe drive it. `null` noise keeps this
            // reproducible run to run; it is a public choice either way, not
            // a secret this harness is withholding.
            var seed = secretBytes(EcdsaP256Sha256.KeyPair.seed_length, "ctgrind-p256-harness-ecdsa-seed-v1");
            taintIf(tainted, &seed);
            const s = reloadVolatile(EcdsaP256Sha256.KeyPair.seed_length, &seed);

            const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(s);

            // PUBLIC message — the verifier has it, so tainting it would
            // manufacture contexts that say nothing about the scheme.
            const msg = "ctgrind harness message";
            const sig = try kp.sign(msg, null);

            std.debug.print("pk={x}\n", .{kp.public_key.toUncompressedSec1()});
            std.debug.print("sig={x}\n", .{sig.toBytes()});
        },
    }
}
