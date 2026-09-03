// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for this module's hand-written
//! Montgomery field, as an actual committed program. Run it through
//! `../../../scripts/ctgrind.sh bn254`.
//!
//! Until this file existed there was none. Commit `1892c814` replaced `Fp`'s
//! `std.crypto.ff` backend with ~450 lines of hand-rolled constant-time
//! arithmetic — CIOS multiply, a dedicated SOS square, a masked conditional
//! subtract, an inline-asm optimization barrier, a limb-wise canonicality
//! comparator — and `bn254` was not on the `ct` module list, so none of it was
//! ever measured. That is the same structural gap that let `p256`'s HIGH (a
//! `cMov` lowered to a secret-dependent branch) survive an audit: the module
//! was absent from the list, so the claim had nothing behind it. `fp.zig`'s
//! own `blackBox` doc comment names the leak it is defending against — "LLVM
//! can recover `bit ∈ {0,1}` and lower the masked select to a data-dependent
//! branch — a secret-dependent branch on the Groth16 prove path" — and
//! deleting that barrier left `zig build test-bn254` green at 163/163.
//!
//! NOT wired into `zig build test-bn254` — memcheck's context count is
//! valgrind's output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## The two targets, and which claim each one pins
//!
//! * `field` — `Fp.mul`, `square`, `add`, `sub`, `neg`, `inv` and `ctSelect`,
//!   driven from a tainted element AND (for `ctSelect`) a tainted select bit.
//!   This is the target for `montMul`/`montSqr` (the CIOS/SOS bodies),
//!   `condSubP`'s mask, `subLimbs`, and above all `blackBox`: the tainted
//!   `ctSelect` condition is the exact value whose laundering the doc comment
//!   says the scalar-multiplication paths depend on. `inv` is included because
//!   it is `powBE` over a PUBLIC exponent (`p-2`) applied to a SECRET base —
//!   the exponent's bits are public, the base's limbs are not.
//! * `scalarmul` — `G1.Jacobian.scalarMul` with the SCALAR tainted: the
//!   shipped secret path (a Groth16 prover's witness scalars, and any consumer
//!   multiplying by a secret). A secret-dependent branch or a secret-indexed
//!   load in the ladder shows up here.
//!
//! ## Deliberate choices, so a later reader does not have to re-derive them
//!
//! 1. The CURVE POINT is public and never tainted. Only the scalar is secret
//!    in every use this module has; tainting the point would report the
//!    coordinate arithmetic's own `condSubP` as a finding nobody claims.
//! 2. `reloadVolatile` forces the tainted bytes through memory so the
//!    optimizer cannot hand the code under test a defined register copy.
//! 3. ReleaseFast only. Debug/ReleaseSafe add overflow checks to the `u128`
//!    limb arithmetic — branches on tainted values that bury the signal.
//! 4. Hex formatting of the results is not constant-time, on purpose: it is
//!    the propagation witness. A zero TOTAL would mean the taint never
//!    arrived, which would make every in-file zero meaningless.

const std = @import("std");
const builtin = @import("builtin");
const fp = @import("fp.zig");
const g1 = @import("g1.zig");
const scalar = @import("scalar.zig");

const Fp = fp.Fp;
const Fr = scalar.Fr;

/// Deterministic secret material, computed at runtime (not folded at comptime)
/// so tainting it marks memory the code under test actually reads.
fn secretBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

/// A tainted field element.
///
/// The bytes are parsed CLEAN and the taint is applied to the resulting limbs
/// afterwards. `fromBytes`'s canonicality check (`geP`) is a documented
/// parse-path branch on data the module calls public — EIP-197 encoding
/// validation of a coordinate that arrived on the wire — so tainting its input
/// would report the module's own input validation as a finding nobody claims,
/// and bury the arithmetic underneath it. What is secret here is the VALUE the
/// arithmetic then runs on.
fn secretFp(comptime domain: []const u8, tainted: bool) !Fp {
    var raw = secretBytes(32, domain);
    var r = reloadVolatile(32, &raw);
    r[0] = 0; // canonical without a comparison: p's top byte is non-zero
    var v = try Fp.fromBytes(r);
    if (tainted) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&v.limbs));
    return v;
}

/// A tainted scalar, same reasoning: `Fr.fromBytes`'s own canonicality branch
/// is parse-path validation, and the secret is the scalar the ladder consumes.
fn secretFr(comptime domain: []const u8, tainted: bool) !Fr {
    var raw = secretBytes(32, domain);
    var r = reloadVolatile(32, &raw);
    r[0] = 0;
    var v = try Fr.fromBytes(r);
    if (tainted) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&v));
    return v;
}

fn printFp(name: []const u8, v: Fp) void {
    std.debug.print("{s}={x}\n", .{ name, v.toBytes() });
}

const Target = enum { field, scalarmul };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "field")) return .field;
    if (std.mem.eql(u8, s, "scalarmul")) return .scalarmul;
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
        .field => {
            const a = try secretFp("ctgrind-bn254-harness-a-v1", tainted);
            const b = try secretFp("ctgrind-bn254-harness-b-v1", tainted);

            printFp("mul", a.mul(b));
            printFp("square", a.square());
            printFp("add", a.add(b));
            printFp("sub", a.sub(b));
            printFp("neg", a.neg());
            printFp("inv", a.inv() catch return error.NotInvertible);

            // The `blackBox` claim itself: a select whose CONDITION is
            // secret. Derived from a tainted limb rather than from a literal,
            // so the bit really is undefined to memcheck.
            var cond_raw = secretBytes(1, "ctgrind-bn254-harness-cond-v1");
            if (tainted) std.valgrind.memcheck.makeMemUndefined(&cond_raw);
            const cond_bytes = reloadVolatile(1, &cond_raw);
            printFp("ctselect", Fp.ctSelect(cond_bytes[0] & 1 == 1, a, b));
        },
        .scalarmul => {
            // The point is PUBLIC (the curve generator); the scalar is not.
            const s = try secretFr("ctgrind-bn254-harness-scalar-v1", tainted);
            const p = g1.Jacobian.fromAffine(g1.Affine.generator);
            const r = p.scalarMul(s).toAffine();
            printFp("x", r.x);
            printFp("y", r.y);
        },
    }
}
