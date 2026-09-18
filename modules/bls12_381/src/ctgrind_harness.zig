// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Part 4
//! claim (quoted below) and `bls_sig.zig`'s own module doc comment, as an
//! actual committed program instead of an unmeasured sentence. Run it
//! through `../../../scripts/checks/ctgrind.sh bls12_381` (once the coordinator
//! adds the `TARGETS`/`MODES`/`PATTERN`/`LABEL` entries this file's doc
//! comment suggests below — that script REFUSES an unlisted module rather
//! than silently skipping it).
//!
//! NOT wired into `zig build test-bls12_381` — memcheck's context count is
//! valgrind's own verdict, not something a Zig test can assert on. `zig
//! build check-ctgrind` compiles it (a rot guard, no valgrind) once the
//! coordinator's `build.zig` discovery picks this file up by its path
//! existing — see that step's own comment for why that is enough.
//!
//! ## Why this module needed a harness
//!
//! `bls12_381` is this repo's "ct25519 equivalent" for the pairing side:
//! `tlock`, `ibe`, `bbs`, `coconut` and `groth16` (at least — `README.md`'s
//! arc) all lean on THIS module's own constant-time property for their own
//! secret material, and until this file existed nothing measured it. The
//! claim itself, quoted verbatim from `SPEC.md`'s "Part 4 constant-time
//! choices" section:
//!
//! > The SECRET-key paths — `keyGen`, `skToPk`, `sign`, `popProve` — touch
//! > `sk` only via `Fr`'s ff-backed constant-time arithmetic and Part 1's
//! > constant-time double-and-add-always `scalarMul` (`skToPk` on `G1`,
//! > `sign`/`popProve` on `G2`); they contain no secret-dependent branches
//! > or memory accesses.
//!
//! `bls_sig.zig`'s own module doc comment (lines 46-53) states the same
//! thing in fewer words. Both sentences name exactly the two call shapes
//! this harness drives: a secret `Fr` scalar through `G1.Jacobian.scalarMul`
//! (the `skToPk` shape) and through `G2.Jacobian.scalarMul` (the
//! `sign`/`popProve` shape). Neither `SPEC.md` nor `README.md` makes any
//! constant-time claim about hash-to-curve or the pairing itself — both
//! operate on PUBLIC messages/points at every real call site (`SPEC.md`'s
//! "Constant-time choices" explicitly calls the verify family and
//! hash-to-curve variable-time), so this harness does not taint anything
//! flowing into `hash_to_curve.zig` or `pairing.zig`: there is no claim
//! there to be evidence for, and tainting a public path would just report
//! that path's ordinary input-validation branches as a finding nobody
//! makes.
//!
//! ## The three targets
//!
//! * `field` — `Fp.mul`/`square`/`add`/`sub`/`neg`/`inv`/`ctSelect`, driven
//!   from tainted `Fp` elements (and, for `ctSelect`, a tainted select bit).
//!   `fp.zig` is this module's OWN hand-rolled Montgomery field (CIOS
//!   multiply, dedicated SOS square, masked conditional subtract, an
//!   inline-asm `blackBox` optimization barrier — see that file's module
//!   doc comment) — structurally the same construction as `bn254/src/fp.zig`
//!   (this harness mirrors that module's `field` target almost line for
//!   line), just `L = 6` limbs for the 381-bit prime instead of 4. `inv` is
//!   included because it is `powBE` over a PUBLIC exponent (`p-2`) applied
//!   to a SECRET base — the exponent's bits are public, the base's limbs
//!   are not.
//! * `g1_scalarmul` — `G1.Jacobian.scalarMul` off the `G1` generator, SCALAR
//!   tainted: the exact shape `bls_sig.skToPk` uses (`SK * G1_generator`).
//! * `g2_scalarmul` — `G2.Jacobian.scalarMul` off the `G2` generator, SCALAR
//!   tainted: the exact shape `bls_sig.sign`/`popProve` use (`SK *
//!   hash-to-curve-output`, here the generator standing in for an arbitrary
//!   `G2` point since the point itself is never secret in any call site —
//!   see "Deliberate choices" below). `G2`'s coordinates live in `Fp2`
//!   (`c0 + c1*u`, `fp2.zig`), so this target's pattern below additionally
//!   needs `fp2.zig` and `g2.zig`, on top of the same `fp.zig`/`scalar.zig`
//!   the `g1_scalarmul` target needs.
//!
//! `Fr` (the scalar; `scalar.zig`) is a bare re-export of
//! `std.crypto.ff`'s Montgomery arithmetic, unlike `Fp` — there is no
//! module-owned `Fr` field arithmetic to give its own target the way
//! `field` does for `Fp`; `Fr` shows up here only as the tainted INPUT the
//! two `scalarmul` targets drive through this module's own ladder code.
//!
//! ## Deliberate choices, so a later reader does not have to re-derive them
//!
//! 1. The CURVE POINT `scalarMul` multiplies is PUBLIC and never tainted —
//!    the `G1`/`G2` generator, standing in for `skToPk`'s literal generator
//!    input and for `sign`'s hash-to-curve OUTPUT (that output is a public
//!    function of a public message; only the exponent `sk` is secret in
//!    every real call site `bls_sig.zig`/`threshold.zig` have). Tainting
//!    the point instead would report the coordinate arithmetic's own
//!    `condSubP`/on-curve bookkeeping as a finding nobody claims.
//! 2. `reloadVolatile` forces the tainted bytes through memory immediately
//!    before the call under test so the optimizer cannot hand the ladder a
//!    defined register copy that predates `makeMemUndefined` — same
//!    reasoning, and same unproven-but-defensive status, as `ct25519`'s
//!    harness doc comment spells out in detail.
//! 3. ReleaseFast only, like `bn254`'s harness: Debug/ReleaseSafe add
//!    overflow-check branches to plain `+`/`-`/`*` on scalar-width integers,
//!    which would bury the ladder's own branch structure under checks that
//!    have nothing to do with this module's constant-time claim. `fp.zig`'s
//!    hot path avoids that already (`@subWithOverflow`/`u128` widening
//!    products never actually overflow their container, so the check never
//!    fires either way) but `scalarMulBytes`'s bit-indexing loop and
//!    `g1.zig`/`g2.zig`'s own glue are ordinary Zig arithmetic, unverified
//!    against this claim at any mode but ReleaseFast.
//! 4. Hex formatting of the results (via `std.debug.print`) is NOT
//!    constant-time, on purpose — it is the propagation witness. A zero
//!    TOTAL for a given row would mean the taint never reached anywhere
//!    observable, which would make every in-file zero on that row mean
//!    "never touched" rather than "no branch found"; a nonzero witness
//!    count is what tells them apart.

const std = @import("std");
const builtin = @import("builtin");
const fp = @import("fp.zig");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const scalar = @import("scalar.zig");

const Fp = fp.Fp;
const Fr = scalar.Fr;

/// Deterministic secret material, computed at runtime (not folded at
/// comptime) so tainting it marks memory the code under test actually
/// reads. Not a KAT — a diagnostic input, not a correctness one; the fixed
/// seed only keeps repeated runs of the table comparable.
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

/// A tainted `Fp` field element. The bytes are parsed CLEAN and the taint
/// is applied to the resulting limbs afterwards: `Fp.fromBytes`'s own
/// canonicality check (`geP`) is parse-path input validation on data this
/// module treats as public wire input, and tainting it would report that
/// validation branch as a finding nobody claims. What is secret is the
/// VALUE the field arithmetic then runs on. `r[0] = 0` makes the draw
/// canonical without a comparison (`p`'s top byte is nonzero, so any
/// 48-byte value whose top byte is `0` is `< p`) — same trick `bn254`'s
/// harness uses.
fn secretFp(comptime domain: []const u8, tainted: bool) !Fp {
    var raw = secretBytes(Fp.encoded_bytes, domain);
    var r = reloadVolatile(Fp.encoded_bytes, &raw);
    r[0] = 0;
    var v = try Fp.fromBytes(r);
    if (tainted) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&v.limbs));
    return v;
}

/// A tainted `Fr` scalar — the secret key `sk` shape. Same clean-parse/
/// taint-after split as `secretFp`, for the same reason (`Fr.fromBytes`'s
/// canonicality check is parse-path validation, not part of the ladder
/// this harness is measuring). `r[0] = 0` is the same trick: `r`'s top byte
/// is `0x73`, so a top byte of `0` is unconditionally `< r`. Unlike `Fp`,
/// `Fr`'s representation (`scalar.zig`) is a bare `std.crypto.ff.Modulus(
/// 256).Fe`, an opaque type this file has no reason to reach inside —
/// `std.mem.asBytes(&v)` taints the whole `Fr` value regardless of its
/// internal layout.
fn secretFr(comptime domain: []const u8, tainted: bool) !Fr {
    var raw = secretBytes(Fr.encoded_bytes, domain);
    var r = reloadVolatile(Fr.encoded_bytes, &raw);
    r[0] = 0;
    var v = try Fr.fromBytes(r);
    if (tainted) std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&v));
    return v;
}

fn printFp(name: []const u8, v: Fp) void {
    std.debug.print("{s}={x}\n", .{ name, v.toBytes() });
}

const Target = enum { field, g1_scalarmul, g2_scalarmul };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "field")) return .field;
    if (std.mem.eql(u8, s, "g1_scalarmul")) return .g1_scalarmul;
    if (std.mem.eql(u8, s, "g2_scalarmul")) return .g2_scalarmul;
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
            const a = try secretFp("ctgrind-bls12_381-harness-a-v1", tainted);
            const b = try secretFp("ctgrind-bls12_381-harness-b-v1", tainted);

            printFp("mul", a.mul(b));
            printFp("square", a.square());
            printFp("add", a.add(b));
            printFp("sub", a.sub(b));
            printFp("neg", a.neg());
            printFp("inv", a.inv() catch return error.NotInvertible);

            // The `blackBox` claim itself (fp.zig's masked conditional
            // subtract/add): a select whose CONDITION is secret. Derived
            // from a tainted byte rather than a literal, so the bit really
            // is undefined to memcheck.
            var cond_raw = secretBytes(1, "ctgrind-bls12_381-harness-cond-v1");
            if (tainted) std.valgrind.memcheck.makeMemUndefined(&cond_raw);
            const cond_bytes = reloadVolatile(1, &cond_raw);
            printFp("ctselect", Fp.ctSelect(cond_bytes[0] & 1 == 1, a, b));
        },
        .g1_scalarmul => {
            // The `skToPk` shape: PK = [sk]G1. Point is PUBLIC (the
            // generator); the scalar is not.
            const s = try secretFr("ctgrind-bls12_381-harness-g1-scalar-v1", tainted);
            const p = g1.Jacobian.fromAffine(g1.Affine.generator);
            const out = p.scalarMul(s).toAffine();
            printFp("x", out.x);
            printFp("y", out.y);
        },
        .g2_scalarmul => {
            // The `sign`/`popProve` shape: R = [sk]Q, Q a G2 point (a
            // hash-to-curve output at every real call site, itself a
            // function of a PUBLIC message — the generator stands in for
            // it here since only the exponent is secret). Point is PUBLIC;
            // the scalar is not.
            const s = try secretFr("ctgrind-bls12_381-harness-g2-scalar-v1", tainted);
            const p = g2.Jacobian.fromAffine(g2.Affine.generator);
            const out = p.scalarMul(s).toAffine();
            printFp("x.c0", out.x.c0);
            printFp("x.c1", out.x.c1);
            printFp("y.c0", out.y.c0);
            printFp("y.c1", out.y.c1);
        },
    }
}

// ── suggested scripts/checks/ctgrind.sh config (coordinator: paste in, do not
// generate mechanically — every existing entry carries hand-written
// reasoning in its own comment; these follow the same shape) ─────────────
//
// declare -A TARGETS=(
//     [bls12_381]="field g1_scalarmul g2_scalarmul"
// )
// declare -A MODES=(
//     [bls12_381]="ReleaseFast"
// )
// declare -A PATTERN=(
//     [bls12_381/field]='fp[.]zig'
//     [bls12_381/g1_scalarmul]='g1[.]zig|fp[.]zig|scalar[.]zig'
//     [bls12_381/g2_scalarmul]='g2[.]zig|fp2[.]zig|fp[.]zig|scalar[.]zig'
// )
// declare -A LABEL=(
//     [bls12_381/field]='bls12_381 fp.zig'
//     [bls12_381/g1_scalarmul]='bls12_381 g1+fp+scalar'
//     [bls12_381/g2_scalarmul]='bls12_381 g2+fp2+fp+scalar'
// )
