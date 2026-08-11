// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "MEASURED, not
//! merely constructed" bullet, as an actual committed program. Run it through
//! `../../../scripts/ctgrind.sh ed448`, which builds every switch/taint
//! combination and prints the control table.
//!
//! Until 2026-08-11 that bullet quoted exact counts (3 errors / 3 contexts for
//! the signing path, 0 / 0 for the ladders in isolation, 860 for the injected
//! defect) with no harness anywhere in the repo. The numbers were real when
//! they were taken; nothing let a reader re-take them, which is the finding
//! this file closes.
//!
//! NOT wired into `zig build test-ed448` — memcheck's context count is
//! valgrind's output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## The two targets, and why there are two
//!
//! * `--target full` — the SHIPPED secret path: `KeyPair.create(seed)`,
//!   `sign`, and `x448.scalarmult`, all driven from a tainted seed. This one
//!   is EXPECTED to report a small non-zero count, and the point of the
//!   measurement is *which* lines: `Fe.invert`'s `if (a.isZero())` guard,
//!   reached from `Point.toBytes` and from the X448 ladder's final
//!   `z_2.invert()`. Both are genuine validations whose outcome is invariant
//!   (a projective `Z` on a complete Edwards curve is never zero; the ladder's
//!   case is fixed by the PUBLIC input point), not scalar-dependent branches.
//!   Run the driver with `--stacks` to read the frames rather than trust that
//!   sentence.
//! * `--target ladder` — `Point.mul` and `Point.mulBasePoint` in isolation,
//!   with no `toBytes` downstream, which is where the "0 errors / 0 contexts"
//!   half of the claim lives. `decaf448`'s `Element.scalarMul` rides exactly
//!   this code; its own harness measures it one level up.
//!
//! Having both in one table is what makes either readable: `full` being
//! non-zero proves the taint propagates through this module's arithmetic at
//! all, so `ladder`'s zero means "no branch found", not "the harness is
//! blind".
//!
//! ## The traps
//!
//! 1. `std.valgrind.doClientRequest` returns early unless
//!    `builtin.valgrind_support`, which the release optimize modes disable.
//!    A ReleaseFast binary built without `-fvalgrind` reports 0 no matter what
//!    the code does. The driver builds both ways and prints that as a row.
//! 2. `reloadVolatile` forces a real load from freshly-tainted memory so the
//!    optimizer cannot feed the ladder a defined register copy. Defensive, not
//!    demonstrated — as in `ct25519`'s harness.
//! 3. Run at ReleaseFast. `Debug`/`ReleaseSafe` add integer-overflow branches
//!    inside `field.zig`'s limb arithmetic, which are branches on tainted
//!    limbs and bury the signal.
//!
//! ## The propagation witness
//!
//! `ladder` cannot use `Point.toBytes` (that is the very `Fe.invert` the other
//! target is about), so it prints the raw projective coordinates through
//! `Fe.toBytes` — a branch-free carry/reduce — and formats them with
//! `std.debug.print`, which is not constant-time. A non-zero total next to a
//! zero in-module count is what distinguishes "no branch found" from "taint
//! never arrived".

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const ed448 = root.ed448;
const x448 = root.x448;
const scalar = root.scalar;
const Point = ed448.Point;

/// Deterministic secret material. Computed at runtime (not folded at comptime)
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

const Target = enum { full, ladder };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "full")) return .full;
    if (std.mem.eql(u8, s, "ladder")) return .ladder;
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

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    // Public message and context: never tainted, so a branch on them (there
    // are several, all on length) cannot be mistaken for a secret-dependent
    // one.
    const msg = "ctgrind harness message";
    const ctx = "";

    switch (target) {
        .full => {
            var seed = secretBytes(57, "ctgrind-ed448-harness-ed448-seed-v1");
            taintIf(tainted, &seed);
            const sk_seed = reloadVolatile(57, &seed);

            const kp = ed448.KeyPair.create(sk_seed);
            const sig = try ed448.sign(kp, msg, ctx);

            var k = secretBytes(56, "ctgrind-ed448-harness-x448-scalar-v1");
            taintIf(tainted, &k);
            const x_scalar = reloadVolatile(56, &k);
            const shared = try x448.scalarmult(x_scalar, x448.base_u);

            // Propagation witnesses: hex formatting is not constant-time.
            std.debug.print("pk={x}\n", .{kp.public_key.toBytes()});
            std.debug.print("sig={x}\n", .{sig.toBytes()});
            std.debug.print("x448={x}\n", .{shared});
        },
        .ladder => {
            var wide = secretBytes(114, "ctgrind-ed448-harness-ladder-scalar-v1");
            taintIf(tainted, &wide);
            const wide_r = reloadVolatile(114, &wide);
            const s: scalar.CompressedScalar = scalar.reduceWide(wide_r);

            const q = Point.mul(Point.basePoint, s);
            const r = Point.mulBasePoint(s);

            // NOT `Point.toBytes`: that runs `Fe.invert`, which is the branch
            // the `full` target exists to account for. `Fe.toBytes` is a
            // branch-free carry/reduce, so it can serve as the witness
            // without contributing the very context under discussion.
            std.debug.print("mul.x={x}\n", .{q.x.toBytes()});
            std.debug.print("mul.y={x}\n", .{q.y.toBytes()});
            std.debug.print("mul.z={x}\n", .{q.z.toBytes()});
            std.debug.print("base.x={x}\n", .{r.x.toBytes()});
            std.debug.print("base.y={x}\n", .{r.y.toBytes()});
            std.debug.print("base.z={x}\n", .{r.z.toBytes()});
        },
    }
}
