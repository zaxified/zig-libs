// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Constant-time
//! note (measured)" and for `element.zig`'s `scalarMul` doc comment, as an
//! actual committed program. Run it through
//! `../../../scripts/ctgrind.sh decaf448`.
//!
//! Both of those texts quoted exact counts ("0 memcheck errors through this
//! function", "makes the same run report 860") with no harness in the repo.
//! The numbers were real when they were taken; nothing let a reader re-take
//! them. This file closes that.
//!
//! NOT wired into `zig build test-decaf448` — memcheck's context count is
//! valgrind's output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## What this measures
//!
//! `Element.scalarMul` with the scalar marked `MAKE_MEM_UNDEFINED`. That
//! function is a pure delegation to `ed448.ed448.Point.mul`'s constant-time
//! 4-bit fixed window, so the property is really ed448's; measuring it HERE is
//! what shows the delegation (the 56 -> 57 byte `scalar.toEd448` widening
//! included) adds no branch of its own.
//!
//! Unlike `ct25519`, this module is not exposed to the defect that module
//! exists to remove: `Point.mul` has no `rejectIdentity` and no error union,
//! so there is nothing for a caller to branch on. The zero here is therefore
//! expected — which is exactly why the control rows and the propagation
//! witness matter more, not less.
//!
//! ## The traps
//!
//! 1. Without `-fvalgrind`, `std.valgrind.doClientRequest` returns early
//!    (`builtin.valgrind_support` is off outside Debug) and every row reads 0
//!    regardless. The driver builds both ways and prints it as a row.
//! 2. `reloadVolatile` forces a real load from freshly-tainted memory so the
//!    ladder cannot be fed a defined register copy. Defensive, not
//!    demonstrated.
//! 3. ReleaseFast only: `Debug`/`ReleaseSafe` add integer-overflow branches
//!    inside ed448's `field.zig` limb arithmetic that bury the signal.
//!
//! ## The propagation witness
//!
//! `Element.encode` runs `Fe.invert`, whose `if (a.isZero())` validation would
//! contribute a context of its own and muddy the reading (see `ed448`'s
//! harness for the accounting of exactly that line). So the witness is the raw
//! projective coordinates through `Fe.toBytes` — a branch-free carry/reduce —
//! formatted with `std.debug.print`, which is not constant-time. A non-zero
//! total next to a zero in-module count is what makes the zero mean "no branch
//! found" rather than "the taint never arrived".

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const Element = root.Element;
const scalar = root.scalar;

fn secretScalarBytes() scalar.CompressedScalar {
    var out: scalar.CompressedScalar = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update("ctgrind-decaf448-harness-secret-scalar-v1");
    st.squeeze(&out);
    // Clear the top byte so the value is comfortably below the group order —
    // `scalarMul` does not reduce, and a wrapping scalar would be a different
    // (still constant-time) input rather than a realistic one.
    out[scalar.encoded_bytes - 1] = 0;
    return out;
}

fn reloadVolatile(s: *const scalar.CompressedScalar) scalar.CompressedScalar {
    var out: scalar.CompressedScalar = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Taint = enum { yes, no };

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
    if (!std.mem.eql(u8, target_arg, "scalarmul")) return error.UnknownTarget;
    const taint = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    var s = secretScalarBytes();
    if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&s);
    const secret = reloadVolatile(&s);

    const q = Element.generator.scalarMul(secret);

    std.debug.print("x={x}\n", .{q.p.x.toBytes()});
    std.debug.print("y={x}\n", .{q.p.y.toBytes()});
    std.debug.print("z={x}\n", .{q.p.z.toBytes()});
}
