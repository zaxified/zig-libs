// SPDX-License-Identifier: MIT

//! ctgrind_harness: the measurement behind `SPEC.md`'s constant-time claim.
//! `../../../scripts/checks/ctgrind.sh rescue` builds it with and without
//! `-fvalgrind`, runs every target tainted and untainted and prints the control
//! table.
//!
//! ## What is tainted
//!
//! The secret input of each target: the 12-element sponge state (`permute`),
//! the field elements to hash (`hash`), the two digests of a Merkle node
//! (`merge`), and the S-box layers' input (`sbox`, `sboxinv`). Lengths are
//! public, as the SPEC says.
//!
//! ## What the count is
//!
//! In-file contexts are branches or table indexes on a tainted value inside
//! `goldilocks.zig`, `perm.zig` or `rpo.zig`. The claim is exactly zero for
//! every target; a nonzero count is a defect to be read, not pinned.
//! Each target prints its (still tainted) result as the propagation witness,
//! so a zero in-file count is never "the taint did not arrive".

const std = @import("std");
const builtin = @import("builtin");
const rescue = @import("root.zig");

const Target = enum { permute, hash, merge, sbox, sboxinv };

const Fe = rescue.Fe;

fn reload(comptime n: usize, s: *const [n]Fe) [n]Fe {
    var out: [n]Fe = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile Fe = b;
        o.* = vb.*;
    }
    return out;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next();
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = std.meta.stringToEnum(Target, target_arg) orelse return error.UnknownTarget;
    const taint = if (std.mem.eql(u8, taint_arg, "yes")) true else if (std.mem.eql(u8, taint_arg, "no")) false else return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    // Secret felts: canonical field elements derived from a fixed seed.
    var secret: [12]Fe = undefined;
    var x: u64 = 0x243f6a8885a308d3;
    for (&secret) |*e| {
        x = x *% 6364136223846793005 +% 1442695040888963407;
        e.* = rescue.fromU64(x);
    }
    if (taint) std.valgrind.memcheck.makeMemUndefined(std.mem.sliceAsBytes(&secret));
    const s = reload(12, &secret);

    switch (target) {
        .permute => {
            var st = s;
            rescue.Rpo256.permute(&st);
            std.debug.print("ctgrind_result={x}\n", .{std.mem.asBytes(&st)});
        },
        .hash => {
            const d = rescue.Rpo256.hashElements(s[0..9]);
            std.debug.print("ctgrind_result={x}\n", .{std.mem.asBytes(&d)});
        },
        .merge => {
            const a: rescue.Rpo256.Digest = s[0..4].*;
            const b: rescue.Rpo256.Digest = s[4..8].*;
            const d = rescue.Rpo256.merge(a, b);
            std.debug.print("ctgrind_result={x}\n", .{std.mem.asBytes(&d)});
        },
        .sbox => {
            var st = s;
            rescue.goldilocks.sboxLayer(12, &st);
            std.debug.print("ctgrind_result={x}\n", .{std.mem.asBytes(&st)});
        },
        .sboxinv => {
            var st = s;
            rescue.goldilocks.sboxInvLayer(12, &st);
            std.debug.print("ctgrind_result={x}\n", .{std.mem.asBytes(&st)});
        },
    }
}
