// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: the module's KATs are a handful of digests. Where did those
// numbers come from? From this sweep, compared against two independent oracles
// by `oracle_sweep.py`. A golden nobody can re-derive is a number, not
// evidence — and no test in `src/` compares EVERY length against a foreign
// implementation.
//
// WHAT IT NEEDS: nothing but the live module. (`oracle_sweep.py`, which reads
// this output, needs Python `hashlib` and `openssl`.)
//
// WHAT IT PRODUCES: one line per length 0..1024:
//     <len> <ripemd160-hex> <hash160-hex>
// over the deterministic family `msg[i] = (7i+13) mod 256`.
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe -O ReleaseFast --dep ripemd160 \
//       -Mmain=sweep.zig -Mripemd160=../src/root.zig \
//       --cache-dir <scratch>/zc-sweep -femit-bin=<scratch>/sweep

const std = @import("std");
const rmd = @import("ripemd160");
const out = @import("out.zig");

pub fn main() !void {
    var msg: [4096]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @intCast((i * 7 + 13) % 256);
    var d: [20]u8 = undefined;
    var n: usize = 0;
    while (n <= 1024) : (n += 1) {
        rmd.Ripemd160.hash(msg[0..n], &d, .{});
        out.print("{d} {x} ", .{ n, &d });
        rmd.hash160(msg[0..n], &d);
        out.print("{x}\n", .{&d});
    }
    out.flush();
}
