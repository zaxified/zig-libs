// SPDX-License-Identifier: MIT
//! Size probe for the `small` lane (CONVENTIONS §4.2): a minimal consumer of
//! montint's run-time-modulus API — `DynModint(8192)`, one secret-exponent
//! `pow` — built at ReleaseSmall under `-Dprofile=default` and
//! `-Dprofile=small` by `scripts/checks/small-sizes.sh`, which holds the size
//! difference (the `montint-asm-unroll` knob) to its floor in
//! `scripts/checks/small-size-expected.tsv`. Inputs are derived from the pid
//! so nothing folds at comptime; the result only feeds the exit code.
const std = @import("std");
const montint = @import("montint");

const D = montint.DynModint(8192);

pub fn main() void {
    var buf: [1024]u8 = undefined;
    const pid: u32 = @bitCast(std.os.linux.getpid());
    for (&buf, 0..) |*b, i| b.* = @truncate(pid *% 2654435761 +% @as(u32, @truncate(i)));
    // The modulus length (and so the slot) comes from the pid too.
    const len = 128 + (pid % 7) * 128;
    buf[0] |= 0x80;
    buf[len - 1] |= 1;
    const m = D.fromBytesBE(buf[0..len]) catch std.os.linux.exit(2);
    const base = m.reduceBytesBE(buf[1..len]);
    const exp = m.reduceBytesBE(buf[2..len]);
    const r = m.pow(&base, &exp);
    var out: [1024]u8 = undefined;
    m.toBytesBE(&r, out[0..len]);
    std.os.linux.exit(out[len / 2]);
}
