// SPDX-License-Identifier: MIT
//! Size probe for the `small` lane (CONVENTIONS §4.2): one Ed448 key pair from a
//! seed and one signature, both of which take the fixed-base `[s]B` (the
//! `ed448-base-comb` knob). Built at ReleaseSmall under `-Dprofile=default` and
//! `-Dprofile=small` by `scripts/checks/small-sizes.sh`; the size difference is
//! held to its floor in `scripts/checks/small-size-expected.tsv`.
const std = @import("std");
const ed448 = @import("ed448");

pub fn main() void {
    var seed: [57]u8 = undefined;
    const pid: u32 = @bitCast(std.os.linux.getpid());
    for (&seed, 0..) |*b, i| b.* = @truncate(pid *% 2654435761 +% @as(u32, @truncate(i)));
    var kp: ed448.ed448.KeyPair = undefined;
    ed448.ed448.KeyPair.createInto(&kp, &seed);
    const sig = ed448.ed448.sign(&kp, "probe", "") catch std.os.linux.exit(2);
    std.os.linux.exit(sig.toBytes()[0] & 1);
}
