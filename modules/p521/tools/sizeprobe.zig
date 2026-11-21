// SPDX-License-Identifier: MIT
//! Size probe for the `small` lane (CONVENTIONS §4.2): one ECDSA key
//! generation, which takes the fixed-base `s·G` (the `p521-base-table` knob).
//! Built at ReleaseSmall under `-Dprofile=default` and `-Dprofile=small` by
//! `scripts/checks/small-sizes.sh`; the size difference is held to its floor
//! in `scripts/checks/small-size-expected.tsv`.
const std = @import("std");
const p521 = @import("p521");

pub fn main() void {
    const E = p521.EcdsaP521Sha512;
    var seed: [E.KeyPair.seed_length]u8 = undefined;
    const pid: u32 = @bitCast(std.os.linux.getpid());
    for (&seed, 0..) |*b, i| b.* = @truncate(pid *% 2654435761 +% @as(u32, @truncate(i)));
    const kp = E.KeyPair.generateDeterministic(seed) catch std.os.linux.exit(2);
    std.os.linux.exit(kp.public_key.toUncompressedSec1()[1] & 1);
}
