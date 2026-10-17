// SPDX-License-Identifier: MIT
//! Size probe for the `small` lane (CONVENTIONS §4.2): one X25519 keygen, the
//! shape of axp-agent's enrollment (the request that added
//! `ct25519-base-comb`). Built at ReleaseSmall under `-Dprofile=default` and
//! `-Dprofile=small` by `scripts/checks/small-sizes.sh`; the size difference
//! is held to its floor in `scripts/checks/small-size-expected.tsv`.
const std = @import("std");
const ct = @import("ct25519");

pub fn main() void {
    var sk: [32]u8 = undefined;
    const pid: u32 = @bitCast(std.os.linux.getpid());
    for (&sk, 0..) |*b, i| b.* = @truncate(pid *% 2654435761 +% @as(u32, @truncate(i)));
    const pk = ct.X25519.recoverPublicKey(sk) catch std.os.linux.exit(2);
    std.os.linux.exit(pk[0] & 1);
}
