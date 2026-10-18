// SPDX-License-Identifier: MIT
//! Size probe for the `small` lane (CONVENTIONS §4.2): a minimal consumer of
//! ssh's DH group-exchange arithmetic — `transport.GexMod` from a server
//! prime and one secret `gexPow` — built at ReleaseSmall under
//! `-Dprofile=default` and `-Dprofile=small` by
//! `scripts/checks/small-sizes.sh`, which holds the size difference (the
//! `ssh-gex-max-bits` knob, together with montint's) to its floor in
//! `scripts/checks/small-size-expected.tsv`. Inputs are derived from the pid
//! so nothing folds at comptime; the result only feeds the exit code.
const std = @import("std");
const ssh = @import("ssh");
const t = ssh.transport;

pub fn main() void {
    var buf: [t.gex_max_prime_len]u8 = undefined;
    const pid: u32 = @bitCast(std.os.linux.getpid());
    for (&buf, 0..) |*b, i| b.* = @truncate(pid *% 2654435761 +% @as(u32, @truncate(i)));
    const len = 256 + (pid % 4) * 128;
    const p = buf[0..@min(len, buf.len)];
    p[0] |= 0x80;
    p[p.len - 1] |= 1;
    const m = t.GexMod.fromBytesBE(p) catch std.os.linux.exit(2);
    var out: [t.gex_max_prime_len]u8 = undefined;
    const r = t.gexPow(&m, &.{2}, p[1..], out[0..p.len]) catch std.os.linux.exit(3);
    std.os.linux.exit(r[r.len / 2]);
}
