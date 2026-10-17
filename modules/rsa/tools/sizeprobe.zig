// SPDX-License-Identifier: MIT
//! Size probe for the `small` lane (CONVENTIONS §4.2): a minimal consumer of
//! rsa's public API — parse a key, sign, verify — built at ReleaseSmall under
//! `-Dprofile=default` and `-Dprofile=small` by `scripts/checks/small-sizes.sh`,
//! which holds the size difference to its floor in
//! `scripts/checks/small-size-expected.tsv`. Inputs are derived from the pid so
//! nothing folds at comptime; the program is never meant to succeed.
const std = @import("std");
const rsa = @import("rsa");

pub fn main() void {
    var buf: [rsa.max_modulus_len]u8 = undefined;
    const pid: u32 = @bitCast(std.os.linux.getpid());
    for (&buf, 0..) |*b, i| b.* = @truncate(pid *% 2654435761 +% @as(u32, @truncate(i)));
    buf[0] |= 0x80;
    buf[buf.len - 1] |= 1;
    const msg = "sizeprobe";
    var out: [rsa.max_modulus_len]u8 = undefined;
    var rc: u8 = 0;
    if (rsa.VerifyKey.fromBytes(&buf, &.{ 1, 0, 1 })) |vk| {
        vk.verifyPkcs1v15(std.crypto.hash.sha2.Sha256, msg, &buf) catch {
            rc |= 1;
        };
    } else |_| rc |= 2;
    var sk: rsa.SecretKey = undefined;
    if (rsa.SecretKey.fromDer(&sk, &buf)) |_| {
        defer sk.deinit();
        _ = rsa.signPkcs1v15(&sk, std.crypto.hash.sha2.Sha256, msg, &out) catch {
            rc |= 4;
        };
    } else |_| rc |= 8;
    std.os.linux.exit(rc);
}
