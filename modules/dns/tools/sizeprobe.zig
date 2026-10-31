// SPDX-License-Identifier: MIT
//! Size probe for the `small` lane (CONVENTIONS §4.2): a minimal consumer of
//! the resolver — one PTR lookup, the shape of zpinger's trace hop names (the
//! request that added `dns-doh`). Built at ReleaseSmall under
//! `-Dprofile=default` and `-Dprofile=small` by `scripts/checks/small-sizes.sh`;
//! the size difference is held to its floor in
//! `scripts/checks/small-size-expected.tsv`. The address is derived from the
//! pid so nothing folds at comptime; the result only feeds the exit code.
const std = @import("std");
const dns = @import("dns");

pub fn main(init: std.process.Init) void {
    const pid: u32 = @bitCast(std.os.linux.getpid());
    var r = dns.Resolver.init(init.io, init.gpa, .{ .timeout_ms = 1, .attempts = 1 });
    defer r.deinit();
    const names = r.reverse(.{ .v4 = .{ 192, 0, 2, @truncate(pid) } }) catch std.os.linux.exit(2);
    defer r.freeNames(names);
    std.os.linux.exit(@intCast(names.len & 1));
}
