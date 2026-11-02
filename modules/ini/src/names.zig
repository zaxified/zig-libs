// SPDX-License-Identifier: MIT

//! Section and key names as hash-table keys: seeded, optionally ASCII-case-folded.

const std = @import("std");

/// Hash of a name, ASCII-case-folded when `fold`, keyed by `seed`.
pub fn hash(seed: u64, fold: bool, s: []const u8) u64 {
    if (!fold) return std.hash.Wyhash.hash(seed, s);
    var h = std.hash.Wyhash.init(seed);
    var buf: [64]u8 = undefined;
    var i: usize = 0;
    while (i < s.len) {
        const n = @min(buf.len, s.len - i);
        for (s[i..][0..n], buf[0..n]) |c, *o| o.* = std.ascii.toLower(c);
        h.update(buf[0..n]);
        i += n;
    }
    return h.final();
}

pub fn eql(fold: bool, a: []const u8, b: []const u8) bool {
    return if (fold) std.ascii.eqlIgnoreCase(a, b) else std.mem.eql(u8, a, b);
}
