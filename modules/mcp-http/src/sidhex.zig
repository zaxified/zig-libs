// SPDX-License-Identifier: MIT

//! sidhex — constant-time lowercase hex for the `Mcp-Session-Id`, a 128-bit
//! CSPRNG value whose possession is the whole gate on a session's
//! GET/POST/DELETE. `std.fmt`'s `{x}` indexes a digit table by each secret
//! nibble (memcheck: ctgrind `mcp-http/sid`, 2026-10-10). Measured by
//! `ctgrind_harness.zig`.

const std = @import("std");

/// Lowercase hex of `src` into `out`, branch- and table-free: each nibble
/// `v` becomes `'0' + v + (v >= 10 ? 39 : 0)` with the comparison taken
/// from a borrow. Used for the session id, which is a bearer secret.
pub fn encode(out: *[32]u8, src: *const [16]u8) void {
    for (src, 0..) |b, i| {
        out[2 * i] = nibbleCt(b >> 4);
        out[2 * i + 1] = nibbleCt(b & 15);
    }
}

inline fn nibbleCt(v: u8) u8 {
    const ge10: u8 = @truncate((@as(u16, 9) -% v) >> 8); // 0xff iff v >= 10
    return '0' + v + (ge10 & 39);
}

test "encode matches std's {x} for varied bytes" {
    var raw: [16]u8 = undefined;
    for (0..16) |round| {
        for (&raw, 0..) |*b, i| b.* = @truncate(i *% 17 +% round *% 101);
        var ours: [32]u8 = undefined;
        encode(&ours, &raw);
        var theirs: [32]u8 = undefined;
        _ = try std.fmt.bufPrint(&theirs, "{x}", .{&raw});
        try std.testing.expectEqualStrings(&theirs, &ours);
    }
}
