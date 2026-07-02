//! netaddr — IP address parse/format + RFC 6724 source/destination selection.
//!
//! STUB. Real implementation to be extracted from zig-fping `src/netutil.zig`
//! (`sortByDestinationPolicy`, `policyPrecedence`, `destinationReachable`).

const std = @import("std");

pub const meta = .{
    .status = .extract, // seeded in zig-fping/src/netutil.zig
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "glibc getaddrinfo reachability / Go net/addrselect.go",
    .deps = .{}, // std only
};

// ── public API (stub) ─────────────────────────────────────────────────────────

/// Parse a dotted-quad IPv4 literal. Placeholder until extraction.
pub fn parseIp4(text: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, text, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 4) return null;
        out[i] = std.fmt.parseInt(u8, part, 10) catch return null;
    }
    return if (i == 4) out else null;
}

test "parseIp4 roundtrip" {
    try std.testing.expectEqual([4]u8{ 192, 168, 0, 1 }, parseIp4("192.168.0.1").?);
    try std.testing.expectEqual(@as(?[4]u8, null), parseIp4("192.168.0"));
    try std.testing.expectEqual(@as(?[4]u8, null), parseIp4("192.168.0.256"));
}
