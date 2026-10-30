// SPDX-License-Identifier: MIT

//! No-panic sweep tests (wave GU, gu-a). Every test name ends with its finding
//! ID; report: ~/CML/20261029-panic-sweep/b64ct-sweep.report.md.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");

const max = std.math.maxInt(usize);

test "encodedLen / encodedWrappedLen: huge n saturates, never wraps (sweep B6-1)" {
    inline for (.{ root.standard, root.standard_no_pad, root.url_safe, root.url_safe_no_pad }) |C| {
        try testing.expectEqual(max, C.encodedLen(max));
        try testing.expectEqual(max, C.encodedLen(max - 100));
        try testing.expectEqual(max, C.encodedWrappedLen(max, 64, .crlf));
        try testing.expectEqual(max, C.encodedWrappedLen(max - 100, 64, .lf));
        // Where the true length fits nothing changes.
        try testing.expectEqual(@as(usize, 0), C.encodedLen(0));
        try testing.expectEqual(@as(usize, 4), C.encodedLen(3));
        try testing.expectEqual(@as(usize, 0), C.encodedWrappedLen(0, 64, .lf));
        try testing.expectEqual(@as(usize, 4 + 1), C.encodedWrappedLen(3, 64, .lf));
        try testing.expectEqual(@as(usize, 64 + 2 + 8 + 2), C.encodedWrappedLen(51 + 3, 64, .crlf));
    }
}
