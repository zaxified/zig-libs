// SPDX-License-Identifier: MIT

//! OFFLINE anchor for the Set-Cookie BUILD direction: every case's line was
//! served to headless Chrome (and read by Go's `net/http.ParseSetCookie`),
//! and Chrome's stored cookie was compared with what the fields mean
//! (`tools/setcookie_oracle.js`, answers frozen in `setcookie_vectors.zig`).
//! `SetCookie.write` must produce exactly the line where the oracle says it
//! works, and refuse where a browser would drop the cookie or read it as
//! something else. No Chrome, Go or bun at test time.

const std = @import("std");
const testing = std.testing;
const vectors = @import("setcookie_vectors.zig");

test "setcookie oracle: write produces what Chrome stores as meant, refuses the rest" {
    var bad: usize = 0;
    var seen = [_]usize{0} ** vectors.classes.len;
    for (vectors.cases, 0..) |c, i| {
        var buf: [8192]u8 = undefined;
        if (c.sc.bufPrint(&buf)) |line| {
            if (!c.want or !std.mem.eql(u8, line, c.line)) {
                bad += 1;
                std.debug.print("case {d}: wrote {s}\n    want {s} (chrome={} go={s} class '{s}')\n", .{ i, line, if (c.want) c.line else "a refusal", c.chrome, c.go, c.class });
            }
        } else |err| if (c.want) {
            bad += 1;
            std.debug.print("case {d}: refused ({s}), want {s} (chrome={} go={s} class '{s}')\n", .{ i, @errorName(err), c.line, c.chrome, c.go, c.class });
        }
        if (c.class.len != 0) {
            for (vectors.classes, &seen) |name, *n| {
                if (std.mem.eql(u8, name, c.class)) {
                    n.* += 1;
                    break;
                }
            } else {
                bad += 1;
                std.debug.print("case {d}: unknown class '{s}'\n", .{ i, c.class });
            }
        }
    }
    for (vectors.classes, seen) |name, n| if (n == 0) {
        bad += 1;
        std.debug.print("class {s}: no case\n", .{name});
    };
    try testing.expectEqual(@as(usize, 0), bad);
}
