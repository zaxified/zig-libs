// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor for the go-playground formats: every case in
//! `go_format_vectors.zig` is a string go-playground/validator v10.30.5 judged
//! with `validate.Var(s, tag)` (`tools/format_oracle.py`, `tools/go_formats/`).
//! `validateFormat` must give Go's verdict, or the one a named class decides
//! where the module deliberately differs. No Go at test time.

const std = @import("std");
const testing = std.testing;
const validate = @import("root.zig");
const vectors = @import("go_format_vectors.zig");

test "go format oracle: validateFormat answers as go-playground does, or as a named class decides" {
    var bad: usize = 0;
    var seen = @as([vectors.classes.len]usize, @splat(0));
    for (vectors.cases) |c| {
        const format = std.meta.stringToEnum(validate.Format, c.format) orelse return error.UnknownFormat;
        const got = validate.validateFormat(format, c.s);
        if (got != c.want) {
            bad += 1;
            std.debug.print("go format oracle: {s} \"{f}\" got {} want {} (go {}, class \"{s}\")\n", .{
                c.format, std.zig.fmtString(c.s), got, c.want, c.go, c.class,
            });
        }
        if (c.class.len != 0) {
            const i = for (vectors.classes, 0..) |name, i| {
                if (std.mem.eql(u8, name, c.class)) break i;
            } else return error.UnknownClass;
            seen[i] += 1;
        } else try testing.expectEqual(c.go, c.want);
    }
    // Every class must decide at least one case, or it is dead weight.
    for (vectors.classes, seen) |name, n| {
        if (n == 0) {
            std.debug.print("go format oracle: class {s} decides nothing\n", .{name});
            bad += 1;
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}
