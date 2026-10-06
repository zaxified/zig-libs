// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor for the text path: query decoding and the
//! coercion of a query/path value to its rule's kind. Python's `parse_qsl`,
//! Go's `net/url` and WHATWG `URLSearchParams` decoded the queries; pydantic
//! (lax mode, fed the bytes the module decodes) judged the coercion, with Go's
//! strconv and Python's `int()`/`float()` beside it (`tools/query_oracle.py`,
//! answers frozen in `query_oracle_vectors.zig`). No Python, Go or bun at
//! test time.

const std = @import("std");
const testing = std.testing;
const validate = @import("root.zig");
const vectors = @import("query_oracle_vectors.zig");

fn classSeen(seen: []usize, class: []const u8) bool {
    for (vectors.classes, seen) |name, *n| {
        if (std.mem.eql(u8, name, class)) {
            n.* += 1;
            return true;
        }
    }
    return false;
}

test "query oracle: validateQuery coerces as pydantic does" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var bad: usize = 0;
    var seen = [_]usize{0} ** vectors.classes.len;
    for (vectors.coerce) |c| {
        const rule = &vectors.rules[c.rule];
        var q: std.Io.Writer.Allocating = .init(a);
        try q.writer.writeAll("v=");
        for (c.value) |byte| try q.writer.print("%{X:0>2}", .{byte});
        var r = try validate.validateQuery(testing.allocator, q.written(), rule[0..1]);
        defer r.deinit();
        // pydantic stops at a field's first error, the module reports them
        // all (a NaN fails both bounds): the wanted code must be among them.
        const has_code = for (r.errors) |e| {
            if (std.mem.eql(u8, e.code, c.want_code)) break true;
        } else c.want_code.len == 0;
        const code: []const u8 = if (r.errors.len == 0) "" else r.errors[0].code;
        if (r.ok() != c.want or !has_code) {
            bad += 1;
            std.debug.print("rule {d} value {any}: want ok={} code '{s}' (class '{s}', go={?} builtin={?}), ours ok={} code '{s}'\n", .{
                c.rule, c.value, c.want, c.want_code, c.class, c.go, c.builtin, r.ok(), code,
            });
        }
        if (c.class.len != 0 and !classSeen(&seen, c.class)) {
            bad += 1;
            std.debug.print("unknown class '{s}'\n", .{c.class});
        }
    }
    for (vectors.decode) |d| if (d.class.len != 0 and !classSeen(&seen, d.class)) {
        bad += 1;
        std.debug.print("query '{s}': class '{s}' (py={?s} go={?s} whatwg={?s})\n", .{ d.query, d.class, d.py, d.go, d.whatwg });
    };
    for (vectors.classes, seen) |name, n| if (n == 0) {
        bad += 1;
        std.debug.print("class {s}: no case\n", .{name});
    };
    try testing.expectEqual(@as(usize, 0), bad);
}

test "query oracle: the first value of a field decodes as the parsers decode it" {
    const absent = "\x00absent";
    const Q = struct { v: []const u8 = absent };
    var bad: usize = 0;
    for (vectors.decode) |d| {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const res = try validate.parseQueryLeaky(Q, arena.allocator(), d.query, .{});
        switch (res) {
            .ok => |v| {
                const got: ?[]const u8 = if (v.v.ptr == absent.ptr) null else v.v;
                const same = if (got) |g| (if (d.want) |w| std.mem.eql(u8, g, w) else false) else d.want == null;
                if (!same) {
                    bad += 1;
                    std.debug.print("query '{s}': want {?s}, ours {?s}\n", .{ d.query, d.want, got });
                }
            },
            .invalid => |r| {
                // A decoded value that is not UTF-8 is refused by the string
                // coercion (the coerce vectors pin that); anything else is a miss.
                const w = d.want orelse "";
                if (std.unicode.utf8ValidateSlice(w) or r.errors.len != 1 or
                    !std.mem.eql(u8, r.errors[0].code, "string_unicode"))
                {
                    bad += 1;
                    std.debug.print("query '{s}': want {?s}, ours invalid", .{ d.query, d.want });
                    for (r.errors) |e| std.debug.print(" [{s}:{s}]", .{ e.path, e.code });
                    std.debug.print("\n", .{});
                }
            },
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}
