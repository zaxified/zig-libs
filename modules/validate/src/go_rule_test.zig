// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor for the rule vocabulary: every case in
//! `go_rule_vectors.zig` is a value go-playground/validator v10.30.5 judged with
//! `validate.Var(v, tag)` (`tools/rule_oracle.py`, `tools/go_formats/`), next to
//! the `Rule` the tag maps to. Both paths must give Go's verdict. No Go at test time.

const std = @import("std");
const testing = std.testing;
const validate = @import("root.zig");
const vectors = @import("go_rule_vectors.zig");

test "go rule oracle: the rule vocabulary answers as go-playground's tags do" {
    var bad: usize = 0;
    for (&vectors.cases) |*c| {
        const rules: *const [1]validate.Rule = &c.rule;
        var tree = try validate.validateJson(testing.allocator, c.doc, rules);
        defer tree.deinit();
        var stream = try validate.validateJsonStreaming(testing.allocator, c.doc, rules, .{});
        defer stream.deinit();
        if (tree.ok() != c.go or stream.ok() != c.go) {
            bad += 1;
            if (bad <= 40) std.debug.print("go rule oracle: {s} on {s}: go {}, tree {}, stream {}\n", .{ c.tag, c.doc, c.go, tree.ok(), stream.ok() });
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}
