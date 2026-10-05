// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor for the rule semantics and the JSON Schema
//! export: python-jsonschema and ajv 8, two independent JSON Schema 2020-12
//! validators, judged documents against the schema each generated rule set
//! exports (`tools/schema_oracle.py`, answers frozen in
//! `schema_oracle_vectors.zig`). No Python, no bun at test time.
//!
//! Per rule set: `writeJsonSchema(rules)` must be the frozen schema (as a
//! JSON value), so the verdicts below were given on what this module really
//! exports. Per document: `validateJson` must answer `want` -- the two
//! validators' common verdict, or the one a named class in the generator
//! decided -- and `validateJsonStreaming` must answer the same as the tree
//! path.

const std = @import("std");
const testing = std.testing;
const validate = @import("root.zig");
const vectors = @import("schema_oracle_vectors.zig");

fn jsonEql(a: std.json.Value, b: std.json.Value) bool {
    const num = struct {
        fn of(v: std.json.Value) ?f64 {
            return switch (v) {
                .integer => |i| @floatFromInt(i),
                .float => |f| f,
                // An integral bound beyond i64 (`1e20`), written without an exponent.
                .number_string => |n| std.fmt.parseFloat(f64, n) catch null,
                else => null,
            };
        }
    };
    if (num.of(a)) |x| if (num.of(b)) |y| return x == y;
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .null => true,
        .bool => |x| x == b.bool,
        .string => |x| std.mem.eql(u8, x, b.string),
        .number_string => |x| std.mem.eql(u8, x, b.number_string),
        .array => |x| blk: {
            if (x.items.len != b.array.items.len) break :blk false;
            for (x.items, b.array.items) |p, q| if (!jsonEql(p, q)) break :blk false;
            break :blk true;
        },
        .object => |x| blk: {
            if (x.count() != b.object.count()) break :blk false;
            var it = x.iterator();
            while (it.next()) |e| {
                const other = b.object.get(e.key_ptr.*) orelse break :blk false;
                if (!jsonEql(e.value_ptr.*, other)) break :blk false;
            }
            break :blk true;
        },
        .integer, .float => unreachable,
    };
}

test "schema oracle: every rule set exports the schema the validators judged" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var bad: usize = 0;
    for (vectors.sets, 0..) |set, i| {
        var out: std.Io.Writer.Allocating = .init(a);
        try validate.writeJsonSchema(set.rules, &out.writer);
        const ours = try std.json.parseFromSliceLeaky(std.json.Value, a, out.written(), .{});
        const want = try std.json.parseFromSliceLeaky(std.json.Value, a, set.schema, .{});
        if (!jsonEql(ours, want)) {
            bad += 1;
            if (bad <= 10) std.debug.print("set {d}: exported {s}\n        frozen   {s}\n", .{ i, out.written(), set.schema });
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

test "schema oracle: validateJson answers what the schema validators answer" {
    var bad: usize = 0;
    var seen = [_]usize{0} ** vectors.classes.len;
    for (vectors.cases) |c| {
        const rules = vectors.sets[c.set].rules;
        var tree = try validate.validateJson(testing.allocator, c.doc, rules);
        defer tree.deinit();
        var stream = try validate.validateJsonStreaming(testing.allocator, c.doc, rules, .{});
        defer stream.deinit();
        if (tree.ok() != stream.ok()) {
            bad += 1;
            std.debug.print("set {d} doc {s}: tree ok={} stream ok={}\n", .{ c.set, c.doc, tree.ok(), stream.ok() });
            continue;
        }
        const want = c.want orelse {
            bad += 1;
            std.debug.print("set {d} doc {s}: undecided (py={?} ajv={?}), ours ok={}\n", .{ c.set, c.doc, c.py, c.ajv, tree.ok() });
            continue;
        };
        if (tree.ok() != want) {
            bad += 1;
            std.debug.print("set {d} doc {s}: want ok={} (py={?} ajv={?} class '{s}'), ours ok={}", .{ c.set, c.doc, want, c.py, c.ajv, c.class, tree.ok() });
            for (tree.errors) |e| std.debug.print(" [{s}:{s}]", .{ e.path, e.code });
            std.debug.print("\n", .{});
        }
        if (c.class.len != 0) {
            for (vectors.classes, &seen) |name, *n| {
                if (std.mem.eql(u8, name, c.class)) {
                    n.* += 1;
                    break;
                }
            } else {
                bad += 1;
                std.debug.print("set {d} doc {s}: unknown class '{s}'\n", .{ c.set, c.doc, c.class });
            }
        }
    }
    // Every class still decides at least one case: a class nothing exercises
    // is a claim about the module that nothing checks.
    for (vectors.classes, seen) |name, n| if (n == 0) {
        bad += 1;
        std.debug.print("class {s}: no case\n", .{name});
    };
    try testing.expectEqual(@as(usize, 0), bad);
}
