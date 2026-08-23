// SPDX-License-Identifier: MIT

//! What a report-widget consumer does with `jsonshape`: reshape a raw JSON
//! feed (a `{items:[...]}`-style endpoint response) into a `dataset.Dataset`
//! two ways — a JSONPath-subset filter expression, and the poc-compatible
//! `[x,y]` default — and cross-check the filtered row set against `jq`,
//! which most consumers of this shape reach for first.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const jsonshape = @import("jsonshape");
const dataset = @import("dataset");

// A sensor feed shaped like a real `getDataview`-style endpoint response.
// `jq -c '[.readings[] | select(.value > 5) | .sensor]'` on this document
// prints `["b","c"]` — the external oracle for the filter-expression case
// below (checked by hand against an installed `jq`; the resulting values
// are asserted directly here since the example itself must stay offline).
const feed =
    \\{"readings":[
    \\  {"sensor":"a","value":3.5},
    \\  {"sensor":"b","value":9.2},
    \\  {"sensor":"c","value":7.8}
    \\]}
;

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // `shape` parses into and returns arena-scoped memory (README "Memory
    // model") — a caller supplies the arena, same contract as `dataset`
    // itself.
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    // JSONPath-subset filter expression: only readings whose value exceeds
    // 5, projected to sensor name (text) + value (float). Matches `jq`'s
    // `select(.value > 5)` above.
    const cols = [_]jsonshape.JsonCol{
        .{ .name = "sensor", .key = "sensor", .type = .text },
        .{ .name = "value", .key = "value", .type = .float },
    };
    const filtered = try jsonshape.shape(a, feed, .{
        .path = "readings[?(@.value > 5)]",
        .columns = &cols,
    });
    std.debug.assert(filtered.rowCount() == 2);
    std.debug.assert(std.mem.eql(u8, filtered.cell(0, "sensor").?.asText().?, "b"));
    std.debug.assert(std.mem.eql(u8, filtered.cell(1, "sensor").?.asText().?, "c"));
    std.debug.print("filter [?(@.value > 5)]: {d} rows, matches jq's select(.value > 5)\n", .{filtered.rowCount()});

    // The poc-compatible `[x,y]` default (no `columns`): x/y pulled
    // positionally from the wildcard-matched objects.
    const xy = try jsonshape.shape(a, feed, .{
        .path = "readings[*]",
        .x = "sensor",
        .y = "value",
    });
    std.debug.assert(xy.rowCount() == 3);
    const series = try xy.seriesXY(a, "x", "y");
    std.debug.print("[x,y] default over readings[*]: {d} points, first=({d:.1})\n", .{ series.len, series[0][1] });

    // A path that resolves to nothing (wrong key) degrades to an empty
    // dataset with the declared columns — not an error. This is the
    // documented behavior contract, exercised as an effect since it is not
    // a failure the module raises.
    const empty = try jsonshape.shape(a, feed, .{ .path = "no_such_key", .columns = &cols });
    std.debug.assert(empty.rowCount() == 0);
    std.debug.assert(empty.columns.len == 2);
    std.debug.print("missing path: 0 rows, {d} declared columns preserved (not an error)\n", .{empty.columns.len});

    // Malformed JSON is the one error this module raises, and it must be
    // nameable from outside.
    if (jsonshape.shape(a, "{not valid json", .{})) |_| {
        unreachable;
    } else |err| switch (err) {
        error.BadJson => std.debug.print("malformed JSON correctly rejected: BadJson\n", .{}),
        error.OutOfMemory => return err,
    }
}
