// SPDX-License-Identifier: MIT

//! What a caller feeding a widget/report pipeline does with `dataset`: build
//! a small table row-at-a-time with `Builder`, serialize it to the module's
//! compact binary wire format, deserialize it back, and project a column for
//! plotting — the transform-algebra shape the module documents (allocator in,
//! new `Dataset` out, nothing mutated in place).
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const dataset = @import("dataset");

pub fn main() !void {
    // dataset's documented memory model: the caller owns an arena for the
    // whole pipeline, transforms allocate from it, nothing is freed
    // per-field. Wrap the arena in a DebugAllocator so a real leak (memory
    // the arena never reclaims, or a stray allocation outside it) still
    // gets caught.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    // Build a small trade blotter: symbol, quantity (int), price (exact
    // fixed-point decimal — never f64 for money).
    const columns = [_]dataset.Column{
        .{ .name = "sym", .type = .text },
        .{ .name = "qty", .type = .int },
        .{ .name = "price", .type = .decimal },
    };
    var builder = dataset.Builder.init(a, &columns);
    try builder.appendRow(&.{ .{ .text = "AAPL" }, .{ .int = 100 }, .{ .decimal = 150_250_000_000_000 } });
    try builder.appendRow(&.{ .{ .text = "MSFT" }, .{ .int = 50 }, .{ .decimal = 410_000_000_000_000 } });
    try builder.appendRow(&.{ .null, .{ .int = 0 }, .{ .decimal = 0 } }); // a row with a missing symbol
    const blotter = try builder.toOwned();

    std.debug.print("built dataset: {d} columns x {d} rows\n", .{ blotter.columns.len, blotter.rowCount() });

    // Round-trip through the wire format, as a cache or IPC layer would.
    const wire = try dataset.serialize(a, blotter);
    std.debug.print("serialized to {d} bytes\n", .{wire.len});

    const restored = dataset.deserialize(a, wire) catch |err| switch (err) {
        error.Corrupt => {
            std.debug.print("wire bytes were corrupt, aborting\n", .{});
            return;
        },
        error.OutOfMemory => return err,
    };
    std.debug.assert(restored.rowCount() == blotter.rowCount());

    // A deliberately truncated buffer must fail by name, not panic — the
    // module's error set has to be nameable from outside to be handled here.
    const truncated = wire[0 .. wire.len - 4];
    if (dataset.deserialize(a, truncated)) |_| {
        std.debug.print("truncated wire unexpectedly parsed\n", .{});
    } else |err| switch (err) {
        error.Corrupt => std.debug.print("truncated wire correctly rejected as corrupt\n", .{}),
        error.OutOfMemory => return err,
    }

    // Project a numeric column for a chart, and total the exact decimal
    // notional (not through the lossy asFloat path).
    const notional = try restored.floatColumn(a, "price");
    var total_raw: i128 = 0;
    for (restored.rows) |row| total_raw += row[2].decimal;
    std.debug.print("qty[0]={d} price[0]~={d:.2}\n", .{ restored.cell(0, "qty").?.int, notional[0] });
    std.debug.print("total notional raw={d} (scale {d})\n", .{ total_raw, dataset.decimal_scale });

    // Emit JSON, as an HTTP API serving this table to a browser widget would.
    const json = try dataset.toJson(a, restored);
    std.debug.print("json bytes: {d}\n", .{json.len});
}
