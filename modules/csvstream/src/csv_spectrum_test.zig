// SPDX-License-Identifier: MIT
//! Drives `LineIterator` + `splitFields` through the vendored maxogden/
//! csv-spectrum corpus (csv_spectrum_vectors.zig), comparing against the
//! corpus's OWN expected JSON -- never against this module's own prior
//! output.
//!
//! Adapter: this module's public API returns per-record field SLICES, not
//! name-keyed rows, so the corpus's array-of-objects shape does not compare
//! directly. This file builds the header->value mapping explicitly (first
//! record = column names, via `splitFields`; every following record zipped
//! against those names) and diffs the result against the parsed JSON fixture
//! field-by-field. That mapping is exactly what the module's own opt-in
//! `Header` helper (header.zig) exists to avoid callers hand-rolling --
//! reused here rather than re-invented.
//!
//! Vectors marked `out_of_scope` are counted (`total_out_of_scope` below is a
//! canary against silently dropping one) and still driven through the parser
//! (must not crash/OOM), but their result is not asserted against `expected`.
//! Each names a specific documented deviation (SPEC.md) or, in one case, a
//! defect in the corpus fixture pair itself -- see csv_spectrum_vectors.zig.

const std = @import("std");
const testing = std.testing;
const csv = @import("root.zig");
const vectors_mod = @import("csv_spectrum_vectors.zig");

/// Splits `bytes` into records, then each record into fields, using this
/// module's own public in-memory API (the layer the corpus is testing --
/// "parse CSV text into rows of fields"). Returns owned-by-`arena` row
/// slices so callers never worry about the per-record borrow contract.
fn parseRows(arena: std.mem.Allocator, bytes: []const u8) ![][][]const u8 {
    var rows = std.array_list.Managed([][]const u8).init(arena);
    var it = csv.LineIterator.init(bytes, '"', 0);
    while (it.next()) |rec| {
        var fbuf: [64][]const u8 = undefined;
        const fields = try csv.splitFields(rec.bytes, &fbuf, ',', '"', arena);
        try rows.append(try arena.dupe([]const u8, fields));
    }
    return rows.toOwnedSlice();
}

/// Compares one data row (already zipped into a `Header`) against the
/// corpus's expected JSON object for that row. Accumulates every mismatch
/// into `mismatches` instead of stopping at the first -- a single `try`
/// here would silently hide every other bad field in the same row.
fn compareRow(
    header: *const csv.Header,
    row: []const []const u8,
    expected: std.json.Value,
    case_name: []const u8,
    row_idx: usize,
    mismatches: *usize,
) void {
    if (expected != .object) {
        std.debug.print("case '{s}' row {d}: expected JSON is not an object ({s})\n", .{ case_name, row_idx, @tagName(expected) });
        mismatches.* += 1;
        return;
    }
    const obj = expected.object;
    if (obj.count() != header.len()) {
        std.debug.print(
            "case '{s}' row {d}: field count mismatch -- header has {d} column(s), expected JSON object has {d} key(s)\n",
            .{ case_name, row_idx, header.len(), obj.count() },
        );
        mismatches.* += 1;
    }
    for (header.names) |name| {
        const got = header.get(row, name) orelse {
            std.debug.print("case '{s}' row {d}: no value for column '{s}' (ragged row)\n", .{ case_name, row_idx, name });
            mismatches.* += 1;
            continue;
        };
        const exp = obj.get(name) orelse {
            std.debug.print("case '{s}' row {d}: expected JSON has no key '{s}'\n", .{ case_name, row_idx, name });
            mismatches.* += 1;
            continue;
        };
        if (exp != .string) {
            std.debug.print("case '{s}' row {d}: expected JSON key '{s}' is not a string ({s})\n", .{ case_name, row_idx, name, @tagName(exp) });
            mismatches.* += 1;
            continue;
        }
        if (!std.mem.eql(u8, exp.string, got)) {
            std.debug.print(
                "MISMATCH case '{s}' row {d} column '{s}': expected \"{s}\", got \"{s}\"\n",
                .{ case_name, row_idx, name, exp.string, got },
            );
            mismatches.* += 1;
        }
    }
}

test "csv-spectrum corpus: vendored count matches expectation (canary)" {
    // If this trips, testdata/csv-spectrum/ was re-vendored or hand-edited
    // without updating csv_spectrum_vectors.zig -- regenerate it, and
    // re-classify any new/changed case, don't just adjust these numbers.
    try testing.expectEqual(@as(usize, 12), vectors_mod.vectors.len);
    var out_of_scope_count: usize = 0;
    for (vectors_mod.vectors) |v| {
        if (v.out_of_scope != null) out_of_scope_count += 1;
    }
    try testing.expectEqual(@as(usize, 4), out_of_scope_count);
}

test "csv-spectrum corpus: in-scope fixtures match the upstream expected JSON" {
    const alloc = testing.allocator;
    var checked: usize = 0;
    var skipped_out_of_scope: usize = 0;
    var mismatches: usize = 0;

    for (vectors_mod.vectors) |v| {
        var arena_state = std.heap.ArenaAllocator.init(alloc);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // Every fixture, in-scope or not, must parse without crashing/OOMing --
        // that much is asserted unconditionally.
        const rows = try parseRows(arena, v.csv);

        if (v.out_of_scope) |reason| {
            _ = reason;
            skipped_out_of_scope += 1;
            continue;
        }

        if (rows.len == 0) {
            std.debug.print("case '{s}': parsed zero records (expected at least a header row)\n", .{v.name});
            mismatches += 1;
            continue;
        }
        var header = try csv.Header.init(arena, rows[0]);
        defer header.deinit();
        const data_rows = rows[1..];

        const parsed = std.json.parseFromSlice(std.json.Value, arena, v.json, .{}) catch |err| {
            std.debug.print("case '{s}': failed to parse its own expected JSON fixture: {t}\n", .{ v.name, err });
            mismatches += 1;
            continue;
        };
        if (parsed.value != .array) {
            std.debug.print("case '{s}': expected JSON is not an array ({s})\n", .{ v.name, @tagName(parsed.value) });
            mismatches += 1;
            continue;
        }
        const expected_rows = parsed.value.array.items;
        if (expected_rows.len != data_rows.len) {
            std.debug.print(
                "case '{s}': row count mismatch -- parsed {d} data row(s), expected JSON has {d}\n",
                .{ v.name, data_rows.len, expected_rows.len },
            );
            mismatches += 1;
        }
        const n = @min(data_rows.len, expected_rows.len);
        for (data_rows[0..n], expected_rows[0..n], 0..) |row, exp, i| {
            compareRow(&header, row, exp, v.name, i, &mismatches);
        }
        checked += 1;
    }

    try testing.expectEqual(@as(usize, 4), skipped_out_of_scope);
    try testing.expectEqual(@as(usize, 8), checked);
    try testing.expectEqual(vectors_mod.vectors.len, checked + skipped_out_of_scope);
    try testing.expectEqual(@as(usize, 0), mismatches);
}
