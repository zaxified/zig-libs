// SPDX-License-Identifier: MIT

//! What a caller does with `csvstream`: walk an in-memory CSV buffer record
//! by record, capture the header, split each data row into fields, coerce
//! them to typed values, and reject a ragged row and a malformed number by
//! name instead of crashing on them.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export). If a
//! type needed to call the API is not public, or an error cannot be named
//! from outside, this file stops compiling. The module's own tests cannot
//! notice either, because they live inside it.

const std = @import("std");
const csvstream = @import("csvstream");

const csv_data =
    \\name,age,score,active
    \\"Alice, A.",30,92.5,true
    \\Bob,25,88.25,false
    \\
;

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var it = csvstream.LineIterator.init(csvstream.stripBom(csv_data), '"', 0);

    // First record is the header row.
    const header_line = it.next() orelse return error.EmptyFile;
    var header_buf: [8][]const u8 = undefined;
    const header_fields = try csvstream.splitFields(header_line.bytes, &header_buf, ',', '"', gpa);
    var header = try csvstream.Header.init(gpa, header_fields);
    defer header.deinit();
    std.debug.print("columns: {d}\n", .{header.len()});

    // Remaining records are data rows.
    while (it.next()) |record| {
        var field_buf: [8][]const u8 = undefined;
        const fields = try csvstream.splitFields(record.bytes, &field_buf, ',', '"', gpa);
        try header.validateArity(fields);

        const name = header.get(fields, "name") orelse return error.MissingName;
        const age_field = header.get(fields, "age") orelse return error.MissingAge;
        const score_field = header.get(fields, "score") orelse return error.MissingScore;
        const active_field = header.get(fields, "active") orelse return error.MissingActive;

        const age = try csvstream.parseInt(u8, age_field);
        const score = try csvstream.parseFloat(f64, score_field);
        const active = try csvstream.parseBool(active_field);

        std.debug.print("{s}: age={d} score={d:.2} active={} offset={d}\n", .{
            name, age, score, active, record.byte_offset,
        });
        if (record.unbalanced_quote) std.debug.print("  warning: unbalanced quote\n", .{});
    }

    // A ragged row (wrong field count) is caught by name, not silently
    // misindexed.
    const ragged = [_][]const u8{ "Carol", "40" };
    header.validateArity(&ragged) catch |err| switch (err) {
        error.FieldCountMismatch => std.debug.print("ragged row correctly rejected\n", .{}),
    };

    // A malformed numeric field is caught by name too.
    _ = csvstream.parseInt(u8, "not-a-number") catch |err| switch (err) {
        error.InvalidCharacter => std.debug.print("malformed age correctly rejected\n", .{}),
        error.Overflow => return err,
    };

    // A malformed boolean field, same treatment.
    _ = csvstream.parseBool("maybe") catch |err| switch (err) {
        error.InvalidBool => std.debug.print("malformed bool correctly rejected\n", .{}),
    };

    // An unbalanced quote ends the record but is flagged, not swallowed —
    // the rest of the buffer stays parseable one record later.
    var quote_it = csvstream.LineIterator.init("\"unterminated,1,2,3\nnext,4,5,6\n", '"', 0);
    const bad_record = quote_it.next().?;
    std.debug.print("unbalanced_quote flag: {}\n", .{bad_record.unbalanced_quote});
    if (!bad_record.unbalanced_quote) return error.ExpectedUnbalancedQuote;
    const next_record = quote_it.next().?;
    var next_buf: [4][]const u8 = undefined;
    const next_fields = try csvstream.splitFields(next_record.bytes, &next_buf, ',', '"', gpa);
    std.debug.print("record after the unbalanced one: {s}\n", .{next_fields[0]});
}
