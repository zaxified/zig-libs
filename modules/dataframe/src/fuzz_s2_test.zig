// SPDX-License-Identifier: MIT

//! Regression tests for what the dataframe fuzz driver found after it learned the `Expr` and
//! window arms of dataframe S2 waves W2-W5 and W8 (2026-11-10). Each test is one finding.

const std = @import("std");
const testing = std.testing;
const df = @import("root.zig");
const csvio = @import("csvio.zig");
const s2w9 = @import("s2w9_test.zig");

// Fuzz seed 168996 (csv target): a 166-byte input of CR-terminated lines read whole under
// `max_bytes = 172` is a frame, so the chunked reader of the same input must not call it
// `InputTooLarge` (every limit is per chunk, a chunk is at most the whole).
test "fuzz s2: chunked csv reader under max_bytes just above the input length" {
    const bytes = "\rx|y,2020-13-01\r\xe6r>@,2020-1-1\rA\xcc\x8a,2020-13-01\r\xf0\x9f\x98\x80,9999-12-31\r\xe1\xba\x9e,n/a\r\xef\xac\x81,\"0000-00-00\"\rj\x9b\x9cVB@$,1999-12-31\rNone,1999-12-31\r\xff\xfe,2020-02-30\r1.123456789012,\rC\xf9\xf9,2020-02-30\r";
    try testing.expectEqual(@as(usize, 166), bytes.len);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const o: csvio.CsvReadOptions = .{ .delimiter = 44, .quote = 34, .has_header = false, .strict_quotes = false, .max_quoted_lines = 1, .max_bytes = 172 };
    const whole = try csvio.readCsv(a, bytes, o);
    const ts = try a.alloc(csvio.TypeOverride, whole.columns.len);
    for (ts, whole.columns) |*t, c| t.* = .{ .name = c.name, .type = c.type };
    var o2 = o;
    o2.types = ts;
    var slow: s2w9.Slow = undefined;
    slow.init(bytes, 0);
    var rd = try df.CsvChunkReader.init(a, &slow.interface, o2, .{});
    var rows: usize = 0;
    while (try rd.next(a, 2)) |ch| rows += ch.len;
    try testing.expectEqual(whole.len, rows);
}
