// SPDX-License-Identifier: MIT

//! OFFLINE replay of the JSON Lines and logfmt oracle (`tools/interop.zig` +
//! `tools/json_oracle.py` + `tools/go_json` + `tools/go_logfmt`, frozen in
//! `json_oracle_vectors.zig`). Python's json, Go's encoding/json and jq each
//! read every line back to exactly its entry -- every field, absent ones as
//! `null` (`user` absent), numbers to the last digit of a u64, and an
//! ill-formed UTF-8 subsequence as one U+FFFD per maximal subpart, the reading
//! Python's own `decode('utf-8', 'replace')` gives. No Python, Go or jq at
//! test time: the replay requires the very bytes they read.

const std = @import("std");
const testing = std.testing;
const accesslog = @import("root.zig");
const vectors = @import("json_oracle_vectors.zig");

test "json oracle: every entry writes the line three foreign readers read back exactly" {
    var bad: usize = 0;
    for (vectors.cases, 0..) |c, i| {
        var out: std.Io.Writer.Allocating = .init(testing.allocator);
        defer out.deinit();
        try accesslog.writeJsonLines(c.entry, &out.writer);
        if (!std.mem.eql(u8, out.written(), c.line)) {
            bad += 1;
            if (bad <= 5) std.debug.print("case {d}: wrote\n{s}judged\n{s}", .{ i, out.written(), c.line });
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}

test "logfmt oracle: every entry writes the line go-logfmt read back exactly" {
    // go-logfmt (the de-facto reference reader) decoded each line to exactly
    // the entry's key/value pairs, raw bytes included; it refused the old
    // `\xHH` control-byte escape outright.
    var bad: usize = 0;
    for (vectors.cases, 0..) |c, i| {
        var out: std.Io.Writer.Allocating = .init(testing.allocator);
        defer out.deinit();
        try accesslog.writeLogfmt(c.entry, &out.writer);
        if (!std.mem.eql(u8, out.written(), c.logfmt)) {
            bad += 1;
            if (bad <= 5) std.debug.print("case {d}: wrote\n{s}judged\n{s}", .{ i, out.written(), c.logfmt });
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
}
