// SPDX-License-Identifier: MIT
//! Opt-in header-row handling: capture a record's fields as column names and
//! build a name→index map, so callers who want name-based field access don't
//! each hand-roll the same `std.StringHashMap(usize)` bookkeeping. Deliberately
//! NOT wired into `StreamReader`/`LineIterator` automatically — reading past
//! the header row (or not) is app policy, this is just the capture helper.
//!
//! Provenance: original work of the zig-libs authors (MIT).

const std = @import("std");

/// Captured header: owned copies of the column names plus a name→index map.
/// `init`'s `fields` (e.g. the output of `splitFields`) are copied, so the
/// caller's row buffer/borrowed bytes may be reused or go out of scope right
/// after `init` returns.
pub const Header = struct {
    names: [][]u8,
    index: std.StringHashMap(usize),
    alloc: std.mem.Allocator,

    /// Copies `fields` (column names, in order) and builds the name→index
    /// map. On a duplicate name, the LAST occurrence's index wins (matches
    /// typical hash-map upsert semantics; callers with strict-uniqueness
    /// requirements should check `names.len == index.count()` themselves).
    pub fn init(alloc: std.mem.Allocator, fields: []const []const u8) !Header {
        const names = try alloc.alloc([]u8, fields.len);
        errdefer alloc.free(names);
        var copied: usize = 0;
        errdefer for (names[0..copied]) |n| alloc.free(n);

        var index = std.StringHashMap(usize).init(alloc);
        errdefer index.deinit();
        try index.ensureTotalCapacity(@intCast(fields.len));

        for (fields, 0..) |f, i| {
            const owned = try alloc.dupe(u8, f);
            names[i] = owned;
            copied += 1;
            index.putAssumeCapacity(owned, i);
        }
        return .{ .names = names, .index = index, .alloc = alloc };
    }

    pub fn deinit(self: *Header) void {
        for (self.names) |n| self.alloc.free(n);
        self.alloc.free(self.names);
        self.index.deinit();
        self.* = undefined;
    }

    /// Number of columns.
    pub fn len(self: *const Header) usize {
        return self.names.len;
    }

    /// Returns the column index for `name`, or null if not present.
    pub fn indexOf(self: *const Header, name: []const u8) ?usize {
        return self.index.get(name);
    }

    /// Looks up `name`'s value in `row` (a record's already-split fields).
    /// Returns null if the name is unknown OR `row` is too short to have that
    /// column (a short row from a ragged file) — both are "no value", not a
    /// crash.
    pub fn get(self: *const Header, row: []const []const u8, name: []const u8) ?[]const u8 {
        const i = self.indexOf(name) orelse return null;
        if (i >= row.len) return null;
        return row[i];
    }

    /// Field-count/arity check: does `row` have exactly as many fields as
    /// this header has columns? Ragged CSV (short/long rows) is common in the
    /// wild; this is an opt-in guard for callers who want to reject it.
    pub fn validateArity(self: *const Header, row: []const []const u8) error{FieldCountMismatch}!void {
        if (row.len != self.names.len) return error.FieldCountMismatch;
    }
};

/// Standalone field-count check against an arbitrary `expected` count (for
/// callers who want arity validation without building a full `Header`, e.g.
/// against a schema constant rather than a captured first row).
pub fn validateArity(row: []const []const u8, expected: usize) error{FieldCountMismatch}!void {
    if (row.len != expected) return error.FieldCountMismatch;
}

// ============================================================
// Tests
// ============================================================

const t = std.testing;

test "Header.init: captures column names and builds the index" {
    var h = try Header.init(t.allocator, &.{ "name", "age", "city" });
    defer h.deinit();
    try t.expectEqual(@as(usize, 3), h.len());
    try t.expectEqual(@as(?usize, 0), h.indexOf("name"));
    try t.expectEqual(@as(?usize, 1), h.indexOf("age"));
    try t.expectEqual(@as(?usize, 2), h.indexOf("city"));
    try t.expectEqual(@as(?usize, null), h.indexOf("missing"));
}

test "Header.init: names are copied, not borrowed (survive source buffer reuse)" {
    var src_buf: [16]u8 = undefined;
    @memcpy(src_buf[0..3], "foo");
    var h = try Header.init(t.allocator, &.{src_buf[0..3]});
    defer h.deinit();
    // Mutate the original source bytes after init(); the header must be unaffected.
    @memcpy(src_buf[0..3], "bar");
    try t.expectEqual(@as(?usize, 0), h.indexOf("foo"));
    try t.expectEqual(@as(?usize, null), h.indexOf("bar"));
}

test "Header.get: name-based lookup against a data row" {
    var h = try Header.init(t.allocator, &.{ "name", "age" });
    defer h.deinit();
    const row = [_][]const u8{ "alice", "30" };
    try t.expectEqualStrings("alice", h.get(&row, "name").?);
    try t.expectEqualStrings("30", h.get(&row, "age").?);
    try t.expectEqual(@as(?[]const u8, null), h.get(&row, "unknown"));
}

test "Header.get: a short (ragged) row returns null instead of an out-of-bounds read" {
    var h = try Header.init(t.allocator, &.{ "a", "b", "c" });
    defer h.deinit();
    const short_row = [_][]const u8{"only_one"};
    try t.expectEqual(@as(?[]const u8, "only_one"), h.get(&short_row, "a"));
    try t.expectEqual(@as(?[]const u8, null), h.get(&short_row, "b"));
    try t.expectEqual(@as(?[]const u8, null), h.get(&short_row, "c"));
}

test "Header.init: duplicate column names — the LAST occurrence's index wins (documented, previously untested)" {
    var h = try Header.init(t.allocator, &.{ "a", "b", "a" });
    defer h.deinit();
    try t.expectEqual(@as(usize, 3), h.len()); // names array keeps every column
    try t.expectEqual(@as(?usize, 2), h.indexOf("a")); // last "a" (index 2) wins, not the first (0)
    try t.expectEqual(@as(?usize, 1), h.indexOf("b"));
}

test "Header.validateArity: matching and mismatching row lengths" {
    var h = try Header.init(t.allocator, &.{ "a", "b", "c" });
    defer h.deinit();
    try h.validateArity(&.{ "1", "2", "3" });
    try t.expectError(error.FieldCountMismatch, h.validateArity(&.{ "1", "2" }));
    try t.expectError(error.FieldCountMismatch, h.validateArity(&.{ "1", "2", "3", "4" }));
}

test "validateArity: standalone arity check against an explicit expected count" {
    try validateArity(&.{ "1", "2" }, 2);
    try t.expectError(error.FieldCountMismatch, validateArity(&.{"1"}, 2));
}

test "Header.init: empty header (zero columns) is valid" {
    var h = try Header.init(t.allocator, &.{});
    defer h.deinit();
    try t.expectEqual(@as(usize, 0), h.len());
    try h.validateArity(&.{});
}
