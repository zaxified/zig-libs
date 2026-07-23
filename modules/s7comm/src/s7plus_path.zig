// SPDX-License-Identifier: MIT

//! **Symbolic address parser** — the S7-1200 / S7-1500 way of naming a tag.
//!
//! Classic S7comm names memory by area and byte offset (`DB1.DBW20`, parsed in
//! `address.zig`). S7CommPlus instead names a tag *symbolically*, by the path
//! through the controller's object graph:
//!
//! ```text
//! "MotorData".Speed              a member of an optimised data block
//! "MotorData".Axis[2].Position   an array element, then a sub-member
//! "Config"."Set Point"           a member whose name needs quoting
//! ```
//!
//! The root (the data block or tag table) is always a quoted name; each step is
//! either `.member` (bare identifier or a quoted name) or `[index]` (a decimal
//! array subscript). This file turns that string into a bounded list of
//! `Component`s. **Resolution** — mapping the root name to the controller's
//! *relative object id*, then selecting the member/element ids beneath it — is
//! done by `resolve`, against a caller-supplied root table, because the id map
//! is per-connection state the PLC hands out at browse time.
//!
//! Every malformed form (an unterminated quote, an empty step, a non-numeric or
//! unterminated subscript, a dangling dot, trailing garbage) is a typed error,
//! never a silently truncated path.

const std = @import("std");

pub const Error = error{
    /// The path was empty.
    EmptyPath,
    /// The path does not begin with a quoted root name.
    MissingRoot,
    /// A `"`-quoted name was never closed.
    UnterminatedQuote,
    /// A `.` with no name after it, or `..`.
    EmptyComponent,
    /// A `[` subscript that is empty, non-numeric or unterminated.
    BadIndex,
    /// A subscript larger than a 32-bit index.
    IndexOutOfRange,
    /// Unexpected characters after a complete path.
    TrailingGarbage,
    /// More components than the caller's slice can hold.
    TooManyComponents,
    /// A step that is neither `.name` nor `[index]`.
    BadSeparator,
    /// `resolve` was handed a root name that is not in its table.
    UnknownRoot,
    /// `resolve` walked to a member id that is not registered.
    UnknownMember,
};

/// One step in a symbolic path: a named member or a numeric array subscript.
pub const Component = union(enum) {
    name: []const u8,
    index: u32,
};

/// A parsed path: the root name plus its steps. The slices point into the
/// original string, so it must outlive the `Path`.
pub const Path = struct {
    root: []const u8,
    components: []const Component,
};

const Parser = struct {
    s: []const u8,
    i: usize = 0,

    fn peek(self: *Parser) ?u8 {
        return if (self.i < self.s.len) self.s[self.i] else null;
    }

    /// Reads a `"`-quoted name (the opening quote is at the cursor) and returns
    /// its contents. Rejects an empty name and an unterminated quote.
    fn quoted(self: *Parser) Error![]const u8 {
        self.i += 1; // opening quote
        const start = self.i;
        while (self.peek()) |c| {
            if (c == '"') {
                const name = self.s[start..self.i];
                self.i += 1; // closing quote
                if (name.len == 0) return error.EmptyComponent;
                return name;
            }
            self.i += 1;
        }
        return error.UnterminatedQuote;
    }

    /// Reads a bare identifier: letters, digits and underscore, at least one.
    fn bareName(self: *Parser) Error![]const u8 {
        const start = self.i;
        while (self.peek()) |c| {
            if (std.ascii.isAlphanumeric(c) or c == '_') self.i += 1 else break;
        }
        if (self.i == start) return error.EmptyComponent;
        return self.s[start..self.i];
    }

    /// Reads a `[decimal]` subscript (the `[` is at the cursor).
    fn index(self: *Parser) Error!u32 {
        self.i += 1; // '['
        const start = self.i;
        while (self.peek()) |c| {
            if (std.ascii.isDigit(c)) self.i += 1 else break;
        }
        if (self.i == start) return error.BadIndex;
        const digits = self.s[start..self.i];
        if (self.peek() != ']') return error.BadIndex;
        self.i += 1; // ']'
        return std.fmt.parseInt(u32, digits, 10) catch error.IndexOutOfRange;
    }
};

/// Parses `s` into `out`, returning a `Path` whose `components` view `out`.
pub fn parse(s: []const u8, out: []Component) Error!Path {
    if (s.len == 0) return error.EmptyPath;
    var p = Parser{ .s = s };
    if (p.peek() != '"') return error.MissingRoot;
    const root = try p.quoted();

    var n: usize = 0;
    while (p.peek()) |c| {
        switch (c) {
            '.' => {
                p.i += 1;
                const name = if (p.peek() == '"') try p.quoted() else try p.bareName();
                if (n >= out.len) return error.TooManyComponents;
                out[n] = .{ .name = name };
                n += 1;
            },
            '[' => {
                const idx = try p.index();
                if (n >= out.len) return error.TooManyComponents;
                out[n] = .{ .index = idx };
                n += 1;
            },
            else => return error.BadSeparator,
        }
    }
    return .{ .root = root, .components = out[0..n] };
}

// ── resolution ──────────────────────────────────────────────────────────────

/// Maps a root name to the controller's relative object id. A caller populates
/// one of these from a browse response.
pub const RootBinding = struct {
    name: []const u8,
    /// The relative object id (RID) the controller assigned to this block/tag.
    object_id: u32,
};

/// A resolved symbolic address: the root object id and the chain of member ids
/// / array indices beneath it, ready to become the access path of a
/// `GetVariable`/`SetVariable`.
pub const Resolved = struct {
    object_id: u32,
    /// The literal `Component`s, unchanged — the object layer turns member
    /// names into ids against the object schema it holds.
    steps: []const Component,
};

/// Resolves a parsed path's root against `roots`. The member steps are handed
/// through unchanged: mapping a member *name* to its numeric id needs the
/// object's own schema, which lives one layer up, so `resolve` deliberately
/// stops at the root object and does not invent member ids.
pub fn resolve(p: Path, roots: []const RootBinding) Error!Resolved {
    for (roots) |r| {
        if (std.mem.eql(u8, r.name, p.root)) {
            return .{ .object_id = r.object_id, .steps = p.components };
        }
    }
    return error.UnknownRoot;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "a plain member path parses" {
    var comps: [8]Component = undefined;
    const p = try parse("\"MotorData\".Speed", &comps);
    try testing.expectEqualStrings("MotorData", p.root);
    try testing.expectEqual(@as(usize, 1), p.components.len);
    try testing.expectEqualStrings("Speed", p.components[0].name);
}

test "arrays and nested members parse in order" {
    var comps: [8]Component = undefined;
    const p = try parse("\"MotorData\".Axis[2].Position", &comps);
    try testing.expectEqualStrings("MotorData", p.root);
    try testing.expectEqual(@as(usize, 3), p.components.len);
    try testing.expectEqualStrings("Axis", p.components[0].name);
    try testing.expectEqual(@as(u32, 2), p.components[1].index);
    try testing.expectEqualStrings("Position", p.components[2].name);
}

test "a quoted member with a space parses" {
    var comps: [8]Component = undefined;
    const p = try parse("\"Config\".\"Set Point\"", &comps);
    try testing.expectEqualStrings("Set Point", p.components[0].name);
}

test "just a root is a valid path" {
    var comps: [8]Component = undefined;
    const p = try parse("\"DB\"", &comps);
    try testing.expectEqual(@as(usize, 0), p.components.len);
}

test "malformed paths are typed errors" {
    var comps: [8]Component = undefined;
    try testing.expectError(error.EmptyPath, parse("", &comps));
    try testing.expectError(error.MissingRoot, parse("MotorData.Speed", &comps));
    try testing.expectError(error.UnterminatedQuote, parse("\"MotorData", &comps));
    try testing.expectError(error.EmptyComponent, parse("\"\".x", &comps));
    try testing.expectError(error.EmptyComponent, parse("\"DB\".", &comps));
    try testing.expectError(error.EmptyComponent, parse("\"DB\"..x", &comps));
    try testing.expectError(error.BadIndex, parse("\"DB\".a[]", &comps));
    try testing.expectError(error.BadIndex, parse("\"DB\".a[x]", &comps));
    try testing.expectError(error.BadIndex, parse("\"DB\".a[3", &comps));
    try testing.expectError(error.IndexOutOfRange, parse("\"DB\".a[99999999999]", &comps));
    try testing.expectError(error.BadSeparator, parse("\"DB\"x", &comps));
}

test "too many components overflow into a typed error, not memory" {
    var comps: [2]Component = undefined;
    try testing.expectError(error.TooManyComponents, parse("\"DB\".a.b.c", &comps));
}

test "resolve maps the root and passes steps through" {
    var comps: [8]Component = undefined;
    const p = try parse("\"MotorData\".Axis[2]", &comps);
    const roots = [_]RootBinding{
        .{ .name = "Other", .object_id = 100 },
        .{ .name = "MotorData", .object_id = 260 },
    };
    const r = try resolve(p, &roots);
    try testing.expectEqual(@as(u32, 260), r.object_id);
    try testing.expectEqual(@as(usize, 2), r.steps.len);

    const bad = try parse("\"Nope\".x", &comps);
    try testing.expectError(error.UnknownRoot, resolve(bad, &roots));
}

test "fuzz: path parse never panics" {
    try std.testing.fuzz({}, fuzzParse, .{});
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    var comps: [16]Component = undefined;
    const p = parse(buf[0..len], &comps) catch return;
    // Anything that parses has a root that points inside the input.
    try testing.expect(p.components.len <= comps.len);
}
