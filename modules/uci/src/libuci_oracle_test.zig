// SPDX-License-Identifier: MIT

//! **External anchor: the real libuci on 465 inputs, parser and serializer.**
//!
//! `testdata/libuci_capture.zig` was taken by `tools/interop.zig` (`zig build
//! interop-uci -- --capture`) against libuci built from OpenWRT source: the
//! 65 grammar probes of `tools/gen_probes.py` and 400 seeded random configs
//! (`tools/libuci_corpus.py`). For each: libuci's canonical dump of what it
//! built, this module's `serialize` of its own parse, and libuci's dump of
//! THAT. Here, with no libuci:
//!
//! - **parser**: this module's dump of each input equals libuci's, or both
//!   refuse it -- except the inputs `expected` classifies as recorded
//!   contract (fail-open on empty words, deliberate strictness);
//! - **serializer**: `serialize` still writes the recorded text, and libuci
//!   read that text as exactly the model it was written from.

const std = @import("std");
const testing = std.testing;
const uci = @import("root.zig");
const rec = @import("testdata/libuci_capture.zig");

/// The dump `tools/oracle_dump.c` prints, from this module's model (the same
/// format `tools/module_dump.zig` prints).
fn dump(a: std.mem.Allocator, pkg: *const uci.Package) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    const hex = struct {
        fn f(al: std.mem.Allocator, o: *std.ArrayList(u8), s: ?[]const u8) !void {
            const v = s orelse return o.appendSlice(al, "-");
            if (v.len == 0) return o.appendSlice(al, ".");
            for (v) |c| try o.print(al, "{x:0>2}", .{c});
        }
    }.f;
    for (pkg.sections) |*s| {
        try out.appendSlice(a, "S ");
        try hex(a, &out, s.type);
        try out.appendSlice(a, " ");
        try hex(a, &out, s.name);
        try out.print(a, " {c}\n", .{@as(u8, if (s.anonymous) 'A' else 'N')});
        for (s.options) |*o| {
            try out.print(a, "O {c} ", .{@as(u8, switch (o.kind) {
                .single => 's',
                .list => 'l',
            })});
            try hex(a, &out, o.key);
            for (o.values) |v| {
                try out.appendSlice(a, " ");
                try hex(a, &out, v);
            }
            try out.appendSlice(a, "\n");
        }
    }
    return out.items;
}

const Class = enum { same, both_reject, module_rejects, module_accepts, value_diverge };

/// Does `pkg` carry an empty section type or option key -- the U18 shape
/// this module accepts on read where libuci reports insufficient arguments?
fn hasEmptyWord(pkg: *const uci.Package) bool {
    for (pkg.sections) |*sec| {
        if (sec.type.len == 0) return true;
        for (sec.options) |*o| if (o.key.len == 0) return true;
    }
    return false;
}

test "libuci oracle: the parser builds libuci's model, the serializer writes text libuci reads back" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var counts = std.EnumArray(Class, usize).initFill(0);
    for (rec.cases, 0..) |c, i| {
        errdefer std.debug.print("case {d}: {f}\n  libuci: {s}\n", .{ i, std.zig.fmtString(c.input), c.libuci });
        const theirs_err = std.mem.startsWith(u8, c.libuci, "ERR");
        const pkg_or = uci.parse(a, c.input);
        const class: Class = if (pkg_or) |pkg| blk: {
            if (theirs_err) break :blk .module_accepts;
            break :blk if (std.mem.eql(u8, try dump(a, &pkg), c.libuci)) .same else .value_diverge;
        } else |_| if (theirs_err) .both_reject else .module_rejects;
        counts.getPtr(class).* += 1;
        switch (class) {
            .same, .both_reject => {},
            // Recorded contract (tools/README.md): fail-open only on the
            // empty-word shape (U18) ...
            .module_accepts => try testing.expect(hasEmptyWord(&(pkg_or catch unreachable))),
            // ... and deliberate strictness only through these refusals
            // (U1/U11/U12/U7).
            .module_rejects => {
                const e = if (pkg_or) |_| unreachable else |err| err;
                try testing.expect(e == error.MixedOptionList or e == error.DuplicateSection or e == error.InvalidName);
            },
            .value_diverge => return error.TestUnexpectedResult,
        }

        // The serializer, for every input this module parses.
        const pkg = pkg_or catch continue;
        if (c.serialized) |text| {
            try testing.expectEqualStrings(text, try uci.serialize(a, &pkg));
            try testing.expectEqualStrings(try dump(a, &pkg), c.libuci_serialized.?);
        } else {
            // A model libuci would not load is refused on write, by name.
            const recorded = c.libuci_serialized.?["SERIALIZE-ERROR ".len..];
            if (uci.serialize(a, &pkg)) |_| return error.TestUnexpectedResult else |e| {
                try testing.expectEqualStrings(recorded, @errorName(e));
            }
        }
    }
    // Pinned (2026-10-06 capture): a regenerated corpus that lost a class
    // shows here, and so does a parser change that moves an input across.
    try testing.expectEqual(@as(usize, 137), counts.get(.same));
    try testing.expectEqual(@as(usize, 316), counts.get(.both_reject));
    try testing.expectEqual(@as(usize, 9), counts.get(.module_rejects));
    try testing.expectEqual(@as(usize, 3), counts.get(.module_accepts));
    try testing.expectEqual(@as(usize, 0), counts.get(.value_diverge));
}
