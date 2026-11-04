// SPDX-License-Identifier: MIT

//! Delta records between two editor states: `save` (write the staged changes
//! as a delta file) and `revert` below package level (turn one section or
//! option back into the committed one). The records are the format
//! `Editor.applyDelta` replays, so the result is checkable: replaying
//! `diffRecords(from, to)` on `from` gives `to` (up to options with no value).

const std = @import("std");
const edit = @import("edit.zig");
const Allocator = std.mem.Allocator;
const Editor = edit.Editor;
const EditError = edit.EditError;

/// Limit `diffRecords` to one section, and inside it to one option key.
pub const Filter = struct {
    section: []const u8,
    key: ?[]const u8 = null,
};

fn putRec(gpa: Allocator, out: *std.ArrayList(u8), prefix: []const u8, pkg: []const u8, sec: []const u8, key: ?[]const u8, value: ?[]const u8) Allocator.Error!void {
    try out.appendSlice(gpa, prefix);
    try out.appendSlice(gpa, pkg);
    try out.append(gpa, '.');
    try out.appendSlice(gpa, sec);
    if (key) |k| {
        try out.append(gpa, '.');
        try out.appendSlice(gpa, k);
    }
    if (value) |v| {
        try out.append(gpa, '=');
        try edit.shellQuote(gpa, out, v);
    }
    try out.append(gpa, '\n');
}

fn optEq(a: *const Editor.Opt, b: *const Editor.Opt) bool {
    if (a.kind != b.kind or a.values.items.len != b.values.items.len) return false;
    for (a.values.items, b.values.items) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

fn putPos(gpa: Allocator, out: *std.ArrayList(u8), pkg: []const u8, id: []const u8, pos: usize) Allocator.Error!void {
    var nb: [24]u8 = undefined;
    const s = std.fmt.bufPrint(&nb, "{d}", .{pos}) catch unreachable; // 24 bytes hold any usize
    try putRec(gpa, out, "^", pkg, id, null, s);
}

/// The delta records that turn the state of `from` into the state of `to`;
/// the two must come from one base (their anonymous ids agree). With a
/// `filter`, only that section (and option) is considered. Options with no
/// value count as absent. Deletions first, then creations and changes in `to`
/// order, then `^` reorders when replaying would not give `to`'s order.
/// Two sections of one state with the same id (a named section called like an
/// anonymous one's generated id) cannot be told apart by any record:
/// `error.DuplicateSection`. Caller frees.
pub fn diffRecords(gpa: Allocator, from: *const Editor, to: *const Editor, pkg_name: []const u8, filter: ?Filter) EditError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var from_ix: std.StringHashMapUnmanaged(usize) = .empty;
    defer from_ix.deinit(gpa);
    var to_ix: std.StringHashMapUnmanaged(usize) = .empty;
    defer to_ix.deinit(gpa);
    for (from.sections.items, 0..) |s, i| {
        const g = try from_ix.getOrPut(gpa, s.id);
        if (g.found_existing) return error.DuplicateSection;
        g.value_ptr.* = i;
    }
    for (to.sections.items, 0..) |s, i| {
        const g = try to_ix.getOrPut(gpa, s.id);
        if (g.found_existing) return error.DuplicateSection;
        g.value_ptr.* = i;
    }
    // A section "survives" when the other state has the same id AND the same
    // namedness: a named section called `cfg0392bd` is not the anonymous one
    // whose generated id is `cfg0392bd` (replaying a type change would keep the
    // old one anonymous).
    const key_only = filter != null and filter.?.key != null;
    if (!key_only) {
        for (from.sections.items) |fs| {
            if (filter) |f| if (!std.mem.eql(u8, f.section, fs.id)) continue;
            if (to_ix.get(fs.id)) |ti| if ((to.sections.items[ti].name == null) == (fs.name == null)) continue;
            try putRec(gpa, &out, "-", pkg_name, fs.id, null, null);
        }
    }
    for (to.sections.items) |ts| {
        if (filter) |f| if (!std.mem.eql(u8, f.section, ts.id)) continue;
        var fi = from_ix.get(ts.id);
        if (fi) |i| if ((from.sections.items[i].name == null) != (ts.name == null)) {
            fi = null;
        };
        if (fi == null) {
            const prefix: []const u8 = if (ts.name != null) "" else "+";
            try putRec(gpa, &out, prefix, pkg_name, ts.id, null, ts.type);
        } else if (!key_only and !std.mem.eql(u8, from.sections.items[fi.?].type, ts.type)) {
            try putRec(gpa, &out, "", pkg_name, ts.id, null, ts.type);
        }
        var fmap: std.StringHashMapUnmanaged(usize) = .empty;
        defer fmap.deinit(gpa);
        var tmap: std.StringHashMapUnmanaged(void) = .empty;
        defer tmap.deinit(gpa);
        if (fi) |i| for (from.sections.items[i].options.items, 0..) |o, oi| {
            const g = try fmap.getOrPut(gpa, o.key);
            if (!g.found_existing) g.value_ptr.* = oi;
        };
        for (ts.options.items) |o| {
            if (o.values.items.len != 0) try tmap.put(gpa, o.key, {});
            if (filter) |f| if (f.key) |k| if (!std.mem.eql(u8, k, o.key)) continue;
            if (o.values.items.len == 0) continue;
            if (fmap.get(o.key)) |oi| {
                if (optEq(&from.sections.items[fi.?].options.items[oi], &o)) continue;
                if (o.kind == .list) try putRec(gpa, &out, "-", pkg_name, ts.id, o.key, null);
            }
            switch (o.kind) {
                .single => try putRec(gpa, &out, "", pkg_name, ts.id, o.key, o.values.items[0]),
                .list => for (o.values.items) |v| try putRec(gpa, &out, "|", pkg_name, ts.id, o.key, v),
            }
        }
        if (fi) |i| for (from.sections.items[i].options.items) |fo| {
            if (filter) |f| if (f.key) |k| if (!std.mem.eql(u8, k, fo.key)) continue;
            if (!tmap.contains(fo.key)) try putRec(gpa, &out, "-", pkg_name, ts.id, fo.key, null);
        };
    }
    if (filter) |f| {
        if (!key_only) if (to_ix.get(f.section)) |pos| try putPos(gpa, &out, pkg_name, f.section, pos);
    } else {
        // Replaying the records above leaves `from` without the deleted
        // sections, then the created ones in `to` order.
        var differs = false;
        var k: usize = 0;
        for (from.sections.items) |fs| {
            const ti = to_ix.get(fs.id) orelse continue;
            if ((to.sections.items[ti].name == null) != (fs.name == null)) continue;
            if (k >= to.sections.items.len or !std.mem.eql(u8, to.sections.items[k].id, fs.id)) {
                differs = true;
                break;
            }
            k += 1;
        }
        if (!differs) {
            for (to.sections.items[@min(k, to.sections.items.len)..]) |ts| {
                const fi = from_ix.get(ts.id) orelse continue;
                if ((from.sections.items[fi].name == null) == (ts.name == null)) {
                    differs = true;
                    break;
                }
            }
        }
        if (differs) for (to.sections.items, 0..) |ts, pos| try putPos(gpa, &out, pkg_name, ts.id, pos);
    }
    return out.toOwnedSlice(gpa);
}
