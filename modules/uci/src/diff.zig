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

/// Error set of `diffRecords`: `WorkLimitExceeded` when the `^` records needed
/// to restore the section order would cost more than `edit.max_delta_work` to
/// replay (such a delta could not be loaded again).
pub const DiffError = EditError || error{WorkLimitExceeded};

/// True when `name` can stand as the package part of a delta record and be read
/// back as that same name: no `.` or `=` (they end the path), no space or `'`
/// (the real `uci` refuses such a name: measured), no control byte, and no
/// leading record operator (`-x.lan.x='1'` is a delete record for package
/// `x`: measured, the real binary writes exactly that and then loses the
/// change too).
pub fn deltaNameOk(name: []const u8) bool {
    if (name.len == 0 or std.mem.findScalar(u8, "+-@^|~", name[0]) != null) return false;
    for (name) |c| if (c < 0x20 or c == 0x7f or c == '.' or c == '=' or c == ' ' or c == '\'') return false;
    return true;
}

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
/// `error.DuplicateSection`. A package name that `deltaNameOk` refuses is
/// `error.InvalidName`. The `^` records are few: only the sections outside the
/// longest run that keeps its relative order are moved (one record for one
/// `reorder`); a reshuffle that would cost more than `edit.max_delta_work` to
/// replay is `error.WorkLimitExceeded`. Caller frees.
pub fn diffRecords(gpa: Allocator, from: *const Editor, to: *const Editor, pkg_name: []const u8, filter: ?Filter) DiffError![]u8 {
    if (!deltaNameOk(pkg_name)) return error.InvalidName;
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
        try putMoves(gpa, &out, from, to, &to_ix, pkg_name);
    }
    return out.toOwnedSlice(gpa);
}

/// The `^` records that turn the order the other records leave (the surviving
/// sections of `from` in their order, then the created ones in `to` order) into
/// `to`'s. Sections of the longest increasing run stay; every other one is
/// moved, in `to` order, to just after its predecessor in `to`.
fn putMoves(gpa: Allocator, out: *std.ArrayList(u8), from: *const Editor, to: *const Editor, to_ix: *const std.StringHashMapUnmanaged(usize), pkg_name: []const u8) DiffError!void {
    const n = to.sections.items.len;
    if (n < 2) return;
    const cur = try gpa.alloc(usize, n); // target index of the section at each replayed position
    defer gpa.free(cur);
    const kept = try gpa.alloc(bool, n);
    defer gpa.free(kept);
    @memset(kept, false);
    var m: usize = 0;
    for (from.sections.items) |fs| {
        const ti = to_ix.get(fs.id) orelse continue;
        if ((to.sections.items[ti].name == null) != (fs.name == null)) continue;
        cur[m] = ti;
        kept[ti] = true;
        m += 1;
    }
    for (kept, 0..) |k, ti| if (!k) {
        cur[m] = ti;
        m += 1;
    };
    std.debug.assert(m == n);
    // longest increasing subsequence of `cur` (patience sorting)
    const tails = try gpa.alloc(usize, n); // tails[l]: position in `cur` ending the best run of length l+1
    defer gpa.free(tails);
    const prev = try gpa.alloc(usize, n);
    defer gpa.free(prev);
    var len: usize = 0;
    for (cur, 0..) |v, i| {
        var lo: usize = 0;
        var hi: usize = len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (cur[tails[mid]] < v) lo = mid + 1 else hi = mid;
        }
        prev[i] = if (lo > 0) tails[lo - 1] else std.math.maxInt(usize);
        tails[lo] = i;
        if (lo == len) len += 1;
    }
    @memset(kept, false); // reused: now "stays in place", by target index
    var at = tails[len - 1];
    while (true) {
        kept[cur[at]] = true;
        if (prev[at] == std.math.maxInt(usize)) break;
        at = prev[at];
    }
    var work: u64 = 0;
    for (0..n) |v| {
        if (kept[v]) continue;
        work +|= 4 * @as(u64, n) + 1; // what `reorder` plus its index rebuild cost on replay
        if (work > edit.max_delta_work / 2) return error.WorkLimitExceeded;
        const i = std.mem.findScalar(usize, cur, v).?;
        std.mem.copyForwards(usize, cur[i .. n - 1], cur[i + 1 .. n]);
        const p: usize = if (v == 0) 0 else std.mem.findScalar(usize, cur[0 .. n - 1], v - 1).? + 1;
        std.mem.copyBackwards(usize, cur[p + 1 .. n], cur[p .. n - 1]);
        cur[p] = v;
        try putPos(gpa, out, pkg_name, to.sections.items[v].id, p);
    }
}
