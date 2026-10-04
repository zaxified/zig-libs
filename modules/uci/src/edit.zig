// SPDX-License-Identifier: MIT
//! Editing a `Package` the way the `uci` CLI does, and reading the staged
//! changes it leaves in its save directory (`/tmp/.uci/<pkg>` on OpenWrt).
//!
//! * `Editor` — a mutable copy of a `Package` with libuci's operations:
//!   `set`, `add`, `delete`, `rename`, `reorder`, `addList`, `delList`.
//!   Sections are addressed as libuci addresses them: a name, `@type[N]`, or
//!   the generated id of an anonymous section (`cfg0389a1`).
//! * `applyDelta` — replay a staged-delta file on a committed package, so a
//!   file-only reader returns what `uci get` / `uci show` return while a
//!   change is set but not committed (LuCI's "Save" without "Apply").
//! * `show` — the `uci show` text form.
//!
//! Every format and rule here was MEASURED against the real `uci` binary
//! (built from OpenWrt's tree by `tools/capture-delta.sh` and driven only
//! through its command line); no libuci source was read. The captures are
//! the tests' expected values.

const std = @import("std");
const root = @import("root.zig");
const Allocator = std.mem.Allocator;
const Package = root.Package;
const Section = root.Section;
const Option = root.Option;

/// The id libuci gives an anonymous section: `cfg` + the package's running
/// section counter (`%02x`, growing past two digits after 255) + the low 16
/// bits of the DJB2 hash (h = 5381; h = h·33 + byte) of the section TYPE
/// (`%04x`). Measured: types `a`/`b`/`ab`/`beta`/`wifi-iface` → `b606`/`b607`/
/// `7728`/`89a1`/`3579`; the counter counts every section the package has
/// allocated — named ones too, and ones a staged `add` created — and is
/// never decremented by a delete.
pub fn anonymousName(buf: *[24]u8, counter: usize, section_type: []const u8) []const u8 {
    var h: u32 = 5381;
    for (section_type) |c| h = h *% 33 +% c;
    return std.fmt.bufPrint(buf, "cfg{x:0>2}{x:0>4}", .{ counter, h & 0xffff }) catch unreachable;
}

pub const EditError = error{
    /// The section reference resolves to nothing.
    NoSuchSection,
    /// A section/option name, section type or option key that `parse` would
    /// refuse (`root.validNameChars` / `root.validTypeChars`), or empty.
    InvalidName,
    /// A rename (or a staged `add`) onto a section name already in use.
    /// Real `uci` then holds two sections of one name — a state `parse`
    /// refuses and `serialize` cannot write — so it is refused here.
    DuplicateSection,
    /// A rename onto an option key already in the section, refused for the
    /// same reason (real `uci` keeps both; `uci get` then answers the first).
    DuplicateOption,
    /// The result would exceed `root.max_total_items`.
    MemoryLimitExceeded,
    OutOfMemory,
};

pub const DeltaError = EditError || error{
    /// A delta record that is not in the format `uci` writes. `Diagnostics.line`
    /// names the line it starts on.
    BadDelta,
};

pub const Editor = struct {
    arena: std.heap.ArenaAllocator,
    name: ?[]const u8,
    sections: std.ArrayList(Sec) = .empty,
    /// libuci's per-package section counter (see `anonymousName`).
    counter: usize = 0,

    const Opt = struct { key: []const u8, kind: Option.Kind, values: std.ArrayList([]const u8) };
    const Sec = struct {
        type: []const u8,
        name: ?[]const u8,
        /// The name, or the generated id of an anonymous section.
        id: []const u8,
        options: std.ArrayList(Opt),
    };

    /// A mutable copy of `pkg`. The counter assumes `pkg` came from `parse`
    /// (section i was the i-th allocated), which is what libuci does on load.
    pub fn init(gpa: Allocator, pkg: *const Package) EditError!Editor {
        var ed: Editor = .{ .arena = .init(gpa), .name = null };
        errdefer ed.arena.deinit();
        const a = ed.arena.allocator();
        if (pkg.name) |n| ed.name = try a.dupe(u8, n);
        for (pkg.sections) |*s| {
            var opts: std.ArrayList(Opt) = .empty;
            for (s.options) |*o| {
                var vals: std.ArrayList([]const u8) = .empty;
                for (o.values) |v| try vals.append(a, try a.dupe(u8, v));
                try opts.append(a, .{ .key = try a.dupe(u8, o.key), .kind = o.kind, .values = vals });
            }
            const ty = try a.dupe(u8, s.type);
            const name: ?[]const u8 = if (s.name) |n| try a.dupe(u8, n) else null;
            try ed.appendSection(ty, name, null, opts);
        }
        return ed;
    }

    pub fn deinit(self: *Editor) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn al(self: *Editor) Allocator {
        return self.arena.allocator();
    }

    fn appendSection(self: *Editor, ty: []const u8, name: ?[]const u8, given_id: ?[]const u8, opts: std.ArrayList(Opt)) EditError!void {
        self.counter += 1;
        const id = name orelse given_id orelse blk: {
            var buf: [24]u8 = undefined;
            break :blk try self.al().dupe(u8, anonymousName(&buf, self.counter, ty));
        };
        try self.sections.append(self.al(), .{ .type = ty, .name = name, .id = id, .options = opts });
    }

    /// The index of the section `ref` names: a section name, an anonymous
    /// section's generated id, or `@type[N]` (N counts named and anonymous
    /// sections of that type; negative counts from the end — `Package.nth`).
    pub fn find(self: *const Editor, ref: []const u8) ?usize {
        if (ref.len > 0 and ref[0] == '@') {
            if (ref[ref.len - 1] != ']') return null;
            const lb = std.mem.indexOfScalar(u8, ref, '[') orelse return null;
            const ty = ref[1..lb];
            var idx = std.fmt.parseInt(i64, ref[lb + 1 .. ref.len - 1], 10) catch return null;
            var count: i64 = 0;
            for (self.sections.items) |s| count += @intFromBool(std.mem.eql(u8, s.type, ty));
            if (idx < 0) idx += count;
            if (idx < 0 or idx >= count) return null;
            var c: i64 = 0;
            for (self.sections.items, 0..) |s, i| {
                if (!std.mem.eql(u8, s.type, ty)) continue;
                if (c == idx) return i;
                c += 1;
            }
            return null;
        }
        for (self.sections.items, 0..) |s, i| if (std.mem.eql(u8, s.id, ref)) return i;
        return null;
    }

    fn must(self: *const Editor, ref: []const u8) EditError!usize {
        return self.find(ref) orelse error.NoSuchSection;
    }

    fn checkName(s: []const u8) EditError!void {
        if (s.len == 0 or !root.validNameChars(s)) return error.InvalidName;
    }
    fn checkType(s: []const u8) EditError!void {
        if (s.len == 0 or !root.validTypeChars(s)) return error.InvalidName;
    }

    /// `uci set pkg.<name>=<type>`: change the type of an existing section,
    /// or create a NAMED section.
    pub fn setSection(self: *Editor, ref: []const u8, section_type: []const u8) EditError!void {
        try checkType(section_type);
        if (self.find(ref)) |i| {
            self.sections.items[i].type = try self.al().dupe(u8, section_type);
            return;
        }
        try checkName(ref);
        try self.appendSection(try self.al().dupe(u8, section_type), try self.al().dupe(u8, ref), null, .empty);
    }

    /// `uci add pkg <type>`: append an anonymous section; returns its
    /// generated id (valid until `deinit`).
    pub fn add(self: *Editor, section_type: []const u8) EditError![]const u8 {
        try checkType(section_type);
        try self.appendSection(try self.al().dupe(u8, section_type), null, null, .empty);
        return self.sections.items[self.sections.items.len - 1].id;
    }

    /// A staged `add` replayed: the id is the one recorded, the counter still
    /// advances (measured).
    fn addWithId(self: *Editor, id: []const u8, section_type: []const u8) EditError!void {
        try checkType(section_type);
        try checkName(id);
        if (self.find(id) != null) return error.DuplicateSection;
        try self.appendSection(try self.al().dupe(u8, section_type), null, try self.al().dupe(u8, id), .empty);
    }

    fn optIndex(sec: *const Sec, key: []const u8) ?usize {
        for (sec.options.items, 0..) |o, i| if (std.mem.eql(u8, o.key, key)) return i;
        return null;
    }

    /// `uci set pkg.sec.key=value`: replace the option (a list becomes a
    /// single option) in place, or append it. An EMPTY value deletes the
    /// option, as `uci` does (it records the set as a delete).
    pub fn set(self: *Editor, ref: []const u8, key: []const u8, value: []const u8) EditError!void {
        const sec = &self.sections.items[try self.must(ref)];
        try checkName(key);
        if (value.len == 0) {
            if (optIndex(sec, key)) |oi| _ = sec.options.orderedRemove(oi);
            return;
        }
        var vals: std.ArrayList([]const u8) = .empty;
        try vals.append(self.al(), try self.al().dupe(u8, value));
        const opt: Opt = .{ .key = try self.al().dupe(u8, key), .kind = .single, .values = vals };
        if (optIndex(sec, key)) |oi| sec.options.items[oi] = opt else try sec.options.append(self.al(), opt);
    }

    /// `uci add_list`: append to a list; a single option becomes a list of
    /// [old, new]; a missing key becomes a one-element list.
    pub fn addList(self: *Editor, ref: []const u8, key: []const u8, value: []const u8) EditError!void {
        const sec = &self.sections.items[try self.must(ref)];
        try checkName(key);
        const v = try self.al().dupe(u8, value);
        if (optIndex(sec, key)) |oi| {
            const o = &sec.options.items[oi];
            o.kind = .list;
            try o.values.append(self.al(), v);
            return;
        }
        var vals: std.ArrayList([]const u8) = .empty;
        try vals.append(self.al(), v);
        try sec.options.append(self.al(), .{ .key = try self.al().dupe(u8, key), .kind = .list, .values = vals });
    }

    /// `uci del_list`: remove EVERY entry equal to `value` from a list. A
    /// single option or a missing key is left alone (measured: `uci` records
    /// nothing for either). The list may end up empty; it stays, as in `uci
    /// show` (`pkg.sec.key=`), and writes nothing on `serialize`.
    pub fn delList(self: *Editor, ref: []const u8, key: []const u8, value: []const u8) EditError!void {
        const sec = &self.sections.items[try self.must(ref)];
        const oi = optIndex(sec, key) orelse return;
        const o = &sec.options.items[oi];
        if (o.kind != .list) return;
        var i: usize = 0;
        while (i < o.values.items.len) {
            if (std.mem.eql(u8, o.values.items[i], value)) _ = o.values.orderedRemove(i) else i += 1;
        }
    }

    /// `uci delete pkg.sec`.
    pub fn delete(self: *Editor, ref: []const u8) EditError!void {
        _ = self.sections.orderedRemove(try self.must(ref));
    }

    /// `uci delete pkg.sec.key` (a missing key is not an error).
    pub fn deleteOption(self: *Editor, ref: []const u8, key: []const u8) EditError!void {
        const sec = &self.sections.items[try self.must(ref)];
        if (optIndex(sec, key)) |oi| _ = sec.options.orderedRemove(oi);
    }

    /// `uci delete pkg.sec.key=<index>`: remove one list entry by 0-based
    /// position (out of range: no-op; the list may end up empty and stays).
    /// On a SINGLE option the index is ignored and the option deleted —
    /// measured both ways: `uci delete p.s.o=0` records `-p.s.o`, and a
    /// replayed `-p.s.o='5'` removes the option.
    pub fn deleteListItem(self: *Editor, ref: []const u8, key: []const u8, index: usize) EditError!void {
        const sec = &self.sections.items[try self.must(ref)];
        const oi = optIndex(sec, key) orelse return;
        const o = &sec.options.items[oi];
        if (o.kind == .single) {
            _ = sec.options.orderedRemove(oi);
            return;
        }
        if (index >= o.values.items.len) return;
        _ = o.values.orderedRemove(index);
    }

    /// `uci rename pkg.sec=<name>`. Naming an anonymous section makes it named.
    pub fn rename(self: *Editor, ref: []const u8, new_name: []const u8) EditError!void {
        const i = try self.must(ref);
        try checkName(new_name);
        if (self.find(new_name)) |j| {
            if (j != i) return error.DuplicateSection;
        }
        const n = try self.al().dupe(u8, new_name);
        self.sections.items[i].name = n;
        self.sections.items[i].id = n;
    }

    /// `uci rename pkg.sec.key=<new key>` (a missing key is not an error).
    pub fn renameOption(self: *Editor, ref: []const u8, key: []const u8, new_key: []const u8) EditError!void {
        const sec = &self.sections.items[try self.must(ref)];
        try checkName(new_key);
        const oi = optIndex(sec, key) orelse return;
        if (optIndex(sec, new_key)) |other| {
            if (other != oi) return error.DuplicateOption;
        }
        sec.options.items[oi].key = try self.al().dupe(u8, new_key);
    }

    /// `uci reorder pkg.sec=<pos>`: move the section to 0-based position
    /// `pos`; past the end means last (measured: `=99` on three sections).
    pub fn reorder(self: *Editor, ref: []const u8, pos: usize) EditError!void {
        const i = try self.must(ref);
        const s = self.sections.orderedRemove(i);
        try self.sections.insert(self.al(), @min(pos, self.sections.items.len), s);
    }

    /// Replay a staged-delta file (the contents of `<savedir>/<pkg_name>`) on
    /// this package, record by record, as `uci` does when it loads a package
    /// with pending changes. Record format (measured):
    ///
    ///   `pkg.sec='type'`        set section (type change, or new named section)
    ///   `pkg.sec.key='v'`       set option          `+pkg.cfgXXXXXX='type'`  add
    ///   `-pkg.sec` / `-pkg.sec.key` / `-pkg.sec.key='N'`  delete (N: list index)
    ///   `|pkg.sec.key='v'`      add_list            `~pkg.sec.key='v'`       del_list
    ///   `@pkg.sec='name'` / `@pkg.sec.key='newkey'`        rename
    ///   `^pkg.sec='N'`          reorder
    ///
    /// Values are shell-style single-quoted (`'it'\''s'`) and may span lines.
    /// Records for another package are skipped, and so is a record whose
    /// section no longer exists — the measured behaviour (a hand-written
    /// delta naming a missing section changes nothing and is no error).
    /// A delta `uci` itself refuses to load cannot be told apart from one it
    /// would accept only by format, so a malformed record is `error.BadDelta`.
    pub fn applyDelta(self: *Editor, pkg_name: []const u8, delta: []const u8, diag: ?*root.Diagnostics) DeltaError!void {
        if (delta.len > root.max_input_len) return self.bad(diag, 0);
        var pos: usize = 0;
        var line: usize = 1;
        while (pos < delta.len) {
            const start_line = line;
            const rec = parseRecord(self.al(), delta, &pos, &line) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.BadDelta => return self.bad(diag, start_line),
            } orelse continue;
            if (!std.mem.eql(u8, rec.pkg, pkg_name)) continue;
            self.replay(rec) catch |e| switch (e) {
                error.NoSuchSection => {},
                error.BadDelta => return self.bad(diag, start_line),
                else => {
                    if (diag) |d| d.line = start_line;
                    return e;
                },
            };
        }
    }

    fn bad(self: *Editor, diag: ?*root.Diagnostics, line: usize) DeltaError {
        _ = self;
        if (diag) |d| d.line = line;
        return error.BadDelta;
    }

    fn replay(self: *Editor, r: Record) DeltaError!void {
        switch (r.op) {
            '+' => {
                if (r.key != null) return error.BadDelta;
                try self.addWithId(r.sec, r.value orelse return error.BadDelta);
            },
            '-' => if (r.key) |k| {
                if (r.value) |v| {
                    const idx = std.fmt.parseInt(usize, v, 10) catch return error.BadDelta;
                    try self.deleteListItem(r.sec, k, idx);
                } else try self.deleteOption(r.sec, k);
            } else {
                if (r.value != null) return error.BadDelta;
                try self.delete(r.sec);
            },
            '|' => try self.addList(r.sec, r.key orelse return error.BadDelta, r.value orelse return error.BadDelta),
            '~' => try self.delList(r.sec, r.key orelse return error.BadDelta, r.value orelse return error.BadDelta),
            '@' => {
                const v = r.value orelse return error.BadDelta;
                if (r.key) |k| try self.renameOption(r.sec, k, v) else try self.rename(r.sec, v);
            },
            '^' => {
                if (r.key != null) return error.BadDelta;
                const v = r.value orelse return error.BadDelta;
                try self.reorder(r.sec, std.fmt.parseInt(usize, v, 10) catch return error.BadDelta);
            },
            0 => {
                const v = r.value orelse return error.BadDelta;
                if (r.key) |k| try self.set(r.sec, k, v) else try self.setSection(r.sec, v);
            },
            else => unreachable,
        }
    }

    /// The edited package, as an independent `Package` (free with
    /// `Package.deinit(gpa)`); the editor stays usable.
    pub fn toPackage(self: *const Editor, gpa: Allocator) EditError!Package {
        var items: usize = 0;
        for (self.sections.items) |s| {
            items += 1 + s.options.items.len;
            for (s.options.items) |o| items += o.values.items.len;
        }
        if (items > root.max_total_items) return error.MemoryLimitExceeded;

        var arena: std.heap.ArenaAllocator = .init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        const secs = try a.alloc(Section, self.sections.items.len);
        for (self.sections.items, secs) |s, *out| {
            const opts = try a.alloc(Option, s.options.items.len);
            for (s.options.items, opts) |o, *oo| {
                const vals = try a.alloc([]const u8, o.values.items.len);
                for (o.values.items, vals) |v, *vv| vv.* = try a.dupe(u8, v);
                oo.* = .{ .key = try a.dupe(u8, o.key), .kind = o.kind, .values = vals };
            }
            out.* = .{
                .type = try a.dupe(u8, s.type),
                .name = if (s.name) |n| try a.dupe(u8, n) else null,
                .anonymous = s.name == null,
                .options = opts,
            };
        }
        return .{
            .name = if (self.name) |n| try a.dupe(u8, n) else null,
            .sections = secs,
            .arena_state = arena.state,
        };
    }

    /// `uci show <pkg_name>` text: `pkg.sec=type`, then `pkg.sec.key='v'`
    /// (a list as space-separated quoted values, an empty list as nothing
    /// after `=`), values quoted shell-style (`'it'\''s'`). `extended`
    /// (`uci show`'s default) addresses anonymous sections as `@type[N]`;
    /// otherwise (`uci -X show`) by their generated id. Caller frees.
    pub fn show(self: *const Editor, gpa: Allocator, pkg_name: []const u8, opts: ShowOptions) Allocator.Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        for (self.sections.items, 0..) |s, i| {
            const ext_index: ?usize = if (s.name == null and opts.extended) blk: {
                var n: usize = 0;
                for (self.sections.items[0..i]) |p| n += @intFromBool(std.mem.eql(u8, p.type, s.type));
                break :blk n;
            } else null;
            for (0..1 + s.options.items.len) |line_i| {
                try out.appendSlice(gpa, pkg_name);
                try out.append(gpa, '.');
                if (ext_index) |n| try out.print(gpa, "@{s}[{d}]", .{ s.type, n }) else try out.appendSlice(gpa, s.id);
                if (line_i == 0) {
                    try out.append(gpa, '=');
                    try out.appendSlice(gpa, s.type);
                } else {
                    const o = s.options.items[line_i - 1];
                    try out.append(gpa, '.');
                    try out.appendSlice(gpa, o.key);
                    try out.append(gpa, '=');
                    for (o.values.items, 0..) |v, vi| {
                        if (vi > 0) try out.append(gpa, ' ');
                        try shellQuote(gpa, &out, v);
                    }
                }
                try out.append(gpa, '\n');
            }
        }
        return out.toOwnedSlice(gpa);
    }
};

pub const ShowOptions = struct {
    /// `@type[N]` for anonymous sections (`uci show`'s default); false gives
    /// the generated ids (`uci -X show`).
    extended: bool = true,
};

fn shellQuote(gpa: Allocator, out: *std.ArrayList(u8), v: []const u8) Allocator.Error!void {
    try out.append(gpa, '\'');
    for (v) |c| {
        if (c == '\'') try out.appendSlice(gpa, "'\\''") else try out.append(gpa, c);
    }
    try out.append(gpa, '\'');
}

/// Replay `delta` on a copy of `pkg` (see `Editor.applyDelta`) and return the
/// result as a new `Package` — what `uci get`/`uci show` report while the
/// changes are staged. `pkg` is not modified. Free with `Package.deinit(gpa)`.
pub fn applyDelta(gpa: Allocator, pkg: *const Package, pkg_name: []const u8, delta: []const u8, diag: ?*root.Diagnostics) DeltaError!Package {
    var ed = try Editor.init(gpa, pkg);
    defer ed.deinit();
    try ed.applyDelta(pkg_name, delta, diag);
    return ed.toPackage(gpa);
}

/// `uci show` of a package as loaded from its file (no staged changes).
pub fn show(gpa: Allocator, pkg: *const Package, pkg_name: []const u8, opts: ShowOptions) (EditError || Allocator.Error)![]u8 {
    var ed = try Editor.init(gpa, pkg);
    defer ed.deinit();
    return ed.show(gpa, pkg_name, opts);
}

const Record = struct {
    op: u8,
    pkg: []const u8,
    sec: []const u8,
    key: ?[]const u8,
    value: ?[]const u8,
};

/// One delta record starting at `pos.*`; null for a blank line.
fn parseRecord(a: Allocator, s: []const u8, pos: *usize, line: *usize) error{ BadDelta, OutOfMemory }!?Record {
    var i = pos.*;
    if (s[i] == '\n') {
        pos.* = i + 1;
        line.* += 1;
        return null;
    }
    var op: u8 = 0;
    if (std.mem.indexOfScalar(u8, "+-@^|~", s[i]) != null) {
        op = s[i];
        i += 1;
    }
    const path_start = i;
    while (i < s.len and s[i] != '=' and s[i] != '\n') i += 1;
    const path = s[path_start..i];
    var parts: [3][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, path, '.');
    while (it.next()) |p| {
        if (n == 3 or p.len == 0) return error.BadDelta;
        parts[n] = p;
        n += 1;
    }
    if (n < 2) return error.BadDelta;

    var value: ?[]const u8 = null;
    if (i < s.len and s[i] == '=') {
        i += 1;
        var v: std.ArrayList(u8) = .empty;
        while (i < s.len and s[i] != '\n') {
            switch (s[i]) {
                '\'' => {
                    i += 1;
                    const close = std.mem.indexOfScalarPos(u8, s, i, '\'') orelse return error.BadDelta;
                    line.* += std.mem.count(u8, s[i..close], "\n");
                    try v.appendSlice(a, s[i..close]);
                    i = close + 1;
                },
                '\\' => {
                    if (i + 1 >= s.len or s[i + 1] == '\n') return error.BadDelta;
                    try v.append(a, s[i + 1]);
                    i += 2;
                },
                else => {
                    try v.append(a, s[i]);
                    i += 1;
                },
            }
        }
        value = v.items;
    }
    if (i < s.len) {
        i += 1; // the record's newline
        line.* += 1;
    }
    pos.* = i;
    return .{ .op = op, .pkg = parts[0], .sec = parts[1], .key = if (n == 3) parts[2] else null, .value = value };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Fixtures captured from the real `uci` by `tools/capture-delta.sh`.
const capture = @embedFile("testdata/delta_capture.txt");

const Scenario = struct { name: []const u8, pkg: []const u8, config: []const u8, delta: []const u8, show_x: []const u8, show: []const u8 };

fn nextScenario(rest: *[]const u8) ?Scenario {
    const head = "### scenario ";
    const at = std.mem.indexOf(u8, rest.*, head) orelse return null;
    var s = rest.*[at + head.len ..];
    const eol = std.mem.indexOfScalar(u8, s, '\n').?;
    var words = std.mem.tokenizeScalar(u8, s[0..eol], ' ');
    const name = words.next().?;
    const pkg = words.next().?;
    s = s[eol + 1 ..];
    const end = std.mem.indexOf(u8, s, "### end\n").?;
    const body = s[0..end];
    rest.* = s[end + "### end\n".len ..];
    return .{
        .name = name,
        .pkg = pkg,
        .config = between(body, "--- config\n", "--- delta\n"),
        .delta = between(body, "--- delta\n", "--- show -X\n"),
        .show_x = between(body, "--- show -X\n", "--- show\n"),
        .show = body[std.mem.indexOf(u8, body, "--- show\n").? + "--- show\n".len ..],
    };
}

fn between(body: []const u8, a: []const u8, b: []const u8) []const u8 {
    const i = std.mem.indexOf(u8, body, a).? + a.len;
    const j = std.mem.indexOfPos(u8, body, i, b).?;
    return body[i..j];
}

test "staged delta replay matches the real uci, scenario by scenario (show and show -X byte for byte)" {
    const gpa = testing.allocator;
    var rest: []const u8 = capture;
    var n: usize = 0;
    while (nextScenario(&rest)) |sc| : (n += 1) {
        var pkg = try root.parse(gpa, sc.config);
        defer pkg.deinit(gpa);
        var ed = try Editor.init(gpa, &pkg);
        defer ed.deinit();
        try ed.applyDelta(sc.pkg, sc.delta, null);
        const sx = try ed.show(gpa, sc.pkg, .{ .extended = false });
        defer gpa.free(sx);
        const se = try ed.show(gpa, sc.pkg, .{});
        defer gpa.free(se);
        testing.expectEqualStrings(sc.show_x, sx) catch |e| {
            std.debug.print("scenario {s} (show -X)\n", .{sc.name});
            return e;
        };
        testing.expectEqualStrings(sc.show, se) catch |e| {
            std.debug.print("scenario {s} (show)\n", .{sc.name});
            return e;
        };
        // The Package form carries the same content: serialize it, parse it
        // back, and `show` (which re-derives @type[N]) agrees.
        var applied = try applyDelta(gpa, &pkg, sc.pkg, sc.delta, null);
        defer applied.deinit(gpa);
        const again = try show(gpa, &applied, sc.pkg, .{});
        defer gpa.free(again);
        try testing.expectEqualStrings(sc.show, again);
    }
    try testing.expectEqual(@as(usize, 3), n);
}

test "the Editor API reproduces the CLI's every_op scenario without a delta" {
    const gpa = testing.allocator;
    var rest: []const u8 = capture;
    const sc = nextScenario(&rest).?;
    try testing.expectEqualStrings("every_op", sc.name);
    var pkg = try root.parse(gpa, sc.config);
    defer pkg.deinit(gpa);
    var ed = try Editor.init(gpa, &pkg);
    defer ed.deinit();
    // The same commands the capture ran, through the API.
    try ed.set("alpha", "v", "Z");
    try ed.set("alpha", "q", "it's");
    try ed.addList("alpha", "l", "z");
    try ed.delList("alpha", "l", "x");
    try ed.set("@beta[1]", "w", "9");
    try ed.delete("@beta[0]");
    try testing.expectEqualStrings("cfg04eae8", try ed.add("gamma"));
    try ed.setSection("new", "delta");
    try ed.renameOption("alpha", "v", "vv");
    try ed.rename("alpha", "aa");
    try ed.reorder("aa", 2);
    try ed.deleteOption("aa", "q");
    try ed.set("aa", "l", "single");
    const sx = try ed.show(gpa, sc.pkg, .{ .extended = false });
    defer gpa.free(sx);
    try testing.expectEqualStrings(sc.show_x, sx);
}

test "anonymousName: ids measured on the real uci" {
    var buf: [24]u8 = undefined;
    const Row = struct { usize, []const u8, []const u8 };
    const rows = [_]Row{
        .{ 1, "a", "cfg01b606" },         .{ 2, "b", "cfg02b607" },           .{ 3, "ab", "cfg037728" },
        .{ 4, "ba", "cfg047748" },        .{ 5, "beta", "cfg0589a1" },        .{ 6, "gamma", "cfg06eae8" },
        .{ 9, "interface", "cfg096d96" }, .{ 13, "wifi-iface", "cfg0d3579" }, .{ 14, "A", "cfg0eb5e6" },
        .{ 255, "t", "cfgffb619" },       .{ 256, "t", "cfg100b619" },        .{ 300, "t", "cfg12cb619" },
    };
    for (rows) |r| try testing.expectEqualStrings(r[2], anonymousName(&buf, r[0], r[1]));
}

test "Package.resolveSection: name, @type[N], generated id" {
    const gpa = testing.allocator;
    var pkg = try root.parse(gpa, "config alpha 'alpha'\n\toption v 'A'\nconfig beta\n\toption w '1'\nconfig beta\n\toption w '2'\n");
    defer pkg.deinit(gpa);
    try testing.expectEqualStrings("A", pkg.resolveSection("alpha").?.get("v").?);
    try testing.expectEqualStrings("2", pkg.resolveSection("@beta[1]").?.get("w").?);
    try testing.expectEqualStrings("2", pkg.resolveSection("@beta[-1]").?.get("w").?);
    // Section 2 of the package, type beta (the capture's `-probe.cfg0289a1`).
    try testing.expectEqualStrings("1", pkg.resolveSection("cfg0289a1").?.get("w").?);
    try testing.expectEqualStrings("2", pkg.resolveSection("cfg0389a1").?.get("w").?);
    try testing.expect(pkg.resolveSection("cfg0189a1") == null); // counter 1 is alpha, a NAMED section
    try testing.expect(pkg.resolveSection("@beta[2]") == null);
    try testing.expect(pkg.resolveSection("@beta[x]") == null);
    try testing.expect(pkg.resolveSection("@beta[0") == null);
    try testing.expect(pkg.resolveSection("nope") == null);
    try testing.expect(pkg.resolveSection("") == null);
}

test "Section.getBool / getInt" {
    const gpa = testing.allocator;
    var pkg = try root.parse(gpa,
        \\config t 'x'
        \\    option y1 '1'
        \\    option y2 'yes'
        \\    option y3 'on'
        \\    option y4 'true'
        \\    option y5 'enabled'
        \\    option n1 '0'
        \\    option n2 'no'
        \\    option n3 'off'
        \\    option n4 'false'
        \\    option n5 'disabled'
        \\    option u1 'Yes'
        \\    option u2 '2'
        \\    option i1 '-42'
        \\    option i2 '+7'
        \\    option i3 '9223372036854775808'
        \\    option i4 '0x10'
        \\    option i5 ' 1'
        \\    option i6 '-'
        \\    option i7 '1_000'
        \\    list l '5'
        \\    list l '6'
        \\
    );
    defer pkg.deinit(gpa);
    const s = pkg.resolveSection("x").?;
    for ([_][]const u8{ "y1", "y2", "y3", "y4", "y5" }) |k| try testing.expectEqual(@as(?bool, true), s.getBool(k));
    for ([_][]const u8{ "n1", "n2", "n3", "n4", "n5" }) |k| try testing.expectEqual(@as(?bool, false), s.getBool(k));
    try testing.expectEqual(@as(?bool, null), s.getBool("u1")); // case-sensitive
    try testing.expectEqual(@as(?bool, null), s.getBool("u2"));
    try testing.expectEqual(@as(?bool, null), s.getBool("missing"));
    try testing.expectEqual(@as(?i64, -42), s.getInt("i1"));
    try testing.expectEqual(@as(?i64, 7), s.getInt("i2"));
    try testing.expectEqual(@as(?i64, null), s.getInt("i3")); // 2^63 does not fit
    try testing.expectEqual(@as(?i64, null), s.getInt("i4"));
    try testing.expectEqual(@as(?i64, null), s.getInt("i5"));
    try testing.expectEqual(@as(?i64, null), s.getInt("i6"));
    try testing.expectEqual(@as(?i64, null), s.getInt("i7")); // not a Zig literal
    try testing.expectEqual(@as(?i64, 5), s.getInt("l")); // a list's first value
    try testing.expectEqual(@as(?i64, null), s.getInt("missing"));
}

test "applyDelta: missing targets and other packages are skipped; malformed records are refused with a line" {
    const gpa = testing.allocator;
    var pkg = try root.parse(gpa, "config a 'n1'\n\toption o 'x'\n\toption q 'keep'\nconfig b\n\toption w \"it's\"\n");
    defer pkg.deinit(gpa);
    // Measured: this hand-written delta leaves everything but n1.q alone.
    const skipped = "p.gone.o='1'\n-p.gone\n|p.gone.l='v'\n@p.gone='z'\np.n1.q='new'\nother.n1.q='nope'\n^p.gone='0'\n";
    var out = try applyDelta(gpa, &pkg, "p", skipped, null);
    defer out.deinit(gpa);
    try testing.expectEqualStrings("new", out.resolveSection("n1").?.get("q").?);
    try testing.expectEqualStrings("x", out.resolveSection("n1").?.get("o").?);
    try testing.expectEqual(@as(usize, 2), out.sections.len);
    try testing.expect(out.sections[1].anonymous);

    const Bad = struct { []const u8, usize };
    const bad = [_]Bad{
        .{ "p.n1.o='x\n", 1 }, // unterminated quote
        .{ "p.n1.o='a'\np.n1.o.z='b'\n", 2 }, // four-part path
        .{ "p\n", 1 }, // no section
        .{ "p..o='a'\n", 1 }, // empty section
        .{ "+p.cfg01abcd\n", 1 }, // add without a type
        .{ "+p.cfg01abcd.k='t'\n", 1 }, // add with an option
        .{ "p.n1.o='a'\n-p.n1.o='first'\n", 2 }, // list index not a number
        .{ "-p.n1='x'\n", 1 }, // section delete with a value
        .{ "^p.n1='last'\n", 1 }, // reorder position not a number
        .{ "^p.n1.o='1'\n", 1 },
        .{ "|p.n1='v'\n", 1 }, // add_list needs an option
        .{ "~p.n1.o\n", 1 }, // del_list needs a value
        .{ "@p.n1\n", 1 }, // rename needs a value
        .{ "p.n1.o\n", 1 }, // set needs a value
        .{ "p.n1.o=a\\", 1 }, // trailing escape
        .{ "p.n1.o='a'\n\np.n1.o='multi\nline'\np.n1.bad-key='v'\n", 5 }, // invalid key, after a blank line and a two-line value
    };
    for (bad) |b| {
        var diag: root.Diagnostics = .{};
        if (applyDelta(gpa, &pkg, "p", b[0], &diag)) |ok| {
            var o = ok;
            o.deinit(gpa);
            std.debug.print("accepted {s}\n", .{b[0]});
            return error.TestUnexpectedResult;
        } else |e| {
            if (e != error.BadDelta and e != error.InvalidName) return e;
            try testing.expectEqual(b[1], diag.line);
        }
    }
}

test "Editor: refusals keep the model one that parse could have produced" {
    const gpa = testing.allocator;
    var pkg = try root.parse(gpa, "config a 'n1'\n\toption o 'x'\n\toption k 'K'\nconfig a 'n2'\nconfig b\n");
    defer pkg.deinit(gpa);
    var ed = try Editor.init(gpa, &pkg);
    defer ed.deinit();
    // Real uci accepts both and ends up with two sections / two options of
    // one name (measured); this module refuses.
    try testing.expectError(error.DuplicateSection, ed.rename("n1", "n2"));
    try testing.expectError(error.DuplicateOption, ed.renameOption("n1", "k", "o"));
    try testing.expectError(error.DuplicateSection, ed.applyDelta("p", "+p.n2='t'\n", null));
    try ed.rename("n1", "n1"); // onto itself: fine
    try ed.renameOption("n1", "k", "k");
    try testing.expectError(error.InvalidName, ed.rename("n1", "bad-name"));
    try testing.expectError(error.InvalidName, ed.rename("n1", ""));
    try testing.expectError(error.InvalidName, ed.set("n1", "bad key", "v"));
    try testing.expectError(error.InvalidName, ed.setSection("n9", "bad type"));
    try testing.expectError(error.InvalidName, ed.setSection("n-9", "t"));
    try testing.expectError(error.InvalidName, ed.add(""));
    try testing.expectError(error.NoSuchSection, ed.set("nope", "k", "v"));
    try testing.expectError(error.NoSuchSection, ed.delete("@b[1]"));
    // Naming an anonymous section makes it named; an empty set deletes.
    try ed.rename("@b[0]", "bee");
    try ed.set("n1", "o", "");
    var out = try ed.toPackage(gpa);
    defer out.deinit(gpa);
    try testing.expect(!out.sections[2].anonymous);
    try testing.expectEqualStrings("bee", out.sections[2].name.?);
    try testing.expect(out.resolveSection("n1").?.option("o") == null);
    // And the result serializes and parses back to itself.
    const text = try root.serialize(gpa, &out);
    defer gpa.free(text);
    var back = try root.parse(gpa, text);
    defer back.deinit(gpa);
    try testing.expect(back.eql(&out));
}

test "Editor.toPackage refuses a model past max_total_items" {
    const gpa = testing.allocator;
    var pkg = try root.parse(gpa, "config t 'x'\n");
    defer pkg.deinit(gpa);
    var ed = try Editor.init(gpa, &pkg);
    defer ed.deinit();
    // 2 items so far (section + option), then values up to the cap exactly.
    try ed.addList("x", "l", "v");
    for (0..root.max_total_items - 3) |_| try ed.addList("x", "l", "v");
    var ok = try ed.toPackage(gpa);
    ok.deinit(gpa);
    try ed.addList("x", "l", "v");
    try testing.expectError(error.MemoryLimitExceeded, ed.toPackage(gpa));
}

test "edges the mutation run asked for (uci edit)" {
    const gpa = testing.allocator;
    var pkg = try root.parse(gpa, "config alpha 'alpha'\n\toption o 'single'\n\toption s 'keep'\n\tlist l 'a'\nconfig beta\n");
    defer pkg.deinit(gpa);
    var ed = try Editor.init(gpa, &pkg);
    defer ed.deinit();
    // add_list on a single option makes it a LIST (two `list` lines when
    // written), not a single option holding two values.
    try ed.addList("alpha", "o", "two");
    // del_list on a single option is a no-op, even when the value matches.
    try ed.delList("alpha", "s", "keep");
    var out = try ed.toPackage(gpa);
    defer out.deinit(gpa);
    const a = out.resolveSection("alpha").?;
    try testing.expectEqual(Option.Kind.list, a.option("o").?.kind);
    try testing.expectEqual(@as(usize, 2), a.option("o").?.values.len);
    try testing.expectEqualStrings("keep", a.get("s").?);
    // Index delete on a single option deletes the option; on a list, the item.
    try ed.applyDelta("p", "-p.alpha.s='5'\n-p.alpha.l='0'\n", null);
    var out2 = try ed.toPackage(gpa);
    defer out2.deinit(gpa);
    const a2 = out2.resolveSection("alpha").?;
    try testing.expect(a2.option("s") == null);
    try testing.expectEqual(@as(usize, 0), a2.option("l").?.values.len);
    // A named section is not addressable by the id it WOULD have had
    // (alpha is section 1, DJB2("alpha") = 6c2b).
    try testing.expect(pkg.resolveSection("cfg016c2b") == null);
    try testing.expect(pkg.resolveSection("cfg0289a1") != null);
    // A one-part path is malformed even with a value; an escaped newline
    // does not continue a record onto the next line.
    var diag: root.Diagnostics = .{};
    try testing.expectError(error.BadDelta, ed.applyDelta("p", "p='x'\n", &diag));
    try testing.expectEqual(@as(usize, 1), diag.line);
    try testing.expectError(error.BadDelta, ed.applyDelta("p", "p.alpha.o=a\\\np.alpha.k='b'\n", &diag));
    try testing.expectEqual(@as(usize, 1), diag.line);
}
